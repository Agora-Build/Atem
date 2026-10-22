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
use atem_client::host_route::{
    HostChallenge, HostRouteBody, RelayReply, host_route_message, sign_host_route,
};
use atem_client::membership::Head;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
    /// The entry hashes from seq 1 to `head` (a relay's `host_route_ok`
    /// must name one of them).
    pub chain: Arc<Vec<Hash32>>,
}

/// What the relay said of this link's proof (§R9.7b), checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteResult {
    /// `host_route_ok` naming this host and a head it holds.
    Routed { host_id: String, head: Head },
    /// `host_route_refused` with the verifier's code.
    Refused(String),
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

/// Sets `handle` to `state` (only when it changed). `true` when the host
/// can answer challenges again after it couldn't (`Off` to `Ready`: a list
/// pinned, a held list reconciled): a link opened meanwhile answered none,
/// so the broker reconnects it once to prove its route (§R9.7b). The first
/// state after `Starting` is no such event (a link waits for it).
pub fn set(handle: &RouteHandle, state: RouteState) -> bool {
    let mut current = handle.lock().unwrap_or_else(|e| e.into_inner());
    if current.same(&state) {
        return false;
    }
    let serving_again =
        matches!(*current, RouteState::Off(_)) && matches!(state, RouteState::Ready { .. });
    *current = state;
    serving_again
}

/// One link's challenge state: the room and `atem_id` it was opened with,
/// whether its one proof went out and the relay's verdict came, whether
/// Astation authenticated it, the lines written.
pub struct LinkRoute {
    handle: RouteHandle,
    room: String,
    atem_id: String,
    proof_sent: bool,
    verdict: bool,
    /// Set by the link's client once Astation authenticated it.
    authenticated: Arc<AtomicBool>,
    /// Set here once the proof went out (read by the link's client).
    proved: Arc<AtomicBool>,
    /// Set here once the relay's `host_route_ok` for that proof came.
    routed_ok: Arc<AtomicBool>,
    lines: u32,
}

impl LinkRoute {
    pub fn new(handle: RouteHandle, room: &str, atem_id: &str) -> Self {
        LinkRoute {
            handle,
            room: room.to_owned(),
            atem_id: atem_id.to_owned(),
            proof_sent: false,
            verdict: false,
            authenticated: Arc::default(),
            proved: Arc::default(),
            routed_ok: Arc::default(),
            lines: 0,
        }
    }

    /// The flag the link's client sets once Astation authenticated the
    /// link: no challenge is answered after it.
    pub fn authenticated_flag(&self) -> Arc<AtomicBool> {
        self.authenticated.clone()
    }

    /// Set once this link's proof went out: its client then waits for the
    /// relay's verdict even when Astation's authentication failed first.
    pub fn proved_flag(&self) -> Arc<AtomicBool> {
        self.proved.clone()
    }

    /// Set once the relay's `host_route_ok` for this link's proof came: the
    /// link proved its route (§R9.7b).
    pub fn routed_ok_flag(&self) -> Arc<AtomicBool> {
        self.routed_ok.clone()
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
        // One challenge per link, only before it is routed or
        // Astation-authenticated (a later one is no new connection).
        if self.verdict || self.authenticated.load(Ordering::SeqCst) {
            self.log("ignored: the link is already routed or authenticated");
            return None;
        }
        if self.proof_sent {
            self.log("ignored: this link already answered a challenge");
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
                self.proof_sent = true;
                self.proved.store(true, Ordering::SeqCst);
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

impl LinkRoute {
    /// The relay's reply to this link's proof, or `None` when `text` isn't
    /// one or is ignored (logged): malformed, before any proof went out,
    /// naming another host, or a head this host doesn't hold.
    pub fn on_reply(&mut self, text: &str) -> Option<RouteResult> {
        let reply = match RelayReply::parse(text.as_bytes())? {
            Ok(reply) => reply,
            Err(refusal) => {
                self.log_reply(&format!("ignored: {refusal}"));
                return None;
            }
        };
        // A verdict counts only for this link's own proof, once.
        let what = match &reply {
            RelayReply::Ok { .. } => "ok",
            RelayReply::Refused { .. } => "refused",
        };
        if !self.proof_sent {
            self.log_reply(&format!("{what} ignored: no proof was sent on this link"));
            return None;
        }
        if self.verdict {
            self.log_reply(&format!("{what} ignored: this link already has a verdict"));
            return None;
        }
        let (host_id, head) = match reply {
            RelayReply::Refused { code } => {
                self.verdict = true;
                self.log_reply(&format!("refused: {code}"));
                return Some(RouteResult::Refused(code));
            }
            RelayReply::Ok { host_id, head } => (host_id, head),
        };
        let state = self
            .handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let RouteState::Ready { id, .. } = state else {
            self.log_reply("ok ignored: the device list can't serve now");
            return None;
        };
        if host_id != id.host_id {
            self.log_reply("ok ignored: another host");
            return None;
        }
        let known = usize::try_from(head.seq)
            .ok()
            .and_then(|seq| id.chain.get(seq.checked_sub(1)?))
            .is_some_and(|hash| *hash == head.hash);
        if !known {
            self.log_reply("ok ignored: a head this host doesn't hold");
            return None;
        }
        self.verdict = true;
        self.routed_ok.store(true, Ordering::SeqCst);
        self.log_reply(&format!("ok at head {}", head.seq));
        Some(RouteResult::Routed { host_id, head })
    }

    fn log_reply(&mut self, line: &str) {
        if self.lines < MAX_LINES_PER_LINK {
            self.lines += 1;
            eprintln!("atem runtime: r9: host_route {line}");
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_protocol::membership::r9log::{TestLog, secret};
    use atem_client::host_route::{HostRouteRefusal, RelayReply};

    const ROOM: &str = "astation-room";

    fn ready(log: &TestLog) -> RouteHandle {
        let handle = new_handle();
        set(
            &handle,
            RouteState::Ready {
                id: RouteIdentity {
                    account_id: "acct-1".into(),
                    genesis_hash: log.log.genesis_hash(),
                    host_id: "host-1".into(),
                    head: log.log.head(),
                    chain: Arc::new(log.log.entries().iter().map(|e| e.hash()).collect()),
                },
                key: Arc::new(HostKey::new(&secret("route host"))),
            },
        );
        handle
    }

    fn ok(host_id: &str, head: Head) -> String {
        RelayReply::Ok {
            host_id: host_id.into(),
            head,
        }
        .to_json()
        .to_string()
    }

    /// §R9.7b: `host_route_ok` holds the link only after this link sent a
    /// proof, for this host, at a head it holds (its head or an ancestor);
    /// anything else is ignored. `host_route_refused` is the relay's code.
    #[test]
    fn the_relays_reply_is_taken_only_for_this_links_proof() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        log.add_native("dev-phone", &["control", "view"]);
        let handle = ready(&log);
        let head = log.log.head();
        let mut link = LinkRoute::new(handle.clone(), ROOM, "atem-x");
        // Unsolicited: no proof went out on this link yet.
        assert_eq!(link.on_reply(&ok("host-1", head)), None);
        let challenge = HostChallenge::new(ROOM).to_json().to_string();
        assert!(link.answer(&challenge).is_some());
        // Another host, an unknown head, a malformed reply: ignored.
        assert_eq!(link.on_reply(&ok("host-2", head)), None);
        let unknown = Head {
            seq: head.seq + 1,
            hash: head.hash,
        };
        assert_eq!(link.on_reply(&ok("host-1", unknown)), None);
        let fork = Head {
            seq: head.seq,
            hash: Hash32([7; 32]),
        };
        assert_eq!(link.on_reply(&ok("host-1", fork)), None);
        assert_eq!(
            link.on_reply(r#"{"type":"relay","op":"host_route_ok","v":1,"host_id":"host-1"}"#),
            None
        );
        // Not a reply at all: not ours to take.
        assert_eq!(
            link.on_reply(r#"{"type":"relay","op":"push_ack","acks":[]}"#),
            None
        );
        // An unknown code is ignored (no verdict yet).
        assert_eq!(
            link.on_reply(r#"{"type":"relay","op":"host_route_refused","v":1,"code":"nope"}"#),
            None
        );
        // This host at its head: routed, once.
        assert_eq!(
            link.on_reply(&ok("host-1", head)),
            Some(RouteResult::Routed {
                host_id: "host-1".into(),
                head
            })
        );
        let refused = RelayReply::refused(&HostRouteRefusal::StaleLog)
            .to_json()
            .to_string();
        assert_eq!(link.on_reply(&ok("host-1", head)), None, "one verdict");
        assert_eq!(link.on_reply(&refused), None, "one verdict");
        // A routed link answers no further challenge.
        assert_eq!(
            link.answer(&HostChallenge::new(ROOM).to_json().to_string()),
            None
        );
        // At an ancestor: routed.
        let mut other = LinkRoute::new(handle.clone(), ROOM, "atem-x");
        assert!(other.answer(&challenge).is_some());
        let ancestor = Head {
            seq: 2,
            hash: log.log.entry(2).unwrap().hash(),
        };
        assert!(matches!(
            other.on_reply(&ok("host-1", ancestor)),
            Some(RouteResult::Routed { .. })
        ));
        // A refusal for this link's proof carries the verifier's code.
        let mut refusing = LinkRoute::new(handle.clone(), ROOM, "atem-x");
        assert_eq!(refusing.on_reply(&refused), None, "no proof yet: ignored");
        assert!(refusing.answer(&challenge).is_some());
        assert_eq!(
            refusing.on_reply(&refused),
            Some(RouteResult::Refused("stale_log".into()))
        );
        // A device list that can't serve any more: an ok is ignored.
        let mut late = LinkRoute::new(handle.clone(), ROOM, "atem-x");
        assert!(late.answer(&challenge).is_some());
        set(&handle, RouteState::Off("device list held"));
        assert_eq!(late.on_reply(&ok("host-1", head)), None);
        // A late ok on a new link (the old one dropped): unsolicited there.
        let mut next = LinkRoute::new(ready(&log), ROOM, "atem-x");
        assert_eq!(next.on_reply(&ok("host-1", head)), None);
    }

    /// §R9.7b: `set` reports the host becoming able to answer challenges
    /// again (`Off` to `Ready`: pinned, reconciled), once per event; the
    /// first state after `Starting`, a new head while serving, and the
    /// same state again are no such event.
    #[test]
    fn set_reports_serving_again_once() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        let state = |log: &TestLog| ready(log).lock().unwrap().clone();
        let handle = new_handle();
        assert!(!set(&handle, state(&log)), "Starting to Ready");
        assert!(!set(&handle, RouteState::Off("device list held")));
        assert!(!set(&handle, RouteState::Off("device list held")));
        let serving = state(&log);
        assert!(set(&handle, serving.clone()), "reconciled");
        assert!(!set(&handle, serving), "the same state again");
        let starting = new_handle();
        assert!(!set(&starting, RouteState::Off("no device list")));
        assert!(set(&starting, state(&log)), "pinned");
        log.add_native("dev-phone", &["control", "view"]);
        assert!(!set(&starting, state(&log)), "a new head while serving");
    }

    /// M1: one challenge per link, never after the link was routed or
    /// Astation authenticated it; M2: an r8 host (no list, no proof) ignores
    /// an unsolicited refusal.
    #[test]
    fn one_challenge_per_link_and_no_verdict_without_a_proof() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        let challenge = || HostChallenge::new(ROOM).to_json().to_string();
        let mut link = LinkRoute::new(ready(&log), ROOM, "atem-x");
        assert!(link.answer(&challenge()).is_some());
        assert_eq!(link.answer(&challenge()), None, "a second challenge");
        // Astation authenticated the link first: no challenge answered.
        let mut authed = LinkRoute::new(ready(&log), ROOM, "atem-x");
        authed.authenticated_flag().store(true, Ordering::SeqCst);
        assert_eq!(authed.answer(&challenge()), None);
        // An r8 host: no list, so no proof; a refusal is not its verdict.
        let off = new_handle();
        set(&off, RouteState::Off("no device list"));
        let mut r8 = LinkRoute::new(off, ROOM, "atem-x");
        assert_eq!(r8.answer(&challenge()), None);
        let refused = RelayReply::refused(&HostRouteRefusal::UnknownHost)
            .to_json()
            .to_string();
        assert_eq!(r8.on_reply(&refused), None);
    }
}

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
//!
//! Astation's local link (`:8080`) carries the same challenge from the
//! selected Station, forwarded unchanged by Astation's proxy, so the Station
//! can tell which host calls it (the delegated host-work design I.5.8,
//! "Which host is calling"; `host.delegated` only, [`Carrier::Local`]). It
//! is answered through the same code, for the same room and `atem_id` as
//! the relay link, with a proof of the proxy kind (`atem-host-route-proxy`,
//! [`RouteKind::Proxy`]; proposed, for Astation's agreement), which no
//! relay verifier takes for a route: Atem doesn't authenticate its local
//! peer, so whoever holds the local link may get a proof for a nonce it
//! chose, and must not route a relay connection as this host with it. The
//! rules are a local link's: only while Astation has authenticated the link
//! (as the paired Astation), once per authenticated generation (a
//! re-authentication on the socket is a new one), and never again on the
//! socket once this host's identity changed on it (host-work-v1 §11.4, "An
//! identity change": retired by the bridge, or found by the route at a
//! challenge or an authentication). The link's client answers it in order
//! with Astation's messages, never the reader, so a challenge Astation
//! forwards right after its authentication reply is judged after that
//! reply; one that comes before is ignored with a line. Its verdict is
//! informational: a runtime.log line.
use super::HostKey;
use atem_client::encoding::Hash32;
use atem_client::host_route::{
    HostChallenge, HostRouteBody, RelayReply, RouteKind, host_route_message, sign_host_route_as,
};
use atem_client::membership::Head;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// runtime.log lines about challenges on one link (one socket) at most.
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

/// Which carrier a link's challenges come over (§R9.7b; the delegated
/// host-work design I.5.8, "Which host is calling").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// The relay identity link: the relay's challenge, answered by the
    /// link's reader as it arrives, before Astation authenticated the link,
    /// once per link.
    Relay,
    /// Astation's local link (`:8080`), which forwards the Station's
    /// challenge and its verdict unchanged (`host.delegated` only): its
    /// proof is the proxy kind.
    Local,
}

impl Carrier {
    /// The kind of proof the carrier gives: a local link's is the proxy
    /// kind, which no relay verifier takes for a route (proposed, for
    /// Astation's agreement), so whoever holds the host's local link can't
    /// route a relay connection as this host with it.
    pub fn kind(self) -> RouteKind {
        match self {
            Carrier::Relay => RouteKind::Relay,
            Carrier::Local => RouteKind::Proxy,
        }
    }
}

/// Who a proof speaks for: a [`RouteState::Ready`] without its head (the
/// host at a new head is the same host). A re-verify changes it (a new
/// `host_channel_key`), and so do a new account or genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteWho {
    account_id: String,
    genesis_hash: Hash32,
    host_id: String,
    /// The public half of `host_channel_key`.
    key: Option<atem_client::PublicKey>,
}

impl RouteWho {
    fn of(state: &RouteState) -> Option<RouteWho> {
        use atem_client::KeyProvider;
        let RouteState::Ready { id, key } = state else {
            return None;
        };
        Some(RouteWho {
            account_id: id.account_id.clone(),
            genesis_hash: id.genesis_hash,
            host_id: id.host_id.clone(),
            key: key.keys.public_key(&key.id).ok(),
        })
    }
}

/// A local link's authentication and identity ([`Carrier::Local`]).
#[derive(Debug, Default)]
struct LocalAuth {
    /// The authenticated generation now; 0 while Astation hasn't
    /// authenticated the link, or authenticates it again.
    generation: u64,
    /// The generations so far.
    generations: u64,
    /// The generation whose challenge was answered, and the one whose
    /// proof got its verdict.
    answered: Option<u64>,
    judged: Option<u64>,
    /// The route identity the link's socket is bound to: the host's at its
    /// first authentication, or at its first answer when the device list
    /// couldn't serve then.
    bound: Option<RouteWho>,
    /// This host's identity changed on the link's socket: nothing more is
    /// answered on it.
    retired: bool,
}

/// One link's challenge state: the room and `atem_id` it was opened with,
/// whether its one proof went out and the relay's verdict came, whether
/// Astation authenticated it, the lines written.
pub struct LinkRoute {
    handle: RouteHandle,
    carrier: Carrier,
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
    /// [`Carrier::Local`] only.
    local: LocalAuth,
    lines: u32,
}

impl LinkRoute {
    pub fn new(handle: RouteHandle, room: &str, atem_id: &str) -> Self {
        LinkRoute {
            handle,
            carrier: Carrier::Relay,
            room: room.to_owned(),
            atem_id: atem_id.to_owned(),
            proof_sent: false,
            verdict: false,
            authenticated: Arc::default(),
            proved: Arc::default(),
            routed_ok: Arc::default(),
            local: LocalAuth::default(),
            lines: 0,
        }
    }

    /// A local link's challenge state (Astation's `:8080`): `room` and
    /// `atem_id` are the relay link's (the relay room, the pairing's
    /// Astation id; this host's `atem_id`).
    pub fn local(handle: RouteHandle, room: &str, atem_id: &str) -> Self {
        LinkRoute {
            carrier: Carrier::Local,
            ..LinkRoute::new(handle, room, atem_id)
        }
    }

    /// A local link: Astation authenticated it (a connect, or a
    /// re-authentication on its socket): a new generation, which may answer
    /// one challenge. The socket's first authentication binds it to the
    /// host's route identity now (if the device list can serve).
    pub fn authenticated(&mut self) {
        let local = &mut self.local;
        local.generations += 1;
        local.generation = local.generations;
        // The socket's identity, checked at each authentication too: one
        // that moved while Astation authenticated the link again retires it
        // now, not at the next challenge.
        let state = self
            .handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.local_same_identity(&state);
    }

    /// A local link: Astation is authenticating it again; no challenge is
    /// answered until it did.
    pub fn unauthenticated(&mut self) {
        self.local.generation = 0;
    }

    /// A local link: this host's identity changed on its socket (the
    /// bridge's identity rules, host-work-v1 §11.4): nothing more is
    /// answered on it, whatever its authentication.
    pub fn retire(&mut self) {
        self.local.retired = true;
    }

    /// A local link: a challenge or verdict that came before (or while)
    /// Astation authenticated the link: never answered, never a verdict,
    /// one runtime.log line within the link's bound.
    pub fn ignore(&mut self, text: &str) {
        if is_host_challenge(text) {
            self.log("ignored: Astation hasn't authenticated this local link");
        } else {
            self.log_reply("ignored: Astation hasn't authenticated this local link");
        }
    }

    /// A local link: retired ([`LinkRoute::retire`], or a challenge under
    /// another route identity than the socket's).
    pub fn retired(&self) -> bool {
        self.local.retired
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

    /// The runtime.log lines written on this link so far (tests).
    #[cfg(test)]
    pub fn lines(&self) -> u32 {
        self.lines
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
        match self.carrier {
            // Only while Astation has authenticated it, once per
            // authentication, never once retired.
            Carrier::Local => {
                if !self.local_may_answer() {
                    return None;
                }
            }
            // One challenge per link, only before it is routed or
            // Astation-authenticated (a later one is no new connection).
            Carrier::Relay => {
                if self.verdict || self.authenticated.load(Ordering::SeqCst) {
                    self.log("ignored: the link is already routed or authenticated");
                    return None;
                }
                if self.proof_sent {
                    self.log("ignored: this link already answered a challenge");
                    return None;
                }
            }
        }
        let state = self
            .handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if self.carrier == Carrier::Local && !self.local_same_identity(&state) {
            return None;
        }
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
        match sign_host_route_as(self.carrier.kind(), &key.keys, &key.id, &body) {
            Ok(proof) => {
                self.proof_sent = true;
                self.local.answered = Some(self.local.generation);
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
    /// A local link answers a challenge only while Astation has
    /// authenticated it, once per authentication, never once retired
    /// (logged otherwise).
    fn local_may_answer(&mut self) -> bool {
        if self.local.retired {
            self.log("ignored: this host's identity changed on this link");
            return false;
        }
        let generation = self.local.generation;
        if generation == 0 {
            self.log("ignored: Astation hasn't authenticated this local link");
            return false;
        }
        if self.local.answered == Some(generation) {
            self.log("ignored: this authentication of the link already answered a challenge");
            return false;
        }
        true
    }

    /// Whether `state` is the route identity a local link's socket is bound
    /// to (binding it when it isn't bound yet: at the socket's first
    /// authentication or answer while the device list can serve); another
    /// one retires the link (logged once).
    fn local_same_identity(&mut self, state: &RouteState) -> bool {
        if self.local.retired {
            return false;
        }
        let Some(now) = RouteWho::of(state) else {
            return true;
        };
        match &self.local.bound {
            None => {
                self.local.bound = Some(now);
                true
            }
            Some(bound) if *bound == now => true,
            Some(_) => {
                self.local.retired = true;
                self.log("not answered: this host's identity changed on this link; nothing more is answered on it");
                false
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
        match self.carrier {
            // A local link: the proof of its current authentication's.
            Carrier::Local => {
                let generation = self.local.generation;
                if generation == 0 || self.local.answered != Some(generation) {
                    self.log_reply(&format!(
                        "{what} ignored: no proof was sent in this authentication of the local link"
                    ));
                    return None;
                }
                if self.local.judged == Some(generation) {
                    self.log_reply(&format!("{what} ignored: this proof already has a verdict"));
                    return None;
                }
            }
            Carrier::Relay => {
                if !self.proof_sent {
                    self.log_reply(&format!("{what} ignored: no proof was sent on this link"));
                    return None;
                }
                if self.verdict {
                    self.log_reply(&format!("{what} ignored: this link already has a verdict"));
                    return None;
                }
            }
        }
        let (host_id, head) = match reply {
            RelayReply::Refused { code } => {
                self.judged();
                if self.carrier == Carrier::Local {
                    self.log_reply(&format!(
                        "refused through Astation's local link: {code}; the link stays, and the Station refuses its calls"
                    ));
                } else {
                    self.log_reply(&format!("refused: {code}"));
                }
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
        self.judged();
        if self.carrier == Carrier::Local {
            // The Station's association for this link's calls: the link
            // stays Astation's, never routed.
            self.log_reply(&format!(
                "ok at head {} through Astation's local link",
                head.seq
            ));
        } else {
            self.routed_ok.store(true, Ordering::SeqCst);
            self.log_reply(&format!("ok at head {}", head.seq));
        }
        Some(RouteResult::Routed { host_id, head })
    }

    /// The verdict for this link's proof came (on a local link, for its
    /// current authentication's).
    fn judged(&mut self) {
        match self.carrier {
            Carrier::Relay => self.verdict = true,
            Carrier::Local => self.local.judged = Some(self.local.generation),
        }
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
        set(&handle, ready_with(log, "route host"));
        handle
    }

    /// `host-1` at `log`'s head, signing with `secret(seed)`.
    fn ready_with(log: &TestLog, seed: &str) -> RouteState {
        RouteState::Ready {
            id: RouteIdentity {
                account_id: "acct-1".into(),
                genesis_hash: log.log.genesis_hash(),
                host_id: "host-1".into(),
                head: log.log.head(),
                chain: Arc::new(log.log.entries().iter().map(|e| e.hash()).collect()),
            },
            key: Arc::new(HostKey::new(&secret(seed))),
        }
    }

    /// A local link's `answer` checked as a Station checks it: a proxy
    /// proof for `nonce`, [`ROOM`] and `atem-x` (the proxy kind's verifier),
    /// which the relay's verifier refuses (its type: a local link's proof is
    /// never a relay route, the H-P review's finding 1).
    fn proxy_verified(
        log: &TestLog,
        answer: &str,
        nonce: &[u8; 32],
    ) -> Result<atem_client::host_route::HostRoute, atem_client::host_route::HostRouteRefusal> {
        use atem_client::host_route::{
            RouteKind, verify_host_route_message, verify_host_route_message_as,
        };
        assert_eq!(
            verify_host_route_message(&log.log, answer.as_bytes(), nonce, ROOM, "atem-x"),
            Err(HostRouteRefusal::Malformed("type")),
            "never a relay route"
        );
        verify_host_route_message_as(
            RouteKind::Proxy,
            &log.log,
            answer.as_bytes(),
            nonce,
            ROOM,
            "atem-x",
        )
    }

    /// A fresh challenge for `room`, and its text.
    fn challenge_for(room: &str) -> (HostChallenge, String) {
        let challenge = HostChallenge::new(room);
        let text = challenge.to_json().to_string();
        (challenge, text)
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

    /// Through Astation's `:8080` proxy (design I.5.8; Atem's reading of
    /// R9.7b for a local link, `host.delegated` only): the Station's
    /// challenge is answered only while Astation has authenticated the
    /// link, only for the link's room (the relay room, as on the relay),
    /// once per authenticated generation, with the relay's proof (the
    /// shared verifier accepts it); a re-authentication on the socket is a
    /// new generation, which answers a fresh one.
    #[test]
    fn a_local_link_answers_once_per_authentication_for_its_room() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        let mut link = LinkRoute::local(ready(&log), ROOM, "atem-x");
        // Before Astation authenticated the link: ignored.
        let (_, text) = challenge_for(ROOM);
        assert_eq!(link.answer(&text), None, "before authentication");
        link.authenticated();
        // Another room than the link's: ignored.
        assert_eq!(link.answer(&challenge_for("another-room").1), None);
        // The link's room: the proof of the relay link's inputs, of the
        // proxy kind, for this challenge.
        let (challenge, text) = challenge_for(ROOM);
        let answer = link.answer(&text).expect("answered once authenticated");
        let route = proxy_verified(&log, &answer, &challenge.nonce).unwrap();
        assert_eq!(route.host_id, "host-1");
        assert_eq!(route.head, log.log.head());
        // A second challenge in the same authentication: ignored.
        assert_eq!(link.answer(&challenge_for(ROOM).1), None, "a second one");
        // Astation authenticating the link again: none while it runs, one
        // fresh one once it did.
        link.unauthenticated();
        assert_eq!(
            link.answer(&challenge_for(ROOM).1),
            None,
            "re-authenticating"
        );
        link.authenticated();
        let (fresh, text) = challenge_for(ROOM);
        let answer = link.answer(&text).expect("a fresh one");
        assert!(proxy_verified(&log, &answer, &fresh.nonce).is_ok());
        assert_eq!(link.answer(&challenge_for(ROOM).1), None);
        // A relay link's proof stays the relay kind.
        let mut relay = LinkRoute::new(ready(&log), ROOM, "atem-x");
        let (challenge, text) = challenge_for(ROOM);
        let answer = relay.answer(&text).unwrap();
        assert!(
            atem_client::host_route::verify_host_route_message(
                &log.log,
                answer.as_bytes(),
                &challenge.nonce,
                ROOM,
                "atem-x"
            )
            .is_ok()
        );
        // A device list that can't serve: no answer, as on the relay.
        let off = new_handle();
        set(&off, RouteState::Off("device list held"));
        let mut held = LinkRoute::local(off, ROOM, "atem-x");
        held.authenticated();
        assert_eq!(held.answer(&challenge_for(ROOM).1), None);
    }

    /// A verdict on a local link counts only for the proof of its current
    /// authentication, once: a refusal carries the verifier's code (the
    /// caller keeps the link), an ok is checked as on the relay and never
    /// makes the link routed.
    #[test]
    fn a_local_links_verdict_counts_only_for_its_authentications_proof() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        let head = log.log.head();
        let refused = RelayReply::refused(&HostRouteRefusal::StaleLog)
            .to_json()
            .to_string();
        let mut link = LinkRoute::local(ready(&log), ROOM, "atem-x");
        link.authenticated();
        // No proof yet: neither verdict is this link's.
        assert_eq!(link.on_reply(&ok("host-1", head)), None);
        assert_eq!(link.on_reply(&refused), None);
        assert!(link.answer(&challenge_for(ROOM).1).is_some());
        assert_eq!(
            link.on_reply(&refused),
            Some(RouteResult::Refused("stale_log".into()))
        );
        assert_eq!(link.on_reply(&refused), None, "one verdict");
        assert_eq!(link.on_reply(&ok("host-1", head)), None, "one verdict");
        // The next authentication: only its own proof's verdict.
        link.unauthenticated();
        link.authenticated();
        assert_eq!(
            link.on_reply(&ok("host-1", head)),
            None,
            "no proof in this authentication"
        );
        assert!(link.answer(&challenge_for(ROOM).1).is_some());
        assert_eq!(link.on_reply(&ok("host-2", head)), None, "another host");
        assert_eq!(
            link.on_reply(&ok("host-1", head)),
            Some(RouteResult::Routed {
                host_id: "host-1".into(),
                head
            })
        );
        assert!(
            !link.routed_ok_flag().load(Ordering::SeqCst),
            "a local link is never routed"
        );
    }

    /// host-work-v1 §11.4, "An identity change", on a local link: once this
    /// host's identity changed on the link's socket nothing more is answered
    /// on it, whatever its authentication: retired by the bridge (the
    /// identity rules), or found by the link itself, which is bound to the
    /// route identity of its first authentication (or of its first answer,
    /// when the device list wasn't open then): a challenge under another
    /// one (a re-verify's new `host_channel_key`) is refused and retires it.
    /// A new socket answers under the new identity.
    #[test]
    fn a_local_link_answers_nothing_once_the_hosts_identity_changed() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        // Retired by the bridge.
        let handle = ready(&log);
        let mut link = LinkRoute::local(handle.clone(), ROOM, "atem-x");
        link.authenticated();
        assert!(!link.retired());
        link.retire();
        assert!(link.retired());
        assert_eq!(link.answer(&challenge_for(ROOM).1), None);
        link.unauthenticated();
        link.authenticated();
        assert_eq!(
            link.answer(&challenge_for(ROOM).1),
            None,
            "a later authentication"
        );
        // Bound at its authentication: a re-verify before its first challenge.
        let mut link = LinkRoute::local(handle.clone(), ROOM, "atem-x");
        link.authenticated();
        log.add_host("host-1", 2, &secret("route host 2"));
        set(&handle, ready_with(&log, "route host 2"));
        assert_eq!(
            link.answer(&challenge_for(ROOM).1),
            None,
            "another identity"
        );
        assert!(link.retired());
        // A new socket answers under the new identity.
        let mut fresh = LinkRoute::local(handle.clone(), ROOM, "atem-x");
        fresh.authenticated();
        let (challenge, text) = challenge_for(ROOM);
        let answer = fresh.answer(&text).expect("the new identity's");
        assert!(proxy_verified(&log, &answer, &challenge.nonce).is_ok());
        // The list opened after the authentication: bound at the first answer.
        let starting = new_handle();
        let mut late = LinkRoute::local(starting.clone(), ROOM, "atem-x");
        late.authenticated();
        set(&starting, ready_with(&log, "route host 2"));
        assert!(late.answer(&challenge_for(ROOM).1).is_some());
        late.unauthenticated();
        late.authenticated();
        log.add_host("host-1", 3, &secret("route host 3"));
        set(&starting, ready_with(&log, "route host 3"));
        assert_eq!(late.answer(&challenge_for(ROOM).1), None);
        assert!(late.retired());
        // The same identity read again (the list reopened, a new head): the
        // same link answers in its next authentication.
        let same = new_handle();
        set(&same, ready_with(&log, "route host 3"));
        let mut kept = LinkRoute::local(same.clone(), ROOM, "atem-x");
        kept.authenticated();
        assert!(kept.answer(&challenge_for(ROOM).1).is_some());
        log.add_native("dev-phone", &["control", "view"]);
        set(&same, ready_with(&log, "route host 3"));
        kept.unauthenticated();
        kept.authenticated();
        assert!(
            kept.answer(&challenge_for(ROOM).1).is_some(),
            "a new head, the same identity"
        );
        assert!(!kept.retired());
    }

    /// The route's identity is checked at each authentication too, not only
    /// at a challenge: a re-verify that lands while Astation authenticates
    /// the link again retires it at once (so the bridge reconnects it with
    /// no challenge needed).
    #[test]
    fn a_local_link_checks_its_identity_at_each_authentication() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        let handle = ready(&log);
        let mut link = LinkRoute::local(handle.clone(), ROOM, "atem-x");
        link.authenticated();
        link.unauthenticated();
        log.add_host("host-1", 2, &secret("route host 2"));
        set(&handle, ready_with(&log, "route host 2"));
        link.authenticated();
        assert!(link.retired(), "retired at the authentication");
        assert_eq!(link.answer(&challenge_for(ROOM).1), None);
        // The same identity again (a new head): not retired.
        let mut kept = LinkRoute::local(handle.clone(), ROOM, "atem-x");
        kept.authenticated();
        kept.unauthenticated();
        log.add_native("dev-phone", &["control", "view"]);
        set(&handle, ready_with(&log, "route host 2"));
        kept.authenticated();
        assert!(!kept.retired());
    }

    /// A challenge or verdict that reaches a local link before (or while)
    /// Astation authenticates it is ignored with a runtime.log line
    /// (`ignore`, never an answer), within the link's bound: per socket,
    /// never reset by a re-authentication.
    #[test]
    fn a_local_links_early_messages_are_logged_within_one_bound_per_socket() {
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        let mut link = LinkRoute::local(ready(&log), ROOM, "atem-x");
        link.ignore(&challenge_for(ROOM).1);
        assert_eq!(link.lines, 1, "an early challenge logged");
        let refused = RelayReply::refused(&HostRouteRefusal::StaleLog)
            .to_json()
            .to_string();
        link.ignore(&refused);
        assert_eq!(link.lines, 2, "an early verdict logged");
        link.authenticated();
        // Even authenticated, `ignore` never answers.
        link.ignore(&challenge_for(ROOM).1);
        assert!(
            link.answer(&challenge_for(ROOM).1).is_some(),
            "still unanswered"
        );
        for _ in 0..20 {
            link.unauthenticated();
            link.ignore(&challenge_for(ROOM).1);
            link.authenticated();
            link.answer(&challenge_for(ROOM).1);
        }
        assert_eq!(link.lines, MAX_LINES_PER_LINK, "one bound for the socket");
    }
}

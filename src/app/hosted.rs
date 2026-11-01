//! The App inside `atem runtime`: it holds the Astation connection, but the
//! sessions are the broker's (each in an `atem worker`) and the session
//! host is the broker's (src/runtime/host_bridge.rs). The broker mirrors its
//! sessions here each tick for mark tasks, takes the session-family messages
//! the App received (`inbox`) and writes the mark-task prompts it queued
//! (`writes`).
//!
//! The TUI without a runtime (bare `atem`) opens no Astation connection at
//! all, so it never sees a session-family message.
use super::App;
use crate::runtime::refusal_log;
use crate::session::{Provider, SessionId};
use crate::session_protocol::wire::{self, Envelope, ErrorCode, Op, SessionMessage};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Instant;

/// Messages kept for the session host per pass, at most.
pub const INBOX_LIMIT: usize = 1024;
/// A relay message larger than this is dropped and counted in runtime.log
/// (§R9.9: a relay message to Atem is at most 256 KiB, the `push_hint`
/// bound; the relay splits a larger `push_ack`, about 337 bytes an
/// identity).
pub const RELAY_MESSAGE_BYTES: usize = 256 * 1024;
/// Relay messages kept for the broker per pass, at most (the rest are
/// dropped: what they acknowledged is resent and acknowledged again).
pub const RELAY_LIMIT: usize = 64;
/// r9 channel envelopes kept for the broker per pass, at most (bytes; each
/// is at most 2 MiB, §R9.7a). Beyond it the envelope's channel is closed
/// (`busy`), never silently short of a frame.
pub const CHANNEL_INBOX_BYTES: usize = 32 << 20;
/// The route reconnect (§R9.7b) waits this long at most for the link's
/// unwritten channel envelopes to go out.
pub const ROUTE_RECONNECT_FLUSH: std::time::Duration = std::time::Duration::from_secs(5);
/// The route reconnect (§R9.7b) waits this long at most for r9 channels
/// mid-admission (a client that keeps opening channels can't hold it off).
pub const ROUTE_RECONNECT_ADMISSION: std::time::Duration = std::time::Duration::from_secs(30);

/// One broker session as mark tasks see it.
#[derive(Debug, Clone)]
pub struct HostedSession {
    pub id: SessionId,
    pub provider: Provider,
    pub cwd: PathBuf,
    /// The agent runs in a connected worker.
    pub live: bool,
    /// A remote lease holder exists.
    pub remote_controlled: bool,
    pub last_used: Instant,
}

#[derive(Debug, Default)]
pub struct Hosted {
    /// Session-family messages from the authenticated link, with the link
    /// generation they arrived on (raw JSON, decoded strictly by the host).
    pub inbox: VecDeque<(u64, String)>,
    pub sessions: Vec<HostedSession>,
    /// Mark-task prompts to write: (task id, session, text).
    pub writes: Vec<(String, SessionId, String)>,
    /// Refusals answered here (oversize, a full inbox): (link generation,
    /// runtime.log line), written by the broker under its rate limit.
    pub refused: Vec<(u64, String)>,
    /// r9 channel envelopes from the link (§R9.7a), with the link
    /// generation they arrived on, in order.
    pub channels: VecDeque<(u64, String)>,
    /// Their bytes.
    pub channel_bytes: usize,
    /// Channels whose envelope was refused unread: (link generation,
    /// handle, close reason): `busy` when it didn't fit the inbox,
    /// `too_large` over the envelope bound.
    pub channel_overflow: Vec<(u64, String, &'static str)>,
    /// Relay messages from the link (§R9.9: `push_ack`), with the link
    /// generation they arrived on, in order (at most `RELAY_LIMIT`).
    pub relay: VecDeque<(u64, String)>,
    /// Relay messages dropped (over a bound), for runtime.log.
    pub relay_dropped: u64,
}

impl Hosted {
    pub fn session(&self, id: &SessionId) -> Option<&HostedSession> {
        self.sessions.iter().find(|s| &s.id == id)
    }

    /// The live Claude session whose directory has the task (most recently used first).
    pub fn mark_task_session(&self, task_id: &str) -> Option<SessionId> {
        let mut sessions: Vec<&HostedSession> = self
            .sessions
            .iter()
            .filter(|s| s.provider == Provider::Claude && s.live)
            .collect();
        sessions.sort_by_key(|s| std::cmp::Reverse(s.last_used));
        sessions
            .into_iter()
            .find(|s| App::mark_task_path(&s.cwd, task_id).is_some_and(|p| p.is_file()))
            .map(|s| s.id.clone())
    }
}

impl App {
    /// A `session`, `terminal` or `agentChat` message from Astation: for the
    /// broker's session host while the link is authenticated, else refused.
    pub(super) fn session_wire(&mut self, text: String) {
        // Only on an authenticated, open link (cleared while re-authenticating).
        if !self.astation_connected || self.astation_client.is_ws_closed() {
            return;
        }
        let link = self.astation_link_gen;
        // Only `atem runtime` has a link (bare `atem` opens none).
        let Some(hosted) = self.hosted.as_mut() else {
            return;
        };
        if hosted.inbox.len() < INBOX_LIMIT {
            hosted.inbox.push_back((link, text));
            return;
        }
        let decoded = wire::decode(text.as_bytes());
        let request = refusal_log::Request::of(&decoded, &text);
        let line = refusal_log::line(&request, "busy", Some("inbox full"));
        if hosted.refused.len() < INBOX_LIMIT {
            hosted.refused.push((link, line));
        }
        let re = match decoded {
            Ok(Envelope::Session(m)) => Some(m.id),
            Ok(Envelope::Family(_)) => None,
            Err(e) => e.id,
        };
        // The host's inbox is full: `busy` (the client may retry).
        self.session_refusal(re, ErrorCode::Busy, None);
    }

    /// An r9 channel envelope for the broker's r9 host (§R9.7a), while the
    /// link is authenticated.
    pub(super) fn channel_envelope(&mut self, text: String) {
        if !self.r9_link_up() {
            return;
        }
        let link = self.astation_link_gen;
        let Some(hosted) = self.hosted.as_mut() else {
            return;
        };
        if hosted.channel_bytes + text.len() <= CHANNEL_INBOX_BYTES {
            hosted.channel_bytes += text.len();
            hosted.channels.push_back((link, text));
            return;
        }
        #[derive(serde::Deserialize)]
        struct Peek {
            channel: Option<String>,
        }
        if let Some(handle) = serde_json::from_str::<Peek>(&text)
            .ok()
            .and_then(|p| p.channel)
            .filter(|h| crate::session_protocol::r9::envelope::is_handle(h))
            && hosted.channel_overflow.len() < INBOX_LIMIT
        {
            hosted.channel_overflow.push((
                link,
                handle,
                crate::session_protocol::r9::envelope::reason::BUSY,
            ));
        }
    }

    /// A relay message (`push_ack`) for the broker's r9 push, while the
    /// link is authenticated; beyond the bound it is dropped (what it
    /// acknowledged is resent and acknowledged again).
    pub(super) fn relay_message(&mut self, text: String) {
        if !self.r9_link_up() {
            return;
        }
        let link = self.astation_link_gen;
        let Some(hosted) = self.hosted.as_mut() else {
            return;
        };
        if hosted.relay.len() < RELAY_LIMIT && text.len() <= RELAY_MESSAGE_BYTES {
            hosted.relay.push_back((link, text));
            return;
        }
        // Counted, never its content; rate-limited to powers of two.
        hosted.relay_dropped += 1;
        if hosted.relay_dropped.is_power_of_two() {
            eprintln!(
                "atem runtime: r9: {} relay message(s) dropped (over {} KiB or {} a pass; the last {} bytes)",
                hosted.relay_dropped,
                RELAY_MESSAGE_BYTES / 1024,
                RELAY_LIMIT,
                text.len()
            );
        }
    }

    /// An r9 channel envelope refused unread (over its bound): its channel
    /// is closed with `why` by the broker.
    pub(super) fn channel_refused(&mut self, handle: String, why: &'static str) {
        if !self.r9_link_up() {
            return;
        }
        let link = self.astation_link_gen;
        if let Some(hosted) = self.hosted.as_mut()
            && hosted.channel_overflow.len() < INBOX_LIMIT
        {
            hosted.channel_overflow.push((link, handle, why));
        }
    }

    /// A session-family message over the size bound: dropped unread and
    /// refused (`unsupported_version`), with a runtime.log line.
    pub(super) fn session_oversize(&mut self, id: Option<String>, family: &str) {
        if self.astation_connected && !self.astation_client.is_ws_closed() {
            let link = self.astation_link_gen;
            if let Some(hosted) = self.hosted.as_mut()
                && hosted.refused.len() < INBOX_LIMIT
            {
                let request = refusal_log::Request::family_only(family);
                let line = refusal_log::line(&request, "unsupported_version", Some("oversize"));
                hosted.refused.push((link, line));
            }
        }
        self.session_refusal(id, ErrorCode::UnsupportedVersion, None);
    }

    /// A session `error` with `code` (answering `re`) on an authenticated link.
    pub(super) fn session_refusal(
        &mut self,
        re: Option<String>,
        code: ErrorCode,
        detail: Option<&str>,
    ) {
        if !self.astation_connected || self.astation_client.is_ws_closed() {
            return;
        }
        let _ = self
            .astation_client
            .try_send_wire(error_detail_text(re, code, detail), false);
    }

    /// The link carries r9 traffic: authenticated by Astation, or routed
    /// for r9 only on a host route proof (§R9.7b); open either way.
    pub(crate) fn r9_link_up(&self) -> bool {
        (self.astation_connected || self.astation_routed) && !self.astation_client.is_ws_closed()
    }

    /// §R9.7b, after a device list was pinned or a held one reconciled
    /// (`route_reconnect`): once nothing is in flight (no Astation
    /// operation (`op_running`), no connect or re-authentication, no
    /// session-family message waiting for admission, for up to
    /// [`ROUTE_RECONNECT_ADMISSION`] no r9 channel mid-admission
    /// (`admitting`), and for up to [`ROUTE_RECONNECT_FLUSH`] no channel
    /// envelope still unwritten, e.g. the welcome of the channel that
    /// reconciled the list), a relay link that proved no route (it answered
    /// no challenge then, or it is an operation's link, which never does)
    /// is dropped and reconnected at once, so the new link answers the
    /// relay's challenge and is routed. Only while the host can still
    /// answer one (else the event is dropped, logged). Once per event: a
    /// local link, a link that already proved, or no link at all (the next
    /// connect proves) ends it too.
    pub fn route_reconnect_due(&mut self, op_running: bool, admitting: bool) -> bool {
        let Some(since) = self.route_reconnect else {
            return false;
        };
        let waiting = self.hosted.as_ref().is_some_and(|h| {
            !h.inbox.is_empty() || !h.channels.is_empty() || !h.channel_overflow.is_empty()
        });
        let unwritten =
            self.astation_client.channel_unwritten() > 0 && since.elapsed() < ROUTE_RECONNECT_FLUSH;
        let admitting_now = admitting && since.elapsed() < ROUTE_RECONNECT_ADMISSION;
        if op_running
            || self.op_route.is_some()
            || self.astation_connect_rx.is_some()
            || self.astation_reauth.is_some()
            || waiting
            || unwritten
            || admitting_now
        {
            return false;
        }
        self.route_reconnect = None;
        if !self.r9_link_up() || !self.astation_client.route_unproved() {
            return false;
        }
        let ready = matches!(
            *self.host_route.lock().unwrap_or_else(|e| e.into_inner()),
            crate::session_protocol::r9::route::RouteState::Ready { .. }
        );
        if !ready {
            eprintln!(
                "atem runtime: r9: relay link not reconnected: the host can't answer a challenge now"
            );
            return false;
        }
        if admitting {
            eprintln!("atem runtime: r9: channels still opening after 30 s; reconnecting anyway");
        }
        eprintln!("atem runtime: r9: relay link reconnecting to prove its route");
        self.drop_astation_link("The relay link reconnects to prove its route".into());
        true
    }

    /// Drops the Astation link (closing its socket) and schedules the
    /// normal reconnect, which authenticates it again.
    pub fn drop_astation_link(&mut self, reason: String) {
        let was_connected = self.astation_connected;
        let was_routed = self.astation_routed;
        self.astation_connected = false;
        self.astation_routed = false;
        // A routed link was never Astation's: its drop starts no grace.
        if was_connected {
            self.on_astation_disconnect();
        }
        self.astation_client = crate::websocket_client::AstationClient::new();
        self.rebuild_menu();
        self.status_message = Some(reason);
        self.astation_reconnect_at = Some(if was_routed && !was_connected {
            self.routed_retry_at()
        } else {
            Instant::now()
        });
    }

    /// The broker could not write a mark task's prompt: the task fails.
    pub async fn mark_write_failed(&mut self, task_id: &str, error: &str) {
        self.main_task_session = None;
        let _ = self
            .astation_client
            .send_mark_result(task_id, false, error)
            .await;
        self.dispatcher.complete_main();
        self.work_items.remove(task_id);
    }
}

/// The answer to a session-family message when no session host serves it
/// (the runtime's journal could not be opened).
pub fn refusal(re: Option<String>) -> String {
    error_text(re, ErrorCode::UnsupportedVersion)
}

/// The detail of the refusal of an op removed in atem-session r6.
pub const REMOVED_OP: &str = "removed in atem-session r6";

/// The detail of the refusal of a plaintext relay-only message (§R9.8a).
pub const REMOVED_POLICY_OP: &str = "removed: relay only is set inside an r9 channel (host_policy_set)";

/// A session `error{code}` answering `re`.
pub fn error_text(re: Option<String>, code: ErrorCode) -> String {
    error_detail_text(re, code, None)
}

/// A session `error{code, detail}` answering `re`.
pub fn error_detail_text(re: Option<String>, code: ErrorCode, detail: Option<&str>) -> String {
    let message = Envelope::Session(SessionMessage {
        id: uuid::Uuid::new_v4().to_string(),
        re,
        op: Op::Error {
            code,
            detail: detail.map(str::to_string),
            revision: None,
            controller: None,
        },
    });
    String::from_utf8(wire::encode(&message)).expect("wire JSON is UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §R9.7b: the reconnect after a pin waits for a running operation (or
    /// a session-family message waiting for admission); with no relay link
    /// that proved no route (none at all here) the event ends unused.
    #[test]
    fn the_route_reconnect_waits_and_happens_once_per_event() {
        let _profile = crate::test_profile::temp();
        let mut app = App::new();
        app.hosted = Some(Hosted::default());
        assert!(!app.route_reconnect_due(false, false), "no event");
        app.route_reconnect = Some(Instant::now());
        assert!(!app.route_reconnect_due(true, false));
        assert!(
            app.route_reconnect.is_some(),
            "kept while an operation runs"
        );
        app.hosted
            .as_mut()
            .unwrap()
            .inbox
            .push_back((1, "{}".into()));
        assert!(!app.route_reconnect_due(false, false));
        assert!(app.route_reconnect.is_some(), "kept while a request waits");
        app.hosted.as_mut().unwrap().inbox.clear();
        assert!(
            !app.route_reconnect_due(false, false),
            "no link to reconnect"
        );
        assert!(app.route_reconnect.is_none(), "consumed");
        assert!(app.astation_reconnect_at.is_none());
    }

    /// §R9.7b review: an operation's relay link (no challenge state) counts
    /// as unproved; the reconnect fires only while the host can still
    /// answer a challenge (else the event is dropped); a channel still
    /// opening holds it for at most 30 s.
    #[test]
    fn the_route_reconnect_rechecks_the_route_and_caps_admission() {
        use crate::session_protocol::membership::r9log::{TestLog, secret};
        use crate::session_protocol::r9::route::{self, RouteIdentity, RouteState};
        use std::time::Duration;
        let _profile = crate::test_profile::temp();
        let mut log = TestLog::genesis("acct-1", &secret("route astation"));
        log.add_host("host-1", 1, &secret("route host"));
        let ready = RouteState::Ready {
            id: RouteIdentity {
                account_id: "acct-1".into(),
                genesis_hash: log.log.genesis_hash(),
                host_id: "host-1".into(),
                head: log.log.head(),
                chain: std::sync::Arc::new(log.log.entries().iter().map(|e| e.hash()).collect()),
            },
            key: std::sync::Arc::new(crate::session_protocol::r9::HostKey::new(&secret(
                "route host",
            ))),
        };
        let linked = || {
            let mut app = App::new();
            app.hosted = Some(Hosted::default());
            app.astation_client.relay_link_for_test();
            app.astation_connected = true;
            app
        };
        // Held again before it fired: dropped, the link stays.
        let mut app = linked();
        route::set(&app.host_route, RouteState::Off("device list held"));
        app.route_reconnect = Some(Instant::now());
        assert!(!app.route_reconnect_due(false, false));
        assert!(app.route_reconnect.is_none() && app.astation_connected);
        // Serving: an operation's relay link reconnects; a channel opening
        // holds it, at most 30 s.
        let mut app = linked();
        route::set(&app.host_route, ready.clone());
        app.route_reconnect = Some(Instant::now());
        assert!(!app.route_reconnect_due(false, true));
        assert!(app.route_reconnect.is_some(), "waits for the channel");
        app.route_reconnect = Instant::now().checked_sub(Duration::from_secs(31));
        assert!(app.route_reconnect_due(false, true), "capped");
        assert!(!app.astation_connected);
        assert!(app.astation_reconnect_at.is_some());
    }
}

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
        if !self.astation_connected || self.astation_client.is_ws_closed() {
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
        if !self.astation_connected || self.astation_client.is_ws_closed() {
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
        if !self.astation_connected || self.astation_client.is_ws_closed() {
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

    /// Drops the Astation link (closing its socket) and schedules the
    /// normal reconnect, which authenticates it again.
    pub fn drop_astation_link(&mut self, reason: String) {
        self.astation_connected = false;
        self.on_astation_disconnect();
        self.astation_client = crate::websocket_client::AstationClient::new();
        self.rebuild_menu();
        self.status_message = Some(reason);
        self.astation_reconnect_at = Some(Instant::now());
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

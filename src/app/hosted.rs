//! The App inside `atem runtime`: it holds the Astation connection, but the
//! sessions are the broker's (each in an `atem worker`) and the session
//! host is the broker's (src/runtime/host_bridge.rs). The broker mirrors its
//! sessions here each tick for mark tasks, takes the session-family messages
//! the App received (`inbox`) and writes the mark-task prompts it queued
//! (`writes`).
//!
//! The TUI without a runtime has no session host: it refuses every remote
//! `session`, `terminal` and `agentChat` message (`error` with
//! `unsupported_version`, as before `welcome`) and changes nothing.
use super::App;
use crate::session::{Provider, SessionId};
use crate::session_protocol::wire::{self, Envelope, ErrorCode, Op, SessionMessage};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Instant;

/// Messages kept for the session host per pass, at most.
const INBOX_LIMIT: usize = 1024;

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
        if let Some(hosted) = self.hosted.as_mut() {
            if hosted.inbox.len() < INBOX_LIMIT {
                hosted.inbox.push_back((link, text));
            }
            return;
        }
        let re = match wire::decode(text.as_bytes()) {
            Ok(Envelope::Session(m)) => Some(m.id),
            Ok(Envelope::Family(_)) => None,
            Err(e) => e.id,
        };
        let _ = self.astation_client.try_send_wire(refusal(re), false);
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

/// The TUI's answer to a session-family message: it serves no sessions.
pub fn refusal(re: Option<String>) -> String {
    let message = Envelope::Session(SessionMessage {
        id: uuid::Uuid::new_v4().to_string(),
        re,
        op: Op::Error {
            code: ErrorCode::UnsupportedVersion,
            detail: Some("sessions are served by atem runtime".into()),
        },
    });
    String::from_utf8(wire::encode(&message)).expect("wire JSON is UTF-8")
}

//! Chat state for the Claude sessions the TUI itself runs (bare `atem`
//! without a runtime): the adapter's events and log keep a `ChatSession`
//! and the local agent registry's status current. Remote chat-v1 is served
//! only by `atem runtime`'s session host (src/runtime/host_bridge.rs); the
//! TUI refuses it. v1 has one adapter, Claude Code.

use super::App;
use crate::agent_client::AgentStatus;
use crate::chat::adapter::{AgentAdapter, AgentEvent, LogItem};
use crate::chat::claude::hooks;
use crate::chat::session::{ChatSession, State};
use crate::session::SessionId;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const CHAT_V1: &str = "chat-v1";

/// Chat for one agent process. A respawn gets a new one (new generation); the
/// adapter is dropped when the process ends, which removes its directory.
pub struct AgentChat {
    pub agent_id: String,
    /// `None` once the agent process has exited.
    pub adapter: Option<Box<dyn AgentAdapter>>,
    pub session: ChatSession,
    /// chat-v1 as of the last poll (what the local registry shows).
    chat_v1: bool,
    /// The adapter's "not available" reason was shown as a notice.
    reason_noticed: bool,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn registry_status(state: State) -> AgentStatus {
    match state {
        State::Ready => AgentStatus::Idle,
        State::Working => AgentStatus::Thinking,
        State::Waiting => AgentStatus::WaitingForInput,
        State::Unknown => AgentStatus::Unknown,
    }
}

impl App {
    /// Prepares chat for the Claude process about to be spawned: the chat for
    /// its session and the arguments to put first on its command line. On
    /// failure Claude starts without chat (`None`, no arguments).
    pub(crate) fn prepare_claude_chat(
        &mut self,
        agent_id: &str,
        args: &[String],
    ) -> (Option<AgentChat>, Vec<String>) {
        if !self.chat_swept {
            // Directories of Atem processes that died without cleaning up.
            self.chat_swept = true;
            hooks::sweep_stale(&self.chat_root);
        }
        match crate::chat::claude::prepare_chat(&self.chat_root, args) {
            Ok((adapter, extra_args)) => {
                let chat = AgentChat {
                    agent_id: agent_id.to_string(),
                    adapter: Some(Box::new(adapter)),
                    session: ChatSession::new(uuid::Uuid::new_v4().to_string(), now_ms()),
                    chat_v1: false,
                    reason_noticed: false,
                };
                (Some(chat), extra_args)
            }
            Err(error) => {
                crate::diagnostics::warn(format!("Chat is off for Claude: {error}"));
                (None, Vec::new())
            }
        }
    }

    /// Each tick: read every agent's events and log into its chat session and
    /// keep the local registry's status in step.
    pub fn poll_chat(&mut self) {
        for id in self.sessions.ids() {
            self.poll_session_chat(&id);
        }
    }

    fn poll_session_chat(&mut self, id: &SessionId) {
        let Some(session) = self.sessions.get_mut(id) else {
            return;
        };
        let input_count = session.input.as_ref().map_or(0, |s| s.input_count());
        // The PTY receiver is dropped when the process exits (finalize_session).
        let exited = session.events.is_none();
        let Some(chat) = session.chat.as_mut() else {
            return;
        };
        let mut notice = None;
        if let Some(adapter) = chat.adapter.as_mut() {
            let now = now_ms();
            // Events first (SessionStarted opens the log), then the log, then turn
            // ends, so a turn completes after its content.
            let mut ended = Vec::new();
            for event in adapter.poll_events() {
                if matches!(event, AgentEvent::TurnEnded) {
                    ended.push(event);
                } else {
                    chat.session.on_event(event, now, input_count);
                }
            }
            for item in adapter.poll_log() {
                if let LogItem::Problem { detail, fatal } = &item {
                    // Fatal problems withdraw chat through capabilities() below.
                    if !fatal {
                        notice.get_or_insert_with(|| detail.clone());
                    }
                    continue;
                }
                chat.session.on_log(item, now, input_count);
            }
            for event in ended {
                chat.session.on_event(event, now, input_count);
            }
        }
        if exited && chat.adapter.is_some() {
            chat.session.on_process_exit(now_ms());
            chat.adapter = None;
        }
        chat.session.tick(Instant::now());

        let caps = chat
            .adapter
            .as_ref()
            .map(|a| a.capabilities())
            .unwrap_or_default();
        if let Some(reason) = &caps.reason
            && !chat.reason_noticed
        {
            chat.reason_noticed = true;
            crate::diagnostics::warn(format!("Chat is off for Claude: {reason}"));
        }
        chat.chat_v1 = caps.chat_v1;
        if let Some(detail) = notice {
            crate::diagnostics::warn(format!("Chat: {detail}"));
        }
        self.sync_chat_registry(id);
    }

    /// The local registry's status and capabilities from the chat.
    fn sync_chat_registry(&mut self, id: &SessionId) {
        let Some(chat) = self.sessions.get(id).and_then(|s| s.chat.as_ref()) else {
            return;
        };
        let (status, capabilities) = if chat.chat_v1 {
            (
                registry_status(chat.session.status().state),
                vec![CHAT_V1.to_string()],
            )
        } else {
            (AgentStatus::Unknown, Vec::new())
        };
        let Some(mut info) = self.agent_registry.get(&chat.agent_id) else {
            return;
        };
        if info.status == status && info.capabilities == capabilities {
            return;
        }
        info.status = status;
        info.capabilities = capabilities;
        self.agent_registry.register(info);
    }
}

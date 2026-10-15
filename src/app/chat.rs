//! chat-v1 host: per-agent chat state wired to the PTY, the agent registry and
//! Astation (see designs/agent-chat-host.md). v1 has one adapter, Claude Code.

use super::App;
use crate::agent_client::AgentStatus;
use crate::chat::adapter::{AgentAdapter, AgentEvent, LogItem};
use crate::chat::claude::{ClaudeAdapter, hooks};
use crate::chat::session::{ChatSession, Out, State};
use crate::chat::wire::{self, ChatEnvelope, Inbound};
use crate::websocket_client::AstationMessage;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HEARTBEAT: Duration = Duration::from_secs(15);
const HISTORY_MESSAGES: usize = 50;
const HISTORY_BYTES: usize = 256 * 1024;
const NOT_AVAILABLE: &str = "chat is not available for this agent";
/// Sent instead of the OS error, which stays local.
const PASTE_FAILED: &str = "could not write to the terminal";
const RESTARTED: &str = "the agent was restarted; reopen the chat";
const SWITCHED: &str = "the conversation was switched; reopen the chat";
/// Open conversations per agent; opening one more closes the oldest.
const MAX_CONVERSATIONS: usize = 8;
pub const CHAT_V1: &str = "chat-v1";

/// Chat for one agent process. A respawn gets a new one (new generation); the
/// adapter is dropped when the process ends, which removes its directory.
pub struct AgentChat {
    pub agent_id: String,
    /// `None` once the agent process has exited.
    pub adapter: Option<Box<dyn AgentAdapter>>,
    pub session: ChatSession,
    /// Open conversations by conversationId.
    pub conversations: HashMap<String, Conversation>,
    /// Counter for `Conversation::opened` (newest open has the largest).
    opens: u64,
    /// chat-v1 as of the last poll (what the registry advertises).
    chat_v1: bool,
    /// The adapter's "not available" reason was shown as a notice.
    reason_noticed: bool,
}

/// One open conversation (one client page).
pub struct Conversation {
    /// Sequence of the next event.
    pub next: u64,
    /// The last time this conversation got the status (opened or heartbeat).
    pub last_heartbeat: Instant,
    /// Order of the last open, to close the oldest past `MAX_CONVERSATIONS`.
    opened: u64,
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

fn not_available(reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{NOT_AVAILABLE}: {reason}"),
        None => NOT_AVAILABLE.to_string(),
    }
}

impl AgentChat {
    /// Number `outs` for one conversation (its own sequence).
    fn for_conversation(&mut self, conversation: &str, outs: &[Out]) -> Vec<ChatEnvelope> {
        let Some(c) = self.conversations.get_mut(conversation) else {
            return Vec::new();
        };
        let generation = self.session.generation();
        outs.iter()
            .map(|out| {
                let env = wire::event(conversation, &self.agent_id, generation, c.next, out);
                c.next += 1;
                env
            })
            .collect()
    }

    /// Tell every open conversation why it ends (`error`, then `close`) and drop them.
    fn end_conversations(&mut self, text: &str) -> Vec<ChatEnvelope> {
        let error = [Out::Error {
            text: text.to_string(),
            request_id: None,
        }];
        let ids: Vec<String> = self.conversations.keys().cloned().collect();
        let mut envelopes = Vec::new();
        for id in &ids {
            envelopes.extend(self.for_conversation(id, &error));
            envelopes.push(wire::close(id, &self.agent_id));
        }
        self.conversations.clear();
        envelopes
    }

    /// Re-send the status to each conversation that has not had it for 15 s.
    fn heartbeats(&mut self) -> Vec<ChatEnvelope> {
        let due: Vec<String> = self
            .conversations
            .iter()
            .filter(|(_, c)| c.last_heartbeat.elapsed() >= HEARTBEAT)
            .map(|(id, _)| id.clone())
            .collect();
        let status = [self.session.heartbeat()];
        let mut envelopes = Vec::new();
        for id in due {
            envelopes.extend(self.for_conversation(&id, &status));
            if let Some(c) = self.conversations.get_mut(&id) {
                c.last_heartbeat = Instant::now();
            }
        }
        envelopes
    }

    /// Record an open (or reopen) of `id`, whose history ends at `next - 1`.
    /// A new conversation past `MAX_CONVERSATIONS` closes the oldest one; its
    /// `close` is returned.
    fn open_conversation(&mut self, id: String, next: u64) -> Vec<ChatEnvelope> {
        let mut envelopes = Vec::new();
        if !self.conversations.contains_key(&id) && self.conversations.len() >= MAX_CONVERSATIONS {
            let oldest = self
                .conversations
                .iter()
                .min_by_key(|(_, c)| c.opened)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                self.conversations.remove(&oldest);
                envelopes.push(wire::close(&oldest, &self.agent_id));
            }
        }
        self.opens += 1;
        self.conversations.insert(
            id,
            Conversation {
                next,
                // The client just got the status; its next heartbeat is in 15 s.
                last_heartbeat: Instant::now(),
                opened: self.opens,
            },
        );
        envelopes
    }

    /// Number `outs` for every open conversation.
    fn broadcast(&mut self, outs: &[Out]) -> Vec<ChatEnvelope> {
        if outs.is_empty() {
            return Vec::new();
        }
        let ids: Vec<String> = self.conversations.keys().cloned().collect();
        ids.iter()
            .flat_map(|c| self.for_conversation(c, outs))
            .collect()
    }
}

impl App {
    /// Before a Claude respawn: report the old process's last state (its exit), tell
    /// its open conversations to reopen, and drop it (removing its directory).
    pub(crate) async fn retire_claude_chat(&mut self) {
        if self.claude_chat.is_none() {
            return;
        }
        self.poll_chat().await;
        if let Some(mut chat) = self.claude_chat.take() {
            let envelopes = chat.end_conversations(RESTARTED);
            self.send_chat(envelopes).await;
        }
    }

    /// Prepares chat for the Claude process about to be spawned and returns the
    /// arguments to put first on its command line. Any earlier chat (an older
    /// process) is dropped. On failure Claude starts without chat.
    pub(crate) fn prepare_claude_chat(&mut self, agent_id: &str, args: &[String]) -> Vec<String> {
        self.claude_chat = None;
        if !self.chat_swept {
            // Directories of Atem processes that died without cleaning up.
            self.chat_swept = true;
            hooks::sweep_stale(&self.chat_root);
        }
        let dir = match hooks::create_session_dir(&self.chat_root) {
            Ok(dir) => dir,
            Err(error) => {
                crate::diagnostics::warn(format!("Chat is off for Claude: {error}"));
                return Vec::new();
            }
        };
        let mut adapter = ClaudeAdapter::new();
        match adapter.prepare_launch(args, &dir) {
            Ok(plan) => {
                self.claude_chat = Some(AgentChat {
                    agent_id: agent_id.to_string(),
                    adapter: Some(Box::new(adapter)),
                    session: ChatSession::new(uuid::Uuid::new_v4().to_string(), now_ms()),
                    conversations: HashMap::new(),
                    opens: 0,
                    chat_v1: false,
                    reason_noticed: false,
                });
                plan.extra_args
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                crate::diagnostics::warn(format!("Chat is off for Claude: {error}"));
                Vec::new()
            }
        }
    }

    /// Each tick: read the agent's events and log, update the session, send what
    /// changed to open conversations, and keep the registry in step.
    pub async fn poll_chat(&mut self) {
        let input_count = self.claude_sender.as_ref().map_or(0, |s| s.input_count());
        // The PTY receiver is dropped when the process exits (finalize_claude_session).
        let exited = self.claude_receiver.is_none();
        let Some(chat) = self.claude_chat.as_mut() else {
            return;
        };
        let mut outs = Vec::new();
        let mut notice = None;
        // History from a log switched to (resume): clients must reload it.
        let mut backfilled = false;
        if let Some(adapter) = chat.adapter.as_mut() {
            let now = now_ms();
            // Events first (SessionStarted opens the log), then the log, then turn
            // ends, so `complete` follows the turn's content.
            let mut ended = Vec::new();
            for event in adapter.poll_events() {
                if matches!(event, AgentEvent::TurnEnded) {
                    ended.push(event);
                } else {
                    outs.extend(chat.session.on_event(event, now, input_count));
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
                backfilled |= matches!(item, LogItem::Backfill(_));
                outs.extend(chat.session.on_log(item, now, input_count));
            }
            for event in ended {
                outs.extend(chat.session.on_event(event, now, input_count));
            }
        }
        if exited && chat.adapter.is_some() {
            outs.extend(chat.session.on_process_exit(now_ms()));
            chat.adapter = None;
        }
        outs.extend(chat.session.tick(Instant::now()));

        let caps = chat
            .adapter
            .as_ref()
            .map(|a| a.capabilities())
            .unwrap_or_default();
        let withdrawn = chat.chat_v1 && !caps.chat_v1 && chat.adapter.is_some();
        if let Some(reason) = &caps.reason
            && !chat.reason_noticed
        {
            chat.reason_noticed = true;
            crate::diagnostics::warn(format!("Chat is off for Claude: {reason}"));
        }
        chat.chat_v1 = caps.chat_v1;

        let mut envelopes = chat.broadcast(&outs);
        envelopes.extend(chat.heartbeats());
        if withdrawn {
            envelopes.extend(chat.end_conversations(&not_available(caps.reason.as_deref())));
        } else if backfilled {
            envelopes.extend(chat.end_conversations(SWITCHED));
        }
        if let Some(detail) = notice {
            crate::diagnostics::warn(format!("Chat: {detail}"));
        }
        self.send_chat(envelopes).await;
        self.sync_chat_registry().await;
    }

    /// Registry status and capabilities from the chat; tells Astation when they change.
    async fn sync_chat_registry(&mut self) {
        let Some(chat) = &self.claude_chat else {
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
        self.send_agent_list_if_connected().await;
    }

    /// The agent list to Astation, when the link is authenticated.
    pub(crate) async fn send_agent_list_if_connected(&self) {
        if self.astation_connected {
            let agents = self.agent_registry.all();
            let _ = self.astation_client.send_agent_list(agents).await;
        }
    }

    async fn send_chat(&mut self, envelopes: Vec<ChatEnvelope>) {
        if !self.astation_connected {
            return;
        }
        for env in envelopes {
            let _ = self
                .astation_client
                .send_message(AstationMessage::AgentChat(env))
                .await;
        }
    }

    /// `agentChat` from Astation: open, submit or close a conversation.
    pub async fn handle_agent_chat(&mut self, env: ChatEnvelope) {
        // Only on an authenticated link (cleared while re-authenticating).
        if !self.astation_connected || self.astation_client.is_ws_closed() {
            return;
        }
        let conversation = env.conversation_id.clone();
        let agent = env.agent_id.clone();
        let inbound = match wire::parse_inbound(&env) {
            Ok(inbound) => inbound,
            Err(text) => {
                let reply = wire::error(&conversation, &agent, &text, None);
                return self.send_chat(vec![reply]).await;
            }
        };
        let request_id = match &inbound {
            Inbound::Submit { request_id, .. } => Some(request_id.as_str()),
            _ => None,
        };
        let available = match &self.claude_chat {
            Some(chat) if chat.agent_id == agent => match &chat.adapter {
                // Exited: history and status stay readable; prompts are refused.
                None => Ok(()),
                Some(adapter) => {
                    let caps = adapter.capabilities();
                    if caps.chat_v1 {
                        Ok(())
                    } else {
                        Err(caps.reason)
                    }
                }
            },
            _ => Err(None),
        };
        if let Err(reason) = available {
            let text = not_available(reason.as_deref());
            let reply = wire::error(&conversation, &agent, &text, request_id);
            return self.send_chat(vec![reply]).await;
        }
        let chat = self.claude_chat.as_mut().expect("checked above");
        let envelopes = match inbound {
            Inbound::Open { before } => {
                let generation = chat.session.generation().to_string();
                let mut envs = Vec::new();
                let mut history_envs = vec![wire::opened(
                    &conversation,
                    &agent,
                    &generation,
                    chat.session.status(),
                )];
                let history =
                    chat.session
                        .history(before.as_deref(), HISTORY_MESSAGES, HISTORY_BYTES);
                let mut sequence = 1;
                for message in &history {
                    history_envs.push(wire::history_message(
                        &conversation,
                        &agent,
                        &generation,
                        sequence,
                        message,
                    ));
                    sequence += 1;
                }
                envs.extend(chat.open_conversation(conversation, sequence));
                envs.extend(history_envs);
                envs
            }
            Inbound::Close => {
                chat.conversations.remove(&conversation);
                Vec::new()
            }
            Inbound::Submit {
                generation,
                request_id,
                text,
            } => {
                if !chat.conversations.contains_key(&conversation) {
                    vec![wire::error(
                        &conversation,
                        &agent,
                        "open the conversation first",
                        Some(&request_id),
                    )]
                } else {
                    let sender = self.claude_sender.as_ref();
                    let input_count = sender.map_or(0, |s| s.input_count());
                    let remote = sender.is_some_and(|s| s.remote_controlled());
                    let outs = match chat.session.submit(
                        &request_id,
                        &generation,
                        &text,
                        input_count,
                        remote,
                    ) {
                        Ok(text) => {
                            let written = match sender {
                                Some(sender) => sender.send_paste(&text),
                                None => Err(anyhow::anyhow!("no terminal")),
                            };
                            match written {
                                Ok(()) => {
                                    chat.session.mark_pasted(&request_id, Instant::now());
                                    Vec::new()
                                }
                                Err(error) => {
                                    crate::diagnostics::warn(format!(
                                        "Chat prompt was not written to Claude: {error}"
                                    ));
                                    chat.session.paste_failed(&request_id, PASTE_FAILED)
                                }
                            }
                        }
                        Err(outs) => outs,
                    };
                    chat.for_conversation(&conversation, &outs)
                }
            }
        };
        self.send_chat(envelopes).await;
    }

    /// Astation disconnected or is re-authenticating: drop every conversation
    /// (nothing is sent). The agent keeps running; a new `open` restores state.
    pub fn close_chat_conversations(&mut self) {
        if let Some(chat) = self.claude_chat.as_mut() {
            chat.conversations.clear();
        }
    }
}

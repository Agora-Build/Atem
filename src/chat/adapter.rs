use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Part {
    Text {
        id: String,
        markdown: String,
    },
    Tool {
        id: String,
        name: String,
        summary: String,
    },
    /// An approval card (r7 §6a): the agent's permission prompt and where it
    /// stands. Made by the broker, never by an adapter.
    Approval(ApprovalCard),
}
impl Part {
    pub fn id(&self) -> &str {
        match self {
            Part::Text { id, .. } | Part::Tool { id, .. } => id,
            Part::Approval(card) => &card.id,
        }
    }
}

/// What a chat-v1 approval card shows: the tool, the redacted summary, the
/// "always allow" rules it offers and the card's state; `rule_id` names the
/// Atem session rule that allowed it (`auto_allowed`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalCard {
    pub id: String,
    pub approval_id: String,
    pub tool: String,
    pub summary: String,
    pub always_rules: Vec<crate::session_protocol::wire::AlwaysRule>,
    pub state: ApprovalCardState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// A short note on how it ended (e.g. the session rule wasn't kept).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalCardState {
    Pending,
    Allowed,
    AlwaysAllowed,
    Denied,
    AnsweredTerminal,
    Expired,
    Closed,
    /// Allowed by an Atem session rule without asking (r7.2).
    AutoAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Done,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum AgentEvent {
    SessionStarted {
        session_id: String,
        log_path: PathBuf,
        /// Why the session (re)started, as the agent names it (Claude: `startup`,
        /// `resume`, `clear`, `compact`); empty when not given.
        source: String,
        /// The adapter keeps reading the same log (compaction, or a resume of the
        /// session already shown): the turn in progress continues.
        same_log: bool,
    },
    PromptSubmitted {
        text: String,
        /// The turn the prompt starts, when the agent names it (Codex);
        /// acceptance then needs the log's prompt of that turn.
        #[serde(default)]
        turn_id: Option<String>,
        /// When the hook fired (its event file's time, unix ms): a remote
        /// prompt pairs only with a hook from after its paste.
        #[serde(default)]
        at_ms: Option<i64>,
    },
    /// The agent can't take a prompt yet, and why (Codex before its first
    /// prompt): the status stays unknown with this detail, and a chat
    /// submit is refused with it.
    NotReady {
        detail: String,
    },
    ToolStarted,
    ToolFinished,
    WaitingForPermission {
        detail: String,
    },
    TurnEnded {
        /// When the agent reported it (its event file's time, unix ms): it
        /// answers only a permission prompt opened before.
        #[serde(default)]
        at_ms: Option<i64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum LogItem {
    /// A prompt as recorded in the log. `id` is the entry uuid.
    UserMessage {
        id: String,
        turn_id: String,
        text: String,
        created_at_ms: i64,
    },
    /// One part of an assistant message (`message_id` groups parts).
    AssistantPart {
        message_id: String,
        part: Part,
        turn_id: String,
        created_at_ms: i64,
    },
    /// A turn started according to the log (Codex's `task_started`): the
    /// agent is working, also on a turn without a prompt (compaction).
    TurnStarted { turn_id: String },
    /// The turn ended according to the log (end_turn or interrupt), at
    /// `at_ms` (the entry's time, unix ms; 0 when it has none).
    TurnEnded {
        turn_id: String,
        outcome: Outcome,
        #[serde(default)]
        at_ms: i64,
    },
    /// Content that was already in a log the adapter switched to (a resume of
    /// another session): history only, never live events. Never nested.
    Backfill(Box<LogItem>),
    /// Something could not be read; `fatal` = format changed, withdraw chat.
    Problem { detail: String, fatal: bool },
    /// A tool call that ended in an error result (Claude's transcript): the
    /// user refused it in the terminal (`Rejected`), or it failed or a hook
    /// denied it (`Failed`). For the worker's approvals only (it ends a
    /// waiting permission prompt); never forwarded or shown. `input` is the
    /// tool input as compact JSON (keys sorted), `text` the result's text
    /// (bounded), `at_ms` the entry's time.
    ToolResult {
        tool_name: String,
        input: String,
        kind: ToolResultKind,
        text: String,
        at_ms: i64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultKind {
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub chat_v1: bool,
    pub reason: Option<String>,
    /// What this agent's chat can't provide (see the `UNAVAILABLE_*` names),
    /// for clients to say so instead of waiting for it.
    pub unavailable: &'static [&'static str],
}

/// Partial text while a reply is written (messages arrive whole).
pub const UNAVAILABLE_STREAMING: &str = "streaming";
/// The model's reasoning.
pub const UNAVAILABLE_REASONING: &str = "reasoning";
/// The model or API error behind a failed turn.
pub const UNAVAILABLE_ERROR_DETAILS: &str = "error_details";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchPlan {
    pub extra_args: Vec<String>,
    pub session_id: Option<String>,
}

pub trait AgentAdapter: Send {
    fn prepare_launch(&mut self, args: &[String], dir: &Path) -> anyhow::Result<LaunchPlan>;
    fn poll_events(&mut self) -> Vec<AgentEvent>;
    fn poll_log(&mut self) -> Vec<LogItem>;
    fn capabilities(&self) -> Capabilities;
}

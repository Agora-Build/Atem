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
}
impl Part {
    pub fn id(&self) -> &str {
        match self {
            Part::Text { id, .. } | Part::Tool { id, .. } => id,
        }
    }
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
    },
    ToolStarted,
    ToolFinished,
    WaitingForPermission {
        detail: String,
    },
    TurnEnded,
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
    /// The turn ended according to the log (end_turn or interrupt).
    TurnEnded { turn_id: String, outcome: Outcome },
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
}

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

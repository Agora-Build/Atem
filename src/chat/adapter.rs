use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEvent {
    SessionStarted {
        session_id: String,
        log_path: PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Something could not be read; `fatal` = format changed, withdraw chat.
    Problem { detail: String, fatal: bool },
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

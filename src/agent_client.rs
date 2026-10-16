/// An agent's activity as Atem reports it to Astation (`agentStatusUpdate`).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Idle,
    Thinking,
    WaitingForInput,
    Disconnected,
    /// Activity cannot be detected.
    Unknown,
}

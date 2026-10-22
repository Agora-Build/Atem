//! terminal-v1's wire types (`{"type":"terminal","data":{"v":1,"op":…}}`):
//! requests from a viewer and the host's `attached`/`frame`/`written`/
//! `exited`/`error` (designs/terminal-v1-implementation.md). The host's
//! frame stream is the atem binary's (`src/terminal_share.rs`, which
//! re-exports these).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    #[serde(flatten)]
    pub message: Message,
}

impl From<Message> for Envelope {
    fn from(message: Message) -> Self {
        Self { v: 1, message }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Message {
    Subscribe {
        terminal_id: String,
        generation: String,
    },
    Unsubscribe {
        terminal_id: String,
        generation: String,
        stream_id: String,
    },
    Ack {
        terminal_id: String,
        generation: String,
        stream_id: String,
        offset: u64,
    },
    Input {
        terminal_id: String,
        generation: String,
        stream_id: String,
        sequence: u64,
        bytes: String,
    },
    Resize {
        terminal_id: String,
        generation: String,
        stream_id: String,
        rows: u16,
        cols: u16,
    },
    Stop {
        terminal_id: String,
        generation: String,
        stream_id: String,
    },
    Attached {
        session: SessionInfo,
        stream_id: String,
    },
    Frame {
        terminal_id: String,
        generation: String,
        stream_id: String,
        offset: u64,
        bytes: String,
        reset: bool,
        complete: bool,
        rows: u16,
        cols: u16,
    },
    Written {
        terminal_id: String,
        generation: String,
        stream_id: String,
        sequence: u64,
        error: Option<String>,
    },
    Exited {
        terminal_id: String,
        generation: String,
        status: String,
    },
    Error {
        terminal_id: Option<String>,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub terminal_id: String,
    pub generation: String,
    pub provider: String,
    pub rows: u16,
    pub cols: u16,
    pub exit_status: Option<String>,
    pub rendering: String,
    pub width_profile: String,
}

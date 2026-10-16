//! Worker protocol v1 between the broker (`atem runtime`) and one `atem
//! worker`: JSON lines `{"v":1,"op":…}` over the worker's same-user Unix
//! socket. One broker connection at a time; the stream is ordered, so a
//! `set_input_epoch` the broker sends before a `write` is applied before it.
//!
//! Connection: the worker speaks first with `hello` — except on the very
//! first connection, where the broker first sends `start` (the launch
//! environment, which is never written to disk) and the worker answers with
//! `hello` once the agent runs. Terminal bytes are base64.

use crate::chat::adapter::{AgentEvent, LogItem};
use crate::runtime::protocol::LaunchEnv;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The worker protocol version.
pub const WORKER_PROTOCOL: u32 = 1;
/// Longest line either side accepts (a `screen` restore is base64).
pub const MAX_LINE: usize = 4 * 1024 * 1024;
/// Most raw bytes in one `output`.
pub const MAX_OUTPUT: usize = 16 * 1024;
/// Most raw bytes in one `write` (the PTY's bound).
pub const MAX_WRITE: usize = crate::pty_session::MAX_INPUT;
/// Most bytes of text in one `paste`.
pub const MAX_PASTE: usize = 256 * 1024;

/// What the broker asks a new worker to run. Written to
/// `<state>/workers/<session_id>.spec.json` (0600) — without the environment,
/// which travels over the socket in `start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerSpec {
    pub session_id: String,
    /// UUID v4, new for every agent process.
    pub process_gen: String,
    /// `claude` or `codex`.
    pub provider: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub rows: u16,
    pub cols: u16,
    /// The worker's socket.
    pub socket: PathBuf,
}

/// The worker record, `<state>/workers/<session_id>.json` (0600, replaced
/// atomically): what a new broker needs to find and verify the worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRecord {
    pub session_id: String,
    pub process_gen: String,
    pub provider: String,
    pub cwd: PathBuf,
    pub created_at_ms: u64,
    pub socket: PathBuf,
    pub worker_pid: u32,
    /// The worker process's start time as the OS reports it
    /// (`adopt::process_start_time`).
    pub start_time: u64,
    pub agent_pid: Option<u32>,
    pub agent_start_time: Option<u64>,
    /// The agent's exit status, once it exited (kept until a broker heard it).
    #[serde(default)]
    pub exited: Option<String>,
}

/// Broker → worker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BrokerMsg {
    /// First connection only, before the agent runs: its environment
    /// (`None`: the worker's own).
    Start {
        #[serde(default)]
        env: Option<LaunchEnv>,
    },
    /// Raw terminal input (base64), written only if `input_epoch` is not
    /// older than the worker's current one → `write_result`.
    Write {
        seq: u64,
        bytes: String,
        input_epoch: u64,
    },
    /// A bracketed paste plus Enter, under the same epoch rule → `write_result`.
    Paste {
        seq: u64,
        text: String,
        input_epoch: u64,
    },
    /// Raises the current input epoch (a lower one is ignored).
    SetInputEpoch {
        epoch: u64,
    },
    Resize {
        rows: u16,
        cols: u16,
    },
    /// Stops the agent; `exited` follows.
    Stop,
    /// → `screen`
    RequestScreen,
}

impl std::fmt::Debug for BrokerMsg {
    // Never prints the environment, input bytes or paste text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerMsg::Start { env } => {
                write!(f, "Start({:?})", env.as_ref().map(|e| e.0.len()))
            }
            BrokerMsg::Write {
                seq,
                bytes,
                input_epoch,
            } => write!(
                f,
                "Write(seq {seq}, epoch {input_epoch}, {} b64 chars)",
                bytes.len()
            ),
            BrokerMsg::Paste {
                seq,
                text,
                input_epoch,
            } => write!(
                f,
                "Paste(seq {seq}, epoch {input_epoch}, {} bytes)",
                text.len()
            ),
            BrokerMsg::SetInputEpoch { epoch } => write!(f, "SetInputEpoch({epoch})"),
            BrokerMsg::Resize { rows, cols } => write!(f, "Resize({rows}x{cols})"),
            BrokerMsg::Stop => f.write_str("Stop"),
            BrokerMsg::RequestScreen => f.write_str("RequestScreen"),
        }
    }
}

impl BrokerMsg {
    pub fn write(seq: u64, bytes: &[u8], input_epoch: u64) -> Self {
        BrokerMsg::Write {
            seq,
            bytes: STANDARD.encode(bytes),
            input_epoch,
        }
    }
}

/// The agent's activity as its chat adapter reports it; `unknown` when it
/// can't be told (no adapter, hooks inactive, exited).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    Ready,
    Working,
    Waiting,
    Unknown,
}

/// Worker → broker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WorkerMsg {
    /// First on every connection (after the agent started).
    Hello {
        session_id: String,
        process_gen: String,
        /// The worker's pid and OS start time (`adopt::process_start_time`).
        pid: u32,
        start_time: u64,
        agent_pid: Option<u32>,
        /// Output bytes produced so far.
        offset: u64,
        input_epoch: u64,
        /// Writes and pastes dropped for a stale epoch so far.
        dropped: u64,
        /// The exit status when the agent already exited.
        exited: Option<String>,
    },
    /// Raw PTY output (base64) starting at stream position `offset`.
    Output {
        bytes: String,
        offset: u64,
    },
    /// The canonical screen as ANSI (base64): reset, contents, input modes;
    /// `output` from `offset` on follows. Sent on `request_screen`, and
    /// unasked after output was skipped because the broker fell behind.
    Screen {
        restore: String,
        offset: u64,
        rows: u16,
        cols: u16,
    },
    /// What the chat adapter read since the last `chat`, in the order the
    /// App handles it (events, log, turn ends follow the log), with the
    /// terminal input count at that moment and the adapter's capability.
    /// At most `worker_chat::BATCH_BYTES` of items; a text over the chat cap
    /// ends with `… (truncated)`. `gap`: items dropped right before these
    /// (no broker took them in time), so the history is incomplete.
    Chat {
        events: Vec<AgentEvent>,
        log: Vec<LogItem>,
        input_count: u64,
        chat_v1: bool,
        reason: Option<String>,
        #[serde(default)]
        gap: u64,
    },
    /// On every connection, before any `chat`: the worker's chat session
    /// (authoritative; it read everything held back meanwhile), so a broker
    /// that adopts this worker goes on from its status and history.
    ChatSnapshot {
        snapshot: crate::chat::session::ChatSnapshot,
        input_count: u64,
        chat_v1: bool,
        reason: Option<String>,
    },
    Activity {
        state: Activity,
        detail: Option<String>,
    },
    Exited {
        status: String,
    },
    WriteResult {
        seq: u64,
        ok: bool,
        bytes_written: usize,
        /// Dropped for a stale input epoch (nothing written).
        #[serde(default)]
        dropped: bool,
        /// Refused before anything was queued (nothing written): the agent
        /// exited, invalid bytes, a paste with control characters, a full
        /// queue. A writer error after queueing leaves it false.
        #[serde(default)]
        no_effect: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Error {
        text: String,
    },
}

impl WorkerMsg {
    pub fn output(bytes: &[u8], offset: u64) -> Self {
        WorkerMsg::Output {
            bytes: STANDARD.encode(bytes),
            offset,
        }
    }
}

#[derive(Serialize)]
struct OutLine<'a, T> {
    v: u32,
    #[serde(flatten)]
    message: &'a T,
}

fn encode<T: Serialize>(message: &T) -> String {
    let mut line = serde_json::to_string(&OutLine {
        v: WORKER_PROTOCOL,
        message,
    })
    .expect("worker messages serialize");
    line.push('\n');
    line
}

pub fn encode_broker(message: &BrokerMsg) -> String {
    encode(message)
}

pub fn encode_worker(message: &WorkerMsg) -> String {
    encode(message)
}

fn parse_line(line: &str) -> Result<serde_json::Value, String> {
    if line.len() > MAX_LINE {
        return Err("message too long".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(line.trim_end()).map_err(|e| format!("invalid message: {e}"))?;
    match value.get("v").and_then(|v| v.as_u64()) {
        Some(v) if v == u64::from(WORKER_PROTOCOL) => Ok(value),
        Some(v) => Err(format!(
            "worker protocol {v} isn't supported (this atem speaks {WORKER_PROTOCOL})"
        )),
        None => Err("message without a version".into()),
    }
}

/// A broker line, checked for version and bounds.
pub fn decode_broker(line: &str) -> Result<BrokerMsg, String> {
    let message: BrokerMsg =
        serde_json::from_value(parse_line(line)?).map_err(|e| format!("invalid message: {e}"))?;
    match &message {
        BrokerMsg::Write { bytes, .. } => {
            write_bytes(bytes)?;
        }
        BrokerMsg::Paste { text, .. } if text.len() > MAX_PASTE => {
            return Err(format!("a paste holds at most {MAX_PASTE} bytes"));
        }
        BrokerMsg::Start { env: Some(env) } => {
            crate::session::check_env(&env.to_os())?;
        }
        _ => {}
    }
    Ok(message)
}

pub fn decode_worker(line: &str) -> Result<WorkerMsg, String> {
    serde_json::from_value(parse_line(line)?).map_err(|e| format!("invalid message: {e}"))
}

/// `write` bytes decoded (1..=MAX_WRITE of them).
pub fn write_bytes(encoded: &str) -> Result<Vec<u8>, String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "write bytes aren't base64".to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_WRITE {
        return Err(format!("a write holds 1..={MAX_WRITE} bytes"));
    }
    Ok(bytes)
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::adapter::{Outcome, Part};

    #[test]
    fn broker_messages_round_trip_as_versioned_lines() {
        let messages = vec![
            BrokerMsg::Start {
                env: Some(LaunchEnv(vec![("PATH".into(), "/bin".into())])),
            },
            BrokerMsg::Start { env: None },
            BrokerMsg::write(1, b"hi\r", 3),
            BrokerMsg::Paste {
                seq: 2,
                text: "fix it".into(),
                input_epoch: 3,
            },
            BrokerMsg::SetInputEpoch { epoch: 4 },
            BrokerMsg::Resize {
                rows: 30,
                cols: 100,
            },
            BrokerMsg::Stop,
            BrokerMsg::RequestScreen,
        ];
        for message in messages {
            let line = encode_broker(&message);
            assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["v"], 1);
            assert_eq!(decode_broker(&line).unwrap(), message);
        }
        let value: serde_json::Value =
            serde_json::from_str(&encode_broker(&BrokerMsg::SetInputEpoch { epoch: 4 })).unwrap();
        assert_eq!(value["op"], "set_input_epoch");
    }

    #[test]
    fn worker_messages_round_trip_with_chat_items() {
        let messages = vec![
            WorkerMsg::Hello {
                session_id: "ses-abcdefgh2345".into(),
                process_gen: "g".into(),
                pid: 7,
                start_time: 99,
                agent_pid: Some(8),
                offset: 3,
                input_epoch: 2,
                dropped: 1,
                exited: None,
            },
            WorkerMsg::output(b"x", 9),
            WorkerMsg::Screen {
                restore: b64(b"\x1bc"),
                offset: 9,
                rows: 24,
                cols: 80,
            },
            WorkerMsg::Chat {
                events: vec![
                    AgentEvent::SessionStarted {
                        session_id: "s".into(),
                        log_path: "/tmp/l.jsonl".into(),
                        source: "startup".into(),
                        same_log: false,
                    },
                    AgentEvent::PromptSubmitted { text: "hi".into() },
                    AgentEvent::TurnEnded,
                ],
                log: vec![
                    LogItem::AssistantPart {
                        message_id: "m".into(),
                        part: Part::Text {
                            id: "p".into(),
                            markdown: "**ok**".into(),
                        },
                        turn_id: "t".into(),
                        created_at_ms: 1,
                    },
                    LogItem::Backfill(Box::new(LogItem::TurnEnded {
                        turn_id: "t".into(),
                        outcome: Outcome::Done,
                    })),
                ],
                input_count: 2,
                chat_v1: true,
                reason: None,
                gap: 3,
            },
            WorkerMsg::Activity {
                state: Activity::Working,
                detail: None,
            },
            WorkerMsg::Exited { status: "0".into() },
            WorkerMsg::WriteResult {
                seq: 1,
                ok: false,
                bytes_written: 0,
                dropped: true,
                no_effect: false,
                error: None,
            },
            WorkerMsg::Error { text: "e".into() },
        ];
        for message in messages {
            let line = encode_worker(&message);
            assert_eq!(decode_worker(&line).unwrap(), message, "{line}");
        }
    }

    #[test]
    fn versions_and_bounds_are_checked() {
        assert!(decode_broker(r#"{"v":2,"op":"stop"}"#).is_err());
        assert!(decode_broker(r#"{"op":"stop"}"#).is_err());
        assert!(decode_broker(r#"{"v":1,"op":"nope"}"#).is_err());
        assert!(decode_broker(&encode_broker(&BrokerMsg::write(1, b"", 0))).is_err());
        assert!(
            decode_broker(&encode_broker(&BrokerMsg::write(
                1,
                &vec![b'x'; MAX_WRITE + 1],
                0
            )))
            .is_err()
        );
        assert!(
            decode_broker(&encode_broker(&BrokerMsg::write(
                1,
                &vec![b'x'; MAX_WRITE],
                0
            )))
            .is_ok()
        );
        let paste = |n| BrokerMsg::Paste {
            seq: 1,
            text: "a".repeat(n),
            input_epoch: 0,
        };
        assert!(decode_broker(&encode_broker(&paste(MAX_PASTE))).is_ok());
        assert!(decode_broker(&encode_broker(&paste(MAX_PASTE + 1))).is_err());
        let many = (0..513).map(|i| (format!("K{i}"), "v".into())).collect();
        let start = BrokerMsg::Start {
            env: Some(LaunchEnv(many)),
        };
        assert!(decode_broker(&encode_broker(&start)).is_err());
        let long = format!(r#"{{"v":1,"op":"stop","x":"{}"}}"#, "a".repeat(MAX_LINE));
        assert!(decode_broker(&long).is_err());
        assert!(decode_worker(r#"{"v":2,"op":"exited","status":"0"}"#).is_err());
    }

    #[test]
    fn broker_messages_never_print_secrets() {
        let start = BrokerMsg::Start {
            env: Some(LaunchEnv(vec![("API_KEY".into(), "sk-secret".into())])),
        };
        let paste = BrokerMsg::Paste {
            seq: 1,
            text: "my password is hunter2".into(),
            input_epoch: 0,
        };
        let text = format!(
            "{start:?} {paste:?} {:?}",
            BrokerMsg::write(1, b"hunter2", 0)
        );
        for secret in ["sk-secret", "API_KEY", "hunter2", "aHVudGVyMg"] {
            assert!(!text.contains(secret), "{text}");
        }
    }
}

//! Local protocol v1 between `atem runtime` and its frontends: JSON lines
//! `{"v":1,"op":…}` over a same-user Unix socket. Terminal bytes are base64.
//! See `designs/agent-runtime.md` "Local protocol (v1)".

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::PathBuf;

/// The protocol version both sides speak.
pub const PROTOCOL: u32 = 1;
/// Longest line either side accepts (a launch carries up to 256 KiB of
/// environment, JSON-escaped; a paste up to `MAX_PASTE` bytes in base64).
pub const MAX_LINE: usize = 2 * 1024 * 1024;
/// Most raw bytes in one `input` (the PTY's own bound).
pub const MAX_INPUT: usize = crate::pty_session::MAX_INPUT;
/// Most raw bytes in one `output`.
pub const MAX_OUTPUT: usize = 16 * 1024;
/// Most bytes of text in one `paste` (bracketed, it still fits one fenced
/// PTY write).
pub const MAX_PASTE: usize = crate::pty_session::MAX_FENCED - 16;
/// Launch arguments: at most this many, and this many bytes in total.
pub const MAX_ARGS: usize = 256;
pub const MAX_ARGS_BYTES: usize = 64 * 1024;

/// A launch environment on the wire. `Debug` never prints it: it may hold
/// provider credentials.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LaunchEnv(pub Vec<(String, String)>);

impl std::fmt::Debug for LaunchEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LaunchEnv({} entries)", self.0.len())
    }
}

impl LaunchEnv {
    /// This process's environment (entries that aren't UTF-8 are left out).
    pub fn current() -> Self {
        Self(
            std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .collect(),
        )
    }

    pub fn to_os(&self) -> Vec<(OsString, OsString)> {
        self.0
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientMsg {
    Hello {
        protocol: u32,
        build: String,
        /// A passive client (the menu looking at the sessions) never keeps
        /// an idle runtime running.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        passive: bool,
    },
    /// → `launched`
    Launch {
        provider: String,
        #[serde(default)]
        args: Vec<String>,
        cwd: PathBuf,
        #[serde(default)]
        env: LaunchEnv,
        rows: u16,
        cols: u16,
    },
    /// → `attached` (a restore snapshot), then `output`
    Attach {
        session_id: String,
        rows: u16,
        cols: u16,
    },
    Detach {
        session_id: String,
    },
    Input {
        session_id: String,
        /// base64
        bytes: String,
    },
    /// Pasted text (base64, at most `MAX_PASTE` bytes): one local input,
    /// written whole (bracketed when the agent asked for it).
    Paste {
        session_id: String,
        bytes: String,
    },
    Resize {
        session_id: String,
        rows: u16,
        cols: u16,
    },
    /// Take control back from a remote terminal-v1 viewer (the prefix `g`).
    /// → `attached` (a fresh restore)
    Reclaim {
        session_id: String,
    },
    /// The person at this frontend says the agent's own approval dialog was
    /// answered here (the prefix `a`): the session's waiting approvals end
    /// (`answered_terminal`). Atem can't tell from the agent which call a
    /// result belongs to, so nothing else ends such a wait.
    ApprovalsAnswered {
        session_id: String,
    },
    /// → `sessions`
    List,
    Stop {
        session_id: String,
    },
    /// Re-read credentials and config; a link whose pairing is gone (after
    /// `atem unpair`) is dropped with its attachments.
    Reload,
    /// → `status`: the Astation link, the session attachment, the journal
    /// and the sessions (`atem status`, `atem --version`; read-only).
    Status,
    /// → `restarting`, then the runtime exits so a client can start its own
    /// build; the sessions' workers keep running and the next runtime adopts
    /// them. Refused while an Astation operation runs.
    Restart,
    /// Runs an Astation operation on the runtime's link: `print`/`ask`
    /// follow, then `done`. One at a time.
    AstationOp {
        request_id: String,
        kind: OpKind,
        #[serde(default)]
        options: OpOptions,
    },
    /// The answer to an `ask`.
    Answer {
        request_id: String,
        question_id: u64,
        value: AnswerValue,
    },
}

/// The Astation operations a client may ask the runtime to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    /// First pairing (`atem pair`).
    Pair,
    /// `atem pair verify`.
    PairVerify,
    CredUnlock,
    CredProjects,
    /// A fresh paired access token (`atem project …` near expiry).
    Token,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::Pair => "pair",
            OpKind::PairVerify => "pair_verify",
            OpKind::CredUnlock => "cred_unlock",
            OpKind::CredProjects => "cred_projects",
            OpKind::Token => "token",
        }
    }
}

/// An operation's options.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpOptions {
    /// `pair --save`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub save: bool,
    /// `token`: the paired Astation whose credentials are wanted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub astation_id: Option<String>,
    /// `cred_projects`: the client's working directory (its Git project).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
}

/// What a client answered: `yes`/`no` (yes_no), `text`, or why it couldn't
/// (`no_terminal`: nothing to ask on; `unanswered`: the terminal closed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum AnswerValue {
    Yes,
    No,
    Text(String),
    NoTerminal(String),
    Unanswered(String),
}

/// How an `ask` is answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskKind {
    YesNo,
    Text,
}

/// How a `print` is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrintLevel {
    Info,
    Warn,
    Error,
}

impl ClientMsg {
    pub fn op(&self) -> &'static str {
        match self {
            ClientMsg::Hello { .. } => "hello",
            ClientMsg::Launch { .. } => "launch",
            ClientMsg::Attach { .. } => "attach",
            ClientMsg::Detach { .. } => "detach",
            ClientMsg::Input { .. } => "input",
            ClientMsg::Paste { .. } => "paste",
            ClientMsg::Resize { .. } => "resize",
            ClientMsg::Reclaim { .. } => "reclaim",
            ClientMsg::ApprovalsAnswered { .. } => "approvals_answered",
            ClientMsg::List => "list",
            ClientMsg::Stop { .. } => "stop",
            ClientMsg::Reload => "reload",
            ClientMsg::Status => "status",
            ClientMsg::Restart => "restart",
            ClientMsg::AstationOp { .. } => "astation_op",
            ClientMsg::Answer { .. } => "answer",
        }
    }

    /// `input` with `bytes` base64-encoded.
    pub fn input(session_id: &str, bytes: &[u8]) -> Self {
        ClientMsg::Input {
            session_id: session_id.into(),
            bytes: STANDARD.encode(bytes),
        }
    }

    /// `paste` of `text`.
    pub fn paste(session_id: &str, text: &str) -> Self {
        ClientMsg::Paste {
            session_id: session_id.into(),
            bytes: STANDARD.encode(text),
        }
    }
}

/// One session as `list`, `launched` and `attached` describe it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub provider: String,
    pub cwd: PathBuf,
    pub created_at_ms: u64,
    /// `running`, `exited`, `interrupted` (the worker went away without a
    /// recorded exit) or `recovery_required` (the worker or its record
    /// can't be trusted; `stop` removes the record).
    pub state: String,
    /// The agent's activity as its worker reports it: `ready`, `working`,
    /// `waiting` or `unknown` (no chat adapter, or not detectable).
    pub status: String,
    /// A local frontend is attached.
    pub attached: bool,
    /// A remote terminal-v1 viewer holds the control lease.
    pub remote_controlled: bool,
    /// The exit status once the process has ended, or why the session
    /// isn't running.
    pub exited: Option<String>,
    /// The canonical screen's size.
    pub rows: u16,
    pub cols: u16,
    /// The process generation: changes with every process (terminal-v1's
    /// generation).
    pub generation: String,
    /// The atem build of the session's worker (its `hello`), when it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_build: Option<String>,
}

/// How the Astation link reached Astation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Local,
    Relay,
}

/// The link's session attachment was welcomed (session-v1 `hello`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcomed {
    /// The atem-session revision it was welcomed under.
    pub revision: u64,
    /// When (wall clock, Unix ms).
    pub at_ms: u64,
    /// What is left of the link's authorization.
    pub ms_left: u64,
}

/// The last `hello` the runtime refused for its revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// The revision that `hello` named (`None`: none).
    pub revision: Option<u64>,
    /// The revision the runtime needs.
    pub needs: u64,
    pub at_ms: u64,
}

/// The r9 device list of the runtime (atem-session-v1.md §R9.3, §R9.5), as
/// `atem status`, `atem agent list` and the terminal's status row show it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceListStatus {
    /// `open`, `held`, `frozen`, `paused` (a write fault in this run) or
    /// `failed` (it couldn't be opened).
    pub state: String,
    /// What it means and what to do, one line.
    pub text: String,
    /// The status row's short form (`None`: nothing to show).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,
    #[serde(default)]
    pub pending_recovery: Vec<PendingRecoveryStatus>,
    /// r9 clients attached now.
    #[serde(default)]
    pub clients: usize,
    /// Push hints and seens the relay hasn't acknowledged yet (§R9.9).
    #[serde(default)]
    pub push_pending: usize,
    /// How long the oldest of them has waited (ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_oldest_ms: Option<u64>,
}

/// A recovery waiting on this host's clock (§R9.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecoveryStatus {
    /// The device it adds (or `recovery key` for a kit replacement).
    pub subject: String,
    pub action: String,
    /// Wall ms when it takes effect unless a manager vetoes it.
    pub effective_at: u64,
}

/// What `status` reports: never a secret (no session id, token or relay
/// code).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStatus {
    /// The Astation link is authenticated.
    pub astation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    /// Relay links: the relay host and this Atem's id in the room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Not connected: a connect is under way or scheduled.
    #[serde(default)]
    pub retrying: bool,
    /// The socket is open but Astation asked to authenticate again.
    #[serde(default)]
    pub reauthenticating: bool,
    /// The relay link is routed for r9 only on a host route proof
    /// (§R9.7b): no Astation authenticated it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub routed: bool,
    /// The link has a session attachment (a verified pairing).
    #[serde(default)]
    pub attachment: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcomed: Option<Welcomed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<Refusal>,
    /// A journal write failed: nothing is admitted until a restart.
    #[serde(default)]
    pub journal_halted: bool,
    /// Why remote sessions are off, if they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_error: Option<String>,
    /// The workers found at start are still being adopted.
    #[serde(default)]
    pub adopting: bool,
    #[serde(default)]
    pub sessions: Vec<SessionSummary>,
    /// The r9 device list, when the runtime has one (open or not).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list: Option<DeviceListStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuntimeMsg {
    Welcome {
        protocol: u32,
        build: String,
        pid: u32,
        /// The runtime's Astation link is authenticated (`astation` follows
        /// on every change).
        #[serde(default)]
        astation: bool,
        /// Why remote sessions are off in this runtime (its session host
        /// could not start), if they are.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_error: Option<String>,
        /// The worker protocol its workers speak (`None`: a runtime from
        /// before the field, which speaks worker protocol 1).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        worker_protocol: Option<u32>,
        /// Its r9 device list (`device_list` follows on every change).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_list: Option<DeviceListStatus>,
    },
    /// The r9 device list changed (held, frozen, paused, failed, a pending
    /// recovery, or back to normal).
    DeviceList {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<DeviceListStatus>,
    },
    Launched {
        session: SessionSummary,
    },
    /// The canonical screen as ANSI (base64): reset, contents, input modes.
    /// `output` from `offset` on follows.
    Attached {
        session: SessionSummary,
        restore: String,
        offset: u64,
    },
    /// Raw PTY bytes (base64) starting at stream position `offset`.
    Output {
        session_id: String,
        bytes: String,
        offset: u64,
    },
    Exited {
        session_id: String,
        generation: String,
        status: String,
    },
    Sessions {
        sessions: Vec<SessionSummary>,
    },
    Detached {
        session_id: String,
        reason: String,
    },
    /// `stop` was done: the agent is stopping (its exit follows), or a
    /// session without a worker was `removed`.
    Stopped {
        session_id: String,
        removed: bool,
    },
    /// The attached session's summary changed (status, remote control,
    /// state); sent to its frontend.
    Session {
        session: SessionSummary,
    },
    /// The runtime's Astation link went up or down; sent to every client.
    Astation {
        connected: bool,
    },
    /// The answer to `status`.
    Status {
        status: RuntimeStatus,
    },
    /// The answer to `restart`: the runtime exits after this pass.
    Restarting,
    Notice {
        text: String,
    },
    /// Output of the operation `request_id`.
    Print {
        request_id: String,
        level: PrintLevel,
        text: String,
    },
    /// A question of the operation `request_id`, answered with `answer`.
    Ask {
        request_id: String,
        question_id: u64,
        kind: AskKind,
        text: String,
    },
    /// The operation `request_id` ended.
    Done {
        request_id: String,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Error {
        text: String,
        /// The op this error answers (the wire name avoids the `op` tag).
        #[serde(
            rename = "in_reply_to",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        op: Option<String>,
    },
}

impl RuntimeMsg {
    pub fn error(text: impl Into<String>, op: Option<&str>) -> Self {
        RuntimeMsg::Error {
            text: text.into(),
            op: op.map(str::to_string),
        }
    }
}

/// Why a line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Another protocol version (`v`, or `hello`'s `protocol`).
    Version(u64),
    /// Not a valid v1 message, or over a bound.
    Invalid(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Version(v) => write!(
                f,
                "protocol {v} isn't supported (this runtime speaks {PROTOCOL})"
            ),
            DecodeError::Invalid(text) => f.write_str(text),
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
        v: PROTOCOL,
        message,
    })
    .expect("protocol messages serialize");
    line.push('\n');
    line
}

/// One line (with its newline) for the socket.
pub fn encode_client(message: &ClientMsg) -> String {
    encode(message)
}

pub fn encode_runtime(message: &RuntimeMsg) -> String {
    encode(message)
}

/// The value of a line, checked for size and version.
fn parse_line(line: &str) -> Result<serde_json::Value, DecodeError> {
    if line.len() > MAX_LINE {
        return Err(DecodeError::Invalid("message too long".into()));
    }
    let value: serde_json::Value = serde_json::from_str(line.trim_end())
        .map_err(|e| DecodeError::Invalid(format!("invalid message: {e}")))?;
    match value.get("v").and_then(|v| v.as_u64()) {
        Some(v) if v == u64::from(PROTOCOL) => Ok(value),
        Some(v) => Err(DecodeError::Version(v)),
        None => Err(DecodeError::Invalid("message without a version".into())),
    }
}

pub fn decode_client(line: &str) -> Result<ClientMsg, DecodeError> {
    let value = parse_line(line)?;
    if value.get("op").and_then(|op| op.as_str()) == Some("hello")
        && let Some(protocol) = value.get("protocol").and_then(|p| p.as_u64())
        && protocol != u64::from(PROTOCOL)
    {
        return Err(DecodeError::Version(protocol));
    }
    let message: ClientMsg = serde_json::from_value(value)
        .map_err(|e| DecodeError::Invalid(format!("invalid message: {e}")))?;
    check_bounds(&message)?;
    Ok(message)
}

pub fn decode_runtime(line: &str) -> Result<RuntimeMsg, DecodeError> {
    let value = parse_line(line)?;
    serde_json::from_value(value).map_err(|e| DecodeError::Invalid(format!("invalid message: {e}")))
}

/// `paste` text decoded (UTF-8, 1..=MAX_PASTE bytes).
pub fn paste_text(encoded: &str) -> Result<String, DecodeError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| DecodeError::Invalid("paste bytes aren't base64".into()))?;
    if bytes.is_empty() || bytes.len() > MAX_PASTE {
        return Err(DecodeError::Invalid(format!(
            "a paste must hold 1..={MAX_PASTE} bytes"
        )));
    }
    String::from_utf8(bytes).map_err(|_| DecodeError::Invalid("a paste must be UTF-8".into()))
}

/// `input` bytes decoded (1..=MAX_INPUT of them).
pub fn input_bytes(encoded: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| DecodeError::Invalid("input bytes aren't base64".into()))?;
    if bytes.is_empty() || bytes.len() > MAX_INPUT {
        return Err(DecodeError::Invalid(format!(
            "input must hold 1..={MAX_INPUT} bytes"
        )));
    }
    Ok(bytes)
}

fn check_bounds(message: &ClientMsg) -> Result<(), DecodeError> {
    match message {
        ClientMsg::Launch { args, env, .. } => {
            let arg_bytes: usize = args.iter().map(|a| a.len() + 1).sum();
            if args.len() > MAX_ARGS || arg_bytes > MAX_ARGS_BYTES {
                return Err(DecodeError::Invalid(
                    "too many launch arguments (at most 256, 64 KiB)".into(),
                ));
            }
            crate::session::check_env(&env.to_os()).map_err(|e| DecodeError::Invalid(e.to_string()))
        }
        ClientMsg::Input { bytes, .. } => input_bytes(bytes).map(|_| ()),
        ClientMsg::Paste { bytes, .. } => paste_text(bytes).map(|_| ()),
        _ => Ok(()),
    }
}

/// Encodes raw output.
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes base64 (`restore`, `output`).
pub fn unb64(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> SessionSummary {
        SessionSummary {
            id: "ses-abcdefghijkl".into(),
            provider: "codex".into(),
            cwd: "/tmp/x".into(),
            created_at_ms: 1,
            state: "running".into(),
            status: "unknown".into(),
            attached: true,
            remote_controlled: false,
            exited: None,
            rows: 24,
            cols: 80,
            generation: "g".into(),
            worker_build: None,
        }
    }

    #[test]
    fn client_messages_round_trip_as_versioned_lines() {
        let messages = vec![
            ClientMsg::Hello {
                protocol: PROTOCOL,
                build: "b".into(),
                passive: false,
            },
            ClientMsg::Hello {
                protocol: PROTOCOL,
                build: "b".into(),
                passive: true,
            },
            ClientMsg::paste("s", "one\ntwo"),
            ClientMsg::Launch {
                provider: "codex".into(),
                args: vec!["--x".into()],
                cwd: "/tmp".into(),
                env: LaunchEnv(vec![("PATH".into(), "/bin".into())]),
                rows: 24,
                cols: 80,
            },
            ClientMsg::Attach {
                session_id: "ses-abcdefghijkl".into(),
                rows: 24,
                cols: 80,
            },
            ClientMsg::Detach {
                session_id: "s".into(),
            },
            ClientMsg::input("s", b"hi\r"),
            ClientMsg::Resize {
                session_id: "s".into(),
                rows: 30,
                cols: 100,
            },
            ClientMsg::Reclaim {
                session_id: "s".into(),
            },
            ClientMsg::ApprovalsAnswered {
                session_id: "s".into(),
            },
            ClientMsg::List,
            ClientMsg::Stop {
                session_id: "s".into(),
            },
            ClientMsg::Reload,
            ClientMsg::AstationOp {
                request_id: "r".into(),
                kind: OpKind::PairVerify,
                options: OpOptions::default(),
            },
            ClientMsg::AstationOp {
                request_id: "r".into(),
                kind: OpKind::Token,
                options: OpOptions {
                    save: true,
                    astation_id: Some("a".into()),
                    cwd: Some("/w".into()),
                },
            },
            ClientMsg::Answer {
                request_id: "r".into(),
                question_id: 2,
                value: AnswerValue::Yes,
            },
            ClientMsg::Answer {
                request_id: "r".into(),
                question_id: 3,
                value: AnswerValue::NoTerminal("no tty".into()),
            },
        ];
        for message in messages {
            let line = encode_client(&message);
            assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["v"], 1);
            assert_eq!(value["op"], message.op());
            assert_eq!(decode_client(&line).unwrap(), message);
        }
    }

    #[test]
    fn runtime_messages_round_trip() {
        let messages = vec![
            RuntimeMsg::Welcome {
                protocol: 1,
                build: "b".into(),
                pid: 7,
                astation: true,
                host_error: Some("remote sessions disabled: x".into()),
                worker_protocol: Some(1),
                device_list: None,
            },
            RuntimeMsg::Launched { session: summary() },
            RuntimeMsg::Attached {
                session: summary(),
                restore: b64(b"\x1bc"),
                offset: 3,
            },
            RuntimeMsg::Output {
                session_id: "s".into(),
                bytes: b64(b"x"),
                offset: 9,
            },
            RuntimeMsg::Exited {
                session_id: "s".into(),
                generation: "g".into(),
                status: "0".into(),
            },
            RuntimeMsg::Sessions {
                sessions: vec![summary()],
            },
            RuntimeMsg::Detached {
                session_id: "s".into(),
                reason: "attached elsewhere".into(),
            },
            RuntimeMsg::Stopped {
                session_id: "s".into(),
                removed: true,
            },
            RuntimeMsg::Session { session: summary() },
            RuntimeMsg::Astation { connected: false },
            RuntimeMsg::Notice { text: "n".into() },
            RuntimeMsg::Print {
                request_id: "r".into(),
                level: PrintLevel::Warn,
                text: "t".into(),
            },
            RuntimeMsg::Ask {
                request_id: "r".into(),
                question_id: 1,
                kind: AskKind::YesNo,
                text: "q".into(),
            },
            RuntimeMsg::Done {
                request_id: "r".into(),
                ok: false,
                error: Some("e".into()),
            },
            RuntimeMsg::error("bad", Some("launch")),
            RuntimeMsg::error("bad", None),
        ];
        for message in messages {
            let line = encode_runtime(&message);
            assert_eq!(decode_runtime(&line).unwrap(), message);
        }
        let line = encode_runtime(&RuntimeMsg::error("bad", Some("launch")));
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["op"], "error");
        assert_eq!(value["in_reply_to"], "launch");
    }

    #[test]
    fn versions_and_bounds_are_checked() {
        assert_eq!(
            decode_client(r#"{"v":2,"op":"list"}"#),
            Err(DecodeError::Version(2))
        );
        assert_eq!(
            decode_client(r#"{"v":1,"op":"hello","protocol":2,"build":"x"}"#),
            Err(DecodeError::Version(2))
        );
        assert!(matches!(
            decode_client(r#"{"op":"list"}"#),
            Err(DecodeError::Invalid(_))
        ));
        assert!(matches!(
            decode_client(r#"{"v":1,"op":"nope"}"#),
            Err(DecodeError::Invalid(_))
        ));
        let long = format!(
            r#"{{"v":1,"op":"stop","session_id":"{}"}}"#,
            "a".repeat(MAX_LINE)
        );
        assert!(matches!(decode_client(&long), Err(DecodeError::Invalid(_))));
        // Input: base64, 1..=MAX_INPUT bytes.
        for bad in [
            ClientMsg::Input {
                session_id: "s".into(),
                bytes: "!!".into(),
            },
            ClientMsg::input("s", b""),
            ClientMsg::input("s", &vec![b'x'; MAX_INPUT + 1]),
        ] {
            assert!(decode_client(&encode_client(&bad)).is_err());
        }
        assert!(
            decode_client(&encode_client(&ClientMsg::input(
                "s",
                &vec![b'x'; MAX_INPUT]
            )))
            .is_ok()
        );
        // Paste: UTF-8, 1..=MAX_PASTE bytes, in one message.
        assert!(
            decode_client(&encode_client(&ClientMsg::paste(
                "s",
                &"p".repeat(MAX_PASTE)
            )))
            .is_ok()
        );
        for bad in [
            ClientMsg::paste("s", ""),
            ClientMsg::paste("s", &"p".repeat(MAX_PASTE + 1)),
            ClientMsg::Paste {
                session_id: "s".into(),
                bytes: STANDARD.encode([0xff, 0xfe]),
            },
        ] {
            assert!(decode_client(&encode_client(&bad)).is_err());
        }
        // Launch environment: at most 512 entries and 256 KiB.
        let launch = |env: Vec<(String, String)>| ClientMsg::Launch {
            provider: "codex".into(),
            args: vec![],
            cwd: "/".into(),
            env: LaunchEnv(env),
            rows: 24,
            cols: 80,
        };
        let many = (0..513).map(|i| (format!("K{i}"), "v".into())).collect();
        assert!(decode_client(&encode_client(&launch(many))).is_err());
        let big = vec![("K".into(), "v".repeat(256 * 1024))];
        assert!(decode_client(&encode_client(&launch(big))).is_err());
        let fine = (0..512).map(|i| (format!("K{i}"), "v".into())).collect();
        assert!(decode_client(&encode_client(&launch(fine))).is_ok());
        let args = ClientMsg::Launch {
            provider: "codex".into(),
            args: vec!["a".into(); MAX_ARGS + 1],
            cwd: "/".into(),
            env: LaunchEnv::default(),
            rows: 24,
            cols: 80,
        };
        assert!(decode_client(&encode_client(&args)).is_err());
    }

    #[test]
    fn a_launch_never_prints_its_environment() {
        let message = ClientMsg::Launch {
            provider: "claude".into(),
            args: vec![],
            cwd: "/".into(),
            env: LaunchEnv(vec![("ANTHROPIC_API_KEY".into(), "sk-secret".into())]),
            rows: 24,
            cols: 80,
        };
        let debug = format!("{message:?}");
        assert!(
            !debug.contains("sk-secret") && !debug.contains("ANTHROPIC"),
            "{debug}"
        );
    }
}

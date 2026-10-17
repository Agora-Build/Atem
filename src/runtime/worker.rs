//! `atem worker --state <dir> --session <id>` (hidden): owns one agent
//! session — the agent process in its PTY, the canonical screen, the chat
//! adapter (Claude's, or Codex's when Atem's Codex hooks are on) and the
//! output stream — and outlives the broker that started
//! it. It serves one broker connection at a time on its socket
//! (`<runtime dir>/atem/workers/<session_id>.sock`, 0600, directory 0700,
//! same-user peers); when that broker goes away the agent keeps running and a
//! new broker can adopt the worker (`adopt.rs`).
//!
//! The broker is the only writer authority: every `write`/`paste` carries the
//! input epoch it was granted under, and the worker drops one whose epoch is
//! older than its current epoch — checked again at the PTY's write boundary,
//! so bytes queued before a `set_input_epoch` are dropped too.
//!
//! The agent normally dies with its worker: the worker holds the PTY master,
//! and its close hangs the agent up (SIGHUP). An agent that survives its
//! worker anyway can't be driven by anyone; adoption reports that session
//! `recovery_required` (the record names the agent's pid and start time).
//!
//! Files (the broker's state dir): `<state>/workers/<sid>.spec.json` (the
//! broker's request, removed once read), `<sid>.json` (the worker record),
//! `<sid>.lock` (one worker per session) and `<sid>.log` (its output).

use super::adopt::process_start_time;
use super::worker_approvals::{Approvals, Event as ApprovalEvent};
use super::worker_protocol::{
    Activity, BrokerMsg, MAX_LINE, MAX_OUTPUT, WorkerMsg, WorkerRecord, WorkerSpec, b64,
    decode_broker, encode_worker, write_bytes,
};
use crate::chat::adapter::{AgentAdapter, AgentEvent, Capabilities, LogItem};
use crate::chat::approvals::Agent;
use crate::chat::session::{ChatSession, State};
use crate::pty_session::{FencedOutcome, PtyEvent, PtyHandle, PtyInput, SpawnSpec};
use crate::session::{Provider, SessionId};
use crate::terminal_share::SharedTerminal;
use anyhow::{Context, Result, anyhow, bail};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// Unsent output to the broker before the worker stops sending it and sends
/// a fresh `screen` once the broker caught up.
pub const OUTPUT_BACKLOG: usize = 1024 * 1024;
/// How long a new connection has to send `start` before the first broker
/// is awaited on the next one.
const HANDSHAKE: Duration = Duration::from_secs(2);
/// The refusal a second broker gets while one is connected.
pub const ANOTHER_BROKER: &str = "another broker is connected to this worker";
/// History a chat snapshot carries at most (well below the line bound).
const SNAPSHOT_MESSAGES: usize = 200;
const SNAPSHOT_BYTES: usize = 1024 * 1024;
/// How often the chat adapter is read.
const CHAT_POLL: Duration = Duration::from_millis(200);
/// Input after the one that released a waiting hook (which is consumed) is
/// consumed too while the released hooks still run, at most this long (they
/// notice within ~100 ms): the user saw only Codex's hook wait, never its
/// dialog, so those keys must not answer it.
const CONSUME_INPUT: Duration = Duration::from_millis(500);

/// `<state>/workers`.
pub fn workers_dir(state: &Path) -> PathBuf {
    state.join("workers")
}

pub fn spec_path(state: &Path, session_id: &str) -> PathBuf {
    workers_dir(state).join(format!("{session_id}.spec.json"))
}

pub fn record_path(state: &Path, session_id: &str) -> PathBuf {
    workers_dir(state).join(format!("{session_id}.json"))
}

pub fn lock_path(state: &Path, session_id: &str) -> PathBuf {
    workers_dir(state).join(format!("{session_id}.lock"))
}

pub fn log_path(state: &Path, session_id: &str) -> PathBuf {
    workers_dir(state).join(format!("{session_id}.log"))
}

/// Removes a released worker's lock and log (its record is gone).
pub fn remove_leftovers(state: &Path, session_id: &str) {
    let _ = std::fs::remove_file(lock_path(state, session_id));
    let _ = std::fs::remove_file(log_path(state, session_id));
}

/// Where worker sockets live: `$XDG_RUNTIME_DIR/atem/workers` when the
/// runtime dir is an absolute, safe directory, else `<state>/workers`.
/// Session logs: `logs/` next to the state dir (`<config>/logs`).
pub fn logs_dir(state: &Path) -> PathBuf {
    state
        .parent()
        .map(|config| config.join("logs"))
        .unwrap_or_default()
}

pub fn socket_dir(state: &Path, runtime_dir: Option<OsString>) -> PathBuf {
    let uid = unsafe { libc::getuid() };
    runtime_dir
        .filter(|dir| {
            !dir.is_empty()
                && Path::new(dir).is_absolute()
                && crate::daemon::check_parent_dir(Path::new(dir), uid).is_ok()
        })
        .map(|dir| PathBuf::from(dir).join("atem").join("workers"))
        .unwrap_or_else(|| workers_dir(state))
}

/// A private directory (0700, this user's, never a symlink), created if missing.
pub fn private_dir(dir: &Path) -> std::io::Result<()> {
    let uid = unsafe { libc::getuid() };
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(std::io::Error::other(format!(
                    "{} is not a directory (a symlink is refused)",
                    dir.display()
                )));
            }
            if meta.uid() != uid {
                return Err(std::io::Error::other(format!(
                    "{} is owned by another user",
                    dir.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Reads a small private JSON file: a regular file of this user, never
/// through a symlink.
fn read_private(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::getuid() } {
        return Err(std::io::Error::other(format!(
            "{} is not this user's regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Replaces `path` with `bytes` (0600) through a temporary file, fsync and rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let result = (|| {
        let _ = std::fs::remove_file(&tmp);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent()
            && let Ok(dir) = std::fs::File::open(dir)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

pub fn write_spec(state: &Path, spec: &WorkerSpec) -> std::io::Result<()> {
    private_dir(&workers_dir(state))?;
    let bytes = serde_json::to_vec(spec).map_err(std::io::Error::other)?;
    write_atomic(&spec_path(state, &spec.session_id), &bytes)
}

pub fn read_spec(state: &Path, session_id: &str) -> Result<WorkerSpec> {
    let path = spec_path(state, session_id);
    let bytes = read_private(&path).with_context(|| format!("reading {}", path.display()))?;
    let spec: WorkerSpec = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a worker spec", path.display()))?;
    if spec.session_id != session_id {
        bail!("{} names another session", path.display());
    }
    Ok(spec)
}

pub fn write_record(state: &Path, record: &WorkerRecord) -> std::io::Result<()> {
    private_dir(&workers_dir(state))?;
    let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    write_atomic(&record_path(state, &record.session_id), &bytes)
}

pub fn read_record(path: &Path) -> Result<WorkerRecord> {
    let bytes = read_private(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a worker record", path.display()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The session's chat adapter. Each owns its session directory (removed
/// when it is dropped), which the approvals watch too.
enum ChatAdapter {
    Claude(Box<crate::chat::claude::ClaudeAdapter>),
    Codex(Box<crate::chat::codex::adapter::CodexAdapter>),
}

impl ChatAdapter {
    fn get(&mut self) -> &mut dyn AgentAdapter {
        match self {
            ChatAdapter::Claude(a) => a.as_mut(),
            ChatAdapter::Codex(a) => a.as_mut(),
        }
    }
}

/// What `agent_command` starts.
struct Launch {
    binary: String,
    args: Vec<String>,
    adapter: Option<ChatAdapter>,
    /// The session directory the approval hook writes to, and for which agent.
    approvals: Option<(PathBuf, Agent)>,
    /// Told to the session's frontends once the broker is connected.
    notice: Option<String>,
}

/// The Codex home of a launch: `CODEX_HOME` in the launch environment
/// (else the worker's own), else `$HOME/.codex`.
fn launch_codex_home(env: Option<&[(OsString, OsString)]>) -> PathBuf {
    let var = |name: &str| -> Option<OsString> {
        match env {
            Some(vars) => vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()),
            #[cfg(not(test))]
            None => std::env::var_os(name),
            // Tests never fall back to the real profile.
            #[cfg(test)]
            None => None,
        }
        .filter(|v| !v.is_empty())
    };
    if let Some(home) = var("CODEX_HOME") {
        return PathBuf::from(home);
    }
    match var("HOME") {
        Some(home) => PathBuf::from(home).join(".codex"),
        #[cfg(not(test))]
        None => crate::chat::codex::codex_home(),
        #[cfg(test)]
        None => PathBuf::from("/nonexistent/codex-home"),
    }
}

/// The binary, arguments and chat adapter for `spec`, exactly as the App
/// launches a session: `CLAUDE_CLI_*`/`CODEX_CLI_*` from the launch
/// environment (else the worker's own), the spec's arguments after them,
/// and for Claude its chat hooks first (approvals included unless
/// `claude_approvals` is off). With Atem's Codex hooks on (`script`), a
/// Codex session gets the Codex chat adapter and its session directory
/// (`approvals/` for the PermissionRequest hook, `events/` for the other
/// events) for the hooks in `~/.codex/hooks.json` (`chat::codex`), whose
/// stable script `script` is refreshed here.
fn agent_command(
    spec: &WorkerSpec,
    env: Option<&[(OsString, OsString)]>,
    chat_root: &Path,
    claude_approvals: bool,
    script: Option<&Path>,
) -> Result<Launch> {
    let provider = Provider::from_alias(&spec.provider)
        .ok_or_else(|| anyhow!("unknown provider {:?}", spec.provider))?;
    Ok(match provider {
        Provider::Claude => {
            let client = env
                .map(crate::claude_client::ClaudeClient::from_env)
                .unwrap_or_else(crate::claude_client::ClaudeClient::new);
            let launch_args = [client.launch_args(), &spec.args[..]].concat();
            let (adapter, chat_args) = match crate::chat::claude::prepare_chat(
                chat_root,
                &launch_args,
                claude_approvals,
            ) {
                Ok((adapter, args)) => (Some(adapter), args),
                Err(error) => {
                    eprintln!("atem worker: chat is off for Claude: {error}");
                    (None, Vec::new())
                }
            };
            let approvals = adapter
                .as_ref()
                .filter(|_| claude_approvals)
                .and_then(|a| a.dir())
                .map(|d| (d.to_path_buf(), Agent::Claude));
            Launch {
                binary: client.binary().to_string(),
                args: [chat_args, launch_args].concat(),
                adapter: adapter.map(|a| ChatAdapter::Claude(Box::new(a))),
                approvals,
                notice: None,
            }
        }
        Provider::Codex => {
            let client = env
                .map(crate::codex_client::CodexClient::from_env)
                .unwrap_or_else(crate::codex_client::CodexClient::new);
            let launch_args = [client.launch_args(), &spec.args[..]].concat();
            let codex_home = launch_codex_home(env);
            let mut notice = None;
            let adapter = script.and_then(|script| {
                if let Err(error) = crate::chat::approvals::install_script(script) {
                    eprintln!("atem worker: could not write {}: {error}", script.display());
                }
                // `[codex] hooks = true` (consent given): the idempotent merge,
                // so a session launched from the menu gets every hook too.
                // Never asks; a failure is a notice and Codex starts anyway.
                if let Err(error) = crate::chat::codex::install(&codex_home, script) {
                    let text = format!(
                        "Atem's Codex hooks could not be merged into {}: {error:#}",
                        codex_home.join("hooks.json").display()
                    );
                    eprintln!("atem worker: {text}");
                    notice = Some(text);
                }
                match crate::chat::codex::adapter::prepare_chat(
                    chat_root,
                    codex_home.clone(),
                    &launch_args,
                ) {
                    Ok((adapter, _)) => Some(adapter),
                    Err(error) => {
                        eprintln!("atem worker: Codex hooks are off: {error}");
                        None
                    }
                }
            });
            let approvals = adapter
                .as_ref()
                .and_then(|a| a.dir())
                .map(|d| (d.to_path_buf(), Agent::Codex));
            Launch {
                binary: client.binary().to_string(),
                args: launch_args,
                adapter: adapter.map(|a| ChatAdapter::Codex(Box::new(a))),
                approvals,
                notice,
            }
        }
    })
}

/// The agent's environment: never an outer session's `ATEM_APPROVAL_DIR`;
/// a Codex session's own (`dir`), which its stable hook command reads.
/// Claude's hook command names its directory itself.
fn approval_env(
    env: Option<Vec<(OsString, OsString)>>,
    dir: Option<&Path>,
) -> Option<Vec<(OsString, OsString)>> {
    let name = OsString::from(crate::chat::approvals::ENV);
    if env.is_none() && dir.is_none() && std::env::var_os(&name).is_none() {
        return None;
    }
    let mut vars = env.unwrap_or_else(|| std::env::vars_os().collect());
    vars.retain(|(k, _)| *k != name);
    if let Some(dir) = dir {
        vars.push((name, dir.as_os_str().to_owned()));
    }
    Some(vars)
}

/// How a worker runs; `run_worker` fills it for the real process, tests run
/// `serve` in-process with their own.
pub struct WorkerOptions {
    pub state: PathBuf,
    /// The worker's pid and OS start time (recorded, sent in `hello`).
    pub pid: u32,
    pub start_time: u64,
    /// Root of the chat session directories (Claude's and Codex's).
    pub chat_root: PathBuf,
    /// Where session logs go (`<logs>/<session_id>/`).
    pub logs: PathBuf,
    /// Peers must run as this user.
    pub uid: u32,
    /// How long to wait for the broker that started the worker.
    pub first_connect: Duration,
    /// After the agent exited with no broker to tell, how long to wait for one.
    pub linger: Duration,
    /// Claude sessions register the approval hook (`[claude] approvals_hook`,
    /// default on).
    pub claude_approvals: bool,
    /// The stable hook script Codex's hooks.json names, when Atem's Codex
    /// hooks are on (`[codex] hooks = true`).
    pub approval_script: Option<PathBuf>,
}

/// One broker connection.
struct Conn {
    tx: mpsc::UnboundedSender<String>,
    /// Bytes queued and not yet written.
    pending: Arc<AtomicUsize>,
    rx: mpsc::Receiver<Result<BrokerMsg, String>>,
    /// Output was skipped: send a fresh `screen` once the broker caught up.
    resync: bool,
    /// The agent's exit was queued on this connection.
    exit_sent: bool,
}

impl Conn {
    fn open(stream: UnixStream) -> Self {
        let (read, mut write) = stream.into_split();
        let (tx, mut out) = mpsc::unbounded_channel::<String>();
        let (in_tx, rx) = mpsc::channel(64);
        let pending = Arc::new(AtomicUsize::new(0));
        let written = pending.clone();
        tokio::spawn(async move {
            while let Some(line) = out.recv().await {
                let ok = write.write_all(line.as_bytes()).await.is_ok();
                written.fetch_sub(line.len(), Ordering::SeqCst);
                if !ok {
                    break;
                }
            }
            let _ = write.shutdown().await;
        });
        tokio::spawn(async move {
            let mut reader = BufReader::new(read);
            let mut line = Vec::new();
            loop {
                let (message, last) =
                    match super::server::read_line_max(&mut reader, &mut line, MAX_LINE).await {
                        Ok(true) => match std::str::from_utf8(&line) {
                            Ok(text) => (decode_broker(text), false),
                            Err(_) => (Err("message isn't UTF-8".to_string()), false),
                        },
                        Ok(false) => break,
                        Err(error) => (Err(error.to_string()), true),
                    };
                if in_tx.send(message).await.is_err() || last {
                    break;
                }
            }
        });
        Self {
            tx,
            pending,
            rx,
            resync: false,
            exit_sent: false,
        }
    }

    fn send(&self, message: &WorkerMsg) {
        let line = encode_worker(message);
        self.pending.fetch_add(line.len(), Ordering::SeqCst);
        if self.tx.send(line.clone()).is_err() {
            self.pending.fetch_sub(line.len(), Ordering::SeqCst);
        }
    }

    fn backlog(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }

    /// Waits until everything queued was written (or the writer gave up).
    async fn flush(&self) {
        for _ in 0..200 {
            if self.backlog() == 0 || self.tx.is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// The peer runs as `uid`.
fn same_user(stream: &UnixStream, uid: u32) -> bool {
    stream.peer_cred().is_ok_and(|cred| cred.uid() == uid)
}

/// Sends `text` as an `error` and closes `stream`.
async fn refuse(mut stream: UnixStream, text: &str) {
    let line = encode_worker(&WorkerMsg::Error { text: text.into() });
    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(line.as_bytes())).await;
    let _ = stream.shutdown().await;
}

struct Worker {
    spec: WorkerSpec,
    options: WorkerOptions,
    record: WorkerRecord,
    input: PtyInput,
    handle: PtyHandle,
    events: Option<mpsc::Receiver<PtyEvent>>,
    parser: vt100::Parser,
    share: SharedTerminal,
    /// The agent's output for the session log.
    log: super::session_log::SessionLog,
    offset: u64,
    dropped: u64,
    adapter: Option<ChatAdapter>,
    /// The session has a chat adapter (from its launch; told in `hello`).
    has_chat: bool,
    /// Approvals reported open: the only source of Codex's waiting status.
    open_approvals: std::collections::HashSet<String>,
    /// The agent's waiting permission prompts (`worker_approvals`).
    approvals: Option<Approvals>,
    /// What the chat adapter saw that may end a waiting prompt.
    approval_evidence: Vec<super::worker_approvals::Evidence>,
    /// After input released waiting hooks (that input was consumed): input
    /// is consumed (never written) until they exited or the deadline passed,
    /// so a key typed at Codex's hook wait never answers its dialog.
    consume: Option<Consume>,
    chat: ChatSession,
    capabilities: Capabilities,
    /// Chat read and not yet sent (no broker connected).
    chat_backlog: super::worker_chat::ChatBacklog,
    activity: (Activity, Option<String>),
    exited: Option<String>,
    exit_deadline: Option<Instant>,
    conn: Option<Conn>,
}

/// Waits for the broker that started this worker: its first message must be
/// `start`. Other connections in the meantime are refused.
async fn first_broker(
    listener: &UnixListener,
    options: &WorkerOptions,
) -> Result<(Conn, Option<Vec<(OsString, OsString)>>)> {
    let deadline = tokio::time::Instant::now() + options.first_connect;
    loop {
        let (stream, _) = tokio::time::timeout_at(deadline, listener.accept())
            .await
            .map_err(|_| anyhow!("no broker connected"))??;
        if !same_user(&stream, options.uid) {
            continue;
        }
        let mut conn = Conn::open(stream);
        // A silent peer gets `HANDSHAKE`, not the whole window.
        let handshake = deadline.min(tokio::time::Instant::now() + HANDSHAKE);
        match tokio::time::timeout_at(handshake, conn.rx.recv()).await {
            Ok(Some(Ok(BrokerMsg::Start { env }))) => {
                return Ok((conn, env.map(|env| env.to_os())));
            }
            Ok(Some(Ok(_))) => conn.send(&WorkerMsg::Error {
                text: "the agent hasn't started: send start first".into(),
            }),
            Ok(Some(Err(text))) => conn.send(&WorkerMsg::Error { text }),
            Ok(None) => {}
            Err(_) if tokio::time::Instant::now() >= deadline => {
                bail!("no broker started the agent")
            }
            Err(_) => conn.send(&WorkerMsg::Error {
                text: "no start within the handshake time".into(),
            }),
        }
        conn.flush().await;
    }
}

/// Serves the session in `spec` on `listener` until the agent exited and a
/// broker heard it (or `linger` passed without one). The worker record is
/// removed when a broker heard the exit, else it stays with the exit status.
pub async fn serve(spec: WorkerSpec, listener: UnixListener, options: WorkerOptions) -> Result<()> {
    if SessionId::parse(&spec.session_id).is_none() {
        bail!("{:?} is not a session id", spec.session_id);
    }
    let (conn, env) = first_broker(&listener, &options).await?;
    let (rows, cols) = (spec.rows.clamp(2, 200), spec.cols.clamp(2, 400));
    let launched = agent_command(
        &spec,
        env.as_deref(),
        &options.chat_root,
        options.claude_approvals,
        options.approval_script.as_deref(),
    )
    .and_then(|launch| {
        let codex_dir = launch
            .approvals
            .as_ref()
            .filter(|(_, agent)| *agent == Agent::Codex)
            .map(|(dir, _)| dir.as_path());
        let spawned = crate::pty_session::spawn_spec(SpawnSpec {
            binary: launch.binary.clone(),
            args: launch.args.clone(),
            cwd: spec.cwd.clone(),
            env: approval_env(env, codex_dir),
            rows,
            cols,
        });
        // Not started: the adapter's directory goes with it.
        spawned.map(|pty| (pty, launch))
    });
    let (pty, launch) = match launched {
        Ok(launched) => launched,
        Err(error) => {
            conn.send(&WorkerMsg::Error {
                text: format!("could not start {}: {error}", spec.provider),
            });
            conn.flush().await;
            return Err(error);
        }
    };
    let agent_pid = pty.resize_handle.process_id();
    let Launch {
        mut adapter,
        approvals,
        notice,
        ..
    } = launch;
    if let Some(ChatAdapter::Codex(codex)) = adapter.as_mut() {
        codex.set_agent_pid(agent_pid);
    }
    let record = WorkerRecord {
        session_id: spec.session_id.clone(),
        process_gen: spec.process_gen.clone(),
        provider: spec.provider.clone(),
        cwd: spec.cwd.clone(),
        created_at_ms: now_ms() as u64,
        socket: spec.socket.clone(),
        worker_pid: options.pid,
        start_time: options.start_time,
        agent_pid,
        agent_start_time: agent_pid.and_then(process_start_time),
        exited: None,
    };
    if let Err(error) = write_record(&options.state, &record) {
        let _ = pty.resize_handle.stop();
        drop(adapter);
        conn.send(&WorkerMsg::Error {
            text: format!("could not write the worker record: {error}"),
        });
        conn.flush().await;
        bail!("could not write the worker record: {error}");
    }
    let mut worker = Worker {
        share: SharedTerminal::new(),
        log: Default::default(),
        spec,
        record,
        input: pty.sender,
        handle: pty.resize_handle,
        events: Some(pty.receiver),
        parser: vt100::Parser::new(rows, cols, crate::pty_session::SCROLLBACK_ROWS),
        offset: 0,
        dropped: 0,
        has_chat: adapter.is_some(),
        // The first `chat_snapshot` already names what the chat offers.
        capabilities: adapter
            .as_mut()
            .map(|a| a.get().capabilities())
            .unwrap_or_default(),
        open_approvals: Default::default(),
        adapter,
        approvals: approvals.map(|(dir, agent)| Approvals::new(&dir, agent, agent_pid)),
        approval_evidence: Vec::new(),
        consume: None,
        chat: ChatSession::new(uuid::Uuid::new_v4().to_string(), now_ms()),
        chat_backlog: Default::default(),
        activity: (Activity::Unknown, None),
        exited: None,
        exit_deadline: None,
        conn: None,
        options,
    };
    worker.connected(conn);
    if let Some(text) = notice {
        worker.send(&WorkerMsg::Notice { text });
    }
    let delivered = worker.run(&listener).await;
    if delivered {
        let _ = std::fs::remove_file(record_path(&worker.options.state, &worker.spec.session_id));
    }
    Ok(())
}

impl Worker {
    fn send(&mut self, message: &WorkerMsg) {
        if let Some(conn) = &self.conn {
            conn.send(message);
        }
    }

    fn hello(&self) -> WorkerMsg {
        WorkerMsg::Hello {
            session_id: self.spec.session_id.clone(),
            process_gen: self.spec.process_gen.clone(),
            pid: self.options.pid,
            start_time: self.options.start_time,
            agent_pid: self.record.agent_pid,
            offset: self.offset,
            input_epoch: self.input.input_epoch(),
            dropped: self.dropped,
            exited: self.exited.clone(),
            chat: self.has_chat,
        }
    }

    /// A broker connected: `hello`, the current activity, chat held back
    /// meanwhile, and the exit when the agent already exited.
    fn connected(&mut self, conn: Conn) {
        conn.send(&self.hello());
        conn.send(&WorkerMsg::Activity {
            state: self.activity.0,
            detail: self.activity.1.clone(),
        });
        self.conn = Some(conn);
        if self.adapter.is_some() || !self.chat_backlog.is_empty() {
            // The snapshot covers what the backlog held (the worker's chat
            // session read it already), so the backlog is not sent too.
            self.chat_backlog.take();
            let snapshot = WorkerMsg::ChatSnapshot {
                snapshot: self.chat.snapshot(SNAPSHOT_MESSAGES, SNAPSHOT_BYTES),
                input_count: self.input.input_count(),
                chat_v1: self.capabilities.chat_v1,
                reason: self.capabilities.reason.clone(),
                unavailable: self.unavailable(),
            };
            self.send(&snapshot);
        }
        // The session rules outlive a broker (the worker owns them).
        let rules = self.approvals.as_ref().map(Approvals::rules);
        if let Some(rules) = rules.filter(|r| !r.is_empty()) {
            self.send(&WorkerMsg::ApprovalRules { rules });
        }
        if let Some(status) = self.exited.clone() {
            self.send(&WorkerMsg::Exited { status });
            if let Some(conn) = &mut self.conn {
                conn.exit_sent = true;
            }
        }
    }

    fn screen(&self) -> WorkerMsg {
        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        WorkerMsg::Screen {
            restore: b64(&crate::terminal_share::restore_bytes(screen)),
            offset: self.offset,
            rows,
            cols,
        }
    }

    /// Runs until done; true when a broker heard the agent's exit.
    async fn run(&mut self, listener: &UnixListener) -> bool {
        let mut poll = tokio::time::interval(CHAT_POLL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let has_events = self.events.is_some();
            let has_conn = self.conn.is_some();
            let events = self.events.as_mut();
            let conn_rx = self.conn.as_mut().map(|c| &mut c.rx);
            tokio::select! {
                event = async { events.unwrap().recv().await }, if has_events => {
                    self.pty_event(event);
                }
                message = async { conn_rx.unwrap().recv().await }, if has_conn => {
                    match message {
                        Some(Ok(message)) => {
                            if self.broker_message(message) {
                                self.flush_conn().await;
                                return self.exited.is_some();
                            }
                        }
                        Some(Err(text)) => self.send(&WorkerMsg::Error { text }),
                        None => {
                            // The broker went away; the agent keeps running.
                            // Its approvals went with it: the agent asks.
                            self.release_approvals();
                            self.consume = None;
                            let heard = self.conn.take().is_some_and(|c| c.exit_sent);
                            if heard {
                                return true;
                            }
                        }
                    }
                }
                accepted = listener.accept() => {
                    if let Ok((stream, _)) = accepted {
                        if !same_user(&stream, self.options.uid) {
                            continue;
                        }
                        // What the current broker already sent (or its close) first.
                        if self.drain_conn() {
                            self.flush_conn().await;
                            return true;
                        }
                        if self.conn.as_ref().is_some_and(|c| !c.tx.is_closed()) {
                            tokio::spawn(refuse(stream, ANOTHER_BROKER));
                        } else {
                            self.connected(Conn::open(stream));
                        }
                    }
                }
                _ = poll.tick() => {
                    self.poll_chat();
                    self.poll_approvals();
                    if self.exit_deadline.is_some_and(|at| Instant::now() >= at) && self.conn.is_none() {
                        eprintln!("atem worker: no broker heard the agent's exit; leaving the record");
                        return false;
                    }
                }
            }
            self.resync();
        }
    }

    /// Handles what the current broker already sent and forgets it once it
    /// closed. True when the worker should end (its exit was heard).
    fn drain_conn(&mut self) -> bool {
        use tokio::sync::mpsc::error::TryRecvError;
        loop {
            let Some(conn) = &mut self.conn else {
                return false;
            };
            match conn.rx.try_recv() {
                Ok(Ok(message)) => {
                    if self.broker_message(message) {
                        return true;
                    }
                }
                Ok(Err(text)) => self.send(&WorkerMsg::Error { text }),
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => {
                    self.release_approvals();
                    self.consume = None;
                    return self.conn.take().is_some_and(|c| c.exit_sent);
                }
            }
        }
    }

    async fn flush_conn(&self) {
        if let Some(conn) = &self.conn {
            conn.flush().await;
        }
    }

    /// After output was skipped, a fresh screen once the broker caught up.
    fn resync(&mut self) {
        let due = self
            .conn
            .as_ref()
            .is_some_and(|c| c.resync && c.backlog() < OUTPUT_BACKLOG / 2);
        if due {
            let screen = self.screen();
            if let Some(conn) = &mut self.conn {
                conn.resync = false;
                conn.send(&screen);
            }
        }
    }

    fn pty_event(&mut self, event: Option<PtyEvent>) {
        match event {
            Some(PtyEvent::Output(bytes)) => {
                let start = self.offset;
                let text = self.share.process(&mut self.parser, &self.input, &bytes);
                self.log.append(&text);
                self.offset += bytes.len() as u64;
                if let Some(conn) = &mut self.conn {
                    if conn.resync || conn.backlog() > OUTPUT_BACKLOG {
                        conn.resync = true;
                    } else {
                        for (i, chunk) in bytes.chunks(MAX_OUTPUT).enumerate() {
                            conn.send(&WorkerMsg::output(chunk, start + (i * MAX_OUTPUT) as u64));
                        }
                    }
                }
            }
            Some(PtyEvent::Fenced { sequence, outcome }) => {
                let message = match outcome {
                    FencedOutcome::Written(n) => WorkerMsg::WriteResult {
                        seq: sequence,
                        ok: true,
                        bytes_written: n,
                        dropped: false,
                        no_effect: false,
                        consumed: false,
                        error: None,
                    },
                    FencedOutcome::Dropped => {
                        self.dropped += 1;
                        dropped(sequence)
                    }
                    FencedOutcome::Failed(error) => WorkerMsg::WriteResult {
                        seq: sequence,
                        ok: false,
                        bytes_written: 0,
                        dropped: false,
                        no_effect: false,
                        consumed: false,
                        error: Some(error),
                    },
                };
                self.send(&message);
            }
            Some(PtyEvent::Error(error)) => eprintln!("atem worker: {error}"),
            Some(PtyEvent::Exit(status)) => self.agent_exited(status),
            None => self.agent_exited("PTY transport closed".into()),
        }
    }

    fn agent_exited(&mut self, status: String) {
        self.events = None;
        self.poll_chat();
        if let Some(mut approvals) = self.approvals.take() {
            let events = approvals.process_ended();
            self.send_approval_events(events);
        }
        // The approvals are done with the session directory: the adapter
        // removes it.
        self.chat.on_process_exit(now_ms());
        self.adapter = None;
        self.set_activity(Activity::Unknown, None);
        if let Some(provider) = crate::session::Provider::from_alias(&self.spec.provider) {
            let notice = self.log.finish(
                &self.options.logs,
                &self.spec.session_id,
                provider,
                self.parser.screen(),
            );
            self.send(&WorkerMsg::Notice { text: notice });
        }
        self.exited = Some(status.clone());
        self.exit_deadline = Some(Instant::now() + self.options.linger);
        self.record.exited = Some(status.clone());
        if let Err(error) = write_record(&self.options.state, &self.record) {
            eprintln!("atem worker: could not record the exit: {error}");
        }
        if let Some(conn) = &mut self.conn {
            conn.send(&WorkerMsg::Exited { status });
            conn.exit_sent = true;
        }
    }

    /// Handles one broker message; true when the worker should end now.
    fn broker_message(&mut self, message: BrokerMsg) -> bool {
        if let BrokerMsg::Write {
            seq,
            release_approvals,
            ..
        }
        | BrokerMsg::Paste {
            seq,
            release_approvals,
            ..
        } = &message
            && ((*release_approvals && self.release_for_input()) || self.consuming())
        {
            self.send(&consumed(*seq));
            return false;
        }
        match message {
            BrokerMsg::Start { .. } => self.send(&WorkerMsg::Error {
                text: "the agent already started".into(),
            }),
            BrokerMsg::Write {
                seq,
                bytes,
                input_epoch,
                not_after,
                ..
            } => {
                let result = write_bytes(&bytes)
                    .map_err(|e| anyhow!(e))
                    .and_then(|bytes| self.admit(input_epoch).map(|()| bytes));
                match result {
                    Ok(bytes) => {
                        if let Err(error) =
                            self.input.write_fenced(bytes, input_epoch, seq, not_after)
                        {
                            self.send(&failed(seq, error.to_string()));
                        }
                    }
                    Err(error) => self.refused(seq, error),
                }
            }
            BrokerMsg::Paste {
                seq,
                text,
                input_epoch,
                not_after,
                ..
            } => match self.admit(input_epoch) {
                Ok(()) => {
                    if let Err(error) = self.input.paste_fenced(&text, input_epoch, seq, not_after)
                    {
                        self.send(&failed(seq, error.to_string()));
                    }
                }
                Err(error) => self.refused(seq, error),
            },
            BrokerMsg::SetInputEpoch { epoch } => {
                self.input.raise_input_epoch(epoch);
            }
            BrokerMsg::Resize { rows, cols } => {
                if self.exited.is_none() {
                    match self.handle.resize(rows, cols) {
                        Ok(()) => self.parser.set_size(rows, cols),
                        Err(error) => self.send(&WorkerMsg::Error {
                            text: error.to_string(),
                        }),
                    }
                }
            }
            BrokerMsg::Stop => {
                if self.exited.is_some() {
                    // The broker heard the exit and releases the worker.
                    return self.conn.as_ref().is_some_and(|c| c.exit_sent);
                }
                let _ = self.handle.stop();
            }
            BrokerMsg::RequestScreen => {
                let screen = self.screen();
                if let Some(conn) = &mut self.conn {
                    // The screen covers everything skipped so far.
                    conn.resync = false;
                    conn.send(&screen);
                }
            }
            BrokerMsg::ApprovalDecision {
                request_id,
                decision,
                rule_id,
                message,
            } => {
                let refused = match self.approvals.as_mut() {
                    Some(a) => a.decide(
                        &request_id,
                        decision,
                        rule_id.as_deref(),
                        message.as_deref(),
                    ),
                    None => Some(ApprovalEvent::Applied {
                        request_id,
                        outcome: super::worker_protocol::ApplyOutcome::NotDelivered,
                    }),
                };
                self.send_approval_events(refused.into_iter().collect());
            }
            BrokerMsg::ReleaseApproval { request_id } => {
                if let Some(a) = self.approvals.as_mut() {
                    a.release(&request_id);
                }
            }
            BrokerMsg::KnownApprovals { request_ids } => {
                if let Some(a) = self.approvals.as_mut() {
                    a.keep_only(&request_ids);
                }
            }
            BrokerMsg::RevokeApprovalRule { rule_id } => {
                let revoked = self
                    .approvals
                    .as_mut()
                    .map(|a| (a.revoke(&rule_id), a.rules()));
                let ok = revoked.as_ref().is_some_and(|(ok, _)| *ok);
                self.send(&WorkerMsg::ApprovalRuleRevoked { rule_id, ok });
                if let Some((true, rules)) = revoked {
                    self.send(&WorkerMsg::ApprovalRules { rules });
                }
            }
        }
        false
    }

    /// Every waiting hook gets "no decision"; the ones released now.
    fn release_approvals(&mut self) -> Vec<String> {
        match self.approvals.as_mut() {
            Some(a) => a.release_all(),
            None => Vec::new(),
        }
    }

    /// Input to Codex: every waiting hook gets "no decision". True when that
    /// released one: the input is consumed, and so is input after it while
    /// the released hooks still run (`consuming`).
    fn release_for_input(&mut self) -> bool {
        let released = self.release_approvals();
        if released.is_empty() {
            return false;
        }
        let mut ids = self.consume.take().map(|c| c.ids).unwrap_or_default();
        ids.extend(released);
        self.consume = Some(Consume {
            until: Instant::now() + CONSUME_INPUT,
            ids,
        });
        true
    }

    /// Input after the one that released waiting hooks is consumed too
    /// while they still run (at most `CONSUME_INPUT`).
    fn consuming(&mut self) -> bool {
        let Some(consume) = &self.consume else {
            return false;
        };
        let running = Instant::now() < consume.until
            && self
                .approvals
                .as_ref()
                .is_some_and(|a| a.hooks_running(&consume.ids));
        if !running {
            self.consume = None;
        }
        running
    }

    /// Reads the approvals directory (a request with no broker connected is
    /// released at once) and reports what happened.
    fn poll_approvals(&mut self) {
        let connected = self.conn.as_ref().is_some_and(|c| !c.tx.is_closed());
        let Some(a) = self.approvals.as_mut() else {
            return;
        };
        let evidence = std::mem::take(&mut self.approval_evidence);
        let events = a.poll(connected, evidence);
        self.send_approval_events(events);
    }

    fn send_approval_events(&mut self, events: Vec<ApprovalEvent>) {
        // Codex reports no permission wait of its own: the approvals the
        // worker reports open (waiting for a remote answer) and the ones it
        // gave back to Codex's own dialog are its waiting status, applied
        // once per batch so a release never flaps it to working.
        for event in &events {
            match event {
                ApprovalEvent::Request { request_id, .. } => {
                    self.open_approvals.insert(request_id.clone());
                }
                ApprovalEvent::Closed { request_id, .. }
                | ApprovalEvent::Applied { request_id, .. } => {
                    self.open_approvals.remove(request_id);
                }
                ApprovalEvent::AutoAllowed { .. }
                | ApprovalEvent::Rules(_)
                | ApprovalEvent::RuleRevoked { .. } => {}
            }
        }
        let released = self.approvals.as_mut().is_some_and(|a| a.take_released());
        if let Some(ChatAdapter::Codex(codex)) = self.adapter.as_mut() {
            codex.set_approvals(self.open_approvals.len(), released);
        }
        for event in events {
            let message = match event {
                ApprovalEvent::Request { request_id, info } => WorkerMsg::ApprovalRequest {
                    request_id,
                    tool: info.tool,
                    summary: info.summary,
                    always_rules: info.always_rules,
                },
                ApprovalEvent::Closed { request_id, reason } => {
                    WorkerMsg::ApprovalClosed { request_id, reason }
                }
                ApprovalEvent::Applied {
                    request_id,
                    outcome,
                } => WorkerMsg::ApprovalApplied {
                    request_id,
                    outcome,
                },
                ApprovalEvent::AutoAllowed {
                    request_id,
                    rule_id,
                    tool,
                    summary,
                } => WorkerMsg::ApprovalAutoAllowed {
                    request_id,
                    rule_id,
                    tool,
                    summary,
                },
                ApprovalEvent::Rules(rules) => WorkerMsg::ApprovalRules { rules },
                ApprovalEvent::RuleRevoked { rule_id, ok } => {
                    WorkerMsg::ApprovalRuleRevoked { rule_id, ok }
                }
            };
            self.send(&message);
        }
    }

    /// A write or paste may go on: the agent runs and `input_epoch` is not
    /// older than the current epoch (a newer one becomes current).
    fn admit(&mut self, input_epoch: u64) -> Result<()> {
        if self.exited.is_some() {
            bail!("the agent exited");
        }
        if input_epoch < self.input.input_epoch() {
            return Err(anyhow!(StaleEpoch));
        }
        self.input.raise_input_epoch(input_epoch);
        Ok(())
    }

    fn refused(&mut self, seq: u64, error: anyhow::Error) {
        if error.is::<StaleEpoch>() {
            self.dropped += 1;
            self.send(&dropped(seq));
        } else {
            self.send(&failed(seq, error.to_string()));
        }
    }

    fn set_activity(&mut self, state: Activity, detail: Option<String>) {
        if self.activity == (state, detail.clone()) {
            return;
        }
        self.activity = (state, detail.clone());
        self.send(&WorkerMsg::Activity { state, detail });
    }

    /// Reads the chat adapter (in the App's order: events, the log, then turn
    /// ends), keeps the activity from it and forwards what it read.
    fn poll_chat(&mut self) {
        let evidence = self.approvals.is_some();
        let Some(adapter) = self.adapter.as_mut().map(ChatAdapter::get) else {
            return;
        };
        let input_count = self.input.input_count();
        let now = now_ms();
        let events = adapter.poll_events();
        let mut log = adapter.poll_log();
        let capabilities = adapter.capabilities();
        // What may end a waiting permission prompt (applied with the next
        // approvals poll): a new prompt or the turn's end, a tool refused in
        // the terminal — each stamped with when the agent reported it, so
        // it answers only a prompt opened before (one read in the same pass
        // as a newer request doesn't). Tool results are the worker's only:
        // never forwarded.
        if evidence {
            use super::worker_approvals::Evidence;
            for e in &events {
                if let AgentEvent::PromptSubmitted { at_ms, .. } | AgentEvent::TurnEnded { at_ms } =
                    e
                {
                    self.approval_evidence.push(Evidence::TurnEnded {
                        interrupted: false,
                        at_ms: *at_ms,
                    });
                }
            }
            for item in &log {
                match item {
                    LogItem::TurnEnded { outcome, at_ms, .. } => {
                        self.approval_evidence.push(Evidence::TurnEnded {
                            interrupted: *outcome == crate::chat::adapter::Outcome::Interrupted,
                            at_ms: (*at_ms != 0).then_some(*at_ms),
                        })
                    }
                    LogItem::ToolResult {
                        tool_name,
                        input,
                        kind,
                        text,
                        at_ms,
                    } => {
                        if let Ok(input) = serde_json::from_str(input) {
                            self.approval_evidence.push(Evidence::Tool {
                                tool_name: tool_name.clone(),
                                input,
                                kind: *kind,
                                text: text.clone(),
                                at_ms: *at_ms,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        log.retain(|item| match item {
            LogItem::ToolResult { .. } => false,
            LogItem::Backfill(inner) => !matches!(**inner, LogItem::ToolResult { .. }),
            _ => true,
        });
        let (ends, others): (Vec<_>, Vec<_>) = events
            .iter()
            .cloned()
            .partition(|e| matches!(e, AgentEvent::TurnEnded { .. }));
        for event in others {
            self.chat.on_event(event, now, input_count);
        }
        for item in &log {
            if !matches!(item, LogItem::Problem { .. }) {
                self.chat.on_log(item.clone(), now, input_count);
            }
        }
        for event in ends {
            self.chat.on_event(event, now, input_count);
        }
        self.chat.tick(Instant::now());
        let changed = capabilities != self.capabilities;
        self.capabilities = capabilities;
        self.chat_backlog.push(events, log, input_count);
        self.flush_chat(changed);
        let (state, detail) = if self.capabilities.chat_v1 {
            let status = self.chat.status();
            let state = match status.state {
                State::Ready => Activity::Ready,
                State::Working => Activity::Working,
                State::Waiting => Activity::Waiting,
                State::Unknown => Activity::Unknown,
            };
            (state, status.detail.clone())
        } else {
            (Activity::Unknown, None)
        };
        self.set_activity(state, detail);
    }

    /// What the adapter's chat can't provide (`Capabilities::unavailable`).
    fn unavailable(&self) -> Vec<String> {
        self.capabilities
            .unavailable
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Sends the held chat batches (or, when `always`, at least the
    /// capability) to a connected broker.
    fn flush_chat(&mut self, always: bool) {
        let Some(conn) = &self.conn else { return };
        let chunks = self.chat_backlog.take();
        if always && chunks.is_empty() {
            conn.send(&WorkerMsg::Chat {
                events: Vec::new(),
                log: Vec::new(),
                input_count: self.input.input_count(),
                chat_v1: self.capabilities.chat_v1,
                reason: self.capabilities.reason.clone(),
                unavailable: self.unavailable(),
                gap: 0,
            });
        }
        for chunk in chunks {
            conn.send(&WorkerMsg::Chat {
                events: chunk.events,
                log: chunk.log,
                input_count: chunk.input_count,
                chat_v1: self.capabilities.chat_v1,
                reason: self.capabilities.reason.clone(),
                unavailable: self.unavailable(),
                gap: chunk.gap,
            });
        }
    }
}

/// A write refused for its stale input epoch.
#[derive(Debug)]
struct StaleEpoch;

impl std::fmt::Display for StaleEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stale input epoch")
    }
}

impl std::error::Error for StaleEpoch {}

/// Input consumed after one released waiting hooks (`Worker::consuming`).
struct Consume {
    until: Instant,
    /// The released hooks.
    ids: Vec<String>,
}

/// Input consumed because it handed a waiting approval to the agent's own
/// dialog (nothing written).
fn consumed(seq: u64) -> WorkerMsg {
    WorkerMsg::WriteResult {
        seq,
        ok: false,
        bytes_written: 0,
        dropped: false,
        no_effect: true,
        consumed: true,
        error: Some(super::worker_protocol::APPROVAL_HANDED.into()),
    }
}

fn dropped(seq: u64) -> WorkerMsg {
    WorkerMsg::WriteResult {
        seq,
        ok: false,
        bytes_written: 0,
        dropped: true,
        no_effect: false,
        consumed: false,
        error: None,
    }
}

/// A write refused before anything was queued (no effect).
fn failed(seq: u64, error: String) -> WorkerMsg {
    WorkerMsg::WriteResult {
        seq,
        ok: false,
        bytes_written: 0,
        dropped: false,
        no_effect: true,
        consumed: false,
        error: Some(error),
    }
}

/// Listens on `socket` (0600) in a private directory (0700): a dead socket
/// there is replaced, a live one is `AddrInUse`.
pub fn listen(socket: &Path) -> std::io::Result<UnixListener> {
    let uid = unsafe { libc::getuid() };
    let dir = socket
        .parent()
        .ok_or_else(|| std::io::Error::other("the socket path has no directory"))?;
    if let Some(parent) = dir.parent()
        && parent.file_name().is_some_and(|name| name == "atem")
    {
        crate::daemon::prepare_socket_dir(parent, uid)?;
    }
    crate::daemon::prepare_socket_dir(dir, uid)?;
    crate::daemon::listen_replacing_dead(socket)
}

/// `atem worker --state <dir> --session <id>`: reads the broker's spec,
/// starts the agent when the broker sends `start`, and serves until done.
pub async fn run_worker(state: PathBuf, session_id: String) -> Result<()> {
    if SessionId::parse(&session_id).is_none() {
        bail!("{session_id:?} is not a session id");
    }
    let pid = std::process::id();
    let start_time =
        process_start_time(pid).ok_or_else(|| anyhow!("cannot read this process's start time"))?;
    private_dir(&workers_dir(&state))?;
    let Some(lock) = crate::daemon::lock_exclusive_with_pid(&lock_path(&state, &session_id))?
    else {
        eprintln!("atem worker: another worker serves {session_id}; exiting");
        return Ok(());
    };
    let spec = read_spec(&state, &session_id)?;
    let _ = std::fs::remove_file(spec_path(&state, &session_id));
    let listener = listen(&spec.socket)?;
    eprintln!(
        "atem worker (pid {pid}) for {session_id} ({}) listening on {}",
        spec.provider,
        spec.socket.display()
    );
    let chat_root = crate::chat::claude::hooks::session_dir_root();
    let socket = spec.socket.clone();
    // Approvals as config.toml says at this launch.
    let config = crate::config::AtemConfig::config_path();
    let approvals = |agent| crate::chat::approvals::enabled(&config, agent);
    let options = WorkerOptions {
        state: state.clone(),
        pid,
        start_time,
        chat_root,
        logs: logs_dir(&state),
        uid: unsafe { libc::getuid() },
        first_connect: Duration::from_secs(30),
        linger: crate::session::EXITED_KEEP,
        claude_approvals: approvals(Agent::Claude),
        approval_script: approvals(Agent::Codex).then(crate::chat::codex::script_path),
    };
    let served = serve(spec, listener, options).await;
    if std::fs::symlink_metadata(&socket).is_ok_and(|m| {
        use std::os::unix::fs::FileTypeExt;
        m.file_type().is_socket()
    }) {
        let _ = std::fs::remove_file(&socket);
    }
    let _ = lock.clear_pid();
    eprintln!("atem worker (pid {pid}) for {session_id} exiting");
    // Released (a broker heard the exit) or never started: nothing to adopt,
    // so the lock and log go too. A record that stays keeps them.
    if !record_path(&state, &session_id).exists() {
        remove_leftovers(&state, &session_id);
    }
    served
}

#[cfg(test)]
mod approval_settings_tests {
    use super::*;

    fn spec(provider: &str) -> WorkerSpec {
        WorkerSpec {
            session_id: SessionId::new().to_string(),
            process_gen: uuid::Uuid::new_v4().to_string(),
            provider: provider.into(),
            args: Vec::new(),
            cwd: PathBuf::from("/"),
            rows: 24,
            cols: 80,
            socket: PathBuf::from("/nonexistent.sock"),
        }
    }

    fn settings(launch: &Launch) -> serde_json::Value {
        let at = launch.args.iter().position(|a| a == "--settings").unwrap();
        serde_json::from_str(&std::fs::read_to_string(&launch.args[at + 1]).unwrap()).unwrap()
    }

    /// `[claude] approvals_hook = false`: chat hooks only, nothing watched.
    #[test]
    fn claude_approvals_follow_the_setting() {
        let root = tempfile::tempdir().unwrap();
        for on in [true, false] {
            let launch = agent_command(&spec("claude"), Some(&[]), root.path(), on, None).unwrap();
            let v = settings(&launch);
            assert_eq!(v["hooks"].get("PermissionRequest").is_some(), on);
            assert_eq!(launch.approvals.is_some(), on);
            assert!(v["hooks"].get("Stop").is_some());
        }
    }

    /// Codex approvals off: no stable script, no session directory.
    #[test]
    fn codex_approvals_only_when_consented() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("hooks").join("approval-hook.sh");
        let off = agent_command(&spec("codex"), Some(&[]), root.path(), true, None).unwrap();
        assert!(off.approvals.is_none() && off.adapter.is_none());
        assert!(!script.exists());
        let on =
            agent_command(&spec("codex"), Some(&[]), root.path(), true, Some(&script)).unwrap();
        assert!(matches!(on.adapter, Some(ChatAdapter::Codex(_))));
        let dir = on.approvals.clone().unwrap().0;
        assert!(dir.join("events").is_dir());
        assert!(script.exists());
        // The adapter owns the session directory.
        drop(on);
        assert!(!dir.exists());
    }

    /// `[codex] hooks = true` (a script): the worker merges every hook into
    /// the launch's CODEX_HOME itself, never asking; unset or false (no
    /// script): nothing written. A failed merge is a notice, Codex starts.
    #[test]
    fn a_consented_codex_launch_merges_the_hooks_itself() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("hooks").join("approval-hook.sh");
        let home = root.path().join("codex-home");
        let env = [(OsString::from("CODEX_HOME"), home.clone().into_os_string())];
        let hooks = home.join("hooks.json");
        let off = agent_command(&spec("codex"), Some(&env), root.path(), true, None).unwrap();
        assert!(off.notice.is_none());
        assert!(!home.exists(), "never written without consent");
        let on =
            agent_command(&spec("codex"), Some(&env), root.path(), true, Some(&script)).unwrap();
        assert!(on.notice.is_none(), "{:?}", on.notice);
        let text = std::fs::read_to_string(&hooks).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        for event in crate::chat::codex::EVENTS {
            assert!(v["hooks"][event].is_array(), "{event}");
        }
        // idempotent
        drop(on);
        let again =
            agent_command(&spec("codex"), Some(&env), root.path(), true, Some(&script)).unwrap();
        assert!(again.notice.is_none());
        assert_eq!(std::fs::read_to_string(&hooks).unwrap(), text);
        // a file it can't merge: left as it is, a notice, chat still set up
        std::fs::write(&hooks, "not json").unwrap();
        let bad =
            agent_command(&spec("codex"), Some(&env), root.path(), true, Some(&script)).unwrap();
        assert!(
            bad.notice
                .as_deref()
                .is_some_and(|n| n.contains("hooks.json"))
        );
        assert!(matches!(bad.adapter, Some(ChatAdapter::Codex(_))));
        assert_eq!(std::fs::read_to_string(&hooks).unwrap(), "not json");
    }
}

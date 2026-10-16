//! The broker's side of workers: start one (`spawn`), find and verify the
//! ones that survived an earlier broker (`adopt`), and talk to one
//! (`WorkerHandle`).
//!
//! A worker is adopted only when its `hello` names the session id and
//! process generation of its record and its pid's start time, read from the
//! OS, equals the recorded one — never on a pid alone, which the OS reuses.
//! Anything else leaves the record for the user (`atem agent stop`) and
//! reports the session `recovery_required`; a worker that is gone with its
//! agent is `interrupted` (or `exited`, when it recorded the agent's exit).
//! Nothing is ever restarted or replayed.

use super::protocol::LaunchEnv;
use super::worker::{ANOTHER_BROKER, read_record, socket_dir, workers_dir, write_spec};
use super::worker_protocol::{
    BrokerMsg, MAX_LINE, WorkerMsg, WorkerRecord, WorkerSpec, decode_worker, encode_broker,
};
use crate::session::SessionId;
use anyhow::{Result, anyhow, bail};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

/// How long a broker waits for a worker's `hello`.
const HELLO_WAIT: Duration = Duration::from_secs(10);
/// Worker messages a broker holds before the worker's stream waits.
const EVENT_QUEUE: usize = 1024;

/// When process `pid` started, as the OS reports it: Linux `/proc/<pid>/stat`
/// field 22 (clock ticks since boot), macOS `proc_pidinfo` (microseconds
/// since the epoch). `None` when the process is gone or can't be read.
pub fn process_start_time(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        parse_stat_start_time(&stat)
    }
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is a proc_bsdinfo of the size passed.
        let written = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if written != size {
            return None;
        }
        Some(
            info.pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Field 22 (`starttime`) of a `/proc/<pid>/stat` line. The command name
/// (field 2) is in parentheses and may hold spaces and parentheses itself,
/// so fields are counted after its last `)`.
pub fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // Field 3 (state) is the first after the name: field 22 is the 20th.
    rest.split_ascii_whitespace().nth(19)?.parse().ok()
}

/// Where workers live and what runs them.
#[derive(Clone, Debug)]
pub struct WorkerPaths {
    /// The `atem` executable.
    pub exe: PathBuf,
    /// The broker's state dir (`<state>/workers/`).
    pub state: PathBuf,
    /// The sockets' directory.
    pub socket_dir: PathBuf,
}

impl WorkerPaths {
    pub fn new(state: &Path, runtime_dir: Option<OsString>) -> Result<Self> {
        Ok(Self {
            exe: std::env::current_exe()?,
            state: state.to_path_buf(),
            socket_dir: socket_dir(state, runtime_dir),
        })
    }
}

/// A new session for `spawn`.
#[derive(Clone, Debug)]
pub struct SpawnRequest {
    pub session_id: SessionId,
    /// UUID v4.
    pub process_gen: String,
    pub provider: crate::session::Provider,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub rows: u16,
    pub cols: u16,
}

/// What `hello` told about a worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerInfo {
    pub session_id: String,
    pub process_gen: String,
    pub pid: u32,
    pub start_time: u64,
    pub agent_pid: Option<u32>,
    pub offset: u64,
    pub input_epoch: u64,
    pub dropped: u64,
    pub exited: Option<String>,
}

/// The broker's connection to one worker. Messages to it go out in the order
/// they are sent here (one writer), so a `set_epoch` before a `write`
/// reaches the worker first.
pub struct WorkerHandle {
    pub info: WorkerInfo,
    tx: mpsc::UnboundedSender<String>,
    events: mpsc::Receiver<WorkerMsg>,
}

impl std::fmt::Debug for WorkerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerHandle")
            .field("info", &self.info)
            .finish()
    }
}

impl WorkerHandle {
    fn send(&self, message: &BrokerMsg) -> Result<()> {
        self.tx
            .send(encode_broker(message))
            .map_err(|_| anyhow!("the worker for {} is gone", self.info.session_id))
    }

    /// Terminal input, written if `input_epoch` is still current at the
    /// worker's write boundary → `write_result`.
    pub fn write(&self, seq: u64, bytes: &[u8], input_epoch: u64) -> Result<()> {
        self.send(&BrokerMsg::write(seq, bytes, input_epoch))
    }

    /// A bracketed paste plus Enter, under the same rule → `write_result`.
    #[allow(dead_code)] // chat-v1 submit, with the session host
    pub fn paste(&self, seq: u64, text: &str, input_epoch: u64) -> Result<()> {
        self.send(&BrokerMsg::Paste {
            seq,
            text: text.into(),
            input_epoch,
        })
    }

    pub fn set_epoch(&self, epoch: u64) -> Result<()> {
        self.send(&BrokerMsg::SetInputEpoch { epoch })
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.send(&BrokerMsg::Resize { rows, cols })
    }

    /// Stops the agent (`exited` follows); after `exited`, releases the worker.
    pub fn stop(&self) -> Result<()> {
        self.send(&BrokerMsg::Stop)
    }

    /// → `screen`
    pub fn request_screen(&self) -> Result<()> {
        self.send(&BrokerMsg::RequestScreen)
    }

    /// The worker's next message; `None` once its connection closed.
    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<WorkerMsg> {
        self.events.recv().await
    }

    /// The next message already received, `Empty` when there is none yet,
    /// `Disconnected` once the connection closed and everything was read.
    pub fn try_next(&mut self) -> Result<WorkerMsg, mpsc::error::TryRecvError> {
        self.events.try_recv()
    }

    /// Connects to a worker's socket (same user; on Linux also its pid),
    /// sends `start` first when given, and verifies its `hello` against
    /// `expect`: session id, process generation, pid, and a start time equal
    /// to the OS's for that pid.
    pub async fn connect(
        socket: &Path,
        expect: &Expect,
        start: Option<Option<LaunchEnv>>,
    ) -> Result<Self> {
        let stream = UnixStream::connect(socket)
            .await
            .map_err(|e| anyhow!("cannot reach the worker at {}: {e}", socket.display()))?;
        let cred = stream.peer_cred()?;
        if cred.uid() != unsafe { libc::getuid() } {
            bail!(
                "the worker socket {} belongs to another user",
                socket.display()
            );
        }
        if let Some(pid) = cred.pid()
            && pid as u32 != expect.pid
        {
            bail!(
                "the worker socket is served by pid {pid}, not {}",
                expect.pid
            );
        }
        let (read, mut write) = stream.into_split();
        if let Some(env) = start {
            write
                .write_all(encode_broker(&BrokerMsg::Start { env }).as_bytes())
                .await?;
        }
        let mut reader = BufReader::new(read);
        let mut line = Vec::new();
        let first = tokio::time::timeout(
            HELLO_WAIT,
            super::server::read_line_max(&mut reader, &mut line, MAX_LINE),
        )
        .await
        .map_err(|_| anyhow!("the worker didn't say hello"))??;
        if !first {
            bail!("the worker closed the connection");
        }
        let info = match decode_worker(std::str::from_utf8(&line)?).map_err(|e| anyhow!(e))? {
            WorkerMsg::Hello {
                session_id,
                process_gen,
                pid,
                start_time,
                agent_pid,
                offset,
                input_epoch,
                dropped,
                exited,
            } => WorkerInfo {
                session_id,
                process_gen,
                pid,
                start_time,
                agent_pid,
                offset,
                input_epoch,
                dropped,
                exited,
            },
            WorkerMsg::Error { text } => bail!("the worker refused: {text}"),
            other => bail!("the worker sent {other:?} before hello"),
        };
        expect.check(&info)?;
        let (tx, mut out) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = out.recv().await {
                if write.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
            let _ = write.shutdown().await;
        });
        let (event_tx, events) = mpsc::channel(EVENT_QUEUE);
        tokio::spawn(async move {
            let mut line = Vec::new();
            while let Ok(true) =
                super::server::read_line_max(&mut reader, &mut line, MAX_LINE).await
            {
                // A line that isn't a message is reported, and reading goes on.
                let message = match std::str::from_utf8(&line) {
                    Ok(text) => {
                        decode_worker(text).unwrap_or_else(|text| WorkerMsg::Error { text })
                    }
                    Err(_) => WorkerMsg::Error {
                        text: "the worker sent a line that isn't UTF-8".into(),
                    },
                };
                if event_tx.send(message).await.is_err() {
                    break;
                }
            }
        });
        Ok(Self { info, tx, events })
    }
}

/// What a worker's `hello` must say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expect {
    pub session_id: String,
    pub process_gen: String,
    pub pid: u32,
    /// `None`: the start time the OS reports for `pid` now.
    pub start_time: Option<u64>,
}

impl Expect {
    fn check(&self, info: &WorkerInfo) -> Result<()> {
        if info.session_id != self.session_id || info.process_gen != self.process_gen {
            bail!(
                "the worker serves {} ({}), not {} ({})",
                info.session_id,
                info.process_gen,
                self.session_id,
                self.process_gen
            );
        }
        if info.pid != self.pid {
            bail!("the worker is pid {}, not {}", info.pid, self.pid);
        }
        let os = process_start_time(self.pid)
            .ok_or_else(|| anyhow!("pid {} is gone or unreadable", self.pid))?;
        if info.start_time != os || self.start_time.is_some_and(|recorded| recorded != os) {
            bail!(
                "pid {} started at {os}, not at the recorded time (a reused pid)",
                self.pid
            );
        }
        Ok(())
    }
}

/// Starts a worker for `request` (detached, own session and log) and
/// connects to it: the spec goes to disk without the environment, which is
/// sent in `start`.
pub async fn spawn(
    paths: &WorkerPaths,
    request: &SpawnRequest,
    env: Option<LaunchEnv>,
) -> Result<WorkerHandle> {
    if let Some(env) = &env {
        crate::session::check_env(&env.to_os()).map_err(|e| anyhow!(e))?;
    }
    let sid = request.session_id.as_str();
    let spec = WorkerSpec {
        session_id: sid.to_string(),
        process_gen: request.process_gen.clone(),
        provider: request.provider.as_str().to_string(),
        args: request.args.clone(),
        cwd: request.cwd.clone(),
        rows: request.rows,
        cols: request.cols,
        socket: paths.socket_dir.join(format!("{sid}.sock")),
    };
    write_spec(&paths.state, &spec)?;
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
    let state = paths.state.as_os_str();
    let pid = crate::daemon::spawn_detached_args(
        &paths.exe,
        &[
            "worker".as_ref(),
            "--state".as_ref(),
            state,
            "--session".as_ref(),
            sid.as_ref(),
        ],
        &home,
        &super::worker::log_path(&paths.state, sid),
        &[],
    )?;
    let expect = Expect {
        session_id: sid.to_string(),
        process_gen: request.process_gen.clone(),
        pid,
        start_time: None,
    };
    let mut last = anyhow!("the worker didn't start listening");
    for _ in 0..100 {
        if spec.socket.exists() {
            match WorkerHandle::connect(&spec.socket, &expect, Some(env.clone())).await {
                Ok(handle) => return Ok(handle),
                Err(error) => {
                    // A connection that got as far as `start` is not retried.
                    if !error.to_string().starts_with("cannot reach") {
                        return Err(error);
                    }
                    last = error;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = std::fs::remove_file(super::worker::spec_path(&paths.state, sid));
    Err(last)
}

/// One worker record, as the broker found it at start.
#[derive(Debug)]
pub enum Adoption {
    /// Verified and connected; the record says what the session is.
    Adopted(WorkerHandle, WorkerRecord),
    /// The worker or its record can't be trusted, or the agent outlived its
    /// worker: the record stays for the user to clean up.
    RecoveryRequired {
        session_id: String,
        record: Option<WorkerRecord>,
        reason: String,
    },
    /// The worker and its agent are gone without a recorded exit.
    Interrupted { record: WorkerRecord },
    /// The worker is gone after recording the agent's exit.
    Exited {
        record: WorkerRecord,
        status: String,
    },
}

impl Adoption {
    pub fn session_id(&self) -> &str {
        match self {
            Adoption::Adopted(handle, _) => &handle.info.session_id,
            Adoption::RecoveryRequired { session_id, .. } => session_id,
            Adoption::Interrupted { record } | Adoption::Exited { record, .. } => {
                &record.session_id
            }
        }
    }

    /// The session's state name.
    pub fn status(&self) -> &'static str {
        match self {
            Adoption::Adopted(..) => "running",
            Adoption::RecoveryRequired { .. } => "recovery_required",
            Adoption::Interrupted { .. } => "interrupted",
            Adoption::Exited { .. } => "exited",
        }
    }
}

/// `pid` runs and started at `start_time`.
fn same_process(pid: Option<u32>, start_time: Option<u64>) -> bool {
    match (pid, start_time) {
        (Some(pid), Some(start)) => process_start_time(pid) == Some(start),
        _ => false,
    }
}

/// Retries of an adoption refused because another broker is connected.
const ADOPT_RETRIES: usize = 3;
const ADOPT_RETRY_DELAY: Duration = Duration::from_millis(300);

async fn connect_record(
    socket: &Path,
    expect: &Expect,
) -> Result<Result<WorkerHandle>, tokio::time::error::Elapsed> {
    tokio::time::timeout(HELLO_WAIT, WorkerHandle::connect(socket, expect, None)).await
}

/// The worker record at `path` (session `session_id`), checked and adopted.
pub async fn adopt_record(path: &Path, session_id: &str) -> Adoption {
    let record = match read_record(path) {
        Ok(record) if record.session_id == session_id => record,
        Ok(_) => {
            return Adoption::RecoveryRequired {
                session_id: session_id.into(),
                record: None,
                reason: "the worker record names another session".into(),
            };
        }
        Err(error) => {
            return Adoption::RecoveryRequired {
                session_id: session_id.into(),
                record: None,
                reason: format!("{error:#}"),
            };
        }
    };
    match process_start_time(record.worker_pid) {
        Some(start) if start == record.start_time => {}
        Some(_) => {
            // A live pid that started at another time: reused, or a forged
            // record. Never adopted.
            return Adoption::RecoveryRequired {
                session_id: session_id.into(),
                reason: format!(
                    "pid {} is not the recorded worker (its start time differs)",
                    record.worker_pid
                ),
                record: Some(record),
            };
        }
        None => {}
    }
    if process_start_time(record.worker_pid).is_none() {
        if same_process(record.agent_pid, record.agent_start_time) {
            return Adoption::RecoveryRequired {
                session_id: session_id.into(),
                reason: "the worker is gone but its agent still runs".into(),
                record: Some(record),
            };
        }
        return match record.exited.clone() {
            Some(status) => Adoption::Exited { record, status },
            None => Adoption::Interrupted { record },
        };
    }
    let expect = Expect {
        session_id: record.session_id.clone(),
        process_gen: record.process_gen.clone(),
        pid: record.worker_pid,
        start_time: Some(record.start_time),
    };
    let mut connected = connect_record(&record.socket, &expect).await;
    // An old broker that is just closing still holds the worker for a moment.
    for _ in 0..ADOPT_RETRIES {
        match &connected {
            Ok(Err(error)) if error.to_string().contains(ANOTHER_BROKER) => {
                tokio::time::sleep(ADOPT_RETRY_DELAY).await;
                connected = connect_record(&record.socket, &expect).await;
            }
            _ => break,
        }
    }
    match connected {
        Ok(Ok(handle)) => Adoption::Adopted(handle, record),
        Ok(Err(error)) => Adoption::RecoveryRequired {
            session_id: session_id.into(),
            reason: format!("{error:#}"),
            record: Some(record),
        },
        Err(_) => Adoption::RecoveryRequired {
            session_id: session_id.into(),
            reason: "the worker didn't answer".into(),
            record: Some(record),
        },
    }
}

/// The worker records under `<state>/workers/` (session id, path), in
/// session id order.
pub fn records(state: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(workers_dir(state)) else {
        return Vec::new();
    };
    let mut found: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let sid = name.strip_suffix(".json")?;
            SessionId::parse(sid)?;
            Some((sid.to_string(), entry.path()))
        })
        .collect();
    found.sort();
    found
}

/// Every worker record under `<state>/workers/`, checked and adopted, in
/// session id order.
#[cfg(test)]
pub async fn adopt(state: &Path) -> Vec<Adoption> {
    let mut adopted = Vec::new();
    for (sid, path) in records(state) {
        adopted.push(adopt_record(&path, &sid).await);
    }
    adopted
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;

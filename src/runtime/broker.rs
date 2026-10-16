//! The broker's sessions (`atem runtime`): every agent session runs in an
//! `atem worker` (worker.rs) that the broker started (`launch`) or adopted
//! at start (adopt.rs). The broker keeps one `BrokerSession` per session:
//! identity (session id, process generation, provider, cwd, creation time),
//! the worker connection, a mirror of the canonical screen, chat state, the
//! activity the worker reports, the input epoch and the exit.
//!
//! Screen: the mirror is fed from the worker's `output` and replaced by its
//! `screen`, so a local restore (and terminal-v1 frames) come from the broker
//! without a round trip to the worker. A worker that may already have
//! produced output (every adopted one) is asked for its `screen` first; a
//! frontend attaching before it arrives gets its restore when it does. A gap
//! in the output stream (the worker skipped output for a slow broker) makes
//! the mirror wait for the next `screen` the same way.
//!
//! Input: the broker is the only writer authority. Each session has an input
//! epoch: at start the worker's `hello.input_epoch` (max with the journal's
//! lease-epoch floor once there is a journal), raised with `set_input_epoch`
//! whenever control changes (a local `reclaim`), and every `write` carries
//! the current one, so bytes queued under an older epoch are dropped at the
//! worker's write boundary. The broker never tags a write with an epoch it
//! didn't grant.
//!
//! Exit: once the broker recorded a worker's `exited` it sends the release
//! `stop`, and the worker removes its record and ends; the session stays
//! (final screen) until reaped `EXITED_KEEP` later. A worker connection that
//! closes without an exit leaves the session `interrupted`, its record kept.

use super::adopt::{self, Adoption, SpawnRequest, WorkerHandle};
use super::protocol::{LaunchEnv, SessionSummary};
use super::worker_protocol::{Activity, WorkerMsg, WorkerRecord, unb64};
use crate::chat::adapter::{AgentEvent, LogItem};
use crate::chat::session::ChatSession;
use crate::session::{OutputTap, SessionId};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

/// Writes sent to a worker and not yet answered, per session; a frontend's
/// further input waits (stays unread) meanwhile. Below the worker's PTY
/// queue (64), which terminal replies share.
pub const MAX_IN_FLIGHT: usize = 32;
/// Worker messages handled per session per pass.
const PER_PASS: usize = 256;
/// The mirror's size until an adopted worker's screen arrives.
const UNKNOWN_SIZE: (u16, u16) = (24, 80);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A session's lifecycle as the broker knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The worker is connected and the agent runs.
    Running,
    /// The agent exited (the final screen is kept).
    Exited,
    /// The worker went away without a recorded exit.
    Interrupted,
    /// The worker or its record can't be trusted (see adopt.rs).
    RecoveryRequired,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::Running => "running",
            SessionState::Exited => "exited",
            SessionState::Interrupted => "interrupted",
            SessionState::RecoveryRequired => "recovery_required",
        }
    }
}

fn activity_name(activity: Activity) -> &'static str {
    match activity {
        Activity::Ready => "ready",
        Activity::Working => "working",
        Activity::Waiting => "waiting",
        Activity::Unknown => "unknown",
    }
}

pub struct BrokerSession {
    pub id: SessionId,
    pub process_gen: String,
    pub provider: String,
    pub cwd: PathBuf,
    pub created_at_ms: u64,
    pub state: SessionState,
    /// The connection to the worker; `None` once it closed.
    worker: Option<WorkerHandle>,
    /// The worker record, for a session without a worker (what the user may
    /// remove with `stop`).
    record: Option<WorkerRecord>,
    /// The exit status, or why the session isn't running.
    pub exit_status: Option<String>,
    pub exited_at: Option<Instant>,
    /// The release `stop` was sent.
    released: bool,
    /// The canonical screen's mirror.
    screen: vt100::Parser,
    /// The mirror is current (else it waits for the worker's `screen`).
    synced: bool,
    screen_requested: bool,
    /// Output stream position the mirror covers.
    offset: u64,
    /// Raw output for an attached local frontend.
    pub tap: OutputTap,
    /// The input epoch writes are tagged with.
    input_epoch: u64,
    next_seq: u64,
    /// Writes sent and not yet answered: seq → bytes.
    in_flight: std::collections::BTreeMap<u64, usize>,
    /// Writes the worker dropped for a stale epoch.
    pub dropped_writes: u64,
    /// chat-v1 state, fed from the worker's `chat` batches.
    pub chat: ChatSession,
    pub chat_v1: bool,
    pub chat_reason: Option<String>,
    pub activity: Activity,
    pub activity_detail: Option<String>,
}

/// What one pass over a worker's messages changed.
#[derive(Debug, Default)]
pub struct Pumped {
    /// The mirror was replaced: attached frontends need a fresh restore.
    pub resync: bool,
    /// Errors of writes the worker failed (not dropped).
    pub failed: Vec<String>,
    /// Bytes of writes dropped for a stale input epoch.
    pub dropped_bytes: usize,
    /// The agent exited, or the worker went away, in this pass.
    pub ended: bool,
}

impl BrokerSession {
    fn new(
        id: SessionId,
        process_gen: String,
        provider: String,
        cwd: PathBuf,
        created_at_ms: u64,
        (rows, cols): (u16, u16),
    ) -> Self {
        let chat = ChatSession::new(process_gen.clone(), now_ms());
        Self {
            id,
            process_gen,
            provider,
            cwd,
            created_at_ms,
            state: SessionState::Running,
            worker: None,
            record: None,
            exit_status: None,
            exited_at: None,
            released: false,
            screen: vt100::Parser::new(rows, cols, crate::pty_session::SCROLLBACK_ROWS),
            synced: false,
            screen_requested: false,
            offset: 0,
            tap: OutputTap::default(),
            input_epoch: 0,
            next_seq: 0,
            in_flight: Default::default(),
            dropped_writes: 0,
            chat,
            chat_v1: false,
            chat_reason: None,
            activity: Activity::Unknown,
            activity_detail: None,
        }
    }

    /// A session the broker just started (`request`) in `handle`'s worker,
    /// created at `created_at_ms` (the worker record's).
    pub fn launched(handle: WorkerHandle, request: &SpawnRequest, created_at_ms: u64) -> Self {
        let mut session = Self::new(
            request.session_id.clone(),
            request.process_gen.clone(),
            request.provider.as_str().to_string(),
            request.cwd.clone(),
            created_at_ms,
            (request.rows.clamp(2, 200), request.cols.clamp(2, 400)),
        );
        // A worker that produced nothing yet has the blank screen of the
        // launch size; anything else is asked for.
        let fresh = handle.info.offset == 0 && handle.info.exited.is_none();
        session.connect(handle, fresh);
        session
    }

    /// A session found at start: an adopted worker, or a record without one.
    /// `None` for an adoption whose session id isn't valid.
    pub fn from_adoption(adoption: Adoption) -> Option<Self> {
        let sid = SessionId::parse(adoption.session_id())?;
        let from_record = |record: &WorkerRecord| {
            Self::new(
                sid.clone(),
                record.process_gen.clone(),
                record.provider.clone(),
                record.cwd.clone(),
                record.created_at_ms,
                UNKNOWN_SIZE,
            )
        };
        Some(match adoption {
            Adoption::Adopted(handle, record) => {
                let mut session = from_record(&record);
                session.connect(handle, false);
                session
            }
            Adoption::Exited { record, status } => {
                let mut session = from_record(&record);
                session.end(SessionState::Exited, status);
                session
            }
            Adoption::Interrupted { record } => {
                let mut session = from_record(&record);
                session.end(SessionState::Interrupted, "interrupted".into());
                session.record = Some(record);
                session
            }
            Adoption::RecoveryRequired { record, reason, .. } => {
                let mut session = match &record {
                    Some(record) => from_record(record),
                    None => Self::new(
                        sid.clone(),
                        String::new(),
                        "unknown".into(),
                        PathBuf::new(),
                        0,
                        UNKNOWN_SIZE,
                    ),
                };
                session.end(
                    SessionState::RecoveryRequired,
                    format!("recovery required: {reason}"),
                );
                session.record = record;
                session
            }
        })
    }

    fn connect(&mut self, handle: WorkerHandle, synced: bool) {
        // No journal yet: the worker's epoch is the floor.
        self.input_epoch = handle.info.input_epoch;
        self.offset = handle.info.offset;
        self.tap.restart_at(self.offset);
        self.synced = synced;
        let exited = handle.info.exited.clone();
        self.worker = Some(handle);
        if !synced {
            self.request_screen();
        }
        if let Some(status) = exited {
            self.record_exit(status);
        }
    }

    fn request_screen(&mut self) {
        if self.screen_requested {
            return;
        }
        if let Some(worker) = &self.worker
            && worker.request_screen().is_ok()
        {
            self.screen_requested = true;
        }
    }

    /// Not running any more: `state` with `status`.
    fn end(&mut self, state: SessionState, status: String) {
        self.state = state;
        self.exit_status = Some(status);
        self.exited_at = Some(Instant::now());
        self.in_flight.clear();
        self.chat.on_process_exit(now_ms());
        self.activity = Activity::Unknown;
        self.activity_detail = None;
    }

    /// Records the agent's exit (once), then releases the worker.
    fn record_exit(&mut self, status: String) {
        if self.state == SessionState::Running {
            self.end(SessionState::Exited, status);
        }
        if !self.released
            && let Some(worker) = &self.worker
            && worker.stop().is_ok()
        {
            self.released = true;
        }
    }

    pub fn is_live(&self) -> bool {
        self.state == SessionState::Running && self.worker.is_some()
    }

    /// A screen to attach to (running, or exited with its final screen).
    pub fn has_screen(&self) -> bool {
        matches!(self.state, SessionState::Running | SessionState::Exited)
            && (self.worker.is_some() || self.synced)
    }

    #[cfg(test)]
    pub fn input_epoch(&self) -> u64 {
        self.input_epoch
    }

    /// Another write may be sent now.
    pub fn can_write(&self) -> bool {
        self.in_flight.len() < MAX_IN_FLIGHT
    }

    /// Writes `bytes` under the current input epoch.
    pub fn write(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        if !self.is_live() {
            anyhow::bail!("The session has ended");
        }
        let worker = self.worker.as_ref().expect("live");
        let seq = self.next_seq;
        worker.write(seq, bytes, self.input_epoch)?;
        self.next_seq += 1;
        self.in_flight.insert(seq, bytes.len());
        Ok(())
    }

    /// Control changed: a new epoch, sent to the worker before any write
    /// under it, so writes queued under the old one are dropped.
    pub fn raise_input_epoch(&mut self) -> anyhow::Result<u64> {
        let Some(worker) = self.worker.as_ref().filter(|_| self.is_live()) else {
            anyhow::bail!("The session has ended");
        };
        let epoch = self.input_epoch + 1;
        worker.set_epoch(epoch)?;
        self.input_epoch = epoch;
        Ok(epoch)
    }

    /// Resizes the agent's terminal and the mirror (a live session, a new size).
    pub fn resize(&mut self, rows: u16, cols: u16) -> anyhow::Result<()> {
        let (rows, cols) = (rows.min(200), cols.min(400));
        // Until the screen arrives the mirror's size says nothing: always sent.
        if rows < 2 || cols < 2 || !self.is_live() || (self.synced && self.size() == (rows, cols)) {
            return Ok(());
        }
        self.worker.as_ref().expect("live").resize(rows, cols)?;
        self.screen.set_size(rows, cols);
        Ok(())
    }

    /// Stops the agent; its exit follows.
    pub fn stop(&self) -> anyhow::Result<()> {
        match &self.worker {
            Some(worker) if self.is_live() => worker.stop(),
            _ => anyhow::bail!("The session has ended"),
        }
    }

    pub fn size(&self) -> (u16, u16) {
        self.screen.screen().size()
    }

    pub fn synced(&self) -> bool {
        self.synced
    }

    /// A screen is still to come from the worker (it isn't current yet and
    /// the worker is connected).
    pub fn screen_pending(&self) -> bool {
        !self.synced && self.worker.is_some()
    }

    /// A fresh restore of the mirror and the stream position output
    /// continues from (what the tap held is covered by it); `None` until the
    /// mirror is current.
    pub fn restore(&mut self) -> Option<(Vec<u8>, u64)> {
        if !self.synced {
            return None;
        }
        let bytes = crate::terminal_share::restore_bytes(self.screen.screen());
        self.tap.take();
        Some((bytes, self.offset))
    }

    /// The record this session's worker left, when it has no worker.
    pub fn record(&self) -> Option<&WorkerRecord> {
        self.record.as_ref()
    }

    pub fn summary(&self, attached: bool) -> SessionSummary {
        let (rows, cols) = self.size();
        SessionSummary {
            id: self.id.to_string(),
            provider: self.provider.clone(),
            cwd: self.cwd.clone(),
            created_at_ms: self.created_at_ms,
            state: self.state.as_str().into(),
            status: activity_name(self.activity).into(),
            attached,
            // Remote control leases come with the session host.
            remote_controlled: false,
            exited: self.exit_status.clone(),
            rows,
            cols,
            generation: self.process_gen.clone(),
        }
    }

    /// Handles what the worker sent since the last pass (bounded), and
    /// notices a closed connection.
    pub fn pump(&mut self) -> Pumped {
        let mut pumped = Pumped::default();
        for _ in 0..PER_PASS {
            let Some(worker) = self.worker.as_mut() else {
                break;
            };
            match worker.try_next() {
                Ok(message) => self.apply(message, &mut pumped),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.worker = None;
                    if self.state == SessionState::Running {
                        eprintln!(
                            "atem runtime: the worker of {} went away without an exit",
                            self.id
                        );
                        self.end(SessionState::Interrupted, "interrupted".into());
                        pumped.ended = true;
                    }
                    break;
                }
            }
        }
        self.chat.tick(Instant::now());
        pumped
    }

    fn apply(&mut self, message: WorkerMsg, pumped: &mut Pumped) {
        match message {
            WorkerMsg::Output { bytes, offset } => {
                let Some(bytes) = unb64(&bytes) else { return };
                self.output(&bytes, offset);
            }
            WorkerMsg::Screen {
                restore,
                offset,
                rows,
                cols,
            } => {
                let Some(restore) = unb64(&restore) else {
                    return;
                };
                let mut screen = vt100::Parser::new(
                    rows.max(2),
                    cols.max(2),
                    crate::pty_session::SCROLLBACK_ROWS,
                );
                screen.process(&restore);
                self.screen = screen;
                self.offset = offset;
                self.tap.restart_at(offset);
                self.synced = true;
                self.screen_requested = false;
                pumped.resync = true;
            }
            WorkerMsg::Chat {
                events,
                log,
                input_count,
                chat_v1,
                reason,
                gap: _,
            } => {
                // The App's order: events, the log, then turn ends.
                let now = now_ms();
                let (ends, others): (Vec<_>, Vec<_>) = events
                    .into_iter()
                    .partition(|e| matches!(e, AgentEvent::TurnEnded));
                for event in others {
                    self.chat.on_event(event, now, input_count);
                }
                for item in log {
                    if !matches!(item, LogItem::Problem { .. }) {
                        self.chat.on_log(item, now, input_count);
                    }
                }
                for event in ends {
                    self.chat.on_event(event, now, input_count);
                }
                self.chat_v1 = chat_v1;
                self.chat_reason = reason;
            }
            WorkerMsg::Activity { state, detail } => {
                if self.state == SessionState::Running {
                    self.activity = state;
                    self.activity_detail = detail;
                }
            }
            WorkerMsg::Exited { status } => {
                let was_running = self.state == SessionState::Running;
                self.record_exit(status);
                pumped.ended |= was_running;
            }
            WorkerMsg::WriteResult {
                seq,
                ok,
                dropped,
                error,
                ..
            } => {
                let bytes = self.in_flight.remove(&seq).unwrap_or(0);
                if dropped {
                    self.dropped_writes += 1;
                    pumped.dropped_bytes += bytes;
                } else if !ok {
                    pumped
                        .failed
                        .push(error.unwrap_or_else(|| "the write failed".into()));
                }
            }
            WorkerMsg::Error { text } => {
                eprintln!("atem runtime: worker of {}: {text}", self.id);
            }
            WorkerMsg::Hello { .. } => {}
        }
    }

    /// Output at stream position `offset`: the part past the mirror's
    /// position goes into it; a gap waits for a fresh screen.
    fn output(&mut self, bytes: &[u8], offset: u64) {
        if !self.synced {
            return;
        }
        if offset > self.offset {
            self.synced = false;
            self.request_screen();
            return;
        }
        let end = offset + bytes.len() as u64;
        if end <= self.offset {
            return;
        }
        let new = &bytes[(self.offset - offset) as usize..];
        self.screen.process(new);
        self.tap.record(new);
        self.offset = end;
    }
}

/// How the broker starts workers.
#[derive(Clone, Debug)]
pub enum Launcher {
    /// `atem worker` processes, detached.
    Process(adopt::WorkerPaths),
    /// Tests: `worker::serve` on a task of this process.
    #[cfg(test)]
    InProcess(InProcess),
}

impl Launcher {
    /// The broker's state dir (worker records).
    pub fn state(&self) -> &Path {
        match self {
            Launcher::Process(paths) => &paths.state,
            #[cfg(test)]
            Launcher::InProcess(in_process) => &in_process.state,
        }
    }

    /// Starts a worker for `request` with the launch environment `env`;
    /// also the creation time its record names.
    pub async fn spawn(
        self,
        request: SpawnRequest,
        env: LaunchEnv,
    ) -> anyhow::Result<(WorkerHandle, u64)> {
        let state = self.state().to_path_buf();
        let handle = match self {
            Launcher::Process(paths) => adopt::spawn(&paths, &request, Some(env)).await?,
            #[cfg(test)]
            Launcher::InProcess(in_process) => in_process.spawn(request.clone(), env).await?,
        };
        let path = super::worker::record_path(&state, request.session_id.as_str());
        let created_at_ms = super::worker::read_record(&path)
            .map_or(now_ms() as u64, |record| record.created_at_ms);
        Ok((handle, created_at_ms))
    }
}

/// Workers served in this process (tests).
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct InProcess {
    pub state: PathBuf,
    pub socket_dir: PathBuf,
    pub chat_root: PathBuf,
}

#[cfg(test)]
impl InProcess {
    async fn spawn(self, request: SpawnRequest, env: LaunchEnv) -> anyhow::Result<WorkerHandle> {
        use super::worker::{self, WorkerOptions};
        crate::session::check_env(&env.to_os()).map_err(|e| anyhow::anyhow!(e))?;
        let sid = request.session_id.to_string();
        let spec = super::worker_protocol::WorkerSpec {
            session_id: sid.clone(),
            process_gen: request.process_gen.clone(),
            provider: request.provider.as_str().to_string(),
            args: request.args.clone(),
            cwd: request.cwd.clone(),
            rows: request.rows,
            cols: request.cols,
            socket: self.socket_dir.join(format!("{sid}.sock")),
        };
        let listener = worker::listen(&spec.socket)?;
        let pid = std::process::id();
        let options = WorkerOptions {
            state: self.state.clone(),
            pid,
            start_time: adopt::process_start_time(pid).expect("own start time"),
            chat_root: self.chat_root.clone(),
            uid: unsafe { libc::getuid() },
            first_connect: std::time::Duration::from_secs(10),
            linger: std::time::Duration::from_secs(30),
        };
        let socket = spec.socket.clone();
        tokio::spawn(worker::serve(spec, listener, options));
        let expect = adopt::Expect {
            session_id: sid,
            process_gen: request.process_gen,
            pid,
            start_time: None,
        };
        WorkerHandle::connect(&socket, &expect, Some(Some(env))).await
    }
}

/// Adopts the workers under `state` one by one, sending each outcome.
pub async fn adopt_all(state: PathBuf, tx: mpsc::UnboundedSender<Adoption>) {
    for (sid, path) in adopt::records(&state) {
        if tx.send(adopt::adopt_record(&path, &sid).await).is_err() {
            return;
        }
    }
}

/// Removes the worker record of `session_id` (its exit was recorded, or the
/// user stopped a session that has no worker). The lock and log stay.
pub fn remove_record(state: &Path, session_id: &str) {
    let _ = std::fs::remove_file(super::worker::record_path(state, session_id));
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;

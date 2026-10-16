//! The runtime's host loop: the agent sessions (each in an `atem worker`,
//! see broker.rs), one `App` (no TUI, the Astation connection) ticked every
//! 16 ms, and local frontends on a same-user Unix socket. Each client has a
//! reader and a writer task; sessions and the `App` stay on the host loop,
//! which they reach through channels. Launches and adoptions run on their
//! own tasks and report back, so a slow worker never stalls the loop.

use super::adopt::{Adoption, SpawnRequest, WorkerHandle};
use super::broker::{BrokerSession, Launcher, SessionState};
use super::protocol::{
    ClientMsg, DecodeError, MAX_OUTPUT, PROTOCOL, RuntimeMsg, SessionSummary, b64, encode_runtime,
    input_bytes,
};
use crate::app::App;
use crate::session::{EXITED_KEEP, Provider, SessionId, Sessions};
use futures_util::FutureExt;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Notify, mpsc};

/// Unsent output per frontend before its stream is dropped for a fresh restore.
pub const BACKLOG_LIMIT: usize = 256 * 1024;
/// Without sessions or clients for this long, the runtime exits.
pub const IDLE_EXIT: Duration = Duration::from_secs(10 * 60);
const TICK: Duration = Duration::from_millis(16);
/// Messages one client may queue before its reader waits.
const CLIENT_QUEUE: usize = 8;
/// Messages handled per client per pass, so one client can't starve others.
const PER_PASS: usize = 64;
/// The prefix of the error a runtime without live sessions sends before it
/// exits for a client of another protocol (`client::RESTARTING` matches it).
pub const RESTARTING: &str = "This runtime speaks another protocol and is restarting";

pub struct Options {
    /// Exit after this long with no sessions and no clients.
    pub idle: Duration,
    /// Peers must run as this user.
    pub uid: u32,
    /// Starts workers; its state dir holds the worker records adopted at start.
    pub launcher: Launcher,
}

/// A launch that finished on its task.
struct LaunchDone {
    client: u64,
    request: SpawnRequest,
    /// The worker and the session's creation time.
    result: anyhow::Result<(WorkerHandle, u64)>,
}

/// A line read from a client.
enum Incoming {
    Message(ClientMsg),
    Bad(DecodeError),
}

enum Outgoing {
    /// `cost`: raw output bytes it carries (counted against the backlog).
    /// `epoch`: dropped when the client's epoch moved past it.
    Line {
        line: String,
        cost: usize,
        epoch: Option<u64>,
    },
    Close,
}

struct Client {
    rx: mpsc::Receiver<Incoming>,
    tx: mpsc::UnboundedSender<Outgoing>,
    /// Raw output bytes queued and not yet written.
    backlog: Arc<AtomicUsize>,
    /// Output of earlier epochs is skipped by the writer.
    epoch: Arc<AtomicU64>,
    greeted: bool,
    /// Input waiting for room in its session's PTY queue; nothing more is
    /// read from this client until it's written.
    pending: Option<ClientMsg>,
    closing: bool,
}

impl Client {
    fn send(&self, message: &RuntimeMsg) {
        let _ = self.tx.send(Outgoing::Line {
            line: encode_runtime(message),
            cost: 0,
            epoch: None,
        });
    }

    fn close(&mut self) {
        self.closing = true;
        let _ = self.tx.send(Outgoing::Close);
    }
}

/// The local frontend attached to a session.
struct Attachment {
    client: u64,
    /// The frontend's terminal size.
    size: (u16, u16),
    /// The canonical screen's size the frontend last got.
    screen: (u16, u16),
    /// It got a restore of the current mirror (else one is due as soon as
    /// the mirror is current).
    restored: bool,
    exited_sent: bool,
}

struct Server {
    app: App,
    options: Options,
    /// Sessions in creation (or adoption) order.
    sessions: BTreeMap<SessionId, BrokerSession>,
    order: Vec<SessionId>,
    /// Launches still starting their worker.
    launching: usize,
    launches: mpsc::UnboundedSender<LaunchDone>,
    clients: BTreeMap<u64, Client>,
    attached: BTreeMap<SessionId, Attachment>,
    next_client: u64,
    idle_since: Option<Instant>,
    /// Exit at the end of this pass (a restart for another protocol).
    restart: bool,
    wake: Arc<Notify>,
}

/// Serves frontends on `listener` with `app` as the host until `shutdown`
/// completes, the runtime has been idle for `options.idle`, or a client of
/// another protocol asks a runtime without live sessions to restart.
pub async fn serve(
    app: App,
    listener: tokio::net::UnixListener,
    options: Options,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    let wake = Arc::new(Notify::new());
    let (accepted_tx, mut accepted) = mpsc::channel::<UnixStream>(16);
    let uid = options.uid;
    let acceptor = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    // Same user only.
                    match stream.peer_cred() {
                        Ok(cred) if cred.uid() == uid => {
                            if accepted_tx.send(stream).await.is_err() {
                                return;
                            }
                        }
                        Ok(cred) => {
                            eprintln!("atem runtime: refused a peer of uid {}", cred.uid())
                        }
                        Err(error) => eprintln!("atem runtime: peer check failed: {error}"),
                    }
                }
                Err(error) => {
                    eprintln!("atem runtime: accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    let (launches, mut launched) = mpsc::unbounded_channel::<LaunchDone>();
    let (adoptions_tx, mut adoptions) = mpsc::unbounded_channel::<Adoption>();
    let adopting = tokio::spawn(super::broker::adopt_all(
        options.launcher.state().to_path_buf(),
        adoptions_tx,
    ));
    let mut server = Server {
        app,
        options,
        sessions: BTreeMap::new(),
        order: Vec::new(),
        launching: 0,
        launches,
        clients: BTreeMap::new(),
        attached: BTreeMap::new(),
        next_client: 0,
        idle_since: None,
        restart: false,
        wake: wake.clone(),
    };
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tick.tick() => {
                server.pump_workers();
                server.reap_exited(Instant::now());
                server.app.tick_host().await;
                server.forward_status();
            }
            Some(stream) = accepted.recv() => server.add_client(stream),
            Some(done) = launched.recv() => server.launched(done),
            Some(adoption) = adoptions.recv() => server.adopted(adoption),
            _ = wake.notified() => {}
        }
        server.handle_clients().await;
        server.flush();
        if server.restart || server.idle_expired() {
            break;
        }
    }
    acceptor.abort();
    adopting.abort();
    // Let writers send what's queued (a restart's error) before the
    // connections close. Workers outlive this broker: the next one adopts them.
    for client in server.clients.values_mut() {
        client.close();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

/// Runs `task`; a panic is logged with `what` and ends only that task.
fn spawn_logged(what: String, task: impl std::future::Future<Output = ()> + Send + 'static) {
    let handle = tokio::spawn(task);
    tokio::spawn(async move {
        if let Err(error) = handle.await
            && error.is_panic()
        {
            eprintln!("atem runtime: {what} panicked; that client is closed");
        }
    });
}

/// One line of at most `MAX_LINE` bytes into `line` (newline included);
/// `Ok(false)` at end of stream.
pub(crate) async fn read_line(
    reader: &mut (impl AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
) -> std::io::Result<bool> {
    read_line_max(reader, line, super::protocol::MAX_LINE).await
}

/// `read_line` with a bound of `max` bytes.
pub(crate) async fn read_line_max(
    reader: &mut (impl AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<bool> {
    line.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(false);
        }
        match available.iter().position(|b| *b == b'\n') {
            Some(end) => {
                line.extend_from_slice(&available[..=end]);
                reader.consume(end + 1);
                return Ok(true);
            }
            None => {
                let count = available.len();
                line.extend_from_slice(available);
                reader.consume(count);
            }
        }
        if line.len() > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too long",
            ));
        }
    }
}

impl Server {
    fn add_client(&mut self, stream: UnixStream) {
        let id = self.next_client;
        self.next_client += 1;
        let (read, mut write) = stream.into_split();
        let (in_tx, rx) = mpsc::channel(CLIENT_QUEUE);
        let (tx, mut out_rx) = mpsc::unbounded_channel::<Outgoing>();
        let backlog = Arc::new(AtomicUsize::new(0));
        let epoch = Arc::new(AtomicU64::new(0));
        let wake = self.wake.clone();
        spawn_logged(format!("client {id} reader"), async move {
            let mut reader = BufReader::new(read);
            let mut line = Vec::new();
            loop {
                // A read error (a line over the bound) ends the connection;
                // an invalid line is answered and reading goes on.
                let (incoming, last) = match read_line(&mut reader, &mut line).await {
                    Ok(true) => match std::str::from_utf8(&line) {
                        Ok(text) => match super::protocol::decode_client(text) {
                            Ok(message) => (Incoming::Message(message), false),
                            Err(error) => (Incoming::Bad(error), false),
                        },
                        Err(_) => (
                            Incoming::Bad(DecodeError::Invalid("message isn't UTF-8".into())),
                            false,
                        ),
                    },
                    Ok(false) => break,
                    Err(error) => (Incoming::Bad(DecodeError::Invalid(error.to_string())), true),
                };
                // Waits (stops reading the socket) while the host holds this
                // client's messages back.
                if in_tx.send(incoming).await.is_err() {
                    break;
                }
                wake.notify_one();
                if last {
                    break;
                }
            }
            drop(in_tx);
            wake.notify_one();
        });
        let (writer_backlog, writer_epoch) = (backlog.clone(), epoch.clone());
        spawn_logged(format!("client {id} writer"), async move {
            while let Some(outgoing) = out_rx.recv().await {
                match outgoing {
                    Outgoing::Line { line, cost, epoch } => {
                        let stale = epoch.is_some_and(|e| e < writer_epoch.load(Ordering::SeqCst));
                        let written = stale || write.write_all(line.as_bytes()).await.is_ok();
                        writer_backlog.fetch_sub(cost, Ordering::SeqCst);
                        if !written {
                            break;
                        }
                    }
                    Outgoing::Close => break,
                }
            }
            let _ = write.shutdown().await;
        });
        self.clients.insert(
            id,
            Client {
                rx,
                tx,
                backlog,
                epoch,
                greeted: false,
                pending: None,
                closing: false,
            },
        );
    }

    fn remove_client(&mut self, id: u64) {
        if let Some(mut client) = self.clients.remove(&id) {
            client.close();
        }
        let gone: Vec<SessionId> = self
            .attached
            .iter()
            .filter(|(_, a)| a.client == id)
            .map(|(sid, _)| sid.clone())
            .collect();
        for sid in gone {
            self.detach(&sid);
        }
    }

    fn detach(&mut self, sid: &SessionId) {
        self.attached.remove(sid);
        if let Some(session) = self.sessions.get_mut(sid) {
            session.tap.close();
        }
    }

    fn send(&self, client: u64, message: &RuntimeMsg) {
        if let Some(client) = self.clients.get(&client) {
            client.send(message);
        }
    }

    fn error(&self, client: u64, text: impl Into<String>, op: &str) {
        self.send(client, &RuntimeMsg::error(text, Some(op)));
    }

    /// Status messages the host would have shown become notices for every frontend.
    fn forward_status(&mut self) {
        let Some(text) = self.app.status_message.take() else {
            return;
        };
        let notice = RuntimeMsg::Notice { text };
        for client in self.clients.values().filter(|c| c.greeted) {
            client.send(&notice);
        }
    }

    /// Sessions whose agent runs.
    fn live_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_live()).count()
    }

    /// No live session, no launch under way and no client: the runtime may
    /// exit (workers that ended or can't be adopted stay on disk).
    fn idle_expired(&mut self) -> bool {
        let idle = self.live_count() == 0 && self.launching == 0 && self.clients.is_empty();
        if !idle {
            self.idle_since = None;
            return false;
        }
        let since = *self.idle_since.get_or_insert_with(Instant::now);
        since.elapsed() >= self.options.idle
    }

    fn insert_session(&mut self, session: BrokerSession) {
        let sid = session.id.clone();
        if self.sessions.insert(sid.clone(), session).is_none() {
            self.order.push(sid);
        }
    }

    fn remove_session(&mut self, sid: &SessionId) {
        self.sessions.remove(sid);
        self.order.retain(|id| id != sid);
    }

    /// A launch's worker started (or didn't).
    fn launched(&mut self, done: LaunchDone) {
        self.launching = self.launching.saturating_sub(1);
        let LaunchDone {
            client,
            request,
            result,
        } = done;
        match result {
            Ok((handle, created_at_ms)) => {
                eprintln!(
                    "atem runtime: launched {} ({}) in worker pid {}",
                    request.session_id,
                    request.provider.as_str(),
                    handle.info.pid
                );
                let session = BrokerSession::launched(handle, &request, created_at_ms);
                let summary = session.summary(false);
                self.insert_session(session);
                self.send(client, &RuntimeMsg::Launched { session: summary });
            }
            Err(error) => self.error(
                client,
                format!("Could not start {}: {error:#}", request.provider.product()),
                "launch",
            ),
        }
    }

    /// A worker record found at start became a session.
    fn adopted(&mut self, adoption: Adoption) {
        let sid = adoption.session_id().to_string();
        match &adoption {
            Adoption::Adopted(handle, _) => eprintln!(
                "atem runtime: adopted worker {sid} (process_gen {}, pid {})",
                handle.info.process_gen, handle.info.pid
            ),
            Adoption::RecoveryRequired { reason, .. } => {
                eprintln!("atem runtime: {sid}: recovery_required ({reason})")
            }
            other => eprintln!("atem runtime: {sid}: {}", other.status()),
        }
        let exited_record = matches!(adoption, Adoption::Exited { .. });
        let Some(session) = BrokerSession::from_adoption(adoption) else {
            return;
        };
        if self.sessions.contains_key(&session.id) {
            return;
        }
        if exited_record {
            // The worker is gone after recording the exit; it is recorded now.
            super::broker::remove_record(self.options.launcher.state(), &sid);
        }
        self.insert_session(session);
    }

    /// What every worker sent since the last pass.
    fn pump_workers(&mut self) {
        for sid in self.order.clone() {
            let Some(session) = self.sessions.get_mut(&sid) else {
                continue;
            };
            let pumped = session.pump();
            if pumped.ended {
                eprintln!(
                    "atem runtime: {sid} {} ({})",
                    session.state.as_str(),
                    session.exit_status.as_deref().unwrap_or("")
                );
            }
            let Some(attachment) = self.attached.get_mut(&sid) else {
                continue;
            };
            if pumped.resync {
                attachment.restored = false;
            }
            let client = attachment.client;
            for text in pumped.failed {
                self.error(client, text, "input");
            }
        }
    }

    /// Removes sessions that exited `EXITED_KEEP` (10 min) before `now`.
    /// Interrupted and recovery-required ones stay until stopped.
    fn reap_exited(&mut self, now: Instant) {
        let due: Vec<SessionId> = self
            .sessions
            .values()
            .filter(|s| {
                s.state == SessionState::Exited
                    && s.exited_at
                        .is_some_and(|at| now.saturating_duration_since(at) >= EXITED_KEEP)
            })
            .map(|s| s.id.clone())
            .collect();
        for sid in due {
            self.remove_session(&sid);
        }
    }

    async fn handle_clients(&mut self) {
        let ids: Vec<u64> = self.clients.keys().copied().collect();
        for id in ids {
            for _ in 0..PER_PASS {
                let Some(client) = self.clients.get_mut(&id) else {
                    break;
                };
                if client.closing {
                    break;
                }
                if let Some(message) = client.pending.take() {
                    if let Some(message) = self.input(id, message) {
                        if let Some(client) = self.clients.get_mut(&id) {
                            client.pending = Some(message);
                        }
                        break;
                    }
                    continue;
                }
                let incoming = match client.rx.try_recv() {
                    Ok(incoming) => incoming,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.remove_client(id);
                        break;
                    }
                };
                let handled = std::panic::AssertUnwindSafe(self.handle(id, incoming))
                    .catch_unwind()
                    .await;
                if handled.is_err() {
                    eprintln!(
                        "atem runtime: handling a message of client {id} panicked; closing it"
                    );
                    self.remove_client(id);
                    break;
                }
            }
        }
    }

    async fn handle(&mut self, id: u64, incoming: Incoming) {
        let greeted = self.clients.get(&id).is_some_and(|c| c.greeted);
        let message = match incoming {
            Incoming::Message(message) => message,
            Incoming::Bad(DecodeError::Version(version)) if !greeted => {
                self.refuse_protocol(id, version);
                return;
            }
            Incoming::Bad(error) => {
                self.send(id, &RuntimeMsg::error(error.to_string(), None));
                if !greeted {
                    self.close(id);
                }
                return;
            }
        };
        if !greeted {
            match message {
                ClientMsg::Hello { .. } => {
                    if let Some(client) = self.clients.get_mut(&id) {
                        client.greeted = true;
                        client.send(&RuntimeMsg::Welcome {
                            protocol: PROTOCOL,
                            build: crate::memory::key_agent::build_id().to_string(),
                            pid: std::process::id(),
                        });
                    }
                }
                other => {
                    self.error(id, "Send hello first", other.op());
                    self.close(id);
                }
            }
            return;
        }
        match message {
            ClientMsg::Hello { .. } => self.error(id, "Already greeted", "hello"),
            ClientMsg::Launch {
                provider,
                args,
                cwd,
                env,
                rows,
                cols,
            } => {
                let provider = match provider.as_str() {
                    "claude-code" => Some(Provider::Claude),
                    other => Provider::from_alias(other),
                };
                let Some(provider) = provider else {
                    return self.error(id, "Expected claude, claude-code or codex", "launch");
                };
                if !cwd.is_absolute() {
                    return self.error(id, "The working directory must be absolute", "launch");
                }
                if let Err(error) = crate::session::check_env(&env.to_os()) {
                    return self.error(id, error, "launch");
                }
                if self.live_count() + self.launching >= Sessions::MAX_LIVE {
                    return self.error(
                        id,
                        format!("At most {} sessions can run at once", Sessions::MAX_LIVE),
                        "launch",
                    );
                }
                let request = SpawnRequest {
                    session_id: SessionId::new(),
                    process_gen: uuid::Uuid::new_v4().to_string(),
                    provider,
                    args,
                    cwd,
                    rows: rows.clamp(2, 200),
                    cols: cols.clamp(2, 400),
                };
                self.launching += 1;
                let launcher = self.options.launcher.clone();
                let (tx, wake) = (self.launches.clone(), self.wake.clone());
                tokio::spawn(async move {
                    let result = launcher.spawn(request.clone(), env).await;
                    let _ = tx.send(LaunchDone {
                        client: id,
                        request,
                        result,
                    });
                    wake.notify_one();
                });
            }
            ClientMsg::Attach {
                session_id,
                rows,
                cols,
            } => {
                let Some(sid) = self.find(&session_id) else {
                    return self.error(id, "Unknown session", "attach");
                };
                let session = &self.sessions[&sid];
                if !session.has_screen() {
                    let text = format!(
                        "Session {sid} is {} ({}); there is nothing to attach to. `atem agent stop {sid}` removes it",
                        session.state.as_str(),
                        session.exit_status.as_deref().unwrap_or("no worker")
                    );
                    return self.error(id, text, "attach");
                }
                let attachment = Attachment {
                    client: id,
                    size: (rows, cols),
                    screen: (0, 0),
                    restored: false,
                    exited_sent: false,
                };
                if let Some(previous) = self.attached.insert(sid.clone(), attachment)
                    && previous.client != id
                {
                    self.send(
                        previous.client,
                        &RuntimeMsg::Detached {
                            session_id: sid.to_string(),
                            reason: "attached elsewhere".into(),
                        },
                    );
                }
                self.adjust_size(&sid, rows, cols);
                if let Some(session) = self.sessions.get_mut(&sid) {
                    session.tap.open();
                }
                self.restore(&sid);
            }
            ClientMsg::Detach { session_id } => {
                let Some(sid) = self.attached_by(id, &session_id) else {
                    return self.error(id, "Not attached to that session", "detach");
                };
                self.detach(&sid);
                self.send(
                    id,
                    &RuntimeMsg::Detached {
                        session_id: sid.to_string(),
                        reason: "detached".into(),
                    },
                );
            }
            message @ ClientMsg::Input { .. } => {
                if let Some(message) = self.input(id, message)
                    && let Some(client) = self.clients.get_mut(&id)
                {
                    client.pending = Some(message);
                }
            }
            ClientMsg::Resize {
                session_id,
                rows,
                cols,
            } => {
                let Some(sid) = self.attached_by(id, &session_id) else {
                    return self.error(id, "Attach to the session first", "resize");
                };
                if let Some(attachment) = self.attached.get_mut(&sid) {
                    attachment.size = (rows, cols);
                }
                self.adjust_size(&sid, rows, cols);
            }
            ClientMsg::Reclaim { session_id } => {
                let Some(sid) = self.attached_by(id, &session_id) else {
                    return self.error(id, "Attach to the session first", "reclaim");
                };
                let Some(session) = self.sessions.get_mut(&sid).filter(|s| s.is_live()) else {
                    return self.send(
                        id,
                        &RuntimeMsg::Notice {
                            text: "The session has ended".into(),
                        },
                    );
                };
                // Control changes: writes queued under the old epoch are
                // dropped at the worker.
                if let Err(error) = session.raise_input_epoch() {
                    return self.error(id, error.to_string(), "reclaim");
                }
                let (rows, cols) = self.attached[&sid].size;
                self.adjust_size(&sid, rows, cols);
                self.restore(&sid);
            }
            ClientMsg::List => {
                let sessions = self.order.iter().map(|sid| self.summary(sid)).collect();
                self.send(id, &RuntimeMsg::Sessions { sessions });
            }
            ClientMsg::Stop { session_id } => {
                let Some(sid) = self.find(&session_id) else {
                    return self.error(id, "No such live session", "stop");
                };
                let session = &self.sessions[&sid];
                match session.state {
                    SessionState::Running if session.is_live() => {
                        if let Err(error) = session.stop() {
                            return self.error(id, error.to_string(), "stop");
                        }
                        self.send(
                            id,
                            &RuntimeMsg::Notice {
                                text: format!("Stopping {sid}"),
                            },
                        );
                    }
                    SessionState::Interrupted | SessionState::RecoveryRequired => {
                        let text = self.forget(&sid);
                        self.send(id, &RuntimeMsg::Notice { text });
                    }
                    _ => self.error(id, "No such live session", "stop"),
                }
            }
            ClientMsg::Reload => {
                if let Ok(config) = crate::config::AtemConfig::load() {
                    self.app.config = config;
                }
                if !self.app.astation_connected {
                    // Credentials or pairing may have changed: try again now.
                    self.app.astation_reconnect_at = Some(Instant::now());
                }
                self.send(
                    id,
                    &RuntimeMsg::Notice {
                        text: "Reloaded".into(),
                    },
                );
            }
        }
    }

    /// Removes a session without a worker and its record. Nothing is
    /// signalled: a recorded process that still runs is named instead.
    fn forget(&mut self, sid: &SessionId) -> String {
        let still_running = self
            .sessions
            .get(sid)
            .and_then(|s| s.record())
            .and_then(|r| {
                let runs = |pid: Option<u32>, start: Option<u64>| {
                    pid.filter(|pid| {
                        start.is_some() && super::adopt::process_start_time(*pid) == start
                    })
                };
                runs(Some(r.worker_pid), Some(r.start_time))
                    .or_else(|| runs(r.agent_pid, r.agent_start_time))
            });
        super::broker::remove_record(self.options.launcher.state(), sid.as_str());
        if self.attached.contains_key(sid) {
            self.detach(sid);
        }
        self.remove_session(sid);
        match still_running {
            Some(pid) => {
                format!("Removed {sid}; its recorded process {pid} still runs and was not stopped")
            }
            None => format!("Removed {sid}"),
        }
    }

    /// Sends what's queued, then closes the connection.
    fn close(&mut self, id: u64) {
        self.remove_client(id);
    }

    /// Another protocol: a runtime without live sessions restarts (a client
    /// of that protocol starts its own); one with live sessions refuses.
    fn refuse_protocol(&mut self, id: u64, version: u64) {
        let live = self.live_count() + self.launching;
        let text = if live == 0 {
            self.restart = true;
            format!("{RESTARTING} (protocol {PROTOCOL}, client {version})")
        } else {
            format!(
                "This runtime speaks protocol {PROTOCOL}, not {version}, and has {live} live sessions; stop your sessions (`atem agent list`) or use the atem that started them"
            )
        };
        self.error(id, text, "hello");
        self.close(id);
    }

    /// Local input always writes (until leases): to the session's worker,
    /// under its current input epoch. `Some(message)` back: too many writes
    /// are in flight; keep it and read nothing more from this client meanwhile.
    fn input(&mut self, id: u64, message: ClientMsg) -> Option<ClientMsg> {
        let ClientMsg::Input { session_id, bytes } = &message else {
            return None;
        };
        let Some(sid) = self.attached_by(id, session_id) else {
            self.error(id, "Attach to the session first", "input");
            return None;
        };
        let bytes = match input_bytes(bytes) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error(id, error.to_string(), "input");
                return None;
            }
        };
        let Some(session) = self.sessions.get_mut(&sid).filter(|s| s.is_live()) else {
            self.error(id, "The session has ended", "input");
            return None;
        };
        if !session.can_write() {
            return Some(message);
        }
        if let Err(error) = session.write(&bytes) {
            self.error(id, error.to_string(), "input");
        }
        None
    }

    /// The local frontend's size for a live session's terminal.
    fn adjust_size(&mut self, sid: &SessionId, rows: u16, cols: u16) {
        if let Some(session) = self.sessions.get_mut(sid)
            && let Err(error) = session.resize(rows, cols)
        {
            self.app.status_message = Some(format!("Failed to resize {sid}: {error}"));
        }
    }

    /// The session a session id names (any state).
    fn find(&self, id: &str) -> Option<SessionId> {
        SessionId::parse(id).filter(|sid| self.sessions.contains_key(sid))
    }

    /// The session `session_id` names when `client` is attached to it.
    fn attached_by(&self, client: u64, session_id: &str) -> Option<SessionId> {
        let sid = SessionId::parse(session_id)?;
        (self.attached.get(&sid)?.client == client).then_some(sid)
    }

    fn summary(&self, sid: &SessionId) -> SessionSummary {
        self.sessions[sid].summary(self.attached.contains_key(sid))
    }

    /// Sends the attached frontend a fresh restore: the mirror of the
    /// canonical screen now, and the stream position output continues from.
    /// Output queued for it before is dropped. Until the mirror is current
    /// (an adopted worker's screen is on its way) the restore waits.
    fn restore(&mut self, sid: &SessionId) {
        let summary = self.summary(sid);
        let Some(attachment) = self.attached.get_mut(sid) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(sid) else {
            return;
        };
        let Some((restore, offset)) = session.restore() else {
            attachment.restored = false;
            return;
        };
        attachment.screen = session.size();
        attachment.restored = true;
        let Some(client) = self.clients.get(&attachment.client) else {
            return;
        };
        client.epoch.fetch_add(1, Ordering::SeqCst);
        client.send(&RuntimeMsg::Attached {
            session: summary,
            restore: b64(&restore),
            offset,
        });
    }

    /// Output since the last pass to each attached frontend, a fresh restore
    /// when one is due (its backlog overflowed, the screen changed size or
    /// was replaced), and the exit.
    fn flush(&mut self) {
        let sids: Vec<SessionId> = self.attached.keys().cloned().collect();
        for sid in sids {
            let client_id = self.attached[&sid].client;
            let Some(session) = self.sessions.get_mut(&sid) else {
                self.attached.remove(&sid);
                self.send(
                    client_id,
                    &RuntimeMsg::Detached {
                        session_id: sid.to_string(),
                        reason: "the session was removed".into(),
                    },
                );
                continue;
            };
            let chunk = session.tap.take();
            let size = session.size();
            let synced = session.synced();
            let exited = (session.state != SessionState::Running).then(|| {
                (
                    session.process_gen.clone(),
                    session
                        .exit_status
                        .clone()
                        .unwrap_or_else(|| "exited".into()),
                )
            });
            let Some(client) = self.clients.get(&client_id) else {
                self.detach(&sid);
                continue;
            };
            let attachment = &self.attached[&sid];
            let mut resync =
                synced && (!attachment.restored || chunk.overflowed || size != attachment.screen);
            if synced && !resync {
                let epoch = client.epoch.load(Ordering::SeqCst);
                let mut offset = chunk.start;
                for piece in chunk.bytes.chunks(MAX_OUTPUT) {
                    if client.backlog.load(Ordering::SeqCst) + piece.len() > BACKLOG_LIMIT {
                        resync = true;
                        break;
                    }
                    client.backlog.fetch_add(piece.len(), Ordering::SeqCst);
                    let _ = client.tx.send(Outgoing::Line {
                        line: encode_runtime(&RuntimeMsg::Output {
                            session_id: sid.to_string(),
                            bytes: b64(piece),
                            offset,
                        }),
                        cost: piece.len(),
                        epoch: Some(epoch),
                    });
                    offset += piece.len() as u64;
                }
            }
            if resync {
                self.restore(&sid);
            }
            let attachment = self.attached.get_mut(&sid).expect("attached");
            // The exit follows the final screen.
            if let Some((generation, status)) = exited
                && attachment.restored
                && !attachment.exited_sent
            {
                attachment.exited_sent = true;
                self.send(
                    client_id,
                    &RuntimeMsg::Exited {
                        session_id: sid.to_string(),
                        generation,
                        status,
                    },
                );
            }
        }
    }
}

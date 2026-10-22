//! The runtime's host loop: the agent sessions (each in an `atem worker`,
//! see broker.rs), one `App` (no TUI, the Astation connection) ticked every
//! 16 ms, and local frontends on a same-user Unix socket. Each client has a
//! reader and a writer task; sessions and the `App` stay on the host loop,
//! which they reach through channels. Launches and adoptions run on their
//! own tasks and report back, so a slow worker never stalls the loop.

use super::adopt::{Adoption, SpawnRequest, WorkerHandle};
use super::broker::{BrokerSession, Launcher, SessionState};
use super::host_bridge::{Clock, HostBridge};
use super::ops::{BUSY, ClientUi, OpCall, OpEnv};
use super::protocol::{
    ClientMsg, DecodeError, MAX_OUTPUT, PROTOCOL, RuntimeMsg, SessionSummary, b64, encode_runtime,
    input_bytes, paste_text,
};
use crate::app::App;
use crate::session::{EXITED_KEEP, Provider, SessionId};
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
/// The prefix of the error a runtime sends a new client while it exits for
/// a restart (`client::RESTARTING` matches it: the client waits for it to
/// go and connects to the next one).
pub const RESTARTING: &str = "This runtime is restarting";
/// The start of the error a `restart` gets while the runtime is busy: an
/// Astation operation runs or a session is starting (`client` matches it).
pub const BUSY_RESTART: &str = "Atem's runtime is busy";
/// The error new work gets once a restart was asked for: the runtime exits
/// after this pass (the next runtime takes it).
pub const RESTARTING_NOW: &str = "Atem's runtime is restarting; try again in a moment";

pub struct Options {
    /// Exit after this long with no sessions and no clients.
    pub idle: Duration,
    /// Peers must run as this user.
    pub uid: u32,
    /// Starts workers; its state dir holds the worker records adopted at start.
    pub launcher: Launcher,
    /// The profile whose pairing names the session host at start (`None`:
    /// unpaired until an authenticated, verified link names it).
    pub profile: Option<crate::profile::Sources>,
    /// The session host's monotonic clock.
    pub clock: Clock,
    /// What Astation operations (pairing, unlock) run with.
    pub ops: OpEnv,
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
    /// Greeted as passive: never keeps an idle runtime running.
    passive: bool,
    /// Input waiting for room in its session's PTY queue; nothing more is
    /// read from this client until it's written.
    pending: Option<ClientMsg>,
    /// A message that waits until the workers found at start are adopted
    /// (`list`, `attach`, `stop`, a protocol refusal); nothing more is read
    /// from this client meanwhile.
    held: Option<Incoming>,
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
    /// The summary it last got (in `attached` or `session`).
    sent: Option<SessionSummary>,
}

struct Server {
    app: App,
    options: Options,
    /// Sessions in creation (or adoption) order.
    sessions: BTreeMap<SessionId, BrokerSession>,
    order: Vec<SessionId>,
    /// Launches still starting their worker.
    launching: usize,
    /// The workers found at start are still being adopted.
    adopting: bool,
    launches: mpsc::UnboundedSender<LaunchDone>,
    clients: BTreeMap<u64, Client>,
    attached: BTreeMap<SessionId, Attachment>,
    next_client: u64,
    idle_since: Option<Instant>,
    /// Exit at the end of this pass (a restart for another protocol).
    restart: bool,
    wake: Arc<Notify>,
    /// The session host (`None` when its journal could not be opened:
    /// remote session messages are refused then).
    bridge: Option<HostBridge>,
    /// Why there is no session host (sent in every `welcome`).
    host_error: Option<String>,
    /// The Astation link state the clients last heard.
    astation: bool,
    /// The device list state the clients last heard.
    device_list: Option<super::protocol::DeviceListStatus>,
    /// The running Astation operation (pairing, unlock), one at a time.
    op: Option<ActiveOp>,
    op_calls: mpsc::UnboundedSender<OpCall>,
    /// The running operation waits for the link to come up.
    op_waiting: Option<OpWaiting>,
}

/// A running operation waits for the link: (encryption, credentials, reply).
type OpWaiting = (
    bool,
    bool,
    tokio::sync::oneshot::Sender<Result<crate::websocket_client::AstationClient, String>>,
);

/// The Astation operation a client asked for (`ops.rs`).
struct ActiveOp {
    client: u64,
    request_id: String,
    answers: mpsc::UnboundedSender<(u64, super::protocol::AnswerValue)>,
    /// Set when the client went away.
    gone: tokio::sync::watch::Sender<bool>,
}

/// Serves frontends on `listener` with `app` as the host until `shutdown`
/// completes, the runtime has been idle for `options.idle`, or a client of
/// another protocol asks a runtime without live sessions to restart.
pub async fn serve(
    mut app: App,
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
    let journal = options.launcher.state().join("journal");
    let (bridge, host_error) =
        match HostBridge::open(&journal, options.profile.as_ref(), options.clock.clone()) {
            Ok(bridge) => (Some(bridge), None),
            Err(error) => {
                // Never repaired behind the user's back: remote sessions stay
                // off until the cause is fixed and the runtime restarts.
                let text = format!("remote sessions disabled: {error:#}");
                eprintln!("atem runtime: {text}");
                (None, Some(text))
            }
        };
    app.hosted = Some(crate::app::hosted::Hosted::default());
    // §R9.7b: the relay link (already connecting) answers the relay's
    // challenge from the device list as opened, then as each pass leaves it.
    crate::session_protocol::r9::route::set(
        &app.host_route,
        match &bridge {
            Some(bridge) => bridge.route_state(),
            None => crate::session_protocol::r9::route::RouteState::Off("remote sessions disabled"),
        },
    );
    let (op_calls, mut op_called) = mpsc::unbounded_channel::<OpCall>();
    let mut server = Server {
        app,
        options,
        sessions: BTreeMap::new(),
        order: Vec::new(),
        launching: 0,
        adopting: true,
        launches,
        clients: BTreeMap::new(),
        attached: BTreeMap::new(),
        next_client: 0,
        idle_since: None,
        restart: false,
        wake: wake.clone(),
        bridge,
        host_error,
        astation: false,
        device_list: None,
        op: None,
        op_calls,
        op_waiting: None,
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
                server.host_pass().await;
                server.forward_status();
                server.forward_astation();
                server.forward_device_list();
                server.op_tick();
            }
            Some(call) = op_called.recv() => server.op_call(call),
            Some(stream) = accepted.recv() => server.add_client(stream),
            Some(done) = launched.recv() => server.launched(done),
            adoption = adoptions.recv(), if server.adopting => match adoption {
                Some(adoption) => server.adopted(adoption),
                None => server.adopting = false,
            },
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
    // Admission has stopped: an orderly stop records it (r8 §H).
    if let Some(bridge) = server.bridge.as_mut() {
        bridge.close_cleanly();
    }
    // Let writers send what's queued (a restart's error) before the
    // connections close. Workers outlive this broker: the next one adopts them.
    for client in server.clients.values_mut() {
        client.close();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

/// Waits until the workers found at start are adopted, so its answer
/// includes them.
fn waits_for_adoption(incoming: &Incoming) -> bool {
    matches!(
        incoming,
        Incoming::Message(ClientMsg::List | ClientMsg::Attach { .. } | ClientMsg::Stop { .. })
            | Incoming::Bad(DecodeError::Version(_))
    )
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
                passive: false,
                pending: None,
                held: None,
                closing: false,
            },
        );
    }

    fn remove_client(&mut self, id: u64) {
        if let Some(mut client) = self.clients.remove(&id) {
            client.close();
        }
        // Its operation ends as a failure (verification tells Astation).
        if let Some(op) = self.op.as_ref().filter(|op| op.client == id) {
            let _ = op.gone.send(true);
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

    /// A notice for the frontend attached to `sid` only.
    fn session_notice(&self, sid: &SessionId, text: String) {
        if let Some(attachment) = self.attached.get(sid) {
            self.send(attachment.client, &RuntimeMsg::Notice { text });
        }
    }

    /// The App's Astation link messages concern every session: a notice for
    /// every frontend. Mark-task notices go to their session's frontend
    /// only; those of no session to the log.
    fn forward_status(&mut self) {
        for (sid, text) in std::mem::take(&mut self.app.task_notices) {
            match sid {
                Some(sid) => self.session_notice(&sid, text),
                None => eprintln!("atem runtime: {text}"),
            }
        }
        let Some(text) = self.app.status_message.take() else {
            return;
        };
        let notice = RuntimeMsg::Notice { text };
        for client in self.clients.values().filter(|c| c.greeted && !c.passive) {
            client.send(&notice);
        }
    }

    /// Every greeted client hears when the Astation link goes up or down.
    /// The r9 device list's state, to every greeted client when it changes
    /// (the status row shows it).
    fn forward_device_list(&mut self) {
        let status = self
            .bridge
            .as_ref()
            .and_then(HostBridge::device_list_status);
        // Clients see the state, not the client count.
        let shown = |s: &Option<super::protocol::DeviceListStatus>| {
            s.as_ref()
                .map(|s| (s.state.clone(), s.label.clone(), s.text.clone()))
        };
        if shown(&status) == shown(&self.device_list) {
            self.device_list = status;
            return;
        }
        self.device_list = status.clone();
        let message = RuntimeMsg::DeviceList { status };
        for client in self.clients.values().filter(|c| c.greeted) {
            client.send(&message);
        }
    }

    fn forward_astation(&mut self) {
        let connected = self.app.astation_connected;
        if connected == self.astation {
            return;
        }
        self.astation = connected;
        let message = RuntimeMsg::Astation { connected };
        for client in self.clients.values().filter(|c| c.greeted) {
            client.send(&message);
        }
    }

    /// Sessions whose agent runs.
    fn live_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_live()).count()
    }

    /// No live session, no launch under way and no client: the runtime may
    /// exit (workers that ended or can't be adopted stay on disk).
    fn idle_expired(&mut self) -> bool {
        let idle = self.live_count() == 0
            && self.launching == 0
            && !self.adopting
            && self.clients.values().all(|c| c.greeted && c.passive);
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
        let Some(mut session) = BrokerSession::from_adoption(adoption) else {
            return;
        };
        if self.sessions.contains_key(&session.id) {
            return;
        }
        if let Some(bridge) = self.bridge.as_mut() {
            bridge.check_adoption(&mut session);
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
            if pumped.ended && self.app.main_task_session.as_ref() == Some(&sid) {
                // The active mark task's session ended: finalize it.
                self.app.dispatcher.set_main_needs_finalize();
            }
            if pumped.ended {
                eprintln!(
                    "atem runtime: {sid} {} ({})",
                    session.state.as_str(),
                    session.exit_status.as_deref().unwrap_or("")
                );
            }
            let Some(attachment) = self.attached.get_mut(&sid) else {
                for text in pumped.notices {
                    eprintln!("atem runtime: {sid}: {text}");
                }
                continue;
            };
            let (client, size) = (attachment.client, attachment.size);
            if pumped.resync {
                // A new screen: a fresh restore, at the frontend's size (the
                // worker's screen may have another one, e.g. after adoption).
                attachment.restored = false;
                self.local_size(&sid, size.0, size.1);
            }
            for text in pumped.failed {
                self.error(client, text, "input");
            }
            for text in pumped.notices {
                self.send(client, &RuntimeMsg::Notice { text });
            }
            if pumped.dropped_bytes > 0 {
                let text = format!(
                    "{} typed bytes were dropped when control changed",
                    pumped.dropped_bytes
                );
                self.send(client, &RuntimeMsg::Notice { text });
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
                if let Some(incoming) = client.held.take() {
                    if self.adopting {
                        client.held = Some(incoming);
                        break;
                    }
                    if !self.handle_caught(id, incoming).await {
                        break;
                    }
                    continue;
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
                if self.adopting && waits_for_adoption(&incoming) {
                    if let Some(client) = self.clients.get_mut(&id) {
                        client.held = Some(incoming);
                    }
                    break;
                }
                if !self.handle_caught(id, incoming).await {
                    break;
                }
            }
        }
    }

    /// `handle`, closing the client when it panics; false then.
    async fn handle_caught(&mut self, id: u64, incoming: Incoming) -> bool {
        let handled = std::panic::AssertUnwindSafe(self.handle(id, incoming))
            .catch_unwind()
            .await;
        if handled.is_err() {
            eprintln!("atem runtime: handling a message of client {id} panicked; closing it");
            self.remove_client(id);
            return false;
        }
        true
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
        if self.restart {
            // Exiting after this pass: nothing new starts here.
            match &message {
                ClientMsg::Hello { .. } if !greeted => {
                    self.error(id, format!("{RESTARTING} for a client"), "hello");
                    return self.close(id);
                }
                ClientMsg::Launch { .. }
                | ClientMsg::AstationOp { .. }
                | ClientMsg::Attach { .. }
                | ClientMsg::Restart => return self.error(id, RESTARTING_NOW, message.op()),
                _ => {}
            }
        }
        if !greeted {
            match message {
                ClientMsg::Hello { passive, .. } => {
                    let host_error = self
                        .host_error
                        .clone()
                        .or_else(|| self.bridge.as_ref().and_then(HostBridge::host_error));
                    if let Some(client) = self.clients.get_mut(&id) {
                        client.greeted = true;
                        client.passive = passive;
                        client.send(&RuntimeMsg::Welcome {
                            protocol: PROTOCOL,
                            build: crate::memory::cred_agent::build_id().to_string(),
                            pid: std::process::id(),
                            astation: self.astation,
                            host_error,
                            worker_protocol: Some(super::worker_protocol::WORKER_PROTOCOL),
                            device_list: self.device_list.clone(),
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
                if self.live_count() + self.launching >= crate::session::MAX_LIVE {
                    return self.error(
                        id,
                        format!(
                            "At most {} sessions can run at once",
                            crate::session::MAX_LIVE
                        ),
                        "launch",
                    );
                }
                // Debug builds: the r9 fixtures' sessions keep the ids their
                // signed grants name (`ATEM_TEST_SESSION_ID` in the launch
                // environment; refused when taken).
                #[cfg(debug_assertions)]
                let session_id = match env
                    .0
                    .iter()
                    .find(|(k, _)| k == "ATEM_TEST_SESSION_ID")
                    .and_then(|(_, v)| SessionId::parse(v))
                {
                    Some(sid) if self.sessions.contains_key(&sid) => {
                        return self.error(id, "That session id is taken", "launch");
                    }
                    Some(sid) => sid,
                    None => SessionId::new(),
                };
                #[cfg(not(debug_assertions))]
                let session_id = SessionId::new();
                let request = SpawnRequest {
                    session_id,
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
                    sent: None,
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
                self.local_size(&sid, rows, cols);
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
            message @ (ClientMsg::Input { .. } | ClientMsg::Paste { .. }) => {
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
                self.local_size(&sid, rows, cols);
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
                // Control changes: a remote lease is revoked and writes
                // queued under the old epoch are dropped at the worker.
                let reclaimed = match self.bridge.as_mut() {
                    Some(bridge) => bridge.local_input(
                        &sid,
                        Vec::new(),
                        &self.app.astation_client,
                        &mut self.sessions,
                    ),
                    None => session.raise_input_epoch().map(|_| ()),
                };
                if let Err(error) = reclaimed {
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
                            &RuntimeMsg::Stopped {
                                session_id: sid.to_string(),
                                removed: false,
                            },
                        );
                    }
                    SessionState::Interrupted | SessionState::RecoveryRequired => {
                        match self.forget(&sid) {
                            Ok(()) => self.send(
                                id,
                                &RuntimeMsg::Stopped {
                                    session_id: sid.to_string(),
                                    removed: true,
                                },
                            ),
                            Err(text) => self.error(id, text, "stop"),
                        }
                    }
                    _ => self.error(id, "No such live session", "stop"),
                }
            }
            ClientMsg::AstationOp {
                request_id,
                kind,
                options,
            } => self.start_op(id, request_id, kind, options),
            ClientMsg::Answer {
                request_id,
                question_id,
                value,
            } => {
                if let Some(op) = self
                    .op
                    .as_ref()
                    .filter(|op| op.client == id && op.request_id == request_id)
                {
                    let _ = op.answers.send((question_id, value));
                }
            }
            ClientMsg::Reload => {
                if let Ok(config) = crate::config::AtemConfig::load() {
                    self.app.config = config;
                }
                // `atem unpair` (or a re-pair) replaced the pairing this link
                // authenticated under: drop it and its attachments.
                let stale = self
                    .app
                    .astation_client
                    .capture()
                    .is_some_and(|capture| capture.check().is_err());
                if self.app.astation_connected && stale {
                    self.app.drop_astation_link(
                        "The Astation pairing changed; the link was dropped".into(),
                    );
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
            ClientMsg::Status => {
                let status = self.status();
                self.send(id, &RuntimeMsg::Status { status });
            }
            ClientMsg::Restart => self.restart_for(id),
        }
    }

    /// What `status` reports: the link, the attachment, the journal and the
    /// sessions.
    fn status(&self) -> super::protocol::RuntimeStatus {
        use super::protocol::{RuntimeStatus, Transport};
        use crate::websocket_client::LinkVia;
        let app = &self.app;
        let connected = app.astation_connected && !app.astation_client.is_ws_closed();
        let (transport, relay) = match app.astation_client.via().filter(|_| connected) {
            Some(LinkVia::Local) => (Some(Transport::Local), None),
            Some(LinkVia::Relay { label }) => (Some(Transport::Relay), Some(label.clone())),
            None => (None, None),
        };
        let link = self.bridge.as_ref().map(HostBridge::link_status);
        let host_error = self
            .host_error
            .clone()
            .or_else(|| self.bridge.as_ref().and_then(HostBridge::host_error));
        RuntimeStatus {
            astation: connected && app.astation_reauth.is_none(),
            transport,
            relay,
            retrying: !connected
                && (app.astation_connect_rx.is_some() || app.astation_reconnect_at.is_some()),
            reauthenticating: connected && app.astation_reauth.is_some(),
            attachment: link.as_ref().is_some_and(|l| l.attachment),
            welcomed: link.as_ref().and_then(|l| l.welcomed.clone()),
            refused: link.as_ref().and_then(|l| l.refused.clone()),
            journal_halted: link.as_ref().is_some_and(|l| l.journal_halted),
            host_error,
            adopting: self.adopting,
            sessions: self.order.iter().map(|sid| self.summary(sid)).collect(),
            device_list: self
                .bridge
                .as_ref()
                .and_then(HostBridge::device_list_status),
        }
    }

    /// `restart`: the runtime exits after this pass so the client can start
    /// its own build (the workers keep running; the next runtime adopts
    /// them). Never while an Astation operation runs (its link would go) or
    /// a session is starting (its launch would be cut off). The other
    /// frontends get `restarting` too: they reattach to the next runtime.
    fn restart_for(&mut self, id: u64) {
        let busy = if self.op.is_some() || self.op_waiting.is_some() {
            Some("an Astation operation is running")
        } else if self.launching > 0 {
            Some("a session is starting")
        } else {
            None
        };
        if let Some(why) = busy {
            return self.error(
                id,
                format!("{BUSY_RESTART}: {why}; restart it once that ends"),
                "restart",
            );
        }
        for (other, client) in &self.clients {
            if *other != id && client.greeted && !client.passive {
                client.send(&RuntimeMsg::Restarting);
            }
        }
        eprintln!("atem runtime: restarting for a client");
        self.restart = true;
        self.send(id, &RuntimeMsg::Restarting);
    }

    /// Starts an Astation operation for client `id`, unless one runs.
    fn start_op(
        &mut self,
        id: u64,
        request_id: String,
        kind: super::protocol::OpKind,
        options: super::protocol::OpOptions,
    ) {
        if self.op.is_some() {
            self.send(
                id,
                &RuntimeMsg::Done {
                    request_id,
                    ok: false,
                    error: Some(BUSY.into()),
                },
            );
            return;
        }
        let Some(client) = self.clients.get(&id) else {
            return;
        };
        let tx = client.tx.clone();
        let out = std::sync::Arc::new(move |message: RuntimeMsg| {
            let _ = tx.send(Outgoing::Line {
                line: encode_runtime(&message),
                cost: 0,
                epoch: None,
            });
        });
        let (answers, answered) = mpsc::unbounded_channel();
        let (gone, gone_rx) = tokio::sync::watch::channel(false);
        let ui = ClientUi::new(request_id.clone(), out, answered, gone_rx);
        eprintln!("atem runtime: {} for client {id}", kind.as_str());
        self.op = Some(ActiveOp {
            client: id,
            request_id: request_id.clone(),
            answers,
            gone,
        });
        super::ops::start(
            request_id,
            kind,
            options,
            ui,
            self.op_calls.clone(),
            self.options.ops.clone(),
        );
    }

    fn op_call(&mut self, call: OpCall) {
        match call {
            OpCall::Link {
                encryption,
                credentials,
                reply,
            } => {
                self.op_waiting = Some((encryption, credentials, reply));
                if !self.app.astation_connected && self.app.astation_connect_rx.is_none() {
                    // Try now rather than at the next retry; only that
                    // attempt's failure answers this operation.
                    self.app.astation_connect_error = None;
                    self.app.astation_reconnect_at = Some(Instant::now());
                }
                self.op_tick();
            }
            OpCall::Install { client, reply } => {
                self.app.install_astation_link(*client);
                let _ = reply.send(());
            }
            OpCall::Finished {
                request_id,
                kind,
                ok,
            } => {
                if self
                    .op
                    .as_ref()
                    .is_some_and(|op| op.request_id == request_id)
                {
                    self.op = None;
                    self.op_waiting = None;
                    self.app.close_op_route();
                    eprintln!(
                        "atem runtime: {} {}",
                        kind.as_str(),
                        if ok { "done" } else { "failed" }
                    );
                    // A verification makes the link a verified pairing: the
                    // host may attach it now.
                    if ok
                        && matches!(
                            kind,
                            super::protocol::OpKind::Pair | super::protocol::OpKind::PairVerify
                        )
                        && let Some(bridge) = self.bridge.as_mut()
                    {
                        bridge.reconsider();
                    }
                }
            }
        }
    }

    /// The running operation's link: handed over once it is up; closed
    /// when it went down or was replaced (the operation fails, no replay).
    fn op_tick(&mut self) {
        if let Some(link_gen) = self.app.op_route_gen()
            && (!self.app.astation_connected || self.app.astation_link_gen != link_gen)
        {
            eprintln!("atem runtime: the Astation link went away during an operation");
            self.app.close_op_route();
        }
        if !self.app.astation_connected
            && self.op_waiting.is_some()
            && let Some(advice) = self.app.astation_connect_error.take()
            && let Some((_, _, reply)) = self.op_waiting.take()
        {
            let _ = reply.send(Err(advice));
            return;
        }
        if self.app.astation_connected
            && let Some((encryption, credentials, reply)) = self.op_waiting.take()
            && let Some(view) = self.app.open_op_route(encryption, credentials)
            && reply.send(Ok(view)).is_err()
        {
            self.app.close_op_route();
        }
    }

    /// Removes a session without a worker and its record. Nothing is
    /// signalled: while a process the record names still runs (its pid with
    /// the recorded start time), the session and record stay and the error
    /// names it.
    fn forget(&mut self, sid: &SessionId) -> Result<(), String> {
        let state = self.options.launcher.state();
        // The record on disk: a session that ran in this broker has none in memory.
        let record = super::worker::read_record(&super::worker::record_path(state, sid.as_str()))
            .ok()
            .filter(|r| r.session_id == sid.as_str())
            .or_else(|| self.sessions.get(sid).and_then(|s| s.record()).cloned());
        let runs = |pid: Option<u32>, start: Option<u64>| {
            pid.filter(|pid| start.is_some() && super::adopt::process_start_time(*pid) == start)
        };
        let still_running = record.as_ref().and_then(|r| {
            runs(Some(r.worker_pid), Some(r.start_time))
                .map(|pid| ("worker", pid))
                .or_else(|| runs(r.agent_pid, r.agent_start_time).map(|pid| ("agent", pid)))
        });
        if let Some((what, pid)) = still_running {
            return Err(format!(
                "The {what} of {sid} (pid {pid}) still runs; it was not stopped and {sid} was kept. Stop that process, then stop {sid} again"
            ));
        }
        super::broker::remove_record(state, sid.as_str());
        if self.attached.contains_key(sid) {
            self.detach(sid);
        }
        self.remove_session(sid);
        Ok(())
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
            format!("{RESTARTING} for another protocol (protocol {PROTOCOL}, client {version})")
        } else {
            format!(
                "This runtime speaks protocol {PROTOCOL}, not {version}, and has {live} live sessions; stop your sessions (`atem agent list`) or use the atem that started them"
            )
        };
        self.error(id, text, "hello");
        self.close(id);
    }

    /// Local input always writes: through the session host, which revokes
    /// any remote lease first, to the session's worker under its current
    /// input epoch. `Some(message)` back: too many writes are in flight;
    /// keep it and read nothing more from this client meanwhile.
    fn input(&mut self, id: u64, message: ClientMsg) -> Option<ClientMsg> {
        let (session_id, op) = match &message {
            ClientMsg::Input { session_id, .. } => (session_id, "input"),
            ClientMsg::Paste { session_id, .. } => (session_id, "paste"),
            _ => return None,
        };
        let Some(sid) = self.attached_by(id, session_id) else {
            self.error(id, "Attach to the session first", op);
            return None;
        };
        let Some(bracketed) = self
            .sessions
            .get(&sid)
            .filter(|s| s.is_live())
            .map(|s| s.bracketed_paste())
        else {
            self.error(id, "The session has ended", op);
            return None;
        };
        let bytes = match &message {
            ClientMsg::Input { bytes, .. } => input_bytes(bytes),
            // One write, so nothing (no remote byte) comes between its pieces.
            ClientMsg::Paste { bytes, .. } => paste_text(bytes)
                .map(|text| crate::terminal_keys::paste(&text, bracketed).into_bytes()),
            _ => return None,
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error(id, error.to_string(), op);
                return None;
            }
        };
        let session = self.sessions.get_mut(&sid).expect("checked above");
        if !session.can_write() {
            return Some(message);
        }
        let written = match self.bridge.as_mut() {
            Some(bridge) => {
                bridge.local_input(&sid, bytes, &self.app.astation_client, &mut self.sessions)
            }
            None => session.write(&bytes),
        };
        if let Err(error) = written {
            self.error(id, error.to_string(), op);
        }
        None
    }

    /// The session host's pass (after the App's): mark-task prompts the App
    /// queued, then the host itself.
    async fn host_pass(&mut self) {
        let writes = self
            .app
            .hosted
            .as_mut()
            .map(|h| std::mem::take(&mut h.writes))
            .unwrap_or_default();
        for (task_id, sid, text) in writes {
            // Local-origin input under the current epoch; no lease is revoked
            // (the App only sends a task while no remote lease is held).
            let written = match self.sessions.get_mut(&sid) {
                Some(session) => session.write(text.as_bytes()),
                None => Err(anyhow::anyhow!("The session has ended")),
            };
            if let Err(error) = written {
                self.app
                    .mark_write_failed(&task_id, &error.to_string())
                    .await;
            }
        }
        match self.bridge.as_mut() {
            Some(bridge) => bridge.tick(&mut self.app, &mut self.sessions, self.adopting),
            None => {
                super::host_bridge::refuse_all(&mut self.app);
                // No session host: the agents ask in their own prompts.
                for session in self.sessions.values_mut() {
                    session.release_untaken();
                }
                if let Some(hosted) = self.app.hosted.as_mut() {
                    hosted.sessions = self
                        .sessions
                        .values()
                        .filter_map(|s| {
                            Some(crate::app::hosted::HostedSession {
                                id: s.id.clone(),
                                provider: Provider::from_alias(&s.provider)?,
                                cwd: s.cwd.clone(),
                                live: s.is_live(),
                                remote_controlled: false,
                                last_used: s.last_used,
                            })
                        })
                        .collect();
                }
            }
        }
    }

    /// The local frontend's size, unless a remote lease holder owns the
    /// size: then it waits in the attachment until a reclaim.
    fn local_size(&mut self, sid: &SessionId, rows: u16, cols: u16) {
        if self
            .bridge
            .as_ref()
            .is_some_and(|b| b.lease_holder(sid.as_str()).is_some())
        {
            return;
        }
        self.adjust_size(sid, rows, cols);
    }

    /// The local frontend's size for a live session's terminal.
    fn adjust_size(&mut self, sid: &SessionId, rows: u16, cols: u16) {
        if let Some(session) = self.sessions.get_mut(sid)
            && let Err(error) = session.resize(rows, cols)
        {
            self.session_notice(sid, format!("Failed to resize {sid}: {error}"));
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
        let mut summary = self.sessions[sid].summary(self.attached.contains_key(sid));
        summary.remote_controlled = self
            .bridge
            .as_ref()
            .is_some_and(|b| b.lease_holder(sid.as_str()).is_some());
        summary
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
        attachment.sent = Some(summary.clone());
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
            let screen_pending = session.screen_pending();
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
            // A changed summary (activity, remote control, state) after the restore.
            let summary = self.summary(&sid);
            let attachment = self.attached.get_mut(&sid).expect("attached");
            if attachment.restored && attachment.sent.as_ref() != Some(&summary) {
                attachment.sent = Some(summary.clone());
                self.send(client_id, &RuntimeMsg::Session { session: summary });
            }
            let attachment = self.attached.get_mut(&sid).expect("attached");
            // The exit follows the final screen, unless none can come any more.
            if let Some((generation, status)) = exited
                && (attachment.restored || !screen_pending)
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

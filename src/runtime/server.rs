//! The runtime's host loop: one `App` (no TUI) ticked every 16 ms, and local
//! frontends on a same-user Unix socket. Each client has a reader and a writer
//! task; the `App` stays on the host loop, which they reach through channels.

use super::protocol::{
    ClientMsg, DecodeError, MAX_OUTPUT, PROTOCOL, RuntimeMsg, SessionSummary, b64, encode_runtime,
    input_bytes,
};
use crate::agent_client::AgentStatus;
use crate::app::App;
use crate::session::{LaunchRequest, Provider, SessionId};
use futures_util::FutureExt;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, UNIX_EPOCH};
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
    exited_sent: bool,
}

struct Server {
    app: App,
    options: Options,
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
    let mut server = Server {
        app,
        options,
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
                server.app.tick_host().await;
                server.forward_status();
            }
            Some(stream) = accepted.recv() => server.add_client(stream),
            _ = wake.notified() => {}
        }
        server.handle_clients().await;
        server.flush();
        if server.restart || server.idle_expired() {
            break;
        }
    }
    acceptor.abort();
    // Let writers send what's queued (a restart's error) before the sessions end.
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
        if line.len() > super::protocol::MAX_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too long",
            ));
        }
    }
}

fn status_name(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Idle => "idle",
        AgentStatus::Thinking => "thinking",
        AgentStatus::WaitingForInput => "waiting_for_input",
        AgentStatus::Disconnected => "disconnected",
        AgentStatus::Unknown => "unknown",
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
        if let Some(session) = self.app.sessions.get_mut(sid) {
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

    fn idle_expired(&mut self) -> bool {
        let idle = self.app.sessions.iter().next().is_none() && self.clients.is_empty();
        if !idle {
            self.idle_since = None;
            return false;
        }
        let since = *self.idle_since.get_or_insert_with(Instant::now);
        since.elapsed() >= self.options.idle
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
                let request = LaunchRequest {
                    provider,
                    args,
                    cwd,
                    env: Some(env.to_os()),
                    rows,
                    cols,
                };
                match self.app.launch_session(request).await {
                    Ok(sid) => {
                        let session = self.summary(&sid);
                        self.send(id, &RuntimeMsg::Launched { session });
                    }
                    Err(error) => self.error(id, error.to_string(), "launch"),
                }
            }
            ClientMsg::Attach {
                session_id,
                rows,
                cols,
            } => {
                let Some(sid) = self.find(&session_id) else {
                    return self.error(id, "Unknown session", "attach");
                };
                let attachment = Attachment {
                    client: id,
                    size: (rows, cols),
                    screen: (0, 0),
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
                self.app.adjust_terminal_size(&sid, rows, cols);
                if let Some(session) = self.app.sessions.get_mut(&sid) {
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
                // Ignored while a remote viewer controls the size.
                self.app.adjust_terminal_size(&sid, rows, cols);
            }
            ClientMsg::Reclaim { session_id } => {
                let Some(sid) = self.attached_by(id, &session_id) else {
                    return self.error(id, "Attach to the session first", "reclaim");
                };
                if !self.app.sessions.get(&sid).is_some_and(|s| s.is_live()) {
                    return self.send(
                        id,
                        &RuntimeMsg::Notice {
                            text: "The session has ended".into(),
                        },
                    );
                }
                self.app.reclaim_session(&sid);
                let (rows, cols) = self.attached[&sid].size;
                self.app.adjust_terminal_size(&sid, rows, cols);
                self.restore(&sid);
            }
            ClientMsg::List => {
                let sessions = self
                    .app
                    .sessions
                    .ids()
                    .iter()
                    .map(|sid| self.summary(sid))
                    .collect();
                self.send(id, &RuntimeMsg::Sessions { sessions });
            }
            ClientMsg::Stop { session_id } => {
                let Some(sid) = self
                    .find(&session_id)
                    .filter(|sid| self.app.sessions.get(sid).is_some_and(|s| s.is_live()))
                else {
                    return self.error(id, "No such live session", "stop");
                };
                self.app.stop_session(&sid);
                self.send(
                    id,
                    &RuntimeMsg::Notice {
                        text: format!("Stopping {sid}"),
                    },
                );
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

    /// Sends what's queued, then closes the connection.
    fn close(&mut self, id: u64) {
        self.remove_client(id);
    }

    /// Another protocol: a runtime without live sessions restarts (a client
    /// of that protocol starts its own); one with live sessions refuses.
    fn refuse_protocol(&mut self, id: u64, version: u64) {
        let live = self.app.sessions.live_count();
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

    /// Writes an `input` to its session. `Some(message)` back: the PTY queue
    /// is full; keep it and read nothing more from this client meanwhile.
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
        let Some(session) = self.app.sessions.get_mut(&sid).filter(|s| s.is_live()) else {
            self.error(id, "The session has ended", "input");
            return None;
        };
        let Some(input) = &session.input else {
            self.error(id, "The session has no terminal", "input");
            return None;
        };
        if input.queue_full() {
            return Some(message);
        }
        // Counts as terminal input (chat-v1's draft check).
        match input.send_bytes(bytes) {
            Ok(()) => session.last_used = Instant::now(),
            Err(error) => self.error(id, error.to_string(), "input"),
        }
        None
    }

    /// A session id or the `claude`/`codex` alias (live or exited sessions).
    fn find(&self, id_or_alias: &str) -> Option<SessionId> {
        if let Some(sid) = self.app.sessions.resolve(id_or_alias) {
            return Some(sid);
        }
        SessionId::parse(id_or_alias).filter(|sid| self.app.sessions.get(sid).is_some())
    }

    /// The session `session_id` names when `client` is attached to it.
    fn attached_by(&self, client: u64, session_id: &str) -> Option<SessionId> {
        let sid = SessionId::parse(session_id).or_else(|| self.find(session_id))?;
        (self.attached.get(&sid)?.client == client).then_some(sid)
    }

    fn summary(&self, sid: &SessionId) -> SessionSummary {
        let session = self.app.sessions.get(sid).expect("a session");
        let (rows, cols) = session.terminal.screen().size();
        let status = self
            .app
            .agent_registry
            .get(sid.as_str())
            .map_or("unknown", |info| status_name(&info.status));
        SessionSummary {
            id: sid.to_string(),
            provider: session.provider.as_str().into(),
            cwd: session.cwd.clone(),
            created_at_ms: session
                .created_at
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            status: status.into(),
            attached: self.attached.contains_key(sid),
            remote_controlled: session
                .input
                .as_ref()
                .is_some_and(|input| input.remote_controlled()),
            exited: session
                .exited_at
                .and(session.share.exit_status.clone())
                .or_else(|| session.exited_at.map(|_| "exited".into())),
            rows,
            cols,
            generation: session.share.generation.clone(),
        }
    }

    /// Sends the attached frontend a fresh restore: the canonical screen now,
    /// and the stream position output continues from. Output queued for it
    /// before is dropped.
    fn restore(&mut self, sid: &SessionId) {
        let summary = self.summary(sid);
        let Some(attachment) = self.attached.get_mut(sid) else {
            return;
        };
        let Some(session) = self.app.sessions.get_mut(sid) else {
            return;
        };
        let screen = session.terminal.screen();
        let restore = crate::terminal_share::restore_bytes(screen);
        attachment.screen = screen.size();
        // The restore covers everything the tap holds.
        session.tap.take();
        let offset = session.tap.offset();
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
    /// when its backlog overflowed or the screen changed size, and the exit.
    fn flush(&mut self) {
        let sids: Vec<SessionId> = self.attached.keys().cloned().collect();
        for sid in sids {
            let client_id = self.attached[&sid].client;
            let Some(session) = self.app.sessions.get_mut(&sid) else {
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
            let size = session.terminal.screen().size();
            let exited = session.exited_at.is_some().then(|| {
                (
                    session.share.generation.clone(),
                    session
                        .share
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
            let mut resync = chunk.overflowed || size != attachment.screen;
            if !resync {
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
            if let Some((generation, status)) = exited
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

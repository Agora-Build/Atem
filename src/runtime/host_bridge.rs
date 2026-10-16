//! The session host inside `atem runtime` (designs/protocol/atem-session-v1.md,
//! compatibility mode): the broker owns `SessionHost` over a `FileJournal`
//! and performs its effects on the workers.
//!
//! Attachment: the App's authenticated Astation link (direct or relay; the
//! App holds one at a time) is one attachment, created when the link becomes
//! authenticated (`App::astation_link_gen` counts those) and fenced when it
//! drops or Astation re-authenticates it. Only the Astation this profile is
//! paired with (the pairing binding the link captured) and verified with
//! (`cred_state.json`) gets one, with `view` and `control`; any
//! other link — unpaired, unverified, or another Astation — gets no
//! attachment at all, so its session-family messages are answered
//! `unauthorized`. `welcome` names the verified account (`data_account`), this
//! device's id from its verification, and the host trust generation from
//! `pairing.json`; a new identity (a pairing verified after the broker
//! started) restarts the host over the same journal with a new runtime
//! generation and epoch.
//!
//! Writes: every byte the host lets through reaches the worker tagged with
//! the worker's current input epoch. When the host's input epoch for a
//! session moves (a lease ends, is taken over or revoked, local input) after
//! remote bytes were sent or while a lease was held, the broker raises the
//! worker's epoch first (`set_input_epoch`, at least the session's lease
//! epoch), so bytes queued under the old lease are dropped at the worker's
//! write boundary; remote bytes are also checked with `admit_write` right
//! before they are sent. Local frontend input goes through `local_input`
//! (it revokes any remote lease) before it is written. Mark tasks write as
//! local-origin input without revoking: they only run with no lease holder.
//!
//! Dispatch: a prompt is pasted through the worker once the chat session
//! accepted it (`ChatSession::submit`); its receipt completes when the chat
//! reports that turn's end. An interrupt writes Esc and completes when a turn
//! ends (or at once when none runs). A stop stops the agent; its exit
//! completes it. Duplicate session messages (same `id`) within 60 s are
//! handled once, whatever link they came on.
//!
//! Approvals (§6a): a worker's `approval_request` opens an approval in the
//! host (whoever holds the lease); the host's effects become `approval_request`
//! for attachments with `control`, a chat-v1 card in the session's
//! conversations, and push requests for the relay (`push_approval`, then
//! `push_resolved` when it stops being pending), sent over the verified link
//! and kept (latest state per approval, bounded) while it is down. The
//! host's hand-off goes to the worker as `approval_decision`, a release as
//! `release_approval`; the worker's `approval_closed`/`approval_applied`
//! finish them (`not_delivered` → the hand-off failed with no effect). An
//! adopted worker is told the approvals this broker knows (none), so it
//! releases what it held for the previous broker.
use super::broker::{BrokerSession, SessionState as BrokerState, WriteOutcome, WriteTag};
use super::worker_approvals::Event as ApprovalEvent;
use super::worker_protocol::{Activity as WorkerActivity, ApplyOutcome};
use crate::app::App;
use crate::app::hosted::{HostedSession, refusal};
use crate::chat::adapter::{ApprovalCard, ApprovalCardState};
use crate::chat::session::{Out, State as ChatState};
use crate::chat::wire::{self as chat_wire, ChatEnvelope, Inbound};
use crate::session::{Provider, SessionId};
use crate::session_protocol::file_journal::FileJournal;
use crate::session_protocol::host::{
    Attach, ChatReply, DispatchReport, Effect, HostConfig, HostContext, LEASE_EPOCH_BLOCK, Origin,
    SessionHost, SessionSpec, random_ids,
};
use crate::session_protocol::wire::{
    self, Activity, ApprovalCloseReason, ApprovalDecision, ApprovalRequest, ClientKind, Envelope,
    FamilyMessage, Permission, ReceiptKind, SessionState,
};
use crate::terminal_share::{FrameStream, Message as TerminalMessage};
use crate::websocket_client::{AstationClient, AstationMessage};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `advance` runs this often.
const ADVANCE_EVERY: u64 = 100;
/// Identical session messages within this window are handled once.
const DEDUP_MS: u64 = 60_000;
/// The authorization of an authenticated link (compatibility mode has no
/// freshness proof yet): at its end the attachment is fenced and the link
/// dropped; the reconnect authenticates it again and gets a new attachment.
pub(super) const LINK_AUTHORIZATION_MS: u64 = 24 * 60 * 60 * 1000;
/// Terminal messages waiting for the transport before streams are dropped.
const TERMINAL_BACKLOG: usize = 128;
const HEARTBEAT: Duration = Duration::from_secs(15);
const HISTORY_MESSAGES: usize = 50;
const HISTORY_BYTES: usize = 256 * 1024;
/// Open conversations per session; opening one more closes the oldest.
const MAX_CONVERSATIONS: usize = 8;
const RESTARTED: &str = "the agent was restarted; reopen the chat";
const NOT_AVAILABLE: &str = "chat is not available for this agent";
const NO_TURN: &str = "no turn was running";
/// Esc interrupts Claude Code's and Codex's current turn.
const INTERRUPT_KEY: &[u8] = b"\x1b";
/// Identity of a host without a verified pairing (no attachment is ever
/// authorized under it).
const UNPAIRED: &str = "unpaired";
const RUNTIME_EPOCH_FILE: &str = "runtime_epoch";
/// How often the link's pairing capture is checked against `pairing.json`.
const CAPTURE_CHECK: Duration = Duration::from_secs(5);
/// Session messages remembered for duplicate detection, at most.
const MAX_SEEN: usize = 4096;
/// Turn outcomes kept for duplicate submits (cleared beyond it).
const MAX_OUTCOMES: usize = 4096;
/// Push requests kept for the relay while the link is down (the oldest go).
pub(super) const MAX_PUSHES: usize = 64;

/// The broker's monotonic clock in milliseconds, and wall time (tests move
/// either forward).
#[derive(Clone, Debug)]
pub struct Clock {
    origin: Instant,
    skew: Arc<AtomicU64>,
    wall_skew: Arc<AtomicU64>,
}

impl Default for Clock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            skew: Arc::new(AtomicU64::new(0)),
            wall_skew: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Clock {
    pub fn now(&self) -> u64 {
        // The shared fixtures run the real runtime on their own clock.
        let base = super::test_hooks::clock_ms()
            .unwrap_or_else(|| self.origin.elapsed().as_millis() as u64);
        base + self.skew.load(Ordering::SeqCst)
    }

    /// Wall-clock milliseconds since the Unix epoch. Unlike `now`, it moves
    /// while the machine is suspended.
    pub fn wall(&self) -> u64 {
        wall_ms() + self.wall_skew.load(Ordering::SeqCst)
    }

    /// Moves the clock `ms` forward (tests).
    #[cfg(test)]
    pub fn skip(&self, ms: u64) {
        self.skew.fetch_add(ms, Ordering::SeqCst);
    }

    /// Moves wall time `ms` forward, the monotonic clock standing still (a
    /// suspend; tests).
    #[cfg(test)]
    pub fn skip_wall(&self, ms: u64) {
        self.wall_skew.fetch_add(ms, Ordering::SeqCst);
    }
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Who this host is (§2): the verified account and device, and the host
/// trust generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
}

/// The identity `src` is verified under with `astation_id`, if it is.
fn verified_identity(
    src: &crate::status::Sources,
    astation_id: &str,
    host_trust_gen: u64,
) -> Option<Identity> {
    let trust = crate::memory::trust::TrustStore::load_from(&src.keys.trust).ok()?;
    let entry = trust.verified(astation_id)?;
    let identity = Identity {
        account_id: entry.data_account.clone(),
        atem_device_id: entry.device_id.clone(),
        host_trust_gen,
    };
    (wire::is_opaque_id(&identity.account_id) && wire::is_opaque_id(&identity.atem_device_id))
        .then_some(identity)
}

/// The identity of the profile's current pairing (at start), else none.
fn start_identity(src: &crate::status::Sources) -> Identity {
    let state = crate::pairing_binding::load(src).ok();
    let trust_gen = state.as_ref().map_or(0, |s| s.host_trust_gen);
    state
        .and_then(|s| s.binding)
        .and_then(|b| verified_identity(src, &b.astation_id, trust_gen))
        .unwrap_or(Identity {
            account_id: UNPAIRED.into(),
            atem_device_id: UNPAIRED.into(),
            host_trust_gen: trust_gen,
        })
}

/// The identity an authenticated link may attach under: the paired Astation
/// it authenticated with, verified. `None` for any other link.
fn link_identity(client: &AstationClient) -> Option<Identity> {
    let astation_id = client.connected_astation_id()?;
    let capture = client.capture()?;
    capture
        .state
        .binding
        .as_ref()
        .filter(|b| b.astation_id == astation_id)?;
    verified_identity(capture.sources(), astation_id, capture.state.host_trust_gen)
}

/// The next runtime epoch, durably (a counter in `dir`, incremented each start).
fn next_runtime_epoch(dir: &Path) -> anyhow::Result<u64> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(RUNTIME_EPOCH_FILE);
    let previous = match std::fs::read_to_string(&path) {
        Ok(text) => text.trim().parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "{} is damaged; move it aside to reset the runtime epoch",
                path.display()
            )
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e.into()),
    };
    let next = previous
        .checked_add(1)
        .filter(|n| *n <= crate::session_protocol::canonical::MAX_SAFE_INTEGER)
        .ok_or_else(|| anyhow::anyhow!("the runtime epoch is exhausted"))?;
    let temp = dir.join(format!("{RUNTIME_EPOCH_FILE}.tmp"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    file.write_all(next.to_string().as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&temp, &path)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(next)
}

fn host_activity(activity: WorkerActivity) -> Activity {
    match activity {
        WorkerActivity::Ready => Activity::Ready,
        WorkerActivity::Working => Activity::Working,
        WorkerActivity::Waiting => Activity::Waiting,
        WorkerActivity::Unknown => Activity::Unknown,
    }
}

/// Remote terminal input admitted by the host, waiting for room at the worker.
struct RemoteWrite {
    bytes: Vec<u8>,
    host_epoch: u64,
    attachment: String,
    stream_id: String,
    sequence: u64,
}

/// What a write the broker sent for the host was.
enum Pending {
    Input {
        attachment: String,
        stream_id: String,
        sequence: u64,
        process_gen: String,
    },
    Prompt(String),
    Interrupt(String),
}

/// The broker's view of one session the host knows.
struct PerSession {
    /// Registered with the host (an invalid id or generation never is).
    registered: bool,
    /// The host input epoch the worker's epoch was last synced to.
    host_epoch: u64,
    /// Remote bytes were sent under the worker's current epoch.
    dirty: bool,
    /// A lease was held at the last sync.
    held: bool,
    state: BrokerState,
    activity: Option<WorkerActivity>,
    remote: VecDeque<RemoteWrite>,
}

/// An approval the host opened, as the worker knows it.
struct OpenApproval {
    sid: String,
    /// The worker's request id (its hook's files).
    worker_id: String,
    /// The receipt whose answer was handed to the worker.
    receipt: Option<String>,
    /// The chat-v1 card (sessions with chat).
    card: Option<ApprovalCard>,
}

/// A push request for the relay (§6a), kept until it went out.
struct PushEntry {
    approval_id: String,
    /// `push_approval`'s data.
    request: Value,
    /// Wall ms when the agent's hook gives up.
    expires_at: u64,
    /// `push_approval` went out.
    sent: bool,
    /// No longer pending: `push_resolved` is due (only once `sent`).
    resolved: Option<ApprovalCloseReason>,
}

struct Conversation {
    attachment: String,
    /// Sequence of the next event.
    next: u64,
    last_heartbeat: Instant,
    opened: u64,
}

#[derive(Default)]
struct Chats {
    conversations: HashMap<String, Conversation>,
    opens: u64,
}

struct Link {
    link_gen: u64,
    attachment: String,
    /// The attachment's authorization ends at whichever comes first: this
    /// monotonic ms, or this wall-clock ms (the monotonic clock stands still
    /// while the machine is suspended).
    deadline: u64,
    wall_deadline: u64,
}

pub struct HostBridge {
    host: SessionHost<FileJournal>,
    dir: std::path::PathBuf,
    clock: Clock,
    /// The link generation last considered (attached or refused).
    considered: Option<u64>,
    link: Option<Link>,
    last_advance: u64,
    /// When the link's pairing capture was last checked.
    capture_checked: Instant,
    recovered: bool,
    seen: HashMap<String, u64>,
    seen_order: VecDeque<(u64, String)>,
    per: BTreeMap<String, PerSession>,
    /// Adopted sessions to register with `restore_session`.
    restore: HashSet<String>,
    streams: HashMap<(String, String), FrameStream>,
    chats: HashMap<String, Chats>,
    /// request id → (session, conversation) of chat submits.
    submitters: HashMap<String, (String, String)>,
    /// Prompts pasted and not reported yet: request id → session.
    prompts: HashMap<String, String>,
    /// Interrupts waiting for a turn to end, per session.
    interrupts: HashMap<String, Vec<String>>,
    pending: HashMap<(String, u64), Pending>,
    /// terminal-v1 messages in order (frames, acks, errors) waiting for the
    /// bounded terminal queue.
    terminal_out: VecDeque<Queued>,
    /// The outcome a prompt's turn ended with, until its receipt is reported.
    outcomes: HashMap<String, crate::chat::adapter::Outcome>,
    /// approval_id → open approvals.
    approvals: HashMap<String, OpenApproval>,
    /// Push requests for the relay, in order.
    pushes: VecDeque<PushEntry>,
}

/// Where effects go: the link's client and the broker's sessions.
struct Cx<'a> {
    client: &'a AstationClient,
    sessions: &'a mut BTreeMap<SessionId, BrokerSession>,
}

impl HostBridge {
    /// Opens the journal in `dir` (one broker per config dir: another
    /// process holding it is an error), takes the next runtime epoch and
    /// builds the host under `profile`'s current identity.
    pub fn open(
        dir: &Path,
        profile: Option<&crate::status::Sources>,
        clock: Clock,
    ) -> anyhow::Result<Self> {
        let journal = FileJournal::open(dir).map_err(|e| anyhow::anyhow!(e.0))?;
        let epoch = next_runtime_epoch(dir)?;
        let identity = profile.map(start_identity).unwrap_or(Identity {
            account_id: UNPAIRED.into(),
            atem_device_id: UNPAIRED.into(),
            host_trust_gen: 0,
        });
        let host = Self::build(journal, &identity, epoch, &clock)?;
        Ok(Self {
            host,
            dir: dir.to_path_buf(),
            clock,
            considered: None,
            link: None,
            last_advance: 0,
            capture_checked: Instant::now(),
            recovered: false,
            seen: HashMap::new(),
            seen_order: VecDeque::new(),
            per: BTreeMap::new(),
            restore: HashSet::new(),
            streams: HashMap::new(),
            chats: HashMap::new(),
            submitters: HashMap::new(),
            prompts: HashMap::new(),
            interrupts: HashMap::new(),
            pending: HashMap::new(),
            terminal_out: VecDeque::new(),
            outcomes: HashMap::new(),
            approvals: HashMap::new(),
            pushes: VecDeque::new(),
        })
    }

    fn build(
        journal: FileJournal,
        identity: &Identity,
        runtime_epoch: u64,
        clock: &Clock,
    ) -> anyhow::Result<SessionHost<FileJournal>> {
        let ctx = HostContext {
            account_id: identity.account_id.clone(),
            atem_device_id: identity.atem_device_id.clone(),
            host_trust_gen: identity.host_trust_gen,
            runtime_gen: uuid::Uuid::new_v4().to_string(),
            runtime_epoch,
        };
        let config = HostConfig {
            wall_offset_ms: wall_ms().saturating_sub(clock.now()),
            ..HostConfig::default()
        };
        SessionHost::new(ctx, config, journal, random_ids()).map_err(|e| anyhow::anyhow!(e.0))
    }

    /// The link may attach now (its pairing was just verified): it is
    /// considered again at the next pass, unless it is attached already.
    pub fn reconsider(&mut self) {
        if self.link.is_none() {
            self.considered = None;
        }
    }

    /// The attachment holding `session_id`'s lease.
    pub fn lease_holder(&self, session_id: &str) -> Option<&str> {
        self.host.lease_holder(session_id)
    }

    /// An adopted worker's input epoch against the journal (before the
    /// session is registered): one beyond the reserved block was never
    /// granted by a broker of this journal, so the session is
    /// `recovery_required`; below the floor it is raised to it.
    pub fn check_adoption(&mut self, session: &mut BrokerSession) {
        let sid = session.id.to_string();
        if session.is_live() {
            let floor = self.host.lease_floor(&sid);
            let hello = session.input_epoch();
            if hello > floor.saturating_add(LEASE_EPOCH_BLOCK) {
                session.refuse_adoption("its input epoch is ahead of the journal");
            } else if floor > hello {
                let _ = session.raise_input_epoch_to(floor);
            }
            // Approvals live in a broker's memory: this one knows none of
            // what the worker held for the previous one, so it releases them.
            let _ = session.known_approvals(Vec::new());
        }
        self.restore.insert(sid);
    }

    /// Local frontend input: revokes any remote lease (a new input epoch,
    /// sent to the worker first when a lease was held or remote bytes were
    /// sent), then writes `bytes` (none for a reclaim). Local writes in
    /// flight — typing, a mark task's prompt — are never dropped by it, so
    /// the worker's epoch only moves with remote control (within the
    /// journal's reserved block).
    pub fn local_input(
        &mut self,
        sid: &SessionId,
        bytes: Vec<u8>,
        client: &AstationClient,
        sessions: &mut BTreeMap<SessionId, BrokerSession>,
    ) -> anyhow::Result<()> {
        let mut cx = Cx { client, sessions };
        if !self.per.get(sid.as_str()).is_some_and(|p| p.registered) {
            // Not a host session (yet): write as is.
            if bytes.is_empty() {
                // No remote lease can exist: nothing to reclaim.
                return Ok(());
            }
            let session = cx
                .sessions
                .get_mut(sid)
                .ok_or_else(|| anyhow::anyhow!("The session has ended"))?;
            return session.write(&bytes);
        }
        let effects = self.host.local_input(sid.as_str(), bytes);
        let mut result = Ok(());
        for effect in effects {
            if let Effect::PtyWrite {
                session_id,
                bytes,
                origin: Origin::Local,
            } = &effect
            {
                self.sync_epoch(session_id, &mut cx);
                if bytes.is_empty() {
                    continue;
                }
                if let Some(session) =
                    SessionId::parse(session_id).and_then(|id| cx.sessions.get_mut(&id))
                {
                    result = session.write(bytes);
                }
                continue;
            }
            self.exec(vec![effect], &mut cx);
        }
        self.sync_all(&mut cx);
        result
    }

    /// One pass: the link, the sessions, the messages the App received, what
    /// the workers reported, timers, writes, frames and chat.
    pub fn tick(
        &mut self,
        app: &mut App,
        sessions: &mut BTreeMap<SessionId, BrokerSession>,
        adopting: bool,
    ) {
        if self
            .link
            .as_ref()
            .is_some_and(|l| self.clock.now() >= l.deadline || self.clock.wall() >= l.wall_deadline)
        {
            // Its authorization ended: the attachment is fenced and the link
            // dropped, so the normal reconnect authenticates it again.
            app.drop_astation_link("Astation link authorization expired; reconnecting".into());
        }
        if self.capture_checked.elapsed() >= CAPTURE_CHECK {
            self.capture_checked = Instant::now();
            // `atem unpair` (or a new pairing) changed the pairing this link
            // authenticated under, even if no `reload` reached the runtime:
            // drop the link with its attachment.
            let stale = app.astation_connected
                && app
                    .astation_client
                    .capture()
                    .is_some_and(|capture| capture.check().is_err());
            if stale {
                app.drop_astation_link("The Astation pairing changed; the link was dropped".into());
            }
        }
        let client = &app.astation_client;
        let mut cx = Cx { client, sessions };
        self.sync_link(app_link(app), &mut cx);
        self.sync_sessions(&mut cx);
        if !adopting && !self.recovered {
            self.recovered = true;
            let effects = self.host.recover();
            self.exec(effects, &mut cx);
        }
        if !adopting && let Some(hosted) = app.hosted.as_mut() {
            let inbox: Vec<(u64, String)> = hosted.inbox.drain(..).collect();
            for (link_gen, text) in inbox {
                self.receive(link_gen, &text, &mut cx);
            }
        }
        self.worker_reports(&mut cx);
        let now = self.clock.now();
        if now >= self.last_advance + ADVANCE_EVERY {
            self.last_advance = now;
            let effects = self.host.advance(now);
            self.exec(effects, &mut cx);
        }
        self.sync_all(&mut cx);
        self.drain_remote(&mut cx);
        self.frames(&mut cx);
        self.heartbeats(&mut cx);
        self.flush_pushes(&mut cx);
        if let Some(hosted) = app.hosted.as_mut() {
            hosted.sessions = cx
                .sessions
                .values()
                .filter_map(|s| {
                    Some(HostedSession {
                        id: s.id.clone(),
                        provider: Provider::from_alias(&s.provider)?,
                        cwd: s.cwd.clone(),
                        live: s.is_live(),
                        remote_controlled: self.host.lease_holder(s.id.as_str()).is_some(),
                        last_used: s.last_used,
                    })
                })
                .collect();
        }
    }

    // ── The link ──

    fn sync_link(&mut self, want: Option<u64>, cx: &mut Cx) {
        if want == self.considered {
            return;
        }
        if let Some(link) = self.link.take() {
            self.drop_attachment(&link.attachment, cx);
        }
        self.considered = want;
        if want.is_none() {
            return;
        }
        let Some(identity) = link_identity(cx.client) else {
            eprintln!(
                "atem runtime: the Astation link is not a verified pairing; no session attachment"
            );
            return;
        };
        if !self.adopt_identity(&identity, cx) {
            return;
        }
        let attachment = uuid::Uuid::new_v4().to_string();
        let attach = Attach {
            client: cx
                .client
                .connected_astation_id()
                .unwrap_or_default()
                .to_string(),
            attachment_gen: attachment.clone(),
            permissions: vec![Permission::View, Permission::Control],
            client_kind: ClientKind::Native,
            authorization_ms: LINK_AUTHORIZATION_MS,
        };
        match self.host.connect(attach) {
            Ok(effects) => {
                self.link = Some(Link {
                    link_gen: want.unwrap_or_default(),
                    attachment,
                    deadline: self.clock.now().saturating_add(LINK_AUTHORIZATION_MS),
                    wall_deadline: self.clock.wall().saturating_add(LINK_AUTHORIZATION_MS),
                });
                self.exec(effects, cx);
            }
            Err(error) => eprintln!("atem runtime: session attachment refused: {error}"),
        }
    }

    /// The host runs under `identity`: a later trust generation moves it on;
    /// another account or device restarts the host (new runtime generation
    /// and epoch) over the same journal. False when the link's trust
    /// generation is older than the host's.
    fn adopt_identity(&mut self, identity: &Identity, cx: &mut Cx) -> bool {
        let ctx = self.host.context().clone();
        if identity.host_trust_gen < ctx.host_trust_gen {
            eprintln!("atem runtime: the Astation link's pairing is older than this host's");
            return false;
        }
        if identity.account_id == ctx.account_id && identity.atem_device_id == ctx.atem_device_id {
            if identity.host_trust_gen > ctx.host_trust_gen {
                match self.host.change_trust_gen(identity.host_trust_gen) {
                    Ok(effects) => self.exec(effects, cx),
                    Err(error) => {
                        eprintln!("atem runtime: {error}");
                        return false;
                    }
                }
            }
            return true;
        }
        let epoch = match next_runtime_epoch(&self.dir) {
            Ok(epoch) => epoch,
            Err(error) => {
                eprintln!("atem runtime: {error:#}");
                return false;
            }
        };
        let runtime_gen = uuid::Uuid::new_v4().to_string();
        match self.host.rebind(
            &identity.account_id,
            &identity.atem_device_id,
            identity.host_trust_gen,
            &runtime_gen,
            epoch,
        ) {
            Ok(effects) => {
                // Every attachment, stream and conversation belonged to the old host.
                self.streams.clear();
                self.chats.clear();
                self.submitters.clear();
                for per in self.per.values_mut() {
                    per.remote.clear();
                    per.host_epoch = u64::MAX;
                }
                self.exec(effects, cx);
                self.sync_all(cx);
                true
            }
            Err(error) => {
                eprintln!(
                    "atem runtime: the session host could not take the new identity: {error}"
                );
                false
            }
        }
    }

    fn drop_attachment(&mut self, attachment: &str, cx: &mut Cx) {
        let effects = self.host.disconnect(attachment);
        self.exec(effects, cx);
        self.streams.retain(|(att, _), _| att != attachment);
        for chats in self.chats.values_mut() {
            chats
                .conversations
                .retain(|_, c| c.attachment != attachment);
        }
        self.terminal_out.clear();
        for per in self.per.values_mut() {
            per.remote.retain(|w| w.attachment != attachment);
        }
    }

    fn current(&self, attachment: &str) -> bool {
        self.link
            .as_ref()
            .is_some_and(|l| l.attachment == attachment)
    }

    // ── Messages ──

    fn receive(&mut self, link_gen: u64, text: &str, cx: &mut Cx) {
        let decoded = wire::decode(text.as_bytes());
        let Some(attachment) = self
            .link
            .as_ref()
            .filter(|l| l.link_gen == link_gen)
            .map(|l| l.attachment.clone())
        else {
            // No attachment for this link (not a verified pairing, or gone).
            if self.considered == Some(link_gen) {
                let re = match &decoded {
                    Ok(Envelope::Session(m)) => Some(m.id.clone()),
                    Ok(Envelope::Family(_)) => None,
                    Err(e) => e.id.clone(),
                };
                let _ = cx.client.try_send_wire(unauthorized(re), false);
            }
            return;
        };
        let now = self.clock.now();
        if let Ok(Envelope::Session(m)) = &decoded {
            // The same message on this attachment again (e.g. over both
            // transports): same id and same content. Another content under
            // the id, or a retry on a new attachment, is handled.
            use sha2::Digest;
            let digest = sha2::Sha256::digest(text.as_bytes());
            let key = format!("{attachment} {} {digest:x}", m.id);
            if self.duplicate(&key, now) {
                return;
            }
        }
        let effects = self.host.receive_decoded(&attachment, decoded, now);
        self.exec(effects, cx);
    }

    /// The same session message (attachment, `id`, content) was handled
    /// within the window.
    fn duplicate(&mut self, id: &str, now: u64) -> bool {
        while let Some((at, old)) = self.seen_order.front() {
            if now.saturating_sub(*at) < DEDUP_MS {
                break;
            }
            if self.seen.get(old) == Some(at) {
                self.seen.remove(old);
            }
            self.seen_order.pop_front();
        }
        if self.seen.contains_key(id) {
            return true;
        }
        self.seen.insert(id.to_string(), now);
        self.seen_order.push_back((now, id.to_string()));
        // Bounded: beyond `MAX_SEEN` the oldest are forgotten early.
        while self.seen_order.len() > MAX_SEEN {
            if let Some((at, old)) = self.seen_order.pop_front()
                && self.seen.get(&old) == Some(&at)
            {
                self.seen.remove(&old);
            }
        }
        false
    }

    fn send(&mut self, attachment: &str, message: &Envelope, cx: &mut Cx) {
        if !self.current(attachment) {
            return;
        }
        let text = String::from_utf8(wire::encode(message)).expect("wire JSON is UTF-8");
        let terminal = matches!(message, Envelope::Family(f) if f.family == "terminal");
        if terminal {
            self.terminal_out.push_back(Queued::Other(text));
            self.flush_terminal(cx);
        } else {
            let _ = cx.client.try_send_wire(text, false);
        }
    }

    fn flush_terminal(&mut self, cx: &mut Cx) {
        while let Some(queued) = self.terminal_out.front() {
            let (Queued::Frame(text) | Queued::Other(text)) = queued;
            if cx.client.try_send_wire(text.clone(), true).is_err() {
                break;
            }
            self.terminal_out.pop_front();
        }
    }

    fn send_chat(&self, env: ChatEnvelope, cx: &mut Cx) {
        let text = serde_json::to_string(&AstationMessage::AgentChat(env))
            .expect("chat envelopes serialize");
        let _ = cx.client.try_send_wire(text, false);
    }

    // ── Effects ──

    fn exec(&mut self, effects: Vec<Effect>, cx: &mut Cx) {
        for effect in effects {
            match effect {
                Effect::Send {
                    attachment,
                    message,
                } => self.send(&attachment, &message, cx),
                // A fenced attachment of this link's client: already gone.
                Effect::Close { .. } => {}
                Effect::PtyWrite {
                    session_id,
                    bytes,
                    origin,
                } => match origin {
                    Origin::Local => {
                        self.sync_epoch(&session_id, cx);
                        if let Some(session) = session_of(cx, &session_id) {
                            let _ = session.write(&bytes);
                        }
                    }
                    Origin::Remote {
                        input_epoch,
                        attachment,
                        stream_id,
                        sequence,
                    } => {
                        if let Some(per) = self.per.get_mut(&session_id) {
                            per.remote.push_back(RemoteWrite {
                                bytes,
                                host_epoch: input_epoch,
                                attachment,
                                stream_id,
                                sequence,
                            });
                        }
                    }
                },
                Effect::Resize {
                    session_id,
                    rows,
                    cols,
                } => {
                    if let Some(session) = session_of(cx, &session_id) {
                        let _ = session.resize(rows, cols);
                    }
                }
                Effect::Stop { session_id } => {
                    if let Some(session) = session_of(cx, &session_id) {
                        let _ = session.stop();
                    }
                }
                Effect::StreamOpened {
                    attachment,
                    session_id,
                    stream_id,
                } => {
                    let generation = self
                        .host
                        .descriptor_of(&session_id)
                        .map(|d| d.process_gen)
                        .unwrap_or_default();
                    self.streams.insert(
                        (attachment, session_id.clone()),
                        FrameStream::new(&session_id, &generation, &stream_id),
                    );
                }
                Effect::StreamClosed {
                    attachment,
                    session_id,
                    stream_id,
                } => {
                    let key = (attachment, session_id);
                    if self
                        .streams
                        .get(&key)
                        .is_some_and(|s| s.stream_id == stream_id)
                    {
                        self.streams.remove(&key);
                    }
                }
                Effect::Forward {
                    attachment,
                    session_id,
                    message,
                } => self.forward(&attachment, &session_id, &message, cx),
                Effect::Dispatch {
                    request_id,
                    target,
                    kind,
                    payload,
                } => {
                    let report = self.dispatch(&request_id, &target.session_id, kind, &payload, cx);
                    if let Some(report) = report {
                        let effects = self.host.dispatch_report(&request_id, report);
                        self.exec(effects, cx);
                    }
                }
                Effect::Reconcile { request_id, .. } => {
                    // A broker restart can't tell what an executing request did.
                    let effects = self
                        .host
                        .dispatch_report(&request_id, DispatchReport::Unknown);
                    self.exec(effects, cx);
                }
                Effect::Approval {
                    request_id,
                    session_id,
                    approval_id,
                    decision,
                    rule_id,
                    message,
                } => self.hand_off(
                    &request_id,
                    &session_id,
                    &approval_id,
                    decision,
                    rule_id,
                    message,
                    cx,
                ),
                Effect::ApprovalReleased {
                    session_id,
                    approval_id,
                } => {
                    if let Some(open) = self.approvals.remove(&approval_id)
                        && let Some(session) = session_of(cx, &session_id)
                    {
                        let _ = session.release_approval(&open.worker_id);
                    }
                }
                Effect::PushApproval { request } => self.approval_opened(request, cx),
                Effect::PushResolved {
                    approval_id,
                    reason,
                } => self.approval_resolved(&approval_id, reason, cx),
                Effect::Chat {
                    attachment,
                    conversation_id,
                    session_id,
                    reply,
                } => self.chat_reply(&attachment, &conversation_id, &session_id, reply, cx),
            }
        }
    }

    /// Performs a request; `Some` when its outcome is known at once.
    fn dispatch(
        &mut self,
        request_id: &str,
        sid: &str,
        kind: ReceiptKind,
        payload: &Value,
        cx: &mut Cx,
    ) -> Option<DispatchReport> {
        let not_after = self.not_after(sid);
        let Some(session) = session_of(cx, sid).filter(|s| s.is_live()) else {
            return Some(DispatchReport::FailedNoEffect);
        };
        match kind {
            ReceiptKind::Prompt => {
                let text = payload.get("text").and_then(Value::as_str).unwrap_or("");
                if !session.chat_v1 {
                    // No chat to observe the turn's end: nothing is typed.
                    return Some(DispatchReport::FailedNoEffect);
                }
                let generation = session.chat.generation().to_string();
                let input_count = session.input_count;
                let text =
                    match session
                        .chat
                        .submit(request_id, &generation, text, input_count, false)
                    {
                        Ok(text) => text,
                        Err(_) => return Some(DispatchReport::FailedNoEffect),
                    };
                match session.paste(&text, not_after) {
                    Ok(seq) => {
                        session.chat.mark_pasted(request_id, Instant::now());
                        self.pending
                            .insert((sid.to_string(), seq), Pending::Prompt(request_id.into()));
                        self.prompts.insert(request_id.into(), sid.to_string());
                        None
                    }
                    Err(error) => {
                        session.chat.paste_failed(request_id, &error.to_string());
                        Some(DispatchReport::FailedNoEffect)
                    }
                }
            }
            ReceiptKind::Interrupt => {
                let state = session.chat.status().state;
                if session.chat_v1 && !matches!(state, ChatState::Working | ChatState::Waiting) {
                    return Some(DispatchReport::Completed {
                        detail: Some(NO_TURN.into()),
                        turn_id: None,
                    });
                }
                match session.write_tagged(INTERRUPT_KEY, WriteTag::Host, not_after) {
                    Ok(seq) => {
                        self.pending.insert(
                            (sid.to_string(), seq),
                            Pending::Interrupt(request_id.into()),
                        );
                        self.interrupts
                            .entry(sid.to_string())
                            .or_default()
                            .push(request_id.into());
                        None
                    }
                    Err(_) => Some(DispatchReport::FailedNoEffect),
                }
            }
            // The exit completes it (`process_exited`).
            ReceiptKind::Stop => match session.stop() {
                Ok(()) => None,
                Err(_) => Some(DispatchReport::FailedNoEffect),
            },
            // Approval answers are handed over with `Effect::Approval`.
            ReceiptKind::Approval => Some(DispatchReport::FailedNoEffect),
        }
    }

    // ── Sessions ──

    fn sync_sessions(&mut self, cx: &mut Cx) {
        let gone: Vec<String> = self
            .per
            .keys()
            .filter(|sid| SessionId::parse(sid).is_none_or(|id| !cx.sessions.contains_key(&id)))
            .cloned()
            .collect();
        for sid in gone {
            self.approvals.retain(|_, a| a.sid != sid);
            let registered = self.per.remove(&sid).is_some_and(|p| p.registered);
            if registered {
                let effects = self.host.remove_session(&sid);
                self.exec(effects, cx);
            }
            self.end_conversations(&sid, RESTARTED, cx);
            self.streams.retain(|(_, s), _| s != &sid);
            self.interrupts.remove(&sid);
        }
        let ids: Vec<SessionId> = cx.sessions.keys().cloned().collect();
        for id in ids {
            let sid = id.to_string();
            if !self.per.contains_key(&sid) {
                self.register(&id, cx);
            }
            self.sync_state(&id, cx);
        }
    }

    fn register(&mut self, id: &SessionId, cx: &mut Cx) {
        let sid = id.to_string();
        let session = &cx.sessions[id];
        let (rows, cols) = session.size();
        let spec = SessionSpec {
            session_id: sid.clone(),
            process_gen: session.process_gen.clone(),
            provider: session.provider.clone(),
            cwd_label: session
                .cwd
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            chat: session.provider == Provider::Claude.as_str(),
            rows,
            cols,
        };
        let result = if self.restore.remove(&sid) {
            self.host.restore_session(spec)
        } else {
            self.host
                .add_session(spec.clone())
                .or_else(|_| self.host.restore_session(spec))
        };
        let registered = match result {
            Ok(effects) => {
                self.exec(effects, cx);
                true
            }
            Err(error) => {
                eprintln!("atem runtime: {sid} is not served to Astation: {error}");
                false
            }
        };
        self.per.insert(
            sid.clone(),
            PerSession {
                registered,
                host_epoch: self.host.input_epoch(&sid).unwrap_or(0),
                dirty: false,
                held: false,
                state: BrokerState::Running,
                activity: None,
                remote: VecDeque::new(),
            },
        );
    }

    /// The session's lifecycle and activity, as the host's registry shows it.
    fn sync_state(&mut self, id: &SessionId, cx: &mut Cx) {
        let sid = id.as_str();
        let session = &cx.sessions[id];
        let (state, status, activity) =
            (session.state, session.exit_status.clone(), session.activity);
        let Some(per) = self.per.get_mut(sid).filter(|p| p.registered) else {
            return;
        };
        if per.state != state {
            per.state = state;
            per.remote.clear();
            let effects = match state {
                BrokerState::Running => Vec::new(),
                BrokerState::Exited => self.host.process_exited(sid, status),
                BrokerState::Interrupted => {
                    self.host
                        .process_lost(sid, SessionState::Interrupted, status)
                }
                BrokerState::RecoveryRequired => {
                    self.host
                        .process_lost(sid, SessionState::RecoveryRequired, status)
                }
            };
            self.interrupts.remove(sid);
            // Nothing more is answered for this process's writes.
            self.pending.retain(|(s, _), _| s != sid);
            self.prompts.retain(|_, s| s != sid);
            self.exec(effects, cx);
            return;
        }
        if state == BrokerState::Running && per.activity != Some(activity) {
            per.activity = Some(activity);
            if let Ok(effects) = self
                .host
                .set_activity(sid, host_activity(activity), wall_ms())
            {
                self.exec(effects, cx);
            }
        }
    }

    // ── Input epochs and remote writes ──

    /// Where a remote write for `sid` stops being valid at the worker's PTY
    /// write boundary: its lease's deadline, as `pty_session::monotonic_ns`
    /// (the base every process shares). `None` without a lease.
    fn not_after(&self, sid: &str) -> Option<u64> {
        let left_ms = self
            .host
            .lease_deadline(sid)?
            .saturating_sub(self.clock.now());
        Some(crate::pty_session::monotonic_ns().saturating_add(left_ms.saturating_mul(1_000_000)))
    }

    fn sync_all(&mut self, cx: &mut Cx) {
        let sids: Vec<String> = self.per.keys().cloned().collect();
        for sid in sids {
            self.sync_epoch(&sid, cx);
        }
    }

    /// The host's input epoch for `sid` moved: if remote bytes may be queued
    /// at the worker (sent under its current epoch, or a lease was held),
    /// the worker's epoch is raised before anything else is written.
    fn sync_epoch(&mut self, sid: &str, cx: &mut Cx) {
        let Some(host_epoch) = self.host.input_epoch(sid) else {
            return;
        };
        let lease_epoch = self.host.lease_epoch(sid).unwrap_or(0);
        let holder = self.host.lease_holder(sid).is_some();
        let Some(per) = self.per.get_mut(sid) else {
            return;
        };
        if per.host_epoch != host_epoch {
            per.host_epoch = host_epoch;
            if per.dirty || per.held {
                per.dirty = false;
                if let Some(session) = session_of(cx, sid) {
                    let _ = session.raise_input_epoch_to(lease_epoch);
                }
            }
        }
        per.held = holder;
    }

    fn drain_remote(&mut self, cx: &mut Cx) {
        let now = self.clock.now();
        let sids: Vec<String> = self
            .per
            .iter()
            .filter(|(_, p)| !p.remote.is_empty())
            .map(|(sid, _)| sid.clone())
            .collect();
        for sid in sids {
            loop {
                let Some(session) = session_of(cx, &sid) else {
                    break;
                };
                if !session.can_write() {
                    break;
                }
                let process_gen = session.process_gen.clone();
                let Some(write) = self.per.get_mut(&sid).and_then(|p| p.remote.pop_front()) else {
                    break;
                };
                // The PTY write boundary: the lease that admitted it still holds.
                let error = if self.host.admit_write(&sid, write.host_epoch, now) {
                    self.sync_epoch(&sid, cx);
                    let not_after = self.not_after(&sid);
                    let session = session_of(cx, &sid).expect("checked above");
                    match session.write_tagged(&write.bytes, WriteTag::Host, not_after) {
                        Ok(seq) => {
                            if let Some(per) = self.per.get_mut(&sid) {
                                per.dirty = true;
                            }
                            self.pending.insert(
                                (sid.clone(), seq),
                                Pending::Input {
                                    attachment: write.attachment,
                                    stream_id: write.stream_id,
                                    sequence: write.sequence,
                                    process_gen,
                                },
                            );
                            continue;
                        }
                        Err(error) => error.to_string(),
                    }
                } else {
                    "control changed; not written".to_string()
                };
                self.written(
                    &write.attachment,
                    &sid,
                    &process_gen,
                    &write.stream_id,
                    write.sequence,
                    Some(error),
                    cx,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn written(
        &mut self,
        attachment: &str,
        sid: &str,
        generation: &str,
        stream_id: &str,
        sequence: u64,
        error: Option<String>,
        cx: &mut Cx,
    ) {
        if !self.current(attachment) {
            return;
        }
        let message = TerminalMessage::Written {
            terminal_id: sid.into(),
            generation: generation.into(),
            stream_id: stream_id.into(),
            sequence,
            error,
        };
        self.queue_terminal(message, cx);
    }

    fn queue_terminal(&mut self, message: TerminalMessage, cx: &mut Cx) {
        let text = serde_json::to_string(&AstationMessage::Terminal(message.into()))
            .expect("terminal messages serialize");
        self.terminal_out.push_back(Queued::Other(text));
        self.flush_terminal(cx);
    }

    /// What the workers answered and the chat sessions produced.
    fn worker_reports(&mut self, cx: &mut Cx) {
        let ids: Vec<SessionId> = cx.sessions.keys().cloned().collect();
        for id in ids {
            let sid = id.to_string();
            let session = cx.sessions.get_mut(&id).expect("listed");
            let results = session.take_results();
            let outs = session.take_chat();
            let reset = session.take_chat_reset();
            let approvals = session.take_approvals();
            for result in results {
                self.write_result(&sid, result, cx);
            }
            self.worker_approvals(&sid, approvals, cx);
            self.chat_outs(&sid, outs, cx);
            if let Some(reason) = reset {
                self.end_conversations(&sid, reason, cx);
            }
        }
    }

    fn write_result(&mut self, sid: &str, result: WriteOutcome, cx: &mut Cx) {
        let Some(pending) = self.pending.remove(&(sid.to_string(), result.seq)) else {
            return;
        };
        let failure = classify(&result);
        match pending {
            Pending::Input {
                attachment,
                stream_id,
                sequence,
                process_gen,
            } => {
                let error = if result.dropped {
                    Some("control changed; not written".to_string())
                } else if !result.ok {
                    Some(result.error.unwrap_or_else(|| "the write failed".into()))
                } else {
                    None
                };
                self.written(
                    &attachment,
                    sid,
                    &process_gen,
                    &stream_id,
                    sequence,
                    error,
                    cx,
                );
            }
            Pending::Prompt(request_id) => {
                if let Some(report) = failure {
                    self.prompts.remove(&request_id);
                    if let Some(session) = session_of(cx, sid) {
                        let reason = result.error.unwrap_or_else(|| "not written".into());
                        session.chat.paste_failed(&request_id, &reason);
                    }
                    let effects = self.host.dispatch_report(&request_id, report);
                    self.exec(effects, cx);
                }
            }
            Pending::Interrupt(request_id) => {
                if let Some(report) = failure {
                    if let Some(waiting) = self.interrupts.get_mut(sid) {
                        waiting.retain(|r| r != &request_id);
                    }
                    let effects = self.host.dispatch_report(&request_id, report);
                    self.exec(effects, cx);
                }
            }
        }
    }

    // ── Approvals (§6a) ──

    /// What a worker reported about its waiting hooks.
    fn worker_approvals(&mut self, sid: &str, events: Vec<ApprovalEvent>, cx: &mut Cx) {
        for event in events {
            match event {
                ApprovalEvent::Request { request_id, info } => {
                    self.open_approval(sid, request_id, info, cx)
                }
                ApprovalEvent::Closed { request_id, reason } => {
                    let Some(id) = self.approval_of(sid, &request_id) else {
                        continue;
                    };
                    let handed_off = self.approvals.get(&id).is_some_and(|o| o.receipt.is_some());
                    if handed_off {
                        // The answers crossed, or the agent ended first.
                        self.card_state(&id, ApprovalCardState::Closed, cx);
                    }
                    // A pending one's card follows the host's close.
                    let effects = self.host.close_approval(&id, reason);
                    self.exec(effects, cx);
                    self.approvals.remove(&id);
                }
                ApprovalEvent::Applied {
                    request_id,
                    outcome,
                } => {
                    let Some(id) = self.approval_of(sid, &request_id) else {
                        continue;
                    };
                    let effects = match outcome {
                        ApplyOutcome::Ok => self.host.approval_applied(&id, true),
                        ApplyOutcome::Unknown => {
                            self.card_state(&id, ApprovalCardState::Closed, cx);
                            self.host.approval_applied(&id, false)
                        }
                        // Nothing reached the agent: the hand-off failed with
                        // no effect (and its prompt is released).
                        ApplyOutcome::NotDelivered => {
                            self.card_state(&id, ApprovalCardState::Closed, cx);
                            match self.approvals.get(&id).and_then(|a| a.receipt.clone()) {
                                Some(rid) => self
                                    .host
                                    .dispatch_report(&rid, DispatchReport::FailedNoEffect),
                                None => Vec::new(),
                            }
                        }
                    };
                    self.exec(effects, cx);
                    self.approvals.remove(&id);
                }
            }
        }
    }

    /// The host approval id of `sid`'s worker request `worker_id`.
    fn approval_of(&self, sid: &str, worker_id: &str) -> Option<String> {
        self.approvals
            .iter()
            .find(|(_, a)| a.sid == sid && a.worker_id == worker_id)
            .map(|(id, _)| id.clone())
    }

    /// A worker's waiting hook: opened in the host, or "no decision" at once
    /// (an unregistered or ended session, a refusal).
    fn open_approval(
        &mut self,
        sid: &str,
        worker_id: String,
        info: crate::session_protocol::host::ApprovalInfo,
        cx: &mut Cx,
    ) {
        let process_gen = session_of(cx, sid).map(|s| s.process_gen.clone());
        let registered = self.per.get(sid).is_some_and(|p| p.registered);
        let opened = match process_gen.filter(|_| registered) {
            Some(process_gen) => {
                let now = self.clock.now();
                let (opened, effects) = self.host.open_approval(sid, &process_gen, info, now);
                if let Ok(id) = &opened {
                    self.approvals.insert(
                        id.clone(),
                        OpenApproval {
                            sid: sid.to_string(),
                            worker_id: worker_id.clone(),
                            receipt: None,
                            card: None,
                        },
                    );
                }
                self.exec(effects, cx);
                opened
            }
            None => Err("not a host session".into()),
        };
        if let Err(error) = opened {
            eprintln!("atem runtime: {sid}: approval not offered remotely: {error}");
            if let Some(session) = session_of(cx, sid) {
                let _ = session.release_approval(&worker_id);
            }
        }
    }

    /// The host handed an answer over: to the worker's waiting hook.
    #[allow(clippy::too_many_arguments)]
    fn hand_off(
        &mut self,
        request_id: &str,
        sid: &str,
        approval_id: &str,
        decision: ApprovalDecision,
        rule_id: Option<String>,
        message: Option<String>,
        cx: &mut Cx,
    ) {
        let worker_id = self.approvals.get(approval_id).map(|a| a.worker_id.clone());
        let sent = match (worker_id, session_of(cx, sid)) {
            (Some(worker_id), Some(session)) => session
                .approval_decision(&worker_id, decision, rule_id, message)
                .is_ok(),
            _ => false,
        };
        if !sent {
            self.card_state(approval_id, ApprovalCardState::Closed, cx);
            let effects = self
                .host
                .dispatch_report(request_id, DispatchReport::FailedNoEffect);
            self.exec(effects, cx);
            self.approvals.remove(approval_id);
            return;
        }
        if let Some(open) = self.approvals.get_mut(approval_id) {
            open.receipt = Some(request_id.to_string());
        }
        let state = match decision {
            ApprovalDecision::AllowOnce => ApprovalCardState::Allowed,
            ApprovalDecision::AllowAlways => ApprovalCardState::AlwaysAllowed,
            ApprovalDecision::Deny => ApprovalCardState::Denied,
        };
        self.card_state(approval_id, state, cx);
    }

    /// A new pending approval: its card in the session's conversations, and
    /// a push request for the relay.
    fn approval_opened(&mut self, request: ApprovalRequest, cx: &mut Cx) {
        let sid = request.session_id.clone();
        let codex = session_of(cx, &sid).is_some_and(|s| s.provider == Provider::Codex.as_str());
        let timeout = if codex {
            crate::chat::approvals::CODEX_TIMEOUT
        } else {
            crate::chat::approvals::CLAUDE_TIMEOUT
        };
        let expires_at = request.created_at.saturating_add(timeout * 1000);
        let chat = self
            .host
            .descriptor_of(&sid)
            .is_some_and(|d| d.capabilities.iter().any(|c| c == "chat-v1"));
        if chat {
            let card = ApprovalCard {
                id: "approval".into(),
                approval_id: request.approval_id.clone(),
                tool: request.tool.clone(),
                summary: request.summary.clone(),
                always_rules: request.always_rules.clone(),
                state: ApprovalCardState::Pending,
            };
            self.card(
                &request.approval_id,
                Some(card),
                ApprovalCardState::Pending,
                cx,
            );
        }
        let data = json!({
            "v": 1,
            "op": "push_approval",
            "approval_id": request.approval_id,
            "atem_device_id": self.host.context().atem_device_id,
            "session_id": sid,
            "tool": request.tool,
            "summary": request.summary,
            "expires_at": expires_at,
        });
        self.pushes.push_back(PushEntry {
            approval_id: request.approval_id,
            request: data,
            expires_at,
            sent: false,
            resolved: None,
        });
        while self.pushes.len() > MAX_PUSHES {
            self.pushes.pop_front();
        }
        self.flush_pushes(cx);
    }

    /// No longer pending: the card says how it ended (a remote answer: its
    /// decision, set at the hand-off) and the push is resolved.
    fn approval_resolved(&mut self, approval_id: &str, reason: ApprovalCloseReason, cx: &mut Cx) {
        let state = match reason {
            ApprovalCloseReason::AnsweredRemote => None,
            ApprovalCloseReason::AnsweredTerminal => Some(ApprovalCardState::AnsweredTerminal),
            ApprovalCloseReason::TimedOut => Some(ApprovalCardState::Expired),
            _ => Some(ApprovalCardState::Closed),
        };
        if let Some(state) = state {
            self.card_state(approval_id, state, cx);
        }
        if let Some(i) = self
            .pushes
            .iter()
            .position(|p| p.approval_id == approval_id)
        {
            if self.pushes[i].sent {
                self.pushes[i].resolved = Some(reason);
            } else {
                // Never pushed: nothing to replace.
                self.pushes.remove(i);
            }
        }
        self.flush_pushes(cx);
    }

    /// Sends what the relay should know, in order, over the verified link:
    /// `push_approval` only for approvals still pending (and not expired),
    /// `push_resolved` only for ones whose `push_approval` went out. Stops
    /// at the first failure (kept for the next pass).
    fn flush_pushes(&mut self, cx: &mut Cx) {
        if self.link.is_none() {
            return;
        }
        let wall = self.clock.wall();
        self.pushes
            .retain(|p| p.sent || p.resolved.is_some() || p.expires_at > wall);
        let mut i = 0;
        while i < self.pushes.len() {
            let p = &self.pushes[i];
            let data = match (p.sent, p.resolved) {
                (false, None) => p.request.clone(),
                (true, Some(reason)) => json!({
                    "v": 1,
                    "op": "push_resolved",
                    "approval_id": p.approval_id,
                    "reason": reason,
                }),
                _ => {
                    i += 1;
                    continue;
                }
            };
            let text = json!({"type": "relay", "data": data}).to_string();
            if cx.client.try_send_wire(text, false).is_err() {
                return;
            }
            if self.pushes[i].sent {
                self.pushes.remove(i);
            } else {
                self.pushes[i].sent = true;
                i += 1;
            }
        }
    }

    /// The card of `approval_id` in a new state.
    fn card_state(&mut self, approval_id: &str, state: ApprovalCardState, cx: &mut Cx) {
        let card = self.approvals.get(approval_id).and_then(|a| a.card.clone());
        self.card(approval_id, card, state, cx);
    }

    /// Shows `card` (in `state`) in the session's conversations and history.
    fn card(
        &mut self,
        approval_id: &str,
        card: Option<ApprovalCard>,
        state: ApprovalCardState,
        cx: &mut Cx,
    ) {
        let Some(mut card) = card else {
            return;
        };
        if card.state == state && state != ApprovalCardState::Pending {
            return;
        }
        card.state = state;
        let Some(sid) = self.approvals.get(approval_id).map(|a| a.sid.clone()) else {
            return;
        };
        if let Some(open) = self.approvals.get_mut(approval_id) {
            open.card = Some(card.clone());
        }
        let Some(session) = session_of(cx, &sid) else {
            return;
        };
        let out = session.chat.approval_card(card, wall_ms() as i64);
        self.broadcast(&sid, &out, None, cx);
    }

    /// The approvals this bridge holds open (tests).
    #[cfg(test)]
    pub(super) fn open_approvals(&self) -> Vec<String> {
        self.approvals.keys().cloned().collect()
    }

    // ── Frames ──

    fn frames(&mut self, cx: &mut Cx) {
        self.flush_terminal(cx);
        if !self.terminal_out.is_empty() {
            if self.terminal_out.len() > TERMINAL_BACKLOG {
                self.congested(cx);
            }
            return;
        }
        let keys: Vec<(String, String)> = self.streams.keys().cloned().collect();
        let mut failed = Vec::new();
        for key in keys {
            if !self.current(&key.0) {
                continue;
            }
            let Some(session) = session_of(cx, &key.1) else {
                continue;
            };
            if !session.synced() {
                continue;
            }
            let exit = (session.state != BrokerState::Running).then(|| {
                session
                    .exit_status
                    .clone()
                    .unwrap_or_else(|| "exited".into())
            });
            let stream = self.streams.get_mut(&key).expect("listed");
            match stream.frames(session.screen(), exit.as_deref()) {
                Ok(messages) => {
                    for message in messages {
                        let text =
                            serde_json::to_string(&AstationMessage::Terminal(message.into()))
                                .expect("terminal messages serialize");
                        self.terminal_out.push_back(Queued::Frame(text));
                    }
                }
                Err(error) => failed.push((key, error)),
            }
        }
        for (key, error) in failed {
            if let Some(stream) = self.streams.remove(&key) {
                self.terminal_error(&key.1, Some(&stream.stream_id), "busy", &error, cx);
            }
        }
        self.flush_terminal(cx);
        if self.terminal_out.len() > TERMINAL_BACKLOG {
            self.congested(cx);
        }
    }

    /// The terminal transport fell behind: the frames waiting go and every
    /// stream ends (viewers subscribe again); `written` acks and errors stay
    /// queued, in order.
    fn congested(&mut self, cx: &mut Cx) {
        drop_frames(&mut self.terminal_out);
        let streams: Vec<((String, String), FrameStream)> = self.streams.drain().collect();
        for ((_, sid), stream) in streams {
            self.terminal_error(
                &sid,
                Some(&stream.stream_id),
                "busy",
                "Terminal transport congested; subscribe again",
                cx,
            );
        }
    }

    /// A terminal-v1 `error`, on the terminal stream (after what is queued).
    fn terminal_error(
        &mut self,
        sid: &str,
        stream_id: Option<&str>,
        code: &str,
        message: &str,
        cx: &mut Cx,
    ) {
        let mut data = json!({
            "v": 1, "op": "error", "terminal_id": sid, "code": code, "message": message,
        });
        if let Some(stream_id) = stream_id {
            data["stream_id"] = Value::String(stream_id.into());
        }
        let text = json!({"type": "terminal", "data": data}).to_string();
        self.terminal_out.push_back(Queued::Other(text));
        self.flush_terminal(cx);
    }

    // ── chat-v1 ──

    /// An authorized terminal-v1 `ack` or chat-v1 `open`/`close`.
    fn forward(&mut self, attachment: &str, sid: &str, message: &FamilyMessage, cx: &mut Cx) {
        let data = message.data.clone().unwrap_or(Value::Null);
        match message.family.as_str() {
            "terminal" => {
                let offset = data.get("offset").and_then(Value::as_u64).unwrap_or(0);
                let key = (attachment.to_string(), sid.to_string());
                let Some(stream) = self.streams.get_mut(&key) else {
                    return;
                };
                if stream.ack(offset).is_err() {
                    let stream_id = stream.stream_id.clone();
                    self.streams.remove(&key);
                    self.terminal_error(
                        sid,
                        Some(&stream_id),
                        "stale_target",
                        "Invalid terminal acknowledgement; subscribe again",
                        cx,
                    );
                }
            }
            "agentChat" => {
                let Ok(env) = serde_json::from_value::<ChatEnvelope>(data) else {
                    return;
                };
                let conversation = env.conversation_id.clone();
                match chat_wire::parse_inbound(&env) {
                    Ok(Inbound::Open { before }) => self.open_conversation(
                        attachment,
                        sid,
                        &conversation,
                        before.as_deref(),
                        cx,
                    ),
                    Ok(Inbound::Close) => {
                        if let Some(chats) = self.chats.get_mut(sid) {
                            chats.conversations.remove(&conversation);
                        }
                    }
                    Ok(Inbound::Submit { .. } | Inbound::Answer { .. }) => {}
                    Err(text) => {
                        let env = chat_error(
                            &conversation,
                            sid,
                            None,
                            None,
                            "unsupported_version",
                            &text,
                        );
                        self.send_chat(env, cx);
                    }
                }
            }
            _ => {}
        }
    }

    fn open_conversation(
        &mut self,
        attachment: &str,
        sid: &str,
        conversation: &str,
        before: Option<&str>,
        cx: &mut Cx,
    ) {
        let Some(session) = session_of(cx, sid) else {
            return;
        };
        // An exited agent's history and status stay readable.
        if !session.chat_v1 && session.state == BrokerState::Running {
            let text = match &session.chat_reason {
                Some(reason) => format!("{NOT_AVAILABLE}: {reason}"),
                None => NOT_AVAILABLE.to_string(),
            };
            let env = chat_error(conversation, sid, None, None, "busy", &text);
            self.send_chat(env, cx);
            return;
        }
        let generation = session.chat.generation().to_string();
        let mut envelopes = vec![chat_wire::opened(
            conversation,
            sid,
            &generation,
            session.chat.status(),
        )];
        let history = session
            .chat
            .history(before, HISTORY_MESSAGES, HISTORY_BYTES);
        let mut sequence = 1;
        for message in &history {
            envelopes.push(chat_wire::history_message(
                conversation,
                sid,
                &generation,
                sequence,
                message,
            ));
            sequence += 1;
        }
        let chats = self.chats.entry(sid.to_string()).or_default();
        let mut closes = Vec::new();
        if !chats.conversations.contains_key(conversation)
            && chats.conversations.len() >= MAX_CONVERSATIONS
            && let Some(oldest) = chats
                .conversations
                .iter()
                .min_by_key(|(_, c)| c.opened)
                .map(|(id, _)| id.clone())
        {
            chats.conversations.remove(&oldest);
            closes.push(chat_wire::close(&oldest, sid));
        }
        chats.opens += 1;
        let opened = chats.opens;
        chats.conversations.insert(
            conversation.to_string(),
            Conversation {
                attachment: attachment.to_string(),
                next: sequence,
                last_heartbeat: Instant::now(),
                opened,
            },
        );
        for env in closes.into_iter().chain(envelopes) {
            self.send_chat(env, cx);
        }
    }

    /// The head of the next event in a conversation (`None` when it isn't open).
    fn next_head(&mut self, sid: &str, conversation: &str, cx: &mut Cx) -> Option<(String, u64)> {
        let generation = session_of(cx, sid)?.chat.generation().to_string();
        let c = self
            .chats
            .get_mut(sid)?
            .conversations
            .get_mut(conversation)?;
        let sequence = c.next;
        c.next += 1;
        Some((generation, sequence))
    }

    /// A receipt's state for a chat submit, in chat-v1 terms (§7).
    fn chat_reply(
        &mut self,
        attachment: &str,
        conversation: &str,
        sid: &str,
        reply: ChatReply,
        cx: &mut Cx,
    ) {
        if !self.current(attachment) {
            return;
        }
        let head = self.next_head(sid, conversation, cx);
        let env = match reply {
            ChatReply::Accepted { request_id } => {
                self.submitters
                    .insert(request_id.clone(), (sid.into(), conversation.into()));
                let mut body = Map::new();
                body.insert("requestId".into(), Value::String(request_id));
                chat_envelope(conversation, sid, "accepted", head, body)
            }
            ChatReply::Complete {
                request_id,
                turn_id,
            } => {
                self.submitters.remove(&request_id);
                // A turn ended interrupted says so (a duplicate after a
                // restart only knows it completed).
                let outcome = self
                    .outcomes
                    .get(&request_id)
                    .copied()
                    .unwrap_or(crate::chat::adapter::Outcome::Done);
                complete_envelope(conversation, sid, head, request_id, turn_id, outcome)
            }
            ChatReply::Error {
                request_id,
                code,
                text,
            } => {
                if let Some(r) = &request_id {
                    self.submitters.remove(r);
                }
                chat_error(conversation, sid, head, request_id.as_deref(), &code, &text)
            }
        };
        self.send_chat(env, cx);
    }

    /// The chat session's output: to every open conversation, except what
    /// belongs to a request (its submitter hears about it through its
    /// receipt); a turn's end completes the prompt and any interrupt.
    fn chat_outs(&mut self, sid: &str, outs: Vec<Out>, cx: &mut Cx) {
        for out in outs {
            let mut except = None;
            match &out {
                Out::Accepted { .. } => continue,
                Out::Error {
                    request_id: Some(request_id),
                    ..
                } => {
                    if self.prompts.remove(request_id).is_some() {
                        let effects = self
                            .host
                            .dispatch_report(request_id, DispatchReport::Unknown);
                        self.exec(effects, cx);
                    }
                    continue;
                }
                Out::Complete {
                    turn_id,
                    request_id,
                    outcome,
                } => {
                    if let Some(request_id) = request_id {
                        except = self.submitters.get(request_id).map(|(_, c)| c.clone());
                        if self.prompts.remove(request_id).is_some() {
                            if self.outcomes.len() >= MAX_OUTCOMES {
                                self.outcomes.clear();
                            }
                            self.outcomes.insert(request_id.clone(), *outcome);
                            let report = DispatchReport::Completed {
                                detail: None,
                                turn_id: Some(turn_id.clone()),
                            };
                            let effects = self.host.dispatch_report(request_id, report);
                            self.exec(effects, cx);
                        }
                    }
                    self.interrupts_done(sid, cx);
                }
                Out::Status(status) if status.state == ChatState::Ready => {
                    self.interrupts_done(sid, cx);
                }
                _ => {}
            }
            self.broadcast(sid, &out, except.as_deref(), cx);
        }
    }

    fn interrupts_done(&mut self, sid: &str, cx: &mut Cx) {
        for request_id in self.interrupts.remove(sid).unwrap_or_default() {
            let report = DispatchReport::Completed {
                detail: None,
                turn_id: None,
            };
            let effects = self.host.dispatch_report(&request_id, report);
            self.exec(effects, cx);
        }
    }

    fn broadcast(&mut self, sid: &str, out: &Out, except: Option<&str>, cx: &mut Cx) {
        let ids: Vec<String> = self
            .chats
            .get(sid)
            .map(|c| {
                c.conversations
                    .iter()
                    .filter(|(id, c)| Some(id.as_str()) != except && self.current(&c.attachment))
                    .map(|(id, _)| id.clone())
                    .collect()
            })
            .unwrap_or_default();
        for id in ids {
            if let Some((generation, sequence)) = self.next_head(sid, &id, cx) {
                let env = chat_wire::event(&id, sid, &generation, sequence, out);
                self.send_chat(env, cx);
            }
        }
    }

    /// Tells every open conversation of `sid` why it ends (`error`, `close`).
    fn end_conversations(&mut self, sid: &str, text: &str, cx: &mut Cx) {
        let ids: Vec<String> = self
            .chats
            .get(sid)
            .map(|c| c.conversations.keys().cloned().collect())
            .unwrap_or_default();
        let error = Out::Error {
            text: text.to_string(),
            request_id: None,
        };
        for id in ids {
            let current = self
                .chats
                .get(sid)
                .and_then(|c| c.conversations.get(&id))
                .is_some_and(|c| self.current(&c.attachment));
            if current {
                if let Some((generation, sequence)) = self.next_head(sid, &id, cx) {
                    self.send_chat(
                        chat_wire::event(&id, sid, &generation, sequence, &error),
                        cx,
                    );
                }
                self.send_chat(chat_wire::close(&id, sid), cx);
            }
        }
        self.chats.remove(sid);
    }

    /// Re-sends the status to each conversation that has not had it for 15 s.
    fn heartbeats(&mut self, cx: &mut Cx) {
        let due: Vec<(String, String)> = self
            .chats
            .iter()
            .flat_map(|(sid, chats)| {
                chats
                    .conversations
                    .iter()
                    .filter(|(_, c)| c.last_heartbeat.elapsed() >= HEARTBEAT)
                    .map(|(id, _)| (sid.clone(), id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (sid, id) in due {
            let Some(status) = session_of(cx, &sid).map(|s| s.chat.heartbeat()) else {
                continue;
            };
            if let Some(c) = self
                .chats
                .get_mut(&sid)
                .and_then(|c| c.conversations.get_mut(&id))
            {
                c.last_heartbeat = Instant::now();
            }
            if let Some((generation, sequence)) = self.next_head(&sid, &id, cx) {
                self.send_chat(
                    chat_wire::event(&id, &sid, &generation, sequence, &status),
                    cx,
                );
            }
        }
    }

    /// Test access to the host.
    #[cfg(test)]
    pub fn host(&self) -> &SessionHost<FileJournal> {
        &self.host
    }
}

/// The link the App holds now: its generation while authenticated.
fn app_link(app: &App) -> Option<u64> {
    (app.astation_connected && app.astation_reauth.is_none() && !app.astation_client.is_ws_closed())
        .then_some(app.astation_link_gen)
}

/// §6: what a failed host write proves (`None`: it was written).
pub(super) fn classify(result: &WriteOutcome) -> Option<DispatchReport> {
    if result.dropped || result.no_effect {
        Some(DispatchReport::FailedNoEffect)
    } else if !result.ok {
        Some(DispatchReport::FailedAfterPossibleEffect)
    } else {
        None
    }
}

/// A terminal message waiting for the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Queued {
    Frame(String),
    Other(String),
}

pub(super) fn drop_frames(queue: &mut VecDeque<Queued>) {
    queue.retain(|q| matches!(q, Queued::Other(_)));
}

pub(super) fn complete_envelope(
    conversation: &str,
    sid: &str,
    head: Option<(String, u64)>,
    request_id: String,
    turn_id: Option<String>,
    outcome: crate::chat::adapter::Outcome,
) -> ChatEnvelope {
    let mut body = Map::new();
    body.insert("requestId".into(), Value::String(request_id));
    if let Some(turn_id) = turn_id {
        body.insert("turnId".into(), Value::String(turn_id));
    }
    let outcome = match outcome {
        crate::chat::adapter::Outcome::Done => "done",
        crate::chat::adapter::Outcome::Interrupted => "interrupted",
    };
    body.insert("outcome".into(), Value::String(outcome.into()));
    chat_envelope(conversation, sid, "complete", head, body)
}

fn session_of<'a>(cx: &'a mut Cx, sid: &str) -> Option<&'a mut BrokerSession> {
    let id = SessionId::parse(sid)?;
    cx.sessions.get_mut(&id)
}

fn chat_envelope(
    conversation: &str,
    sid: &str,
    op: &str,
    head: Option<(String, u64)>,
    mut body: Map<String, Value>,
) -> ChatEnvelope {
    if let Some((generation, sequence)) = head {
        body.insert("generation".into(), Value::String(generation));
        body.insert("sequence".into(), Value::from(sequence));
    }
    ChatEnvelope {
        v: 1,
        op: op.into(),
        conversation_id: conversation.into(),
        agent_id: sid.into(),
        body,
    }
}

/// chat-v1 `error{requestId?, code, text}`.
fn chat_error(
    conversation: &str,
    sid: &str,
    head: Option<(String, u64)>,
    request_id: Option<&str>,
    code: &str,
    text: &str,
) -> ChatEnvelope {
    let mut body = Map::new();
    if let Some(request_id) = request_id {
        body.insert("requestId".into(), Value::String(request_id.into()));
    }
    body.insert("code".into(), Value::String(code.into()));
    body.insert("text".into(), Value::String(text.into()));
    chat_envelope(conversation, sid, "error", head, body)
}

/// A session `error{code:"unauthorized"}` for a link without an attachment.
fn unauthorized(re: Option<String>) -> String {
    use crate::session_protocol::wire::{ErrorCode, Op, SessionMessage};
    let message = Envelope::Session(SessionMessage {
        id: uuid::Uuid::new_v4().to_string(),
        re,
        op: Op::Error {
            code: ErrorCode::Unauthorized,
            detail: None,
        },
    });
    String::from_utf8(wire::encode(&message)).expect("wire JSON is UTF-8")
}

/// Without a session host (its journal could not be opened), session-family
/// messages are refused as the TUI refuses them.
pub fn refuse_all(app: &mut App) {
    let Some(hosted) = app.hosted.as_mut() else {
        return;
    };
    let inbox: Vec<(u64, String)> = hosted.inbox.drain(..).collect();
    for (_, text) in inbox {
        let re = match wire::decode(text.as_bytes()) {
            Ok(Envelope::Session(m)) => Some(m.id),
            Ok(Envelope::Family(_)) => None,
            Err(e) => e.id,
        };
        let _ = app.astation_client.try_send_wire(refusal(re), false);
    }
}

#[cfg(test)]
#[path = "host_bridge_tests.rs"]
mod tests;

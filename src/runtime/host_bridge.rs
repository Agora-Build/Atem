//! The session host inside `atem runtime` (designs/protocol/atem-session-v1.md,
//! compatibility mode): the broker owns `SessionHost` over a `FileJournal`
//! and performs its effects on the workers.
//!
//! Attachment: the App's authenticated Astation link (direct or relay; the
//! App holds one at a time) is one attachment, created when the link becomes
//! authenticated (`App::astation_link_gen` counts those) and fenced when it
//! drops or Astation re-authenticates it. A second `hello` on the link (a
//! client reset, e.g. after sleep) replaces it: the host fences the old
//! attachment and the link's messages go to the new one (`Effect::Replaced`;
//! r7.1). Each `hello`'s outcome is one line in runtime.log. Only the Astation this profile is
//! paired with (the pairing binding the link captured) and verified with
//! (`cred/state.json`) gets one, with `view` and `control`; any
//! other link — unpaired, unverified, or another Astation — gets no
//! attachment at all, so its session-family messages are answered
//! `unauthorized`. `welcome` names the verified account (`data_account`), this
//! device's id from its verification, and the host trust generation from
//! `pairing/trust_gen`; a new identity (a pairing verified after the broker
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
//! (it revokes any remote lease) before it is written. Chisel/mark tasks use
//! the same authorized prompt receipts as other executable messages.
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
//!
//! Atem session rules (§6a r7.2): a worker's `approval_rules` go to the host
//! (`approval_rules` for attachments with `control`, chat-v1 `opened` and
//! `rules`); its `approval_auto_allowed` becomes an `auto_allowed` card in
//! the session's conversations and one runtime.log line naming the rule
//! (never the command) — no approval, no push, no lease. A revoke
//! (`approval_rule_revoke`, from any attachment with `control`, lease or
//! not: r7.3) goes to the worker as `revoke_approval_rule` and completes on
//! its `approval_rule_revoked` (one runtime.log line: rule and session,
//! never the command). Each rule carries the
//! account, device and trust generation it was granted under (sent with the
//! `allow_always` decision): a broker that registers an adopted worker's
//! session accepts only the rules granted under its current identity and
//! trust (`confirm_approval_rules`; the worker drops the rest, and allows by
//! none until then), and a rebind or trust change drops them all.
use super::broker::{BrokerSession, SessionState as BrokerState, WriteOutcome, WriteTag};
use super::delegated::start::{DelegatedStart, StartView};
use super::delegated::station::{Inbound as StationInbound, LinkKind, Station};
use super::project_scope::{AgentHasher, ProjectHasher, ProjectScopes};
use super::refusal_log::{self, RefusalLog, Request};
use super::worker_approvals::Event as ApprovalEvent;
use super::worker_protocol::{Activity as WorkerActivity, ApplyOutcome, HeldRule, RuleGrant};
use crate::app::App;
use crate::app::hosted::refusal;
use crate::chat::adapter::{ApprovalCard, ApprovalCardState};
use crate::chat::history::{self, Conversations, HistoryCall, HistoryKey, Opening, is_card};
use crate::chat::session::{Out, State as ChatState};
use crate::chat::wire::{self as chat_wire, ChatEnvelope, CloseReason, Inbound};
use crate::session::{Provider, SessionId};
use crate::session_protocol::file_journal::FileJournal;
use crate::session_protocol::host::{
    AdoptedChat, Attach, ChatReply, DETAIL_TURN_DONE, DETAIL_TURN_INTERRUPTED, DispatchReport,
    Effect, HostConfig, HostContext, HostInterrupt, LEASE_EPOCH_BLOCK, LEASE_MS, Origin,
    RECONCILE_MS, Reconciled, SessionHost, SessionSpec, random_ids, reconcile_turn,
};
use crate::session_protocol::journal::TurnIds;
use crate::session_protocol::membership::{
    self, CarriageResult, Held, HostFences, MembershipHost, host_now,
};
use crate::session_protocol::r9::{
    self as r9host, HostKey, Now as R9Now, Parts as R9Parts, R9Host,
    route::{RouteIdentity, RouteState},
};
use crate::session_protocol::wire::{
    self, Activity, ApprovalCloseReason, ApprovalDecision, ApprovalRequest, ClientKind, Envelope,
    FamilyMessage, Permission, ReceiptKind, ReceiptState, SessionState,
};
use crate::terminal_share::{FrameStream, Message as TerminalMessage};
use crate::websocket_client::{AstationClient, AstationMessage};
use atem_client::canonical::StrictValue;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "host_work_bridge.rs"]
mod host_work_bridge;

/// `advance` runs this often.
const ADVANCE_EVERY: u64 = 100;
/// The `host-work` principal's lease is renewed this long after its grant
/// or last renewal while its turn runs (session-v1 R9.14 item 1: every 5 s,
/// a 15 s lease).
const HOST_WORK_RENEW_MS: u64 = 5_000;
/// The client name of the `host-work` principal's internal attachment.
const HOST_WORK_CLIENT: &str = "atem-internal-host-work";
/// Identical session messages within this window are handled once.
const DEDUP_MS: u64 = 60_000;
/// The authorization of an authenticated link (compatibility mode has no
/// freshness proof yet): at its end the attachment is fenced and the link
/// dropped; the reconnect authenticates it again and gets a new attachment.
pub(super) const LINK_AUTHORIZATION_MS: u64 = 24 * 60 * 60 * 1000;
/// Terminal messages waiting for the transport before streams are dropped.
const TERMINAL_BACKLOG: usize = 128;
const HEARTBEAT: Duration = Duration::from_secs(15);
const RESTARTED: &str = "the agent was restarted; reopen the chat";
const NOT_AVAILABLE: &str = "chat is not available for this agent";
const NO_TURN: &str = "no turn was running";
/// An interrupt on a session without chat: nothing knows whether a turn runs.
const NO_TURN_STATE: &str = "no turn state; use the terminal";
/// An interrupt whose Esc only handed a waiting Codex approval to Codex's
/// own dialog (the worker consumed it).
const INTERRUPT_HANDED: &str =
    "the approval was handed to the terminal; interrupt again to stop the turn";
/// The note on an `allow_always` card whose session rule the full session
/// couldn't keep.
const RULE_NOT_KEPT: &str =
    "allowed once; the rule wasn't kept: this session already holds 32 rules";
/// A revoke whose rule the worker no longer held.
const RULE_GONE: &str = "the rule is no longer active";
/// Esc interrupts Claude Code's and Codex's current turn.
const INTERRUPT_KEY: &[u8] = b"\x1b";
/// Identity of a host without a verified pairing (no attachment is ever
/// authorized under it).
const UNPAIRED: &str = "unpaired";
const RUNTIME_EPOCH_FILE: &str = "runtime_epoch";
/// How often the link's pairing capture is checked against the pairing.
const CAPTURE_CHECK: Duration = Duration::from_secs(5);
/// Why the link was dropped: a carriage fenced its attachment.
const DEVICE_LIST_DROP: &str =
    "Remote access to this host changed (device list); the link was dropped";
/// Why the link was dropped: a refusal couldn't be recorded.
const REFUSAL_DROP: &str = "The session journal couldn't record a refusal; the link was dropped";
/// Session messages remembered for duplicate detection, at most.
const MAX_SEEN: usize = 4096;
/// An r9 channel's terminal frames wait while this much is queued for it.
const R9_FRAME_BACKLOG: usize = 512 * 1024;
/// Why the link was dropped: a device list was pinned while it ran.
const DEVICE_LIST_PINNED: &str =
    "A device list was pinned; remote clients connect with atem-session r9";

/// The broker's monotonic clock in milliseconds, and wall time (tests move
/// either forward).
#[derive(Clone, Debug)]
pub struct Clock {
    origin: Instant,
    skew: Arc<AtomicU64>,
    wall_skew: Arc<AtomicU64>,
    /// Tests (`Clock::manual`): the monotonic clock moves only with
    /// `skip`, never in real time.
    #[cfg(test)]
    manual: bool,
}

impl Default for Clock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            skew: Arc::new(AtomicU64::new(0)),
            wall_skew: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            manual: false,
        }
    }
}

impl Clock {
    /// Tests: a monotonic clock at 0 that moves only with `skip`, so a "not
    /// yet" assertion needs no margin against real time (PR 5 review I3).
    #[cfg(test)]
    pub fn manual() -> Self {
        Self {
            manual: true,
            ..Self::default()
        }
    }

    pub fn now(&self) -> u64 {
        #[cfg(test)]
        if self.manual {
            return self.skew.load(Ordering::SeqCst);
        }
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
    src: &crate::profile::Sources,
    astation_id: &str,
    host_trust_gen: u64,
) -> Option<Identity> {
    let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust).ok()?;
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
fn start_identity(src: &crate::profile::Sources) -> Identity {
    let state = crate::pairing::load(src).ok();
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

/// The principal a verified link speaks for (r8 §H, compatibility mode):
/// the paired Astation, within the verified account. One per link today;
/// with account trust each device with a grant becomes its own. Ids that
/// can't form an opaque id are named by their digest instead (the same
/// pair always gives the same principal); no Astation id, no principal.
fn link_principal(identity: &Identity, astation_id: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    if astation_id.is_empty() {
        return None;
    }
    let principal = format!("astation:{}:{astation_id}", identity.account_id);
    if wire::is_opaque_id(&principal) {
        return Some(principal);
    }
    let digest = Sha256::digest(format!("{}\n{astation_id}", identity.account_id));
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    Some(format!("astation:{hex}"))
}

/// The previous run's runtime epoch, before this run takes the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviousEpoch {
    /// The counter's value (0: a fresh journal, no run before).
    Known(u64),
    /// No counter next to the journal's state: it was lost. Which epochs
    /// earlier runs used is unknown, so the previous run's clean close and
    /// clean checkpoint can't be vouched for.
    Lost,
}

/// Files only the session journal writes, after a run took its epoch:
/// next to one, a missing `runtime_epoch` was lost (not a fresh journal).
const JOURNAL_STATE: [&str; 4] = ["principals", "floors", "refused", "clean_close"];

fn journal_has_state(dir: &Path) -> bool {
    JOURNAL_STATE
        .iter()
        .any(|f| dir.join(f).symlink_metadata().is_ok())
        || std::fs::read_dir(dir.join("receipts")).is_ok_and(|mut d| d.next().is_some())
}

/// The highest runtime epoch any surviving file names: the journal's clean
/// close, the device list's clean checkpoint and fault records (both
/// copies). `None`: no file names one.
fn recorded_epoch(dir: &Path, pairing: Option<&crate::paths::PairingPaths>) -> Option<u64> {
    let epoch_in = |path: &Path, pointer: &str| {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.pointer(pointer)?.as_u64())
    };
    let mut found = vec![
        epoch_in(&dir.join("clean_close"), "/runtime_epoch"),
        epoch_in(&dir.join("membership_fault"), "/runtime_epoch"),
    ];
    if let Some(pairing) = pairing {
        found.push(epoch_in(&pairing.membership, "/checkpoint/runtime_epoch"));
        found.push(epoch_in(&pairing.fault, "/runtime_epoch"));
    }
    found.into_iter().flatten().max()
}

/// The runtime epoch the counter in `dir` holds: the previous run's, before
/// this run takes the next one. Missing while the session journal holds
/// state, or while a surviving file names an earlier epoch (the device
/// list's checkpoint survives the journal directory's loss), it was lost.
fn current_runtime_epoch(
    dir: &Path,
    pairing: Option<&crate::paths::PairingPaths>,
) -> anyhow::Result<PreviousEpoch> {
    let path = dir.join(RUNTIME_EPOCH_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map(PreviousEpoch::Known)
            .map_err(|_| {
                anyhow::anyhow!(
                    "{} is damaged; move it aside to reset the runtime epoch",
                    path.display()
                )
            }),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && (journal_has_state(dir) || recorded_epoch(dir, pairing).is_some()) =>
        {
            Ok(PreviousEpoch::Lost)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PreviousEpoch::Known(0)),
        Err(e) => Err(e.into()),
    }
}

/// The epoch a run takes after the counter was lost: above every epoch a
/// surviving file names (+ 1), and at least the wall clock in ms and the
/// newest write time in the journal and `pairing/` (counters that count
/// starts from 1 stay far below). It can't be above an epoch nothing
/// records: after an earlier loss had jumped the counter to the clock, a
/// second loss with the clock set back can reuse one. No authority depends
/// on that (the clean close is consumed at each start and needs the exact
/// previous epoch; a checkpoint match only decides a log line).
fn epoch_after_lost(dir: &Path, pairing: Option<&crate::paths::PairingPaths>) -> u64 {
    let ms = |t: std::time::SystemTime| {
        t.duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    };
    let newest = |d: &Path| {
        std::fs::read_dir(d)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|e| std::fs::symlink_metadata(e.path()).ok())
                    .filter_map(|m| m.modified().ok())
                    .map(ms)
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    };
    let mut floor = ms(std::time::SystemTime::now()).max(newest(dir));
    if let Some(pairing) = pairing {
        floor = floor.max(newest(pairing.dir()));
    }
    let recorded = recorded_epoch(dir, pairing).map_or(0, |e| e.saturating_add(1));
    floor.max(recorded).max(1)
}

/// The next runtime epoch, durably (a counter in `dir`, incremented each start).
fn next_runtime_epoch(
    dir: &Path,
    pairing: Option<&crate::paths::PairingPaths>,
) -> anyhow::Result<u64> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(RUNTIME_EPOCH_FILE);
    let next = match current_runtime_epoch(dir, pairing)? {
        PreviousEpoch::Known(previous) => previous.checked_add(1),
        PreviousEpoch::Lost => Some(epoch_after_lost(dir, pairing)),
    }
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
    /// The interrupt key the host wrote on its own authority for
    /// host-work's attempt (session-v1 R9.14 item 5): no receipt; its
    /// outcome goes to host-work (`host_interrupt_reports`).
    HostInterrupt(String),
}

/// What became of an interrupt written with host authority (session-v1
/// R9.14 item 5), as host-work hears it (`host_interrupt_reports`), once
/// per write. Everything but `Ok` and `ErrorAfterQueue` wrote nothing, so
/// host-work writes it again on its next pass while the intent is pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptReport {
    /// The worker wrote it: delivered.
    Ok,
    /// Codex's worker consumed it: it only handed a waiting approval to
    /// Codex's own dialog, or fell in the consume window after such a
    /// release (`CONSUME_INPUT`). Nothing written.
    Consumed,
    /// Dropped at the worker's write boundary (a newer input epoch).
    Dropped,
    /// Nothing written: refused before it was queued, or it never reached
    /// the worker. Or unanswered: the process ended; nothing is left to
    /// interrupt, whatever was written.
    NoEffect,
    /// A writer error after queueing: it may have reached the terminal, so
    /// it counts as delivered (no blind second Esc; item 5's 10 s rule).
    ErrorAfterQueue,
}

/// What `HostBridge::host_interrupt` (or `host_interrupt_revoke_lease`)
/// did. Everything it caused is already performed: nothing to carry out.
#[derive(Debug, Clone, PartialEq)]
pub enum Interrupted {
    /// The input epoch moved, another controller's lease was revoked, and
    /// the interrupt key was written: its outcome comes in
    /// `host_interrupt_reports`.
    Written,
    /// Only another controller's lease was revoked (if any): the revoke-only
    /// call, or `host_interrupt` while a write of the attempt is
    /// outstanding. Nothing written.
    Revoked,
    /// Refused before anything moved: `NotCurrentTurn`, `NotExecuting` or
    /// `Halted` (never `Written` or `Revoked`).
    Refused(HostInterrupt),
}

/// The device list's publisher into the start view (Decision 16).
fn list_publisher(
    view: &Arc<std::sync::Mutex<StartView>>,
) -> crate::session_protocol::membership::Publisher {
    let view = view.clone();
    Box::new(move |state| {
        view.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .list = Some(state);
    })
}

/// Host-work's start check under the drive hook (debug builds): the
/// verdict the test last gave (`verdict.json`).
#[cfg(debug_assertions)]
struct DriveCheck(Arc<std::sync::atomic::AtomicBool>);

#[cfg(debug_assertions)]
impl crate::session_protocol::host::StartCheck for DriveCheck {
    fn check(
        &self,
        _req: &crate::session_protocol::host::StartRequest<'_>,
    ) -> crate::session_protocol::host::StartVerdict {
        use crate::session_protocol::host::StartVerdict;
        if self.0.load(Ordering::SeqCst) {
            StartVerdict::Go
        } else {
            StartVerdict::Withdraw
        }
    }
}

/// Host-work's prompt `executing` at a start, reconciled with the adopted
/// worker's chat (session-v1 R9.14 items 5, 6; `reconcile_host_work`).
struct Reconciling {
    sid: String,
    process_gen: String,
    /// The turn it started, as journaled at the chat's acceptance.
    turn: TurnIds,
    /// When the start's recovery asked (the bridge's clock, ms): the wait
    /// for the adopted chat ends `RECONCILE_MS` after.
    since: u64,
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

struct Link {
    link_gen: u64,
    attachment: String,
    /// The attachment's authorization ends at whichever comes first: this
    /// monotonic ms, or this wall-clock ms (the monotonic clock stands still
    /// while the machine is suspended).
    deadline: u64,
    wall_deadline: u64,
    /// When its attachment was last welcomed (wall ms), for `atem status`.
    welcomed_at: Option<u64>,
}

pub struct HostBridge {
    local: Option<(String, Identity)>,
    /// The delegated host-work features this runtime runs, read once at its
    /// start (`test_hooks::host_features`: off unless the debug-only hook
    /// turns them on).
    features: super::test_hooks::HostFeatures,
    /// The `host-work` principal's internal attachment (session-v1 R9.14
    /// item 1), only with `host.delegated`: new at every start.
    host_work: Option<String>,
    /// What host-work's start check reads (design I.4.3; step 4's
    /// Decision 16): the session host's `StartCheck` (`DelegatedStart`)
    /// and the delegated dispatch share it. Never locked while calling
    /// into the session host.
    start_view: Arc<std::sync::Mutex<StartView>>,
    work: host_work_bridge::State,
    host: SessionHost<FileJournal>,
    dir: std::path::PathBuf,
    clock: Clock,
    /// The link generation last considered (attached or refused).
    considered: Option<u64>,
    link: Option<Link>,
    last_advance: u64,
    /// The host clock (§R9.5) at the last 100 ms pass: a pass also runs
    /// when it moved 100 ms (the device list's waits, service expiry and
    /// push resends are on it; the fixtures move it alone).
    last_host: (u64, u64),
    /// When the link's pairing capture was last checked.
    capture_checked: Instant,
    recovered: bool,
    seen: HashMap<String, u64>,
    seen_order: VecDeque<(u64, String)>,
    per: BTreeMap<String, PerSession>,
    /// Adopted sessions to register with `restore_session`.
    restore: HashSet<String>,
    streams: HashMap<(String, String), FrameStream>,
    /// Open chat-v1 conversations per session.
    chats: HashMap<String, Conversations>,
    /// `next` tokens are made under this key (r8 §B): random per run.
    history_key: HistoryKey,
    /// request id → (session, conversation) of chat submits.
    submitters: HashMap<String, (String, String)>,
    /// Prompts pasted and not reported yet: request id → session.
    prompts: HashMap<String, String>,
    /// The framing tags of the prompts this runtime pasted (`prompt_tags`):
    /// chat-v1 shows them to attachments with `control` only.
    prompt_tags: super::prompt_tags::PromptTags,
    /// Sessions whose terminal frames are held from attachments without
    /// `control` while a framed prompt's turn runs (`view_pause_pass`), as
    /// kept in each session's pause file.
    view_pauses: super::prompt_tags::Pauses,
    /// Sessions whose pause file was read (a restarted broker's adopted
    /// sessions, once each).
    pauses_loaded: HashSet<String>,
    /// Sessions whose pause file a failed write left behind `view_pauses`
    /// (`rewrite_pauses`), and when to try again.
    pauses_dirty: HashSet<String>,
    pauses_retry_at: Option<std::time::Instant>,
    /// Interrupts waiting for a turn to end, per session.
    interrupts: HashMap<String, Vec<String>>,
    pending: HashMap<(String, u64), Pending>,
    /// What became of interrupts written with host authority, for
    /// host-work (`host_interrupt_reports`): (the attempt's request id,
    /// report), in the order the answers came (a session's in its write
    /// order).
    interrupt_reports: Vec<(String, InterruptReport)>,
    /// The drive hook's own copy of `interrupt_reports` (debug builds): it
    /// reads this one, so host-work's intents, which drain the shared
    /// stream every pass, see every report (Task 16b review m7). Cleared
    /// each pass while the hook isn't set.
    #[cfg(debug_assertions)]
    drive_interrupt_reports: Vec<(String, InterruptReport)>,
    /// Debug builds: host interrupt writes handed to a worker so far, for
    /// the state dump (a test counts the writes themselves).
    #[cfg(debug_assertions)]
    host_interrupt_writes: u64,
    /// Host-work's prompts `executing` at the start, waiting for their
    /// adopted worker's chat (`reconcile_host_work`): request id → what is
    /// reconciled.
    reconciling: BTreeMap<String, Reconciling>,
    /// The drive hook's start-check verdict (debug builds): go, until the
    /// test says otherwise.
    #[cfg(debug_assertions)]
    drive_go: Arc<std::sync::atomic::AtomicBool>,
    /// terminal-v1 messages in order (frames, acks, errors) waiting for the
    /// bounded terminal queue.
    terminal_out: VecDeque<Queued>,
    /// approval_id → open approvals.
    approvals: HashMap<String, OpenApproval>,
    /// Rule revocations sent to a worker: request id → (session, rule id).
    revokes: HashMap<String, (String, String)>,
    /// Push requests for the relay (`push_queue`).
    pushes: super::push_queue::PushQueue,
    /// runtime.log lines for refused requests, rate-limited per link.
    refusal_log: RefusalLog,
    /// The request being handled (its link and what a refusal line says
    /// about it): error replies while it is set are logged.
    refusing: Option<(u64, Request, Option<String>)>,
    /// The host closed the link's attachment: drop the link after this pass.
    close_link: bool,
    /// Why the link is dropped, when not a refusal that couldn't be recorded.
    close_reason: Option<&'static str>,
    /// The r9 device list (§R9.3; `session_protocol::membership`), when this
    /// host has one.
    membership: Option<MembershipHost>,
    /// Why the device list couldn't be opened (remote sessions disabled).
    membership_error: Option<String>,
    /// Fence effects of the device list's start, for the first pass.
    membership_effects: Vec<Effect>,
    /// The last `hello` refused for its revision (`atem status`): the
    /// revision it named and when (wall ms). A welcome clears it.
    last_refusal: Option<(Option<u64>, u64)>,
    /// r9 admission over the link's channel envelopes (§R9.7a).
    r9: R9Host,
    /// The link generation the r9 host runs on, and the socket it runs on.
    r9_link: Option<u64>,
    r9_socket: u64,
    /// The host's Station link (its calls and the Station's messages,
    /// host-work-v1 §11.4): only with `host.delegated` (Decision 11).
    station: Option<Station>,
    /// Fetch results not carried because an entry didn't read back (never
    /// expected: they came from the strict reader).
    unconverted_fetches: u64,
    /// The profile's pairing files (the device list is reopened from them).
    pairing: Option<crate::paths::PairingPaths>,
    /// The pinned host's `host_channel_key`; r9 can't serve without it.
    host_key: Option<std::sync::Arc<HostKey>>,
    host_key_error: Option<String>,
    /// The device list's entry hashes up to its head, built once per head
    /// (§R9.7b: a relay's `host_route_ok` must name one of them).
    route_chain: std::cell::RefCell<Option<std::sync::Arc<Vec<atem_client::encoding::Hash32>>>>,
    /// The loaded key's public half (b64u), to tell a re-pin's new key.
    host_pub: Option<String>,
    /// Envelopes of an ended link generation dropped so far.
    stale_envelopes: u64,
    /// The device-list files as last opened (a change reopens them).
    list_stamp: Vec<Option<(u64, u64, i64, i64)>>,
    /// Service `projects` scopes: the sessions' launch projects and their
    /// keyed hashes (§R9.6, `project_scope`).
    projects: ProjectScopes,
    /// Sessions whose worker record (and launch project) wasn't read yet.
    project_unread: HashMap<String, Instant>,
}

/// What `atem status` shows of the link's session attachment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkStatus {
    /// The link has a session attachment (a verified pairing).
    pub attachment: bool,
    pub welcomed: Option<crate::runtime::protocol::Welcomed>,
    pub refused: Option<crate::runtime::protocol::Refusal>,
    pub journal_halted: bool,
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
        profile: Option<&crate::profile::Sources>,
        clock: Clock,
    ) -> anyhow::Result<Self> {
        let journal = FileJournal::open(dir).map_err(|e| anyhow::anyhow!(e.0))?;
        // r8 §H: the previous run ended cleanly only if the journal's
        // clean-close record names its epoch, read before this run takes
        // the next one (which supersedes the record in any case).
        let epoch_pairing = profile.map(|p| &p.paths.pairing);
        let previous = match current_runtime_epoch(dir, epoch_pairing)? {
            PreviousEpoch::Known(previous) => previous,
            PreviousEpoch::Lost => {
                // No epoch matches: no clean close, no clean checkpoint
                // (queued work is rejected, recovery waits resume from the
                // last persisted time).
                eprintln!(
                    "atem runtime: {} is missing next to the session journal's state; \
                     the previous run is treated as not closed cleanly and this run takes \
                     an epoch above every one a surviving file names",
                    dir.join(RUNTIME_EPOCH_FILE).display()
                );
                0
            }
        };
        let epoch = next_runtime_epoch(dir, epoch_pairing)?;
        let mut identity = profile.map(start_identity).unwrap_or(Identity {
            account_id: UNPAIRED.into(),
            atem_device_id: UNPAIRED.into(),
            host_trust_gen: 0,
        });
        // r9: with a device list the host is the one it pins (§R9.2).
        if let Some((account, pin)) = profile.and_then(|p| membership::peek_pin(&p.paths.pairing))
            && wire::is_opaque_id(&account)
            && wire::is_opaque_id(&pin.host_id)
        {
            identity = Identity {
                account_id: account,
                atem_device_id: pin.host_id,
                host_trust_gen: pin.host_trust_gen.max(identity.host_trust_gen),
            };
        }
        let mut host = Self::build(journal, &identity, epoch, previous, &clock)?;
        // Host-work's start check (session-v1 R9.14 item 3) whenever a
        // session host is built: `restart_at` and `rebind` keep it, so every
        // host-work request of this run is checked against the view (none
        // installed would withdraw them all). The drive hook (debug builds)
        // replaces it with its own verdicts once host-work's attachment
        // exists.
        let features = super::test_hooks::host_features();
        let start_view = Arc::new(std::sync::Mutex::new(StartView::new(
            &identity.atem_device_id,
        )));
        host.set_start_check(Box::new(DelegatedStart(start_view.clone())));
        // The principals host-work tasks name keep their control states from
        // the first control write on (the device list's start fences below
        // may be one): a task compares its sender's control generation with
        // the one it was accepted under. Each scheduling pass renews the set.
        match crate::runtime::host_work::Store::named_principals_at(dir.parent().unwrap_or(dir)) {
            Ok(named) => host.keep_principals(named),
            // The store won't open for hosting either: nothing of it
            // dispatches until it does.
            Err(error) => eprintln!(
                "atem runtime: agent hosting records can't be read ({error:#}); the principals their tasks name are kept once hosting runs"
            ),
        }
        // r9 §R9.3: the device list is opened before any remote admission
        // and before recovered work is resolved; its start fences go
        // through the host's §H fence now (only durable generations: no
        // attachment exists yet).
        let (membership, membership_error, membership_effects) = match profile {
            Some(profile) => {
                let mut fences = HostFences::new(&mut host);
                let opened = MembershipHost::open(
                    &profile.paths.pairing,
                    dir,
                    epoch,
                    &host_now(),
                    &mut fences,
                );
                let effects = fences.effects;
                match opened {
                    Ok(Some((membership, fenced))) => {
                        if !fenced.is_empty() {
                            eprintln!(
                                "atem runtime: device list: replayed {} fence(s) at start",
                                fenced.len()
                            );
                        }
                        (Some(membership), None, effects)
                    }
                    Ok(None) => (None, None, effects),
                    Err(error) => {
                        eprintln!(
                            "atem runtime: device list: {error}; r9 remote access is refused"
                        );
                        (None, Some(error), effects)
                    }
                }
            }
            None => (None, None, Vec::new()),
        };
        let pairing = profile.map(|p| p.paths.pairing.clone());
        // §R9.6: the pairing directory vouches for the revoked grants'
        // files (its copy of their bound, and a pinned list's floor).
        let vouch = pairing
            .as_ref()
            .map(|p| crate::session_protocol::r9::PairingVouch {
                copy: p.revoked_floor.clone(),
                pin_floor: membership::pin_wall_floor(p),
            });
        let (host_key, host_key_error) = match (&membership, &pairing) {
            (Some(m), Some(pairing)) => {
                match membership::host_channel_seed(pairing, m.membership(), &m.pin_of().host_id) {
                    Ok(seed) => (Some(std::sync::Arc::new(HostKey::new(&seed))), None),
                    Err(error) => {
                        eprintln!(
                            "atem runtime: device list: {error}; r9 remote access is refused"
                        );
                        (None, Some(error))
                    }
                }
            }
            _ => (None, None),
        };
        // With `host.delegated` on, the start view is told the list's state
        // at every change (Decision 16) and its deferral is kept on disk.
        let mut membership = membership;
        if let Some(m) = membership.as_mut()
            && features.delegated
        {
            m.set_persist_deferred(true);
            m.set_publisher(list_publisher(&start_view));
        }
        // r9 "No compatibility": a device list (even one that failed to
        // open) refuses r8 admission.
        host.set_refuse_r8(membership.is_some() || membership_error.is_some());
        // §R9.5: the previous run's clean checkpoint names its epoch.
        let checkpoint_clean = membership
            .as_ref()
            .map(|m| m.previous_checkpoint() == Some(previous));
        if checkpoint_clean == Some(false) {
            eprintln!(
                "atem runtime: device list: the previous run (epoch {previous}) left no clean checkpoint; recovery waits resume from the last persisted time"
            );
        }
        let host_pub = host_key
            .as_ref()
            .and(pairing.as_ref())
            .and_then(membership::peek_host_pub);
        let list_stamp = pairing
            .as_ref()
            .map(membership::list_stamp)
            .unwrap_or_default();
        let hasher: Arc<dyn ProjectHasher> = match profile {
            #[cfg(debug_assertions)]
            Some(_) if super::test_hooks::project_hashes().is_some() => {
                Arc::new(super::project_scope::TableHasher {
                    file: super::test_hooks::project_hashes().unwrap(),
                })
            }
            Some(src) => Arc::new(AgentHasher { src: src.clone() }),
            None => Arc::new(NoHasher),
        };
        Ok(Self {
            local: None,
            features,
            host_work: None,
            start_view,
            work: host_work_bridge::State::open(dir, profile.is_some()),
            projects: ProjectScopes::new(hasher),
            project_unread: HashMap::new(),
            r9: {
                let mut r9 = R9Host::with_pairing(r9host::Limits::default(), Some(dir), vouch);
                if let Some(pairing) = &pairing {
                    // §R9.8a: a pending policy write is rolled forward first.
                    r9.set_policy_paths(pairing.clone(), dir.to_path_buf());
                }
                r9
            },
            r9_link: None,
            r9_socket: 0,
            station: None,
            unconverted_fetches: 0,
            pairing,
            host_key,
            host_pub,
            stale_envelopes: 0,
            host_key_error,
            route_chain: Default::default(),
            list_stamp,
            host,
            dir: dir.to_path_buf(),
            clock,
            considered: None,
            link: None,
            last_advance: 0,
            last_host: (0, 0),
            capture_checked: Instant::now(),
            recovered: false,
            seen: HashMap::new(),
            seen_order: VecDeque::new(),
            per: BTreeMap::new(),
            restore: HashSet::new(),
            streams: HashMap::new(),
            chats: HashMap::new(),
            history_key: HistoryKey::random(),
            submitters: HashMap::new(),
            prompts: HashMap::new(),
            prompt_tags: Default::default(),
            view_pauses: Default::default(),
            pauses_loaded: HashSet::new(),
            pauses_dirty: HashSet::new(),
            pauses_retry_at: None,
            interrupts: HashMap::new(),
            pending: HashMap::new(),
            interrupt_reports: Vec::new(),
            #[cfg(debug_assertions)]
            drive_interrupt_reports: Vec::new(),
            #[cfg(debug_assertions)]
            host_interrupt_writes: 0,
            reconciling: BTreeMap::new(),
            #[cfg(debug_assertions)]
            drive_go: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            terminal_out: VecDeque::new(),
            approvals: HashMap::new(),
            revokes: HashMap::new(),
            pushes: Default::default(),
            refusal_log: RefusalLog::default(),
            refusing: None,
            close_link: false,
            close_reason: None,
            membership,
            membership_error,
            membership_effects,
            last_refusal: None,
        })
    }

    /// The link's attachment, its welcome and authorization, the last
    /// refused `hello` and the journal, for `atem status`.
    pub fn link_status(&self) -> LinkStatus {
        use crate::runtime::protocol::{Refusal, Welcomed};
        let (now, wall) = (self.clock.now(), self.clock.wall());
        let welcomed = self.link.as_ref().and_then(|link| {
            Some(Welcomed {
                revision: crate::session_protocol::revision::REVISION,
                at_ms: link.welcomed_at?,
                ms_left: link
                    .deadline
                    .saturating_sub(now)
                    .min(link.wall_deadline.saturating_sub(wall)),
            })
        });
        LinkStatus {
            attachment: self.link.is_some(),
            refused: self.last_refusal.map(|(revision, at_ms)| Refusal {
                revision,
                needs: crate::session_protocol::revision::REVISION,
                at_ms,
            }),
            welcomed,
            journal_halted: self.host.journal_halted(),
        }
    }

    fn build(
        journal: FileJournal,
        identity: &Identity,
        runtime_epoch: u64,
        previous_epoch: u64,
        clock: &Clock,
    ) -> anyhow::Result<SessionHost<FileJournal>> {
        let ctx = HostContext {
            account_id: identity.account_id.clone(),
            atem_device_id: identity.atem_device_id.clone(),
            host_trust_gen: identity.host_trust_gen,
            runtime_gen: uuid::Uuid::new_v4().to_string(),
            runtime_epoch,
        };
        let default = HostConfig::default();
        let config = HostConfig {
            wall_offset_ms: host_now().wall_ms.saturating_sub(clock.now()),
            ..default
        };
        SessionHost::open(ctx, config, journal, random_ids(), Some(previous_epoch))
            .map_err(|e| anyhow::anyhow!(e.0))
    }

    /// At an orderly stop (signal, idle exit, replacement), after the last
    /// pass: the delegated clock's last reading (host-work-v1 §11.6), and
    /// the journal's clean-close record, if it is healthy (r8 §H).
    pub fn close_cleanly(&mut self) {
        self.work_close();
        if let Some(membership) = self.membership.as_mut()
            && membership.close(&host_now())
        {
            eprintln!("atem runtime: device list checkpointed");
        }
        if self.host.close_cleanly() {
            eprintln!("atem runtime: session journal closed cleanly");
        } else {
            eprintln!(
                "atem runtime: session journal not closed cleanly (a write failed in this run)"
            );
        }
    }

    /// Why remote sessions are disabled since the start, if they are (the
    /// recovered requests couldn't be resolved durably).
    pub fn host_error(&self) -> Option<String> {
        self.host
            .start_error()
            .map(|e| format!("remote sessions disabled: {e}; restart Atem"))
    }

    /// The r9 device list: none (not paired for r9), open (Task 7 admits
    /// through it), or failed to open (Task 7 refuses r9 admission; r8 is
    /// unaffected, so `host_error` doesn't report it).
    #[cfg(test)]
    pub fn device_list(&self) -> membership::DeviceList {
        use membership::DeviceList;
        match (&self.membership, &self.membership_error) {
            (Some(_), _) => DeviceList::Open,
            (None, Some(_)) => DeviceList::Failed,
            (None, None) => DeviceList::None,
        }
    }

    /// Applies a carried suffix or window to the device list (§R9.3: one
    /// step of the pass, before the carrier's admission) and performs its
    /// fences: removed principals' attachments fenced, leases revoked,
    /// queued work rejected (r8 §H); on a write fault the same in memory and
    /// the journal halts. `None` without a device list.
    fn carry(&mut self, carried: &[StrictValue], cx: &mut Cx) -> Option<CarriageResult> {
        let membership = self.membership.as_mut()?;
        let mut fences = HostFences::new(&mut self.host);
        let result = membership.apply_carriage(carried, &host_now(), &mut fences);
        let effects = fences.effects;
        let closing = self.close_link;
        self.exec(effects, cx);
        self.carriage_closed(closing);
        self.sync_all(cx);
        Some(result)
    }

    /// Every pass, in debug builds: a test carriage
    /// (`ATEM_TEST_MEMBERSHIP_FAULTS/carry.json`, as the host's own relay
    /// fetch), whatever the clocks do (release builds: never one).
    fn test_carriage(&mut self, cx: &mut Cx) {
        if self.membership.is_none() {
            return;
        }
        if let Some(text) = super::test_hooks::membership_carry() {
            let entries = StrictValue::parse(text.as_bytes(), usize::MAX)
                .ok()
                .and_then(|v| v.get("entries"))
                .and_then(|e| e.items());
            let line = match entries {
                Some(entries) => match self.carry(&entries, cx) {
                    Some(result) => {
                        let carried = self.r9_call(|r9, parts| r9.carried(&result, None, parts));
                        self.r9_exec(carried, cx);
                        format!(
                            "{:?} head={} fences={}",
                            result.carried,
                            self.membership.as_ref().map_or(0, |m| m.head().seq),
                            result.fences.len()
                        )
                    }
                    None => "no device list".into(),
                },
                None => "unreadable carry.json".into(),
            };
            super::test_hooks::membership_carried(&line);
        }
    }

    /// The device list's 100 ms pass: recovery waits on the host clock, the
    /// time waited persisted.
    fn membership_pass(&mut self, cx: &mut Cx) {
        self.reopen_list_if_changed(cx);
        if self.membership.is_none() {
            return;
        }
        let pending = std::mem::take(&mut self.membership_effects);
        if !pending.is_empty() {
            self.exec(pending, cx);
        }
        if self
            .membership
            .as_ref()
            .is_some_and(MembershipHost::unpaired)
        {
            // `atem unpair` removed the device list: this host has none now,
            // and every channel ends.
            self.membership = None;
            self.sync_list_view();
            self.host_key = None;
            self.host_pub = None;
            self.restart_channels(cx);
            self.sync_refuse_r8(cx);
        }
        let Some(membership) = self.membership.as_mut() else {
            return;
        };
        let mut fences = HostFences::new(&mut self.host);
        let changes = membership.advance(&host_now(), &mut fences);
        let effects = fences.effects;
        if !effects.is_empty() {
            self.exec(effects, cx);
            self.sync_all(cx);
        }
        if !changes.is_empty() {
            self.r9_call(|r9, parts| r9.announce(parts));
        }
    }

    // ── r9 (§R9.7a) ──

    /// An envelope of another link generation (it arrived while the link
    /// was re-authenticated or replaced): its channel ended with that
    /// generation; dropped, counted in runtime.log.
    fn stale_envelope(&mut self, link_gen: u64) {
        self.stale_envelopes += 1;
        if self.stale_envelopes.is_power_of_two() {
            eprintln!(
                "atem runtime: r9: {} envelope(s) of an ended link generation dropped (the last of generation {link_gen})",
                self.stale_envelopes
            );
        }
    }

    /// Every channel ends while the socket stays up (a re-pin or unpair):
    /// each live handle gets `close{closed}` on the link, the link
    /// generation goes on (envelopes of this pass are still served).
    fn restart_channels(&mut self, cx: &mut Cx) {
        // The old pin's approvals and their hints go with it (§R9.9: a
        // hint is bound to the account, genesis and host trust generation).
        self.r9.reset_push();
        let before = self.r9_attachments();
        // The closes are queued in the engine with the ones already there
        // and sent on this socket by the pass's flush.
        let effects = self.r9_call(|r9, parts| r9.restart(parts));
        for gone in &before {
            self.forget_r9(gone);
        }
        if let Some(link_gen) = self.r9_link {
            let up = self.r9_call(|r9, parts| r9.link_up(link_gen, parts));
            self.r9_exec(up, cx);
        }
        self.r9_exec(effects, cx);
    }

    /// The device list for `atem status`, `atem agent list` and the status
    /// row: `None` without one. Failed is shown too (`host_error` doesn't
    /// report it: r8 sessions are unaffected without a list).
    pub fn device_list_status(&self) -> Option<crate::runtime::protocol::DeviceListStatus> {
        let now = host_now();
        let mut status = device_list_status_of(
            self.membership.as_ref(),
            self.membership_error
                .as_deref()
                .or(self.host_key_error.as_deref()),
            self.r9.status().attachments,
            &now,
        )?;
        let push = self.r9.push_status(now.wall_ms);
        status.push_pending = push.pending;
        status.push_oldest_ms = push.oldest_ms;
        Some(status)
    }

    /// Whether the relay link answers a `host_challenge` now (§R9.7b): only
    /// with a pinned device list that can serve (not held, frozen or
    /// faulted; the journal not halted; the host channel key loaded), at
    /// its head. Push's suppression rules (§R9.9) with the same words.
    pub(super) fn route_state(&self) -> RouteState {
        if self.host.journal_halted() {
            return RouteState::Off("journal halted");
        }
        if self.membership_error.is_some() {
            return RouteState::Off("device list failed");
        }
        let Some(m) = &self.membership else {
            return RouteState::Off(r9host::push::NO_LIST);
        };
        let Some(key) = &self.host_key else {
            return RouteState::Off("no host channel key");
        };
        if m.unpaired() {
            return RouteState::Off(r9host::push::NO_LIST);
        }
        if m.is_frozen() {
            return RouteState::Off("device list frozen");
        }
        if m.faulted().is_some() {
            return RouteState::Off("device list faulted");
        }
        if m.held().is_some() {
            return RouteState::Off("device list held");
        }
        let log = m.membership();
        let head = m.head();
        let mut cached = self.route_chain.borrow_mut();
        let current = cached.as_ref().is_some_and(|chain| {
            usize::try_from(head.seq).is_ok_and(|n| chain.len() == n)
                && chain.last() == Some(&head.hash)
        });
        if !current {
            *cached = Some(std::sync::Arc::new(
                log.entries().iter().map(|e| e.hash()).collect(),
            ));
        }
        let chain = cached.clone().expect("built above");
        RouteState::Ready {
            id: RouteIdentity {
                account_id: log.account_id().to_owned(),
                genesis_hash: log.genesis_hash(),
                host_id: m.pin_of().host_id.clone(),
                head,
                chain,
            },
            key: key.clone(),
        }
    }

    /// Runs `f` on the r9 host with this bridge's session host, device
    /// list and clocks.
    fn r9_call<T>(&mut self, f: impl FnOnce(&mut R9Host, &mut R9Parts<'_, FileJournal>) -> T) -> T {
        let list = match (
            &mut self.membership,
            &self.membership_error,
            &self.host_key,
            &self.host_key_error,
        ) {
            (_, Some(error), _, _) => r9host::DeviceList::Failed(error),
            (Some(m), None, Some(key), _) => r9host::DeviceList::Open { m, key: &**key },
            (Some(_), None, None, Some(error)) => r9host::DeviceList::Failed(error),
            (Some(_), None, None, None) => r9host::DeviceList::Failed("no host channel key"),
            (None, None, _, _) => r9host::DeviceList::None,
        };
        let mut parts = R9Parts {
            host: &mut self.host,
            list,
            now: R9Now {
                mono: self.clock.now(),
                host: host_now(),
            },
            projects: &self.projects,
        };
        let out = f(&mut self.r9, &mut parts);
        // A channel opened or closed: the natives' gates follow it.
        self.refresh_gates();
        out
    }

    /// The start view's caught-up natives (design I.5.8, "Native
    /// senders"): those holding an open channel whose `hello` carriage
    /// brought the host up to their own head (`R9Host::native_caught_up`).
    fn refresh_gates(&mut self) {
        if !self.features.delegated {
            return;
        }
        let natives = self
            .r9
            .caught_up_natives()
            .into_iter()
            .map(|(principal, _)| principal)
            .collect();
        self.start_view().gates.set_caught_up(natives);
    }

    /// The start view, locked (a poisoned lock is taken as it is: the view
    /// holds no invariant a panic could break halfway).
    pub(super) fn start_view(&self) -> std::sync::MutexGuard<'_, StartView> {
        self.start_view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The start view's device list follows `self.membership`: a list that
    /// opened tells it its state at every change (a new one is given the
    /// publisher here), and none (unpaired, failed, being reopened) leaves
    /// it without one, so no delegated task starts.
    /// Only while `host.delegated` is on: with it off nothing reads the view
    /// (Task 19 review M1).
    fn sync_list_view(&mut self) {
        if !self.features.delegated {
            return;
        }
        match self.membership.as_mut() {
            Some(m) if m.has_publisher() => {}
            Some(m) => {
                m.set_persist_deferred(true);
                m.set_publisher(list_publisher(&self.start_view));
            }
            None => self.start_view().list = None,
        }
    }

    /// The session host's effects of an r9 call; attachments the r9 host
    /// let go are forgotten here too.
    fn r9_exec(&mut self, effects: Vec<Effect>, cx: &mut Cx) {
        let before: HashSet<String> = self.r9_attachments();
        self.exec(effects, cx);
        let after = self.r9_attachments();
        for gone in before.difference(&after) {
            self.forget_r9(gone);
        }
        self.sync_all(cx);
    }

    /// Approval cards and session rules are shown to (and answerable by)
    /// an attachment with `control`; an r9 principal also needs the
    /// `approval` op when it is scoped (§R9.6: a service without it gets
    /// no cards).
    fn shows_cards(&self, attachment: &str) -> bool {
        self.host.attachment_can(attachment, Permission::Control)
            && (!self.r9.owns(attachment) || self.r9.sees_approvals(attachment))
    }

    /// A session the runtime just added (launched or adopted), before any
    /// pass registered it: its launch project is read now from its worker's
    /// record, written before the worker's `hello`, so a message sent right
    /// after a launch resolves to it (local routes match on the project); a
    /// pass would learn it only after requests handled in between.
    pub fn session_added(&mut self, sid: &SessionId) {
        if let Some(state) = self.dir.parent()
            && let Ok(record) =
                super::worker::read_record(&super::worker::record_path(state, sid.as_str()))
        {
            self.projects.session(sid.as_str(), record.project_key);
        }
    }

    /// A session the runtime removed: its launch project goes with it, also
    /// when no pass registered it.
    pub fn session_removed(&mut self, sid: &SessionId) {
        self.projects.forget(sid.as_str());
    }

    /// The keyed hashes of the sessions' launch projects (never waiting
    /// for the cred agent): once a session's become known, its descriptor
    /// goes out again, so attachments whose `projects` scope now holds it
    /// see it (§R9.6; out-of-scope ones still get nothing).
    fn project_pass(&mut self, cx: &mut Cx) {
        if !self.project_unread.is_empty()
            && let Some(state) = self.dir.parent()
        {
            // A record not there yet (or unreadable) is looked for again
            // every `RETRY`, not every pass.
            let now = Instant::now();
            let due: Vec<String> = self
                .project_unread
                .iter()
                .filter(|(_, at)| now >= **at)
                .map(|(sid, _)| sid.clone())
                .collect();
            for sid in due {
                let path = super::worker::record_path(state, &sid);
                match super::worker::read_record(&path) {
                    Ok(record) => {
                        self.project_unread.remove(&sid);
                        self.projects.session(&sid, record.project_key);
                    }
                    Err(_) => {
                        self.project_unread
                            .insert(sid, now + super::project_scope::RETRY);
                    }
                }
            }
        }
        let mut kids = self.r9.scope_project_kids();
        if let Some(m) = &self.membership {
            kids.extend(super::project_scope::project_kids_of(
                m.membership(),
                host_now().wall_ms,
            ));
        }
        for sid in self.projects.pass(&kids, Instant::now()) {
            self.host.registry_resend(&sid);
            let effects = self.host.take_effects();
            self.r9_exec(effects, cx);
        }
    }

    fn r9_attachments(&self) -> HashSet<String> {
        self.r9.attachments().into_iter().map(|(a, _)| a).collect()
    }

    /// The broker's side of a closed r9 attachment: its streams,
    /// conversations and remote writes go (the link's terminal queue isn't
    /// its).
    fn forget_r9(&mut self, attachment: &str) {
        self.streams.retain(|(att, _), _| att != attachment);
        for chats in self.chats.values_mut() {
            chats.map.retain(|_, c| c.attachment != attachment);
        }
        for per in self.per.values_mut() {
            per.remote.retain(|w| w.attachment != attachment);
        }
    }

    /// Channels run on the authenticated link: a new link generation
    /// starts a new set (the old one's channels all closed, §R9.7a 6).
    fn sync_r9_link(&mut self, want: Option<u64>, cx: &mut Cx) {
        if want == self.r9_link {
            return;
        }
        // A re-authentication (or a new generation) on a socket that is
        // still up: the router learns each channel ended (§R9.7a 6), the
        // closes handed to that socket now, before anything of the new
        // generation; what it can't take now is dropped and counted (N9).
        // A socket that is gone takes everything with it.
        let before = self.r9_attachments();
        // Live: the generation's own socket is still up (a reconnect made a
        // new socket, and the old generation's closes never go on it).
        let live = !cx.client.is_ws_closed() && cx.client.socket_gen() == self.r9_socket;
        let client = cx.client;
        let mut effects = self.r9_call(|r9, parts| {
            if live {
                r9.end_generation(parts, &mut |text| client.try_send_channel(text))
            } else {
                r9.link_down(parts)
            }
        });
        for gone in &before {
            self.forget_r9(gone);
        }
        if let Some(link_gen) = want {
            effects.extend(self.r9_call(|r9, parts| r9.link_up(link_gen, parts)));
        }
        self.r9_link = want;
        self.r9_socket = cx.client.socket_gen();
        self.r9_exec(effects, cx);
    }

    /// The host's Station link follows the r9 link (host-work-v1 §11.4):
    /// only with `host.delegated` (Decision 11; off, the bridge has none and
    /// the Station's messages are dropped, as before); a new generation
    /// starts afresh, its kind and the selected Station's origin taken then.
    fn sync_station_link(&mut self, app: &App) {
        if !self.features.delegated {
            self.station = None;
            return;
        }
        let link_gen = self.r9_link;
        self.station.get_or_insert_with(Station::new).sync_link(
            link_gen,
            || station_link_kind(app),
            || app.astation_client.selected_station_origin(),
        );
        self.refresh_fetch_view();
    }

    /// The start view's copy of the host's own fetch on its Station link
    /// (the gates' device-list part, design I.5.8), after the link or its
    /// fetch changed. The list it is judged against is the view's own, as
    /// it commits.
    fn refresh_fetch_view(&self) {
        if !self.features.delegated {
            return;
        }
        let fetch = self.station.as_ref().and_then(Station::list_fetch);
        self.start_view().fetch = fetch;
    }

    /// The device list's deferral, as the fetch reads it: the deferred
    /// entry's `seq` (design I.4.3).
    fn list_deferral(&self) -> Option<u64> {
        self.membership
            .as_ref()
            .and_then(MembershipHost::deferred_stop)
            .map(|d| d.seq)
    }

    /// The Station's messages of this pass, as received (none while
    /// `host.delegated` is off: dropped), and the host's calls: the device
    /// list's fetch (design I.5.8, session-v1 R9.3). A fetch result is
    /// applied as any carriage, with no more trust than any carrier: the
    /// list's own verification (`carry`), then the r9 engine's effects
    /// (`R9Host::carried`: fences, push recipients, `membership_head`).
    /// Calls go on the link's control queue, as the relay's push messages.
    fn station_pass(&mut self, messages: Vec<String>, cx: &mut Cx) {
        let applied = self.membership.as_ref().map(MembershipHost::head);
        let deferred = self.list_deferral();
        let Some(station) = self.station.as_mut() else {
            return;
        };
        let mut calls: Vec<atem_client::control::MembershipFetch> = station
            .tick(host_now().mono_ms, applied, deferred)
            .into_iter()
            .collect();
        for text in messages {
            let applied = self.membership.as_ref().map(MembershipHost::head);
            let deferred = self.list_deferral();
            let Some(station) = self.station.as_mut() else {
                return;
            };
            let inbound = station.receive(&text, applied, deferred);
            // A `heads` may name a head beyond the list: the gate's
            // device-list part follows before anything else runs.
            self.refresh_fetch_view();
            match inbound {
                StationInbound::Nothing => {}
                StationInbound::Send(call) => calls.push(call),
                StationInbound::Carry(entries) => {
                    // Every entry or none: a carriage is never shortened.
                    let carried: Result<Vec<StrictValue>, _> = entries
                        .iter()
                        .map(|e| StrictValue::parse(e.to_json().to_string().as_bytes(), usize::MAX))
                        .collect();
                    // Where the carriage stopped at a deferred entry, if it
                    // did: nothing past it applies before its wait ends.
                    let mut stopped_at = None;
                    match carried {
                        Ok(carried) => {
                            if let Some(result) = self.carry(&carried, cx) {
                                stopped_at = result.deferred_at();
                                let effects =
                                    self.r9_call(|r9, parts| r9.carried(&result, None, parts));
                                self.r9_exec(effects, cx);
                            }
                        }
                        Err(_) => {
                            self.unconverted_fetches += 1;
                            if self.unconverted_fetches.is_power_of_two() {
                                eprintln!(
                                    "atem runtime: {} device-list fetch result(s) not carried (an entry didn't read back)",
                                    self.unconverted_fetches
                                );
                            }
                        }
                    }
                    let after = self.membership.as_ref().map(MembershipHost::head);
                    if let (Some(before), Some(after), Some(station)) =
                        (applied, after, self.station.as_mut())
                        && let Some(call) = station.fetch.carried(&before, &after, stopped_at)
                    {
                        calls.push(call);
                    }
                }
            }
        }
        let Some(station) = self.station.as_mut() else {
            return;
        };
        for call in calls {
            let sent = self.r9_link.is_some()
                && call
                    .to_json()
                    .is_ok_and(|text| cx.client.try_send_wire(text.to_string(), false).is_ok());
            if !sent {
                station.fetch.unsent();
            }
        }
        self.refresh_fetch_view();
    }

    /// The device list changed on disk while the runtime runs (a pairing
    /// pinned one, `atem unpair` removed it, a re-pin replaced it): it is
    /// opened again, the session host takes the pin's identity, r8 is
    /// refused from then on, and every channel and the link's r8
    /// attachment start over.
    fn reopen_list_if_changed(&mut self, cx: &mut Cx) {
        let Some(pairing) = self.pairing.clone() else {
            return;
        };
        let stamp = membership::list_stamp(&pairing);
        if stamp == self.list_stamp {
            return;
        }
        self.list_stamp = stamp;
        // Our own writes move the stamp too: only another pin matters.
        let pinned = membership::peek_pin_genesis(&pairing);
        let host_pub = membership::peek_host_pub(&pairing);
        let same = match (&self.membership, &pinned) {
            (Some(m), Some((account, pin, genesis))) => {
                !m.unpaired()
                    && m.membership().account_id() == account
                    && m.pin_of() == pin
                    && m.membership().genesis_hash().to_hex() == *genesis
                    && (self.host_key.is_none() || host_pub == self.host_pub)
            }
            (None, None) => {
                self.membership_error.is_none() && !membership::has_device_list_files(&pairing)
            }
            _ => false,
        };
        if same {
            // The same pin (our own writes moved the stamp): never reopened
            // (that would drop the run's in-memory state: a fault, a hold);
            // only a host key that was missing is looked for again.
            if self.host_key.is_none()
                && let Some(m) = &self.membership
            {
                match membership::host_channel_seed(&pairing, m.membership(), &m.pin_of().host_id) {
                    Ok(seed) => {
                        self.host_key = Some(std::sync::Arc::new(HostKey::new(&seed)));
                        self.host_pub = membership::peek_host_pub(&pairing);
                        self.host_key_error = None;
                    }
                    Err(error) => self.host_key_error = Some(error),
                }
            }
            return;
        }
        eprintln!("atem runtime: device list: changed on disk; opening it again");
        self.restart_channels(cx);
        let pinned = pinned.map(|(account, pin, _)| (account, pin));
        self.membership = None;
        // No delegated task starts while the list is reopened.
        self.sync_list_view();
        self.membership_error = None;
        self.host_key = None;
        self.host_key_error = None;
        if let Some((account, pin)) = &pinned
            && wire::is_opaque_id(account)
            && wire::is_opaque_id(&pin.host_id)
        {
            let identity = Identity {
                account_id: account.clone(),
                atem_device_id: pin.host_id.clone(),
                host_trust_gen: pin.host_trust_gen,
            };
            if !self.adopt_identity(&identity, cx) {
                self.membership_error =
                    Some("the device list names an older host trust generation".into());
            }
        }
        if self.membership_error.is_none() {
            let epoch = self.host.context().runtime_epoch;
            let mut fences = HostFences::new(&mut self.host);
            let opened = MembershipHost::open(&pairing, &self.dir, epoch, &host_now(), &mut fences);
            #[cfg(test)]
            after_reopen(&pairing);
            let effects = fences.effects;
            match opened {
                Ok(Some((m, _))) => {
                    match membership::host_channel_seed(
                        &pairing,
                        m.membership(),
                        &m.pin_of().host_id,
                    ) {
                        Ok(seed) => {
                            self.host_key = Some(std::sync::Arc::new(HostKey::new(&seed)));
                            self.host_pub = membership::peek_host_pub(&pairing);
                        }
                        Err(error) => {
                            eprintln!("atem runtime: device list: {error}");
                            self.host_key_error = Some(error);
                        }
                    }
                    eprintln!(
                        "atem runtime: device list: opened at seq {} for {}",
                        m.head().seq,
                        m.pin_of().host_id
                    );
                    self.membership = Some(m);
                    self.sync_list_view();
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("atem runtime: device list: {error}; r9 remote access is refused");
                    self.membership_error = Some(error);
                }
            }
            self.exec(effects, cx);
        }
        // The stamp stays the one read before opening: a pin still being
        // written (its key and applied head first, the list last) changes
        // it again, and the next pass opens the finished list.
        self.sync_refuse_r8(cx);
    }

    /// r9 "No compatibility": r8 admission is refused while a device list
    /// exists (open or failed). When one appears, the link's r8 attachment
    /// (possibly welcomed) goes; the link gets a new, unwelcomed one.
    fn sync_refuse_r8(&mut self, cx: &mut Cx) {
        let refuse = self.membership.is_some() || self.membership_error.is_some();
        if refuse == self.host.refuses_r8() {
            return;
        }
        self.host.set_refuse_r8(refuse);
        if refuse {
            // r9 (§R9.9): nothing in clear to the relay from now on, not
            // even what was queued before the pin.
            self.pushes = Default::default();
        }
        if refuse && let Some(link) = self.link.take() {
            eprintln!("atem runtime: {DEVICE_LIST_PINNED}");
            let want = self.considered;
            self.drop_attachment(&link.attachment, cx);
            // At once a new, unwelcomed attachment: its r8 hello is refused.
            self.considered = None;
            self.sync_link(want, cx);
        }
    }

    /// An r9 channel is mid-admission (§R9.7b: the route reconnect waits).
    pub fn r9_admitting(&self) -> bool {
        self.r9.admitting()
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
        self.work_config();
        // Displayed times (descriptors, receipts, `welcome.server_time`)
        // follow the host clock, which moves while the machine sleeps.
        self.host
            .set_wall_offset(host_now().wall_ms.saturating_sub(self.clock.now()));
        #[cfg(debug_assertions)]
        if let Some(hold) = super::test_hooks::hold_dispatch() {
            self.host.hold_dispatch(hold);
        }
        // An r9 host (r8 refused, §R9) never welcomes the link's attachment
        // and its link carries no session authority: its end would only
        // close every r9 channel on the link daily (each channel has its
        // own lifetime, §R9.7a). An r8 host's link ends as before.
        let r8 = !self.host.refuses_r8();
        if self.link.as_ref().is_some_and(|l| {
            r8 && (self.clock.now() >= l.deadline || self.clock.wall() >= l.wall_deadline)
        }) {
            // Its authorization ended: the attachment is fenced and the link
            // dropped, so the normal reconnect authenticates it again.
            app.drop_astation_link("Astation link authorization expired; reconnecting".into());
        }
        if self.capture_checked.elapsed() >= CAPTURE_CHECK {
            self.capture_checked = Instant::now();
            // `atem unpair` (or a new pairing) changed the pairing this link
            // authenticated under, even if no `reload` reached the runtime:
            // drop the link with its attachment.
            let stale = (app.astation_connected || app.astation_routed)
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
        self.load_prompt_tags(&cx);
        self.sync_local(&mut cx);
        if !adopting && !self.recovered {
            self.recovered = true;
            let effects = self.host.recover();
            self.exec(effects, &mut cx);
            if let Some(error) = self.host_error() {
                eprintln!("atem runtime: {error}");
            }
        }
        // After the start's recovery, so recovered work meets the sessions
        // adopted by then.
        if self.recovered {
            // Host-work's executing prompts whose adopted chat arrived.
            self.reconcile_host_work(&mut cx);
            self.sync_host_work(&mut cx);
            #[cfg(debug_assertions)]
            self.drive_pass(&mut cx);
        }
        self.sync_r9_link(r9_app_link(app), &mut cx);
        self.sync_station_link(app);
        if !adopting
            && app
                .hosted
                .as_ref()
                .is_some_and(|h| !h.inbox.is_empty() || !h.channels.is_empty())
        {
            // A pin made just now (by a pairing in this runtime) is seen by
            // the very next request, never after it: an r8 hello is never
            // welcomed on a host that has a device list.
            self.reopen_list_if_changed(&mut cx);
        }
        if !adopting && let Some(hosted) = app.hosted.as_mut() {
            let inbox: Vec<(u64, String)> = hosted.inbox.drain(..).collect();
            for (link_gen, text) in inbox {
                self.receive(link_gen, &text, &mut cx);
            }
            let channels: Vec<(u64, String)> = hosted.channels.drain(..).collect();
            hosted.channel_bytes = 0;
            let overflow = std::mem::take(&mut hosted.channel_overflow);
            for (link_gen, text) in channels {
                #[cfg(debug_assertions)]
                if super::test_hooks::no_init_limit() {
                    self.r9.reset_init_limiter();
                }
                if Some(link_gen) == self.r9_link {
                    let effects = self.r9_call(|r9, parts| r9.on_envelope(&text, parts));
                    self.r9_exec(effects, &mut cx);
                } else {
                    self.stale_envelope(link_gen);
                }
            }
            for (link_gen, text) in std::mem::take(&mut hosted.relay) {
                // §R9.9: the relay's `push_ack` on the link it was sent on;
                // §11.4: the Station's messages to this host (below).
                if Some(link_gen) == self.r9_link {
                    self.r9.relay_message(&text);
                }
            }
            let station = self.r9.take_station_messages();
            self.station_pass(station, &mut cx);
            for (link_gen, handle, why) in overflow {
                if Some(link_gen) == self.r9_link {
                    let effects = self.r9_call(|r9, parts| r9.refuse_unread(&handle, why, parts));
                    self.r9_exec(effects, &mut cx);
                } else {
                    self.stale_envelope(link_gen);
                }
            }
        }
        self.worker_reports(&mut cx);
        self.app_refusals(&mut app.hosted);
        let now = self.clock.now();
        let host = host_now();
        let host_moved = host.wall_ms >= self.last_host.0 + ADVANCE_EVERY
            || host.mono_ms >= self.last_host.1 + ADVANCE_EVERY
            || host.mono_ms < self.last_host.1;
        if now >= self.last_advance + ADVANCE_EVERY || host_moved {
            self.last_advance = now;
            self.last_host = (host.wall_ms, host.mono_ms);
            let effects = self.host.advance(now);
            self.exec(effects, &mut cx);
            self.finished_hand_offs(&mut cx);
            self.membership_pass(&mut cx);
            let effects = self.r9_call(|r9, parts| r9.tick(parts));
            self.r9_exec(effects, &mut cx);
        }
        if self.host_work.is_some() {
            self.renew_host_work_leases();
            let effects = self.host.take_effects();
            self.exec(effects, &mut cx);
        }
        self.test_carriage(&mut cx);
        self.sync_local(&mut cx);
        self.work_config();
        self.project_pass(&mut cx);
        self.sync_all(&mut cx);
        if !adopting {
            self.work_pass(&mut cx);
        }
        self.drain_remote(&mut cx);
        self.view_pause_pass(&cx);
        self.frames(&mut cx);
        self.heartbeats(&mut cx);
        self.flush_pushes(&mut cx);
        let effects = self.r9_call(|r9, parts| r9.reap(parts));
        self.r9_exec(effects, &mut cx);
        // Only for the state dump (PR 5 review M9).
        #[cfg(debug_assertions)]
        let chats = super::test_hooks::state_dump()
            .is_some()
            .then(|| chat_dump(&cx));
        let client = cx.client;
        // §R9.8a: a committed relay-only result's write is what a local
        // link waits for before it closes.
        let mut receipt = None;
        self.r9.flush(&mut |text, wants| {
            let (sent, delivered) = client.try_send_channel_with(text, wants);
            if delivered.is_some() {
                receipt = delivered;
            }
            sent
        });
        let policy_changes = self.r9.take_policy_changes();
        if self.r9_link.is_some() {
            self.r9
                .flush_relay(&mut |text| client.try_send_wire(text, false).is_ok());
        }
        self.r9.end_pass();
        // §R9.7b: the relay link answers challenges at this pass's state;
        // able to again (pinned, reconciled): its link proves its route.
        if crate::session_protocol::r9::route::set(&app.host_route, self.route_state()) {
            app.route_reconnect = Some(std::time::Instant::now());
        }
        for relay_only in policy_changes {
            app.host_policy_changed(relay_only);
        }
        if let Some(receipt) = receipt {
            app.relay_only_receipt(receipt);
        }
        self.r9.set_refuse_opens(app.relay_only_drop_pending());
        if let Some(reason) = self.take_close() {
            app.drop_astation_link(reason.into());
        }
        #[cfg(debug_assertions)]
        self.dump_state(chats);
    }

    /// Debug builds (`ATEM_TEST_STATE_DUMP`): the state the r9 fixtures
    /// assert, written after each pass with the pass number
    /// (`tests/r9_runner`).
    #[cfg(debug_assertions)]
    fn dump_state(&mut self, chats: Option<Value>) {
        use serde_json::json;
        let Some(file) = super::test_hooks::state_dump() else {
            return;
        };
        let head =
            |h: atem_client::membership::Head| json!({"seq": h.seq, "hash": h.hash.to_hex()});
        let (receipt_ids, session_ids, principals) = self.host.debug_ids();
        let receipts: serde_json::Map<String, serde_json::Value> = receipt_ids
            .iter()
            .filter_map(|rid| {
                let r = serde_json::to_value(self.host.receipt(rid)?).ok()?;
                Some((
                    rid.clone(),
                    json!({"state": r["state"], "detail": r["detail"]}),
                ))
            })
            .collect();
        let leases: serde_json::Map<String, serde_json::Value> = session_ids
            .iter()
            .map(|sid| {
                (
                    sid.clone(),
                    json!({"holder": self.host.lease_holder(sid),
                           "epoch": self.host.lease_epoch(sid)}),
                )
            })
            .collect();
        let visible: serde_json::Map<String, serde_json::Value> = self
            .r9
            .attachment_ids()
            .into_iter()
            .map(|att| {
                let n = self.host.receipts_visible(&att);
                (att, json!(n))
            })
            .collect();
        let status = self.r9.status();
        let mut state = json!({
            "journal_halted": self.host.journal_halted(),
            "channels": status.channels,
            "attachments": status.attachments,
            "leases": leases,
            "receipts": receipts,
            "receipts_visible": visible,
            "membership_error": self.membership_error,
            "station": self.station.as_ref().map(|station| {
                let mut dump = station.dump();
                // The gates' device-list part now (design I.5.8).
                dump["list_part"] = json!(self.membership.as_ref().is_some_and(|m| {
                    station.fetch.part().holds(m.membership(), self.list_deferral())
                }));
                dump
            }),
        });
        if let Some(m) = self.membership.as_ref() {
            let control_gen: serde_json::Map<String, serde_json::Value> = principals
                .iter()
                .map(|p| (p.clone(), json!(self.host.control_gen(p))))
                .collect();
            state["membership"] = json!({
                "head": head(m.head()),
                "applied": head(m.applied().head),
                "frozen": m.is_frozen(),
                "frozen_durable": m.frozen_durable(),
                "faulted": m.faulted().is_some(),
                "held": m.held().is_some(),
                "unclean": m.unclean().map(head),
                "carriage_record": m.carriage_record_present(),
                "fault_record": m.fault_record_present(),
                "control_gen": control_gen,
                "members": m.membership().members(),
                "records": m.membership().records().iter().map(|r| {
                    (r.entry_hash.to_hex(), json!(r.state().as_str()))
                }).collect::<serde_json::Map<String, serde_json::Value>>(),
                "evidence": {
                    "count": m.membership().evidence().count,
                    "reason": m.membership().evidence().recent.last().map(|r| r.reason.as_str()),
                },
                "recovery_key": atem_client::encoding::b64u(m.membership().recovery_key().as_bytes()),
                "k_backup": m.membership().k_backup().map(|k| json!({
                    "blob_version": k.blob_version, "backup_hash": k.backup_hash.to_hex()})),
            });
        }
        state["chats"] = chats.unwrap_or_default();
        state["reconciling"] = json!(self.reconciling.keys().collect::<Vec<_>>());
        // Host-work's scheduling passes and the host interrupt writes so far
        // (a broker tick isn't a scheduling pass: those run every 100 ms).
        state["host_work"] = json!({"passes": self.work.passes,
            "interrupt_writes": self.host_interrupt_writes});
        // The pass number: a reader can wait for a pass after its own
        // action (a dump from before it can't satisfy an assert).
        static PASS: AtomicU64 = AtomicU64::new(0);
        state["pass"] = json!(PASS.fetch_add(1, Ordering::SeqCst) + 1);
        let text = state.to_string();
        let tmp = file.with_extension("tmp");
        if std::fs::write(&tmp, &text).is_ok() {
            let _ = std::fs::rename(&tmp, &file);
        }
    }

    /// After a carriage's effects: the device-list reason goes with this
    /// carriage's own link drop only (`closing`: a drop was already due).
    fn carriage_closed(&mut self, closing: bool) {
        if !closing && self.close_link {
            self.close_reason = Some(DEVICE_LIST_DROP);
        }
    }

    /// The link drop due after this pass, with its reason; the reason never
    /// outlives the pass.
    fn take_close(&mut self) -> Option<&'static str> {
        let reason = self.close_reason.take();
        std::mem::take(&mut self.close_link).then(|| reason.unwrap_or(REFUSAL_DROP))
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
        let astation_id = cx
            .client
            .connected_astation_id()
            .unwrap_or_default()
            .to_string();
        let Some(principal) = link_principal(&identity, &astation_id) else {
            eprintln!(
                "atem runtime: the Astation id can't name a principal; no session attachment"
            );
            return;
        };
        let attachment = uuid::Uuid::new_v4().to_string();
        let attach = Attach {
            client: astation_id,
            principal,
            attachment_gen: attachment.clone(),
            permissions: link_permissions(),
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
                    welcomed_at: None,
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
                self.drop_all_rules(cx);
            }
            return true;
        }
        let epoch = match next_runtime_epoch(&self.dir, self.pairing.as_ref()) {
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
                self.drop_all_rules(cx);
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

    /// After the host was rebound or its trust moved on: every session rule
    /// was granted under the old account, device or trust generation, so
    /// every worker drops all of them (the host already cleared its copy).
    fn drop_all_rules(&mut self, cx: &mut Cx) {
        for session in cx.sessions.values() {
            let _ = session.revoke_all_approval_rules();
        }
    }

    /// What a session rule granted now is granted under.
    fn rule_grant(&self) -> RuleGrant {
        let ctx = self.host.context();
        RuleGrant {
            account_id: ctx.account_id.clone(),
            atem_device_id: ctx.atem_device_id.clone(),
            host_trust_gen: ctx.host_trust_gen,
        }
    }

    fn drop_attachment(&mut self, attachment: &str, cx: &mut Cx) {
        let effects = self.host.disconnect(attachment);
        self.exec(effects, cx);
        self.forget_attachment(attachment);
    }

    /// The broker's side of a fenced attachment: its frame streams, chat
    /// conversations, queued terminal messages and remote writes go.
    fn forget_attachment(&mut self, attachment: &str) {
        self.streams.retain(|(att, _), _| att != attachment);
        for chats in self.chats.values_mut() {
            chats.map.retain(|_, c| c.attachment != attachment);
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

    /// The attachment is the link's own or an r9 channel's: its messages
    /// have somewhere to go.
    fn reachable(&self, attachment: &str) -> bool {
        self.current(attachment)
            || self.r9.owns(attachment)
            || (!attachment.is_empty() && attachment == self.local_attachment())
    }

    /// The `host-work` principal's internal attachment, while the session
    /// host has it (`host.delegated` on; session-v1 R9.14 item 1).
    pub fn host_work_attachment(&self) -> Option<&str> {
        self.host_work
            .as_deref()
            .filter(|att| self.host.attachment_principal(att) == Some(wire::HOST_WORK_PRINCIPAL))
    }

    /// One of the runtime's internal attachments (`local`'s, `host-work`'s):
    /// nothing addressed to it leaves the host.
    fn internal(&self, attachment: &str) -> bool {
        !attachment.is_empty()
            && (attachment == self.local_attachment()
                || self.host_work.as_deref() == Some(attachment))
    }

    pub(super) fn local_attachment(&self) -> &str {
        self.local.as_ref().map_or("", |(attachment, _)| attachment)
    }

    /// `local` still has the authority of a verified host: paired, a pinned
    /// device list (so r8 is refused) that is neither frozen nor faulted, a
    /// usable session journal.
    /// Without it `sync_local` fences `local`. A new host identity, an
    /// unpairing or a device list that went unusable is a real change of
    /// authority; a plain session-journal halt fences `local` in memory
    /// only, a pause for its tasks (`local_halted`: they wait, and the
    /// restart that ends the halt brings back its durable control state).
    /// The switches in `runtime.toml` are not part of it (`collab_paused`).
    pub(super) fn local_authorized(&self) -> bool {
        self.host.context().account_id != UNPAIRED
            && self.host.refuses_r8()
            && !self.host.journal_halted()
            && self.membership_error.is_none()
            && self
                .membership
                .as_ref()
                .is_none_or(|m| !m.is_frozen() && m.faulted().is_none() && m.held().is_none())
    }

    /// Local work may dispatch now: authorized, and not paused by
    /// `runtime.toml` (not loading, hosting off) or a failed receipt
    /// database. `[collab] send` only governs new sends (`collab_ready`).
    pub(super) fn local_healthy(&self) -> bool {
        self.hosting_enabled() && self.local_authorized()
    }

    /// Keeps the internal local attachment. A pause leaves it (and `local`'s
    /// control generation) alone, so queued local work and return grants
    /// resume as they were; a lost authority or a new host identity fences
    /// `local` and ends the attachment. A plain session-journal halt does
    /// too, in memory only: `local`'s tasks take it as a pause
    /// (`local_halted`) and wait for the restart.
    fn sync_local(&mut self, cx: &mut Cx) {
        let context = self.host.context();
        let identity = Identity {
            account_id: context.account_id.clone(),
            atem_device_id: context.atem_device_id.clone(),
            host_trust_gen: context.host_trust_gen,
        };
        let current = self.local.as_ref().is_some_and(|(att, bound)| {
            *bound == identity && self.host.attachment_principal(att) == Some("local")
        });
        if current && self.local_authorized() {
            return;
        }
        if let Some((old, _)) = self.local.take() {
            let effects = self.host.fence_principal("local", 0);
            self.exec(effects, cx);
            let effects = self.host.disconnect(&old);
            self.exec(effects, cx);
        }
        if !self.local_healthy() {
            return;
        }
        let attachment = uuid::Uuid::new_v4().to_string();
        let attach = Attach {
            client: "atem-internal-local".into(),
            principal: "local".into(),
            attachment_gen: attachment.clone(),
            permissions: vec![Permission::View, Permission::Control],
            client_kind: ClientKind::Native,
            authorization_ms: atem_client::canonical::MAX_SAFE_INTEGER
                .saturating_sub(self.clock.now()),
        };
        if let Ok(effects) = self.host.connect(attach) {
            self.local = Some((attachment.clone(), identity));
            self.exec(effects, cx);
            if self.host.welcome_r9(&attachment, self.clock.now()).is_err() {
                self.local = None;
                let effects = self.host.disconnect(&attachment);
                self.exec(effects, cx);
            }
            let effects = self.host.take_effects();
            self.exec(effects, cx);
        }
    }

    /// Keeps the `host-work` principal's internal attachment (session-v1
    /// R9.14 item 1), only while `host.delegated` is on: made through the
    /// session host's connect and welcome path as `local`'s is, with `view`
    /// and `control`, never over a link. It is new at every start (a new
    /// bridge) and after the session host dropped it (a new identity
    /// restarts the host). Unlike `local`'s it is never fenced: a frozen,
    /// faulted or held device list, or a halted journal, stops delegated
    /// tasks through the start check. A halted journal welcomes nobody, so a
    /// missing one waits for the restart.
    fn sync_host_work(&mut self, cx: &mut Cx) {
        if !self.features.delegated || self.host_work_attachment().is_some() {
            return;
        }
        self.host_work = None;
        if self.host.journal_halted() {
            return;
        }
        let attachment = uuid::Uuid::new_v4().to_string();
        let attach = Attach {
            client: HOST_WORK_CLIENT.into(),
            principal: wire::HOST_WORK_PRINCIPAL.into(),
            attachment_gen: attachment.clone(),
            permissions: vec![Permission::View, Permission::Control],
            client_kind: ClientKind::Native,
            authorization_ms: atem_client::canonical::MAX_SAFE_INTEGER
                .saturating_sub(self.clock.now()),
        };
        match self.host.connect(attach) {
            Ok(effects) => {
                self.exec(effects, cx);
                match self.host.welcome_r9(&attachment, self.clock.now()) {
                    Ok(_) => {
                        self.host_work = Some(attachment);
                        #[cfg(debug_assertions)]
                        if super::test_hooks::host_work_drive_on() {
                            self.install_drive_check();
                        }
                    }
                    Err(code) => {
                        eprintln!(
                            "atem runtime: the host-work attachment was not welcomed ({code:?})"
                        );
                        let effects = self.host.disconnect(&attachment);
                        self.exec(effects, cx);
                    }
                }
                let effects = self.host.take_effects();
                self.exec(effects, cx);
            }
            Err(error) => eprintln!("atem runtime: the host-work attachment was refused: {error}"),
        }
    }

    /// The `host-work` principal's leases (session-v1 R9.14 item 1, design
    /// I.4.2): each lease its attachment holds is renewed on the runtime's
    /// own pass every 5 s (`HOST_WORK_RENEW_MS`; a lease lasts 15 s) while
    /// its turn runs (a request of it on that session is still `accepted`
    /// or `executing`), and released at the first pass after the turn ended.
    /// If the runtime stops, the lease lapses like any other. The effects
    /// (its own replies, which go nowhere, and the viewers' `lease_changed`)
    /// wait in the session host for the pass (`take_effects`).
    pub fn renew_host_work_leases(&mut self) {
        let Some(att) = self.host_work_attachment().map(str::to_string) else {
            return;
        };
        let now = self.clock.now();
        for sid in self.host.leases_of(&att) {
            if self.host.has_open_request(wire::HOST_WORK_PRINCIPAL, &sid) {
                // Last granted or renewed `LEASE_MS - deadline + now` ago.
                let due = self.host.lease_deadline(&sid).is_some_and(|deadline| {
                    now.saturating_add(LEASE_MS - HOST_WORK_RENEW_MS) >= deadline
                });
                if due {
                    let _ = self.host.renew(&att, &sid, now);
                }
            } else {
                let _ = self.host.release(&att, &sid, now);
            }
        }
    }

    // ── Messages ──

    fn receive(&mut self, link_gen: u64, text: &str, cx: &mut Cx) {
        let decoded = wire::decode(text.as_bytes());
        let (hello, hello_revision) = match &decoded {
            Ok(Envelope::Session(m)) => match &m.op {
                wire::Op::Hello { revision, .. } => (Some(m.id.clone()), *revision),
                _ => (None, None),
            },
            _ => (None, None),
        };
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
                if hello.is_some() {
                    log_handshake("refused unauthorized (no attachment on this link)");
                } else {
                    let request = Request::of(&decoded, text);
                    let line = refusal_log::line(&request, "unauthorized", Some("no attachment"));
                    self.log_refusal(link_gen, line);
                }
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
        // `hello` outcomes have their own line (`log_hello`).
        if hello.is_none() {
            let reason = decoded.as_ref().err().map(refusal_log::decode_reason);
            self.refusing = Some((link_gen, Request::of(&decoded, text), reason));
        }
        let effects = self.host.receive_decoded(&attachment, decoded, now);
        let outcome = hello.as_deref().and_then(|id| log_hello(id, &effects));
        self.exec(effects, cx);
        self.refusing = None;
        let wall = self.clock.wall();
        match outcome {
            Some(HelloOutcome::Welcomed) => {
                if let Some(link) = self.link.as_mut() {
                    link.welcomed_at = Some(wall);
                }
                self.last_refusal = None;
            }
            Some(HelloOutcome::Refused(code)) if code == "unsupported_version" => {
                self.last_refusal = Some((hello_revision, wall));
            }
            _ => {}
        }
    }

    /// Writes `line` unless the link's refusal lines are suppressed.
    fn log_refusal(&mut self, link_gen: u64, line: String) {
        let now = self.clock.now();
        refusal_log::write(self.refusal_log.record(link_gen, now, line));
    }

    /// An error reply (`code`) to the request being handled: logged once
    /// per reply, never with its content.
    fn refused(&mut self, code: &str) {
        let Some((link_gen, request, reason)) = self.refusing.clone() else {
            return;
        };
        let line = refusal_log::line(&request, code, reason.as_deref());
        self.log_refusal(link_gen, line);
    }

    /// Refusals the App answered itself (oversize, a full inbox).
    fn app_refusals(&mut self, hosted: &mut Option<crate::app::hosted::Hosted>) {
        let refused = hosted
            .as_mut()
            .map(|h| std::mem::take(&mut h.refused))
            .unwrap_or_default();
        for (link_gen, line) in refused {
            self.log_refusal(link_gen, line);
        }
        let now = self.clock.now();
        refusal_log::write(self.refusal_log.flush(now));
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
        if self.internal(attachment) {
            return;
        }
        if self.r9.owns(attachment) {
            let host_id = self.host.context().atem_device_id.clone();
            self.r9.deliver(
                attachment,
                message,
                &self.projects,
                &host_id,
                host_now().mono_ms,
            );
            return;
        }
        if !self.current(attachment) {
            return;
        }
        if self.refusing.is_some()
            && let Some(code) = error_code(message)
        {
            self.refused(&code);
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

    fn send_chat(&mut self, attachment: &str, env: ChatEnvelope, cx: &mut Cx) {
        if self.internal(attachment) {
            return;
        }
        if env.op == "error"
            && let Some(code) = env.body.get("code").and_then(Value::as_str)
        {
            self.refused(code);
        }
        let sid = env.agent_id.clone();
        let mut text = serde_json::to_string(&AstationMessage::AgentChat(env))
            .expect("chat envelopes serialize");
        // The live framing tags are for `control` only (`prompt_tags`): the
        // same-length placeholder keeps every count and position.
        // Only a session the broker has is read (an envelope's `agentId` can
        // be a refused request's raw text, never a path).
        if !self.host.attachment_can(attachment, Permission::Control) {
            if let Some(state) = self.dir.parent()
                && SessionId::parse(&sid).is_some_and(|id| cx.sessions.contains_key(&id))
            {
                self.prompt_tags.load(state, &sid);
            }
            if let Some(redacted) = self.prompt_tags.redact(&sid, &text) {
                text = redacted;
            }
        }
        if self.r9.owns(attachment) {
            let host_id = self.host.context().atem_device_id.clone();
            self.r9.deliver_family(
                attachment,
                &sid,
                &text,
                &self.projects,
                &host_id,
                host_now().mono_ms,
            );
            return;
        }
        if !self.current(attachment) {
            return;
        }
        let _ = cx.client.try_send_wire(text, false);
    }

    // ── Effects ──

    fn exec(&mut self, effects: Vec<Effect>, cx: &mut Cx) {
        for effect in effects {
            match effect {
                Effect::Send {
                    attachment,
                    mut message,
                } => {
                    crate::session_protocol::host::fill_results(&mut message, |target, result| {
                        session_of(cx, &target.session_id)
                            .filter(|s| s.chat.generation() == target.process_gen)
                            .map(|s| {
                                history::turn_replies(
                                    &s.chat,
                                    &result.turn_id,
                                    &result.user_message_id,
                                )
                            })
                    });
                    self.send(&attachment, &message, cx)
                }
                // A fenced attachment of this link's client: already gone.
                // The host closed the link's own attachment without a reply
                // (r8 §I.4: a refusal it couldn't record): the link drops at
                // the end of the pass, so the client treats the request's
                // delivery as uncertain. Other attachments it closes are
                // already gone from the link.
                Effect::Close { attachment } => {
                    if !attachment.is_empty() && attachment == self.local_attachment() {
                        self.local = None;
                        continue;
                    }
                    if self.host_work.as_deref() == Some(attachment.as_str()) {
                        self.host_work = None;
                        continue;
                    }
                    if self.r9.owns(&attachment) {
                        self.r9.close_attachment(&attachment, host_now().mono_ms);
                        self.forget_r9(&attachment);
                    } else if self.current(&attachment) && self.host.refuses_r8() {
                        // With a device list the link is the r9 clients'
                        // transport: an r8 fence (a freeze fences every
                        // remote principal) never drops it. Its unwelcomed
                        // attachment goes; the next pass makes a new one.
                        let want = self.considered;
                        self.link = None;
                        self.considered = None;
                        self.sync_link(want, cx);
                    } else if self.current(&attachment) {
                        self.close_link = true;
                    }
                }
                // A second `hello` on the link: the link's attachment is now
                // `new`; what belonged to `old` goes (the host fenced it).
                Effect::Replaced { old, new } => {
                    if let Some(link) = self.link.as_mut().filter(|l| l.attachment == old) {
                        link.attachment = new;
                        self.forget_attachment(&old);
                    }
                }
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
                // R9.14 items 5, 6: host-work's prompt, with the turn it
                // started, is decided from the adopted worker's chat.
                Effect::Reconcile {
                    request_id,
                    target,
                    kind: ReceiptKind::Prompt,
                    turn: Some(turn),
                } => {
                    let reconciling = Reconciling {
                        sid: target.session_id,
                        process_gen: target.process_gen,
                        turn,
                        since: self.clock.now(),
                    };
                    self.reconciling.insert(request_id, reconciling);
                    self.reconcile_host_work(cx);
                }
                Effect::Reconcile { request_id, .. } => {
                    // A broker restart can't tell what an executing request
                    // did (a host-work prompt without its turn too: fail
                    // closed).
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
                // R9.14 item 5: as local input, under the worker's epoch
                // raised first (another controller's queued bytes are
                // dropped) and with no lease deadline.
                Effect::HostInterrupt {
                    session_id,
                    request_id,
                } => {
                    self.sync_epoch(&session_id, cx);
                    let written = session_of(cx, &session_id)
                        .map(|s| s.write_tagged(INTERRUPT_KEY, WriteTag::Host, None));
                    match written {
                        Some(Ok(seq)) => {
                            #[cfg(debug_assertions)]
                            {
                                self.host_interrupt_writes += 1;
                            }
                            self.pending
                                .insert((session_id, seq), Pending::HostInterrupt(request_id));
                        }
                        // Nothing reached the worker.
                        _ => self.interrupt_reported(request_id, InterruptReport::NoEffect),
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

    // ── Interrupt with host authority (session-v1 R9.14 item 5) ──
    // Host-work's interrupt intents carry their decisions out through these
    // (`delegated/interrupts.rs`; design I.5.7), as the drive hook does.

    /// Interrupts the turn of host-work's attempt `request_id` on `sid`
    /// with the host's own authority (`SessionHost::host_interrupt`, given
    /// the chat's half of the turn check, `running_request`), in one step:
    /// the turn check, the input epoch and the revocation of another
    /// controller's lease (`revoked`), and the interrupt key, written as
    /// local input is (under the worker's new epoch, no lease deadline).
    /// Everything is performed here. Receipt-less: the attempt's prompt
    /// receipt completes `interrupted` with its turn. The write's outcome
    /// comes once in `host_interrupt_reports`; while it is outstanding,
    /// this runs only the revoke-only step (`Revoked`), so one attempt never
    /// has two writes in flight. Run it after the pass's `advance`.
    fn host_interrupt(&mut self, sid: &str, request_id: &str, cx: &mut Cx) -> Interrupted {
        if self.host_interrupt_outstanding(sid, request_id) {
            return self.host_interrupt_revoke_lease(sid, request_id, cx);
        }
        let running = running_request(cx, sid);
        match self
            .host
            .host_interrupt(sid, request_id, running.as_deref())
        {
            HostInterrupt::Written(effects) => {
                self.exec(effects, cx);
                Interrupted::Written
            }
            refused => Interrupted::Refused(refused),
        }
    }

    /// A host interrupt write for `request_id` on `sid` waits for the
    /// worker's answer (its report hasn't come).
    pub fn host_interrupt_outstanding(&self, sid: &str, request_id: &str) -> bool {
        self.pending.iter().any(|((s, _), p)| {
            s == sid && matches!(p, Pending::HostInterrupt(r) if r == request_id)
        })
    }

    /// Item 5's later passes once the interrupt was delivered: the same
    /// turn check, then only another controller's lease revoked (the
    /// worker's epoch raised, so its queued bytes are dropped); nothing
    /// written. Performed here, as `host_interrupt`.
    fn host_interrupt_revoke_lease(
        &mut self,
        sid: &str,
        request_id: &str,
        cx: &mut Cx,
    ) -> Interrupted {
        let running = running_request(cx, sid);
        match self
            .host
            .host_interrupt_revoke_lease(sid, request_id, running.as_deref())
        {
            HostInterrupt::Revoked(effects) => {
                self.exec(effects, cx);
                self.sync_epoch(sid, cx);
                Interrupted::Revoked
            }
            refused => Interrupted::Refused(refused),
        }
    }

    /// Host-work's prompt `request_id`, `executing` at the start, still
    /// waits for its adopted worker's chat to be reconciled (R9.14 items 5,
    /// 6; `SessionHost::recover` has the order at a start). Until then its
    /// turn check refuses (`NotCurrentTurn`: no turn state yet), which says
    /// nothing of the turn, so an interrupt intent of it stays pending
    /// (`intents::AttemptNow::Reconciling`, design I.5.7).
    pub fn host_work_reconciling(&self, request_id: &str) -> bool {
        self.reconciling.contains_key(request_id)
    }

    /// Host-work's prompts `executing` at the start (R9.14 items 5, 6; the
    /// session host's `Reconcile` with their turn), each decided by the
    /// session host's one table (`reconcile_turn`, which the fixtures' fake
    /// runtime reads too) from its adopted worker's chat, once that arrived
    /// (`BrokerSession::chat_synced`), at this pass or a later one, and
    /// `RECONCILE_MS` after the recovery at the latest: a turn still
    /// running stays `executing`, the restored chat's current turn rebound
    /// to it (`ChatSession::rebind_turn`), so the turn check
    /// (`running_request`) and the turn's end (`chat_outs`) find it again;
    /// a turn that ended completes with its outcome when known, else
    /// `outcome_unknown`; a process that is gone is `outcome_unknown`
    /// (`agent exited`), and so is a chat without turn state, one showing
    /// another turn, or one that never arrived (fail closed).
    fn reconcile_host_work(&mut self, cx: &mut Cx) {
        let now = self.clock.now();
        let ids: Vec<String> = self.reconciling.keys().cloned().collect();
        for request_id in ids {
            let executing = self
                .host
                .receipt(&request_id)
                .is_some_and(|r| r.state == ReceiptState::Executing);
            if !executing {
                // Settled meanwhile (its process ended, its session went).
                self.reconciling.remove(&request_id);
                continue;
            }
            let r = &self.reconciling[&request_id];
            let expired = now >= r.since.saturating_add(RECONCILE_MS);
            match reconciled(session_of(cx, &r.sid).map(|s| &*s), r, expired) {
                Reconciled::Wait => {}
                Reconciled::Running => {
                    let r = self.reconciling.remove(&request_id).unwrap();
                    let rebound = session_of(cx, &r.sid).is_some_and(|s| {
                        s.chat
                            .rebind_turn(&r.turn.turn_id, &request_id, &r.turn.user_message_id)
                    });
                    debug_assert!(rebound, "decided from the same chat");
                    self.prompts.insert(request_id, r.sid);
                }
                Reconciled::Report(report) => {
                    self.reconciling.remove(&request_id);
                    let effects = self.host.dispatch_report(&request_id, report);
                    self.exec(effects, cx);
                }
            }
        }
    }

    // ── The drive hook (debug builds, `ATEM_TEST_HOST_WORK_DRIVE`) ──
    // The delegated fixtures play host-work's side (session-v1 R9.14)
    // through these, as its dispatcher and its interrupt intents do.

    /// Host-work's start check answers what the drive hook last said
    /// (`verdict.json`; `go` at each runtime start).
    #[cfg(debug_assertions)]
    fn install_drive_check(&mut self) {
        self.host
            .set_start_check(Box::new(DriveCheck(self.drive_go.clone())));
    }

    /// The drive hook's pass: each write's outcome since the last pass,
    /// then its commands, once host-work's attachment exists (until then
    /// they wait in their directory).
    #[cfg(debug_assertions)]
    fn drive_pass(&mut self, cx: &mut Cx) {
        use super::test_hooks;
        if !test_hooks::host_work_drive_on() {
            // Nobody reads the copy: kept bounded.
            self.drive_interrupt_reports.clear();
            return;
        }
        for line in self.drive_reports() {
            test_hooks::host_work_driven(&line);
        }
        if self.host_work_attachment().is_none() {
            return;
        }
        for command in test_hooks::host_work_drive() {
            let line = self.drive(command, cx);
            test_hooks::host_work_driven(&line);
        }
    }

    /// Performs one drive command; its result line.
    #[cfg(debug_assertions)]
    fn drive(&mut self, command: super::test_hooks::DriveCommand, cx: &mut Cx) -> Value {
        use super::test_hooks::DriveAction;
        let mut line = json!({"file": command.file});
        let result = match command.action {
            DriveAction::Verdict(go) => {
                self.drive_go.store(go, Ordering::SeqCst);
                json!({"verdict": if go { "go" } else { "withdraw" }})
            }
            DriveAction::Submit(a) => self.drive_submit(&a, cx),
            DriveAction::Withdraw(a) => match self.drive_immutable(&a) {
                Some((rid, immutable)) => {
                    let withdrawal = self.host.withdraw(&rid, &immutable);
                    let effects = self.host.take_effects();
                    self.exec(effects, cx);
                    json!({"withdrawal": withdrawal.as_str()})
                }
                None => json!({"error": "unknown session"}),
            },
            DriveAction::Interrupt {
                session_id,
                request_id,
                revoke_only,
            } => {
                // After the session host's `advance`, as `host_interrupt`
                // asks (PR 5 review M5).
                let effects = self.host.advance(self.clock.now());
                self.exec(effects, cx);
                let outcome = if revoke_only {
                    self.host_interrupt_revoke_lease(&session_id, &request_id, cx)
                } else {
                    self.host_interrupt(&session_id, &request_id, cx)
                };
                let word = match &outcome {
                    Interrupted::Written => "written",
                    Interrupted::Revoked => "revoked",
                    Interrupted::Refused(refused) => refused.as_str(),
                };
                json!({"interrupt": word})
            }
            DriveAction::Unreadable(why) => json!({"error": why}),
        };
        line.as_object_mut()
            .unwrap()
            .extend(result.as_object().unwrap().clone());
        line
    }

    /// The attempt's request id and its immutable values (§6): the
    /// session's current target, the digest of its prompt, its provenance.
    #[cfg(debug_assertions)]
    fn drive_immutable(
        &self,
        a: &super::test_hooks::DriveAttempt,
    ) -> Option<(String, crate::session_protocol::host::Immutable)> {
        let ctx = self.host.context();
        let target = wire::Target {
            account_id: ctx.account_id.clone(),
            atem_device_id: ctx.atem_device_id.clone(),
            host_trust_gen: ctx.host_trust_gen,
            session_id: a.session_id.clone(),
            process_gen: self.host.descriptor_of(&a.session_id)?.process_gen,
        };
        let payload_digest =
            crate::session_protocol::canonical::payload_digest(&json!({"text": a.text})).ok()?;
        let provenance = crate::session_protocol::host::Provenance {
            task_id: a.task_id.clone(),
            sender: a.sender.clone(),
        };
        Some((
            a.request_id.clone(),
            crate::session_protocol::host::Immutable {
                target,
                payload_digest,
                provenance,
            },
        ))
    }

    /// Host-work submits the attempt's prompt on its internal attachment,
    /// acquiring the lease, and the effects are performed (its dispatch
    /// pastes the prompt, so the chat's acceptance journals its turn): the
    /// refusal host-work heard, else its receipt after the step.
    #[cfg(debug_assertions)]
    fn drive_submit(&mut self, a: &super::test_hooks::DriveAttempt, cx: &mut Cx) -> Value {
        let Some(att) = self.host_work_attachment().map(str::to_string) else {
            return json!({"error": "no host-work attachment"});
        };
        let Some((rid, immutable)) = self.drive_immutable(a) else {
            return json!({"error": "unknown session"});
        };
        let effects = self.host.advance(self.clock.now());
        self.exec(effects, cx);
        let id = uuid::Uuid::new_v4().to_string();
        let data = json!({"v": 1, "op": "submit", "id": id,
            "binding": {"target": immutable.target, "attachment_gen": att},
            "request_id": rid, "kind": "prompt", "payload": {"text": a.text},
            "acquire": true});
        let effects = self.host.submit_host_work(&att, data, immutable.provenance);
        let refused = effects.iter().find_map(|e| match e {
            Effect::Send {
                attachment,
                message: Envelope::Session(m),
            } if *attachment == att && m.re.as_deref() == Some(id.as_str()) => match &m.op {
                wire::Op::Error { code, detail, .. } => {
                    let mut r = json!({"code": code});
                    if let Some(d) = detail {
                        r["detail"] = json!(d);
                    }
                    Some(r)
                }
                _ => None,
            },
            _ => None,
        });
        self.exec(effects, cx);
        if let Some(refused) = refused {
            return refused;
        }
        // The receipt after the step (a listed request's too, in the run).
        match self.host.receipt(&rid) {
            Some(r) => {
                let mut out = json!({"state": r.state});
                if let Some(d) = r.detail {
                    out["detail"] = json!(d);
                }
                out
            }
            None => json!({"error": "no receipt"}),
        }
    }

    /// The outcomes of host interrupt writes since the last call, as the
    /// drive hook reports them: from its own copy, never the stream host-
    /// work's intents read (Task 16b review m7).
    #[cfg(debug_assertions)]
    fn drive_reports(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.drive_interrupt_reports)
            .into_iter()
            .map(|(request_id, report)| {
                let outcome = match report {
                    InterruptReport::Ok => "ok",
                    InterruptReport::Consumed => "consumed",
                    InterruptReport::Dropped => "dropped",
                    InterruptReport::NoEffect => "no_effect",
                    InterruptReport::ErrorAfterQueue => "error_after_queue",
                };
                json!({"report": request_id, "outcome": outcome})
            })
            .collect()
    }

    /// What became of the interrupts written with host authority since the
    /// last call: (attempt's request id, report), each write's once. Host-
    /// work's intents take them every scheduling pass.
    pub fn host_interrupt_reports(&mut self) -> Vec<(String, InterruptReport)> {
        std::mem::take(&mut self.interrupt_reports)
    }

    /// A host interrupt write's outcome, for host-work (and, in debug
    /// builds, the drive hook's own copy).
    fn interrupt_reported(&mut self, request_id: String, report: InterruptReport) {
        #[cfg(debug_assertions)]
        self.drive_interrupt_reports
            .push((request_id.clone(), report));
        self.interrupt_reports.push((request_id, report));
    }

    /// `sid`'s process ended or the session went: its host interrupt
    /// writes get no answer, and there is nothing left to interrupt
    /// (`NoEffect`).
    fn host_interrupts_unanswered(&mut self, sid: &str) {
        let keys: Vec<(String, u64)> = self
            .pending
            .iter()
            .filter(|((s, _), p)| s == sid && matches!(p, Pending::HostInterrupt(_)))
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            if let Some(Pending::HostInterrupt(request_id)) = self.pending.remove(&key) {
                self.interrupt_reported(request_id, InterruptReport::NoEffect);
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
                    let detail = match &session.chat_reason {
                        Some(reason) => format!("{NOT_AVAILABLE}: {reason}"),
                        None => format!("{NOT_AVAILABLE}; use the terminal"),
                    };
                    return Some(DispatchReport::Refused { detail });
                }
                let generation = session.chat.generation().to_string();
                let input_count = session.input_count;
                let text =
                    match session
                        .chat
                        .submit(request_id, &generation, text, input_count, false)
                    {
                        Ok(text) => text,
                        // Why (the agent is busy, Codex before its first
                        // prompt, ...) goes to the submitter.
                        Err(outs) => {
                            let detail = outs.iter().find_map(|o| match o {
                                Out::Error { text, .. } => Some(text.clone()),
                                _ => None,
                            });
                            return Some(match detail {
                                Some(detail) => DispatchReport::Refused { detail },
                                None => DispatchReport::FailedNoEffect,
                            });
                        }
                    };
                let sent_ms = wall_ms() as i64;
                match session.paste(&text, not_after) {
                    Ok(seq) => {
                        session
                            .chat
                            .mark_pasted(request_id, Instant::now(), sent_ms);
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
                // Esc only while a turn is known to run: without chat
                // there is no turn state, and in `ready` or `unknown` (Codex
                // before its first prompt: Esc on its startup trust dialog
                // quits it) nothing is written.
                if !session.chat_v1 {
                    return Some(DispatchReport::Refused {
                        detail: NO_TURN_STATE.into(),
                    });
                }
                if !turn_known_to_run(session) {
                    return Some(DispatchReport::Completed {
                        detail: Some(NO_TURN.into()),
                        turn_id: None,
                        user_message_id: None,
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
            // The worker owns the rules; its answer completes it.
            ReceiptKind::ApprovalRuleRevoke => {
                let rule_id = payload.get("rule_id").and_then(Value::as_str).unwrap_or("");
                match session.revoke_approval_rule(rule_id) {
                    Ok(()) => {
                        self.revokes
                            .insert(request_id.into(), (sid.into(), rule_id.into()));
                        None
                    }
                    Err(_) => Some(DispatchReport::FailedNoEffect),
                }
            }
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
            self.projects.forget(&sid);
            self.project_unread.remove(&sid);
            self.approvals.retain(|_, a| a.sid != sid);
            let registered = self.per.remove(&sid).is_some_and(|p| p.registered);
            if registered {
                let effects = self.host.remove_session(&sid);
                self.exec(effects, cx);
            }
            self.end_conversations(&sid, CloseReason::Restarted, cx);
            self.streams.retain(|(_, s), _| s != &sid);
            self.interrupts.remove(&sid);
            self.host_interrupts_unanswered(&sid);
            self.revokes.retain(|_, (s, _)| s != &sid);
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
        // Its launch project, as recorded at launch (§R9.6): the worker
        // keeps it in its record (read when the session was added, and at
        // the next passes until it is there).
        self.project_unread.insert(sid.clone(), Instant::now());
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
            // Claude (its chat adapter, or why it is off, says the rest);
            // Codex only with a chat adapter (Atem's Codex hooks on).
            chat: session.provider == Provider::Claude.as_str() || session.chat_offered,
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
                // Its session rules (an adopted worker's are unconfirmed
                // until `rules_reported` accepts them), which it may have
                // sent before this.
                if let Some(session) = cx.sessions.get(id) {
                    let _ = session.request_approval_rules();
                }
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
            self.host_interrupts_unanswered(sid);
            self.pending.retain(|(s, _), _| s != sid);
            self.prompts.retain(|_, s| s != sid);
            self.revokes.retain(|_, (s, _)| s != sid);
            self.exec(effects, cx);
            return;
        }
        if state == BrokerState::Running && per.activity != Some(activity) {
            per.activity = Some(activity);
            if let Ok(effects) =
                self.host
                    .set_activity(sid, host_activity(activity), host_now().wall_ms)
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
        if !self.reachable(attachment) {
            return;
        }
        let message = TerminalMessage::Written {
            terminal_id: sid.into(),
            generation: generation.into(),
            stream_id: stream_id.into(),
            sequence,
            error,
        };
        self.queue_terminal(attachment, sid, message, cx);
    }

    fn queue_terminal(
        &mut self,
        attachment: &str,
        sid: &str,
        message: TerminalMessage,
        cx: &mut Cx,
    ) {
        let text = serde_json::to_string(&AstationMessage::Terminal(message.into()))
            .expect("terminal messages serialize");
        if self.r9.owns(attachment) {
            let host_id = self.host.context().atem_device_id.clone();
            self.r9.deliver_family(
                attachment,
                sid,
                &text,
                &self.projects,
                &host_id,
                host_now().mono_ms,
            );
            return;
        }
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
                // It only handed a waiting Codex approval to Codex's dialog,
                // or Codex's dialog was open (the worker says which).
                let failure = if result.consumed {
                    Some(DispatchReport::Refused {
                        detail: result
                            .error
                            .clone()
                            .unwrap_or_else(|| super::worker_protocol::APPROVAL_HANDED.into()),
                    })
                } else {
                    failure
                };
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
            Pending::HostInterrupt(request_id) => {
                self.interrupt_reported(request_id, interrupt_report(&result));
            }
            Pending::Interrupt(request_id) => {
                let failure = if result.consumed {
                    Some(DispatchReport::Refused {
                        detail: INTERRUPT_HANDED.into(),
                    })
                } else {
                    failure
                };
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
                ApprovalEvent::RuleNotKept { request_id } => {
                    let Some(id) = self.approval_of(sid, &request_id) else {
                        continue;
                    };
                    eprintln!(
                        "atem runtime: {sid}: a session rule was not kept (the session holds 32)"
                    );
                    if let Some(card) = self.approvals.get_mut(&id).and_then(|a| a.card.as_mut()) {
                        card.note = Some(RULE_NOT_KEPT.into());
                    }
                    self.card_state(&id, ApprovalCardState::Allowed, cx);
                }
                ApprovalEvent::AutoAllowed {
                    request_id: _,
                    rule_id,
                    tool,
                    summary,
                } => self.auto_allowed(sid, rule_id, tool, summary, cx),
                ApprovalEvent::Rules(rules) => self.rules_reported(sid, rules, cx),
                ApprovalEvent::RuleRevoked { rule_id, ok } => {
                    let rid = self
                        .revokes
                        .iter()
                        .find(|(_, (s, r))| s == sid && *r == rule_id)
                        .map(|(rid, _)| rid.clone());
                    let Some(rid) = rid else {
                        continue;
                    };
                    self.revokes.remove(&rid);
                    eprintln!("{}", rule_revoked_line(sid, &rule_id, ok));
                    let report = if ok {
                        DispatchReport::Completed {
                            detail: None,
                            turn_id: None,
                            user_message_id: None,
                        }
                    } else {
                        DispatchReport::Refused {
                            detail: RULE_GONE.into(),
                        }
                    };
                    let effects = self.host.dispatch_report(&rid, report);
                    self.exec(effects, cx);
                }
            }
        }
    }

    /// A request the worker allowed by a session rule: one runtime.log line
    /// (the rule and the tool, never the command) and an `auto_allowed`
    /// card in the session's conversations. No approval, push or lease.
    fn auto_allowed(
        &mut self,
        sid: &str,
        rule_id: String,
        tool: String,
        summary: String,
        cx: &mut Cx,
    ) {
        eprintln!("{}", auto_allowed_line(sid, &tool, &rule_id));
        let chat = self
            .host
            .descriptor_of(sid)
            .is_some_and(|d| d.capabilities.iter().any(|c| c == "chat-v1"));
        if !chat {
            return;
        }
        let card = ApprovalCard {
            id: "approval".into(),
            approval_id: uuid::Uuid::new_v4().to_string(),
            tool,
            summary,
            always_rules: Vec::new(),
            state: ApprovalCardState::AutoAllowed,
            rule_id: Some(rule_id),
            note: None,
            reason: None,
        };
        let Some(session) = session_of(cx, sid) else {
            return;
        };
        let out = session.approval_card(card, wall_ms() as i64);
        self.broadcast_to(sid, &out, None, true, cx);
    }

    /// A worker's session rules. Unconfirmed ones (an adopted worker's)
    /// are accepted only when granted under the host's current account,
    /// device and trust generation: the worker confirms those and drops the
    /// others, then reports again. Confirmed rules under the current
    /// identity go to the host (session-v1 `approval_rules`) and to the
    /// session's conversations with `control` (chat-v1 `rules`) when they
    /// changed.
    fn rules_reported(&mut self, sid: &str, held: Vec<HeldRule>, cx: &mut Cx) {
        let Some(session) = session_of(cx, sid) else {
            return;
        };
        let process_gen = session.process_gen.clone();
        // Rules a worker reports before its session is registered with the
        // host (e.g. right after adoption) are dropped here: `register`
        // asks the worker for them again once it is.
        if !self.per.get(sid).is_some_and(|p| p.registered) {
            return;
        }
        let grant = self.rule_grant();
        if held.iter().any(|r| !r.confirmed) {
            let accepted = held
                .iter()
                .filter(|r| !r.confirmed && r.granted_under == grant)
                .map(|r| r.rule.rule_id.clone())
                .collect();
            if let Err(error) = session.confirm_approval_rules(accepted) {
                eprintln!("atem runtime: {sid}: session rules not confirmed: {error}");
            }
            // Its next report lists what it kept.
            return;
        }
        // A confirmed rule under another identity is being dropped by a
        // `revoke_all_approval_rules` already on its way.
        let rules: Vec<wire::AlwaysRule> = held
            .into_iter()
            .filter(|r| r.granted_under == grant)
            .map(|r| r.rule)
            .collect();
        if self.host.approval_rules(sid) == rules {
            return;
        }
        match self.host.set_approval_rules(sid, &process_gen, rules) {
            Ok(effects) => self.exec(effects, cx),
            Err(error) => {
                eprintln!("atem runtime: {sid}: session rules not shown: {error}");
                return;
            }
        }
        let rules = self.host.approval_rules(sid);
        let ids: Vec<(String, String)> = self
            .chats
            .get(sid)
            .map(|c| {
                c.map
                    .iter()
                    .filter(|(_, c)| self.reachable(&c.attachment))
                    .filter(|(_, c)| self.shows_cards(&c.attachment))
                    .map(|(id, c)| (id.clone(), c.attachment.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for (id, att) in ids {
            if let Some((generation, sequence)) = self.next_head(sid, &id, cx) {
                self.send_chat(
                    &att,
                    chat_wire::rules(&id, sid, &generation, sequence, &rules),
                    cx,
                );
            }
        }
    }

    /// Handed-off answers the host finished without the worker's report
    /// (the 630 s deadline: `outcome_unknown`): the card closes and the
    /// approval is forgotten.
    fn finished_hand_offs(&mut self, cx: &mut Cx) {
        use crate::session_protocol::wire::ReceiptState;
        let finished: Vec<(String, ReceiptState)> = self
            .approvals
            .iter()
            .filter_map(|(id, a)| {
                let state = self.host.receipt(a.receipt.as_ref()?)?.state;
                matches!(
                    state,
                    ReceiptState::Completed | ReceiptState::Rejected | ReceiptState::OutcomeUnknown
                )
                .then(|| (id.clone(), state))
            })
            .collect();
        for (id, state) in finished {
            if state != ReceiptState::Completed {
                self.card_state(&id, ApprovalCardState::Closed, cx);
            }
            self.approvals.remove(&id);
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
                // §R9.9: created_at (the card's and the hints') on the host
                // clock, which moves while the machine sleeps.
                let wall = host_now().wall_ms;
                let (opened, effects) =
                    self.host
                        .open_approval_at(sid, &process_gen, info, now, wall);
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
        // The approval closed `answered_remote` in the host's same step.
        self.card_reason(approval_id, ApprovalCloseReason::AnsweredRemote);
        let worker_id = self.approvals.get(approval_id).map(|a| a.worker_id.clone());
        let sent = match (worker_id, session_of(cx, sid)) {
            (Some(worker_id), Some(session)) => session
                .approval_decision(
                    &worker_id,
                    decision,
                    rule_id.map(|r| (r, self.rule_grant())),
                    message,
                )
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
                rule_id: None,
                note: None,
                reason: None,
            };
            self.card(
                &request.approval_id,
                Some(card),
                ApprovalCardState::Pending,
                cx,
            );
        }
        if self.host.refuses_r8() {
            // r9 (§R9.9): never the tool or summary in clear to the relay,
            // only hints sealed per control device, signed with the host
            // channel key (`r9::push`).
            let wait_ms = timeout * 1000;
            self.r9_call(|r9, parts| r9.approval_opened(&request, wait_ms, parts));
            return;
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
        let wall = self.clock.wall();
        self.pushes
            .open(&request.approval_id, data, expires_at, wall);
        self.flush_pushes(cx);
    }

    /// No longer pending: the card says how it ended (a remote answer: its
    /// decision, set at the hand-off) and the push is resolved.
    fn approval_resolved(&mut self, approval_id: &str, reason: ApprovalCloseReason, cx: &mut Cx) {
        self.card_reason(approval_id, reason);
        let state = match reason {
            ApprovalCloseReason::AnsweredRemote => None,
            ApprovalCloseReason::AnsweredTerminal => Some(ApprovalCardState::AnsweredTerminal),
            ApprovalCloseReason::TimedOut => Some(ApprovalCardState::Expired),
            _ => Some(ApprovalCardState::Closed),
        };
        if let Some(state) = state {
            self.card_state(approval_id, state, cx);
        }
        // An r9 host sends no clear push at all (not even a resolve of one
        // pushed before its pin; that entry went at the pin): its resolved
        // hint (§R9.9).
        if self.host.refuses_r8() {
            self.r9_call(|r9, parts| r9.approval_resolved(approval_id, reason, parts));
        } else {
            self.pushes.resolve(approval_id, reason);
        }
        self.flush_pushes(cx);
    }

    /// Sends the due push requests over the verified link (`push_queue`).
    fn flush_pushes(&mut self, cx: &mut Cx) {
        let link_up = self.link.is_some();
        let wall = self.clock.wall();
        let client = cx.client;
        self.pushes.flush(link_up, wall, &mut |text| {
            client.try_send_wire(text, false).is_ok()
        });
    }

    /// r8 `approval.card_reason`: the card's final states carry why its
    /// approval closed (the first close; a later card state keeps it).
    fn card_reason(&mut self, approval_id: &str, reason: ApprovalCloseReason) {
        if let Some(card) = self
            .approvals
            .get_mut(approval_id)
            .and_then(|a| a.card.as_mut())
        {
            card.reason.get_or_insert(reason);
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
        let out = session.approval_card(card, wall_ms() as i64);
        self.broadcast_to(&sid, &out, None, true, cx);
    }

    /// The approvals this bridge holds open (tests).
    #[cfg(test)]
    pub(super) fn open_approvals(&self) -> Vec<String> {
        self.approvals.keys().cloned().collect()
    }

    // ── Frames ──

    /// Reads the prompt tags and terminal pauses of every session the broker
    /// has (`prompt_tags`), once each: a restarted broker learns those of
    /// adopted sessions before it serves their chat or frames.
    /// Sessions that are gone are forgotten (their tags are dead: their
    /// turns ended; a pause file left to rewrite goes with its worker's
    /// files), so what is kept follows the broker's sessions.
    fn load_prompt_tags(&mut self, cx: &Cx) {
        let Some(state) = self.dir.parent().map(Path::to_path_buf) else {
            return;
        };
        let known =
            |sid: &str| SessionId::parse(sid).is_some_and(|id| cx.sessions.contains_key(&id));
        self.prompt_tags.retain(known);
        self.pauses_loaded.retain(|sid| known(sid));
        self.pauses_dirty.retain(|sid| known(sid));
        for sid in cx.sessions.keys() {
            self.prompt_tags.load(&state, sid.as_str());
            self.load_pauses(&state, sid.as_str());
        }
    }

    /// Session `sid`'s pause file, once (a pause written before a restart
    /// goes on holding the frames).
    pub(super) fn load_pauses(&mut self, state: &Path, sid: &str) {
        if self.pauses_loaded.insert(sid.to_string()) {
            let pauses = super::prompt_tags::load_pauses(state, sid, &host_now());
            if !pauses.is_empty() {
                self.view_pauses
                    .entry(sid.to_string())
                    .or_default()
                    .extend(pauses);
            }
        }
    }

    /// Holds terminal frames from attachments without `control` while a
    /// framed prompt's turn runs on the session, until `Pause::holds` says
    /// it ended: the session no longer live, the receipt completed or
    /// rejected, or (its outcome unknown: a restart, a prompt the agent
    /// didn't take in time) the chat showing the agent took the prompt and
    /// its turn ended; at the latest the host's bound (a day on the wall
    /// and monotonic clocks; never the task's deadline). Each change is
    /// written to the session's pause file.
    fn view_pause_pass(&mut self, cx: &Cx) {
        use super::prompt_tags::{ChatSigns, TurnSigns};
        self.rewrite_pauses();
        if self.view_pauses.is_empty() {
            return;
        }
        let now = host_now();
        let sessions: Vec<String> = self.view_pauses.keys().cloned().collect();
        for sid in sessions {
            let session = SessionId::parse(&sid).and_then(|id| cx.sessions.get(&id));
            let live = session.is_some_and(|s| s.is_live());
            let pauses = self.view_pauses.remove(&sid).unwrap_or_default();
            let before = pauses.len();
            let holding: Vec<_> = pauses
                .into_iter()
                .filter(|p| {
                    let chat = session.map_or(ChatSigns::Unknown, |s| chat_signs(s, &p.tag));
                    p.holds(
                        TurnSigns {
                            receipt: self.host.receipt(&p.receipt_id).map(|r| r.state),
                            live,
                            chat,
                        },
                        &now,
                    )
                })
                .collect();
            if holding.len() != before {
                self.write_pauses(&sid, &holding);
            }
            if !holding.is_empty() {
                self.view_pauses.insert(sid, holding);
            }
        }
    }

    /// Writes session `sid`'s pauses (none: removes the file). One that
    /// fails leaves the file behind what is held here (an attempt's pause
    /// that was never pasted, a pause that ended): the session is rewritten
    /// from memory at the next pass that can (`rewrite_pauses`).
    pub(super) fn write_pauses(&mut self, sid: &str, pauses: &[super::prompt_tags::Pause]) -> bool {
        let written = self
            .dir
            .parent()
            .ok_or_else(|| std::io::Error::other("no state directory"))
            .and_then(|state| super::prompt_tags::write_pauses(state, sid, pauses));
        match written {
            Ok(()) => {
                self.pauses_dirty.remove(sid);
                true
            }
            Err(error) => {
                if self.pauses_dirty.insert(sid.to_string()) {
                    eprintln!("atem runtime: {sid}: terminal pause not written: {error}");
                }
                false
            }
        }
    }

    /// Rewrites the pause files a write left behind, from memory, at most
    /// once a second.
    fn rewrite_pauses(&mut self) {
        if self.pauses_dirty.is_empty()
            || self
                .pauses_retry_at
                .is_some_and(|at| at > std::time::Instant::now())
        {
            return;
        }
        self.pauses_retry_at = Some(std::time::Instant::now() + std::time::Duration::from_secs(1));
        let dirty: Vec<String> = self.pauses_dirty.iter().cloned().collect();
        for sid in dirty {
            let pauses = self.view_pauses.get(&sid).cloned().unwrap_or_default();
            self.write_pauses(&sid, &pauses);
        }
    }

    /// Whether the stream `key` gets no frames now: its session's framed
    /// prompt is in its turn and the attachment has no `control`. A held
    /// stream drops what it had pending and resumes with a full frame.
    fn frames_held(&mut self, key: &(String, String)) -> bool {
        if !self.view_pauses.contains_key(&key.1)
            || self.host.attachment_can(&key.0, Permission::Control)
        {
            return false;
        }
        if let Some(stream) = self.streams.get_mut(key) {
            stream.hold();
        }
        true
    }

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
            if self.r9.owns(&key.0) {
                self.r9_frames(&key, cx);
                continue;
            }
            if !self.current(&key.0) {
                continue;
            }
            if self.frames_held(&key) {
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
                self.terminal_error(&key.0, &key.1, Some(&stream.stream_id), "busy", &error, cx);
            }
        }
        self.flush_terminal(cx);
        if self.terminal_out.len() > TERMINAL_BACKLOG {
            self.congested(cx);
        }
    }

    /// An r9 channel's stream: frames go into its channel (sealed, bounded
    /// by the channel's queue), held back while the channel has a backlog.
    fn r9_frames(&mut self, key: &(String, String), cx: &mut Cx) {
        if self.r9.backlog(&key.0) > R9_FRAME_BACKLOG || self.frames_held(key) {
            return;
        }
        let Some(session) = session_of(cx, &key.1) else {
            return;
        };
        if !session.synced() {
            return;
        }
        let exit = (session.state != BrokerState::Running).then(|| {
            session
                .exit_status
                .clone()
                .unwrap_or_else(|| "exited".into())
        });
        let Some(stream) = self.streams.get_mut(key) else {
            return;
        };
        match stream.frames(session.screen(), exit.as_deref()) {
            Ok(messages) => {
                let host_id = self.host.context().atem_device_id.clone();
                for message in messages {
                    let text = serde_json::to_string(&AstationMessage::Terminal(message.into()))
                        .expect("terminal messages serialize");
                    self.r9.deliver_family(
                        &key.0,
                        &key.1,
                        &text,
                        &self.projects,
                        &host_id,
                        host_now().mono_ms,
                    );
                }
            }
            Err(error) => {
                if let Some(stream) = self.streams.remove(key) {
                    self.terminal_error(
                        &key.0,
                        &key.1,
                        Some(&stream.stream_id),
                        "busy",
                        &error,
                        cx,
                    );
                }
            }
        }
    }

    /// The terminal transport fell behind: the frames waiting go and every
    /// stream ends (viewers subscribe again); `written` acks and errors stay
    /// queued, in order. r9 channels' streams aren't on that transport.
    fn congested(&mut self, cx: &mut Cx) {
        drop_frames(&mut self.terminal_out);
        let link_streams: Vec<(String, String)> = self
            .streams
            .keys()
            .filter(|(att, _)| !self.r9.owns(att))
            .cloned()
            .collect();
        let streams: Vec<((String, String), FrameStream)> = link_streams
            .into_iter()
            .filter_map(|k| self.streams.remove(&k).map(|s| (k, s)))
            .collect();
        for ((att, sid), stream) in streams {
            self.terminal_error(
                &att,
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
        attachment: &str,
        sid: &str,
        stream_id: Option<&str>,
        code: &str,
        message: &str,
        cx: &mut Cx,
    ) {
        self.refused(code);
        let mut data = json!({
            "v": 1, "op": "error", "terminal_id": sid, "code": code, "message": message,
        });
        if let Some(stream_id) = stream_id {
            data["stream_id"] = Value::String(stream_id.into());
        }
        let text = json!({"type": "terminal", "data": data}).to_string();
        if self.r9.owns(attachment) {
            let host_id = self.host.context().atem_device_id.clone();
            self.r9.deliver_family(
                attachment,
                sid,
                &text,
                &self.projects,
                &host_id,
                host_now().mono_ms,
            );
            return;
        }
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
                        attachment,
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
                if env.op == "history" {
                    self.history(attachment, sid, &env, cx);
                    return;
                }
                match chat_wire::parse_inbound(&env) {
                    Ok(Inbound::Open) => self.open_conversation(attachment, sid, &conversation, cx),
                    Ok(Inbound::Close) => {
                        if let Some(chats) = self.chats.get_mut(sid) {
                            chats.close(&conversation, attachment);
                        }
                    }
                    Ok(
                        Inbound::Submit { .. }
                        | Inbound::Answer { .. }
                        | Inbound::RevokeRule { .. },
                    ) => {}
                    Err(text) => {
                        let env = chat_error(
                            &conversation,
                            sid,
                            None,
                            None,
                            "unsupported_version",
                            &text,
                        );
                        self.send_chat(attachment, env, cx);
                    }
                }
            }
            _ => {}
        }
    }

    fn open_conversation(&mut self, attachment: &str, sid: &str, conversation: &str, cx: &mut Cx) {
        // Approval cards and session rules only for an attachment that may
        // answer them.
        let control = self.shows_cards(attachment);
        let rules = if control {
            self.host.approval_rules(sid)
        } else {
            Vec::new()
        };
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
            self.send_chat(attachment, env, cx);
            return;
        }
        let opening = Opening {
            conversation,
            agent: sid,
            attachment,
            control,
            status: session.chat.status(),
            unavailable: &session.chat_unavailable,
            rules: &rules,
        };
        let envelopes = self.chats.entry(sid.to_string()).or_default().open(
            &session.chat,
            &self.history_key,
            &opening,
        );
        for env in envelopes {
            self.send_chat(attachment, env, cx);
        }
    }

    /// A chat-v1 `history` (r8 §B): a page of the retained history in the
    /// conversation's stream, or an error there.
    fn history(&mut self, attachment: &str, sid: &str, env: &ChatEnvelope, cx: &mut Cx) {
        let control = self.shows_cards(attachment);
        let now_ms = self.clock.now();
        let Some(session) = session_of(cx, sid) else {
            return;
        };
        let data = serde_json::to_value(env).unwrap_or(Value::Null);
        let call = HistoryCall {
            data: &data,
            conversation: &env.conversation_id,
            agent: sid,
            attachment,
            control,
            now_ms,
        };
        let envelopes = self.chats.entry(sid.to_string()).or_default().history(
            &session.chat,
            &self.history_key,
            &call,
        );
        for env in envelopes {
            self.send_chat(attachment, env, cx);
        }
    }

    /// The head of the next event in a conversation (`None` when it isn't open).
    fn next_head(&mut self, sid: &str, conversation: &str, cx: &mut Cx) -> Option<(String, u64)> {
        let generation = session_of(cx, sid)?.chat.generation().to_string();
        let sequence = self.chats.get_mut(sid)?.next_head(conversation)?;
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
        if !self.reachable(attachment) {
            return;
        }
        // A refused removed form (r8 §A) takes no sequence.
        let head = match &reply {
            ChatReply::Error {
                sequenced: false, ..
            } => None,
            _ => self.next_head(sid, conversation, cx),
        };
        let env = match reply {
            ChatReply::Accepted { request_id, lease } => {
                self.submitters
                    .insert(request_id.clone(), (sid.into(), conversation.into()));
                let mut body = Map::new();
                body.insert("requestId".into(), Value::String(request_id));
                if let Some(l) = lease {
                    // r8 §F: the admitting reply of an acquiring Send.
                    body.insert(
                        "lease".into(),
                        json!({"lease_epoch": l.lease_epoch, "ms_left": l.ms_left}),
                    );
                }
                chat_envelope(conversation, sid, "accepted", head, body)
            }
            ChatReply::Complete {
                request_id,
                turn_id,
                interrupted,
            } => {
                self.submitters.remove(&request_id);
                // The receipt's detail keeps the outcome (also after a restart).
                let outcome = if interrupted {
                    crate::chat::adapter::Outcome::Interrupted
                } else {
                    crate::chat::adapter::Outcome::Done
                };
                complete_envelope(conversation, sid, head, request_id, turn_id, outcome)
            }
            ChatReply::Error {
                request_id,
                code,
                text,
                controller,
                page_id,
                ..
            } => {
                if let Some(r) = &request_id {
                    self.submitters.remove(r);
                }
                let mut env =
                    chat_error(conversation, sid, head, request_id.as_deref(), &code, &text);
                if let Some(p) = page_id {
                    env.body.insert("page_id".into(), Value::String(p));
                }
                if let Some(c) = controller {
                    // r8 §F: `lease_held` names the holder.
                    env.body.insert("controller".into(), json!(c));
                }
                env
            }
        };
        self.send_chat(attachment, env, cx);
    }

    /// The chat session's output: to every open conversation, except what
    /// belongs to a request (its submitter hears about it through its
    /// receipt); a turn's end completes the prompt and any interrupt.
    fn chat_outs(&mut self, sid: &str, outs: Vec<Out>, cx: &mut Cx) {
        for out in outs {
            let mut except = None;
            match &out {
                Out::Accepted { request_id } => {
                    // R9.14 items 5, 6: a host-work prompt journals the turn
                    // it started.
                    if self.prompts.contains_key(request_id) {
                        self.turn_started(sid, request_id, cx);
                    }
                    continue;
                }
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
                            let detail = match outcome {
                                crate::chat::adapter::Outcome::Done => DETAIL_TURN_DONE,
                                crate::chat::adapter::Outcome::Interrupted => {
                                    DETAIL_TURN_INTERRUPTED
                                }
                            };
                            // r8 §D: the prompt's user message, journaled
                            // with the turn (ids only).
                            let user_message_id = session_of(cx, sid).and_then(|s| {
                                s.chat.user_message_of(request_id).map(str::to_string)
                            });
                            let report = DispatchReport::Completed {
                                detail: Some(detail.to_string()),
                                turn_id: Some(turn_id.clone()),
                                user_message_id,
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
                // A recovered approval card: only where cards are shown.
                Out::Recovered { message, .. } if is_card(message) => {
                    self.broadcast_to(sid, &out, None, true, cx);
                    continue;
                }
                _ => {}
            }
            self.broadcast(sid, &out, except.as_deref(), cx);
        }
    }

    /// The chat accepted the prompt `request_id` this runtime pasted: for
    /// host-work's (R9.14 items 5, 6), the turn it started and its user
    /// message, as the retained history shows them, are journaled
    /// (`SessionHost::turn_started`; for any other prompt nothing is
    /// written). When the history doesn't show them, nothing is, and a
    /// restart fails the receipt closed.
    fn turn_started(&mut self, sid: &str, request_id: &str, cx: &mut Cx) {
        let turn = session_of(cx, sid)
            .and_then(|s| s.chat.prompt_turn(request_id))
            .map(|(turn_id, user_message_id)| TurnIds {
                turn_id: turn_id.to_string(),
                user_message_id: user_message_id.to_string(),
            });
        if let Some(turn) = turn {
            let _ = self.host.turn_started(request_id, turn);
        }
    }

    fn interrupts_done(&mut self, sid: &str, cx: &mut Cx) {
        for request_id in self.interrupts.remove(sid).unwrap_or_default() {
            let report = DispatchReport::Completed {
                detail: None,
                turn_id: None,
                user_message_id: None,
            };
            let effects = self.host.dispatch_report(&request_id, report);
            self.exec(effects, cx);
        }
    }

    fn broadcast(&mut self, sid: &str, out: &Out, except: Option<&str>, cx: &mut Cx) {
        self.broadcast_to(sid, out, except, false, cx);
    }

    /// `broadcast`; with `control`, only to conversations of attachments
    /// with `control` (approval cards, §6a).
    fn broadcast_to(
        &mut self,
        sid: &str,
        out: &Out,
        except: Option<&str>,
        control: bool,
        cx: &mut Cx,
    ) {
        let ids: Vec<(String, bool, String)> = self
            .chats
            .get(sid)
            .map(|c| {
                c.map
                    .iter()
                    .filter(|(id, c)| Some(id.as_str()) != except && self.reachable(&c.attachment))
                    .map(|(id, c)| {
                        let can = self.shows_cards(&c.attachment);
                        (id.clone(), can, c.attachment.clone())
                    })
                    .filter(|(_, can, _)| !control || *can)
                    .collect()
            })
            .unwrap_or_default();
        for (id, can, att) in ids {
            // A view-only conversation's coverage names no card (r8 §C).
            let own = match out {
                Out::Coverage(_) => {
                    session_of(cx, sid).map(|s| Out::Coverage(history::coverage_for(&s.chat, can)))
                }
                _ => None,
            };
            if let Some((generation, sequence)) = self.next_head(sid, &id, cx) {
                let env =
                    chat_wire::event(&id, sid, &generation, sequence, own.as_ref().unwrap_or(out));
                self.send_chat(&att, env, cx);
            }
        }
    }

    /// Tells every open conversation of `sid` why it ends (`error`, then
    /// `close` with its reason, r8 §C).
    fn end_conversations(&mut self, sid: &str, reason: CloseReason, cx: &mut Cx) {
        let text = close_text(reason);
        let ids: Vec<String> = self
            .chats
            .get(sid)
            .map(|c| c.map.keys().cloned().collect())
            .unwrap_or_default();
        let error = Out::Error {
            text: text.to_string(),
            request_id: None,
        };
        for id in ids {
            let att = self
                .chats
                .get(sid)
                .and_then(|c| c.map.get(&id))
                .map(|c| c.attachment.clone())
                .filter(|a| self.reachable(a));
            if let Some(att) = att {
                if let Some((generation, sequence)) = self.next_head(sid, &id, cx) {
                    self.send_chat(
                        &att,
                        chat_wire::event(&id, sid, &generation, sequence, &error),
                        cx,
                    );
                }
                self.send_chat(&att, chat_wire::close(&id, sid, reason), cx);
            }
        }
        self.chats.remove(sid);
    }

    /// Re-sends the status to each conversation that has not had it for 15 s.
    fn heartbeats(&mut self, cx: &mut Cx) {
        let due: Vec<(String, String, String)> = self
            .chats
            .iter()
            .flat_map(|(sid, chats)| {
                chats
                    .map
                    .iter()
                    .filter(|(_, c)| c.last_heartbeat.elapsed() >= HEARTBEAT)
                    .map(|(id, c)| (sid.clone(), id.clone(), c.attachment.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (sid, id, att) in due {
            let Some(status) = session_of(cx, &sid).map(|s| s.chat.heartbeat()) else {
                continue;
            };
            if let Some(c) = self.chats.get_mut(&sid).and_then(|c| c.map.get_mut(&id)) {
                c.last_heartbeat = Instant::now();
            }
            if let Some((generation, sequence)) = self.next_head(&sid, &id, cx) {
                self.send_chat(
                    &att,
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
/// What the link's attachment may do: `view` and `control` (tests can make
/// it view-only).
fn link_permissions() -> Vec<Permission> {
    #[cfg(test)]
    if VIEW_ONLY_LINK.with(std::cell::Cell::get) {
        return vec![Permission::View];
    }
    vec![Permission::View, Permission::Control]
}

#[cfg(test)]
thread_local! {
    /// Tests: the next link attaches view-only.
    pub(super) static VIEW_ONLY_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The text of the `error` before a `close` with `reason`.
fn close_text(reason: CloseReason) -> &'static str {
    match reason {
        CloseReason::Withdrawn => super::broker::CHAT_WITHDRAWN,
        CloseReason::Switched => super::broker::CHAT_SWITCHED,
        CloseReason::Restarted => RESTARTED,
        CloseReason::Evicted => "a newer conversation replaced this one",
    }
}

/// Tests only: something to run right after a device-list reopen read the
/// files (keyed by the pairing directory, so parallel tests never fire
/// each other's), e.g. a pin's last file landing in that window.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub(super) static AFTER_REOPEN: std::sync::Mutex<
    Vec<(std::path::PathBuf, Box<dyn FnOnce() + Send>)>,
> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn after_reopen(pairing: &crate::paths::PairingPaths) {
    let dir = pairing.dir().to_path_buf();
    let hook = {
        let mut hooks = AFTER_REOPEN.lock().unwrap();
        hooks
            .iter()
            .position(|(d, _)| *d == dir)
            .map(|i| hooks.remove(i).1)
    };
    if let Some(hook) = hook {
        hook();
    }
}

/// The device list for `atem status`, `atem agent list` and the status
/// row (see [`HostBridge::device_list_status`]): `m` open, or `error` why
/// it failed; `clients` the r9 attachments.
pub(crate) fn device_list_status_of(
    m: Option<&MembershipHost>,
    error: Option<&str>,
    clients: usize,
    now: &atem_client::membership::HostNow,
) -> Option<crate::runtime::protocol::DeviceListStatus> {
    use crate::runtime::protocol::{DeviceListStatus, PendingRecoveryStatus};
    const REPAIR: &str = "re-pair this host from a device you trust: atem unpair, then atem pair";
    if let Some(error) = error {
        return Some(DeviceListStatus {
            state: "failed".into(),
            text: format!("failed ({error}); remote access is off"),
            label: Some("Remote off".into()),
            head_seq: None,
            pending_recovery: Vec::new(),
            clients,
            ..Default::default()
        });
    }
    let m = m?;
    let head_seq = Some(m.head().seq);
    let pending: Vec<PendingRecoveryStatus> = m
        .membership()
        .pending_recovery(now)
        .iter()
        .map(|p| {
            let p = atem_client::session::r9::PendingRecovery::of(p);
            PendingRecoveryStatus {
                subject: p.subject,
                action: p.action,
                effective_at: p.effective_at,
            }
        })
        .collect();
    let (state, text, label) = if m.is_frozen() {
        (
            "frozen",
            format!("frozen (conflicting signed history); remote access is paused; {REPAIR}"),
            Some("Remote frozen"),
        )
    } else if let Some(why) = m.faulted() {
        (
            "paused",
            format!(
                "paused (a device-list write failed: {why}); remote access stops until atem runtime restart"
            ),
            Some("Remote paused"),
        )
    } else if let Some(held) = m.held() {
        let text = match held {
            Held::IntentMismatch(_) => format!(
                "held (the recorded device-list write doesn't match the list); remote access is off; {REPAIR}"
            ),
            _ => "held (a device-list write fault was recorded); remote access waits until a managing device (Astation on your Mac or phone) connects to reconcile".to_string(),
        };
        ("held", text, Some("Remote held"))
    } else {
        let n = match clients {
            1 => "1 remote client".to_string(),
            n => format!("{n} remote clients"),
        };
        (
            "open",
            format!("pinned at seq {} ({n})", m.head().seq),
            (!pending.is_empty()).then_some("Recovery pending"),
        )
    };
    // How full the list is (D23), whatever its state.
    let text = format!(
        "{text}; {}",
        crate::session_protocol::membership::capacity_text(&m.membership().capacity())
    );
    Some(DeviceListStatus {
        state: state.into(),
        text,
        label: label.map(str::to_string),
        head_seq,
        pending_recovery: pending,
        clients,
        ..Default::default()
    })
}

/// No profile (tests without one): no project hash is ever known.
struct NoHasher;

impl ProjectHasher for NoHasher {
    fn hash(&self, _: &[(String, String)]) -> anyhow::Result<Vec<String>> {
        anyhow::bail!("no profile")
    }
}

/// The link generation r9 traffic runs on: authenticated by Astation, or
/// routed for r9 only on a host route proof (§R9.7b). Never while Astation
/// is authenticating an authenticated link again (a routed one keeps it).
fn r9_app_link(app: &App) -> Option<u64> {
    // A routed link keeps its r9 carrier while Astation authenticates it.
    (app.r9_link_up()
        && !app.station_direct_blocked()
        && (app.astation_reauth.is_none() || app.astation_routed))
        .then_some(app.astation_link_gen)
}

/// How the App's link reaches the Station: routed on the host's route
/// proof with no Astation (§R9.7b), else Astation's local link or the
/// relay.
fn station_link_kind(app: &App) -> LinkKind {
    if app.astation_routed && !app.astation_connected {
        return LinkKind::Routed;
    }
    match app.astation_client.via() {
        Some(crate::websocket_client::LinkVia::Local) => LinkKind::Local,
        _ => LinkKind::Relay,
    }
}

fn app_link(app: &App) -> Option<u64> {
    (app.astation_connected
        && !app.station_direct_blocked()
        && app.astation_reauth.is_none()
        && !app.astation_client.is_ws_closed())
    .then_some(app.astation_link_gen)
}

/// The worker's answer to a host interrupt's write, for host-work (the
/// worker's `consumed` answer also says `no_effect`).
fn interrupt_report(result: &WriteOutcome) -> InterruptReport {
    if result.consumed {
        InterruptReport::Consumed
    } else if result.dropped {
        InterruptReport::Dropped
    } else if result.no_effect {
        InterruptReport::NoEffect
    } else if !result.ok {
        InterruptReport::ErrorAfterQueue
    } else {
        InterruptReport::Ok
    }
}

/// Today's Esc rule: a turn is known to run only with chat, `working` or
/// `waiting` (in `ready` or `unknown` nothing is written: Esc on Codex's
/// startup trust dialog quits it).
fn turn_known_to_run(s: &BrokerSession) -> bool {
    s.chat_v1
        && matches!(
            s.chat.status().state,
            ChatState::Working | ChatState::Waiting
        )
}

/// The chat's half of R9.14 item 5's turn check, for the session host: the
/// request whose turn `sid`'s chat shows running under today's Esc rule
/// (`turn_known_to_run`). None for a session that isn't live, has no turn
/// state (no chat: no blind Esc), shows no turn running (its prompt not
/// taken yet, the turn ended, Codex before its first prompt) or one typed
/// at the terminal.
fn running_request(cx: &mut Cx, sid: &str) -> Option<String> {
    let s = session_of(cx, sid).filter(|s| s.is_live())?;
    turn_known_to_run(s)
        .then(|| s.chat.current_request_id())
        .flatten()
        .map(str::to_string)
}

/// Each session's chat as the reconciliation of host-work's prompts reads
/// it (R9.14 items 5, 6), for the state dump (debug builds).
#[cfg(debug_assertions)]
fn chat_dump(cx: &Cx) -> Value {
    let chats: Map<String, Value> = cx
        .sessions
        .iter()
        .map(|(id, s)| {
            let outcome = s.chat.last_outcome().map(|o| match o {
                crate::chat::adapter::Outcome::Done => "done",
                crate::chat::adapter::Outcome::Interrupted => "interrupted",
            });
            let chat = json!({"synced": s.chat_synced, "chat": s.chat_v1,
                "current_turn": s.chat.current_turn_id(),
                "last_completed": s.chat.last_completed_turn(), "outcome": outcome,
                "request_id": s.chat.current_request_id()});
            (id.to_string(), chat)
        })
        .collect();
    Value::Object(chats)
}

/// What `s`, the session of host-work's prompt `r` as the broker has it,
/// shows of the turn the prompt started, at a start (R9.14 items 5, 6),
/// read with the session host's table (`reconcile_turn`). A worker with
/// no chat adapter sends no chat: none is waited for.
fn reconciled(s: Option<&BrokerSession>, r: &Reconciling, expired: bool) -> Reconciled {
    let s = s.filter(|s| s.is_live() && s.process_gen == r.process_gen);
    let chat = match s {
        // No worker of that process was adopted, or its agent exited.
        None => AdoptedChat {
            live: false,
            arrived: false,
            chat: false,
            current_turn: None,
            last_completed: None,
            last_outcome: None,
        },
        Some(s) => AdoptedChat {
            live: true,
            arrived: s.chat_synced || !s.chat_offered,
            chat: s.chat_v1,
            current_turn: s.chat.current_turn_id(),
            last_completed: s.chat.last_completed_turn(),
            last_outcome: s.chat.last_outcome(),
        },
    };
    reconcile_turn(&r.turn, &chat, expired)
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

/// What session `s`'s chat shows of the turn of the prompt that carries
/// `tag`: no turn state; the prompt not taken (no user message carries the
/// tag); its turn running; or ended (the chat `ready`, and that turn the
/// last one completed, or no longer the current one).
fn chat_signs(s: &BrokerSession, tag: &str) -> super::prompt_tags::ChatSigns {
    use super::prompt_tags::ChatSigns;
    use crate::chat::adapter::Part;
    use crate::chat::session::Role;
    if tag.is_empty() || !s.chat_v1 {
        return ChatSigns::Unknown;
    }
    let taken = s
        .chat
        .retained()
        .filter(|m| m.role == Role::User)
        .filter(|m| {
            m.parts
                .iter()
                .any(|p| matches!(p, Part::Text { markdown, .. } if markdown.contains(tag)))
        })
        .last()
        .map(|m| m.turn_id.clone());
    match taken {
        None => ChatSigns::NotTaken,
        Some(turn)
            if s.chat.status().state == ChatState::Ready
                && (s.chat.last_completed_turn() == Some(turn.as_str())
                    || s.chat.current_turn_id() != Some(turn.as_str())) =>
        {
            ChatSigns::Ended
        }
        Some(_) => ChatSigns::Running,
    }
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

/// One line in runtime.log per session handshake outcome of the `hello`
/// `id`: welcomed, replaced (and welcomed) or refused with its code. Never a
/// payload; attachments by their first 8 characters.
fn log_hello(id: &str, effects: &[Effect]) -> Option<HelloOutcome> {
    use crate::session_protocol::wire::{Op, SessionMessage};
    let short = |a: &str| a.chars().take(8).collect::<String>();
    let mut replaced = None;
    for effect in effects {
        match effect {
            Effect::Replaced { old, new } => replaced = Some((short(old), short(new))),
            Effect::Send {
                message:
                    Envelope::Session(SessionMessage {
                        re: Some(re), op, ..
                    }),
                ..
            } if re == id => match op {
                Op::Welcome {
                    attachment_gen,
                    host_trust_gen,
                    ..
                } => {
                    let replaced = replaced
                        .as_ref()
                        .map(|(old, new)| (old.as_str(), new.as_str()));
                    log_handshake(&welcome_line(
                        replaced,
                        &short(attachment_gen),
                        *host_trust_gen,
                    ));
                    return Some(HelloOutcome::Welcomed);
                }
                Op::Error { code, .. } => {
                    let code = serde_json::to_value(code)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default();
                    log_handshake(&format!("refused {code}"));
                    return Some(HelloOutcome::Refused(code));
                }
                _ => {}
            },
            _ => {}
        }
    }
    None
}

/// runtime.log's welcome line: the attachment (or the one it replaced) and
/// the host trust generation the welcome carried.
fn welcome_line(replaced: Option<(&str, &str)>, attachment: &str, trust_gen: u64) -> String {
    match replaced {
        Some((old, new)) => {
            format!("replaced attachment {old} with {new}; welcome (trust gen {trust_gen})")
        }
        None => format!("welcome (attachment {attachment}, trust gen {trust_gen})"),
    }
}

/// What became of a session `hello`.
enum HelloOutcome {
    Welcomed,
    /// Refused with this error code.
    Refused(String),
}

fn log_handshake(what: &str) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        % 86_400;
    eprintln!(
        "{:02}:{:02}:{:02} atem runtime: session hello: {what}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    );
}

/// runtime.log's line for a request allowed by a session rule: the session,
/// the tool and the rule, never the command or its summary.
pub(super) fn auto_allowed_line(sid: &str, tool: &str, rule_id: &str) -> String {
    format!("atem runtime: {sid}: {tool} allowed by session rule {rule_id}")
}

/// The runtime.log line for a remote rule revocation: the rule and the
/// session only, never the command.
pub(super) fn rule_revoked_line(sid: &str, rule_id: &str, ok: bool) -> String {
    if ok {
        format!("atem runtime: {sid}: session rule {rule_id} revoked")
    } else {
        format!("atem runtime: {sid}: session rule {rule_id} not revoked (no longer active)")
    }
}

/// The code of an error reply: a session `error`, a terminal-v1 `error`, or
/// a `rejected` receipt.
fn error_code(message: &Envelope) -> Option<String> {
    use crate::session_protocol::wire::{Op, ReceiptState};
    match message {
        Envelope::Session(m) => match &m.op {
            Op::Error { code, .. } => serde_json::to_value(code)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string)),
            Op::Receipt(r) if r.state == ReceiptState::Rejected => Some("rejected".into()),
            _ => None,
        },
        Envelope::Family(f) if f.family == "terminal" => {
            let data = f.data.as_ref()?;
            (data["op"] == "error").then(|| data["code"].as_str().unwrap_or("?").to_string())
        }
        Envelope::Family(_) => None,
    }
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
            revision: None,
            controller: None,
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

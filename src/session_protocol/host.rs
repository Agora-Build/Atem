//! The host authority for atem-session v1 (contract r7, compatibility mode,
//! moving to r8): revision admission (r8 §A: only `hello{revision: 8}` is
//! welcomed, `welcome` names the revision and `revision::FEATURES`; ops of
//! unadvertised features and the forms r8 removed are `unsupported_version`),
//! attachments and hello/welcome (§3), the session registry with a
//! per-attachment `seq` (§4), control leases with input-epoch fencing (§5),
//! submissions with durable receipts (§6) and errors without disclosure (§7).
//!
//! `SessionHost` is pure: it never touches sockets, PTYs, processes or files.
//! Time is the injected monotonic clock (`advance`, and the `now` passed with
//! every message and write check, so expiry never waits for a timer tick);
//! every input returns the
//! `Effect`s the runtime must perform, in order. Durability goes through the
//! `Journal`: a receipt state is reported only after its record is durable.
//!
//! There are no legacy paths (§0): removed message families and ops are
//! answered `unsupported_version` and change nothing, and every remote
//! mutation is a session-v1 request (or a bound terminal-v1/chat-v1 request)
//! carrying `binding` and the current lease, after `welcome`.
//!
//! The PTY write boundary is the runtime's: right before writing a queued
//! remote chunk it calls `admit_write(session, input_epoch, now)`; transfer,
//! expiry, release, revoke, local input and the holder's attachment going
//! away bump the epoch first, so bytes queued under an older lease are
//! dropped, never written.
//!
//! Refused terminal-v1 requests are answered with terminal-v1 `error`, and a
//! chat-v1 `submit` hears about its request through chat-v1 ops
//! (`Effect::Chat`); removed forms get a session `error` without `re`.
//!
//! Approvals (r7): the runtime opens an agent permission prompt with
//! `open_approval`, whoever holds the lease (delivery is independent of
//! control): subscribed attachments with `control` get `approval_request`
//! (again after every `list`) and `Effect::PushApproval` asks the relay to
//! push it to the account's devices. Any attachment with `control` answers
//! with a `kind:"approval"` submission (r8 §G): the lease is neither needed
//! nor checked, taken or moved, r7's `acquire` on an answer is refused, and
//! the first admitted answer wins (later ones are `stale_target`). Once the
//! answer is `executing` the approval closes
//! (`answered_remote`) and `Effect::Approval` hands the decision to the
//! agent, whose report (`approval_applied`, `close_approval`,
//! `dispatch_report`) finishes the receipt. Every close also resolves the
//! push (`Effect::PushResolved`). The process ending closes a pending
//! approval and tells the runtime to answer "no decision"
//! (`Effect::ApprovalReleased`); the terminal can always answer instead
//! (`close_approval(answered_terminal)`), and lease changes never close one.
//!
//! Principals and the control fence (r8 §H): every attachment speaks for
//! the principal its link authenticated (`Attach::principal`; today one per
//! link, the paired, verified Astation, while the fixture harness gives each
//! client its own). Per principal the journal keeps whether it holds
//! `control` and a `control_gen` that only rises; accepted work records its
//! submitter's principal and generation and runs only while that principal
//! holds `control` at that generation. A connect that takes `control` away
//! writes the fence first (`Record::Control`), then fences the principal's
//! attachments with `control`, revokes its leases and rejects its queued
//! work (`control revoked`); if a write of that step fails it does the same
//! in memory and the journal halts.
//!
//! Persistence (r8 §I): a request is accepted only once its `accepted`
//! record is durable. Any failed journal write halts the journal: every
//! session request but `hello` is `busy` (`journal halted; restart Atem`), a
//! `hello` is not welcomed, nothing queued is dispatched and no remote byte
//! passes `admit_write`, until the runtime restarts (`restart_at`, or a new
//! process over the reopened journal). A failed admission write is put on
//! the refusal list before its `busy` (`acceptance not recorded`); if even
//! that fails the link is closed without a reply. An orderly stop with a
//! healthy journal writes the clean-close record (`close_cleanly`). At start
//! (`recover`) recovered queued work is resolved in the appendix's order:
//! refused (`acceptance not confirmed`), no clean close (`authorization
//! history unknown`), trust changed, an older `control_gen` (`control
//! revoked`), else it waits for its principal to be welcomed with `control`
//! and is `control not confirmed` 60 s after the start.
//!
//! Chat Send (r8 §F, `chat.send_acquire`): a session-v1 `prompt` submit or
//! a chat-v1 `text` submit may carry `acquire` (with `takeover` and
//! `expected_controller`) and acquire the lease in the same step as its
//! durable acceptance; the admitting reply carries the sender's lease.
//!
//! Atem session rules (r7.2): the runtime reports a session's active rules
//! (`set_approval_rules`; the worker owns them); attachments with `control`
//! get `approval_rules` on every change and after each `sessions` snapshot.
//! Any attachment with `control` revokes one with a
//! `kind:"approval_rule_revoke"` submission (r7.3: with or without the
//! lease, which it never needs, checks, takes or moves; an active rule of
//! that exact process only, else `stale_target`), dispatched to the runtime
//! like other work.

use super::canonical::{self, MAX_SAFE_INTEGER};
use super::journal::{self, ControlState, Journal, JournalError, Record, Refusal, Stored};
use super::revision::{FEATURES, REVISION};
use super::wire::{
    self, Activity, AlwaysRule, ApprovalAnswer, ApprovalCloseReason, ApprovalDecision,
    ApprovalRequest, Binding, ClientKind, Controller, DecodeError, Descriptor, Envelope, ErrorCode,
    FamilyMessage, LeaseChangeReason, MAX_IN_FLIGHT, MAX_PROMPT_BYTES, Op, Permission, Receipt,
    ReceiptKind, ReceiptLease, ReceiptState, RuleRevoke, SessionMessage, SessionState, Target,
    TerminalRequest,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// A lease lasts this long from its grant or renewal (§5).
pub const LEASE_MS: u64 = 15_000;
/// Removed sessions answer `unknown_session` for this long (§4).
pub const TOMBSTONE_MS: u64 = 10 * 60 * 1000;
/// Receipts outlive their session's close by this long (§6).
pub const RECEIPT_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// An interrupt or stop that shows no effect within this is `outcome_unknown`.
pub const OBSERVE_MS: u64 = 10_000;
/// A transport's attachment is replaced by a second `hello` at most once per
/// this interval (r7.1); more often is `busy`.
pub const REPLACE_INTERVAL_MS: u64 = 1_000;
/// Lease epochs are reserved durably in blocks, so an epoch is never issued
/// twice across restarts without an fsync per grant.
pub const LEASE_EPOCH_BLOCK: u64 = 64;
/// Default per-session receipt bound (`receipt_limit` beyond it).
pub const DEFAULT_MAX_RECEIPTS: usize = 4096;
/// Pending approvals per session; `open_approval` refuses beyond it.
pub const MAX_PENDING_APPROVALS: usize = 16;
/// A handed-off answer the agent hasn't confirmed by then (above Claude
/// Code's 600 s hook timeout) is `outcome_unknown`.
pub const APPROVAL_HANDOFF_MS: u64 = 630_000;
/// Recovered queued work whose principal isn't welcomed with `control` by
/// then (after the host's start) is `control not confirmed` (r8 §H).
pub const CONFIRM_MS: u64 = 60_000;

pub const DETAIL_APPROVAL_CLOSED: &str = "the approval closed before the answer was handed over";
pub const DETAIL_APPROVAL_CROSSED: &str = "the terminal answered too; which answer won is unknown";
pub const DETAIL_APPROVAL_UNCONFIRMED: &str = "the agent did not confirm the decision";
pub const DETAIL_DECISION_NOT_DELIVERED: &str = "could not hand the decision to the agent";
pub const DETAIL_RULE_NOT_REVOKED: &str = "could not revoke the rule";
pub const DETAIL_TRUST_CHANGED: &str = "host trust changed";
pub const DETAIL_SESSION_CLOSED: &str = "session closed";
pub const DETAIL_CONTROL_REVOKED: &str = "control revoked";
pub const DETAIL_CONTROL_NOT_CONFIRMED: &str = "control not confirmed";
pub const DETAIL_HISTORY_UNKNOWN: &str = "authorization history unknown";
pub const DETAIL_ACCEPTANCE_NOT_CONFIRMED: &str = "acceptance not confirmed";
/// `busy` for a failed admission write, a definitive refusal (r8 §I.2).
pub const DETAIL_ACCEPTANCE_NOT_RECORDED: &str = "acceptance not recorded";
/// `busy` for every request after a failed journal write (r8 §I).
pub const DETAIL_JOURNAL_HALTED: &str = "journal halted; restart Atem";
/// `busy` for an acquiring Send to a session without chat-v1 (r8 §F).
pub const DETAIL_NO_CHAT: &str = "chat is not available for this agent";
pub const DETAIL_NO_TERMINAL_WRITE: &str = "could not write to the terminal";
pub const DETAIL_WRITE_INTERRUPTED: &str = "write interrupted";
pub const DETAIL_AGENT_EXITED: &str = "agent exited";
pub const DETAIL_NO_INTERRUPT: &str = "no interrupt observed";
pub const DETAIL_INTERRUPT_NOT_SENT: &str = "could not send the interrupt";
pub const DETAIL_STOP_FAILED: &str = "stop failed";
pub const DETAIL_STILL_RUNNING: &str = "process still running";
pub const DETAIL_UNRECONCILED: &str = "outcome could not be established";
pub const DETAIL_REPAIR: &str = "host counters exhausted; pair again";
/// A completed `prompt` receipt's `detail`: its turn's outcome (chat-v1
/// `complete.outcome`), kept in the journal as one of these two words.
pub const DETAIL_TURN_DONE: &str = "done";
pub const DETAIL_TURN_INTERRUPTED: &str = "interrupted";

// ── Inputs and outputs ────────────────────────────────────────────────────

/// The host's own context (§2), fixed per runtime start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostContext {
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
    pub runtime_gen: String,
    pub runtime_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct HostConfig {
    pub max_receipts_per_session: usize,
    /// Wall clock = this + the monotonic clock (display times only).
    pub wall_offset_ms: u64,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            max_receipts_per_session: DEFAULT_MAX_RECEIPTS,
            wall_offset_ms: 0,
        }
    }
}

/// An authenticated connection, as the transport established it: identity,
/// kind and permissions never come from message fields.
#[derive(Debug, Clone)]
pub struct Attach {
    /// The authenticated client device; a new attachment fences its previous one.
    pub client: String,
    /// The authenticated principal the link speaks for (r8 §H): set from
    /// the link's authentication, never from message fields or the relay.
    /// An opaque id (`wire::is_opaque_id`). Today the runtime's one
    /// principal is the paired, verified Astation; with account trust each
    /// device with a grant is its own.
    pub principal: String,
    pub attachment_gen: String,
    pub permissions: Vec<Permission>,
    pub client_kind: ClientKind,
    /// Remaining authorization of the authenticated link.
    pub authorization_ms: u64,
}

/// An agent session the runtime registers.
#[derive(Debug, Clone)]
pub struct SessionSpec {
    pub session_id: String,
    pub process_gen: String,
    pub provider: String,
    pub cwd_label: String,
    /// Offers chat-v1 (else terminal-v1 only).
    pub chat: bool,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Typed on the host's own terminal; never fenced.
    Local,
    /// From the lease holder; written only if `admit_write` still admits `input_epoch`
    /// still holds at the write boundary.
    Remote {
        input_epoch: u64,
        attachment: String,
        stream_id: String,
        sequence: u64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    Send {
        attachment: String,
        message: Envelope,
    },
    /// The attachment is fenced: close its transport.
    Close {
        attachment: String,
    },
    /// A second `hello` on the welcomed attachment `old` fenced it and
    /// replaced it with `new` on the same transport (compatibility mode,
    /// r7.1): route that transport's messages to `new` from now on. Comes
    /// before anything sent to `new`.
    Replaced {
        old: String,
        new: String,
    },
    PtyWrite {
        session_id: String,
        bytes: Vec<u8>,
        origin: Origin,
    },
    Resize {
        session_id: String,
        rows: u16,
        cols: u16,
    },
    Stop {
        session_id: String,
    },
    /// Start/stop streaming terminal frames to a subscribed attachment.
    StreamOpened {
        attachment: String,
        session_id: String,
        stream_id: String,
    },
    StreamClosed {
        attachment: String,
        session_id: String,
        stream_id: String,
    },
    /// An authorized request the runtime serves itself (terminal-v1 `ack`,
    /// chat-v1 `open`/`close`); its binding was checked.
    Forward {
        attachment: String,
        session_id: String,
        message: FamilyMessage,
    },
    /// Perform the request (`executing` is already durable). Report back with
    /// `dispatch_report`.
    Dispatch {
        request_id: String,
        target: Target,
        kind: ReceiptKind,
        payload: Value,
    },
    /// After a restart: establish what an `executing` request did. Report
    /// back with `dispatch_report` (`Unknown` when it can't be established).
    Reconcile {
        request_id: String,
        target: Target,
        kind: ReceiptKind,
    },
    /// Hand the lease holder's answer to the agent's waiting permission
    /// prompt (`executing` is already durable). Report back with
    /// `approval_applied` (or `close_approval`, or `dispatch_report` with
    /// `FailedNoEffect` when the decision could not be delivered).
    Approval {
        request_id: String,
        session_id: String,
        approval_id: String,
        decision: ApprovalDecision,
        rule_id: Option<String>,
        message: Option<String>,
    },
    /// The host closed a pending approval (process ended, restart): answer
    /// the agent's waiting prompt with "no decision" so its own prompt asks.
    ApprovalReleased {
        session_id: String,
        approval_id: String,
    },
    /// A new pending approval: ask the relay to push it to the account's
    /// devices with `control` (best effort; never blocks the approval).
    PushApproval {
        request: ApprovalRequest,
    },
    /// The approval is no longer pending (answered, closed, released): the
    /// relay replaces its notification.
    PushResolved {
        approval_id: String,
        reason: ApprovalCloseReason,
    },
    /// A chat-v1 reply to the conversation that submitted (or was refused).
    /// The runtime's chat stream renders it with its own `generation` and
    /// `sequence` head.
    Chat {
        attachment: String,
        conversation_id: String,
        session_id: String,
        reply: ChatReply,
    },
}

/// chat-v1 results of a chat `submit`, mapped from its receipt (§6: chat-v1
/// `accepted`/`complete` follow the receipt's `accepted`/`completed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatReply {
    /// `lease` only on the reply that admitted an acquiring Send (r8 §F).
    Accepted {
        request_id: String,
        lease: Option<ReceiptLease>,
    },
    /// The turn ended (`outcome: "done"`, or `"interrupted"` when
    /// `interrupted`); `turn_id` is the provider's turn.
    Complete {
        request_id: String,
        turn_id: Option<String>,
        interrupted: bool,
    },
    /// `code` is a §7 error code for refusals, or `rejected` /
    /// `outcome_unknown` for a final receipt; `text` its bounded detail.
    Error {
        request_id: Option<String>,
        code: String,
        text: String,
        /// `false` for a request that never enters the conversation's
        /// sequenced stream (r8 §A: a removed form or an op of an
        /// unadvertised feature), so an open conversation's sequence is not
        /// advanced by it.
        sequenced: bool,
        /// The holder a `lease_held` names (r8 §F).
        controller: Option<Controller>,
    },
}

/// What the runtime observed for a dispatched (or reconciled) request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchReport {
    /// The kind's completion (§6 table) was observed; for a prompt,
    /// `turn_id` is the provider's turn that ended.
    Completed {
        detail: Option<String>,
        turn_id: Option<String>,
    },
    /// Failed with proof that nothing reached the agent (e.g. the PTY
    /// reservation failed, the signal could not be delivered).
    FailedNoEffect,
    /// Refused before anything reached the agent, for a reason the
    /// submitter should see (a prompt while the agent is busy, or before
    /// Codex's first prompt): rejected with this detail.
    Refused { detail: String },
    /// Failed after a possible partial effect (e.g. the writer errored).
    FailedAfterPossibleEffect,
    /// Reconciliation could not establish the outcome.
    Unknown,
}

/// What the runtime knows of an agent permission prompt (r7). The runtime
/// redacts before opening: `summary` is the command's first line or the
/// file path (never full inputs such as file contents) and rule labels are
/// stripped of secrets the same way; the host only checks the bounds.
/// `always_rules` are the agent's own suggestions, offered as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalInfo {
    pub tool: String,
    pub summary: String,
    pub always_rules: Vec<AlwaysRule>,
}

// ── State ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Approval {
    request: ApprovalRequest,
    /// Opening order (catch-up after `list` goes in this order).
    order: u64,
    /// The remote answer handed to the agent, awaiting its report.
    handed_off: Option<String>,
    /// Monotonic time by which the agent must confirm a handed-off answer.
    handoff_deadline: Option<u64>,
}

#[derive(Debug, Clone)]
struct Lease {
    attachment: String,
    /// The holder attachment's principal (its leases are revoked with its
    /// `control`, live attachment or gone).
    principal: String,
    controller_session: String,
    deadline: u64,
}

/// A principal's control state in this run (r8 §H): the durable state, and
/// whether an attachment of it was welcomed with `control` in this run.
#[derive(Debug, Clone, Copy)]
struct PrincipalState {
    control: bool,
    control_gen: u64,
    confirmed: bool,
}

/// What §F's admission planned for the lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeasePlan {
    /// Held live by the submitting attachment: no change.
    Own,
    Grant,
    Takeover,
}

/// The §F admission parameters of a submit.
#[derive(Debug, Clone, Default)]
pub struct SendParams {
    pub acquire: Option<bool>,
    pub takeover: Option<bool>,
    pub expected_controller: Option<Controller>,
}

impl SendParams {
    fn any(&self) -> bool {
        self.acquire.is_some() || self.takeover.is_some() || self.expected_controller.is_some()
    }
}

/// How a refused request is answered beyond its code.
#[derive(Debug, Default)]
struct Refused {
    detail: Option<&'static str>,
    controller: Option<Controller>,
    /// No reply: the link is closed (r8 §I.4).
    close: bool,
}

/// Whether accepted work may be dispatched now (r8 §H dispatch check).
enum Gate {
    Go,
    /// Its principal isn't confirmed in this run yet (recovered work).
    Wait,
    Revoked,
}

#[derive(Debug, Clone)]
struct Session {
    spec: SessionSpec,
    state: SessionState,
    activity: Activity,
    activity_since: u64,
    created_at: u64,
    exit_status: Option<String>,
    lease: Option<Lease>,
    lease_epoch: u64,
    epochs_reserved: u64,
    input_epoch: u64,
    /// Accepted prompts waiting for the executing one (one paste at a time).
    queued: VecDeque<String>,
}

#[derive(Debug, Clone)]
struct Attachment {
    client: String,
    principal: String,
    controller_session: Option<String>,
    permissions: Vec<Permission>,
    client_kind: ClientKind,
    authorization_deadline: u64,
    /// Registry messages sent in this epoch, once subscribed by `list`.
    registry_seq: Option<u64>,
    /// session_id → terminal-v1 stream id.
    streams: HashMap<String, String>,
    /// When this attachment replaced an earlier one with a second `hello`
    /// (host clock); a replacement within `REPLACE_INTERVAL_MS` is `busy`.
    replaced_at: Option<u64>,
}

impl Attachment {
    fn can(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }
    fn welcomed(&self) -> bool {
        self.controller_session.is_some()
    }
}

#[derive(Debug, Clone)]
struct Entry {
    stored: Stored,
    /// The live attachment that submitted it (gets its state changes).
    submitted_by: Option<String>,
    /// Interrupt/stop: no effect observed by then → `outcome_unknown`.
    observe_deadline: Option<u64>,
    /// Submitted through chat-v1 in this conversation: replies use chat ops.
    chat: Option<String>,
    /// The provider turn a completed prompt ended (chat `complete`).
    turn_id: Option<String>,
}

pub type IdSource = Box<dyn FnMut() -> String + Send>;

/// UUID v4 ids for host messages, controller sessions and streams.
pub fn random_ids() -> IdSource {
    Box::new(|| uuid::Uuid::new_v4().to_string())
}

pub struct SessionHost<J: Journal> {
    ctx: HostContext,
    config: HostConfig,
    journal: J,
    ids: IdSource,
    now: u64,
    /// Own counters exhausted: stop admitting (§1).
    halted: bool,
    sessions: BTreeMap<String, Session>,
    /// Removed session ids → removal time.
    tombstones: HashMap<String, u64>,
    /// session_id → when it closed or was removed (receipt retention).
    ended: HashMap<String, u64>,
    attachments: BTreeMap<String, Attachment>,
    receipts: BTreeMap<String, Entry>,
    /// session_id → its request ids (the receipts index, kept with
    /// `receipts`): per-session scans don't walk every receipt.
    by_session: HashMap<String, BTreeSet<String>>,
    lease_floors: HashMap<String, u64>,
    /// approval_id → open approvals (pending, or handed off and awaiting the
    /// agent's report). Not persisted: a restart releases them.
    approvals: BTreeMap<String, Approval>,
    approvals_opened: u64,
    /// session_id → (process_gen, its active Atem session rules), as the
    /// runtime reported them (r7.2). Not persisted: the workers report
    /// them again.
    rules: BTreeMap<String, (String, Vec<AlwaysRule>)>,
    /// Admission order of the next new request.
    next_order: u64,
    /// principal → its control state (r8 §H).
    principals: BTreeMap<String, PrincipalState>,
    /// A journal write failed in this run (r8 §I): no more writes, no
    /// welcome, no dispatch, no remote byte, until the restart.
    journal_halted: bool,
    /// The previous run ended with a clean close naming its epoch.
    previous_clean: bool,
    /// The start's resolution of recovered work ran (`recover`).
    resolved: bool,
    /// Why remote sessions are disabled: the start's resolution couldn't be
    /// persisted (r8 §H, §I.3).
    start_error: Option<String>,
    /// When this run started (monotonic ms): the 60 s confirmation window.
    started_at: u64,
    /// Recovered accepted work waiting for its principal's confirmation.
    waiting: BTreeSet<String>,
    /// How the request being refused is answered beyond its code.
    refused: Refused,
    out: Vec<Effect>,
}

type Checked<T = ()> = Result<T, ErrorCode>;

impl<J: Journal> SessionHost<J> {
    /// A host over `journal`, reloading what it holds (apply the crash rules
    /// with `recover` once the surviving sessions are registered). The
    /// previous run's clean-close record is discarded (as after a run that
    /// didn't end cleanly); a runtime start uses `open`.
    pub fn new(
        ctx: HostContext,
        config: HostConfig,
        journal: J,
        ids: IdSource,
    ) -> Result<Self, JournalError> {
        Self::open(ctx, config, journal, ids, None)
    }

    /// A host over `journal` at a runtime start. `previous_epoch` is the
    /// runtime epoch of the previous run (read before this run's epoch was
    /// taken): that run ended cleanly only when the journal's clean-close
    /// record names it. The record is removed either way.
    pub fn open(
        ctx: HostContext,
        config: HostConfig,
        mut journal: J,
        ids: IdSource,
        previous_epoch: Option<u64>,
    ) -> Result<Self, JournalError> {
        let found = journal.take_clean_close();
        let previous_clean = found.is_some() && found == previous_epoch;
        let mut host = Self {
            ctx,
            config,
            journal,
            ids,
            now: 0,
            halted: false,
            sessions: BTreeMap::new(),
            tombstones: HashMap::new(),
            ended: HashMap::new(),
            attachments: BTreeMap::new(),
            receipts: BTreeMap::new(),
            by_session: HashMap::new(),
            lease_floors: HashMap::new(),
            approvals: BTreeMap::new(),
            approvals_opened: 0,
            rules: BTreeMap::new(),
            next_order: 0,
            principals: BTreeMap::new(),
            journal_halted: false,
            previous_clean,
            resolved: false,
            start_error: None,
            started_at: 0,
            waiting: BTreeSet::new(),
            refused: Refused::default(),
            out: Vec::new(),
        };
        host.reload()?;
        Ok(host)
    }

    /// The journal halted after a failed write (r8 §I): until the restart.
    pub fn journal_halted(&self) -> bool {
        self.journal_halted
    }

    /// Whether the previous run ended with a clean close naming its epoch.
    pub fn previous_run_clean(&self) -> bool {
        self.previous_clean
    }

    /// Why remote sessions are disabled since the start, if they are: the
    /// resolution of recovered work couldn't be persisted.
    pub fn start_error(&self) -> Option<&str> {
        self.start_error.as_deref()
    }

    /// At an orderly stop, after admission stopped: writes the clean-close
    /// record naming this run's epoch, only if the journal is healthy (no
    /// failed write in this run, the start's resolution persisted). True
    /// when it was written.
    pub fn close_cleanly(&mut self) -> bool {
        if self.journal_halted || self.start_error.is_some() {
            return false;
        }
        self.journal
            .write_clean_close(self.ctx.runtime_epoch)
            .is_ok()
    }

    /// Appends `record`; any failure halts the journal (r8 §I).
    fn append(&mut self, record: Record) -> bool {
        if self.journal_halted {
            return false;
        }
        if self.journal.append(record).is_ok() {
            return true;
        }
        self.halt_journal();
        false
    }

    /// A journal write failed: nothing more is written, welcomed or
    /// dispatched in this run. Every session's input epoch moves on, so
    /// remote bytes already queued are dropped at the write boundary (which
    /// also checks the halt).
    fn halt_journal(&mut self) {
        if self.journal_halted {
            return;
        }
        self.journal_halted = true;
        for s in self.sessions.values_mut() {
            s.input_epoch += 1;
        }
    }

    /// The principal's control state (a principal the journal doesn't
    /// know holds no `control` yet, at generation 1).
    fn principal(&self, principal: &str) -> PrincipalState {
        self.principals
            .get(principal)
            .copied()
            .unwrap_or(PrincipalState {
                control: false,
                control_gen: 1,
                confirmed: false,
            })
    }

    pub fn context(&self) -> &HostContext {
        &self.ctx
    }

    pub fn journal(&self) -> &J {
        &self.journal
    }

    pub fn journal_mut(&mut self) -> &mut J {
        &mut self.journal
    }

    /// The journal back, to build a host with another context over it.
    pub fn into_journal(self) -> J {
        self.journal
    }

    /// The durable lease-epoch floor of `session_id` (0 when none was reserved).
    pub fn lease_floor(&self, session_id: &str) -> u64 {
        self.lease_floors.get(session_id).copied().unwrap_or(0)
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    fn take(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.out)
    }

    fn wall(&self) -> u64 {
        self.config
            .wall_offset_ms
            .saturating_add(self.now)
            .min(MAX_SAFE_INTEGER)
    }

    fn new_id(&mut self) -> String {
        (self.ids)()
    }

    // ── Runtime inputs ──

    /// Registers a new agent session. An id is never reused: not while live
    /// or tombstoned, not while receipts name it, and not once lease epochs
    /// were reserved for it.
    pub fn add_session(&mut self, spec: SessionSpec) -> Result<Vec<Effect>, String> {
        let sid = &spec.session_id;
        let known = self.lease_floors.contains_key(sid) || self.by_session.contains_key(sid);
        if known {
            return Err("session_id already used".into());
        }
        self.register(spec)
    }

    /// Re-registers a worker that survived a host restart (before
    /// `recover`): its receipts and lease floor carry over.
    pub fn restore_session(&mut self, spec: SessionSpec) -> Result<Vec<Effect>, String> {
        self.register(spec)
    }

    fn register(&mut self, spec: SessionSpec) -> Result<Vec<Effect>, String> {
        if !wire::is_session_id(&spec.session_id) || !wire::is_uuid_v4(&spec.process_gen) {
            return Err("invalid session_id or process_gen".into());
        }
        let sid = &spec.session_id;
        if self.sessions.contains_key(sid) || self.tombstones.contains_key(sid) {
            return Err("session_id already used".into());
        }
        let floor = self
            .lease_floors
            .get(&spec.session_id)
            .copied()
            .unwrap_or(0);
        let sid = spec.session_id.clone();
        let wall = self.wall();
        self.sessions.insert(
            sid.clone(),
            Session {
                spec,
                state: SessionState::Running,
                activity: Activity::Unknown,
                activity_since: wall,
                created_at: wall,
                exit_status: None,
                lease: None,
                lease_epoch: floor,
                epochs_reserved: floor,
                input_epoch: 0,
                queued: VecDeque::new(),
            },
        );
        self.registry_changed(&sid);
        Ok(self.take())
    }

    /// A new authenticated attachment. Any earlier attachment of the same
    /// client is fenced first (closed; anything still arriving on it is
    /// refused). It holds no lease and must `hello` before anything else.
    ///
    /// The link's permissions are what its principal holds now (r8 §H): a
    /// principal that loses `control` is fenced first (`revoke_control`),
    /// one that regains it keeps its raised `control_gen`.
    pub fn connect(&mut self, a: Attach) -> Result<Vec<Effect>, String> {
        if !wire::is_uuid_v4(&a.attachment_gen) || self.attachments.contains_key(&a.attachment_gen)
        {
            return Err("attachment_gen must be a new UUID v4".into());
        }
        if !wire::is_opaque_id(&a.principal) {
            return Err("principal must be an opaque id".into());
        }
        let has_control = a.permissions.contains(&Permission::Control);
        self.resolve_once();
        self.principal_control(&a.principal, has_control);
        let old: Vec<String> = self
            .attachments
            .iter()
            .filter(|(_, x)| x.client == a.client)
            .map(|(id, _)| id.clone())
            .collect();
        for id in old {
            self.drop_attachment(&id);
            self.out.push(Effect::Close { attachment: id });
        }
        let deadline = self
            .now
            .saturating_add(a.authorization_ms)
            .min(MAX_SAFE_INTEGER);
        self.attachments.insert(
            a.attachment_gen,
            Attachment {
                client: a.client,
                principal: a.principal,
                controller_session: None,
                permissions: a.permissions,
                client_kind: a.client_kind,
                authorization_deadline: deadline,
                registry_seq: None,
                streams: HashMap::new(),
                replaced_at: None,
            },
        );
        Ok(self.take())
    }

    /// The principal's link authenticated with (`has`) or without `control`.
    fn principal_control(&mut self, principal: &str, has: bool) {
        let st = self.principal(principal);
        if st.control && !has {
            self.revoke_control(principal);
        } else if !st.control && has {
            // A grant keeps the raised generation (a failed write halts the
            // journal: then nothing of it is welcomed or dispatched anyway).
            self.append(Record::Control {
                principal: principal.to_string(),
                control: true,
                control_gen: st.control_gen,
            });
            self.principals.insert(
                principal.to_string(),
                PrincipalState {
                    control: true,
                    ..st
                },
            );
        }
    }

    /// r8 §H: `principal` lost `control`. In one step: the fence (its raised
    /// `control_gen`) is written durably; its live attachments with
    /// `control` are fenced and every lease held by one of its attachments
    /// (live or gone) is revoked; each of its accepted requests not yet
    /// executing is rejected (`control revoked`), persisted. If a write of
    /// the step fails, the rest happens in memory (the rejections reported
    /// to any live submitter, never persisted) and the journal halts; the
    /// restart rejects the same requests (no clean close). Executing work
    /// isn't cancelled.
    fn revoke_control(&mut self, principal: &str) {
        let st = self.principal(principal);
        let raised = st.control_gen.saturating_add(1).min(MAX_SAFE_INTEGER);
        let mut durable = self.append(Record::Control {
            principal: principal.to_string(),
            control: false,
            control_gen: raised,
        });
        self.principals.insert(
            principal.to_string(),
            PrincipalState {
                control: false,
                control_gen: raised,
                confirmed: false,
            },
        );
        let fenced: Vec<String> = self
            .attachments
            .iter()
            .filter(|(_, a)| a.principal == principal && a.can(Permission::Control))
            .map(|(id, _)| id.clone())
            .collect();
        for id in fenced {
            self.drop_attachment(&id);
            self.out.push(Effect::Close { attachment: id });
        }
        let held: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.lease.as_ref().is_some_and(|l| l.principal == principal))
            .map(|(id, _)| id.clone())
            .collect();
        for sid in held {
            self.end_lease(&sid, LeaseChangeReason::Revoked, None);
        }
        let mut queued: Vec<(u64, String)> = self
            .receipts
            .values()
            .filter(|e| e.stored.state == ReceiptState::Accepted && e.stored.principal == principal)
            .map(|e| (e.stored.order, e.stored.request_id.clone()))
            .collect();
        queued.sort();
        for (_, rid) in queued {
            self.waiting.remove(&rid);
            durable = durable
                && self.transition(&rid, ReceiptState::Rejected, Some(DETAIL_CONTROL_REVOKED));
            if !durable {
                self.reject_in_memory(&rid, DETAIL_CONTROL_REVOKED);
            }
        }
    }

    /// A rejection the journal couldn't take (it halted): the request is
    /// `rejected` in memory and its live submitter is told; the restart
    /// rejects it durably (r8 §H, "A failed revocation write").
    fn reject_in_memory(&mut self, rid: &str, detail: &str) {
        let wall = self.wall();
        let Some(e) = self.receipts.get_mut(rid) else {
            return;
        };
        if e.stored.state != ReceiptState::Accepted {
            return;
        }
        e.stored.state = ReceiptState::Rejected;
        e.stored.detail = Some(detail.to_string());
        e.stored.payload = None;
        e.stored.updated_at = wall;
        let reply = match e.chat.clone() {
            Some(conversation_id) => Reply::Chat { conversation_id },
            None => Reply::Session(None),
        };
        if let Some(att) = e.submitted_by.clone() {
            self.report_state(&att, reply, rid);
        }
    }

    /// The transport closed. A held lease is not released: it expires.
    pub fn disconnect(&mut self, attachment: &str) -> Vec<Effect> {
        self.drop_attachment(attachment);
        self.take()
    }

    /// Fences or forgets an attachment. A lease it holds is not released (it
    /// expires), but its queued remote bytes are dropped at the write boundary.
    fn drop_attachment(&mut self, id: &str) {
        for s in self.sessions.values_mut() {
            if s.lease.as_ref().is_some_and(|l| l.attachment == id) {
                s.input_epoch += 1;
            }
        }
        if let Some(a) = self.attachments.remove(id) {
            for (session_id, stream_id) in a.streams {
                self.out.push(Effect::StreamClosed {
                    attachment: id.to_string(),
                    session_id,
                    stream_id,
                });
            }
        }
        for e in self.receipts.values_mut() {
            if e.submitted_by.as_deref() == Some(id) {
                e.submitted_by = None;
            }
        }
    }

    /// The monotonic clock moved to `now`: leases expire (`now >= deadline`),
    /// observation windows close, pending durable writes are retried and
    /// tombstones/receipts past retention are dropped.
    pub fn advance(&mut self, now: u64) -> Vec<Effect> {
        self.tick(now);
        self.take()
    }

    fn tick(&mut self, now: u64) {
        self.now = self.now.max(now);
        let now = self.now;
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.lease.as_ref().is_some_and(|l| now >= l.deadline))
            .map(|(id, _)| id.clone())
            .collect();
        for sid in expired {
            self.end_lease(&sid, LeaseChangeReason::Expired, None);
        }
        if !self.waiting.is_empty() && now >= self.started_at.saturating_add(CONFIRM_MS) {
            // r8 §H: recovered work whose principal wasn't confirmed in time.
            for rid in std::mem::take(&mut self.waiting) {
                self.finish(
                    &rid,
                    ReceiptState::Rejected,
                    Some(DETAIL_CONTROL_NOT_CONFIRMED),
                );
            }
        }
        let unobserved: Vec<(String, ReceiptKind)> = self
            .receipts
            .values()
            .filter(|e| e.stored.state == ReceiptState::Executing)
            .filter(|e| e.observe_deadline.is_some_and(|d| now >= d))
            .map(|e| (e.stored.request_id.clone(), e.stored.kind))
            .collect();
        let unconfirmed: Vec<(String, String)> = self
            .approvals
            .iter()
            .filter(|(_, a)| a.handoff_deadline.is_some_and(|d| now >= d))
            .filter_map(|(id, a)| Some((id.clone(), a.handed_off.clone()?)))
            .collect();
        for (approval_id, rid) in unconfirmed {
            self.approvals.remove(&approval_id);
            self.finish(
                &rid,
                ReceiptState::OutcomeUnknown,
                Some(DETAIL_APPROVAL_UNCONFIRMED),
            );
        }
        for (rid, kind) in unobserved {
            let detail = match kind {
                ReceiptKind::Stop => DETAIL_STILL_RUNNING,
                _ => DETAIL_NO_INTERRUPT,
            };
            self.finish(&rid, ReceiptState::OutcomeUnknown, Some(detail));
        }
        self.tombstones
            .retain(|_, t| now < t.saturating_add(TOMBSTONE_MS));
        let past: Vec<String> = self
            .ended
            .iter()
            .filter(|(_, t)| now >= t.saturating_add(RECEIPT_RETENTION_MS))
            .map(|(sid, _)| sid.clone())
            .collect();
        for sid in past {
            self.evict_receipts(&sid);
        }
    }

    fn evict_receipts(&mut self, sid: &str) {
        for rid in self.receipt_ids(sid) {
            let record = Record::Evicted {
                request_id: rid.clone(),
            };
            if !self.append(record) {
                return; // the journal halted
            }
            self.receipts.remove(&rid);
            self.unindex(sid, &rid);
        }
        self.ended.remove(sid);
    }

    fn index(&mut self, sid: &str, rid: &str) {
        self.by_session
            .entry(sid.to_string())
            .or_default()
            .insert(rid.to_string());
    }

    fn unindex(&mut self, sid: &str, rid: &str) {
        if let Some(ids) = self.by_session.get_mut(sid) {
            ids.remove(rid);
            if ids.is_empty() {
                self.by_session.remove(sid);
            }
        }
    }

    /// `sid`'s request ids, in request-id order (as `receipts` iterates).
    fn receipt_ids(&self, sid: &str) -> Vec<String> {
        self.by_session
            .get(sid)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// `sid`'s receipts, in request-id order.
    fn receipts_of<'a>(&'a self, sid: &str) -> impl Iterator<Item = &'a Entry> + 'a {
        self.by_session
            .get(sid)
            .into_iter()
            .flatten()
            .filter_map(|rid| self.receipts.get(rid))
    }

    /// Local terminal input on the host: it bumps the input epoch and revokes
    /// any remote lease before the bytes are written (§5 local input wins).
    pub fn local_input(&mut self, session_id: &str, bytes: Vec<u8>) -> Vec<Effect> {
        let Some(s) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };
        s.input_epoch += 1;
        self.end_lease(session_id, LeaseChangeReason::LocalInput, None);
        self.out.push(Effect::PtyWrite {
            session_id: session_id.to_string(),
            bytes,
            origin: Origin::Local,
        });
        self.take()
    }

    /// Called by the PTY writer right before writing a queued remote chunk,
    /// with the monotonic time of the write: the chunk's input epoch must
    /// still be current and its lease unexpired (`now >= deadline` is
    /// expired, whether or not `advance` ran).
    /// Nothing passes after a journal halt (r8 §H).
    pub fn admit_write(&self, session_id: &str, input_epoch: u64, now: u64) -> bool {
        !self.journal_halted
            && self.sessions.get(session_id).is_some_and(|s| {
                s.input_epoch == input_epoch && s.lease.as_ref().is_some_and(|l| now < l.deadline)
            })
    }

    /// The outcome of a `Dispatch` or `Reconcile`.
    pub fn dispatch_report(&mut self, request_id: &str, report: DispatchReport) -> Vec<Effect> {
        let Some(e) = self.receipts.get(request_id) else {
            return Vec::new();
        };
        if e.stored.state != ReceiptState::Executing {
            return Vec::new();
        }
        let kind = e.stored.kind;
        let (state, detail) = match report {
            DispatchReport::Completed { detail, turn_id } => {
                if let Some(e) = self.receipts.get_mut(request_id) {
                    e.turn_id = turn_id;
                }
                let detail = detail.map(|d| bounded_detail(&d));
                (ReceiptState::Completed, detail)
            }
            DispatchReport::FailedNoEffect => (
                ReceiptState::Rejected,
                Some(
                    match kind {
                        ReceiptKind::Prompt => DETAIL_NO_TERMINAL_WRITE,
                        ReceiptKind::Approval => DETAIL_DECISION_NOT_DELIVERED,
                        ReceiptKind::ApprovalRuleRevoke => DETAIL_RULE_NOT_REVOKED,
                        ReceiptKind::Interrupt => DETAIL_INTERRUPT_NOT_SENT,
                        ReceiptKind::Stop => DETAIL_STOP_FAILED,
                    }
                    .to_string(),
                ),
            ),
            DispatchReport::Refused { detail } => {
                (ReceiptState::Rejected, Some(bounded_detail(&detail)))
            }
            DispatchReport::FailedAfterPossibleEffect => (
                ReceiptState::OutcomeUnknown,
                Some(
                    match kind {
                        ReceiptKind::Prompt => DETAIL_WRITE_INTERRUPTED,
                        ReceiptKind::Approval => DETAIL_APPROVAL_UNCONFIRMED,
                        ReceiptKind::ApprovalRuleRevoke => DETAIL_UNRECONCILED,
                        ReceiptKind::Interrupt => DETAIL_NO_INTERRUPT,
                        ReceiptKind::Stop => DETAIL_STILL_RUNNING,
                    }
                    .to_string(),
                ),
            ),
            DispatchReport::Unknown => (
                ReceiptState::OutcomeUnknown,
                Some(DETAIL_UNRECONCILED.to_string()),
            ),
        };
        let no_effect = state == ReceiptState::Rejected;
        self.finish(request_id, state, detail.as_deref());
        if kind == ReceiptKind::Approval {
            let ids: Vec<String> = self
                .approvals
                .iter()
                .filter(|(_, a)| a.handed_off.as_deref() == Some(request_id))
                .map(|(id, _)| id.clone())
                .collect();
            for approval_id in ids {
                let a = self.approvals.remove(&approval_id).unwrap();
                if no_effect {
                    // The decision never reached the prompt: stop its wait.
                    self.out.push(Effect::ApprovalReleased {
                        session_id: a.request.session_id,
                        approval_id,
                    });
                }
            }
        }
        self.take()
    }

    /// The agent process ended: its lease ends, a `stop` completes, other
    /// executing work is `outcome_unknown` ("agent exited") and accepted work
    /// is rejected.
    pub fn process_exited(&mut self, session_id: &str, exit_status: Option<String>) -> Vec<Effect> {
        self.process_ended(session_id, SessionState::Exited, exit_status)
    }

    /// The agent process can no longer be reached: its worker went away
    /// without an exit (`Interrupted`) or can't be trusted
    /// (`RecoveryRequired`). As `process_exited`, with that state.
    pub fn process_lost(
        &mut self,
        session_id: &str,
        state: SessionState,
        status: Option<String>,
    ) -> Vec<Effect> {
        match state {
            SessionState::Interrupted | SessionState::RecoveryRequired => {
                self.process_ended(session_id, state, status)
            }
            _ => Vec::new(),
        }
    }

    fn process_ended(
        &mut self,
        session_id: &str,
        state: SessionState,
        exit_status: Option<String>,
    ) -> Vec<Effect> {
        let wall = self.wall();
        let Some(s) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };
        if s.state != SessionState::Running {
            return Vec::new();
        }
        s.state = state;
        s.activity = Activity::Unknown;
        s.exit_status = exit_status;
        s.activity_since = wall;
        self.close_pending(session_id, ApprovalCloseReason::ProcessEnded);
        self.clear_rules(session_id);
        self.end_lease(session_id, LeaseChangeReason::ProcessEnded, None);
        self.process_gone(session_id);
        self.registry_changed(session_id);
        self.take()
    }

    /// The session's agent process is gone: a `stop` completes, other
    /// executing work is `outcome_unknown` ("agent exited"), accepted work is
    /// rejected.
    fn process_gone(&mut self, session_id: &str) {
        let process_gen = self.sessions[session_id].spec.process_gen.clone();
        let work: Vec<(String, ReceiptState, ReceiptKind)> = self
            .receipts_of(session_id)
            .filter(|e| e.stored.target.process_gen == process_gen)
            .map(|e| (e.stored.request_id.clone(), e.stored.state, e.stored.kind))
            .collect();
        for (rid, state, kind) in work {
            match (state, kind) {
                (ReceiptState::Executing, ReceiptKind::Stop) => {
                    self.finish(&rid, ReceiptState::Completed, None)
                }
                (ReceiptState::Executing, _) => self.finish(
                    &rid,
                    ReceiptState::OutcomeUnknown,
                    Some(DETAIL_AGENT_EXITED),
                ),
                (ReceiptState::Accepted, _) => {
                    self.finish(&rid, ReceiptState::Rejected, Some(DETAIL_SESSION_CLOSED))
                }
                _ => {}
            }
        }
        self.forget_finished_approvals();
    }

    /// The session no longer accepts submissions; its receipts are kept for
    /// `RECEIPT_RETENTION_MS`. With `process_gone` its executing work is
    /// finished as after `process_exited`; otherwise it may still complete.
    pub fn close_session(&mut self, session_id: &str, process_gone: bool) -> Vec<Effect> {
        let Some(s) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };
        s.state = SessionState::Closed;
        self.ended.entry(session_id.to_string()).or_insert(self.now);
        self.close_pending(session_id, ApprovalCloseReason::ProcessEnded);
        self.clear_rules(session_id);
        self.end_lease(session_id, LeaseChangeReason::Revoked, None);
        self.reject_accepted(|t| t.session_id == session_id, DETAIL_SESSION_CLOSED);
        if process_gone {
            self.process_gone(session_id);
        }
        self.registry_changed(session_id);
        self.take()
    }

    /// The provider's activity changed (from agent-native events; `Unknown`
    /// when it can't be detected). `since` is wall-clock ms.
    pub fn set_activity(
        &mut self,
        session_id: &str,
        activity: Activity,
        since: u64,
    ) -> Result<Vec<Effect>, String> {
        let s = self
            .sessions
            .get_mut(session_id)
            .filter(|s| s.state == SessionState::Running)
            .ok_or("no running session")?;
        s.activity = activity;
        s.activity_since = since.min(MAX_SAFE_INTEGER);
        self.registry_changed(session_id);
        Ok(self.take())
    }

    /// The agent process was replaced (restart/resume): a new `process_gen`.
    /// Leases end, the old process's executing work is `outcome_unknown`
    /// ("agent exited") and its accepted work rejected; terminal streams of
    /// the old process close.
    pub fn replace_process(
        &mut self,
        session_id: &str,
        process_gen: &str,
    ) -> Result<Vec<Effect>, String> {
        let s = self.sessions.get(session_id).ok_or("unknown session")?;
        if s.state == SessionState::Closed {
            // Closed is final: its receipts are on their retention clock.
            return Err("session is closed".into());
        }
        if !wire::is_uuid_v4(process_gen) || s.spec.process_gen == process_gen {
            return Err("process_gen must be a new UUID v4".into());
        }
        let used = self
            .receipts_of(session_id)
            .any(|e| e.stored.target.process_gen == process_gen);
        if used {
            return Err("process_gen already used".into());
        }
        self.close_pending(session_id, ApprovalCloseReason::ProcessEnded);
        self.clear_rules(session_id);
        self.end_lease(session_id, LeaseChangeReason::ProcessEnded, None);
        self.reject_accepted(|t| t.session_id == session_id, DETAIL_SESSION_CLOSED);
        self.process_gone(session_id);
        let wall = self.wall();
        let s = self.sessions.get_mut(session_id).unwrap();
        s.spec.process_gen = process_gen.to_string();
        s.state = SessionState::Running;
        s.exit_status = None;
        s.activity = Activity::Unknown;
        s.activity_since = wall;
        s.input_epoch += 1;
        s.queued.clear();
        self.close_streams(session_id);
        self.registry_changed(session_id);
        Ok(self.take())
    }

    /// Removes the session: subscribers get its last descriptor with
    /// `state:"removed"`; late requests get `unknown_session`.
    pub fn remove_session(&mut self, session_id: &str) -> Vec<Effect> {
        if !self.sessions.contains_key(session_id) {
            return Vec::new();
        }
        self.close_pending(session_id, ApprovalCloseReason::ProcessEnded);
        self.clear_rules(session_id);
        self.end_lease(session_id, LeaseChangeReason::Revoked, None);
        self.reject_accepted(|t| t.session_id == session_id, DETAIL_SESSION_CLOSED);
        self.process_gone(session_id);
        self.sessions.get_mut(session_id).unwrap().state = SessionState::Removed;
        self.registry_changed(session_id);
        self.sessions.remove(session_id);
        self.tombstones.insert(session_id.to_string(), self.now);
        self.ended.entry(session_id.to_string()).or_insert(self.now);
        self.close_streams(session_id);
        self.take()
    }

    /// Ends every terminal stream on the session.
    fn close_streams(&mut self, session_id: &str) {
        for (att, a) in self.attachments.iter_mut() {
            if let Some(stream_id) = a.streams.remove(session_id) {
                self.out.push(Effect::StreamClosed {
                    attachment: att.clone(),
                    session_id: session_id.to_string(),
                    stream_id,
                });
            }
        }
    }

    /// The host trust generation moved on (unpair/rebind): every lease is
    /// revoked and work not yet dispatched is rejected ("host trust changed").
    pub fn change_trust_gen(&mut self, host_trust_gen: u64) -> Result<Vec<Effect>, String> {
        if host_trust_gen <= self.ctx.host_trust_gen || host_trust_gen > MAX_SAFE_INTEGER {
            return Err("host_trust_gen must increase".into());
        }
        self.ctx.host_trust_gen = host_trust_gen;
        // Session rules were granted under the old trust: the runtime has
        // the workers drop them; viewers see the lists empty.
        let ruled: Vec<String> = self.rules.keys().cloned().collect();
        for sid in ruled {
            self.clear_rules(&sid);
        }
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for sid in &ids {
            self.end_lease(sid, LeaseChangeReason::Revoked, None);
        }
        self.reject_accepted(|t| t.host_trust_gen != host_trust_gen, DETAIL_TRUST_CHANGED);
        Ok(self.take())
    }

    fn reject_accepted(&mut self, which: impl Fn(&Target) -> bool, detail: &str) {
        let ids: Vec<String> = self
            .receipts
            .values()
            .filter(|e| e.stored.state == ReceiptState::Accepted && which(&e.stored.target))
            .map(|e| e.stored.request_id.clone())
            .collect();
        for rid in ids {
            self.finish(&rid, ReceiptState::Rejected, Some(detail));
        }
    }

    /// An orderly broker restart (new `runtime_gen`, higher `runtime_epoch`)
    /// at the host's current time: as `restart_at` with `orderly`.
    pub fn restart(
        &mut self,
        runtime_gen: &str,
        runtime_epoch: u64,
    ) -> Result<Vec<Effect>, String> {
        let now = self.now;
        self.restart_at(runtime_gen, runtime_epoch, now, true)
    }

    /// A broker restart at monotonic `now` (new `runtime_gen`, higher
    /// `runtime_epoch`): an `orderly` one first writes the clean-close
    /// record if the journal is healthy (r8 §H), a crash doesn't. Then the
    /// journal is reopened, every attachment and lease is gone, receipts and
    /// principals are reloaded, the 60 s confirmation window starts at
    /// `now`, and the start's rules are applied (`recover`). Sessions
    /// (workers) stay. Timers don't fire.
    pub fn restart_at(
        &mut self,
        runtime_gen: &str,
        runtime_epoch: u64,
        now: u64,
        orderly: bool,
    ) -> Result<Vec<Effect>, String> {
        if !wire::is_uuid_v4(runtime_gen) || runtime_gen == self.ctx.runtime_gen {
            return Err("runtime_gen must be a new UUID v4".into());
        }
        if runtime_epoch <= self.ctx.runtime_epoch || runtime_epoch > MAX_SAFE_INTEGER {
            return Err("runtime_epoch must increase".into());
        }
        let previous_epoch = self.ctx.runtime_epoch;
        if orderly {
            self.close_cleanly();
        }
        // Read the journal before changing anything else. A failed restart
        // leaves the host as it was, halted: the journal couldn't be
        // reopened (a rollback still pending, a reload that failed) and
        // must not take writes until a real process restart.
        let replayed = self
            .journal
            .reopen()
            .and_then(|()| self.journal.load())
            .and_then(journal::replay);
        let replayed = match replayed {
            Ok(r) => r,
            Err(e) => {
                self.halt_journal();
                return Err(e.0);
            }
        };
        let found = self.journal.take_clean_close();
        self.previous_clean = found.is_some() && found == Some(previous_epoch);
        self.now = self.now.max(now);
        self.started_at = self.now;
        self.journal_halted = false;
        self.start_error = None;
        self.resolved = false;
        self.waiting.clear();
        self.ctx.runtime_gen = runtime_gen.to_string();
        self.ctx.runtime_epoch = runtime_epoch;
        self.attachments.clear();
        self.out.clear();
        // Approvals live in memory only: the waiting prompts get "no
        // decision" (nobody is attached to answer them any more).
        for (approval_id, a) in std::mem::take(&mut self.approvals) {
            if a.handed_off.is_none() {
                self.out.push(Effect::PushResolved {
                    approval_id: approval_id.clone(),
                    reason: ApprovalCloseReason::Released,
                });
                self.out.push(Effect::ApprovalReleased {
                    session_id: a.request.session_id,
                    approval_id,
                });
            }
        }
        // The workers report their rules to the new broker.
        self.rules.clear();
        self.install(replayed);
        for (sid, s) in self.sessions.iter_mut() {
            let floor = self.lease_floors.get(sid).copied().unwrap_or(0);
            s.lease = None;
            s.lease_epoch = floor;
            s.epochs_reserved = floor;
            s.input_epoch += 1;
            s.queued.clear();
        }
        let mut fx = self.take();
        fx.extend(self.recover());
        Ok(fx)
    }

    /// The host's identity changed (a pairing verified under another
    /// account or device while the runtime runs): as `restart` (new
    /// `runtime_gen`, higher `runtime_epoch`), under the new identity and a
    /// trust generation that never decreases. Nothing changes on failure.
    pub fn rebind(
        &mut self,
        account_id: &str,
        atem_device_id: &str,
        host_trust_gen: u64,
        runtime_gen: &str,
        runtime_epoch: u64,
    ) -> Result<Vec<Effect>, String> {
        if !wire::is_opaque_id(account_id) || !wire::is_opaque_id(atem_device_id) {
            return Err("invalid account or device id".into());
        }
        if host_trust_gen < self.ctx.host_trust_gen || host_trust_gen > MAX_SAFE_INTEGER {
            return Err("host_trust_gen must not decrease".into());
        }
        let previous = self.ctx.clone();
        self.ctx.account_id = account_id.to_string();
        self.ctx.atem_device_id = atem_device_id.to_string();
        self.ctx.host_trust_gen = host_trust_gen;
        let restarted = self.restart(runtime_gen, runtime_epoch);
        if restarted.is_err() {
            self.ctx = previous;
        }
        restarted
    }

    fn reload(&mut self) -> Result<(), JournalError> {
        let replayed = journal::replay(self.journal.load()?)?;
        self.install(replayed);
        Ok(())
    }

    fn install(&mut self, replayed: journal::Replayed) {
        self.receipts = replayed
            .receipts
            .into_iter()
            .map(|(rid, stored)| {
                let entry = Entry {
                    stored,
                    submitted_by: None,
                    observe_deadline: None,
                    chat: None,
                    turn_id: None,
                };
                (rid, entry)
            })
            .collect();
        // Nobody is confirmed in a new run (r8 §H).
        self.principals = replayed
            .principals
            .into_iter()
            .map(
                |(
                    p,
                    ControlState {
                        control,
                        control_gen,
                    },
                )| {
                    let st = PrincipalState {
                        control,
                        control_gen,
                        confirmed: false,
                    };
                    (p, st)
                },
            )
            .collect();
        self.by_session.clear();
        let ids: Vec<(String, String)> = self
            .receipts
            .values()
            .map(|e| {
                (
                    e.stored.target.session_id.clone(),
                    e.stored.request_id.clone(),
                )
            })
            .collect();
        for (sid, rid) in ids {
            self.index(&sid, &rid);
        }
        self.lease_floors = replayed.lease_epochs;
        self.next_order = self
            .receipts
            .values()
            .map(|e| e.stored.order + 1)
            .max()
            .unwrap_or(0);
    }

    /// The per-session index lists exactly the receipts there are.
    #[cfg(test)]
    pub fn index_matches_receipts(&self) -> bool {
        let mut rebuilt: HashMap<String, BTreeSet<String>> = HashMap::new();
        for e in self.receipts.values() {
            rebuilt
                .entry(e.stored.target.session_id.clone())
                .or_default()
                .insert(e.stored.request_id.clone());
        }
        rebuilt == self.by_session
    }

    /// The start's rules (r8 §H Recovery, §I.3), once per start, before
    /// anything is dispatched: requests on the refusal list are `rejected`
    /// ("acceptance not confirmed"), then the list is cleared; after a run
    /// without a clean close every other recovered `accepted` request is
    /// `rejected` ("authorization history unknown"); after a clean close a
    /// changed trust generation rejects it ("host trust changed"), a
    /// `control_gen` below its principal's durable one too ("control
    /// revoked"), and the rest waits for its principal to be welcomed with
    /// `control` (`CONFIRM_MS`). `executing` work is never dispatched again,
    /// only reconciled. If a resolution can't be persisted, remote sessions
    /// stay disabled (`start_error`, the journal halted) and nothing is
    /// dispatched or reconciled.
    pub fn recover(&mut self) -> Vec<Effect> {
        self.resolve_once();
        if self.start_error.is_some() {
            return self.take();
        }
        let mut executing: Vec<&Entry> = self
            .receipts
            .values()
            .filter(|e| e.stored.state == ReceiptState::Executing)
            .collect();
        executing.sort_by_key(|e| e.stored.order);
        let reconcile: Vec<Effect> = executing
            .into_iter()
            .map(|e| Effect::Reconcile {
                request_id: e.stored.request_id.clone(),
                target: e.stored.target.clone(),
                kind: e.stored.kind,
            })
            .collect();
        self.out.extend(reconcile);
        self.take()
    }

    /// The start's resolution, once per start: before `recover`'s
    /// reconciliation, and before the first connect (a link may connect
    /// while workers are still being adopted; its control changes then
    /// apply to resolved work, so recovered work gets the start's detail).
    /// Principals already confirmed get their waiting work at once.
    fn resolve_once(&mut self) {
        if self.resolved {
            return;
        }
        self.resolved = true;
        if let Err(e) = self.resolve_start() {
            self.halt_journal();
            self.start_error = Some(e);
            return;
        }
        let confirmed: Vec<String> = self
            .principals
            .iter()
            .filter(|(_, p)| p.confirmed && p.control)
            .map(|(id, _)| id.clone())
            .collect();
        for p in confirmed {
            self.confirm(&p);
        }
    }

    fn resolve_start(&mut self) -> Result<(), String> {
        const UNPERSISTED: &str = "the recovered requests could not be resolved durably";
        let refused = self.journal.refusals().map_err(|e| e.0)?;
        let mut on_list = HashSet::new();
        for r in refused {
            on_list.insert(r.request_id.clone());
            match self.receipts.get(&r.request_id).map(|e| e.stored.state) {
                Some(ReceiptState::Accepted) => {
                    let detail = Some(DETAIL_ACCEPTANCE_NOT_CONFIRMED);
                    if !self.transition(&r.request_id, ReceiptState::Rejected, detail) {
                        return Err(UNPERSISTED.into());
                    }
                }
                // Already resolved (a restart after a crash mid-way): it
                // keeps its state.
                Some(_) => {}
                None => self
                    .record_refused(r)
                    .map_err(|()| UNPERSISTED.to_string())?,
            }
        }
        self.journal.clear_refusals().map_err(|e| e.0)?;
        let mut queued: Vec<(u64, String)> = self
            .receipts
            .values()
            .filter(|e| e.stored.state == ReceiptState::Accepted)
            .map(|e| (e.stored.order, e.stored.request_id.clone()))
            .collect();
        queued.sort();
        for (_, rid) in queued {
            debug_assert!(!on_list.contains(&rid));
            let (principal, control_gen, trust) = {
                let s = &self.receipts[&rid].stored;
                (s.principal.clone(), s.control_gen, s.target.host_trust_gen)
            };
            let detail = if !self.previous_clean {
                Some(DETAIL_HISTORY_UNKNOWN)
            } else if trust != self.ctx.host_trust_gen {
                Some(DETAIL_TRUST_CHANGED)
            } else if control_gen < self.principal(&principal).control_gen {
                Some(DETAIL_CONTROL_REVOKED)
            } else {
                None
            };
            match detail {
                Some(d) => {
                    if !self.transition(&rid, ReceiptState::Rejected, Some(d)) {
                        return Err(UNPERSISTED.into());
                    }
                }
                None => {
                    self.waiting.insert(rid);
                }
            }
        }
        Ok(())
    }

    /// A refused request whose `accepted` record never reached the disk:
    /// recorded directly as `rejected` with its immutable values (§I.3).
    fn record_refused(&mut self, r: Refusal) -> Result<(), ()> {
        let updated_at = self.wall();
        let record = Record::Rejected {
            request_id: r.request_id.clone(),
            target: r.target.clone(),
            kind: r.kind,
            payload_digest: r.payload_digest.clone(),
            detail: DETAIL_ACCEPTANCE_NOT_CONFIRMED.into(),
            updated_at,
        };
        if !self.append(record) {
            return Err(());
        }
        let order = self.next_order;
        self.next_order += 1;
        let stored = Stored {
            request_id: r.request_id.clone(),
            target: r.target.clone(),
            kind: r.kind,
            payload_digest: r.payload_digest,
            payload: None,
            state: ReceiptState::Rejected,
            detail: Some(DETAIL_ACCEPTANCE_NOT_CONFIRMED.into()),
            updated_at,
            order,
            principal: String::new(),
            control_gen: 0,
        };
        self.index(&r.target.session_id, &r.request_id);
        self.receipts.insert(
            r.request_id,
            Entry {
                stored,
                submitted_by: None,
                observe_deadline: None,
                chat: None,
                turn_id: None,
            },
        );
        Ok(())
    }

    /// Recovered work waiting for its principal: in admission order, each
    /// is dispatched if its `control_gen` is still current, else rejected.
    fn confirm(&mut self, principal: &str) {
        let Some(st) = self.principals.get_mut(principal) else {
            return;
        };
        if !st.control {
            return;
        }
        st.confirmed = true;
        let mut mine: Vec<(u64, String)> = self
            .waiting
            .iter()
            .filter_map(|rid| self.receipts.get(rid))
            .filter(|e| e.stored.principal == principal)
            .map(|e| (e.stored.order, e.stored.request_id.clone()))
            .collect();
        mine.sort();
        for (_, rid) in mine {
            self.waiting.remove(&rid);
            self.schedule(&rid);
        }
    }

    // ── Queries ──

    /// The attachment holding `session_id`'s lease.
    pub fn lease_holder(&self, session_id: &str) -> Option<&str> {
        self.sessions
            .get(session_id)?
            .lease
            .as_ref()
            .map(|l| l.attachment.as_str())
    }

    /// The session's current descriptor (as `list` would send it).
    pub fn descriptor_of(&self, session_id: &str) -> Option<Descriptor> {
        self.sessions.get(session_id).map(|s| self.descriptor(s))
    }

    /// The deadline (monotonic ms) of the session's current lease, if one is
    /// held.
    pub fn lease_deadline(&self, session_id: &str) -> Option<u64> {
        self.sessions
            .get(session_id)?
            .lease
            .as_ref()
            .map(|l| l.deadline)
    }

    /// Live attachments that were welcomed (r8 fixtures' `attachments`).
    pub fn welcomed_attachments(&self) -> usize {
        self.attachments.values().filter(|a| a.welcomed()).count()
    }

    /// The live attachment `attachment` was granted `permission`.
    pub fn attachment_can(&self, attachment: &str, permission: Permission) -> bool {
        self.attachments
            .get(attachment)
            .is_some_and(|a| a.can(permission))
    }

    pub fn lease_epoch(&self, session_id: &str) -> Option<u64> {
        self.sessions.get(session_id).map(|s| s.lease_epoch)
    }

    pub fn input_epoch(&self, session_id: &str) -> Option<u64> {
        self.sessions.get(session_id).map(|s| s.input_epoch)
    }

    pub fn receipt(&self, request_id: &str) -> Option<Receipt> {
        self.receipts.get(request_id).map(|e| to_receipt(&e.stored))
    }

    /// Receipts `attachment` could read with `receipt_query` (view
    /// permission, current trust generation, a visible session).
    pub fn receipts_visible(&self, attachment: &str) -> usize {
        let Some(a) = self.attachments.get(attachment) else {
            return 0;
        };
        if !a.welcomed() || !a.can(Permission::View) {
            return 0;
        }
        self.receipts
            .values()
            .filter(|e| {
                let t = &e.stored.target;
                self.same_host(t) && self.sessions.contains_key(&t.session_id)
            })
            .count()
    }

    fn same_host(&self, t: &Target) -> bool {
        t.account_id == self.ctx.account_id
            && t.atem_device_id == self.ctx.atem_device_id
            && t.host_trust_gen == self.ctx.host_trust_gen
    }

    // ── Messages ──

    /// One message from `attachment`, arriving at monotonic `now`, strictly
    /// decoded here.
    pub fn receive(&mut self, attachment: &str, bytes: &[u8], now: u64) -> Vec<Effect> {
        self.receive_decoded(attachment, wire::decode(bytes), now)
    }

    /// One message from `attachment`, arriving at monotonic `now`, already
    /// decoded with `wire::decode`. Timers due by `now` fire first, so expiry
    /// (`now >= deadline`) never depends on `advance` having run.
    pub fn receive_decoded(
        &mut self,
        attachment: &str,
        msg: Result<Envelope, DecodeError>,
        now: u64,
    ) -> Vec<Effect> {
        self.tick(now);
        let re = match &msg {
            Ok(Envelope::Session(m)) => Some(m.id.clone()),
            Err(e) => e.id.clone(),
            Ok(Envelope::Family(_)) => None,
        };
        if !self.attachments.contains_key(attachment) {
            // Unknown or fenced: refused, and nothing else happens.
            self.error(attachment, re, ErrorCode::Unauthorized, None);
            return self.take();
        }
        match msg {
            // Removed ops (§0) and invalid representations: no effect.
            Err(e) if e.hello => self.refuse_hello(attachment, e.id),
            Err(e) => self.error(attachment, e.id, e.code, None),
            Ok(Envelope::Session(m)) => self.on_session(attachment, m),
            Ok(Envelope::Family(f)) => self.on_family(attachment, f),
        }
        self.take()
    }

    fn send(&mut self, attachment: &str, re: Option<String>, op: Op) {
        let message = Envelope::Session(SessionMessage {
            id: self.new_id(),
            re,
            op,
        });
        self.out.push(Effect::Send {
            attachment: attachment.to_string(),
            message,
        });
    }

    fn error(
        &mut self,
        attachment: &str,
        re: Option<String>,
        code: ErrorCode,
        detail: Option<&str>,
    ) {
        let detail = detail.map(str::to_string);
        let op = Op::Error {
            code,
            detail,
            revision: None,
            controller: None,
        };
        self.send(attachment, re, op);
    }

    /// Answers a refused request: its code, with what `self.refused` adds
    /// (a detail, `lease_held`'s holder), or no reply and the link closed.
    fn refuse(&mut self, att: &str, re: Option<String>, code: ErrorCode) {
        let refused = std::mem::take(&mut self.refused);
        if refused.close {
            self.drop_attachment(att);
            self.out.push(Effect::Close {
                attachment: att.to_string(),
            });
            return;
        }
        let detail = refused.detail.or(match code {
            ErrorCode::Busy if self.journal_halted => Some(DETAIL_JOURNAL_HALTED),
            ErrorCode::Busy if self.halted => Some(DETAIL_REPAIR),
            _ => None,
        });
        let op = Op::Error {
            code,
            detail: detail.map(str::to_string),
            revision: None,
            controller: refused.controller,
        };
        self.send(att, re, op);
    }

    /// r8 §A: a `hello` without `revision: 8` (absent, another number or not
    /// an integer) gets `unsupported_version` naming the host's revision,
    /// and nothing else happens: no attachment is welcomed or replaced.
    fn refuse_hello(&mut self, attachment: &str, re: Option<String>) {
        let op = Op::Error {
            code: ErrorCode::UnsupportedVersion,
            detail: Some(format!("atem-session revision {REVISION} required")),
            revision: Some(REVISION),
            controller: None,
        };
        self.send(attachment, re, op);
    }

    /// Checks shared by every request after `welcome`. After a journal halt
    /// every request is `busy`, on a welcomed attachment or not (r8 §I).
    fn admit_request(&self, att: &str) -> Checked {
        let a = &self.attachments[att];
        if self.journal_halted {
            return Err(ErrorCode::Busy);
        }
        if !a.welcomed() {
            // Any session op before welcome is a removed form (§0).
            return Err(ErrorCode::UnsupportedVersion);
        }
        if self.halted {
            return Err(ErrorCode::Busy);
        }
        if self.now >= a.authorization_deadline {
            return Err(ErrorCode::Paused);
        }
        Ok(())
    }

    fn on_session(&mut self, att: &str, m: SessionMessage) {
        let re = Some(m.id.clone());
        let result = match m.op {
            Op::Hello { revision, .. } if revision != Some(REVISION) => {
                self.refuse_hello(att, re);
                return;
            }
            Op::Hello { resume, .. } => self.hello(att, re.clone(), resume.is_some()),
            Op::ResumeProof { .. } => Err(ErrorCode::Unauthorized),
            op => self.admit_request(att).and_then(|()| match op {
                Op::List {} => self.list(att, re.clone()),
                Op::Acquire { binding, takeover } => {
                    self.acquire(att, re.clone(), &binding, takeover)
                }
                Op::Renew { binding } => self.renew(att, re.clone(), &binding),
                Op::Release { binding } => self.release(att, re.clone(), &binding),
                Op::Submit {
                    binding,
                    request_id,
                    kind,
                    payload,
                    acquire,
                    takeover,
                    expected_controller,
                } => {
                    let send = SendParams {
                        acquire,
                        takeover,
                        expected_controller,
                    };
                    self.submit_session(att, re.clone(), &binding, &request_id, kind, payload, send)
                }
                Op::ReceiptQuery {
                    binding,
                    request_ids,
                } => self.receipt_query(att, re.clone(), &binding, &request_ids),
                // Host-to-client ops are not requests.
                _ => Err(ErrorCode::UnsupportedVersion),
            }),
        };
        if let Err(code) = result {
            self.refuse(att, re, code);
        }
        self.refused = Refused::default();
    }

    /// Compatibility mode (§3, r7.1): no resume; every `hello` gets a new
    /// `controller_session` and holds no lease. A `hello` on an attachment
    /// that was already welcomed replaces it (`replace`); each attachment is
    /// still welcomed once.
    fn hello(&mut self, att: &str, re: Option<String>, resume: bool) -> Checked {
        if resume {
            return Err(ErrorCode::Unauthorized);
        }
        if self.journal_halted {
            // r8 §I: not welcomed until the restart (every other request on
            // the link is `busy`).
            return Ok(());
        }
        if self.now >= self.attachments[att].authorization_deadline {
            return Err(ErrorCode::Paused);
        }
        let replaced;
        let att = if self.attachments[att].welcomed() {
            replaced = self.replace(att)?;
            replaced.as_str()
        } else {
            att
        };
        let controller_session = self.new_id();
        let (now, wall) = (self.now, self.wall());
        let a = self.attachments.get_mut(att).unwrap();
        a.controller_session = Some(controller_session.clone());
        let op = Op::Welcome {
            account_id: self.ctx.account_id.clone(),
            atem_device_id: self.ctx.atem_device_id.clone(),
            host_trust_gen: self.ctx.host_trust_gen,
            runtime_gen: self.ctx.runtime_gen.clone(),
            controller_session,
            attachment_gen: att.to_string(),
            client_kind: a.client_kind,
            permissions: a.permissions.clone(),
            authorization_ms_left: a.authorization_deadline - now,
            server_time: wall,
            revision: Some(REVISION),
            features: Some(FEATURES.iter().map(|f| f.to_string()).collect()),
        };
        self.send(att, re, op);
        // r8 §H: a principal welcomed with `control` is confirmed in this
        // run; its recovered work may run.
        if self.attachments[att].can(Permission::Control) {
            let principal = self.attachments[att].principal.clone();
            self.confirm(&principal);
        }
        Ok(())
    }

    /// Fences the welcomed attachment `old` as a transport drop would, and
    /// puts a new, unwelcomed attachment of the same client in its place:
    /// same permissions, kind and authorization deadline (not renewed). Its
    /// leases end now (none is carried over); its streams close and its
    /// replies stop. Receipts and pending approvals stay. At most one
    /// replacement per `REPLACE_INTERVAL_MS` and transport (`busy`).
    fn replace(&mut self, old: &str) -> Checked<String> {
        let a = self.attachments[old].clone();
        if a.replaced_at
            .is_some_and(|t| self.now < t.saturating_add(REPLACE_INTERVAL_MS))
        {
            return Err(ErrorCode::Busy);
        }
        let new = uuid::Uuid::new_v4().to_string();
        self.out.push(Effect::Replaced {
            old: old.to_string(),
            new: new.clone(),
        });
        let held: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.lease.as_ref().is_some_and(|l| l.attachment == old))
            .map(|(id, _)| id.clone())
            .collect();
        self.drop_attachment(old);
        for sid in held {
            self.end_lease(&sid, LeaseChangeReason::Released, None);
        }
        self.attachments.insert(
            new.clone(),
            Attachment {
                client: a.client,
                principal: a.principal,
                controller_session: None,
                permissions: a.permissions,
                client_kind: a.client_kind,
                authorization_deadline: a.authorization_deadline,
                registry_seq: None,
                streams: HashMap::new(),
                replaced_at: Some(self.now),
            },
        );
        Ok(new)
    }

    /// The binding names this host, this attachment and a live session the
    /// attachment may see. Mismatches never reveal current values.
    fn check_binding(&self, att: &str, b: &Binding) -> Checked<&Session> {
        let a = &self.attachments[att];
        if b.attachment_gen != att || !self.same_host(&b.target) {
            return Err(ErrorCode::StaleTarget);
        }
        let s = self
            .sessions
            .get(&b.target.session_id)
            .filter(|_| a.can(Permission::View))
            .ok_or(ErrorCode::UnknownSession)?;
        if s.spec.process_gen != b.target.process_gen {
            return Err(ErrorCode::StaleTarget);
        }
        Ok(s)
    }

    /// A mutation needs `control`, the current lease held by this attachment
    /// at exactly `lease_epoch`, and a running session.
    fn check_mutation(&self, att: &str, s: &Session, lease_epoch: Option<u64>) -> Checked {
        if !self.attachments[att].can(Permission::Control) {
            return Err(ErrorCode::Forbidden);
        }
        // A session that no longer accepts work says so, whatever the lease.
        if s.state != SessionState::Running {
            return Err(ErrorCode::SessionClosed);
        }
        if !self.lease_live(att, s, lease_epoch) {
            return Err(ErrorCode::StaleLease);
        }
        Ok(())
    }

    /// `att` holds `s`'s lease at exactly `lease_epoch` and it hasn't expired.
    fn lease_live(&self, att: &str, s: &Session, lease_epoch: Option<u64>) -> bool {
        s.lease.as_ref().is_some_and(|l| {
            l.attachment == att && Some(s.lease_epoch) == lease_epoch && self.now < l.deadline
        })
    }

    // ── Registry (§4) ──

    fn descriptor(&self, s: &Session) -> Descriptor {
        let mut capabilities = vec!["terminal-v1".to_string()];
        if s.spec.chat {
            capabilities.push("chat-v1".into());
        }
        Descriptor {
            session_id: s.spec.session_id.clone(),
            process_gen: s.spec.process_gen.clone(),
            provider: s.spec.provider.clone(),
            cwd_label: s.spec.cwd_label.clone(),
            state: s.state,
            activity: s.activity,
            activity_since: s.activity_since,
            controller: s.lease.as_ref().map(|l| Controller {
                controller_session: l.controller_session.clone(),
                lease_epoch: s.lease_epoch,
            }),
            capabilities,
            created_at: s.created_at,
        }
    }

    fn next_seq(&mut self, att: &str) -> Option<u64> {
        let a = self.attachments.get_mut(att)?;
        let next = a.registry_seq.unwrap_or(0).checked_add(1);
        match next.filter(|n| *n <= MAX_SAFE_INTEGER) {
            Some(n) => {
                a.registry_seq = Some(n);
                Some(n)
            }
            None => {
                self.halted = true;
                None
            }
        }
    }

    /// `list` subscribes the attachment: a snapshot now, changes after it.
    fn list(&mut self, att: &str, re: Option<String>) -> Checked {
        if !self.attachments[att].can(Permission::View) {
            return Err(ErrorCode::Forbidden);
        }
        let sessions: Vec<Descriptor> =
            self.sessions.values().map(|s| self.descriptor(s)).collect();
        let seq = self.next_seq(att).ok_or(ErrorCode::Busy)?;
        let op = Op::Sessions {
            runtime_gen: self.ctx.runtime_gen.clone(),
            runtime_epoch: self.ctx.runtime_epoch,
            seq,
            sessions,
        };
        self.send(att, re, op);
        // Catch-up: every pending approval, after the snapshot, for an
        // attachment that may answer it.
        if !self.attachments[att].can(Permission::Control) {
            return Ok(());
        }
        let mut pending: Vec<&Approval> = self
            .approvals
            .values()
            .filter(|a| a.handed_off.is_none())
            .collect();
        pending.sort_by_key(|a| a.order);
        let requests: Vec<ApprovalRequest> =
            pending.into_iter().map(|a| a.request.clone()).collect();
        for r in requests {
            self.send(att, None, Op::ApprovalRequest(r));
        }
        // And the sessions' active session rules (r7.2).
        let rules: Vec<Op> = self
            .rules
            .iter()
            .filter(|(_, (_, r))| !r.is_empty())
            .map(|(sid, (process_gen, r))| Op::ApprovalRules {
                session_id: sid.clone(),
                process_gen: process_gen.clone(),
                rules: r.clone(),
            })
            .collect();
        for op in rules {
            self.send(att, None, op);
        }
        Ok(())
    }

    /// Sends the session's complete new descriptor to every subscribed viewer.
    fn registry_changed(&mut self, sid: &str) {
        let Some(descriptor) = self.sessions.get(sid).map(|s| self.descriptor(s)) else {
            return;
        };
        for att in self.subscribers() {
            let Some(seq) = self.next_seq(&att) else {
                continue;
            };
            let op = Op::SessionChanged {
                runtime_gen: self.ctx.runtime_gen.clone(),
                runtime_epoch: self.ctx.runtime_epoch,
                seq,
                descriptor: descriptor.clone(),
            };
            self.send(&att, None, op);
        }
    }

    // ── Leases (§5) ──

    fn lease_reply(&mut self, att: &str, re: Option<String>, b: &Binding) {
        let s = &self.sessions[&b.target.session_id];
        let l = s.lease.as_ref().expect("replying for a held lease");
        let binding = Binding {
            lease_epoch: Some(s.lease_epoch),
            ..b.clone()
        };
        let ms_left = l.deadline.saturating_sub(self.now);
        self.send(att, re, Op::Lease { binding, ms_left });
    }

    fn lease_changed(&mut self, sid: &str, reason: LeaseChangeReason, except: Option<&str>) {
        let s = &self.sessions[sid];
        let op = Op::LeaseChanged {
            session_id: sid.to_string(),
            process_gen: s.spec.process_gen.clone(),
            controller: s.lease.as_ref().map(|l| Controller {
                controller_session: l.controller_session.clone(),
                lease_epoch: s.lease_epoch,
            }),
            lease_epoch: s.lease_epoch,
            reason,
        };
        let viewers: Vec<String> = self
            .attachments
            .iter()
            .filter(|(id, a)| {
                a.welcomed() && a.can(Permission::View) && Some(id.as_str()) != except
            })
            .map(|(id, _)| id.clone())
            .collect();
        for att in viewers {
            self.send(&att, None, op.clone());
        }
    }

    /// Ends the held lease (new epoch, input epoch bumped first so queued
    /// remote bytes are dropped) and tells viewers.
    fn end_lease(&mut self, sid: &str, reason: LeaseChangeReason, except: Option<&str>) {
        let Some(s) = self.sessions.get_mut(sid) else {
            return;
        };
        if s.lease.take().is_none() {
            return;
        }
        s.input_epoch += 1;
        // Within the reservation: a grant reserves its own revocation epoch.
        s.lease_epoch += 1;
        self.lease_changed(sid, reason, except);
        self.registry_changed(sid);
        // Pending approvals stay: an attachment with `control` may still
        // answer them.
    }

    /// Makes sure epochs up to `need` are durably reserved.
    fn reserve_epochs(&mut self, sid: &str, need: u64) -> bool {
        if need <= self.sessions[sid].epochs_reserved {
            return true;
        }
        let Some(reserved) = need
            .checked_add(LEASE_EPOCH_BLOCK)
            .filter(|r| *r <= MAX_SAFE_INTEGER)
        else {
            self.halted = true;
            return false;
        };
        let record = Record::LeaseEpochs {
            session_id: sid.to_string(),
            reserved,
        };
        if !self.append(record) {
            return false;
        }
        self.sessions.get_mut(sid).unwrap().epochs_reserved = reserved;
        self.lease_floors.insert(sid.to_string(), reserved);
        true
    }

    fn acquire(&mut self, att: &str, re: Option<String>, b: &Binding, takeover: bool) -> Checked {
        let s = self.check_binding(att, b)?;
        if !self.attachments[att].can(Permission::Control) {
            return Err(ErrorCode::Forbidden);
        }
        if s.state != SessionState::Running {
            return Err(ErrorCode::SessionClosed);
        }
        let controller = self.attachments[att].controller_session.clone().unwrap();
        let held = s
            .lease
            .as_ref()
            .map(|l| (l.attachment.clone(), l.controller_session.clone()));
        // The grant's epoch and the epoch that will end it.
        let need = s.lease_epoch + 2;
        let previous = match held {
            // Repeat acquire: the current lease, unchanged.
            Some((holder, _)) if holder == att => {
                self.lease_reply(att, re, b);
                return Ok(());
            }
            Some((_, c)) if c == controller => return Err(ErrorCode::StaleLease),
            Some((_, c)) if !takeover => {
                // r8 §F: every `lease_held` names the holder.
                self.refused.controller = Some(Controller {
                    controller_session: c,
                    lease_epoch: need - 2,
                });
                return Err(ErrorCode::LeaseHeld);
            }
            Some((holder, _)) => Some(holder),
            None => None,
        };
        let sid = b.target.session_id.clone();
        if !self.reserve_epochs(&sid, need) {
            return Err(ErrorCode::Busy);
        }
        self.grant(att, &sid, previous.is_some());
        self.lease_reply(att, re, b);
        self.lease_announced(&sid, previous.is_some(), Some(att));
        // A takeover keeps pending approvals: the new holder saw them (they
        // follow every snapshot) and answers under its own epoch.
        Ok(())
    }

    /// Gives `att` the lease of `sid` (epochs reserved): a new epoch, and a
    /// new input epoch when it was taken from another holder.
    fn grant(&mut self, att: &str, sid: &str, takeover: bool) {
        let controller = self.attachments[att].controller_session.clone().unwrap();
        let principal = self.attachments[att].principal.clone();
        let deadline = self
            .now
            .saturating_add(LEASE_MS)
            .min(self.attachments[att].authorization_deadline);
        let s = self.sessions.get_mut(sid).unwrap();
        if takeover {
            s.input_epoch += 1;
        }
        s.lease_epoch += 1;
        s.lease = Some(Lease {
            attachment: att.to_string(),
            principal,
            controller_session: controller,
            deadline,
        });
    }

    fn lease_announced(&mut self, sid: &str, takeover: bool, except: Option<&str>) {
        let reason = if takeover {
            LeaseChangeReason::Takeover
        } else {
            LeaseChangeReason::Granted
        };
        self.lease_changed(sid, reason, except);
        self.registry_changed(sid);
    }

    fn holds(&self, att: &str, b: &Binding) -> Checked<()> {
        let s = self.check_binding(att, b)?;
        if self.lease_live(att, s, b.lease_epoch) {
            Ok(())
        } else {
            Err(ErrorCode::StaleLease)
        }
    }

    /// Renews only the live lease at its epoch; never re-acquires.
    fn renew(&mut self, att: &str, re: Option<String>, b: &Binding) -> Checked {
        self.holds(att, b)?;
        if !self.attachments[att].can(Permission::Control) {
            return Err(ErrorCode::Forbidden);
        }
        let deadline = self
            .now
            .saturating_add(LEASE_MS)
            .min(self.attachments[att].authorization_deadline);
        let s = self.sessions.get_mut(&b.target.session_id).unwrap();
        s.lease.as_mut().unwrap().deadline = deadline;
        self.lease_reply(att, re, b);
        Ok(())
    }

    fn release(&mut self, att: &str, re: Option<String>, b: &Binding) -> Checked {
        self.holds(att, b)?;
        self.end_lease(&b.target.session_id, LeaseChangeReason::Released, Some(att));
        self.send(att, re, Op::LeaseReleased {});
        Ok(())
    }

    // ── Submissions and receipts (§6) ──

    #[allow(clippy::too_many_arguments)]
    fn submit_session(
        &mut self,
        att: &str,
        re: Option<String>,
        b: &Binding,
        request_id: &str,
        kind: ReceiptKind,
        payload: Value,
        send: SendParams,
    ) -> Checked {
        self.submit(att, Reply::Session(re), b, request_id, kind, payload, send)
    }

    /// r8 §F field rules of the admission parameters: `None` for the r7 form
    /// (none present), else whether a takeover was confirmed and of which
    /// lease. Refused `invalid_request`, nothing recorded. Beside an approval
    /// answer they are r7's removed `acquire` (§G): `unsupported_version`.
    fn send_rules(
        &self,
        kind: ReceiptKind,
        b: &Binding,
        send: &SendParams,
    ) -> Checked<Option<Option<Controller>>> {
        if !send.any() {
            return Ok(None);
        }
        if kind == ReceiptKind::Approval {
            return Err(ErrorCode::UnsupportedVersion);
        }
        let valid = send.acquire == Some(true)
            && send.takeover.is_none_or(|t| t)
            && send.takeover.is_some() == send.expected_controller.is_some()
            && b.lease_epoch.is_none()
            && kind == ReceiptKind::Prompt;
        if !valid {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Some(send.expected_controller.clone()))
    }

    /// r8 §F ownership at this instant (expiry already applied by the tick
    /// that came with the message), never as a client last displayed it.
    /// `expected` is `Some` for a confirmed takeover.
    fn lease_plan(
        &mut self,
        att: &str,
        sid: &str,
        expected: Option<&Controller>,
    ) -> Checked<LeasePlan> {
        let controller = self.attachments[att].controller_session.clone();
        let s = &self.sessions[sid];
        let Some(l) = &s.lease else {
            // Nobody's control is taken: a grant, with or without takeover.
            return Ok(LeasePlan::Grant);
        };
        if l.attachment == att {
            return Ok(LeasePlan::Own);
        }
        if Some(&l.controller_session) == controller.as_ref() {
            return Err(ErrorCode::StaleLease);
        }
        let current = Controller {
            controller_session: l.controller_session.clone(),
            lease_epoch: s.lease_epoch,
        };
        if expected == Some(&current) {
            return Ok(LeasePlan::Takeover);
        }
        // Held by another; no takeover, or one confirmed against a lease
        // that is no longer the holder's.
        self.refused.controller = Some(current);
        Err(ErrorCode::LeaseHeld)
    }

    /// §6 admission, with r8's §F acquire (`send`) and §I persistence.
    /// `reply` is how the submitter hears about it: session `receipt`s, or
    /// chat-v1 ops for a chat `submit`.
    #[allow(clippy::too_many_arguments)]
    fn submit(
        &mut self,
        att: &str,
        reply: Reply,
        b: &Binding,
        request_id: &str,
        kind: ReceiptKind,
        payload: Value,
        send: SendParams,
    ) -> Checked {
        self.check_binding(att, b)?;
        let acquire = self.send_rules(kind, b, &send)?;
        let digest =
            canonical::payload_digest(&payload).map_err(|_| ErrorCode::UnsupportedVersion)?;
        if let Some(e) = self.receipts.get(request_id) {
            let st = &e.stored;
            if st.target != b.target || st.kind != kind || st.payload_digest != digest {
                return Err(ErrorCode::RequestIdReused);
            }
            // Same request, whatever flags it carries: the recorded state,
            // no lease, no re-execution.
            self.report_state(att, reply, request_id);
            return Ok(());
        }
        let sid = b.target.session_id.clone();
        let answer = match kind {
            ReceiptKind::Approval => {
                Some(ApprovalAnswer::parse(&payload).map_err(|_| ErrorCode::UnsupportedVersion)?)
            }
            _ => None,
        };
        let mut plan = None;
        if let Some(expected) = &acquire {
            // §F: `control`, a session that accepts work and runs chat, then
            // ownership, then the prompt's static checks.
            if !self.attachments[att].can(Permission::Control) {
                return Err(ErrorCode::Forbidden);
            }
            let s = &self.sessions[&sid];
            if s.state != SessionState::Running {
                return Err(ErrorCode::SessionClosed);
            }
            if !s.spec.chat {
                self.refused.detail = Some(DETAIL_NO_CHAT);
                return Err(ErrorCode::Busy);
            }
            plan = Some(self.lease_plan(att, &sid, expected.as_ref())?);
            let text = payload["text"].as_str().unwrap_or_default();
            if crate::chat::session::clean_prompt(text).is_err() {
                return Err(ErrorCode::InvalidRequest);
            }
        } else if matches!(
            kind,
            ReceiptKind::ApprovalRuleRevoke | ReceiptKind::Approval
        ) {
            // r7.3 revoke and r8 §G answer: `control` and a running session;
            // the lease is neither needed nor checked (a stale or foreign
            // `lease_epoch` is ignored), and they never take, renew or move
            // it, nor fence the holder's queued input.
            if !self.attachments[att].can(Permission::Control) {
                return Err(ErrorCode::Forbidden);
            }
            if self.sessions[&sid].state != SessionState::Running {
                return Err(ErrorCode::SessionClosed);
            }
        } else {
            self.check_mutation(att, &self.sessions[&sid], b.lease_epoch)?;
        }
        if let Some(answer) = &answer
            && !self.answerable(&b.target, answer)
        {
            return Err(ErrorCode::StaleTarget);
        }
        if kind == ReceiptKind::ApprovalRuleRevoke {
            let revoke = RuleRevoke::parse(&payload).map_err(|_| ErrorCode::UnsupportedVersion)?;
            if !self.rule_active(&b.target, &revoke.rule_id) {
                return Err(ErrorCode::StaleTarget);
            }
        }
        let held = self.by_session.get(&sid).map_or(0, BTreeSet::len);
        if held >= self.config.max_receipts_per_session {
            return Err(ErrorCode::ReceiptLimit);
        }
        let in_flight = self
            .receipts
            .values()
            .filter(|e| e.submitted_by.as_deref() == Some(att))
            .filter(|e| !journal::is_final(e.stored.state))
            .count();
        if in_flight >= MAX_IN_FLIGHT {
            return Err(ErrorCode::Busy);
        }
        let updated_at = self.wall();
        let moves = matches!(plan, Some(LeasePlan::Grant | LeasePlan::Takeover));
        // §F step 9: a grant or takeover reserves its epochs durably first.
        if moves {
            let need = self.sessions[&sid].lease_epoch + 2;
            if !self.reserve_epochs(&sid, need) {
                if !self.journal_halted {
                    return Err(ErrorCode::Busy); // counters exhausted
                }
                return self.admission_failed(request_id, &b.target, kind, &digest, updated_at);
            }
        }
        let principal = self.attachments[att].principal.clone();
        let control_gen = self.principal(&principal).control_gen;
        let record = Record::Accepted {
            request_id: request_id.to_string(),
            target: b.target.clone(),
            kind,
            payload_digest: digest.clone(),
            payload: payload.clone(),
            updated_at,
            principal: principal.clone(),
            control_gen,
        };
        // §I.1: accepted only once durable; only then does anything act.
        if !self.append(record) {
            return self.admission_failed(request_id, &b.target, kind, &digest, updated_at);
        }
        let order = self.next_order;
        self.next_order += 1;
        let stored = Stored {
            request_id: request_id.to_string(),
            target: b.target.clone(),
            kind,
            payload_digest: digest,
            payload: Some(payload),
            state: ReceiptState::Accepted,
            detail: None,
            updated_at,
            order,
            principal,
            control_gen,
        };
        let chat = match &reply {
            Reply::Chat { conversation_id } => Some(conversation_id.clone()),
            Reply::Session(_) => None,
        };
        self.index(&b.target.session_id, request_id);
        self.receipts.insert(
            request_id.to_string(),
            Entry {
                stored,
                submitted_by: Some(att.to_string()),
                observe_deadline: None,
                chat,
                turn_id: None,
            },
        );
        // §F step 11: only now the lease moves, then the reply carries it.
        if moves {
            let takeover = plan == Some(LeasePlan::Takeover);
            self.grant(att, &sid, takeover);
            self.lease_announced(&sid, takeover, Some(att));
        }
        match (plan, reply) {
            (Some(_), Reply::Session(re)) => {
                let s = &self.sessions[&sid];
                let l = s.lease.as_ref().expect("an admitted Send holds the lease");
                let mut receipt = to_receipt(&self.receipts[request_id].stored);
                receipt.lease = Some(ReceiptLease {
                    lease_epoch: s.lease_epoch,
                    ms_left: l.deadline.saturating_sub(self.now),
                });
                self.send(att, re, Op::Receipt(receipt));
            }
            (Some(_), Reply::Chat { conversation_id }) => {
                let s = &self.sessions[&sid];
                let l = s.lease.as_ref().expect("an admitted Send holds the lease");
                let lease = ReceiptLease {
                    lease_epoch: s.lease_epoch,
                    ms_left: l.deadline.saturating_sub(self.now),
                };
                self.out.push(Effect::Chat {
                    attachment: att.to_string(),
                    conversation_id,
                    session_id: sid.clone(),
                    reply: ChatReply::Accepted {
                        request_id: request_id.to_string(),
                        lease: Some(lease),
                    },
                });
            }
            (_, reply) => self.report_state(att, reply, request_id),
        }
        self.schedule(request_id);
        Ok(())
    }

    /// §I.2: an admission write failed (the journal halted). Nothing moved,
    /// nothing was recorded or scheduled. The refusal goes on the refusal
    /// list before the reply (`busy`, "acceptance not recorded"); if even
    /// that can't be written, the link is closed without a reply (§I.4).
    fn admission_failed(
        &mut self,
        request_id: &str,
        target: &Target,
        kind: ReceiptKind,
        digest: &str,
        updated_at: u64,
    ) -> Checked {
        let refusal = Refusal {
            request_id: request_id.to_string(),
            target: target.clone(),
            kind,
            payload_digest: digest.to_string(),
            updated_at,
        };
        match self.journal.record_refusal(refusal) {
            Ok(()) => self.refused.detail = Some(DETAIL_ACCEPTANCE_NOT_RECORDED),
            Err(_) => self.refused.close = true,
        }
        Err(ErrorCode::Busy)
    }

    /// Tells `att` the request's current state on its channel.
    fn report_state(&mut self, att: &str, reply: Reply, rid: &str) {
        let e = &self.receipts[rid];
        match reply {
            Reply::Session(re) => {
                let receipt = to_receipt(&e.stored);
                self.send(att, re, Op::Receipt(receipt));
            }
            Reply::Chat { conversation_id } => {
                let reply = chat_reply(e);
                self.out.push(Effect::Chat {
                    attachment: att.to_string(),
                    conversation_id,
                    session_id: e.stored.target.session_id.clone(),
                    reply,
                });
            }
        }
    }

    /// Prompts paste one at a time per session (queued while another prompt
    /// executes); interrupt and stop go at once.
    fn schedule(&mut self, rid: &str) {
        let e = &self.receipts[rid];
        if e.stored.kind != ReceiptKind::Prompt {
            self.start(rid);
            return;
        }
        let sid = e.stored.target.session_id.clone();
        match self.sessions.get_mut(&sid) {
            Some(s) => {
                s.queued.push_back(rid.to_string());
                self.pump_queue(&sid);
            }
            None => self.finish(rid, ReceiptState::Rejected, Some(DETAIL_SESSION_CLOSED)),
        }
    }

    fn prompt_executing(&self, sid: &str) -> bool {
        self.receipts_of(sid).any(|e| {
            e.stored.kind == ReceiptKind::Prompt && e.stored.state == ReceiptState::Executing
        })
    }

    fn pump_queue(&mut self, sid: &str) {
        // r8 §H: nothing queued is dispatched after a journal halt.
        while !self.journal_halted && !self.prompt_executing(sid) {
            let Some(rid) = self
                .sessions
                .get_mut(sid)
                .and_then(|s| s.queued.pop_front())
            else {
                return;
            };
            if self
                .receipts
                .get(&rid)
                .is_some_and(|e| e.stored.state == ReceiptState::Accepted)
            {
                self.start(&rid);
            }
        }
    }

    /// Why an accepted request may not be dispatched now, if it may not.
    fn dispatch_blocker(&self, t: &Target) -> Option<&'static str> {
        if t.host_trust_gen != self.ctx.host_trust_gen {
            return Some(DETAIL_TRUST_CHANGED);
        }
        let running = self.sessions.get(&t.session_id).is_some_and(|s| {
            s.spec.process_gen == t.process_gen && s.state == SessionState::Running
        });
        (!running).then_some(DETAIL_SESSION_CLOSED)
    }

    /// r8 §H dispatch check: the submitter principal must hold `control`
    /// now, confirmed in this run, at the recorded `control_gen`.
    fn control_gate(&self, rid: &str) -> Gate {
        let s = &self.receipts[rid].stored;
        let p = self.principal(&s.principal);
        if p.control_gen != s.control_gen || (p.confirmed && !p.control) {
            Gate::Revoked
        } else if p.confirmed {
            Gate::Go
        } else {
            Gate::Wait
        }
    }

    /// accepted → executing (durable before the first side effect) → Dispatch.
    fn start(&mut self, rid: &str) {
        if self.journal_halted {
            // r8 §H: it stays accepted; the restart resolves it.
            return;
        }
        let target = self.receipts[rid].stored.target.clone();
        if let Some(detail) = self.dispatch_blocker(&target) {
            self.finish(rid, ReceiptState::Rejected, Some(detail));
            return;
        }
        match self.control_gate(rid) {
            Gate::Go => {}
            Gate::Wait => {
                self.waiting.insert(rid.to_string());
                return;
            }
            Gate::Revoked => {
                self.finish(rid, ReceiptState::Rejected, Some(DETAIL_CONTROL_REVOKED));
                return;
            }
        }
        // The payload is dropped once the request leaves `accepted`.
        let payload = self.receipts[rid]
            .stored
            .payload
            .clone()
            .unwrap_or(Value::Null);
        let kind = self.receipts[rid].stored.kind;
        let answer = if kind == ReceiptKind::Approval {
            // Handed over only while its approval is still pending (after a
            // restart it never is).
            match ApprovalAnswer::parse(&payload) {
                Ok(a) if self.answerable(&target, &a) => Some(a),
                _ => {
                    self.finish(rid, ReceiptState::Rejected, Some(DETAIL_APPROVAL_CLOSED));
                    return;
                }
            }
        } else {
            None
        };
        if !self.transition(rid, ReceiptState::Executing, None) {
            // §I.6: no effect; the journal halted, so the rejection can't be
            // recorded either: the restart resolves it (it stays accepted).
            return;
        }
        let now = self.now;
        let e = self.receipts.get_mut(rid).unwrap();
        if matches!(e.stored.kind, ReceiptKind::Interrupt | ReceiptKind::Stop) {
            e.observe_deadline = Some(now.saturating_add(OBSERVE_MS));
        }
        let s = &e.stored;
        if let Some(a) = answer {
            self.hand_off(rid, &target, a);
            return;
        }
        let effect = Effect::Dispatch {
            request_id: rid.to_string(),
            target: s.target.clone(),
            kind: s.kind,
            payload,
        };
        self.out.push(effect);
    }

    // ── Approvals (r7) ──

    /// The runtime opens an agent permission prompt for `session_id`'s
    /// process `process_gen` at monotonic `now` (timers due by then fire
    /// first). Refused (`Err`: the agent's own prompt asks) unless the
    /// session runs that process, the info is within bounds and fewer than
    /// `MAX_PENDING_APPROVALS` are pending — whoever holds the lease.
    /// Subscribed attachments with `control` get `approval_request`, and the
    /// relay is asked to push it (`Effect::PushApproval`). The effects are
    /// returned either way.
    pub fn open_approval(
        &mut self,
        session_id: &str,
        process_gen: &str,
        info: ApprovalInfo,
        now: u64,
    ) -> (Result<String, String>, Vec<Effect>) {
        self.tick(now);
        let opened = self.open_checked(session_id, process_gen, info);
        (opened, self.take())
    }

    fn open_checked(
        &mut self,
        session_id: &str,
        process_gen: &str,
        info: ApprovalInfo,
    ) -> Result<String, String> {
        wire::validate_approval_info(&info.tool, &info.summary, &info.always_rules)?;
        if self.halted || self.journal_halted {
            // Nobody could answer it: the agent's own prompt asks.
            return Err("host halted".into());
        }
        self.sessions
            .get(session_id)
            .filter(|s| s.state == SessionState::Running && s.spec.process_gen == process_gen)
            .ok_or("no running session with that process")?;
        let pending = self
            .approvals
            .values()
            .filter(|a| a.request.session_id == session_id && a.handed_off.is_none())
            .count();
        if pending >= MAX_PENDING_APPROVALS {
            return Err("too many pending approvals".into());
        }
        let approval_id = self.new_id();
        let request = ApprovalRequest {
            approval_id: approval_id.clone(),
            session_id: session_id.to_string(),
            process_gen: process_gen.to_string(),
            tool: info.tool,
            summary: info.summary,
            created_at: self.wall(),
            always_rules: info.always_rules,
        };
        self.approvals_opened += 1;
        self.approvals.insert(
            approval_id.clone(),
            Approval {
                request: request.clone(),
                order: self.approvals_opened,
                handed_off: None,
                handoff_deadline: None,
            },
        );
        for att in self.approval_viewers() {
            self.send(&att, None, Op::ApprovalRequest(request.clone()));
        }
        self.out.push(Effect::PushApproval { request });
        Ok(approval_id)
    }

    /// The runtime saw the approval end without the remote answer: answered
    /// in the terminal, interrupted (Esc), timed out, or the process ended.
    /// A pending one closes for viewers; one whose remote answer was already
    /// handed over finishes `outcome_unknown` (the answers crossed, or the
    /// agent never confirmed it). `answered_remote` is the host's own reason
    /// and is ignored here, as are unknown ids.
    pub fn close_approval(
        &mut self,
        approval_id: &str,
        reason: ApprovalCloseReason,
    ) -> Vec<Effect> {
        // The host owns the remote hand-off.
        if reason == ApprovalCloseReason::AnsweredRemote {
            return Vec::new();
        }
        let Some(a) = self.approvals.remove(approval_id) else {
            return Vec::new();
        };
        match a.handed_off {
            Some(rid) => {
                let detail = match reason {
                    ApprovalCloseReason::AnsweredTerminal => DETAIL_APPROVAL_CROSSED,
                    ApprovalCloseReason::ProcessEnded => DETAIL_AGENT_EXITED,
                    _ => DETAIL_APPROVAL_UNCONFIRMED,
                };
                self.finish(&rid, ReceiptState::OutcomeUnknown, Some(detail));
            }
            None => self.approval_closed(approval_id, reason),
        }
        self.take()
    }

    /// The agent's report on a handed-over answer: applied (`completed`), or
    /// not known to be (`outcome_unknown`: the terminal's answer may have
    /// won). Ignored for anything not handed over.
    pub fn approval_applied(&mut self, approval_id: &str, ok: bool) -> Vec<Effect> {
        let rid = match self.approvals.get(approval_id) {
            Some(Approval {
                handed_off: Some(rid),
                ..
            }) => rid.clone(),
            _ => return Vec::new(),
        };
        self.approvals.remove(approval_id);
        if ok {
            self.finish(&rid, ReceiptState::Completed, None);
        } else {
            self.finish(
                &rid,
                ReceiptState::OutcomeUnknown,
                Some(DETAIL_APPROVAL_CROSSED),
            );
        }
        self.take()
    }

    /// Pending (not yet answered) approvals of `session_id`, in opening order.
    pub fn pending_approvals(&self, session_id: &str) -> Vec<String> {
        let mut pending: Vec<&Approval> = self
            .approvals
            .values()
            .filter(|a| a.request.session_id == session_id && a.handed_off.is_none())
            .collect();
        pending.sort_by_key(|a| a.order);
        pending
            .into_iter()
            .map(|a| a.request.approval_id.clone())
            .collect()
    }

    /// The answer names an approval pending for exactly this target's
    /// session and process, and (for `allow_always`) one of its rules.
    fn answerable(&self, t: &Target, answer: &ApprovalAnswer) -> bool {
        self.approvals.get(&answer.approval_id).is_some_and(|a| {
            let r = &a.request;
            a.handed_off.is_none()
                && r.session_id == t.session_id
                && r.process_gen == t.process_gen
                && answer
                    .rule_id
                    .as_ref()
                    .is_none_or(|id| r.always_rules.iter().any(|x| &x.rule_id == id))
        })
    }

    /// `executing` is durable: the approval closes for viewers
    /// (`answered_remote`) and the decision goes to the agent.
    fn hand_off(&mut self, rid: &str, target: &Target, a: ApprovalAnswer) {
        let deadline = self.now.saturating_add(APPROVAL_HANDOFF_MS);
        if let Some(entry) = self.approvals.get_mut(&a.approval_id) {
            entry.handed_off = Some(rid.to_string());
            entry.handoff_deadline = Some(deadline);
        }
        self.approval_closed(&a.approval_id, ApprovalCloseReason::AnsweredRemote);
        self.out.push(Effect::Approval {
            request_id: rid.to_string(),
            session_id: target.session_id.clone(),
            approval_id: a.approval_id,
            decision: a.decision,
            rule_id: a.rule_id,
            message: a.message,
        });
    }

    /// Tells every attachment that got the approval that it closed, and
    /// resolves its push.
    fn approval_closed(&mut self, approval_id: &str, reason: ApprovalCloseReason) {
        for att in self.approval_viewers() {
            let op = Op::ApprovalClosed {
                approval_id: approval_id.to_string(),
                reason,
            };
            self.send(&att, None, op);
        }
        self.out.push(Effect::PushResolved {
            approval_id: approval_id.to_string(),
            reason,
        });
    }

    /// Subscribed attachments that may answer approvals (`control`).
    fn approval_viewers(&self) -> Vec<String> {
        self.subscribers()
            .into_iter()
            .filter(|id| self.attachments[id].can(Permission::Control))
            .collect()
    }

    /// Closes `sid`'s pending approvals (the host's decision: the process
    /// ended) and has the runtime answer them "no decision".
    fn close_pending(&mut self, sid: &str, reason: ApprovalCloseReason) {
        let ids = self.pending_approvals(sid);
        for id in ids {
            self.approvals.remove(&id);
            self.approval_closed(&id, reason);
            self.out.push(Effect::ApprovalReleased {
                session_id: sid.to_string(),
                approval_id: id,
            });
        }
    }

    /// Forgets handed-off approvals whose receipt is final (e.g. finished
    /// with the process); the agent's report on them would change nothing.
    fn forget_finished_approvals(&mut self) {
        let receipts = &self.receipts;
        self.approvals.retain(|_, a| {
            a.handed_off.as_ref().is_none_or(|rid| {
                receipts
                    .get(rid)
                    .is_some_and(|e| !journal::is_final(e.stored.state))
            })
        });
    }

    // ── Atem session rules (r7.2) ──

    /// The runtime's report of `session_id`'s active session rules for its
    /// process `process_gen` (the worker owns them). A change goes to every
    /// subscribed attachment with `control` as `approval_rules`. Refused
    /// for another process or out-of-bounds rules.
    pub fn set_approval_rules(
        &mut self,
        session_id: &str,
        process_gen: &str,
        rules: Vec<AlwaysRule>,
    ) -> Result<Vec<Effect>, String> {
        wire::validate_session_rules(&rules)?;
        self.sessions
            .get(session_id)
            .filter(|s| s.state == SessionState::Running && s.spec.process_gen == process_gen)
            .ok_or("no running session with that process")?;
        let unchanged = self
            .rules
            .get(session_id)
            .is_some_and(|(g, r)| g == process_gen && *r == rules)
            || (rules.is_empty() && !self.rules.contains_key(session_id));
        if !unchanged {
            if rules.is_empty() {
                self.rules.remove(session_id);
            } else {
                self.rules.insert(
                    session_id.to_string(),
                    (process_gen.to_string(), rules.clone()),
                );
            }
            self.rules_changed(session_id, process_gen, rules);
        }
        Ok(self.take())
    }

    /// `session_id`'s active session rules (none for an unknown session).
    pub fn approval_rules(&self, session_id: &str) -> Vec<AlwaysRule> {
        self.rules
            .get(session_id)
            .map(|(_, r)| r.clone())
            .unwrap_or_default()
    }

    /// `rule_id` is one of the target process's active rules.
    fn rule_active(&self, t: &Target, rule_id: &str) -> bool {
        self.rules
            .get(&t.session_id)
            .is_some_and(|(g, r)| *g == t.process_gen && r.iter().any(|x| x.rule_id == rule_id))
    }

    fn rules_changed(&mut self, sid: &str, process_gen: &str, rules: Vec<AlwaysRule>) {
        for att in self.approval_viewers() {
            let op = Op::ApprovalRules {
                session_id: sid.to_string(),
                process_gen: process_gen.to_string(),
                rules: rules.clone(),
            };
            self.send(&att, None, op);
        }
    }

    /// The process ended: its rules went with it (an empty list says so).
    fn clear_rules(&mut self, sid: &str) {
        if let Some((process_gen, _)) = self.rules.remove(sid) {
            self.rules_changed(sid, &process_gen, Vec::new());
        }
    }

    /// Welcomed attachments subscribed to the registry (`list`) with `view`.
    fn subscribers(&self) -> Vec<String> {
        self.attachments
            .iter()
            .filter(|(_, a)| a.registry_seq.is_some() && a.can(Permission::View))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Persists and applies one transition, then tells the submitter.
    /// `false` (nothing changed) when the durable write fails.
    fn transition(&mut self, rid: &str, to: ReceiptState, detail: Option<&str>) -> bool {
        let Some(e) = self.receipts.get(rid) else {
            return false;
        };
        let from = e.stored.state;
        if !journal::valid_transition(from, to) {
            return false;
        }
        let updated_at = self.wall();
        let detail = detail.map(str::to_string);
        let record = Record::Transition {
            request_id: rid.to_string(),
            state: to,
            detail: detail.clone(),
            updated_at,
        };
        if !self.append(record) {
            return false;
        }
        let e = self.receipts.get_mut(rid).unwrap();
        e.stored.state = to;
        e.stored.detail = detail;
        e.stored.updated_at = updated_at;
        e.stored.payload = None;
        let kind = e.stored.kind;
        let sid = e.stored.target.session_id.clone();
        let reply = match e.chat.clone() {
            // chat-v1 has no `executing`: the turn just runs.
            Some(_) if to == ReceiptState::Executing => None,
            Some(conversation_id) => Some(Reply::Chat { conversation_id }),
            None => Some(Reply::Session(None)),
        };
        if let (Some(att), Some(reply)) = (e.submitted_by.clone(), reply) {
            self.report_state(&att, reply, rid);
        }
        if from == ReceiptState::Executing && kind == ReceiptKind::Prompt {
            self.pump_queue(&sid);
        }
        true
    }

    /// A transition to a final state, reported once durable. If the write
    /// fails the journal halts (r8 §I.6) and the receipt stays where it was
    /// until the restart resolves it.
    fn finish(&mut self, rid: &str, to: ReceiptState, detail: Option<&str>) {
        self.transition(rid, to, detail);
    }

    /// Only receipts bound to exactly the binding's target; ids of other
    /// targets are simply absent.
    fn receipt_query(
        &mut self,
        att: &str,
        re: Option<String>,
        b: &Binding,
        request_ids: &[String],
    ) -> Checked {
        let a = &self.attachments[att];
        if b.attachment_gen != att || !self.same_host(&b.target) {
            return Err(ErrorCode::StaleTarget);
        }
        // Receipts stay addressable by session_id/process_gen (§3), so an
        // earlier process_gen of a visible session may be queried.
        if !a.can(Permission::View) || !self.sessions.contains_key(&b.target.session_id) {
            return Err(ErrorCode::UnknownSession);
        }
        let mut seen = Vec::new();
        let receipts: Vec<Receipt> = request_ids
            .iter()
            .filter(|rid| {
                let first = !seen.contains(rid);
                seen.push(*rid);
                first
            })
            .filter_map(|rid| self.receipts.get(rid))
            .filter(|e| e.stored.target == b.target)
            .map(|e| to_receipt(&e.stored))
            .collect();
        self.send(att, re, Op::Receipts { receipts });
        Ok(())
    }

    // ── terminal-v1 and chat-v1 (§2) ──

    fn on_family(&mut self, att: &str, f: FamilyMessage) {
        let result = match f.family.as_str() {
            "terminal" | "agentChat" => self.admit_request(att).and_then(|()| {
                if f.family == "terminal" {
                    self.on_terminal(att, &f)
                } else {
                    self.on_chat(att, &f)
                }
            }),
            // Not session traffic: nothing to authorize here.
            _ => Ok(()),
        };
        if let Err(code) = result {
            let refused = std::mem::take(&mut self.refused);
            if refused.close {
                // r8 §I.4: no durable refusal, no reply.
                self.drop_attachment(att);
                self.out.push(Effect::Close {
                    attachment: att.to_string(),
                });
            } else {
                self.family_error(att, &f, code, refused.detail, refused.controller);
            }
        }
        self.refused = Refused::default();
    }

    /// A refused terminal-v1 or chat-v1 request is answered in its own family
    /// (removed forms never get here: they fail decoding and get a session
    /// `error`). Nothing about other targets is disclosed.
    fn family_error(
        &mut self,
        att: &str,
        f: &FamilyMessage,
        code: ErrorCode,
        detail: Option<&'static str>,
        controller: Option<Controller>,
    ) {
        let field = |name: &str| {
            f.data
                .as_ref()
                .and_then(|d| d.get(name))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        match f.family.as_str() {
            "terminal" => {
                let mut data = json!({
                    "v": 1,
                    "op": "error",
                    "terminal_id": field("terminal_id"),
                    "code": code_name(code),
                    "message": code_text(code),
                });
                if let Some(stream_id) = field("stream_id") {
                    data["stream_id"] = Value::String(stream_id);
                }
                self.out.push(Effect::Send {
                    attachment: att.to_string(),
                    message: Envelope::Family(FamilyMessage {
                        family: "terminal".into(),
                        data: Some(data),
                        binding: None,
                        request: None,
                    }),
                });
            }
            "agentChat" => {
                let submit = field("op").as_deref() == Some("submit");
                self.out.push(Effect::Chat {
                    attachment: att.to_string(),
                    conversation_id: field("conversationId").unwrap_or_default(),
                    session_id: field("agentId").unwrap_or_default(),
                    reply: ChatReply::Error {
                        request_id: field("requestId").filter(|_| submit),
                        code: code_name(code),
                        text: detail.unwrap_or(code_text(code)).to_string(),
                        sequenced: !f.data.as_ref().is_some_and(refused_chat_form),
                        controller,
                    },
                });
            }
            _ => self.error(att, None, code, None),
        }
    }

    fn on_terminal(&mut self, att: &str, f: &FamilyMessage) -> Checked {
        // Host-only terminal ops (frame, attached, …) are not requests.
        let (Some(req), Some(b)) = (&f.request, &f.binding) else {
            return Err(ErrorCode::UnsupportedVersion);
        };
        let s = self.check_binding(att, b)?.clone();
        f.check_binding_ids()?;
        let sid = s.spec.session_id.clone();
        let stream = |host: &Self, stream_id: &str| -> Checked {
            let current = host.attachments[att].streams.get(&sid);
            if current.map(String::as_str) == Some(stream_id) {
                Ok(())
            } else {
                Err(ErrorCode::StaleTarget)
            }
        };
        match req {
            TerminalRequest::Subscribe { .. } => {
                let stream_id = self.new_id();
                let info = crate::terminal_share::SessionInfo {
                    terminal_id: sid.clone(),
                    generation: s.spec.process_gen.clone(),
                    provider: s.spec.provider.clone(),
                    rows: s.spec.rows,
                    cols: s.spec.cols,
                    exit_status: s.exit_status.clone(),
                    rendering: "vt100-screen-diff".into(),
                    width_profile: "atem-unicode-width-0.1.14".into(),
                };
                let attached = crate::terminal_share::Envelope::from(
                    crate::terminal_share::Message::Attached {
                        session: info,
                        stream_id: stream_id.clone(),
                    },
                );
                let replaced = self
                    .attachments
                    .get_mut(att)
                    .unwrap()
                    .streams
                    .insert(sid.clone(), stream_id.clone());
                if let Some(old) = replaced {
                    self.out.push(Effect::StreamClosed {
                        attachment: att.to_string(),
                        session_id: sid.clone(),
                        stream_id: old,
                    });
                }
                let data = serde_json::to_value(attached).expect("terminal message serializes");
                self.out.push(Effect::Send {
                    attachment: att.to_string(),
                    message: Envelope::Family(FamilyMessage {
                        family: "terminal".into(),
                        data: Some(data),
                        binding: None,
                        request: None,
                    }),
                });
                self.out.push(Effect::StreamOpened {
                    attachment: att.to_string(),
                    session_id: sid,
                    stream_id,
                });
            }
            TerminalRequest::Unsubscribe { stream_id, .. } => {
                stream(self, stream_id)?;
                self.attachments.get_mut(att).unwrap().streams.remove(&sid);
                self.out.push(Effect::StreamClosed {
                    attachment: att.to_string(),
                    session_id: sid,
                    stream_id: stream_id.clone(),
                });
            }
            TerminalRequest::Ack { stream_id, .. } => {
                stream(self, stream_id)?;
                self.out.push(Effect::Forward {
                    attachment: att.to_string(),
                    session_id: sid,
                    message: f.clone(),
                });
            }
            TerminalRequest::Input {
                stream_id,
                sequence,
                bytes,
                ..
            } => {
                stream(self, stream_id)?;
                self.check_mutation(att, &s, b.lease_epoch)?;
                use base64::{Engine, engine::general_purpose::STANDARD};
                let bytes = STANDARD
                    .decode(bytes)
                    .map_err(|_| ErrorCode::UnsupportedVersion)?;
                let origin = Origin::Remote {
                    input_epoch: s.input_epoch,
                    attachment: att.to_string(),
                    stream_id: stream_id.clone(),
                    sequence: *sequence,
                };
                self.out.push(Effect::PtyWrite {
                    session_id: sid,
                    bytes,
                    origin,
                });
            }
            TerminalRequest::Resize {
                stream_id,
                rows,
                cols,
                ..
            } => {
                stream(self, stream_id)?;
                self.check_mutation(att, &s, b.lease_epoch)?;
                let s = self.sessions.get_mut(&sid).unwrap();
                s.spec.rows = *rows;
                s.spec.cols = *cols;
                self.out.push(Effect::Resize {
                    session_id: sid,
                    rows: *rows,
                    cols: *cols,
                });
            }
            TerminalRequest::Stop { stream_id, .. } => {
                stream(self, stream_id)?;
                self.check_mutation(att, &s, b.lease_epoch)?;
                self.out.push(Effect::Stop { session_id: sid });
            }
        }
        Ok(())
    }

    /// chat-v1 `submit` is the §6 `submit` (`kind:"prompt"`, `request_id =
    /// requestId`, `payload = {"text": text}`); `open`/`close` are reads the
    /// runtime serves.
    fn on_chat(&mut self, att: &str, f: &FamilyMessage) -> Checked {
        let Some(b) = &f.binding else {
            // Host-only chat ops are not requests.
            return Err(ErrorCode::UnsupportedVersion);
        };
        if f.data.as_ref().is_some_and(refused_chat_form) {
            return Err(ErrorCode::UnsupportedVersion);
        }
        let s = self.check_binding(att, b)?;
        f.check_binding_ids()?;
        if !s.spec.chat {
            return Err(ErrorCode::UnknownSession);
        }
        let sid = s.spec.session_id.clone();
        let data = f.data.as_ref().ok_or(ErrorCode::UnsupportedVersion)?;
        match data["op"].as_str() {
            // A session rule revoked from chat (r7.3: `control`, no lease).
            Some("submit") if data.get(wire::RULE_REVOKE_FIELD).is_some() => {
                let request_id = data["requestId"]
                    .as_str()
                    .ok_or(ErrorCode::UnsupportedVersion)?
                    .to_string();
                let payload = data[wire::RULE_REVOKE_FIELD].clone();
                let reply = Reply::Chat {
                    conversation_id: data["conversationId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                };
                let send = chat_send_params(data)?;
                self.submit(
                    att,
                    reply,
                    b,
                    &request_id,
                    ReceiptKind::ApprovalRuleRevoke,
                    payload,
                    send,
                )
            }
            Some("submit") if data.get("approval").is_some() => {
                let request_id = data["requestId"]
                    .as_str()
                    .ok_or(ErrorCode::UnsupportedVersion)?
                    .to_string();
                let payload = data["approval"].clone();
                let reply = Reply::Chat {
                    conversation_id: data["conversationId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                };
                // §G: `acquire` beside an answer is the removed r7 form
                // (`send_rules` refuses it `unsupported_version`).
                let send = chat_send_params(data)?;
                self.submit(
                    att,
                    reply,
                    b,
                    &request_id,
                    ReceiptKind::Approval,
                    payload,
                    send,
                )
            }
            Some("submit") => {
                let text = data["text"].as_str().ok_or(ErrorCode::UnsupportedVersion)?;
                let request_id = data["requestId"]
                    .as_str()
                    .ok_or(ErrorCode::UnsupportedVersion)?;
                if text.len() > MAX_PROMPT_BYTES {
                    return Err(ErrorCode::UnsupportedVersion);
                }
                let payload = json!({ "text": text });
                let request_id = request_id.to_string();
                let reply = Reply::Chat {
                    conversation_id: data["conversationId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                };
                // §F: the same admission parameters as the session form.
                let send = chat_send_params(data)?;
                self.submit(
                    att,
                    reply,
                    b,
                    &request_id,
                    ReceiptKind::Prompt,
                    payload,
                    send,
                )
            }
            Some("open" | "close") => {
                self.out.push(Effect::Forward {
                    attachment: att.to_string(),
                    session_id: sid,
                    message: f.clone(),
                });
                Ok(())
            }
            _ => Err(ErrorCode::UnsupportedVersion),
        }
    }
}

/// The §F admission parameters beside a chat-v1 `submit` (`acquire`,
/// `takeover`, `expected_controller`); a value of the wrong type fails
/// decoding (`unsupported_version`), the field rules are `send_rules`'.
fn chat_send_params(data: &Value) -> Checked<SendParams> {
    fn field<T: serde::de::DeserializeOwned>(data: &Value, name: &str) -> Checked<Option<T>> {
        data.get(name)
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|_| ErrorCode::UnsupportedVersion)
    }
    Ok(SendParams {
        acquire: field(data, "acquire")?,
        takeover: field(data, "takeover")?,
        expected_controller: field(data, "expected_controller")?,
    })
}

/// How a submitter hears about its request.
#[derive(Debug, Clone)]
enum Reply {
    /// session-v1 `receipt` (with `re` for the direct reply).
    Session(Option<String>),
    /// chat-v1 `accepted` / `complete` / `error`.
    Chat { conversation_id: String },
}

/// A chat submit's current state in chat-v1 terms.
fn chat_reply(e: &Entry) -> ChatReply {
    let s = &e.stored;
    let request_id = s.request_id.clone();
    let error = |code: &str| ChatReply::Error {
        request_id: Some(request_id.clone()),
        code: code.to_string(),
        text: s.detail.clone().unwrap_or_default(),
        sequenced: true,
        controller: None,
    };
    match s.state {
        ReceiptState::Accepted | ReceiptState::Executing => ChatReply::Accepted {
            request_id: request_id.clone(),
            lease: None,
        },
        ReceiptState::Completed => ChatReply::Complete {
            request_id: request_id.clone(),
            turn_id: e.turn_id.clone(),
            interrupted: s.kind == ReceiptKind::Prompt
                && s.detail.as_deref() == Some(DETAIL_TURN_INTERRUPTED),
        },
        ReceiptState::Rejected => error("rejected"),
        ReceiptState::OutcomeUnknown => error("outcome_unknown"),
    }
}

/// chat-v1 forms r8 refuses before anything else (§A), answered with an
/// unsequenced `unsupported_version`: `open.before`/`open.generation` (the
/// r7.2 paging form, removed: never read as an open of the newest page; an
/// open conversation is not reset and none opens) and `history`
/// (`chat.history`/`chat.lookup`, not advertised yet).
// TODO(r8 task 5): serve `history` once those features ship.
fn refused_chat_form(data: &Value) -> bool {
    let removed_open =
        data["op"] == "open" && (data.get("before").is_some() || data.get("generation").is_some());
    removed_open || data["op"] == "history"
}

/// The wire name of a §7 code.
pub fn code_name(code: ErrorCode) -> String {
    match serde_json::to_value(code) {
        Ok(Value::String(s)) => s,
        _ => unreachable!("error codes serialize as strings"),
    }
}

/// Fixed human text per code: never paths, OS errors or other targets' ids.
pub fn code_text(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::UnsupportedVersion => "unsupported request",
        ErrorCode::Unauthorized => "not authorized",
        ErrorCode::Forbidden => "not permitted",
        ErrorCode::StaleTarget => "the session changed; list again",
        ErrorCode::UnknownSession => "unknown session",
        ErrorCode::LeaseHeld => "another controller holds control",
        ErrorCode::StaleLease => "control lease is not current",
        ErrorCode::RequestIdReused => "request id already used",
        ErrorCode::ReceiptLimit => "too many requests for this session",
        ErrorCode::SessionClosed => "the session no longer accepts requests",
        ErrorCode::Busy => "busy; try again",
        ErrorCode::Paused => "authorization expired; control paused",
        ErrorCode::InvalidRequest => "invalid request",
    }
}

fn to_receipt(s: &Stored) -> Receipt {
    Receipt {
        request_id: s.request_id.clone(),
        target: s.target.clone(),
        kind: s.kind,
        state: s.state,
        detail: s.detail.clone(),
        updated_at: s.updated_at,
        lease: None,
    }
}

/// `detail` is bounded (§1); cut at a char boundary.
fn bounded_detail(d: &str) -> String {
    let mut end = d.len().min(wire::MAX_DETAIL_BYTES);
    while !d.is_char_boundary(end) {
        end -= 1;
    }
    d[..end].to_string()
}

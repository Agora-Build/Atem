//! The host authority for atem-session v1 (contract r6, compatibility mode):
//! attachments and hello/welcome (§3), the session registry with a
//! per-attachment `seq` (§4), control leases with input-epoch fencing (§5),
//! submissions with durable receipts (§6) and errors without disclosure (§7).
//!
//! `SessionHost` is pure: it never touches sockets, PTYs, processes or files.
//! Time is the injected monotonic clock (`advance`); every input returns the
//! `Effect`s the runtime must perform, in order. Durability goes through the
//! `Journal`: a receipt state is reported only after its record is durable.
//!
//! There are no legacy paths (§0): removed message families and ops are
//! answered `unsupported_version` and change nothing, and every remote
//! mutation is a session-v1 request (or a bound terminal-v1/chat-v1 request)
//! carrying `binding` and the current lease, after `welcome`.
//!
//! The PTY write boundary is the runtime's: right before writing a queued
//! remote chunk it calls `admit_write(session, input_epoch)`; transfer,
//! expiry, release, revoke and local input bump the epoch first, so bytes
//! queued under an older lease are dropped, never written.

use super::canonical::{self, MAX_SAFE_INTEGER};
use super::journal::{self, Journal, JournalError, Record, Stored};
use super::wire::{
    self, Activity, Binding, ClientKind, Controller, DecodeError, Descriptor, Envelope, ErrorCode,
    FamilyMessage, LeaseChangeReason, MAX_IN_FLIGHT, MAX_PROMPT_BYTES, Op, Permission, Receipt,
    ReceiptKind, ReceiptState, SessionMessage, SessionState, Target, TerminalRequest,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// A lease lasts this long from its grant or renewal (§5).
pub const LEASE_MS: u64 = 15_000;
/// Removed sessions answer `unknown_session` for this long (§4).
pub const TOMBSTONE_MS: u64 = 10 * 60 * 1000;
/// Receipts outlive their session's close by this long (§6).
pub const RECEIPT_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// An interrupt or stop that shows no effect within this is `outcome_unknown`.
pub const OBSERVE_MS: u64 = 10_000;
/// Lease epochs are reserved durably in blocks, so an epoch is never issued
/// twice across restarts without an fsync per grant.
const LEASE_EPOCH_BLOCK: u64 = 64;
/// Default per-session receipt bound (`receipt_limit` beyond it).
pub const DEFAULT_MAX_RECEIPTS: usize = 4096;

pub const DETAIL_APPROVAL: &str = "approval answers are not supported in v1";
pub const DETAIL_TRUST_CHANGED: &str = "host trust changed";
pub const DETAIL_SESSION_CLOSED: &str = "session closed";
pub const DETAIL_NOT_RECORDED: &str = "could not record the request";
pub const DETAIL_NO_TERMINAL_WRITE: &str = "could not write to the terminal";
pub const DETAIL_WRITE_INTERRUPTED: &str = "write interrupted";
pub const DETAIL_AGENT_EXITED: &str = "agent exited";
pub const DETAIL_NO_INTERRUPT: &str = "no interrupt observed";
pub const DETAIL_INTERRUPT_NOT_SENT: &str = "could not send the interrupt";
pub const DETAIL_STOP_FAILED: &str = "stop failed";
pub const DETAIL_STILL_RUNNING: &str = "process still running";
pub const DETAIL_UNRECONCILED: &str = "outcome could not be established";
pub const DETAIL_REPAIR: &str = "host counters exhausted; pair again";

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
    /// From the lease holder; written only if `admit_write(input_epoch)`
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
}

/// What the runtime observed for a dispatched (or reconciled) request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchReport {
    /// The kind's completion (§6 table) was observed.
    Completed { detail: Option<String> },
    /// Failed with proof that nothing reached the agent (e.g. the PTY
    /// reservation failed, the signal could not be delivered).
    FailedNoEffect,
    /// Failed after a possible partial effect (e.g. the writer errored).
    FailedAfterPossibleEffect,
    /// Reconciliation could not establish the outcome.
    Unknown,
}

// ── State ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Lease {
    attachment: String,
    controller_session: String,
    deadline: u64,
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
    controller_session: Option<String>,
    permissions: Vec<Permission>,
    client_kind: ClientKind,
    authorization_deadline: u64,
    /// Registry messages sent in this epoch, once subscribed by `list`.
    registry_seq: Option<u64>,
    /// session_id → terminal-v1 stream id.
    streams: HashMap<String, String>,
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
    /// A final state is waiting for a durable write (retried on `advance`).
    finishing: bool,
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
    lease_floors: HashMap<String, u64>,
    /// Admission order of the next new request.
    next_order: u64,
    /// Final transitions whose durable write failed, retried on `advance`.
    retry: Vec<(String, ReceiptState, Option<String>)>,
    out: Vec<Effect>,
}

type Checked<T = ()> = Result<T, ErrorCode>;

impl<J: Journal> SessionHost<J> {
    /// A host over `journal`, reloading what it holds (apply the crash rules
    /// with `recover` once the surviving sessions are registered).
    pub fn new(
        ctx: HostContext,
        config: HostConfig,
        journal: J,
        ids: IdSource,
    ) -> Result<Self, JournalError> {
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
            lease_floors: HashMap::new(),
            next_order: 0,
            retry: Vec::new(),
            out: Vec::new(),
        };
        host.reload()?;
        Ok(host)
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

    /// Registers an agent session (new or surviving a broker restart).
    pub fn add_session(&mut self, spec: SessionSpec) -> Result<Vec<Effect>, String> {
        if !wire::is_session_id(&spec.session_id) || !wire::is_uuid_v4(&spec.process_gen) {
            return Err("invalid session_id or process_gen".into());
        }
        if self.sessions.contains_key(&spec.session_id)
            || self.tombstones.contains_key(&spec.session_id)
        {
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
    pub fn connect(&mut self, a: Attach) -> Result<Vec<Effect>, String> {
        if !wire::is_uuid_v4(&a.attachment_gen) || self.attachments.contains_key(&a.attachment_gen)
        {
            return Err("attachment_gen must be a new UUID v4".into());
        }
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
                controller_session: None,
                permissions: a.permissions,
                client_kind: a.client_kind,
                authorization_deadline: deadline,
                registry_seq: None,
                streams: HashMap::new(),
            },
        );
        Ok(self.take())
    }

    /// The transport closed. A held lease is not released: it expires.
    pub fn disconnect(&mut self, attachment: &str) -> Vec<Effect> {
        self.drop_attachment(attachment);
        self.take()
    }

    fn drop_attachment(&mut self, id: &str) {
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
        for (rid, state, detail) in std::mem::take(&mut self.retry) {
            self.persist_final(&rid, state, detail);
        }
        let unobserved: Vec<(String, ReceiptKind)> = self
            .receipts
            .values()
            .filter(|e| !e.finishing && e.stored.state == ReceiptState::Executing)
            .filter(|e| e.observe_deadline.is_some_and(|d| now >= d))
            .map(|e| (e.stored.request_id.clone(), e.stored.kind))
            .collect();
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
        self.take()
    }

    fn evict_receipts(&mut self, sid: &str) {
        let ids: Vec<String> = self
            .receipts
            .values()
            .filter(|e| e.stored.target.session_id == sid)
            .map(|e| e.stored.request_id.clone())
            .collect();
        for rid in ids {
            let record = Record::Evicted {
                request_id: rid.clone(),
            };
            if self.journal.append(record).is_err() {
                return; // retried on the next advance
            }
            self.receipts.remove(&rid);
        }
        self.ended.remove(sid);
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

    /// Called by the PTY writer right before writing a queued remote chunk.
    pub fn admit_write(&self, session_id: &str, input_epoch: u64) -> bool {
        self.sessions
            .get(session_id)
            .is_some_and(|s| s.input_epoch == input_epoch && s.lease.is_some())
    }

    /// The outcome of a `Dispatch` or `Reconcile`.
    pub fn dispatch_report(&mut self, request_id: &str, report: DispatchReport) -> Vec<Effect> {
        let Some(e) = self.receipts.get(request_id) else {
            return Vec::new();
        };
        if e.finishing || e.stored.state != ReceiptState::Executing {
            return Vec::new();
        }
        let kind = e.stored.kind;
        let (state, detail) = match report {
            DispatchReport::Completed { detail } => {
                let detail = detail.map(|d| bounded_detail(&d));
                (ReceiptState::Completed, detail)
            }
            DispatchReport::FailedNoEffect => (
                ReceiptState::Rejected,
                Some(
                    match kind {
                        ReceiptKind::Prompt | ReceiptKind::Approval => DETAIL_NO_TERMINAL_WRITE,
                        ReceiptKind::Interrupt => DETAIL_INTERRUPT_NOT_SENT,
                        ReceiptKind::Stop => DETAIL_STOP_FAILED,
                    }
                    .to_string(),
                ),
            ),
            DispatchReport::FailedAfterPossibleEffect => (
                ReceiptState::OutcomeUnknown,
                Some(DETAIL_WRITE_INTERRUPTED.to_string()),
            ),
            DispatchReport::Unknown => (
                ReceiptState::OutcomeUnknown,
                Some(DETAIL_UNRECONCILED.to_string()),
            ),
        };
        self.finish(request_id, state, detail.as_deref());
        self.take()
    }

    /// The agent process ended: its lease ends, a `stop` completes, other
    /// executing work is `outcome_unknown` ("agent exited") and accepted work
    /// is rejected.
    pub fn process_exited(&mut self, session_id: &str, exit_status: Option<String>) -> Vec<Effect> {
        let wall = self.wall();
        let Some(s) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };
        if s.state != SessionState::Running {
            return Vec::new();
        }
        s.state = SessionState::Exited;
        s.activity = Activity::Unknown;
        s.exit_status = exit_status;
        s.activity_since = wall;
        self.end_lease(session_id, LeaseChangeReason::ProcessEnded, None);
        let process_gen = self.sessions[session_id].spec.process_gen.clone();
        let work: Vec<(String, ReceiptState, ReceiptKind)> = self
            .receipts
            .values()
            .filter(|e| {
                e.stored.target.session_id == session_id
                    && e.stored.target.process_gen == process_gen
            })
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
        self.registry_changed(session_id);
        self.take()
    }

    /// The session no longer accepts submissions; its receipts are kept for
    /// `RECEIPT_RETENTION_MS`.
    pub fn close_session(&mut self, session_id: &str) -> Vec<Effect> {
        let Some(s) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };
        s.state = SessionState::Closed;
        self.ended.entry(session_id.to_string()).or_insert(self.now);
        self.end_lease(session_id, LeaseChangeReason::Revoked, None);
        self.reject_accepted(|t| t.session_id == session_id, DETAIL_SESSION_CLOSED);
        self.registry_changed(session_id);
        self.take()
    }

    /// Removes the session: subscribers get its last descriptor with
    /// `state:"removed"`; late requests get `unknown_session`.
    pub fn remove_session(&mut self, session_id: &str) -> Vec<Effect> {
        if !self.sessions.contains_key(session_id) {
            return Vec::new();
        }
        self.end_lease(session_id, LeaseChangeReason::Revoked, None);
        self.reject_accepted(|t| t.session_id == session_id, DETAIL_SESSION_CLOSED);
        self.sessions.get_mut(session_id).unwrap().state = SessionState::Removed;
        self.registry_changed(session_id);
        self.sessions.remove(session_id);
        self.tombstones.insert(session_id.to_string(), self.now);
        self.ended.entry(session_id.to_string()).or_insert(self.now);
        for a in self.attachments.values_mut() {
            a.streams.remove(session_id);
        }
        self.take()
    }

    /// The host trust generation moved on (unpair/rebind): every lease is
    /// revoked and work not yet dispatched is rejected ("host trust changed").
    pub fn change_trust_gen(&mut self, host_trust_gen: u64) -> Result<Vec<Effect>, String> {
        if host_trust_gen <= self.ctx.host_trust_gen || host_trust_gen > MAX_SAFE_INTEGER {
            return Err("host_trust_gen must increase".into());
        }
        self.ctx.host_trust_gen = host_trust_gen;
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

    /// A broker restart (new `runtime_gen`, higher `runtime_epoch`): every
    /// attachment and lease is gone, receipts are reloaded from the journal
    /// and the §6 crash rules applied (`recover`). Sessions (workers) stay.
    pub fn restart(
        &mut self,
        runtime_gen: &str,
        runtime_epoch: u64,
    ) -> Result<Vec<Effect>, String> {
        if !wire::is_uuid_v4(runtime_gen) || runtime_gen == self.ctx.runtime_gen {
            return Err("runtime_gen must be a new UUID v4".into());
        }
        if runtime_epoch <= self.ctx.runtime_epoch || runtime_epoch > MAX_SAFE_INTEGER {
            return Err("runtime_epoch must increase".into());
        }
        self.ctx.runtime_gen = runtime_gen.to_string();
        self.ctx.runtime_epoch = runtime_epoch;
        self.attachments.clear();
        self.retry.clear();
        self.out.clear();
        self.reload().map_err(|e| e.0)?;
        for (sid, s) in self.sessions.iter_mut() {
            let floor = self.lease_floors.get(sid).copied().unwrap_or(0);
            s.lease = None;
            s.lease_epoch = floor;
            s.epochs_reserved = floor;
            s.input_epoch += 1;
            s.queued.clear();
        }
        Ok(self.recover())
    }

    fn reload(&mut self) -> Result<(), JournalError> {
        let replayed = journal::replay(self.journal.load()?)?;
        self.receipts = replayed
            .receipts
            .into_iter()
            .map(|(rid, stored)| {
                let entry = Entry {
                    stored,
                    submitted_by: None,
                    observe_deadline: None,
                    finishing: false,
                };
                (rid, entry)
            })
            .collect();
        self.lease_floors = replayed.lease_epochs;
        self.next_order = self
            .receipts
            .values()
            .map(|e| e.stored.order + 1)
            .max()
            .unwrap_or(0);
        Ok(())
    }

    /// §6 crash rules: `executing` work is never dispatched again, only
    /// reconciled; `accepted` work is dispatched once under its original
    /// target if the trust generation is unchanged, else rejected.
    pub fn recover(&mut self) -> Vec<Effect> {
        let mut pending: Vec<&Entry> = self.receipts.values().collect();
        pending.sort_by_key(|e| e.stored.order);
        let pending: Vec<(String, ReceiptState, ReceiptKind, Target)> = pending
            .into_iter()
            .map(|e| {
                let s = &e.stored;
                (s.request_id.clone(), s.state, s.kind, s.target.clone())
            })
            .collect();
        for (rid, state, kind, target) in pending {
            match state {
                ReceiptState::Executing => self.out.push(Effect::Reconcile {
                    request_id: rid,
                    target,
                    kind,
                }),
                ReceiptState::Accepted => self.schedule(&rid),
                _ => {}
            }
        }
        self.take()
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

    /// One message from `attachment`, strictly decoded here.
    pub fn receive(&mut self, attachment: &str, bytes: &[u8]) -> Vec<Effect> {
        self.receive_decoded(attachment, wire::decode(bytes))
    }

    /// One message from `attachment`, already decoded with `wire::decode`.
    pub fn receive_decoded(
        &mut self,
        attachment: &str,
        msg: Result<Envelope, DecodeError>,
    ) -> Vec<Effect> {
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
        self.send(attachment, re, Op::Error { code, detail });
    }

    /// Checks shared by every request after `welcome`.
    fn admit_request(&self, att: &str) -> Checked {
        let a = &self.attachments[att];
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
            Op::Hello { resume } => self.hello(att, re.clone(), resume.is_some()),
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
                } => self.submit(att, re.clone(), &binding, &request_id, kind, payload),
                Op::ReceiptQuery {
                    binding,
                    request_ids,
                } => self.receipt_query(att, re.clone(), &binding, &request_ids),
                // Host-to-client ops are not requests.
                _ => Err(ErrorCode::UnsupportedVersion),
            }),
        };
        if let Err(code) = result {
            let detail = (code == ErrorCode::Busy && self.halted).then_some(DETAIL_REPAIR);
            self.error(att, re, code, detail);
        }
    }

    /// Compatibility mode (§3): no resume; every `hello` on a fresh attachment
    /// gets a new `controller_session` and holds no lease.
    fn hello(&mut self, att: &str, re: Option<String>, resume: bool) -> Checked {
        if resume {
            return Err(ErrorCode::Unauthorized);
        }
        if self.attachments[att].welcomed() {
            // One welcome per attachment; a new one needs a new attachment.
            return Err(ErrorCode::Unauthorized);
        }
        if self.now >= self.attachments[att].authorization_deadline {
            return Err(ErrorCode::Paused);
        }
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
        };
        self.send(att, re, op);
        Ok(())
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
        let holds = s
            .lease
            .as_ref()
            .is_some_and(|l| l.attachment == att && Some(s.lease_epoch) == lease_epoch);
        if !holds {
            return Err(ErrorCode::StaleLease);
        }
        if s.state != SessionState::Running {
            return Err(ErrorCode::SessionClosed);
        }
        Ok(())
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
        Ok(())
    }

    /// Sends the session's complete new descriptor to every subscribed viewer.
    fn registry_changed(&mut self, sid: &str) {
        let Some(descriptor) = self.sessions.get(sid).map(|s| self.descriptor(s)) else {
            return;
        };
        let subscribers: Vec<String> = self
            .attachments
            .iter()
            .filter(|(_, a)| a.registry_seq.is_some() && a.can(Permission::View))
            .map(|(id, _)| id.clone())
            .collect();
        for att in subscribers {
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
        if self.journal.append(record).is_err() {
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
            Some(_) if !takeover => return Err(ErrorCode::LeaseHeld),
            Some((holder, _)) => Some(holder),
            None => None,
        };
        let sid = b.target.session_id.clone();
        if !self.reserve_epochs(&sid, need) {
            return Err(ErrorCode::Busy);
        }
        let deadline = self
            .now
            .saturating_add(LEASE_MS)
            .min(self.attachments[att].authorization_deadline);
        let s = self.sessions.get_mut(&sid).unwrap();
        if previous.is_some() {
            s.input_epoch += 1;
        }
        s.lease_epoch += 1;
        s.lease = Some(Lease {
            attachment: att.to_string(),
            controller_session: controller,
            deadline,
        });
        self.lease_reply(att, re, b);
        let reason = if previous.is_some() {
            LeaseChangeReason::Takeover
        } else {
            LeaseChangeReason::Granted
        };
        self.lease_changed(&sid, reason, Some(att));
        self.registry_changed(&sid);
        Ok(())
    }

    fn holds(&self, att: &str, b: &Binding) -> Checked<()> {
        let s = self.check_binding(att, b)?;
        let holds = s
            .lease
            .as_ref()
            .is_some_and(|l| l.attachment == att && Some(s.lease_epoch) == b.lease_epoch);
        if holds {
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

    fn submit(
        &mut self,
        att: &str,
        re: Option<String>,
        b: &Binding,
        request_id: &str,
        kind: ReceiptKind,
        payload: Value,
    ) -> Checked {
        self.check_binding(att, b)?;
        let digest =
            canonical::payload_digest(&payload).map_err(|_| ErrorCode::UnsupportedVersion)?;
        if let Some(e) = self.receipts.get(request_id) {
            let st = &e.stored;
            if st.target != b.target || st.kind != kind || st.payload_digest != digest {
                return Err(ErrorCode::RequestIdReused);
            }
            // Same request: the recorded receipt, no lease, no re-execution.
            let receipt = to_receipt(st);
            self.send(att, re, Op::Receipt(receipt));
            return Ok(());
        }
        if kind == ReceiptKind::Approval {
            self.error(att, re, ErrorCode::Forbidden, Some(DETAIL_APPROVAL));
            return Ok(());
        }
        let sid = &b.target.session_id;
        self.check_mutation(att, &self.sessions[sid], b.lease_epoch)?;
        let held = self
            .receipts
            .values()
            .filter(|e| &e.stored.target.session_id == sid)
            .count();
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
        let record = Record::Accepted {
            request_id: request_id.to_string(),
            target: b.target.clone(),
            kind,
            payload_digest: digest.clone(),
            payload: payload.clone(),
            updated_at,
        };
        // `accepted` is durable before the reply; if it can't be, nothing
        // was recorded and the client may retry the same request.
        self.journal.append(record).map_err(|_| ErrorCode::Busy)?;
        let order = self.next_order;
        self.next_order += 1;
        let stored = Stored {
            request_id: request_id.to_string(),
            target: b.target.clone(),
            kind,
            payload_digest: digest,
            payload,
            state: ReceiptState::Accepted,
            detail: None,
            updated_at,
            order,
        };
        let receipt = to_receipt(&stored);
        self.receipts.insert(
            request_id.to_string(),
            Entry {
                stored,
                submitted_by: Some(att.to_string()),
                observe_deadline: None,
                finishing: false,
            },
        );
        self.send(att, re, Op::Receipt(receipt));
        self.schedule(request_id);
        Ok(())
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
        self.receipts.values().any(|e| {
            e.stored.target.session_id == sid
                && e.stored.kind == ReceiptKind::Prompt
                && e.stored.state == ReceiptState::Executing
        })
    }

    fn pump_queue(&mut self, sid: &str) {
        while !self.prompt_executing(sid) {
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

    /// accepted → executing (durable before the first side effect) → Dispatch.
    fn start(&mut self, rid: &str) {
        let target = self.receipts[rid].stored.target.clone();
        if let Some(detail) = self.dispatch_blocker(&target) {
            self.finish(rid, ReceiptState::Rejected, Some(detail));
            return;
        }
        if !self.transition(rid, ReceiptState::Executing, None) {
            self.finish(rid, ReceiptState::Rejected, Some(DETAIL_NOT_RECORDED));
            return;
        }
        let now = self.now;
        let e = self.receipts.get_mut(rid).unwrap();
        if matches!(e.stored.kind, ReceiptKind::Interrupt | ReceiptKind::Stop) {
            e.observe_deadline = Some(now.saturating_add(OBSERVE_MS));
        }
        let s = &e.stored;
        let effect = Effect::Dispatch {
            request_id: rid.to_string(),
            target: s.target.clone(),
            kind: s.kind,
            payload: s.payload.clone(),
        };
        self.out.push(effect);
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
        if self.journal.append(record).is_err() {
            return false;
        }
        let e = self.receipts.get_mut(rid).unwrap();
        e.stored.state = to;
        e.stored.detail = detail;
        e.stored.updated_at = updated_at;
        e.finishing = false;
        let receipt = to_receipt(&e.stored);
        let kind = e.stored.kind;
        let sid = e.stored.target.session_id.clone();
        if let Some(att) = e.submitted_by.clone() {
            self.send(&att, None, Op::Receipt(receipt));
        }
        if from == ReceiptState::Executing && kind == ReceiptKind::Prompt {
            self.pump_queue(&sid);
        }
        true
    }

    /// A transition to a final state: reported once durable; if the write
    /// fails the receipt stays where it was and the write is retried.
    fn finish(&mut self, rid: &str, to: ReceiptState, detail: Option<&str>) {
        self.persist_final(rid, to, detail.map(str::to_string));
    }

    fn persist_final(&mut self, rid: &str, to: ReceiptState, detail: Option<String>) {
        let valid = self
            .receipts
            .get(rid)
            .is_some_and(|e| journal::valid_transition(e.stored.state, to));
        if !valid {
            return;
        }
        if !self.transition(rid, to, detail.as_deref()) {
            if let Some(e) = self.receipts.get_mut(rid) {
                e.finishing = true;
            }
            self.retry.push((rid.to_string(), to, detail));
        }
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
            self.error(att, None, code, None);
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
        let s = self.check_binding(att, b)?;
        f.check_binding_ids()?;
        if !s.spec.chat {
            return Err(ErrorCode::UnknownSession);
        }
        let sid = s.spec.session_id.clone();
        let data = f.data.as_ref().ok_or(ErrorCode::UnsupportedVersion)?;
        match data["op"].as_str() {
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
                self.submit(att, None, b, &request_id, ReceiptKind::Prompt, payload)
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

fn to_receipt(s: &Stored) -> Receipt {
    Receipt {
        request_id: s.request_id.clone(),
        target: s.target.clone(),
        kind: s.kind,
        state: s.state,
        detail: s.detail.clone(),
        updated_at: s.updated_at,
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

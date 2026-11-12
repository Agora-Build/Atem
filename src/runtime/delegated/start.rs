//! The start check (design I.4.3; host-work-v1 §11.6 "The start check";
//! session-v1 R9.14 item 3): whether a delegated task may start, against
//! what the host has committed.
//!
//! - **The view** ([`StartView`]) holds what the check reads: the device
//!   list's state (frozen, held, faulted, deferred, its head and members),
//!   the senders' standings (revoked, held, coverage), the routes of the
//!   `runtime.toml` that loaded, the gates, the project-scope hashes, the
//!   journal's halt and the delegated clock's last reading. It sits behind
//!   `Arc<Mutex<_>>`, and what it shows is updated at the moment it commits
//!   (step 4's Decision 16): the device list tells it at each change, before
//!   any fence the change brings reaches the session host
//!   (`MembershipHost::set_publisher`), `runtime.toml` when it loads, the
//!   gates after each r9 call. So the check, asked inside the session host's
//!   `accepted` → `executing` step, sees a freeze committed earlier in the
//!   same call chain.
//! - **The check** ([`may_start`]) is conditions 2, 2a, 3, 4 and 5, and the
//!   deadline on the delegated clock. It answers the event that stops the
//!   task, if any ([`Event`]), whose state the task takes
//!   ([`Event::outcome`]).
//! - **At the start** ([`DelegatedStart`], the session host's `StartCheck`)
//!   the same check runs for the attempt being made `executing`; a refusal
//!   withdraws it (`withdrawn by the host`) and the event is kept with the
//!   attempt, so its end can tell a hold's withdrawal (not counted) from the
//!   rest. The check only locks the view: nothing that holds the view's lock
//!   calls into the session host.
use super::details;
use super::gate::{GateView, Gates};
use super::{Admission, DelegatedSender, SenderStanding};
use crate::runtime::host_work::{Accepted, Config, WorkRecord};
use crate::session_protocol::host::{StartCheck, StartRequest, StartVerdict};
use crate::session_protocol::membership::ListState;
use crate::session_protocol::wire::Target;
use atem_client::channel::Principal;
use atem_client::membership::MemberStatus;
use atem_client::membership::entry::MemberKind;
use atem_client::principal::{Authority, Need, Op};
use atem_client::session::host_work::WorkState;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

/// An unstarted task past its deadline: host-work v1's text (§4), the one
/// delegated tasks keep (§11.6 adds none for it).
pub const EXPIRED_BEFORE_SUBMISSION: &str = "expired before submission";

/// What stops a delegated task from starting now (design I.3.3, I.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A `revoke` record (I.5.5).
    Revoked,
    /// Removed from the device list (or a new key: a new member, R9.2).
    Removed,
    /// Held (a `hold` record): waits for `release` or the deadline.
    Held,
    /// The current grant no longer covers the target, `notify` and `prompt`.
    Narrowed,
    /// The route's revision, principals or profile changed.
    RouteChanged,
    /// The device list is frozen, held or faulted (or gone).
    AuthorityChanged,
    /// The sender's revocation gate is closed (I.5.8).
    GateClosed,
    /// The host's last carriage stopped at a deferred entry.
    Deferred,
    /// A project scope can't be compared: a locked cred agent (R9.6).
    ScopePending,
    /// The session journal halted, the device list usable.
    Halted,
    /// The deadline passed on the delegated clock.
    Expired,
}

impl Event {
    /// The state and detail the task takes (host-work-v1 §11.6 "Details").
    pub fn outcome(&self) -> (WorkState, &'static str) {
        match self {
            Event::Revoked | Event::Removed => (WorkState::Cancelled, details::SENDER_REVOKED),
            Event::Held => (WorkState::Blocked, details::PAUSED),
            Event::Narrowed => (WorkState::Failed, details::AUTHORIZATION_NARROWED),
            Event::RouteChanged => (WorkState::Failed, details::ROUTE_CHANGED),
            Event::AuthorityChanged => (WorkState::Failed, details::AUTHORITY_CHANGED),
            Event::GateClosed => (WorkState::Blocked, details::REVOCATIONS_NOT_YET_CHECKED),
            Event::Deferred => (WorkState::Blocked, details::DEVICE_LIST_UPDATE_PENDING),
            Event::ScopePending => (WorkState::Blocked, details::WAITING_FOR_UNLOCK),
            Event::Halted => (WorkState::Blocked, details::JOURNAL_HALTED),
            Event::Expired => (WorkState::Expired, EXPIRED_BEFORE_SUBMISSION),
        }
    }

    /// A task blocked by it keeps its place in its session's queue. Not for
    /// `paused`, `revocations not yet checked` and `device list update
    /// pending` (§11.6, "Waiting doesn't hold the session"): later tasks of
    /// other senders, local ones included, may pass it.
    pub fn holds_session(&self) -> bool {
        !matches!(self, Event::Held | Event::GateClosed | Event::Deferred)
    }
}

/// What the check needs of a delegated task: its admission record and the
/// rest of what it was accepted under, from a task record that read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartTask {
    pub task_id: String,
    pub admission: Admission,
    /// `expires_at`, compared with the delegated clock.
    pub deadline: u64,
    pub target: Target,
    /// The route and profile it was accepted under (condition 4).
    pub accepted: Accepted,
}

impl StartTask {
    /// A delegated task's (none for a v1 task).
    pub fn of(r: &WorkRecord) -> Option<StartTask> {
        Some(StartTask {
            task_id: r.task.task_id.clone(),
            admission: r.delegated.clone()?,
            deadline: r.task.expires_at,
            target: r.task.target.clone(),
            accepted: r.accepted(),
        })
    }
}

/// The project-scope hashes the cred agent made (`ProjectScopes`), as the
/// check compares a service scope's `projects` entries with them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeHashes {
    /// (session, kid) → `h1.<kid>.<hash>`.
    pub hashes: HashMap<(String, String), String>,
    /// The kids a comparison is pending under (`ProjectScopes::pending_for`).
    pub pending: BTreeSet<String>,
}

impl ScopeHashes {
    /// Whether `session` is in `entry`'s project: `None` while pending.
    fn matches(&self, session: &str, entry: &str) -> Option<bool> {
        let Some(kid) = crate::runtime::project_scope::kid_of(entry) else {
            return Some(false);
        };
        match self.hashes.get(&(session.to_string(), kid.to_string())) {
            Some(hash) => Some(hash == entry),
            None if self.pending.contains(kid) => None,
            // No launch project recorded: never in a `projects` scope.
            None => Some(false),
        }
    }
}

/// What the start check reads (see the module doc).
pub struct StartView {
    /// The device list as it committed; none without one that opened
    /// (no delegated task starts then).
    pub list: Option<ListState>,
    /// The session journal halted.
    pub halted: bool,
    /// The senders' standings by principal: none until the host syncs
    /// feeds (`NoFeeds`; PR 10 fills them as records apply).
    pub standings: BTreeMap<String, SenderStanding>,
    /// The `runtime.toml` that last loaded.
    pub config: Config,
    pub gates: Gates,
    pub scopes: ScopeHashes,
    /// This host's id (a service scope's `hosts`).
    pub host_id: String,
    /// `D`, the delegated clock's reading of this pass (none: no clock, or
    /// a damaged one; deadlines aren't compared then, and the dispatch
    /// waits).
    pub now_d_ms: Option<u64>,
    /// The live attempts the session host may ask about: attempt id → its
    /// task.
    live: HashMap<String, StartTask>,
    /// The event a start refused each attempt for.
    refused: HashMap<String, Event>,
}

impl StartView {
    pub fn new(host_id: &str) -> StartView {
        StartView {
            list: None,
            halted: false,
            standings: BTreeMap::new(),
            config: Config::default(),
            gates: Gates::closed_until_feeds(),
            scopes: ScopeHashes::default(),
            host_id: host_id.to_string(),
            now_d_ms: None,
            live: HashMap::new(),
            refused: HashMap::new(),
        }
    }

    /// `attempt_id` is about to be submitted for `task` (after its row
    /// committed): the start check may be asked about it.
    pub fn register(&mut self, attempt_id: &str, task: StartTask) {
        self.live.insert(attempt_id.to_string(), task);
    }

    /// Tests: whether `attempt_id` is registered as live.
    #[cfg(test)]
    pub fn is_live(&self, attempt_id: &str) -> bool {
        self.live.contains_key(attempt_id)
    }

    /// The event a start refused `attempt_id` for, if one did.
    pub fn refused(&self, attempt_id: &str) -> Option<Event> {
        self.refused.get(attempt_id).copied()
    }

    /// `attempt_id` ended: forgotten, and the event a start refused it
    /// for, if one did.
    pub fn forget(&mut self, attempt_id: &str) -> Option<Event> {
        self.live.remove(attempt_id);
        self.refused.remove(attempt_id)
    }
}

/// Conditions 2, 2a, 3, 4 and 5 of design I.4.3, and the deadline on the
/// delegated clock (`now_d_ms`; none: not compared), for `task` against
/// `view`: `Ok` when it may start, else what stops it. Events that settle
/// the task come before those that only make it wait, so a revoked or
/// removed sender is cancelled however its gate stands:
///
/// 1. the device list frozen, held or faulted (or gone): `failed`,
///    `sender's authority changed` (2a);
/// 2. the sender removed from the list (or another key in its place),
///    then revoked: `cancelled`, `sender revoked` (2);
/// 3. the route or profile changed (4), the grant narrowed (3): `failed`;
/// 4. the deadline passed: `expired`;
/// 5. the journal halted (2a), the sender held (2), a deferred entry (2),
///    the gate closed (5), a project scope pending (3): `blocked`.
///
/// Expiry alone is ignored: a lapsed grant is judged as it stood (3).
pub fn may_start(view: &StartView, task: &StartTask, now_d_ms: Option<u64>) -> Result<(), Event> {
    let adm = &task.admission;
    let Some(list) = &view.list else {
        return Err(Event::AuthorityChanged);
    };
    if list.frozen || list.held || list.faulted || list.unpaired {
        return Err(Event::AuthorityChanged);
    }
    let (device_id, principal) = match &adm.sender {
        DelegatedSender::Native { device_id } => (
            device_id,
            Principal::Native {
                device_id: device_id.clone(),
            },
        ),
        DelegatedSender::Service { device_id, .. } => (
            device_id,
            Principal::Service {
                device_id: device_id.clone(),
            },
        ),
    };
    let member = list
        .membership
        .member(device_id)
        .filter(|m| m.status == MemberStatus::Active)
        .filter(|m| {
            atem_client::membership::service_key_fingerprint(&m.member.auth_key)
                .is_ok_and(|key| key == adm.principal_key)
        })
        .filter(|m| {
            matches!(
                (&adm.sender, &m.member.kind),
                (DelegatedSender::Native { .. }, MemberKind::Native { .. })
                    | (DelegatedSender::Service { .. }, MemberKind::Service { .. })
            )
        });
    let Some(member) = member else {
        return Err(Event::Removed);
    };
    let standing = view
        .standings
        .get(&adm.principal)
        .cloned()
        .unwrap_or_default();
    if standing.revoked.is_some() {
        return Err(Event::Revoked);
    }
    if view.config.route_changed(&task.accepted) {
        return Err(Event::RouteChanged);
    }
    // Judged as the grant stands, whatever its expiry (time 0).
    let authority = Authority::of_member(&principal, &member.member, &view.host_id, 0)
        .map_err(|_| Event::Narrowed)?;
    if !authority.allows(Need::Op(Op::Notify)) || !authority.allows(Need::Op(Op::Prompt)) {
        return Err(Event::Narrowed);
    }
    let session = &task.target.session_id;
    let scope_pending = !authority.session_in_scope(&view.host_id, session, &|entry| {
        view.scopes.matches(session, entry)
    });
    if scope_pending {
        // In scope if every comparison still pending matched: waiting for
        // unlock, never narrowed; out of it whatever they say: narrowed.
        let pending_in = authority.session_in_scope(&view.host_id, session, &|entry| {
            view.scopes.matches(session, entry).or(Some(true))
        });
        if !pending_in {
            return Err(Event::Narrowed);
        }
    }
    if now_d_ms.is_some_and(|d| d >= task.deadline) {
        return Err(Event::Expired);
    }
    if view.halted {
        return Err(Event::Halted);
    }
    if standing.held {
        return Err(Event::Held);
    }
    if list.deferred.is_some() {
        return Err(Event::Deferred);
    }
    // A service's gate is its current coverage's origin (Decision 14).
    let gate_of = match &adm.sender {
        DelegatedSender::Native { .. } => Some(adm.sender.clone()),
        DelegatedSender::Service { device_id, .. } => {
            standing.coverage.map(|feed| DelegatedSender::Service {
                device_id: device_id.clone(),
                feed,
            })
        }
    };
    if !gate_of.is_some_and(|sender| view.gates.open_for(&sender)) {
        return Err(Event::GateClosed);
    }
    if scope_pending {
        return Err(Event::ScopePending);
    }
    Ok(())
}

/// Host-work's start check in the session host (session-v1 R9.14 item 3):
/// the attempt being made `executing` may start when it is a live attempt
/// of a delegated task, the view has a reading of the delegated clock, and
/// [`may_start`] says so; anything else is withdrawn (fail closed), and the
/// event, when there is one, is kept with the attempt.
pub struct DelegatedStart(pub Arc<Mutex<StartView>>);

impl StartCheck for DelegatedStart {
    fn check(&self, req: &StartRequest<'_>) -> StartVerdict {
        let mut view = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(task) = view.live.get(req.request_id) else {
            return StartVerdict::Withdraw;
        };
        let its = task.task_id == req.provenance.task_id
            && task.admission.principal == req.provenance.sender
            && task.target.session_id == req.session_id
            && task.target.process_gen == req.process_gen;
        if !its {
            return StartVerdict::Withdraw;
        }
        // No reading of the delegated clock: the deadline can't be compared,
        // so the attempt doesn't start (Task 19 review M3).
        if view.now_d_ms.is_none() {
            return StartVerdict::Withdraw;
        }
        match may_start(&view, task, view.now_d_ms) {
            Ok(()) => StartVerdict::Go,
            Err(event) => {
                view.refused.insert(req.request_id.to_string(), event);
                StartVerdict::Withdraw
            }
        }
    }
}

#[cfg(test)]
#[path = "start_tests.rs"]
mod tests;

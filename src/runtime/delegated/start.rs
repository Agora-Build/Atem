//! The start check (design I.4.3; host-work-v1 §11.6 "The start check";
//! session-v1 R9.14 item 3): whether a delegated task may start, against
//! what the host has committed.
//!
//! - **The view** ([`StartView`]) holds what the check reads: the device
//!   list's state (frozen, held, faulted, deferred, its head and members),
//!   the senders' standings (revoked, held, coverage), the routes of the
//!   `runtime.toml` that loaded, the gates and the host's own device-list
//!   fetch (their device-list part, [`StartView::fetched`]), the
//!   project-scope hashes, the journal's halt and the delegated clock's
//!   last reading. It sits behind `Arc<Mutex<_>>`, and what it shows is
//!   updated at the moment it commits (step 4's Decision 16): the device
//!   list tells it at each change, before any fence the change brings
//!   reaches the session host (`MembershipHost::set_publisher`),
//!   `runtime.toml` when it loads, the gates after each r9 call, the fetch
//!   after each of the Station's messages. So the check, asked inside the
//!   session host's `accepted` → `executing` step, sees a freeze committed
//!   earlier in the same call chain.
//! - **The check** ([`may_start`]) is conditions 2, 2a, 3, 4 and 5, and the
//!   deadline on the delegated clock. It answers the event that stops the
//!   task, if any ([`Event`]), whose state the task takes
//!   ([`Event::outcome`]).
//! - **A launch** ([`launch_check`]) of a delegated sender is checked the
//!   same way at the spawn boundary, before its worker is spawned
//!   ("Launches"): conditions 2, 2a, 3 with `launch`, 4 (the profile it was
//!   approved under) and 5, and its expiry on the delegated clock. A reason
//!   that can clear makes it wait, one that can't fails it
//!   ([`LaunchVerdict`]); the bridge's `launches` acts on it.
//! - **At the start** ([`DelegatedStart`], the session host's `StartCheck`)
//!   the same check runs for the attempt being made `executing`; a refusal
//!   withdraws it (`withdrawn by the host`) and the event is kept with the
//!   attempt, so its end can tell a hold's withdrawal (not counted) from the
//!   rest. The check only locks the view: nothing that holds the view's lock
//!   calls into the session host.
use super::details;
use super::fetch::ListPart;
use super::gate::{GateView, Gates};
use super::{Admission, DelegatedSender, SenderStanding};
use crate::runtime::host_work::{Accepted, Config, Profile, WorkRecord};
use crate::session_protocol::host::{StartCheck, StartRequest, StartVerdict};
use crate::session_protocol::membership::ListState;
use crate::session_protocol::wire::Target;
use atem_client::channel::Principal;
use atem_client::membership::entry::MemberKind;
use atem_client::membership::{MemberState, MemberStatus};
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
    /// Whether a task on `session`, whose launch project is `project` (its
    /// record's, host-private), is in `entry`'s project: the session's hash
    /// under the entry's kid, else the task's project's (ruling T20c: it
    /// outlives the session); `None` while pending.
    fn matches(&self, session: &str, project: &str, entry: &str) -> Option<bool> {
        let Some(kid) = crate::runtime::project_scope::kid_of(entry) else {
            return Some(false);
        };
        let task = crate::runtime::project_scope::task_project_key(project);
        let hash = |key: &str| self.hashes.get(&(key.to_string(), kid.to_string()));
        match hash(session).or_else(|| hash(&task)) {
            Some(hash) => Some(hash == entry),
            None if self.pending.contains(kid) => None,
            // No launch project recorded: never in a `projects` scope.
            None => Some(false),
        }
    }
}

/// The host's own device-list fetch on its Station link, as the
/// revocation gate reads it (design I.5.8): the gate's device-list part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StationFetch {
    /// The link's Station (`StationLink::origin`): none when the selection
    /// can't be read, and then no Station's gate has this part.
    pub origin: Option<String>,
    pub part: ListPart,
}

/// What the start check reads (see the module doc).
pub struct StartView {
    /// The device list as it committed; none without one that opened
    /// (no delegated task starts then).
    pub list: Option<ListState>,
    /// The session journal halted.
    pub halted: bool,
    /// The senders' standings by principal, as the control feeds
    /// committed them (`FeedStore`'s publisher, Decision 16).
    pub standings: BTreeMap<String, SenderStanding>,
    /// The stored control state couldn't be read (`Feeds::Damaged`): no
    /// sender's revocations can be checked, so no delegated task starts,
    /// `revocations not yet checked`, a native's caught-up channel
    /// included (fail closed, never an empty state in its place).
    pub controls_damaged: bool,
    /// The `runtime.toml` that last loaded.
    pub config: Config,
    pub gates: Gates,
    /// The host's own device-list fetch on its Station link (none without
    /// one): set when the link changes and after each of its messages.
    pub fetch: Option<StationFetch>,
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
            controls_damaged: false,
            config: Config::default(),
            gates: Gates::default(),
            fetch: None,
            scopes: ScopeHashes::default(),
            host_id: host_id.to_string(),
            now_d_ms: None,
            live: HashMap::new(),
            refused: HashMap::new(),
        }
    }

    /// The Station whose gate has its device-list part now (design I.5.8:
    /// "fetched the device list up to its head, or up to a deferred
    /// entry"), against `list` as it committed: the host's own Station,
    /// while its fetch is up to the head it announced last or stopped at
    /// the deferred entry `list` still defers ([`ListPart::holds`]). Read
    /// at every check, so it follows the list at the moment it commits
    /// (Decision 16).
    pub fn fetched(&self, list: &ListState) -> Option<&str> {
        let fetch = self.fetch.as_ref()?;
        let deferred = list.deferred.map(|d| d.seq);
        if !fetch.part.holds(&list.membership, deferred) {
            return None;
        }
        fetch.origin.as_deref()
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
/// 5. the journal halted (2a), a control state that doesn't read (5), the
///    sender held (2), a deferred entry (2), the gate closed (5), a
///    project scope pending (3): `blocked`.
///
/// Expiry alone is ignored: a lapsed grant is judged as it stood (3).
pub fn may_start(view: &StartView, task: &StartTask, now_d_ms: Option<u64>) -> Result<(), Event> {
    let adm = &task.admission;
    let sender = in_effect(view, adm)?;
    if view.config.route_changed(&task.accepted) {
        return Err(Event::RouteChanged);
    }
    let authority = sender.authority(view)?;
    if !authority.allows(Need::Op(Op::Notify)) || !authority.allows(Need::Op(Op::Prompt)) {
        return Err(Event::Narrowed);
    }
    let scope_pending = scope_pending(
        view,
        adm,
        &authority,
        &task.target.session_id,
        &task.accepted.project,
    )?;
    if now_d_ms.is_some_and(|d| d >= task.deadline) {
        return Err(Event::Expired);
    }
    waits(view, &sender, adm, scope_pending)
}

/// A delegated sender as the committed device list and control state have
/// it now (conditions 2a and 2, the parts that settle a task): the list it
/// was checked on, its member entry and principal, and its standing.
struct InEffect<'v> {
    list: &'v ListState,
    member: &'v MemberState,
    principal: Principal,
    standing: SenderStanding,
}

impl InEffect<'_> {
    /// Its authority as its grant stands, whatever its expiry (time 0):
    /// a lapsed grant is judged as it stood (condition 3).
    fn authority(&self, view: &StartView) -> Result<Authority, Event> {
        Authority::of_member(&self.principal, &self.member.member, &view.host_id, 0)
            .map_err(|_| Event::Narrowed)
    }
}

/// Conditions 2a and 2 (what settles): the device list usable, else
/// `AuthorityChanged`; the sender a member in effect under the key and kind
/// it was admitted with, else `Removed`; then no `revoke` record, else
/// `Revoked`.
fn in_effect<'v>(view: &'v StartView, adm: &Admission) -> Result<InEffect<'v>, Event> {
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
    Ok(InEffect {
        list,
        member,
        principal,
        standing,
    })
}

/// Condition 3's scope for `key` (a task's session, or a launch's profile
/// scope key) whose launch project is `project` (the task's record's, or
/// the launch's profile's; its hashes outlive the session, ruling T20c):
/// `Narrowed` when it is out of `authority`'s scope whatever the
/// comparisons still pending say; else whether one is pending (in scope
/// only if they match: waiting for unlock, never narrowed).
fn scope_pending(
    view: &StartView,
    adm: &Admission,
    authority: &Authority,
    key: &str,
    project: &str,
) -> Result<bool, Event> {
    // An entry the task's project matched at admission decides without a
    // hash (Task 20 review I1); the hashes only for a kid it didn't see.
    let live = |entry: &str| view.scopes.matches(key, project, entry);
    let pending = !authority.session_in_scope(&view.host_id, key, &|entry| {
        adm.project_matches(entry, &live)
    });
    if pending {
        // In scope if every comparison still pending matched: waiting for
        // unlock, never narrowed; out of it whatever they say: narrowed.
        let pending_in = authority.session_in_scope(&view.host_id, key, &|entry| {
            adm.project_matches(entry, &live).or(Some(true))
        });
        if !pending_in {
            return Err(Event::Narrowed);
        }
    }
    Ok(pending)
}

/// What makes it wait: the journal halted (2a), the sender held (2), a
/// deferred entry (2), the gate closed (5), then a project scope pending
/// (3).
fn waits(
    view: &StartView,
    sender: &InEffect<'_>,
    adm: &Admission,
    scope_pending: bool,
) -> Result<(), Event> {
    if view.halted {
        return Err(Event::Halted);
    }
    // No sender's revocations can be checked (fail closed).
    if view.controls_damaged {
        return Err(Event::GateClosed);
    }
    if sender.standing.held {
        return Err(Event::Held);
    }
    if sender.list.deferred.is_some() {
        return Err(Event::Deferred);
    }
    // A service's gate is its current coverage's origin (Decision 14); a
    // Station's gate needs its device-list part too (I.5.8).
    let fetched = view.fetched(sender.list);
    let gate_of = match &adm.sender {
        DelegatedSender::Native { .. } => Some(adm.sender.clone()),
        DelegatedSender::Service { device_id, .. } => {
            sender
                .standing
                .coverage
                .clone()
                .map(|feed| DelegatedSender::Service {
                    device_id: device_id.clone(),
                    feed,
                })
        }
    };
    if !gate_of.is_some_and(|sender| view.gates.open_for(&sender, fetched)) {
        return Err(Event::GateClosed);
    }
    if scope_pending {
        return Err(Event::ScopePending);
    }
    Ok(())
}

/// What the spawn-boundary check says of a delegated sender's launch
/// (design I.4.3, "Launches"; host-work-v1 §11.6, "Launches").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchVerdict {
    /// It may be spawned now.
    Go,
    /// A reason that can clear (§11.6's `blocked` details: the sender held,
    /// the gate closed, a deferred entry, a scope waiting for unlock, the
    /// journal halted): it waits at the spawn boundary while its expiry
    /// holds, nothing spawned.
    Wait(&'static str),
    /// A reason that can't clear, with the event's detail (the sender
    /// revoked or removed, narrowed, its profile changed, the device list
    /// frozen, held or faulted), or its expiry passed (`expired before the
    /// spawn`): it ends `failed` at once, nothing spawned. Never
    /// `outcome_unknown`.
    Fail(&'static str),
}

/// What the spawn-boundary check needs of a delegated sender's launch
/// (`host_launch`, §3): its admission record, the profile it was approved
/// under and its expiry. A launch has no route: the admission's `route_id`
/// is empty, and the profile stands for the route of condition 4 (its id,
/// revision, principals, directory and project as approved); its `projects`
/// entries were matched against the profile's scope key (as the launch
/// itself was authorized).
#[derive(Clone)]
pub struct StartLaunch {
    pub admission: Admission,
    pub profile: Profile,
    /// `expires_at`, compared with the delegated clock.
    pub expires_at: u64,
}

/// Conditions 2, 2a, 3 (with `launch` in place of `notify` and `prompt`),
/// 4 and 5 of design I.4.3 for a delegated sender's `launch`, and its
/// expiry, against `view` at `now_d_ms` (the delegated clock's reading):
/// checked at the spawn boundary, before the worker is spawned ("Launches").
/// The events and their order are [`may_start`]'s, condition 4 being the
/// profile it was approved under and the deadline its expiry; what settles
/// a task fails the launch with the event's detail, what blocks one makes it
/// wait, and an expiry passed is `expired before the spawn`.
///
/// Hosting §5's fences come first and are its callers': a receipt-database
/// fault, a halted session journal alone and hosting switched off fence a
/// launch (`outcome_unknown`), so the halt's wait here is only what the
/// check alone says.
pub fn launch_check(view: &StartView, launch: &StartLaunch, now_d_ms: u64) -> LaunchVerdict {
    match launch_event(view, launch, now_d_ms) {
        Ok(()) => LaunchVerdict::Go,
        Err(Event::Expired) => LaunchVerdict::Fail(details::EXPIRED_BEFORE_THE_SPAWN),
        Err(event) => match event.outcome() {
            (WorkState::Blocked, detail) => LaunchVerdict::Wait(detail),
            (_, detail) => LaunchVerdict::Fail(detail),
        },
    }
}

/// [`launch_check`]'s event, as [`may_start`] gives a task's.
fn launch_event(view: &StartView, launch: &StartLaunch, now_d_ms: u64) -> Result<(), Event> {
    let adm = &launch.admission;
    let sender = in_effect(view, adm)?;
    if view.config.profile(&launch.profile.id) != Some(&launch.profile) {
        return Err(Event::RouteChanged);
    }
    let authority = sender.authority(view)?;
    // `launch`, no `sessions` scope, and still among the profile's
    // principals (as `host_launch` was authorized, §3).
    if !launch.profile.permits(&authority) {
        return Err(Event::Narrowed);
    }
    let scope_pending = scope_pending(
        view,
        adm,
        &authority,
        &launch.profile.scope_key(),
        &launch.profile.project,
    )?;
    if now_d_ms >= launch.expires_at {
        return Err(Event::Expired);
    }
    waits(view, &sender, adm, scope_pending)
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

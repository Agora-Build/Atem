//! Host senders on the receiving host (the delegated host-work design
//! II.2, II.3, II.7, II.8; host-work-v1 §11.5, §11.6): another Atem host of
//! the account, `host:<host_id>`, sending work through the Station
//! mailbox. Everything here is behind `host.senders` (the debug-only hook,
//! only with `host.delegated`).
//!
//! - **Who it is** ([`classify_host`], design I.1.3, II.2.1): a current host
//!   of the device list (an `add_host`, no `remove_host` since), authorized
//!   as a sender (II.3.1), with the authorization generation and the
//!   membership epoch it has now (II.2.2), which its tasks record at
//!   admission. Otherwise refused: it has no v1 path.
//! - **Route consent** ([`Consent`], II.2.3): `runtime.toml`'s route
//!   `principals` take `project:<name>` (every host the signed project
//!   lists, when this host is in it too) and `host:<host_id>` (that host),
//!   only with `host.senders` on (`host_work::Config::validate_for`): with
//!   it off the file refuses them, as main does any unknown principal.
//! - **What it may do** ([`host_sender_permits`], II.2.3, I.4.3 conditions 2
//!   and 3): both locks, the route's consent and a signed project's grant,
//!   and its standing in the device list: a current host, authorized, and,
//!   for a task, at the generation and epoch its admission recorded
//!   ([`HostSender::admitted`]). Mailbox admission takes the permit's
//!   values into the task's record ([`super::Admission::for_host`]); the
//!   start check asks it again before every attempt.
//! - **What the device list's entries do to its tasks** ([`list_effects`],
//!   II.2.2, II.3.1, II.8): a `host_sender_revoke` or a `remove_host` of the
//!   sender cancels its unstarted tasks admitted before it (`sender
//!   revoked`), a revoke with `interrupt_running` writes an interrupt intent
//!   for each of them that started; a project entry fails the unstarted
//!   tasks the list as of that entry no longer covers (`sender's
//!   authorization narrowed`), per entry, so a later restore revives none;
//!   a readmit and a newer `add_host` do nothing. They are written in one
//!   transaction with host-work's own applied device-list `seq`
//!   ([`applied_seq`], in `host-work.sqlite`), so a crash between an entry's
//!   commit and its effects loses none: the next pass, and the start before
//!   its recovery, replay every entry after it, keyed by the entry's `seq`.
use super::effects::{self, Followup};
use super::start::Event;
use super::{DelegatedSender, SenderClass};
use crate::runtime::host_work::{Route, Store, WorkRecord};
use crate::runtime::test_hooks::HostFeatures;
use anyhow::{Result, bail};
use atem_client::encoding::Hash32;
use atem_client::host_principal::{host_principal, parse_host_principal};
use atem_client::membership::entry::Action;
use atem_client::membership::{HostSenderState, Membership, ProjectOp, project_name_ok};
use atem_client::session::host_work::{LaunchState, WorkState};
use atem_client::session::wire::is_delegated_sender;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::BTreeSet;

/// Host-work's applied device-list `seq` (II.3.1, "Crash safety"): one row,
/// naming the list it counts in. Made by the first pass that writes it,
/// only with `host.senders` on (hook off: no table, as on main).
const APPLIED_TABLE: &str = "CREATE TABLE IF NOT EXISTS host_senders_applied (
    id INTEGER PRIMARY KEY CHECK (id = 1), genesis TEXT NOT NULL, seq INTEGER NOT NULL)";

/// The prefix of a route principal naming a signed project (II.2.3).
const PROJECT_PREFIX: &str = "project:";

/// A route principal that consents to host senders (design II.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent<'a> {
    /// `project:<name>`: every host the signed project `name` lists, when
    /// this host is in it too, within that project's ops.
    Project(&'a str),
    /// `host:<host_id>`: that host only, within the ops of every project in
    /// effect that lists both hosts.
    Host(&'a str),
}

impl Consent<'_> {
    /// The consent `principal` names: `None` when it is neither form
    /// (another principal, or none), `Some(Err(why))` for one of the forms
    /// outside its grammar (a project name by the shared core's
    /// `project_name_ok`, a host id by the device list's).
    pub fn parse(principal: &str) -> Option<Result<Consent<'_>, &'static str>> {
        if let Some(name) = principal.strip_prefix(PROJECT_PREFIX) {
            return Some(if project_name_ok(name) {
                Ok(Consent::Project(name))
            } else {
                Err("a project name is 1-32 of a-z, 0-9 and -")
            });
        }
        if principal.starts_with("host:") {
            return Some(match parse_host_principal(principal) {
                Some(host_id) => Ok(Consent::Host(host_id)),
                None => Err("a host id is 1-128 letters, digits, `.`, `_`, `:` or `-`"),
            });
        }
        None
    }
}

/// [`super::classify`] of a `host:` principal (see there).
pub fn classify_host(principal: &str, list: &Membership, features: HostFeatures) -> SenderClass {
    if !features.delegated || !features.senders || !is_delegated_sender(principal) {
        return SenderClass::Refused;
    }
    let Some(host_id) = parse_host_principal(principal) else {
        return SenderClass::Refused;
    };
    match host_standing(list, host_id, None) {
        Ok((generation, epoch)) => SenderClass::Delegated(DelegatedSender::Host {
            host_id: host_id.to_owned(),
            generation,
            epoch,
        }),
        Err(_) => SenderClass::Refused,
    }
}

/// What a host sender asks of this host, by the ops it needs of a project
/// (design II.2.3; collaboration §5). The start check asks `Task`; a
/// launch on message and a notice come with mailbox admission (planned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum HostOp {
    /// A message task: `message`, `notify` and `prompt`.
    Task,
    /// A launch on message: a task's ops and `launch`.
    LaunchOnMessage,
    /// A host or project notice: `message`.
    Notice,
}

impl HostOp {
    /// The project ops it needs, all of them.
    pub fn needs(self) -> &'static [ProjectOp] {
        match self {
            HostOp::Task => &[ProjectOp::Message, ProjectOp::Notify, ProjectOp::Prompt],
            HostOp::LaunchOnMessage => &[
                ProjectOp::Launch,
                ProjectOp::Message,
                ProjectOp::Notify,
                ProjectOp::Prompt,
            ],
            HostOp::Notice => &[ProjectOp::Message],
        }
    }
}

/// What a host sender's task recorded at admission (design I.4.1, II.3.1):
/// the sender's authorization generation and membership epoch then, and
/// the route entry that consented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted<'a> {
    pub generation: u64,
    pub epoch: u64,
    pub consent: &'a str,
}

/// A host sender as [`host_sender_permits`] judges it: its `host_id`, and
/// for a task already admitted what its admission recorded (none at
/// admission itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSender<'a> {
    pub host_id: &'a str,
    pub admitted: Option<Admitted<'a>>,
}

/// Both locks held (design II.2.3), and the standing they were held at:
/// what a task's admission records (I.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPermit {
    /// The route entry that consents: `host:<sender>` or `project:<name>`.
    pub consent: String,
    /// The projects in effect whose ops the permission is, by name: every
    /// one listing both hosts for `host:` consent, the named one for
    /// `project:` consent.
    pub projects: Vec<String>,
    /// Their ops, as a set.
    pub ops: Vec<ProjectOp>,
    /// The sender's authorization generation (II.3.1).
    pub generation: u64,
    /// The sender's membership epoch (II.2.2).
    pub epoch: u64,
}

/// Whether host `sender` may do `op` on `this_host` through `route`, on the
/// committed device list `list` (design II.2.3, I.4.3 conditions 2 and 3),
/// in the start check's order:
///
/// 1. **Its standing** (condition 2): a current host, else `Removed`; its
///    membership epoch the one admission recorded, else `Removed` (a task
///    admitted before a removal never starts after a re-add); authorized as
///    a sender, else `Revoked`; at the generation admission recorded, else
///    `Revoked` (revoked and readmitted since: the readmit admits only work
///    signed after it). Each is `cancelled`, `sender revoked`. A new key (a
///    newer `add_host`) changes none of these.
/// 2. **The route's consent** (II.2.3's first lock): the entries of
///    `route.principals` that name the sender, `host:<sender>` first, then
///    each `project:<name>` in the route's order; for a task, only the
///    entry its admission recorded, which must still be there, else
///    `RouteChanged` (condition 4: the start check compares the route's
///    revision before this).
/// 3. **The grant** (the second lock): for `host:<sender>`, the ops of
///    every project in effect listing both hosts; for `project:<name>`,
///    that project's ops while it lists both hosts (a project lets a host
///    reach every *other* host it lists, so a sender is never this host).
///    The first entry whose grant covers all of `op`'s ops admits; none:
///    `Narrowed` (`failed`, `sender's authorization narrowed` for a task).
///
/// At admission any refusal is the admission's own (`forbidden`); a task's
/// takes the event's state.
pub fn host_sender_permits(
    list: &Membership,
    this_host: &str,
    sender: &HostSender<'_>,
    route: &Route,
    op: HostOp,
) -> Result<HostPermit, Event> {
    let admitted = sender.admitted.map(|a| (a.generation, a.epoch));
    let (generation, epoch) = host_standing(list, sender.host_id, admitted)?;
    let own = host_principal(sender.host_id);
    let entries: Vec<&str> = match sender.admitted {
        Some(a) if route.principals.iter().any(|p| p == a.consent) => vec![a.consent],
        Some(_) => return Err(Event::RouteChanged),
        None => route
            .principals
            .iter()
            .filter(|p| **p == own)
            .chain(
                route
                    .principals
                    .iter()
                    .filter(|p| matches!(Consent::parse(p), Some(Ok(Consent::Project(_))))),
            )
            .map(String::as_str)
            .collect(),
    };
    for entry in entries {
        let Some((projects, ops)) = grant(list, this_host, sender.host_id, entry) else {
            continue;
        };
        if op.needs().iter().all(|need| ops.contains(need)) {
            return Ok(HostPermit {
                consent: entry.to_owned(),
                projects,
                ops: ops.into_iter().collect(),
                generation,
                epoch,
            });
        }
    }
    Err(Event::Narrowed)
}

/// Whether a task admitted with `admitted` from `host_id` is still covered
/// for `op` on `list` (conditions 2 and 3, the device list's part): its
/// standing, and its recorded consent's grant now. What the device list's
/// own entries do to such a task (`list_effects`): `Removed` or `Revoked`
/// (cancelled), `Narrowed` (failed); no route is read.
pub fn host_task_covered(
    list: &Membership,
    this_host: &str,
    host_id: &str,
    admitted: Admitted<'_>,
    op: HostOp,
) -> Result<(), Event> {
    host_standing(list, host_id, Some((admitted.generation, admitted.epoch)))?;
    let (_, ops) = grant(list, this_host, host_id, admitted.consent).ok_or(Event::Narrowed)?;
    if op.needs().iter().all(|need| ops.contains(need)) {
        Ok(())
    } else {
        Err(Event::Narrowed)
    }
}

/// `host_id`'s authorization generation and membership epoch on `list`
/// while it may send (step 1 of [`host_sender_permits`]), checked against
/// `admitted` (a task's recorded generation and epoch) when given.
pub fn host_standing(
    list: &Membership,
    host_id: &str,
    admitted: Option<(u64, u64)>,
) -> Result<(u64, u64), Event> {
    if list.host(host_id).is_none() {
        return Err(Event::Removed);
    }
    let epoch = list.host_membership_epoch(host_id).ok_or(Event::Removed)?;
    if admitted.is_some_and(|(_, e)| e != epoch) {
        return Err(Event::Removed);
    }
    let generation = match list.host_sender_state(host_id) {
        Some(HostSenderState::Authorized { generation }) => generation,
        Some(HostSenderState::Revoked { .. }) => return Err(Event::Revoked),
        None => return Err(Event::Removed),
    };
    if admitted.is_some_and(|(g, _)| g != generation) {
        return Err(Event::Revoked);
    }
    Ok((generation, epoch))
}

/// The grant route entry `entry` gives `sender` toward `this_host` now
/// (step 3 of [`host_sender_permits`]): the projects in effect it rests
/// on and their ops; none when the entry doesn't name the sender, or names
/// no project in effect listing both hosts.
fn grant(
    list: &Membership,
    this_host: &str,
    sender: &str,
    entry: &str,
) -> Option<(Vec<String>, BTreeSet<ProjectOp>)> {
    if sender == this_host {
        return None;
    }
    let both = |name: &str| {
        let hosts = list.project_hosts(name);
        hosts.contains(&sender) && hosts.contains(&this_host)
    };
    let projects: Vec<String> = match Consent::parse(entry)?.ok()? {
        Consent::Host(host_id) if host_id == sender => list
            .host_projects(sender)
            .into_iter()
            .filter(|name| both(name))
            .map(str::to_owned)
            .collect(),
        Consent::Host(_) => return None,
        Consent::Project(name) if both(name) => vec![name.to_owned()],
        Consent::Project(_) => return None,
    };
    if projects.is_empty() {
        return None;
    }
    let ops = projects
        .iter()
        .filter_map(|name| list.project(name))
        .flat_map(|project| project.ops.iter().copied())
        .collect();
    Some((projects, ops))
}

/// Host-work's applied device-list `seq` in `db` for the list whose genesis
/// is `genesis`: the last entry whose effects on host senders' tasks are
/// durable; 0 when none was written (the table not made yet). A row of
/// another list is damage (a store is one identity's, its list's): an
/// error, never a count restarted.
pub fn applied_seq(db: &Connection, genesis: &Hash32) -> Result<u64> {
    let made: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_senders_applied')",
        [],
        |r| r.get(0),
    )?;
    if !made {
        return Ok(0);
    }
    let row: Option<(String, u64)> = db
        .query_row(
            "SELECT genesis, seq FROM host_senders_applied WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(0),
        Some((stored, seq)) if stored == genesis.to_hex() => Ok(seq),
        Some(_) => bail!("host senders' applied device-list seq names another device list"),
    }
}

/// Writes `seq` as host-work's applied device-list `seq` for the list of
/// `genesis`, in `tx` (the effects' own transaction).
pub fn set_applied_seq(tx: &Transaction, genesis: &Hash32, seq: u64) -> Result<()> {
    tx.execute_batch(APPLIED_TABLE)?;
    tx.execute(
        "INSERT INTO host_senders_applied(id, genesis, seq) VALUES(1, ?1, ?2)
        ON CONFLICT(id) DO UPDATE SET genesis=excluded.genesis, seq=excluded.seq",
        params![genesis.to_hex(), seq],
    )?;
    Ok(())
}

/// A host sender's launch on message this run reserved and hasn't spawned
/// (its spawn check never let it go, `StartView::launch_gone`): what a
/// project entry may stop (ruling R51). A launch of a run before a restart
/// is the start's recovery's (`Store::recover`: of unknown outcome unless
/// its session is live, never spawned again), never one of these.
#[derive(Debug, Clone)]
pub struct QueuedLaunch {
    pub request_id: String,
    /// Its admission record (the sender's grant when its request was
    /// admitted, `device_list_seq` among it).
    pub admission: super::Admission,
}

/// What [`list_effects`] asks of the bridge once its transaction
/// committed.
#[derive(Debug, Default)]
pub struct ListEffects {
    /// A live attempt's withdrawal, the intents carried out.
    pub followups: Vec<Followup>,
    /// The queued launches an entry stopped, with why (request id,
    /// detail): `failed` in the transaction, with their waiting tasks; the
    /// bridge drops them from its queue, and its spawn check refuses one the
    /// launcher holds.
    pub launches: Vec<(String, &'static str)>,
}

/// The effects on host senders' tasks of `list`'s entries after `after`
/// (host-work's applied `seq`) up to its head, in `tx`, entry by entry
/// (design II.2.2, II.3.1, II.8), and on `launches` (this run's queued
/// launches on message); what must wait for the commit is returned. The
/// caller writes the new applied `seq` in the same transaction.
///
/// - **`host_sender_revoke`** at `seq` (II.3.1): the sender's tasks
///   admitted before it (their generation below `seq`) stop as a revoke
///   stops them (`effects::stop`: unstarted ones `cancelled`, `sender
///   revoked`; a live attempt's withdrawal asked, the task settling from
///   it; a started one goes on). With `interrupt_running`, an intent
///   (reason `revoke`, the revocation the entry's `seq` in decimal, as the
///   control state names a host principal's) for each of those whose turn
///   may run (`effects::interrupt`).
/// - **`remove_host`** of a sender at `seq`: its tasks admitted before it
///   (their epoch below `seq`) stop the same way (`Removed`: `cancelled`,
///   `sender revoked`). This host's own removal is the device list's
///   (every principal fenced, a new identity's store).
/// - **`project_set`, `project_remove`** at `seq`, per entry (the owner's
///   decision, 2026-11-22; Astation's integration requirement, #120
///   comment 7028723996, final readings item 9): each host sender's task
///   that waits, or whose attempt is live, admitted on a list before `seq`
///   (`Admission::device_list_seq` below it), is judged on the list as of
///   `seq` ([`Membership::prefixes`], [`host_task_covered`]): one no
///   longer covered stops with the event (`Narrowed`: `failed`, `sender's
///   authorization narrowed`), and stays stopped whatever a later entry
///   restores. Tasks awaiting their result or of unknown outcome are kept.
///   A queued launch on message (ruling R51: a spawn is a start), admitted
///   before `seq`, that the list as of `seq` no longer covers for a launch
///   on message (its consent's projects with `launch` and a task's ops,
///   [`HostOp::LaunchOnMessage`]) fails with the event's detail, its record
///   `failed` and why kept (`admit::launch_failed`, as the spawn check's
///   refusal), and every task waiting for it that waits still fails with
///   it (`approved route launch not started: <why>`); a later restore
///   revives neither.
/// - **`host_sender_readmit`, `add_host`**: nothing (cancelled tasks stay
///   cancelled; a new key changes no authorization).
///
/// Entries go in `seq` order, so a task two entries reach (a narrowing
/// and a revoke) takes the first one's outcome: an unstarted task is
/// settled by it in `tx`, and of the withdrawals asked for one live
/// attempt only the first is kept.
///
/// Idempotent, keyed by the entry's `seq`: a task already in the state
/// the entry gives is left, an intent already written isn't written again,
/// so entries applied again (a replay) add nothing, and revive nothing.
pub fn list_effects(
    store: &Store,
    tx: &Transaction,
    list: &Membership,
    this_host: &str,
    after: u64,
    launches: &[QueuedLaunch],
) -> Result<ListEffects> {
    let mut out = Vec::new();
    let mut stopped = Vec::new();
    // The list as of each project entry, read forward once; host senders'
    // tasks a project entry may stop, read at the first one; the queued
    // launches not stopped yet.
    let mut prefixes = list.prefixes();
    let mut reachable: Option<Vec<WorkRecord>> = None;
    let mut queued: Vec<&QueuedLaunch> = launches.iter().collect();
    for seq in after.saturating_add(1)..=list.head().seq {
        let Some(entry) = list.entry(seq) else {
            continue;
        };
        match &entry.action {
            Action::HostSenderRevoke {
                host_id,
                interrupt_running,
            } => {
                let principal = host_principal(host_id);
                let mut tasks =
                    admitted_before(store, &principal, |generation, _| generation < seq)?;
                effects::stop(store, tx, &mut tasks, Event::Revoked, &mut out)?;
                if *interrupt_running {
                    effects::interrupt(store, tx, &principal, &tasks, &seq.to_string(), &mut out)?;
                }
            }
            Action::RemoveHost { host_id } if host_id != this_host => {
                let principal = host_principal(host_id);
                let mut tasks = admitted_before(store, &principal, |_, epoch| epoch < seq)?;
                effects::stop(store, tx, &mut tasks, Event::Removed, &mut out)?;
            }
            Action::ProjectSet { .. } | Action::ProjectRemove { .. } => {
                let Some(then) = prefixes.as_of(seq) else {
                    bail!("the device list has no position {seq}");
                };
                let tasks = match &mut reachable {
                    Some(tasks) => tasks,
                    None => reachable.insert(host_senders_tasks(store)?),
                };
                narrowed(store, tx, tasks, then, seq, this_host, &mut out)?;
                stopped.extend(launches_narrowed(
                    store,
                    tx,
                    &mut queued,
                    then,
                    seq,
                    this_host,
                )?);
            }
            _ => {}
        }
    }
    first_withdrawals(&mut out);
    Ok(ListEffects {
        followups: out,
        launches: stopped,
    })
}

/// The project entry at `seq`'s effect on `queued` launches, `then` the
/// list as of it (ruling R51): each admitted before `seq` that `then` no
/// longer covers for a launch on message leaves `queued`; if its record
/// still says `starting`, it fails with the event's detail, why kept, and
/// the tasks waiting for it that wait (no live attempt: none has its
/// session) fail with it. What it stopped (request id, detail).
fn launches_narrowed(
    store: &Store,
    tx: &Transaction,
    queued: &mut Vec<&QueuedLaunch>,
    then: &Membership,
    seq: u64,
    this_host: &str,
) -> Result<Vec<(String, &'static str)>> {
    let mut reached = Vec::new();
    queued.retain(|launch| {
        let admission = &launch.admission;
        let event = admission.host_admitted().and_then(|(host_id, admitted)| {
            if admission.device_list_seq >= seq {
                return None;
            }
            host_task_covered(then, this_host, host_id, admitted, HostOp::LaunchOnMessage).err()
        });
        match event {
            Some(event) => {
                reached.push((launch.request_id.clone(), event));
                false
            }
            None => true,
        }
    });
    let mut stopped = Vec::new();
    for (request_id, event) in reached {
        let Some(mut record) = store.launch(&request_id)? else {
            continue;
        };
        if record.status.state != LaunchState::Starting {
            continue;
        }
        let (_, detail) = event.outcome();
        super::admit::launch_failed(tx, &request_id, detail)?;
        record.status.state = LaunchState::Failed;
        store.save_launch(&record)?;
        let why = super::admit::launch_not_started(detail);
        for task_id in super::admit::waiting_for(tx, &request_id)? {
            let Some(mut r) = store.work(&task_id)? else {
                continue;
            };
            if !matches!(r.status.state, WorkState::Queued | WorkState::Blocked)
                || store.live_attempt(&task_id)?.is_some()
            {
                continue;
            }
            r.status.state = WorkState::Failed;
            r.status.detail = why.clone();
            store.save_work(&r)?;
        }
        stopped.push((request_id, detail));
    }
    Ok(stopped)
}

/// Of the withdrawals `out` asks for one attempt, the first: a task's
/// first stop, in `seq` order, is its outcome.
fn first_withdrawals(out: &mut Vec<Followup>) {
    let mut asked = BTreeSet::new();
    out.retain(|followup| match followup {
        Followup::Withdraw { attempt_id, .. } => asked.insert(attempt_id.clone()),
        _ => true,
    });
}

/// `principal`'s (a host sender's) tasks that wait or run, each with its
/// live attempt, whose admission's generation and epoch `before` takes.
fn admitted_before(
    store: &Store,
    principal: &str,
    before: impl Fn(u64, u64) -> bool,
) -> Result<Vec<effects::Task>> {
    let mut tasks = effects::tasks_of(store, principal)?;
    tasks.retain(|(r, _)| {
        r.delegated
            .as_ref()
            .and_then(|a| a.host_admitted())
            .is_some_and(|(_, admitted)| before(admitted.generation, admitted.epoch))
    });
    Ok(tasks)
}

/// Host senders' tasks that wait or run (`queued`, `blocked`,
/// `submitting`, `submitted`): what a project entry may stop. One read of
/// the active tasks a catch-up.
fn host_senders_tasks(store: &Store) -> Result<Vec<WorkRecord>> {
    let mut tasks = store.active_tasks()?;
    tasks.retain(|r| {
        r.delegated
            .as_ref()
            .and_then(|a| a.host_admitted())
            .is_some()
    });
    Ok(tasks)
}

/// The effect of the project entry at `seq`, `then` the list as of it, on
/// `tasks` (those no entry of this catch-up reached yet): every one
/// admitted on a list before `seq` that `then` no longer covers is reached,
/// and leaves `tasks`. If it still waits, or its attempt is live, as `tx`
/// has it now (an entry before this one, a revoke or removal, may have
/// settled it), it stops with the event [`host_task_covered`] gives (a
/// narrowing); a started one goes on. A task admitted at `seq` or after was
/// judged on a list that had the entry.
fn narrowed(
    store: &Store,
    tx: &Transaction,
    tasks: &mut Vec<WorkRecord>,
    then: &Membership,
    seq: u64,
    this_host: &str,
    out: &mut Vec<Followup>,
) -> Result<()> {
    let mut reached = Vec::new();
    tasks.retain(|r| {
        let event = r.delegated.as_ref().and_then(|admission| {
            let (host_id, admitted) = admission.host_admitted()?;
            if admission.device_list_seq >= seq {
                return None;
            }
            host_task_covered(then, this_host, host_id, admitted, HostOp::Task).err()
        });
        match event {
            Some(event) => {
                reached.push((r.task.task_id.clone(), event));
                false
            }
            None => true,
        }
    });
    for (task_id, event) in reached {
        let Some(r) = store.work(&task_id)? else {
            continue;
        };
        let live = store.live_attempt(&task_id)?;
        if live.is_none() && !matches!(r.status.state, WorkState::Queued | WorkState::Blocked) {
            continue;
        }
        let mut one = [(r, live)];
        effects::stop(store, tx, &mut one, event, out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_protocol::membership::r9log::{MAC, TestLog, secret};
    use ProjectOp::{Launch, Message, Notify, Prompt};
    use atem_client::membership::entry::Action;
    use atem_client::membership::{
        host_sender_readmit, host_sender_revoke, project_remove, project_set,
    };

    /// This host.
    const HOST: &str = "host-a";

    /// The list: the Mac, this host and hosts B, C and D; projects `build`
    /// (A, B: `message`, `notify`, `prompt`), `deploy` (A, B: `launch`,
    /// `message`) and `notes` (A, C: `message`). D shares none.
    fn list() -> TestLog {
        let mut log = TestLog::genesis("acct-h", &secret("hs astation"));
        log.add_host(HOST, 1, &secret("hs host a"));
        for id in ["host-b", "host-c", "host-d"] {
            log.add_host(id, 1, &secret(id));
        }
        log.append(
            MAC,
            project_set("build", [HOST, "host-b"], [Message, Notify, Prompt], 0).unwrap(),
        );
        log.append(
            MAC,
            project_set("deploy", [HOST, "host-b"], [Launch, Message], 0).unwrap(),
        );
        log.append(
            MAC,
            project_set("notes", [HOST, "host-c"], [Message], 0).unwrap(),
        );
        log
    }

    fn route(principals: &[&str]) -> Route {
        Route {
            id: "r".into(),
            revision: 1,
            profile_id: "p".into(),
            principals: principals.iter().map(|p| p.to_string()).collect(),
            labels: vec![],
            launch: Default::default(),
            results: false,
            auto_report: Default::default(),
        }
    }

    fn new(host_id: &str) -> HostSender<'_> {
        HostSender {
            host_id,
            admitted: None,
        }
    }

    fn permits(
        log: &TestLog,
        sender: &str,
        principals: &[&str],
        op: HostOp,
    ) -> Result<HostPermit, Event> {
        host_sender_permits(&log.log, HOST, &new(sender), &route(principals), op)
    }

    fn add_seq(log: &TestLog, host_id: &str) -> u64 {
        log.log.host_membership_epoch(host_id).unwrap()
    }

    /// Design II.2.3's table, each op: a message task needs `message`,
    /// `notify` and `prompt`; a launch on message also `launch`; a notice
    /// `message`. `host:<sender>` grants the union of every project listing
    /// both hosts; `project:<name>` that project's ops alone.
    #[test]
    fn every_op_by_each_consent() {
        let log = list();
        let b = add_seq(&log, "host-b");
        // `host:host-b`: build ∪ deploy, every op.
        for op in [HostOp::Task, HostOp::LaunchOnMessage, HostOp::Notice] {
            let permit = permits(&log, "host-b", &["host:host-b"], op).unwrap();
            assert_eq!(
                permit,
                HostPermit {
                    consent: "host:host-b".into(),
                    projects: vec!["build".into(), "deploy".into()],
                    ops: vec![Launch, Message, Notify, Prompt],
                    generation: b,
                    epoch: b,
                },
                "{op:?}"
            );
        }
        // `project:build`: a task and a notice, no launch.
        assert_eq!(
            permits(&log, "host-b", &["project:build"], HostOp::Task)
                .unwrap()
                .projects,
            ["build"]
        );
        assert_eq!(
            permits(&log, "host-b", &["project:build"], HostOp::Notice)
                .unwrap()
                .ops,
            [Message, Notify, Prompt]
        );
        assert_eq!(
            permits(&log, "host-b", &["project:build"], HostOp::LaunchOnMessage),
            Err(Event::Narrowed)
        );
        // `project:deploy`: a notice only (no `notify` or `prompt`).
        assert_eq!(
            permits(&log, "host-b", &["project:deploy"], HostOp::Notice)
                .unwrap()
                .consent,
            "project:deploy"
        );
        for op in [HostOp::Task, HostOp::LaunchOnMessage] {
            assert_eq!(
                permits(&log, "host-b", &["project:deploy"], op),
                Err(Event::Narrowed),
                "{op:?}"
            );
        }
        // Per entry, never summed across entries: build's task ops and
        // deploy's launch don't make a launch on message.
        assert_eq!(
            permits(
                &log,
                "host-b",
                &["project:deploy", "project:build"],
                HostOp::LaunchOnMessage
            ),
            Err(Event::Narrowed)
        );
        // The first entry that covers the op admits: `host:` first.
        assert_eq!(
            permits(
                &log,
                "host-b",
                &["project:build", "host:host-b"],
                HostOp::Task
            )
            .unwrap()
            .consent,
            "host:host-b"
        );
        assert_eq!(
            permits(
                &log,
                "host-b",
                &["local", "project:deploy", "project:build"],
                HostOp::Task
            )
            .unwrap()
            .consent,
            "project:build"
        );
        // Host C: `notes` gives notices only.
        assert!(permits(&log, "host-c", &["host:host-c"], HostOp::Notice).is_ok());
        assert_eq!(
            permits(&log, "host-c", &["project:notes"], HostOp::Task),
            Err(Event::Narrowed)
        );
    }

    /// Both locks are needed (II.2.3): a route that doesn't consent to the
    /// sender (another host, a project that doesn't list it, no host-sender
    /// entry at all) admits nothing, whatever its projects grant; a route
    /// that consents to a host this host shares no project with admits
    /// nothing either; nor does a project that doesn't list this host, and
    /// no host sends to itself.
    #[test]
    fn each_lock_missing_refuses() {
        let mut log = list();
        for principals in [
            &["local", "member:dev-phone"][..],
            &["host:host-c"],
            &["project:notes"],
            &["project:nothing"],
            &[],
        ] {
            assert_eq!(
                permits(&log, "host-b", principals, HostOp::Notice),
                Err(Event::Narrowed),
                "{principals:?}"
            );
        }
        // Consent with no grant: D shares no project with this host.
        assert_eq!(
            permits(&log, "host-d", &["host:host-d"], HostOp::Notice),
            Err(Event::Narrowed)
        );
        // A project of B and C only: this host isn't in it.
        log.append(
            MAC,
            project_set("other", ["host-b", "host-c"], [Message], 0).unwrap(),
        );
        assert_eq!(
            permits(&log, "host-b", &["project:other"], HostOp::Notice),
            Err(Event::Narrowed)
        );
        // No host sends to itself, whatever the route says.
        assert_eq!(
            permits(
                &log,
                HOST,
                &["host:host-a", "project:build"],
                HostOp::Notice
            ),
            Err(Event::Narrowed)
        );
    }

    /// Condition 2 for host senders (design I.4.3, II.3.1, II.2.2): a host
    /// no `add_host` names or a removed one is `Removed`; a revoked one
    /// `Revoked`. A task also needs the generation and epoch its admission
    /// recorded: after a revoke and a readmit it is `Revoked`, after a
    /// removal and a re-add `Removed`; a re-verification (a newer
    /// `add_host`, no removal) changes neither. Its recorded consent must
    /// still be in the route (`RouteChanged`), and its grant still cover it.
    #[test]
    fn standing_and_what_admission_recorded() {
        let mut log = list();
        let b = add_seq(&log, "host-b");
        let task =
            |log: &TestLog, generation, epoch, consent: &'static str, principals: &[&str]| {
                host_sender_permits(
                    &log.log,
                    HOST,
                    &HostSender {
                        host_id: "host-b",
                        admitted: Some(Admitted {
                            generation,
                            epoch,
                            consent,
                        }),
                    },
                    &route(principals),
                    HostOp::Task,
                )
            };
        assert!(task(&log, b, b, "project:build", &["project:build"]).is_ok());
        assert_eq!(
            permits(&log, "host-z", &["host:host-z"], HostOp::Notice),
            Err(Event::Removed)
        );
        // Only the recorded entry counts, and it must still be there.
        assert_eq!(
            task(&log, b, b, "project:build", &["host:host-b"]),
            Err(Event::RouteChanged)
        );
        // Re-verification: nothing changes.
        log.add_host("host-b", 2, &secret("host-b 2"));
        assert!(task(&log, b, b, "project:build", &["project:build"]).is_ok());
        assert!(task(&log, b, b, "host:host-b", &["host:host-b"]).is_ok());
        // Narrowed: build keeps `message` alone.
        log.append(
            MAC,
            project_set("build", [HOST, "host-b"], [Message], 0).unwrap(),
        );
        assert_eq!(
            task(&log, b, b, "project:build", &["project:build"]),
            Err(Event::Narrowed)
        );
        assert_eq!(
            task(&log, b, b, "host:host-b", &["host:host-b"]),
            Err(Event::Narrowed)
        );
        log.append(
            MAC,
            project_set("build", [HOST, "host-b"], [Message, Notify, Prompt], 0).unwrap(),
        );
        // Revoked, then readmitted: an earlier task stays out.
        log.append(MAC, host_sender_revoke("host-b", false, 0).unwrap());
        assert_eq!(
            task(&log, b, b, "project:build", &["project:build"]),
            Err(Event::Revoked)
        );
        assert_eq!(
            permits(&log, "host-b", &["project:build"], HostOp::Notice),
            Err(Event::Revoked)
        );
        log.append(MAC, host_sender_readmit("host-b", 0).unwrap());
        let readmitted = log.log.head().seq;
        assert_eq!(
            task(&log, b, b, "project:build", &["project:build"]),
            Err(Event::Revoked)
        );
        assert_eq!(
            permits(&log, "host-b", &["project:build"], HostOp::Task)
                .unwrap()
                .generation,
            readmitted
        );
        assert!(task(&log, readmitted, b, "project:build", &["project:build"]).is_ok());
        // Removed, then added again: an earlier task stays out; a new one
        // needs a new project_set listing it.
        log.append(
            MAC,
            Action::RemoveHost {
                host_id: "host-b".into(),
            },
        );
        assert_eq!(
            task(&log, readmitted, b, "project:build", &["project:build"]),
            Err(Event::Removed)
        );
        log.add_host("host-b", 3, &secret("host-b 3"));
        let re_added = log.log.head().seq;
        assert_eq!(
            task(&log, readmitted, b, "project:build", &["project:build"]),
            Err(Event::Removed)
        );
        assert_eq!(
            permits(&log, "host-b", &["project:build"], HostOp::Notice),
            Err(Event::Narrowed),
            "no project lists it since its re-add"
        );
        log.append(
            MAC,
            project_set("build", [HOST, "host-b"], [Message, Notify, Prompt], 0).unwrap(),
        );
        let permit = permits(&log, "host-b", &["project:build"], HostOp::Task).unwrap();
        assert_eq!((permit.generation, permit.epoch), (readmitted, re_added));
        // A project removed: narrowed.
        log.append(MAC, project_remove("build", 0).unwrap());
        assert_eq!(
            task(
                &log,
                readmitted,
                re_added,
                "project:build",
                &["project:build"]
            ),
            Err(Event::Narrowed)
        );
    }

    /// [`host_task_covered`]: the device list's part of the check (no
    /// route), as the device list's own effects judge a task.
    #[test]
    fn a_task_is_covered_by_its_recorded_consent_only() {
        let mut log = list();
        let b = add_seq(&log, "host-b");
        let covered = |log: &TestLog, consent| {
            host_task_covered(
                &log.log,
                HOST,
                "host-b",
                Admitted {
                    generation: b,
                    epoch: b,
                    consent,
                },
                HostOp::Task,
            )
        };
        assert_eq!(covered(&log, "project:build"), Ok(()));
        assert_eq!(covered(&log, "host:host-b"), Ok(()));
        assert_eq!(covered(&log, "project:deploy"), Err(Event::Narrowed));
        log.append(MAC, project_remove("build", 0).unwrap());
        assert_eq!(covered(&log, "project:build"), Err(Event::Narrowed));
        assert_eq!(covered(&log, "host:host-b"), Err(Event::Narrowed));
        log.append(MAC, host_sender_revoke("host-b", true, 0).unwrap());
        assert_eq!(covered(&log, "host:host-b"), Err(Event::Revoked));
    }

    /// Every host id the device list allows (1 to 128 characters) is one a
    /// receipt's `sender` can name too (`is_opaque_id`, the same bound):
    /// the longest classifies, and its consent parses; one longer is no
    /// host id at all.
    #[test]
    fn the_longest_host_id_classifies() {
        let senders = HostFeatures::parse("host.delegated,host.senders").unwrap();
        let mut log = list();
        let longest = "h".repeat(128);
        log.add_host(&longest, 1, &secret("hs longest"));
        let principal = host_principal(&longest);
        assert!(matches!(
            classify_host(&principal, &log.log, senders),
            SenderClass::Delegated(DelegatedSender::Host { .. })
        ));
        assert_eq!(
            Consent::parse(&principal),
            Some(Ok(Consent::Host(longest.as_str())))
        );
        assert!(matches!(
            Consent::parse(&host_principal(&"h".repeat(129))),
            Some(Err(_))
        ));
    }

    /// The consent forms' grammar (II.2.3), as `runtime.toml` reads them.
    #[test]
    fn consents_parse() {
        assert_eq!(
            Consent::parse("project:astation"),
            Some(Ok(Consent::Project("astation")))
        );
        assert_eq!(
            Consent::parse("host:Host_B.1-b:2"),
            Some(Ok(Consent::Host("Host_B.1-b:2")))
        );
        for bad in ["project:", "project:A", "project:a b", "host:", "host:a b"] {
            assert!(matches!(Consent::parse(bad), Some(Err(_))), "{bad}");
        }
        for other in ["local", "member:a", "Project:a", "hosts:a", "project"] {
            assert_eq!(Consent::parse(other), None, "{other}");
        }
    }
}

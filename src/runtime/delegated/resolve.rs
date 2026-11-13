//! `work_resolve` (feature `host.delegated`; design I.4.5, I.4.6;
//! host-work-v1 §11.2 and §11.6 "Unknown outcomes"): a delegated sender's
//! task of unknown outcome, settled by a person.
//!
//! - **Only an unresolved delegated `outcome_unknown` task.** It becomes
//!   `failed` with the resolution's detail, kept byte for byte, or
//!   `completed` with its result, and records `resolved{by, at}`: the
//!   resolver and the host's wall clock then. A v1 task (`local`, a browser
//!   grant, a service no feed covers) is never resolved: its
//!   `outcome_unknown` keeps v1 and expires at its deadline.
//! - **Once.** The same resolution again (the same canonical `resolution`,
//!   whoever asks) returns the recorded status, the first resolver's
//!   `resolved` included, and writes nothing; another is
//!   `request_id_reused`.
//! - **Durable before visible.** The resolution, and the end of the task's
//!   alert ([`Store::end_alert`]), are written in the caller's transaction
//!   (`BEGIN IMMEDIATE`, [`Store::immediate`]), which it commits before it
//!   answers.
//!
//! Who may resolve (the task's sender with current authority, or the
//! owner) is the bridge's check (`HostBridge::work_resolve`), made before
//! this. `resolved` reaches the wire only behind `host.delegated` (§11.2,
//! "Compatibility"): the bridge serves `work_resolve` only then, and strips
//! it from what it answers otherwise.
use crate::runtime::host_work::{RESULT_PUBLISHED, Store};
use crate::session_protocol::r9::HostWorkError;
use atem_client::session::host_work::{Resolution, Resolved, WorkState, WorkStatus};
use rusqlite::Transaction;

/// Why [`resolve`] settles nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveRefusal {
    /// No such task, a v1 task, or a task that isn't `outcome_unknown` and
    /// wasn't resolved: `forbidden`.
    Forbidden,
    /// A resolved task, and another resolution than its own:
    /// `request_id_reused`.
    Reused,
    /// The store couldn't be read or written: `busy`. Nothing was resolved
    /// (the caller's transaction is rolled back).
    Store,
}

impl ResolveRefusal {
    /// The error `work_resolve` answers it with (host-work-v1 §7, §11.2).
    pub fn error(self) -> HostWorkError {
        match self {
            ResolveRefusal::Forbidden => "forbidden".into(),
            ResolveRefusal::Reused => "request_id_reused".into(),
            ResolveRefusal::Store => "busy".into(),
        }
    }
}

/// Resolves the task `task_id` as `resolution`, by `by` (`member:<id>` or
/// `service:<id>`, the task's sender or the owner; `local`, the host's own
/// command), at the host's wall clock `now_wall_ms`, in `tx`: the store's
/// own `BEGIN IMMEDIATE` transaction, which the caller commits before the
/// status is shown. The task's status after it: as resolved now, or as
/// recorded when the same resolution came before. `resolution` is one a
/// reader takes (the decoder checks it, §11.2).
pub fn resolve(
    store: &Store,
    tx: &Transaction,
    task_id: &str,
    by: &str,
    resolution: &Resolution,
    now_wall_ms: u64,
) -> Result<WorkStatus, ResolveRefusal> {
    let mut record = store
        .work(task_id)
        .map_err(|_| ResolveRefusal::Store)?
        .ok_or(ResolveRefusal::Forbidden)?;
    if record.delegated.is_none() {
        return Err(ResolveRefusal::Forbidden);
    }
    if record.status.resolved.is_some() {
        return if settled_as(&record.status, resolution) {
            Ok(record.status)
        } else {
            Err(ResolveRefusal::Reused)
        };
    }
    if record.status.state != WorkState::OutcomeUnknown {
        return Err(ResolveRefusal::Forbidden);
    }
    let resolved = Resolved {
        by: by.to_owned(),
        at: now_wall_ms,
    };
    if !resolved.valid() {
        return Err(ResolveRefusal::Forbidden);
    }
    match resolution {
        Resolution::Failed { detail } => {
            record.status.state = WorkState::Failed;
            record.status.detail = detail.clone();
        }
        Resolution::Done { result } => {
            record.status.state = WorkState::Completed;
            record.status.result = Some(result.clone());
            record.status.detail = RESULT_PUBLISHED.into();
        }
    }
    record.status.resolved = Some(resolved);
    store
        .end_alert(tx, task_id)
        .map_err(|_| ResolveRefusal::Store)?;
    store
        .save_work(&record)
        .map_err(|_| ResolveRefusal::Store)?;
    Ok(record.status)
}

/// Whether the resolved task's status `status` is what `resolution` makes
/// (the same canonical resolution: for `failed` the same detail, byte for
/// byte; for `done` the same snapshot, digest included).
fn settled_as(status: &WorkStatus, resolution: &Resolution) -> bool {
    match resolution {
        Resolution::Failed { detail } => {
            status.state == WorkState::Failed && status.detail == *detail
        }
        Resolution::Done { result } => {
            status.state == WorkState::Completed && status.result.as_ref() == Some(result)
        }
    }
}

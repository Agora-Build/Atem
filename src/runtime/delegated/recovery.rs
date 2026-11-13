//! Recovery of delegated tasks at a start (design I.6.2, I.6.3;
//! host-work-v1 §11.6 "Restart"; session-v1 R9.14 item 6): before
//! host-work dispatches anything, once per store, in the design's order.
//!
//! 1. **Identity.** The store is bound to this host's identity; one bound
//!    to another was moved aside first (`work_store_ready`, hosting §9).
//! 2. **The session journal**, recovered earlier in the same pass
//!    (`SessionHost::recover`, §H as R9.14 item 6 revises it): host-work's
//!    `accepted` requests were rejected `withdrawn at recovery`, and its
//!    `executing` prompts handed to the reconciliation of their adopted
//!    chats (Task 16a), whose decision this step reads from the receipts,
//!    never deciding it again. A journal that halted at its start resolved
//!    nothing: an attempt it still shows `accepted` stays live, and nothing
//!    starts until the restart that withdraws it.
//! 3. **Pending interrupt intents**: none yet (PR 8 carries them out here).
//! 4. **Reconcile** every delegated task, the start view made current first
//!    (the device list, `runtime.toml`, the standings, the project scopes,
//!    a reading of the delegated clock), so a task takes the event that
//!    settles it, not `queued` (Task 20's note):
//!    - a live attempt, by its receipt (I.6.3; the mapping is
//!      `attempt_end`'s): absent → `not_admitted`; `rejected` →
//!      `withdrawn` (at recovery, by the host) or `rejected` (`acceptance
//!      not confirmed`, …), its task `failed` with the receipt's detail when
//!      its target is gone (`session closed`, `host trust changed`), else
//!      back to `queued`; `executing`, `completed` or `outcome_unknown` →
//!      `started`, its task following the receipt (`submitted`,
//!      `awaiting_result`, `outcome_unknown` with the receipt's detail).
//!      Nothing is submitted here, and an ended attempt's id never is
//!      again (`Store::may_submit`);
//!    - a task whose attempt started before follows its receipt;
//!    - a task going back to `queued`, and one that waited unstarted, take
//!      the event that settles it now (`may_start`'s order): `cancelled`,
//!      `sender revoked`, for a revoked or removed sender (I.6.3), `failed`
//!      for a frozen, held or faulted device list or a grant narrowed off
//!      the target. A route change and the deadline are steps 5 and 6; the
//!      waits are the dispatch's, after the gates closed.
//! 5. **Routes**: an unstarted task of a changed route fails `route
//!    changed`.
//! 6. **Deadlines**, on a fresh reading of the delegated clock (none: none
//!    compared, as the dispatch waits): an unstarted task past its deadline
//!    expires (`expired before submission`), and so does one awaiting its
//!    result. A task of unknown outcome is left as it is (design: it stays
//!    unresolved; PR 7 keeps `settle_due` from expiring it).
//! 7. **Gates closed**: every Station's revocation gate. A native's own
//!    caught-up channel was carried in this run, so it still opens its own.
//!
//! With `host.delegated` off (the hook removed after tasks were accepted,
//! step 4's Decision 10), attempts are reconciled the same way, a task
//! going back to `queued` is `blocked`, `host.delegated is off`, and only
//! the deadlines settle the rest.
use super::delegated_dispatch::WAITING_FOR_A_READY_AGENT;
use super::*;
use crate::runtime::delegated::attempts::{Attempt, AttemptEnd, SessionAnswer, attempt_end};
use crate::runtime::delegated::start::{EXPIRED_BEFORE_SUBMISSION, Event, StartTask, may_start};
use crate::session_protocol::host::{DETAIL_SESSION_CLOSED, DETAIL_TRUST_CHANGED};

/// One task as a recovery step left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Recovered {
    pub task_id: String,
    pub state: WorkState,
    pub detail: String,
}

impl Recovered {
    fn of(r: &WorkRecord) -> Recovered {
        Recovered {
            task_id: r.task.task_id.clone(),
            state: r.status.state,
            detail: r.status.detail.clone(),
        }
    }
}

/// One step of the recovery, in design I.6.2's order: the log the tests
/// read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RecoveryStep {
    /// 1: the identity the store is bound to.
    Identity(HostTarget),
    /// 2: the session journal recovered (`halted`: its start resolved
    /// nothing, so nothing starts until the restart).
    SessionJournal { halted: bool },
    /// 3: the interrupt intents carried out (none until PR 8).
    PendingIntents(Vec<String>),
    /// 4: each task the step reconciled by its receipt, or settled.
    Reconcile(Vec<Recovered>),
    /// 5: the tasks failed `route changed`.
    Routes(Vec<String>),
    /// 6: the tasks expired.
    Deadlines(Vec<String>),
    /// 7: every Station's gate closed.
    GatesClosed,
}

impl HostBridge {
    /// The start's recovery of delegated tasks (see the module doc): its
    /// steps. Run once a store is bound, after the session journal's
    /// recovery and before anything is dispatched; an error is a receipt
    /// database fault.
    pub(super) fn recover_delegated(&mut self, cx: &mut Cx) -> anyhow::Result<Vec<RecoveryStep>> {
        let mut steps = vec![
            RecoveryStep::Identity(self.work_host()),
            RecoveryStep::SessionJournal {
                halted: self.host.journal_halted(),
            },
            RecoveryStep::PendingIntents(Vec::new()),
        ];
        // The start view current before any start condition is read.
        self.refresh_start_view();
        self.take_reading();
        let mut reconciled = Vec::new();
        for mut r in self.delegated_active()? {
            if self.recover_task(&mut r, cx)? {
                reconciled.push(Recovered::of(&r));
            }
        }
        steps.push(RecoveryStep::Reconcile(reconciled));
        let mut routed = Vec::new();
        if self.features.delegated {
            for mut r in self.delegated_active()? {
                if unstarted(&r) && self.work_route_changed(&r.accepted()) {
                    self.settle_task(&mut r, WorkState::Failed, details::ROUTE_CHANGED)?;
                    routed.push(r.task.task_id);
                }
            }
        }
        steps.push(RecoveryStep::Routes(routed));
        // A fresh reading of the delegated clock.
        let mut expired = Vec::new();
        if let Some(d) = self.take_reading() {
            for mut r in self.delegated_active()? {
                if unstarted(&r) && d >= r.task.expires_at {
                    self.settle_task(&mut r, WorkState::Expired, EXPIRED_BEFORE_SUBMISSION)?;
                    expired.push(r.task.task_id);
                }
            }
            let store = self.work.store.as_ref().unwrap();
            expired.extend(store.settle_awaiting_delegated(d)?);
        }
        steps.push(RecoveryStep::Deadlines(expired));
        if self.features.delegated {
            self.start_view().gates.close_stations();
        }
        steps.push(RecoveryStep::GatesClosed);
        Ok(steps)
    }

    /// The delegated tasks that wait or run (`queued`, `blocked`,
    /// `submitting`, `submitted`), oldest first.
    fn delegated_active(&self) -> anyhow::Result<Vec<WorkRecord>> {
        let tasks = self.work.store.as_ref().unwrap().active_tasks()?;
        Ok(tasks
            .into_iter()
            .filter(|r| r.delegated.is_some())
            .collect())
    }

    /// Step 4 for `r`: true when it was reconciled by a receipt or settled.
    fn recover_task(&mut self, r: &mut WorkRecord, cx: &mut Cx) -> anyhow::Result<bool> {
        let live = self
            .work
            .store
            .as_ref()
            .unwrap()
            .live_attempt(&r.task.task_id)?;
        if let Some(attempt) = live {
            self.recover_attempt(r, &attempt)?;
            return Ok(true);
        }
        match r.status.state {
            // Its attempt started before the crash: it follows that receipt.
            WorkState::Submitting | WorkState::Submitted => {
                self.follow_receipt(r, cx)?;
                Ok(true)
            }
            WorkState::Queued | WorkState::Blocked => {
                let (state, detail) = self.unstarted_state(r);
                if !state.terminal() {
                    return Ok(false);
                }
                self.settle_task(r, state, detail)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// The live attempt `a` of `r`, by its receipt (design I.6.3), never
    /// sent again: `accepted` (the journal's start resolved nothing) leaves
    /// it live; started, it ends `started` and the task follows the receipt;
    /// with a proof of no effect it ends with it, and the task fails when
    /// its target is gone, else waits again (or takes the event that settles
    /// it now).
    fn recover_attempt(&mut self, r: &mut WorkRecord, a: &Attempt) -> anyhow::Result<()> {
        let receipt = self.host.attempt_receipt(&a.attempt_id, &r.task.task_id);
        let end = match &receipt {
            None => Some(AttemptEnd::NotAdmitted),
            // No start check of this run refused it: never a hold's
            // withdrawal, so it counts.
            Some(rc) => attempt_end(
                SessionAnswer::Receipt(rc.state, rc.detail.as_deref()),
                false,
            ),
        };
        let Some(end) = end else {
            return Ok(());
        };
        if end == AttemptEnd::Started {
            return self.end_started(r, a);
        }
        let next = match (end, receipt.as_ref().and_then(|rc| rc.detail.as_deref())) {
            (AttemptEnd::Rejected, Some(DETAIL_SESSION_CLOSED)) => {
                (WorkState::Failed, DETAIL_SESSION_CLOSED)
            }
            (AttemptEnd::Rejected, Some(DETAIL_TRUST_CHANGED)) => {
                (WorkState::Failed, DETAIL_TRUST_CHANGED)
            }
            _ => self.unstarted_state(r),
        };
        self.end_attempt(r, a, end, next)
    }

    /// Where an unstarted task stands at the reconciliation: the event
    /// that settles it now (a revoked or removed sender, a frozen, held or
    /// faulted list, a narrowed grant), else `queued` (its waits are the
    /// dispatch's; a route change and the deadline are later steps). With
    /// `host.delegated` off: `blocked`, `host.delegated is off`.
    fn unstarted_state(&self, r: &WorkRecord) -> (WorkState, &'static str) {
        if !self.features.delegated {
            return (WorkState::Blocked, details::HOST_DELEGATED_IS_OFF);
        }
        let event =
            StartTask::of(r).and_then(|task| may_start(&self.start_view(), &task, None).err());
        match event {
            Some(
                e @ (Event::AuthorityChanged | Event::Removed | Event::Revoked | Event::Narrowed),
            ) => e.outcome(),
            _ => (WorkState::Queued, WAITING_FOR_A_READY_AGENT),
        }
    }
}

/// Not started: `queued` or `blocked`.
fn unstarted(r: &WorkRecord) -> bool {
    matches!(r.status.state, WorkState::Queued | WorkState::Blocked)
}

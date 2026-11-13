//! The bridge's side of interrupt intents (design I.4.4, I.5.7, I.6.2 step
//! 3; session-v1 R9.14 item 5): the deadline's intent is written, and every
//! pending intent's decision ([`intents_pass`]) is carried out through the
//! bridge's own entries, so the chat's half of the turn check always runs
//! (Task 15's rulings T15a, T15c).
//!
//! - **The deadline** (I.4.4): a delegated task whose attempt waits to start
//!   or runs (`submitting`, `submitted`) when the delegated clock's `D`
//!   reaches its deadline gets an intent with reason `deadline` for its
//!   current attempt, committed in its own `BEGIN IMMEDIATE` transaction
//!   before the pass carries it out.
//! - **Each scheduling pass** (after the task loop, so the records it acts
//!   on are fresh) and the start's recovery, step 3, carry out the pending
//!   intents, after the session host's `advance` (a lease past its deadline
//!   ends `expired`, not `revoked`) and after the start's reconciliation of
//!   host-work's prompts (`reconcile_host_work`, which runs earlier in the
//!   same tick):
//!   - `Deliver`: the bridge's `host_interrupt` (the whole turn check, the
//!     input epoch, another controller's lease revoked, the Esc); a write
//!     is remembered until its report comes;
//!   - `RevokeOnly`: `host_interrupt_revoke_lease`, nothing written;
//!   - `Withdraw`: the attempt is withdrawn in the session host (`accepted`)
//!     or ended from its receipt (`rejected`) or its absence (never
//!     admitted), and the task takes the intent's state (`expired before
//!     submission`, or `sender revoked`) in one `BEGIN IMMEDIATE`
//!     transaction with the attempt's end; a withdrawal that found it
//!     started, or couldn't be recorded (the journal halted), leaves the
//!     intent pending;
//!   - `Done`: `done_ms` written; `Wait`: nothing.
//! - **While hosting is paused** (`runtime.toml` doesn't load, or `enabled
//!   = false`; ruling T26a): the stops still run (`paused_stops`), on the
//!   scheduling pass's 100 ms cadence, once the store was recovered and
//!   with no receipt-database fault. Each such pass takes a fresh `D`,
//!   writes the deadline's intents and carries every pending intent out. A
//!   deadline interrupt only takes execution away (a stop always wins,
//!   ruling T4d), and the turn's own lease goes on renewing meanwhile.
//!   Nothing else of the scheduling pass runs: nothing is dispatched,
//!   reconciled, settled or launched, so nothing new starts. The one
//!   request served meanwhile is `work_interrupt`, a stop too (ruling
//!   T27a, `stops_while_paused`). Two residuals:
//!   - a **receipt-database fault** holds the intents in that database
//!     until the restart it asks for (`atem runtime restart`); recovery's
//!     step 3 and the first pass's deadline sweep carry them out then;
//!   - a **runtime started while paused** opens and recovers its store
//!     only once hosting is on: its pending intents (step 3) and deadlines
//!     wait for that.
//! - **The reports** of host interrupt writes are taken at the start of
//!   every scheduling pass (`take_interrupt_reports`, so a turn the Esc
//!   ended reads `interrupted at deadline` in the pass that reconciles it),
//!   again by `carry_out_intents`, and by `work_interrupt` before it
//!   decides (Task 27 review m3): the stream never grows. The drive
//!   hook reads a copy of its own (Task 16b review m7).
//! - **`work_interrupt`** (feature `host.delegated`; design I.4.5;
//!   host-work-v1 §11.2): the task's sender holding `interrupt`, or the
//!   owner, interrupts a delegated task's turn while it is the session's
//!   current turn, through the same entries and the same record of this
//!   run's writes (`Runs`), so a turn gets one Esc from it and a pending
//!   intent together (ruling T27a: one Esc per attempt and turn, from any
//!   source). A one-shot request: no intent, nothing repeated, and the
//!   turn it ends reads `turn interrupted`. A stop, so it is served while
//!   hosting is paused too (`stops_while_paused`), except after a
//!   receipt-database fault or with the session journal halted (`busy`).
use super::*;
use crate::runtime::delegated::attempts::{AttemptEnd, SessionAnswer, attempt_end};
use crate::runtime::delegated::authority::interrupter;
use crate::runtime::delegated::intents::{
    AttemptNow, Decision, Intent, IntentReason, intents_pass,
};
use crate::session_protocol::host::{HostInterrupt, Immutable, Provenance, Withdrawal};

/// Design I.4.4: the delegated task `r` waits to start or runs
/// (`submitting`, `submitted`: an attempt `accepted`, or its turn) at its
/// deadline on `D` (`now_d`; none: no reading, nothing compared).
pub(super) fn past_deadline(r: &WorkRecord, now_d: Option<u64>) -> bool {
    r.delegated.is_some()
        && matches!(r.status.state, WorkState::Submitting | WorkState::Submitted)
        && now_d.is_some_and(|d| d >= r.task.expires_at)
}

/// Host-work-v1 §11.2: a `work_interrupt` that found the task's turn not
/// the session's current turn answers the task's status as it is, `detail`
/// `not running` in this one result (never stored).
fn not_running(mut status: WorkStatus) -> ResultBody {
    status.detail = details::NOT_RUNNING.into();
    ResultBody::Work { work: status }
}

impl HostBridge {
    /// The reports of host interrupt writes since the last call, taken into
    /// this run's intents (a delivery's turn stored as `delivered_turn`)
    /// before the scheduling pass reconciles any receipt, so a turn the
    /// deadline's Esc ended is known as the deadline's in that pass (Task 26
    /// review M1). With nothing delegated possible they are dropped.
    pub(super) fn take_interrupt_reports(&mut self) -> anyhow::Result<()> {
        let reports = self.host_interrupt_reports();
        if reports.is_empty() || !self.may_hold_delegated() {
            return Ok(());
        }
        let now = self.clock.now();
        let work = &mut self.work;
        let Some(store) = work.store.as_ref() else {
            return Ok(());
        };
        work.intents.reported(store, &reports, now)
    }

    /// Whether a stop requested while hosting is paused (`work_interrupt`,
    /// ruling T27a) is served now: `host.delegated` on, the store open,
    /// recovered and without a receipt-database fault, on a paired host.
    /// The r9 engine takes `work_interrupt` while paused only then
    /// (`R9Host::enable_host_work_stops`), and the paused pass hands it to
    /// the bridge; everything else stays `busy` until hosting is back.
    pub(super) fn stops_while_paused(&self, identity: &HostTarget) -> bool {
        self.features.delegated
            && identity.account_id != UNPAIRED
            && !self.work.error
            && self.work.recovered
            && self.work.store.is_some()
    }

    /// Ruling T26a: hosting is paused (`runtime.toml` doesn't load, or
    /// `enabled = false`), and the stops still run (see the module doc): a
    /// fresh `D`, the deadline's intents of tasks past it, every pending
    /// intent carried out. Only once the store was recovered, with no
    /// receipt-database fault, and where a delegated task may exist; on the
    /// scheduling pass's cadence, whose time the caller took.
    pub(super) fn paused_stops(&mut self, cx: &mut Cx) {
        if self.work.error
            || !self.work.recovered
            || self.work.store.is_none()
            || !self.may_hold_delegated()
            // Debug builds: held by the test (`hold_host_work`).
            || crate::runtime::test_hooks::host_work_held()
        {
            return;
        }
        #[cfg(debug_assertions)]
        {
            self.work.passes += 1;
        }
        let now_d = self.take_reading();
        let stopped = (|| -> anyhow::Result<()> {
            for r in self.work.store.as_ref().unwrap().active_tasks()? {
                if past_deadline(&r, now_d) {
                    self.deadline_intent(&r)?;
                }
            }
            self.carry_out_intents(cx).map(|_| ())
        })();
        if stopped.is_err() {
            self.work_fail();
        }
    }

    /// Design I.4.4: the delegated task `r`, unstarted or running
    /// (`submitting`, `submitted`), reached its deadline on `D`: an
    /// interrupt intent with reason `deadline` for its current attempt
    /// (`receipt_id`), committed before anything acts on it. Once per
    /// attempt (a read first, so a pass after it writes nothing).
    pub(super) fn deadline_intent(&self, r: &WorkRecord) -> anyhow::Result<()> {
        let store = self.work.store.as_ref().unwrap();
        let (task, attempt) = (&r.task.task_id, &r.status.receipt_id);
        if store.has_intent(task, attempt, &IntentReason::Deadline)? {
            return Ok(());
        }
        let tx = store.immediate()?;
        store.write_intent(&tx, task, attempt, IntentReason::Deadline)?;
        tx.commit()?;
        Ok(())
    }

    /// One pass of the pending interrupt intents (see the module doc): the
    /// task ids of the intents it looked at, oldest first. The reports of
    /// host interrupt writes are taken whatever the store holds; with
    /// nothing delegated possible (`may_hold_delegated`) nothing else is
    /// read, as on main.
    pub(super) fn carry_out_intents(&mut self, cx: &mut Cx) -> anyhow::Result<Vec<String>> {
        let reports = self.host_interrupt_reports();
        if !self.may_hold_delegated() {
            return Ok(Vec::new());
        }
        let now = self.clock.now();
        let mut runs = std::mem::take(&mut self.work.intents);
        let decided = {
            let store = self.work.store.as_ref().unwrap();
            let mut failed = None;
            let decided = intents_pass(
                store,
                &mut |i| match self.attempt_now(i, cx) {
                    Ok(now) => now,
                    Err(e) => {
                        failed.get_or_insert(e);
                        AttemptNow::NotShown
                    }
                },
                &reports,
                &mut runs,
                now,
            );
            match (decided, failed) {
                (Ok(decided), None) => Ok(decided),
                (Err(e), _) | (_, Some(e)) => Err(e),
            }
        };
        let decided = match decided {
            Ok(decided) => decided,
            Err(e) => {
                self.work.intents = runs;
                return Err(e);
            }
        };
        // What acts on the session host runs after its `advance` (Task 15
        // review M6: a lease past its deadline ends `expired`, not
        // `revoked`); each action checks the turn again itself.
        if decided.iter().any(|(_, d)| {
            matches!(
                d,
                Decision::Deliver { .. } | Decision::RevokeOnly | Decision::Withdraw
            )
        }) {
            let effects = self.host.advance(self.clock.now());
            self.exec(effects, cx);
        }
        let mut looked = Vec::new();
        let mut result = Ok(());
        for (intent, decision) in decided {
            looked.push(intent.task_id.clone());
            if let Err(e) = self.carry_out(&intent, decision, &mut runs, cx) {
                result = Err(e);
                break;
            }
        }
        // `work_interrupt`'s record of a turn goes once its attempt no
        // longer executes (ruling T27a: one Esc per attempt and turn).
        runs.prune(&mut |task, attempt| {
            self.host
                .attempt_receipt(attempt, task)
                .is_some_and(|rc| rc.state == ReceiptState::Executing)
        });
        self.work.intents = runs;
        result.map(|()| looked)
    }

    /// Carries out `decision` for `intent`.
    fn carry_out(
        &mut self,
        intent: &Intent,
        decision: Decision,
        runs: &mut crate::runtime::delegated::intents::Runs,
        cx: &mut Cx,
    ) -> anyhow::Result<()> {
        let attempt = intent.attempt_id.as_str();
        match decision {
            Decision::Wait => {}
            Decision::Done => {
                self.work.store.as_ref().unwrap().intent_done(intent.id)?;
                runs.forget(attempt);
            }
            Decision::Deliver { turn } => {
                if let Some(sid) = self.intent_session(intent)
                    && self.host_interrupt(&sid, attempt, cx) == Interrupted::Written
                {
                    runs.written(attempt, &turn);
                }
            }
            Decision::RevokeOnly => {
                if let Some(sid) = self.intent_session(intent) {
                    let _ = self.host_interrupt_revoke_lease(&sid, attempt, cx);
                }
            }
            Decision::Withdraw => {
                if self.withdraw_for_intent(intent, cx)? {
                    self.work.store.as_ref().unwrap().intent_done(intent.id)?;
                    runs.forget(attempt);
                }
            }
        }
        Ok(())
    }

    /// The session of `intent`'s attempt, as its receipt names it.
    fn intent_session(&self, intent: &Intent) -> Option<String> {
        self.host
            .attempt_receipt(&intent.attempt_id, &intent.task_id)
            .map(|r| r.target.session_id)
    }

    /// What `intent`'s attempt is now ([`HostBridge::attempt_state`]).
    fn attempt_now(&self, intent: &Intent, cx: &mut Cx) -> anyhow::Result<AttemptNow> {
        self.attempt_state(&intent.task_id, &intent.attempt_id, cx)
    }

    /// What attempt `attempt` of `task` is now: its receipt (host-work's
    /// request for that task only), its row's end, and, while it executes,
    /// the start's reconciliation and the chat's half of the turn check
    /// (`running_request`: today's Esc rule and the chat's current request).
    fn attempt_state(&self, task: &str, attempt: &str, cx: &mut Cx) -> anyhow::Result<AttemptNow> {
        let store = self.work.store.as_ref().unwrap();
        let Some(receipt) = self.host.attempt_receipt(attempt, task) else {
            return Ok(AttemptNow::Absent {
                live: store.may_submit(task, attempt)?,
            });
        };
        Ok(match receipt.state {
            ReceiptState::Accepted => AttemptNow::Unstarted,
            ReceiptState::Rejected => AttemptNow::Rejected {
                live: store.may_submit(task, attempt)?,
            },
            ReceiptState::Completed | ReceiptState::OutcomeUnknown => AttemptNow::Ended,
            ReceiptState::Executing if self.host_work_reconciling(attempt) => {
                AttemptNow::Reconciling
            }
            ReceiptState::Executing => {
                let sid = receipt.target.session_id.as_str();
                let shown = running_request(cx, sid).as_deref() == Some(attempt);
                // Shown running: the chat's current turn is the attempt's.
                // A chat that names no turn (unreachable: the request is
                // the turn's) shows nothing, so it never gets a second Esc
                // under another name (Task 26 review M3).
                match session_of(cx, sid)
                    .filter(|_| shown)
                    .and_then(|s| s.chat.current_turn_id().map(str::to_string))
                {
                    Some(turn) => AttemptNow::Running { turn },
                    None => AttemptNow::NotShown,
                }
            }
        })
    }

    /// `work_interrupt` of `task_id` from `a` (feature `host.delegated`;
    /// design I.4.5; host-work-v1 §11.2; session-v1 R9.14 item 5). Only with
    /// `host.delegated` on (off: `busy`, as before the hook,
    /// [`crate::runtime::delegated::request`]). Only a delegated task, and
    /// only its sender holding `interrupt` with current authority or the
    /// owner ([`interrupter`]): anything else is `forbidden` (a v1 task,
    /// one the host doesn't have, `local`).
    ///
    /// When the task's current attempt (`receipt_id`) runs the session's
    /// current turn (`attempt_state`'s `Running`: executing, rebound, and
    /// shown running by the chat), the turn is interrupted with host
    /// authority after the session host's `advance`: the bridge's
    /// `host_interrupt`, whose turn check runs again. The result is the
    /// task's status as it stood before (§11.2). One Esc per attempt and
    /// turn, from any source (ruling T27a): the write goes into this run's
    /// record (`Runs::requested`), shared with the intents, and when that
    /// record says the turn already got its interrupt, or one is in flight
    /// (`Runs::running`, after the reports that came since the last pass
    /// are taken in: Task 27 review m3), nothing is written: only another
    /// controller's lease is revoked, once, and the result is the task's
    /// status as it is (its own detail: the turn is current, so not `not
    /// running`). A report that can't be taken in is a receipt-database
    /// fault: `busy`.
    ///
    /// Served while hosting is paused too, as a stop (ruling T27a, like
    /// T26a's deadline step): see `stops_while_paused`.
    ///
    /// Otherwise (queued, an attempt not executing, its turn not shown
    /// running or still being reconciled after a restart, or ended) nothing
    /// happens: the status as it is, with `detail` `not running` in this
    /// result only, never stored. A halted session journal is `busy`: the
    /// turn may be current, and nothing passes until the restart.
    pub(super) fn work_interrupt(
        &mut self,
        a: &Sender,
        req: &hw::Request,
        task_id: &str,
        cx: &mut Cx,
    ) -> Result<ResultBody, HostWorkError> {
        if !self.features.delegated {
            return crate::runtime::delegated::request(self.features, req);
        }
        let store = self.work.store.as_ref().ok_or("busy")?;
        let r = store
            .work(task_id)
            .map_err(|_| "busy")?
            .ok_or("forbidden")?;
        let adm = r.delegated.as_ref().ok_or("forbidden")?;
        self.delegated_caller_by(a, &r, adm, interrupter)
            .map_err(|_| "forbidden")?;
        let status = r.status;
        let attempt = status.receipt_id.clone();
        let now = self
            .attempt_state(task_id, &attempt, cx)
            .map_err(|_| "busy")?;
        let (AttemptNow::Running { turn }, Some(sid)) = (
            now,
            self.host
                .attempt_receipt(&attempt, task_id)
                .map(|rc| rc.target.session_id),
        ) else {
            return Ok(not_running(status));
        };
        // The reports that came since the last pass first (Task 27 review
        // m3): a write that wrote nothing frees the turn now, so this
        // request isn't lost as a revoke-only answer.
        if self.take_interrupt_reports().is_err() {
            self.work_fail();
            return Err("busy".into());
        }
        // Task 15 review M6: a lease past its deadline ends `expired`.
        let effects = self.host.advance(self.clock.now());
        self.exec(effects, cx);
        let done = match self.work.intents.running(&attempt, &turn, self.clock.now()) {
            Decision::Deliver { .. } => self.host_interrupt(&sid, &attempt, cx),
            _ => self.host_interrupt_revoke_lease(&sid, &attempt, cx),
        };
        match done {
            Interrupted::Written => {
                self.work.intents.requested(task_id, &attempt, &turn);
                Ok(ResultBody::Work { work: status })
            }
            Interrupted::Revoked => Ok(ResultBody::Work { work: status }),
            Interrupted::Refused(HostInterrupt::Halted) => Err("busy".into()),
            Interrupted::Refused(_) => Ok(not_running(status)),
        }
    }

    /// Withdraws `intent`'s unstarted attempt (design I.5.7): an `accepted`
    /// one in the session host (`withdrawn by the host`); a `rejected` one
    /// ends from its receipt; one absent from the recovered journal was
    /// never admitted. The task takes the intent's state with the attempt's
    /// end (`end_attempt`: one `BEGIN IMMEDIATE` transaction, the state
    /// first). True when the intent is done: the attempt ended (here or
    /// already); false when the withdrawal found it started (the next pass
    /// interrupts it) or couldn't be recorded (the journal halted: nothing
    /// starts until the restart, which withdraws it).
    fn withdraw_for_intent(&mut self, intent: &Intent, cx: &mut Cx) -> anyhow::Result<bool> {
        let store = self.work.store.as_ref().unwrap();
        let (task, attempt) = (intent.task_id.as_str(), intent.attempt_id.as_str());
        let Some(mut r) = store.work(task)? else {
            return Ok(true);
        };
        let Some(a) = store
            .live_attempt(task)?
            .filter(|a| a.attempt_id == attempt)
        else {
            return Ok(true);
        };
        let end = match self.host.attempt_receipt(attempt, task) {
            // Absent from the recovered journal: never admitted (I.6.3).
            None => AttemptEnd::NotAdmitted,
            Some(rc) if rc.state == ReceiptState::Rejected => attempt_end(
                SessionAnswer::Receipt(rc.state, rc.detail.as_deref()),
                false,
            )
            .unwrap_or(AttemptEnd::Rejected),
            Some(_) => {
                // In the journal (`accepted`): the withdrawal finds it by
                // its id, so these values go nowhere.
                let immutable = Immutable {
                    target: r.task.target.clone(),
                    payload_digest: String::new(),
                    provenance: Provenance {
                        task_id: task.to_string(),
                        sender: r.principal.clone(),
                    },
                };
                let withdrawal = self.host.withdraw(attempt, &immutable);
                let effects = self.host.take_effects();
                self.exec(effects, cx);
                match withdrawal {
                    Withdrawal::Started | Withdrawal::Halted => return Ok(false),
                    w => attempt_end(SessionAnswer::Withdrawal(w), false)
                        .unwrap_or(AttemptEnd::Withdrawn { counted: true }),
                }
            }
        };
        self.end_attempt(&mut r, &a, end, intent.reason.withdrawn())?;
        Ok(true)
    }
}

//! Dispatch of delegated tasks (design I.4.2, I.4.3, I.6.4; host-work-v1
//! §11.6; session-v1 R9.14): a delegated sender's task runs under the
//! session host's `host-work` principal, never on the sender's channel.
//!
//! In each scheduling pass, a delegated task:
//!
//! - **with a live attempt** is settled from the session host's receipt of
//!   it (`attempt_receipt`: only host-work's request for that task): still
//!   `accepted`, it waits for its turn and holds its session, unless an
//!   event that settles the task applies (a revocation, a removal, a
//!   narrowing off the target, a route change, a frozen, held or faulted
//!   device list): then it is withdrawn first and the task takes the
//!   event's state once the withdrawal is confirmed (I.5.5); started, the
//!   attempts are over and the task follows that receipt; withdrawn,
//!   rejected or never admitted, the attempt ends with that proof and the
//!   task takes the event's state (the start check's, kept with the
//!   attempt), in one `BEGIN IMMEDIATE` transaction, the state first, so it
//!   beats `too many attempts`;
//! - **waiting** (`queued`, `blocked`) gets an attempt when conditions 1 to
//!   6 hold (the deadline on the delegated clock): one `BEGIN IMMEDIATE`
//!   transaction makes the attempt and the task's `submitting`, it commits,
//!   then the attempt's prompt is submitted (only the task's live attempt,
//!   checked after the commit), with its provenance, in the same
//!   synchronous step, after the session host's clock moved. It goes
//!   through the normal dispatch, so its turn is journaled.
//! - **blocked for a hold, a closed gate or a deferred entry** doesn't hold
//!   its session (§11.6), so later tasks of other senders, local ones
//!   included, may pass it; the sender's own later tasks there wait behind
//!   it, so one sender's tasks keep their order.
//!
//! Never v1's rules: no sender channel, no `work_lost`. So the events of
//! design I.3.3 reach a delegated task only through the start check's
//! conditions (`may_start`, `Event::outcome`): its sender's grant expiring
//! and its control generation moving fail nothing; a narrowing fails only
//! an unstarted task the grant no longer covers, a route change only an
//! unstarted one; a removal or a revocation cancels an unstarted one
//! (`sender revoked`). Tasks awaiting their result or of unknown outcome
//! are kept (`Store::settle_lost` reads v1 rows only). With `host.delegated`
//! off (the hook removed after tasks were accepted, step 4's Decision 10),
//! an unstarted task stays `blocked`, `host.delegated is off`, and expires at
//! its deadline on the delegated clock; a started one follows its receipt.
use super::*;
use crate::runtime::delegated::attempts::{Attempt, AttemptEnd, SessionAnswer, attempt_end};
use crate::runtime::delegated::start::{EXPIRED_BEFORE_SUBMISSION, Event, StartTask, may_start};
use crate::session_protocol::host::{
    DETAIL_SESSION_CLOSED, DETAIL_TRUST_CHANGED, Immutable, Provenance, Withdrawal,
};

/// A task that waits for its first attempt (host-work v1's text).
pub(super) const WAITING_FOR_A_READY_AGENT: &str = "waiting for a ready agent";
/// The dispatch intent is durable (host-work v1's text).
const DISPATCH_INTENT: &str = "dispatch intent persisted";

/// What a scheduling pass's delegated tasks share with each other.
#[derive(Default)]
pub(super) struct Waits {
    /// (sender, session) → the detail of the sender's earliest task there
    /// that waits without holding the session: its later tasks there wait
    /// behind it.
    by_sender: HashMap<(String, String), &'static str>,
}

impl HostBridge {
    /// One delegated task `r` in a scheduling pass (see the module doc):
    /// sessions it holds go into `occupied`; `now_d` is the delegated
    /// clock's reading of the pass (none: no clock, or a damaged record:
    /// delegated work waits).
    pub(super) fn schedule_delegated(
        &mut self,
        r: &mut WorkRecord,
        occupied: &mut HashSet<String>,
        waits: &mut Waits,
        now_d: Option<u64>,
        cx: &mut Cx,
    ) -> anyhow::Result<()> {
        let sid = r.task.target.session_id.clone();
        // Design I.4.4: an attempt still waiting to start, or a turn still
        // running, at the deadline: an interrupt intent, durable before the
        // pass carries it out (after this loop).
        if matches!(r.status.state, WorkState::Submitting | WorkState::Submitted)
            && now_d.is_some_and(|d| d >= r.task.expires_at)
        {
            self.deadline_intent(r)?;
        }
        let live = self
            .work
            .store
            .as_ref()
            .unwrap()
            .live_attempt(&r.task.task_id)?;
        if let Some(attempt) = live
            && self.settle_attempt(r, &attempt, now_d, cx)?
        {
            occupied.insert(sid);
            return Ok(());
        }
        match r.status.state {
            // Its last attempt started: the task follows that receipt.
            WorkState::Submitting | WorkState::Submitted => {
                self.follow_receipt(r, cx)?;
                if matches!(
                    r.status.state,
                    WorkState::Submitting | WorkState::Submitted | WorkState::OutcomeUnknown
                ) {
                    occupied.insert(sid);
                }
                Ok(())
            }
            WorkState::Queued | WorkState::Blocked => {
                self.dispatch_delegated(r, occupied, waits, now_d, cx)
            }
            _ => Ok(()),
        }
    }

    /// `r`'s last attempt started: the task follows that receipt (the turn
    /// its prompt became, stored once known), written when it changed.
    pub(super) fn follow_receipt(&mut self, r: &mut WorkRecord, cx: &Cx) -> anyhow::Result<()> {
        let before = (r.status.clone(), r.turn_id.clone());
        if r.turn_id.is_none() {
            r.turn_id = self.collab_task_turn(r, cx.sessions);
        }
        self.reconcile_work(r)?;
        if (&r.status, &r.turn_id) != (&before.0, &before.1) {
            self.work.store.as_ref().unwrap().save_work(r)?;
        }
        Ok(())
    }

    /// A waiting delegated task: an attempt when conditions 1 to 6 hold.
    fn dispatch_delegated(
        &mut self,
        r: &mut WorkRecord,
        occupied: &mut HashSet<String>,
        waits: &mut Waits,
        now_d: Option<u64>,
        cx: &mut Cx,
    ) -> anyhow::Result<()> {
        let sid = r.task.target.session_id.clone();
        let order = (r.principal.clone(), sid.clone());
        // Decision 10: accepted while `host.delegated` was on, never
        // dispatched without it; its deadline still holds (on `D`).
        if !self.features.delegated {
            if now_d.is_some_and(|d| d >= r.task.expires_at) {
                return self.settle_task(r, WorkState::Expired, EXPIRED_BEFORE_SUBMISSION);
            }
            return self.block(r, details::HOST_DELEGATED_IS_OFF);
        }
        // No reading of the delegated clock: nothing is compared with a
        // deadline, so nothing starts; the task waits as it is.
        let Some(now_d) = now_d else {
            return Ok(());
        };
        let Some(task) = StartTask::of(r) else {
            return Ok(());
        };
        // Conditions 1 (the deadline) and 2 to 5. The view's lock is let go
        // before anything calls into the session host.
        let checked = may_start(&self.start_view(), &task, Some(now_d));
        if let Err(event) = checked {
            let (state, detail) = event.outcome();
            if state.terminal() {
                return self.settle_task(r, state, detail);
            }
            if event.holds_session() {
                occupied.insert(sid);
            } else {
                waits.by_sender.entry(order).or_insert(detail);
            }
            return self.block(r, detail);
        }
        // One sender's tasks keep their order behind one that lets the
        // session go (what settles a task applies to it all the same).
        if let Some(detail) = waits.by_sender.get(&order) {
            return self.block(r, detail);
        }
        // Condition 1: no earlier task of its session holds it.
        if !occupied.insert(sid.clone()) {
            return self.block(r, "waiting for an earlier task on this session");
        }
        // Condition 6.
        if let Some(reason) = self.delegated_session_blocker(r, cx) {
            return self.block(r, reason);
        }
        let paths = self
            .work
            .store
            .as_ref()
            .unwrap()
            .attachment_paths(&r.attachment_owner, &r.task.attachments);
        let Ok(paths) = paths else {
            return self.block(r, "waiting for verified screenshot attachments");
        };
        // The `host-work` principal's attachment: it exists once the
        // session host welcomed it (a halted journal welcomes none).
        let Some(att) = self.host_work_attachment().map(str::to_string) else {
            return Ok(());
        };
        let Some((binding, _)) = self.host.binding_for_work(&att, &r.task.target) else {
            return self.block(r, "target session unavailable");
        };
        // A journal that halted earlier in this pass (the view's halt is the
        // pass's): no attempt it would only refuse (Task 19 review M4).
        if self.host.journal_halted() {
            return self.block(r, details::JOURNAL_HALTED);
        }
        // A fresh tag for this attempt, drawn after its input is fixed.
        let (prompt, tag) = match self.render_task_prompt(r, &paths)? {
            Ok(rendered) => rendered,
            Err(detail) => return self.settle_task(r, WorkState::Failed, &detail),
        };
        // One `BEGIN IMMEDIATE` transaction: the task still waits, its
        // attempt (no earlier one live, none started, fewer than 8 counted)
        // and its `submitting`; committed before the submit.
        let attempt = {
            let store = self.work.store.as_ref().unwrap();
            let tx = store.immediate()?;
            let Some(mut fresh) = store.work(&r.task.task_id)? else {
                return Ok(());
            };
            if !matches!(fresh.status.state, WorkState::Queued | WorkState::Blocked) {
                *r = fresh;
                return Ok(());
            }
            let attempt = match store.new_attempt(&tx, &r.task.task_id) {
                Ok(attempt) => attempt,
                // Refused (it started, one is live, too many): nothing made.
                Err(e) if e.is::<crate::runtime::delegated::attempts::AttemptRefused>() => {
                    drop(tx);
                    if let Some(fresh) = store.work(&r.task.task_id)? {
                        *r = fresh;
                    }
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            fresh = store
                .work(&r.task.task_id)?
                .ok_or_else(|| anyhow::anyhow!("no task {}", r.task.task_id))?;
            fresh.status.state = WorkState::Submitting;
            fresh.status.detail = DISPATCH_INTENT.into();
            store.save_work(&fresh)?;
            tx.commit()?;
            *r = fresh;
            attempt
        };
        // Debug builds: the runtime is killed here, the attempt committed
        // and not submitted (VII.A test 7's first crash point).
        #[cfg(not(test))]
        if crate::runtime::test_hooks::crash_after_attempt_commit() {
            eprintln!(
                "atem runtime: test hook: killed after an attempt's commit, before its submit"
            );
            // SAFETY: signals this process; nothing after it runs.
            unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
        }
        // The start check may be asked about it from here on.
        self.start_view().register(&attempt.attempt_id, task);
        if let Err((detail, error)) = self.record_prompt_pause(&sid, &attempt.attempt_id, &tag) {
            eprintln!("atem runtime: {sid}: {detail}: {error}");
            // Never submitted: the attempt ends, never admitted.
            return self.end_attempt(
                r,
                &attempt,
                AttemptEnd::NotAdmitted,
                (WorkState::Blocked, detail),
            );
        }
        // Only the task's live attempt, as committed.
        if !self
            .work
            .store
            .as_ref()
            .unwrap()
            .may_submit(&r.task.task_id, &attempt.attempt_id)?
        {
            return Ok(());
        }
        // The session host's clock first (leases and timers due by now),
        // then the submit, which acquires the lease with the prompt.
        let effects = self.host.advance(self.clock.now());
        self.exec(effects, cx);
        let id = uuid::Uuid::new_v4().to_string();
        let data = json!({"v": 1, "op": "submit", "id": id, "binding": binding,
            "request_id": attempt.attempt_id, "kind": "prompt", "payload": {"text": prompt},
            "acquire": true});
        let provenance = Provenance {
            task_id: r.task.task_id.clone(),
            sender: r.principal.clone(),
        };
        let effects = self.host.submit_host_work(&att, data, provenance);
        let refused = effects.iter().find_map(|e| match e {
            Effect::Send {
                attachment,
                message: Envelope::Session(m),
            } if *attachment == att && m.re.as_deref() == Some(id.as_str()) => match &m.op {
                wire::Op::Error { code, .. } => Some(*code),
                _ => None,
            },
            _ => None,
        });
        self.exec(effects, cx);
        match refused {
            // Refused before anything was recorded: never admitted (or its
            // id another submitter's, not counted), so it may be tried
            // again with a fresh id.
            Some(code)
                if self
                    .host
                    .attempt_receipt(&attempt.attempt_id, &r.task.task_id)
                    .is_none() =>
            {
                let end = attempt_end(SessionAnswer::Refused(code), false)
                    .unwrap_or(AttemptEnd::NotAdmitted);
                self.end_attempt(
                    r,
                    &attempt,
                    end,
                    (WorkState::Queued, WAITING_FOR_A_READY_AGENT),
                )
            }
            _ => self
                .settle_attempt(r, &attempt, Some(now_d), cx)
                .map(|_| ()),
        }
    }

    /// Settles the live attempt `a` of `r` from the session host's receipt
    /// of it (design I.6.3, I.6.4): true while it is still live (`accepted`:
    /// it waits for its turn, holding its session). Started, its end is
    /// `started` and the task follows the receipt; with a proof of no
    /// effect, it ends with it and the task takes the event's state.
    fn settle_attempt(
        &mut self,
        r: &mut WorkRecord,
        a: &Attempt,
        now_d: Option<u64>,
        cx: &mut Cx,
    ) -> anyhow::Result<bool> {
        let receipt = self.host.attempt_receipt(&a.attempt_id, &r.task.task_id);
        // The start check's withdrawal for a hold isn't counted.
        let event = self.start_view().refused(&a.attempt_id);
        let held = event == Some(Event::Held);
        let end = match &receipt {
            // Absent: never admitted (I.6.3).
            None => Some(AttemptEnd::NotAdmitted),
            Some(rc) => attempt_end(SessionAnswer::Receipt(rc.state, rc.detail.as_deref()), held),
        };
        let Some(end) = end else {
            // `accepted`, and an event that settles the task applies now:
            // the attempt is withdrawn first, and the task settles from
            // the withdrawal (design I.5.5, I.5.6).
            if self.withdraw_for_event(r, a, now_d, cx)? {
                return Ok(false);
            }
            // `accepted`: live, waiting for its turn.
            let before = r.status.clone();
            self.reconcile_work(r)?;
            if r.status != before {
                self.work.store.as_ref().unwrap().save_work(r)?;
            }
            return Ok(true);
        };
        if end == AttemptEnd::Started {
            self.end_started(r, a)?;
            return Ok(false);
        }
        // A proof of no effect: the task's next state.
        let detail = receipt.as_ref().and_then(|rc| rc.detail.clone());
        let withdrawn_at_start = matches!(end, AttemptEnd::Withdrawn { .. })
            && detail.as_deref() == Some(details::WITHDRAWN_BY_THE_HOST);
        let next = match (end, detail.as_deref(), event) {
            // The target is gone (I.6.3): it fails with the receipt's detail.
            (AttemptEnd::Rejected, Some(DETAIL_SESSION_CLOSED), _) => {
                (WorkState::Failed, DETAIL_SESSION_CLOSED)
            }
            (AttemptEnd::Rejected, Some(DETAIL_TRUST_CHANGED), _) => {
                (WorkState::Failed, DETAIL_TRUST_CHANGED)
            }
            // Withdrawn at the start: the event the check refused it for.
            (_, _, Some(event)) if withdrawn_at_start => event.outcome(),
            // Otherwise it waits again, unless an event settles it now.
            _ => self.waiting_state(r, now_d),
        };
        self.end_attempt(r, a, end, next)?;
        Ok(false)
    }

    /// The live attempt `a` of `r` started (its receipt `executing` or past
    /// it): the task's attempts are over, and it follows that receipt. One
    /// `BEGIN IMMEDIATE` transaction writes the reconciled task and ends the
    /// attempt `started`.
    pub(super) fn end_started(&mut self, r: &mut WorkRecord, a: &Attempt) -> anyhow::Result<()> {
        let mut next = r.clone();
        self.reconcile_work(&mut next)?;
        let store = self.work.store.as_ref().unwrap();
        let tx = store.immediate()?;
        store.save_work(&next)?;
        store.end_attempt(&tx, &r.task.task_id, &a.attempt_id, AttemptEnd::Started)?;
        tx.commit()?;
        *r = next;
        self.start_view().forget(&a.attempt_id);
        Ok(())
    }

    /// The live attempt `a` of `r` waits `accepted` (unstarted, design
    /// I.3.2): when an event that settles the task applies now (the sender
    /// revoked or removed, its grant narrowed off the target, its route
    /// changed, the device list frozen, held or faulted: `may_start`'s, so
    /// the details are the dispatch's own), the attempt is withdrawn in the
    /// session host and, once that is confirmed, ended, the task taking the
    /// event's state (design I.3.3, I.5.5, I.5.6; VII.A test 6). True when
    /// it did. A withdrawal that found the attempt started leaves it to its
    /// receipt; one that couldn't be confirmed (the journal halted) leaves
    /// it as it is: nothing becomes `executing` until the restart, which
    /// withdraws it. The deadline is left to the start check (and the
    /// deadline's interrupt intents), and with `host.delegated` off nothing
    /// is withdrawn here (step 4's Decision 10: a started task follows its
    /// receipt).
    fn withdraw_for_event(
        &mut self,
        r: &mut WorkRecord,
        a: &Attempt,
        now_d: Option<u64>,
        cx: &mut Cx,
    ) -> anyhow::Result<bool> {
        if !self.features.delegated || self.host.journal_halted() {
            return Ok(false);
        }
        let Some(task) = StartTask::of(r) else {
            return Ok(false);
        };
        let checked = may_start(&self.start_view(), &task, now_d);
        let Err(event) = checked else {
            return Ok(false);
        };
        if !event.outcome().0.terminal() || event == Event::Expired {
            return Ok(false);
        }
        // The request is in the journal (`accepted`), so the withdrawal
        // finds it by its id: these values go nowhere.
        let immutable = Immutable {
            target: r.task.target.clone(),
            payload_digest: String::new(),
            provenance: Provenance {
                task_id: r.task.task_id.clone(),
                sender: r.principal.clone(),
            },
        };
        let withdrawal = self.host.withdraw(&a.attempt_id, &immutable);
        let effects = self.host.take_effects();
        self.exec(effects, cx);
        let end = match withdrawal {
            Withdrawal::Started | Withdrawal::Halted => return Ok(false),
            w => attempt_end(SessionAnswer::Withdrawal(w), false)
                .unwrap_or(AttemptEnd::Withdrawn { counted: true }),
        };
        self.end_attempt(r, a, end, event.outcome())?;
        Ok(true)
    }

    /// Where a task that may get another attempt goes: the event that stops
    /// it now if one does (a revocation while it waited cancels it, I.6.3),
    /// else back to `queued`.
    fn waiting_state(&self, r: &WorkRecord, now_d: Option<u64>) -> (WorkState, &'static str) {
        if !self.features.delegated {
            return (WorkState::Blocked, details::HOST_DELEGATED_IS_OFF);
        }
        let checked = StartTask::of(r).map(|task| may_start(&self.start_view(), &task, now_d));
        match checked {
            Some(Err(event)) => event.outcome(),
            _ => (WorkState::Queued, WAITING_FOR_A_READY_AGENT),
        }
    }

    /// Ends attempt `a` of `r` with `end`, the task taking `next`, in one
    /// `BEGIN IMMEDIATE` transaction: the state first, so an event's beats
    /// `too many attempts` (`end_attempt` fails only a task still waiting).
    /// A task whose stored state is already terminal (a cancel, an event
    /// settled it) keeps it: only the attempt ends. Never pasted: its
    /// terminal pause goes.
    pub(super) fn end_attempt(
        &mut self,
        r: &mut WorkRecord,
        a: &Attempt,
        end: AttemptEnd,
        next: (WorkState, &'static str),
    ) -> anyhow::Result<()> {
        {
            let store = self.work.store.as_ref().unwrap();
            let tx = store.immediate()?;
            let mut record = store
                .work(&r.task.task_id)?
                .ok_or_else(|| anyhow::anyhow!("no task {}", r.task.task_id))?;
            if !record.status.state.terminal() {
                record.status.state = next.0;
                record.status.detail = next.1.into();
                store.save_work(&record)?;
            }
            store.end_attempt(&tx, &r.task.task_id, &a.attempt_id, end)?;
            tx.commit()?;
            *r = store
                .work(&r.task.task_id)?
                .ok_or_else(|| anyhow::anyhow!("no task {}", r.task.task_id))?;
        }
        self.start_view().forget(&a.attempt_id);
        let sid = r.task.target.session_id.clone();
        self.drop_prompt_pause(&sid, &a.attempt_id);
        Ok(())
    }

    /// `r` waits, `blocked` with `detail` (written only when it changes).
    fn block(&self, r: &mut WorkRecord, detail: &str) -> anyhow::Result<()> {
        if r.status.state != WorkState::Blocked || r.status.detail != detail {
            r.status.state = WorkState::Blocked;
            r.status.detail = detail.into();
            self.work.store.as_ref().unwrap().save_work(r)?;
        }
        Ok(())
    }

    /// `r` settles, `state` with `detail` (cancelled, failed, expired).
    pub(super) fn settle_task(
        &self,
        r: &mut WorkRecord,
        state: WorkState,
        detail: &str,
    ) -> anyhow::Result<()> {
        r.status.state = state;
        r.status.detail = detail.into();
        self.work.store.as_ref().unwrap().save_work(r)
    }

    /// Condition 6 (design I.4.3): the session is live, with chat, `ready`,
    /// no draft, no lease held, no approval open, and is the one the task's
    /// profile launched (its process, directory, provider and launch
    /// project). What it waits for, if it waits (host-work v1's texts).
    fn delegated_session_blocker(&self, r: &WorkRecord, cx: &Cx) -> Option<&'static str> {
        let sid = r.task.target.session_id.as_str();
        let Some(s) = SessionId::parse(sid).and_then(|id| cx.sessions.get(&id)) else {
            return Some("target session unavailable");
        };
        let profile = self.work.config.profile(&r.profile_id);
        if s.process_gen != r.task.target.process_gen
            || profile.is_none_or(|p| s.cwd != p.cwd || s.provider != p.provider)
            || self.projects.key_of(sid) != Some(r.project.as_str())
        {
            return Some("target session unavailable");
        }
        if !s.is_live() || !s.chat_v1 || s.chat.status().state != ChatState::Ready {
            return Some("agent is busy, unavailable or readiness is unknown");
        }
        if s.chat.has_unsent_input(s.input_count) {
            return Some("terminal has unsent input");
        }
        if self.host.lease_holder(sid).is_some() {
            return Some("waiting for controller to release the lease");
        }
        if self.approvals.values().any(|p| p.sid == sid) {
            return Some("waiting for approval resolution");
        }
        None
    }
}

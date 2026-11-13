//! The requests about a delegated sender's task, in the bridge (design
//! I.4.5, I.5.5, I.5.6; host-work-v1 §11.2 "Authority"; step 4's Decision
//! 15): who may query, cancel or complete it and read its reply (the
//! interaction rule, [`interaction`]), and a cancel that withdraws a live
//! attempt in the session host before the task is cancelled.
//!
//! v1 tasks never come here: `work_request_as` keeps host-work v1's caller
//! rule for them, byte for byte.
use super::*;
use crate::runtime::delegated::Admission;
use crate::runtime::delegated::attempts::{AttemptEnd, SessionAnswer, attempt_end};
use crate::runtime::delegated::authority::{Caller, Grounds, Refused, interaction};
use crate::runtime::delegated::start::Event;
use crate::session_protocol::host::{Immutable, Provenance, Withdrawal};
use crate::session_protocol::wire::ReceiptState;

/// A task cancelled before its prompt was submitted (host-work v1's text,
/// kept for delegated tasks: §11.6 adds none for a cancel).
pub(super) const CANCELLED_BEFORE_SUBMISSION: &str = "cancelled before submission";

impl HostBridge {
    /// The store may hold a delegated task: `host.delegated` is on, or the
    /// store held one when it opened (the delegated clock is built for it
    /// then, `ensure_clock`; with the hook off no new one is admitted).
    /// Otherwise nothing looks for one, as on main.
    pub(super) fn may_hold_delegated(&self) -> bool {
        self.features.delegated || self.work.clock.is_some()
    }

    /// Who `a` is to the delegated task `r`, admitted as `adm` (design
    /// I.4.5, Decision 15): its sender with current authority, or the owner.
    /// Read on the host's device list while it is open and serving, the
    /// sender's control standing, and a grant's expiry against the later of
    /// the wall clock (what resolved the caller's channel authority) and the
    /// delegated clock's `D`, which never trails it in a real build.
    pub(super) fn delegated_caller(
        &self,
        a: &Sender,
        r: &WorkRecord,
        adm: &Admission,
    ) -> Result<Caller, Refused> {
        self.delegated_caller_by(a, r, adm, interaction)
    }

    /// [`HostBridge::delegated_caller`] under `rule` ([`interaction`], or
    /// `work_interrupt`'s `interrupter`), on the same grounds.
    pub(super) fn delegated_caller_by(
        &self,
        a: &Sender,
        r: &WorkRecord,
        adm: &Admission,
        rule: crate::runtime::delegated::authority::Rule,
    ) -> Result<Caller, Refused> {
        let Some(authority) = a.remote() else {
            return Err(Refused::NotTheSender);
        };
        let Some(list) = self.open_list() else {
            return Err(Refused::NoList);
        };
        let standing = self
            .start_view()
            .standings
            .get(&adm.principal)
            .cloned()
            .unwrap_or_default();
        let now_d = self.start_view().now_d_ms.unwrap_or(0);
        let host_id = self.host.context().atem_device_id.clone();
        let session = r.task.target.session_id.as_str();
        rule(
            &authority.name(),
            authority.key.as_bytes(),
            adm,
            session,
            &Grounds {
                list,
                standing: &standing,
                host_id: &host_id,
                now_ms: host_now().wall_ms.max(now_d),
                projects: &|entry| self.projects.matches(session, entry),
            },
        )
    }

    /// Who `a` is to a message whose agent recipients include delegated
    /// tasks (`tasks`, each with its admission), for `message_query` and a
    /// `message_publish` retry: the tasks' caller rule, every one of them
    /// (the owner, or the sender with current authority over each); `None`
    /// when it may not.
    pub(super) fn delegated_message_caller(
        &self,
        a: &Sender,
        tasks: &[WorkRecord],
    ) -> Option<Caller> {
        let mut caller = Caller::Sender;
        for t in tasks {
            let adm = t.delegated.as_ref()?;
            match self.delegated_caller(a, t, adm).ok()? {
                Caller::Owner => caller = Caller::Owner,
                Caller::Sender => {}
            }
        }
        Some(caller)
    }

    /// `work_cancel` of the delegated task `r` by its sender (design I.4.5,
    /// I.5.5, I.5.6). With no attempt live, v1's rule: `queued` or
    /// `blocked` becomes `cancelled` (again on `cancelled`: the status),
    /// anything else is `busy`. With one live:
    /// - **never admitted** (no receipt): nothing submits it again (the
    ///   dispatch submits only an attempt it just made), so it ends
    ///   unadmitted with the cancel;
    /// - **`accepted`**: it is withdrawn in the session host first; once
    ///   that is confirmed (`rejected`, `withdrawn by the host`) the task is
    ///   `cancelled` and the attempt ended, in one `BEGIN IMMEDIATE`
    ///   transaction, and the start check forgets it. A withdrawal that can't
    ///   be confirmed (the session journal halted, before or by it) is
    ///   `busy`, with nothing changed: never a cancelled task with a live
    ///   attempt (the restart withdraws it);
    /// - **started** (`executing` or past it): `busy`; it runs, and the
    ///   pass settles it from its receipt;
    /// - **already proven side-effect-free** (`rejected`): it ends with that
    ///   proof, and the task is `cancelled`.
    pub(super) fn delegated_cancel(
        &mut self,
        mut r: WorkRecord,
        cx: &mut Cx,
    ) -> Result<WorkStatus, &'static str> {
        let task_id = r.task.task_id.clone();
        let live = self
            .work
            .store
            .as_ref()
            .ok_or("busy")?
            .live_attempt(&task_id)
            .map_err(|_| "busy")?;
        let Some(attempt) = live else {
            match r.status.state {
                WorkState::Cancelled => {}
                WorkState::Queued | WorkState::Blocked => {
                    r.status.state = WorkState::Cancelled;
                    r.status.detail = CANCELLED_BEFORE_SUBMISSION.into();
                    let store = self.work.store.as_ref().ok_or("busy")?;
                    store.save_work(&r).map_err(|_| "busy")?;
                }
                _ => return Err("busy"),
            }
            return Ok(r.status);
        };
        let id = attempt.attempt_id.clone();
        let held = self.start_view().refused(&id) == Some(Event::Held);
        let receipt = self
            .host
            .attempt_receipt(&id, &task_id)
            .map(|rc| (rc.state, rc.detail));
        let end = match receipt {
            None => AttemptEnd::NotAdmitted,
            Some((ReceiptState::Accepted, _)) => {
                if self.host.journal_halted() {
                    return Err("busy");
                }
                // The request is in the journal (`accepted`), so the
                // withdrawal finds it by its id: these values go nowhere.
                let immutable = Immutable {
                    target: r.task.target.clone(),
                    payload_digest: String::new(),
                    provenance: Provenance {
                        task_id: task_id.clone(),
                        sender: r.principal.clone(),
                    },
                };
                let withdrawal = self.host.withdraw(&id, &immutable);
                let effects = self.host.take_effects();
                self.exec(effects, cx);
                match withdrawal {
                    Withdrawal::Started | Withdrawal::Halted => return Err("busy"),
                    w => attempt_end(SessionAnswer::Withdrawal(w), held)
                        .unwrap_or(AttemptEnd::Withdrawn { counted: !held }),
                }
            }
            Some((state, detail)) => {
                match attempt_end(SessionAnswer::Receipt(state, detail.as_deref()), held) {
                    Some(AttemptEnd::Started) | None => return Err("busy"),
                    Some(end) => end,
                }
            }
        };
        self.end_attempt(
            &mut r,
            &attempt,
            end,
            (WorkState::Cancelled, CANCELLED_BEFORE_SUBMISSION),
        )
        .map_err(|_| "busy")?;
        Ok(r.status)
    }
}

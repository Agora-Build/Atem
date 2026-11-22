//! The requests about a delegated sender's task, in the bridge (design
//! I.4.5, I.4.6, I.5.5, I.5.6; host-work-v1 §11.2 "Authority"; step 4's
//! Decision 15): who may query, cancel, complete or resolve it and read its
//! reply (the interaction rule, [`interaction`]), a cancel that withdraws a
//! live attempt in the session host before the task is cancelled, and
//! `work_resolve` ([`resolve`]).
//!
//! v1 tasks never come here: `work_request_as` keeps host-work v1's caller
//! rule for them, byte for byte.
use super::*;
use crate::runtime::delegated::Admission;
use crate::runtime::delegated::attempts::{AttemptEnd, SessionAnswer, attempt_end};
use crate::runtime::delegated::authority::{Caller, Grounds, Refused, every_caller, interaction};
use crate::runtime::delegated::resolve::{ResolveRefusal, resolve};
use crate::runtime::delegated::start::Event;
use crate::session_protocol::host::{Immutable, Provenance, Withdrawal};
use crate::session_protocol::wire::ReceiptState;

/// A task cancelled before its prompt was submitted (host-work v1's text,
/// kept for delegated tasks: §11.6 adds none for a cancel).
pub(super) use crate::runtime::delegated::start::CANCELLED_BEFORE_SUBMISSION;

impl HostBridge {
    /// A request naming a UUID v5 task (`work_query`, `reply_query`,
    /// `work_interrupt`, `work_resolve`; host-work-v1 §11.2, §11.5;
    /// Astation's asks, #120 comments 7028723996 and 7082465179, the second
    /// for `reply_query`): a host sender's selector task, which the owner
    /// manages, and whose reply it reads, from a channel. Served on only
    /// when both hold:
    ///
    /// - the caller is the owner (a native member holding `control` at the
    ///   head of the open list, under its own key), decided before the
    ///   task is looked for, so nobody else learns whether it exists;
    /// - the task is on this host and its recorded provenance is a host
    ///   sender's selector task ([`host_selector_task`]).
    ///
    /// Anything else is answered as a task the host doesn't have
    /// (`forbidden`, no detail), whoever asks: a v5 id grants nothing. A
    /// UUID v4 passes untouched, its rules today's. Then the op's own path
    /// (the owner rule of `delegated_caller`, the op's effect) runs as for
    /// any delegated task: `reply_query`'s a read of the reply as stored,
    /// nothing completed, cancelled or sent again. (`work_cancel` and
    /// `work_complete` never name a v5: the core's reader refuses one, and
    /// the owner may do neither; their arm calls this all the same.)
    pub(super) fn selector_task_named(
        &self,
        a: &Sender,
        task_id: &str,
    ) -> Result<(), HostWorkError> {
        if !atem_client::session::wire::is_uuid_v5(task_id) {
            return Ok(());
        }
        let missing = || HostWorkError::from("forbidden");
        let is_owner = a
            .remote()
            .zip(self.open_list())
            .is_some_and(|(caller, list)| {
                crate::runtime::delegated::authority::owner(
                    &caller.name(),
                    caller.key.as_bytes(),
                    list,
                )
            });
        if !is_owner {
            return Err(missing());
        }
        let store = self.work.store.as_ref().ok_or("busy")?;
        let r = store
            .work(task_id)
            .map_err(|_| "busy")?
            .ok_or_else(missing)?;
        let message = match &r.message {
            Some(frame) => store.message(&frame.message_id).map_err(|_| "busy")?,
            None => None,
        };
        if host_selector_task(&r, message.as_ref(), &self.work_host()) {
            Ok(())
        } else {
            Err(missing())
        }
    }

    /// The store may hold a delegated task: `host.delegated` is on, or the
    /// store held one when it opened (the delegated clock is built for it
    /// then, `ensure_clock`; with the hook off no new one is admitted).
    /// Otherwise nothing looks for one, as on main.
    pub(super) fn may_hold_delegated(&self) -> bool {
        self.features.delegated || self.work.clock.is_some()
    }

    /// A service sender's requests while its control standing decides
    /// them (design I.5.5 step 2, ruling T32b; only with `host.delegated`
    /// on): `busy` while the control state can't be read (its revocation
    /// and hold are unknown: I1's answer, before any other refusal), and
    /// `forbidden` once a control record revoked it: the host refuses all
    /// its future requests, whatever they ask (a new task or a notice, an
    /// attachment, a launch or its query, the profiles, its own tasks),
    /// from the standings committed (Decision 16). Natives, browser grants
    /// and `local` don't depend on control records: nothing.
    pub(super) fn service_refused(&self, a: &Sender) -> Result<(), HostWorkError> {
        if !self.features.delegated {
            return Ok(());
        }
        let Some(authority) = a.remote() else {
            return Ok(());
        };
        let principal = authority.name();
        let Some(list) = self.open_list() else {
            return Ok(());
        };
        if crate::runtime::delegated::active_service(&principal, list).is_none() {
            return Ok(());
        }
        if self.controls_unchecked() {
            return Err("busy".into());
        }
        let revoked = self
            .start_view()
            .standings
            .get(&principal)
            .is_some_and(|standing| standing.revoked.is_some());
        if revoked {
            return Err("forbidden".into());
        }
        Ok(())
    }

    /// Who `a` is to the delegated task `r`, admitted as `adm` (design
    /// I.4.5, Decision 15): its sender with current authority, or the owner.
    /// A service sender is `Refused::Unchecked` (`busy`) while the control
    /// state can't be read (ruling T32b); the owner still reads.
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
                // A service's standing can't be checked (ruling T32b).
                unchecked: self.controls_unchecked(),
                host_id: &host_id,
                now_ms: host_now().wall_ms.max(now_d),
                // The session's hash, else the task's launch project's
                // (ruling T20c: kept host-private with its record, hashed
                // under a new kid without the session).
                projects: &|entry| {
                    let task = crate::runtime::project_scope::task_project_key(&r.project);
                    self.projects
                        .matches(session, entry)
                        .or_else(|| self.projects.matches(&task, entry))
                },
            },
        )
    }

    /// Who `a` is to a message whose agent recipients include delegated
    /// tasks (`tasks`, each with its admission), for `message_query` and a
    /// `message_publish` retry: the tasks' caller rule, every one of them
    /// (the owner, or the sender with current authority over each); why
    /// not when it may not: a refusal that stands (`forbidden`) before one
    /// that can't be decided yet (`busy`), whatever the recipients' order
    /// (`every_caller`, Task 32 re-review N3).
    pub(super) fn delegated_message_caller(
        &self,
        a: &Sender,
        tasks: &[WorkRecord],
    ) -> Result<Caller, Refused> {
        every_caller(tasks.iter().map(|t| {
            let adm = t.delegated.as_ref().ok_or(Refused::NotTheSender)?;
            self.delegated_caller(a, t, adm)
        }))
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

    /// `work_resolve` (feature `host.delegated`; design I.4.5, I.4.6,
    /// host-work-v1 §11.2) of `task_id` as `resolution`, from `a`. Only
    /// with `host.delegated` on (with it off, `busy` as before the hook:
    /// [`crate::runtime::delegated::request`]). A delegated task its caller
    /// may name, the task's sender with current authority or the owner (the
    /// interaction rule, `delegated_caller`), else `forbidden`: a v1 task,
    /// one the host doesn't have, `local` (the host's own command is not
    /// this op); `busy` while the rule can't be decided yet (a service while
    /// the control state doesn't read, ruling T32b; a `projects` comparison
    /// not made yet), as for the task's other requests. Its launch project
    /// is registered first, as `work_query` registers it (ruling T20c): an
    /// unresolved task's record closes a day after its deadline, so a start
    /// doesn't. Then [`resolve`]'s rule, in one `BEGIN IMMEDIATE`
    /// transaction committed before the answer: the task and its alert's
    /// end are durable before anything shows them.
    pub(super) fn work_resolve(
        &mut self,
        a: &Sender,
        req: &hw::Request,
        task_id: &str,
        resolution: &hw::Resolution,
    ) -> Result<ResultBody, HostWorkError> {
        if !self.features.delegated {
            return crate::runtime::delegated::request(self.features, req);
        }
        // A UUID v5: a host sender's selector task, the owner's alone.
        self.selector_task_named(a, task_id)?;
        let r = self
            .work
            .store
            .as_ref()
            .ok_or("busy")?
            .work(task_id)
            .map_err(|_| "busy")?
            .ok_or("forbidden")?;
        let adm = r.delegated.as_ref().ok_or("forbidden")?;
        self.keep_task_project(&r);
        self.delegated_caller(a, &r, adm).map_err(Refused::code)?;
        let store = self.work.store.as_ref().ok_or("busy")?;
        let tx = store.immediate().map_err(|_| "busy")?;
        let work = resolve(
            store,
            &tx,
            task_id,
            &a.name(),
            resolution,
            host_now().wall_ms,
        )
        .map_err(ResolveRefusal::error)?;
        tx.commit().map_err(|_| "busy")?;
        Ok(ResultBody::Work { work })
    }

    /// `alert_list` (feature `host.alerts`; design I.4.6, host-work-v1
    /// §11.3) from `a`: the page of unresolved alerts after `after`. Only
    /// with `host.alerts` on (with it off, `busy` as before the hook:
    /// [`crate::runtime::delegated::request`]). It answers native members
    /// holding `control` at the host's head, the members that get approval
    /// hints: the channel refuses everyone else before decoding
    /// (`Need::Alerts`), and so does this, `local` included (the owner's
    /// own view is the host's command, not this op). An `after` the host has
    /// no unresolved alert for is `stale_target`, `unknown alert`. Read
    /// only: it records nothing.
    pub(super) fn alert_list(
        &self,
        a: &Sender,
        req: &hw::Request,
        after: Option<&str>,
    ) -> Result<ResultBody, HostWorkError> {
        if !(self.features.delegated && self.features.alerts) {
            return crate::runtime::delegated::request(self.features, req);
        }
        if !a.remote().is_some_and(|a| a.allows(Need::Alerts)) {
            return Err("forbidden".into());
        }
        let store = self.work.store.as_ref().ok_or("busy")?;
        let (alerts, more) = store
            .alert_page(after, atem_client::session::alerts::MAX_PAGE)
            .map_err(|refused| refused.error())?;
        Ok(ResultBody::Alerts { alerts, more })
    }

    /// The capacity limits on unresolved outcomes (design I.4.6,
    /// host-work-v1 §11.6 "Capacity"), for a request of `a` that would make
    /// a new task (`work_enqueue`, `message_publish` with an agent
    /// recipient): at 64 of its own unresolved, or 256 on the host, a remote
    /// sender is refused `busy`, `too many unresolved outcomes`, until the
    /// owner resolves some. `local` never is. Only with `host.delegated`
    /// on: with it off nothing is counted, as on main.
    pub(super) fn unresolved_capacity(&self, a: &Sender) -> Result<(), HostWorkError> {
        let Some(sender) = a.remote() else {
            return Ok(());
        };
        if !self.features.delegated {
            return Ok(());
        }
        let store = self.work.store.as_ref().ok_or("busy")?;
        match store.over_capacity(&sender.name()) {
            Ok(false) => Ok(()),
            Ok(true) => Err(HostWorkError {
                code: "busy",
                detail: Some(details::TOO_MANY_UNRESOLVED_OUTCOMES),
            }),
            Err(_) => Err("busy".into()),
        }
    }
}

/// Whether `r` is a host sender's selector task as this host recorded it
/// (host-work-v1 §11.5, "The selector task id" and "On the receiving
/// host"): delegated as host sender `host:<host_id>` (its principal and its
/// admission's), from the stored message `message` of that sender (the one
/// its record names), one of whose `select` recipients for this host
/// (`host`) resolved to it: its id is `selector_task_id` of the message,
/// that recipient and the task's session, and the recipient's recorded
/// receipt lists it.
pub(super) fn host_selector_task(
    r: &WorkRecord,
    message: Option<&crate::runtime::host_work::MessageRecord>,
    host: &HostTarget,
) -> bool {
    use atem_client::session::messages::{Delivery, Destination};
    use atem_client::session::select::selector_task_id;
    let (Some(admission), Some(frame), Some(record)) = (&r.delegated, &r.message, message) else {
        return false;
    };
    let crate::runtime::delegated::DelegatedSender::Host { host_id, .. } = &admission.sender else {
        return false;
    };
    let principal = atem_client::host_principal::host_principal(host_id);
    let task_id = r.task.task_id.as_str();
    r.principal == principal
        && admission.principal == principal
        && r.status.task_id == task_id
        && record.message.message_id == frame.message_id
        && record.message.sender == principal
        && record.receipt.sender == principal
        && record.message.recipients.iter().any(|recipient| {
            &recipient.host == host
                && matches!(recipient.destination, Destination::Select { .. })
                && selector_task_id(
                    &frame.message_id,
                    &recipient.recipient_id,
                    &r.task.target.session_id,
                ) == task_id
                && record.receipt.recipients.iter().any(|receipt| {
                    receipt.recipient_id == recipient.recipient_id
                        && matches!(&receipt.delivery,
                            Delivery::Resolved { tasks } if tasks.iter().any(|t| t.task_id == task_id))
                })
        })
}

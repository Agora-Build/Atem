//! (`impl HostBridge`) `atem message cancel` and `complete` of a task on
//! another host (the delegated host-work design II.4.4, II.7; host-work-v1
//! §11.5, "On the sending host"), with the debug-only hook's
//! `host.senders` on (with it off, or for a task no status of another host
//! named, the commands are stage 1's).
//!
//! - **Which task.** A task id another host's status recorded for one of
//!   this host's messages (`remote_tasks`).
//! - **Who.** As stage 1 allows: the task's sending session (for a
//!   complete, its process too), or the owner outside any session.
//! - **When.** What the newest status says decides only what can't change:
//!   a cancel of a task it shows started or ended is refused, as is a
//!   complete of one it shows failed, cancelled, expired or of unknown
//!   outcome (that host's owner resolves those; one shown completed is
//!   done).
//! - **What.** A `cancel` or `complete` envelope of its own (a fresh id),
//!   sealed to the host's current key at the generation the message went
//!   to, signed at the committed head, made on `D` and alive while its
//!   message is (at most 24 h); its exact bytes enqueued in the put engine
//!   ([`Policy::Repeat`]) with its own delivery row, in one transaction,
//!   before any put. A complete's result names the reply this host got
//!   back ([`results_back::naming`], frozen at the command), and a delivery
//!   of that reply still queued is cancelled in that transaction, as stage
//!   1's completion does. A stop of the task that still stands is not sent
//!   again; the command says what happened ([`StopOutcome`]).
//! - **A complete waits for its task** (ruling R50): while the newest
//!   status shows the task before `awaiting_result` (its turn may still
//!   run, and the host completes only a task awaiting its result), the
//!   complete is held, durable with the command, nothing sealed; the status
//!   that shows `awaiting_result` makes it due and the next pass seals and
//!   enqueues it ([`HostBridge::remote_stops_pass`]). A status showing the
//!   task ended otherwise drops it, with why; its message's expiry expires
//!   it. A `busy` answer by its own id (a race) holds it again under a
//!   fresh id.
//! - **Until.** Put every 10 minutes until a status shows its effect (the
//!   task `cancelled` or `completed`), the host refuses it by its own id
//!   (`busy` for a cancel, `forbidden`), or it expires (`remote_send.rs`).
use super::*;
use crate::runtime::delegated::outbox::{self, Policy};
use crate::runtime::delegated::remote_send::{self, Sealer};
use crate::runtime::delegated::results_back::{self, RemoteTask};
use crate::runtime::delegated::send_plan::{Me, signs};
use crate::runtime::protocol::{RemoteStop, StopOutcome};
use anyhow::{Result, anyhow, bail};
use atem_client::host_mail::{EnvelopePlain, HostRef};
use atem_client::session::host_work::ContextSnapshot;
use rusqlite::OptionalExtension;

/// A stop of a task on another host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    Cancel,
    Complete,
}

impl Stop {
    /// Its row's kind.
    fn kind(self) -> &'static str {
        match self {
            Stop::Cancel => "cancel",
            Stop::Complete => "complete",
        }
    }
}

impl HostBridge {
    /// `stop` of the task `task_id` on another host, by `caller` (none: the
    /// owner; `sessions` for a complete's process check), as the module
    /// docs say: its host and what became of it, once committed; `None`
    /// when no other host's task has that id (or host senders are off), so
    /// stage 1's answer stands.
    pub(super) fn remote_stop(
        &mut self,
        caller: Option<&SessionId>,
        task_id: &str,
        stop: Stop,
        sessions: Option<&BTreeMap<SessionId, BrokerSession>>,
    ) -> Result<Option<RemoteStop>> {
        if !self.senders_on() {
            return Ok(None);
        }
        let Some(store) = self.work.store.as_ref() else {
            return Ok(None);
        };
        let mut found = results_back::remote_task(&store.db, task_id)?;
        let task = match found.len() {
            0 => return Ok(None),
            1 => found.remove(0),
            _ => bail!("task id {task_id} names tasks on several hosts"),
        };
        self.remote_stop_allowed(caller, &task, stop, sessions)?;
        if let Some(why) = refused_now(&task, stop) {
            bail!("task {task_id} on host {} {why}", task.host_id);
        }
        let said = |outcome| {
            Ok(Some(RemoteStop {
                host: task.host_id.clone(),
                outcome,
            }))
        };
        if stop == Stop::Complete && task.state == "completed" {
            return said(StopOutcome::Done);
        }
        let store = self.work.store.as_ref().unwrap();
        match remote_send::stop_standing(&store.db, &task, stop.kind())? {
            remote_send::Standing::Pending => return said(StopOutcome::Pending),
            remote_send::Standing::Done => return said(StopOutcome::Done),
            remote_send::Standing::None => {}
        }
        let Some(now_d) = self.start_view().now_d_ms else {
            bail!("the delegated clock has no reading yet; see `atem status`");
        };
        if now_d >= task.expires_at {
            bail!("task {task_id}'s message expired");
        }
        // A complete's result, frozen now: the reply this host got back.
        let result = (stop == Stop::Complete)
            .then(|| results_back::naming(&task.task_id, task.reply.as_ref()));
        // Ruling R50: a complete of a task not shown awaiting its result is
        // held; it goes once a status shows it.
        let held = stop == Stop::Complete && task.state != "awaiting_result";
        let id = uuid::Uuid::new_v4().to_string();
        let sealed = if held {
            None
        } else {
            let plain = plain_of(&task, result.clone());
            match self.seal_stop(&task, &id, &plain, now_d) {
                Ok(bytes) => Some(bytes),
                Err(Sealing::Unavailable) => bail!(delegated_send_pass::SEAL_UNAVAILABLE),
                Err(Sealing::Refused(why)) => bail!(why),
            }
        };
        let Some(store) = self.outbox_store() else {
            bail!(
                "host senders' outbox unavailable (the control feeds aren't loaded); see `atem status`"
            );
        };
        let to = HostRef {
            host_id: task.host_id.clone(),
            host_trust_gen: task.host_trust_gen,
        };
        let tx = store.immediate()?;
        let n = sealed
            .map(|bytes| outbox::enqueue(&tx, &bytes, &to, Policy::Repeat))
            .transpose()?;
        remote_send::stop_row(&tx, &task, stop.kind(), &id, n, now_d)?;
        if let Some(result) = &result {
            remote_send::hold_result(&tx, &task, result)?;
        }
        // Completed: the reply isn't delivered from now on (stage 1's).
        if stop == Stop::Complete
            && let Some(mut delivery) = task
                .work_id
                .as_deref()
                .map(|id| store.work(id))
                .transpose()?
                .flatten()
            && matches!(
                delivery.status.state,
                WorkState::Queued | WorkState::Blocked
            )
        {
            delivery.status.state = WorkState::Cancelled;
            delivery.status.detail = collab_bridge::COMPLETED_BY_SENDER.into();
            store.save_work(&delivery)?;
        }
        tx.commit()?;
        said(if held {
            StopOutcome::Queued
        } else {
            StopOutcome::Sent
        })
    }

    /// The held `complete`s, each pass with `host.senders` on (ruling R50):
    /// those whose message expired on `D` expired; each one a status made
    /// due sealed under its own id with the result frozen at the command,
    /// and enqueued with its row `ready`, in one transaction; one that can't
    /// be sealed for good (its host no longer current, no key, this host no
    /// longer signing) dropped with why; none while nothing can be sealed
    /// (no list, host key or `D`).
    pub(super) fn remote_stops_pass(&mut self) {
        if !self.senders_on() || self.work.mail_prepared.as_ref() != Some(&self.work_host()) {
            return;
        }
        let Some(now_d) = self.start_view().now_d_ms else {
            return;
        };
        let Some(store) = self.outbox_store() else {
            return;
        };
        let due = remote_send::expire_held(&store.db, now_d)
            .and_then(|_| remote_send::due_stops(&store.db));
        let due = match due {
            Ok(due) => due,
            Err(error) => {
                eprintln!("atem runtime: host senders' held completes not read ({error:#})");
                return;
            }
        };
        for (object_id, host_id, message_id, task_id) in due {
            if let Err(error) = self.seal_held(&object_id, &host_id, &message_id, &task_id, now_d) {
                eprintln!(
                    "atem runtime: the complete of task {task_id} not sealed yet ({error:#}); tried again"
                );
            }
        }
    }

    /// The due complete `object_id` of `task_id` sealed and enqueued (or
    /// dropped with why), in its own transaction.
    fn seal_held(
        &self,
        object_id: &str,
        host_id: &str,
        message_id: &str,
        task_id: &str,
        now_d: u64,
    ) -> Result<()> {
        let store = self.outbox_store().ok_or_else(|| anyhow!("no store"))?;
        let Some(task) = results_back::remote_task(&store.db, task_id)?
            .into_iter()
            .find(|t| t.message_id == message_id && t.host_id == host_id)
        else {
            let tx = store.immediate()?;
            remote_send::drop_stop(&tx, object_id, host_id, "not sent: its task is gone")?;
            return Ok(tx.commit()?);
        };
        let result = match remote_send::held_result(&store.db, message_id, host_id, task_id)? {
            Some(result) => result,
            None => results_back::naming(task_id, task.reply.as_ref()),
        };
        let plain = plain_of(&task, Some(result));
        let bytes = match self.seal_stop(&task, object_id, &plain, now_d) {
            Ok(bytes) => bytes,
            Err(Sealing::Unavailable) => return Ok(()),
            Err(Sealing::Refused(why)) => {
                let tx = store.immediate()?;
                remote_send::drop_stop(&tx, object_id, host_id, &format!("not sent: {why}"))?;
                return Ok(tx.commit()?);
            }
        };
        let to = HostRef {
            host_id: task.host_id.clone(),
            host_trust_gen: task.host_trust_gen,
        };
        let tx = store.immediate()?;
        let n = outbox::enqueue(&tx, &bytes, &to, Policy::Repeat)?;
        remote_send::sealed_due(&tx, object_id, host_id, n)?;
        Ok(tx.commit()?)
    }

    /// Whether `caller` may stop `task`, as stage 1 allows (collaboration
    /// §10, "Who sees what"): the session that sent its message (for a
    /// complete, its process too), or the owner outside any session.
    fn remote_stop_allowed(
        &self,
        caller: Option<&SessionId>,
        task: &RemoteTask,
        stop: Stop,
        sessions: Option<&BTreeMap<SessionId, BrokerSession>>,
    ) -> Result<()> {
        let Some(caller) = caller else {
            return Ok(());
        };
        let store = self.work.store.as_ref().unwrap();
        let origin = store
            .db
            .query_row(
                "SELECT record FROM origins WHERE message_id=?1",
                [&task.message_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|o| serde_json::from_str::<crate::runtime::collab::results::Origin>(&o).ok());
        let sender = origin
            .as_ref()
            .is_some_and(|o| o.target.session_id == caller.as_str());
        match stop {
            Stop::Cancel if !sender => bail!(
                "task {} is not one of this session's messages; only the session that sent it (or the owner, outside any session) cancels it",
                task.task_id
            ),
            Stop::Complete
                if !sender
                    || sessions.and_then(|s| s.get(caller)).is_none_or(|s| {
                        origin
                            .as_ref()
                            .is_none_or(|o| s.process_gen != o.target.process_gen)
                    }) =>
            {
                bail!("only the task's sending session completes it")
            }
            _ => Ok(()),
        }
    }

    /// `plain`, the stop `id` of `task`, sealed now (`now_d`) to its
    /// host's current key at the generation its message went to, signed at
    /// the committed head: its exact bytes, or why it can't be sealed
    /// (now, or for good).
    fn seal_stop(
        &self,
        task: &RemoteTask,
        id: &str,
        plain: &EnvelopePlain,
        now_d: u64,
    ) -> std::result::Result<Vec<u8>, Sealing> {
        let (Some(list), Some(key)) = (self.send_list(), self.host_key.clone()) else {
            return Err(Sealing::Unavailable);
        };
        let host = self.work_host();
        let me = Me {
            host_id: &host.atem_device_id,
            atem_id: &host.atem_device_id,
            host_trust_gen: host.host_trust_gen,
        };
        signs(&list, me).map_err(Sealing::Refused)?;
        let sealer = Sealer {
            list: &list,
            me,
            account: &host.account_id,
            key: &key,
        };
        let to = HostRef {
            host_id: task.host_id.clone(),
            host_trust_gen: task.host_trust_gen,
        };
        // Alive while its message is, never more than a day from now.
        let expires_at = task
            .expires_at
            .min(now_d.saturating_add(hw::MAX_LIFETIME_MS));
        remote_send::seal(&sealer, &to, id, now_d, expires_at, plain).map_err(Sealing::Refused)
    }
}

/// Why a stop isn't sealed: nothing can be sealed now (no committed list or
/// host key), or this one can't be, with why.
enum Sealing {
    Unavailable,
    Refused(String),
}

/// The envelope plaintext of a stop of `task`: a `complete` with `result`,
/// else a `cancel`.
fn plain_of(task: &RemoteTask, result: Option<ContextSnapshot>) -> EnvelopePlain {
    match result {
        Some(result) => EnvelopePlain::Complete {
            task_id: task.task_id.clone(),
            result,
        },
        None => EnvelopePlain::Cancel {
            task_id: task.task_id.clone(),
        },
    }
}

/// Why `stop` of `task` can't reach it whatever comes later, as its newest
/// status says (the module docs): none when it may still.
fn refused_now(task: &RemoteTask, stop: Stop) -> Option<String> {
    let state = task.state.as_str();
    match stop {
        Stop::Cancel if !matches!(state, "queued" | "blocked" | "submitting") => Some(format!(
            "is {state}; only a task that hasn't started can be cancelled"
        )),
        Stop::Complete if matches!(state, "failed" | "cancelled" | "expired") => Some(format!(
            "is {state}; only a task awaiting its result can be completed"
        )),
        // A delegated task of unknown outcome moves only by its owner's
        // resolution there (review L3).
        Stop::Complete if state == "outcome_unknown" => Some(
            "is outcome_unknown; a task of unknown outcome is resolved by that host's owner, never completed by its sender"
                .into(),
        ),
        _ => None,
    }
}

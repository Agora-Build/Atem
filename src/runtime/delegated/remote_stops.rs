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
//!   complete of one it shows failed, cancelled or expired (one it shows
//!   completed is done). Anything else goes: a status may lag behind, and
//!   the host answers a stop it doesn't reach by its own id.
//! - **What.** A `cancel` or `complete` envelope of its own (a fresh id),
//!   sealed to the host's current key at the generation the message went
//!   to, signed at the committed head, made on `D` and alive while its
//!   message is (at most 24 h); its exact bytes enqueued in the put engine
//!   ([`Policy::Repeat`]) with its own delivery row, in one transaction,
//!   before any put. A complete's result names the reply this host got
//!   back ([`results_back::naming`]), and a delivery of that reply still
//!   queued is cancelled in that transaction, as stage 1's completion
//!   does. A stop of the task that still stands is not sent again.
//! - **Until.** Put every 10 minutes until a status shows its effect (the
//!   task `cancelled` or `completed`), the host refuses it by its own id
//!   (`busy`, `forbidden`), or it expires (`remote_send.rs`).
use super::*;
use crate::runtime::delegated::outbox::{self, Policy};
use crate::runtime::delegated::remote_send::{self, Sealer};
use crate::runtime::delegated::results_back::{self, RemoteTask};
use crate::runtime::delegated::send_plan::{Me, signs};
use anyhow::{Result, anyhow, bail};
use atem_client::host_mail::{EnvelopePlain, HostRef};
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
    /// docs say: `Some(its host)` once its envelope is committed; `None`
    /// when no other host's task has that id (or host senders are off), so
    /// stage 1's answer stands.
    pub(super) fn remote_stop(
        &mut self,
        caller: Option<&SessionId>,
        task_id: &str,
        stop: Stop,
        sessions: Option<&BTreeMap<SessionId, BrokerSession>>,
    ) -> Result<Option<String>> {
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
        if stop == Stop::Complete && task.state == "completed" {
            return Ok(Some(task.host_id));
        }
        let store = self.work.store.as_ref().unwrap();
        if remote_send::stop_stands(&store.db, &task, stop.kind())? {
            return Ok(Some(task.host_id));
        }
        let Some(now_d) = self.start_view().now_d_ms else {
            bail!("the delegated clock has no reading yet; see `atem status`");
        };
        if now_d >= task.expires_at {
            bail!("task {task_id}'s message expired");
        }
        let bytes = self.seal_stop(&task, stop, now_d)?;
        let Some(store) = self.outbox_store() else {
            bail!(
                "host senders' outbox unavailable (the control feeds aren't loaded); see `atem status`"
            );
        };
        let to = HostRef {
            host_id: task.host_id.clone(),
            host_trust_gen: task.host_trust_gen,
        };
        let object = atem_client::host_mail::parse_object(&bytes)
            .map_err(|e| anyhow!("the envelope doesn't read ({e})"))?;
        let (_, body) = atem_client::host_mail::MailBody::from_object(&object)?;
        let tx = store.immediate()?;
        let n = outbox::enqueue(&tx, &bytes, &to, Policy::Repeat)?;
        remote_send::stop_row(&tx, &task, stop.kind(), &body.id, n, now_d)?;
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
        Ok(Some(task.host_id))
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

    /// `stop`'s envelope of `task`, sealed now (`now_d`) to its host's
    /// current key at the generation its message went to, signed at the
    /// committed head: its exact bytes, or why it can't be sealed.
    fn seal_stop(&self, task: &RemoteTask, stop: Stop, now_d: u64) -> Result<Vec<u8>> {
        let (Some(list), Some(key)) = (self.send_list(), self.host_key.clone()) else {
            bail!(delegated_send_pass::SEAL_UNAVAILABLE);
        };
        let host = self.work_host();
        let me = Me {
            host_id: &host.atem_device_id,
            atem_id: &host.atem_device_id,
            host_trust_gen: host.host_trust_gen,
        };
        signs(&list, me).map_err(|e| anyhow!(e))?;
        let sealer = Sealer {
            list: &list,
            me,
            account: &host.account_id,
            key: &key,
        };
        let plain = match stop {
            Stop::Cancel => EnvelopePlain::Cancel {
                task_id: task.task_id.clone(),
            },
            Stop::Complete => EnvelopePlain::Complete {
                task_id: task.task_id.clone(),
                result: results_back::naming(&task.task_id, task.reply.as_ref()),
            },
        };
        let to = HostRef {
            host_id: task.host_id.clone(),
            host_trust_gen: task.host_trust_gen,
        };
        // Alive while its message is, never more than a day from now.
        let expires_at = task
            .expires_at
            .min(now_d.saturating_add(hw::MAX_LIFETIME_MS));
        let id = uuid::Uuid::new_v4().to_string();
        remote_send::seal(&sealer, &to, &id, now_d, expires_at, &plain).map_err(|e| anyhow!(e))
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
        _ => None,
    }
}

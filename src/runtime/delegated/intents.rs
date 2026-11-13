//! Interrupt intents (design I.5.7, I.4.4; session-v1 R9.14 item 5;
//! host-work-v1 §11.6): the host's durable commitment to stop a delegated
//! task's attempt, kept in `host-work.sqlite` (`intents`) before anything
//! acts on it.
//!
//! - **Made by** a task's deadline (a delegated turn still running at it,
//!   or an attempt still waiting `accepted`: [`IntentReason::Deadline`]),
//!   and, once the feeds exist (PR 10), a `revoke` with `interrupt_running`
//!   ([`IntentReason::Revoke`]). Written in a `BEGIN IMMEDIATE`
//!   transaction (`Store::immediate`) and committed before it is carried
//!   out; one per attempt and reason (and revocation).
//! - **Carried out each pass until done** ([`intents_pass`]: decisions only,
//!   which the bridge carries out through its own entries, so the chat's
//!   half of the turn check is never skipped; Task 15's ruling T15c):
//!   - an attempt not yet `executing` is withdrawn, and the task expires
//!     (a deadline) or is cancelled (a revocation): [`Decision::Withdraw`];
//!   - an `executing` attempt whose turn the session's chat shows running is
//!     interrupted with host authority, once per turn in a run
//!     ([`Decision::Deliver`]); while the intent is pending only the lease
//!     revocation repeats ([`Decision::RevokeOnly`]), so a native takeover
//!     can't defeat it;
//!   - a write that wrote nothing (`consumed`, `dropped`, `no_effect`) is
//!     written again on the next pass; an error after queueing counts as
//!     delivered (no blind second Esc) and is written again only if the
//!     turn is still the current one [`REWRITE_AFTER_ERROR_MS`] later;
//!   - an `executing` attempt not shown running (its prompt not taken yet,
//!     no turn state), or still waiting for the start's reconciliation
//!     (R9.14 item 6), keeps the intent pending ([`Decision::Wait`]): a
//!     turn that starts a moment later can't be missed, and a refusal is
//!     never read as "the turn ended";
//!   - done ([`Decision::Done`]) once the attempt's turn ended (its receipt
//!     `completed` or `outcome_unknown`: interrupted, ended, or, after a
//!     restart, not provably current) or its attempt ended without
//!     starting.
//! - **Across a restart** a pending intent is carried out again (design
//!   I.6.2 step 3): what this run delivered is kept in memory only
//!   ([`Runs`]), so a turn still current after the start's reconciliation
//!   gets the interrupt once more. `delivered_turn` records, durably, the
//!   turn that last got it.
//! - **One Esc per (attempt, turn), from any source** (ruling T27a):
//!   `work_interrupt` (host-work-v1 §11.2), a one-shot request with no
//!   intent of its own, shares [`Runs`] with the intents ([`Runs::running`],
//!   [`Runs::requested`]). Every interrupt written to an attempt's turn is
//!   recorded, so a later request or intent in that turn writes nothing.
//!   A request's delivery is kept in memory whatever intents exist (dropped
//!   once its attempt no longer executes, [`Runs::prune`]), and, where the
//!   attempt has a pending intent, stored on it as `delivered_turn` with
//!   `delivered_by` `work_interrupt`: a turn it ended still reads `turn
//!   interrupted`, never `interrupted at deadline`. Across a restart this
//!   run's record is gone, so a turn still current can get one more Esc,
//!   from a request as from a pending intent (the residual).
//! - **A newer build's reason** (none is planned): [`pending_intents`]
//!   refuses a row whose reason this build can't read (a receipt-database
//!   fault), so adding a reason means a downgrade stops at it (no shims,
//!   by the owner's rule).
//! - **The `delivered_by` column** (ruling T27a): a step-4 build before it
//!   ignores the column (every query names its columns), but its
//!   `intent_delivered` doesn't clear a request's marker, so after going
//!   back to a newer build a turn that build's deadline Esc ended reads
//!   `turn interrupted`. Only unreleased dev builds are affected: v0.8.x
//!   has no `intents` table, and going back to it already needs the file
//!   moved aside.
//!
//! [`pending_intents`]: Store::pending_intents
use crate::runtime::delegated::details;
use crate::runtime::delegated::start::EXPIRED_BEFORE_SUBMISSION;
use crate::runtime::host_bridge::InterruptReport;
use crate::runtime::host_work::Store;
use anyhow::{Result, bail};
use atem_client::session::host_work::WorkState;
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::HashMap;

/// An error after queueing counts as delivered; the interrupt is written
/// again only if the turn is still the session's current one this long
/// after (session-v1 R9.14 item 5, §6's bound for an interrupt).
pub const REWRITE_AFTER_ERROR_MS: u64 = 10_000;

/// Why an intent was made (design I.5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentReason {
    /// The task's deadline passed while its attempt was unstarted or its
    /// turn ran (I.4.4).
    Deadline,
    /// A `revoke` with `interrupt_running` (or a later `interrupt_running`
    /// record): the record's id.
    Revoke { revocation: String },
}

impl IntentReason {
    fn name(&self) -> &'static str {
        match self {
            IntentReason::Deadline => "deadline",
            IntentReason::Revoke { .. } => "revoke",
        }
    }

    fn revocation(&self) -> Option<&str> {
        match self {
            IntentReason::Deadline => None,
            IntentReason::Revoke { revocation } => Some(revocation),
        }
    }

    fn read(name: &str, revocation: Option<String>) -> Option<IntentReason> {
        match (name, revocation) {
            ("deadline", None) => Some(IntentReason::Deadline),
            ("revoke", Some(revocation)) => Some(IntentReason::Revoke { revocation }),
            _ => None,
        }
    }

    /// The state and detail the task takes when its unstarted attempt is
    /// withdrawn (I.5.7): expired (§4's `expired before submission`) for a
    /// deadline, cancelled (`sender revoked`) for a revocation.
    pub fn withdrawn(&self) -> (WorkState, &'static str) {
        match self {
            IntentReason::Deadline => (WorkState::Expired, EXPIRED_BEFORE_SUBMISSION),
            IntentReason::Revoke { .. } => (WorkState::Cancelled, details::SENDER_REVOKED),
        }
    }
}

/// One intent as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// Its row.
    pub id: i64,
    pub task_id: String,
    pub attempt_id: String,
    pub reason: IntentReason,
    /// Host wall time it was written.
    pub created_ms: u64,
    /// Host wall time it was done; none while pending.
    pub done_ms: Option<u64>,
    /// The turn that last got its interrupt (the worker wrote it, or an
    /// error after queueing may have), any run.
    pub delivered_turn: Option<String>,
    /// That interrupt was `work_interrupt`'s (§11.2, ruling T27a), not this
    /// intent's: the turn isn't the deadline's (`interrupted at deadline`).
    pub delivered_by_request: bool,
}

/// `intents.delivered_by`'s value for `work_interrupt`'s delivery (NULL:
/// the intent's own).
const BY_REQUEST: &str = "work_interrupt";

const COLUMNS: &str = "rowid,task_id,attempt_id,reason,revocation,created_ms,done_ms,\
    delivered_turn,delivered_by IS NOT NULL";

/// The intents table's `delivered_by` column (ruling T27a), added to a
/// table without it (`ALTER TABLE … ADD COLUMN`, guarded by `pragma
/// table_info`): NULL, or [`BY_REQUEST`].
pub(crate) fn track_delivered_by(db: &rusqlite::Connection) -> Result<()> {
    let there: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('intents') WHERE name='delivered_by')",
        [],
        |r| r.get(0),
    )?;
    if !there {
        db.execute_batch("ALTER TABLE intents ADD COLUMN delivered_by TEXT;")?;
    }
    Ok(())
}

fn intent(r: &rusqlite::Row) -> rusqlite::Result<(Intent, bool)> {
    let name: String = r.get(3)?;
    let revocation: Option<String> = r.get(4)?;
    let reason = IntentReason::read(&name, revocation);
    let readable = reason.is_some();
    Ok((
        Intent {
            id: r.get(0)?,
            task_id: r.get(1)?,
            attempt_id: r.get(2)?,
            reason: reason.unwrap_or(IntentReason::Deadline),
            created_ms: r.get(5)?,
            done_ms: r.get(6)?,
            delivered_turn: r.get(7)?,
            delivered_by_request: r.get(8)?,
        },
        readable,
    ))
}

impl Store {
    /// Writes the intent to stop attempt `attempt_id` of `task_id` for
    /// `reason`, in `tx` (the store's own `BEGIN IMMEDIATE` transaction):
    /// it is acted on only once `tx` commits. One per attempt and reason
    /// (and revocation): false when it was there already.
    pub fn write_intent(
        &self,
        tx: &Transaction,
        task_id: &str,
        attempt_id: &str,
        reason: IntentReason,
    ) -> Result<bool> {
        let written = tx.execute(
            "INSERT OR IGNORE INTO intents(task_id,attempt_id,reason,revocation,created_ms)
            VALUES(?1,?2,?3,?4,?5)",
            params![
                task_id,
                attempt_id,
                reason.name(),
                reason.revocation(),
                crate::session_protocol::membership::host_now().wall_ms
            ],
        )?;
        Ok(written == 1)
    }

    /// The intents not done yet, oldest first, through their own index (a
    /// pass reads no done one). A row this build can't read is an error: a
    /// receipt-database fault, never an intent skipped.
    pub fn pending_intents(&self) -> Result<Vec<Intent>> {
        let mut q = self.db.prepare(&format!(
            "SELECT {COLUMNS} FROM intents INDEXED BY intents_pending
            WHERE done_ms IS NULL ORDER BY rowid"
        ))?;
        let rows = q.query_map([], intent)?;
        let mut out = Vec::new();
        for row in rows {
            let (intent, readable) = row?;
            if !readable {
                bail!("interrupt intent {} unreadable", intent.id);
            }
            out.push(intent);
        }
        Ok(out)
    }

    /// Every intent of `task_id`, oldest first.
    #[cfg(test)]
    pub fn intents_of(&self, task_id: &str) -> Result<Vec<Intent>> {
        let mut q = self.db.prepare(&format!(
            "SELECT {COLUMNS} FROM intents WHERE task_id=?1 ORDER BY rowid"
        ))?;
        let rows = q.query_map([task_id], intent)?;
        Ok(rows
            .map(|r| r.map(|(i, _)| i))
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The turn the interrupt of attempt `attempt_id`'s intent for
    /// `reason`'s kind reached (`delivered_turn`), if the intent delivered
    /// one itself (not `work_interrupt`'s, ruling T27a).
    pub fn delivered_turn(
        &self,
        task_id: &str,
        attempt_id: &str,
        reason: &IntentReason,
    ) -> Result<Option<String>> {
        Ok(self
            .db
            .query_row(
                "SELECT delivered_turn FROM intents WHERE attempt_id=?1 AND reason=?3
                AND task_id=?2 AND delivered_turn IS NOT NULL AND delivered_by IS NULL
                LIMIT 1",
                params![attempt_id, task_id, reason.name()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Whether attempt `attempt_id` of `task_id` has an intent for
    /// `reason`'s kind (any revocation), pending or done.
    pub fn has_intent(
        &self,
        task_id: &str,
        attempt_id: &str,
        reason: &IntentReason,
    ) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM intents WHERE attempt_id=?1 AND reason=?3 AND task_id=?2)",
            params![attempt_id, task_id, reason.name()],
            |r| r.get(0),
        )?)
    }

    /// The pending intents of `attempt_id` got their own interrupt in
    /// `turn`.
    pub fn intent_delivered(&self, attempt_id: &str, turn: &str) -> Result<()> {
        self.db.execute(
            "UPDATE intents SET delivered_turn=?2, delivered_by=NULL
            WHERE attempt_id=?1 AND done_ms IS NULL",
            params![attempt_id, turn],
        )?;
        Ok(())
    }

    /// `work_interrupt`'s interrupt reached `attempt_id`'s turn `turn`
    /// (ruling T27a): stored on its pending intents, if it has any, as
    /// their delivery by the request (none: nothing is written).
    pub fn intent_requested(&self, attempt_id: &str, turn: &str) -> Result<()> {
        self.db.execute(
            "UPDATE intents SET delivered_turn=?2, delivered_by=?3
            WHERE attempt_id=?1 AND done_ms IS NULL",
            params![attempt_id, turn, BY_REQUEST],
        )?;
        Ok(())
    }

    /// Intent `id` is done (once: a done intent stays as it was).
    pub fn intent_done(&self, id: i64) -> Result<()> {
        self.db.execute(
            "UPDATE intents SET done_ms=?2 WHERE rowid=?1 AND done_ms IS NULL",
            params![id, crate::session_protocol::membership::host_now().wall_ms],
        )?;
        Ok(())
    }

    /// The intent `id`, as stored.
    #[cfg(test)]
    pub fn intent(&self, id: i64) -> Result<Option<Intent>> {
        Ok(self
            .db
            .query_row(
                &format!("SELECT {COLUMNS} FROM intents WHERE rowid=?1"),
                [id],
                intent,
            )
            .optional()?
            .map(|(i, _)| i))
    }
}

/// An intent's attempt as the bridge sees it in this pass: its receipt in
/// the session journal (`attempt_receipt`: host-work's request for that
/// task only), whether its row in `attempts` has an end, and, while it is
/// `executing`, what the session's chat shows (the chat's half of the turn
/// check, the bridge's `running_request`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptNow {
    /// No receipt (never admitted; or settled and evicted). `live`: its
    /// row has no end yet (only at a start's recovery: a crash between its
    /// commit and its submit, design I.6.3 "Absent").
    Absent { live: bool },
    /// `accepted`: it hasn't started.
    Unstarted,
    /// `rejected` (withdrawn, or refused at its start): no side effect.
    /// `live`: host-work hasn't ended its row yet.
    Rejected { live: bool },
    /// `executing`, waiting for the start's reconciliation with its adopted
    /// worker's chat (R9.14 item 6): nothing is known of its turn yet.
    Reconciling,
    /// `executing`, and the chat shows its turn running: the turn's id.
    Running { turn: String },
    /// `executing`, but no turn of it is shown running: its prompt not
    /// taken yet, no turn state, the journal halted. Says nothing of
    /// whether the turn ended.
    NotShown,
    /// `completed` or `outcome_unknown`: its turn ended, or (after a
    /// restart) can't be shown current; nothing to interrupt.
    Ended,
}

/// What to do with a pending intent now ([`intents_pass`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Interrupt the turn `turn` with host authority (the bridge's
    /// `host_interrupt`, which runs the whole turn check first).
    Deliver { turn: String },
    /// Only revoke a lease another controller holds (the bridge's
    /// `host_interrupt_revoke_lease`); nothing written.
    RevokeOnly,
    /// Withdraw the unstarted attempt; the task takes
    /// [`IntentReason::withdrawn`].
    Withdraw,
    /// Nothing is left to do: the intent is done.
    Done,
    /// Nothing now; it stays pending.
    Wait,
}

/// What this run knows of each attempt's interrupt (memory only: a
/// restart delivers once more to a turn still current, R9.14 item 5): every
/// interrupt written to an attempt's turn, an intent's or `work_interrupt`'s
/// (host-work-v1 §11.2), so a turn gets one Esc from all of them (ruling
/// T27a).
#[derive(Debug, Default)]
pub struct Runs {
    /// Attempt → its write still waiting for the worker's answer (one at a
    /// time).
    writing: HashMap<String, Writing>,
    /// Attempt → its last delivery.
    delivered: HashMap<String, Delivered>,
}

/// Who wrote an attempt's interrupt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Writer {
    /// A pending intent of it: the delivery is the intent's own
    /// (`delivered_turn`).
    Intent,
    /// `work_interrupt` for task `task_id`: kept whatever intents exist,
    /// until the attempt no longer executes ([`Runs::prune`]); stored on a
    /// pending intent as the request's delivery.
    Request { task_id: String },
}

/// A write waiting for the worker's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Writing {
    turn: String,
    by: Writer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Delivered {
    turn: String,
    /// The bridge clock when the report came.
    at_ms: u64,
    /// An error after queueing: it may not have reached the terminal.
    uncertain: bool,
    by: Writer,
}

impl Runs {
    /// The bridge wrote the interrupt for `attempt_id`'s turn `turn`: its
    /// report comes in a later pass.
    pub fn written(&mut self, attempt_id: &str, turn: &str) {
        self.writing.insert(
            attempt_id.to_string(),
            Writing {
                turn: turn.to_string(),
                by: Writer::Intent,
            },
        );
    }

    /// `work_interrupt` (host-work-v1 §11.2) wrote the interrupt for task
    /// `task_id`'s attempt `attempt_id`, turn `turn` (ruling T27a). While
    /// its report is awaited, and once it is reported written, the turn has
    /// had its interrupt: a later request or intent in that turn writes
    /// nothing ([`Runs::running`]). Kept whatever intents exist, until the
    /// attempt no longer executes ([`Runs::prune`]); stored on a pending
    /// intent of the attempt as the request's delivery, so the turn, if
    /// this ends it, reads `turn interrupted`.
    pub fn requested(&mut self, task_id: &str, attempt_id: &str, turn: &str) {
        self.writing.insert(
            attempt_id.to_string(),
            Writing {
                turn: turn.to_string(),
                by: Writer::Request {
                    task_id: task_id.to_string(),
                },
            },
        );
    }

    /// Whether this run has a record of `attempt_id`'s interrupt.
    #[cfg(test)]
    pub fn knows(&self, attempt_id: &str) -> bool {
        self.writing.contains_key(attempt_id) || self.delivered.contains_key(attempt_id)
    }

    /// Drops what `work_interrupt` recorded for attempts that no longer
    /// execute (`executing(task, attempt)` false: their turn ended, or they
    /// never started), so the record stays bounded by the turns that run.
    /// An intent's record goes when the intent is done ([`Runs::forget`]).
    pub fn prune(&mut self, executing: &mut dyn FnMut(&str, &str) -> bool) {
        self.delivered.retain(|attempt, d| match &d.by {
            Writer::Intent => true,
            Writer::Request { task_id } => executing(task_id, attempt),
        });
    }

    /// What an interrupt of `attempt_id`'s turn `turn`, shown running, does
    /// now (`now_ms` on the bridge clock), an intent's or `work_interrupt`'s:
    /// only the lease revocation ([`Decision::RevokeOnly`]) while a write is
    /// in flight, or once this turn got its interrupt in this run (unless
    /// that was an error after queueing [`REWRITE_AFTER_ERROR_MS`] ago);
    /// else the interrupt ([`Decision::Deliver`]).
    pub fn running(&self, attempt_id: &str, turn: &str, now_ms: u64) -> Decision {
        if self.writing.contains_key(attempt_id) {
            // One write in flight at a time.
            return Decision::RevokeOnly;
        }
        match self.delivered.get(attempt_id) {
            Some(d)
                if d.turn == turn
                    && !(d.uncertain
                        && now_ms >= d.at_ms.saturating_add(REWRITE_AFTER_ERROR_MS)) =>
            {
                Decision::RevokeOnly
            }
            _ => Decision::Deliver {
                turn: turn.to_string(),
            },
        }
    }

    /// `attempt_id` has no pending intent any more.
    pub fn forget(&mut self, attempt_id: &str) {
        self.writing.remove(attempt_id);
        self.delivered.remove(attempt_id);
    }

    /// The reports of this run's writes (`reports`: the bridge's
    /// `host_interrupt_reports`, each write's once), at `now_ms` on the
    /// bridge clock: `ok` and `error_after_queue` are deliveries, kept for
    /// the turn (an intent's written durably as its `delivered_turn`;
    /// `work_interrupt`'s on a pending intent of the attempt, if any, as
    /// the request's), the rest wrote nothing. Reports of writes neither
    /// made (the drive hook's) are ignored.
    pub fn reported(
        &mut self,
        store: &Store,
        reports: &[(String, InterruptReport)],
        now_ms: u64,
    ) -> Result<()> {
        for (attempt, report) in reports {
            let Some(Writing { turn, by }) = self.writing.remove(attempt) else {
                continue;
            };
            let uncertain = match report {
                InterruptReport::Ok => false,
                InterruptReport::ErrorAfterQueue => true,
                // Nothing written: written again on the next pass.
                InterruptReport::Consumed
                | InterruptReport::Dropped
                | InterruptReport::NoEffect => continue,
            };
            match &by {
                Writer::Intent => store.intent_delivered(attempt, &turn)?,
                Writer::Request { .. } => store.intent_requested(attempt, &turn)?,
            }
            self.delivered.insert(
                attempt.clone(),
                Delivered {
                    turn,
                    at_ms: now_ms,
                    uncertain,
                    by,
                },
            );
        }
        Ok(())
    }
}

/// One pass of the pending intents (oldest first): the reports of this
/// run's writes since the last pass (`reports`: the bridge's
/// `host_interrupt_reports`, each write's once) are taken into `runs` (a
/// delivery's turn written durably as `delivered_turn`), then each intent
/// gets its decision from its attempt's state (`now_of`) and `runs`, at
/// `now_ms` on the bridge clock. Nothing here acts on the session host:
/// the bridge carries the decisions out (Task 15's ruling T15c), after the
/// pass's `advance` and the start's reconciliation (`reconcile_host_work`).
///
/// Several intents of one attempt: the first one pending decides the
/// interrupt; the others wait (or are done with it).
pub fn intents_pass(
    store: &Store,
    now_of: &mut dyn FnMut(&Intent) -> AttemptNow,
    reports: &[(String, InterruptReport)],
    runs: &mut Runs,
    now_ms: u64,
) -> Result<Vec<(Intent, Decision)>> {
    runs.reported(store, reports, now_ms)?;
    let mut decided: HashMap<String, Decision> = HashMap::new();
    let mut out = Vec::new();
    for intent in store.pending_intents()? {
        let attempt = intent.attempt_id.clone();
        if let Some(first) = decided.get(&attempt) {
            let decision = if *first == Decision::Done {
                Decision::Done
            } else {
                Decision::Wait
            };
            out.push((intent, decision));
            continue;
        }
        let decision = match now_of(&intent) {
            AttemptNow::Absent { live: true }
            | AttemptNow::Unstarted
            | AttemptNow::Rejected { live: true } => Decision::Withdraw,
            AttemptNow::Absent { live: false }
            | AttemptNow::Rejected { live: false }
            | AttemptNow::Ended => Decision::Done,
            AttemptNow::Reconciling | AttemptNow::NotShown => Decision::Wait,
            AttemptNow::Running { turn } => runs.running(&attempt, &turn, now_ms),
        };
        decided.insert(attempt, decision.clone());
        out.push((intent, decision));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::delegated::{Admission, DelegatedSender};
    use crate::runtime::host_work::WorkRecord;
    use crate::session_protocol::wire::Target;
    use atem_client::session::host_work::{self as hw, HostTarget, WorkStatus, WorkTask};

    fn uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .bind(&HostTarget {
                account_id: "acct".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
            })
            .unwrap();
        (dir, store)
    }

    /// A delegated task, enqueued: its id.
    fn task(store: &Store) -> String {
        let task_id = uuid();
        let r = WorkRecord {
            principal: "member:dev-phone".into(),
            attachment_owner: String::new(),
            control_gen: 1,
            route_id: "r".into(),
            route_revision: 1,
            profile_id: "p".into(),
            profile_revision: 1,
            project: "local:project".into(),
            digest: hw::digest(task_id.as_bytes()),
            task: WorkTask {
                task_id: task_id.clone(),
                workflow_id: uuid(),
                target: Target {
                    account_id: "acct".into(),
                    atem_device_id: "host".into(),
                    host_trust_gen: 1,
                    session_id: "ses-aaaaaaaaaaaa".into(),
                    process_gen: uuid(),
                },
                expires_at: u64::MAX / 2,
                prompt: "build it".into(),
                context: vec![],
                attachments: vec![],
            },
            status: WorkStatus {
                task_id: task_id.clone(),
                receipt_id: uuid(),
                state: WorkState::Queued,
                detail: "waiting for a ready agent".into(),
                result: None,
                resolved: None,
            },
            turn_id: None,
            authorization_expires_at: None,
            message: None,
            delegated: Some(Admission {
                principal: "member:dev-phone".into(),
                principal_key: "ab".repeat(32),
                sender: DelegatedSender::Native {
                    device_id: "dev-phone".into(),
                },
                feed: None,
                route_id: "r".into(),
                route_revision: 1,
                ops_at_admission: vec!["notify".into(), "prompt".into()],
                scope_at_admission: serde_json::Value::Null,
                grant_expires_at: None,
                device_list_seq: 3,
                projects_matched: vec![],
            }),
        };
        store.enqueue(&r).unwrap();
        task_id
    }

    fn write(store: &Store, task: &str, attempt: &str, reason: IntentReason) -> bool {
        let tx = store.immediate().unwrap();
        let written = store.write_intent(&tx, task, attempt, reason).unwrap();
        tx.commit().unwrap();
        written
    }

    fn revoke(id: &str) -> IntentReason {
        IntentReason::Revoke {
            revocation: id.into(),
        }
    }

    /// One pass where every intent's attempt is `now`: the decisions.
    fn pass(
        store: &Store,
        now: AttemptNow,
        reports: &[(String, InterruptReport)],
        runs: &mut Runs,
        now_ms: u64,
    ) -> Vec<Decision> {
        intents_pass(store, &mut |_| now.clone(), reports, runs, now_ms)
            .unwrap()
            .into_iter()
            .map(|(_, d)| d)
            .collect()
    }

    fn running(turn: &str) -> AttemptNow {
        AttemptNow::Running { turn: turn.into() }
    }

    fn deliver(turn: &str) -> Decision {
        Decision::Deliver { turn: turn.into() }
    }

    /// An intent is durable once its `BEGIN IMMEDIATE` transaction commits,
    /// never before: another connection sees none until then. One per
    /// attempt and reason (and revocation); a deadline's and a revocation's
    /// may stand side by side. Read back as written, oldest first.
    #[test]
    fn an_intent_is_written_once_and_read_back_after_its_commit() {
        let (dir, store) = store();
        let task = task(&store);
        let attempt = uuid();
        let other = rusqlite::Connection::open(dir.path().join("host-work.sqlite")).unwrap();
        let count = || -> i64 {
            other
                .query_row("SELECT count(*) FROM intents", [], |r| r.get(0))
                .unwrap()
        };
        let tx = store.immediate().unwrap();
        assert!(
            store
                .write_intent(&tx, &task, &attempt, IntentReason::Deadline)
                .unwrap()
        );
        assert_eq!(count(), 0, "not before the commit");
        tx.commit().unwrap();
        assert_eq!(count(), 1);
        assert!(!write(&store, &task, &attempt, IntentReason::Deadline));
        assert!(write(&store, &task, &attempt, revoke("rec-1")));
        assert!(!write(&store, &task, &attempt, revoke("rec-1")));
        assert!(write(&store, &task, &attempt, revoke("rec-2")));
        let pending = store.pending_intents().unwrap();
        assert_eq!(
            pending.iter().map(|i| i.reason.clone()).collect::<Vec<_>>(),
            [IntentReason::Deadline, revoke("rec-1"), revoke("rec-2")]
        );
        assert!(pending.iter().all(|i| i.task_id == task
            && i.attempt_id == attempt
            && i.done_ms.is_none()
            && i.delivered_turn.is_none()
            && i.created_ms > 0));
        assert!(
            store
                .has_intent(&task, &attempt, &IntentReason::Deadline)
                .unwrap()
        );
        assert!(
            !store
                .has_intent(&task, &uuid(), &IntentReason::Deadline)
                .unwrap()
        );
        store.intent_delivered(&attempt, "turn-1").unwrap();
        store.intent_done(pending[0].id).unwrap();
        let first = store.intent(pending[0].id).unwrap().unwrap();
        assert_eq!(first.delivered_turn.as_deref(), Some("turn-1"));
        let done = first.done_ms.unwrap();
        // Done once: a second time changes nothing.
        store.intent_done(pending[0].id).unwrap();
        assert_eq!(
            store.intent(pending[0].id).unwrap().unwrap().done_ms,
            Some(done)
        );
        assert_eq!(store.pending_intents().unwrap().len(), 2);
        assert_eq!(store.intents_of(&task).unwrap().len(), 3);
    }

    /// The pass reads pending intents only, through their own partial
    /// index: done ones, however many, are never scanned.
    #[test]
    fn pending_intents_are_read_through_their_index() {
        let (_dir, store) = store();
        let plan: Vec<String> = store
            .db
            .prepare(&format!(
                "EXPLAIN QUERY PLAN SELECT {COLUMNS} FROM intents INDEXED BY intents_pending
                WHERE done_ms IS NULL ORDER BY rowid"
            ))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(
            plan.iter().any(|p| p.contains("intents_pending")),
            "{plan:?}"
        );
        let task = task(&store);
        for _ in 0..50 {
            let attempt = uuid();
            write(&store, &task, &attempt, IntentReason::Deadline);
        }
        for i in store.pending_intents().unwrap() {
            store.intent_done(i.id).unwrap();
        }
        assert!(store.pending_intents().unwrap().is_empty());
    }

    /// Design I.5.7: not `executing` → withdrawn (an `accepted` attempt; a
    /// `rejected` or absent one host-work hasn't ended); ended, or one that
    /// never started and ended → done; still being reconciled at a start,
    /// or `executing` with no turn shown running → pending, nothing done
    /// (never read as "the turn ended").
    #[test]
    fn decisions_follow_the_attempts_state() {
        let (_dir, store) = store();
        let task = task(&store);
        write(&store, &task, &uuid(), IntentReason::Deadline);
        let mut runs = Runs::default();
        for (now, want) in [
            (AttemptNow::Unstarted, Decision::Withdraw),
            (AttemptNow::Rejected { live: true }, Decision::Withdraw),
            (AttemptNow::Absent { live: true }, Decision::Withdraw),
            (AttemptNow::Rejected { live: false }, Decision::Done),
            (AttemptNow::Absent { live: false }, Decision::Done),
            (AttemptNow::Ended, Decision::Done),
            (AttemptNow::Reconciling, Decision::Wait),
            (AttemptNow::NotShown, Decision::Wait),
            (running("turn-1"), deliver("turn-1")),
        ] {
            assert_eq!(
                pass(&store, now.clone(), &[], &mut runs, 0),
                [want],
                "{now:?}"
            );
        }
        // Deciding records nothing: the bridge says what it wrote.
        assert_eq!(
            pass(&store, running("turn-1"), &[], &mut runs, 0),
            [deliver("turn-1")]
        );
    }

    /// Session-v1 R9.14 item 5: one Esc per turn. While the write waits for
    /// its report only the revocation runs; once delivered (`ok`), only the
    /// revocation repeats, for as long as that turn is current; a turn of
    /// its own (another id) gets its own. The delivery's turn is written
    /// durably on the intent.
    #[test]
    fn delivered_once_per_turn_then_only_the_revocation() {
        let (_dir, store) = store();
        let task = task(&store);
        let attempt = uuid();
        write(&store, &task, &attempt, IntentReason::Deadline);
        let mut runs = Runs::default();
        assert_eq!(
            pass(&store, running("turn-1"), &[], &mut runs, 0),
            [deliver("turn-1")]
        );
        runs.written(&attempt, "turn-1");
        for _ in 0..3 {
            assert_eq!(
                pass(&store, running("turn-1"), &[], &mut runs, 100),
                [Decision::RevokeOnly],
                "one write in flight"
            );
        }
        let ok = [(attempt.clone(), InterruptReport::Ok)];
        assert_eq!(
            pass(&store, running("turn-1"), &ok, &mut runs, 200),
            [Decision::RevokeOnly]
        );
        assert_eq!(
            store.pending_intents().unwrap()[0]
                .delivered_turn
                .as_deref(),
            Some("turn-1")
        );
        for at in [300, 60_000, 3_600_000] {
            assert_eq!(
                pass(&store, running("turn-1"), &[], &mut runs, at),
                [Decision::RevokeOnly],
                "no blind second Esc"
            );
        }
        assert_eq!(
            pass(&store, running("turn-2"), &[], &mut runs, 3_600_000),
            [deliver("turn-2")]
        );
        // A report of a write no intent made (the drive hook's) is ignored.
        let foreign = [(uuid(), InterruptReport::Ok)];
        assert_eq!(
            pass(&store, running("turn-2"), &foreign, &mut runs, 3_600_000),
            [deliver("turn-2")]
        );
    }

    /// `consumed`, `dropped` and `no_effect` wrote nothing: the next pass
    /// writes again (still the current turn).
    #[test]
    fn a_write_that_wrote_nothing_is_written_again() {
        let (_dir, store) = store();
        let task = task(&store);
        let attempt = uuid();
        write(&store, &task, &attempt, IntentReason::Deadline);
        let mut runs = Runs::default();
        for report in [
            InterruptReport::Consumed,
            InterruptReport::Dropped,
            InterruptReport::NoEffect,
        ] {
            assert_eq!(
                pass(&store, running("turn-1"), &[], &mut runs, 0),
                [deliver("turn-1")]
            );
            runs.written(&attempt, "turn-1");
            assert_eq!(
                pass(
                    &store,
                    running("turn-1"),
                    &[(attempt.clone(), report)],
                    &mut runs,
                    0
                ),
                [deliver("turn-1")],
                "{report:?}"
            );
            assert_eq!(store.pending_intents().unwrap()[0].delivered_turn, None);
        }
    }

    /// An error after queueing may have reached the terminal: it counts as
    /// delivered (no blind second Esc), and is written again only if the
    /// turn is still the current one 10 s later on the bridge clock.
    #[test]
    fn an_error_after_queueing_is_written_again_ten_seconds_later() {
        let (_dir, store) = store();
        let task = task(&store);
        let attempt = uuid();
        write(&store, &task, &attempt, IntentReason::Deadline);
        let mut runs = Runs::default();
        pass(&store, running("turn-1"), &[], &mut runs, 1_000);
        runs.written(&attempt, "turn-1");
        let error = [(attempt.clone(), InterruptReport::ErrorAfterQueue)];
        assert_eq!(
            pass(&store, running("turn-1"), &error, &mut runs, 2_000),
            [Decision::RevokeOnly]
        );
        assert_eq!(
            store.pending_intents().unwrap()[0]
                .delivered_turn
                .as_deref(),
            Some("turn-1"),
            "counts as delivered"
        );
        assert_eq!(
            pass(
                &store,
                running("turn-1"),
                &[],
                &mut runs,
                2_000 + REWRITE_AFTER_ERROR_MS - 1
            ),
            [Decision::RevokeOnly]
        );
        assert_eq!(
            pass(
                &store,
                running("turn-1"),
                &[],
                &mut runs,
                2_000 + REWRITE_AFTER_ERROR_MS
            ),
            [deliver("turn-1")]
        );
        // The turn ended meanwhile: nothing written, the intent done.
        assert_eq!(
            pass(
                &store,
                AttemptNow::Ended,
                &[],
                &mut runs,
                2_000 + REWRITE_AFTER_ERROR_MS
            ),
            [Decision::Done]
        );
    }

    /// A restart forgets what the last run delivered (memory only): a turn
    /// still current after the start's reconciliation gets the interrupt
    /// once more (R9.14 item 5); the stored `delivered_turn` stays a record.
    #[test]
    fn a_new_run_delivers_once_more() {
        let (_dir, store) = store();
        let task = task(&store);
        let attempt = uuid();
        write(&store, &task, &attempt, IntentReason::Deadline);
        let mut runs = Runs::default();
        pass(&store, running("turn-1"), &[], &mut runs, 0);
        runs.written(&attempt, "turn-1");
        pass(
            &store,
            running("turn-1"),
            &[(attempt.clone(), InterruptReport::Ok)],
            &mut runs,
            0,
        );
        let mut next_run = Runs::default();
        assert_eq!(
            pass(&store, AttemptNow::Reconciling, &[], &mut next_run, 0),
            [Decision::Wait]
        );
        assert_eq!(
            pass(&store, running("turn-1"), &[], &mut next_run, 0),
            [deliver("turn-1")]
        );
    }

    /// Two intents of one attempt (a deadline and a revocation): the first
    /// decides the interrupt, the second waits with it (one Esc); both are
    /// done when the turn ended; a withdrawal is the first's only.
    #[test]
    fn several_intents_of_one_attempt_write_once() {
        let (_dir, store) = store();
        let task = task(&store);
        let attempt = uuid();
        write(&store, &task, &attempt, IntentReason::Deadline);
        write(&store, &task, &attempt, revoke("rec-1"));
        let mut runs = Runs::default();
        assert_eq!(
            pass(&store, running("turn-1"), &[], &mut runs, 0),
            [deliver("turn-1"), Decision::Wait]
        );
        assert_eq!(
            pass(&store, AttemptNow::Unstarted, &[], &mut runs, 0),
            [Decision::Withdraw, Decision::Wait]
        );
        assert_eq!(
            pass(&store, AttemptNow::Ended, &[], &mut runs, 0),
            [Decision::Done, Decision::Done]
        );
    }

    /// Ruling T27a: one Esc per attempt and turn, from any source.
    /// `work_interrupt`'s write (host-work-v1 §11.2) and the intents share
    /// `Runs`. While the request's write is in flight, and once it is
    /// reported written, the turn has had its interrupt: a pending intent
    /// only revokes, and so would a later request (`running`). On a pending
    /// intent it is stored as the request's delivery (`delivered_turn`, the
    /// request's marker: not the deadline's turn), and a later delivery of
    /// the intent's own clears the marker. Without an intent it is kept in
    /// memory all the same, until the attempt no longer executes (`prune`).
    /// A request whose write wrote nothing leaves the turn to be written.
    #[test]
    fn a_requested_write_counts_for_its_turn_whatever_the_intents() {
        let (_dir, store) = store();
        let task = task(&store);
        let attempt = uuid();
        write(&store, &task, &attempt, IntentReason::Deadline);
        let mut runs = Runs::default();
        assert_eq!(runs.running(&attempt, "turn-1", 0), deliver("turn-1"));
        runs.requested(&task, &attempt, "turn-1");
        assert_eq!(runs.running(&attempt, "turn-1", 0), Decision::RevokeOnly);
        assert_eq!(
            pass(&store, running("turn-1"), &[], &mut runs, 100),
            [Decision::RevokeOnly],
            "one write in flight"
        );
        let ok = [(attempt.clone(), InterruptReport::Ok)];
        for at in [200, 60_000, 3_600_000] {
            let reports: &[_] = if at == 200 { &ok } else { &[] };
            assert_eq!(
                pass(&store, running("turn-1"), reports, &mut runs, at),
                [Decision::RevokeOnly],
                "delivered by the request"
            );
        }
        let stored = &store.pending_intents().unwrap()[0];
        assert_eq!(
            (
                stored.delivered_turn.as_deref(),
                stored.delivered_by_request
            ),
            (Some("turn-1"), true),
            "stored as the request's"
        );
        assert_eq!(
            store
                .delivered_turn(&task, &attempt, &IntentReason::Deadline)
                .unwrap(),
            None,
            "not the deadline's turn"
        );
        // A later turn of the attempt: the intent's own delivery.
        assert_eq!(
            pass(&store, running("turn-2"), &[], &mut runs, 3_600_000),
            [deliver("turn-2")]
        );
        runs.written(&attempt, "turn-2");
        let ok2 = [(attempt.clone(), InterruptReport::Ok)];
        pass(&store, running("turn-2"), &ok2, &mut runs, 3_600_000);
        let stored = &store.pending_intents().unwrap()[0];
        assert_eq!(
            (
                stored.delivered_turn.as_deref(),
                stored.delivered_by_request
            ),
            (Some("turn-2"), false)
        );
        // Nothing written: the turn is still to be written.
        let other_task = self::task(&store);
        let other = uuid();
        runs.requested(&other_task, &other, "turn-9");
        let consumed = [(other.clone(), InterruptReport::Consumed)];
        runs.reported(&store, &consumed, 0).unwrap();
        assert_eq!(runs.running(&other, "turn-9", 0), deliver("turn-9"));
        // No intent at all: kept in memory, one Esc for the turn, until
        // the attempt no longer executes; nothing stored.
        let alone_task = self::task(&store);
        let alone = uuid();
        runs.requested(&alone_task, &alone, "turn-5");
        runs.reported(&store, &[(alone.clone(), InterruptReport::Ok)], 0)
            .unwrap();
        assert_eq!(runs.running(&alone, "turn-5", 0), Decision::RevokeOnly);
        assert!(store.intents_of(&alone_task).unwrap().is_empty());
        let mut asked = Vec::new();
        runs.prune(&mut |task, attempt| {
            asked.push((task.to_string(), attempt.to_string()));
            true
        });
        assert_eq!(
            asked,
            [(alone_task.clone(), alone.clone())],
            "requests only"
        );
        assert_eq!(runs.running(&alone, "turn-5", 0), Decision::RevokeOnly);
        runs.prune(&mut |_, _| false);
        assert_eq!(runs.running(&alone, "turn-5", 0), deliver("turn-5"));
        assert_eq!(
            runs.running(&attempt, "turn-2", 0),
            Decision::RevokeOnly,
            "an intent's record stays until the intent is done"
        );
    }

    /// The task's state when its unstarted attempt is withdrawn: expired
    /// for a deadline, cancelled for a revocation (design I.5.7).
    #[test]
    fn a_withdrawal_expires_or_cancels_the_task() {
        assert_eq!(
            IntentReason::Deadline.withdrawn(),
            (WorkState::Expired, "expired before submission")
        );
        assert_eq!(
            revoke("rec-1").withdrawn(),
            (WorkState::Cancelled, details::SENDER_REVOKED)
        );
    }
}

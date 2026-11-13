//! Attempts (design I.6.4; host-work-v1 §11.6 "Attempts and
//! `receipt_id`"): each dispatch of a delegated task is an attempt, with a
//! fresh UUID v4 that is the session-v1 `request_id` of its prompt,
//! committed in its row (`attempts`, in `host-work.sqlite`) before the
//! submit, in a `BEGIN IMMEDIATE` transaction ([`Store::immediate`]).
//!
//! - At most one attempt of a task is live (no end yet); the database
//!   refuses a second live row too (`attempts_live`).
//! - A new attempt is made only once the previous one is proven
//!   side-effect-free: never admitted, withdrawn, rejected, or
//!   `request_id_reused`. One that started (`executing` or past it) ends
//!   the task's attempts for good.
//! - At most [`MAX_ATTEMPTS`] counted attempts, then the task is `failed`,
//!   `too many attempts`. A hold's withdrawal and a `request_id_reused`
//!   aren't counted.
//! - An ended attempt is never submitted again under its id
//!   ([`Store::may_submit`]): its end is durable, so this holds after a
//!   restart; a new host identity moves the whole store aside.
//! - The task's `receipt_id` is its current attempt's id
//!   ([`Store::new_attempt`] writes it into the task's status).
//!
//! What the session host answers an attempt maps to its end in one place,
//! [`attempt_end`].
use crate::runtime::delegated::details;
use crate::runtime::host_work::Store;
use crate::session_protocol::host::{HostInterrupt, Withdrawal};
use crate::session_protocol::wire::{ErrorCode, ReceiptState};
use anyhow::{Result, anyhow, bail};
use atem_client::session::host_work::WorkState;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

/// The counted attempts a task gets (design I.6.4).
pub const MAX_ATTEMPTS: u32 = 8;

/// One attempt of a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// A fresh UUID v4: the session-v1 `request_id` of its prompt.
    pub attempt_id: String,
    /// Its place among the task's attempts, counted or not (from 1).
    pub n: u32,
    /// It counts toward [`MAX_ATTEMPTS`] (every attempt until an end says
    /// otherwise).
    pub counted: bool,
}

/// How an attempt ended. Every end but `Started` is a proof that it had no
/// side effect, so the task may get a new attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptEnd {
    /// The session host never admitted it (refused before anything was
    /// recorded; absent from the recovered journal).
    NotAdmitted,
    /// Host-work withdrew it before it started (session-v1 R9.14 items 3,
    /// 4 and 6). `counted: false` for a hold's withdrawal.
    Withdrawn { counted: bool },
    /// Its receipt is `rejected` for another reason.
    Rejected,
    /// It reached `executing` (or past it): the task's attempts are over.
    Started,
    /// Its id is recorded under another submitter (`request_id_reused`,
    /// R9.14 item 7): never admitted, not counted.
    Reused,
}

impl AttemptEnd {
    fn as_str(self) -> &'static str {
        match self {
            AttemptEnd::NotAdmitted => "not_admitted",
            AttemptEnd::Withdrawn { .. } => "withdrawn",
            AttemptEnd::Rejected => "rejected",
            AttemptEnd::Started => "started",
            AttemptEnd::Reused => "reused",
        }
    }

    fn read(name: &str, counted: bool) -> Option<Self> {
        Some(match name {
            "not_admitted" => AttemptEnd::NotAdmitted,
            "withdrawn" => AttemptEnd::Withdrawn { counted },
            "rejected" => AttemptEnd::Rejected,
            "started" => AttemptEnd::Started,
            "reused" => AttemptEnd::Reused,
            _ => return None,
        })
    }

    /// Whether it counts toward [`MAX_ATTEMPTS`].
    pub fn counted(self) -> bool {
        match self {
            AttemptEnd::Withdrawn { counted } => counted,
            AttemptEnd::Reused => false,
            _ => true,
        }
    }

    /// A proof that the attempt had no side effect.
    pub fn no_effect(self) -> bool {
        self != AttemptEnd::Started
    }
}

/// Why [`Store::new_attempt`] made none (the error it returns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptRefused {
    /// A v1 task: it has no admission record, so no attempts.
    NotDelegated,
    /// The task doesn't wait to run (not `queued` or `blocked`).
    NotWaiting,
    /// Its current attempt has no end yet.
    Live,
    /// An attempt started: the task's attempts are over for good.
    Started,
    /// [`MAX_ATTEMPTS`] counted attempts (the task is `failed`).
    TooMany,
}

impl std::fmt::Display for AttemptRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AttemptRefused::NotDelegated => "not a delegated task",
            AttemptRefused::NotWaiting => "the task doesn't wait to run",
            AttemptRefused::Live => "the task's current attempt hasn't ended",
            AttemptRefused::Started => "an attempt of the task started",
            AttemptRefused::TooMany => details::TOO_MANY_ATTEMPTS,
        })
    }
}

impl std::error::Error for AttemptRefused {}

/// What the session host answered about an attempt.
#[derive(Debug)]
pub enum SessionAnswer<'a> {
    /// `submit_host_work` refused it with this `error` code, recording
    /// nothing.
    Refused(ErrorCode),
    /// Its receipt: state and detail.
    Receipt(ReceiptState, Option<&'a str>),
    /// `SessionHost::withdraw` (R9.14 item 4).
    Withdrawal(Withdrawal),
    /// `SessionHost::host_interrupt` (R9.14 item 5).
    // The mapping's own: the interrupt intents decide from the attempt's
    // receipt (`intents::AttemptNow`), never from an interrupt's answer.
    #[allow(dead_code)]
    Interrupt(&'a HostInterrupt),
}

/// The end an answer gives the attempt, or none while it proves nothing
/// yet (an `accepted` receipt, an interrupt that found no current turn):
/// the receipt decides then. `held`: host-work withdrew it for a hold, so
/// the withdrawal isn't counted (design I.6.4).
///
/// - A submit refused before anything was recorded was never admitted;
///   `request_id_reused` is `Reused` (not counted, a fresh id next).
/// - A receipt `executing`, `completed` or `outcome_unknown` started; one
///   `rejected` with host-work's withdrawal detail was withdrawn (at
///   recovery: never for a hold), any other `rejected` is `Rejected`.
/// - A withdrawal `rejected`, `listed`, `list_full` or `halted` never runs:
///   `Withdrawn`. A halted journal admits nothing until the restart, which
///   rejects host-work's `accepted` requests (R9.14 item 6) and finds an
///   unlisted one absent, so ending it here is what keeps its id from
///   being submitted again. `reused` is `Reused`, `started` `Started`.
/// - An interrupt that was written, or revoked a lease, passed the turn
///   check: the attempt is executing (`Started`).
pub fn attempt_end(answer: SessionAnswer<'_>, held: bool) -> Option<AttemptEnd> {
    let withdrawn = AttemptEnd::Withdrawn { counted: !held };
    match answer {
        SessionAnswer::Refused(ErrorCode::RequestIdReused) => Some(AttemptEnd::Reused),
        SessionAnswer::Refused(_) => Some(AttemptEnd::NotAdmitted),
        SessionAnswer::Receipt(ReceiptState::Accepted, _) => None,
        SessionAnswer::Receipt(
            ReceiptState::Executing | ReceiptState::Completed | ReceiptState::OutcomeUnknown,
            _,
        ) => Some(AttemptEnd::Started),
        SessionAnswer::Receipt(ReceiptState::Rejected, detail) => Some(match detail {
            Some(details::WITHDRAWN_BY_THE_HOST) => withdrawn,
            Some(details::WITHDRAWN_AT_RECOVERY) => AttemptEnd::Withdrawn { counted: true },
            _ => AttemptEnd::Rejected,
        }),
        SessionAnswer::Withdrawal(
            Withdrawal::Rejected | Withdrawal::Listed | Withdrawal::ListFull | Withdrawal::Halted,
        ) => Some(withdrawn),
        SessionAnswer::Withdrawal(Withdrawal::Reused) => Some(AttemptEnd::Reused),
        SessionAnswer::Withdrawal(Withdrawal::Started) => Some(AttemptEnd::Started),
        SessionAnswer::Interrupt(HostInterrupt::Written(_) | HostInterrupt::Revoked(_)) => {
            Some(AttemptEnd::Started)
        }
        SessionAnswer::Interrupt(
            HostInterrupt::NotCurrentTurn | HostInterrupt::NotExecuting | HostInterrupt::Halted,
        ) => None,
    }
}

impl Store {
    /// A `BEGIN IMMEDIATE` transaction on the store (design I.5.9): it
    /// holds the write lock from its start, so what it reads stays true
    /// until it commits.
    pub fn immediate(&self) -> Result<Transaction<'_>> {
        Ok(Transaction::new_unchecked(
            &self.db,
            TransactionBehavior::Immediate,
        )?)
    }

    /// A new attempt of the delegated task `task_id`, in `tx` (the store's
    /// own `BEGIN IMMEDIATE` transaction: [`Store::immediate`]); the task's
    /// `receipt_id` becomes its id. It is durable once `tx` commits, before
    /// its submit. Refused ([`AttemptRefused`]): a v1 task, an attempt
    /// that started, one still live, [`MAX_ATTEMPTS`] counted, or a task
    /// that doesn't wait to run.
    pub fn new_attempt(&self, tx: &Transaction, task_id: &str) -> Result<Attempt> {
        let mut record = self
            .work(task_id)?
            .ok_or_else(|| anyhow!("no task {task_id}"))?;
        if record.delegated.is_none() {
            return Err(AttemptRefused::NotDelegated.into());
        }
        let (started, live, counted, all): (u32, u32, u32, u32) = tx.query_row(
            r#"SELECT coalesce(sum("end"='started'),0), coalesce(sum("end" IS NULL),0),
            coalesce(sum(counted),0), count(*) FROM attempts WHERE task_id=?1"#,
            [task_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        let refused = if started > 0 {
            Some(AttemptRefused::Started)
        } else if live > 0 {
            Some(AttemptRefused::Live)
        } else if counted >= MAX_ATTEMPTS {
            Some(AttemptRefused::TooMany)
        } else if !matches!(record.status.state, WorkState::Queued | WorkState::Blocked) {
            Some(AttemptRefused::NotWaiting)
        } else {
            None
        };
        if let Some(refused) = refused {
            return Err(refused.into());
        }
        let attempt = Attempt {
            attempt_id: uuid::Uuid::new_v4().to_string(),
            n: all + 1,
            counted: true,
        };
        tx.execute(
            "INSERT INTO attempts(task_id,attempt_id,n,counted,created_ms) VALUES(?1,?2,?3,1,?4)",
            params![
                task_id,
                attempt.attempt_id,
                attempt.n,
                crate::session_protocol::membership::host_now().wall_ms
            ],
        )?;
        record.status.receipt_id = attempt.attempt_id.clone();
        self.save_work(&record)?;
        Ok(attempt)
    }

    /// Records how the attempt `attempt_id` of `task_id` ended, in `tx`.
    /// An end is final: the same end again changes nothing, another is an
    /// error. With a proof of no effect that makes [`MAX_ATTEMPTS`] counted
    /// attempts, the task is `failed`, `too many attempts`, in the same
    /// transaction.
    pub fn end_attempt(
        &self,
        tx: &Transaction,
        task_id: &str,
        attempt_id: &str,
        end: AttemptEnd,
    ) -> Result<()> {
        let row: Option<(Option<String>, bool)> = tx
            .query_row(
                r#"SELECT "end",counted FROM attempts WHERE task_id=?1 AND attempt_id=?2"#,
                [task_id, attempt_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((ended, counted)) = row else {
            bail!("no attempt {attempt_id} of task {task_id}");
        };
        if let Some(name) = ended {
            if AttemptEnd::read(&name, counted) == Some(end) {
                return Ok(());
            }
            bail!("attempt {attempt_id} already ended ({name})");
        }
        tx.execute(
            r#"UPDATE attempts SET "end"=?3, counted=?4 WHERE task_id=?1 AND attempt_id=?2"#,
            params![task_id, attempt_id, end.as_str(), end.counted()],
        )?;
        if end.no_effect() {
            let total: u32 = tx.query_row(
                "SELECT coalesce(sum(counted),0) FROM attempts WHERE task_id=?1",
                [task_id],
                |r| r.get(0),
            )?;
            if total >= MAX_ATTEMPTS
                && let Some(mut record) = self.work(task_id)?
                && !record.status.state.terminal()
            {
                record.status.state = WorkState::Failed;
                record.status.detail = details::TOO_MANY_ATTEMPTS.into();
                self.save_work(&record)?;
            }
        }
        Ok(())
    }

    /// The task's live attempt (no end yet), if any.
    pub fn live_attempt(&self, task_id: &str) -> Result<Option<Attempt>> {
        Ok(self
            .db
            .query_row(
                r#"SELECT attempt_id,n,counted FROM attempts WHERE task_id=?1 AND "end" IS NULL"#,
                [task_id],
                |r| {
                    Ok(Attempt {
                        attempt_id: r.get(0)?,
                        n: r.get(1)?,
                        counted: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Whether `attempt_id` may be submitted: only the live attempt of
    /// `task_id`, asked within this run, after its row's commit. Never one
    /// that ended, whatever ended it. At recovery a live attempt is
    /// reconciled from its receipt, never resent.
    pub fn may_submit(&self, task_id: &str, attempt_id: &str) -> Result<bool> {
        Ok(self.db.query_row(
            r#"SELECT EXISTS(SELECT 1 FROM attempts
            WHERE task_id=?1 AND attempt_id=?2 AND "end" IS NULL)"#,
            [task_id, attempt_id],
            |r| r.get(0),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::delegated::{Admission, DelegatedSender};
    use crate::runtime::host_work::WorkRecord;
    use crate::session_protocol::wire::Target;
    use atem_client::session::host_work::{
        self as hw, HostTarget, WorkState, WorkStatus, WorkTask,
    };
    use rusqlite::Connection;
    use std::time::Duration;

    fn uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn host() -> HostTarget {
        HostTarget {
            account_id: "acct".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        }
    }

    /// A native member's task, delegated (an admission record) or not.
    fn record(delegated: bool) -> WorkRecord {
        let task_id = uuid();
        WorkRecord {
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
                task_id,
                receipt_id: uuid(),
                state: WorkState::Queued,
                detail: "waiting for a ready agent".into(),
                result: None,
                resolved: None,
            },
            turn_id: None,
            authorization_expires_at: None,
            message: None,
            delegated: delegated.then(|| Admission {
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
        }
    }

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        (dir, store)
    }

    /// A delegated task, enqueued: its id.
    fn task(store: &Store) -> String {
        let r = record(true);
        store.enqueue(&r).unwrap();
        r.task.task_id
    }

    /// A new attempt in its own `BEGIN IMMEDIATE` transaction, committed.
    fn new(store: &Store, task: &str) -> anyhow::Result<Attempt> {
        let tx = store.immediate()?;
        let attempt = store.new_attempt(&tx, task)?;
        tx.commit()?;
        Ok(attempt)
    }

    fn end(store: &Store, task: &str, attempt: &Attempt, end: AttemptEnd) {
        let tx = store.immediate().unwrap();
        store
            .end_attempt(&tx, task, &attempt.attempt_id, end)
            .unwrap();
        tx.commit().unwrap();
    }

    /// Why `new_attempt` refused.
    fn refused(result: anyhow::Result<Attempt>) -> AttemptRefused {
        *result
            .expect_err("refused")
            .downcast_ref::<AttemptRefused>()
            .expect("an AttemptRefused")
    }

    fn status(store: &Store, task: &str) -> WorkStatus {
        store.work(task).unwrap().unwrap().status
    }

    /// Design I.6.4: an attempt id is a fresh UUID v4 (lowercase), in its
    /// row once the `BEGIN IMMEDIATE` transaction that made it commits:
    /// only then does another connection see it, and while it is open no
    /// other writer can begin. So a submit that follows the commit never
    /// names an attempt a crash could lose.
    #[test]
    fn attempt_ids_are_fresh_uuid_v4_committed_before_the_submit() {
        let (dir, store) = store();
        let task = task(&store);
        let other = Connection::open(dir.path().join("host-work.sqlite")).unwrap();
        other.busy_timeout(Duration::ZERO).unwrap();
        let seen = |id: &str| -> i64 {
            other
                .query_row(
                    "SELECT count(*) FROM attempts WHERE attempt_id=?1",
                    [id],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let enqueued = status(&store, &task).receipt_id;
        let tx = store.immediate().unwrap();
        assert!(
            other.execute_batch("BEGIN IMMEDIATE").is_err(),
            "the attempt's transaction holds the write lock from its start"
        );
        let first = store.new_attempt(&tx, &task).unwrap();
        assert_eq!(seen(&first.attempt_id), 0, "not before the commit");
        tx.commit().unwrap();
        assert_eq!(seen(&first.attempt_id), 1, "committed");
        assert_eq!((first.n, first.counted), (1, true));
        assert_eq!(status(&store, &task).receipt_id, first.attempt_id);
        let mut ids = vec![enqueued, first.attempt_id.clone()];
        end(&store, &task, &first, AttemptEnd::Reused);
        for n in 2..=12 {
            let a = new(&store, &task).unwrap();
            assert_eq!(a.n, n);
            ids.push(a.attempt_id.clone());
            end(&store, &task, &a, AttemptEnd::Reused);
        }
        for id in &ids[1..] {
            let parsed = uuid::Uuid::parse_str(id).unwrap();
            assert_eq!(parsed.get_version_num(), 4, "{id}");
            assert_eq!(*id, parsed.hyphenated().to_string(), "lowercase: {id}");
        }
        let mut distinct = ids.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            ids.len(),
            "every id fresh, the enqueue's too"
        );
    }

    /// At most one live attempt per task: a second is refused while the
    /// first has no end, and the database refuses a second live row too.
    #[test]
    fn at_most_one_live_attempt() {
        let (_dir, store) = store();
        let task = task(&store);
        assert_eq!(store.live_attempt(&task).unwrap(), None);
        let first = new(&store, &task).unwrap();
        assert_eq!(refused(new(&store, &task)), AttemptRefused::Live);
        assert_eq!(store.live_attempt(&task).unwrap(), Some(first.clone()));
        assert!(
            store
                .db
                .execute(
                    "INSERT INTO attempts(task_id,attempt_id,n,counted,created_ms)
                    VALUES(?1,?2,2,1,0)",
                    [&task, &uuid()],
                )
                .is_err(),
            "one live row per task"
        );
        end(&store, &task, &first, AttemptEnd::NotAdmitted);
        assert_eq!(store.live_attempt(&task).unwrap(), None);
        // Another task's attempt is its own.
        let other = self::task(&store);
        let mine = new(&store, &task).unwrap();
        let theirs = new(&store, &other).unwrap();
        assert_eq!(store.live_attempt(&task).unwrap(), Some(mine));
        assert_eq!(store.live_attempt(&other).unwrap(), Some(theirs));
    }

    /// A new attempt only once the previous one is proven side-effect-free
    /// (never admitted, withdrawn, rejected, or `request_id_reused`); one
    /// that started ends the task's attempts for good. Only a delegated
    /// task that waits to run has attempts.
    #[test]
    fn a_new_attempt_only_after_proof_of_no_effect() {
        let (_dir, store) = store();
        let task = task(&store);
        for no_effect in [
            AttemptEnd::NotAdmitted,
            AttemptEnd::Withdrawn { counted: true },
            AttemptEnd::Withdrawn { counted: false },
            AttemptEnd::Rejected,
            AttemptEnd::Reused,
        ] {
            let a = new(&store, &task).unwrap();
            end(&store, &task, &a, no_effect);
        }
        let started = new(&store, &task).unwrap();
        end(&store, &task, &started, AttemptEnd::Started);
        for _ in 0..2 {
            assert_eq!(refused(new(&store, &task)), AttemptRefused::Started);
        }
        // A v1 task has no attempts, nor does one that doesn't wait to run.
        let v1 = record(false);
        store.enqueue(&v1).unwrap();
        assert_eq!(
            refused(new(&store, &v1.task.task_id)),
            AttemptRefused::NotDelegated
        );
        let done = self::task(&store);
        let mut r = store.work(&done).unwrap().unwrap();
        r.status.state = WorkState::Cancelled;
        store.save_work(&r).unwrap();
        assert_eq!(refused(new(&store, &done)), AttemptRefused::NotWaiting);
        let blocked = self::task(&store);
        let mut r = store.work(&blocked).unwrap().unwrap();
        r.status.state = WorkState::Blocked;
        store.save_work(&r).unwrap();
        assert!(new(&store, &blocked).is_ok(), "blocked waits to run");
    }

    /// Design I.6.4: at most 8 attempts, then `failed`, `too many
    /// attempts`, committed with the eighth's end (it survives a restart);
    /// no ninth.
    #[test]
    fn eight_attempts_then_failed_too_many_attempts() {
        let (dir, store) = store();
        let task = task(&store);
        for n in 1..=MAX_ATTEMPTS {
            let a = new(&store, &task).unwrap();
            assert_eq!(a.n, n);
            end(&store, &task, &a, AttemptEnd::Rejected);
            let s = status(&store, &task);
            if n < MAX_ATTEMPTS {
                assert_eq!(s.state, WorkState::Queued, "after {n}");
            } else {
                assert_eq!(s.state, WorkState::Failed);
                assert_eq!(
                    s.detail,
                    crate::runtime::delegated::details::TOO_MANY_ATTEMPTS
                );
            }
        }
        assert_eq!(refused(new(&store, &task)), AttemptRefused::TooMany);
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(status(&store, &task).state, WorkState::Failed);
        assert_eq!(refused(new(&store, &task)), AttemptRefused::TooMany);
    }

    /// Attempts a hold withdrew don't count (design I.6.4): however many,
    /// the task still has its 8.
    #[test]
    fn attempts_withdrawn_by_a_hold_dont_count() {
        let (_dir, store) = store();
        let task = task(&store);
        for _ in 0..20 {
            let a = new(&store, &task).unwrap();
            end(&store, &task, &a, AttemptEnd::Withdrawn { counted: false });
        }
        assert_eq!(status(&store, &task).state, WorkState::Queued);
        for _ in 1..MAX_ATTEMPTS {
            let a = new(&store, &task).unwrap();
            end(&store, &task, &a, AttemptEnd::Withdrawn { counted: true });
        }
        assert_eq!(status(&store, &task).state, WorkState::Queued);
        let last = new(&store, &task).unwrap();
        assert_eq!(last.n, 20 + MAX_ATTEMPTS);
        end(
            &store,
            &task,
            &last,
            AttemptEnd::Withdrawn { counted: true },
        );
        assert_eq!(status(&store, &task).state, WorkState::Failed);
    }

    /// An attempt the session host answered `request_id_reused` (an id
    /// recorded under another submitter, R9.14 item 7) was never admitted:
    /// it ends `Reused`, isn't counted, and the next attempt takes a fresh
    /// id.
    #[test]
    fn request_id_reused_takes_a_fresh_id_not_counted() {
        let (_dir, store) = store();
        let task = task(&store);
        let end_of_reused = attempt_end(SessionAnswer::Refused(ErrorCode::RequestIdReused), false);
        assert_eq!(end_of_reused, Some(AttemptEnd::Reused));
        let mut seen = Vec::new();
        for _ in 0..(2 * MAX_ATTEMPTS) {
            let a = new(&store, &task).unwrap();
            assert!(!seen.contains(&a.attempt_id));
            seen.push(a.attempt_id.clone());
            end(&store, &task, &a, end_of_reused.unwrap());
            assert!(!store.may_submit(&task, &a.attempt_id).unwrap());
        }
        assert_eq!(status(&store, &task).state, WorkState::Queued);
        assert!(new(&store, &task).is_ok());
    }

    /// Every answer of the session host an attempt can get, and the end it
    /// gives the attempt (or none: it is still live, or the answer proves
    /// nothing). Halted, listed and withdrawn attempts never run, so they
    /// end; `held` keeps a withdrawal uncounted.
    #[test]
    fn session_answers_map_to_attempt_ends() {
        use crate::runtime::delegated::details::{WITHDRAWN_AT_RECOVERY, WITHDRAWN_BY_THE_HOST};
        use AttemptEnd::*;
        let w = |counted| Some(Withdrawn { counted });
        let (written, revoked) = (
            HostInterrupt::Written(vec![]),
            HostInterrupt::Revoked(vec![]),
        );
        for held in [false, true] {
            let withdrawn = w(!held);
            let cases: Vec<(SessionAnswer, Option<AttemptEnd>)> = vec![
                (
                    SessionAnswer::Refused(ErrorCode::RequestIdReused),
                    Some(Reused),
                ),
                (SessionAnswer::Refused(ErrorCode::Busy), Some(NotAdmitted)),
                (
                    SessionAnswer::Refused(ErrorCode::LeaseHeld),
                    Some(NotAdmitted),
                ),
                (
                    SessionAnswer::Refused(ErrorCode::InvalidRequest),
                    Some(NotAdmitted),
                ),
                (
                    SessionAnswer::Refused(ErrorCode::SessionClosed),
                    Some(NotAdmitted),
                ),
                (SessionAnswer::Receipt(ReceiptState::Accepted, None), None),
                (
                    SessionAnswer::Receipt(ReceiptState::Executing, None),
                    Some(Started),
                ),
                (
                    SessionAnswer::Receipt(ReceiptState::Completed, Some("done")),
                    Some(Started),
                ),
                (
                    SessionAnswer::Receipt(ReceiptState::OutcomeUnknown, None),
                    Some(Started),
                ),
                (
                    SessionAnswer::Receipt(ReceiptState::Rejected, Some("session closed")),
                    Some(Rejected),
                ),
                (
                    SessionAnswer::Receipt(ReceiptState::Rejected, None),
                    Some(Rejected),
                ),
                (
                    SessionAnswer::Receipt(ReceiptState::Rejected, Some(WITHDRAWN_BY_THE_HOST)),
                    withdrawn,
                ),
                (
                    SessionAnswer::Receipt(ReceiptState::Rejected, Some(WITHDRAWN_AT_RECOVERY)),
                    w(true),
                ),
                (SessionAnswer::Withdrawal(Withdrawal::Rejected), withdrawn),
                (SessionAnswer::Withdrawal(Withdrawal::Listed), withdrawn),
                (SessionAnswer::Withdrawal(Withdrawal::ListFull), withdrawn),
                (SessionAnswer::Withdrawal(Withdrawal::Halted), withdrawn),
                (SessionAnswer::Withdrawal(Withdrawal::Reused), Some(Reused)),
                (
                    SessionAnswer::Withdrawal(Withdrawal::Started),
                    Some(Started),
                ),
                (SessionAnswer::Interrupt(&written), Some(Started)),
                (SessionAnswer::Interrupt(&revoked), Some(Started)),
                (
                    SessionAnswer::Interrupt(&HostInterrupt::NotCurrentTurn),
                    None,
                ),
                (SessionAnswer::Interrupt(&HostInterrupt::NotExecuting), None),
                (SessionAnswer::Interrupt(&HostInterrupt::Halted), None),
            ];
            for (answer, expected) in cases {
                let label = format!("{answer:?}, held {held}");
                assert_eq!(attempt_end(answer, held), expected, "{label}");
            }
        }
    }

    /// Task 14's obligation (design I.6.4): an ended attempt is never
    /// submitted again under its id, whatever ended it, after a restart
    /// too, and after the host's identity changed (its store is moved
    /// aside: nothing of it is submitted again). An end is final.
    #[test]
    fn an_ended_attempt_is_never_submittable_again() {
        let (dir, store) = store();
        let ends = [
            AttemptEnd::NotAdmitted,
            AttemptEnd::Withdrawn { counted: true },
            AttemptEnd::Withdrawn { counted: false },
            AttemptEnd::Rejected,
            AttemptEnd::Started,
            AttemptEnd::Reused,
        ];
        let withdrawals = [
            Withdrawal::Rejected,
            Withdrawal::Listed,
            Withdrawal::ListFull,
            Withdrawal::Reused,
            Withdrawal::Started,
            Withdrawal::Halted,
        ];
        let mut ended = Vec::new();
        let answered = withdrawals
            .into_iter()
            .map(|w| attempt_end(SessionAnswer::Withdrawal(w), false).expect("ends it"));
        for e in ends.into_iter().chain(answered) {
            let task = task(&store);
            let a = new(&store, &task).unwrap();
            assert!(store.may_submit(&task, &a.attempt_id).unwrap(), "live");
            end(&store, &task, &a, e);
            assert!(!store.may_submit(&task, &a.attempt_id).unwrap(), "{e:?}");
            assert_ne!(
                store.live_attempt(&task).unwrap().map(|l| l.attempt_id),
                Some(a.attempt_id.clone())
            );
            // The same end again is no change; another is refused.
            end(&store, &task, &a, e);
            let other = if e == AttemptEnd::Started {
                AttemptEnd::Rejected
            } else {
                AttemptEnd::Started
            };
            let tx = store.immediate().unwrap();
            assert!(store.end_attempt(&tx, &task, &a.attempt_id, other).is_err());
            drop(tx);
            ended.push((task, a));
        }
        // Not an attempt of that task, or none at all: never submittable.
        let (task, a) = &ended[0];
        assert!(!store.may_submit(&ended[1].0, &a.attempt_id).unwrap());
        assert!(!store.may_submit(task, &uuid()).unwrap());
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        for (task, a) in &ended {
            assert!(
                !store.may_submit(task, &a.attempt_id).unwrap(),
                "after a restart"
            );
        }
        // A new identity moves the store aside: the new one has none of it.
        store.retire(1).unwrap();
        let store = Store::open(dir.path()).unwrap();
        for (task, a) in &ended {
            assert!(
                !store.may_submit(task, &a.attempt_id).unwrap(),
                "after a rebind"
            );
            assert_eq!(store.live_attempt(task).unwrap(), None);
            assert!(store.work(task).unwrap().is_none());
        }
    }
}

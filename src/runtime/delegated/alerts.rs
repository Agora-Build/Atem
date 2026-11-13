//! Owner alerts and the capacity limits on unknown outcomes (feature
//! `host.alerts`; design I.4.6, host-work-v1 §11.3 and §11.6 "Unknown
//! outcomes", "Capacity").
//!
//! An alert is the host's record that a delegated sender's task became
//! `outcome_unknown` and nobody has resolved it: one per such task, in
//! `host-work.sqlite` (`alerts`; its sequence number from `alert_seq`).
//! - **Raised** when the task becomes `outcome_unknown`, in the
//!   transaction that writes that state ([`Store::save_work`] calls
//!   [`Store::track_alert`]), so it is durable before anything shows it
//!   (`alert_list`, and its push hints). A task reaches
//!   `outcome_unknown` once: no task gets a second alert. A v1 task
//!   (`local`, a browser grant, a service no feed covers) never gets one.
//! - **Kept past the deadline.** A delegated task of unknown outcome doesn't
//!   expire: at its deadline it stops holding its session and keeps its
//!   alert, its reason the one it was raised with (`Store::settle_due`).
//! - **Ended** when its task is resolved (`work_resolve`, or the host's own
//!   command: [`crate::runtime::delegated::resolve::resolve`] calls
//!   [`Store::end_alert`] in its transaction) or a reply moves it to
//!   `awaiting_result`; any other write that takes the task out of
//!   `outcome_unknown` ends it too, in the same transaction. An ended alert
//!   is kept (its row and sequence number), never listed again.
//! - **Listed** for native members holding `control` (`alert_list`,
//!   [`Store::alert_page`]) in the host's order, by `seq`.
//! - **Counted** ([`Store::unresolved`]) for the limits: at [`NOTE_AT`]
//!   unresolved on the host a new alert's reason says so; at
//!   [`PER_SENDER`] from one sender, or [`PER_HOST`] on the host, a remote
//!   sender's request that would make a new task is refused `busy`, `too
//!   many unresolved outcomes` ([`Store::over_capacity`]); `local` never is.
//! - **Hinted** (session-v1 R9.9, `host.alerts` only): an alert raised in
//!   this run of the store is handed to the push hints once its row is
//!   committed, and one that ended stops its hints
//!   ([`Store::alert_changes`], read by the bridge's pass only after a
//!   raise or an end, [`HintWatch`]).
use crate::runtime::delegated::details;
use crate::runtime::host_work::{Store, WorkRecord};
use crate::session_protocol::membership::host_now;
use crate::session_protocol::r9::HostWorkError;
use anyhow::{Result, bail};
use atem_client::session::alerts::{
    Alert, AlertKind, MAX_PAGE, MAX_REASON_BYTES, page, valid_reason,
};
use atem_client::session::host_work::WorkState;
use rusqlite::{Connection, OptionalExtension, params};
use std::cell::Cell;
use std::collections::BTreeMap;

/// At this many unresolved outcomes on the host, a new alert's reason says
/// how many there are (design I.4.6: "the alert says so").
pub const NOTE_AT: u32 = 32;
/// At this many unresolved outcomes from one sender, its requests that
/// would make a new task are refused.
pub const PER_SENDER: u32 = 64;
/// At this many unresolved outcomes on the host, every remote sender's
/// requests that would make a new task are refused.
pub const PER_HOST: u32 = 256;
/// The `detail` of `alert_list`'s `stale_target` for an `after` the host
/// has no alert for (host-work-v1 §11.3, "An unknown cursor").
pub use details::UNKNOWN_ALERT;

/// The alerts' tables, made when the store opens (additive: a database of
/// an earlier build gets them, empty).
pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE, task_id TEXT NOT NULL UNIQUE,
        session_id TEXT NOT NULL, sender TEXT NOT NULL, reason TEXT NOT NULL,
        created_ms INTEGER NOT NULL, ended_ms INTEGER);
    CREATE INDEX IF NOT EXISTS alerts_unresolved ON alerts(seq) WHERE ended_ms IS NULL;
    CREATE INDEX IF NOT EXISTS alerts_unresolved_sender ON alerts(sender)
        WHERE ended_ms IS NULL;
    CREATE TABLE IF NOT EXISTS alert_seq (id INTEGER PRIMARY KEY CHECK (id = 1),
        seq INTEGER NOT NULL);";

/// The unresolved outcomes on the host.
const COUNT_UNRESOLVED: &str = "SELECT count(*) FROM alerts WHERE ended_ms IS NULL";
/// The unresolved outcomes per sender.
const UNRESOLVED_BY_SENDER: &str =
    "SELECT sender,count(*) FROM alerts WHERE ended_ms IS NULL GROUP BY sender";
/// The unresolved alerts, in the host's order.
const UNRESOLVED_ALERTS: &str = "SELECT alert_id,seq,session_id,task_id,sender,reason,created_ms
    FROM alerts WHERE ended_ms IS NULL ORDER BY seq";

/// The unresolved alerts raised after a `seq`, in the host's order (the
/// partial index `alerts_unresolved`).
const UNRESOLVED_AFTER: &str = "SELECT alert_id,seq,session_id,task_id,sender,reason,created_ms
    FROM alerts WHERE ended_ms IS NULL AND seq > ?1 ORDER BY seq";
/// Whether an alert is still unresolved (its primary key).
const STILL_UNRESOLVED: &str =
    "SELECT EXISTS(SELECT 1 FROM alerts WHERE alert_id=?1 AND ended_ms IS NULL)";

/// What the alerts' push hints (session-v1 R9.9) still have to
/// look at, in memory for one run of the store: an alert raised in it is
/// handed to the hints once its row is committed (durable before
/// visible), and one that ended stops its hints. Alerts raised before the
/// store opened get no hint: a broker restart ends the resends, as it ends
/// the approvals' (R9.9), and `alert_list` still lists them. Nothing is
/// read while nothing was raised or ended, so an idle pass costs no query.
#[derive(Debug, Default)]
pub struct HintWatch {
    /// An alert was raised or ended since the last look (perhaps in a
    /// transaction that rolled back: the look reads committed rows only).
    changed: Cell<bool>,
    /// Alerts up to this `seq` were looked at: the counter when the store
    /// opened, then at each look.
    through: Cell<u64>,
}

impl HintWatch {
    /// The watch of a store just opened: alerts raised from now on.
    pub(crate) fn open(db: &Connection) -> Result<Self> {
        let through: Option<u64> = db
            .query_row("SELECT seq FROM alert_seq WHERE id=1", [], |r| r.get(0))
            .optional()?;
        Ok(Self {
            changed: Cell::new(false),
            through: Cell::new(through.unwrap_or(0)),
        })
    }
}

/// What changed for the alerts' push hints since the last look.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AlertChanges {
    /// Alerts raised since, still unresolved, in the host's order.
    pub raised: Vec<Alert>,
    /// Of the alerts whose hints are tracked, those no longer unresolved.
    pub ended: Vec<String>,
}

/// Why [`Store::alert_page`] gives no page.
#[derive(Debug)]
pub enum PageRefused {
    /// An `after` the host has no unresolved alert for (it ended, or never
    /// was): `stale_target`, [`UNKNOWN_ALERT`].
    StaleCursor,
    /// A limit outside `1..=MAX_PAGE` (the host's own fault: the request
    /// has no limit): `invalid_request`.
    InvalidLimit,
    /// The store couldn't be read: `busy`.
    Store,
}

impl PageRefused {
    /// The error `alert_list` answers it with (host-work-v1 §7, §11.3).
    pub fn error(&self) -> HostWorkError {
        match self {
            PageRefused::StaleCursor => HostWorkError {
                code: "stale_target",
                detail: Some(UNKNOWN_ALERT),
            },
            PageRefused::InvalidLimit => "invalid_request".into(),
            PageRefused::Store => "busy".into(),
        }
    }
}

impl Store {
    /// The alert of the delegated task `task`, which just became
    /// `outcome_unknown` (host-work-v1 §11.3), written in `tx`: the
    /// transaction that writes the task's state (durable before anything
    /// shows it). Its reason is `reason` (the task's detail: `agent
    /// exited`, `write interrupted`, …), or `outcome could not be
    /// established` for one no reader would take; at [`NOTE_AT`] unresolved
    /// on the host, this one counted, it says how many there are, within
    /// the reason's 256 bytes ([`reason_with_note`]). Its `seq` is the
    /// host's next (`alert_seq`, never reused), its `created_at` the host's
    /// wall clock, its `host_id` the store's own host (none before the
    /// store is bound, which no task is). The caller raises one per task
    /// ([`Store::track_alert`]); a second for a task is refused by the
    /// table (`task_id` is unique).
    pub fn raise_alert(&self, tx: &Connection, task: &WorkRecord, reason: &str) -> Result<Alert> {
        let unresolved: u32 = tx.query_row(COUNT_UNRESOLVED, [], |r| r.get(0))?;
        let seq: u64 = tx.query_row(
            "INSERT INTO alert_seq(id,seq) VALUES(1,1)
            ON CONFLICT(id) DO UPDATE SET seq=seq+1 RETURNING seq",
            [],
            |r| r.get(0),
        )?;
        let alert = Alert {
            alert_id: uuid::Uuid::new_v4().to_string(),
            seq,
            kind: AlertKind::OutcomeUnknown,
            host_id: self.bound()?.map(|h| h.atem_device_id).unwrap_or_default(),
            session_id: task.task.target.session_id.clone(),
            task_id: task.task.task_id.clone(),
            sender: task.principal.clone(),
            reason: reason_with_note(reason, unresolved.saturating_add(1)),
            created_at: host_now().wall_ms,
        };
        // Every field as the reader takes it (the host's own id aside, which
        // the store keeps apart): admission checked each of them, so this
        // never fails a write in practice.
        let checked = Alert {
            host_id: "host".into(),
            ..alert.clone()
        };
        if !checked.valid() {
            bail!("task {}: no valid alert for it", task.task.task_id);
        }
        self.hints.changed.set(true);
        tx.execute(
            "INSERT INTO alerts(alert_id,seq,task_id,session_id,sender,reason,created_ms)
            VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                alert.alert_id,
                alert.seq,
                alert.task_id,
                alert.session_id,
                alert.sender,
                alert.reason,
                alert.created_at
            ],
        )?;
        Ok(alert)
    }

    /// Ends the unresolved alert of `task_id`, if it has one, in `tx` (the
    /// transaction that resolves the task or moves it on): it is no longer
    /// listed or counted, and its row stays. Whether one ended.
    pub fn end_alert(&self, tx: &Connection, task_id: &str) -> Result<bool> {
        let ended = tx.execute(
            "UPDATE alerts SET ended_ms=?2 WHERE task_id=?1 AND ended_ms IS NULL",
            params![task_id, host_now().wall_ms],
        )? == 1;
        if ended {
            self.hints.changed.set(true);
        }
        Ok(ended)
    }

    /// What the alerts' push hints have to know since the last look
    /// ([`HintWatch`]): the alerts raised since, still unresolved, and which
    /// of `tracked` (the alerts whose hints wait for the relay) ended.
    /// Nothing is read unless an alert was raised or ended since. Committed
    /// rows only: a raise in a transaction that rolled back shows nothing.
    /// After a failed read the next look tries again.
    pub fn alert_changes(&self, tracked: &[String]) -> Result<AlertChanges> {
        if !self.hints.changed.get() {
            return Ok(AlertChanges::default());
        }
        let host_id = self.bound()?.map(|h| h.atem_device_id).unwrap_or_default();
        let counter: u64 = self
            .db
            .query_row("SELECT seq FROM alert_seq WHERE id=1", [], |r| r.get(0))
            .optional()?
            .unwrap_or(0);
        let mut q = self.db.prepare(UNRESOLVED_AFTER)?;
        let raised = q
            .query_map([self.hints.through.get()], |r| {
                Ok(Alert {
                    alert_id: r.get(0)?,
                    seq: r.get(1)?,
                    kind: AlertKind::OutcomeUnknown,
                    host_id: host_id.clone(),
                    session_id: r.get(2)?,
                    task_id: r.get(3)?,
                    sender: r.get(4)?,
                    reason: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut ended = Vec::new();
        for id in tracked {
            let live: bool = self.db.query_row(STILL_UNRESOLVED, [id], |r| r.get(0))?;
            if !live {
                ended.push(id.clone());
            }
        }
        let through = raised
            .iter()
            .map(|a| a.seq)
            .fold(counter.max(self.hints.through.get()), u64::max);
        self.hints.through.set(through);
        self.hints.changed.set(false);
        Ok(AlertChanges { raised, ended })
    }

    /// Keeps the alert of the task `record` in step with the record being
    /// written, in `db`'s transaction ([`Store::save_work`]'s): a delegated
    /// task `outcome_unknown` and not resolved has one (raised the first
    /// time, never again: a task reaches `outcome_unknown` once); any other
    /// state, or a resolution, ends it. A v1 task has none.
    pub(crate) fn track_alert(&self, db: &Connection, record: &WorkRecord) -> Result<()> {
        if record.delegated.is_none() {
            return Ok(());
        }
        let id = &record.task.task_id;
        if record.status.state != WorkState::OutcomeUnknown || record.status.resolved.is_some() {
            self.end_alert(db, id)?;
            return Ok(());
        }
        let raised: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM alerts WHERE task_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if !raised {
            self.raise_alert(db, record, &record.status.detail)?;
        }
        Ok(())
    }

    /// `alert_list`'s page (host-work-v1 §11.3): the unresolved alerts
    /// after `after`, at most `limit` in the host's order (by `seq`, never
    /// `created_at`), and whether more follow, as the shared core's
    /// reference ([`atem_client::session::alerts::page`]) makes it. Read
    /// only. Refused: an `after` the host has no unresolved alert for
    /// ([`PageRefused::StaleCursor`]), and a `limit` outside
    /// `1..=MAX_PAGE`.
    pub fn alert_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Alert>, bool), PageRefused> {
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(PageRefused::InvalidLimit);
        }
        let alerts = self.unresolved_alerts().map_err(|_| PageRefused::Store)?;
        page(&alerts, after, limit).ok_or(PageRefused::StaleCursor)
    }

    /// The unresolved alerts, in the host's order.
    pub(crate) fn unresolved_alerts(&self) -> Result<Vec<Alert>> {
        let host_id = self.bound()?.map(|h| h.atem_device_id).unwrap_or_default();
        let mut q = self.db.prepare(UNRESOLVED_ALERTS)?;
        let alerts = q
            .query_map([], |r| {
                Ok(Alert {
                    alert_id: r.get(0)?,
                    seq: r.get(1)?,
                    kind: AlertKind::OutcomeUnknown,
                    host_id: host_id.clone(),
                    session_id: r.get(2)?,
                    task_id: r.get(3)?,
                    sender: r.get(4)?,
                    reason: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(alerts)
    }

    /// The unresolved outcomes (one per unresolved alert): on the host, and
    /// per sender (only senders with some).
    pub fn unresolved(&self) -> Result<(u32, BTreeMap<String, u32>)> {
        let mut q = self.db.prepare(UNRESOLVED_BY_SENDER)?;
        let by_sender: BTreeMap<String, u32> = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok((by_sender.values().sum(), by_sender))
    }

    /// Whether a remote sender's request that would make a new task is
    /// refused for unresolved outcomes (design I.4.6, host-work-v1 §11.6
    /// "Capacity"): [`PER_SENDER`] of `sender`'s own, or [`PER_HOST`] on
    /// the host. `local` is never asked.
    pub fn over_capacity(&self, sender: &str) -> Result<bool> {
        let (host, by_sender) = self.unresolved()?;
        Ok(host >= PER_HOST || by_sender.get(sender).is_some_and(|n| *n >= PER_SENDER))
    }
}

/// An alert's reason (host-work-v1 §11.3): `reason` when a reader takes it
/// (1-256 bytes, no control or Cf character, not blank), else `outcome
/// could not be established`; with `unresolved` at [`NOTE_AT`] or more,
/// followed by `; <unresolved> outcomes unresolved on this host` (§11.3's
/// example), the reason cut at a character boundary so the whole stays
/// within 256 bytes.
pub fn reason_with_note(reason: &str, unresolved: u32) -> String {
    let base = if valid_reason(reason) && !reason.trim().is_empty() {
        reason
    } else {
        details::OUTCOME_NOT_ESTABLISHED
    };
    if unresolved < NOTE_AT {
        return base.to_owned();
    }
    let note = format!(
        "; {unresolved} {}",
        details::OUTCOMES_UNRESOLVED_ON_THIS_HOST
    );
    let mut end = MAX_REASON_BYTES.saturating_sub(note.len()).min(base.len());
    while !base.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{note}", &base[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::delegated::{Admission, DelegatedSender};
    use atem_client::session::host_work::{WorkStatus, WorkTask, digest};
    use atem_client::session::wire::Target;

    /// A delegated task of `sender` (a native member's or a service's),
    /// queued.
    fn record(sender: &str) -> WorkRecord {
        let task_id = uuid::Uuid::new_v4().to_string();
        let device_id = sender.split_once(':').unwrap().1.to_string();
        WorkRecord {
            principal: sender.into(),
            attachment_owner: String::new(),
            control_gen: 1,
            route_id: "r".into(),
            route_revision: 1,
            profile_id: "p".into(),
            profile_revision: 1,
            project: "local:project".into(),
            digest: digest(b"task"),
            task: WorkTask {
                attachments: vec![],
                task_id: task_id.clone(),
                workflow_id: uuid::Uuid::new_v4().to_string(),
                target: Target {
                    account_id: "acct".into(),
                    atem_device_id: "host".into(),
                    host_trust_gen: 1,
                    session_id: "ses-aaaaaaaaaaaa".into(),
                    process_gen: uuid::Uuid::new_v4().to_string(),
                },
                expires_at: u64::MAX >> 12,
                prompt: "build it".into(),
                context: vec![],
            },
            status: WorkStatus {
                task_id,
                receipt_id: uuid::Uuid::new_v4().to_string(),
                state: WorkState::Queued,
                detail: String::new(),
                result: None,
                resolved: None,
            },
            turn_id: None,
            authorization_expires_at: None,
            message: None,
            deadline_passed: false,
            delegated: Some(Admission {
                principal: sender.into(),
                principal_key: "ab".repeat(32),
                sender: DelegatedSender::Native { device_id },
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

    /// `sender`'s delegated task, enqueued and then written
    /// `outcome_unknown` with `detail`, as the lifecycle writes it: its id.
    fn unknown(store: &Store, sender: &str, detail: &str) -> String {
        let mut r = record(sender);
        assert!(store.enqueue(&r).unwrap());
        r.status.state = WorkState::OutcomeUnknown;
        r.status.detail = detail.into();
        store.save_work(&r).unwrap();
        r.task.task_id
    }

    /// The reason of `task`'s alert.
    fn reason_of(store: &Store, task: &str) -> String {
        store
            .db
            .query_row("SELECT reason FROM alerts WHERE task_id=?1", [task], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// Design I.4.6 ("At 32 unresolved on a host, the alert says so"),
    /// host-work-v1 §11.3: from the 32nd unresolved outcome on the host, a
    /// new alert's reason says how many there are, as §11.3's example does
    /// (`agent exited; 32 outcomes unresolved on this host`), within its
    /// 256 bytes: a long reason is cut, at a character boundary, so the
    /// note fits. Before the 32nd, and once resolutions bring the count
    /// under it again, the reason is the task's detail alone. A detail no
    /// reader would take (a control character, blank, too long) is no
    /// reason: the alert says `outcome could not be established`.
    #[test]
    fn thirty_two_unresolved_says_so_in_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let first: Vec<String> = (0..31)
            .map(|_| unknown(&store, "member:dev-phone", details::AGENT_EXITED))
            .collect();
        for task in &first {
            assert_eq!(reason_of(&store, task), details::AGENT_EXITED);
        }
        // The 32nd, from another sender: the count is the host's.
        let at = unknown(&store, "service:svc-bot", details::WRITE_INTERRUPTED);
        assert_eq!(
            reason_of(&store, &at),
            "write interrupted; 32 outcomes unresolved on this host"
        );
        let next = unknown(&store, "member:dev-phone", details::AGENT_EXITED);
        assert_eq!(
            reason_of(&store, &next),
            "agent exited; 33 outcomes unresolved on this host"
        );
        // A reason of the full 256 bytes is cut at a character boundary
        // (`é` is two bytes) so the note fits.
        let long = unknown(&store, "member:dev-phone", &"é".repeat(128));
        let reason = reason_of(&store, &long);
        let note = "; 34 outcomes unresolved on this host";
        assert!(reason.ends_with(note), "{reason}");
        assert!(reason.len() <= MAX_REASON_BYTES, "{}", reason.len());
        assert_eq!(reason.len(), 2 * 109 + note.len());
        assert!(reason.starts_with('é') && valid_reason(&reason));
        // A detail that is no reason.
        for (n, detail) in ["agent\nexited", "   ", &"x".repeat(257)]
            .iter()
            .enumerate()
        {
            let task = unknown(&store, "member:dev-phone", detail);
            assert_eq!(
                reason_of(&store, &task),
                format!(
                    "outcome could not be established; {} outcomes unresolved on this host",
                    35 + n
                )
            );
        }
        // Resolutions bring the count under 32: no note.
        for task in &first[..10] {
            assert!(store.end_alert(&store.db, task).unwrap());
        }
        assert_eq!(store.unresolved().unwrap().0, 27);
        let under = unknown(&store, "member:dev-phone", details::AGENT_EXITED);
        assert_eq!(reason_of(&store, &under), details::AGENT_EXITED);
        // Every reason is one the reader takes.
        let mut q = store.db.prepare("SELECT reason FROM alerts").unwrap();
        let reasons: Vec<String> = q
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(reasons.len(), 38);
        assert!(reasons.iter().all(|r| valid_reason(r)), "{reasons:?}");
    }

    /// Durable before visible (host-work-v1 §11.6; the plan's constraints):
    /// an alert is written in the transaction that makes its task
    /// `outcome_unknown`, and ended in the one that moves it on, so a
    /// failure of either leaves the task as it was. A task saved again in
    /// the same state keeps its one alert, and only a delegated task has
    /// one. The queries the passes and `alert_list` make read the
    /// unresolved alerts through their own indexes, never the ended ones,
    /// which are kept for good.
    #[test]
    fn an_alert_is_written_with_its_tasks_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let count = |store: &Store| -> u32 {
            store
                .db
                .query_row("SELECT count(*) FROM alerts", [], |r| r.get(0))
                .unwrap()
        };
        // The alert can't be written: nor is the state.
        store
            .db
            .execute_batch(
                "CREATE TRIGGER no_alerts BEFORE INSERT ON alerts BEGIN
                    SELECT RAISE(ABORT, 'no alerts'); END;",
            )
            .unwrap();
        let mut r = record("member:dev-phone");
        assert!(store.enqueue(&r).unwrap());
        r.status.state = WorkState::OutcomeUnknown;
        r.status.detail = details::AGENT_EXITED.into();
        assert!(store.save_work(&r).is_err());
        let stored = store.work(&r.task.task_id).unwrap().unwrap();
        assert_eq!(stored.status.state, WorkState::Queued);
        store.db.execute_batch("DROP TRIGGER no_alerts").unwrap();
        store.save_work(&r).unwrap();
        assert_eq!(count(&store), 1);
        // Saved again (a pass that rewrites it): the same one alert.
        store.save_work(&r).unwrap();
        assert_eq!(count(&store), 1);
        assert_eq!(store.unresolved().unwrap().0, 1);
        // Its end can't be written: the task stays `outcome_unknown`.
        store
            .db
            .execute_batch(
                "CREATE TRIGGER no_end BEFORE UPDATE ON alerts BEGIN
                    SELECT RAISE(ABORT, 'no end'); END;",
            )
            .unwrap();
        let mut moved = r.clone();
        moved.status.state = WorkState::AwaitingResult;
        assert!(store.save_work(&moved).is_err());
        assert_eq!(
            store.work(&r.task.task_id).unwrap().unwrap().status.state,
            WorkState::OutcomeUnknown
        );
        store.db.execute_batch("DROP TRIGGER no_end").unwrap();
        store.save_work(&moved).unwrap();
        assert_eq!(store.unresolved().unwrap(), (0, BTreeMap::new()));
        assert_eq!(count(&store), 1, "an ended alert is kept");
        // Back in `outcome_unknown` (never, in the lifecycle): no second
        // alert for the task.
        store.save_work(&r).unwrap();
        assert_eq!(count(&store), 1);
        // A v1 task of unknown outcome has none.
        let mut v1 = record("member:dev-phone");
        v1.delegated = None;
        assert!(store.enqueue(&v1).unwrap());
        v1.status.state = WorkState::OutcomeUnknown;
        store.save_work(&v1).unwrap();
        assert_eq!(count(&store), 1);
        // The queries read the unresolved alerts by their partial indexes.
        for (sql, index) in [
            (COUNT_UNRESOLVED, "alerts_unresolved"),
            (UNRESOLVED_BY_SENDER, "alerts_unresolved_sender"),
            (UNRESOLVED_ALERTS, "alerts_unresolved"),
        ] {
            let mut q = store
                .db
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let steps: Vec<String> = q
                .query_map([], |r| r.get(3))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(steps.iter().all(|s| s.contains(index)), "{sql}: {steps:?}");
        }
        let mut q = store
            .db
            .prepare("EXPLAIN QUERY PLAN SELECT 1 FROM alerts WHERE task_id=?1")
            .unwrap();
        let steps: Vec<String> = q
            .query_map(["x"], |r| r.get(3))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(steps.iter().all(|s| s.starts_with("SEARCH")), "{steps:?}");
    }
}

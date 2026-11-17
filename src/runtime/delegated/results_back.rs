//! Results back between hosts, their store (the delegated host-work design
//! II.4.4; host-work-v1 §11.5, "On the receiving host" and "On the sending
//! host"), behind the debug-only hook's `host.senders`: its tables are made
//! only then ([`prepare`]), with the mailbox's.
//!
//! - **On the receiving host: a result owed** (`mail_result_owed`). A
//!   trigger on `results` marks a host sender's task's reply owed in the
//!   statement that makes it `submitted` (`atem message reply`, or its
//!   context's publication), whoever writes it: the mark commits with the
//!   reply. The bridge seals `{"kind":"result","task_id","reply"}` to the
//!   sender, enqueues it in the put engine (until stored) and records it
//!   sent (`mail_result_sent`), in one transaction ([`result_sent`]), or
//!   clears the mark when the sender can't receive one ([`clear_result`]).
//!   One result per task: a task with one sent is never owed again.
//! - **On the sending host: what came back** (`remote_tasks`), per message,
//!   host and recipient: the resolution B's first status recorded (each
//!   task with its receipt, or `no_match`, `stored` or `refused` with no
//!   task), each task's state as the newest status says (a status applies
//!   only when made after the one recorded, [`apply_status`]; a resolution
//!   never changes), and a task's reply once its result came
//!   ([`record_reply`]: once, its delivery `due`, or `kept` with why). A
//!   reply `due` is delivered by the bridge into the session that sent the
//!   message (`queued`, with the delivery task's id) or kept with why.
//!   Each status and result is judged first (`accept_result_among`, in the
//!   bridge) against [`candidates`]: the rows a result from that host may
//!   answer.
use super::remote_send;
use crate::runtime::host_work::Store;
use anyhow::Result;
use atem_client::host_mail::{ExpectedResult, HostRef};
use atem_client::session::host_work::{
    ContextKind, ContextSnapshot, MAX_LIFETIME_MS, ResultReply, WorkState, digest,
};
use atem_client::session::messages::{Delivery, RecipientReceipt, WorkProgress};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// A reply kept, never delivered: the route that sent the message takes no
/// results (collaboration §10: shown by `atem message status`, never
/// prompted).
pub const NO_RESULTS: &str = "reply kept, not delivered: the sending route doesn't take results";
/// A reply kept: its return grant ran out (the message's expiry) first.
pub const GRANT_EXPIRED: &str = "reply kept, not delivered: its return grant expired";
/// A reply kept: its task ended at the host that ran it.
pub const TASK_ENDED: &str = "reply kept, not delivered: its task ended";
/// A reply kept: no current project lists both hosts (design II.4.4).
pub const NOT_GRANTED: &str = "result not delivered: sender no longer granted";

/// The tables and the trigger (made by [`prepare`], only with
/// `host.senders`). Additive, as every host-work table.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS mail_result_owed (task_id TEXT PRIMARY KEY) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mail_result_sent (
        task_id TEXT PRIMARY KEY, outbox_n INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TRIGGER IF NOT EXISTS mail_result_inserted AFTER INSERT ON results
    WHEN NEW.state='submitted' BEGIN
        INSERT OR IGNORE INTO mail_result_owed(task_id)
        SELECT NEW.task_id FROM work WHERE id=NEW.task_id AND CASE WHEN json_valid(record)
            THEN json_extract(record, '$.principal') GLOB 'host:*' ELSE 0 END
            AND NOT EXISTS(SELECT 1 FROM mail_result_sent WHERE task_id=NEW.task_id);
    END;
    CREATE TABLE IF NOT EXISTS remote_tasks (
        message_id TEXT NOT NULL, host_id TEXT NOT NULL, recipient_id TEXT NOT NULL,
        task_id TEXT NOT NULL, receipt_id TEXT NOT NULL, state TEXT NOT NULL,
        detail TEXT NOT NULL, result TEXT, at_ms INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        reply TEXT, reply_at INTEGER, delivery TEXT, delivery_detail TEXT, work_id TEXT,
        PRIMARY KEY(message_id, host_id, recipient_id, task_id));
    CREATE INDEX IF NOT EXISTS remote_tasks_delivery ON remote_tasks(delivery)
        WHERE delivery IN ('due', 'queued');
    CREATE INDEX IF NOT EXISTS remote_tasks_work ON remote_tasks(work_id)
        WHERE work_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS remote_tasks_replies ON remote_tasks(expires_at)
        WHERE reply IS NOT NULL;
    CREATE INDEX IF NOT EXISTS remote_deliveries_host
        ON remote_deliveries(host_id, host_trust_gen, created_ms);
    CREATE TRIGGER IF NOT EXISTS mail_result_submitted AFTER UPDATE OF state ON results
    WHEN NEW.state='submitted' AND OLD.state IS NOT 'submitted' BEGIN
        INSERT OR IGNORE INTO mail_result_owed(task_id)
        SELECT NEW.task_id FROM work WHERE id=NEW.task_id AND CASE WHEN json_valid(record)
            THEN json_extract(record, '$.principal') GLOB 'host:*' ELSE 0 END
            AND NOT EXISTS(SELECT 1 FROM mail_result_sent WHERE task_id=NEW.task_id);
    END;";

/// The tables in `store`, made if missing.
pub fn prepare(store: &Store) -> Result<()> {
    store.db.execute_batch(TABLES)?;
    Ok(())
}

/// The tasks whose result is owed, at most `limit`.
pub fn owed_results(db: &Connection, limit: usize) -> Result<Vec<String>> {
    let mut q = db.prepare("SELECT task_id FROM mail_result_owed LIMIT ?1")?;
    let rows = q.query_map([limit as i64], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// No result of `task_id` is owed any more: none can go (its sender can't
/// receive one, or the reply isn't submitted); the owner still reads it.
pub fn clear_result(tx: &Transaction, task_id: &str) -> Result<()> {
    tx.execute("DELETE FROM mail_result_owed WHERE task_id=?1", [task_id])?;
    Ok(())
}

/// The result of `task_id` enqueued as the engine's row `n`, in the
/// transaction that enqueued it: never owed again.
pub fn result_sent(tx: &Transaction, task_id: &str, n: i64) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO mail_result_sent(task_id, outbox_n) VALUES(?1, ?2)",
        params![task_id, n],
    )?;
    clear_result(tx, task_id)
}

/// One of this host's rows a result from a host may answer (design II.4.4):
/// a request's delivery row to it at its generation, sealed and put (or
/// about to be), with what the row expects back.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub message_id: String,
    pub host_id: String,
    pub recipient_id: String,
    /// The message's expiry: its return grant's.
    pub expires_at: u64,
    /// A status recorded its resolution.
    pub resolved: bool,
    pub expected: ExpectedResult,
}

/// The request rows to `sender` (its host at its generation) made since
/// `since_ms` that were sealed (a row refused before it was sealed never
/// reached it), each with what it expects back: the tasks of the recorded
/// resolution, and its cancel and complete envelopes.
pub fn candidates(db: &Connection, sender: &HostRef, since_ms: u64) -> Result<Vec<Candidate>> {
    let mut q = db.prepare(
        "SELECT d.message_id, d.recipient_id, o.expires_at FROM remote_deliveries d
        JOIN mail_outbox o ON o.n=d.outbox_n
        WHERE d.kind='request' AND d.host_id=?1 AND d.host_trust_gen=?2 AND d.created_ms>=?3
        ORDER BY d.created_ms",
    )?;
    let rows: Vec<(String, String, u64)> = q
        .query_map(
            params![sender.host_id, sender.host_trust_gen, since_ms],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?
        .collect::<rusqlite::Result<_>>()?;
    let mut tasks = db.prepare(
        "SELECT task_id FROM remote_tasks WHERE message_id=?1 AND host_id=?2 ORDER BY rowid",
    )?;
    let mut stops = db.prepare(
        "SELECT object_id FROM remote_deliveries WHERE message_id=?1 AND host_id=?2
        AND kind IN ('cancel', 'complete')",
    )?;
    rows.into_iter()
        .map(|(message_id, recipient_id, expires_at)| {
            let recorded: Vec<String> = tasks
                .query_map([&message_id, &sender.host_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let cancel_complete_ids = stops
                .query_map([&message_id, &sender.host_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(Candidate {
                expected: ExpectedResult {
                    recipient: sender.clone(),
                    message_id: message_id.clone(),
                    cancel_complete_ids,
                    task_ids: recorded.iter().filter(|t| !t.is_empty()).cloned().collect(),
                },
                resolved: !recorded.is_empty(),
                message_id,
                host_id: sender.host_id.clone(),
                recipient_id,
                expires_at,
            })
        })
        .collect()
}

/// How far back a result's row may have been made: a message lives at
/// most 24 h, and a result made at its end 24 h more.
pub const CANDIDATES_SINCE_MS: u64 = 2 * MAX_LIFETIME_MS;

/// The results the mailbox kept for this host's check, oldest first, at
/// most `limit`: `(object_hash, bytes)` (`mailbox_store`'s seam).
pub fn kept(db: &Connection, limit: usize) -> Result<Vec<(String, Vec<u8>)>> {
    let mut q = db.prepare(
        "SELECT object_hash, bytes FROM mailbox_results ORDER BY at_ms, position LIMIT ?1",
    )?;
    let rows = q.query_map([limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The kept result `object_hash` judged: gone, in the transaction that
/// applied it.
pub fn judged(tx: &Transaction, object_hash: &str) -> Result<()> {
    tx.execute(
        "DELETE FROM mailbox_results WHERE object_hash=?1",
        [object_hash],
    )?;
    Ok(())
}

fn state_name(state: WorkState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// A status of `c`'s host, made at `at`, naming `recipients`: applied when
/// made after the one recorded for the message and host (statuses arrive
/// in any order). The first records the resolution of `c`'s recipient
/// (each task, or its `no_match`, `stored` or `refused` with no task) and
/// moves the row: `refused` with the code for a refused recipient, else
/// `accepted`. A later one updates the recorded tasks only: a resolution
/// never changes. Whether it applied.
pub fn apply_status(
    tx: &Transaction,
    c: &Candidate,
    recipients: &[RecipientReceipt],
    at: u64,
) -> Result<bool> {
    let recorded: Option<u64> = tx.query_row(
        "SELECT max(at_ms) FROM remote_tasks WHERE message_id=?1 AND host_id=?2",
        [&c.message_id, &c.host_id],
        |r| r.get(0),
    )?;
    if recorded.is_some_and(|recorded| at <= recorded) {
        return Ok(false);
    }
    let Some(receipt) = recipients.iter().find(|r| r.recipient_id == c.recipient_id) else {
        return Ok(false);
    };
    let tasks: Vec<&WorkProgress> = match &receipt.delivery {
        Delivery::Work { work } => vec![work],
        Delivery::Resolved { tasks } => tasks.iter().collect(),
        _ => vec![],
    };
    let first = recorded.is_none();
    if first {
        let (state, detail) = match &receipt.delivery {
            Delivery::Stored {} => ("stored", String::new()),
            Delivery::NoMatch {} => ("no_match", String::new()),
            Delivery::Refused { code } => ("refused", code.clone()),
            _ => ("", String::new()),
        };
        if !state.is_empty() {
            insert(tx, c, "", "", state, &detail, None, at)?;
        }
        for task in &tasks {
            insert(
                tx,
                c,
                &task.task_id,
                &task.receipt_id,
                &state_name(task.state),
                &task.detail,
                task.result.as_ref(),
                at,
            )?;
        }
        match &receipt.delivery {
            Delivery::Refused { code } => {
                remote_send::refused_by_receiver(tx, &c.message_id, &c.host_id, code)?
            }
            _ => remote_send::accepted(tx, &c.message_id, &c.host_id)?,
        };
    } else {
        for task in &tasks {
            tx.execute(
                "UPDATE remote_tasks SET state=?4, detail=?5, result=?6
                WHERE message_id=?1 AND host_id=?2 AND task_id=?3 AND task_id!=''",
                params![
                    c.message_id,
                    c.host_id,
                    task.task_id,
                    state_name(task.state),
                    task.detail,
                    task.result
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?
                ],
            )?;
        }
    }
    tx.execute(
        "UPDATE remote_tasks SET at_ms=?3 WHERE message_id=?1 AND host_id=?2",
        params![c.message_id, c.host_id, at],
    )?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn insert(
    tx: &Transaction,
    c: &Candidate,
    task_id: &str,
    receipt_id: &str,
    state: &str,
    detail: &str,
    result: Option<&atem_client::session::messages::ContextReference>,
    at: u64,
) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO remote_tasks(message_id, host_id, recipient_id, task_id,
            receipt_id, state, detail, result, at_ms, expires_at)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            c.message_id,
            c.host_id,
            c.recipient_id,
            task_id,
            receipt_id,
            state,
            detail,
            result.map(serde_json::to_string).transpose()?,
            at,
            c.expires_at
        ],
    )?;
    Ok(())
}

/// The object-level refusal of `object_id` by `c`'s host (the request, or
/// one of its cancel or complete envelopes): that row `refused` with the
/// code.
pub fn apply_refusal(tx: &Transaction, c: &Candidate, object_id: &str, code: &str) -> Result<()> {
    remote_send::refused_by_receiver(tx, object_id, &c.host_id, code)?;
    Ok(())
}

/// The reply to `c`'s task `task_id`, recorded once (another copy changes
/// nothing): `due` for delivery, or with `kept` never delivered, with why.
/// Whether it was recorded now.
pub fn record_reply(
    tx: &Transaction,
    c: &Candidate,
    task_id: &str,
    reply: &ResultReply,
    kept: Option<&str>,
    at: u64,
) -> Result<bool> {
    Ok(tx.execute(
        "UPDATE remote_tasks SET reply=?4, reply_at=?5, delivery=?6, delivery_detail=?7
        WHERE message_id=?1 AND host_id=?2 AND task_id=?3 AND reply IS NULL",
        params![
            c.message_id,
            c.host_id,
            task_id,
            serde_json::to_string(reply)?,
            at,
            if kept.is_some() { "kept" } else { "due" },
            kept
        ],
    )? == 1)
}

/// A remote task's reply waiting for its delivery, or delivered: its key,
/// the state B last said, the reply, the message's workflow and expiry.
#[derive(Debug, Clone)]
pub struct Delivering {
    pub message_id: String,
    pub host_id: String,
    pub recipient_id: String,
    pub task_id: String,
    pub state: String,
    /// Always read (a row whose reply doesn't read is never listed).
    pub reply: Option<ResultReply>,
    pub workflow_id: String,
    pub expires_at: u64,
    /// The delivery task, once queued.
    pub work_id: Option<String>,
}

const DELIVERING: &str = "SELECT t.message_id, t.host_id, t.recipient_id, t.task_id, t.state,
    t.reply, coalesce(json_extract(o.envelope, '$.workflow_id'), ''), t.expires_at, t.work_id
    FROM remote_tasks t LEFT JOIN outbox o ON o.message_id=t.message_id";

fn delivering(r: &rusqlite::Row<'_>) -> rusqlite::Result<(Delivering, String)> {
    let reply = r.get(5)?;
    Ok((
        Delivering {
            message_id: r.get(0)?,
            host_id: r.get(1)?,
            recipient_id: r.get(2)?,
            task_id: r.get(3)?,
            state: r.get(4)?,
            reply: None,
            workflow_id: r.get(6)?,
            expires_at: r.get(7)?,
            work_id: r.get(8)?,
        },
        reply,
    ))
}

/// Each row with its reply read (a row whose reply doesn't read is left
/// out: nothing can be delivered of it).
fn read_delivering(rows: Vec<(Delivering, String)>) -> Vec<Delivering> {
    rows.into_iter()
        .filter_map(|(d, reply)| {
            Some(Delivering {
                reply: Some(serde_json::from_str(&reply).ok()?),
                ..d
            })
        })
        .collect()
}

/// The replies due for delivery, at most `limit`.
pub fn due(db: &Connection, limit: usize) -> Result<Vec<Delivering>> {
    let mut q = db.prepare(&format!(
        "{DELIVERING} WHERE t.delivery='due' ORDER BY t.reply_at LIMIT ?1"
    ))?;
    let rows = q
        .query_map([limit as i64], delivering)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(read_delivering(rows))
}

/// The replies whose delivery task is queued and hasn't started.
pub fn queued(db: &Connection) -> Result<Vec<Delivering>> {
    let mut q = db.prepare(&format!(
        "{DELIVERING} JOIN work w ON w.id=t.work_id
        WHERE t.delivery='queued' AND w.state IN ('queued', 'blocked')"
    ))?;
    let rows = q
        .query_map([], delivering)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(read_delivering(rows))
}

/// `d`'s reply queued for delivery as the task `work_id`, in `tx`.
pub fn delivered(tx: &Transaction, d: &Delivering, work_id: &str) -> Result<()> {
    tx.execute(
        "UPDATE remote_tasks SET delivery='queued', delivery_detail=NULL, work_id=?5
        WHERE message_id=?1 AND host_id=?2 AND recipient_id=?3 AND task_id=?4",
        params![d.message_id, d.host_id, d.recipient_id, d.task_id, work_id],
    )?;
    Ok(())
}

/// `d`'s reply kept as data, never delivered, with why, in `tx`.
pub fn keep(tx: &Transaction, d: &Delivering, why: &str) -> Result<()> {
    tx.execute(
        "UPDATE remote_tasks SET delivery='kept', delivery_detail=?5
        WHERE message_id=?1 AND host_id=?2 AND recipient_id=?3 AND task_id=?4",
        params![d.message_id, d.host_id, d.recipient_id, d.task_id, why],
    )?;
    Ok(())
}

/// The remote reply the local task `work_id` delivers, if it delivers one:
/// its task's id at the host, the host, and the reply. None in a store
/// without these tables (`host.senders` never on).
pub fn delivery_of(
    db: &Connection,
    work_id: &str,
) -> Result<Option<(String, String, ResultReply)>> {
    let made: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='remote_tasks')",
        [],
        |r| r.get(0),
    )?;
    if !made {
        return Ok(None);
    }
    db.query_row(
        "SELECT task_id, host_id, reply FROM remote_tasks WHERE work_id=?1",
        [work_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, String>(2)?)),
    )
    .optional()?
    .map(|(task_id, host_id, reply)| Ok((task_id, host_id, serde_json::from_str(&reply)?)))
    .transpose()
}

/// Another host's reply as a delivery task's result: the reply, the task
/// it answers and the host that ran it.
pub fn snapshot(task_id: &str, host_id: &str, reply: &ResultReply) -> ContextSnapshot {
    let text = serde_json::json!({
        "result_id": reply.result_id,
        "task_id": task_id,
        "host": host_id,
        "text": reply.text,
        "context": reply.context,
    })
    .to_string();
    ContextSnapshot {
        kind: ContextKind::Result,
        id: format!("result:{}", reply.result_id),
        version: 1,
        digest: digest(text.as_bytes()),
        text,
    }
}

/// How long past its message's expiry another host's reply keeps its text
/// and context here (as a settled task's payload, a day).
const KEEP_REPLY_MS: u64 = 24 * 60 * 60 * 1000;

/// Replies whose message expired [`KEEP_REPLY_MS`] or more before `now_ms`
/// (the delegated clock's `D`) dropped to their ids and digest (the
/// mailbox's minute prune, never under a clock anchor); their rows stay.
pub fn prune_replies(db: &Connection, now_ms: u64) -> Result<usize> {
    Ok(db.execute(
        "UPDATE remote_tasks SET reply=json_set(reply, '$.text', '', '$.context', json('[]'),
            '$.dropped', json('true'))
        WHERE reply IS NOT NULL AND expires_at + ?2 <= ?1
            AND json_extract(reply, '$.dropped') = 0",
        params![now_ms, KEEP_REPLY_MS],
    )?)
}

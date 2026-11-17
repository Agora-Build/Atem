//! Admission of host senders' mail on the receiving host, its store (the
//! delegated host-work design II.4.2 step 7, II.4.4, II.7; host-work-v1
//! §11.5, "On the receiving host"), behind the debug-only hook's
//! `host.senders`: its tables are made only then ([`prepare`]), with the
//! mailbox's. The decisions themselves are the bridge's (`admit_pass.rs`);
//! here is what they keep.
//!
//! - **Early stops** (`mail_stops`, ruling R38): a `cancel` or `complete`
//!   opened before its request (a free between two pages can open a later
//!   object of a sender first) is kept, bound to its sender, its own object
//!   id and the task it names, until its object's expiry; at most
//!   [`MAX_EARLY_STOPS`] per sender (one more stays in the inbox,
//!   back-pressure as ruling R31's). Its request's admission takes it
//!   ([`take_stops`]) in its own transaction.
//! - **Whole refusals** (`mail_refusals`): a request admission refused as a
//!   whole (the sender, the message id, its digest and the code), kept for
//!   good beside the host-work message records, which are never deleted
//!   either: a resend is judged against both ([`refusal`]), never only
//!   against the mailbox's claims, which are pruned.
//! - **Status owed** (`mail_status_owed`): a host sender's message whose
//!   status is to go to it. A trigger on `work` marks it in the statement
//!   that changes the state of one of its tasks (a host sender's: its
//!   principal `host:…`), whoever writes it; the bridge seals the message's
//!   current status, enqueues it and clears the mark in one transaction
//!   ([`sent`], [`clear`]).
//! - **The latest status** (`mail_status_sent`): per message, the put
//!   engine's row of the status sent last. A newer one supersedes it while
//!   the Station hasn't stored it (the engine settles it: never put again):
//!   each status is its own object with its own id, and carries every
//!   task's current state.
use super::outbox;
use crate::runtime::host_work::{MessageRecord, Store};
use anyhow::{Result, anyhow};
use atem_client::host_mail::EnvelopePlain;
use atem_client::session::messages::{Delivery, RecipientReceipt, WorkProgress};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Early stops kept per sender host, at most (ruling R38).
pub const MAX_EARLY_STOPS: u64 = 32;

/// Admission's tables and the trigger that marks a status owed (made by
/// [`prepare`], only with `host.senders`). Additive, as every host-work
/// table.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS mail_stops (
        sender_host TEXT NOT NULL, object_id TEXT NOT NULL, task_id TEXT NOT NULL,
        kind TEXT NOT NULL, expires_at INTEGER NOT NULL, generation INTEGER NOT NULL,
        epoch INTEGER NOT NULL,
        PRIMARY KEY(sender_host, object_id)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS mail_stops_task ON mail_stops(sender_host, task_id);
    CREATE TABLE IF NOT EXISTS mail_refusals (
        sender_host TEXT NOT NULL, message_id TEXT NOT NULL, digest TEXT NOT NULL,
        code TEXT NOT NULL, at_ms INTEGER NOT NULL,
        PRIMARY KEY(sender_host, message_id)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mail_status_owed (message_id TEXT PRIMARY KEY) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mail_status_sent (
        message_id TEXT PRIMARY KEY, outbox_n INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TRIGGER IF NOT EXISTS mail_status_changed AFTER UPDATE OF state ON work
    WHEN NEW.state IS NOT OLD.state AND CASE WHEN json_valid(NEW.record)
        THEN json_extract(NEW.record, '$.principal') GLOB 'host:*'
            AND json_extract(NEW.record, '$.message.message_id') IS NOT NULL
        ELSE 0 END
    BEGIN
        INSERT OR IGNORE INTO mail_status_owed(message_id)
            VALUES(json_extract(NEW.record, '$.message.message_id'));
    END;";

/// Admission's tables in `store`, made if missing.
pub fn prepare(store: &Store) -> Result<()> {
    store.db.execute_batch(TABLES)?;
    Ok(())
}

/// One inbox row as admission reads it (`mailbox_store`'s seam).
#[derive(Debug, Clone)]
pub struct InboxRow {
    pub n: i64,
    pub sender_host: String,
    pub object_id: String,
    /// None when its bytes no longer read as a plaintext.
    pub plain: Option<EnvelopePlain>,
    /// Its object's expiry and `signed_at_head.seq`: 0 for a row written
    /// before the inbox kept them.
    pub expires_at: u64,
    pub signed_seq: u64,
    /// Held (ruling R47): a stop waiting for room among its sender's early
    /// stops.
    pub held: bool,
}

/// The inbox's first `limit` rows, in mailbox order.
pub fn inbox(db: &Connection, limit: usize) -> Result<Vec<InboxRow>> {
    let mut q = db.prepare(
        "SELECT n, sender_host, object_id, plain, coalesce(expires_at, 0),
            coalesce(signed_seq, 0), held FROM mailbox_inbox ORDER BY n LIMIT ?1",
    )?;
    let rows = q.query_map([limit as i64], |r| {
        Ok(InboxRow {
            n: r.get(0)?,
            sender_host: r.get(1)?,
            object_id: r.get(2)?,
            plain: EnvelopePlain::parse(&r.get::<_, Vec<u8>>(3)?).ok(),
            expires_at: r.get(4)?,
            signed_seq: r.get(5)?,
            held: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Inbox row `n` taken: decided. Whether it was still there.
pub fn take_row(tx: &Transaction, n: i64) -> Result<bool> {
    Ok(tx.execute("DELETE FROM mailbox_inbox WHERE n=?1", [n])? == 1)
}

/// Inbox row `n` held (ruling R47): a stop waiting for room, holding its
/// own sender's task starts only.
pub fn hold_row(tx: &Transaction, n: i64) -> Result<()> {
    tx.execute("UPDATE mailbox_inbox SET held=1 WHERE n=?1", [n])?;
    Ok(())
}

/// `row`, a `cancel` or `complete` (`kind`) of `task_id` opened before its
/// request, kept as an early stop until its expiry, bound to its sender's
/// authorization generation and membership epoch now (`standing`; review
/// L5: after a revoke and a readmit, or a removal and a re-add, it no
/// longer applies); false when its sender has [`MAX_EARLY_STOPS`] already
/// (it stays in the inbox).
pub fn keep_stop(
    tx: &Transaction,
    row: &InboxRow,
    task_id: &str,
    kind: &str,
    standing: (u64, u64),
) -> Result<bool> {
    let kept: u64 = tx.query_row(
        "SELECT count(*) FROM mail_stops WHERE sender_host=?1",
        [&row.sender_host],
        |r| r.get(0),
    )?;
    if kept >= MAX_EARLY_STOPS {
        return Ok(false);
    }
    tx.execute(
        "INSERT OR IGNORE INTO mail_stops(sender_host, object_id, task_id, kind, expires_at,
            generation, epoch) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.sender_host,
            row.object_id,
            task_id,
            kind,
            row.expires_at,
            standing.0,
            standing.1
        ],
    )?;
    Ok(true)
}

/// The early stops of `sender_host` naming `task_id`, taken: the kinds
/// (`cancel`, `complete`) of those kept at its `standing` now (generation,
/// epoch); the others are dropped.
pub fn take_stops(
    tx: &Transaction,
    sender_host: &str,
    task_id: &str,
    standing: (u64, u64),
) -> Result<Vec<String>> {
    let kinds: Vec<String> = {
        let mut q = tx.prepare(
            "SELECT kind FROM mail_stops WHERE sender_host=?1 AND task_id=?2
            AND generation=?3 AND epoch=?4",
        )?;
        q.query_map(params![sender_host, task_id, standing.0, standing.1], |r| {
            r.get(0)
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    tx.execute(
        "DELETE FROM mail_stops WHERE sender_host=?1 AND task_id=?2",
        [sender_host, task_id],
    )?;
    Ok(kinds)
}

/// Early stops whose object expired by `now_ms` (the delegated clock's
/// `D`) dropped: their request can no longer come.
pub fn prune_stops(db: &Connection, now_ms: u64) -> Result<usize> {
    Ok(db.execute("DELETE FROM mail_stops WHERE expires_at <= ?1", [now_ms])?)
}

/// The early stops kept now: `(sender host, task id, kind)` (tests).
#[cfg(test)]
pub fn stops(db: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut q = db.prepare(
        "SELECT sender_host, task_id, kind FROM mail_stops ORDER BY sender_host, task_id",
    )?;
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The recorded whole refusal of `sender_host`'s message `message_id`: its
/// digest and code.
pub fn refusal(
    db: &Connection,
    sender_host: &str,
    message_id: &str,
) -> Result<Option<(String, String)>> {
    Ok(db
        .query_row(
            "SELECT digest, code FROM mail_refusals WHERE sender_host=?1 AND message_id=?2",
            [sender_host, message_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

/// Records the whole refusal of `sender_host`'s message `message_id`
/// (`digest`) with `code`, for good.
pub fn refuse(
    tx: &Transaction,
    sender_host: &str,
    message_id: &str,
    digest: &str,
    code: &str,
    at_ms: u64,
) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO mail_refusals(sender_host, message_id, digest, code, at_ms)
        VALUES(?1, ?2, ?3, ?4, ?5)",
        params![sender_host, message_id, digest, code, at_ms],
    )?;
    Ok(())
}

/// The messages whose status is owed, at most `limit`.
pub fn owed(db: &Connection, limit: usize) -> Result<Vec<String>> {
    let mut q = db.prepare("SELECT message_id FROM mail_status_owed LIMIT ?1")?;
    let rows = q.query_map([limit as i64], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// No status of `message_id` is owed any more (none can go: its sender
/// can't receive one now; the record keeps the state).
pub fn clear(tx: &Transaction, message_id: &str) -> Result<()> {
    tx.execute(
        "DELETE FROM mail_status_owed WHERE message_id=?1",
        [message_id],
    )?;
    Ok(())
}

/// The status of `message_id` enqueued as the engine's row `n`, in the
/// transaction that enqueued it: the one before it superseded (settled,
/// never put, while the Station hasn't stored it), and none owed.
pub fn sent(tx: &Transaction, message_id: &str, n: i64) -> Result<()> {
    let before: Option<i64> = tx
        .query_row(
            "SELECT outbox_n FROM mail_status_sent WHERE message_id=?1",
            [message_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(before) = before.filter(|b| *b != n) {
        outbox::settle(tx, before)?;
    }
    tx.execute(
        "INSERT INTO mail_status_sent(message_id, outbox_n) VALUES(?1, ?2)
        ON CONFLICT(message_id) DO UPDATE SET outbox_n=excluded.outbox_n",
        params![message_id, n],
    )?;
    clear(tx, message_id)
}

/// `sender_host`'s resend of its request `message_id`, read as a duplicate
/// by the mailbox (ruling R45): the admitted message's status is owed
/// again, so one the Station lost goes again (superseding keeps one
/// waiting). Nothing for a message not admitted from that sender, or in a
/// store without admission's tables.
pub fn resend_status(tx: &Transaction, sender_host: &str, message_id: &str) -> Result<()> {
    let made: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='mail_status_owed')",
        [],
        |r| r.get(0),
    )?;
    if made {
        tx.execute(
            "INSERT OR IGNORE INTO mail_status_owed(message_id)
            SELECT id FROM messages WHERE id=?1
                AND json_extract(record, '$.message.sender')=?2",
            params![
                message_id,
                atem_client::host_principal::host_principal(sender_host)
            ],
        )?;
    }
    Ok(())
}

/// The refusals the mailbox marked for a status to their sender (`report`,
/// an authenticated object refused at II.4.2's checks 5 or 6): `(evidence,
/// sender host, object id)`, at most `limit`, oldest first.
pub fn reports(db: &Connection, limit: usize) -> Result<Vec<(String, String, String)>> {
    let mut q = db.prepare(
        "SELECT evidence, sender_host, object_id FROM mailbox_refused
        WHERE report=1 AND sender_host IS NOT NULL AND object_id IS NOT NULL
        ORDER BY n LIMIT ?1",
    )?;
    let rows = q.query_map([limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The refusal `evidence` reported (its status enqueued), in that
/// transaction: never reported again.
pub fn reported(tx: &Transaction, evidence: &str) -> Result<()> {
    tx.execute(
        "UPDATE mailbox_refused SET report=0 WHERE evidence=?1",
        [evidence],
    )?;
    Ok(())
}

/// The receipts of `record`'s recipients now (design II.4.4): each task's
/// current state, a resolution's tasks in their fixed order; the other
/// deliveries as recorded.
pub fn receipts(store: &Store, record: &MessageRecord) -> Result<Vec<RecipientReceipt>> {
    let progress = |task_id: &str| -> Result<WorkProgress> {
        let task = store
            .work(task_id)?
            .ok_or_else(|| anyhow!("missing task {task_id} of a host sender's message"))?;
        Ok((&task.status).into())
    };
    record
        .receipt
        .recipients
        .iter()
        .map(|r| {
            let delivery = match &r.delivery {
                Delivery::Work { work } => Delivery::Work {
                    work: progress(&work.task_id)?,
                },
                Delivery::Resolved { tasks } => Delivery::Resolved {
                    tasks: tasks
                        .iter()
                        .map(|t| progress(&t.task_id))
                        .collect::<Result<_>>()?,
                },
                other => other.clone(),
            };
            Ok(RecipientReceipt {
                recipient_id: r.recipient_id.clone(),
                delivery,
            })
        })
        .collect()
}

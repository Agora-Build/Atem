//! Admission of host senders' mail on the receiving host, its store (the
//! delegated host-work design II.4.2 step 7, II.4.4, II.7; host-work-v1
//! §11.5, "On the receiving host"), behind the debug-only hook's
//! `host.senders`: its tables are made only then ([`prepare`]), with the
//! mailbox's. The decisions themselves are the bridge's (`admit_pass.rs`);
//! here is what they keep.
//!
//! - **Whole refusals** (`mail_refusals`): a request admission refused as a
//!   whole (the sender, the message id, its digest and the code), kept for
//!   good beside the host-work message records, which are never deleted
//!   either: a resend is judged against both ([`refusal`]), never only
//!   against the mailbox's claims, which are pruned.
//! - **The latest status** (`mail_status_sent`): per message, the put
//!   engine's row of the status sent last.
use crate::runtime::host_work::{MessageRecord, Store};
use anyhow::{Result, anyhow};
use atem_client::host_mail::EnvelopePlain;
use atem_client::session::messages::{Delivery, RecipientReceipt, WorkProgress};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Admission's tables (made by [`prepare`], only with `host.senders`).
/// Additive, as every host-work table.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS mail_refusals (
        sender_host TEXT NOT NULL, message_id TEXT NOT NULL, digest TEXT NOT NULL,
        code TEXT NOT NULL, at_ms INTEGER NOT NULL,
        PRIMARY KEY(sender_host, message_id)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mail_status_sent (
        message_id TEXT PRIMARY KEY, outbox_n INTEGER NOT NULL) WITHOUT ROWID;";

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
    #[allow(dead_code)]
    pub expires_at: u64,
    pub signed_seq: u64,
}

/// The inbox's first `limit` rows, in mailbox order.
pub fn inbox(db: &Connection, limit: usize) -> Result<Vec<InboxRow>> {
    let mut q = db.prepare(
        "SELECT n, sender_host, object_id, plain, coalesce(expires_at, 0),
            coalesce(signed_seq, 0) FROM mailbox_inbox ORDER BY n LIMIT ?1",
    )?;
    let rows = q.query_map([limit as i64], |r| {
        Ok(InboxRow {
            n: r.get(0)?,
            sender_host: r.get(1)?,
            object_id: r.get(2)?,
            plain: EnvelopePlain::parse(&r.get::<_, Vec<u8>>(3)?).ok(),
            expires_at: r.get(4)?,
            signed_seq: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Inbox row `n` taken: decided. Whether it was still there.
pub fn take_row(tx: &Transaction, n: i64) -> Result<bool> {
    Ok(tx.execute("DELETE FROM mailbox_inbox WHERE n=?1", [n])? == 1)
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

/// The status of `message_id` enqueued as the engine's row `n`, in the
/// transaction that enqueued it.
pub fn sent(tx: &Transaction, message_id: &str, n: i64) -> Result<()> {
    tx.execute(
        "INSERT INTO mail_status_sent(message_id, outbox_n) VALUES(?1, ?2)
        ON CONFLICT(message_id) DO UPDATE SET outbox_n=excluded.outbox_n",
        params![message_id, n],
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

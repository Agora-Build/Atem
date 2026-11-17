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
use crate::runtime::host_work::Store;
use anyhow::Result;
use rusqlite::{Connection, Transaction, params};

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

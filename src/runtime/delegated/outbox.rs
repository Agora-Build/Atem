//! The sending host's put engine (host-work-v1 §11.5, "The mailbox calls",
//! rules 3 and 8; the delegated host-work design II.4.3, II.4.4), behind
//! the debug-only hook's `host.senders`: every object this host puts into
//! another host's mailbox on its Station, whatever made it. A row is one
//! object to put: its target host, its exact sealed bytes, its state, and
//! when it is put again. Its users are the remote delivery rows (envelopes:
//! `remote_send.rs`) and, later, the receiving host's status objects and
//! results back; each enqueues already sealed bytes in its own
//! transaction ([`enqueue`]), so an object is durable with whatever
//! decided it, before any put.
//!
//! - **Two policies, differing only in when a put is repeated.**
//!   [`Policy::Repeat`] (an envelope: a request, `cancel` or `complete`):
//!   the same bytes again every [`RESEND_MS`] until its owner settles it
//!   ([`settle`]: accepted), it is refused, or it expires; a mailbox that
//!   lost it (a reset, a done object's resend) gets it again and
//!   deduplicates it. [`Policy::UntilStored`] (a status or a result): put
//!   until the Station answers `mailbox_stored`, never after.
//! - **Answers** (rule 3). `mailbox_stored`: a repeat row is `stored`, put
//!   again in 10 minutes; an until-stored row is `done`. `quota`: put
//!   again after a backoff ([`quota_backoff_ms`]), the object kept.
//!   `id_reused`, `expired`, `forbidden`: `refused` with the code, final.
//!   A put with no answer goes again with a fresh id (`puts.rs`).
//! - **Expiry.** A row not settled by its object's `expires_at` (at most 24
//!   h after its `created_at`) is `expired` and put no more.
//! - **Time.** The schedule and expiry are on the delegated clock's `D`
//!   (durable across a restart); the 35 s retirement of a live put is on
//!   the pass's monotonic clock.
//! - **Bounded.** A final row's bytes are dropped a day after its object's
//!   expiry ([`prune`]); the row stays.
use crate::runtime::host_work::Store;
use anyhow::{Result, anyhow, bail};
use atem_client::host_mail::mailbox::PutRefusal;
use atem_client::host_mail::{HostRef, MailBody, object_hash, parse_object};
use rusqlite::{OptionalExtension, Transaction, params};

/// A repeat row is put again this long after the Station stored it.
pub const RESEND_MS: u64 = 10 * 60 * 1000;
/// A final row's bytes are kept this long after its object's expiry.
const KEEP_BYTES_MS: u64 = 24 * 60 * 60 * 1000;

/// When a row is put again (the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Every 10 minutes until settled, refused or expired: envelopes.
    Repeat,
    /// Until stored: status objects and results.
    UntilStored,
}

impl Policy {
    fn as_str(self) -> &'static str {
        match self {
            Policy::Repeat => "repeat",
            Policy::UntilStored => "until_stored",
        }
    }
}

/// The engine's table and index, made by [`prepare`] (only with
/// `host.senders`). `state`: `queued` (never stored), `stored` (a repeat
/// row the Station stored), `done` (settled, or an until-stored row
/// stored), `refused` (with its `code`), `expired`.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS mail_outbox (
        n INTEGER PRIMARY KEY, object_id TEXT NOT NULL, kind TEXT NOT NULL,
        sender_host TEXT NOT NULL, sender_gen INTEGER NOT NULL,
        target_host TEXT NOT NULL, target_gen INTEGER NOT NULL,
        policy TEXT NOT NULL, bytes BLOB NOT NULL, object_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL, state TEXT NOT NULL, code TEXT,
        next_put_ms INTEGER NOT NULL, puts INTEGER NOT NULL DEFAULT 0,
        quota INTEGER NOT NULL DEFAULT 0, UNIQUE(target_host, object_id));
    CREATE INDEX IF NOT EXISTS mail_outbox_due ON mail_outbox(next_put_ms)
        WHERE state IN ('queued','stored');";

/// The engine's table in `store`, made if missing.
pub fn prepare(store: &Store) -> Result<()> {
    store.db.execute_batch(TABLES)?;
    Ok(())
}

/// Puts `bytes` (one sealed object, already made) to `target` under
/// `policy`, in the caller's transaction `tx`: durable with whatever
/// decided it, put only once `tx` commits. Its sender, id and expiry are
/// the object's own; `target` must be its recipient. The same object again
/// is the same row; other bytes under its key `(target, id)` are refused.
pub fn enqueue(tx: &Transaction, bytes: &[u8], target: &HostRef, policy: Policy) -> Result<i64> {
    let object = parse_object(bytes).map_err(|e| anyhow!("not a mailbox object ({e})"))?;
    let (kind, body) = MailBody::from_object(&object)?;
    if body.recipient != *target {
        bail!("the object's recipient isn't {}", target.host_id);
    }
    let hash = object_hash(&object).to_hex();
    let found: Option<(i64, String)> = tx
        .query_row(
            "SELECT n, object_hash FROM mail_outbox WHERE target_host=?1 AND object_id=?2",
            params![target.host_id, body.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((n, existing)) = found {
        return if existing == hash {
            Ok(n)
        } else {
            Err(anyhow!("id_reused"))
        };
    }
    tx.execute(
        "INSERT INTO mail_outbox(object_id, kind, sender_host, sender_gen, target_host,
            target_gen, policy, bytes, object_hash, expires_at, state, next_put_ms)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'queued', 0)",
        params![
            body.id,
            kind.body_type(),
            body.sender.host_id,
            body.sender.host_trust_gen,
            target.host_id,
            target.host_trust_gen,
            policy.as_str(),
            bytes,
            hash,
            body.expires_at
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// A row due for a put: its number and its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    pub n: i64,
    pub bytes: Vec<u8>,
}

/// The rows of `sender` due for a put at `now_ms` (`D`), oldest first, at
/// most `limit`, none of `live` (being put now).
pub fn due(
    store: &Store,
    sender: &HostRef,
    now_ms: u64,
    live: &[i64],
    limit: usize,
) -> Result<Vec<Due>> {
    let mut q = store.db.prepare(
        "SELECT n, bytes FROM mail_outbox WHERE state IN ('queued','stored')
        AND next_put_ms <= ?1 AND expires_at > ?1 AND sender_host=?2 AND sender_gen=?3
        ORDER BY next_put_ms, n",
    )?;
    let rows = q.query_map(
        params![now_ms, sender.host_id, sender.host_trust_gen],
        |r| {
            Ok(Due {
                n: r.get(0)?,
                bytes: r.get(1)?,
            })
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        let row = row?;
        if live.contains(&row.n) {
            continue;
        }
        out.push(row);
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

/// `mailbox_stored` for row `n` at `now_ms`: a repeat row `stored`, put
/// again in [`RESEND_MS`]; an until-stored row `done`. A row settled,
/// refused or expired meanwhile stays so.
pub fn stored(store: &Store, n: i64, now_ms: u64) -> Result<()> {
    store.db.execute(
        "UPDATE mail_outbox SET puts=puts+1, quota=0,
            state=CASE policy WHEN 'repeat' THEN 'stored' ELSE 'done' END,
            next_put_ms=?2
        WHERE n=?1 AND state IN ('queued','stored')",
        params![n, now_ms.saturating_add(RESEND_MS)],
    )?;
    Ok(())
}

/// How long after its `count`th `quota` in a row a row is put again: 30 s,
/// doubling, at most [`RESEND_MS`].
pub fn quota_backoff_ms(count: u32) -> u64 {
    (30_000u64 << count.min(5)).min(RESEND_MS)
}

/// `mailbox_put_refused` of row `n` at `now_ms`: `quota` puts it again
/// after the backoff; any other code refuses it for good, with the code.
pub fn refused(store: &Store, n: i64, code: PutRefusal, now_ms: u64) -> Result<()> {
    if code == PutRefusal::Quota {
        let count: Option<u32> = store
            .db
            .query_row("SELECT quota FROM mail_outbox WHERE n=?1", [n], |r| {
                r.get(0)
            })
            .optional()?;
        store.db.execute(
            "UPDATE mail_outbox SET quota=quota+1, next_put_ms=?2
            WHERE n=?1 AND state IN ('queued','stored')",
            params![
                n,
                now_ms.saturating_add(quota_backoff_ms(count.unwrap_or(0)))
            ],
        )?;
    } else {
        store.db.execute(
            "UPDATE mail_outbox SET state='refused', code=?2
            WHERE n=?1 AND state IN ('queued','stored')",
            params![n, code.code()],
        )?;
    }
    Ok(())
}

/// The owner settles row `n` in its own transaction (a repeat row's
/// delivery accepted): put no more.
pub fn settle(tx: &Transaction, n: i64) -> Result<()> {
    tx.execute(
        "UPDATE mail_outbox SET state='done' WHERE n=?1 AND state IN ('queued','stored')",
        [n],
    )?;
    Ok(())
}

/// Rows whose object expired by `now_ms` without being settled: `expired`.
pub fn expire(store: &Store, now_ms: u64) -> Result<usize> {
    Ok(store.db.execute(
        "UPDATE mail_outbox SET state='expired'
        WHERE state IN ('queued','stored') AND expires_at <= ?1",
        [now_ms],
    )?)
}

/// A final row's bytes dropped a day after its object's expiry.
pub fn prune(store: &Store, now_ms: u64) -> Result<usize> {
    Ok(store.db.execute(
        "UPDATE mail_outbox SET bytes=x''
        WHERE state IN ('done','refused','expired') AND length(bytes) > 0
            AND expires_at <= ?1",
        [now_ms.saturating_sub(KEEP_BYTES_MS)],
    )?)
}

/// A row as `atem message status` reads it: its state, code, puts and
/// quota refusals in a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowState {
    pub state: String,
    pub code: Option<String>,
    pub puts: u64,
    pub quota: u32,
}

pub fn row_state(db: &rusqlite::Connection, n: i64) -> Result<Option<RowState>> {
    Ok(db
        .query_row(
            "SELECT state, code, puts, quota FROM mail_outbox WHERE n=?1",
            [n],
            |r| {
                Ok(RowState {
                    state: r.get(0)?,
                    code: r.get(1)?,
                    puts: r.get(2)?,
                    quota: r.get(3)?,
                })
            },
        )
        .optional()?)
}

#[cfg(test)]
#[path = "outbox_tests.rs"]
mod tests;

//! The sending host's delivery rows (the delegated host-work design
//! II.4.4, "Outbox and resends"; collaboration §7), behind the debug-only
//! hook's `host.senders`: one row per (envelope, target host), the first
//! user of the put engine ([`super::outbox`]).
//!
//! - **States:** `publishing` → `ready` → `sent` → `accepted` | `refused`
//!   | `expired`. A send with context has its rows `publishing` from the
//!   send on (committed with its stage-1 outbox row), until the context is
//!   published and frozen; a refused or expired publication takes them
//!   with it (a trigger on the stage-1 outbox row).
//! - **Sealing, once** ([`commit_request`]): the host-sender Message
//!   (stage 1's text and frozen context, sender `host:<this host>`, the
//!   planned hosts' `select` recipients) sealed per target host to its
//!   current `enc_key` in this host's committed device list, signed with
//!   this host's `host_channel_key`, `signed_at_head` the committed head;
//!   its exact bytes enqueued ([`outbox::enqueue`], [`Policy::Repeat`]) in
//!   the transaction that accepts the message, with the row `ready`. A
//!   target that can't be sealed to now (no longer a current host at its
//!   generation, no key) has its row `refused` with the reason; this host
//!   no longer signing refuses every row.
//! - **The engine moves the rows** (a trigger, in the engine's own
//!   statement), each state with its detail: a `ready` row stored is
//!   `sent`, refused is `refused` with the Station's code; a `sent` row
//!   stays `sent` when the Station refuses a later copy (the first was
//!   stored and may be running on the receiver), its code recorded, but a
//!   Station `expired` is its expiry; an expired object's row `expired`.
//! - **Acceptance** is the receiver's status naming its resolution, which
//!   the sending host reads with the results back (not built here):
//!   [`accepted`] is its seam, settling the engine row too.
use super::outbox::{self, Policy};
use super::send_plan::{Me, Plan, signs};
use crate::runtime::host_work::Store;
use crate::session_protocol::r9::HostKey;
use anyhow::{Result, bail};
use atem_client::host_mail::{EnvelopePlain, HostRef, MailFields};
use atem_client::host_principal::host_principal;
use atem_client::membership::Membership;
use atem_client::session::host_work::HostTarget;
use atem_client::session::messages::{Destination, Message, Recipient};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

/// The rows' table and the triggers that move them (made by [`prepare`],
/// only with `host.senders`).
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS remote_deliveries (
        object_id TEXT NOT NULL, host_id TEXT NOT NULL, host_trust_gen INTEGER NOT NULL,
        message_id TEXT NOT NULL, kind TEXT NOT NULL, recipient_id TEXT NOT NULL,
        task_id TEXT, outbox_n INTEGER, state TEXT NOT NULL, code TEXT,
        detail TEXT NOT NULL, created_ms INTEGER NOT NULL,
        PRIMARY KEY(object_id, host_id)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS remote_deliveries_message ON remote_deliveries(message_id);
    CREATE INDEX IF NOT EXISTS remote_deliveries_outbox ON remote_deliveries(outbox_n);
    CREATE TRIGGER IF NOT EXISTS remote_deliveries_put AFTER UPDATE ON mail_outbox
    WHEN NEW.state IS NOT OLD.state OR NEW.code IS NOT OLD.code BEGIN
        UPDATE remote_deliveries SET
            state=CASE
                WHEN NEW.state='expired' THEN 'expired'
                WHEN state='sent' AND NEW.state='refused' AND NEW.code='expired' THEN 'expired'
                WHEN state='ready' AND NEW.state='refused' THEN 'refused'
                WHEN state='ready' AND NEW.state IN ('stored', 'done') THEN 'sent'
                ELSE state END,
            code=NEW.code,
            detail=CASE
                WHEN NEW.state='expired'
                    OR state='sent' AND NEW.state='refused' AND NEW.code='expired'
                    THEN 'expired before it was accepted'
                WHEN state='ready' AND NEW.state='refused'
                    THEN 'the Station refused it (' || NEW.code || ')'
                WHEN (state='sent' OR NEW.state IN ('stored', 'done')) AND NEW.code IS NULL
                    THEN 'stored in the host''s mailbox; put again every 10 minutes until accepted'
                WHEN state='sent' OR NEW.state IN ('stored', 'done')
                    THEN 'stored in the host''s mailbox; the Station refused a later copy ('
                        || NEW.code || ')'
                WHEN NEW.code='quota'
                    THEN 'the Station''s quota is full; put again after a backoff'
                ELSE 'waiting to be put in the host''s mailbox' END
        WHERE outbox_n=NEW.n AND state IN ('ready', 'sent');
    END;
    CREATE TRIGGER IF NOT EXISTS remote_deliveries_publication AFTER UPDATE OF state ON outbox
    WHEN NEW.state IN ('refused', 'expired') BEGIN
        UPDATE remote_deliveries SET state=NEW.state, detail=NEW.detail
        WHERE message_id=NEW.message_id AND state='publishing';
    END;";

/// The put engine's tables and the rows', in `store`, made if missing.
pub fn prepare(store: &Store) -> Result<()> {
    outbox::prepare(store)?;
    store.db.execute_batch(TABLES)?;
    Ok(())
}

/// A send's part for other hosts, fixed at the send: whether a selector
/// can reach this host's agents too, and the host-sender Message's
/// `select` recipients (one per planned host).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePart {
    pub local: bool,
    pub recipients: Vec<Recipient>,
}

impl RemotePart {
    /// The part of `plan` (it plans other hosts) in `account`: a fresh
    /// recipient id per host.
    pub fn of(plan: &Plan, account: &str) -> RemotePart {
        RemotePart {
            local: plan.local.is_some(),
            recipients: plan
                .remote
                .iter()
                .map(|t| Recipient {
                    recipient_id: uuid::Uuid::new_v4().to_string(),
                    host: HostTarget {
                        account_id: account.to_owned(),
                        atem_device_id: t.host_id.clone(),
                        host_trust_gen: t.host_trust_gen,
                    },
                    destination: Destination::Select {
                        selectors: t.selectors.clone(),
                        budget: t.budget,
                        launch: t.launch,
                    },
                })
                .collect(),
        }
    }

    /// The host-sender Message of `local` (the stage-1 message: its ids,
    /// times, text and frozen context) from `sender_host`: one Message for
    /// every planned host (design II.4.2).
    pub fn message(&self, local: &Message, sender_host: &str) -> Message {
        Message {
            sender: host_principal(sender_host),
            reply_to: None,
            from_session: None,
            recipients: self.recipients.clone(),
            mark: None,
            ..local.clone()
        }
    }
}

/// A row's detail while its message's context publishes.
pub const PUBLISHING: &str = "waiting for verified context publication";

/// Rows of `part` for the message `message_id`, `publishing`, in the
/// transaction that reserves its context.
pub fn reserve(tx: &Transaction, message_id: &str, part: &RemotePart, now_ms: u64) -> Result<()> {
    for r in &part.recipients {
        upsert(
            tx,
            message_id,
            "request",
            message_id,
            r,
            None,
            None,
            "publishing",
            PUBLISHING,
            now_ms,
        )?;
    }
    Ok(())
}

/// What signs and seals: this host's committed device list, this host,
/// its account and its `host_channel_key`.
pub struct Sealer<'a> {
    pub list: &'a Membership,
    pub me: Me<'a>,
    pub account: &'a str,
    pub key: &'a HostKey,
}

/// The request envelopes of `local` (the accepted stage-1 message, its
/// context frozen) to `part`'s hosts, in the accepting transaction `tx`:
/// each sealed once, its bytes enqueued, its row `ready` (or `refused`,
/// with why). Refused whole as content (`invalid message content`) when
/// it isn't a Message a host sender may send.
pub fn commit_request(
    tx: &Transaction,
    sealer: &Sealer,
    local: &Message,
    part: &RemotePart,
) -> Result<()> {
    let message = part.message(local, sealer.me.host_id);
    if !message.valid_from_host(sealer.me.host_id) {
        bail!("invalid message content");
    }
    let plain = EnvelopePlain::Request { message };
    let signing = signs(sealer.list, sealer.me);
    for r in &part.recipients {
        let to = HostRef {
            host_id: r.host.atem_device_id.clone(),
            host_trust_gen: r.host.host_trust_gen,
        };
        // Sealed once: a row past `publishing` keeps its bytes.
        if sealed_before(tx, &local.message_id, &to.host_id)? {
            continue;
        }
        let sealed = signing.clone().and_then(|()| {
            seal(
                sealer,
                &to,
                &local.message_id,
                local.created_at,
                local.expires_at,
                &plain,
            )
        });
        let id = &local.message_id;
        match sealed {
            Ok(bytes) => {
                let n = outbox::enqueue(tx, &bytes, &to, Policy::Repeat)?;
                let detail = "waiting to be put in the host's mailbox";
                upsert(
                    tx,
                    id,
                    "request",
                    id,
                    r,
                    None,
                    Some(n),
                    "ready",
                    detail,
                    local.created_at,
                )?;
            }
            Err(why) => {
                upsert(
                    tx,
                    id,
                    "request",
                    id,
                    r,
                    None,
                    None,
                    "refused",
                    &why,
                    local.created_at,
                )?;
            }
        }
    }
    Ok(())
}

/// Whether the row of `object_id` to `host_id` is past `publishing`.
fn sealed_before(tx: &Transaction, object_id: &str, host_id: &str) -> Result<bool> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM remote_deliveries WHERE object_id=?1 AND host_id=?2
            AND state!='publishing')",
        params![object_id, host_id],
        |r| r.get(0),
    )?)
}

/// `plain` sealed to `to` (its current key in the committed list) as the
/// object `id`, signed at the committed head: its exact bytes.
pub fn seal(
    sealer: &Sealer,
    to: &HostRef,
    id: &str,
    created_at: u64,
    expires_at: u64,
    plain: &EnvelopePlain,
) -> std::result::Result<Vec<u8>, String> {
    let list = sealer.list;
    if list
        .host(&to.host_id)
        .is_none_or(|h| h.host_trust_gen != to.host_trust_gen)
    {
        return Err(format!(
            "host {} is no longer a current host at trust generation {}",
            to.host_id, to.host_trust_gen
        ));
    }
    let key = list.host_enc_key(&to.host_id).ok_or_else(|| {
        format!(
            "host {} has no encryption key in the device list now",
            to.host_id
        )
    })?;
    let fields = MailFields {
        account_id: sealer.account.to_owned(),
        genesis_hash: list.genesis_hash(),
        sender: HostRef {
            host_id: sealer.me.host_id.to_owned(),
            host_trust_gen: sealer.me.host_trust_gen,
        },
        recipient: to.clone(),
        enc_kid: atem_client::encoding::hex(&key.current.kid),
        id: id.to_owned(),
        created_at,
        expires_at,
        signed_at_head: list.head(),
    };
    let object = sealer
        .key
        .seal_envelope(&fields, plain, &key.current.key)
        .map_err(|e| format!("the envelope couldn't be sealed ({e})"))?;
    Ok(object.to_json().to_string().into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn upsert(
    tx: &Transaction,
    message_id: &str,
    kind: &str,
    object_id: &str,
    r: &Recipient,
    task_id: Option<&str>,
    outbox_n: Option<i64>,
    state: &str,
    detail: &str,
    now_ms: u64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO remote_deliveries(object_id, host_id, host_trust_gen, message_id, kind,
            recipient_id, task_id, outbox_n, state, detail, created_ms)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(object_id, host_id) DO UPDATE SET outbox_n=excluded.outbox_n,
            state=excluded.state, detail=excluded.detail",
        params![
            object_id,
            r.host.atem_device_id,
            r.host.host_trust_gen,
            message_id,
            kind,
            r.recipient_id,
            task_id,
            outbox_n,
            state,
            detail,
            now_ms
        ],
    )?;
    Ok(())
}

/// The receiver's status named the envelope `object_id`'s effect at
/// `host_id` (the results back feed it): the row `accepted`, its engine
/// row settled (put no more). Whether a `ready` or `sent` row moved.
#[cfg_attr(not(test), allow(dead_code))]
pub fn accepted(tx: &Transaction, object_id: &str, host_id: &str) -> Result<bool> {
    let n: Option<Option<i64>> = tx
        .query_row(
            "SELECT outbox_n FROM remote_deliveries WHERE object_id=?1 AND host_id=?2
            AND state IN ('ready', 'sent')",
            params![object_id, host_id],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    let Some(n) = n else {
        return Ok(false);
    };
    tx.execute(
        "UPDATE remote_deliveries SET state='accepted', detail='accepted by the host'
        WHERE object_id=?1 AND host_id=?2",
        params![object_id, host_id],
    )?;
    if let Some(n) = n {
        outbox::settle(tx, n)?;
    }
    Ok(true)
}

/// One delivery row, as `atem message status` will show it (not built yet).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct Row {
    pub host_id: String,
    pub kind: String,
    pub task_id: Option<String>,
    pub state: String,
    pub code: Option<String>,
    pub detail: String,
    /// Its engine row (none before it is sealed).
    pub outbox: Option<outbox::RowState>,
}

/// The rows of the message `message_id`, in the order they were made.
#[cfg_attr(not(test), allow(dead_code))]
pub fn rows(db: &rusqlite::Connection, message_id: &str) -> Result<Vec<Row>> {
    let mut q = db.prepare(
        "SELECT host_id, kind, task_id, state, code, detail, outbox_n FROM remote_deliveries
        WHERE message_id=?1 ORDER BY created_ms, kind DESC, host_id",
    )?;
    let rows = q
        .query_map([message_id], |r| {
            Ok((
                Row {
                    host_id: r.get(0)?,
                    kind: r.get(1)?,
                    task_id: r.get(2)?,
                    state: r.get(3)?,
                    code: r.get(4)?,
                    detail: r.get(5)?,
                    outbox: None,
                },
                r.get::<_, Option<i64>>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(mut row, n)| {
            row.outbox = n.map(|n| outbox::row_state(db, n)).transpose()?.flatten();
            Ok(row)
        })
        .collect()
}

#[cfg(test)]
#[path = "remote_send_tests.rs"]
mod tests;

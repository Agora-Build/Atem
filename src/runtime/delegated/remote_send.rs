//! The sending host's delivery rows (the delegated host-work design
//! II.4.4, "Outbox and resends"; collaboration §7), behind the debug-only
//! hook's `host.senders`: one row per (envelope, target host), the first
//! user of the put engine ([`super::outbox`]).
//!
//! - **States:** `publishing` → `ready` → `sent` → `accepted` | `refused`
//!   | `expired`; and `skipped`, a host a `project:` fan-out planned but
//!   can't send to (ruling R40), with why, never put. A send with context has its rows `publishing` from the
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
//!   the sending host reads with the results back (`results_back.rs`):
//!   [`accepted`] and [`refused_by_receiver`], each settling the engine row
//!   too.
//! - **Stops** (`atem message cancel` and `complete` of a task on another
//!   host, `remote_stops.rs`): a `cancel` or `complete` envelope's own row
//!   ([`stop_row`]), kind and task id with it, put by the same engine
//!   ([`Policy::Repeat`]) until a status shows its effect
//!   ([`status_shown`]: `accepted`), the host refuses it by its own id
//!   ([`refused_by_receiver`]), or it expires. A `complete` of a task not
//!   yet shown awaiting its result is `held` (its result frozen,
//!   `remote_held`), `due` once a status shows it, then sealed; `dropped`
//!   when the task ends otherwise, `expired` with its message; a `busy`
//!   answer holds it again under a fresh id ([`rehold`]; ruling R50).
use super::outbox::{self, Policy};
use super::send_plan::{Me, Plan, Skipped, signs};
use crate::runtime::host_work::Store;
use crate::session_protocol::r9::HostKey;
use anyhow::{Result, bail};
use atem_client::host_mail::{EnvelopePlain, HostRef, MailFields};
use atem_client::host_principal::host_principal;
use atem_client::membership::Membership;
use atem_client::session::host_work::HostTarget;
use atem_client::session::messages::{Destination, Message, Recipient};
use rusqlite::{OptionalExtension, Transaction, params};
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
                WHEN NEW.code='malformed' AND NEW.state='refused'
                    THEN 'its sealed bytes no longer read; not put'
                WHEN NEW.code='malformed'
                    THEN 'stored in the host''s mailbox; its sealed bytes no longer read, not put again'
                WHEN state='ready' AND NEW.state='refused'
                    THEN 'the Station refused it (' || NEW.code || ')'
                WHEN (state='sent' OR NEW.state IN ('stored', 'done')) AND NEW.code IS NULL
                    THEN 'stored in the host''s mailbox; put again every 10 minutes until accepted'
                WHEN state='sent' OR NEW.state IN ('stored', 'done')
                    THEN 'stored in the host''s mailbox; the Station refused a later copy ('
                        || NEW.code || ')'
                WHEN NEW.code='quota'
                    THEN 'the Station''s quota is full; put again after a backoff'
                WHEN NEW.code='forbidden'
                    THEN 'the Station refused it (forbidden); put again on a later link or once the device list moves'
                ELSE 'waiting to be put in the host''s mailbox' END
        WHERE outbox_n=NEW.n AND state IN ('ready', 'sent');
    END;
    CREATE INDEX IF NOT EXISTS remote_deliveries_held ON remote_deliveries(state)
        WHERE kind='complete' AND state IN ('held', 'due');
    CREATE TABLE IF NOT EXISTS remote_held (
        message_id TEXT NOT NULL, host_id TEXT NOT NULL, task_id TEXT NOT NULL,
        result TEXT NOT NULL, PRIMARY KEY(message_id, host_id, task_id)) WITHOUT ROWID;
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

/// A send's part for other hosts, fixed at the send: the host-sender
/// Message's `select` recipients (one per planned host), and the hosts a
/// fan-out skipped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePart {
    pub recipients: Vec<Recipient>,
    /// The hosts a `project:` fan-out skipped, and why (ruling R40): rows
    /// of their own, never put.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<Skipped>,
}

impl RemotePart {
    /// The part of `plan` (it plans other hosts) in `account`: a fresh
    /// recipient id per host.
    pub fn of(plan: &Plan, account: &str) -> RemotePart {
        RemotePart {
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
            skipped: plan.skipped.clone(),
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
    write_skipped(tx, message_id, part, now_ms)?;
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
    write_skipped(tx, &local.message_id, part, local.created_at)?;
    // A fan-out that skipped every host it planned seals nothing.
    if part.recipients.is_empty() {
        return Ok(());
    }
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

/// The rows of the hosts `part`'s fan-out skipped (ruling R40): `skipped`,
/// their reason as detail, never put (written once).
fn write_skipped(tx: &Transaction, message_id: &str, part: &RemotePart, now_ms: u64) -> Result<()> {
    for s in &part.skipped {
        tx.execute(
            "INSERT INTO remote_deliveries(object_id, host_id, host_trust_gen, message_id, kind,
                recipient_id, state, detail, created_ms)
            VALUES(?1, ?2, ?3, ?1, 'request', '', 'skipped', ?4, ?5)
            ON CONFLICT(object_id, host_id) DO NOTHING",
            params![message_id, s.host_id, s.host_trust_gen, s.reason, now_ms],
        )?;
    }
    Ok(())
}

/// The hosts the fan-out of `message_id` skipped, each `<host>: <why>`.
pub fn skipped(db: &rusqlite::Connection, message_id: &str) -> Result<Vec<String>> {
    let mut q = db.prepare(
        "SELECT host_id, detail FROM remote_deliveries WHERE message_id=?1 AND state='skipped'
        ORDER BY host_id",
    )?;
    let rows = q.query_map([message_id], |r| {
        Ok(format!(
            "{}: {}",
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The rows of `local` to `part`'s hosts not sealed yet, refused with
/// `why`, in the accepting transaction `tx` (nothing is sealed).
pub fn refuse_unsealed(
    tx: &Transaction,
    local: &Message,
    part: &RemotePart,
    why: &str,
) -> Result<()> {
    let id = &local.message_id;
    for r in &part.recipients {
        if !sealed_before(tx, id, &r.host.atem_device_id)? {
            upsert(
                tx,
                id,
                "request",
                id,
                r,
                None,
                None,
                "refused",
                why,
                local.created_at,
            )?;
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
pub fn accepted(tx: &Transaction, object_id: &str, host_id: &str) -> Result<bool> {
    settle_row(
        tx,
        object_id,
        host_id,
        "accepted",
        None,
        "accepted by the host",
    )
}

/// The receiver's status refused the envelope `object_id` at `host_id`
/// (`refused{code}`, or `invalid_request` for its checks 5 and 6; the
/// results back feed it): the row `refused` with `code`, its engine row
/// settled. Whether a `ready` or `sent` row moved.
pub fn refused_by_receiver(
    tx: &Transaction,
    object_id: &str,
    host_id: &str,
    code: &str,
) -> Result<bool> {
    let detail = format!("refused by the host ({code})");
    settle_row(tx, object_id, host_id, "refused", Some(code), &detail)
}

/// A `ready` or `sent` row's final state from the receiver, its engine
/// row settled (the row moves first: the engine's trigger then finds it
/// final and leaves it).
fn settle_row(
    tx: &Transaction,
    object_id: &str,
    host_id: &str,
    state: &str,
    code: Option<&str>,
    detail: &str,
) -> Result<bool> {
    let n: Option<Option<i64>> = tx
        .query_row(
            "SELECT outbox_n FROM remote_deliveries WHERE object_id=?1 AND host_id=?2
            AND state IN ('ready', 'sent')",
            params![object_id, host_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(n) = n else {
        return Ok(false);
    };
    tx.execute(
        "UPDATE remote_deliveries SET state=?3, code=?4, detail=?5
        WHERE object_id=?1 AND host_id=?2",
        params![object_id, host_id, state, code, detail],
    )?;
    if let Some(n) = n {
        outbox::settle(tx, n)?;
    }
    Ok(true)
}

/// A held `complete`'s detail (ruling R50).
pub const HELD: &str = "held until the host's status shows the task awaiting its result";
/// A `complete` held again after the host answered it `busy` by its own id.
pub const HELD_AFTER_BUSY: &str = "the host answered busy: the task wasn't awaiting its result there; held until its status shows it";

/// The `cancel` or `complete` (`kind`) envelope `object_id` of `task` (a
/// task on another host this host's message reached), in `tx`: its own
/// delivery row, `ready` when sealed and enqueued as the engine's row `n`
/// (design II.4.4: put every 10 minutes until a status shows its effect,
/// the host answers it by its own id, or it expires), or, with no `n`, a
/// `complete` `held` until the host's status shows the task awaiting its
/// result (ruling R50).
pub fn stop_row(
    tx: &Transaction,
    task: &super::results_back::RemoteTask,
    kind: &str,
    object_id: &str,
    n: Option<i64>,
    now_ms: u64,
) -> Result<()> {
    let (state, detail) = match n {
        Some(_) => ("ready", "waiting to be put in the host's mailbox"),
        None => ("held", HELD),
    };
    tx.execute(
        "INSERT INTO remote_deliveries(object_id, host_id, host_trust_gen, message_id, kind,
            recipient_id, task_id, outbox_n, state, detail, created_ms)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            object_id,
            task.host_id,
            task.host_trust_gen,
            task.message_id,
            kind,
            task.recipient_id,
            task.task_id,
            n,
            state,
            detail,
            now_ms
        ],
    )?;
    Ok(())
}

/// A `complete`'s result for `task`, frozen at the command (what it names
/// when it is sealed, then or later), in `tx`.
pub fn hold_result(
    tx: &Transaction,
    task: &super::results_back::RemoteTask,
    result: &atem_client::session::host_work::ContextSnapshot,
) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO remote_held(message_id, host_id, task_id, result)
        VALUES(?1, ?2, ?3, ?4)",
        params![
            task.message_id,
            task.host_id,
            task.task_id,
            serde_json::to_string(result)?
        ],
    )?;
    Ok(())
}

/// The result frozen for a `complete` of task `task_id` of `message_id`
/// at `host_id`.
pub fn held_result(
    db: &rusqlite::Connection,
    message_id: &str,
    host_id: &str,
    task_id: &str,
) -> Result<Option<atem_client::session::host_work::ContextSnapshot>> {
    db.query_row(
        "SELECT result FROM remote_held WHERE message_id=?1 AND host_id=?2 AND task_id=?3",
        params![message_id, host_id, task_id],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|text| Ok(serde_json::from_str(&text)?))
    .transpose()
}

/// How an earlier `kind` stop of a task stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// None stands (none made, or one refused, dropped or expired).
    None,
    /// One is held or on its way: another would add nothing.
    Pending,
    /// The host's status showed its effect.
    Done,
}

/// How a `kind` stop of `task` stands now.
pub fn stop_standing(
    db: &rusqlite::Connection,
    task: &super::results_back::RemoteTask,
    kind: &str,
) -> Result<Standing> {
    let states: Vec<String> = db
        .prepare(
            "SELECT state FROM remote_deliveries WHERE message_id=?1 AND host_id=?2
            AND task_id=?3 AND kind=?4",
        )?
        .query_map(
            params![task.message_id, task.host_id, task.task_id, kind],
            |r| r.get(0),
        )?
        .collect::<rusqlite::Result<_>>()?;
    Ok(if states.iter().any(|s| s == "accepted") {
        Standing::Done
    } else if states
        .iter()
        .any(|s| matches!(s.as_str(), "held" | "due" | "ready" | "sent"))
    {
        Standing::Pending
    } else {
        Standing::None
    })
}

/// A status of `host_id` shows task `task_id` of `message_id` `state`, in
/// `tx`:
/// - a stop whose effect that is (`cancelled` for a cancel, `completed` for
///   a complete) is `accepted`, its engine row settled (design II.4.4:
///   "until a status shows their effect");
/// - a held `complete` is `due` when the task awaits its result (sealed by
///   the pass), and `dropped`, with why, when the task ended otherwise or
///   its outcome is unknown (ruling R50).
pub fn status_shown(
    tx: &Transaction,
    message_id: &str,
    host_id: &str,
    task_id: &str,
    state: &str,
) -> Result<()> {
    let effect = match state {
        "cancelled" => Some("cancel"),
        "completed" => Some("complete"),
        _ => None,
    };
    if let Some(kind) = effect {
        let ids: Vec<String> = tx
            .prepare(
                "SELECT object_id FROM remote_deliveries WHERE message_id=?1 AND host_id=?2
                AND task_id=?3 AND kind=?4 AND state IN ('ready', 'sent')",
            )?
            .query_map(params![message_id, host_id, task_id, kind], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let detail = format!("the host's status shows the task {state}");
        for id in ids {
            settle_row(tx, &id, host_id, "accepted", None, &detail)?;
        }
    }
    match state {
        "awaiting_result" => {
            tx.execute(
                "UPDATE remote_deliveries SET state='due',
                    detail='the host''s status shows the task awaiting its result; sealed next'
                WHERE message_id=?1 AND host_id=?2 AND task_id=?3 AND kind='complete'
                    AND state='held'",
                params![message_id, host_id, task_id],
            )?;
        }
        "cancelled" | "failed" | "expired" | "completed" | "outcome_unknown" => {
            tx.execute(
                "UPDATE remote_deliveries SET state='dropped', code=NULL, detail=?4
                WHERE message_id=?1 AND host_id=?2 AND task_id=?3 AND kind='complete'
                    AND state IN ('held', 'due')",
                params![
                    message_id,
                    host_id,
                    task_id,
                    format!("not sent: the host's status shows the task {state}")
                ],
            )?;
        }
        _ => {}
    }
    Ok(())
}

/// The host answered the `complete` `object_id` `busy` by its own id (a
/// race: the task wasn't awaiting its result there; ruling R50): held
/// again under a fresh id, its engine row settled, to be sealed again once
/// a status shows the task awaiting its result; dropped, with why, when
/// the newest status already shows it ended. Whether it was a complete on
/// its way (else the refusal ends the row as any other).
pub fn rehold(tx: &Transaction, object_id: &str, host_id: &str) -> Result<bool> {
    let row: Option<(Option<i64>, String, String)> = tx
        .query_row(
            "SELECT outbox_n, message_id, task_id FROM remote_deliveries
            WHERE object_id=?1 AND host_id=?2 AND kind='complete' AND state IN ('ready', 'sent')",
            params![object_id, host_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((n, message_id, task_id)) = row else {
        return Ok(false);
    };
    if let Some(n) = n {
        outbox::settle(tx, n)?;
    }
    let shown: Option<String> = tx
        .query_row(
            "SELECT state FROM remote_tasks WHERE message_id=?1 AND host_id=?2 AND task_id=?3",
            params![message_id, host_id, task_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(state) = shown.filter(|s| {
        matches!(
            s.as_str(),
            "cancelled" | "failed" | "expired" | "completed" | "outcome_unknown"
        )
    }) {
        tx.execute(
            "UPDATE remote_deliveries SET state='dropped', code='busy', outbox_n=NULL, detail=?3
            WHERE object_id=?1 AND host_id=?2",
            params![
                object_id,
                host_id,
                format!("the host answered busy; its status shows the task {state}")
            ],
        )?;
        return Ok(true);
    }
    tx.execute(
        "UPDATE remote_deliveries SET object_id=?3, state='held', code='busy', outbox_n=NULL,
            detail=?4
        WHERE object_id=?1 AND host_id=?2",
        params![
            object_id,
            host_id,
            uuid::Uuid::new_v4().to_string(),
            HELD_AFTER_BUSY
        ],
    )?;
    Ok(true)
}

/// The `complete` rows due to be sealed (a status showed their task
/// awaiting its result): (object id, host, message, task).
pub fn due_stops(db: &rusqlite::Connection) -> Result<Vec<(String, String, String, String)>> {
    let mut q = db.prepare(
        "SELECT object_id, host_id, message_id, task_id FROM remote_deliveries
        WHERE kind='complete' AND state IN ('held', 'due') AND state='due'",
    )?;
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The due `complete` `object_id` sealed and enqueued as the engine's row
/// `n`: `ready`, in `tx`.
pub fn sealed_due(tx: &Transaction, object_id: &str, host_id: &str, n: i64) -> Result<()> {
    tx.execute(
        "UPDATE remote_deliveries SET state='ready', outbox_n=?3, code=NULL,
            detail='waiting to be put in the host''s mailbox'
        WHERE object_id=?1 AND host_id=?2 AND state='due'",
        params![object_id, host_id, n],
    )?;
    Ok(())
}

/// A held or due `complete` that can't go (`why`): `dropped`.
pub fn drop_stop(tx: &Transaction, object_id: &str, host_id: &str, why: &str) -> Result<()> {
    tx.execute(
        "UPDATE remote_deliveries SET state='dropped', detail=?3
        WHERE object_id=?1 AND host_id=?2 AND state IN ('held', 'due')",
        params![object_id, host_id, why],
    )?;
    Ok(())
}

/// Held and due `complete`s whose message expired by `now_ms` (`D`):
/// `expired`, never sent.
pub fn expire_held(db: &rusqlite::Connection, now_ms: u64) -> Result<usize> {
    Ok(db.execute(
        "UPDATE remote_deliveries SET state='expired', detail='expired before it was sent'
        WHERE kind='complete' AND state IN ('held', 'due') AND EXISTS(
            SELECT 1 FROM remote_tasks t WHERE t.message_id=remote_deliveries.message_id
                AND t.host_id=remote_deliveries.host_id AND t.task_id=remote_deliveries.task_id
                AND t.expires_at <= ?1)",
        [now_ms],
    )?)
}

/// One delivery row, as `atem message status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
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

//! The receiving host's mailbox in its host-work store (host-work-v1
//! §11.5, "The mailbox calls", rules 4, 5 and 7, and the receiver's
//! verdicts; the delegated host-work design II.4.2, II.4.3), behind the
//! debug-only hook's `host.senders`: its tables are made only then
//! ([`prepare`]), so a store of a host without it is main's.
//!
//! - **The cursor** (`mailbox_cursor`, one row): the mailbox read, its
//!   last position processed, and the host identity it belongs to
//!   (account, device, trust generation and the device list's genesis).
//!   A new identity's store is a new file (host-work's store is moved
//!   aside), so it starts empty; a row of another identity in this store
//!   doesn't load ([`read`]: fail closed) and owes nothing.
//! - **Each page in one transaction** ([`commit_page`], `BEGIN IMMEDIATE`,
//!   Astation's ask on #120): only from the store's own cursor (a page
//!   continuing another cursor or mailbox commits nothing:
//!   [`Commit::Stale`]), each object's decision with its row, the objects
//!   kept waiting, the dones owed and the cursor moved to the page's
//!   `through`. Only after that commit does the bridge send a done; the
//!   dones owed are rows (`mailbox_dones`) until their answer, so a crash
//!   between the commit and the done sends them after the restart.
//! - **The decisions** (the shared core's [`open_envelope`], with this
//!   host's own identity, keys, committed device list and the delegated
//!   clock): an opened `request`, `cancel` or `complete` is an inbox row
//!   (`mailbox_inbox`, the seam to admission, which consumes it); a refusal
//!   is a refusal row (`mailbox_refused`) with its evidence (the
//!   `object_hash`, or for bytes that don't parse the SHA-256 of the bytes
//!   as fetched), those bytes and the reason, `report` set for a refusal
//!   after the copy was shown to be the sender's (admission sends its
//!   status); a waiting object is a pending row (`mailbox_pending`), held
//!   once by its `object_hash`, never done. A copy that claims an id
//!   (opened or refused authenticated) records its claim (`mailbox_claims`,
//!   `(sender host, id)` and its `sealed_hash`): the sender's object again
//!   is a duplicate with the first verdict, its id with another sealed
//!   part a refusal (`id_reused`) kept as evidence, the first standing; an
//!   unauthenticated refusal's same bytes again are a duplicate of it.
//!   Duplicates are marked done and record nothing.
//! - **The pending limits** (design II.4.2): 64 per claimed `(host_id,
//!   host_trust_gen)` and 256 in all; one over either is dropped undecided
//!   (no verdict, no row, no id) and marked done all the same (Atem's
//!   refinement, agreed with Astation 2026-11-16). A waiting object is
//!   judged again after the device list advances or its expiry passes
//!   ([`rejudge_pending`]); decided, it owes a done only in the mailbox
//!   read now (a reset dropped its old position).
//! - **A reset** ([`mark_reset`], rule 7): marked durably before anything
//!   is asked for it, as the cursor itself (the announced mailbox at
//!   position 0), the dones owed to the old mailbox dropped, in one
//!   transaction. A start finds it and reads on from there; the gate's
//!   mailbox part stays closed until the read reaches the announced head.
//! - **An object that can't be decided now** (the key provider failed):
//!   nothing of its page commits ([`Commit::Undecided`]); asked again.
use super::mailbox::Observed;
use super::sync::HostIdentity;
use crate::runtime::host_work::Store;
use anyhow::{Result, anyhow};
use atem_client::KeyProvider;
use atem_client::encoding::Hash32;
use atem_client::host_mail::mailbox::{MailboxEntry, MailboxSyncResult};
use atem_client::host_mail::receive::reason::MALFORMED;
use atem_client::host_mail::{
    EnvelopePlain, EnvelopeVerdict, MailBody, Recipient, object_hash, open_envelope, parse_object,
};
use atem_client::membership::Membership;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::json;

/// Waiting objects per claimed `(host_id, host_trust_gen)`, at most
/// (design II.4.2).
pub const MAX_PENDING_PER_SENDER: usize = 64;
/// Waiting objects in all, at most (design II.4.2).
pub const MAX_PENDING: usize = 256;
/// The reason kept for the sender's id with another sealed part
/// (§11.5, "Which copies claim an id"): evidence only, never on the wire.
pub const ID_REUSED: &str = "id_reused";

/// The mailbox's tables, made by [`prepare`] (only with `host.senders`).
/// Additive, as every host-work table.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS mailbox_cursor (
        one INTEGER PRIMARY KEY CHECK (one = 1), identity TEXT NOT NULL,
        mailbox_id TEXT NOT NULL, cursor INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mailbox_dones (
        mailbox_id TEXT NOT NULL, position INTEGER NOT NULL,
        PRIMARY KEY(mailbox_id, position)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mailbox_claims (
        sender_host TEXT NOT NULL, object_id TEXT NOT NULL, sealed_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL, PRIMARY KEY(sender_host, object_id)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mailbox_inbox (
        n INTEGER PRIMARY KEY, sender_host TEXT NOT NULL, object_id TEXT NOT NULL,
        kind TEXT NOT NULL, plain BLOB NOT NULL, object_hash TEXT NOT NULL,
        at_ms INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS mailbox_refused (
        n INTEGER PRIMARY KEY, evidence TEXT NOT NULL UNIQUE, reason TEXT NOT NULL,
        sender_host TEXT, object_id TEXT, report INTEGER NOT NULL, bytes BLOB NOT NULL,
        at_ms INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS mailbox_pending (
        object_hash TEXT PRIMARY KEY, host_id TEXT NOT NULL, host_trust_gen INTEGER NOT NULL,
        mailbox_id TEXT NOT NULL, position INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        bytes BLOB NOT NULL) WITHOUT ROWID;";

/// The mailbox's tables in `store`, made if missing.
pub fn prepare(store: &Store) -> Result<()> {
    store.db.execute_batch(TABLES)?;
    Ok(())
}

/// The identity a row belongs to, as stored.
fn identity_text(identity: &HostIdentity) -> String {
    json!({
        "account_id": identity.host.account_id,
        "atem_device_id": identity.host.atem_device_id,
        "host_trust_gen": identity.host.host_trust_gen,
        "genesis": identity.genesis.map(|g| g.to_hex()),
    })
    .to_string()
}

/// The stored cursor: `(identity, mailbox_id, cursor)`.
fn cursor_row(db: &rusqlite::Connection) -> Result<Option<(String, String, u64)>> {
    Ok(db
        .query_row(
            "SELECT identity, mailbox_id, cursor FROM mailbox_cursor WHERE one=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?)
}

/// The cursor of `identity`'s mailbox (none: never read); an error for a
/// row of another identity.
fn own_cursor(db: &rusqlite::Connection, identity: &HostIdentity) -> Result<Option<(String, u64)>> {
    match cursor_row(db)? {
        None => Ok(None),
        Some((of, id, at)) if of == identity_text(identity) => Ok(Some((id, at))),
        Some(_) => Err(anyhow!(
            "the stored mailbox state is another host identity's"
        )),
    }
}

/// The store as the mailbox client observes it for `identity`.
pub fn read(store: &Store, identity: &HostIdentity) -> Result<Observed> {
    let cursor = own_cursor(&store.db, identity)?;
    let inbox = store
        .db
        .query_row("SELECT count(*) FROM mailbox_inbox", [], |r| r.get(0))?;
    Ok(Observed {
        identity: identity.clone(),
        cursor,
        inbox,
        owed: owed_dones(store, identity)?,
    })
}

fn set_cursor(tx: &Transaction, identity: &HostIdentity, mailbox_id: &str, at: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO mailbox_cursor(one, identity, mailbox_id, cursor) VALUES(1, ?1, ?2, ?3)
        ON CONFLICT(one) DO UPDATE SET identity=excluded.identity,
            mailbox_id=excluded.mailbox_id, cursor=excluded.cursor",
        params![identity_text(identity), mailbox_id, at],
    )?;
    Ok(())
}

/// A reset of `identity`'s mailbox (rule 7), marked durably before
/// anything is asked for it: the cursor at position 0 of the announced
/// `mailbox_id`, and the dones owed to the old mailbox dropped.
pub fn mark_reset(store: &Store, identity: &HostIdentity, mailbox_id: &str) -> Result<()> {
    let tx = store.immediate()?;
    own_cursor(&tx, identity)?;
    set_cursor(&tx, identity, mailbox_id, 0)?;
    tx.execute("DELETE FROM mailbox_dones", [])?;
    tx.commit()?;
    Ok(())
}

/// The dones owed to `identity`'s mailbox, by position (none for another
/// identity's state: never sent under this one).
pub fn owed_dones(store: &Store, identity: &HostIdentity) -> Result<Vec<u64>> {
    let Ok(Some((mailbox_id, _))) = own_cursor(&store.db, identity) else {
        return Ok(Vec::new());
    };
    let mut q = store.db.prepare(
        "SELECT position FROM mailbox_dones WHERE mailbox_id=?1 ORDER BY position LIMIT 64",
    )?;
    let positions = q
        .query_map([mailbox_id], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<u64>>>()?;
    Ok(positions)
}

/// The Station answered the done of `position` in `mailbox_id`: no longer
/// owed.
pub fn done_answered(
    store: &Store,
    identity: &HostIdentity,
    mailbox_id: &str,
    position: u64,
) -> Result<()> {
    own_cursor(&store.db, identity)?;
    store.db.execute(
        "DELETE FROM mailbox_dones WHERE mailbox_id=?1 AND position=?2",
        params![mailbox_id, position],
    )?;
    Ok(())
}

/// What a page's commit did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Commit {
    /// Committed: the cursor is at the page's `through`.
    Committed(Committed),
    /// The page doesn't continue the store's own cursor (another cursor or
    /// mailbox, or another identity's state): nothing committed.
    Stale,
    /// An object couldn't be decided now (a local failure, or nothing to
    /// decide with: no clock, the list not serving): nothing committed.
    Undecided,
}

/// A committed page: its objects' decisions, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Committed {
    pub decided: Vec<Decision>,
}

/// What became of one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Opened: an inbox row.
    Opened,
    /// Refused: a refusal row, its reason.
    Refused(&'static str),
    /// A copy already decided: the first verdict stands.
    Duplicate,
    /// Kept waiting (not done).
    Pending,
    /// Over the pending limits: dropped undecided, marked done.
    Overflow,
}

/// What objects are decided with: this host's committed device list, its
/// identity and keys as the receiver (`host_enc::recipient_at`), and the
/// delegated clock's `D` (design I.6.5).
pub struct DecideCx<'a> {
    pub list: &'a Membership,
    pub recipient: &'a Recipient,
    pub provider: &'a dyn KeyProvider,
    pub now_ms: u64,
}

/// `page` of `identity`'s mailbox, in one `BEGIN IMMEDIATE` transaction
/// (rule 4, the module docs): only from the store's own cursor; each
/// object decided (`decide`: none when nothing can be decided now) with
/// its row and its done owed; the cursor moved to `through`.
pub fn commit_page(
    store: &Store,
    identity: &HostIdentity,
    page: &MailboxSyncResult,
    decide: Option<&DecideCx>,
) -> Result<Commit> {
    let tx = store.immediate()?;
    let Ok(cursor) = own_cursor(&tx, identity) else {
        return Ok(Commit::Stale);
    };
    let continues = match &cursor {
        Some((id, at)) => *id == page.mailbox_id && *at == page.after,
        None => page.after == 0,
    };
    if !continues {
        return Ok(Commit::Stale);
    }
    let mut decided = Vec::new();
    for entry in &page.objects {
        let Some(cx) = decide else {
            return Ok(Commit::Undecided);
        };
        let Some(decision) = decide_entry(&tx, entry, cx, &page.mailbox_id)? else {
            return Ok(Commit::Undecided);
        };
        if decision != Decision::Pending {
            owe_done(&tx, &page.mailbox_id, entry.position)?;
        }
        decided.push(decision);
    }
    set_cursor(&tx, identity, &page.mailbox_id, page.through)?;
    tx.commit()?;
    Ok(Commit::Committed(Committed { decided }))
}

/// The waiting objects judged again (after the device list advanced, or
/// one's expiry passed), in one transaction: each decided now gets its row
/// and leaves the waiting ones; its done is owed when it waits in the
/// mailbox read now. The decisions made; an object that can't be decided
/// now keeps waiting.
pub fn rejudge_pending(
    store: &Store,
    identity: &HostIdentity,
    cx: &DecideCx,
) -> Result<Vec<Decision>> {
    let tx = store.immediate()?;
    let Some((current, _)) = own_cursor(&tx, identity)? else {
        return Ok(Vec::new());
    };
    let waiting: Vec<(String, String, u64, Vec<u8>)> = {
        let mut q = tx.prepare(
            "SELECT object_hash, mailbox_id, position, bytes FROM mailbox_pending ORDER BY position",
        )?;
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut decided = Vec::new();
    for (hash, mailbox_id, position, bytes) in waiting {
        let Ok(object) = parse_object(&bytes) else {
            continue;
        };
        let verdict = open_envelope(&object, cx.list, cx.recipient, cx.provider, cx.now_ms);
        if matches!(
            verdict,
            EnvelopeVerdict::Pending { .. } | EnvelopeVerdict::Unavailable { .. }
        ) {
            continue;
        }
        tx.execute("DELETE FROM mailbox_pending WHERE object_hash=?1", [&hash])?;
        let Some(decision) = record(&tx, &object, &bytes, verdict, &mailbox_id, position)? else {
            continue;
        };
        if mailbox_id == current {
            owe_done(&tx, &mailbox_id, position)?;
        }
        decided.push(decision);
    }
    tx.commit()?;
    Ok(decided)
}

/// The earliest expiry of a waiting object (a waiting object is judged
/// again once it passed).
pub fn pending_expiry(store: &Store) -> Result<Option<u64>> {
    Ok(store
        .db
        .query_row("SELECT min(expires_at) FROM mailbox_pending", [], |r| {
            r.get(0)
        })?)
}

fn owe_done(tx: &Transaction, mailbox_id: &str, position: u64) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO mailbox_dones(mailbox_id, position) VALUES(?1, ?2)",
        params![mailbox_id, position],
    )?;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// One page object decided (none: it can't be now).
fn decide_entry(
    tx: &Transaction,
    entry: &MailboxEntry,
    cx: &DecideCx,
    mailbox_id: &str,
) -> Result<Option<Decision>> {
    let object = match entry.parse_object() {
        Ok(object) => object,
        // Check 1: not a signed object at all, refused under the SHA-256
        // of the bytes as fetched.
        Err(_) => {
            return refuse(
                tx,
                &Hash32::of(entry.bytes()),
                MALFORMED,
                None,
                entry.bytes(),
            )
            .map(Some);
        }
    };
    let verdict = open_envelope(&object, cx.list, cx.recipient, cx.provider, cx.now_ms);
    record(
        tx,
        &object,
        entry.bytes(),
        verdict,
        mailbox_id,
        entry.position,
    )
}

/// A verdict's rows (the module docs); none for `Unavailable`.
fn record(
    tx: &Transaction,
    object: &atem_client::SignedObject,
    bytes: &[u8],
    verdict: EnvelopeVerdict,
    mailbox_id: &str,
    position: u64,
) -> Result<Option<Decision>> {
    let (_, body) = MailBody::from_object(object)?;
    let hash = object_hash(object);
    Ok(Some(match verdict {
        EnvelopeVerdict::Unavailable { .. } => return Ok(None),
        EnvelopeVerdict::Refused { reason, evidence } => {
            refuse(tx, &evidence, reason, None, bytes)?
        }
        EnvelopeVerdict::Pending {
            host_id,
            host_trust_gen,
        } => pend(
            tx,
            &hash,
            &host_id,
            host_trust_gen,
            &body,
            mailbox_id,
            position,
            bytes,
        )?,
        EnvelopeVerdict::Open { plain, .. } => match claim(tx, &body, &hash, bytes)? {
            Some(other) => other,
            None => {
                let kind = match &plain {
                    EnvelopePlain::Request { .. } => "request",
                    EnvelopePlain::Cancel { .. } => "cancel",
                    EnvelopePlain::Complete { .. } => "complete",
                };
                tx.execute(
                        "INSERT INTO mailbox_inbox(sender_host, object_id, kind, plain, object_hash, at_ms)
                        VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            body.sender.host_id,
                            body.id,
                            kind,
                            plain.to_bytes()?.as_slice(),
                            hash.to_hex(),
                            now_ms()
                        ],
                    )?;
                Decision::Opened
            }
        },
        EnvelopeVerdict::RefusedAuthenticated { reason, .. } => {
            match claim(tx, &body, &hash, bytes)? {
                Some(other) => other,
                None => refuse(tx, &hash, reason, Some(&body), bytes)?,
            }
        }
    }))
}

/// The claim of the sender's verified copy, `(sender host, id)`: none when
/// it is new (claimed now; the caller writes its row), else what the copy
/// is: a duplicate (the same sealed part), or a reused id (another).
fn claim(
    tx: &Transaction,
    body: &MailBody,
    hash: &Hash32,
    bytes: &[u8],
) -> Result<Option<Decision>> {
    let sealed: Option<String> = tx
        .query_row(
            "SELECT sealed_hash FROM mailbox_claims WHERE sender_host=?1 AND object_id=?2",
            params![body.sender.host_id, body.id],
            |r| r.get(0),
        )
        .optional()?;
    match sealed {
        Some(sealed) if sealed == body.sealed_hash.to_hex() => Ok(Some(Decision::Duplicate)),
        Some(_) => refuse(tx, hash, ID_REUSED, None, bytes).map(Some),
        None => {
            tx.execute(
                "INSERT INTO mailbox_claims(sender_host, object_id, sealed_hash, expires_at)
                VALUES(?1, ?2, ?3, ?4)",
                params![
                    body.sender.host_id,
                    body.id,
                    body.sealed_hash.to_hex(),
                    body.expires_at
                ],
            )?;
            Ok(None)
        }
    }
}

/// A refusal row under `evidence` (a duplicate when one is there): `body`
/// for a refusal of the sender's own copy, reported by admission.
fn refuse(
    tx: &Transaction,
    evidence: &Hash32,
    reason: &'static str,
    body: Option<&MailBody>,
    bytes: &[u8],
) -> Result<Decision> {
    let written = tx.execute(
        "INSERT OR IGNORE INTO mailbox_refused(evidence, reason, sender_host, object_id, report, bytes, at_ms)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            evidence.to_hex(),
            reason,
            body.map(|b| b.sender.host_id.as_str()),
            body.map(|b| b.id.as_str()),
            body.is_some(),
            bytes,
            now_ms()
        ],
    )?;
    Ok(if written == 0 {
        Decision::Duplicate
    } else {
        Decision::Refused(reason)
    })
}

/// A waiting object (held once, at its latest position), or an overflow.
#[allow(clippy::too_many_arguments)]
fn pend(
    tx: &Transaction,
    hash: &Hash32,
    host_id: &str,
    host_trust_gen: u64,
    body: &MailBody,
    mailbox_id: &str,
    position: u64,
    bytes: &[u8],
) -> Result<Decision> {
    let moved = tx.execute(
        "UPDATE mailbox_pending SET mailbox_id=?2, position=?3 WHERE object_hash=?1",
        params![hash.to_hex(), mailbox_id, position],
    )?;
    if moved > 0 {
        return Ok(Decision::Pending);
    }
    let (all, of_pair): (u64, u64) = tx.query_row(
        "SELECT count(*), count(CASE WHEN host_id=?1 AND host_trust_gen=?2 THEN 1 END)
        FROM mailbox_pending",
        params![host_id, host_trust_gen],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if all >= MAX_PENDING as u64 || of_pair >= MAX_PENDING_PER_SENDER as u64 {
        return Ok(Decision::Overflow);
    }
    tx.execute(
        "INSERT INTO mailbox_pending(object_hash, host_id, host_trust_gen, mailbox_id, position, expires_at, bytes)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            hash.to_hex(),
            host_id,
            host_trust_gen,
            mailbox_id,
            position,
            body.expires_at,
            bytes
        ],
    )?;
    Ok(Decision::Pending)
}

#[cfg(test)]
#[path = "mailbox_store_tests.rs"]
mod tests;

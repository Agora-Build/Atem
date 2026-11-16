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
//!   status; an earlier row of the same bytes is upgraded so); a waiting
//!   object is a pending row (`mailbox_pending`), held once by its
//!   `object_hash`, never done. An `atem-result` is never judged here
//!   (ruling R28): it is kept (`mailbox_results`: its exact bytes,
//!   `object_hash`, sender, id and position) for the sending host's
//!   `accept_result`, committed and done like any object, never counted
//!   as inbox (it starts no work).
//! - **Bounded** ([`Limits`], [`prune`]): refusals keep their bytes within
//!   a budget (the oldest first, those not reported before those reported;
//!   the evidence hash stays), results within their own limits (over them
//!   dropped undecided, done); claims, refusals and results are pruned
//!   [`KEEP_MARGIN_MS`] after their object's expiry. A copy that claims an id
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
//!   ([`rejudge_pending`]); decided, it owes a done only at a position of
//!   the mailbox read now: a reset detaches it from its old one.
//! - **A reset** ([`mark_reset`], rule 7): marked durably before anything
//!   is asked for it, as the cursor itself (the announced mailbox at
//!   position 0), the dones owed to the old mailbox dropped and every
//!   waiting object detached from its position, in one transaction. A start finds it and reads on from there; the gate's
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
    EnvelopePlain, EnvelopeVerdict, MailBody, MailKind, Recipient, object_hash, open_envelope,
    parse_object,
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
/// How long after its object's expiry a claim or a refusal is kept (24 h).
/// A claim must outlive every copy of its object that can still arrive:
/// the Station keeps an object until its `expires_at` on the Station's own
/// clock, which this host bounds only from above (I.6.5's cap), and a
/// sender's clock may lag too. A day past the expiry, an object's whole
/// longest lifetime again, covers a Station or sender clock up to a day
/// behind; a copy arriving later still is judged anew (refused `expired`).
pub const KEEP_MARGIN_MS: u64 = 24 * 60 * 60 * 1000;
/// The longest an object can still be live after it arrives: its 24 h
/// lifetime and the 60 s its `created_at` may be ahead (check 5). An
/// expiry beyond it (`lifetime_too_long`), or none (bytes that don't
/// parse), counts as this.
const LONGEST_LIFE_MS: u64 = 24 * 60 * 60 * 1000 + 60_000;

/// What the mailbox keeps at most (review finding 2: anything a sender or
/// the Station can make this host keep is bounded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The exact bytes refusals keep, in all: beyond it the oldest go
    /// first, those not reported before those reported (their evidence
    /// hash stays).
    pub evidence_bytes: u64,
    /// Results kept for the sending host's own check, at most.
    pub results: u64,
    /// Their bytes, at most.
    pub result_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            evidence_bytes: 16 << 20,
            results: 256,
            result_bytes: 64 << 20,
        }
    }
}

/// The mailbox's tables, made by [`prepare`] (only with `host.senders`).
/// Additive, as every host-work table. `mailbox_kept` is the refusals'
/// kept bytes, kept by triggers.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS mailbox_cursor (
        one INTEGER PRIMARY KEY CHECK (one = 1), identity TEXT NOT NULL,
        mailbox_id TEXT NOT NULL, cursor INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mailbox_dones (
        mailbox_id TEXT NOT NULL, position INTEGER NOT NULL,
        PRIMARY KEY(mailbox_id, position)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mailbox_claims (
        sender_host TEXT NOT NULL, object_id TEXT NOT NULL, sealed_hash TEXT NOT NULL,
        keep_until INTEGER NOT NULL, PRIMARY KEY(sender_host, object_id)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS mailbox_claims_keep ON mailbox_claims(keep_until);
    CREATE TABLE IF NOT EXISTS mailbox_inbox (
        n INTEGER PRIMARY KEY, sender_host TEXT NOT NULL, object_id TEXT NOT NULL,
        kind TEXT NOT NULL, plain BLOB NOT NULL, object_hash TEXT NOT NULL,
        at_ms INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS mailbox_refused (
        n INTEGER PRIMARY KEY, evidence TEXT NOT NULL UNIQUE, reason TEXT NOT NULL,
        sender_host TEXT, object_id TEXT, report INTEGER NOT NULL, bytes BLOB,
        keep_until INTEGER NOT NULL, at_ms INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS mailbox_refused_keep ON mailbox_refused(keep_until);
    CREATE INDEX IF NOT EXISTS mailbox_refused_bytes ON mailbox_refused(report, n)
        WHERE bytes IS NOT NULL;
    CREATE TABLE IF NOT EXISTS mailbox_kept (
        one INTEGER PRIMARY KEY CHECK (one = 1), bytes INTEGER NOT NULL) WITHOUT ROWID;
    INSERT OR IGNORE INTO mailbox_kept(one, bytes) VALUES(1, 0);
    CREATE TRIGGER IF NOT EXISTS mailbox_kept_insert AFTER INSERT ON mailbox_refused BEGIN
        UPDATE mailbox_kept SET bytes=bytes+coalesce(length(NEW.bytes),0) WHERE one=1;
    END;
    CREATE TRIGGER IF NOT EXISTS mailbox_kept_update AFTER UPDATE OF bytes ON mailbox_refused BEGIN
        UPDATE mailbox_kept SET bytes=bytes-coalesce(length(OLD.bytes),0)
            +coalesce(length(NEW.bytes),0) WHERE one=1;
    END;
    CREATE TRIGGER IF NOT EXISTS mailbox_kept_delete AFTER DELETE ON mailbox_refused BEGIN
        UPDATE mailbox_kept SET bytes=bytes-coalesce(length(OLD.bytes),0) WHERE one=1;
    END;
    CREATE TABLE IF NOT EXISTS mailbox_pending (
        object_hash TEXT PRIMARY KEY, host_id TEXT NOT NULL, host_trust_gen INTEGER NOT NULL,
        mailbox_id TEXT NOT NULL, position INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        bytes BLOB NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mailbox_results (
        object_hash TEXT PRIMARY KEY, sender_host TEXT NOT NULL, object_id TEXT NOT NULL,
        mailbox_id TEXT NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
        keep_until INTEGER NOT NULL, at_ms INTEGER NOT NULL) WITHOUT ROWID;";

/// The mailbox's tables in `store`, made if missing.
pub fn prepare(store: &Store) -> Result<()> {
    let tx = store.immediate()?;
    tx.execute_batch(TABLES)?;
    tx.commit()?;
    Ok(())
}

/// Whether `store` has any of the mailbox's tables (only a host that ran
/// `host.senders` does).
#[cfg(test)]
pub fn made_in(store: &Store) -> bool {
    store
        .db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name GLOB 'mailbox_*')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false)
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
/// `mailbox_id`, the dones owed to the old mailbox dropped, and every
/// waiting object detached from its position (review finding 1: under the
/// same id a position may hold another object now; a waiting object owes a
/// done only once the read from 0 lists it again).
pub fn mark_reset(store: &Store, identity: &HostIdentity, mailbox_id: &str) -> Result<()> {
    let tx = store.immediate()?;
    own_cursor(&tx, identity)?;
    set_cursor(&tx, identity, mailbox_id, 0)?;
    tx.execute("DELETE FROM mailbox_dones", [])?;
    tx.execute("UPDATE mailbox_pending SET mailbox_id=''", [])?;
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

/// Claims, refusals and kept results whose time is over at `now_ms` (the
/// delegated clock's `D`): [`KEEP_MARGIN_MS`] after their object's expiry.
/// How many rows went.
pub fn prune(store: &Store, now_ms: u64) -> Result<u64> {
    let tx = store.immediate()?;
    let mut gone = 0;
    for table in ["mailbox_claims", "mailbox_refused", "mailbox_results"] {
        gone += tx.execute(
            &format!("DELETE FROM {table} WHERE keep_until <= ?1"),
            [now_ms],
        )? as u64;
    }
    tx.commit()?;
    Ok(gone)
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
    /// Over the pending or the results' limits: dropped undecided, marked
    /// done.
    Overflow,
    /// An `atem-result`, kept for the sending host's own check.
    Result,
}

/// What objects are decided with: this host's committed device list, its
/// identity and keys as the receiver (`host_enc::recipient_at`), the
/// delegated clock's `D` (design I.6.5), and what the store keeps at most.
pub struct DecideCx<'a> {
    pub list: &'a Membership,
    pub recipient: &'a Recipient,
    pub provider: &'a dyn KeyProvider,
    pub now_ms: u64,
    pub limits: Limits,
}

impl DecideCx<'_> {
    /// When a row about an object expiring at `expires_at` (none: not
    /// known) goes ([`prune`]).
    fn keep_until(&self, expires_at: Option<u64>) -> u64 {
        let longest = self.now_ms.saturating_add(LONGEST_LIFE_MS);
        expires_at
            .map_or(longest, |at| at.min(longest))
            .saturating_add(KEEP_MARGIN_MS)
    }
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
/// and leaves the waiting ones; its done is owed when it waits at a
/// position of the mailbox read now (a reset detached it: [`mark_reset`]).
/// One whose bytes no longer parse is refused `malformed`. The decisions
/// made; an object that can't be decided now keeps waiting.
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
        let decision = match parse_object(&bytes) {
            Err(_) => refuse(&tx, cx, &Hash32::of(&bytes), MALFORMED, None, &bytes, None)?,
            Ok(object) => {
                let verdict = open_envelope(&object, cx.list, cx.recipient, cx.provider, cx.now_ms);
                if matches!(
                    verdict,
                    EnvelopeVerdict::Pending { .. } | EnvelopeVerdict::Unavailable { .. }
                ) {
                    continue;
                }
                let Some(decision) =
                    record(&tx, cx, &object, &bytes, verdict, &mailbox_id, position)?
                else {
                    continue;
                };
                decision
            }
        };
        tx.execute("DELETE FROM mailbox_pending WHERE object_hash=?1", [&hash])?;
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

/// One page object decided (none: it can't be now). An `atem-result` is
/// kept for the sending host's own check (ruling R28), never judged as an
/// envelope.
fn decide_entry(
    tx: &Transaction,
    entry: &MailboxEntry,
    cx: &DecideCx,
    mailbox_id: &str,
) -> Result<Option<Decision>> {
    let bytes = entry.bytes();
    let object = match entry.parse_object() {
        Ok(object) => object,
        // Check 1: not a signed object at all, refused under the SHA-256
        // of the bytes as fetched.
        Err(_) => {
            return refuse(tx, cx, &Hash32::of(bytes), MALFORMED, None, bytes, None).map(Some);
        }
    };
    let (kind, body) = MailBody::from_object(&object)?;
    if kind == MailKind::Result {
        return keep_result(tx, cx, &object, &body, bytes, mailbox_id, entry.position).map(Some);
    }
    let verdict = open_envelope(&object, cx.list, cx.recipient, cx.provider, cx.now_ms);
    record(tx, cx, &object, bytes, verdict, mailbox_id, entry.position)
}

/// An `atem-result` kept (ruling R28): its exact bytes, `object_hash`,
/// sender, id and position, for the sending host's `accept_result`; the
/// same object again is a duplicate; over [`Limits`] it is dropped
/// undecided (marked done).
fn keep_result(
    tx: &Transaction,
    cx: &DecideCx,
    object: &atem_client::SignedObject,
    body: &MailBody,
    bytes: &[u8],
    mailbox_id: &str,
    position: u64,
) -> Result<Decision> {
    let hash = object_hash(object).to_hex();
    let present: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM mailbox_results WHERE object_hash=?1)",
        [&hash],
        |r| r.get(0),
    )?;
    if present {
        return Ok(Decision::Duplicate);
    }
    let (count, kept): (u64, u64) = tx.query_row(
        "SELECT count(*), coalesce(sum(length(bytes)), 0) FROM mailbox_results",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count >= cx.limits.results || kept + bytes.len() as u64 > cx.limits.result_bytes {
        return Ok(Decision::Overflow);
    }
    tx.execute(
        "INSERT INTO mailbox_results(object_hash, sender_host, object_id, mailbox_id, position,
            bytes, keep_until, at_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            hash,
            body.sender.host_id,
            body.id,
            mailbox_id,
            position,
            bytes,
            cx.keep_until(Some(body.expires_at)),
            now_ms()
        ],
    )?;
    Ok(Decision::Result)
}

/// A verdict's rows (the module docs); none for `Unavailable`.
fn record(
    tx: &Transaction,
    cx: &DecideCx,
    object: &atem_client::SignedObject,
    bytes: &[u8],
    verdict: EnvelopeVerdict,
    mailbox_id: &str,
    position: u64,
) -> Result<Option<Decision>> {
    let (_, body) = MailBody::from_object(object)?;
    let hash = object_hash(object);
    let expires = Some(body.expires_at);
    Ok(Some(match verdict {
        EnvelopeVerdict::Unavailable { .. } => return Ok(None),
        EnvelopeVerdict::Refused { reason, evidence } => {
            refuse(tx, cx, &evidence, reason, None, bytes, expires)?
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
        EnvelopeVerdict::Open { plain, .. } => match claim(tx, cx, &body, &hash, bytes)? {
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
            match claim(tx, cx, &body, &hash, bytes)? {
                Some(other) => other,
                None => refuse(tx, cx, &hash, reason, Some(&body), bytes, expires)?,
            }
        }
    }))
}

/// The claim of the sender's verified copy, `(sender host, id)`: none when
/// it is new (claimed now; the caller writes its row), else what the copy
/// is: a duplicate (the same sealed part), or a reused id (another).
fn claim(
    tx: &Transaction,
    cx: &DecideCx,
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
        Some(_) => refuse(tx, cx, hash, ID_REUSED, None, bytes, Some(body.expires_at)).map(Some),
        None => {
            tx.execute(
                "INSERT INTO mailbox_claims(sender_host, object_id, sealed_hash, keep_until)
                VALUES(?1, ?2, ?3, ?4)",
                params![
                    body.sender.host_id,
                    body.id,
                    body.sealed_hash.to_hex(),
                    cx.keep_until(Some(body.expires_at))
                ],
            )?;
            Ok(None)
        }
    }
}

/// A refusal row under `evidence`, its bytes within the evidence budget
/// ([`Limits::evidence_bytes`]): `body` for a refusal of the sender's own
/// copy, reported by admission. The same evidence again is a duplicate,
/// unless this is the sender's own copy claiming its id now while that
/// row says nothing to report (the same bytes refused before they could
/// be verified): the row is upgraded to report it (review finding 4).
fn refuse(
    tx: &Transaction,
    cx: &DecideCx,
    evidence: &Hash32,
    reason: &'static str,
    body: Option<&MailBody>,
    bytes: &[u8],
    expires_at: Option<u64>,
) -> Result<Decision> {
    let report: Option<bool> = tx
        .query_row(
            "SELECT report FROM mailbox_refused WHERE evidence=?1",
            [evidence.to_hex()],
            |r| r.get(0),
        )
        .optional()?;
    match (report, body) {
        (None, _) => {
            tx.execute(
                "INSERT INTO mailbox_refused(evidence, reason, sender_host, object_id, report,
                    bytes, keep_until, at_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    evidence.to_hex(),
                    reason,
                    body.map(|b| b.sender.host_id.as_str()),
                    body.map(|b| b.id.as_str()),
                    body.is_some(),
                    bytes,
                    cx.keep_until(expires_at),
                    now_ms()
                ],
            )?;
        }
        (Some(false), Some(body)) => {
            tx.execute(
                "UPDATE mailbox_refused SET reason=?2, sender_host=?3, object_id=?4, report=1,
                    keep_until=max(keep_until, ?5) WHERE evidence=?1",
                params![
                    evidence.to_hex(),
                    reason,
                    body.sender.host_id,
                    body.id,
                    cx.keep_until(expires_at)
                ],
            )?;
        }
        (Some(_), _) => return Ok(Decision::Duplicate),
    }
    keep_within(tx, cx.limits.evidence_bytes)?;
    Ok(Decision::Refused(reason))
}

/// The refusals' kept bytes within `budget`: the oldest go first, those
/// not reported before those reported; their evidence hash stays.
fn keep_within(tx: &Transaction, budget: u64) -> Result<()> {
    loop {
        let kept: u64 = tx.query_row("SELECT bytes FROM mailbox_kept WHERE one=1", [], |r| {
            r.get(0)
        })?;
        if kept <= budget {
            return Ok(());
        }
        let dropped = tx.execute(
            "UPDATE mailbox_refused SET bytes=NULL WHERE n=(SELECT n FROM mailbox_refused
                WHERE bytes IS NOT NULL ORDER BY report, n LIMIT 1)",
            [],
        )?;
        if dropped == 0 {
            return Ok(());
        }
    }
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

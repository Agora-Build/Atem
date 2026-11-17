//! The receiving host's mailbox in its host-work store (host-work-v1
//! §11.5, "The mailbox calls", rules 4, 5 and 7, and the receiver's
//! verdicts; the delegated host-work design II.4.2, II.4.3), behind the
//! debug-only hook's `host.senders`: its tables are made only then
//! ([`prepare`]), so a store of a host without it is main's.
//!
//! - **The cursor** (`mailbox_cursor`, one row): the mailbox read, its
//!   last position processed and the furthest one ever read in it
//!   (`read_to`: a rewind lowers the cursor, never this), the lowest
//!   position left on the Station for want of room (below), and the host
//!   identity it belongs to (account, device, trust generation and the
//!   device list's genesis). A new
//!   identity's store is a new file (host-work's store is moved aside), so
//!   it starts empty; a row of another identity in this store doesn't load
//!   ([`read`]: fail closed) and owes nothing.
//! - **Each page in one transaction** ([`commit_page`], `BEGIN IMMEDIATE`,
//!   Astation's ask on #120): only from the store's own cursor (a page
//!   continuing another cursor or mailbox commits nothing:
//!   [`Commit::Stale`]), each object's decision with its row, the objects
//!   kept waiting, the dones owed, the position of one left on the Station
//!   and the cursor moved to the page's `through`. Only after that commit
//!   does the bridge send a done; the dones owed are rows (`mailbox_dones`)
//!   until their answer, so a crash between the commit and the done sends
//!   them after the restart.
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
//!   `accept_result`, committed and done like any object, never counted as
//!   inbox (it starts no work). A copy arriving [`KEEP_MARGIN_MS`] or more
//!   after its object's expiry is done as expired, evidence only: it claims
//!   nothing and reports nothing.
//! - **Claims** (`mailbox_claims`): a copy that claims an id (opened or
//!   refused authenticated) records `(sender host, id)` and its
//!   `sealed_hash`: the sender's object again is a duplicate with the first
//!   verdict, its id with another sealed part a refusal (`id_reused`, its
//!   sender and id kept, unreported), the first standing; an
//!   unauthenticated refusal's same bytes again are a duplicate of it.
//!   Duplicates are marked done and record nothing.
//! - **Back-pressure, never loss** (ruling R31, [`Limits`]): an opened
//!   envelope or a result that doesn't fit its inbox (its sender's share,
//!   or all) is left on the Station, charged to its sender's own Station
//!   quota: no row, no claim, no done. The page records the lowest such
//!   position (and the room freed when the first of them was left, and
//!   when the last of them expires); once room has freed since (an inbox
//!   row or a kept result gone), or `D` passed that expiry (the Station has
//!   dropped them), the cursor is rewound durably to just before it
//!   ([`rewind_if_room`]) and it is read again. A request, cancel or
//!   complete left there isn't committed: the gate's mailbox part stays
//!   closed until a read after the rewind passes its position (the highest
//!   such position this read left there, `skip_inbox_now`, folded at the
//!   rewind into the highest awaiting the re-read, `skip_inbox`); a result
//!   left there holds no gate (ruling R35: results start no work).
//! - **Bounded** ([`Limits`], [`prune`]): refusals keep their bytes within
//!   a budget (unauthenticated first, then unreported, the oldest first;
//!   the evidence hash stays) and unauthenticated refusal rows within a
//!   count; claims, refusals and results are pruned [`KEEP_MARGIN_MS`]
//!   after their object's expiry.
//! - **The pending limits** (design II.4.2): 64 per claimed `(host_id,
//!   host_trust_gen)` and 256 in all; one over either is dropped undecided
//!   (no verdict, no row, no id) and marked done all the same (Atem's
//!   refinement, agreed with Astation 2026-11-16). A waiting object is
//!   judged again after the device list advances or its expiry passes
//!   ([`rejudge_pending`]); decided, it owes a done only at a position of
//!   the mailbox read now: a reset detaches it from its old one. One that
//!   decides to open with no room for it keeps waiting, marked (`no_room`:
//!   it holds the gate's mailbox part, as a request, cancel or complete
//!   left on the Station does; ruling R39: only one waiting for a newer
//!   sender generation holds none), and is judged again once room frees
//!   ([`freed`] moves).
//! - **A reset** ([`mark_reset`], rule 7): marked durably before anything
//!   is asked for it, as the cursor itself (the announced mailbox at
//!   position 0, nothing read in it yet), the dones owed to the old mailbox
//!   dropped, every waiting object detached from its position and any
//!   position left on the Station forgotten, in one transaction. A start finds it and reads on
//!   from there; the gate's mailbox part stays closed until the read
//!   reaches the announced head.
//! - **An object that can't be decided now** (the key provider failed):
//!   nothing of its page commits ([`Commit::Undecided`]); asked again.
use super::mailbox::Observed;
use super::sync::HostIdentity;
use crate::runtime::host_work::Store;
use anyhow::{Result, anyhow};
use atem_client::KeyProvider;
use atem_client::encoding::Hash32;
use atem_client::host_mail::mailbox::{MailboxEntry, MailboxSyncResult};
use atem_client::host_mail::receive::reason::{EXPIRED, MALFORMED};
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

/// What the mailbox keeps at most (anything a sender or the Station can
/// make this host keep is bounded). An object that doesn't fit an inbox is
/// left on the Station (ruling R31: never done, never dropped), charged to
/// its sender's own Station quota, and read again once room frees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The exact bytes refusals keep, in all: beyond it the oldest go
    /// first, unauthenticated before authenticated, unreported before
    /// reported (their evidence hash stays).
    pub evidence_bytes: u64,
    /// Unauthenticated refusal rows kept, at most (the oldest go first:
    /// the same bytes again are refused again, unreported).
    pub unauthenticated: u64,
    /// Opened requests, cancels and completes waiting for admission, per
    /// sender host and in all.
    pub inbox_per_sender: u64,
    pub inbox: u64,
    /// Results kept for the sending host's own check, per (claimed) sender
    /// host and in all, and their bytes in all.
    pub results_per_sender: u64,
    pub results: u64,
    pub result_bytes: u64,
}

impl Default for Limits {
    /// 16 MiB of evidence and 1,024 unauthenticated refusals; the inbox 32
    /// per sender, 128 in all (about 48 MiB at the 240 KiB Message bound);
    /// results 64 per sender, 256 and 64 MiB in all.
    fn default() -> Self {
        Limits {
            evidence_bytes: 16 << 20,
            unauthenticated: 1024,
            inbox_per_sender: 32,
            inbox: 128,
            results_per_sender: 64,
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
        mailbox_id TEXT NOT NULL, cursor INTEGER NOT NULL, skip_at INTEGER,
        skip_freed INTEGER NOT NULL DEFAULT 0, freed INTEGER NOT NULL DEFAULT 0,
        skip_expires INTEGER, skip_inbox INTEGER, read_to INTEGER NOT NULL DEFAULT 0,
        skip_inbox_now INTEGER) WITHOUT ROWID;
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
        at_ms INTEGER NOT NULL, expires_at INTEGER, signed_seq INTEGER,
        held INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS mailbox_refused (
        n INTEGER PRIMARY KEY, evidence TEXT NOT NULL UNIQUE, reason TEXT NOT NULL,
        sender_host TEXT, object_id TEXT, report INTEGER NOT NULL, bytes BLOB,
        keep_until INTEGER NOT NULL, at_ms INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS mailbox_refused_keep ON mailbox_refused(keep_until);
    CREATE INDEX IF NOT EXISTS mailbox_refused_bytes
        ON mailbox_refused((sender_host IS NOT NULL), report, n) WHERE bytes IS NOT NULL;
    CREATE INDEX IF NOT EXISTS mailbox_refused_unauthenticated ON mailbox_refused(n)
        WHERE sender_host IS NULL;
    CREATE INDEX IF NOT EXISTS mailbox_inbox_sender ON mailbox_inbox(sender_host);
    CREATE TRIGGER IF NOT EXISTS mailbox_inbox_freed AFTER DELETE ON mailbox_inbox BEGIN
        UPDATE mailbox_cursor SET freed=freed+1 WHERE one=1;
    END;
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
        bytes BLOB NOT NULL, no_room INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS mailbox_results (
        object_hash TEXT PRIMARY KEY, sender_host TEXT NOT NULL, object_id TEXT NOT NULL,
        mailbox_id TEXT NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
        keep_until INTEGER NOT NULL, at_ms INTEGER NOT NULL) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS mailbox_results_sender ON mailbox_results(sender_host);
    CREATE TRIGGER IF NOT EXISTS mailbox_results_freed AFTER DELETE ON mailbox_results BEGIN
        UPDATE mailbox_cursor SET freed=freed+1 WHERE one=1;
    END;";

/// The columns the mailbox's tables gained after their first shape
/// (review P5: a store made by an earlier build of this mailbox gets them
/// when its tables are made): `(table, column, kind)`. An inbox row's
/// object's expiry and `signed_at_head.seq` are admission's (an early stop
/// is kept until its expiry; the sender's standing is checked again at
/// admission); a row written before them has neither, and admission refuses
/// it (it can't tell when it was signed).
const NEW_COLUMNS: [(&str, &str, &str); 11] = [
    ("mailbox_cursor", "skip_at", "INTEGER"),
    ("mailbox_cursor", "skip_freed", "INTEGER NOT NULL DEFAULT 0"),
    ("mailbox_cursor", "freed", "INTEGER NOT NULL DEFAULT 0"),
    ("mailbox_cursor", "skip_expires", "INTEGER"),
    ("mailbox_cursor", "skip_inbox", "INTEGER"),
    ("mailbox_cursor", "read_to", "INTEGER NOT NULL DEFAULT 0"),
    ("mailbox_cursor", "skip_inbox_now", "INTEGER"),
    ("mailbox_pending", "no_room", "INTEGER NOT NULL DEFAULT 0"),
    ("mailbox_inbox", "expires_at", "INTEGER"),
    ("mailbox_inbox", "signed_seq", "INTEGER"),
    ("mailbox_inbox", "held", "INTEGER NOT NULL DEFAULT 0"),
];

/// The mailbox's tables in `store`, made if missing (a table of an earlier
/// shape gets its new columns first).
pub fn prepare(store: &Store) -> Result<()> {
    let tx = store.immediate()?;
    for (table, column, kind) in NEW_COLUMNS {
        let (made, present): (bool, bool) = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1),
                EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name=?2)",
            [table, column],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if made && !present {
            tx.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"))?;
        }
    }
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
    // Rows admission holds (ruling R47) hold their own sender's task starts
    // only, not the gate.
    let inbox = store
        .db
        .query_row("SELECT count(*) FROM mailbox_inbox WHERE held=0", [], |r| {
            r.get(0)
        })?;
    let held = {
        let mut q = store
            .db
            .prepare("SELECT DISTINCT sender_host FROM mailbox_inbox WHERE held=1")?;
        q.query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let (skipped, rewind_due, skip_expires, skipped_inbox, read_to) = store
        .db
        .query_row(
            "SELECT skip_at IS NOT NULL, skip_at IS NOT NULL AND freed > skip_freed,
                CASE WHEN skip_at IS NOT NULL THEN skip_expires END,
                skip_inbox IS NOT NULL OR skip_inbox_now IS NOT NULL, max(cursor, read_to)
            FROM mailbox_cursor WHERE one=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?
        .unwrap_or((false, false, None, false, 0));
    let owed_count = match &cursor {
        Some((mailbox_id, _)) => store.db.query_row(
            "SELECT count(*) FROM mailbox_dones WHERE mailbox_id=?1",
            [mailbox_id],
            |r| r.get(0),
        )?,
        None => 0,
    };
    Ok(Observed {
        identity: identity.clone(),
        cursor,
        inbox,
        owed: owed_dones(store, identity)?,
        owed_count,
        skipped,
        skipped_inbox,
        read_to,
        waiting_for_room: store.db.query_row(
            "SELECT count(*) FROM mailbox_pending WHERE no_room=1",
            [],
            |r| r.get(0),
        )?,
        rewind_due,
        skip_expires,
        held,
    })
}

/// The cursor at `at` of `mailbox_id`, and the furthest position read in
/// it (`read_to`, ruling R35: a rewind lowers the cursor, never this; a
/// reset sets it to 0, [`mark_reset`]). SQLite reads every right-hand side
/// on the row as it was.
fn set_cursor(tx: &Transaction, identity: &HostIdentity, mailbox_id: &str, at: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO mailbox_cursor(one, identity, mailbox_id, cursor, read_to)
        VALUES(1, ?1, ?2, ?3, ?3)
        ON CONFLICT(one) DO UPDATE SET identity=excluded.identity,
            mailbox_id=excluded.mailbox_id, cursor=excluded.cursor,
            read_to=CASE WHEN mailbox_id=excluded.mailbox_id
                THEN max(read_to, excluded.cursor) ELSE excluded.cursor END",
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
    tx.execute(
        "UPDATE mailbox_cursor SET skip_at=NULL, skip_expires=NULL, skip_inbox=NULL,
            skip_inbox_now=NULL, read_to=0 WHERE one=1",
        [],
    )?;
    tx.execute("DELETE FROM mailbox_dones", [])?;
    tx.execute("UPDATE mailbox_pending SET mailbox_id=''", [])?;
    tx.commit()?;
    Ok(())
}

/// Ruling R31: once room has freed (an inbox row or a kept result gone)
/// since an object was left on the Station for want of it, or once `D`
/// (`now_ms`) passed the expiry of every object left there (review P4: the
/// Station has dropped them), the cursor is rewound durably to just before
/// the lowest such position, under the same mailbox (its positions and
/// owed dones stand), so the next page reads it again: objects decided
/// meanwhile come back as duplicates and are done again, waiting ones are
/// re-pointed, gone ones are no longer listed. Whether it did.
pub fn rewind_if_room(store: &Store, identity: &HostIdentity, now_ms: u64) -> Result<bool> {
    let tx = store.immediate()?;
    own_cursor(&tx, identity)?;
    // The requests, cancels and completes this read left there now await
    // the re-read (review finding 1): folded into those awaiting it.
    let rewound = tx.execute(
        "UPDATE mailbox_cursor SET cursor=min(cursor, skip_at - 1), skip_at=NULL,
            skip_expires=NULL,
            skip_inbox=CASE WHEN skip_inbox_now IS NULL THEN skip_inbox
                ELSE max(coalesce(skip_inbox, 0), skip_inbox_now) END,
            skip_inbox_now=NULL
        WHERE one=1 AND skip_at IS NOT NULL
            AND (freed > skip_freed OR skip_expires <= ?1)",
        [now_ms],
    )?;
    tx.commit()?;
    Ok(rewound > 0)
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
    /// No room for it (ruling R31): left on the Station, not done, no row
    /// and no claim; read again once room frees.
    Skipped,
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
    // The lowest position left on the Station, and when the last of them
    // expires; the highest of them that is a request, cancel or complete
    // (ruling R35: only those hold the gate).
    let mut skipped: Option<(u64, u64)> = None;
    let mut skipped_inbox: Option<u64> = None;
    for entry in &page.objects {
        let Some(cx) = decide else {
            return Ok(Commit::Undecided);
        };
        let Some(decision) = decide_entry(&tx, entry, cx, &page.mailbox_id)? else {
            return Ok(Commit::Undecided);
        };
        match decision {
            Decision::Pending => {}
            Decision::Skipped => {
                // Never past the longest life after now (as `keep_until`).
                let longest = decide.map_or(0, |cx| cx.now_ms.saturating_add(LONGEST_LIFE_MS));
                let mail = entry
                    .parse_object()
                    .ok()
                    .and_then(|o| MailBody::from_object(&o).ok());
                let expires = mail
                    .as_ref()
                    .map_or(longest, |(_, body)| body.expires_at.min(longest));
                skipped = Some(match skipped {
                    None => (entry.position, expires),
                    Some((at, until)) => (at.min(entry.position), until.max(expires)),
                });
                // Only an envelope is ever skipped for want of inbox room;
                // a result for want of the results' room.
                if mail.is_some_and(|(kind, _)| kind == MailKind::Envelope) {
                    skipped_inbox = skipped_inbox.max(Some(entry.position));
                }
            }
            _ => owe_done(&tx, &page.mailbox_id, entry.position)?,
        }
        decided.push(decision);
    }
    set_cursor(&tx, identity, &page.mailbox_id, page.through)?;
    // Ruling R35: a request, cancel or complete left on the Station holds
    // the gate until a read after a rewind covers its position again. Two
    // kinds (review finding 1): those an earlier read left there, awaiting
    // this re-read (`skip_inbox`, the highest of them: a page covering it
    // re-read them all; a later page of the same read only moves on), and
    // those this read leaves there (`skip_inbox_now`), which only the next
    // rewind folds into the first, so a re-read leaving one there again
    // never loses it to a higher one read since.
    tx.execute(
        "UPDATE mailbox_cursor SET skip_inbox=NULL
        WHERE one=1 AND skip_inbox > ?1 AND skip_inbox <= ?2",
        [page.after, page.through],
    )?;
    if let Some(at) = skipped_inbox {
        tx.execute(
            "UPDATE mailbox_cursor SET skip_inbox_now=max(coalesce(skip_inbox_now, 0), ?1)
            WHERE one=1",
            [at],
        )?;
    }
    if let Some((at, expires)) = skipped {
        // The lowest position left on the Station; the room freed so far
        // when the first of them was left (review P2: a later skip keeps
        // the room freed since an earlier one: only room freed after the
        // first rewinds); the latest expiry of them (P4). SQLite reads
        // every right-hand side on the row as it was.
        tx.execute(
            "UPDATE mailbox_cursor SET
                skip_freed=CASE WHEN skip_at IS NULL THEN freed ELSE skip_freed END,
                skip_expires=CASE WHEN skip_at IS NULL THEN ?2
                    ELSE max(coalesce(skip_expires, 0), ?2) END,
                skip_at=min(coalesce(skip_at, ?1), ?1)
            WHERE one=1",
            [at, expires],
        )?;
    }
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
            Err(_) => refuse(
                &tx,
                cx,
                &Hash32::of(&bytes),
                MALFORMED,
                None,
                false,
                &bytes,
                None,
            )?,
            Ok(object) => match too_late(&tx, cx, &object, &bytes)? {
                Some(decision) => decision,
                None => {
                    let verdict =
                        open_envelope(&object, cx.list, cx.recipient, cx.provider, cx.now_ms);
                    if matches!(
                        verdict,
                        EnvelopeVerdict::Pending { .. } | EnvelopeVerdict::Unavailable { .. }
                    ) {
                        continue;
                    }
                    match record(&tx, cx, &object, &bytes, verdict, &mailbox_id, position)? {
                        None => continue,
                        // No room for it: it keeps waiting (never done), and
                        // holds the gate's mailbox part as a request, cancel
                        // or complete left on the Station does (review
                        // finding 2, ruling R39; only waiting for a newer
                        // sender generation holds none).
                        Some(Decision::Skipped) => {
                            tx.execute(
                                "UPDATE mailbox_pending SET no_room=1 WHERE object_hash=?1",
                                [&hash],
                            )?;
                            continue;
                        }
                        Some(decision) => decision,
                    }
                }
            },
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

/// The room freed so far (every inbox row and kept result gone counts):
/// a waiting object that decided to open with no room for it is judged
/// again once it moved (review P1).
pub fn freed(store: &Store) -> Result<u64> {
    Ok(store
        .db
        .query_row("SELECT freed FROM mailbox_cursor WHERE one=1", [], |r| {
            r.get(0)
        })
        .optional()?
        .unwrap_or(0))
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
            return refuse(
                tx,
                cx,
                &Hash32::of(bytes),
                MALFORMED,
                None,
                false,
                bytes,
                None,
            )
            .map(Some);
        }
    };
    if let Some(decision) = too_late(tx, cx, &object, bytes)? {
        return Ok(Some(decision));
    }
    let (kind, body) = MailBody::from_object(&object)?;
    if kind == MailKind::Result {
        return keep_result(tx, cx, &object, &body, bytes, mailbox_id, entry.position).map(Some);
    }
    let verdict = open_envelope(&object, cx.list, cx.recipient, cx.provider, cx.now_ms);
    record(tx, cx, &object, bytes, verdict, mailbox_id, entry.position)
}

/// A copy arriving [`KEEP_MARGIN_MS`] or more after its object's expiry
/// (review O3): done as expired, not judged: evidence only, no claim, no
/// report (its claim may have been pruned; one made now would contradict
/// the first verdict). Admission still dedupes a request's `(sender host,
/// message id)` against its own permanent records.
fn too_late(
    tx: &Transaction,
    cx: &DecideCx,
    object: &atem_client::SignedObject,
    bytes: &[u8],
) -> Result<Option<Decision>> {
    let (_, body) = MailBody::from_object(object)?;
    if body.expires_at.saturating_add(KEEP_MARGIN_MS) > cx.now_ms {
        return Ok(None);
    }
    let evidence = object_hash(object);
    refuse(
        tx,
        cx,
        &evidence,
        EXPIRED,
        None,
        false,
        bytes,
        Some(body.expires_at),
    )
    .map(Some)
}

/// An `atem-result` kept (ruling R28): its exact bytes, `object_hash`,
/// sender, id and position, for the sending host's `accept_result`; the
/// same object again is a duplicate; with no room for it in its sender's
/// share or in all ([`Limits`]) it is left on the Station (ruling R31).
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
    // Expired on `D`: never delivered (design II.4.4, one that expired
    // unread isn't), so done as expired whatever the room. Skipped, its skip
    // would end at once (at its expiry) and it would be read again unpaced.
    if body.expires_at <= cx.now_ms {
        let evidence = object_hash(object);
        return refuse(
            tx,
            cx,
            &evidence,
            EXPIRED,
            None,
            false,
            bytes,
            Some(body.expires_at),
        );
    }
    let (count, of_sender, kept): (u64, u64, u64) = tx.query_row(
        "SELECT count(*), count(CASE WHEN sender_host=?1 THEN 1 END),
            coalesce(sum(length(bytes)), 0) FROM mailbox_results",
        [&body.sender.host_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if count >= cx.limits.results
        || of_sender >= cx.limits.results_per_sender
        || kept + bytes.len() as u64 > cx.limits.result_bytes
    {
        return Ok(Decision::Skipped);
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
            refuse(tx, cx, &evidence, reason, None, false, bytes, expires)?
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
        EnvelopeVerdict::Open { plain, .. } => match claimed(tx, cx, &body, &hash, bytes)? {
            // The sender's resend of a request admission decided: its
            // status goes again (ruling R45: the Station may have lost it).
            Some(Decision::Duplicate) if matches!(plain, EnvelopePlain::Request { .. }) => {
                super::admit::resend_status(tx, &body.sender.host_id, &body.id)?;
                Decision::Duplicate
            }
            Some(other) => other,
            // No room in its sender's share or in all: left on the Station,
            // unclaimed (ruling R31).
            None if !inbox_room(tx, cx, &body.sender.host_id)? => Decision::Skipped,
            None => {
                claim(tx, cx, &body)?;
                let kind = match &plain {
                    EnvelopePlain::Request { .. } => "request",
                    EnvelopePlain::Cancel { .. } => "cancel",
                    EnvelopePlain::Complete { .. } => "complete",
                };
                tx.execute(
                    "INSERT INTO mailbox_inbox(sender_host, object_id, kind, plain, object_hash, at_ms,
                        expires_at, signed_seq) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        body.sender.host_id,
                        body.id,
                        kind,
                        plain.to_bytes()?.as_slice(),
                        hash.to_hex(),
                        now_ms(),
                        body.expires_at,
                        body.signed_at_head.seq
                    ],
                )?;
                Decision::Opened
            }
        },
        EnvelopeVerdict::RefusedAuthenticated { reason, .. } => {
            match claimed(tx, cx, &body, &hash, bytes)? {
                Some(other) => other,
                None => {
                    claim(tx, cx, &body)?;
                    refuse(tx, cx, &hash, reason, Some(&body), true, bytes, expires)?
                }
            }
        }
    }))
}

/// What the sender's verified copy is when its `(sender host, id)` is
/// claimed already: a duplicate (the same sealed part), or a reused id
/// (another: evidence with its sender and id, unreported); none when it
/// isn't claimed.
fn claimed(
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
        None => Ok(None),
        Some(sealed) if sealed == body.sealed_hash.to_hex() => Ok(Some(Decision::Duplicate)),
        Some(_) => refuse(
            tx,
            cx,
            hash,
            ID_REUSED,
            Some(body),
            false,
            bytes,
            Some(body.expires_at),
        )
        .map(Some),
    }
}

/// The claim of the sender's verified copy, `(sender host, id)`.
fn claim(tx: &Transaction, cx: &DecideCx, body: &MailBody) -> Result<()> {
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
    Ok(())
}

/// Whether the inbox has room for one more of `sender`'s objects: within
/// its share and in all ([`Limits`]).
fn inbox_room(tx: &Transaction, cx: &DecideCx, sender: &str) -> Result<bool> {
    let (all, of_sender): (u64, u64) = tx.query_row(
        "SELECT count(*), count(CASE WHEN sender_host=?1 THEN 1 END) FROM mailbox_inbox",
        [sender],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(all < cx.limits.inbox && of_sender < cx.limits.inbox_per_sender)
}

/// A refusal row under `evidence`, its bytes within the evidence budget
/// ([`Limits::evidence_bytes`]): `body` for the sender's own verified copy
/// (its sender and id recorded), `report` when admission reports it. The
/// same evidence again is a duplicate, unless this is the sender's own copy
/// claiming its id now, to report, while that row says nothing to report
/// (the same bytes refused before they could be verified): the row is
/// upgraded to report it (review finding 4). Unauthenticated rows are
/// capped by count ([`Limits::unauthenticated`]), the oldest dropped.
#[allow(clippy::too_many_arguments)]
fn refuse(
    tx: &Transaction,
    cx: &DecideCx,
    evidence: &Hash32,
    reason: &'static str,
    body: Option<&MailBody>,
    report: bool,
    bytes: &[u8],
    expires_at: Option<u64>,
) -> Result<Decision> {
    let reported: Option<bool> = tx
        .query_row(
            "SELECT report FROM mailbox_refused WHERE evidence=?1",
            [evidence.to_hex()],
            |r| r.get(0),
        )
        .optional()?;
    match (reported, body.filter(|_| report)) {
        (None, _) => {
            tx.execute(
                "INSERT INTO mailbox_refused(evidence, reason, sender_host, object_id, report,
                    bytes, keep_until, at_ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    evidence.to_hex(),
                    reason,
                    body.map(|b| b.sender.host_id.as_str()),
                    body.map(|b| b.id.as_str()),
                    report,
                    bytes,
                    cx.keep_until(expires_at),
                    now_ms()
                ],
            )?;
            if body.is_none() {
                tx.execute(
                    "DELETE FROM mailbox_refused WHERE sender_host IS NULL AND n NOT IN
                    (SELECT n FROM mailbox_refused WHERE sender_host IS NULL
                        ORDER BY n DESC LIMIT ?1)",
                    [cx.limits.unauthenticated],
                )?;
            }
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

/// The refusals' kept bytes within `budget`: unauthenticated before
/// authenticated (review O4: a reused id's bytes are the sender's own
/// signature over two sealed parts), unreported before reported, the
/// oldest first; their evidence hash stays.
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
                WHERE bytes IS NOT NULL ORDER BY (sender_host IS NOT NULL), report, n LIMIT 1)",
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

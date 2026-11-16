//! The receiving host's mailbox in its host-work store (host-work-v1
//! §11.5, "The mailbox calls", rules 4, 5 and 7; the delegated host-work
//! design II.4.2, II.4.3), behind the debug-only hook's `host.senders`:
//! its tables are made only then ([`prepare`]), so a store of a host
//! without it is main's.
//!
//! - **The cursor** (`mailbox_cursor`, one row): the mailbox read, its
//!   last position processed, and the host identity it belongs to
//!   (account, device, trust generation and the device list's genesis).
//!   A new identity's store is a new file (host-work's store is moved
//!   aside), so it starts empty; a row of another identity in this store
//!   doesn't load ([`read`]: fail closed).
//! - **Each page in one transaction** ([`commit_page`], `BEGIN IMMEDIATE`):
//!   only from the store's own cursor (a page continuing another cursor or
//!   mailbox commits nothing: [`Commit::Stale`]), the cursor moved to the
//!   page's `through`.
//! - **A reset** ([`mark_reset`], rule 7): marked durably before anything
//!   is asked for it, as the cursor itself: the announced mailbox at
//!   position 0, in one transaction. A start finds it and reads on from
//!   there; the gate's mailbox part stays closed until the read reaches
//!   the announced head.
use super::mailbox::Observed;
use super::sync::HostIdentity;
use crate::runtime::host_work::Store;
use anyhow::{Result, anyhow};
use atem_client::host_mail::mailbox::MailboxSyncResult;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::json;

/// The mailbox's tables, made by [`prepare`] (only with `host.senders`).
/// Additive, as every host-work table.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS mailbox_cursor (
        one INTEGER PRIMARY KEY CHECK (one = 1), identity TEXT NOT NULL,
        mailbox_id TEXT NOT NULL, cursor INTEGER NOT NULL) WITHOUT ROWID;";

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
    Ok(Observed {
        identity: identity.clone(),
        cursor: own_cursor(&store.db, identity)?,
        inbox: 0,
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
/// `mailbox_id`.
pub fn mark_reset(store: &Store, identity: &HostIdentity, mailbox_id: &str) -> Result<()> {
    let tx = store.immediate()?;
    own_cursor(&tx, identity)?;
    set_cursor(&tx, identity, mailbox_id, 0)?;
    tx.commit()?;
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
    /// An object couldn't be decided now (a local failure, the device list
    /// not serving, no clock): nothing committed; asked again later.
    Undecided,
}

/// A committed page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Committed {}

/// What objects are decided with (the next commit adds it).
pub struct DecideCx {}

/// `page` of `identity`'s mailbox, in one `BEGIN IMMEDIATE` transaction
/// (rule 4): only from the store's own cursor, which moves to `through`.
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
    if !page.objects.is_empty() && decide.is_none() {
        return Ok(Commit::Undecided);
    }
    set_cursor(&tx, identity, &page.mailbox_id, page.through)?;
    tx.commit()?;
    Ok(Commit::Committed(Committed::default()))
}

#[cfg(test)]
#[path = "mailbox_store_tests.rs"]
mod tests;

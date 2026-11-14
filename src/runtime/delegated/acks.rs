//! The host's acknowledgments of control records to its own Station
//! (host-work-v1 §11.4 "Acknowledgments", wire rules 9 and 10 (O5); the
//! delegated host-work design I.5.5, I.5.8 "Acknowledgment" and "Delivery
//! progress is not application"; step 4's Decision 20): the results a host
//! owes its Station, written in the transaction that applies their records,
//! sent once it committed, and sent again as §11.4 says. Only with
//! `host.delegated` on: the book and its table exist only then (the feed
//! store's [`super::feeds::FeedStore::with_acks`]).
//!
//! - **Durable before acknowledged.** A record's result is written in the
//!   record's own transaction (the feed store's `FeedTx`:
//!   [`AckBook::on_committed`]) with its effects, its intents and the scan
//!   cursor, and goes only once that transaction committed: the bridge
//!   sends at the end of its Station step, after the records' followups
//!   (a revoke's session-v1 fence included). A crash at any point loses no
//!   result: a row stays until a connection took it with no refusal, and a
//!   restart sends what the book holds again. A sent mark that can't be
//!   written is kept in memory: nothing goes again on that connection.
//! - **What a result says.** Exactly the state's per-effect results for
//!   that application (`Applied::effects`; a re-verified pending record's
//!   `Reapplied::applied.effects`): each effect not in force with the
//!   state's reason (O5), written by the shared core's builder
//!   (`ControlAck::to_json`), never `write_intent`'s boolean. The same
//!   record applied again (a `pending` one that applies, a `duplicate`) is
//!   acknowledged again with that result. A collision (the state's verdict,
//!   `Why::Collision`: another body under a `record_id` its principal's
//!   record counted with) is never kept, whether or not the first body's
//!   result still is: logged once, acknowledged nowhere, so it can't make
//!   the Station refuse an ack carrying others. Another body the state
//!   took as no collision (the body held never counted: `pending` or
//!   `refused`) replaces the result held, and goes in an ack of its own
//!   (the Station may track the first body under that id). A row that
//!   doesn't read, or that the writer wouldn't take, is skipped, kept as it
//!   is, and logged once with no content.
//! - **What an ack names.** The host's own claim (the account, the root,
//!   the host id and trust generation of the identity its store is bound
//!   to), and the host's own Station's feed and its cursor as committed now,
//!   whatever feed a result's record was read from (wire rule 9): a
//!   feedless result (a record carried over a channel), and a re-verified
//!   one whose feed a reset has replaced since (**Atem's reading, for
//!   Astation**: a result names its record, the ack's feed and cursor say
//!   how far the host reads the feed it reads now). A result read from
//!   another Station's feed (one the host has left) is dropped unsent: the
//!   host has no link to that Station.
//! - **Resends** (§11.4). In-force results (`applied` or `duplicate`) of
//!   `revoke` and `interrupt_running` records are kept: a service's own
//!   revoke's (signed with its key) is sent again on every connection and
//!   every [`RESEND_EVERY_MS`] on `D` until its `issued_at` plus
//!   [`RESEND_FOR_MS`], then dropped; any other (a native's record, an
//!   `interrupt_running`) once per connection. Every other result goes once,
//!   and stays until its connection ends with no `control_ack_refused` (or
//!   [`ONCE_KEPT_MS`] pass on it with none); on a refused connection it goes
//!   again on the next, and after a restart once more.
//!   **Bounded (Atem's reading, for Astation):** at most
//!   [`RESENT_PER_PRINCIPAL`] results of a principal that are entirely
//!   `duplicate`, once per connection, are kept for resending, its first
//!   ones (§11.4 says "at most once per connection"; the Station counts
//!   each effect once per host, whichever record said so), so a Station
//!   that re-issues stops without end can't grow the book. A result that
//!   puts an effect in force (`applied`: once per effect) and a service's
//!   own revoke (bounded by its 25 hours) are always kept (review I1).
//! - **A connection** is a link generation on its socket
//!   ([`StationLink`]): a restart, a reconnection and a re-authentication
//!   each start a new one.
//! - **A refusal** (`control_ack_refused`, Decision 20) advances nothing
//!   here: no result is taken as delivered, dropped or moved on; the sync
//!   closes the gates. **Atem's reading:** nothing more is sent on the
//!   connection the refused ack went on (an ack's claim is its link's
//!   association or it isn't, so the next one there would be refused too,
//!   and closing the gates again with each); the book goes on at the next
//!   connection, where everything sent on the refused one goes again: its
//!   results read as never sent (in memory; ruling T36b, N4), so a second
//!   refused connection in a row that never took one loses none.
//! - **The cursor** ("the ack of the cursor itself goes on"). An ack also
//!   goes when the committed cursor moved since the last ack of this run,
//!   with whatever results are due (none, for a page with no record).
//! - **A new host identity's store** reads its feed from 0 and acknowledges
//!   what it applied itself (**Atem's reading, for Astation and
//!   Auth/Portal**): a stop applied under the previous identity is
//!   `applied` again under the new one, never `duplicate` from another
//!   store; the old store's results go aside with it, unsent ones
//!   included. The Station counts per host and effect, so nothing counts
//!   twice.
use super::station::StationLink;
use anyhow::{Context, Result, anyhow};
use atem_client::control::relay::MAX_ACK_RESULTS;
use atem_client::control::{
    AckResult, ApplicationResult, Applied, ControlAck, ControlAction, ControlPrincipal,
    ControlRecord, ControlSigner, EffectKind, EffectResult, EffectWhy, FeedPos, Why,
};
use atem_client::encoding::Hash32;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// A service's own revoke's in-force result is sent again this often while
/// connected (§11.4), on `D`.
pub const RESEND_EVERY_MS: u64 = 600_000;
/// ...until this long after its `issued_at` (§11.4: the latest deadline of
/// the ledger's revocation, 24 hours after a start at most an hour after
/// `issued_at`, plus an hour), on `D`.
pub const RESEND_FOR_MS: u64 = 25 * 3_600_000;
/// A principal's results kept for resending that are entirely `duplicate`
/// and go once per connection, at most (review I1: one that puts an effect
/// in force, and a service's own revoke, are always kept; the module docs).
pub const RESENT_PER_PRINCIPAL: usize = 4;
/// A result that goes once leaves the book this long (on `D`) after it went
/// on a connection that no `control_ack_refused` came on, if that connection
/// lasts (a refusal answers an ack at once); else when the connection ends.
pub const ONCE_KEPT_MS: u64 = 600_000;

/// The book's table, made with the book (`host.delegated` on only).
/// `resend_until_ms`: 0, sent once; `NULL`, once per connection; else
/// every connection and every 10 minutes until then, on `D`. `sent_gen`
/// and `sent_ms`: the link generation and `D` of its last send (`NULL`:
/// never sent).
/// `digest`: the hex SHA-256 of the record's body's `jcs`, the body whose
/// result the row holds (review m2). `alone`: 1 when it replaced another
/// body's result under its `record_id` (ruling T36b, N2): it goes in an ack
/// of its own.
const TABLE: &str = "CREATE TABLE IF NOT EXISTS control_acks (
    origin TEXT NOT NULL, feed_id TEXT NOT NULL, key TEXT NOT NULL, principal TEXT NOT NULL,
    digest TEXT NOT NULL, effects TEXT NOT NULL, resend_until_ms INTEGER, sent_gen INTEGER,
    sent_ms INTEGER, alone INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(principal, key))";

/// How often a result is sent again (the module docs). Ordered: what a
/// result is kept for is the most of what its applications ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resend {
    /// Once: not in force, or not a stop's.
    Once,
    /// Once per connection.
    PerConnection,
    /// A service's own revoke's: every connection and every
    /// [`RESEND_EVERY_MS`] until this `D` (its `issued_at` plus
    /// [`RESEND_FOR_MS`]).
    Until(u64),
}

impl Resend {
    /// How `record`'s result, `applied`, is sent again.
    fn of(record: &ControlRecord, applied: &Applied) -> Resend {
        let in_force = applied.effects.iter().any(|e| {
            matches!(
                e.result,
                ApplicationResult::Applied | ApplicationResult::Duplicate
            )
        });
        let action = record.action();
        let stop = matches!(
            action,
            ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. }
        );
        if !(in_force && stop) {
            return Resend::Once;
        }
        let own_revoke = matches!(record.principal(), ControlPrincipal::Service(_))
            && matches!(record.signer(), ControlSigner::Principal)
            && matches!(action, ControlAction::Revoke { .. });
        if own_revoke {
            Resend::Until(record.issued_at().saturating_add(RESEND_FOR_MS))
        } else {
            Resend::PerConnection
        }
    }

    fn stored(self) -> Option<i64> {
        match self {
            Resend::Once => Some(0),
            Resend::PerConnection => None,
            Resend::Until(until) => Some(i64::try_from(until).unwrap_or(i64::MAX)),
        }
    }

    fn read(stored: Option<i64>) -> Option<Resend> {
        match stored {
            None => Some(Resend::PerConnection),
            Some(0) => Some(Resend::Once),
            Some(until) => u64::try_from(until).ok().map(Resend::Until),
        }
    }
}

/// One record's result as the record's transaction gives it, for the book
/// ([`AckBook::on_committed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acked {
    /// The feed it was read from: its Station's origin and `feed_id`;
    /// empty for a record read at no position (carried over a channel).
    pub origin: String,
    pub feed_id: String,
    /// `service:<id>` or `host:<host_id>`.
    pub principal: String,
    pub record_id: String,
    /// SHA-256 of the record's body's `jcs`: which body under `record_id`.
    pub digest: Hash32,
    /// Every effect the record carries with its result, in the record's
    /// order, each not in force with its reason (O5): the state's own.
    pub effects: Vec<EffectResult>,
    pub resend: Resend,
    /// The state took it as a collision (`Why::Collision`, ruling T36b,
    /// N2): never kept.
    pub collision: bool,
}

impl Acked {
    /// `record`'s result, as `applied` gives it, read at `pos`.
    pub fn of(record: &ControlRecord, applied: &Applied, pos: Option<&FeedPos>) -> Acked {
        Acked {
            origin: pos.map_or_else(String::new, |p| p.origin.clone()),
            feed_id: pos.map_or_else(String::new, |p| p.feed_id.clone()),
            principal: record.principal().name(),
            record_id: record.record_id().to_owned(),
            digest: Hash32::of(record.object().jcs().as_bytes()),
            effects: applied.effects.clone(),
            resend: Resend::of(record, applied),
            collision: applied.why == Some(Why::Collision),
        }
    }
}

/// The host's claim an ack carries: the identity its store is bound to,
/// and the device list's root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub host_trust_gen: u64,
}

/// An ack due now ([`AckBook::due`]), and the results it carries; hand it
/// back to [`AckBook::sent`] once the link took it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueAck {
    pub ack: ControlAck,
    /// Its results' rows: `(principal, record_id)`.
    rows: Vec<(String, String)>,
}

/// A connection: a link generation and its socket.
type Link = (u64, u64);

/// When a result last went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    Never,
    /// On a connection of an earlier run: any connection of this run is
    /// another.
    Earlier,
    /// On `link`, at `D` = `at_ms` (`None`: no reading then).
    On {
        link: Link,
        at_ms: Option<u64>,
    },
}

/// One result the book holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    origin: String,
    feed_id: String,
    principal: String,
    record_id: String,
    digest: Hash32,
    effects: Vec<EffectResult>,
    resend: Resend,
    sent: Sent,
    /// It replaced another body's result under its `record_id` (ruling
    /// T36b, N2): it goes in an ack of its own.
    alone: bool,
}

impl Row {
    /// Due on `link` at `now_d`; `held`: the connection a refusal came on.
    fn due(&self, link: Link, held: Option<Link>, now_d: Option<u64>) -> bool {
        let on_this = matches!(self.sent, Sent::On { link: l, .. } if l == link);
        match self.resend {
            _ if self.sent == Sent::Never => true,
            // Once more after a restart (whether its connection was refused
            // isn't known), and on the connection after a refused one
            // (review m1).
            Resend::Once => match self.sent {
                Sent::Earlier => true,
                Sent::On { link: l, .. } => l != link && Some(l) == held,
                Sent::Never => true,
            },
            Resend::PerConnection => !on_this,
            Resend::Until(until) => {
                if now_d.is_some_and(|d| d >= until) {
                    return false;
                }
                if !on_this {
                    return true;
                }
                match (self.sent, now_d) {
                    (
                        Sent::On {
                            at_ms: Some(at), ..
                        },
                        Some(d),
                    ) => d < at || d >= at.saturating_add(RESEND_EVERY_MS),
                    // Sent with no reading, one now: the ten minutes start.
                    (Sent::On { at_ms: None, .. }, Some(_)) => true,
                    _ => false,
                }
            }
        }
    }

    /// Done with for good, on `link` at `now_d` (`held`: the connection a
    /// refusal came on): one that goes once, sent on a connection that
    /// ended with no refusal, or that lasted [`ONCE_KEPT_MS`] with none
    /// (review m1); one past its resends.
    fn spent(&self, link: Link, held: Option<Link>, now_d: Option<u64>) -> bool {
        match (self.resend, self.sent) {
            (_, Sent::Never) | (Resend::Once, Sent::Earlier) => false,
            (Resend::Once, Sent::On { link: l, at_ms }) => {
                Some(l) != held
                    && (l != link
                        || at_ms
                            .zip(now_d)
                            .is_some_and(|(at, d)| d >= at.saturating_add(ONCE_KEPT_MS)))
            }
            (Resend::Until(until), _) => now_d.is_some_and(|d| d >= until),
            (Resend::PerConnection, _) => false,
        }
    }

    /// Leaves the book: spent, or read from another Station's feed than
    /// `link`'s (one the host has left: never sent there).
    fn gone(&self, link: &StationLink, held: Option<Link>, now_d: Option<u64>) -> bool {
        self.spent((link.link_gen, link.socket), held, now_d)
            || (!self.origin.is_empty() && link.origin.as_deref().is_some_and(|o| self.origin != o))
    }

    /// Kept for resending and entirely `duplicate` once per connection: what
    /// the per-principal bound takes (review I1).
    fn bounded(resend: Resend, effects: &[EffectResult]) -> bool {
        resend == Resend::PerConnection
            && effects
                .iter()
                .all(|e| e.result == ApplicationResult::Duplicate)
    }

    fn result(&self) -> AckResult {
        AckResult::Record {
            record_id: self.record_id.clone(),
            effects: self.effects.clone(),
        }
    }
}

/// The results the host owes its own Station (the module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckBook {
    /// In the order they were first written.
    rows: Vec<Row>,
    /// The feed and cursor the last ack of this run named.
    acked: Option<(String, u64)>,
    /// The connection the last ack went on.
    link: Option<Link>,
    /// A refusal came on this connection: nothing more goes on it.
    held: Option<Link>,
    /// The collisions logged, `(principal, record_id)` (ruling T36b, N2:
    /// once each; bounded by the record ids the state counts).
    collisions: BTreeSet<(String, String)>,
    refusals: u64,
    /// Rows that don't read, or that the shared writer wouldn't take: kept
    /// on disk as they are, never sent (review m6).
    unreadable: u64,
    /// Results the shared writer wouldn't take, not kept (none from the
    /// state, which writes only well-formed results).
    unwritable: u64,
    /// `runtime.log` lines not taken yet.
    lines: Vec<String>,
}

impl AckBook {
    /// The book in `db`, its table made if missing.
    pub fn load(db: &Connection) -> Result<AckBook> {
        db.execute_batch(TABLE)?;
        // A table of an earlier build of this branch, made before `alone`.
        let has_alone = db
            .prepare("SELECT 1 FROM pragma_table_info('control_acks') WHERE name='alone'")?
            .exists([])?;
        if !has_alone {
            db.execute_batch(
                "ALTER TABLE control_acks ADD COLUMN alone INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        let mut book = AckBook::default();
        let mut q = db.prepare(
            "SELECT origin, feed_id, key, principal, digest, effects, resend_until_ms, sent_gen,
                alone
            FROM control_acks ORDER BY rowid",
        )?;
        // Each column read as whatever it holds: a row that doesn't read is
        // skipped, never the whole book.
        let rows = q.query_map([], |r| {
            let text = |i| r.get::<_, String>(i).ok();
            Ok((
                (text(0), text(1), text(2), text(3), text(4), text(5)),
                r.get::<_, Option<i64>>(6).ok(),
                r.get::<_, Option<i64>>(7).ok(),
                r.get::<_, i64>(8).ok(),
            ))
        })?;
        for row in rows {
            let read = row.ok().and_then(|(texts, resend, sent, alone)| {
                let (Some(origin), Some(feed_id), Some(record_id), Some(principal)) =
                    (texts.0, texts.1, texts.2, texts.3)
                else {
                    return None;
                };
                let row = Row {
                    origin,
                    feed_id,
                    principal,
                    record_id,
                    digest: Hash32::from_hex(&texts.4?).ok()?,
                    effects: read_effects(&texts.5?).ok()?,
                    resend: Resend::read(resend?)?,
                    sent: if sent?.is_some() {
                        Sent::Earlier
                    } else {
                        Sent::Never
                    },
                    alone: alone? != 0,
                };
                writable(&row.result()).then_some(row)
            });
            match read {
                Some(row) => book.rows.push(row),
                None => book.unreadable += 1,
            }
        }
        if book.unreadable > 0 {
            // Once, with no content.
            book.lines.push(format!(
                "atem runtime: {} control acknowledgment row(s) don't read; kept as they are, never sent",
                book.unreadable
            ));
        }
        Ok(book)
    }

    /// The results of records applied in `tx`, the records' own transaction
    /// (each written there; adopt the book only once `tx` committed). A
    /// record already held, the same body applied again (a `pending` one
    /// that now applies, one served again), is held with its new result,
    /// due again, sent again as the most of what its results ask. A
    /// collision (the state's verdict, ruling T36b, N2) is never kept,
    /// whether or not a result is held under its `record_id`: logged once,
    /// with no content (review m2). Another body the state took as no
    /// collision (the body held never counted) replaces the result held,
    /// in an ack of its own from then on. A principal's first
    /// [`RESENT_PER_PRINCIPAL`] results that are entirely `duplicate` once
    /// per connection are kept for resending, a later one goes once; one
    /// that puts an effect in force, and a service's own revoke, are always
    /// kept (review I1), and a result once kept stays kept when its record
    /// is applied again (ruling T36b, N1): only a new result, or one held
    /// to go once, is capped.
    pub fn on_committed(&mut self, tx: &Connection, results: &[Acked]) -> Result<()> {
        for acked in results {
            if acked.collision {
                let key = (acked.principal.clone(), acked.record_id.clone());
                if !self.collisions.contains(&key) {
                    self.lines.push(format!(
                        "atem runtime: another body under {} record {} isn't acknowledged; the first body's result stands",
                        acked.principal, acked.record_id
                    ));
                    self.collisions.insert(key);
                }
                continue;
            }
            let held = self
                .rows
                .iter()
                .position(|r| r.principal == acked.principal && r.record_id == acked.record_id);
            let result = AckResult::Record {
                record_id: acked.record_id.clone(),
                effects: acked.effects.clone(),
            };
            if !writable(&result) {
                self.unwritable += 1;
                if self.unwritable.is_power_of_two() {
                    self.lines.push(format!(
                        "atem runtime: {} control acknowledgment(s) the shared writer refused; not kept",
                        self.unwritable
                    ));
                }
                continue;
            }
            // Another body than the one held, which the state took as no
            // collision: the body held never counted.
            let replaced = held.is_some_and(|i| self.rows[i].digest != acked.digest);
            let mut resend = match held {
                Some(i) if !replaced => acked.resend.max(self.rows[i].resend),
                _ => acked.resend,
            };
            let cappable = held.is_none_or(|i| replaced || self.rows[i].resend == Resend::Once);
            if Row::bounded(resend, &acked.effects) && cappable {
                let bounded = self
                    .rows
                    .iter()
                    .enumerate()
                    .filter(|(i, r)| {
                        Some(*i) != held
                            && r.principal == acked.principal
                            && Row::bounded(r.resend, &r.effects)
                    })
                    .count();
                if bounded >= RESENT_PER_PRINCIPAL {
                    resend = Resend::Once;
                }
            }
            let alone = replaced || held.is_some_and(|i| self.rows[i].alone);
            let row = Row {
                origin: acked.origin.clone(),
                feed_id: acked.feed_id.clone(),
                principal: acked.principal.clone(),
                record_id: acked.record_id.clone(),
                digest: acked.digest,
                effects: acked.effects.clone(),
                resend,
                sent: Sent::Never,
                alone,
            };
            tx.execute(
                "INSERT INTO control_acks(origin,feed_id,key,principal,digest,effects,resend_until_ms,sent_gen,sent_ms,alone)
                VALUES(?1,?2,?3,?4,?5,?6,?7,NULL,NULL,?8)
                ON CONFLICT(principal,key) DO UPDATE SET origin=excluded.origin,
                    feed_id=excluded.feed_id, digest=excluded.digest, effects=excluded.effects,
                    resend_until_ms=excluded.resend_until_ms, sent_gen=NULL, sent_ms=NULL,
                    alone=excluded.alone",
                params![
                    row.origin,
                    row.feed_id,
                    row.record_id,
                    row.principal,
                    row.digest.to_hex(),
                    effects_text(&row.effects),
                    resend.stored(),
                    i64::from(alone),
                ],
            )?;
            match held {
                Some(i) => self.rows[i] = row,
                None => self.rows.push(row),
            }
        }
        Ok(())
    }

    /// The acks due on `link` at `now_d` (`D`; `None`: no reading, so no
    /// resend by time), naming `feed` (the host's own Station's feed and its
    /// committed cursor; `None`: none read, nothing goes) under `claim`: the
    /// results due, at most [`MAX_ACK_RESULTS`] an ack and a `record_id` once
    /// each, or one ack with none when only the cursor moved. Nothing on a
    /// connection a refusal came on, nor with no link or origin.
    pub fn due(
        &self,
        link: &StationLink,
        feed: Option<(&str, u64)>,
        claim: &Claim,
        now_d: Option<u64>,
    ) -> Vec<DueAck> {
        let id = (link.link_gen, link.socket);
        let (Some(origin), Some((feed_id, cursor))) = (link.origin.as_deref(), feed) else {
            return Vec::new();
        };
        if self.held == Some(id) {
            return Vec::new();
        }
        let due: Vec<&Row> = self
            .rows
            .iter()
            .filter(|r| (r.origin.is_empty() || r.origin == origin) && r.due(id, self.held, now_d))
            .collect();
        let moved = self
            .acked
            .as_ref()
            .is_none_or(|(f, c)| f != feed_id || *c != cursor);
        if due.is_empty() && !moved {
            return Vec::new();
        }
        let ack = |rows: Vec<&Row>| DueAck {
            ack: ControlAck {
                account_id: claim.account_id.clone(),
                genesis_hash: claim.genesis_hash,
                host_id: claim.host_id.clone(),
                host_trust_gen: claim.host_trust_gen,
                origin: origin.to_owned(),
                feed_id: feed_id.to_owned(),
                cursor,
                results: rows.iter().map(|r| r.result()).collect(),
            },
            rows: rows
                .iter()
                .map(|r| (r.principal.clone(), r.record_id.clone()))
                .collect(),
        };
        let mut acks = Vec::new();
        let mut batch: Vec<&Row> = Vec::new();
        let mut ids = BTreeSet::new();
        for row in due {
            // A result that replaced another body's goes alone (ruling
            // T36b, N2): the Station may track the first body's effects
            // under its id and refuse the whole ack carrying it.
            if row.alone {
                acks.push(ack(vec![row]));
                continue;
            }
            if batch.len() == MAX_ACK_RESULTS || ids.contains(row.record_id.as_str()) {
                acks.push(ack(std::mem::take(&mut batch)));
                ids.clear();
            }
            ids.insert(row.record_id.as_str());
            batch.push(row);
        }
        if !batch.is_empty() || acks.is_empty() {
            acks.push(ack(batch));
        }
        acks
    }

    /// `sent`, acks [`AckBook::due`] gave, were handed to `link` at `now_d`:
    /// their results are marked sent there, the cursor they named is the one
    /// acknowledged, and what is spent (one sent once, on a connection that
    /// ended or lasted [`ONCE_KEPT_MS`] with no refusal; a result past its
    /// resends; one read from another Station's feed than `link`'s) leaves
    /// the book, in `tx`. Whether anything changed (else nothing was
    /// written).
    pub fn sent(
        &mut self,
        tx: &Connection,
        link: &StationLink,
        now_d: Option<u64>,
        sent: &[DueAck],
    ) -> Result<bool> {
        let mut changed = false;
        for (principal, record_id) in self.mark_sent(link, now_d, sent) {
            tx.execute(
                "UPDATE control_acks SET sent_gen=?3, sent_ms=?4 WHERE principal=?1 AND key=?2",
                params![
                    principal,
                    record_id,
                    i64::try_from(link.link_gen).unwrap_or(i64::MAX),
                    now_d.map(|d| i64::try_from(d).unwrap_or(i64::MAX)),
                ],
            )?;
            changed = true;
        }
        let gone: Vec<(String, String)> = self
            .rows
            .iter()
            .filter(|r| r.gone(link, self.held, now_d))
            .map(|r| (r.principal.clone(), r.record_id.clone()))
            .collect();
        for (principal, record_id) in &gone {
            tx.execute(
                "DELETE FROM control_acks WHERE principal=?1 AND key=?2",
                params![principal, record_id],
            )?;
        }
        if !gone.is_empty() {
            self.rows
                .retain(|r| !gone.contains(&(r.principal.clone(), r.record_id.clone())));
            changed = true;
        }
        Ok(changed)
    }

    /// [`AckBook::sent`]'s marks in memory alone, as when they couldn't be
    /// written (review m5): the results marked sent on `link` at `now_d`,
    /// so none goes again on it; what leaves the book waits for a write.
    /// The rows marked.
    pub fn mark_sent(
        &mut self,
        link: &StationLink,
        now_d: Option<u64>,
        sent: &[DueAck],
    ) -> Vec<(String, String)> {
        let id = (link.link_gen, link.socket);
        let mut marked = Vec::new();
        for due in sent {
            for (principal, record_id) in &due.rows {
                let Some(row) = self
                    .rows
                    .iter_mut()
                    .find(|r| r.principal == *principal && r.record_id == *record_id)
                else {
                    continue;
                };
                row.sent = Sent::On {
                    link: id,
                    at_ms: now_d,
                };
                marked.push((principal.clone(), record_id.clone()));
            }
            self.acked = Some((due.ack.feed_id.clone(), due.ack.cursor));
            self.link = Some(id);
        }
        marked
    }

    /// Whether [`AckBook::sent`] with nothing sent would remove something:
    /// a result past its resends, or one read from another Station's feed
    /// than `link`'s.
    pub fn tidy_due(&self, link: &StationLink, now_d: Option<u64>) -> bool {
        self.rows.iter().any(|r| r.gone(link, self.held, now_d))
    }

    /// `control_ack_refused` (Decision 20): nothing advances (the module
    /// docs); nothing more goes on the connection the last ack went on, and
    /// what went on it reads as never sent (in memory), so it goes on the
    /// next connection that takes it, however many refused connections
    /// come first (ruling T36b, N4).
    pub fn on_refused(&mut self) {
        self.refusals += 1;
        self.held = self.link;
        if let Some(held) = self.held {
            for row in &mut self.rows {
                if matches!(row.sent, Sent::On { link, .. } if link == held) {
                    row.sent = Sent::Never;
                }
            }
        }
    }

    /// The `runtime.log` lines not taken yet (rows that don't read, a
    /// collision, a result the writer refused).
    pub fn take_lines(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    /// For the state dump (debug builds).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub fn dump(&self) -> Value {
        json!({
            "results": self.rows.len(),
            "unsent": self.rows.iter().filter(|r| r.sent == Sent::Never).count(),
            "acked": self.acked.as_ref().map(|(feed_id, cursor)| json!({"feed_id": feed_id, "cursor": cursor})),
            "held": self.held.is_some() && self.held == self.link,
            "refusals": self.refusals,
            "unreadable": self.unreadable,
        })
    }
}

/// An origin and a feed the writer takes, for [`writable`]: any would do.
const CHECK_ORIGIN: &str = "https://station.agora.build";
const CHECK_FEED: &str = "00000000-0000-4000-8000-000000000000";

/// Whether the shared core's writer takes `result` (its grammar, wire rule
/// 3's effect sets and rule 10's reasons), in an ack of its own (review
/// m6): one it wouldn't take is never put in a batch, where it would take
/// the others down with it.
fn writable(result: &AckResult) -> bool {
    ControlAck {
        account_id: "acct".into(),
        genesis_hash: Hash32([0; 32]),
        host_id: "host".into(),
        host_trust_gen: 1,
        origin: CHECK_ORIGIN.into(),
        feed_id: CHECK_FEED.into(),
        cursor: 0,
        results: vec![result.clone()],
    }
    .to_json()
    .is_ok()
}

/// Effects as the book's table keeps them: the wire's form.
fn effects_text(effects: &[EffectResult]) -> String {
    Value::Array(
        effects
            .iter()
            .map(|e| {
                let mut o = json!({"effect": e.effect.code(), "result": e.result.code()});
                if let Some(why) = &e.why {
                    o["why"] = json!(why.code());
                }
                o
            })
            .collect(),
    )
    .to_string()
}

fn read_effects(text: &str) -> Result<Vec<EffectResult>> {
    let value: Value = serde_json::from_str(text)?;
    value
        .as_array()
        .context("effects aren't a list")?
        .iter()
        .map(|e| {
            let text = |k: &str| {
                e.get(k)
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("an effect without {k}"))
            };
            Ok(EffectResult {
                effect: EffectKind::from_code(text("effect")?).context("an effect")?,
                result: ApplicationResult::from_code(text("result")?).context("a result")?,
                why: match e.get("why") {
                    None => None,
                    Some(why) => Some(
                        why.as_str()
                            .and_then(EffectWhy::read)
                            .context("an effect's reason")?,
                    ),
                },
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "acks_tests.rs"]
mod tests;

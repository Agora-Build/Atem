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
//!   (a revoke's session-v1 fence included). A crash between the commit and
//!   the send loses nothing: the row goes at the next connection.
//! - **What a result says.** Exactly the state's per-effect results for
//!   that application (`Applied::effects`; a re-verified pending record's
//!   `Reapplied::applied.effects`): each effect not in force with the
//!   state's reason (O5), written by the shared core's builder
//!   (`ControlAck::to_json`), never `write_intent`'s boolean. A record
//!   applied again (a `duplicate`) is acknowledged again with that result.
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
//!   `interrupt_running`) once per connection. Every other result goes once.
//!   **Bounded (Atem's reading, for Astation):** at most
//!   [`RESENT_PER_PRINCIPAL`] results of a principal are kept for resending,
//!   its first ones (§11.4 says "at most once per connection"; the Station
//!   counts each effect once per host, whichever record said so, and a
//!   principal's revocation and its interrupt are each put in force once),
//!   so a Station that re-issues stops without end can't grow the book.
//! - **A connection** is a link generation on its socket
//!   ([`StationLink`]): a restart, a reconnection and a re-authentication
//!   each start a new one.
//! - **A refusal** (`control_ack_refused`, Decision 20) advances nothing
//!   here: no result is taken as delivered, dropped or moved on, and no
//!   resend's schedule changes; the sync closes the gates. **Atem's
//!   reading:** nothing more is sent on the connection the refused ack went
//!   on (an ack's claim is its link's association or it isn't, so the next
//!   one there would be refused too, and closing the gates again with
//!   each); the book goes on at the next connection.
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
    ControlRecord, ControlSigner, EffectKind, EffectResult, EffectWhy, FeedPos,
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
/// The in-force results of a principal kept for resending, at most (the
/// module docs).
pub const RESENT_PER_PRINCIPAL: usize = 4;

/// The book's table, made with the book (`host.delegated` on only).
/// `resend_until_ms`: 0, sent once; `NULL`, once per connection; else
/// every connection and every 10 minutes until then, on `D`. `sent_gen`
/// and `sent_ms`: the link generation and `D` of its last send (`NULL`:
/// never sent).
const TABLE: &str = "CREATE TABLE IF NOT EXISTS control_acks (
    origin TEXT NOT NULL, feed_id TEXT NOT NULL, key TEXT NOT NULL, principal TEXT NOT NULL,
    effects TEXT NOT NULL, resend_until_ms INTEGER, sent_gen INTEGER, sent_ms INTEGER,
    PRIMARY KEY(principal, key))";

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
    /// Every effect the record carries with its result, in the record's
    /// order, each not in force with its reason (O5): the state's own.
    pub effects: Vec<EffectResult>,
    pub resend: Resend,
}

impl Acked {
    /// `record`'s result, as `applied` gives it, read at `pos`.
    pub fn of(record: &ControlRecord, applied: &Applied, pos: Option<&FeedPos>) -> Acked {
        Acked {
            origin: pos.map_or_else(String::new, |p| p.origin.clone()),
            feed_id: pos.map_or_else(String::new, |p| p.feed_id.clone()),
            principal: record.principal().name(),
            record_id: record.record_id().to_owned(),
            effects: applied.effects.clone(),
            resend: Resend::of(record, applied),
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
    effects: Vec<EffectResult>,
    resend: Resend,
    sent: Sent,
}

impl Row {
    /// Due on `link` at `now_d`.
    fn due(&self, link: Link, now_d: Option<u64>) -> bool {
        let on_this = matches!(self.sent, Sent::On { link: l, .. } if l == link);
        match self.resend {
            _ if self.sent == Sent::Never => true,
            Resend::Once => false,
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

    /// Done with for good: sent once, or past its resends.
    fn spent(&self, now_d: Option<u64>) -> bool {
        match (self.resend, self.sent) {
            (_, Sent::Never) => false,
            (Resend::Once, _) => true,
            (Resend::Until(until), _) => now_d.is_some_and(|d| d >= until),
            (Resend::PerConnection, _) => false,
        }
    }

    /// Leaves the book: spent, or read from another Station's feed than
    /// `link`'s (one the host has left: never sent there).
    fn gone(&self, link: &StationLink, now_d: Option<u64>) -> bool {
        self.spent(now_d)
            || (!self.origin.is_empty() && link.origin.as_deref().is_some_and(|o| self.origin != o))
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
    refusals: u64,
    /// Rows that don't read: kept on disk, never sent.
    unreadable: u64,
}

impl AckBook {
    /// The book in `db`, its table made if missing.
    pub fn load(db: &Connection) -> Result<AckBook> {
        db.execute_batch(TABLE)?;
        let mut book = AckBook::default();
        let mut q = db.prepare(
            "SELECT origin, feed_id, key, principal, effects, resend_until_ms, sent_gen
            FROM control_acks ORDER BY rowid",
        )?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        })?;
        for row in rows {
            let (origin, feed_id, record_id, principal, effects, resend, sent) = row?;
            match (read_effects(&effects), Resend::read(resend)) {
                (Ok(effects), Some(resend)) => book.rows.push(Row {
                    origin,
                    feed_id,
                    principal,
                    record_id,
                    effects,
                    resend,
                    sent: if sent.is_some() {
                        Sent::Earlier
                    } else {
                        Sent::Never
                    },
                }),
                _ => book.unreadable += 1,
            }
        }
        Ok(book)
    }

    /// The results of records applied in `tx`, the records' own transaction
    /// (each written there; adopt the book only once `tx` committed). A
    /// record already held is held with its new result, due again; it is
    /// sent again as the most of what its results ask, a principal's first
    /// [`RESENT_PER_PRINCIPAL`] kept for resending.
    pub fn on_committed(&mut self, tx: &Connection, results: &[Acked]) -> Result<()> {
        for acked in results {
            let held = self
                .rows
                .iter()
                .position(|r| r.principal == acked.principal && r.record_id == acked.record_id);
            let mut resend = held.map_or(acked.resend, |i| acked.resend.max(self.rows[i].resend));
            let newly_kept = held.is_none_or(|i| self.rows[i].resend == Resend::Once);
            if resend != Resend::Once && newly_kept {
                let kept = self
                    .rows
                    .iter()
                    .filter(|r| r.principal == acked.principal && r.resend != Resend::Once)
                    .count();
                if kept >= RESENT_PER_PRINCIPAL {
                    resend = Resend::Once;
                }
            }
            let row = Row {
                origin: acked.origin.clone(),
                feed_id: acked.feed_id.clone(),
                principal: acked.principal.clone(),
                record_id: acked.record_id.clone(),
                effects: acked.effects.clone(),
                resend,
                sent: Sent::Never,
            };
            tx.execute(
                "INSERT INTO control_acks(origin,feed_id,key,principal,effects,resend_until_ms,sent_gen,sent_ms)
                VALUES(?1,?2,?3,?4,?5,?6,NULL,NULL)
                ON CONFLICT(principal,key) DO UPDATE SET origin=excluded.origin,
                    feed_id=excluded.feed_id, effects=excluded.effects,
                    resend_until_ms=excluded.resend_until_ms, sent_gen=NULL, sent_ms=NULL",
                params![
                    row.origin,
                    row.feed_id,
                    row.record_id,
                    row.principal,
                    effects_text(&row.effects),
                    resend.stored(),
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
            .filter(|r| (r.origin.is_empty() || r.origin == origin) && r.due(id, now_d))
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
    /// their results are marked sent there (one sent once leaves the book),
    /// the cursor they named is the one acknowledged, and what is spent (a
    /// result past its resends, one read from another Station's feed than
    /// `link`'s) leaves the book, in `tx`. Whether anything changed (else
    /// nothing was written).
    pub fn sent(
        &mut self,
        tx: &Connection,
        link: &StationLink,
        now_d: Option<u64>,
        sent: &[DueAck],
    ) -> Result<bool> {
        let id = (link.link_gen, link.socket);
        let mut changed = false;
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
            self.acked = Some((due.ack.feed_id.clone(), due.ack.cursor));
            self.link = Some(id);
        }
        let gone: Vec<(String, String)> = self
            .rows
            .iter()
            .filter(|r| r.gone(link, now_d))
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

    /// Whether [`AckBook::sent`] with nothing sent would remove something:
    /// a result past its resends, or one read from another Station's feed
    /// than `link`'s.
    pub fn tidy_due(&self, link: &StationLink, now_d: Option<u64>) -> bool {
        self.rows.iter().any(|r| r.gone(link, now_d))
    }

    /// `control_ack_refused` (Decision 20): nothing advances (the module
    /// docs); nothing more goes on the connection the last ack went on.
    pub fn on_refused(&mut self) {
        self.refusals += 1;
        self.held = self.link;
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

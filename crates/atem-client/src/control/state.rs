//! Applying control records on a host (delegated host-work design I.5.5),
//! with the per-effect application results it reports (I.5.8, "Delivery
//! progress is not application").
//!
//! [`ControlState`] is a host's control state: pure and deterministic (no
//! clocks, no I/O). The host stores [`ControlState::to_json`] in the same
//! `host-work.sqlite` transaction as the [`HostAction`]s a record's
//! application returns and its scan cursor, and resumes with
//! [`ControlState::from_json`]. A state belongs to one device list (its
//! account and genesis); re-pairing starts a new one (II.3.1, "After a
//! freeze").
//!
//! **Verified in the transaction.** [`ControlState::apply`] verifies the
//! record ([`verify_control`]) against the list it is given. That must be
//! the device list at the head of the transaction that applies the record,
//! never a verdict from before: a manager removed in between is caught
//! (Astation's review of the plan). A frozen list applies nothing new
//! (`pending`, R9.4).
//!
//! **Effects** (I.5.8). A record's effects are, by action:
//! - `cover`: cover;
//! - `revoke`: the revocation, and the interrupt for it with
//!   `interrupt_running: true`;
//! - `hold`: hold; `release`: release;
//! - `interrupt_running`: the interrupt for the principal's revocation (for
//!   a host principal, the revocation at its `revoke_seq`).
//!
//! Each effect gets one result:
//! - `applied`: this record put it in force on this host;
//! - `duplicate`: this host already had it in force: the same record, a
//!   re-signed copy, a revoke of a revoked principal, an interrupt for a
//!   revocation already interrupted. For the revocation, `duplicate` means
//!   exactly "this host already has the revocation in force", which the
//!   Station's ledger counts as applied there (decision 8);
//! - `pending`: not in force yet, and it can be later (see below);
//! - `refused`: not in force, and never from this record.
//!
//! The record's result is `applied` when any effect is, `duplicate` when
//! every effect is, else `pending` or `refused`.
//!
//! **The rules** (I.5.4, I.5.5):
//! 1. **Idempotent by `record_id`.** A record that counted (`applied` or
//!    `duplicate`) is kept with the SHA-256 of its body's `jcs`. The same
//!    body again is `duplicate` for every effect, whatever its signature
//!    bytes, its position or what the list says now: a revoke whose signer
//!    was removed since stays applied. Another body under that `record_id`
//!    is `refused` and `evidence`: the first counts. A record kept pending
//!    or refused takes no `record_id`, so a forgery never blocks the
//!    genuine record.
//! 2. **Verification.** A `Pending` verdict is `pending`; a `Refused` one
//!    is `refused` and `evidence` (I.5.4: kept as evidence, alerted).
//! 3. **A revoke is final**, from any feed or from none: a stop counts
//!    wherever it comes from (decision 8's native revoke from another
//!    Station's feed).
//! 4. **One interrupt per revocation.** A service is revoked once: an
//!    interrupt (a revoke's `interrupt_running: true`, or an
//!    `interrupt_running` record) is applied once, and waits (`pending`)
//!    while the service isn't revoked here. A host principal can be
//!    revoked again after a readmit: one interrupt per `revoke_seq`, which
//!    waits until `host_applied_seq` reaches it (II.3.1, "A later
//!    interrupt"). That is host-work's applied device-list `seq`, whose
//!    effects (the cancellations, and the revoke's own interrupt intents)
//!    are durable, not the list's head (`verify_control` already checked
//!    that `revoke_seq` names that host's `host_sender_revoke` in the list,
//!    ruling T10a). A revoke entry that carried `interrupt_running: true`
//!    applied its interrupt with it, so a later record for it is a
//!    duplicate. Bound to no feed, a host principal's record counts from
//!    any feed and over a channel alike.
//! 5. **Coverage** (I.5.2) is per Station, and covers are ordered by
//!    their `(issued_at, record_id)` (ruling T11a). A `cover` read at its
//!    own feed's position starts it. Another Station's `cover` takes it
//!    over only when strictly newer than the newest cover taken from the
//!    covering Station; an older or equal one is `refused` and changes
//!    nothing. Covers are signed by the principal's own key only (I.5.4),
//!    so a replayed old cover can't take coverage back. The same Station's
//!    `cover` is a `duplicate`; a newer one from another `feed_id` (its
//!    feed after a reset) moves the coverage's order to that feed, from
//!    its position (a [`HostAction::Cover`] names it). **A cover never
//!    releases:** it only starts delegated execution for future tasks
//!    (I.5.5 step 5), and a hold survives every coverage change.
//! 6. **Hold and release** follow feed order within the coverage's
//!    current feed: taken only from it, at their own feed's position (the
//!    body's `feed_id`), after the coverage's cover there and after the
//!    last hold or release taken in that feed. One that asks for the hold
//!    state already recorded is a `duplicate` (and the latest in feed
//!    order, if it is in order); one that would change it is `applied` if
//!    it is in order, else `refused`. So only a release from the current
//!    covering feed, after that feed's cover, lifts a hold.
//! 7. **After a revoke**, `cover`, `hold` and `release` are ignored: they
//!    change nothing, a `duplicate` when they ask for what is recorded
//!    (the coverage's Station, the hold state), else `refused`. A revoked
//!    principal is never released and never covered anew.
//!
//! **Resets** (I.5.2). A reset's snapshot re-issues each covered
//! principal's state: first its `cover`, signed anew for the new feed (so
//! newer than the old feed's), then its `hold` or `release`, also signed
//! anew (they are taken only at their own feed's position), and its revoke
//! and interrupt records as they are, or signed anew. The snapshot's cover
//! moves the coverage's order to the new feed: its hold and release are
//! ordered within it (`feed_seq` restarts), and the old feed's no longer
//! apply. On a host that applied the old feed each re-issued record is a
//! `duplicate`; on one that never saw it they apply, so a reset loses no
//! stop.
//!
//! **Pending records** are the host's to keep (bounded, I.5.4), and to
//! apply again after every device-list advance, every advance of
//! host-work's applied device-list `seq`, and every revocation applied.
//! Refused ones with `evidence` are kept as evidence and alerted (I.5.4).
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::canonical::MAX_SAFE_INTEGER;
use crate::encoding::Hash32;
use crate::error::{Error, Result};
use crate::membership::{Action, Membership};
use crate::session::wire::is_uuid_v4;
use crate::station_route::normalize_relay;

use super::record::{ControlAction, ControlPrincipal, ControlRecord};
use super::verify::{ControlCheck, verify_control};

/// A record's position in the feed it was read from (I.5.3: `feed_seq`
/// isn't a field of the record). `None` beside a record carried over a
/// channel, which is bound to no feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPos {
    pub feed_id: String,
    pub feed_seq: u64,
}

/// The application result of a record, or of one of its effects: the
/// vocabulary of `control_records_result` (II.3.1) and of acknowledgments
/// (I.5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationResult {
    /// This record put the effect in force.
    Applied,
    /// This host already had it in force.
    Duplicate,
    /// Not in force yet; the host keeps the record and applies it again.
    Pending,
    /// Not in force, and never from this record.
    Refused,
}

impl ApplicationResult {
    /// The wire name.
    pub fn code(self) -> &'static str {
        match self {
            ApplicationResult::Applied => "applied",
            ApplicationResult::Duplicate => "duplicate",
            ApplicationResult::Pending => "pending",
            ApplicationResult::Refused => "refused",
        }
    }

    /// From the wire name, exactly.
    pub fn from_code(code: &str) -> Option<Self> {
        [
            ApplicationResult::Applied,
            ApplicationResult::Duplicate,
            ApplicationResult::Pending,
            ApplicationResult::Refused,
        ]
        .into_iter()
        .find(|result| result.code() == code)
    }
}

/// One effect a record carries (I.5.8, "results and counts are per
/// effect").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectKind {
    /// The principal's revocation (I.5.5 step 2).
    Revocation,
    /// The interrupt for that revocation (step 3).
    Interrupt,
    Hold,
    Release,
    Cover,
}

impl EffectKind {
    /// The wire name.
    pub fn code(self) -> &'static str {
        match self {
            EffectKind::Revocation => "revocation",
            EffectKind::Interrupt => "interrupt",
            EffectKind::Hold => "hold",
            EffectKind::Release => "release",
            EffectKind::Cover => "cover",
        }
    }

    /// From the wire name, exactly.
    pub fn from_code(code: &str) -> Option<Self> {
        [
            EffectKind::Revocation,
            EffectKind::Interrupt,
            EffectKind::Hold,
            EffectKind::Release,
            EffectKind::Cover,
        ]
        .into_iter()
        .find(|kind| kind.code() == code)
    }

    /// The effects a record with `action` carries, in this order.
    fn of(action: ControlAction) -> Vec<EffectKind> {
        match action {
            ControlAction::Cover => vec![EffectKind::Cover],
            ControlAction::Revoke {
                interrupt_running: false,
            } => vec![EffectKind::Revocation],
            ControlAction::Revoke {
                interrupt_running: true,
            } => vec![EffectKind::Revocation, EffectKind::Interrupt],
            ControlAction::Hold => vec![EffectKind::Hold],
            ControlAction::Release => vec![EffectKind::Release],
            ControlAction::InterruptRunning { .. } => vec![EffectKind::Interrupt],
        }
    }
}

/// One effect's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectResult {
    pub effect: EffectKind,
    pub result: ApplicationResult,
}

/// What the host does in the transaction that applies the record (I.5.5).
/// Principals are named in full (`service:<id>`, `host:<host_id>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAction {
    /// A service is revoked: refuse its requests, fence it (§H), cancel
    /// its unstarted tasks (`sender revoked`), withdrawing attempts not
    /// yet `executing`.
    Revoke(String),
    /// An interrupt intent for each started task of `principal` admitted
    /// before `revocation` (I.5.7). `revocation` is the `record_id` of the
    /// revoke that revoked a service, or a host principal's `revoke_seq`
    /// in decimal.
    Interrupt {
        principal: String,
        revocation: String,
    },
    /// Hold the principal's unstarted tasks (`blocked`, `paused`).
    Hold(String),
    /// Let them run again: a release from the covering feed (a cover
    /// never releases).
    Release(String),
    /// The principal's future tasks are delegated, under `origin`'s gate,
    /// from its feed `feed_id`. Also beside a reset's cover, a `duplicate`:
    /// the coverage now follows the feed's new `feed_id`.
    Cover {
        principal: String,
        origin: String,
        feed_id: String,
    },
}

/// What [`ControlState::apply`] did with one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The record's result, from its effects'.
    pub record_result: ApplicationResult,
    /// Every effect the record carries, with its result.
    pub effects: Vec<EffectResult>,
    /// What the host does, in this transaction.
    pub actions: Vec<HostAction>,
    /// Keep the record as evidence and alert (I.5.4): it failed
    /// verification, or reuses the `record_id` of a record that counted
    /// with another body.
    pub evidence: bool,
}

impl Applied {
    /// Every effect of a record with `action` gets `result`; nothing done.
    fn all(action: ControlAction, result: ApplicationResult, evidence: bool) -> Self {
        Applied {
            record_result: result,
            effects: EffectKind::of(action)
                .into_iter()
                .map(|effect| EffectResult { effect, result })
                .collect(),
            actions: Vec::new(),
            evidence,
        }
    }
}

/// A host's control state (the module docs give the rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlState {
    /// The device list it belongs to.
    account_id: String,
    genesis_hash: Hash32,
    /// Every record that counted: its `record_id` and the SHA-256 of its
    /// body's `jcs`.
    records: BTreeMap<String, Hash32>,
    /// Service principals, by device id.
    services: BTreeMap<String, ServiceControl>,
    /// Host principals, by `host_id`: the `revoke_seq`s a record
    /// interrupted.
    hosts: BTreeMap<String, BTreeSet<u64>>,
}

/// One service's control state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ServiceControl {
    /// The `record_id` of the revoke that revoked it.
    revoked_by: Option<String>,
    /// Its revocation's interrupt applied.
    interrupted: bool,
    coverage: Option<Coverage>,
    /// The last hold or release taken, and where; `None` is released.
    hold: Option<HoldAt>,
}

/// The Station whose feed covers a service: its feed's current
/// `feed_id`, the position of the cover that started the coverage there
/// (`since`), and the newest cover taken from that Station.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Coverage {
    origin: String,
    feed_id: String,
    since: u64,
    cover: CoverKey,
}

/// Which of two covers is newer: `(issued_at, record_id)` (ruling T11a).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CoverKey {
    issued_at: u64,
    record_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HoldAt {
    held: bool,
    at: FeedPos,
}

/// The effects' results and the host's actions, as a record is applied.
#[derive(Default)]
struct Outcome {
    effects: Vec<EffectResult>,
    actions: Vec<HostAction>,
}

impl Outcome {
    fn effect(&mut self, effect: EffectKind, result: ApplicationResult) {
        self.effects.push(EffectResult { effect, result });
    }

    /// The record's result: applied when any effect is, duplicate when
    /// every effect is, else pending or refused.
    fn record_result(&self) -> ApplicationResult {
        let any = |r| self.effects.iter().any(|e| e.result == r);
        if any(ApplicationResult::Applied) {
            ApplicationResult::Applied
        } else if self
            .effects
            .iter()
            .all(|e| e.result == ApplicationResult::Duplicate)
        {
            ApplicationResult::Duplicate
        } else if any(ApplicationResult::Pending) {
            ApplicationResult::Pending
        } else {
            ApplicationResult::Refused
        }
    }
}

impl ControlState {
    /// The empty control state of the device list `list` belongs to (its
    /// account and genesis).
    pub fn new(list: &Membership) -> Self {
        ControlState {
            account_id: list.account_id().to_owned(),
            genesis_hash: list.genesis_hash(),
            records: BTreeMap::new(),
            services: BTreeMap::new(),
            hosts: BTreeMap::new(),
        }
    }

    /// Applies `rec`, verified against `list`: the device list at the head
    /// of the transaction that applies it. `pos` is where it was read
    /// (`None` over a channel). `host_applied_seq` is host-work's applied
    /// device-list `seq` (II.3.1), not the list's head. The module docs
    /// give the rules.
    ///
    /// The caller passes `pos` only for a record read from a feed it syncs
    /// whose `origin` and `feed_id` are the record body's: [`FeedPos`]
    /// carries no origin, so the state takes the body's. The host never
    /// applies a record while it is held after a write fault (R9.3), which
    /// the state can't see.
    ///
    /// A list of another account or genesis than the state's applies
    /// nothing (`refused`, no evidence: the caller's error, not the
    /// record's); a frozen one applies nothing new (`pending`; a record
    /// that counted is still a `duplicate`).
    pub fn apply(
        &mut self,
        rec: &ControlRecord,
        list: &Membership,
        pos: Option<FeedPos>,
        host_applied_seq: u64,
    ) -> Applied {
        use ApplicationResult::{Duplicate, Pending, Refused};
        let action = rec.action();
        if list.account_id() != self.account_id || list.genesis_hash() != self.genesis_hash {
            return Applied::all(action, Refused, false);
        }
        let digest = Hash32::of(rec.object().jcs().as_bytes());
        match self.records.get(rec.record_id()) {
            Some(counted) if *counted == digest => return Applied::all(action, Duplicate, false),
            Some(_) => return Applied::all(action, Refused, true),
            None => {}
        }
        if list.frozen().is_some() {
            return Applied::all(action, Pending, false);
        }
        match verify_control(rec, list) {
            ControlCheck::Valid(_) => {}
            ControlCheck::Pending(_) => return Applied::all(action, Pending, false),
            ControlCheck::Refused(_) => return Applied::all(action, Refused, true),
        }

        let mut out = Outcome::default();
        match rec.principal() {
            ControlPrincipal::Service(id) => self.apply_service(rec, id, pos, &mut out),
            ControlPrincipal::Host(host_id) => {
                self.apply_host(rec, host_id, list, host_applied_seq, &mut out)
            }
        }
        let record_result = out.record_result();
        if matches!(record_result, ApplicationResult::Applied | Duplicate) {
            self.records.insert(rec.record_id().to_owned(), digest);
        }
        Applied {
            record_result,
            effects: out.effects,
            actions: out.actions,
            evidence: false,
        }
    }

    fn apply_service(
        &mut self,
        rec: &ControlRecord,
        id: &str,
        pos: Option<FeedPos>,
        out: &mut Outcome,
    ) {
        let principal = rec.principal().name();
        let mut state = self.services.get(id).cloned().unwrap_or_default();
        // The parse gives every service record its feed.
        let (origin, feed_id) = rec.feed().unwrap_or_default();
        match rec.action() {
            ControlAction::Revoke { interrupt_running } => {
                let revocation = match &state.revoked_by {
                    Some(by) => {
                        out.effect(EffectKind::Revocation, ApplicationResult::Duplicate);
                        by.clone()
                    }
                    None => {
                        out.effect(EffectKind::Revocation, ApplicationResult::Applied);
                        out.actions.push(HostAction::Revoke(principal.clone()));
                        let by = rec.record_id().to_owned();
                        state.revoked_by = Some(by.clone());
                        by
                    }
                };
                if interrupt_running {
                    interrupt(&mut state, principal, revocation, out);
                }
            }
            ControlAction::InterruptRunning { .. } => match state.revoked_by.clone() {
                Some(revocation) => interrupt(&mut state, principal, revocation, out),
                None => out.effect(EffectKind::Interrupt, ApplicationResult::Pending),
            },
            ControlAction::Cover => {
                let key = CoverKey {
                    issued_at: rec.issued_at(),
                    record_id: rec.record_id().to_owned(),
                };
                cover(&mut state, principal, key, origin, feed_id, pos, out);
            }
            ControlAction::Hold => hold(&mut state, principal, true, origin, feed_id, pos, out),
            ControlAction::Release => hold(&mut state, principal, false, origin, feed_id, pos, out),
        }
        if self.services.contains_key(id) || state != ServiceControl::default() {
            self.services.insert(id.to_owned(), state);
        }
    }

    fn apply_host(
        &mut self,
        rec: &ControlRecord,
        host_id: &str,
        list: &Membership,
        host_applied_seq: u64,
        out: &mut Outcome,
    ) {
        // The parse gives a host principal's record exactly this form.
        let ControlAction::InterruptRunning {
            revoke_seq: Some(revoke_seq),
        } = rec.action()
        else {
            out.effect(EffectKind::Interrupt, ApplicationResult::Refused);
            return;
        };
        if host_applied_seq < revoke_seq {
            out.effect(EffectKind::Interrupt, ApplicationResult::Pending);
            return;
        }
        let by_record = self
            .hosts
            .get(host_id)
            .is_some_and(|seqs| seqs.contains(&revoke_seq));
        let by_entry = matches!(
            list.entry(revoke_seq).map(|entry| &entry.action),
            Some(Action::HostSenderRevoke {
                interrupt_running: true,
                ..
            })
        );
        if by_record || by_entry {
            out.effect(EffectKind::Interrupt, ApplicationResult::Duplicate);
            return;
        }
        self.hosts
            .entry(host_id.to_owned())
            .or_default()
            .insert(revoke_seq);
        out.effect(EffectKind::Interrupt, ApplicationResult::Applied);
        out.actions.push(HostAction::Interrupt {
            principal: rec.principal().name(),
            revocation: revoke_seq.to_string(),
        });
    }

    /// The state's durable form: sorted maps, absent parts omitted.
    ///
    /// ```json
    /// {"v":1,"account_id":"…","genesis_hash":"<hex>",
    ///  "hosts":{"<host_id>":{"interrupted":[<revoke_seq>,…]}},
    ///  "records":{"<record_id>":"<hex SHA-256 of the body's jcs>"},
    ///  "services":{"<device_id>":{
    ///    "coverage":{"cover":{"issued_at":<ms>,"record_id":"…"},
    ///                "feed_id":"…","origin":"…","since":<feed_seq>},
    ///    "hold":{"feed_id":"…","feed_seq":<n>,"held":true},
    ///    "interrupted":false,"revoked_by":"<record_id>"}}}
    /// ```
    pub fn to_json(&self) -> Value {
        let records: Map<String, Value> = self
            .records
            .iter()
            .map(|(id, digest)| (id.clone(), json!(digest.to_hex())))
            .collect();
        let services: Map<String, Value> = self
            .services
            .iter()
            .map(|(id, state)| (id.clone(), state.to_json()))
            .collect();
        let hosts: Map<String, Value> = self
            .hosts
            .iter()
            .map(|(id, seqs)| (id.clone(), json!({"interrupted": seqs})))
            .collect();
        // Keys in sorted order, whatever `serde_json::Map` preserves.
        let mut o = Map::new();
        o.insert("account_id".into(), json!(self.account_id));
        o.insert("genesis_hash".into(), json!(self.genesis_hash.to_hex()));
        o.insert("hosts".into(), Value::Object(hosts));
        o.insert("records".into(), Value::Object(records));
        o.insert("services".into(), Value::Object(services));
        o.insert("v".into(), json!(1));
        Value::Object(o)
    }

    /// A state from [`ControlState::to_json`], read strictly: exactly its
    /// fields, its types and grammars, and its invariants (an interrupt
    /// only after a revocation, the revocation's and the coverage's cover
    /// records among those that counted, sorted unique `revoke_seq`s).
    pub fn from_json(value: &Value) -> Result<Self> {
        let o = fields(
            value,
            &[
                "v",
                "account_id",
                "genesis_hash",
                "records",
                "services",
                "hosts",
            ],
            &[],
            "control state",
        )?;
        if o["v"].as_u64() != Some(1) {
            return Err(Error::Malformed("control state v"));
        }
        let account_id = o["account_id"]
            .as_str()
            .filter(|id| (1..=128).contains(&id.len()))
            .ok_or(Error::Malformed("control state account_id"))?
            .to_owned();
        let genesis_hash = hash(&o["genesis_hash"], "control state genesis_hash")?;

        let mut records = BTreeMap::new();
        for (id, digest) in object(&o["records"], "control state records")? {
            if !is_uuid_v4(id) {
                return Err(Error::Malformed("control state record_id"));
            }
            records.insert(id.clone(), hash(digest, "control state record digest")?);
        }

        let mut services = BTreeMap::new();
        for (id, state) in object(&o["services"], "control state services")? {
            if !matches!(
                ControlPrincipal::parse(&format!("service:{id}")),
                Some(ControlPrincipal::Service(_))
            ) {
                return Err(Error::Malformed("control state service"));
            }
            services.insert(id.clone(), ServiceControl::from_json(state, &records)?);
        }

        let mut hosts = BTreeMap::new();
        for (id, state) in object(&o["hosts"], "control state hosts")? {
            if !matches!(
                ControlPrincipal::parse(&format!("host:{id}")),
                Some(ControlPrincipal::Host(_))
            ) {
                return Err(Error::Malformed("control state host"));
            }
            let what = "control state host interrupted";
            let state = fields(state, &["interrupted"], &[], what)?;
            let seqs = state["interrupted"]
                .as_array()
                .filter(|seqs| !seqs.is_empty())
                .ok_or(Error::Malformed(what))?;
            let mut set = BTreeSet::new();
            for seq in seqs {
                let seq = seq
                    .as_u64()
                    .filter(|seq| (1..=MAX_SAFE_INTEGER).contains(seq))
                    .ok_or(Error::Malformed(what))?;
                // Strictly increasing: sorted, no repeat.
                if set.last().is_some_and(|last| *last >= seq) {
                    return Err(Error::Malformed(what));
                }
                set.insert(seq);
            }
            hosts.insert(id.clone(), set);
        }

        Ok(ControlState {
            account_id,
            genesis_hash,
            records,
            services,
            hosts,
        })
    }
}

/// The interrupt for `revocation`: applied once.
fn interrupt(state: &mut ServiceControl, principal: String, revocation: String, out: &mut Outcome) {
    if state.interrupted {
        out.effect(EffectKind::Interrupt, ApplicationResult::Duplicate);
    } else {
        state.interrupted = true;
        out.effect(EffectKind::Interrupt, ApplicationResult::Applied);
        out.actions.push(HostAction::Interrupt {
            principal,
            revocation,
        });
    }
}

/// `pos`, when the record was read at its own feed's position.
fn positioned(pos: Option<FeedPos>, feed_id: &str) -> Option<FeedPos> {
    pos.filter(|pos| pos.feed_id == feed_id)
}

/// A `cover` from `origin`'s feed `feed_id`, issued as `key` (ruling
/// T11a). It never releases.
fn cover(
    state: &mut ServiceControl,
    principal: String,
    key: CoverKey,
    origin: &str,
    feed_id: &str,
    pos: Option<FeedPos>,
    out: &mut Outcome,
) {
    let Some(pos) = positioned(pos, feed_id) else {
        out.effect(EffectKind::Cover, ApplicationResult::Refused);
        return;
    };
    let revoked = state.revoked_by.is_some();
    let same_station = state.coverage.as_ref().is_some_and(|c| c.origin == origin);
    let newer = state.coverage.as_ref().is_none_or(|c| key > c.cover);
    let result = if same_station {
        // The same coverage. A newer cover (nothing changes after a revoke)
        // is the newest; from another `feed_id`, the Station's feed after a
        // reset, it moves the coverage's order to that feed.
        if let Some(c) = state.coverage.as_mut().filter(|_| !revoked && newer) {
            if c.feed_id != feed_id {
                c.feed_id = feed_id.to_owned();
                c.since = pos.feed_seq;
                out.actions.push(HostAction::Cover {
                    principal,
                    origin: origin.to_owned(),
                    feed_id: feed_id.to_owned(),
                });
            }
            c.cover = key;
        }
        ApplicationResult::Duplicate
    } else if revoked || !newer {
        // Never covered anew after a revoke; another Station's cover no
        // newer than the coverage's changes nothing.
        ApplicationResult::Refused
    } else {
        state.coverage = Some(Coverage {
            origin: origin.to_owned(),
            feed_id: feed_id.to_owned(),
            since: pos.feed_seq,
            cover: key,
        });
        out.actions.push(HostAction::Cover {
            principal,
            origin: origin.to_owned(),
            feed_id: feed_id.to_owned(),
        });
        ApplicationResult::Applied
    };
    out.effect(EffectKind::Cover, result);
}

/// A `hold` (`held`) or `release` from `origin`'s feed `feed_id`.
fn hold(
    state: &mut ServiceControl,
    principal: String,
    held: bool,
    origin: &str,
    feed_id: &str,
    pos: Option<FeedPos>,
    out: &mut Outcome,
) {
    let effect = if held {
        EffectKind::Hold
    } else {
        EffectKind::Release
    };
    let Some(pos) = positioned(pos, feed_id) else {
        out.effect(effect, ApplicationResult::Refused);
        return;
    };
    let recorded = state.hold.as_ref().is_some_and(|h| h.held);
    // Ignored after a revoke.
    if state.revoked_by.is_some() {
        let result = if held == recorded {
            ApplicationResult::Duplicate
        } else {
            ApplicationResult::Refused
        };
        out.effect(effect, result);
        return;
    }
    // Taken from the covering Station's current feed, after the coverage's
    // cover there and after the last hold or release taken in that feed.
    let in_order = state.coverage.as_ref().is_some_and(|c| {
        c.origin == origin
            && c.feed_id == pos.feed_id
            && pos.feed_seq > c.since
            && state
                .hold
                .as_ref()
                .is_none_or(|h| h.at.feed_id != pos.feed_id || pos.feed_seq > h.at.feed_seq)
    });
    let result = if held == recorded {
        ApplicationResult::Duplicate
    } else if in_order {
        out.actions.push(if held {
            HostAction::Hold(principal)
        } else {
            HostAction::Release(principal)
        });
        ApplicationResult::Applied
    } else {
        ApplicationResult::Refused
    };
    if in_order {
        state.hold = Some(HoldAt { held, at: pos });
    }
    out.effect(effect, result);
}

impl ServiceControl {
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        if let Some(c) = &self.coverage {
            let cover = json!({"issued_at": c.cover.issued_at, "record_id": c.cover.record_id});
            let coverage = json!({
                "cover": cover, "feed_id": c.feed_id, "origin": c.origin, "since": c.since,
            });
            o.insert("coverage".into(), coverage);
        }
        if let Some(h) = &self.hold {
            let hold = json!({"feed_id": h.at.feed_id, "feed_seq": h.at.feed_seq, "held": h.held});
            o.insert("hold".into(), hold);
        }
        o.insert("interrupted".into(), json!(self.interrupted));
        if let Some(by) = &self.revoked_by {
            o.insert("revoked_by".into(), json!(by));
        }
        Value::Object(o)
    }

    fn from_json(value: &Value, records: &BTreeMap<String, Hash32>) -> Result<Self> {
        let what = "control state service";
        let o = fields(
            value,
            &["interrupted"],
            &["revoked_by", "coverage", "hold"],
            what,
        )?;
        let revoked_by = match o.get("revoked_by") {
            None => None,
            Some(by) => Some(
                by.as_str()
                    .filter(|by| records.contains_key(*by))
                    .ok_or(Error::Malformed("control state revoked_by"))?
                    .to_owned(),
            ),
        };
        let interrupted = o["interrupted"]
            .as_bool()
            .filter(|interrupted| !interrupted || revoked_by.is_some())
            .ok_or(Error::Malformed("control state interrupted"))?;
        let coverage = match o.get("coverage") {
            None => None,
            Some(c) => {
                let what = "control state coverage";
                let c = fields(c, &["origin", "feed_id", "since", "cover"], &[], what)?;
                let origin = c["origin"]
                    .as_str()
                    .filter(|origin| normalize_relay(origin).as_deref() == Ok(*origin))
                    .ok_or(Error::Malformed(what))?;
                let cover = fields(&c["cover"], &["issued_at", "record_id"], &[], what)?;
                Some(Coverage {
                    origin: origin.to_owned(),
                    feed_id: feed_id(&c["feed_id"], what)?,
                    since: c["since"].as_u64().ok_or(Error::Malformed(what))?,
                    cover: CoverKey {
                        issued_at: cover["issued_at"]
                            .as_u64()
                            .filter(|at| *at <= MAX_SAFE_INTEGER)
                            .ok_or(Error::Malformed(what))?,
                        // The cover counted: it is among the records.
                        record_id: cover["record_id"]
                            .as_str()
                            .filter(|id| records.contains_key(*id))
                            .ok_or(Error::Malformed(what))?
                            .to_owned(),
                    },
                })
            }
        };
        let hold = match o.get("hold") {
            None => None,
            Some(h) => {
                let what = "control state hold";
                let h = fields(h, &["held", "feed_id", "feed_seq"], &[], what)?;
                Some(HoldAt {
                    held: h["held"].as_bool().ok_or(Error::Malformed(what))?,
                    at: FeedPos {
                        feed_id: feed_id(&h["feed_id"], what)?,
                        feed_seq: h["feed_seq"].as_u64().ok_or(Error::Malformed(what))?,
                    },
                })
            }
        };
        Ok(ServiceControl {
            revoked_by,
            interrupted,
            coverage,
            hold,
        })
    }
}

/// `value` as an object with every `required` field and no field outside
/// `required` and `optional`.
fn fields<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
    what: &'static str,
) -> Result<&'a Map<String, Value>> {
    let o = value.as_object().ok_or(Error::Malformed(what))?;
    let known = |key: &str| required.contains(&key) || optional.contains(&key);
    if !o.keys().all(|key| known(key)) || !required.iter().all(|key| o.contains_key(*key)) {
        return Err(Error::Malformed(what));
    }
    Ok(o)
}

fn object<'a>(value: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or(Error::Malformed(what))
}

fn hash(value: &Value, what: &'static str) -> Result<Hash32> {
    value
        .as_str()
        .and_then(|text| Hash32::from_hex(text).ok())
        .ok_or(Error::Malformed(what))
}

fn feed_id(value: &Value, what: &'static str) -> Result<String> {
    value
        .as_str()
        .filter(|id| is_uuid_v4(id))
        .map(str::to_owned)
        .ok_or(Error::Malformed(what))
}

#[cfg(test)]
mod control_state_tests {
    use super::*;
    use crate::canonical::jcs;
    use crate::control::record::{
        ControlAbout, ControlAction, ControlBody, ControlFeed, ControlPrincipal, ControlSigner,
        build_control, principal_key_of,
    };
    use crate::control::verify::{ControlCheck, verify_control};
    use crate::encoding::b64u;
    use crate::keys::PublicKey;
    use crate::membership::{
        Action, HostNow, HostRecord, Member, MemberKind, Role, ServiceScope, draft_on,
        host_sender_readmit, host_sender_revoke, service_add, sign_entry,
    };
    use crate::provider::{KeyId, KeyProvider};
    use crate::software::SoftwareKeys;
    use serde_json::json;

    use ApplicationResult as R;
    use ControlAction as C;
    use EffectKind as E;
    use HostAction as H;

    const ACCOUNT: &str = "acct-test-1";
    const T0: u64 = 1_800_000_000_000;
    const HOUR: u64 = 3_600_000;
    const INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";
    const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];

    /// A feed: its Station's origin and its `feed_id`.
    type Feed = (&'static str, &'static str);
    /// The Station `station-dev`'s feed.
    const A: Feed = (
        "https://station-dev.agora.build",
        "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
    );
    /// The same Station's feed after a reset: a new `feed_id` (I.5.2).
    const A2: Feed = (
        "https://station-dev.agora.build",
        "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    );
    /// Another Station's feed.
    const B: Feed = (
        "https://station-b.example.com",
        "1d2c3b4a-5f6e-4d7c-b8a9-0f1e2d3c4b5a",
    );

    fn revoke(interrupt_running: bool) -> ControlAction {
        C::Revoke { interrupt_running }
    }

    const INTERRUPT: ControlAction = C::InterruptRunning { revoke_seq: None };

    /// The `n`th record id (a UUID v4).
    fn rid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    /// When the service record `n` is issued: records are numbered in the
    /// order they are issued.
    fn issued(n: u32) -> u64 {
        T0 + 2 * HOUR + u64::from(n)
    }

    fn at(feed: Feed, feed_seq: u64) -> Option<FeedPos> {
        Some(FeedPos {
            feed_id: feed.1.into(),
            feed_seq,
        })
    }

    /// Every key, by the id it signs as: natives `mac` (P-256) and `phone`
    /// (Ed25519), both managers, and `ipad`; services `svc-1` (P-256),
    /// `svc-2` and `svc-new` (Ed25519); the host `host-a`; the kit.
    fn keys() -> SoftwareKeys {
        let mut keys = SoftwareKeys::new();
        keys.insert_p256(KeyId::new("mac"), &[1; 32]).unwrap();
        keys.insert_ed25519(KeyId::new("phone"), &[2; 32]);
        keys.insert_p256(KeyId::new("ipad"), &[3; 32]).unwrap();
        keys.insert_p256(KeyId::new("svc-1"), &[6; 32]).unwrap();
        keys.insert_ed25519(KeyId::new("svc-2"), &[7; 32]);
        keys.insert_ed25519(KeyId::new("svc-new"), &[8; 32]);
        keys.insert_ed25519(KeyId::new("host-a"), &[9; 32]);
        keys.insert_ed25519(KeyId::new("kit"), &[10; 32]);
        for (i, id) in ["mac", "phone", "ipad"].into_iter().enumerate() {
            keys.insert_x25519(KeyId::new(format!("enc-{id}")), &[20 + i as u8; 32]);
        }
        keys
    }

    fn now(at: u64) -> HostNow {
        HostNow {
            wall_ms: at,
            mono_ms: at,
            boot_id: "b".into(),
        }
    }

    /// An account's device list and the keys that sign for it.
    struct Fx {
        keys: SoftwareKeys,
        list: Membership,
    }

    impl Fx {
        /// The account `ACCOUNT`.
        fn new() -> Self {
            Self::account(ACCOUNT)
        }

        /// Managers `mac` (its genesis) and `phone`, the services `svc-1`
        /// and `svc-2`, and the host `host-a`.
        fn account(account_id: &str) -> Self {
            let keys = keys();
            let body = draft_on(
                account_id,
                &Hash32([0; 32]),
                1,
                &Hash32([0; 32]),
                "mac",
                T0,
                &Action::Genesis {
                    member: native(&keys, "mac", &ALL),
                    recovery_key: key(&keys, "kit"),
                },
            );
            let genesis = sign_entry(&keys, &KeyId::new("mac"), body).unwrap();
            let list = Membership::from_genesis(account_id, &genesis.hash(), genesis).unwrap();
            let mut fx = Fx { keys, list };
            let phone = native(&fx.keys, "phone", &ALL);
            fx.append("mac", Action::Add { member: phone });
            for id in ["svc-1", "svc-2"] {
                fx.add_service(id);
            }
            let host = HostRecord {
                host_id: "host-a".into(),
                host_trust_gen: 1,
                host_key: key(&fx.keys, "host-a"),
            };
            fx.append("mac", Action::AddHost { host });
            fx
        }

        fn add_service(&mut self, id: &str) -> u64 {
            let scope = ServiceScope::new(["host-a"]);
            let action = service_add(id, key(&self.keys, id), &scope, T0 + HOUR, T0).unwrap();
            self.append("mac", action)
        }

        /// `action` signed by `signer`, carried to the list. Its `seq`.
        fn append(&mut self, signer: &str, action: Action) -> u64 {
            let at = T0 + self.list.head().seq;
            let body = self.list.draft(signer, at, &action);
            let entry = sign_entry(&self.keys, &KeyId::new(signer), body).unwrap();
            let eval = self
                .list
                .evaluate_objects(&[entry.object().clone()], &now(at));
            assert_eq!(eval.stop, None, "{action:?}");
            self.list = eval.next;
            self.list.head().seq
        }

        /// `host-a`'s `host_sender_revoke`, signed by `mac`. Its `seq`.
        fn revoke_host(&mut self, interrupt_running: bool) -> u64 {
            let action = host_sender_revoke("host-a", interrupt_running, T0).unwrap();
            self.append("mac", action)
        }

        fn readmit_host(&mut self) -> u64 {
            self.append("mac", host_sender_readmit("host-a", T0).unwrap())
        }

        /// The record `n` about the service `principal`, in `feed`, its
        /// `signer` the principal itself or `member:<signer>`.
        fn service_body(
            &self,
            n: u32,
            principal: &str,
            signer: &str,
            action: ControlAction,
            feed: Feed,
        ) -> ControlBody {
            ControlBody {
                account_id: self.list.account_id().into(),
                genesis_hash: self.list.genesis_hash(),
                feed: Some(ControlFeed {
                    origin: feed.0.into(),
                    feed_id: feed.1.into(),
                }),
                principal: ControlPrincipal::Service(principal.into()),
                principal_key: Some(principal_key_of(&key(&self.keys, principal)).unwrap()),
                signer: if signer == principal {
                    ControlSigner::Principal
                } else {
                    ControlSigner::Member(signer.into())
                },
                action,
                record_id: rid(n),
                issued_at: issued(n),
                about: ControlAbout {
                    integration_id: Some(INTEGRATION.into()),
                    by: "owner".into(),
                },
            }
        }

        /// `body` signed with the key `key_id` (the named signer's, or a
        /// forgery's).
        fn sign(&self, body: &ControlBody, key_id: &str) -> ControlRecord {
            let object = build_control(&self.keys, &KeyId::new(key_id), body).unwrap();
            ControlRecord::from_signed(object).unwrap()
        }

        /// The record `n` about the service `principal`, signed by `signer`.
        fn svc(
            &self,
            n: u32,
            principal: &str,
            signer: &str,
            action: ControlAction,
            feed: Feed,
        ) -> ControlRecord {
            self.sign(
                &self.service_body(n, principal, signer, action, feed),
                signer,
            )
        }

        /// The record `n` about the service `principal`, signed by itself
        /// and issued at `issued_at` (a cover a Station retained, or one
        /// signed with an older time).
        fn svc_issued(
            &self,
            n: u32,
            principal: &str,
            action: ControlAction,
            feed: Feed,
            issued_at: u64,
        ) -> ControlRecord {
            let mut body = self.service_body(n, principal, principal, action, feed);
            body.issued_at = issued_at;
            self.sign(&body, principal)
        }

        /// The record `n`: `member:<signer>`'s `interrupt_running` of
        /// `host-a` after the revoke at `revoke_seq`.
        fn host(&self, n: u32, signer: &str, revoke_seq: u64) -> ControlRecord {
            let body = ControlBody {
                account_id: self.list.account_id().into(),
                genesis_hash: self.list.genesis_hash(),
                feed: None,
                principal: ControlPrincipal::Host("host-a".into()),
                principal_key: None,
                signer: ControlSigner::Member(signer.into()),
                action: C::InterruptRunning {
                    revoke_seq: Some(revoke_seq),
                },
                record_id: rid(n),
                issued_at: T0 + 2 * HOUR,
                about: ControlAbout {
                    integration_id: None,
                    by: "owner".into(),
                },
            };
            self.sign(&body, signer)
        }

        fn state(&self) -> ControlState {
            ControlState::new(&self.list)
        }
    }

    fn key(keys: &SoftwareKeys, id: &str) -> PublicKey {
        keys.public_key(&KeyId::new(id)).unwrap()
    }

    fn native(keys: &SoftwareKeys, id: &str, roles: &[Role]) -> Member {
        Member {
            device_id: id.into(),
            auth_key: key(keys, id),
            kind: MemberKind::Native {
                enc_key: key(keys, &format!("enc-{id}")),
                roles: roles.iter().copied().collect(),
            },
        }
    }

    /// `result` for the record and its `effects`, with `actions`.
    fn out(
        record_result: ApplicationResult,
        effects: &[(EffectKind, ApplicationResult)],
        actions: Vec<HostAction>,
    ) -> Applied {
        Applied {
            record_result,
            effects: effects
                .iter()
                .map(|&(effect, result)| EffectResult { effect, result })
                .collect(),
            actions,
            evidence: false,
        }
    }

    /// Every effect `result`, nothing done.
    fn all(result: ApplicationResult, kinds: &[EffectKind]) -> Applied {
        let effects: Vec<_> = kinds.iter().map(|&kind| (kind, result)).collect();
        out(result, &effects, vec![])
    }

    fn dup(kinds: &[EffectKind]) -> Applied {
        all(R::Duplicate, kinds)
    }

    fn evidence(mut applied: Applied) -> Applied {
        applied.evidence = true;
        applied
    }

    fn service(id: &str) -> String {
        format!("service:{id}")
    }

    fn cover_action(id: &str, feed: Feed) -> HostAction {
        H::Cover {
            principal: service(id),
            origin: feed.0.into(),
            feed_id: feed.1.into(),
        }
    }

    fn interrupt_action(principal: String, revocation: String) -> HostAction {
        H::Interrupt {
            principal,
            revocation,
        }
    }

    /// One step of a sequence: a record, where it was read, host-work's
    /// applied device-list `seq`, and what `apply` returns.
    struct Step(ControlRecord, Option<FeedPos>, u64, Applied);

    impl Step {
        /// A service's record (host-work's applied `seq` plays no part).
        fn new(rec: &ControlRecord, pos: Option<FeedPos>, want: Applied) -> Self {
            Step(rec.clone(), pos, 0, want)
        }
    }

    /// Applies each step in order against `list`.
    fn run(state: &mut ControlState, list: &Membership, steps: Vec<Step>) {
        for (i, Step(rec, pos, applied_seq, want)) in steps.into_iter().enumerate() {
            let got = state.apply(&rec, list, pos, applied_seq);
            assert_eq!(
                got,
                want,
                "step {i}: {} {}",
                rec.action().name(),
                rec.record_id()
            );
        }
    }

    #[test]
    fn same_record_twice_duplicate() {
        let fx = Fx::new();
        let mut state = fx.state();
        let cover = fx.svc(1, "svc-1", "svc-1", C::Cover, A);
        let hold = fx.svc(2, "svc-1", "svc-1", C::Hold, A);
        let revoke = fx.svc(3, "svc-1", "svc-1", revoke(true), A);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &cover,
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(&cover, at(A, 1), dup(&[E::Cover])),
                Step::new(
                    &hold,
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                Step::new(&hold, at(A, 2), dup(&[E::Hold])),
                Step::new(
                    &revoke,
                    at(A, 3),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied), (E::Interrupt, R::Applied)],
                        vec![
                            H::Revoke(service("svc-1")),
                            interrupt_action(service("svc-1"), rid(3)),
                        ],
                    ),
                ),
                // Served again at another position, or carried with none:
                // still the same record, whatever the state since.
                Step::new(&revoke, at(A, 9), dup(&[E::Revocation, E::Interrupt])),
                Step::new(&revoke, None, dup(&[E::Revocation, E::Interrupt])),
                Step::new(&cover, None, dup(&[E::Cover])),
                Step::new(&hold, at(A, 2), dup(&[E::Hold])),
            ],
        );

        // The same body with other signature bytes is the same record.
        let wire = json!({"body": revoke.object().body(), "sig": b64u(&[7u8; 64])});
        let again = ControlRecord::parse(wire.to_string().as_bytes()).unwrap();
        assert_ne!(again.object().sig(), revoke.object().sig());
        assert_eq!(
            state.apply(&again, &fx.list, None, 0),
            dup(&[E::Revocation, E::Interrupt])
        );
    }

    #[test]
    fn resigned_copy_duplicate() {
        let mut fx = Fx::new();
        let r = fx.revoke_host(false);
        let mut state = fx.state();
        let phone = fx.svc(1, "svc-1", "phone", revoke(true), A);
        // Astation's re-signed copy: the same body, a current manager, a new
        // record id (I.5.4); and the Station's own revoke (I.8).
        let mac = fx.svc(2, "svc-1", "mac", revoke(true), A);
        let own = fx.svc(3, "svc-1", "svc-1", revoke(true), A);
        let own_without_interrupt = fx.svc(4, "svc-1", "svc-1", revoke(false), A);
        let host_phone = fx.host(5, "phone", r);
        let host_mac = fx.host(6, "mac", r);
        let head = fx.list.head().seq;
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &phone,
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied), (E::Interrupt, R::Applied)],
                        vec![
                            H::Revoke(service("svc-1")),
                            interrupt_action(service("svc-1"), rid(1)),
                        ],
                    ),
                ),
                Step::new(&mac, at(A, 2), dup(&[E::Revocation, E::Interrupt])),
                Step::new(&own, at(A, 3), dup(&[E::Revocation, E::Interrupt])),
                Step::new(&own_without_interrupt, at(A, 4), dup(&[E::Revocation])),
                Step(
                    host_phone,
                    None,
                    head,
                    out(
                        R::Applied,
                        &[(E::Interrupt, R::Applied)],
                        vec![interrupt_action("host:host-a".into(), r.to_string())],
                    ),
                ),
                Step(host_mac, None, head, dup(&[E::Interrupt])),
            ],
        );
    }

    #[test]
    fn revoke_then_resigned_revoke_with_interrupt_applied_for_interrupt() {
        let fx = Fx::new();
        let mut state = fx.state();
        let first = fx.svc(1, "svc-1", "phone", revoke(false), A);
        let with_interrupt = fx.svc(2, "svc-1", "mac", revoke(true), A);
        let again = fx.svc(3, "svc-1", "svc-1", revoke(true), A);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &first,
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied)],
                        vec![H::Revoke(service("svc-1"))],
                    ),
                ),
                // The revocation is in force; the interrupt is new: applied
                // for it, the intent naming the revocation that applied.
                Step::new(
                    &with_interrupt,
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Duplicate), (E::Interrupt, R::Applied)],
                        vec![interrupt_action(service("svc-1"), rid(1))],
                    ),
                ),
                Step::new(&again, at(A, 3), dup(&[E::Revocation, E::Interrupt])),
                Step::new(&first, at(A, 1), dup(&[E::Revocation])),
            ],
        );
    }

    #[test]
    fn later_interrupt_applied_then_duplicate() {
        let fx = Fx::new();
        let mut state = fx.state();
        let revoked = fx.svc(1, "svc-1", "svc-1", revoke(false), A);
        let interrupt = fx.svc(2, "svc-1", "mac", INTERRUPT, A);
        let own_interrupt = fx.svc(3, "svc-1", "svc-1", INTERRUPT, A);
        let revoke_with_interrupt = fx.svc(4, "svc-1", "phone", revoke(true), A);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &revoked,
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied)],
                        vec![H::Revoke(service("svc-1"))],
                    ),
                ),
                Step::new(
                    &interrupt,
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Interrupt, R::Applied)],
                        vec![interrupt_action(service("svc-1"), rid(1))],
                    ),
                ),
                // One interrupt per revocation, whoever signs the next.
                Step::new(&own_interrupt, at(A, 3), dup(&[E::Interrupt])),
                Step::new(&interrupt, at(A, 2), dup(&[E::Interrupt])),
                Step::new(
                    &revoke_with_interrupt,
                    at(A, 4),
                    dup(&[E::Revocation, E::Interrupt]),
                ),
            ],
        );
    }

    #[test]
    fn service_interrupt_waits_for_its_revocation() {
        let fx = Fx::new();
        let mut state = fx.state();
        let interrupt = fx.svc(1, "svc-2", "mac", INTERRUPT, A);
        let revoked = fx.svc(2, "svc-2", "svc-2", revoke(false), B);
        run(
            &mut state,
            &fx.list,
            vec![
                // "Also interrupt" follows a revocation this host hasn't
                // applied: it waits, and takes no record id.
                Step::new(&interrupt, at(A, 1), all(R::Pending, &[E::Interrupt])),
                Step::new(&interrupt, at(A, 1), all(R::Pending, &[E::Interrupt])),
                // The revocation, from any feed (another Station's here).
                Step::new(
                    &revoked,
                    at(B, 1),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied)],
                        vec![H::Revoke(service("svc-2"))],
                    ),
                ),
                Step::new(
                    &interrupt,
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Interrupt, R::Applied)],
                        vec![interrupt_action(service("svc-2"), rid(2))],
                    ),
                ),
                Step::new(&interrupt, at(A, 1), dup(&[E::Interrupt])),
            ],
        );
    }

    #[test]
    fn hold_release_by_feed_order() {
        let fx = Fx::new();
        let mut state = fx.state();
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let held = out(
            R::Applied,
            &[(E::Hold, R::Applied)],
            vec![H::Hold(service("svc-1"))],
        );
        let released = out(
            R::Applied,
            &[(E::Release, R::Applied)],
            vec![H::Release(service("svc-1"))],
        );
        // A hold or release elsewhere than at its own feed's position.
        let unplaced = fx.svc(11, "svc-1", "svc-1", C::Release, A);
        // svc-2 has no coverage on this host.
        let uncovered = fx.svc(12, "svc-2", "svc-2", C::Hold, A);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &s(1, C::Cover),
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(&s(2, C::Hold), at(A, 2), held.clone()),
                // Held already: a duplicate, now the last in feed order.
                Step::new(&s(3, C::Hold), at(A, 4), dup(&[E::Hold])),
                // A release before the last hold in feed order: superseded.
                Step::new(&s(4, C::Release), at(A, 3), all(R::Refused, &[E::Release])),
                Step::new(&s(5, C::Release), at(A, 5), released.clone()),
                Step::new(&s(6, C::Hold), at(A, 6), held.clone()),
                // Another record at the same position: not after it.
                Step::new(&s(7, C::Release), at(A, 6), all(R::Refused, &[E::Release])),
                Step::new(&unplaced, None, all(R::Refused, &[E::Release])),
                Step::new(&unplaced, at(B, 7), all(R::Refused, &[E::Release])),
                Step::new(&uncovered, at(A, 8), all(R::Refused, &[E::Hold])),
                Step::new(&s(9, C::Release), at(A, 9), released),
                Step::new(&unplaced, at(A, 10), dup(&[E::Release])),
            ],
        );
    }

    #[test]
    fn release_after_revoke_ignored() {
        let fx = Fx::new();
        let mut state = fx.state();
        let s1 = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let s2 = |n: u32, action: ControlAction| fx.svc(n, "svc-2", "svc-2", action, A);
        let other_station = fx.svc(20, "svc-1", "svc-1", C::Cover, B);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &s1(1, C::Cover),
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(
                    &s1(2, C::Hold),
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                Step::new(
                    &s1(3, revoke(false)),
                    at(A, 3),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied)],
                        vec![H::Revoke(service("svc-1"))],
                    ),
                ),
                // Never released after a revoke, never a new coverage;
                // asking for what is recorded changes nothing either.
                Step::new(&s1(4, C::Release), at(A, 4), all(R::Refused, &[E::Release])),
                Step::new(&s1(5, C::Hold), at(A, 5), dup(&[E::Hold])),
                Step::new(&other_station, at(B, 1), all(R::Refused, &[E::Cover])),
                Step::new(&s1(6, C::Cover), at(A, 6), dup(&[E::Cover])),
                Step::new(&s1(7, C::Release), at(A, 7), all(R::Refused, &[E::Release])),
                // Revoked, never held: a hold is ignored too.
                Step::new(
                    &s2(8, C::Cover),
                    at(A, 8),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-2", A)],
                    ),
                ),
                Step::new(
                    &s2(9, revoke(false)),
                    at(A, 9),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied)],
                        vec![H::Revoke(service("svc-2"))],
                    ),
                ),
                Step::new(&s2(10, C::Hold), at(A, 10), all(R::Refused, &[E::Hold])),
                Step::new(&s2(11, C::Release), at(A, 11), dup(&[E::Release])),
            ],
        );
    }

    #[test]
    fn release_from_other_feed_refused() {
        let fx = Fx::new();
        let mut state = fx.state();
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let b = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, B);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &a(1, C::Cover),
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(
                    &a(2, C::Hold),
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                // Another Station's feed doesn't cover it.
                Step::new(&b(3, C::Release), at(B, 1), all(R::Refused, &[E::Release])),
                // A release naming the covering feed, read from another.
                Step::new(&a(4, C::Release), at(B, 2), all(R::Refused, &[E::Release])),
                Step::new(
                    &a(5, C::Release),
                    at(A, 3),
                    out(
                        R::Applied,
                        &[(E::Release, R::Applied)],
                        vec![H::Release(service("svc-1"))],
                    ),
                ),
                Step::new(&b(6, C::Hold), at(B, 3), all(R::Refused, &[E::Hold])),
            ],
        );

        // Another Station whose records name the covering feed's feed_id:
        // still not the covering Station.
        let reusing: Feed = (B.0, A.1);
        let hold = fx.svc(7, "svc-1", "svc-1", C::Hold, reusing);
        assert_eq!(
            state.apply(&hold, &fx.list, at(A, 4), 0),
            all(R::Refused, &[E::Hold])
        );
    }

    #[test]
    fn a_newer_cover_from_another_station_takes_coverage_and_the_hold_persists() {
        let fx = Fx::new();
        let mut state = fx.state();
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let b = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, B);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &a(1, C::Cover),
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(
                    &a(2, C::Hold),
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                // B's cover is newer than A's: B's feed covers it from its
                // cover on. A cover never releases (ruling T11a): A's hold
                // stays in force.
                Step::new(
                    &b(3, C::Cover),
                    at(B, 5),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", B)],
                    ),
                ),
                // B's records before its cover aren't part of its coverage.
                Step::new(&b(4, C::Release), at(B, 4), all(R::Refused, &[E::Release])),
                // Held already; now the last in B's feed order.
                Step::new(&b(5, C::Hold), at(B, 6), dup(&[E::Hold])),
                Step::new(&b(6, C::Release), at(B, 6), all(R::Refused, &[E::Release])),
                // Only the covering feed's release, after its cover, lifts it.
                Step::new(
                    &b(7, C::Release),
                    at(B, 7),
                    out(
                        R::Applied,
                        &[(E::Release, R::Applied)],
                        vec![H::Release(service("svc-1"))],
                    ),
                ),
                // B covering again: the same coverage.
                Step::new(&b(8, C::Cover), at(B, 8), dup(&[E::Cover])),
                Step::new(
                    &b(9, C::Hold),
                    at(B, 9),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                // Back to A with a newer cover: B's hold stays too.
                Step::new(
                    &a(10, C::Cover),
                    at(A, 3),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(
                    &b(11, C::Release),
                    at(B, 10),
                    all(R::Refused, &[E::Release]),
                ),
                Step::new(
                    &a(12, C::Release),
                    at(A, 4),
                    out(
                        R::Applied,
                        &[(E::Release, R::Applied)],
                        vec![H::Release(service("svc-1"))],
                    ),
                ),
            ],
        );
    }

    #[test]
    fn a_stale_cover_from_a_previous_station_neither_releases_nor_takes_coverage() {
        let fx = Fx::new();
        let mut state = fx.state();
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let b = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, B);
        // B covered svc-1 first; A took it over with a newer cover and
        // holds it.
        let b_cover = b(1, C::Cover);
        let a_cover = a(8, C::Cover);
        // What B retained: a cover signed anew but issued before A's, and
        // one issued at the same time with a lower record id.
        let older = fx.svc_issued(4, "svc-1", C::Cover, B, issued(7));
        let same_time = fx.svc_issued(5, "svc-1", C::Cover, B, issued(8));
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &b_cover,
                    at(B, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", B)],
                    ),
                ),
                Step::new(
                    &a_cover,
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(
                    &a(9, C::Hold),
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                // B's own cover again (a sync from 0, a snapshot): the same
                // record, changing nothing.
                Step::new(&b_cover, at(B, 1), dup(&[E::Cover])),
                // Not newer than A's: refused, no release, no coverage.
                Step::new(&older, at(B, 2), all(R::Refused, &[E::Cover])),
                Step::new(&same_time, at(B, 3), all(R::Refused, &[E::Cover])),
                // A still covers it, and it is still held: B's release is
                // refused, and only A's lifts the hold.
                Step::new(&b(10, C::Release), at(B, 4), all(R::Refused, &[E::Release])),
                Step::new(
                    &a(11, C::Release),
                    at(A, 3),
                    out(
                        R::Applied,
                        &[(E::Release, R::Applied)],
                        vec![H::Release(service("svc-1"))],
                    ),
                ),
            ],
        );
    }

    #[test]
    fn a_release_from_the_old_station_after_a_move_refused() {
        let fx = Fx::new();
        let mut state = fx.state();
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let b = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, B);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &a(1, C::Cover),
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(
                    &a(2, C::Hold),
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                Step::new(
                    &b(3, C::Cover),
                    at(B, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", B)],
                    ),
                ),
                // A no longer covers it, in order or not.
                Step::new(&a(4, C::Release), at(A, 3), all(R::Refused, &[E::Release])),
                Step::new(&a(4, C::Release), at(A, 3), all(R::Refused, &[E::Release])),
                Step::new(
                    &b(5, C::Release),
                    at(B, 2),
                    out(
                        R::Applied,
                        &[(E::Release, R::Applied)],
                        vec![H::Release(service("svc-1"))],
                    ),
                ),
                Step::new(&a(6, C::Hold), at(A, 4), all(R::Refused, &[E::Hold])),
            ],
        );
    }

    #[test]
    fn after_a_reset_hold_and_release_are_ordered_within_the_new_feed() {
        let fx = Fx::new();
        let mut state = fx.state();
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let a2 = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A2);
        let held = out(
            R::Applied,
            &[(E::Hold, R::Applied)],
            vec![H::Hold(service("svc-1"))],
        );
        let released = out(
            R::Applied,
            &[(E::Release, R::Applied)],
            vec![H::Release(service("svc-1"))],
        );
        // An old-feed cover the host kept pending, issued before the reset.
        let old_cover = fx.svc_issued(9, "svc-1", C::Cover, A, issued(3));
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &a(1, C::Cover),
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                Step::new(&a(2, C::Hold), at(A, 5), held.clone()),
                Step::new(&a(3, C::Release), at(A, 6), released.clone()),
                // The reset's snapshot (A2, feed_seq from 1): its cover is
                // the same coverage (a duplicate) and moves its order to A2.
                Step::new(
                    &a2(4, C::Cover),
                    at(A2, 1),
                    out(
                        R::Duplicate,
                        &[(E::Cover, R::Duplicate)],
                        vec![cover_action("svc-1", A2)],
                    ),
                ),
                // Ordered within A2: 2 is after A2's cover, though below the
                // old feed's 6.
                Step::new(&a2(5, C::Hold), at(A2, 2), held.clone()),
                Step::new(
                    &a2(6, C::Release),
                    at(A2, 2),
                    all(R::Refused, &[E::Release]),
                ),
                // The old feed's records no longer order against A2's.
                Step::new(&a(7, C::Release), at(A, 7), all(R::Refused, &[E::Release])),
                Step::new(&a2(8, C::Release), at(A2, 3), released.clone()),
                // A cover of the old feed, older than A2's: the same Station
                // (a duplicate) that doesn't move the order back.
                Step::new(&old_cover, at(A, 8), dup(&[E::Cover])),
                Step::new(&a(10, C::Hold), at(A, 9), all(R::Refused, &[E::Hold])),
                Step::new(&a2(11, C::Hold), at(A2, 4), held),
            ],
        );
    }

    #[test]
    fn conflicting_body_same_id_refused_and_evidence() {
        let fx = Fx::new();
        let mut state = fx.state();
        let first = fx.svc(1, "svc-1", "svc-1", revoke(false), A);
        // Another body under the same record id, validly signed.
        let second = fx.svc(1, "svc-1", "svc-1", revoke(true), A);
        let interrupt = fx.svc(2, "svc-1", "mac", INTERRUPT, A);
        // A forgery (svc-2's key for svc-1's record) under the id a genuine
        // record uses later: refused, and it doesn't take the id.
        let forged = fx.sign(&fx.service_body(3, "svc-1", "svc-1", C::Hold, A), "svc-2");
        let genuine = fx.svc(3, "svc-1", "svc-1", C::Cover, A);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &first,
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied)],
                        vec![H::Revoke(service("svc-1"))],
                    ),
                ),
                Step::new(
                    &second,
                    at(A, 2),
                    evidence(all(R::Refused, &[E::Revocation, E::Interrupt])),
                ),
                // The first counts; the second changed nothing (its
                // interrupt wasn't applied).
                Step::new(&first, at(A, 1), dup(&[E::Revocation])),
                Step::new(
                    &interrupt,
                    at(A, 3),
                    out(
                        R::Applied,
                        &[(E::Interrupt, R::Applied)],
                        vec![interrupt_action(service("svc-1"), rid(1))],
                    ),
                ),
                Step::new(
                    &second,
                    None,
                    evidence(all(R::Refused, &[E::Revocation, E::Interrupt])),
                ),
                Step::new(&forged, at(A, 4), evidence(all(R::Refused, &[E::Hold]))),
                Step::new(&genuine, at(A, 5), all(R::Refused, &[E::Cover])),
            ],
        );
        // svc-1 is revoked, so its cover is ignored; on a fresh state the
        // genuine record under the forged id applies.
        let mut fresh = fx.state();
        assert_eq!(
            fresh.apply(&forged, &fx.list, at(A, 4), 0),
            evidence(all(R::Refused, &[E::Hold]))
        );
        assert_eq!(
            fresh.apply(&genuine, &fx.list, at(A, 5), 0),
            out(
                R::Applied,
                &[(E::Cover, R::Applied)],
                vec![cover_action("svc-1", A)]
            )
        );
        assert_eq!(
            fresh.apply(&forged, &fx.list, at(A, 4), 0),
            evidence(all(R::Refused, &[E::Hold]))
        );
    }

    #[test]
    fn verification_refusals_are_evidence_and_pending_waits() {
        let mut fx = Fx::new();
        let mut state = fx.state();
        // A service the list doesn't hold yet: pending, applied once the
        // list holds it.
        let unknown = fx.svc(1, "svc-new", "svc-new", C::Cover, A);
        let pending = all(R::Pending, &[E::Cover]);
        assert_eq!(state.apply(&unknown, &fx.list, at(A, 1), 0), pending);
        assert_eq!(state.apply(&unknown, &fx.list, at(A, 1), 0), pending);
        fx.add_service("svc-new");
        assert_eq!(
            state.apply(&unknown, &fx.list, at(A, 1), 0),
            out(
                R::Applied,
                &[(E::Cover, R::Applied)],
                vec![cover_action("svc-new", A)]
            )
        );
        // A manager's hold: refused whatever the list holds, and evidence.
        let manager_hold = fx.svc(2, "svc-1", "mac", C::Hold, A);
        assert_eq!(
            state.apply(&manager_hold, &fx.list, at(A, 2), 0),
            evidence(all(R::Refused, &[E::Hold]))
        );
        // A record of another account.
        let other = Fx::account("acct-test-2").svc(3, "svc-1", "svc-1", revoke(true), A);
        assert_eq!(
            state.apply(&other, &fx.list, at(A, 3), 0),
            evidence(all(R::Refused, &[E::Revocation, E::Interrupt]))
        );
    }

    #[test]
    fn host_interrupt_pending_until_revoke_applied() {
        let mut fx = Fx::new();
        let r1 = fx.revoke_host(false);
        let mut state = fx.state();
        let host = "host:host-a".to_string();
        let first = fx.host(1, "mac", r1);
        let copy = fx.host(2, "phone", r1);
        let applied = out(
            R::Applied,
            &[(E::Interrupt, R::Applied)],
            vec![interrupt_action(host.clone(), r1.to_string())],
        );
        run(
            &mut state,
            &fx.list,
            vec![
                // Host-work's applied device-list seq (not the list's head)
                // hasn't reached the revoke: its cancellations aren't
                // durable yet.
                Step(
                    first.clone(),
                    None,
                    r1 - 1,
                    all(R::Pending, &[E::Interrupt]),
                ),
                Step(first.clone(), None, r1, applied),
                Step(first.clone(), None, r1, dup(&[E::Interrupt])),
                Step(copy, None, r1 + 5, dup(&[E::Interrupt])),
                // Bound to no feed: where it was read plays no part.
                Step(first, at(A, 1), r1, dup(&[E::Interrupt])),
            ],
        );

        // Readmitted, then revoked again with `interrupt_running`: the
        // revoke's own interrupt is applied with the entry, so a later
        // record for it is a duplicate once host-work applied that seq.
        fx.readmit_host();
        let r2 = fx.revoke_host(true);
        let for_r2 = fx.host(3, "mac", r2);
        // Readmitted and revoked once more, without it.
        fx.readmit_host();
        let r3 = fx.revoke_host(false);
        let for_r3 = fx.host(4, "mac", r3);
        // A revoke the host's list doesn't hold yet.
        let beyond = fx.host(5, "mac", r3 + 3);
        run(
            &mut state,
            &fx.list,
            vec![
                Step(
                    for_r2.clone(),
                    None,
                    r2 - 1,
                    all(R::Pending, &[E::Interrupt]),
                ),
                Step(for_r2, None, r2, dup(&[E::Interrupt])),
                Step(for_r3.clone(), None, r2, all(R::Pending, &[E::Interrupt])),
                Step(
                    for_r3.clone(),
                    None,
                    r3,
                    out(
                        R::Applied,
                        &[(E::Interrupt, R::Applied)],
                        vec![interrupt_action(host.clone(), r3.to_string())],
                    ),
                ),
                Step(for_r3, None, r3, dup(&[E::Interrupt])),
                Step(beyond, None, r3 + 3, all(R::Pending, &[E::Interrupt])),
            ],
        );
    }

    #[test]
    fn manager_removed_before_the_transaction_refused() {
        let mut fx = Fx::new();
        let r = fx.revoke_host(false);
        let before = fx.list.clone();
        let by_phone = fx.svc(1, "svc-1", "phone", revoke(true), A);
        let interrupt = fx.host(2, "phone", r);
        // Verified before the transaction: valid then.
        assert!(matches!(
            verify_control(&by_phone, &before),
            ControlCheck::Valid(_)
        ));
        assert!(matches!(
            verify_control(&interrupt, &before),
            ControlCheck::Valid(_)
        ));
        let mut applied_before = fx.state();
        assert_eq!(
            applied_before
                .apply(&by_phone, &before, at(A, 1), 0)
                .record_result,
            R::Applied
        );

        // `phone` removed before the transaction that applies them: they
        // are verified against that transaction's head, and refused.
        fx.append(
            "mac",
            Action::Remove {
                device_id: "phone".into(),
            },
        );
        let mut state = fx.state();
        let head = fx.list.head().seq;
        let resigned = fx.svc(3, "svc-1", "mac", revoke(true), A);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &by_phone,
                    at(A, 1),
                    evidence(all(R::Refused, &[E::Revocation, E::Interrupt])),
                ),
                Step(
                    interrupt.clone(),
                    None,
                    head,
                    evidence(all(R::Refused, &[E::Interrupt])),
                ),
                // Nothing was applied: Astation's re-signed copy applies.
                Step::new(
                    &resigned,
                    at(A, 2),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied), (E::Interrupt, R::Applied)],
                        vec![
                            H::Revoke(service("svc-1")),
                            interrupt_action(service("svc-1"), rid(3)),
                        ],
                    ),
                ),
                // The refused record took no id: refused again.
                Step::new(
                    &by_phone,
                    at(A, 1),
                    evidence(all(R::Refused, &[E::Revocation, E::Interrupt])),
                ),
            ],
        );

        // A record applied before its signer was removed stays applied: the
        // same record is acknowledged as a duplicate (a revoke is final).
        assert_eq!(
            applied_before.apply(&by_phone, &fx.list, at(A, 1), 0),
            dup(&[E::Revocation, E::Interrupt])
        );
    }

    #[test]
    fn feed_reset_snapshot_reissues_are_duplicates() {
        let mut fx = Fx::new();
        let r = fx.revoke_host(false);
        let head = fx.list.head().seq;
        // Feed A: svc-1 covered, held, revoked by a manager, then
        // interrupted; svc-2 covered and held; host-a interrupted.
        let s1 =
            |n: u32, action: ControlAction, feed: Feed| fx.svc(n, "svc-1", "svc-1", action, feed);
        let s2 =
            |n: u32, action: ControlAction, feed: Feed| fx.svc(n, "svc-2", "svc-2", action, feed);
        let cover1 = s1(1, C::Cover, A);
        let hold1 = s1(2, C::Hold, A);
        let revoked = fx.svc(3, "svc-1", "mac", revoke(false), A);
        let interrupted = fx.svc(4, "svc-1", "phone", INTERRUPT, A);
        let cover2 = s2(5, C::Cover, A);
        let hold2 = s2(6, C::Hold, A);
        let host_interrupt = fx.host(7, "mac", r);
        let history = vec![
            Step::new(
                &cover1,
                at(A, 1),
                out(
                    R::Applied,
                    &[(E::Cover, R::Applied)],
                    vec![cover_action("svc-1", A)],
                ),
            ),
            Step::new(
                &hold1,
                at(A, 2),
                out(
                    R::Applied,
                    &[(E::Hold, R::Applied)],
                    vec![H::Hold(service("svc-1"))],
                ),
            ),
            Step::new(
                &revoked,
                at(A, 3),
                out(
                    R::Applied,
                    &[(E::Revocation, R::Applied)],
                    vec![H::Revoke(service("svc-1"))],
                ),
            ),
            Step::new(
                &interrupted,
                at(A, 4),
                out(
                    R::Applied,
                    &[(E::Interrupt, R::Applied)],
                    vec![interrupt_action(service("svc-1"), rid(3))],
                ),
            ),
            Step::new(
                &cover2,
                at(A, 5),
                out(
                    R::Applied,
                    &[(E::Cover, R::Applied)],
                    vec![cover_action("svc-2", A)],
                ),
            ),
            Step::new(
                &hold2,
                at(A, 6),
                out(
                    R::Applied,
                    &[(E::Hold, R::Applied)],
                    vec![H::Hold(service("svc-2"))],
                ),
            ),
            Step(
                host_interrupt.clone(),
                None,
                head,
                out(
                    R::Applied,
                    &[(E::Interrupt, R::Applied)],
                    vec![interrupt_action("host:host-a".into(), r.to_string())],
                ),
            ),
        ];
        let mut state = fx.state();
        run(&mut state, &fx.list, history);

        // The Station's feed is reset (A2: a new feed_id, the same origin).
        // Its snapshot re-issues each covered principal's state: the
        // service-signed cover, hold or release signed anew for the new
        // feed, the native records as they are (no Station can re-sign
        // them), and the Station's own revoke beside the native one.
        let snapshot = vec![
            Step::new(&s1(11, C::Cover, A2), at(A2, 1), dup(&[E::Cover])),
            Step::new(&s1(12, C::Hold, A2), at(A2, 2), dup(&[E::Hold])),
            Step::new(&revoked, at(A2, 3), dup(&[E::Revocation])),
            Step::new(
                &s1(13, revoke(true), A2),
                at(A2, 4),
                dup(&[E::Revocation, E::Interrupt]),
            ),
            Step::new(&interrupted, at(A2, 5), dup(&[E::Interrupt])),
            // The coverage's order moves to A2: a duplicate naming A2.
            Step::new(
                &s2(14, C::Cover, A2),
                at(A2, 6),
                out(
                    R::Duplicate,
                    &[(E::Cover, R::Duplicate)],
                    vec![cover_action("svc-2", A2)],
                ),
            ),
            Step::new(&s2(15, C::Hold, A2), at(A2, 7), dup(&[E::Hold])),
            Step(
                host_interrupt.clone(),
                at(A2, 8),
                head,
                dup(&[E::Interrupt]),
            ),
        ];
        let after_reset = |state: &mut ControlState| {
            // The old feed's release no longer applies, even in its order.
            let old_release = s2(18, C::Release, A);
            assert_eq!(
                state.apply(&old_release, &fx.list, at(A, 7), 0),
                all(R::Refused, &[E::Release])
            );
            // The new feed continues the coverage: its release applies.
            let release = s2(16, C::Release, A2);
            assert_eq!(
                state.apply(&release, &fx.list, at(A2, 9), 0),
                out(
                    R::Applied,
                    &[(E::Release, R::Applied)],
                    vec![H::Release(service("svc-2"))]
                )
            );
            // The old feed's identity is gone; nothing of svc-1 was lost.
            let release1 = s1(17, C::Release, A2);
            assert_eq!(
                state.apply(&release1, &fx.list, at(A2, 10), 0),
                all(R::Refused, &[E::Release])
            );
        };
        run(&mut state, &fx.list, snapshot);
        after_reset(&mut state);

        // A host that never saw feed A: the snapshot alone applies every
        // stop, so a reset loses none.
        let mut fresh = fx.state();
        run(
            &mut fresh,
            &fx.list,
            vec![
                Step::new(
                    &s1(11, C::Cover, A2),
                    at(A2, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A2)],
                    ),
                ),
                Step::new(
                    &s1(12, C::Hold, A2),
                    at(A2, 2),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-1"))],
                    ),
                ),
                Step::new(
                    &revoked,
                    at(A2, 3),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Applied)],
                        vec![H::Revoke(service("svc-1"))],
                    ),
                ),
                Step::new(
                    &s1(13, revoke(true), A2),
                    at(A2, 4),
                    out(
                        R::Applied,
                        &[(E::Revocation, R::Duplicate), (E::Interrupt, R::Applied)],
                        vec![interrupt_action(service("svc-1"), rid(3))],
                    ),
                ),
                Step::new(&interrupted, at(A2, 5), dup(&[E::Interrupt])),
                Step::new(
                    &s2(14, C::Cover, A2),
                    at(A2, 6),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-2", A2)],
                    ),
                ),
                Step::new(
                    &s2(15, C::Hold, A2),
                    at(A2, 7),
                    out(
                        R::Applied,
                        &[(E::Hold, R::Applied)],
                        vec![H::Hold(service("svc-2"))],
                    ),
                ),
                Step(
                    host_interrupt,
                    at(A2, 8),
                    head,
                    out(
                        R::Applied,
                        &[(E::Interrupt, R::Applied)],
                        vec![interrupt_action("host:host-a".into(), r.to_string())],
                    ),
                ),
            ],
        );
        after_reset(&mut fresh);
    }

    #[test]
    fn another_device_list_or_a_frozen_one_applies_nothing() {
        let fx = Fx::new();
        let mut state = fx.state();
        let cover = fx.svc(1, "svc-1", "svc-1", C::Cover, A);

        // A state belongs to one device list: another account's list
        // applies nothing to it (its own record, valid there).
        let other = Fx::account("acct-test-2");
        let theirs = other.svc(2, "svc-1", "svc-1", C::Cover, A);
        assert!(matches!(
            verify_control(&theirs, &other.list),
            ControlCheck::Valid(_)
        ));
        assert_eq!(
            state.apply(&theirs, &other.list, at(A, 1), 0),
            all(R::Refused, &[E::Cover])
        );

        // A frozen list (a manager-signed sibling of its head): nothing is
        // applied while it is frozen (R9.4).
        let head = fx.list.head();
        let prev = fx.list.entry(head.seq - 1).unwrap().hash();
        let sibling = draft_on(
            ACCOUNT,
            &fx.list.genesis_hash(),
            head.seq,
            &prev,
            "mac",
            T0 + 99,
            &Action::Add {
                member: native(&fx.keys, "ipad", &[Role::View]),
            },
        );
        let sibling = sign_entry(&fx.keys, &KeyId::new("mac"), sibling).unwrap();
        let frozen = fx
            .list
            .evaluate_objects(&[sibling.object().clone()], &now(T0 + 100))
            .next;
        assert!(frozen.frozen().is_some());
        assert_eq!(
            state.apply(&cover, &frozen, at(A, 1), 0),
            all(R::Pending, &[E::Cover])
        );
        assert_eq!(state, fx.state());
        assert_eq!(
            state.apply(&cover, &fx.list, at(A, 1), 0).record_result,
            R::Applied
        );
    }

    /// A state with every part: svc-1 covered, held, revoked and
    /// interrupted; svc-2 covered and released in feed B; host-a
    /// interrupted after its revoke at `r`.
    fn full_state(fx: &mut Fx) -> (ControlState, Vec<ControlRecord>, u64) {
        let r = fx.revoke_host(false);
        let records = vec![
            fx.svc(1, "svc-1", "svc-1", C::Cover, A),
            fx.svc(2, "svc-1", "svc-1", C::Hold, A),
            fx.svc(3, "svc-1", "mac", revoke(true), A),
            fx.svc(4, "svc-2", "svc-2", C::Cover, B),
            fx.svc(5, "svc-2", "svc-2", C::Release, B),
            fx.host(6, "mac", r),
        ];
        let positions = [at(A, 1), at(A, 2), at(A, 3), at(B, 1), at(B, 2), None];
        let mut state = fx.state();
        for (rec, pos) in records.iter().zip(positions) {
            let result = state.apply(rec, &fx.list, pos, r).record_result;
            assert!(
                matches!(result, R::Applied | R::Duplicate),
                "{}",
                rec.record_id()
            );
        }
        (state, records, r)
    }

    fn digest(rec: &ControlRecord) -> String {
        Hash32::of(rec.object().jcs().as_bytes()).to_hex()
    }

    #[test]
    fn state_json_round_trips() {
        let mut fx = Fx::new();
        let empty = fx.state();
        let json = empty.to_json();
        assert_eq!(
            json,
            json!({
                "v": 1, "account_id": ACCOUNT,
                "genesis_hash": fx.list.genesis_hash().to_hex(),
                "records": {}, "services": {}, "hosts": {},
            })
        );
        assert_eq!(ControlState::from_json(&json).unwrap(), empty);

        let (state, records, r) = full_state(&mut fx);
        let json = state.to_json();
        let mut digests = serde_json::Map::new();
        for rec in &records {
            digests.insert(rec.record_id().into(), json!(digest(rec)));
        }
        assert_eq!(
            json,
            json!({
                "v": 1, "account_id": ACCOUNT,
                "genesis_hash": fx.list.genesis_hash().to_hex(),
                "records": digests,
                "services": {
                    "svc-1": {
                        "revoked_by": rid(3), "interrupted": true,
                        "coverage": {
                            "origin": A.0, "feed_id": A.1, "since": 1,
                            "cover": {"issued_at": issued(1), "record_id": rid(1)},
                        },
                        "hold": {"held": true, "feed_id": A.1, "feed_seq": 2},
                    },
                    "svc-2": {
                        "interrupted": false,
                        "coverage": {
                            "origin": B.0, "feed_id": B.1, "since": 1,
                            "cover": {"issued_at": issued(4), "record_id": rid(4)},
                        },
                        "hold": {"held": false, "feed_id": B.1, "feed_seq": 2},
                    },
                },
                "hosts": {"host-a": {"interrupted": [r]}},
            })
        );
        // Sorted maps: the serialized form is its own canonical form.
        assert_eq!(json.to_string(), jcs(&json).unwrap());

        let back = ControlState::from_json(&json).unwrap();
        assert_eq!(back, state);
        assert_eq!(back.to_json(), json);

        // A resumed state goes on exactly as the one it was saved from.
        let mut resumed = back;
        let mut original = state;
        let next = [
            (fx.svc(7, "svc-2", "svc-2", C::Hold, B), at(B, 3)),
            (fx.svc(8, "svc-2", "svc-2", revoke(false), B), at(B, 4)),
            (records[2].clone(), at(A, 3)),
            (fx.svc(9, "svc-1", "svc-1", C::Hold, A), at(A, 5)),
        ];
        for (rec, pos) in next {
            assert_eq!(
                resumed.apply(&rec, &fx.list, pos.clone(), r),
                original.apply(&rec, &fx.list, pos, r)
            );
        }
        assert_eq!(resumed, original);
        assert_eq!(resumed.to_json(), original.to_json());
    }

    #[test]
    fn state_json_refuses_what_it_never_writes() {
        let mut fx = Fx::new();
        let (state, _, _) = full_state(&mut fx);
        let good = state.to_json();
        type Edit = Box<dyn Fn(&mut Value)>;
        let edits: Vec<(&str, Edit)> = vec![
            ("v 2", Box::new(|j| j["v"] = json!(2))),
            ("unknown field", Box::new(|j| j["extra"] = json!(1))),
            (
                "missing hosts",
                Box::new(|j| {
                    j.as_object_mut().unwrap().remove("hosts");
                }),
            ),
            ("null", Box::new(|j| j["records"] = Value::Null)),
            ("empty account", Box::new(|j| j["account_id"] = json!(""))),
            (
                "uppercase hash",
                Box::new(|j| {
                    j["genesis_hash"] = json!(j["genesis_hash"].as_str().unwrap().to_uppercase())
                }),
            ),
            (
                "record id",
                Box::new(|j| j["records"]["not-a-uuid"] = json!("00".repeat(32))),
            ),
            (
                "record digest",
                Box::new(|j| j["records"][rid(1)] = json!("00")),
            ),
            (
                "service id",
                Box::new(|j| j["services"]["recovery"] = json!({"interrupted": false})),
            ),
            (
                "service field",
                Box::new(|j| j["services"]["svc-1"]["extra"] = json!(1)),
            ),
            (
                "interrupted without revoked_by",
                Box::new(|j| j["services"]["svc-2"]["interrupted"] = json!(true)),
            ),
            (
                "revoked_by not a record",
                Box::new(|j| j["services"]["svc-2"]["revoked_by"] = json!(rid(99))),
            ),
            (
                "coverage origin",
                Box::new(|j| {
                    j["services"]["svc-1"]["coverage"]["origin"] = json!("https://Station.example")
                }),
            ),
            (
                "coverage without its cover",
                Box::new(|j| {
                    j["services"]["svc-1"]["coverage"]
                        .as_object_mut()
                        .unwrap()
                        .remove("cover");
                }),
            ),
            (
                "cover not a record",
                Box::new(|j| {
                    j["services"]["svc-1"]["coverage"]["cover"]["record_id"] = json!(rid(99))
                }),
            ),
            (
                "cover issued_at",
                Box::new(|j| j["services"]["svc-1"]["coverage"]["cover"]["issued_at"] = json!("1")),
            ),
            (
                "hold feed",
                Box::new(|j| j["services"]["svc-1"]["hold"]["feed_id"] = json!("feed")),
            ),
            (
                "host seqs unsorted",
                Box::new(|j| j["hosts"]["host-a"]["interrupted"] = json!([9, 3])),
            ),
            (
                "host seqs repeated",
                Box::new(|j| j["hosts"]["host-a"]["interrupted"] = json!([3, 3])),
            ),
            (
                "host seqs empty",
                Box::new(|j| j["hosts"]["host-a"]["interrupted"] = json!([])),
            ),
            (
                "host seq zero",
                Box::new(|j| j["hosts"]["host-a"]["interrupted"] = json!([0])),
            ),
        ];
        for (what, edit) in edits {
            let mut bad = good.clone();
            edit(&mut bad);
            assert!(ControlState::from_json(&bad).is_err(), "{what}");
        }
        assert_eq!(ControlState::from_json(&good).unwrap(), state);
    }

    #[test]
    fn codes_are_the_result_vocabulary() {
        let results = [R::Applied, R::Duplicate, R::Pending, R::Refused];
        let codes: Vec<_> = results.iter().map(|r| r.code()).collect();
        assert_eq!(codes, ["applied", "duplicate", "pending", "refused"]);
        for r in results {
            assert_eq!(ApplicationResult::from_code(r.code()), Some(r));
        }
        let kinds = [E::Revocation, E::Interrupt, E::Hold, E::Release, E::Cover];
        let codes: Vec<_> = kinds.iter().map(|k| k.code()).collect();
        assert_eq!(
            codes,
            ["revocation", "interrupt", "hold", "release", "cover"]
        );
        for k in kinds {
            assert_eq!(EffectKind::from_code(k.code()), Some(k));
        }
        assert_eq!(ApplicationResult::from_code("Applied"), None);
        assert_eq!(EffectKind::from_code("revoke"), None);
    }
}

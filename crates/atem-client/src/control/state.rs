//! Applying control records on a host (delegated host-work design I.5.5),
//! with the per-effect application results it reports (I.5.8, "Delivery
//! progress is not application").
//!
//! [`ControlState`] is a host's control state: pure and deterministic (no
//! clocks, no I/O). [`ControlState::apply`] never changes the state it is
//! called on: it returns the record's results and the next state
//! ([`Transition`]).
//!
//! **Persistence, per principal.** The state is one part per principal
//! ([`ControlState::part`]), and a record changes at most its own
//! principal's ([`Transition::touched`]). The host writes the touched parts
//! of the next state (one row per principal) in the same
//! `host-work.sqlite` transaction as the [`HostAction`]s `apply` returns and
//! its scan cursor, and adopts the next state only once that transaction
//! committed; if the transaction fails, it applies the record again to the
//! state it kept, which gives the same results and actions. It resumes
//! with [`ControlState::from_parts`] for its pinned device list, which
//! loads that list's parts only and reports an earlier pairing's leftover
//! rows to delete ([`LoadedParts::foreign`]); at a live re-pair the host
//! deletes the old list's rows in the transaction that adopts the new
//! list's empty state. [`ControlState::to_json`] and [`ControlState::from_json`]
//! carry the same parts whole, for a store that keeps one value. A state
//! belongs to one device list (its account and genesis); re-pairing starts
//! a new one (II.3.1, "After a freeze").
//!
//! **Queries.** [`ControlState::standing`] is what is in force for one
//! principal: its revocation, the revocations whose interrupt is in force,
//! the hold and the covering feed ([`Standing`]). [`Applied::why`] says why
//! a record is pending or refused, or kept as evidence ([`Why`]).
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
//!   revocation already interrupted, a hold while held. For the
//!   revocation, `duplicate` means exactly "this host already has the
//!   revocation in force", which the Station's ledger counts as applied
//!   there (decision 8);
//! - `pending`: not in force yet, and it can be later (see below);
//! - `refused`: not in force, and never from this record.
//!
//! The record's result is `applied` when any effect is, `duplicate` when
//! every effect is, else `pending` or `refused`
//! ([`ApplicationResult::of_effects`]).
//!
//! **The rules** (I.5.4, I.5.5; rules 1, 5 and 6 as Atem proposes them for
//! Astation's and Auth/Portal's agreement):
//! 1. **Idempotent by principal and `record_id`.** A record that counted
//!    (`applied` or `duplicate`) is kept, under its principal, with the
//!    SHA-256 of its body's `jcs`. The same body again is `duplicate` for
//!    every effect, whatever its signature bytes, its position or what the
//!    list says now: a revoke whose signer was removed since stays
//!    applied. A record of one principal never blocks another principal's
//!    record with the same `record_id`. Another body under a `record_id`
//!    this principal's record counted with is verified first; then it is
//!    kept as `evidence`, and the first body keeps the id: a stop (`hold`,
//!    `revoke`, `interrupt_running`) still applies its effects (a stop
//!    only ever adds), while a `cover` or `release` is `refused`. A record
//!    kept pending or refused takes no `record_id`, so a forgery never
//!    blocks the genuine record. **Bounded** (decision 19, rulings T4a and
//!    T4d, for Astation's agreement): a principal keeps at most
//!    [`MAX_RECORD_IDS`] counted ids, and the next evicts its oldest,
//!    never the record that revoked it nor the coverage's cover; the
//!    principal's evicted floor is the newest `issued_at` evicted. An
//!    evicted record that comes back grants nothing. The floor guards only
//!    what can grant or lift, a `cover` or a `release`: one under an id
//!    not counted, issued no later than the floor, may be one replayed
//!    (`feed_seq` isn't signed, so whoever serves the host the covering
//!    feed, the Station or a carrier that rewrites its pages such as the
//!    `:8080` proxy, which signs no release, could re-serve an evicted
//!    release at a fresh position and lift a hold in force). It is
//!    `refused` and kept as evidence ([`Why::PossibleReplay`]). A cover
//!    or release applies when it was issued after every evicted record of
//!    that principal, which a Station meets for every record it signed
//!    itself when each cover or release it signs for a principal is issued
//!    after every record it signed for it before. A
//!    stop never meets the floor: a `hold` applies as any hold (an
//!    evicted one replayed holds again, which grants nothing), and a
//!    `revoke` or `interrupt_running` replayed is a `duplicate` (a
//!    revocation and its interrupts are final). A revoked principal's
//!    cover and release are inert already (rule 7). The residual: a
//!    Station whose clock lags the floor (after a switch to it, or after
//!    another Station's record issued ahead of its clock was evicted) has
//!    its covers and releases refused as possible replays until its
//!    `issued_at` passes the floor, which fails safe (holds stay, nothing
//!    new starts). An evicted manager's copy whose signer was removed since
//!    comes back `refused` as evidence (verified against today's list),
//!    and changes nothing.
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
//!    that `revoke_seq` names that host's `host_sender_revoke` in the
//!    list). A revoke entry that carried `interrupt_running: true` applied
//!    its interrupt with it, so a later record for it is a duplicate.
//!    Bound to no feed, a host principal's record counts from any feed and
//!    over a channel alike.
//! 5. **Coverage** (I.5.2) is per Station, and covers are ordered by their
//!    `(issued_at, record_id)`. A `cover` read at its own feed's position
//!    starts it. Another Station's `cover` takes it over only when strictly
//!    newer than the newest cover taken from the covering Station; an
//!    older or equal one is `refused` and changes nothing. Covers are
//!    signed by the principal's own key only (I.5.4), so a replayed old
//!    cover can't take coverage back. The same Station's `cover` is a
//!    `duplicate`; a newer one from another `feed_id` (its feed after a
//!    reset) moves the coverage's order to that feed, from its position (a
//!    [`HostAction::Cover`] names it). **A cover never releases:** it only
//!    starts delegated execution for future tasks (I.5.5 step 5), and a
//!    hold survives every coverage change.
//! 6. **A stop always wins: a hold applies from any feed, or from none;
//!    only a release follows feed order.** A hold is `applied` unless one
//!    is in force (`duplicate`). A release is taken only from the
//!    coverage's current feed, read at its own position there, after that
//!    feed's cover and after the last hold or release taken from that feed
//!    (a hold read at its own feed's position counts there whether or not
//!    that feed covers the principal); it lifts every hold, another feed's
//!    included. A release while none is in force is a `duplicate`; else
//!    one in order is `applied`, and any other `refused`. **And only a
//!    release issued after the holds** (O1, Astation's review of PR 2,
//!    #120 comment 6848326392): the state keeps, per principal, the newest
//!    `issued_at` of every hold it verified while the principal wasn't
//!    revoked (one that held, one that found it held, one read out of
//!    order, from another feed or at no position, one under a counted id),
//!    and a release in order lifts the hold only when issued strictly
//!    after it; one issued no later (the same millisecond included) is
//!    `refused` ([`Why::NotAfterHold`], no evidence) and takes no position
//!    in the feed's order. Feed order alone can't stop it: `feed_seq` isn't
//!    signed, so a carrier that withheld an older release, or the Station's
//!    own release refused before, could serve it after a newer hold. The
//!    time is never lowered or cleared: no release, cover, eviction, reset
//!    or restart erases it.
//! 7. **After a revoke**, `cover`, `hold` and `release` are ignored: they
//!    change nothing, a `duplicate` when they ask for what is recorded
//!    (the coverage's Station, the hold state), else `refused`. A revoked
//!    principal is never released and never covered anew.
//!
//! **Resets** (I.5.2). A reset's snapshot re-issues each covered
//! principal's state, from the Station's current effective state (never a
//! restored backup's view): first its `cover`, signed anew for the new
//! feed (so newer than the old feed's), then its `hold` or `release`, also
//! signed anew, and its revoke and interrupt records as they are, or
//! signed anew. The snapshot's cover moves the coverage's order to the new
//! feed: its releases are ordered within it (`feed_seq` restarts), and the
//! old feed's no longer apply. On a host that applied the old feed each
//! re-issued record is a `duplicate`; on one that never saw it they apply.
//! A snapshot whose cover isn't newer leaves the coverage on the old feed:
//! its holds still apply, its releases are refused until a newer cover.
//!
//! **Pending records** are the host's to keep (bounded, I.5.4), and to
//! apply again after every device-list advance, every advance of
//! host-work's applied device-list `seq`, and every revocation applied.
//! Refused ones with `evidence` are kept as evidence and alerted (I.5.4).
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::canonical::MAX_SAFE_INTEGER;
use crate::encoding::Hash32;
use crate::error::{Error, Result};
use crate::membership::{Action, Membership};
use crate::session::wire::is_uuid_v4;
use crate::station_route::normalize_relay;

use super::record::{ControlAction, ControlPrincipal, ControlRecord};
use super::verify::{ControlCheck, PendingReason, RefusalReason, verify_control};

/// The most counted record ids a principal keeps (rule 1, decision 19);
/// the next evicts the oldest, never the record that revoked it nor the
/// coverage's cover, and raises the principal's evicted floor. Its records
/// are then at most this many triples of some 125 bytes, about 32 KB (see
/// [`ControlState::part`] for the whole part's bound).
pub const MAX_RECORD_IDS: usize = 256;

/// The state's format: `"v"` of [`ControlState::to_json`].
const STATE_VERSION: u64 = 2;

/// A record's position in the feed it was read from (I.5.3: `feed_seq`
/// isn't a field of the record): the feed's Station `origin`, its
/// `feed_id`, and the position. `None` beside a record carried over a
/// channel, which is bound to no feed. A record is read at its own feed's
/// position only when `origin` and `feed_id` are its body's; otherwise
/// `apply` treats it as read at no position (a Station that copies another
/// Station's `feed_id` gets no position in that feed). **Host rule:**
/// `origin` is the host's own configured Station origin, the feed it
/// syncs, never one taken from a page or a record: that is what bounds a
/// part's `order` (one entry per origin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPos {
    pub origin: String,
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

    /// A record's result from its effects' (host-work-v1 §11.1): `applied`
    /// when any effect is, `duplicate` when every effect is, else `pending`
    /// when any is, else `refused`.
    pub fn of_effects(effects: &[EffectResult]) -> Self {
        let any = |r| effects.iter().any(|e| e.result == r);
        if any(ApplicationResult::Applied) {
            ApplicationResult::Applied
        } else if effects
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
    pub(super) fn of(action: ControlAction) -> Vec<EffectKind> {
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

/// Why a record is pending or refused, or kept as evidence
/// ([`Applied::why`]): what a host keeps beside a pending record or a
/// record kept as evidence, and alerts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// It waits: [`verify_control`]'s reason, a frozen list, a service's
    /// interrupt before its revocation, or a host principal's before
    /// host-work applied its revoke.
    Pending(PendingReason),
    /// [`verify_control`] refused it (evidence), or the list is another
    /// account's or genesis's (`wrong_account`, no evidence: the caller's
    /// error, not the record's).
    Refused(RefusalReason),
    /// A `cover` read at no position of its own feed, or a `release` not
    /// taken in feed order: not from the coverage's current feed at its own
    /// position, not after that feed's cover and its last hold or release,
    /// or with no coverage (rules 5 and 6).
    Order,
    /// A `cover`, `hold` or `release` after a revoke, asking for what isn't
    /// recorded (rule 7).
    AfterRevoke,
    /// Another body under a `record_id` this principal's record counted
    /// with (rule 1; evidence): a `cover` or `release` is refused, a stop
    /// applies as any other (its effects say how).
    Collision,
    /// Another Station's `cover`, no newer than the coverage's (rule 5).
    NotNewer,
    /// A `cover` or `release` whose `record_id` isn't counted, issued no
    /// later than the newest record of its principal the bound evicted (its
    /// evicted floor): possibly an evicted record replayed, so refused and
    /// kept as evidence (rule 1, rulings T4a and T4d; never a stop).
    PossibleReplay,
    /// A `release` taken in feed order while a hold is in force, issued no
    /// later than the newest hold the state verified for its principal
    /// (rule 6, O1): it would lift a hold signed after it, so refused (no
    /// evidence: a genuine record, only stale).
    NotAfterHold,
}

impl Why {
    /// A stable name: the reason's own for `Pending` and `Refused` (the
    /// sets are disjoint), else `order`, `after_revoke`, `collision`,
    /// `not_newer`, `possible_replay` or `not_after_hold`.
    pub fn code(self) -> &'static str {
        match self {
            Why::Pending(reason) => reason.code(),
            Why::Refused(reason) => reason.code(),
            Why::Order => "order",
            Why::AfterRevoke => "after_revoke",
            Why::Collision => "collision",
            Why::NotNewer => "not_newer",
            Why::PossibleReplay => "possible_replay",
            Why::NotAfterHold => "not_after_hold",
        }
    }

    /// From the name, exactly.
    pub fn from_code(code: &str) -> Option<Self> {
        PendingReason::ALL
            .into_iter()
            .map(Why::Pending)
            .chain(RefusalReason::ALL.into_iter().map(Why::Refused))
            .chain([
                Why::Order,
                Why::AfterRevoke,
                Why::Collision,
                Why::NotNewer,
                Why::PossibleReplay,
                Why::NotAfterHold,
            ])
            .find(|why| why.code() == code)
    }
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
    /// verification, or reuses the `record_id` of a record of the same
    /// principal that counted with another body.
    pub evidence: bool,
    /// Why it is pending or refused, or kept as evidence: set exactly then
    /// (a colliding record is `Collision`, whatever its result); `None`
    /// for a record that counted without question.
    pub why: Option<Why>,
}

impl Applied {
    /// Every effect of a record with `action` gets `result`; nothing done.
    fn all(
        action: ControlAction,
        result: ApplicationResult,
        evidence: bool,
        why: Option<Why>,
    ) -> Self {
        Applied {
            record_result: result,
            effects: EffectKind::of(action)
                .into_iter()
                .map(|effect| EffectResult { effect, result })
                .collect(),
            actions: Vec::new(),
            evidence,
            why,
        }
    }
}

/// What applying a record gives ([`ControlState::apply`]): its results and
/// the state after it. Store the [`ControlState::part`]s of `next` that
/// [`Transition::touched`] names in the transaction that carries out
/// `applied.actions`, and adopt `next` only once it committed: until then
/// the state applied on is the current one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub applied: Applied,
    pub next: ControlState,
    /// The principals whose part changed.
    touched: Vec<String>,
}

impl Transition {
    /// The principals whose part `next` changed: the record's principal,
    /// or none (a duplicate, a pending or refused record that changed
    /// nothing). Write exactly these parts of `next`; every other part is
    /// the state's applied on.
    pub fn touched(&self) -> Vec<String> {
        self.touched.clone()
    }
}

/// What a host's control state has in force for one principal
/// ([`ControlState::standing`]). A principal the state holds nothing for
/// has nothing in force (`Standing::default()`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Standing {
    /// A service's revocation: the `record_id` of the revoke that revoked
    /// it (I.5.5 step 2). Always `None` for a host principal, whose
    /// revocation is a device-list entry (`host_sender_revoke`), not a
    /// record.
    pub revoked: Option<String>,
    /// The revocations whose interrupt a record put in force, as
    /// [`HostAction::Interrupt`] names them: a service's revoking
    /// `record_id`, a host principal's `revoke_seq` in decimal (a revoke
    /// entry that carried `interrupt_running: true` interrupted with the
    /// entry, which is the device list's). Sorted as text: `"10"` before
    /// `"9"`.
    pub interrupted: BTreeSet<String>,
    /// A hold is in force (I.5.5 step 4).
    pub held: bool,
    /// The feed whose Station covers it (I.5.2): its future tasks are
    /// delegated, under that origin's gate. `None`: not covered.
    pub coverage: Option<Coverage>,
}

/// A covering feed: its Station's exact origin and the feed's current
/// `feed_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub origin: String,
    pub feed_id: String,
}

/// What [`ControlState::from_parts`] loaded: the state of the device list
/// it was given, and the principals whose stored parts name another list
/// (an earlier pairing's leftovers), never loaded: delete their rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedParts {
    pub state: ControlState,
    /// Sorted.
    pub foreign: Vec<String>,
}

/// A host's control state (the module docs give the rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlState {
    /// The device list it belongs to.
    account_id: String,
    genesis_hash: Hash32,
    /// By principal (`service:<id>`, `host:<host_id>`), every principal a
    /// record counted for. An apply copies only its own principal's part;
    /// the others stay shared with the state it was applied on.
    principals: BTreeMap<String, Arc<Part>>,
}

/// One principal's part of the state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Part {
    /// Every record of the principal that counted and wasn't evicted,
    /// oldest first. At most [`MAX_RECORD_IDS`]; never empty in a stored
    /// part.
    records: Vec<Counted>,
    /// The newest `issued_at` among the records the bound evicted: a
    /// `cover` or `release` under an id not counted, issued no later, may
    /// be one of them replayed (rule 1). `None` until one is
    /// evicted; from then on the records stay full.
    evicted_floor: Option<u64>,
    /// A service's control state (the default for a host principal).
    service: ServiceControl,
    /// A host principal's: the `revoke_seq`s a record interrupted (empty
    /// for a service).
    interrupted: BTreeSet<u64>,
}

/// A record that counted: its `record_id`, the SHA-256 of its body's
/// `jcs`, and its `issued_at` (the evicted floor's input).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Counted {
    record_id: String,
    digest: Hash32,
    issued_at: u64,
}

/// One service's control state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ServiceControl {
    /// The `record_id` of the revoke that revoked it.
    revoked_by: Option<String>,
    /// Its revocation's interrupt applied.
    interrupted: bool,
    coverage: Option<Covering>,
    /// A hold is in force.
    held: bool,
    /// The newest `issued_at` of every hold verified for the principal
    /// while it wasn't revoked (rule 6, O1): applied, a duplicate while
    /// held, read out of order, from another feed or at none, or under a
    /// counted id. A release lifts the hold only when issued after it. Never
    /// lowered and never cleared: a release, a cover, an eviction, a reset
    /// and a restart keep it. `None`: no hold's time known.
    hold_issued_at: Option<u64>,
    /// By Station origin, one feed (its `feed_id`) and the position of the
    /// last hold or release taken from it: a release from the covering
    /// feed comes after it. Another feed of the origin replaces the entry,
    /// but never the covering feed's, the only one a release reads (a
    /// reset's new feed starts after its cover, `since`); so the map holds
    /// one entry per origin the principal's holds and releases were read
    /// from.
    order: BTreeMap<String, (String, u64)>,
}

/// The Station whose feed covers a service: its feed's current
/// `feed_id`, the position of the cover that started the coverage there
/// (`since`), and the newest cover taken from that Station.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Covering {
    origin: String,
    feed_id: String,
    since: u64,
    cover: CoverKey,
}

/// Which of two covers is newer: `(issued_at, record_id)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CoverKey {
    issued_at: u64,
    record_id: String,
}

/// The effects' results, the host's actions and why an effect isn't in
/// force, as a record is applied.
#[derive(Default)]
struct Outcome {
    effects: Vec<EffectResult>,
    actions: Vec<HostAction>,
    why: Option<Why>,
}

impl Outcome {
    fn effect(&mut self, effect: EffectKind, result: ApplicationResult) {
        self.effects.push(EffectResult { effect, result });
    }

    /// An effect that isn't in force (`pending` or `refused`), and why.
    fn not_in_force(&mut self, effect: EffectKind, result: ApplicationResult, why: Why) {
        self.effect(effect, result);
        self.why.get_or_insert(why);
    }

    fn record_result(&self) -> ApplicationResult {
        ApplicationResult::of_effects(&self.effects)
    }
}

impl Part {
    /// The digest `record_id` counted with, if it is counted.
    fn counted(&self, record_id: &str) -> Option<Hash32> {
        self.records
            .iter()
            .find(|c| c.record_id == record_id)
            .map(|c| c.digest)
    }

    /// Whether a `cover` or `release` issued at `issued_at`, under an id
    /// not counted, may be an evicted record replayed: issued no later than
    /// the newest one evicted.
    fn possible_replay(&self, issued_at: u64) -> bool {
        self.evicted_floor.is_some_and(|floor| issued_at <= floor)
    }

    /// Counts `record_id` (not counted yet) as the newest; past
    /// [`MAX_RECORD_IDS`], evicts the oldest id that is neither the
    /// revocation's record nor the coverage's cover, raising the evicted
    /// floor to its `issued_at`.
    fn count(&mut self, record_id: &str, digest: Hash32, issued_at: u64) {
        self.records.push(Counted {
            record_id: record_id.to_owned(),
            digest,
            issued_at,
        });
        if self.records.len() <= MAX_RECORD_IDS {
            return;
        }
        let pinned = [
            self.service.revoked_by.as_deref(),
            self.service
                .coverage
                .as_ref()
                .map(|c| c.cover.record_id.as_str()),
        ];
        // At most two are pinned, so one of the oldest three goes.
        if let Some(oldest) = self
            .records
            .iter()
            .position(|c| !pinned.contains(&Some(c.record_id.as_str())))
        {
            let evicted = self.records.remove(oldest);
            self.evicted_floor = Some(
                self.evicted_floor
                    .map_or(evicted.issued_at, |floor| floor.max(evicted.issued_at)),
            );
        }
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
            && self.evicted_floor.is_none()
            && self.service == ServiceControl::default()
            && self.interrupted.is_empty()
    }

    /// The part's durable form (keys in sorted order): its device list's
    /// `account_id` and `genesis_hash`, its `records` and `evicted_floor`,
    /// and a service's control state, or a host principal's `interrupted`
    /// `revoke_seq`s (omitted when none).
    fn to_json(&self, host: bool, account_id: &str, genesis_hash: &Hash32) -> Value {
        let records: Vec<Value> = self
            .records
            .iter()
            .map(|c| json!([c.record_id, c.digest.to_hex(), c.issued_at]))
            .collect();
        let mut o = Map::new();
        o.insert("account_id".into(), json!(account_id));
        // A host principal's service state is the default: no coverage.
        if let Some(c) = &self.service.coverage {
            let cover = json!({"issued_at": c.cover.issued_at, "record_id": c.cover.record_id});
            let coverage = json!({
                "cover": cover, "feed_id": c.feed_id, "origin": c.origin, "since": c.since,
            });
            o.insert("coverage".into(), coverage);
        }
        if let Some(floor) = self.evicted_floor {
            o.insert("evicted_floor".into(), json!(floor));
        }
        o.insert("genesis_hash".into(), json!(genesis_hash.to_hex()));
        if host {
            if !self.interrupted.is_empty() {
                o.insert("interrupted".into(), json!(self.interrupted));
            }
        } else {
            let service = &self.service;
            o.insert("held".into(), json!(service.held));
            if let Some(at) = service.hold_issued_at {
                o.insert("hold_issued_at".into(), json!(at));
            }
            o.insert("interrupted".into(), json!(service.interrupted));
            if !service.order.is_empty() {
                let order: Map<String, Value> = service
                    .order
                    .iter()
                    .map(|(origin, (feed_id, at))| {
                        let mut feed = Map::new();
                        feed.insert(feed_id.clone(), json!(at));
                        (origin.clone(), Value::Object(feed))
                    })
                    .collect();
                o.insert("order".into(), Value::Object(order));
            }
        }
        o.insert("records".into(), Value::Array(records));
        if let Some(by) = self.service.revoked_by.as_ref().filter(|_| !host) {
            o.insert("revoked_by".into(), json!(by));
        }
        Value::Object(o)
    }

    /// A part [`Part::to_json`] wrote for `principal` (its canonical name)
    /// of the device list `account_id`/`genesis_hash`, read strictly. A part
    /// of another device list is [`Error::GenesisMismatch`].
    fn from_json(
        principal: &str,
        value: &Value,
        account_id: &str,
        genesis_hash: &Hash32,
    ) -> Result<Self> {
        let parsed = ControlPrincipal::parse(principal)
            .filter(|p| p.name() == principal)
            .ok_or(Error::Malformed("control state principal"))?;
        let host = parsed.is_host();
        let o = if host {
            fields(
                value,
                &["account_id", "genesis_hash", "records"],
                &["evicted_floor", "interrupted"],
                "control state host",
            )?
        } else {
            fields(
                value,
                &[
                    "account_id",
                    "genesis_hash",
                    "held",
                    "interrupted",
                    "records",
                ],
                &[
                    "coverage",
                    "evicted_floor",
                    "hold_issued_at",
                    "order",
                    "revoked_by",
                ],
                "control state service",
            )?
        };
        // Its device list: the state's.
        let (account, genesis) = part_list(value)?;
        if account != account_id || genesis != *genesis_hash {
            return Err(Error::GenesisMismatch);
        }
        let records = records(&o["records"])?;
        let evicted_floor = match o.get("evicted_floor") {
            None => None,
            // Evicting leaves the records full.
            Some(floor) => Some(
                floor
                    .as_u64()
                    .filter(|floor| *floor <= MAX_SAFE_INTEGER)
                    .filter(|_| records.len() == MAX_RECORD_IDS)
                    .ok_or(Error::Malformed("control state evicted_floor"))?,
            ),
        };
        let mut interrupted = BTreeSet::new();
        let service = if host {
            if let Some(seqs) = o.get("interrupted") {
                let what = "control state host interrupted";
                let seqs = seqs
                    .as_array()
                    .filter(|seqs| !seqs.is_empty())
                    .ok_or(Error::Malformed(what))?;
                for seq in seqs {
                    let seq = seq
                        .as_u64()
                        .filter(|seq| (1..=MAX_SAFE_INTEGER).contains(seq))
                        .ok_or(Error::Malformed(what))?;
                    // Strictly increasing: sorted, no repeat.
                    if interrupted.last().is_some_and(|last| *last >= seq) {
                        return Err(Error::Malformed(what));
                    }
                    interrupted.insert(seq);
                }
            }
            ServiceControl::default()
        } else {
            ServiceControl::from_json(o, &records)?
        };
        Ok(Part {
            records,
            evicted_floor,
            service,
            interrupted,
        })
    }
}

impl ControlState {
    /// The empty control state of the device list `list` belongs to (its
    /// account and genesis).
    pub fn new(list: &Membership) -> Self {
        ControlState {
            account_id: list.account_id().to_owned(),
            genesis_hash: list.genesis_hash(),
            principals: BTreeMap::new(),
        }
    }

    /// Applies `rec`, verified against `list`: the device list at the head
    /// of the transaction that applies it. `pos` is where it was read
    /// (`None` over a channel). `host_applied_seq` is host-work's applied
    /// device-list `seq` (II.3.1), not the list's head. The module docs
    /// give the rules.
    ///
    /// The state it is called on doesn't change: the [`Transition`] gives
    /// the record's results, the next state and the principals whose part
    /// changed, which the caller stores and adopts once the transaction
    /// storing them has committed. So a failed transaction loses no
    /// effect: applying the record again to the state kept gives the same
    /// results and actions.
    ///
    /// The caller passes `pos` for a record read from a feed it syncs; a
    /// record whose body names another origin or `feed_id` than `pos` is
    /// read at no position (its hold still applies; its cover and release
    /// don't). The host never applies a record while it is held after a
    /// write fault (R9.3), which the state can't see.
    ///
    /// A list of another account or genesis than the state's applies
    /// nothing (`refused`, no evidence: the caller's error, not the
    /// record's); a frozen one applies nothing new (`pending`; a record
    /// that counted is still a `duplicate`).
    pub fn apply(
        &self,
        rec: &ControlRecord,
        list: &Membership,
        pos: Option<FeedPos>,
        host_applied_seq: u64,
    ) -> Transition {
        let principal = rec.principal().name();
        let mut next = self.clone();
        let applied = next.apply_in_place(rec, &principal, list, pos, host_applied_seq);
        let touched = if self.principals.get(&principal) == next.principals.get(&principal) {
            Vec::new()
        } else {
            vec![principal]
        };
        Transition {
            applied,
            next,
            touched,
        }
    }

    fn apply_in_place(
        &mut self,
        rec: &ControlRecord,
        principal: &str,
        list: &Membership,
        pos: Option<FeedPos>,
        host_applied_seq: u64,
    ) -> Applied {
        use ApplicationResult::{Duplicate, Pending, Refused};
        let action = rec.action();
        if list.account_id() != self.account_id || list.genesis_hash() != self.genesis_hash {
            let why = Why::Refused(RefusalReason::WrongAccount);
            return Applied::all(action, Refused, false, Some(why));
        }
        let digest = Hash32::of(rec.object().jcs().as_bytes());
        let kept = self.principals.get(principal);
        let counted = kept.and_then(|part| part.counted(rec.record_id()));
        if counted == Some(digest) {
            return Applied::all(action, Duplicate, false, None);
        }
        if list.frozen().is_some() {
            let why = Why::Pending(PendingReason::ListFrozen);
            return Applied::all(action, Pending, false, Some(why));
        }
        match verify_control(rec, list) {
            ControlCheck::Valid(_) => {}
            ControlCheck::Pending(reason) => {
                return Applied::all(action, Pending, false, Some(Why::Pending(reason)));
            }
            ControlCheck::Refused(reason) => {
                return Applied::all(action, Refused, true, Some(Why::Refused(reason)));
            }
        }
        // A cover or release (what can grant or lift) under an id this
        // principal doesn't count, issued no later than the newest record
        // the bound evicted, may be an evicted record replayed: `feed_seq`
        // isn't signed, so whoever serves the feed could re-serve one at a
        // fresh position. Refused, as evidence (ruling T4a). A legitimate
        // one is issued after every record of the principal its Station
        // signed before, so after the floor unless another Station's record
        // issued ahead of it was evicted. Never a stop (ruling T4d): a
        // hold applies as any hold, a replayed one only holding again, and
        // a revoke or interrupt replayed is a duplicate (both are final).
        // Nor a revoked principal's: rule 7 makes its cover and release
        // inert already.
        let guarded = matches!(action, ControlAction::Cover | ControlAction::Release);
        if counted.is_none()
            && guarded
            && kept.is_some_and(|part| {
                part.service.revoked_by.is_none() && part.possible_replay(rec.issued_at())
            })
        {
            return Applied::all(action, Refused, true, Some(Why::PossibleReplay));
        }
        // Another body under a record_id this principal's record counted
        // with: evidence, and the first body keeps the id. A stop still
        // applies (it only ever adds); a cover or release doesn't.
        let collides = counted.is_some();
        if collides && matches!(action, ControlAction::Cover | ControlAction::Release) {
            return Applied::all(action, Refused, true, Some(Why::Collision));
        }

        let mut part = self
            .principals
            .get(principal)
            .map_or_else(Part::default, |part| Part::clone(part));
        let mut out = Outcome::default();
        match rec.principal() {
            ControlPrincipal::Service(_) => {
                apply_service(&mut part.service, rec, principal, pos, &mut out)
            }
            ControlPrincipal::Host(_) => {
                apply_host(&mut part.interrupted, rec, list, host_applied_seq, &mut out)
            }
        }
        let record_result = out.record_result();
        if !collides && matches!(record_result, ApplicationResult::Applied | Duplicate) {
            part.count(rec.record_id(), digest, rec.issued_at());
        }
        self.store(principal, part);
        let why = if collides {
            Some(Why::Collision)
        } else if matches!(record_result, Pending | Refused) {
            out.why
        } else {
            None
        };
        Applied {
            record_result,
            effects: out.effects,
            actions: out.actions,
            evidence: collides,
            why,
        }
    }

    /// Keeps `part` as `principal`'s: none when empty, the part already
    /// kept when it is the same.
    fn store(&mut self, principal: &str, part: Part) {
        if part.is_empty() {
            self.principals.remove(principal);
        } else if self.principals.get(principal).map(|kept| &**kept) != Some(&part) {
            self.principals.insert(principal.to_owned(), Arc::new(part));
        }
    }

    /// What is in force for `principal` (`service:<id>`, `host:<host_id>`,
    /// as [`ControlPrincipal::name`] writes it): nothing for a principal
    /// the state holds nothing for, or a name that is none.
    pub fn standing(&self, principal: &str) -> Standing {
        let Some(part) = self.principals.get(principal) else {
            return Standing::default();
        };
        let service = &part.service;
        let mut interrupted: BTreeSet<String> =
            part.interrupted.iter().map(u64::to_string).collect();
        if let Some(by) = service.revoked_by.as_ref().filter(|_| service.interrupted) {
            interrupted.insert(by.clone());
        }
        Standing {
            revoked: service.revoked_by.clone(),
            interrupted,
            held: service.held,
            coverage: service.coverage.as_ref().map(|c| Coverage {
                origin: c.origin.clone(),
                feed_id: c.feed_id.clone(),
            }),
        }
    }

    /// Every principal the state has a part for, sorted.
    pub fn principals(&self) -> Vec<String> {
        self.principals.keys().cloned().collect()
    }

    /// `principal`'s part, in its durable form; `None` when the state has
    /// none (no record of it counted). Keys in sorted order:
    ///
    /// ```json
    /// service:<id>:   {"account_id":"…",
    ///                  "coverage":{"cover":{"issued_at":<ms>,"record_id":"…"},
    ///                              "feed_id":"…","origin":"…","since":<feed_seq>},
    ///                  "evicted_floor":<ms>,"genesis_hash":"<hex>",
    ///                  "held":true,"hold_issued_at":<ms>,"interrupted":false,
    ///                  "order":{"<origin>":{"<feed_id>":<feed_seq>}},
    ///                  "records":[["<record_id>","<hex SHA-256 of the body's jcs>",<issued_at>],…],
    ///                  "revoked_by":"<record_id>"}
    /// host:<host_id>: {"account_id":"…","evicted_floor":<ms>,"genesis_hash":"<hex>",
    ///                  "interrupted":[<revoke_seq>,…],"records":[…]}
    /// ```
    ///
    /// Every part names its device list (`account_id`, `genesis_hash`), so
    /// a store of parts never loads into another list's state. `records`
    /// are oldest first, one to [`MAX_RECORD_IDS`]; `order` holds one feed
    /// per Station origin; `hold_issued_at` is the newest `issued_at` of
    /// every hold verified for the service (rule 6, O1), present from the
    /// first one on and whenever `held`. A service's `coverage`, `order`,
    /// `hold_issued_at` and `revoked_by`, a host's `interrupted`, and
    /// `evicted_floor` until a record is evicted, are omitted when there
    /// are none. **A stored part without `hold_issued_at`** (written
    /// before O1, still `"v": 2`) is read as "no hold's time known" only
    /// while `held` is false: every hold a later release could lift is
    /// then verified after the load, so its time is recorded first; a
    /// held part without it is refused as damage
    /// ([`Error::Malformed`]), since the hold in force has no known time. A part is at
    /// most 256 records of some 125 bytes (about 32 KB), plus one `order`
    /// entry per origin the principal's holds and releases were read from
    /// (a host syncs its own Station's origin only), and a few hundred
    /// bytes more. A touched principal always has a part in `next`.
    pub fn part(&self, principal: &str) -> Option<Value> {
        let part = self.principals.get(principal)?;
        Some(part.to_json(is_host(principal), &self.account_id, &self.genesis_hash))
    }

    /// The state of `list`'s device list (the pinned list the caller
    /// holds; never inferred from the parts) made of the `parts` of that
    /// list (each [`ControlState::part`] with its principal, in any order),
    /// and the principals whose parts name another account or genesis
    /// (ruling T4e). Those are an earlier pairing's leftovers, such as the
    /// rows a live re-pair didn't delete: never loaded, so a service id
    /// that recurs in the new list inherits no revoke, hold or coverage,
    /// and reported in [`LoadedParts::foreign`] for the host to delete. The
    /// list's own parts are read strictly: each principal once (a key
    /// given twice fails, whichever list its parts name), exactly its
    /// kind's form, its types and grammars, and its invariants (an
    /// interrupt only after a revocation; the revocation's and the
    /// coverage's cover records among its records; an evicted floor only
    /// with full records; one feed per origin in `order`; a hold's time
    /// whenever held; sorted unique `revoke_seq`s; no empty list or map).
    /// A part whose device list can't
    /// be read (no `account_id`, a `genesis_hash` that isn't hex) might be
    /// the list's own, so it fails too: nothing is skipped unless it names
    /// another list. Never [`Error::GenesisMismatch`].
    pub fn from_parts(
        list: &Membership,
        parts: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<LoadedParts> {
        let parts: Vec<(String, Value)> = parts.into_iter().collect();
        let (state, foreign) = Self::assemble(
            list.account_id().to_owned(),
            list.genesis_hash(),
            parts.iter().map(|(p, part)| (p.as_str(), part)),
            true,
        )?;
        Ok(LoadedParts { state, foreign })
    }

    /// The state of `account_id`/`genesis_hash` made of `parts`; a part of
    /// another list is skipped and its principal returned when
    /// `skip_foreign`, else it fails ([`Error::GenesisMismatch`]).
    fn assemble<'a>(
        account_id: String,
        genesis_hash: Hash32,
        parts: impl Iterator<Item = (&'a str, &'a Value)>,
        skip_foreign: bool,
    ) -> Result<(Self, Vec<String>)> {
        let mut principals = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut foreign = Vec::new();
        for (principal, value) in parts {
            if !seen.insert(principal) {
                return Err(Error::Malformed("control state principal given twice"));
            }
            if skip_foreign {
                let (account, genesis) = part_list(value)?;
                if account != account_id || genesis != genesis_hash {
                    foreign.push(principal.to_owned());
                    continue;
                }
            }
            let part = Part::from_json(principal, value, &account_id, &genesis_hash)?;
            principals.insert(principal.to_owned(), Arc::new(part));
        }
        foreign.sort();
        let state = ControlState {
            account_id,
            genesis_hash,
            principals,
        };
        Ok((state, foreign))
    }

    /// The whole state's durable form: every part by principal, sorted.
    ///
    /// ```json
    /// {"account_id":"…","genesis_hash":"<hex>",
    ///  "principals":{"<principal>":<its part>,…},"v":2}
    /// ```
    pub fn to_json(&self) -> Value {
        let principals: Map<String, Value> = self
            .principals
            .iter()
            .map(|(principal, part)| {
                let part = part.to_json(is_host(principal), &self.account_id, &self.genesis_hash);
                (principal.clone(), part)
            })
            .collect();
        // Keys in sorted order, whatever `serde_json::Map` preserves.
        let mut o = Map::new();
        o.insert("account_id".into(), json!(self.account_id));
        o.insert("genesis_hash".into(), json!(self.genesis_hash.to_hex()));
        o.insert("principals".into(), Value::Object(principals));
        o.insert("v".into(), json!(STATE_VERSION));
        Value::Object(o)
    }

    /// A state from [`ControlState::to_json`], read strictly: exactly its
    /// fields, `v` 2, and each part as [`ControlState::from_parts`] reads
    /// it, of the header's account and genesis.
    pub fn from_json(value: &Value) -> Result<Self> {
        let o = fields(
            value,
            &["v", "account_id", "genesis_hash", "principals"],
            &[],
            "control state",
        )?;
        if o["v"].as_u64() != Some(STATE_VERSION) {
            return Err(Error::Malformed("control state v"));
        }
        let account_id = o["account_id"]
            .as_str()
            .filter(|id| (1..=128).contains(&id.len()))
            .ok_or(Error::Malformed("control state account_id"))?
            .to_owned();
        let genesis_hash = hash(&o["genesis_hash"], "control state genesis_hash")?;
        let principals = object(&o["principals"], "control state principals")?;
        let (state, _) = Self::assemble(
            account_id,
            genesis_hash,
            principals.iter().map(|(p, part)| (p.as_str(), part)),
            false,
        )?;
        Ok(state)
    }
}

/// The device list a part names: its `account_id` and `genesis_hash`.
fn part_list(value: &Value) -> Result<(&str, Hash32)> {
    let o = object(value, "control state part")?;
    let account = o
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or(Error::Malformed("control state part account_id"))?;
    let genesis = o
        .get("genesis_hash")
        .map(|g| hash(g, "control state part genesis_hash"))
        .unwrap_or(Err(Error::Malformed("control state part genesis_hash")))?;
    Ok((account, genesis))
}

/// Whether `principal` (a canonical name) is a host principal's.
fn is_host(principal: &str) -> bool {
    ControlPrincipal::parse(principal).is_some_and(|p| p.is_host())
}

/// A service's record, applied to its control state `state`.
fn apply_service(
    state: &mut ServiceControl,
    rec: &ControlRecord,
    principal: &str,
    pos: Option<FeedPos>,
    out: &mut Outcome,
) {
    let principal = principal.to_owned();
    // The parse gives every service record its feed.
    let (origin, feed_id) = rec.feed().unwrap_or_default();
    let pos = positioned(pos, origin, feed_id);
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
                interrupt(state, principal, revocation, out);
            }
        }
        ControlAction::InterruptRunning { .. } => match state.revoked_by.clone() {
            Some(revocation) => interrupt(state, principal, revocation, out),
            None => out.not_in_force(
                EffectKind::Interrupt,
                ApplicationResult::Pending,
                Why::Pending(PendingReason::NotRevoked),
            ),
        },
        ControlAction::Cover => {
            let key = CoverKey {
                issued_at: rec.issued_at(),
                record_id: rec.record_id().to_owned(),
            };
            cover(state, principal, key, pos, out);
        }
        ControlAction::Hold => hold(state, principal, rec.issued_at(), pos, out),
        ControlAction::Release => release(state, principal, rec.issued_at(), pos, out),
    }
}

/// A host principal's record, applied to the `revoke_seq`s a record
/// interrupted, `interrupted`.
fn apply_host(
    interrupted: &mut BTreeSet<u64>,
    rec: &ControlRecord,
    list: &Membership,
    host_applied_seq: u64,
    out: &mut Outcome,
) {
    // The parse gives a host principal's record exactly this form.
    let ControlAction::InterruptRunning {
        revoke_seq: Some(revoke_seq),
    } = rec.action()
    else {
        out.not_in_force(
            EffectKind::Interrupt,
            ApplicationResult::Refused,
            Why::Refused(RefusalReason::NotARevoke),
        );
        return;
    };
    if host_applied_seq < revoke_seq {
        out.not_in_force(
            EffectKind::Interrupt,
            ApplicationResult::Pending,
            Why::Pending(PendingReason::RevokeNotApplied),
        );
        return;
    }
    let by_entry = matches!(
        list.entry(revoke_seq).map(|entry| &entry.action),
        Some(Action::HostSenderRevoke {
            interrupt_running: true,
            ..
        })
    );
    if interrupted.contains(&revoke_seq) || by_entry {
        out.effect(EffectKind::Interrupt, ApplicationResult::Duplicate);
        return;
    }
    interrupted.insert(revoke_seq);
    out.effect(EffectKind::Interrupt, ApplicationResult::Applied);
    out.actions.push(HostAction::Interrupt {
        principal: rec.principal().name(),
        revocation: revoke_seq.to_string(),
    });
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

/// `pos`, when the record was read at its own feed's position: the
/// position's origin and `feed_id` are the body's.
fn positioned(pos: Option<FeedPos>, origin: &str, feed_id: &str) -> Option<FeedPos> {
    pos.filter(|pos| pos.origin == origin && pos.feed_id == feed_id)
}

/// A `cover` read at `pos` (its own feed's position, or none), issued as
/// `key`. It never releases.
fn cover(
    state: &mut ServiceControl,
    principal: String,
    key: CoverKey,
    pos: Option<FeedPos>,
    out: &mut Outcome,
) {
    let Some(pos) = pos else {
        out.not_in_force(EffectKind::Cover, ApplicationResult::Refused, Why::Order);
        return;
    };
    let revoked = state.revoked_by.is_some();
    let same_station = state
        .coverage
        .as_ref()
        .is_some_and(|c| c.origin == pos.origin);
    let newer = state.coverage.as_ref().is_none_or(|c| key > c.cover);
    if same_station {
        // The same coverage. A newer cover (nothing changes after a revoke)
        // is the newest; from another `feed_id`, the Station's feed after a
        // reset, it moves the coverage's order to that feed.
        if let Some(c) = state.coverage.as_mut().filter(|_| !revoked && newer) {
            if c.feed_id != pos.feed_id {
                c.feed_id = pos.feed_id.clone();
                c.since = pos.feed_seq;
                out.actions.push(HostAction::Cover {
                    principal,
                    origin: pos.origin,
                    feed_id: pos.feed_id,
                });
            }
            c.cover = key;
        }
        out.effect(EffectKind::Cover, ApplicationResult::Duplicate);
    } else if revoked {
        // Never covered anew after a revoke.
        out.not_in_force(
            EffectKind::Cover,
            ApplicationResult::Refused,
            Why::AfterRevoke,
        );
    } else if !newer {
        // Another Station's cover no newer than the coverage's changes
        // nothing.
        out.not_in_force(EffectKind::Cover, ApplicationResult::Refused, Why::NotNewer);
    } else {
        state.coverage = Some(Covering {
            origin: pos.origin.clone(),
            feed_id: pos.feed_id.clone(),
            since: pos.feed_seq,
            cover: key,
        });
        out.actions.push(HostAction::Cover {
            principal,
            origin: pos.origin,
            feed_id: pos.feed_id,
        });
        out.effect(EffectKind::Cover, ApplicationResult::Applied);
    }
}

/// The last hold or release taken from `pos`'s feed, at `pos` if later.
/// One feed per origin (ruling T4b): another feed of the origin replaces
/// the entry, unless the entry is the covering feed's, the only one a
/// release reads (another feed's matters only once a cover moves the
/// coverage there, and a release must then come after that cover).
fn take_order(state: &mut ServiceControl, pos: &FeedPos) {
    let covering = state
        .coverage
        .as_ref()
        .filter(|c| c.origin == pos.origin)
        .map(|c| c.feed_id.clone());
    if let Some((feed_id, at)) = state.order.get_mut(&pos.origin) {
        if *feed_id == pos.feed_id {
            *at = (*at).max(pos.feed_seq);
            return;
        }
        if covering.as_deref() == Some(feed_id.as_str()) {
            return;
        }
    }
    state
        .order
        .insert(pos.origin.clone(), (pos.feed_id.clone(), pos.feed_seq));
}

/// A `hold` issued at `issued_at`, read at `pos` (its own feed's position,
/// or none): a stop, it applies whichever feed it comes from, and its time
/// is kept whether it holds or finds the principal held (O1).
fn hold(
    state: &mut ServiceControl,
    principal: String,
    issued_at: u64,
    pos: Option<FeedPos>,
    out: &mut Outcome,
) {
    // Ignored after a revoke (nothing lifts a hold then).
    if state.revoked_by.is_some() {
        if state.held {
            out.effect(EffectKind::Hold, ApplicationResult::Duplicate);
        } else {
            out.not_in_force(
                EffectKind::Hold,
                ApplicationResult::Refused,
                Why::AfterRevoke,
            );
        }
        return;
    }
    let result = if state.held {
        ApplicationResult::Duplicate
    } else {
        state.held = true;
        out.actions.push(HostAction::Hold(principal));
        ApplicationResult::Applied
    };
    state.hold_issued_at = Some(state.hold_issued_at.map_or(issued_at, |t| t.max(issued_at)));
    // A later release from this feed comes after it.
    if let Some(pos) = &pos {
        take_order(state, pos);
    }
    out.effect(EffectKind::Hold, result);
}

/// A `release` issued at `issued_at`, read at `pos`: taken only from the
/// coverage's current feed, after its cover and after the last hold or
/// release taken from that feed; it lifts every hold, and only when issued
/// strictly after every hold verified for the principal (O1). One issued
/// no later is refused and takes no position in the feed's order.
fn release(
    state: &mut ServiceControl,
    principal: String,
    issued_at: u64,
    pos: Option<FeedPos>,
    out: &mut Outcome,
) {
    // Ignored after a revoke.
    if state.revoked_by.is_some() {
        if state.held {
            out.not_in_force(
                EffectKind::Release,
                ApplicationResult::Refused,
                Why::AfterRevoke,
            );
        } else {
            out.effect(EffectKind::Release, ApplicationResult::Duplicate);
        }
        return;
    }
    let in_order = pos.as_ref().is_some_and(|pos| {
        state.coverage.as_ref().is_some_and(|c| {
            c.origin == pos.origin && c.feed_id == pos.feed_id && pos.feed_seq > c.since
        }) && state
            .order
            .get(&pos.origin)
            .filter(|(feed_id, _)| *feed_id == pos.feed_id)
            .is_none_or(|(_, last)| pos.feed_seq > *last)
    });
    let after_holds = state.hold_issued_at.is_none_or(|at| issued_at > at);
    if !state.held {
        if let Some(pos) = pos.as_ref().filter(|_| in_order) {
            take_order(state, pos);
        }
        out.effect(EffectKind::Release, ApplicationResult::Duplicate);
    } else if !in_order {
        out.not_in_force(EffectKind::Release, ApplicationResult::Refused, Why::Order);
    } else if !after_holds {
        // Signed no later than a hold it would lift: a release withheld,
        // or refused before, served after a newer hold.
        out.not_in_force(
            EffectKind::Release,
            ApplicationResult::Refused,
            Why::NotAfterHold,
        );
    } else {
        if let Some(pos) = &pos {
            take_order(state, pos);
        }
        state.held = false;
        out.actions.push(HostAction::Release(principal));
        out.effect(EffectKind::Release, ApplicationResult::Applied);
    }
}

impl ServiceControl {
    /// A service part's fields `o`, its `records` read already.
    fn from_json(o: &Map<String, Value>, records: &[Counted]) -> Result<Self> {
        let counted = |id: &str| records.iter().any(|c| c.record_id == id);
        let revoked_by = match o.get("revoked_by") {
            None => None,
            Some(by) => Some(
                by.as_str()
                    .filter(|by| counted(by))
                    .ok_or(Error::Malformed("control state revoked_by"))?
                    .to_owned(),
            ),
        };
        let interrupted = o["interrupted"]
            .as_bool()
            .filter(|interrupted| !interrupted || revoked_by.is_some())
            .ok_or(Error::Malformed("control state interrupted"))?;
        let held = o["held"]
            .as_bool()
            .ok_or(Error::Malformed("control state held"))?;
        // Absent: no hold's time known, safe only while nothing is held
        // (a hold applied after the load records its time before any
        // release could lift it). A held part without it is damage.
        let hold_issued_at = match o.get("hold_issued_at") {
            None if held => return Err(Error::Malformed("control state hold_issued_at")),
            None => None,
            Some(at) => Some(
                at.as_u64()
                    .filter(|at| *at <= MAX_SAFE_INTEGER)
                    .ok_or(Error::Malformed("control state hold_issued_at"))?,
            ),
        };
        let coverage = match o.get("coverage") {
            None => None,
            Some(c) => {
                let what = "control state coverage";
                let c = fields(c, &["origin", "feed_id", "since", "cover"], &[], what)?;
                let cover = fields(&c["cover"], &["issued_at", "record_id"], &[], what)?;
                Some(Covering {
                    origin: origin(&c["origin"], what)?,
                    feed_id: feed_id(&c["feed_id"], what)?,
                    since: c["since"]
                        .as_u64()
                        .filter(|at| *at <= MAX_SAFE_INTEGER)
                        .ok_or(Error::Malformed(what))?,
                    cover: CoverKey {
                        issued_at: cover["issued_at"]
                            .as_u64()
                            .filter(|at| *at <= MAX_SAFE_INTEGER)
                            .ok_or(Error::Malformed(what))?,
                        // The cover counted: it is among the records.
                        record_id: cover["record_id"]
                            .as_str()
                            .filter(|id| counted(id))
                            .ok_or(Error::Malformed(what))?
                            .to_owned(),
                    },
                })
            }
        };
        let mut order = BTreeMap::new();
        if let Some(feeds_by_origin) = o.get("order") {
            let what = "control state order";
            let feeds_by_origin = object(feeds_by_origin, what)?;
            if feeds_by_origin.is_empty() {
                return Err(Error::Malformed(what));
            }
            for (at_origin, feeds) in feeds_by_origin {
                // One feed per origin.
                let feeds = object(feeds, what)?;
                let [(id, at)] = feeds.iter().collect::<Vec<_>>()[..] else {
                    return Err(Error::Malformed(what));
                };
                let entry = (
                    feed_id(&json!(id), what)?,
                    at.as_u64()
                        .filter(|at| *at <= MAX_SAFE_INTEGER)
                        .ok_or(Error::Malformed(what))?,
                );
                order.insert(origin(&json!(at_origin), what)?, entry);
            }
        }
        Ok(ServiceControl {
            revoked_by,
            interrupted,
            coverage,
            held,
            hold_issued_at,
            order,
        })
    }
}

/// A part's `records`: one to [`MAX_RECORD_IDS`] `[record_id, digest,
/// issued_at]` triples, oldest first, each id a UUID v4 once.
fn records(value: &Value) -> Result<Vec<Counted>> {
    let what = "control state records";
    let items = value
        .as_array()
        .filter(|items| (1..=MAX_RECORD_IDS).contains(&items.len()))
        .ok_or(Error::Malformed(what))?;
    let mut seen = BTreeSet::new();
    let mut records = Vec::with_capacity(items.len());
    for item in items {
        let [id, digest, issued_at] = item.as_array().map(Vec::as_slice).unwrap_or_default() else {
            return Err(Error::Malformed(what));
        };
        let id = id
            .as_str()
            .filter(|id| is_uuid_v4(id) && seen.insert(*id))
            .ok_or(Error::Malformed("control state record_id"))?;
        records.push(Counted {
            record_id: id.to_owned(),
            digest: hash(digest, "control state record digest")?,
            issued_at: issued_at
                .as_u64()
                .filter(|at| *at <= MAX_SAFE_INTEGER)
                .ok_or(Error::Malformed("control state record issued_at"))?,
        });
    }
    Ok(records)
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

/// A Station's exact origin, as `normalize_relay` writes it.
fn origin(value: &Value, what: &'static str) -> Result<String> {
    value
        .as_str()
        .filter(|origin| normalize_relay(origin).as_deref() == Ok(*origin))
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
            origin: feed.0.into(),
            feed_id: feed.1.into(),
            feed_seq,
        })
    }

    /// Applies a record and adopts the next state (the caller's
    /// transaction committed).
    trait Adopt {
        fn adopt(
            &mut self,
            rec: &ControlRecord,
            list: &Membership,
            pos: Option<FeedPos>,
            host_applied_seq: u64,
        ) -> Applied;
    }

    impl Adopt for ControlState {
        /// The results without `why`, which every test checks here only
        /// against its rule (set exactly when the record is pending,
        /// refused or evidence) and `applied_names_why_for_pending_and_refused`
        /// checks value by value. `touched` names the record's principal
        /// exactly when its part changed, and no other part changes.
        fn adopt(
            &mut self,
            rec: &ControlRecord,
            list: &Membership,
            pos: Option<FeedPos>,
            host_applied_seq: u64,
        ) -> Applied {
            let transition = self.apply(rec, list, pos, host_applied_seq);
            let principal = rec.principal().name();
            let changed = self.part(&principal) != transition.next.part(&principal);
            assert_eq!(
                transition.touched(),
                if changed {
                    vec![principal.clone()]
                } else {
                    vec![]
                },
                "touched: {}",
                rec.record_id()
            );
            for p in self.principals() {
                if p != principal {
                    assert_eq!(self.part(&p), transition.next.part(&p), "{p} untouched");
                }
            }
            let Transition {
                mut applied, next, ..
            } = transition;
            let explains = matches!(
                applied.record_result,
                ApplicationResult::Pending | ApplicationResult::Refused
            ) || applied.evidence;
            assert_eq!(
                applied.why.is_some(),
                explains,
                "why {:?} for {:?} of {}",
                applied.why,
                applied.record_result,
                rec.record_id()
            );
            applied.why = None;
            *self = next;
            applied
        }
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
            Self::with_genesis_at(account_id, T0)
        }

        /// The same members, under a genesis signed at `genesis_at`: a
        /// re-pair of the account is another genesis.
        fn with_genesis_at(account_id: &str, genesis_at: u64) -> Self {
            let keys = keys();
            let body = draft_on(
                account_id,
                &Hash32([0; 32]),
                1,
                &Hash32([0; 32]),
                "mac",
                genesis_at,
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
            why: None,
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
            let got = state.adopt(&rec, list, pos, applied_seq);
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
            state.adopt(&again, &fx.list, None, 0),
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
        // A hold or release elsewhere than at its own feed's position.
        let unplaced = fx.svc(11, "svc-1", "svc-1", C::Release, A);
        // svc-2 has no coverage on this host: its hold applies all the same
        // (a stop always wins).
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
                Step::new(&s(2, C::Hold), at(A, 2), held("svc-1")),
                // Held already: a duplicate, now the last in feed order.
                Step::new(&s(3, C::Hold), at(A, 4), dup(&[E::Hold])),
                // A release before the last hold in feed order: superseded.
                Step::new(&s(4, C::Release), at(A, 3), all(R::Refused, &[E::Release])),
                Step::new(&s(5, C::Release), at(A, 5), released("svc-1")),
                Step::new(&s(6, C::Hold), at(A, 6), held("svc-1")),
                // Another record at the same position: not after it.
                Step::new(&s(7, C::Release), at(A, 6), all(R::Refused, &[E::Release])),
                Step::new(&unplaced, None, all(R::Refused, &[E::Release])),
                Step::new(&unplaced, at(B, 7), all(R::Refused, &[E::Release])),
                Step::new(&uncovered, at(A, 8), held("svc-2")),
                Step::new(&s(9, C::Release), at(A, 9), released("svc-1")),
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
                // B's hold applies (a stop always wins); B's release can't
                // lift it, A's can.
                Step::new(&b(6, C::Hold), at(B, 3), held("svc-1")),
                Step::new(&b(7, C::Release), at(B, 4), all(R::Refused, &[E::Release])),
            ],
        );

        // Another Station whose records name the covering feed's feed_id:
        // still not the covering Station, in its own feed or in A's.
        let reusing: Feed = (B.0, A.1);
        let release = fx.svc(8, "svc-1", "svc-1", C::Release, reusing);
        for pos in [at(A, 4), at(reusing, 4)] {
            assert_eq!(
                state.adopt(&release, &fx.list, pos, 0),
                all(R::Refused, &[E::Release])
            );
        }
        assert_eq!(
            state.adopt(
                &fx.svc(9, "svc-1", "svc-1", C::Release, A),
                &fx.list,
                at(A, 4),
                0
            ),
            released("svc-1")
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
                // cover on. A cover never releases: A's hold stays in
                // force.
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
                // A still holds, though it no longer covers: a stop always
                // wins. Only B's release lifts it.
                Step::new(&a(6, C::Hold), at(A, 4), held("svc-1")),
                Step::new(&a(7, C::Release), at(A, 5), all(R::Refused, &[E::Release])),
                Step::new(&b(8, C::Release), at(B, 3), released("svc-1")),
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
                // The old feed's hold still applies (a stop always wins); its
                // release doesn't, A2's does.
                Step::new(&a(10, C::Hold), at(A, 9), held),
                Step::new(&a2(11, C::Hold), at(A2, 4), dup(&[E::Hold])),
                Step::new(
                    &a(12, C::Release),
                    at(A, 10),
                    all(R::Refused, &[E::Release]),
                ),
                Step::new(&a2(13, C::Release), at(A2, 5), released),
            ],
        );
    }

    #[test]
    fn conflicting_body_same_id_is_evidence_and_the_first_keeps_the_id() {
        let fx = Fx::new();
        let mut state = fx.state();
        let first = fx.svc(1, "svc-1", "svc-1", revoke(false), A);
        // Another body under the same record id, validly signed: a stop, so
        // its effects apply (here the interrupt it adds), and evidence.
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
                    evidence(out(
                        R::Applied,
                        &[(E::Revocation, R::Duplicate), (E::Interrupt, R::Applied)],
                        vec![interrupt_action(service("svc-1"), rid(1))],
                    )),
                ),
                // The first keeps the id.
                Step::new(&first, at(A, 1), dup(&[E::Revocation])),
                Step::new(&interrupt, at(A, 3), dup(&[E::Interrupt])),
                Step::new(&second, None, evidence(dup(&[E::Revocation, E::Interrupt]))),
                Step::new(&forged, at(A, 4), evidence(all(R::Refused, &[E::Hold]))),
                // svc-1 is revoked: its cover is ignored.
                Step::new(&genuine, at(A, 5), all(R::Refused, &[E::Cover])),
            ],
        );
        // On a fresh state the genuine record under the forged id applies.
        let mut fresh = fx.state();
        assert_eq!(
            fresh.adopt(&forged, &fx.list, at(A, 4), 0),
            evidence(all(R::Refused, &[E::Hold]))
        );
        assert_eq!(
            fresh.adopt(&genuine, &fx.list, at(A, 5), 0),
            out(
                R::Applied,
                &[(E::Cover, R::Applied)],
                vec![cover_action("svc-1", A)]
            )
        );
        assert_eq!(
            fresh.adopt(&forged, &fx.list, at(A, 4), 0),
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
        assert_eq!(state.adopt(&unknown, &fx.list, at(A, 1), 0), pending);
        assert_eq!(state.adopt(&unknown, &fx.list, at(A, 1), 0), pending);
        fx.add_service("svc-new");
        assert_eq!(
            state.adopt(&unknown, &fx.list, at(A, 1), 0),
            out(
                R::Applied,
                &[(E::Cover, R::Applied)],
                vec![cover_action("svc-new", A)]
            )
        );
        // A manager's hold: refused whatever the list holds, and evidence.
        let manager_hold = fx.svc(2, "svc-1", "mac", C::Hold, A);
        assert_eq!(
            state.adopt(&manager_hold, &fx.list, at(A, 2), 0),
            evidence(all(R::Refused, &[E::Hold]))
        );
        // A record of another account.
        let other = Fx::account("acct-test-2").svc(3, "svc-1", "svc-1", revoke(true), A);
        assert_eq!(
            state.adopt(&other, &fx.list, at(A, 3), 0),
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
                .adopt(&by_phone, &before, at(A, 1), 0)
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
            applied_before.adopt(&by_phone, &fx.list, at(A, 1), 0),
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
                state.adopt(&old_release, &fx.list, at(A, 7), 0),
                all(R::Refused, &[E::Release])
            );
            // The new feed continues the coverage: its release applies.
            let release = s2(16, C::Release, A2);
            assert_eq!(
                state.adopt(&release, &fx.list, at(A2, 9), 0),
                out(
                    R::Applied,
                    &[(E::Release, R::Applied)],
                    vec![H::Release(service("svc-2"))]
                )
            );
            // The old feed's identity is gone; nothing of svc-1 was lost.
            let release1 = s1(17, C::Release, A2);
            assert_eq!(
                state.adopt(&release1, &fx.list, at(A2, 10), 0),
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
            state.adopt(&theirs, &other.list, at(A, 1), 0),
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
            state.adopt(&cover, &frozen, at(A, 1), 0),
            all(R::Pending, &[E::Cover])
        );
        assert_eq!(state, fx.state());
        assert_eq!(
            state.adopt(&cover, &fx.list, at(A, 1), 0).record_result,
            R::Applied
        );
    }

    /// A state with every part: svc-1 covered, held, revoked and
    /// interrupted; svc-2 covered and released in feed B, then held from
    /// feed A, which doesn't cover it; host-a interrupted after its revoke
    /// at `r`, by a record under svc-1's cover's `record_id`.
    fn full_state(fx: &mut Fx) -> (ControlState, Vec<ControlRecord>, u64) {
        let r = fx.revoke_host(false);
        let records = vec![
            fx.svc(1, "svc-1", "svc-1", C::Cover, A),
            fx.svc(2, "svc-1", "svc-1", C::Hold, A),
            fx.svc(3, "svc-1", "mac", revoke(true), A),
            fx.svc(4, "svc-2", "svc-2", C::Cover, B),
            fx.svc(5, "svc-2", "svc-2", C::Release, B),
            fx.host(1, "mac", r),
            fx.svc(6, "svc-2", "svc-2", C::Hold, A),
        ];
        let positions = [
            at(A, 1),
            at(A, 2),
            at(A, 3),
            at(B, 1),
            at(B, 2),
            None,
            at(A, 4),
        ];
        let mut state = fx.state();
        for (rec, pos) in records.iter().zip(positions) {
            let result = state.adopt(rec, &fx.list, pos, r).record_result;
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
                "v": 2, "account_id": ACCOUNT,
                "genesis_hash": fx.list.genesis_hash().to_hex(),
                "principals": {},
            })
        );
        assert_eq!(ControlState::from_json(&json).unwrap(), empty);

        let (state, records, r) = full_state(&mut fx);
        let json = state.to_json();
        // By principal, each record that counted with its digest, oldest
        // first: svc-1's cover and host-a's interrupt share an id.
        let pairs = |recs: &[&ControlRecord]| -> Value {
            recs.iter()
                .map(|rec| json!([rec.record_id(), digest(rec), rec.issued_at()]))
                .collect()
        };
        let genesis = fx.list.genesis_hash().to_hex();
        assert_eq!(records[5].record_id(), rid(1));
        assert_eq!(
            json,
            json!({
                "v": 2, "account_id": ACCOUNT,
                "genesis_hash": fx.list.genesis_hash().to_hex(),
                "principals": {
                    "host:host-a": {
                        "account_id": ACCOUNT, "genesis_hash": genesis,
                        "interrupted": [r],
                        "records": pairs(&[&records[5]]),
                    },
                    "service:svc-1": {
                        "account_id": ACCOUNT, "genesis_hash": genesis,
                        "records": pairs(&[&records[0], &records[1], &records[2]]),
                        "revoked_by": rid(3), "interrupted": true,
                        "coverage": {
                            "origin": A.0, "feed_id": A.1, "since": 1,
                            "cover": {"issued_at": issued(1), "record_id": rid(1)},
                        },
                        "held": true,
                        "hold_issued_at": issued(2),
                        "order": {A.0: {A.1: 2}},
                    },
                    "service:svc-2": {
                        "account_id": ACCOUNT, "genesis_hash": genesis,
                        "records": pairs(&[&records[3], &records[4], &records[6]]),
                        "interrupted": false,
                        "coverage": {
                            "origin": B.0, "feed_id": B.1, "since": 1,
                            "cover": {"issued_at": issued(4), "record_id": rid(4)},
                        },
                        "held": true,
                        "hold_issued_at": issued(6),
                        "order": {A.0: {A.1: 4}, B.0: {B.1: 2}},
                    },
                },
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
                resumed.adopt(&rec, &fx.list, pos.clone(), r),
                original.adopt(&rec, &fx.list, pos, r)
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
        let svc1 = "service:svc-1";
        let svc2 = "service:svc-2";
        let host = "host:host-a";
        type Edit = Box<dyn Fn(&mut Value)>;
        let edits: Vec<(&str, Edit)> = vec![
            ("v 1", Box::new(|j| j["v"] = json!(1))),
            ("v 3", Box::new(|j| j["v"] = json!(3))),
            ("unknown field", Box::new(|j| j["extra"] = json!(1))),
            (
                "missing principals",
                Box::new(|j| {
                    j.as_object_mut().unwrap().remove("principals");
                }),
            ),
            ("null", Box::new(|j| j["principals"] = Value::Null)),
            ("empty account", Box::new(|j| j["account_id"] = json!(""))),
            (
                "account not a string",
                Box::new(|j| j["account_id"] = json!(7)),
            ),
            (
                "no account",
                Box::new(|j| {
                    j.as_object_mut().unwrap().remove("account_id");
                }),
            ),
            (
                "genesis not hex",
                Box::new(|j| j["genesis_hash"] = json!("zz")),
            ),
            (
                "genesis not a string",
                Box::new(|j| j["genesis_hash"] = json!(7)),
            ),
            (
                "no genesis",
                Box::new(|j| {
                    j.as_object_mut().unwrap().remove("genesis_hash");
                }),
            ),
            (
                "uppercase hash",
                Box::new(|j| {
                    j["genesis_hash"] = json!(j["genesis_hash"].as_str().unwrap().to_uppercase())
                }),
            ),
            (
                "the earlier form, records by id",
                Box::new(move |j| {
                    j["principals"][svc1]["records"] = json!({rid(1): "00".repeat(32)})
                }),
            ),
            (
                "record id",
                Box::new(move |j| j["principals"][svc1]["records"][0][0] = json!("not-a-uuid")),
            ),
            (
                "record digest",
                Box::new(move |j| j["principals"][svc1]["records"][0][1] = json!("00")),
            ),
            (
                "record without its issued_at",
                Box::new(move |j| {
                    j["principals"][svc1]["records"][0] = json!([rid(1), "00".repeat(32)])
                }),
            ),
            (
                "record of four",
                Box::new(move |j| {
                    j["principals"][svc1]["records"][0] = json!([rid(1), "00".repeat(32), 1, 1])
                }),
            ),
            (
                "record issued_at",
                Box::new(move |j| j["principals"][svc1]["records"][0][2] = json!("1")),
            ),
            (
                "record issued_at unsafe",
                Box::new(move |j| {
                    j["principals"][svc1]["records"][0][2] = json!(MAX_SAFE_INTEGER + 1)
                }),
            ),
            (
                "a part of another account",
                Box::new(move |j| j["principals"][svc1]["account_id"] = json!("acct-test-2")),
            ),
            (
                "a part of another genesis",
                Box::new(move |j| j["principals"][host]["genesis_hash"] = json!("11".repeat(32))),
            ),
            (
                "a part without its genesis",
                Box::new(move |j| {
                    j["principals"][svc2]
                        .as_object_mut()
                        .unwrap()
                        .remove("genesis_hash");
                }),
            ),
            (
                "an evicted floor before the records are full",
                Box::new(move |j| j["principals"][svc1]["evicted_floor"] = json!(5)),
            ),
            (
                "an evicted floor that isn't an integer",
                Box::new(move |j| j["principals"][host]["evicted_floor"] = json!("5")),
            ),
            (
                "order with two feeds of one origin",
                Box::new(move |j| j["principals"][svc1]["order"][A.0][A2.1] = json!(3)),
            ),
            (
                "record id twice",
                Box::new(move |j| {
                    let first = j["principals"][svc1]["records"][0].clone();
                    j["principals"][svc1]["records"]
                        .as_array_mut()
                        .unwrap()
                        .push(first);
                }),
            ),
            (
                "records empty",
                Box::new(move |j| j["principals"][host]["records"] = json!([])),
            ),
            (
                "records over the bound",
                Box::new(move |j| {
                    j["principals"][host]["records"] = (1..=MAX_RECORD_IDS as u32 + 1)
                        .map(|n| json!([rid(1000 + n), "00".repeat(32), 1]))
                        .collect();
                }),
            ),
            (
                "records principal",
                Box::new(move |j| j["principals"]["svc-1"] = j["principals"][svc1].clone()),
            ),
            (
                "records of no principal",
                Box::new(move |j| {
                    j["principals"]["service:recovery"] = j["principals"][svc1].clone()
                }),
            ),
            (
                "a member principal",
                Box::new(move |j| j["principals"]["member:mac"] = j["principals"][host].clone()),
            ),
            (
                "service field",
                Box::new(move |j| j["principals"][svc1]["extra"] = json!(1)),
            ),
            (
                "a service's field on a host",
                Box::new(move |j| j["principals"][host]["held"] = json!(false)),
            ),
            (
                "a host's seqs on a service",
                Box::new(move |j| j["principals"][svc2]["interrupted"] = json!([3])),
            ),
            (
                "a service without interrupted",
                Box::new(move |j| {
                    j["principals"][svc2]
                        .as_object_mut()
                        .unwrap()
                        .remove("interrupted");
                }),
            ),
            (
                "interrupted without revoked_by",
                Box::new(move |j| j["principals"][svc2]["interrupted"] = json!(true)),
            ),
            (
                "revoked_by not a record",
                Box::new(move |j| j["principals"][svc2]["revoked_by"] = json!(rid(99))),
            ),
            (
                "revoked_by another principal's record",
                Box::new(move |j| j["principals"][svc2]["revoked_by"] = json!(rid(3))),
            ),
            (
                "cover another principal's record",
                Box::new(move |j| {
                    j["principals"][svc2]["coverage"]["cover"]["record_id"] = json!(rid(1))
                }),
            ),
            (
                "held missing",
                Box::new(move |j| {
                    j["principals"][svc2]
                        .as_object_mut()
                        .unwrap()
                        .remove("held");
                }),
            ),
            (
                "held not a boolean",
                Box::new(move |j| j["principals"][svc2]["held"] = json!(1)),
            ),
            (
                "coverage origin",
                Box::new(move |j| {
                    j["principals"][svc1]["coverage"]["origin"] = json!("https://Station.example")
                }),
            ),
            (
                "coverage without its cover",
                Box::new(move |j| {
                    j["principals"][svc1]["coverage"]
                        .as_object_mut()
                        .unwrap()
                        .remove("cover");
                }),
            ),
            (
                "cover not a record",
                Box::new(move |j| {
                    j["principals"][svc1]["coverage"]["cover"]["record_id"] = json!(rid(99))
                }),
            ),
            (
                "cover issued_at",
                Box::new(move |j| {
                    j["principals"][svc1]["coverage"]["cover"]["issued_at"] = json!("1")
                }),
            ),
            (
                "the hold of an earlier form",
                Box::new(move |j| {
                    j["principals"][svc1]["hold"] =
                        json!({"held": true, "feed_id": A.1, "feed_seq": 2})
                }),
            ),
            (
                "order feed",
                Box::new(move |j| j["principals"][svc1]["order"][A.0] = json!({"feed": 2})),
            ),
            (
                "order origin",
                Box::new(move |j| {
                    j["principals"][svc1]["order"] = json!({"https://Station.example": {A.1: 2}})
                }),
            ),
            (
                "order position",
                Box::new(move |j| j["principals"][svc1]["order"][A.0][A.1] = json!("2")),
            ),
            (
                "order position unsafe",
                Box::new(move |j| {
                    j["principals"][svc1]["order"][A.0][A.1] = json!(MAX_SAFE_INTEGER + 1)
                }),
            ),
            (
                "coverage since unsafe",
                Box::new(move |j| {
                    j["principals"][svc1]["coverage"]["since"] = json!(MAX_SAFE_INTEGER + 1)
                }),
            ),
            (
                "order empty",
                Box::new(move |j| j["principals"][svc1]["order"] = json!({})),
            ),
            (
                "an origin's order empty",
                Box::new(move |j| j["principals"][svc1]["order"][A.0] = json!({})),
            ),
            (
                "host seqs unsorted",
                Box::new(move |j| j["principals"][host]["interrupted"] = json!([9, 3])),
            ),
            (
                "host seqs repeated",
                Box::new(move |j| j["principals"][host]["interrupted"] = json!([3, 3])),
            ),
            (
                "host seqs empty",
                Box::new(move |j| j["principals"][host]["interrupted"] = json!([])),
            ),
            (
                "host seq zero",
                Box::new(move |j| j["principals"][host]["interrupted"] = json!([0])),
            ),
        ];
        for (what, edit) in edits {
            let mut bad = good.clone();
            edit(&mut bad);
            // A part naming another list in a whole state is that list's
            // mismatch; anything else, a header the state can't read
            // included, is malformed (it names no list).
            let got = ControlState::from_json(&bad);
            if what.starts_with("a part of another") {
                assert!(matches!(got, Err(Error::GenesisMismatch)), "{what}");
            } else {
                assert!(matches!(got, Err(Error::Malformed(_))), "{what}");
            }
        }
        assert_eq!(ControlState::from_json(&good).unwrap(), state);
    }

    fn held(id: &str) -> Applied {
        out(
            R::Applied,
            &[(E::Hold, R::Applied)],
            vec![H::Hold(service(id))],
        )
    }

    fn released(id: &str) -> Applied {
        out(
            R::Applied,
            &[(E::Release, R::Applied)],
            vec![H::Release(service(id))],
        )
    }

    /// A stop always wins (PR 3 review I1): after a reset whose snapshot
    /// cover isn't newer than the coverage's, the coverage stays on the old
    /// feed, yet the new feed's hold applies; only its release waits for a
    /// newer cover, and the covering feed's release lifts the hold.
    #[test]
    fn a_hold_from_the_new_feed_after_a_reset_whose_cover_isnt_newer_applies() {
        let fx = Fx::new();
        let mut state = fx.state();
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let a2 = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A2);
        // The snapshot's cover, signed with a clock behind the old cover.
        let old_cover = fx.svc_issued(2, "svc-1", C::Cover, A2, issued(1) - 1);
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
                // The same Station, not newer: the coverage stays on A.
                Step::new(&old_cover, at(A2, 1), dup(&[E::Cover])),
                Step::new(&a2(3, C::Hold), at(A2, 2), held("svc-1")),
                Step::new(
                    &a2(4, C::Release),
                    at(A2, 3),
                    all(R::Refused, &[E::Release]),
                ),
                Step::new(&a(5, C::Release), at(A, 2), released("svc-1")),
            ],
        );
    }

    /// A stop always wins: a Station whose cover lost the takeover (not
    /// newer than the coverage's) still holds; its release is refused, and
    /// the covering feed's release lifts the hold. A replayed hold is a
    /// duplicate (its `record_id` counted): it holds nothing again.
    #[test]
    fn a_hold_from_a_station_that_lost_the_takeover_applies() {
        let fx = Fx::new();
        let mut state = fx.state();
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let b = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, B);
        let b_hold = b(6, C::Hold);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &a(5, C::Cover),
                    at(A, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-1", A)],
                    ),
                ),
                // Issued before A's: B lost the takeover.
                Step::new(&b(1, C::Cover), at(B, 1), all(R::Refused, &[E::Cover])),
                Step::new(&b_hold, at(B, 2), held("svc-1")),
                Step::new(&b(7, C::Release), at(B, 3), all(R::Refused, &[E::Release])),
                Step::new(&a(8, C::Release), at(A, 2), released("svc-1")),
                Step::new(&b_hold, at(B, 2), dup(&[E::Hold])),
                Step::new(&a(9, C::Release), at(A, 3), dup(&[E::Release])),
            ],
        );
    }

    /// A hold with no coverage at all applies; a release needs one.
    #[test]
    fn a_hold_with_no_coverage_applies() {
        let fx = Fx::new();
        let mut state = fx.state();
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-2", "svc-2", action, A);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(&s(1, C::Hold), at(A, 1), held("svc-2")),
                Step::new(&s(2, C::Release), at(A, 2), all(R::Refused, &[E::Release])),
                // Once covered, a release after the cover lifts it.
                Step::new(
                    &s(3, C::Cover),
                    at(A, 3),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-2", A)],
                    ),
                ),
                Step::new(&s(4, C::Release), at(A, 4), released("svc-2")),
            ],
        );
    }

    /// Within the covering feed, a hold read out of order (say it waited)
    /// still applies; a release must follow the feed's last hold or
    /// release.
    #[test]
    fn an_out_of_order_hold_applies_an_out_of_order_release_is_refused() {
        let fx = Fx::new();
        let mut state = fx.state();
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
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
                Step::new(&s(2, C::Hold), at(A, 2), held("svc-1")),
                Step::new(&s(4, C::Release), at(A, 4), released("svc-1")),
                Step::new(&s(3, C::Hold), at(A, 3), held("svc-1")),
                // Not after the feed's last hold or release (at 4).
                Step::new(&s(5, C::Release), at(A, 4), all(R::Refused, &[E::Release])),
                Step::new(&s(6, C::Release), at(A, 5), released("svc-1")),
            ],
        );
    }

    /// Record ids are per principal (PR 3 review I2): one principal's
    /// record under the `record_id` of another's never blocks it, so a
    /// Station holding a service key can't pre-empt a native stop.
    #[test]
    fn record_ids_are_per_principal() {
        let mut fx = Fx::new();
        let r = fx.revoke_host(false);
        let head = fx.list.head().seq;
        let mut state = fx.state();
        // svc-2's own cover, under the id the native records below use.
        let squatter = fx.svc(1, "svc-2", "svc-2", C::Cover, B);
        let native = fx.svc(1, "svc-1", "mac", revoke(true), A);
        let host = fx.host(1, "mac", r);
        run(
            &mut state,
            &fx.list,
            vec![
                Step::new(
                    &squatter,
                    at(B, 1),
                    out(
                        R::Applied,
                        &[(E::Cover, R::Applied)],
                        vec![cover_action("svc-2", B)],
                    ),
                ),
                Step::new(
                    &native,
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
                Step(
                    host,
                    None,
                    head,
                    out(
                        R::Applied,
                        &[(E::Interrupt, R::Applied)],
                        vec![interrupt_action("host:host-a".into(), r.to_string())],
                    ),
                ),
                Step::new(&squatter, at(B, 1), dup(&[E::Cover])),
                Step::new(&native, at(A, 1), dup(&[E::Revocation, E::Interrupt])),
            ],
        );
    }

    /// The same principal's record under a counted `record_id` with another
    /// body (PR 3 review I2): verified first; a stop (`hold`, `revoke`,
    /// `interrupt_running`) still applies and is kept as evidence; a
    /// `release` or `cover` is refused and kept as evidence. The first body
    /// keeps the id.
    #[test]
    fn a_colliding_stop_applies_a_colliding_release_or_cover_is_refused() {
        let fx = Fx::new();
        let mut state = fx.state();
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let cover = s(1, C::Cover);
        // Under rid 3 (the release's), a hold; under rid 2 (the hold's), a
        // release; under rid 1 (the cover's), a cover and a revoke.
        let hold_on_3 = fx.svc(3, "svc-1", "svc-1", C::Hold, A);
        let release_on_2 = fx.svc(2, "svc-1", "svc-1", C::Release, A);
        let cover_on_1 = fx.svc_issued(1, "svc-1", C::Cover, A, issued(9));
        let revoke_on_1 = fx.svc(1, "svc-1", "mac", revoke(true), A);
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
                Step::new(&s(2, C::Hold), at(A, 2), held("svc-1")),
                Step::new(&s(3, C::Release), at(A, 3), released("svc-1")),
                Step::new(&hold_on_3, at(A, 4), evidence(held("svc-1"))),
                Step::new(
                    &release_on_2,
                    at(A, 5),
                    evidence(all(R::Refused, &[E::Release])),
                ),
                Step::new(
                    &cover_on_1,
                    at(A, 6),
                    evidence(all(R::Refused, &[E::Cover])),
                ),
                Step::new(
                    &revoke_on_1,
                    at(A, 7),
                    evidence(out(
                        R::Applied,
                        &[(E::Revocation, R::Applied), (E::Interrupt, R::Applied)],
                        vec![
                            H::Revoke(service("svc-1")),
                            interrupt_action(service("svc-1"), rid(1)),
                        ],
                    )),
                ),
                Step::new(
                    &revoke_on_1,
                    None,
                    evidence(dup(&[E::Revocation, E::Interrupt])),
                ),
                // The first bodies keep their ids.
                Step::new(&cover, at(A, 1), dup(&[E::Cover])),
                Step::new(&s(3, C::Release), at(A, 3), dup(&[E::Release])),
            ],
        );
    }

    /// A record under a colliding id is verified before the collision: one
    /// the list can't verify yet waits, one that fails is refused for that.
    #[test]
    fn a_record_under_a_colliding_id_is_verified_first() {
        let mut fx = Fx::new();
        let mut state = fx.state();
        let cover = fx.svc(1, "svc-1", "svc-1", C::Cover, A);
        assert_eq!(
            state.adopt(&cover, &fx.list, at(A, 1), 0).record_result,
            R::Applied
        );
        // ipad isn't a member yet: its revoke under the cover's id waits.
        let body = fx.service_body(1, "svc-1", "ipad", revoke(false), A);
        let by_ipad = fx.sign(&body, "ipad");
        assert_eq!(
            state.adopt(&by_ipad, &fx.list, at(A, 2), 0),
            all(R::Pending, &[E::Revocation])
        );
        // Once ipad is a manager, it applies, and the collision is evidence.
        let ipad = native(&fx.keys, "ipad", &ALL);
        fx.append("mac", Action::Add { member: ipad });
        assert_eq!(
            state.adopt(&by_ipad, &fx.list, at(A, 2), 0),
            evidence(out(
                R::Applied,
                &[(E::Revocation, R::Applied)],
                vec![H::Revoke(service("svc-1"))],
            ))
        );
    }

    /// A record is read at its own feed's position only when the position's
    /// origin and `feed_id` are the body's (PR 3 review M1): a Station that
    /// copies another's `feed_id` gets no position in that feed.
    #[test]
    fn a_position_of_another_origin_is_no_position() {
        let fx = Fx::new();
        let mut state = fx.state();
        let reusing: Feed = (B.0, A.1);
        let cover = fx.svc(1, "svc-1", "svc-1", C::Cover, reusing);
        let release = fx.svc(2, "svc-1", "svc-1", C::Release, reusing);
        assert_eq!(
            state.adopt(&cover, &fx.list, at(A, 1), 0),
            all(R::Refused, &[E::Cover])
        );
        assert_eq!(
            state.adopt(&release, &fx.list, at(A, 2), 0),
            dup(&[E::Release])
        );
        // At its own origin's position it covers.
        assert_eq!(
            state.adopt(&cover, &fx.list, at(reusing, 1), 0),
            out(
                R::Applied,
                &[(E::Cover, R::Applied)],
                vec![cover_action("svc-1", reusing)],
            )
        );
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

    // ------------------------------------------------- host queries (step 4)

    fn standing(
        revoked: Option<String>,
        interrupted: &[String],
        held: bool,
        coverage: Option<Feed>,
    ) -> Standing {
        Standing {
            revoked,
            interrupted: interrupted.iter().cloned().collect(),
            held,
            coverage: coverage.map(|(origin, feed_id)| Coverage {
                origin: origin.into(),
                feed_id: feed_id.into(),
            }),
        }
    }

    /// `standing` is what the state has in force for a principal: its
    /// revocation (the revoking record's id), the revocations whose
    /// interrupt is in force, the hold and the covering feed. A host
    /// principal's revocation is a device-list entry: only its interrupts
    /// are here, by `revoke_seq`.
    #[test]
    fn standing_reports_revoked_interrupted_held_and_coverage() {
        let mut fx = Fx::new();
        let r = fx.revoke_host(false);
        let head = fx.list.head().seq;
        let mut state = fx.state();
        let svc1 = service("svc-1");
        let s1 =
            |n: u32, action: ControlAction, feed: Feed| fx.svc(n, "svc-1", "svc-1", action, feed);

        state.adopt(&s1(1, C::Cover, A), &fx.list, at(A, 1), 0);
        assert_eq!(state.standing(&svc1), standing(None, &[], false, Some(A)));
        state.adopt(&s1(2, C::Hold, B), &fx.list, at(B, 1), 0);
        assert_eq!(state.standing(&svc1), standing(None, &[], true, Some(A)));
        // A newer cover from B takes coverage; the hold persists.
        state.adopt(&s1(3, C::Cover, B), &fx.list, at(B, 2), 0);
        assert_eq!(state.standing(&svc1), standing(None, &[], true, Some(B)));
        // Revoked, then interrupted by a later record of a manager.
        state.adopt(
            &fx.svc(4, "svc-1", "mac", revoke(false), A),
            &fx.list,
            at(A, 2),
            0,
        );
        assert_eq!(
            state.standing(&svc1),
            standing(Some(rid(4)), &[], true, Some(B))
        );
        // Applying doesn't change the state it is called on.
        let interrupt = fx.svc(5, "svc-1", "phone", INTERRUPT, A);
        let t = state.apply(&interrupt, &fx.list, at(A, 3), 0);
        assert_eq!(
            state.standing(&svc1),
            standing(Some(rid(4)), &[], true, Some(B))
        );
        assert_eq!(
            t.next.standing(&svc1),
            standing(Some(rid(4)), &[rid(4)], true, Some(B))
        );

        // A host principal: its interrupts, by revoke_seq in decimal.
        let host = "host:host-a";
        state.adopt(&fx.host(6, "mac", r), &fx.list, None, head);
        assert_eq!(
            state.standing(host),
            standing(None, &[r.to_string()], false, None)
        );
        fx.readmit_host();
        let r2 = fx.revoke_host(false);
        state.adopt(&fx.host(7, "mac", r2), &fx.list, None, r2);
        assert_eq!(
            state.standing(host),
            standing(None, &[r.to_string(), r2.to_string()], false, None)
        );
        assert_eq!(state.principals(), vec![host.to_string(), svc1.clone()]);
    }

    /// A principal the state holds nothing for, or a name that is no
    /// principal at all, stands with nothing in force; a pending or refused
    /// record leaves no principal behind.
    #[test]
    fn standing_of_an_unknown_principal_is_empty() {
        let fx = Fx::new();
        let mut state = fx.state();
        let empty = Standing::default();
        assert_eq!(empty, standing(None, &[], false, None));
        for p in ["service:svc-1", "host:host-a", "member:mac", "svc-1", ""] {
            assert_eq!(state.standing(p), empty, "{p}");
        }
        assert!(state.principals().is_empty());
        // Pending (a service the list doesn't hold) and refused (a forgery).
        let unknown = fx.svc(1, "svc-new", "svc-new", C::Hold, A);
        assert_eq!(
            state.adopt(&unknown, &fx.list, at(A, 1), 0).record_result,
            R::Pending
        );
        let forged = fx.sign(&fx.service_body(2, "svc-1", "svc-1", C::Hold, A), "svc-2");
        assert_eq!(
            state.adopt(&forged, &fx.list, at(A, 2), 0).record_result,
            R::Refused
        );
        assert!(state.principals().is_empty());
        assert_eq!(state.part("service:svc-1"), None);
        assert_eq!(state.standing("service:svc-new"), empty);
        // A duplicate release (nothing held) counts: its principal has a
        // part, and still nothing in force.
        let release = fx.svc(3, "svc-2", "svc-2", C::Release, A);
        assert_eq!(
            state.adopt(&release, &fx.list, at(A, 3), 0),
            dup(&[E::Release])
        );
        assert_eq!(state.principals(), vec![service("svc-2")]);
        assert_eq!(state.standing(&service("svc-2")), empty);
        assert_eq!(state.standing("service:svc-1"), empty);
    }

    /// The state splits into one part per principal and recombines from
    /// them exactly, in any order; a host that writes only the parts a
    /// transition touched keeps the same state.
    #[test]
    fn parts_round_trip_and_touched_names_only_changed_principals() {
        let mut fx = Fx::new();
        let (state, records, r) = full_state(&mut fx);
        let principals = state.principals();
        assert_eq!(
            principals,
            vec![
                "host:host-a".to_string(),
                service("svc-1"),
                service("svc-2")
            ]
        );
        let parts: Vec<(String, Value)> = principals
            .iter()
            .map(|p| (p.clone(), state.part(p).unwrap()))
            .collect();
        let json = state.to_json();
        for (p, part) in &parts {
            assert_eq!(&json["principals"][p], part, "{p}");
        }
        let loaded = ControlState::from_parts(&fx.list, parts.clone()).unwrap();
        assert_eq!(loaded.state, state);
        assert!(loaded.foreign.is_empty());
        let reversed: Vec<_> = parts.iter().rev().cloned().collect();
        assert_eq!(
            ControlState::from_parts(&fx.list, reversed).unwrap().state,
            state
        );
        assert_eq!(
            ControlState::from_parts(&fx.list, Vec::new()).unwrap(),
            LoadedParts {
                state: fx.state(),
                foreign: Vec::new()
            }
        );
        assert_eq!(state.part("service:svc-3"), None);

        // Only the touched parts written, transaction by transaction.
        let mut store: BTreeMap<String, Value> = BTreeMap::new();
        let mut kept = fx.state();
        let positions = [
            at(A, 1),
            at(A, 2),
            at(A, 3),
            at(B, 1),
            at(B, 2),
            None,
            at(A, 4),
        ];
        let replays = records.iter().zip(positions.clone());
        for (rec, pos) in records.iter().zip(positions).chain(replays) {
            let t = kept.apply(rec, &fx.list, pos, r);
            for p in t.touched() {
                store.insert(p.clone(), t.next.part(&p).unwrap());
            }
            kept = t.next;
            let loaded = ControlState::from_parts(&fx.list, store.clone())
                .unwrap()
                .state;
            assert_eq!(loaded, kept, "{}", rec.record_id());
        }
        assert_eq!(kept, state);

        // A record of one principal touches that one only; a duplicate,
        // a pending or a refused record touches none.
        let t = state.apply(
            &fx.svc(7, "svc-2", "svc-2", C::Release, B),
            &fx.list,
            at(B, 3),
            r,
        );
        assert_eq!(t.touched(), vec![service("svc-2")]);
        assert_eq!(t.applied.record_result, R::Applied);
        for p in ["host:host-a", "service:svc-1"] {
            assert_eq!(t.next.part(p), state.part(p), "{p}");
        }
        for (rec, pos) in [
            (records[1].clone(), at(A, 2)),
            (fx.svc(8, "svc-new", "svc-new", C::Hold, A), at(A, 5)),
            (
                fx.sign(&fx.service_body(9, "svc-2", "svc-2", C::Hold, A), "svc-1"),
                at(A, 6),
            ),
        ] {
            let t = state.apply(&rec, &fx.list, pos, r);
            assert!(t.touched().is_empty(), "{}", rec.record_id());
            assert_eq!(t.next, state);
        }
        // A principal's first record touches it.
        let fresh = fx.state();
        let t = fresh.apply(&records[3], &fx.list, at(B, 1), r);
        assert_eq!(t.touched(), vec![service("svc-2")]);

        // Parts are read as strictly as the whole state: a principal given
        // twice, a name that isn't one, a part out of its kind's form.
        let svc1 = parts[1].1.clone();
        let refused: Vec<(&str, Vec<(String, Value)>)> = vec![
            ("twice", vec![parts[1].clone(), parts[1].clone()]),
            ("not a principal", vec![("svc-1".into(), svc1.clone())]),
            ("a member", vec![("member:mac".into(), svc1.clone())]),
            (
                "a service's part for a host",
                vec![("host:host-a".into(), svc1.clone())],
            ),
            (
                "a host's part for a service",
                vec![(service("svc-1"), parts[0].1.clone())],
            ),
            ("not an object", vec![(service("svc-1"), json!([]))]),
        ];
        for (what, parts) in refused {
            assert!(ControlState::from_parts(&fx.list, parts).is_err(), "{what}");
        }
    }

    fn why(
        state: &ControlState,
        rec: &ControlRecord,
        list: &Membership,
        pos: Option<FeedPos>,
        applied_seq: u64,
    ) -> (ApplicationResult, Option<Why>, bool) {
        let applied = state.apply(rec, list, pos, applied_seq).applied;
        (applied.record_result, applied.why, applied.evidence)
    }

    /// `why` says why a record is pending or refused, or why it is kept as
    /// evidence; nothing for a record that counted without question.
    #[test]
    fn applied_names_why_for_pending_and_refused() {
        use super::super::verify::{PendingReason as P, RefusalReason as F};
        let mut fx = Fx::new();
        let r = fx.revoke_host(false);
        let mut state = fx.state();
        let s1 =
            |n: u32, action: ControlAction, feed: Feed| fx.svc(n, "svc-1", "svc-1", action, feed);
        let s2 =
            |n: u32, action: ControlAction, feed: Feed| fx.svc(n, "svc-2", "svc-2", action, feed);
        let list = &fx.list;

        // Another device list; a frozen one.
        let other = Fx::account("acct-test-2");
        let theirs = other.svc(1, "svc-1", "svc-1", C::Cover, A);
        assert_eq!(
            why(&state, &theirs, &other.list, at(A, 1), 0),
            (R::Refused, Some(Why::Refused(F::WrongAccount)), false)
        );
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
        assert_eq!(
            why(&state, &s1(2, C::Cover, A), &frozen, at(A, 1), 0),
            (R::Pending, Some(Why::Pending(P::ListFrozen)), false)
        );

        // Verification: pending, and refused (evidence).
        let pendings = [
            (
                fx.svc(3, "svc-new", "svc-new", C::Hold, A),
                0,
                P::PrincipalUnknown,
            ),
            (
                fx.sign(
                    &fx.service_body(4, "svc-1", "ipad", revoke(false), A),
                    "ipad",
                ),
                0,
                P::SignerUnknown,
            ),
            (fx.host(5, "mac", r + 9), r + 9, P::RevokeNotInList),
            // The list holds the revoke; host-work hasn't applied it.
            (fx.host(6, "mac", r), r - 1, P::RevokeNotApplied),
            // A service's interrupt waits for its revocation here.
            (s1(7, INTERRUPT, A), 0, P::NotRevoked),
        ];
        for (rec, applied_seq, reason) in pendings {
            assert_eq!(
                why(&state, &rec, list, at(A, 1), applied_seq),
                (R::Pending, Some(Why::Pending(reason)), false),
                "{}",
                reason.code()
            );
        }
        let refusals = [
            (fx.svc(8, "svc-1", "mac", C::Hold, A), F::SignerNotAllowed),
            (
                fx.sign(&fx.service_body(9, "svc-1", "svc-1", C::Hold, A), "svc-2"),
                F::BadSignature,
            ),
        ];
        for (rec, reason) in refusals {
            assert_eq!(
                why(&state, &rec, list, at(A, 1), 0),
                (R::Refused, Some(Why::Refused(reason)), true),
                "{}",
                reason.code()
            );
        }

        // Order: a cover at no position of its own feed; a release with no
        // coverage, out of order, or from a feed that doesn't cover.
        assert_eq!(
            why(&state, &s1(10, C::Cover, A), list, None, 0),
            (R::Refused, Some(Why::Order), false)
        );
        state.adopt(&s1(11, C::Hold, A), list, at(A, 1), 0);
        assert_eq!(
            why(&state, &s1(12, C::Release, A), list, at(A, 2), 0),
            (R::Refused, Some(Why::Order), false)
        );
        state.adopt(&s1(13, C::Cover, A), list, at(A, 3), 0);
        state.adopt(&s1(14, C::Hold, A), list, at(A, 5), 0);
        for (rec, pos) in [
            (s1(15, C::Release, A), at(A, 4)),
            (s1(16, C::Release, B), at(B, 1)),
        ] {
            assert_eq!(
                why(&state, &rec, list, pos, 0),
                (R::Refused, Some(Why::Order), false)
            );
        }
        // Not newer: another Station's cover issued before the coverage's.
        let stale = fx.svc_issued(17, "svc-1", C::Cover, B, issued(1));
        assert_eq!(
            why(&state, &stale, list, at(B, 2), 0),
            (R::Refused, Some(Why::NotNewer), false)
        );
        // Counted without question: nothing.
        assert_eq!(
            why(&state, &s1(13, C::Cover, A), list, at(A, 3), 0),
            (R::Duplicate, None, false)
        );
        assert_eq!(
            why(&state, &s1(18, C::Release, A), list, at(A, 6), 0),
            (R::Applied, None, false)
        );

        // Collision: another body under a counted id is evidence; a cover
        // or release is refused, a stop applies.
        assert_eq!(
            why(
                &state,
                &fx.svc_issued(13, "svc-1", C::Cover, A, issued(99)),
                list,
                at(A, 7),
                0
            ),
            (R::Refused, Some(Why::Collision), true)
        );
        assert_eq!(
            why(&state, &s1(11, C::Release, A), list, at(A, 7), 0),
            (R::Refused, Some(Why::Collision), true)
        );
        assert_eq!(
            why(
                &state,
                &fx.svc(14, "svc-1", "mac", revoke(false), A),
                list,
                at(A, 7),
                0
            ),
            (R::Applied, Some(Why::Collision), true)
        );

        // After a revoke: cover, hold and release asking for what isn't
        // recorded.
        state.adopt(&s2(20, C::Cover, A), list, at(A, 8), 0);
        state.adopt(&s2(21, revoke(false), A), list, at(A, 9), 0);
        for (rec, pos) in [
            (s2(22, C::Hold, A), at(A, 10)),
            (
                fx.svc_issued(23, "svc-2", C::Cover, B, issued(99)),
                at(B, 3),
            ),
        ] {
            assert_eq!(
                why(&state, &rec, list, pos, 0),
                (R::Refused, Some(Why::AfterRevoke), false)
            );
        }
        state.adopt(&s1(24, revoke(false), A), list, at(A, 11), 0);
        assert_eq!(
            why(&state, &s1(25, C::Release, A), list, at(A, 12), 0),
            (R::Refused, Some(Why::AfterRevoke), false)
        );

        // Every reason has its own word.
        let all = [
            Why::Pending(P::PrincipalUnknown),
            Why::Pending(P::SignerUnknown),
            Why::Pending(P::RevokeNotInList),
            Why::Pending(P::ListFrozen),
            Why::Pending(P::NotRevoked),
            Why::Pending(P::RevokeNotApplied),
            Why::Refused(F::WrongAccount),
            Why::Refused(F::BadSignature),
            Why::Refused(F::KeyMismatch),
            Why::Refused(F::SignerNotAllowed),
            Why::Refused(F::RemovedManager),
            Why::Refused(F::HostKeySigned),
            Why::Refused(F::NotAService),
            Why::Refused(F::NotARevoke),
            Why::Order,
            Why::AfterRevoke,
            Why::Collision,
            Why::NotNewer,
            Why::PossibleReplay,
        ];
        let codes: BTreeSet<&str> = all.iter().map(|w| w.code()).collect();
        assert_eq!(codes.len(), all.len());
        assert_eq!(
            [Why::Order, Why::AfterRevoke, Why::Collision, Why::NotNewer].map(Why::code),
            ["order", "after_revoke", "collision", "not_newer"]
        );
        assert_eq!(Why::PossibleReplay.code(), "possible_replay");
        assert_eq!(Why::Pending(P::ListFrozen).code(), "list_frozen");
        assert_eq!(Why::Pending(P::NotRevoked).code(), "not_revoked");
        assert_eq!(
            Why::Pending(P::RevokeNotApplied).code(),
            "revoke_not_applied"
        );
        for w in all {
            assert_eq!(Why::from_code(w.code()), Some(w));
        }
        assert_eq!(Why::from_code("Order"), None);
    }

    /// The record ids of `principal` the state counts, oldest first.
    fn ids_of(state: &ControlState, principal: &str) -> Vec<String> {
        state.part(principal).map_or_else(Vec::new, |part| {
            part["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| pair[0].as_str().unwrap().to_owned())
                .collect()
        })
    }

    /// Adopts the records `ns` of svc-2 with `action`, signed by itself,
    /// read at no position; each counts.
    fn fill(
        state: &mut ControlState,
        fx: &Fx,
        ns: std::ops::RangeInclusive<u32>,
        action: ControlAction,
    ) {
        for n in ns {
            let rec = fx.svc(n, "svc-2", "svc-2", action, A);
            let result = state.adopt(&rec, &fx.list, None, 0).record_result;
            assert!(matches!(result, R::Applied | R::Duplicate), "{n}");
        }
    }

    /// A principal keeps at most `MAX_RECORD_IDS` counted record ids; the
    /// next one evicts its oldest, but never the revocation's record nor
    /// the coverage's cover, and raises the principal's evicted floor (the
    /// newest `issued_at` evicted). Another principal's ids are its own.
    #[test]
    fn record_ids_per_principal_are_bounded_oldest_first() {
        assert_eq!(MAX_RECORD_IDS, 256);
        let fx = Fx::new();
        let mut state = fx.state();
        let svc2 = service("svc-2");
        let ids = |ns: &mut dyn Iterator<Item = u32>| -> Vec<String> { ns.map(rid).collect() };
        // svc-1 under the same ids: never evicted by svc-2's.
        state.adopt(
            &fx.svc(2, "svc-1", "svc-1", C::Hold, A),
            &fx.list,
            at(A, 1),
            0,
        );
        state.adopt(
            &fx.svc(1, "svc-2", "svc-2", C::Cover, A),
            &fx.list,
            at(A, 2),
            0,
        );
        state.adopt(
            &fx.svc(2, "svc-2", "svc-2", C::Hold, A),
            &fx.list,
            at(A, 3),
            0,
        );
        fill(&mut state, &fx, 3..=256, C::Hold);
        assert_eq!(ids_of(&state, &svc2), ids(&mut (1..=256)));
        assert_eq!(state.part(&svc2).unwrap().get("evicted_floor"), None);
        // The 257th evicts the oldest that isn't pinned: rid 2, not the
        // coverage's cover (rid 1).
        fill(&mut state, &fx, 257..=257, C::Hold);
        let want: Vec<String> = ids(&mut std::iter::once(1).chain(3..=257));
        assert_eq!(ids_of(&state, &svc2), want);
        fill(&mut state, &fx, 258..=258, C::Hold);
        assert_eq!(
            ids_of(&state, &svc2),
            ids(&mut std::iter::once(1).chain(4..=258))
        );
        assert_eq!(
            state.part(&svc2).unwrap()["evicted_floor"],
            json!(issued(3))
        );
        assert_eq!(ids_of(&state, &service("svc-1")), vec![rid(2)]);
        // A hold the state no longer counts is verified again and applied
        // as a hold, whatever the floor (a stop always wins, ruling T4d):
        // while held, a duplicate, and it counts again (newest).
        assert_eq!(
            state.adopt(&fx.svc(3, "svc-2", "svc-2", C::Hold, A), &fx.list, None, 0),
            dup(&[E::Hold])
        );
        assert_eq!(
            ids_of(&state, &svc2),
            ids(&mut std::iter::once(1).chain(5..=258).chain(std::iter::once(3)))
        );

        // The revocation's record is pinned too, however old it gets.
        state.adopt(
            &fx.svc(300, "svc-2", "svc-2", revoke(false), A),
            &fx.list,
            at(A, 4),
            0,
        );
        fill(&mut state, &fx, 301..=556, C::Hold);
        let got = ids_of(&state, &svc2);
        assert_eq!(got.len(), MAX_RECORD_IDS);
        assert_eq!(&got[..2], &[rid(1), rid(300)]);
        assert_eq!(&got[2..], &ids(&mut (303..=556))[..]);
        assert_eq!(
            state.part(&svc2).unwrap()["evicted_floor"],
            json!(issued(302))
        );
        // The state still reads back (its pins are among its records).
        assert_eq!(ControlState::from_json(&state.to_json()).unwrap(), state);
        assert_eq!(
            state.standing(&svc2),
            standing(Some(rid(300)), &[], true, Some(A))
        );
        // Revoked, its cover, hold and release are ignored by rule 7 before
        // any floor: an evicted hold back is a duplicate (held), no evidence.
        assert_eq!(
            state.adopt(&fx.svc(5, "svc-2", "svc-2", C::Hold, A), &fx.list, None, 0),
            dup(&[E::Hold])
        );
    }

    /// A revoke the state evicted, coming back, is verified again and is
    /// still a duplicate: the revocation is in force, and no floor applies
    /// to a revoke or an interrupt (a replay of one is always a duplicate;
    /// a new one is a stop). The revoking record itself is never evicted.
    /// (A manager's copy whose signer was removed since is refused instead,
    /// as evidence; nothing changes either way.)
    #[test]
    fn an_evicted_revoke_replayed_is_still_duplicate() {
        let mut fx = Fx::new();
        let mut state = fx.state();
        let svc2 = service("svc-2");
        let first = fx.svc(1, "svc-2", "phone", revoke(false), A);
        let copy = fx.svc(2, "svc-2", "svc-2", revoke(true), A);
        let by_phone = fx.svc(3, "svc-2", "phone", revoke(false), A);
        assert_eq!(
            state.adopt(&first, &fx.list, at(A, 1), 0).record_result,
            R::Applied
        );
        assert_eq!(
            state.adopt(&copy, &fx.list, at(A, 2), 0).record_result,
            R::Applied
        );
        assert_eq!(
            state.adopt(&by_phone, &fx.list, at(A, 3), 0),
            dup(&[E::Revocation])
        );
        fill(&mut state, &fx, 10..=264, revoke(false));
        let ids = ids_of(&state, &svc2);
        assert_eq!(ids[0], rid(1));
        assert!(!ids.contains(&rid(2)) && !ids.contains(&rid(3)), "evicted");
        assert_eq!(
            state.part(&svc2).unwrap()["evicted_floor"],
            json!(issued(3))
        );
        let before = state.clone();

        // Each comes back a duplicate, whatever its position.
        for (rec, pos) in [(&first, at(A, 1)), (&copy, at(A, 9)), (&by_phone, None)] {
            let t = state.apply(rec, &fx.list, pos, 0);
            assert_eq!(t.applied.record_result, R::Duplicate, "{}", rec.record_id());
            assert!(t.applied.actions.is_empty());
            assert!(t.applied.effects.iter().all(|e| e.result == R::Duplicate));
            assert_eq!(t.next.standing(&svc2), before.standing(&svc2));
        }

        // phone removed: its evicted copy is verified against today's list
        // and refused; the first, never evicted, is still a duplicate.
        fx.append(
            "mac",
            Action::Remove {
                device_id: "phone".into(),
            },
        );
        let t = state.apply(&by_phone, &fx.list, at(A, 3), 0);
        assert_eq!(
            (t.applied.record_result, t.applied.evidence, t.applied.why),
            (
                R::Refused,
                true,
                Some(Why::Refused(
                    super::super::verify::RefusalReason::RemovedManager
                ))
            )
        );
        assert_eq!(t.next, state);
        assert_eq!(
            state.adopt(&first, &fx.list, at(A, 1), 0),
            dup(&[E::Revocation])
        );
    }

    /// svc-2 covered by A, held, released and held again, then full of
    /// duplicate holds until its first release is evicted: the floor is
    /// `issued(4)`, the release's.
    fn held_with_its_release_evicted(fx: &Fx) -> ControlState {
        let mut state = fx.state();
        let s2 = |n: u32, action: ControlAction| fx.svc(n, "svc-2", "svc-2", action, A);
        state.adopt(&s2(2, C::Cover), &fx.list, at(A, 1), 0);
        assert_eq!(
            state.adopt(&s2(3, C::Hold), &fx.list, at(A, 2), 0),
            held("svc-2")
        );
        assert_eq!(
            state.adopt(&s2(4, C::Release), &fx.list, at(A, 3), 0),
            released("svc-2")
        );
        assert_eq!(
            state.adopt(&s2(5, C::Hold), &fx.list, at(A, 4), 0),
            held("svc-2")
        );
        fill(&mut state, fx, 10..=263, C::Hold);
        let ids = ids_of(&state, &service("svc-2"));
        assert!(!ids.contains(&rid(3)) && !ids.contains(&rid(4)), "evicted");
        assert_eq!(
            state.part(&service("svc-2")).unwrap()["evicted_floor"],
            json!(issued(4))
        );
        state
    }

    /// A release the state evicted, re-served at a fresh position of the
    /// covering feed (by anyone who controls feed positions: `feed_seq`
    /// isn't signed, so the `:8080` proxy or an impostor on 127.0.0.1:8080
    /// could), would lift a hold in force; issued no later than the newest
    /// evicted record, it is refused as a possible replay (T4a), and the
    /// hold stays.
    #[test]
    fn an_evicted_release_replayed_at_a_fresh_position_is_refused_and_the_hold_stays() {
        let fx = Fx::new();
        let mut state = held_with_its_release_evicted(&fx);
        let svc2 = service("svc-2");
        let release = fx.svc(4, "svc-2", "svc-2", C::Release, A);
        for pos in [at(A, 9), at(A, 3), None] {
            let t = state.apply(&release, &fx.list, pos.clone(), 0);
            assert_eq!(
                (t.applied.record_result, t.applied.evidence, t.applied.why),
                (R::Refused, true, Some(Why::PossibleReplay)),
                "{pos:?}"
            );
            assert!(t.applied.actions.is_empty() && t.touched().is_empty());
            assert_eq!(t.next, state);
        }
        assert_eq!(
            state.adopt(&release, &fx.list, at(A, 9), 0),
            evidence(all(R::Refused, &[E::Release]))
        );
        assert_eq!(state.standing(&svc2), standing(None, &[], true, Some(A)));
    }

    /// A hold the state evicted, replayed after a release, holds again: no
    /// floor applies to a hold (ruling T4d), a stop that grants nothing.
    /// The old Station's cover and the release, replayed under the floor,
    /// are refused as possible replays; they change nothing.
    #[test]
    fn an_evicted_hold_replayed_after_a_release_holds_again() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc2 = service("svc-2");
        let s2 =
            |n: u32, action: ControlAction, feed: Feed| fx.svc(n, "svc-2", "svc-2", action, feed);
        let stale_cover = s2(1, C::Cover, B);
        let cover = s2(2, C::Cover, A);
        let hold = s2(3, C::Hold, A);
        let release = s2(4, C::Release, A);
        assert_eq!(
            state
                .adopt(&stale_cover, &fx.list, at(B, 1), 0)
                .record_result,
            R::Applied
        );
        assert_eq!(
            state.adopt(&cover, &fx.list, at(A, 1), 0).record_result,
            R::Applied
        );
        assert_eq!(state.adopt(&hold, &fx.list, at(A, 2), 0), held("svc-2"));
        assert_eq!(
            state.adopt(&release, &fx.list, at(A, 3), 0),
            released("svc-2")
        );
        // Duplicate releases (nothing held) until the three are evicted.
        fill(&mut state, &fx, 10..=264, C::Release);
        let ids = ids_of(&state, &svc2);
        assert_eq!(ids[0], rid(2), "the coverage's cover is pinned");
        for n in [1, 3, 4] {
            assert!(!ids.contains(&rid(n)), "{n} evicted");
        }

        for (rec, pos) in [
            (&stale_cover, at(B, 1)),
            (&release, at(A, 3)),
            (&release, at(A, 9)),
        ] {
            let t = state.apply(rec, &fx.list, pos, 0);
            assert_eq!(
                (t.applied.record_result, t.applied.evidence, t.applied.why),
                (R::Refused, true, Some(Why::PossibleReplay)),
                "{}",
                rec.record_id()
            );
            assert!(t.applied.actions.is_empty() && t.touched().is_empty());
            assert_eq!(t.next, state);
        }
        // The hold, at its own position, at a fresh one or at none: it
        // holds again, never refused as a replay.
        for pos in [at(A, 2), at(A, 9), None] {
            let t = state.apply(&hold, &fx.list, pos.clone(), 0);
            assert_eq!(t.applied, held("svc-2"), "{pos:?}");
        }
        assert_eq!(state.adopt(&hold, &fx.list, at(A, 2), 0), held("svc-2"));
        assert_eq!(state.standing(&svc2), standing(None, &[], true, Some(A)));
        // Counted again: a duplicate now.
        assert_eq!(state.adopt(&hold, &fx.list, None, 0), dup(&[E::Hold]));

        // Where nothing was evicted, the same hold is a duplicate.
        let mut kept = fx.state();
        for (rec, pos) in [
            (&stale_cover, at(B, 1)),
            (&cover, at(A, 1)),
            (&hold, at(A, 2)),
            (&release, at(A, 3)),
        ] {
            kept.adopt(rec, &fx.list, pos, 0);
        }
        assert_eq!(kept.adopt(&hold, &fx.list, at(A, 2), 0), dup(&[E::Hold]));
        assert!(!kept.standing(&svc2).held);
    }

    /// After a switch to a Station whose clock lags the floor, its fresh
    /// hold, issued below the floor, applies (a stop always wins); its
    /// cover and release below the floor are refused as possible replays
    /// until its `issued_at` passes the floor, which fails safe: the hold
    /// stays and nothing new starts. Its release lifts the hold only once
    /// issued after every hold too (O1): the fill's holds are newer.
    #[test]
    fn a_lagging_stations_fresh_hold_below_the_floor_applies() {
        let fx = Fx::new();
        let mut state = held_with_its_release_evicted(&fx);
        let svc2 = service("svc-2");
        let floor = issued(4);
        // Released by A first, above the floor.
        let s2 = |n: u32, action: ControlAction| fx.svc(n, "svc-2", "svc-2", action, A);
        assert_eq!(
            state.adopt(&s2(600, C::Release), &fx.list, at(A, 9), 0),
            released("svc-2")
        );
        // Station B, lagging: everything it signs is issued at the floor.
        let lagging =
            |n: u32, action: ControlAction| fx.svc_issued(n, "svc-2", action, B, floor - 1);
        assert_eq!(
            state.adopt(&lagging(601, C::Hold), &fx.list, at(B, 1), 0),
            held("svc-2")
        );
        for (n, action, pos) in [(602, C::Cover, at(B, 2)), (603, C::Release, at(B, 3))] {
            let t = state.apply(&lagging(n, action), &fx.list, pos, 0);
            assert_eq!(
                (t.applied.record_result, t.applied.evidence, t.applied.why),
                (R::Refused, true, Some(Why::PossibleReplay)),
                "{}",
                action.name()
            );
            assert_eq!(t.next, state);
        }
        assert_eq!(state.standing(&svc2), standing(None, &[], true, Some(A)));
        // Once its clock passes the floor (which every eviction raises: read
        // it), its cover takes coverage and its release lifts the hold.
        let floor_now = |state: &ControlState| {
            state.part(&svc2).unwrap()["evicted_floor"]
                .as_u64()
                .unwrap()
        };
        assert!(floor_now(&state) > floor);
        assert_eq!(
            state.adopt(
                &fx.svc_issued(604, "svc-2", C::Cover, B, floor_now(&state) + 1),
                &fx.list,
                at(B, 4),
                0
            ),
            out(
                R::Applied,
                &[(E::Cover, R::Applied)],
                vec![cover_action("svc-2", B)]
            )
        );
        let past_the_floor = fx.svc_issued(605, "svc-2", C::Release, B, floor_now(&state) + 1);
        refused_for(
            &state,
            &fx.list,
            &past_the_floor,
            at(B, 5),
            Why::NotAfterHold,
        );
        let newest_hold = hold_time(&state, &svc2).unwrap();
        assert!(newest_hold > floor_now(&state));
        assert_eq!(
            state.adopt(
                &fx.svc_issued(606, "svc-2", C::Release, B, newest_hold + 1),
                &fx.list,
                at(B, 5),
                0
            ),
            released("svc-2")
        );
    }

    /// A record issued after the newest evicted record is no possible
    /// replay, one millisecond above the floor included; a cover or release
    /// issued at the floor is one. A release above the floor still lifts
    /// the hold only when issued after every hold (O1): the fill's newer
    /// holds leave one just above the floor refused, not as evidence.
    #[test]
    fn a_fresh_record_above_the_evicted_floor_applies() {
        let fx = Fx::new();
        let mut state = held_with_its_release_evicted(&fx);
        let svc2 = service("svc-2");
        let floor = issued(4);
        let at_floor = fx.svc_issued(600, "svc-2", C::Release, A, floor);
        assert_eq!(
            state.adopt(&at_floor, &fx.list, at(A, 9), 0),
            evidence(all(R::Refused, &[E::Release]))
        );
        let just_above = fx.svc_issued(601, "svc-2", C::Release, A, floor + 1);
        refused_for(&state, &fx.list, &just_above, at(A, 9), Why::NotAfterHold);
        let after_the_holds = fx.svc_issued(
            605,
            "svc-2",
            C::Release,
            A,
            hold_time(&state, &svc2).unwrap() + 1,
        );
        assert_eq!(
            state.adopt(&after_the_holds, &fx.list, at(A, 9), 0),
            released("svc-2")
        );
        let s2 = |n: u32, action: ControlAction| fx.svc(n, "svc-2", "svc-2", action, A);
        assert_eq!(
            state.adopt(&s2(602, C::Hold), &fx.list, at(A, 10), 0),
            held("svc-2")
        );
        assert_eq!(
            state.adopt(&s2(603, C::Release), &fx.list, at(A, 11), 0),
            released("svc-2")
        );
        // Another Station's newer cover takes coverage.
        assert_eq!(
            state.adopt(
                &fx.svc(604, "svc-2", "svc-2", C::Cover, B),
                &fx.list,
                at(B, 1),
                0
            ),
            out(
                R::Applied,
                &[(E::Cover, R::Applied)],
                vec![cover_action("svc-2", B)]
            )
        );
        assert_eq!(state.standing(&svc2), standing(None, &[], false, Some(B)));
    }

    /// The order a release follows keeps one feed per Station origin: a
    /// reset's new feed replaces the old one's entry, and a hold read from
    /// a feed that doesn't cover never displaces the covering feed's entry
    /// (the only one a release reads). Many resets keep the part small.
    #[test]
    fn the_order_map_keeps_one_feed_per_origin_across_resets() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc2 = service("svc-2");
        let feed = |k: u32| -> Feed {
            let id = format!("{k:08x}-1111-4111-8111-111111111111");
            (A.0, Box::leak(id.into_boxed_str()))
        };
        let s2 = |n: u32, action: ControlAction, f: Feed| fx.svc(n, "svc-2", "svc-2", action, f);
        let mut sizes = Vec::new();
        for k in 0..60 {
            let f = feed(k);
            let n = 3 * k + 1;
            let covered = state.adopt(&s2(n, C::Cover, f), &fx.list, at(f, 1), 0);
            assert!(matches!(covered.record_result, R::Applied | R::Duplicate));
            assert_eq!(
                state.adopt(&s2(n + 1, C::Hold, f), &fx.list, at(f, 2), 0),
                held("svc-2")
            );
            assert_eq!(
                state.adopt(&s2(n + 2, C::Release, f), &fx.list, at(f, 3), 0),
                released("svc-2")
            );
            let part = state.part(&svc2).unwrap();
            assert_eq!(part["order"], json!({A.0: {f.1: 3}}), "reset {k}");
            sizes.push(part.to_string().len() - part["records"].to_string().len());
        }
        // Everything but the records stays the same size.
        assert!(sizes.windows(2).all(|w| w[0] == w[1]), "{sizes:?}");

        // A hold from an older feed of the origin (a pending record applied
        // late) doesn't displace the covering feed's entry; another
        // origin's hold adds that origin's.
        let covering = feed(59);
        assert_eq!(
            state.adopt(&s2(400, C::Hold, feed(58)), &fx.list, at(feed(58), 9), 0),
            held("svc-2")
        );
        assert_eq!(
            state.adopt(&s2(401, C::Hold, B), &fx.list, at(B, 5), 0),
            dup(&[E::Hold])
        );
        assert_eq!(
            state.part(&svc2).unwrap()["order"],
            json!({A.0: {covering.1: 3}, B.0: {B.1: 5}})
        );
        // So the covering feed's release after its last hold or release
        // still applies; one before it is refused.
        assert_eq!(
            state.adopt(&s2(402, C::Release, covering), &fx.list, at(covering, 3), 0),
            all(R::Refused, &[E::Release])
        );
        assert_eq!(
            state.adopt(&s2(403, C::Release, covering), &fx.list, at(covering, 4), 0),
            released("svc-2")
        );
        assert_eq!(ControlState::from_json(&state.to_json()).unwrap(), state);
    }

    /// The parts of `state`, by principal.
    fn parts_of(state: &ControlState) -> Vec<(String, Value)> {
        state
            .principals()
            .into_iter()
            .map(|p| {
                let part = state.part(&p).unwrap();
                (p, part)
            })
            .collect()
    }

    /// Parts carry their device list's account and genesis: after a re-pair
    /// (a new genesis), the old list's parts never load, so a service id
    /// that recurs in the new list doesn't inherit the old revoke, hold or
    /// coverage. `from_parts` loads only the list it is given and reports
    /// the others' keys for the host to delete (ruling T4e). The whole
    /// state reads only parts of its own list.
    #[test]
    fn parts_of_another_device_list_are_skipped_and_reported_after_a_re_pair() {
        let fx = Fx::new();
        let mut state = fx.state();
        let s1 = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        state.adopt(&s1(1, C::Cover), &fx.list, at(A, 1), 0);
        state.adopt(&s1(2, C::Hold), &fx.list, at(A, 2), 0);
        state.adopt(
            &fx.svc(3, "svc-2", "svc-2", revoke(true), A),
            &fx.list,
            at(A, 3),
            0,
        );
        let parts = parts_of(&state);
        for (p, part) in &parts {
            assert_eq!(part["account_id"], json!(ACCOUNT), "{p}");
            assert_eq!(
                part["genesis_hash"],
                json!(fx.list.genesis_hash().to_hex()),
                "{p}"
            );
        }
        let loaded = ControlState::from_parts(&fx.list, parts.clone()).unwrap();
        assert_eq!(loaded.state, state);
        assert!(loaded.foreign.is_empty());

        // Re-paired: the same account, a new genesis, svc-1 and svc-2 again.
        let repaired = Fx::with_genesis_at(ACCOUNT, T0 + 1);
        assert_ne!(repaired.list.genesis_hash(), fx.list.genesis_hash());
        assert!(repaired.list.member("svc-1").is_some());
        let other = Fx::account("acct-test-2");
        for list in [&repaired.list, &other.list] {
            // Every part foreign: the list's empty state, every key reported.
            let loaded = ControlState::from_parts(list, parts.clone()).unwrap();
            assert_eq!(loaded.state, ControlState::new(list));
            assert_eq!(loaded.foreign, vec![service("svc-1"), service("svc-2")],);
            // In any order, and a subset reports its own keys.
            let reversed: Vec<_> = parts.iter().rev().cloned().collect();
            let loaded = ControlState::from_parts(list, reversed).unwrap();
            assert_eq!(loaded.foreign, vec![service("svc-1"), service("svc-2")]);
            let loaded = ControlState::from_parts(list, parts[1..].to_vec()).unwrap();
            assert_eq!(loaded.foreign, vec![service("svc-2")]);
        }
        // The recurring ids inherit nothing.
        let fresh = ControlState::from_parts(&repaired.list, parts.clone())
            .unwrap()
            .state;
        for p in ["service:svc-1", "service:svc-2"] {
            assert_eq!(fresh.standing(p), Standing::default(), "{p}");
        }

        // The whole state: a part of another list (or another account) in
        // it is refused, whatever its header says.
        let json = state.to_json();
        type Edit = Box<dyn Fn(&mut Value)>;
        let edits: Vec<Edit> = vec![
            Box::new(|j| j["principals"]["service:svc-1"]["genesis_hash"] = json!("11".repeat(32))),
            Box::new(|j| j["principals"]["service:svc-2"]["account_id"] = json!("acct-test-2")),
            Box::new(|j| {
                j["principals"]["service:svc-1"]
                    .as_object_mut()
                    .unwrap()
                    .remove("account_id");
            }),
        ];
        for edit in edits {
            let mut bad = json.clone();
            edit(&mut bad);
            assert!(ControlState::from_json(&bad).is_err(), "{bad}");
        }
    }

    /// A store mixing the current list's parts with an old list's leftovers
    /// (a live re-pair whose old rows weren't deleted) loads the current
    /// list's: its revoke, interrupt and hold stay in force; the old parts
    /// are reported, never loaded (ruling T4e).
    #[test]
    fn a_mixed_store_keeps_the_current_lists_parts_and_reports_the_old() {
        // The old list: svc-2 covered and held, host-a interrupted.
        let mut old = Fx::new();
        let r = old.revoke_host(false);
        let mut before = old.state();
        before.adopt(
            &old.svc(1, "svc-2", "svc-2", C::Cover, A),
            &old.list,
            at(A, 1),
            0,
        );
        before.adopt(
            &old.svc(2, "svc-2", "svc-2", C::Hold, A),
            &old.list,
            at(A, 2),
            0,
        );
        before.adopt(&old.host(3, "mac", r), &old.list, None, old.list.head().seq);
        // The current list: svc-1 held, then revoked with its interrupt.
        let current = Fx::with_genesis_at(ACCOUNT, T0 + 1);
        let mut now = current.state();
        let s1 = |n: u32, action: ControlAction| current.svc(n, "svc-1", "svc-1", action, A);
        assert_eq!(
            now.adopt(&s1(4, C::Hold), &current.list, at(A, 1), 0),
            held("svc-1")
        );
        assert_eq!(
            now.adopt(&s1(5, revoke(true)), &current.list, at(A, 2), 0)
                .record_result,
            R::Applied
        );
        // The store: the current list's svc-1 beside the old svc-2 and host-a.
        let mut store = parts_of(&before);
        store.extend(parts_of(&now));
        for order in [store.clone(), store.iter().rev().cloned().collect()] {
            let loaded = ControlState::from_parts(&current.list, order).unwrap();
            assert_eq!(loaded.state, now);
            assert_eq!(
                loaded.foreign,
                vec!["host:host-a".to_string(), service("svc-2")]
            );
            assert_eq!(
                loaded.state.standing(&service("svc-1")),
                standing(Some(rid(5)), &[rid(5)], true, None)
            );
            assert_eq!(
                loaded.state.standing(&service("svc-2")),
                Standing::default()
            );
        }
    }

    /// A part of the current list that fails strict reading still fails the
    /// load, and so does a part whose device list can't be read or a
    /// principal given twice: nothing is skipped that might be the current
    /// list's (ruling T4e).
    #[test]
    fn a_damaged_part_of_the_current_list_still_fails() {
        let fx = Fx::new();
        let mut state = fx.state();
        state.adopt(
            &fx.svc(1, "svc-1", "svc-1", C::Hold, A),
            &fx.list,
            at(A, 1),
            0,
        );
        let (p, part) = parts_of(&state).remove(0);
        let damaged = |edit: &dyn Fn(&mut Value)| {
            let mut part = part.clone();
            edit(&mut part);
            vec![(p.clone(), part)]
        };
        let cases: Vec<(&str, Vec<(String, Value)>)> = vec![
            ("held not a boolean", damaged(&|j| j["held"] = json!(1))),
            ("no records", damaged(&|j| j["records"] = json!([]))),
            (
                "genesis not hex",
                damaged(&|j| j["genesis_hash"] = json!("zz")),
            ),
            (
                "genesis not a string",
                damaged(&|j| j["genesis_hash"] = json!(7)),
            ),
            (
                "no genesis",
                damaged(&|j| {
                    j.as_object_mut().unwrap().remove("genesis_hash");
                }),
            ),
            (
                "account not a string",
                damaged(&|j| j["account_id"] = json!(7)),
            ),
            (
                "no account",
                damaged(&|j| {
                    j.as_object_mut().unwrap().remove("account_id");
                }),
            ),
            ("not an object", vec![(p.clone(), json!([]))]),
            (
                "given twice",
                vec![(p.clone(), part.clone()), (p.clone(), part.clone())],
            ),
            (
                "a name that is no principal",
                vec![("svc-1".into(), part.clone())],
            ),
        ];
        for (what, parts) in cases {
            assert!(ControlState::from_parts(&fx.list, parts).is_err(), "{what}");
        }
        // A foreign part beside it changes nothing about that: the
        // damaged part names this list.
        let other = Fx::with_genesis_at(ACCOUNT, T0 + 1);
        let mut theirs = other.state();
        theirs.adopt(
            &other.svc(2, "svc-2", "svc-2", C::Hold, A),
            &other.list,
            at(A, 1),
            0,
        );
        let mut mixed = parts_of(&theirs);
        assert_eq!(
            ControlState::from_parts(&fx.list, mixed.clone())
                .unwrap()
                .foreign,
            vec![service("svc-2")]
        );
        mixed.extend(damaged(&|j| j["held"] = json!(1)));
        assert!(ControlState::from_parts(&fx.list, mixed).is_err());
    }

    // ------------------- O1: a release lifts only holds issued before it

    /// `rec` is refused, not as evidence, for `why`, and changes nothing:
    /// no action, no part touched, the same state.
    fn refused_for(
        state: &ControlState,
        list: &Membership,
        rec: &ControlRecord,
        pos: Option<FeedPos>,
        want: Why,
    ) {
        let t = state.apply(rec, list, pos.clone(), 0);
        assert_eq!(
            (t.applied.record_result, t.applied.evidence, t.applied.why),
            (R::Refused, false, Some(want)),
            "{} at {pos:?}",
            rec.record_id()
        );
        assert!(t.applied.actions.is_empty(), "{}", rec.record_id());
        assert!(t.touched().is_empty(), "{}", rec.record_id());
        assert_eq!(&t.next, state, "{}", rec.record_id());
    }

    /// The newest `issued_at` of a hold `principal`'s part keeps.
    fn hold_time(state: &ControlState, principal: &str) -> Option<u64> {
        state
            .part(principal)
            .and_then(|part| part.get("hold_issued_at").map(|t| t.as_u64().unwrap()))
    }

    /// O1 (Astation's review of PR 2, #120 comment 6848326392): a release
    /// lifts a hold only when it was issued strictly after every hold the
    /// state verified for the principal. A release the carrier withheld,
    /// or one refused before, served in feed order after a newer hold, is
    /// refused (`not_after_hold`; a genuine record, only stale, so no
    /// evidence) and changes nothing, the feed's order included; a release
    /// issued after the hold lifts it.
    #[test]
    fn a_release_lifts_only_holds_issued_before_it() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc1 = service("svc-1");
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let refused_before = s(5, C::Release);
        let withheld = s(4, C::Release);
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
                Step::new(&s(2, C::Hold), at(A, 2), held("svc-1")),
                // At the hold's own position: not after it in the feed.
                Step::new(&refused_before, at(A, 2), all(R::Refused, &[E::Release])),
                Step::new(&s(3, C::Release), at(A, 3), released("svc-1")),
                Step::new(&s(6, C::Hold), at(A, 4), held("svc-1")),
            ],
        );
        assert_eq!(hold_time(&state, &svc1), Some(issued(6)));
        // Both in feed order now, both issued before the hold in force.
        refused_for(&state, &fx.list, &withheld, at(A, 5), Why::NotAfterHold);
        refused_for(
            &state,
            &fx.list,
            &refused_before,
            at(A, 6),
            Why::NotAfterHold,
        );
        assert_eq!(
            state.adopt(&withheld, &fx.list, at(A, 5), 0),
            all(R::Refused, &[E::Release])
        );
        assert!(state.standing(&svc1).held);
        // The refused release took no position: one issued after the hold,
        // at the same position, lifts it.
        assert_eq!(
            state.adopt(&s(7, C::Release), &fx.list, at(A, 5), 0),
            released("svc-1")
        );
        assert_eq!(state.standing(&svc1), standing(None, &[], false, Some(A)));
        // The hold's time stays: a later release changes nothing of it.
        assert_eq!(hold_time(&state, &svc1), Some(issued(6)));
    }

    /// The tie rule is conservative: a release issued in the same
    /// millisecond as the hold leaves it; one a millisecond later lifts it.
    #[test]
    fn a_release_issued_at_the_holds_time_leaves_it() {
        let fx = Fx::new();
        let mut state = fx.state();
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        state.adopt(&s(1, C::Cover), &fx.list, at(A, 1), 0);
        assert_eq!(
            state.adopt(&s(2, C::Hold), &fx.list, at(A, 2), 0),
            held("svc-1")
        );
        let tie = fx.svc_issued(3, "svc-1", C::Release, A, issued(2));
        refused_for(&state, &fx.list, &tie, at(A, 3), Why::NotAfterHold);
        let after = fx.svc_issued(4, "svc-1", C::Release, A, issued(2) + 1);
        assert_eq!(
            state.adopt(&after, &fx.list, at(A, 3), 0),
            released("svc-1")
        );
    }

    /// A newer hold while held is a duplicate, yet its time is kept (the
    /// part changes): a release issued after the hold in force but not
    /// after the newer one leaves the principal held. An older hold never
    /// lowers the time.
    #[test]
    fn a_newer_hold_while_held_protects_too() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc1 = service("svc-1");
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        state.adopt(&s(1, C::Cover), &fx.list, at(A, 1), 0);
        state.adopt(&s(2, C::Hold), &fx.list, at(A, 2), 0);
        let newer = state.apply(&s(5, C::Hold), &fx.list, at(A, 3), 0);
        assert_eq!(newer.applied, dup(&[E::Hold]));
        assert_eq!(newer.touched(), vec![svc1.clone()]);
        state.adopt(&s(5, C::Hold), &fx.list, at(A, 3), 0);
        assert_eq!(hold_time(&state, &svc1), Some(issued(5)));
        // A record id already counted, re-served: nothing changes.
        assert!(
            state
                .apply(&s(5, C::Hold), &fx.list, at(A, 3), 0)
                .touched()
                .is_empty()
        );
        // An older hold, delivered late: a duplicate, the time stays.
        assert_eq!(
            state.adopt(&s(3, C::Hold), &fx.list, None, 0),
            dup(&[E::Hold])
        );
        assert_eq!(hold_time(&state, &svc1), Some(issued(5)));
        refused_for(
            &state,
            &fx.list,
            &s(4, C::Release),
            at(A, 4),
            Why::NotAfterHold,
        );
        assert_eq!(
            state.adopt(&s(6, C::Release), &fx.list, at(A, 4), 0),
            released("svc-1")
        );
    }

    /// Every verified hold counts, wherever it was read: from a feed that
    /// doesn't cover the principal, over a channel (no position), and one
    /// under a counted record id (evidence, still applied as a stop).
    #[test]
    fn a_hold_from_another_feed_with_no_position_or_a_colliding_id_protects() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc1 = service("svc-1");
        let a = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        let b = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, B);
        state.adopt(&a(1, C::Cover), &fx.list, at(A, 1), 0);
        // Station B covers nothing here: its hold applies all the same.
        assert_eq!(
            state.adopt(&b(5, C::Hold), &fx.list, at(B, 1), 0),
            held("svc-1")
        );
        refused_for(
            &state,
            &fx.list,
            &a(3, C::Release),
            at(A, 2),
            Why::NotAfterHold,
        );
        // A hold over a channel, read at no position.
        assert_eq!(
            state.adopt(&a(8, C::Hold), &fx.list, None, 0),
            dup(&[E::Hold])
        );
        assert_eq!(hold_time(&state, &svc1), Some(issued(8)));
        refused_for(
            &state,
            &fx.list,
            &a(6, C::Release),
            at(A, 2),
            Why::NotAfterHold,
        );
        // A hold under the cover's record id: evidence, applied as a stop,
        // and its time is kept like any hold's.
        let mut colliding = fx.service_body(10, "svc-1", "svc-1", C::Hold, A);
        colliding.record_id = rid(1);
        let colliding = fx.sign(&colliding, "svc-1");
        assert_eq!(
            state.adopt(&colliding, &fx.list, at(A, 2), 0),
            evidence(dup(&[E::Hold]))
        );
        assert_eq!(hold_time(&state, &svc1), Some(issued(10)));
        refused_for(
            &state,
            &fx.list,
            &a(9, C::Release),
            at(A, 3),
            Why::NotAfterHold,
        );
        assert_eq!(
            state.adopt(&a(11, C::Release), &fx.list, at(A, 3), 0),
            released("svc-1")
        );
    }

    /// No floor, eviction, feed reset, coverage change or restart erases
    /// the hold's time. The evicted floor can't protect here (the release
    /// was issued after it): the hold's time does.
    #[test]
    fn the_hold_time_survives_eviction_reset_coverage_change_and_restart() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc2 = service("svc-2");
        let s2 =
            |n: u32, action: ControlAction, feed: Feed| fx.svc(n, "svc-2", "svc-2", action, feed);
        // A release, record `n`, issued at `at` (after the floor, before
        // the newest hold): its id none the fill counts.
        let release =
            |n: u32, feed: Feed, at: u32| fx.svc_issued(n, "svc-2", C::Release, feed, issued(at));
        state.adopt(&s2(1, C::Cover, A), &fx.list, at(A, 1), 0);
        assert_eq!(
            state.adopt(&s2(2, C::Hold, A), &fx.list, at(A, 2), 0),
            held("svc-2")
        );
        // Newer holds at no position, duplicates, until the first hold is
        // evicted: the floor is its time, the hold's time the newest.
        fill(&mut state, &fx, 10..=264, C::Hold);
        assert!(!ids_of(&state, &svc2).contains(&rid(2)), "evicted");
        let part = state.part(&svc2).unwrap();
        assert_eq!(part["evicted_floor"], json!(issued(2)));
        assert_eq!(part["hold_issued_at"], json!(issued(264)));
        refused_for(
            &state,
            &fx.list,
            &release(300, A, 100),
            at(A, 3),
            Why::NotAfterHold,
        );
        // A reset: the newer cover moves the order to the new feed.
        assert_eq!(
            state
                .adopt(&s2(400, C::Cover, A2), &fx.list, at(A2, 1), 0)
                .actions,
            vec![cover_action("svc-2", A2)]
        );
        refused_for(
            &state,
            &fx.list,
            &release(301, A2, 200),
            at(A2, 2),
            Why::NotAfterHold,
        );
        // Another Station takes the coverage over.
        assert_eq!(
            state
                .adopt(&s2(401, C::Cover, B), &fx.list, at(B, 1), 0)
                .actions,
            vec![cover_action("svc-2", B)]
        );
        refused_for(
            &state,
            &fx.list,
            &release(302, B, 250),
            at(B, 2),
            Why::NotAfterHold,
        );
        assert_eq!(hold_time(&state, &svc2), Some(issued(264)));
        // A restart, from the whole state or from the parts.
        let whole = ControlState::from_json(&state.to_json()).unwrap();
        let parts = ControlState::from_parts(&fx.list, parts_of(&state))
            .unwrap()
            .state;
        for resumed in [&whole, &parts] {
            assert_eq!(resumed, &state);
            refused_for(
                resumed,
                &fx.list,
                &release(303, B, 260),
                at(B, 2),
                Why::NotAfterHold,
            );
        }
        assert_eq!(
            state.adopt(&s2(500, C::Release, B), &fx.list, at(B, 2), 0),
            released("svc-2")
        );
    }

    /// A revoke stays final: no release, however new, lifts the hold, and
    /// a hold after it changes nothing (its time included).
    #[test]
    fn no_release_lifts_a_hold_after_a_revoke() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc1 = service("svc-1");
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        state.adopt(&s(1, C::Cover), &fx.list, at(A, 1), 0);
        state.adopt(&s(2, C::Hold), &fx.list, at(A, 2), 0);
        state.adopt(&s(3, revoke(false)), &fx.list, at(A, 3), 0);
        refused_for(
            &state,
            &fx.list,
            &s(10, C::Release),
            at(A, 4),
            Why::AfterRevoke,
        );
        let later = state.apply(&s(11, C::Hold), &fx.list, at(A, 4), 0);
        assert_eq!(later.applied, dup(&[E::Hold]));
        state.adopt(&s(11, C::Hold), &fx.list, at(A, 4), 0);
        assert_eq!(hold_time(&state, &svc1), Some(issued(2)));
        assert_eq!(
            state.standing(&svc1),
            standing(Some(rid(3)), &[], true, Some(A))
        );
    }

    /// The hold's time in a stored part: a service part keeps it once a
    /// hold was verified, never a host principal's. A part without it is
    /// read as "no hold's time known" only while it holds nothing (every
    /// hold a later release could lift is then verified after the load,
    /// and so recorded); a held part without it is damage.
    #[test]
    fn a_stored_part_reads_the_hold_time_strictly() {
        let fx = Fx::new();
        let mut state = fx.state();
        let svc1 = service("svc-1");
        let s = |n: u32, action: ControlAction| fx.svc(n, "svc-1", "svc-1", action, A);
        state.adopt(&s(1, C::Cover), &fx.list, at(A, 1), 0);
        state.adopt(&s(5, C::Hold), &fx.list, at(A, 2), 0);
        let held_part = state.part(&svc1).unwrap();
        assert_eq!(held_part["hold_issued_at"], json!(issued(5)));
        state.adopt(&s(6, C::Release), &fx.list, at(A, 3), 0);
        let free_part = state.part(&svc1).unwrap();
        assert_eq!(free_part["held"], json!(false));
        let load = |part: Value| ControlState::from_parts(&fx.list, vec![(svc1.clone(), part)]);
        let without = |mut part: Value| {
            part.as_object_mut().unwrap().remove("hold_issued_at");
            part
        };
        // Free: no time known, read as none.
        let mut unknown = load(without(free_part.clone())).unwrap().state;
        assert_eq!(hold_time(&unknown, &svc1), None);
        assert_eq!(
            unknown.adopt(&s(3, C::Hold), &fx.list, at(A, 4), 0),
            held("svc-1")
        );
        assert_eq!(
            unknown.adopt(&s(4, C::Release), &fx.list, at(A, 5), 0),
            released("svc-1")
        );
        // Held: damage, never "no time known".
        assert!(load(without(held_part.clone())).is_err());
        let mut whole = state.to_json();
        whole["principals"][&svc1] = without(held_part.clone());
        assert!(ControlState::from_json(&whole).is_err());
        // Its form: a safe integer, never null.
        for bad in [
            json!(null),
            json!("1"),
            json!(-1),
            json!(1.5),
            json!(9_007_199_254_740_992u64),
        ] {
            let mut part = held_part.clone();
            part["hold_issued_at"] = bad.clone();
            assert!(load(part).is_err(), "{bad}");
        }
        // Never on a host principal's part.
        let mut fx = Fx::new();
        let r = fx.revoke_host(false);
        let mut host = fx.state();
        host.adopt(&fx.host(7, "mac", r), &fx.list, None, r);
        let mut part = host.part("host:host-a").unwrap();
        part["hold_issued_at"] = json!(issued(5));
        assert!(ControlState::from_parts(&fx.list, vec![("host:host-a".into(), part)]).is_err());
    }

    #[test]
    fn not_after_hold_is_a_why() {
        assert_eq!(Why::NotAfterHold.code(), "not_after_hold");
        assert_eq!(Why::from_code("not_after_hold"), Some(Why::NotAfterHold));
    }
}

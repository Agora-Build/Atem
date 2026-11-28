//! A replacement feed's snapshot, checked for **consistency** with what a
//! restored Station retained (host-work-v1 §11.1, "Resets"; Astation #114,
//! items 2 and 6, agreed 2026-11-22). Sans-I/O and pure: no clock, no
//! storage.
//!
//! **What it never says.** [`SnapshotConsistency::Consistent`] means the
//! snapshot contradicts nothing the caller handed in: the records the
//! restored Station retained, the marks, the covered set and the
//! provisioned set. It is never a
//! statement that the retained records are the whole history, that a mark
//! bounds every time the old deployment signed or reserved, or that every
//! author's stops reached the Station: what the rollback lost, nothing
//! here can see. Those stay the Station's and the owner's open
//! obligations (#114, items 1, 3 and 4).
//!
//! **The checks**, first over the retained records, then record by record
//! in publication order, then over the whole snapshot; the first that
//! fails is the answer ([`SnapshotInconsistency`]):
//! 0. `invalid_retained`: a retained record that isn't valid at the
//!    verifying head (`reason`: [`verify_control`]'s pending or refusal
//!    code; `index`: its position in the retained records), but a stop a
//!    removed manager signed (below). The input itself is in question:
//!    verify the retained records at a head that includes them, or drop
//!    what doesn't verify from what is passed as retained. Never a request
//!    to sign anything again: a record whose signature nobody verified
//!    (a forgery, another account's) is never a stop to re-sign.
//! 1. `invalid_record`: the record isn't valid at the verifying head
//!    ([`verify_control`] on the list given; `reason` is its pending or
//!    refusal code). A removed manager's original is `removed_manager`: a
//!    current manager signs it again, a new `record_id` (I.5.4).
//! 2. `wrong_origin`: a service's record naming another Station's origin.
//! 3. `not_signed_anew`: a cover, hold or release whose signed object is a
//!    retained record's: those are always signed anew.
//! 4. `not_candidate_feed`: a record signed anew with the service's own
//!    key that doesn't name the candidate feed. A current manager's stop
//!    may name any feed of this origin, and so may a retained stop carried
//!    as it is (below).
//! 5. `cover_not_first`: a covered principal's first record isn't its
//!    cover, or a hold or release comes before its principal's cover.
//! 6. `uncovered_cover`: a cover for a principal outside the covered set.
//! 7. `not_above_mark`: a record signed anew with the service's own key,
//!    issued at or below its principal's mark (`U_p`, or the mark the
//!    Station signs above), or for a principal with no mark given.
//!
//! Then, at `index` the snapshot's length:
//! 8. `cover_not_first`: a covered principal the snapshot holds no cover
//!    for.
//! 9. `coverage_dropped`: a principal the Station provisioned at its origin
//!    and hasn't handed over (`provisioned`, in sorted order) that is
//!    neither covered, nor revoked by a `revoke` of that principal the
//!    snapshot carries (every snapshot record verified at the head by
//!    then), nor removed from the device list at the head (host-work-v1
//!    §11.1, "Which principals a Station currently covers", agreed with
//!    Astation, Astation #114 comments 7208700195 and 7209301522; the input
//!    requested there). A Portal-only revoke, an expiry, an absent key or a
//!    missing reservation never clears coverage. An empty `provisioned`
//!    checks nothing here. Its place, after the covered principals'
//!    missing covers and before the retained stops' effects, is Atem's
//!    choice.
//! 10. `stop_lost` or `stop_not_resigned`: an effect of a retained `revoke`
//!    or `interrupt_running` (its principal's revocation, and the
//!    interrupt with it) that the snapshot alone, applied to a fresh state
//!    (a host that never read the old feed), doesn't keep (below), in the
//!    retained order: `stop_lost` when that stop is valid at the head (the
//!    snapshot drops what it could carry), `stop_not_resigned` when it is
//!    refused `removed_manager` (`reason`): a genuine stop, its signature
//!    verified under the former manager's key, which a current manager
//!    signs again (I.5.4). A retained service's interrupt is due once its
//!    principal is revoked, by a retained revoke or after the snapshot,
//!    and must then be in force. One not yet due (a retained
//!    `interrupt_running` of a principal nothing revokes) waits, pending,
//!    on a host that read the old feed, which interrupts at a later
//!    revoke: the snapshot must then hold an `interrupt_running` of that
//!    principal (the retained one carried unchanged, or a current
//!    manager's copy) so a new host holds it pending too. A host
//!    principal's interrupt is in force when its device-list revoke itself
//!    carried `interrupt_running`. Holds and releases aren't
//!    compared: the Portal's current state decides those.
//!    `stop_not_resigned` is effect-only: any valid snapshot stop that
//!    keeps the original's effects passes it. Whether a stop is a
//!    conforming copy of the original is
//!    [`check_resigned_copy`](super::check_resigned_copy)'s, stricter: a
//!    conforming copy always keeps every effect, so the two never disagree
//!    in that direction, and the snapshots this passes and that refuses
//!    are the adapter's to refuse.
//!
//! **Carried as it is** (Atem's reading of host-work-v1 §11.1, "Resets":
//! the snapshot's revoke and interrupt records "as they are or signed
//! anew"; a current manager's, agreed with Astation, #114 comment
//! 7082464868, item 2; the service's own key's, agreed with Astation,
//! #114 comment 7089435073). A snapshot `revoke` or `interrupt_running` whose
//! signed object (body and signature) is a retained record's is that
//! record carried unchanged, whoever signed it: it needs neither the
//! candidate feed nor the mark (a stop applies from any feed, rule 3, and
//! needs no safety clock, #114 R4). It must still be valid at the head and
//! of this origin. Any other record the service's own key signs in a
//! snapshot is signed anew.
//!
//! **The snapshot alone** is applied at the verifying head, as a host
//! applies a feed ([`ControlState::apply`], `host_applied_seq` the head's
//! `seq`), each record at its position in the candidate feed (`feed_seq`
//! from 1), a record left pending applied once more after the rest, as a
//! host applies its pending records again after a revocation.
use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::MAX_SAFE_INTEGER;
use crate::error::{Error, Result};
use crate::membership::{Action, MemberStatus, Membership};
use crate::session::wire::is_uuid_v4;
use crate::station_route::normalize_relay;

use super::record::{ControlAction, ControlPrincipal, ControlRecord, ControlSigner};
use super::state::{ApplicationResult, ControlState, EffectKind, FeedPos};
use super::verify::{ControlCheck, RefusalReason, verify_control};

/// What [`check_snapshot_consistency`] compares.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotInput<'a> {
    /// The device list at the head every snapshot record is verified at,
    /// never frozen.
    pub list: &'a Membership,
    /// The Station's exact origin, as `normalize_relay` writes it.
    pub origin: &'a str,
    /// The replacement feed's `feed_id` (a UUID v4).
    pub candidate_feed_id: &'a str,
    /// The records the restored Station retained, in its feed's order.
    pub retained: &'a [ControlRecord],
    /// The snapshot's records, in publication order.
    pub snapshot: &'a [ControlRecord],
    /// Each service principal's mark (`service:<id>` → ms since the
    /// epoch): a record its own key signs anew is issued strictly after
    /// it.
    pub marks: &'a BTreeMap<String, u64>,
    /// The principals the snapshot covers (`service:<id>`).
    pub covered: &'a BTreeSet<String>,
    /// The services the Station provisioned at `origin` and hasn't handed
    /// over (`service:<id>`, the identity `covered` uses): each must be
    /// covered, revoked by the snapshot or removed at the head
    /// (`coverage_dropped`). Required; empty checks nothing.
    pub provisioned: &'a BTreeSet<String>,
}

/// The answer: consistent with what was handed in, or the first
/// inconsistency. Never a proof that the history, or a clock, is complete
/// (the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotConsistency {
    /// Nothing handed in contradicts the snapshot.
    Consistent,
    /// The first check that failed.
    Inconsistent(SnapshotInconsistency),
}

/// Where the snapshot first contradicts what was handed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInconsistency {
    /// The snapshot record's position (from 0); the snapshot's length for
    /// what only the whole snapshot shows (a covered principal with no
    /// cover, a retained stop's effect not kept); for
    /// `invalid_retained`, the record's position in the retained records.
    pub index: usize,
    /// The snapshot record's `record_id`; for `invalid_retained`,
    /// `stop_lost` and `stop_not_resigned`, the retained record's; `None`
    /// for a covered principal with no cover.
    pub record_id: Option<String>,
    /// The principal it is about (`service:<id>`, `host:<host_id>`).
    pub principal: String,
    pub code: InconsistencyCode,
    /// `invalid_retained`, `invalid_record` and `stop_not_resigned`
    /// (always `removed_manager`): [`verify_control`]'s pending or refusal
    /// code.
    pub reason: Option<String>,
    /// `stop_lost` and `stop_not_resigned`: the effect the snapshot
    /// doesn't keep, [`EffectKind::Revocation`] or
    /// [`EffectKind::Interrupt`].
    pub effect: Option<EffectKind>,
    /// `stop_lost` or `stop_not_resigned` of a host principal's interrupt:
    /// its `revoke_seq`.
    pub revoke_seq: Option<u64>,
}

/// Why a snapshot is inconsistent (the module docs give each check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InconsistencyCode {
    InvalidRetained,
    InvalidRecord,
    WrongOrigin,
    NotSignedAnew,
    NotCandidateFeed,
    CoverNotFirst,
    UncoveredCover,
    NotAboveMark,
    CoverageDropped,
    StopLost,
    StopNotResigned,
}

impl InconsistencyCode {
    /// A stable name.
    pub fn code(self) -> &'static str {
        match self {
            InconsistencyCode::InvalidRetained => "invalid_retained",
            InconsistencyCode::InvalidRecord => "invalid_record",
            InconsistencyCode::WrongOrigin => "wrong_origin",
            InconsistencyCode::NotSignedAnew => "not_signed_anew",
            InconsistencyCode::NotCandidateFeed => "not_candidate_feed",
            InconsistencyCode::CoverNotFirst => "cover_not_first",
            InconsistencyCode::UncoveredCover => "uncovered_cover",
            InconsistencyCode::NotAboveMark => "not_above_mark",
            InconsistencyCode::CoverageDropped => "coverage_dropped",
            InconsistencyCode::StopLost => "stop_lost",
            InconsistencyCode::StopNotResigned => "stop_not_resigned",
        }
    }

    /// Every code, in the order the checks first run (`cover_not_first`
    /// runs again after the last snapshot record, and `stop_lost` and
    /// `stop_not_resigned` interleave in the retained order).
    pub const ALL: [InconsistencyCode; 11] = [
        InconsistencyCode::InvalidRetained,
        InconsistencyCode::InvalidRecord,
        InconsistencyCode::WrongOrigin,
        InconsistencyCode::NotSignedAnew,
        InconsistencyCode::NotCandidateFeed,
        InconsistencyCode::CoverNotFirst,
        InconsistencyCode::UncoveredCover,
        InconsistencyCode::NotAboveMark,
        InconsistencyCode::CoverageDropped,
        InconsistencyCode::StopLost,
        InconsistencyCode::StopNotResigned,
    ];
}

/// Checks a replacement feed's snapshot for consistency with what the
/// restored Station retained (the module docs give the checks, and what
/// the answer never says). Input outside its grammar is
/// [`Error::Malformed`]: an origin not in `normalize_relay`'s form, a
/// candidate feed that isn't a UUID v4, a mark, covered or provisioned
/// principal that isn't a service's (`service:<id>`, canonical), a mark
/// above 2^53 − 1, or a frozen device list (it verifies nothing new, R9.4).
pub fn check_snapshot_consistency(input: &SnapshotInput<'_>) -> Result<SnapshotConsistency> {
    check_input(input)?;
    let found =
        |index, rec: Option<&ControlRecord>, principal: &str, code, reason: Option<&str>| {
            Ok(SnapshotConsistency::Inconsistent(SnapshotInconsistency {
                index,
                record_id: rec.map(|r| r.record_id().to_owned()),
                principal: principal.to_owned(),
                code,
                reason: reason.map(str::to_owned),
                effect: None,
                revoke_seq: None,
            }))
        };
    use InconsistencyCode as Code;
    // The retained records first: the input itself. Only a removed
    // manager's stop may fail to verify (it is a genuine stop, its
    // signature verified under its signer's key from the list's history).
    for (i, rec) in input.retained.iter().enumerate() {
        let reason = match verify_control(rec, input.list) {
            ControlCheck::Valid(_) | ControlCheck::Refused(RefusalReason::RemovedManager) => {
                continue;
            }
            ControlCheck::Pending(r) => r.code(),
            ControlCheck::Refused(r) => r.code(),
        };
        let principal = rec.principal().name();
        return found(
            i,
            Some(rec),
            &principal,
            Code::InvalidRetained,
            Some(reason),
        );
    }
    // The principals with a record so far, and those with a cover.
    let mut seen = BTreeSet::new();
    let mut covers = BTreeSet::new();
    for (i, rec) in input.snapshot.iter().enumerate() {
        let principal = rec.principal().name();
        let at = |code, reason| found(i, Some(rec), &principal, code, reason);
        match verify_control(rec, input.list) {
            ControlCheck::Valid(_) => {}
            ControlCheck::Pending(reason) => return at(Code::InvalidRecord, Some(reason.code())),
            ControlCheck::Refused(reason) => return at(Code::InvalidRecord, Some(reason.code())),
        }
        // Valid, so the service's own key signed it when it names its
        // principal as its signer.
        let own_key = *rec.signer() == ControlSigner::Principal;
        let action = rec.action();
        let stop = matches!(
            action,
            ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. }
        );
        let retained = input.retained.iter().any(|r| r.object() == rec.object());
        // A retained stop carried as it is is no record signed anew,
        // whoever signed it.
        let signed_anew = own_key && !(stop && retained);
        if let Some((origin, feed_id)) = rec.feed() {
            if origin != input.origin {
                return at(Code::WrongOrigin, None);
            }
            if retained && !stop {
                return at(Code::NotSignedAnew, None);
            }
            if signed_anew && feed_id != input.candidate_feed_id {
                return at(Code::NotCandidateFeed, None);
            }
        }
        let first = seen.insert(principal.clone());
        let cover = action == ControlAction::Cover;
        let hold_or_release = matches!(action, ControlAction::Hold | ControlAction::Release);
        if (first && !cover && input.covered.contains(&principal))
            || (hold_or_release && !covers.contains(&principal))
        {
            return at(Code::CoverNotFirst, None);
        }
        if cover && !input.covered.contains(&principal) {
            return at(Code::UncoveredCover, None);
        }
        let mark = input.marks.get(&principal);
        if signed_anew && mark.is_none_or(|mark| rec.issued_at() <= *mark) {
            return at(Code::NotAboveMark, None);
        }
        if cover {
            covers.insert(principal);
        }
    }
    let end = input.snapshot.len();
    if let Some(principal) = input.covered.iter().find(|p| !covers.contains(*p)) {
        return found(end, None, principal, Code::CoverNotFirst, None);
    }
    if let Some(principal) = input
        .provisioned
        .iter()
        .find(|p| coverage_dropped(input, p))
    {
        return found(end, None, principal, Code::CoverageDropped, None);
    }
    Ok(match stop_lost(input, end) {
        Some(lost) => SnapshotConsistency::Inconsistent(lost),
        None => SnapshotConsistency::Consistent,
    })
}

/// The input's grammar (the docs of [`check_snapshot_consistency`]).
fn check_input(input: &SnapshotInput<'_>) -> Result<()> {
    if input.list.frozen().is_some() {
        return Err(Error::Malformed("snapshot device list frozen"));
    }
    if normalize_relay(input.origin).as_deref() != Ok(input.origin) {
        return Err(Error::Malformed("snapshot origin"));
    }
    if !is_uuid_v4(input.candidate_feed_id) {
        return Err(Error::Malformed("snapshot candidate_feed_id"));
    }
    let marks_ok = input
        .marks
        .iter()
        .all(|(p, mark)| is_service(p) && *mark <= MAX_SAFE_INTEGER);
    if !marks_ok {
        return Err(Error::Malformed("snapshot marks"));
    }
    if !input.covered.iter().all(|p| is_service(p)) {
        return Err(Error::Malformed("snapshot covered"));
    }
    if !input.provisioned.iter().all(|p| is_service(p)) {
        return Err(Error::Malformed("snapshot provisioned"));
    }
    Ok(())
}

/// Whether the provisioned service `principal` lost its coverage: not in
/// `covered`, no `revoke` of it in the snapshot (each verified at the head
/// already), and not removed from the device list at the head.
fn coverage_dropped(input: &SnapshotInput<'_>, principal: &str) -> bool {
    if input.covered.contains(principal) {
        return false;
    }
    let revoked = input.snapshot.iter().any(|r| {
        matches!(r.action(), ControlAction::Revoke { .. }) && r.principal().name() == principal
    });
    let removed = principal
        .strip_prefix("service:")
        .and_then(|id| input.list.member(id))
        .is_some_and(|state| state.status == MemberStatus::Removed);
    !revoked && !removed
}

/// `service:<id>`, exactly as [`ControlPrincipal::name`] writes it.
fn is_service(name: &str) -> bool {
    ControlPrincipal::parse(name).is_some_and(|p| !p.is_host() && p.name() == name)
}

/// The first effect of a retained stop, in the retained order (a
/// record's revocation, then its interrupt), not in force after the
/// snapshot alone: `stop_lost` when that stop is valid at the head,
/// `stop_not_resigned` when a removed manager signed it (the module docs;
/// every other retained record verified at the head already).
fn stop_lost(input: &SnapshotInput<'_>, end: usize) -> Option<SnapshotInconsistency> {
    let list = input.list;
    let fresh = in_force(list, input.snapshot, input.origin, input.candidate_feed_id);
    // The services a retained revoke names, valid or not.
    let revoked: BTreeSet<String> = input
        .retained
        .iter()
        .filter(|r| matches!(r.action(), ControlAction::Revoke { .. }))
        .map(|r| r.principal().name())
        .collect();
    for rec in input.retained {
        let (revokes, interrupts) = match rec.action() {
            ControlAction::Revoke { interrupt_running } => (true, interrupt_running),
            ControlAction::InterruptRunning { .. } => (false, true),
            _ => continue,
        };
        let principal = rec.principal().name();
        let has = fresh.standing(&principal);
        // Every other failure was reported as `invalid_retained` first.
        let (code, reason) = match verify_control(rec, list) {
            ControlCheck::Refused(RefusalReason::RemovedManager) => (
                InconsistencyCode::StopNotResigned,
                Some(RefusalReason::RemovedManager.code()),
            ),
            _ => (InconsistencyCode::StopLost, None),
        };
        let lost = |effect, revoke_seq| SnapshotInconsistency {
            index: end,
            record_id: Some(rec.record_id().to_owned()),
            principal: principal.clone(),
            code,
            reason: reason.map(str::to_owned),
            effect: Some(effect),
            revoke_seq,
        };
        match (rec.principal(), rec.action()) {
            (
                ControlPrincipal::Host(host_id),
                ControlAction::InterruptRunning {
                    revoke_seq: Some(seq),
                },
            ) => {
                // In force through a record, or through its device-list
                // revoke itself.
                let by_entry = matches!(
                    list.entry(seq).map(|entry| &entry.action),
                    Some(Action::HostSenderRevoke { host_id: h, interrupt_running: true })
                        if h == host_id
                );
                if !by_entry && !has.interrupted.contains(&seq.to_string()) {
                    return Some(lost(EffectKind::Interrupt, Some(seq)));
                }
            }
            _ => {
                if revokes && has.revoked.is_none() {
                    return Some(lost(EffectKind::Revocation, None));
                }
                // An interrupt is due once its principal is revoked: then it
                // is in force. Until then it waits on a host that read the
                // old feed, so the snapshot holds an `interrupt_running` of
                // that principal for a new host to hold pending too (every
                // snapshot record verified at the head already).
                let due = revokes || revoked.contains(&principal) || has.revoked.is_some();
                let pending_too = || {
                    input.snapshot.iter().any(|r| {
                        r.principal().name() == principal
                            && matches!(r.action(), ControlAction::InterruptRunning { .. })
                    })
                };
                let kept = if due {
                    !has.interrupted.is_empty()
                } else {
                    pending_too()
                };
                if interrupts && !kept {
                    return Some(lost(EffectKind::Interrupt, None));
                }
            }
        }
    }
    None
}

/// The state `records` leave on a fresh state of `list`, applied in order
/// at its head, each at its position in `feed` (`feed_seq` from 1); a
/// record left pending is applied once more after the rest, as a
/// host applies its pending records again after a revocation (only a
/// service's interrupt waits on a later record here: a verdict doesn't
/// change on one list, and a host principal's interrupt verified at the
/// head never waits for `host_applied_seq`, which is the head's).
fn in_force(
    list: &Membership,
    records: &[ControlRecord],
    origin: &str,
    feed_id: &str,
) -> ControlState {
    let head = list.head().seq;
    let pos = |i: usize| {
        Some(FeedPos {
            origin: origin.to_owned(),
            feed_id: feed_id.to_owned(),
            feed_seq: i as u64 + 1,
        })
    };
    let mut state = ControlState::new(list);
    let mut waiting = Vec::new();
    for (i, rec) in records.iter().enumerate() {
        let t = state.apply(rec, list, pos(i), head);
        if t.applied.record_result == ApplicationResult::Pending {
            waiting.push(i);
        }
        state = t.next;
    }
    for i in waiting {
        state = state.apply(&records[i], list, pos(i), head).next;
    }
    state
}

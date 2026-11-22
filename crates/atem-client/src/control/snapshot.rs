//! A replacement feed's snapshot, checked for **consistency** with what a
//! restored Station retained (host-work-v1 §11.1, "Resets"; Astation #114,
//! items 2 and 6, agreed 2026-11-22). Sans-I/O and pure: no clock, no
//! storage.
//!
//! **What it never says.** [`SnapshotConsistency::Consistent`] means the
//! snapshot contradicts nothing the caller handed in: the records the
//! restored Station retained, the marks and the covered set. It is never a
//! statement that the retained records are the whole history, that a mark
//! bounds every time the old deployment signed or reserved, or that every
//! author's stops reached the Station: what the rollback lost, nothing
//! here can see. Those stay the Station's and the owner's open
//! obligations (#114, items 1, 3 and 4).
//!
//! **The checks**, record by record in publication order, then over the
//! whole snapshot; the first that fails is the answer
//! ([`SnapshotInconsistency`]):
//! 1. `invalid_record`: the record isn't valid at the verifying head
//!    ([`verify_control`] on the list given; `reason` is its pending or
//!    refusal code). A removed manager's original is `removed_manager`: a
//!    current manager signs it again, a new `record_id` (I.5.4).
//! 2. `wrong_origin`: a service's record naming another Station's origin.
//! 3. `not_candidate_feed`: a record the service's own key signed (a
//!    cover, hold, release, revoke or interrupt) that doesn't name the
//!    candidate feed: in a snapshot it is signed anew. A current manager's
//!    stop may name any feed of this origin: carried unchanged, it still
//!    names the old feed, and hosts apply a stop from any feed (rule 3;
//!    #114 item 2).
//! 4. `cover_not_first`: a covered principal's first record isn't its
//!    cover, or a hold or release comes before its principal's cover; at
//!    the end, a covered principal the snapshot holds no cover for.
//! 5. `not_above_mark`: a record the service's own key signed, issued at
//!    or below its principal's mark (`U_p`, or the mark the Station signs
//!    above), or for a principal with no mark given.
//! 6. `uncovered_cover`: a cover for a principal outside the covered set.
//! 7. `stop_lost`, at the end: a revocation, or the interrupt of one, in
//!    force in a [`ControlState`] built from the retained records but not
//!    in force after the snapshot alone is applied to a fresh state (a
//!    host that never read the old feed). Holds and releases aren't
//!    compared: the Portal's current state decides those.
//!
//! **Both states** are built at the verifying head, as a host builds its
//! own ([`ControlState::apply`], `host_applied_seq` the head's `seq`): the
//! retained records in the order given, at no feed position (only stops
//! are compared, and a stop applies from any feed or none), the snapshot
//! at its positions in the candidate feed (`feed_seq` from 1); a record
//! left pending is applied once more after the rest, as a host applies its
//! pending records again after a revocation. A retained record that isn't
//! valid at the head (a removed manager's original, say) is in force in
//! neither: its re-signing is the re-sign alert's
//! ([`super::AckLedger::resign_alerts`]), not this check's.
use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::MAX_SAFE_INTEGER;
use crate::error::{Error, Result};
use crate::membership::Membership;
use crate::session::wire::is_uuid_v4;
use crate::station_route::normalize_relay;

use super::record::{ControlAction, ControlPrincipal, ControlRecord, ControlSigner};
use super::state::{ApplicationResult, ControlState, FeedPos};
use super::verify::{ControlCheck, verify_control};

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
    /// epoch): a record its own key signs is issued strictly after it.
    pub marks: &'a BTreeMap<String, u64>,
    /// The principals the snapshot covers (`service:<id>`).
    pub covered: &'a BTreeSet<String>,
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
    /// cover, a stop lost).
    pub index: usize,
    /// The snapshot record's `record_id`; for a service's stop lost, the
    /// `record_id` of the retained revoke that revoked it; `None` for a
    /// covered principal with no cover and for a host principal's
    /// interrupt lost.
    pub record_id: Option<String>,
    /// The principal it is about (`service:<id>`, `host:<host_id>`).
    pub principal: String,
    pub code: InconsistencyCode,
    /// `invalid_record`: [`verify_control`]'s pending or refusal code;
    /// `stop_lost`: the effect lost, `revocation` or `interrupt`.
    pub reason: Option<String>,
    /// `stop_lost` of a host principal's interrupt: its `revoke_seq`.
    pub revoke_seq: Option<u64>,
}

/// Why a snapshot is inconsistent (the module docs give each check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InconsistencyCode {
    InvalidRecord,
    WrongOrigin,
    NotCandidateFeed,
    CoverNotFirst,
    NotAboveMark,
    UncoveredCover,
    StopLost,
}

impl InconsistencyCode {
    /// A stable name.
    pub fn code(self) -> &'static str {
        match self {
            InconsistencyCode::InvalidRecord => "invalid_record",
            InconsistencyCode::WrongOrigin => "wrong_origin",
            InconsistencyCode::NotCandidateFeed => "not_candidate_feed",
            InconsistencyCode::CoverNotFirst => "cover_not_first",
            InconsistencyCode::NotAboveMark => "not_above_mark",
            InconsistencyCode::UncoveredCover => "uncovered_cover",
            InconsistencyCode::StopLost => "stop_lost",
        }
    }

    /// Every code, in the order the checks run.
    pub const ALL: [InconsistencyCode; 7] = [
        InconsistencyCode::InvalidRecord,
        InconsistencyCode::WrongOrigin,
        InconsistencyCode::NotCandidateFeed,
        InconsistencyCode::CoverNotFirst,
        InconsistencyCode::NotAboveMark,
        InconsistencyCode::UncoveredCover,
        InconsistencyCode::StopLost,
    ];
}

/// Checks a replacement feed's snapshot for consistency with what the
/// restored Station retained (the module docs give the checks, and what
/// the answer never says). Input outside its grammar is
/// [`Error::Malformed`]: an origin not in `normalize_relay`'s form, a
/// candidate feed that isn't a UUID v4, a mark or covered principal that
/// isn't a service's (`service:<id>`, canonical), a mark above 2^53 − 1,
/// or a frozen device list (it verifies nothing new, R9.4).
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
                revoke_seq: None,
            }))
        };
    use InconsistencyCode as Code;
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
        if let Some((origin, feed_id)) = rec.feed() {
            if origin != input.origin {
                return at(Code::WrongOrigin, None);
            }
            if own_key && feed_id != input.candidate_feed_id {
                return at(Code::NotCandidateFeed, None);
            }
        }
        let first = seen.insert(principal.clone());
        let action = rec.action();
        let cover = action == ControlAction::Cover;
        let hold_or_release = matches!(action, ControlAction::Hold | ControlAction::Release);
        if (first && !cover && input.covered.contains(&principal))
            || (hold_or_release && !covers.contains(&principal))
        {
            return at(Code::CoverNotFirst, None);
        }
        let mark = input.marks.get(&principal);
        if own_key && mark.is_none_or(|mark| rec.issued_at() <= *mark) {
            return at(Code::NotAboveMark, None);
        }
        if cover {
            if !input.covered.contains(&principal) {
                return at(Code::UncoveredCover, None);
            }
            covers.insert(principal);
        }
    }
    let end = input.snapshot.len();
    if let Some(principal) = input.covered.iter().find(|p| !covers.contains(*p)) {
        return found(end, None, principal, Code::CoverNotFirst, None);
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
    Ok(())
}

/// `service:<id>`, exactly as [`ControlPrincipal::name`] writes it.
fn is_service(name: &str) -> bool {
    ControlPrincipal::parse(name).is_some_and(|p| !p.is_host() && p.name() == name)
}

/// The first stop in force from the retained records that the snapshot
/// alone doesn't put in force: by principal (sorted), its revocation, then
/// its interrupt (a host principal's by `revoke_seq`, ascending).
fn stop_lost(input: &SnapshotInput<'_>, end: usize) -> Option<SnapshotInconsistency> {
    let retained = in_force(input.list, input.retained, None);
    let feed = (input.origin, input.candidate_feed_id);
    let fresh = in_force(input.list, input.snapshot, Some(feed));
    for principal in retained.principals() {
        let (had, has) = (retained.standing(&principal), fresh.standing(&principal));
        let lost = |reason: &str, revoke_seq| SnapshotInconsistency {
            index: end,
            // A service's revocation and its interrupt are named by the
            // retained revoke that revoked it.
            record_id: had.revoked.clone(),
            principal: principal.clone(),
            code: InconsistencyCode::StopLost,
            reason: Some(reason.to_owned()),
            revoke_seq,
        };
        if had.revoked.is_some() && has.revoked.is_none() {
            return Some(lost("revocation", None));
        }
        if ControlPrincipal::parse(&principal).is_some_and(|p| p.is_host()) {
            // A host principal's interrupts, one per `revoke_seq`.
            let mut seqs: Vec<u64> = had
                .interrupted
                .difference(&has.interrupted)
                .filter_map(|seq| seq.parse().ok())
                .collect();
            seqs.sort_unstable();
            if let Some(seq) = seqs.first() {
                return Some(lost("interrupt", Some(*seq)));
            }
        } else if !had.interrupted.is_empty() && has.interrupted.is_empty() {
            return Some(lost("interrupt", None));
        }
    }
    None
}

/// The state `records` leave on a fresh state of `list`, applied in order
/// at its head, each at its position in `feed` (`feed_seq` from 1) or at
/// none; a record left pending is applied once more after the rest, as a
/// host applies its pending records again after a revocation (only a
/// service's interrupt waits on a later record here: a verdict doesn't
/// change on one list, and a host principal's interrupt verified at the
/// head never waits for `host_applied_seq`, which is the head's).
fn in_force(
    list: &Membership,
    records: &[ControlRecord],
    feed: Option<(&str, &str)>,
) -> ControlState {
    let head = list.head().seq;
    let pos = |i: usize| {
        feed.map(|(origin, feed_id)| FeedPos {
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

//! A current native manager's re-signed copy of a stop that a removed or
//! demoted manager signed (host-work-v1 §11.1, "A current manager's copy of
//! a former manager's stop", condition (c), as corrected in Astation #114;
//! agreed with Astation, Astation #114 comments 7208700195 and 7209301522):
//! one shared judgement, so the Mac and the Station judge a copy alike.
//! Sans-I/O and pure: no clock, no storage.
//!
//! [`check_resigned_copy`] says whether `copy`, a current manager's stop,
//! carries exactly `original`'s stop intent, so that it discharges the
//! original's obligation (design I.5.4's "the same body, a new
//! `record_id`", made precise). The checks, in this order, the first that
//! fails the answer ([`CopyRefusal`]):
//!
//! 1. `malformed`: either object isn't a signed control record that reads
//!    strictly (a `record_id` that isn't a UUID v4 among them), the
//!    candidate feed isn't a UUID v4, or the list is frozen (it verifies
//!    nothing new, R9.4; the snapshot checker refuses one too).
//! 2. `not_a_stop`: the original is a `cover`, `hold` or `release`. Those
//!    are never copied: the Station signs them anew with its own key.
//! 3. `original_invalid`: the original's signature doesn't verify under any
//!    `auth_key` its signer had in the list's history, at some `seq`. Its
//!    signer may since have been removed or demoted: that is the point.
//! 4. `copy_invalid`: the copy isn't valid at the list's head
//!    ([`verify_control`]) with a current native manager as its signer (a
//!    record valid under the principal's own key is no manager's copy).
//! 5. `same_record_id`: the copy's `record_id` is the original's (a
//!    `record_id` that isn't a UUID v4 doesn't read: 1).
//! 6. The stop intent, field by field in the body's wire order:
//!    `intent_mismatch` naming the first field that differs, among
//!    `account_id`, `genesis_hash`, `origin`, `principal`, `principal_key`,
//!    `action`, `interrupt_running`, `revoke_seq`, `about.integration_id`
//!    and `about.by`; at `feed_id`'s place (after `origin`), a service's
//!    copy names the original's feed or the candidate feed, else
//!    `feed_mismatch`. `signer`, `record_id` and `issued_at` may differ;
//!    `origin` never.
//!
//! The field order, the details, the frozen list's refusal and
//! `signed_by_principal` are Atem's readings.
//!
//! **What it says, and what it doesn't.** A copy that passes carries the
//! original's stop intent and is a current manager's valid stop: it keeps
//! every effect the original has. Whether the original needs a copy, and a
//! publication's other conditions (the copy in its author's final verified
//! signer report, the final snapshot checked), are the Station's.
//! [`check_snapshot_consistency`](super::check_snapshot_consistency) is
//! weaker and stays so: its `stop_not_resigned` is an effect-only check,
//! which any valid stop keeping the original's effects satisfies (a
//! current manager's revoke with another `about`, the principal's own
//! revoke signed anew). A conforming copy always keeps every effect, so the
//! two never disagree in that direction; the snapshots the checker passes
//! and this refuses are the adapter's to refuse (Astation's publication
//! rule, #114 comment 7208700195, built on this).
use crate::membership::Membership;
use crate::session::wire::is_uuid_v4;

use super::record::{ControlAction, ControlPrincipal, ControlRecord, ControlSigner};
use super::verify::{ControlCheck, VerifiedSigner, verify_control};

/// The refusal codes, in the order the checks run (`intent_mismatch` and
/// `feed_mismatch` interleave in the body's field order).
pub const COPY_CHECK_CODES: [&str; 7] = [
    "malformed",
    "not_a_stop",
    "original_invalid",
    "copy_invalid",
    "same_record_id",
    "intent_mismatch",
    "feed_mismatch",
];

/// Why a copy doesn't discharge its original. `code()` is the stable name,
/// `detail()` what more it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyRefusal {
    /// The original or the copy isn't a signed control record that reads
    /// strictly (`original`, `copy`), the candidate feed isn't a UUID v4
    /// (`candidate_feed_id`), or the list is frozen (`list frozen`).
    Malformed(&'static str),
    /// The original's action is `cover`, `hold` or `release`.
    NotAStop,
    /// The original's signature verifies under no `auth_key` its signer had
    /// in the list's history: `unknown_signer` (the list records no key of
    /// it), `host_key_signed` (a host's own key signs no control record),
    /// `bad_signature`.
    OriginalInvalid(&'static str),
    /// The copy isn't a current native manager's stop valid at the head:
    /// [`verify_control`]'s pending or refusal code, or
    /// `signed_by_principal` for a record valid under the principal's own
    /// key.
    CopyInvalid(&'static str),
    /// The copy's `record_id` is the original's.
    SameRecordId,
    /// The first field of the stop intent that differs (the module docs).
    IntentMismatch(&'static str),
    /// A service's copy names neither the original's feed nor the candidate
    /// feed.
    FeedMismatch,
}

impl CopyRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            CopyRefusal::Malformed(_) => "malformed",
            CopyRefusal::NotAStop => "not_a_stop",
            CopyRefusal::OriginalInvalid(_) => "original_invalid",
            CopyRefusal::CopyInvalid(_) => "copy_invalid",
            CopyRefusal::SameRecordId => "same_record_id",
            CopyRefusal::IntentMismatch(_) => "intent_mismatch",
            CopyRefusal::FeedMismatch => "feed_mismatch",
        }
    }

    /// What the refusal names, when it names something.
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            CopyRefusal::Malformed(what)
            | CopyRefusal::OriginalInvalid(what)
            | CopyRefusal::CopyInvalid(what)
            | CopyRefusal::IntentMismatch(what) => Some(what),
            CopyRefusal::NotAStop | CopyRefusal::SameRecordId | CopyRefusal::FeedMismatch => None,
        }
    }
}

impl std::fmt::Display for CopyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.detail() {
            Some(detail) => write!(f, "{} ({detail})", self.code()),
            None => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for CopyRefusal {}

/// Which feed a service's copy names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyFeed {
    /// The original's feed.
    Original,
    /// The plan's candidate feed, of the same origin.
    Candidate,
}

impl CopyFeed {
    /// `original` or `candidate`.
    pub fn code(self) -> &'static str {
        match self {
            CopyFeed::Original => "original",
            CopyFeed::Candidate => "candidate",
        }
    }
}

/// A copy that discharges its original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResignedCopy {
    pub original_record_id: String,
    pub copy_record_id: String,
    /// The copy's signer, `member:<device_id>`: a current native manager.
    pub signer: String,
    /// `service:<id>` or `host:<host_id>`.
    pub principal: String,
    /// The stop, the original's and the copy's.
    pub action: ControlAction,
    /// Which feed a service's copy names; `None` for a host principal's
    /// record, which names no feed.
    pub feed: Option<CopyFeed>,
}

/// Judges `copy_json` as a current manager's re-signed copy of
/// `original_json` (each `{"body","sig"}` as received) on `log` at its
/// head, `candidate_feed_id` the plan's candidate feed (the module docs
/// give the checks and their order). Pure.
pub fn check_resigned_copy(
    log: &Membership,
    original_json: &[u8],
    copy_json: &[u8],
    candidate_feed_id: &str,
) -> Result<ResignedCopy, CopyRefusal> {
    let original =
        ControlRecord::parse(original_json).map_err(|_| CopyRefusal::Malformed("original"))?;
    let copy = ControlRecord::parse(copy_json).map_err(|_| CopyRefusal::Malformed("copy"))?;
    if !is_uuid_v4(candidate_feed_id) {
        return Err(CopyRefusal::Malformed("candidate_feed_id"));
    }
    if log.frozen().is_some() {
        return Err(CopyRefusal::Malformed("list frozen"));
    }
    judge(log, &original, &copy, candidate_feed_id)
}

/// The checks after the reading, on records already parsed.
pub(crate) fn judge(
    log: &Membership,
    original: &ControlRecord,
    copy: &ControlRecord,
    candidate_feed_id: &str,
) -> Result<ResignedCopy, CopyRefusal> {
    if !is_stop(original.action()) {
        return Err(CopyRefusal::NotAStop);
    }
    original_signed(log, original).map_err(CopyRefusal::OriginalInvalid)?;
    let signer = match verify_control(copy, log) {
        ControlCheck::Valid(valid) => match valid.signer {
            VerifiedSigner::Manager { device_id } => format!("member:{device_id}"),
            VerifiedSigner::Principal { .. } => {
                return Err(CopyRefusal::CopyInvalid("signed_by_principal"));
            }
        },
        ControlCheck::Pending(reason) => return Err(CopyRefusal::CopyInvalid(reason.code())),
        ControlCheck::Refused(reason) => return Err(CopyRefusal::CopyInvalid(reason.code())),
    };
    if copy.record_id() == original.record_id() {
        return Err(CopyRefusal::SameRecordId);
    }
    let feed = same_intent(original, copy, candidate_feed_id)?;
    Ok(ResignedCopy {
        original_record_id: original.record_id().to_owned(),
        copy_record_id: copy.record_id().to_owned(),
        signer,
        principal: copy.principal().name(),
        action: copy.action(),
        feed,
    })
}

fn is_stop(action: ControlAction) -> bool {
    matches!(
        action,
        ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. }
    )
}

/// The original's signature under a key its signer had in the list's
/// history (any `seq`): its signer's `auth_key` as an `add` (or a
/// `recovery_add` that took effect) recorded it.
fn original_signed(log: &Membership, rec: &ControlRecord) -> Result<(), &'static str> {
    let id = match (rec.signer(), rec.principal()) {
        (ControlSigner::Member(id), _) => id.as_str(),
        (ControlSigner::Principal, ControlPrincipal::Service(id)) => id.as_str(),
        (ControlSigner::Principal, ControlPrincipal::Host(_)) => return Err("host_key_signed"),
    };
    let keys = log.keys_ever(id);
    if keys.is_empty() {
        return Err("unknown_signer");
    }
    if keys.iter().any(|(_, key)| rec.object().verify(key).is_ok()) {
        Ok(())
    } else {
        Err("bad_signature")
    }
}

/// The stop intent, field by field in the body's wire order: the first
/// that differs, or which feed a service's copy names.
fn same_intent(
    original: &ControlRecord,
    copy: &ControlRecord,
    candidate_feed_id: &str,
) -> Result<Option<CopyFeed>, CopyRefusal> {
    let (o, c) = (original.body(), copy.body());
    let differs = |field| Err(CopyRefusal::IntentMismatch(field));
    if o.account_id != c.account_id {
        return differs("account_id");
    }
    if o.genesis_hash != c.genesis_hash {
        return differs("genesis_hash");
    }
    let origin = |b: &super::record::ControlBody| b.feed.as_ref().map(|f| f.origin.clone());
    if origin(o) != origin(c) {
        return differs("origin");
    }
    // Both name a feed, or neither (the origins are equal).
    let feed = match (&o.feed, &c.feed) {
        (Some(of), Some(cf)) if cf.feed_id == of.feed_id => Some(CopyFeed::Original),
        (Some(_), Some(cf)) if cf.feed_id == candidate_feed_id => Some(CopyFeed::Candidate),
        (Some(_), Some(_)) => return Err(CopyRefusal::FeedMismatch),
        _ => None,
    };
    if o.principal != c.principal {
        return differs("principal");
    }
    if o.principal_key != c.principal_key {
        return differs("principal_key");
    }
    if o.action.name() != c.action.name() {
        return differs("action");
    }
    match (o.action, c.action) {
        (
            ControlAction::Revoke {
                interrupt_running: a,
            },
            ControlAction::Revoke {
                interrupt_running: b,
            },
        ) if a != b => return differs("interrupt_running"),
        (
            ControlAction::InterruptRunning { revoke_seq: a },
            ControlAction::InterruptRunning { revoke_seq: b },
        ) if a != b => return differs("revoke_seq"),
        _ => {}
    }
    if o.about.integration_id != c.about.integration_id {
        return differs("about.integration_id");
    }
    if o.about.by != c.about.by {
        return differs("about.by");
    }
    Ok(feed)
}

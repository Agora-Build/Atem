//! Control records (delegated host-work design I.5.3 to I.5.5, I.5.8;
//! `designs/protocol/atem-host-work-v1.md` §11.1): signed stops of a
//! service or a host sender, which hosts apply to the delegated work they
//! hold for it. Planned: no host advertises `host.senders` yet.
//!
//! These are production exports for Station builders (plan decision 6): a
//! Station that isn't written in Rust uses them instead of reimplementing
//! the format, its verification or the per-effect rules. The built-in
//! Station uses `atem_client::control` directly; both are the same code.
//!
//! - **Build** a record from its typed body: `build_control_record` signs
//!   through an `AppKeyProvider` (purpose `ServiceControl` for the
//!   integration's own service key, no owner confirmation;
//!   `ControlRecord`, a fresh confirmation, for a native manager); a signer
//!   that answers later (a KMS, WebCrypto) takes
//!   `control_record_signing_input`, signs it, and hands the signature to
//!   `control_record_with_signature`, which verifies it before returning the
//!   record. Every body is checked exactly as the hosts' parse checks it,
//!   so nothing is signed that a host refuses as malformed.
//! - **Read** one: `parse_control_record` (the body, field by field) and
//!   `verify_control_record` (the verdict against a verified device list:
//!   valid, pending or refused, with its reason).
//! - **Apply** them: `ControlStateHandle` is the reference control state of
//!   one device list (`ControlState`): `apply` gives each record's
//!   per-effect results and the host actions, the next state as a new
//!   handle and the principals whose part it changed (`touched`); the
//!   handle applied on never changes. Persist the next state (whole,
//!   `to_json()`, or the touched principals' `part`s) in the same
//!   transaction as your own state, use the next handle once that
//!   transaction committed (keep the old one if it failed: applying the
//!   record again gives the same results), and load the state with
//!   `from_json` or `from_parts` at start. `standing` is what is in force
//!   for one principal.
//!
//! Errors: a record its parse refuses is `Invalid{code}` (`malformed`,
//! `unknown_field`, `field_not_allowed`, `not_for_host_principal`,
//! `wrong_type`, or the signed-object layer's code); a state that doesn't
//! load is `Stored{code}`.
use std::sync::Arc;

use atem_client::KeyId;
use atem_client::canonical::{Numbers, parse_strict};
use atem_client::control::{
    ApplicationResult, Applied, CONTROL_TYPE, ControlAction, ControlBody, ControlCheck,
    ControlRecord, ControlState, EffectKind, FeedPos, HostAction, VerifiedSigner, build_control,
    control_signing_input, control_with_signature, verify_control,
};
use atem_client::encoding::Hash32;
use atem_client::provider::KeyProvider;
use serde_json::{Map, Value, json};

use crate::encoding::{canonical, canonical_lossy, safe_int};
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, object_json};
use crate::types::{
    ControlApplied, ControlCheckInfo, ControlCoverage, ControlEffectKind, ControlEffectResult,
    ControlFeedPos, ControlHostAction, ControlRecordBody, ControlResultKind, ControlStanding,
    ControlStatePart, PublicKeyData,
};

/// Largest control state `ControlStateHandle::from_json` reads, checked
/// before parsing (and the most `from_parts` reads, its parts in all). A
/// principal's part keeps at most 256 counted record ids (about 125 bytes
/// each, `MAX_RECORD_IDS`) and one order entry per Station origin, and
/// only principals of the device list count records (at most 1,024
/// entries), so a state stays well under this.
pub const MAX_CONTROL_STATE_JSON: usize = 64 << 20;

/// The control state's format (`"v"`): 2, one part per principal.
const STATE_VERSION: u64 = 2;

impl ControlRecordBody {
    /// The body object, every given field in it, read by the hosts' own
    /// parse (`ControlBody::from_json`).
    pub(crate) fn to_body(&self) -> Result<ControlBody> {
        let mut o = Map::new();
        o.insert("type".into(), json!(CONTROL_TYPE));
        o.insert("v".into(), json!(1));
        o.insert("account_id".into(), json!(self.account_id));
        o.insert("genesis_hash".into(), json!(self.genesis_hash));
        if let Some(origin) = &self.origin {
            o.insert("origin".into(), json!(origin));
        }
        if let Some(feed_id) = &self.feed_id {
            o.insert("feed_id".into(), json!(feed_id));
        }
        o.insert("principal".into(), json!(self.principal));
        if let Some(key) = &self.principal_key {
            o.insert("principal_key".into(), json!(key));
        }
        o.insert("signer".into(), json!(self.signer));
        o.insert("action".into(), json!(self.action));
        if let Some(interrupt_running) = self.interrupt_running {
            o.insert("interrupt_running".into(), json!(interrupt_running));
        }
        if let Some(seq) = self.revoke_seq {
            o.insert("revoke_seq".into(), json!(safe_int(seq, "revoke_seq")?));
        }
        o.insert("record_id".into(), json!(self.record_id));
        o.insert(
            "issued_at".into(),
            json!(safe_int(self.issued_at, "issued_at")?),
        );
        let mut about = Map::new();
        if let Some(id) = &self.integration_id {
            about.insert("integration_id".into(), json!(id));
        }
        about.insert("by".into(), json!(self.by));
        o.insert("about".into(), Value::Object(about));
        Ok(ControlBody::from_json(&Value::Object(o))?)
    }

    pub(crate) fn of(body: &ControlBody) -> Self {
        let (interrupt_running, revoke_seq) = match body.action {
            ControlAction::Revoke { interrupt_running } => (Some(interrupt_running), None),
            ControlAction::InterruptRunning { revoke_seq } => (None, revoke_seq),
            _ => (None, None),
        };
        ControlRecordBody {
            account_id: body.account_id.clone(),
            genesis_hash: body.genesis_hash.to_hex(),
            origin: body.feed.as_ref().map(|feed| feed.origin.clone()),
            feed_id: body.feed.as_ref().map(|feed| feed.feed_id.clone()),
            principal: body.principal.name(),
            principal_key: body.principal_key.map(|key| key.to_hex()),
            signer: body.signer.name(&body.principal),
            action: body.action.name().into(),
            interrupt_running,
            revoke_seq,
            record_id: body.record_id.clone(),
            issued_at: body.issued_at,
            integration_id: body.about.integration_id.clone(),
            by: body.about.by.clone(),
        }
    }
}

fn record(record_json: &str) -> Result<ControlRecord> {
    Ok(ControlRecord::parse(record_json.as_bytes())?)
}

pub(crate) fn build_control_record_with(
    provider: &dyn KeyProvider,
    key_id: &str,
    body: &ControlRecordBody,
) -> Result<String> {
    let object = build_control(provider, &KeyId::new(key_id), &body.to_body()?)?;
    Ok(object_json(&object))
}

/// Signs a control record with `key_id` through `provider` and returns its
/// wire JSON (`{"body":{…},"sig":"…"}`, canonical). The body is checked as
/// a host's parse checks it first (`Invalid` otherwise, nothing signed).
/// The provider sees purpose `ServiceControl` when `signer` is the
/// principal itself (a service key a Station holds: no owner confirmation)
/// and `ControlRecord` for `member:<device_id>` (a fresh confirmation of
/// `body_json`). Which key may sign which action is the verifier's
/// (`verify_control_record`): a native manager signs `revoke` and
/// `interrupt_running` only, the principal's own key every action. Keep
/// the record (and its `record_id`) durably before you send or announce it.
#[cfg(feature = "uniffi")]
#[uniffi::export]
pub fn build_control_record(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    key_id: String,
    body: ControlRecordBody,
) -> Result<String> {
    build_control_record_with(&crate::provider::Platform(provider), &key_id, &body)
}

/// The bytes a key signs for `body`: `enc(["atem-host-work-control-v1",
/// jcs(body)])`, after the same checks as `build_control_record`. For a
/// signer that answers later; give its signature to
/// `control_record_with_signature` with the same body.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn control_record_signing_input(body: ControlRecordBody) -> Result<Vec<u8>> {
    Ok(control_signing_input(&body.to_body()?)?.as_bytes().to_vec())
}

/// The record of `body` with `signature` (P-256 64-byte `r‖s`, either S,
/// normalized to low S; or Ed25519) by `signer_key` over
/// `control_record_signing_input(body)`. The signature is verified under
/// `signer_key` before the record is returned (`Invalid{bad_signature}`
/// otherwise; an X25519 key is `wrong_alg`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn control_record_with_signature(
    body: ControlRecordBody,
    signer_key: PublicKeyData,
    signature: Vec<u8>,
) -> Result<String> {
    let object = control_with_signature(&body.to_body()?, &signer_key.to_key()?, &signature)?;
    Ok(object_json(&object))
}

/// A record's body, field by field, read as a host reads it (strict JSON,
/// at most 16 KiB, exactly the body's fields). The signature is not
/// checked: that needs the device list (`verify_control_record`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_control_record(record_json: String) -> Result<ControlRecordBody> {
    Ok(ControlRecordBody::of(record(&record_json)?.body()))
}

/// Verifies a record against `log` (I.5.4): the key and its algorithm
/// come from the device-list entry of the signer the body names, never
/// from the record. `Pending` waits for the list (verify again after every
/// advance); `Refused` is kept as evidence. A record its parse refuses is
/// an error (`Invalid{code}`); in a feed, refuse it per record and keep it
/// as evidence too. A `Valid` verdict is for this list only: a host
/// verifies again in the transaction that applies the record
/// (`ControlStateHandle::apply` does), and never applies one while its list
/// is frozen.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_control_record(
    log: Arc<MembershipLog>,
    record_json: String,
) -> Result<ControlCheckInfo> {
    let rec = record(&record_json)?;
    Ok(check_info(&rec, &verify_control(&rec, &log.lock())))
}

fn check_info(rec: &ControlRecord, check: &ControlCheck) -> ControlCheckInfo {
    match check {
        ControlCheck::Valid(valid) => {
            let (signer, key_seq) = match &valid.signer {
                VerifiedSigner::Principal { key_seq } => (rec.principal().name(), Some(*key_seq)),
                VerifiedSigner::Manager { device_id } => (format!("member:{device_id}"), None),
            };
            ControlCheckInfo::Valid {
                signer,
                key_seq,
                head: valid.head.into(),
            }
        }
        ControlCheck::Pending(reason) => ControlCheckInfo::Pending {
            reason: reason.code().into(),
        },
        ControlCheck::Refused(reason) => ControlCheckInfo::Refused {
            reason: reason.code().into(),
        },
    }
}

pub(crate) fn result_kind(result: ApplicationResult) -> ControlResultKind {
    match result {
        ApplicationResult::Applied => ControlResultKind::Applied,
        ApplicationResult::Duplicate => ControlResultKind::Duplicate,
        ApplicationResult::Pending => ControlResultKind::Pending,
        ApplicationResult::Refused => ControlResultKind::Refused,
    }
}

pub(crate) fn effect_kind(effect: EffectKind) -> ControlEffectKind {
    match effect {
        EffectKind::Revocation => ControlEffectKind::Revocation,
        EffectKind::Interrupt => ControlEffectKind::Interrupt,
        EffectKind::Hold => ControlEffectKind::Hold,
        EffectKind::Release => ControlEffectKind::Release,
        EffectKind::Cover => ControlEffectKind::Cover,
    }
}

fn applied_info(applied: Applied) -> ControlApplied {
    ControlApplied {
        result: result_kind(applied.record_result),
        effects: applied
            .effects
            .iter()
            .map(|e| ControlEffectResult {
                effect: effect_kind(e.effect),
                result: result_kind(e.result),
            })
            .collect(),
        actions: applied
            .actions
            .into_iter()
            .map(|action| match action {
                HostAction::Revoke(principal) => ControlHostAction::Revoke { principal },
                HostAction::Interrupt {
                    principal,
                    revocation,
                } => ControlHostAction::Interrupt {
                    principal,
                    revocation,
                },
                HostAction::Hold(principal) => ControlHostAction::Hold { principal },
                HostAction::Release(principal) => ControlHostAction::Release { principal },
                HostAction::Cover {
                    principal,
                    origin,
                    feed_id,
                } => ControlHostAction::Cover {
                    principal,
                    origin,
                    feed_id,
                },
            })
            .collect(),
        evidence: applied.evidence,
    }
}

/// The reference control state of one device list (I.5.5, I.5.8): which
/// principals are revoked, interrupted, covered by which Station's feed,
/// held, and every record that counted. `apply` is the host's rules, so a
/// Station (or a test) predicts exactly what a host reports.
///
/// **A handle never changes.** `apply` returns the record's results and the
/// next state as a new handle (`ControlTransition`); the handle it was
/// called on stays as it was, so it is safe to share across threads.
///
/// **Persistence.** In one transaction, store the next state with what you
/// do with the results (your cursor, acknowledgments, alerts): whole
/// (`next.to_json()`), or one row per principal, writing the `part` of
/// each principal the transition `touched` (no other part changed). Once
/// it committed, use `next` from then on; if it failed, keep the handle
/// you applied on and apply the record again: the same results and
/// actions come back, so no effect is lost. Load the state with
/// `from_json` or `from_parts` at start; never re-apply records to rebuild
/// it (a record verified then may not verify against today's list, and
/// idempotency is by the records kept). Each principal keeps at most 256
/// counted record ids, oldest evicted first (never its revocation's record
/// nor the coverage's cover; a cover or release under an evicted id,
/// issued no later than the newest evicted, is refused as a possible
/// replay, never a hold, revoke or interrupt). Every part names its device
/// list (account and genesis).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ControlStateHandle {
    state: ControlState,
}

impl ControlStateHandle {
    pub(crate) fn wrap(state: ControlState) -> Arc<Self> {
        Arc::new(ControlStateHandle { state })
    }
}

impl std::fmt::Debug for ControlStateHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlStateHandle").finish_non_exhaustive()
    }
}

/// What `ControlStateHandle::apply` gives: the record's results and the
/// state after it.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ControlTransition {
    /// What the record did, and what the host does with it.
    pub applied: ControlApplied,
    /// The state after the record. Store `next.to_json()` (or the parts
    /// of `touched`) in the transaction that acts on `applied`, and use
    /// `next` once it committed. Until then, and if it fails, the handle
    /// `apply` was called on is the current state: it didn't change.
    pub next: Arc<ControlStateHandle>,
    /// The principals whose part `next` changed: the record's principal,
    /// or none. Write exactly these `next.part(…)`s.
    pub touched: Vec<String>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl ControlStateHandle {
    /// The empty control state of `log`'s device list (its account and
    /// genesis): for a device list that has none yet. Re-pairing (a new
    /// genesis) starts a new one.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(log: Arc<MembershipLog>) -> Arc<Self> {
        Self::wrap(ControlState::new(&log.lock()))
    }

    /// A state `to_json()` wrote, for `log`'s device list. `Stored{code}`:
    /// `too_large` (over 64 MiB), `malformed` (not strict JSON, not an
    /// object, no `v`), `unsupported_version` (a `v` other than 2: 1 is the
    /// format before parts per principal),
    /// `account_mismatch`, `genesis_mismatch` (another device list's state),
    /// `stored_invalid` (the state's own rules refuse it, or it isn't
    /// exactly `to_json()`'s form). Nothing is loaded then. A
    /// `genesis_mismatch` after a re-pair (the stored state is the old
    /// device list's) means the new list starts with `new`; on any other
    /// error keep the work it guards stopped and never start again from an
    /// empty state.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_json(log: Arc<MembershipLog>, state_json: String) -> Result<Arc<Self>> {
        if state_json.len() > MAX_CONTROL_STATE_JSON {
            return Err(AtemError::stored(
                "too_large",
                format!("a control state is at most {MAX_CONTROL_STATE_JSON} bytes"),
            ));
        }
        let value = parse_strict(
            state_json.as_bytes(),
            MAX_CONTROL_STATE_JSON,
            Numbers::IntegersOnly,
        )
        .map_err(|e| AtemError::stored("malformed", format!("not strict JSON: {e:?}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| AtemError::stored("malformed", "not an object"))?;
        match object.get("v").map(Value::as_u64) {
            None => return Err(AtemError::stored("malformed", "no state version `v`")),
            Some(Some(STATE_VERSION)) => {}
            Some(_) => {
                return Err(AtemError::stored(
                    "unsupported_version",
                    format!("this binding reads control state version {STATE_VERSION}"),
                ));
            }
        }
        {
            let list = log.lock();
            if object.get("account_id").and_then(Value::as_str) != Some(list.account_id()) {
                return Err(AtemError::stored(
                    "account_mismatch",
                    "the state is of another account",
                ));
            }
            let genesis = object
                .get("genesis_hash")
                .and_then(Value::as_str)
                .and_then(|h| Hash32::from_hex(h).ok());
            if genesis != Some(list.genesis_hash()) {
                return Err(AtemError::stored(
                    "genesis_mismatch",
                    "the state is of another device list",
                ));
            }
        }
        let state = ControlState::from_json(&value)
            .map_err(|e| AtemError::stored("stored_invalid", e.to_string()))?;
        // Exactly the export: another spelling of the state is refused.
        let exact = match (canonical(&state.to_json()), canonical(&value)) {
            (Ok(ours), Ok(theirs)) => ours == theirs,
            _ => false,
        };
        if !exact {
            return Err(AtemError::stored(
                "stored_invalid",
                "the state isn't exactly to_json()'s form",
            ));
        }
        Ok(Self::wrap(state))
    }

    /// The state of `log`'s device list made of `parts` (each principal's
    /// `part`, in any order), read as `from_json` reads a whole state.
    /// Every part names its device list. `Stored{code}`: `too_large` (over
    /// 64 MiB in all), `malformed` (a part that isn't strict JSON or not an
    /// object), `account_mismatch`, `genesis_mismatch` (a part of another
    /// device list: after a re-pair, start the new list with `new` and
    /// clear the old parts; a recurring service id then inherits nothing),
    /// `stored_invalid` (a principal given twice, a name that is no
    /// principal, a part its rules refuse or not exactly `part()`'s form).
    /// Nothing is loaded then; on any code but `genesis_mismatch` keep the
    /// work it guards stopped.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_parts(log: Arc<MembershipLog>, parts: Vec<ControlStatePart>) -> Result<Arc<Self>> {
        let total: usize = parts
            .iter()
            .map(|p| p.principal.len() + p.part_json.len())
            .sum();
        if total > MAX_CONTROL_STATE_JSON {
            return Err(AtemError::stored(
                "too_large",
                format!(
                    "a control state's parts are at most {MAX_CONTROL_STATE_JSON} bytes in all"
                ),
            ));
        }
        let mut values = Vec::with_capacity(parts.len());
        for part in parts {
            let value = parse_strict(
                part.part_json.as_bytes(),
                MAX_CONTROL_STATE_JSON,
                Numbers::IntegersOnly,
            )
            .map_err(|e| {
                AtemError::stored(
                    "malformed",
                    format!("{}'s part: not strict JSON: {e:?}", part.principal),
                )
            })?;
            values.push((part.principal, value));
        }
        let list = log.lock();
        // Each part of this device list, named as `from_json` names it.
        for (principal, value) in &values {
            let object = value.as_object().ok_or_else(|| {
                AtemError::stored("malformed", format!("{principal}'s part: not an object"))
            })?;
            if object.get("account_id").and_then(Value::as_str) != Some(list.account_id()) {
                return Err(AtemError::stored(
                    "account_mismatch",
                    format!("{principal}'s part is of another account"),
                ));
            }
            let genesis = object
                .get("genesis_hash")
                .and_then(Value::as_str)
                .and_then(|h| Hash32::from_hex(h).ok());
            if genesis != Some(list.genesis_hash()) {
                return Err(AtemError::stored(
                    "genesis_mismatch",
                    format!("{principal}'s part is of another device list"),
                ));
            }
        }
        let state = ControlState::from_parts(&list, values.iter().cloned())
            .map_err(|e| AtemError::stored("stored_invalid", e.to_string()))?;
        drop(list);
        // Exactly the export: another spelling of a part is refused.
        for (principal, value) in &values {
            let exact = match (
                state.part(principal).map(|p| canonical(&p)),
                canonical(value),
            ) {
                (Some(Ok(ours)), Ok(theirs)) => ours == theirs,
                _ => false,
            };
            if !exact {
                return Err(AtemError::stored(
                    "stored_invalid",
                    format!("{principal}'s part isn't exactly part()'s form"),
                ));
            }
        }
        Ok(Self::wrap(state))
    }

    /// The durable state: canonical JSON (`"v": 2`, one part per
    /// principal). Store the next state's after every `apply` (or its
    /// touched parts), in the same transaction as what you do with the
    /// result.
    pub fn to_json(&self) -> String {
        canonical_lossy(&self.state.to_json())
    }

    /// Every principal the state has a part for (one a record counted for),
    /// sorted.
    pub fn principals(&self) -> Vec<String> {
        self.state.principals()
    }

    /// `principal`'s part (`service:<id>`, `host:<host_id>`), canonical
    /// JSON, or `None` when the state has none: what a store keeping one
    /// row per principal writes for each principal a transition `touched`.
    pub fn part(&self, principal: String) -> Option<String> {
        self.state
            .part(&principal)
            .map(|part| canonical_lossy(&part))
    }

    /// What is in force for `principal` (`service:<id>`, `host:<host_id>`):
    /// its revocation, the revocations whose interrupt is in force, the
    /// hold and the covering feed. A principal the state holds nothing for
    /// (or a name that is none) has nothing in force.
    pub fn standing(&self, principal: String) -> ControlStanding {
        let standing = self.state.standing(&principal);
        ControlStanding {
            revoked: standing.revoked,
            interrupted: standing.interrupted.into_iter().collect(),
            held: standing.held,
            coverage: standing.coverage.map(|c| ControlCoverage {
                origin: c.origin,
                feed_id: c.feed_id,
            }),
        }
    }

    /// Verifies `record_json` against `log` (the device list at the head
    /// of this transaction) and applies it to this state: each effect's
    /// result, what the host does, and whether to keep the record as
    /// evidence, with the next state (`ControlTransition`). This handle
    /// doesn't change. `pos` is where it was read: a feed the caller syncs
    /// (`None` over a channel). A record whose body names another `origin`
    /// or `feed_id` than `pos` counts as read at no position: its hold
    /// still applies, its cover and release don't. `host_applied_seq` is
    /// host-work's applied device-list `seq` (a host principal's interrupt
    /// waits for it). A list of another account or genesis applies nothing
    /// (`refused`, no evidence); a frozen one applies nothing new
    /// (`pending`).
    ///
    /// Read `effects`, not only `result`: for the revocation, `duplicate`
    /// means "already in force on this host" and counts as done. Errors: a
    /// record its parse refuses is `Invalid{code}` (keep it as evidence);
    /// a `feed_seq` above 2^53 − 1 is `Invalid{not_canonical}`.
    pub fn apply(
        &self,
        record_json: String,
        log: Arc<MembershipLog>,
        pos: Option<ControlFeedPos>,
        host_applied_seq: u64,
    ) -> Result<ControlTransition> {
        let rec = record(&record_json)?;
        let pos = match pos {
            Some(pos) => Some(FeedPos {
                feed_seq: safe_int(pos.feed_seq, "feed_seq")?,
                origin: pos.origin,
                feed_id: pos.feed_id,
            }),
            None => None,
        };
        let transition = self.state.apply(&rec, &log.lock(), pos, host_applied_seq);
        Ok(ControlTransition {
            touched: transition.touched(),
            applied: applied_info(transition.applied),
            next: Self::wrap(transition.next),
        })
    }
}

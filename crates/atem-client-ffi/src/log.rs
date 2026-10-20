//! The membership log (§R9.2–§R9.5) as one object. The app stores the
//! entries (`entries()`, canonical JSON, in order) and rebuilds the object
//! with `verify` at start; nothing else needs storing for a client (the
//! host's head is authoritative, §6 "storage policy").
//!
//! Mutating calls (`extend`, `advance`, a publisher's reply) change the
//! object in place, so every holder sees the new state; `snapshot` copies.
use std::sync::{Arc, Mutex, MutexGuard};

use atem_client::SignedObject;
use atem_client::channel::HeadRelation;
use atem_client::encoding::b64u;
use atem_client::membership::{
    Action, Conflict, Effect, Entry, Evaluation, Head, HostNow, Invalid, Member, MemberKind,
    MemberStatus, Membership, Stop,
};

use crate::encoding::{canonical, canonical_lossy, hash_of, safe_int, signed, strict};
use crate::error::{AtemError, Result};
use crate::types::{
    CarriageResult, CarriageStop, FreezeInfo, HeadRelationKind, HostClock, HostInfo, KBackupInfo,
    LogHead, MemberInfo, MemberStatusKind, MembershipEffect, PendingRecoveryInfo,
};

impl From<&HostClock> for HostNow {
    fn from(c: &HostClock) -> Self {
        HostNow {
            wall_ms: c.wall_ms,
            mono_ms: c.mono_ms,
            boot_id: c.boot_id.clone(),
        }
    }
}

impl From<Head> for LogHead {
    fn from(h: Head) -> Self {
        LogHead {
            seq: h.seq,
            hash: h.hash.to_hex(),
        }
    }
}

impl LogHead {
    pub(crate) fn to_head(&self) -> Result<Head> {
        if self.seq == 0 {
            return Err(AtemError::malformed("a head's seq is at least 1"));
        }
        Ok(Head {
            seq: self.seq,
            hash: hash_of(&self.hash)?,
        })
    }
}

pub(crate) fn entries_of(json: &[String]) -> Result<Vec<Entry>> {
    json.iter()
        .enumerate()
        .map(|(i, text)| {
            let object = signed(text).map_err(|e| match e {
                AtemError::Invalid { code, detail } => AtemError::Membership {
                    code,
                    detail,
                    index: Some(i as u64),
                },
                other => other,
            })?;
            Entry::parse(object).map_err(|reason| AtemError::membership(&reason, Some(i)))
        })
        .collect()
}

pub(crate) fn objects_of(json: &[String]) -> Result<Vec<SignedObject>> {
    json.iter().map(|t| signed(t)).collect()
}

pub(crate) fn object_json(object: &SignedObject) -> String {
    canonical_lossy(&object.to_json())
}

fn member_info(member: &Member, status: MemberStatus) -> MemberInfo {
    let (kind, roles, enc_key, scope_json, expires_at) = match &member.kind {
        MemberKind::Native { enc_key, roles } => (
            "native",
            roles.iter().map(|r| r.as_str().to_owned()).collect(),
            Some(enc_key.into()),
            None,
            None,
        ),
        MemberKind::Service { scope, expires_at } => (
            "service",
            vec!["service".to_owned()],
            None,
            Some(canonical_lossy(&scope.to_json())),
            Some(*expires_at),
        ),
    };
    let (status, pending_entry_hash) = match status {
        MemberStatus::Active => (MemberStatusKind::Active, None),
        MemberStatus::Pending { entry_hash } => {
            (MemberStatusKind::Pending, Some(entry_hash.to_hex()))
        }
        MemberStatus::Cancelled => (MemberStatusKind::Cancelled, None),
        MemberStatus::Removed => (MemberStatusKind::Removed, None),
    };
    MemberInfo {
        device_id: member.device_id.clone(),
        kind: kind.into(),
        roles,
        status,
        pending_entry_hash,
        auth_key: (&member.auth_key).into(),
        enc_key,
        scope_json,
        expires_at,
        member_json: canonical_lossy(&member.to_json()),
    }
}

pub(crate) fn effect_info(effect: &Effect) -> MembershipEffect {
    match effect {
        Effect::Appended(h) => MembershipEffect::Appended { head: (*h).into() },
        Effect::MemberAdded { device_id } => MembershipEffect::MemberAdded {
            device_id: device_id.clone(),
        },
        Effect::MemberRemoved { device_id } => MembershipEffect::MemberRemoved {
            device_id: device_id.clone(),
        },
        Effect::RolesChanged { device_id } => MembershipEffect::RolesChanged {
            device_id: device_id.clone(),
        },
        Effect::HostKeyChanged { host_id } => MembershipEffect::HostKeyChanged {
            host_id: host_id.clone(),
        },
        Effect::HostRemoved { host_id } => MembershipEffect::HostRemoved {
            host_id: host_id.clone(),
        },
        Effect::RecoveryPending { entry_hash } => MembershipEffect::RecoveryPending {
            entry_hash: entry_hash.to_hex(),
        },
        Effect::RecoveryActive { entry_hash, reason } => MembershipEffect::RecoveryActive {
            entry_hash: entry_hash.to_hex(),
            reason: reason.as_str().into(),
        },
        Effect::RecoveryCancelled { entry_hash, reason } => MembershipEffect::RecoveryCancelled {
            entry_hash: entry_hash.to_hex(),
            reason: reason.as_str().into(),
        },
        Effect::RecoveryKeyReplaced => MembershipEffect::RecoveryKeyReplaced,
        Effect::KBackupRecorded { blob_version } => MembershipEffect::KBackupRecorded {
            blob_version: *blob_version,
        },
        Effect::VetoReplaced(h) => MembershipEffect::VetoReplaced { head: (*h).into() },
        Effect::Evidence(reason) => MembershipEffect::Evidence {
            reason: reason.as_str().into(),
        },
        Effect::Frozen => MembershipEffect::Frozen,
    }
}

pub(crate) fn stop_info(stop: &Stop) -> CarriageStop {
    match stop {
        Stop::Frozen => CarriageStop::Frozen,
        Stop::Invalid { index, reason } => CarriageStop::Invalid {
            index: *index as u64,
            code: reason.code().into(),
        },
        Stop::NeedBefore { index, seq } => CarriageStop::NeedBefore {
            index: *index as u64,
            seq: *seq,
        },
        Stop::Deferred { index, on } => CarriageStop::Deferred {
            index: *index as u64,
            on: on.to_hex(),
        },
        Stop::Conflict { index, outcome } => CarriageStop::Conflict {
            index: *index as u64,
            outcome: match outcome {
                Conflict::Freeze => "freeze".into(),
                Conflict::Ignored(reason) => format!("ignored:{}", reason.as_str()),
                Conflict::ReplacedVeto => "replaced_veto".into(),
            },
        },
    }
}

fn carriage_result(eval: &Evaluation, committed: bool) -> CarriageResult {
    CarriageResult {
        appended: eval.appended as u64,
        head: eval.next.head().into(),
        stop: eval.stop.as_ref().map(stop_info),
        effects: eval.effects.iter().map(effect_info).collect(),
        committed,
    }
}

/// A structural check of an unsigned body with the verifier's own parser
/// (the signature is checked against the chain later): so the owner is
/// only asked to confirm a body the verifier would accept.
pub(crate) fn structural_entry(body: &serde_json::Value) -> std::result::Result<Entry, Invalid> {
    let zero = b64u(&[0u8; 64]);
    let mut object = serde_json::json!({"body": body, "sig": zero});
    if body["action"] == "set_recovery_key" && body["kit"] == "current" {
        object["kit_sig"] = serde_json::json!(zero);
    }
    let object = SignedObject::parse(
        canonical(&object)
            .map_err(|_| Invalid::Malformed("outside the canonical domain"))?
            .as_bytes(),
    )?;
    Entry::parse(object)
}

/// A verified membership log.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct MembershipLog {
    inner: Mutex<Membership>,
}

impl MembershipLog {
    pub(crate) fn wrap(log: Membership) -> Arc<Self> {
        Arc::new(MembershipLog {
            inner: Mutex::new(log),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Membership> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The member object of `member_json`, checked by the verifier's own
    /// schema (wrapped in an `add` after this log's head).
    pub(crate) fn parse_member(&self, member_json: &str) -> Result<Member> {
        let member = strict(member_json)?;
        let mut body = self.draft_value("member-check", 0, &member_action(member))?;
        body["signer"] = serde_json::json!("member-check");
        match structural_entry(&body)?.action {
            Action::Add { member } => Ok(member),
            _ => Err(AtemError::malformed("member")),
        }
    }

    fn draft_value(
        &self,
        signer: &str,
        signed_at: u64,
        action: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let fields = action
            .as_object()
            .ok_or(AtemError::malformed("the action is a JSON object"))?;
        if !fields.get("action").is_some_and(|a| a.is_string()) {
            return Err(AtemError::malformed("the action names its `action`"));
        }
        // The common fields come from the crate's own drafter.
        let mut body = self.lock().draft(
            signer,
            signed_at,
            &Action::Remove {
                device_id: String::new(),
            },
        );
        let object = body.as_object_mut().expect("a draft is an object");
        object.remove("device_id");
        for (k, v) in fields {
            if matches!(
                k.as_str(),
                "type"
                    | "v"
                    | "account_id"
                    | "genesis_hash"
                    | "seq"
                    | "prev_hash"
                    | "signer"
                    | "signed_at"
            ) {
                return Err(AtemError::malformed("the action can't set common fields"));
            }
            object.insert(k.clone(), v.clone());
        }
        Ok(body)
    }
}

fn member_action(member: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"action": "add", "member": member})
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl MembershipLog {
    /// Verifies a whole chain from its genesis (`genesis_hash` the anchor
    /// the app holds: the kit's or the pairing's). Entries after one that
    /// depends on a still-pending entry are left out (see `deferred`).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn verify(
        account_id: String,
        genesis_hash: String,
        entries: Vec<String>,
        now: HostClock,
    ) -> Result<Arc<Self>> {
        let entries = entries_of(&entries)?;
        let verified = Membership::verify_chain(
            &account_id,
            &hash_of(&genesis_hash)?,
            &entries,
            &(&now).into(),
        )
        .map_err(|e| AtemError::membership(&e.reason, Some(e.index)))?;
        Ok(Self::wrap(verified.membership))
    }

    /// A copy (later changes to either don't affect the other).
    pub fn snapshot(&self) -> Arc<Self> {
        Self::wrap(self.lock().clone())
    }

    pub fn account_id(&self) -> String {
        self.lock().account_id().into()
    }

    pub fn genesis_hash(&self) -> String {
        self.lock().genesis_hash().to_hex()
    }

    pub fn head(&self) -> LogHead {
        self.lock().head().into()
    }

    /// The entries in order (canonical JSON): what the app stores.
    pub fn entries(&self) -> Vec<String> {
        self.lock()
            .entries()
            .iter()
            .map(|e| object_json(e.object()))
            .collect()
    }

    /// Entries after `seq` (a carriage, a fetch answer).
    pub fn entries_after(&self, seq: u64) -> Vec<String> {
        self.lock()
            .entries()
            .iter()
            .filter(|e| e.seq > seq)
            .map(|e| object_json(e.object()))
            .collect()
    }

    /// Members in effect (removed and cancelled ones are left out; `member`
    /// still answers for them).
    pub fn members(&self) -> Vec<MemberInfo> {
        let log = self.lock();
        log.members()
            .into_iter()
            .filter_map(|id| log.member(id))
            .map(|m| member_info(&m.member, m.status))
            .collect()
    }

    pub fn member(&self, device_id: String) -> Option<MemberInfo> {
        self.lock()
            .member(&device_id)
            .map(|m| member_info(&m.member, m.status))
    }

    /// A host current in the log (its newest `add_host`).
    pub fn host(&self, host_id: String) -> Option<HostInfo> {
        self.lock().host(&host_id).map(|h| HostInfo {
            host_id: h.host_id.clone(),
            host_trust_gen: h.host_trust_gen,
            host_key: (&h.host_key).into(),
        })
    }

    pub fn recovery_key(&self) -> crate::types::PublicKeyData {
        self.lock().recovery_key().into()
    }

    pub fn k_backup(&self) -> Option<KBackupInfo> {
        self.lock().k_backup().map(|k| KBackupInfo {
            blob_version: k.blob_version,
            kids: k.kids.clone(),
            recovery_key: (&k.recovery_key).into(),
            backup_hash: k.backup_hash.to_hex(),
        })
    }

    pub fn frozen(&self) -> Option<FreezeInfo> {
        self.lock().frozen().map(|f| FreezeInfo {
            seq: f.seq,
            ours_json: object_json(&f.ours),
            theirs_json: object_json(&f.theirs),
            at: f.at,
        })
    }

    /// Pending recovery entries, with when they take effect on this clock.
    pub fn pending_recovery(&self, now: HostClock) -> Vec<PendingRecoveryInfo> {
        self.lock()
            .pending_recovery(&(&now).into())
            .into_iter()
            .map(|p| PendingRecoveryInfo {
                entry_hash: p.entry_hash.to_hex(),
                seq: p.seq,
                action: p.action.into(),
                subject: p.subject,
                effective_at: p.effective_at,
            })
            .collect()
    }

    /// How a head another party signed relates to this log.
    pub fn relation(&self, head: LogHead) -> Result<HeadRelationKind> {
        let head = head.to_head()?;
        Ok(match HeadRelation::of(&self.lock(), head) {
            HeadRelation::Same => HeadRelationKind::Same,
            HeadRelation::HostBehind => HeadRelationKind::HostBehind,
            HeadRelation::HostAhead => HeadRelationKind::HostAhead,
            HeadRelation::Diverged => HeadRelationKind::Diverged,
        })
    }

    /// Evaluates entries (fetched from the relay, or carried) without
    /// changing this log: the §R9.3 carriage algorithm and §R9.4 conflict
    /// rows.
    pub fn evaluate(&self, entries: Vec<String>, now: HostClock) -> Result<CarriageResult> {
        let objects = objects_of(&entries)?;
        let eval = self.lock().evaluate_objects(&objects, &(&now).into());
        Ok(carriage_result(&eval, false))
    }

    /// Evaluates entries and keeps the result: the valid prefix, ended
    /// waits, evidence or a freeze (a client extending its log with a fetch
    /// from the relay). Check `stop`: entries after it were not applied.
    pub fn extend(&self, entries: Vec<String>, now: HostClock) -> Result<CarriageResult> {
        let objects = objects_of(&entries)?;
        let mut log = self.lock();
        let eval = log.evaluate_objects(&objects, &(&now).into());
        let result = carriage_result(&eval, true);
        *log = eval.next;
        Ok(result)
    }

    /// Ends waits that are over on this clock (pending recoveries).
    pub fn advance(&self, now: HostClock) -> Vec<MembershipEffect> {
        self.lock()
            .advance(&(&now).into())
            .iter()
            .map(effect_info)
            .collect()
    }

    /// The body of the next entry after this head, signed by `signer`:
    /// `action_json` is the action and its own fields, e.g.
    /// `{"action":"remove","device_id":"dev-ipad"}` or `{"action":"add",
    /// "member":{…}}`. Checked by the verifier's schema before it is
    /// returned, so the owner only confirms a body the verifier accepts.
    /// Returns canonical JSON: show it, then prepare it with an
    /// `EntryPublisher`.
    pub fn draft_entry(
        &self,
        signer: String,
        signed_at: u64,
        action_json: String,
    ) -> Result<String> {
        let action = strict(&action_json)?;
        let body = self.draft_value(&signer, safe_int(signed_at, "signed_at")?, &action)?;
        structural_entry(&body)?;
        canonical(&body)
    }

    /// Checks a member object (`add`/`recovery_add`'s `member`) with the
    /// verifier's schema; returns it in canonical JSON.
    pub fn check_member(&self, member_json: String) -> Result<String> {
        canonical(&self.parse_member(&member_json)?.to_json())
    }
}

#[cfg(feature = "host")]
use crate::types::AdmissionInfo;

#[cfg(feature = "host")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl MembershipLog {
    /// Host role (feature `host`, never in an app build): the membership
    /// side of admitting `device_id` after its carriage (`more`: the hello
    /// said more entries follow); commits the evaluation like `extend`.
    pub fn admit_carrier(
        &self,
        device_id: String,
        entries: Vec<String>,
        more: bool,
        now: HostClock,
    ) -> Result<AdmissionInfo> {
        use atem_client::membership::Admission;
        let objects = objects_of(&entries)?;
        let now: HostNow = (&now).into();
        let mut log = self.lock();
        let eval = log.evaluate_objects(&objects, &now);
        let admission = eval.admission(&device_id, more, &now);
        *log = eval.next;
        Ok(match admission {
            Admission::Frozen => AdmissionInfo::Frozen,
            Admission::Invalid {
                head,
                index,
                reason,
                need_before,
            } => AdmissionInfo::Invalid {
                head: head.into(),
                index: index as u64,
                code: reason.code().into(),
                need_before,
            },
            Admission::Incomplete { head } => AdmissionInfo::Incomplete { head: head.into() },
            Admission::RecoveryPending {
                entry_hash,
                effective_at,
            } => AdmissionInfo::RecoveryPending {
                entry_hash: entry_hash.to_hex(),
                effective_at,
            },
            Admission::Unauthorized(detail) => AdmissionInfo::Unauthorized {
                detail: detail.into(),
            },
            Admission::Member { head, state } => AdmissionInfo::Member {
                head: head.into(),
                device_id: state.member.device_id,
            },
        })
    }
}

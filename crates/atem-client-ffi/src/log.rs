//! The membership log (§R9.2–§R9.5) as one object. The app stores its
//! durable snapshot (`stored_json()`: the entries, the recovery records with
//! their wait clocks and decisions, evidence and a freeze; the same form
//! the host keeps in `membership.json`) after every change, and rebuilds the
//! object with `from_stored` at start, against the anchors it holds. `verify`
//! from the entries alone starts every pending wait again and loses where
//! wait-ended decisions took effect.
//!
//! Mutating calls (`extend`, `advance`, a publisher's reply) change the
//! object in place, so every holder sees the new state; `snapshot` copies.
use std::sync::{Arc, Mutex, MutexGuard};

use atem_client::SignedObject;
use atem_client::canonical::{Numbers, parse_strict};
use atem_client::channel::HeadRelation;
use atem_client::encoding::{Hash32, b64u};
use atem_client::membership::{
    Action, CapacityLevel, ChangeRefusal, Conflict, Effect, Entry, Evaluation, Head, HostNow,
    Invalid, Member, MemberKind, MemberStatus, Membership, Stop,
};

use crate::encoding::{MAX_SAFE, canonical, canonical_lossy, hash_of, safe_int, signed, strict};
use crate::error::{AtemError, Result};
use crate::types::{
    CapacityInfo, CapacityLevelKind, CarriageResult, CarriageStop, ChangeRefusalInfo, FreezeInfo,
    HeadRelationKind, HostClock, HostInfo, KBackupInfo, LogHead, MemberInfo, MemberStatusKind,
    MembershipEffect, PendingRecoveryInfo,
};

/// Largest durable snapshot `MembershipLog::from_stored` reads: the host's
/// own bound on `membership.json` (`src/session_protocol/membership/store.rs`
/// `MAX_FILE`, 16 MiB: a full log of 1024 entries with bodies ≤ 4 KiB, plus
/// recovery records and evidence). Checked before parsing.
pub const MAX_STORED_JSON: usize = 16 << 20;

/// The snapshot format `stored_json` writes (`"v"`). A later binding reads
/// every earlier version (migrating it) and refuses only versions newer
/// than its own (`Stored{unsupported_version}`).
pub const STORED_VERSION: u64 = 1;

impl HostClock {
    /// The reading as the core takes it. Both times are milliseconds and at
    /// most 2^53 − 1 (the JSON integer domain the durable snapshot is
    /// written in): anything above, e.g. nanoseconds passed by mistake, is
    /// refused here rather than making the log unexportable later.
    pub(crate) fn host_now(&self) -> Result<HostNow> {
        if self.wall_ms > MAX_SAFE || self.mono_ms > MAX_SAFE {
            return Err(AtemError::malformed(
                "a HostClock time is milliseconds, at most 2^53 - 1",
            ));
        }
        Ok(HostNow {
            wall_ms: self.wall_ms,
            mono_ms: self.mono_ms,
            boot_id: self.boot_id.clone(),
        })
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

fn level_kind(level: CapacityLevel) -> CapacityLevelKind {
    match level {
        CapacityLevel::Ok => CapacityLevelKind::Ok,
        CapacityLevel::NearlyFull => CapacityLevelKind::NearlyFull,
        CapacityLevel::Full => CapacityLevelKind::Full,
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
            &now.host_now()?,
        )
        .map_err(|e| AtemError::membership(&e.reason, Some(e.index)))?;
        Ok(Self::wrap(verified.membership))
    }

    /// Rebuilds a log from its durable snapshot (`stored_json()`), checked
    /// against the anchors the app holds (`account_id`, and `genesis_hash`
    /// from the pairing or the kit), never against the snapshot's own: the
    /// shared verifier replays the chain with the recorded decisions at
    /// their positions, checks one recovery record per pending-type entry,
    /// the head, recovery keys and a freeze (`Membership::from_stored_client`:
    /// the host's checks on `membership.json`, plus the restore-only
    /// `host_confirmed` decision a kit restore records). The snapshot must
    /// be exactly what `stored_json()` writes for its version `v`: any other
    /// field, a missing record or a changed value is refused. Errors:
    /// `Stored{code}` (`too_large`, `malformed`, `unsupported_version`,
    /// `account_mismatch`, `genesis_mismatch`, `stored_invalid`); a
    /// malformed anchor or clock is `Invalid`.
    ///
    /// `now` is this run's first reading of the verifier clock, taken as the
    /// host takes one at start: on the same boot every wait goes on from
    /// first sight, on another boot from the time last persisted (time
    /// while the machine was off, or not persisted, never counts). Nothing
    /// in the snapshot, `signed_at` or any relay time counts as time
    /// waited. Export once right after loading. Restoring grants nothing:
    /// it is a verified log, like `verify`'s.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_stored(
        account_id: String,
        genesis_hash: String,
        stored_json: String,
        now: HostClock,
    ) -> Result<Arc<Self>> {
        let genesis = hash_of(&genesis_hash)?;
        let now = now.host_now()?;
        if stored_json.len() > MAX_STORED_JSON {
            return Err(AtemError::stored(
                "too_large",
                format!("a snapshot is at most {MAX_STORED_JSON} bytes"),
            ));
        }
        let mut value = parse_strict(
            stored_json.as_bytes(),
            MAX_STORED_JSON,
            Numbers::IntegersOnly,
        )
        .map_err(|e| AtemError::stored("malformed", format!("not strict JSON: {e:?}")))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| AtemError::stored("malformed", "not an object"))?;
        // The version first: a later format is never read as this one.
        match object.remove("v").map(|v| v.as_u64()) {
            None => return Err(AtemError::stored("malformed", "no snapshot version `v`")),
            Some(Some(STORED_VERSION)) => {}
            Some(_) => {
                return Err(AtemError::stored(
                    "unsupported_version",
                    format!("this binding reads snapshot version {STORED_VERSION}"),
                ));
            }
        }
        match object.get("account_id").and_then(|v| v.as_str()) {
            None => return Err(AtemError::stored("malformed", "account_id")),
            Some(a) if a != account_id => {
                return Err(AtemError::stored(
                    "account_mismatch",
                    "the snapshot is of another account",
                ));
            }
            Some(_) => {}
        }
        match object
            .get("genesis_hash")
            .and_then(|v| v.as_str())
            .and_then(|h| Hash32::from_hex(h).ok())
        {
            None => return Err(AtemError::stored("malformed", "genesis_hash")),
            Some(h) if h != genesis => {
                return Err(AtemError::stored(
                    "genesis_mismatch",
                    "the snapshot is of another genesis",
                ));
            }
            Some(_) => {}
        }
        let mut log = Membership::from_stored_client(&account_id, &genesis, &value)
            .map_err(|e| AtemError::stored("stored_invalid", e.0))?;
        // Exactly the export: a field `to_stored` doesn't write (which
        // `from_stored` would ignore, as it ignores the host's own) or any
        // other spelling of the state is refused.
        let exact = match (canonical(&log.to_stored()), canonical(&value)) {
            (Ok(ours), Ok(theirs)) => ours == theirs,
            _ => false,
        };
        if !exact {
            return Err(AtemError::stored(
                "stored_invalid",
                "the snapshot holds more than the log's durable state",
            ));
        }
        log.checkpoint(&now);
        Ok(Self::wrap(log))
    }

    /// The durable snapshot (canonical JSON, `"v": 1`): the entries, the
    /// recovery records with their wait clocks and decisions, evidence and
    /// a freeze. Commit it durably after every change (`advance(now)`, then
    /// export, then commit, then act on the effects), and once right after
    /// `from_stored`; reload it with `from_stored`. Taking it records no
    /// clock reading: only `advance`/`extend` do.
    pub fn stored_json(&self) -> Result<String> {
        let mut value = self.lock().to_stored();
        value
            .as_object_mut()
            .expect("the stored form is an object")
            .insert("v".into(), serde_json::json!(STORED_VERSION));
        canonical(&value)
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
    pub fn pending_recovery(&self, now: HostClock) -> Result<Vec<PendingRecoveryInfo>> {
        let now = now.host_now()?;
        Ok(self
            .lock()
            .pending_recovery(&now)
            .into_iter()
            .map(|p| PendingRecoveryInfo {
                entry_hash: p.entry_hash.to_hex(),
                seq: p.seq,
                action: p.action.into(),
                subject: p.subject,
                effective_at: p.effective_at,
            })
            .collect())
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
        let eval = self.lock().evaluate_objects(&objects, &now.host_now()?);
        Ok(carriage_result(&eval, false))
    }

    /// Evaluates entries and keeps the result: the valid prefix, ended
    /// waits, evidence or a freeze (a client extending its log with a fetch
    /// from the relay). Check `stop`: entries after it were not applied.
    pub fn extend(&self, entries: Vec<String>, now: HostClock) -> Result<CarriageResult> {
        let objects = objects_of(&entries)?;
        let mut log = self.lock();
        let eval = log.evaluate_objects(&objects, &now.host_now()?);
        let result = carriage_result(&eval, true);
        *log = eval.next;
        Ok(result)
    }

    /// Ends waits that are over on this clock (pending recoveries).
    pub fn advance(&self, now: HostClock) -> Result<Vec<MembershipEffect>> {
        let now = now.host_now()?;
        Ok(self.lock().advance(&now).iter().map(effect_info).collect())
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

    /// How full the log is (D23): entries, members and hosts against the
    /// verifier's limits (1024, 256, 64), nearly full from 90 %. Show a warning
    /// from `nearly_full`: renewals use one entry each, and a full log
    /// needs re-pairing.
    pub fn capacity(&self) -> CapacityInfo {
        let c = self.lock().capacity();
        CapacityInfo {
            entries: c.entries,
            max_entries: c.max_entries,
            members: c.members,
            max_members: c.max_members,
            hosts: c.hosts,
            max_hosts: c.max_hosts,
            level: level_kind(c.level),
            entries_level: level_kind(c.entries_level()),
            members_level: level_kind(c.members_level()),
            hosts_level: level_kind(c.hosts_level()),
        }
    }

    /// Whether to draft `action_json` (as `draft_entry` takes it) as the
    /// next entry at `now_ms` (the time it would be signed): `None` to go
    /// ahead, else why not (`LogFull`, `MembersFull`, `HostsFull`, or `ServiceChangeTooSoon` for a
    /// service change that grants anything new, e.g. a renewal, within
    /// 24 h of that service's last entry; narrowing and `remove` are never
    /// paced). Advisory, for signers only: hosts accept any valid entry.
    /// A malformed action is `Invalid`/`Membership` as in `draft_entry`.
    pub fn check_change(
        &self,
        action_json: String,
        now_ms: u64,
    ) -> Result<Option<ChangeRefusalInfo>> {
        let action = strict(&action_json)?;
        // A placeholder signer: who signs isn't judged here.
        let signer = match action["action"].as_str() {
            Some("recovery_add") => atem_client::membership::RECOVERY_SIGNER,
            _ => "change-check",
        };
        let body = self.draft_value(signer, safe_int(now_ms, "now_ms")?, &action)?;
        let entry = structural_entry(&body)?;
        let log = self.lock();
        Ok(
            match atem_client::membership::check_change(&log, &entry.action, now_ms) {
                Ok(()) => None,
                Err(ChangeRefusal::LogFull) => Some(ChangeRefusalInfo::LogFull),
                Err(ChangeRefusal::MembersFull) => Some(ChangeRefusalInfo::MembersFull),
                Err(ChangeRefusal::HostsFull) => Some(ChangeRefusalInfo::HostsFull),
                Err(ChangeRefusal::ServiceChangeTooSoon {
                    last_signed_at,
                    retry_at,
                }) => Some(ChangeRefusalInfo::ServiceChangeTooSoon {
                    last_signed_at,
                    retry_at,
                }),
            },
        )
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
        let now: HostNow = now.host_now()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChangeRefusalInfo;
    use atem_client::membership::{Role, RolesChange};

    /// The shared log L (six entries).
    fn log_l() -> (Arc<MembershipLog>, HostClock) {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../designs/protocol/fixtures/r9-vectors-membership-log.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let entries = v["log"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["entry"].to_string())
            .collect();
        let now = HostClock {
            wall_ms: 1_793_264_001_000,
            mono_ms: 1000,
            boot_id: "boot-1".into(),
        };
        let log = MembershipLog::verify(
            v["account_id"].as_str().unwrap().into(),
            v["genesis_hash"].as_str().unwrap().into(),
            entries,
            now.clone(),
        )
        .unwrap();
        (log, now)
    }

    /// A full log is `LogFull` from `check_change`, never a
    /// `membership_invalid` of the draft at seq 1025.
    #[test]
    fn a_full_log_is_log_full_not_an_invalid_draft() {
        let (log, now) = log_l();
        {
            let mut m = log.lock();
            let host_now = now.host_now().unwrap();
            let mut i = 0u64;
            while m.head().seq < atem_client::membership::MAX_ENTRIES {
                let roles = if i % 2 == 0 {
                    [Role::Control, Role::View].into()
                } else {
                    [Role::Control, Role::Manage, Role::View].into()
                };
                let body = m.draft(
                    "dev-mac",
                    1,
                    &Action::SetRoles {
                        device_id: "dev-phone".into(),
                        change: RolesChange::Native(roles),
                    },
                );
                let wire = serde_json::json!({"body": body, "sig": b64u(&[0u8; 64])});
                let entry = Entry::parse_bytes(wire.to_string().as_bytes()).unwrap();
                m.append_unchecked_for_tests(entry, &host_now);
                i += 1;
            }
        }
        assert_eq!(log.capacity().entries, 1024);
        for action in [
            r#"{"action":"remove","device_id":"svc-discord"}"#,
            r#"{"action":"remove_host","host_id":"host-a"}"#,
        ] {
            assert_eq!(
                log.check_change(action.into(), 1_793_264_001_000).unwrap(),
                Some(ChangeRefusalInfo::LogFull),
                "{action}"
            );
        }
        // A malformed action is still refused as `draft_entry` refuses it.
        assert!(matches!(
            log.check_change(r#"{"action":"remove"}"#.into(), 1),
            Err(AtemError::Membership { .. })
        ));
    }
}

//! Push hints, seen, acks and the escalation schedule (§R9.9), and browser
//! grants (§R9.6).
//!
//! A phone receiving a hint: `verify_push_hint(…, Client)` → offer it to its
//! `PushHintBook` (dedup; a resolved dominates) → `open` it with its
//! `enc_key` (only then is the content shown). The relay: `verify_push_hint
//! (…, Relay)`, its book, and the schedule (`push_stages`, `push_send_now`,
//! `push_next_due`), all from the signed `created_at`.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use atem_client::principal::{BrowserGrant, Op};
use atem_client::provider::{KeyId, KeyProvider};
use atem_client::push::{
    self, Accepted, ApprovalKey, DeviceClass, Hint, HintBook, HintState, Identity, RecipientInfo,
    Seen, Stage, Verifier,
};

use crate::encoding::{canonical, hash_of, signed, strict};
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, object_json};
use crate::types::{
    ApprovalRef, BrowserGrantInfo, DeviceKind, HintContent, HintOffer, HintStateInfo,
    PublicKeyData, PushRecipient, PushStage, PushStageDue, PushVerifier, SeenInfo,
};

impl From<&ApprovalKey> for ApprovalRef {
    fn from(k: &ApprovalKey) -> Self {
        ApprovalRef {
            account_id: k.account_id.clone(),
            genesis_hash: k.genesis_hash.clone(),
            host_id: k.host_id.clone(),
            host_trust_gen: k.host_trust_gen,
            session_id: k.session_id.clone(),
            process_gen: k.process_gen.clone(),
            approval_id: k.approval_id.clone(),
        }
    }
}

impl ApprovalRef {
    fn to_key(&self) -> Result<ApprovalKey> {
        Ok(ApprovalKey {
            account_id: self.account_id.clone(),
            genesis_hash: hash_of(&self.genesis_hash)?.to_hex(),
            host_id: self.host_id.clone(),
            host_trust_gen: self.host_trust_gen,
            session_id: self.session_id.clone(),
            process_gen: self.process_gen.clone(),
            approval_id: self.approval_id.clone(),
        })
    }
}

fn recipient(r: &PushRecipient) -> RecipientInfo {
    RecipientInfo {
        class: match r.device_class {
            DeviceKind::Desktop => DeviceClass::Desktop,
            DeviceKind::Mobile => DeviceClass::Mobile,
        },
        connected: r.connected,
        immediate_mobile: r.immediate_mobile,
    }
}

fn stage_of(s: PushStage) -> Stage {
    match s {
        PushStage::InApp => Stage::InApp,
        PushStage::DesktopOs => Stage::DesktopOs,
        PushStage::MobileImmediate => Stage::MobileImmediate,
        PushStage::Mobile => Stage::Mobile,
    }
}

fn stage_info(s: Stage) -> PushStage {
    match s {
        Stage::InApp => PushStage::InApp,
        Stage::DesktopOs => PushStage::DesktopOs,
        Stage::MobileImmediate => PushStage::MobileImmediate,
        Stage::Mobile => PushStage::Mobile,
    }
}

fn ack_json(identity: &Identity) -> String {
    canonical(&identity.to_ack())
}

/// A verified push hint (only `verify_push_hint` makes one).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PushHint {
    hint: Hint,
}

impl PushHint {
    pub(crate) fn open_with(
        &self,
        provider: &dyn KeyProvider,
        enc_key_id: &str,
        device_id: &str,
    ) -> Result<HintContent> {
        let plain = self
            .hint
            .open(provider, &KeyId::new(enc_key_id), device_id)?;
        Ok(HintContent {
            tool: plain.tool,
            summary: plain.summary,
        })
    }
}

/// §R9.9 verification with the verifier's log and wall clock, in order:
/// exact fields, the host's newest key, binding, times, skew (the
/// verifier's rule), staleness. The sealed part is checked when it is
/// offered to a book or opened.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_push_hint(
    hint_json: String,
    log: Arc<MembershipLog>,
    now_ms: u64,
    verifier: PushVerifier,
) -> Result<Arc<PushHint>> {
    let object = signed(&hint_json)?;
    let verifier = match verifier {
        PushVerifier::Client => Verifier::Client,
        PushVerifier::Relay => Verifier::Relay,
    };
    let hint = Hint::verify(&object, &log.lock(), now_ms, verifier)?;
    Ok(Arc::new(PushHint { hint }))
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PushHint {
    pub fn approval(&self) -> ApprovalRef {
        self.hint.key().into()
    }

    pub fn state(&self) -> HintStateInfo {
        match self.hint.state() {
            HintState::Open {
                device_id,
                enc_kid,
                sealed_hash,
            } => HintStateInfo::Open {
                device_id: device_id.clone(),
                enc_kid: enc_kid.clone(),
                sealed_hash: sealed_hash.to_hex(),
            },
            HintState::Resolved {
                reason,
                resolved_at,
            } => HintStateInfo::Resolved {
                reason: reason.clone(),
                resolved_at: *resolved_at,
            },
        }
    }

    pub fn created_at(&self) -> u64 {
        self.hint.created_at()
    }

    pub fn expires_at(&self) -> u64 {
        self.hint.expires_at()
    }

    /// The hint's `push_ack` entry (canonical JSON).
    pub fn ack_json(&self) -> String {
        ack_json(&self.hint.identity())
    }

    /// The hint in canonical JSON (what to forward or store).
    pub fn json(&self) -> String {
        object_json(self.hint.object())
    }

    /// The sealed part is the one `sealed_hash` names (none on a resolved).
    pub fn check_sealed(&self) -> Result<()> {
        Ok(self.hint.check_sealed()?)
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl PushHint {
    /// Opens the sealed tool and summary with this device's `enc_key`
    /// (`enc_key_id` in the provider): refused for another device or
    /// another key before anything is opened.
    pub fn open(
        &self,
        provider: Arc<dyn crate::provider::AppKeyProvider>,
        enc_key_id: String,
        device_id: String,
    ) -> Result<HintContent> {
        self.open_with(
            &crate::provider::Platform(provider),
            &enc_key_id,
            &device_id,
        )
    }
}

/// Accepted hints by identity: a client's dedup, the relay's store.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PushHintBook {
    inner: Mutex<HintBook>,
}

impl PushHintBook {
    fn lock(&self) -> MutexGuard<'_, HintBook> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PushHintBook {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Arc<Self> {
        Arc::new(PushHintBook {
            inner: Mutex::new(HintBook::new()),
        })
    }

    /// Offers a verified hint: the same identity with other bytes is
    /// refused `duplicate` (the first stays); a new open must carry its
    /// sealed part (`bad_sealed`).
    pub fn offer(&self, hint: Arc<PushHint>) -> Result<HintOffer> {
        Ok(match self.lock().offer(hint.hint.clone())? {
            Accepted::Accepted => HintOffer::Accepted,
            Accepted::Idempotent => HintOffer::Idempotent,
            Accepted::IgnoredAfterResolved => HintOffer::IgnoredAfterResolved,
        })
    }

    pub fn is_resolved(&self, approval: ApprovalRef) -> Result<bool> {
        Ok(self.lock().is_resolved(&approval.to_key()?))
    }

    /// Forgets hints whose `expires_at + 300 s` passed.
    pub fn prune(&self, now_ms: u64) {
        self.lock().prune(now_ms)
    }
}

/// The stages for one recipient and when each is due (signed `created_at`
/// only).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn push_stages(created_at: u64, recipient_: PushRecipient) -> Vec<PushStageDue> {
    push::stages(created_at, recipient(&recipient_))
        .into_iter()
        .map(|(stage, due)| PushStageDue {
            stage: stage_info(stage),
            due,
            provider_push: stage.is_provider_push(),
        })
        .collect()
}

/// Whether a stage is sent at `now` (due, before the 15 s guard, not
/// resolved, and for the mobile stage not seen).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn push_send_now(
    stage: PushStage,
    due: u64,
    now: u64,
    expires_at: u64,
    resolved: bool,
    seen: bool,
) -> bool {
    push::send_now(stage_of(stage), due, now, expires_at, resolved, seen)
}

/// The provider guard: `expires_at − 15 s`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn push_guard(expires_at: u64) -> u64 {
    push::guard(expires_at)
}

/// The next time something may become due for this recipient.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn push_next_due(
    created_at: u64,
    expires_at: u64,
    recipient_: PushRecipient,
    sent: Vec<PushStage>,
    now: u64,
) -> Option<u64> {
    let sent: BTreeSet<Stage> = sent.into_iter().map(stage_of).collect();
    push::next_due(created_at, expires_at, recipient(&recipient_), &sent, now)
}

/// Verifies a host-signed seen (exact fields, signature, binding).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_seen(seen_json: String, log: Arc<MembershipLog>) -> Result<SeenInfo> {
    let seen = Seen::verify(&signed(&seen_json)?, &log.lock())?;
    Ok(SeenInfo {
        approval: seen.key().into(),
        created_at: seen.created_at(),
        device_id: seen.device_id().into(),
        seen_at: seen.seen_at(),
    })
}

/// Whether a seen falls in its open's window (same `created_at`, `seen_at`
/// within −300 s … +1200 s).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seen_in_window(
    seen_json: String,
    log: Arc<MembershipLog>,
    open_created_at: u64,
) -> Result<bool> {
    let seen = Seen::verify(&signed(&seen_json)?, &log.lock())?;
    Ok(seen.in_window(open_created_at))
}

/// A seen's `push_ack` entry.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seen_ack_json(seen_json: String, log: Arc<MembershipLog>) -> Result<String> {
    let seen = Seen::verify(&signed(&seen_json)?, &log.lock())?;
    Ok(ack_json(&seen.identity()))
}

/// `{"type":"relay","op":"push_ack","acks":[…]}` from ack entries.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn push_ack_message(acks: Vec<String>) -> Result<String> {
    let identities = acks
        .iter()
        .map(|a| Ok(Identity::from_ack(&strict(a)?)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(canonical(&push::push_ack(&identities)))
}

/// The ack entries a `push_ack` names (entries that don't parse ack
/// nothing).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_push_ack(message_json: String) -> Result<Vec<String>> {
    Ok(push::parse_push_ack(&strict(&message_json)?)
        .iter()
        .map(ack_json)
        .collect())
}

pub(crate) fn sign_seen_with(
    provider: &dyn KeyProvider,
    host_key_id: &str,
    approval: &ApprovalRef,
    created_at: u64,
    device_id: &str,
    seen_at: u64,
) -> Result<String> {
    let object = push::seen(
        provider,
        &KeyId::new(host_key_id),
        &approval.to_key()?,
        created_at,
        device_id,
        seen_at,
    )?;
    Ok(object_json(&object))
}

/// Host role: signs a seen for `device_id` with `host_channel_key`.
#[cfg(feature = "uniffi")]
#[uniffi::export]
pub fn sign_seen(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    host_key_id: String,
    approval: ApprovalRef,
    created_at: u64,
    device_id: String,
    seen_at: u64,
) -> Result<String> {
    sign_seen_with(
        &crate::provider::Platform(provider),
        &host_key_id,
        &approval,
        created_at,
        &device_id,
        seen_at,
    )
}

fn grant_info(grant: &BrowserGrant) -> BrowserGrantInfo {
    BrowserGrantInfo {
        grant_id: grant.grant_id.clone(),
        account_id: grant.account_id.clone(),
        genesis_hash: grant.genesis_hash.to_hex(),
        issuer: grant.issuer.clone(),
        browser_key: (&grant.browser_key).into(),
        host_id: grant.host_id.clone(),
        host_trust_gen: grant.host_trust_gen,
        session_id: grant.session_id.clone(),
        // The wire's order: a set, sorted by bytes.
        ops: {
            let mut ops: Vec<String> = grant.ops.iter().map(|o| o.as_str().to_owned()).collect();
            ops.sort();
            ops
        },
        issued_at: grant.issued_at,
        expires_at: grant.expires_at,
        grant_hash: grant.grant_hash().to_hex(),
    }
}

/// Parses a browser grant strictly (exact fields, P-256 browser key, known
/// ops). Its authority is the host's to judge.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_browser_grant(grant_json: String) -> Result<BrowserGrantInfo> {
    Ok(grant_info(&BrowserGrant::parse(signed(&grant_json)?)?))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn issue_browser_grant_with(
    log: &MembershipLog,
    provider: &dyn KeyProvider,
    issuer_key_id: &str,
    issuer: &str,
    browser_key: &PublicKeyData,
    host_id: &str,
    host_trust_gen: u64,
    session_id: Option<&str>,
    ops: &[String],
    issued_at: u64,
    expires_at: u64,
) -> Result<String> {
    let ops: BTreeSet<Op> = ops
        .iter()
        .map(|o| Op::parse(o).ok_or_else(|| AtemError::malformed("unknown op")))
        .collect::<Result<_>>()?;
    let log = log.lock();
    let body = BrowserGrant::body(
        &log,
        &atem_client::session::new_id(),
        issuer,
        &browser_key.to_key()?,
        host_id,
        host_trust_gen,
        session_id,
        &ops,
        issued_at,
        expires_at,
    );
    let grant = BrowserGrant::issue(&log, provider, &KeyId::new(issuer_key_id), body)?;
    Ok(object_json(&grant.object))
}

/// A phone issues a browser grant (the QR): a native member with `control`
/// signs it with its `auth_key` (purpose `BrowserGrant`, a fresh
/// confirmation). `ops` must contain `view`; at most 1 h.
#[cfg(feature = "uniffi")]
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn issue_browser_grant(
    log: Arc<MembershipLog>,
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    issuer_key_id: String,
    issuer: String,
    browser_key: PublicKeyData,
    host_id: String,
    host_trust_gen: u64,
    session_id: Option<String>,
    ops: Vec<String>,
    issued_at: u64,
    expires_at: u64,
) -> Result<String> {
    issue_browser_grant_with(
        &log,
        &crate::provider::Platform(provider),
        &issuer_key_id,
        &issuer,
        &browser_key,
        &host_id,
        host_trust_gen,
        session_id.as_deref(),
        &ops,
        issued_at,
        expires_at,
    )
}

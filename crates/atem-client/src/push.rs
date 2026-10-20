//! Push hints, seen and the relay's schedule (§R9.9).
//!
//! Atem never sends tool or summary in clear. For each approval the host
//! signs one **open** hint per recipient (every native member with
//! `control` at its head), the tool and summary HPKE-sealed to that
//! member's `enc_key`, and later one **resolved** hint; a device that saw
//! the card in the foreground makes the host sign a **seen**. Everything
//! here is pure and shared:
//!
//! - the host builds and signs: [`open_hint`], [`resolved_hint`],
//!   [`seen`], [`recipients`]; it keeps the per-approval state of seen with
//!   [`HostApproval`] and resends until acknowledged with [`Outbox`];
//! - clients and the relay verify: [`Hint::verify`] (signature by the
//!   newest `add_host` key of the host in the verifier's log, binding,
//!   times, skew, staleness, sealed part), [`Seen::verify`]; a recipient
//!   opens its sealed part with [`Hint::open`]; both keep accepted hints by
//!   their full identity with [`HintBook`] (identical bytes idempotent,
//!   other bytes refused, a resolved dominates an open);
//! - the schedule ([`stages`], [`send_now`]) is a pure function of the
//!   **signed `created_at`**, `expires_at` and the relay's clock, so a late
//!   receipt, a retry, a restart or a failover can't move a deadline;
//!   [`RelayLedger`] is a reference relay over a shared store (the real
//!   relay is Astation's: its HTTP shapes and storage are its own).
//!
//! Identity of a hint or seen: `(account_id, genesis_hash, host_id,
//! host_trust_gen, session_id, process_gen, approval_id)`, plus `state` and
//! `recipient.device_id` for a hint and `device_id` for a seen; every match,
//! deduplication and suppression uses all of it.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::SignedObject;
use crate::canonical::jcs;
use crate::domain;
use crate::encoding::{Hash32, enc, u64_field};
use crate::error::{Error, Result};
use crate::hpke::{self, Sealed};
use crate::keys::{PublicKey, enc_kid};
use crate::membership::{MemberKind, MemberStatus, Membership, Role};
use crate::provider::{KeyId, KeyProvider};
use crate::signed::SealedPart;

/// `expires_at − created_at` is at most 15 minutes.
pub const MAX_HINT_LIFETIME_MS: u64 = 900_000;
/// Clients refuse a `created_at` more than this far ahead of their clock,
/// and stop showing a hint this long after `expires_at`; a seen applies
/// within this of the approval's window; Atem resends until `expires_at` +
/// this.
pub const CLIENT_SKEW_MS: u64 = 300_000;
/// The relay refuses an open whose `created_at` is further than this from
/// its clock at first receipt (never clamped).
pub const RELAY_SKEW_MS: u64 = 120_000;
/// No provider send at or after `expires_at −` this.
pub const GUARD_MARGIN_MS: u64 = 15_000;
/// The mobile stage is due this long after `created_at`.
pub const MOBILE_STAGE_MS: u64 = 60_000;
/// A seen with no open yet is kept until `created_at +` this.
pub const PENDING_SEEN_MS: u64 = 1_200_000;
/// At most this many pending seens per account (the oldest dropped first).
pub const MAX_PENDING_SEENS: usize = 256;
/// Atem resends an unacknowledged hint or seen this often.
pub const RESEND_MS: u64 = 10_000;
/// The sealed summary and tool bounds (§1, r8's approval bounds).
pub const MAX_TOOL_BYTES: usize = 128;
pub const MAX_SUMMARY_BYTES: usize = 512;

// -------------------------------------------------------------- identity

/// The approval a hint or seen is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApprovalKey {
    pub account_id: String,
    /// Lowercase hex (a public value: ordered for maps).
    pub genesis_hash: String,
    pub host_id: String,
    pub host_trust_gen: u64,
    pub session_id: String,
    pub process_gen: String,
    pub approval_id: String,
}

impl ApprovalKey {
    /// The approval `approval_id` of `session_id`/`process_gen` on host
    /// `host_id` (at `host_trust_gen`) of the account `log` names.
    pub fn new(
        log: &Membership,
        host_id: &str,
        host_trust_gen: u64,
        session_id: &str,
        process_gen: &str,
        approval_id: &str,
    ) -> Self {
        ApprovalKey {
            account_id: log.account_id().into(),
            genesis_hash: log.genesis_hash().to_hex(),
            host_id: host_id.into(),
            host_trust_gen,
            session_id: session_id.into(),
            process_gen: process_gen.into(),
            approval_id: approval_id.into(),
        }
    }

    fn fields(&self, out: &mut Map<String, Value>) {
        out.insert("account_id".into(), json!(self.account_id));
        out.insert("genesis_hash".into(), json!(self.genesis_hash));
        out.insert("host_id".into(), json!(self.host_id));
        out.insert("host_trust_gen".into(), json!(self.host_trust_gen));
        out.insert("session_id".into(), json!(self.session_id));
        out.insert("process_gen".into(), json!(self.process_gen));
        out.insert("approval_id".into(), json!(self.approval_id));
    }

    fn read(o: &Map<String, Value>) -> Result<ApprovalKey> {
        let s = |k: &'static str| -> Result<String> {
            o.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or(Error::Malformed(k))
        };
        Ok(ApprovalKey {
            account_id: s("account_id")?,
            genesis_hash: Hash32::from_hex(&s("genesis_hash")?)?.to_hex(),
            host_id: s("host_id")?,
            host_trust_gen: o
                .get("host_trust_gen")
                .and_then(Value::as_u64)
                .filter(|g| *g >= 1)
                .ok_or(Error::Malformed("host_trust_gen"))?,
            session_id: s("session_id")?,
            process_gen: s("process_gen")?,
            approval_id: s("approval_id")?,
        })
    }
}

/// The full identity (`push_ack` entries name it).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Identity {
    /// An open hint for one recipient.
    Open {
        key: ApprovalKey,
        device_id: String,
    },
    Resolved {
        key: ApprovalKey,
    },
    Seen {
        key: ApprovalKey,
        device_id: String,
    },
}

impl Identity {
    pub fn key(&self) -> &ApprovalKey {
        match self {
            Identity::Open { key, .. }
            | Identity::Resolved { key }
            | Identity::Seen { key, .. } => key,
        }
    }

    /// The `push_ack` entry.
    pub fn to_ack(&self) -> Value {
        let mut o = Map::new();
        match self {
            Identity::Open { key, device_id } => {
                o.insert("kind".into(), json!("hint"));
                key.fields(&mut o);
                o.insert("state".into(), json!("open"));
                o.insert("device_id".into(), json!(device_id));
            }
            Identity::Resolved { key } => {
                o.insert("kind".into(), json!("hint"));
                key.fields(&mut o);
                o.insert("state".into(), json!("resolved"));
            }
            Identity::Seen { key, device_id } => {
                o.insert("kind".into(), json!("seen"));
                key.fields(&mut o);
                o.insert("device_id".into(), json!(device_id));
            }
        }
        Value::Object(o)
    }

    /// A `push_ack` entry as received (exact fields).
    pub fn from_ack(value: &Value) -> Result<Identity> {
        let o = value.as_object().ok_or(Error::Malformed("ack"))?;
        let key = ApprovalKey::read(o)?;
        let device = || -> Result<String> {
            o.get("device_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(Error::Malformed("device_id"))
        };
        let (identity, n) = match (
            o.get("kind").and_then(Value::as_str),
            o.get("state").and_then(Value::as_str),
        ) {
            (Some("hint"), Some("open")) => (
                Identity::Open {
                    key,
                    device_id: device()?,
                },
                10,
            ),
            (Some("hint"), Some("resolved")) => (Identity::Resolved { key }, 9),
            (Some("seen"), None) => (
                Identity::Seen {
                    key,
                    device_id: device()?,
                },
                9,
            ),
            _ => return Err(Error::Malformed("ack kind")),
        };
        if o.len() != n {
            return Err(Error::Malformed("unknown field in an ack"));
        }
        Ok(identity)
    }
}

/// `{"type":"relay","op":"push_ack","acks":[…]}`.
pub fn push_ack(acks: &[Identity]) -> Value {
    json!({"type": "relay", "op": "push_ack", "acks": acks.iter().map(Identity::to_ack).collect::<Vec<_>>()})
}

/// The identities a `push_ack` names (an entry that doesn't parse is
/// skipped: it acknowledges nothing).
pub fn parse_push_ack(message: &Value) -> Vec<Identity> {
    if message.get("type").and_then(Value::as_str) != Some("relay")
        || message.get("op").and_then(Value::as_str) != Some("push_ack")
    {
        return Vec::new();
    }
    message
        .get("acks")
        .and_then(Value::as_array)
        .map(|acks| {
            acks.iter()
                .filter_map(|a| Identity::from_ack(a).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// `{"type":"relay","op":"push_hint","hints":[…]}`.
pub fn push_hint_message(hints: &[SignedObject]) -> Value {
    json!({"type": "relay", "op": "push_hint", "hints": hints.iter().map(SignedObject::to_json).collect::<Vec<_>>()})
}

/// `{"type":"relay","op":"push_seen","seen":{body, sig}}`.
pub fn push_seen_message(seen: &SignedObject) -> Value {
    json!({"type": "relay", "op": "push_seen", "seen": seen.to_json()})
}

// ------------------------------------------------------------- the hint

/// The sealed plaintext: `jcs({"summary":…, "tool":…})`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintPlain {
    pub tool: String,
    pub summary: String,
}

impl HintPlain {
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.tool.is_empty()
            || self.tool.len() > MAX_TOOL_BYTES
            || self.summary.len() > MAX_SUMMARY_BYTES
        {
            return Err(Error::TooLarge);
        }
        Ok(Zeroizing::new(
            jcs(&json!({"summary": self.summary, "tool": self.tool}))?.into_bytes(),
        ))
    }

    /// Exactly the canonical `{"summary","tool"}` (anything else refused).
    fn parse(plain: &[u8]) -> Result<HintPlain> {
        let value =
            crate::canonical::parse_strict(plain, 4096, crate::canonical::Numbers::IntegersOnly)?;
        let o = value.as_object().ok_or(Error::Malformed("plaintext"))?;
        if o.len() != 2 {
            return Err(Error::Malformed("plaintext fields"));
        }
        let parsed = HintPlain {
            tool: o
                .get("tool")
                .and_then(Value::as_str)
                .ok_or(Error::Malformed("tool"))?
                .to_owned(),
            summary: o
                .get("summary")
                .and_then(Value::as_str)
                .ok_or(Error::Malformed("summary"))?
                .to_owned(),
        };
        if *parsed.bytes()? != plain {
            return Err(Error::Malformed("plaintext not canonical"));
        }
        Ok(parsed)
    }
}

/// `info = enc(["atem-push-seal-v1", account_id, genesis_hash, host_id,
/// u64(host_trust_gen), approval_id, session_id, process_gen,
/// u64(created_at), u64(expires_at), device_id, enc_kid])`.
pub fn seal_info(
    key: &ApprovalKey,
    created_at: u64,
    expires_at: u64,
    device_id: &str,
    enc_kid: &str,
) -> Result<Vec<u8>> {
    let genesis = Hash32::from_hex(&key.genesis_hash)?;
    Ok(enc(&[
        domain::PUSH_SEAL.as_bytes(),
        key.account_id.as_bytes(),
        genesis.as_bytes(),
        key.host_id.as_bytes(),
        &u64_field(key.host_trust_gen),
        key.approval_id.as_bytes(),
        key.session_id.as_bytes(),
        key.process_gen.as_bytes(),
        &u64_field(created_at),
        &u64_field(expires_at),
        device_id.as_bytes(),
        enc_kid.as_bytes(),
    ]))
}

/// The recipients of an approval's open hints: every native member with
/// `control` in effect at the host's head, with its `enc_key`.
pub fn recipients(log: &Membership) -> Vec<(String, PublicKey)> {
    log.members()
        .into_iter()
        .filter_map(|id| {
            let state = log.member(id)?;
            match &state.member.kind {
                MemberKind::Native { enc_key, roles }
                    if state.status == MemberStatus::Active && roles.contains(&Role::Control) =>
                {
                    Some((id.to_owned(), enc_key.clone()))
                }
                _ => None,
            }
        })
        .collect()
}

fn open_body(
    key: &ApprovalKey,
    created_at: u64,
    expires_at: u64,
    device_id: &str,
    kid: &str,
    sealed: &Sealed,
) -> Value {
    let mut o = Map::new();
    o.insert("type".into(), json!("atem-push-hint"));
    o.insert("v".into(), json!(1));
    o.insert("state".into(), json!("open"));
    key.fields(&mut o);
    o.insert("created_at".into(), json!(created_at));
    o.insert("expires_at".into(), json!(expires_at));
    o.insert(
        "recipient".into(),
        json!({"device_id": device_id, "enc_kid": kid}),
    );
    o.insert("sealed_hash".into(), json!(sealed.hash().to_hex()));
    Value::Object(o)
}

#[allow(clippy::too_many_arguments)]
fn sign_open(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    key: &ApprovalKey,
    created_at: u64,
    expires_at: u64,
    device_id: &str,
    kid: &str,
    sealed: Sealed,
) -> Result<SignedObject> {
    let body = open_body(key, created_at, expires_at, device_id, kid, &sealed);
    Ok(
        SignedObject::sign(provider, host_key, body)?.with_sealed(SealedPart {
            enc: sealed.enc.to_vec(),
            ct: sealed.ct,
        }),
    )
}

/// The host signs one open hint for `device_id`, the tool and summary
/// sealed to its `enc_key` (with `host_channel_key` behind `provider`).
#[allow(clippy::too_many_arguments)]
pub fn open_hint(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    key: &ApprovalKey,
    created_at: u64,
    expires_at: u64,
    device_id: &str,
    enc_key: &PublicKey,
    plain: &HintPlain,
) -> Result<SignedObject> {
    let kid = enc_kid(enc_key)?;
    let info = seal_info(key, created_at, expires_at, device_id, &kid)?;
    let recipient = enc_key.as_32().ok_or(Error::BadKey)?;
    let sealed = hpke::seal(recipient, &info, b"", &plain.bytes()?)?;
    sign_open(
        provider, host_key, key, created_at, expires_at, device_id, &kid, sealed,
    )
}

/// `open_hint` with the HPKE ephemeral `DeriveKeyPair(ikm_e)` (known-answer
/// vectors only).
#[cfg(feature = "test-vectors")]
#[allow(clippy::too_many_arguments)]
pub fn open_hint_with_ikm(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    key: &ApprovalKey,
    created_at: u64,
    expires_at: u64,
    device_id: &str,
    enc_key: &PublicKey,
    plain: &HintPlain,
    ikm_e: &[u8; 32],
) -> Result<SignedObject> {
    let kid = enc_kid(enc_key)?;
    let info = seal_info(key, created_at, expires_at, device_id, &kid)?;
    let recipient = enc_key.as_32().ok_or(Error::BadKey)?;
    let sealed = hpke::seal_with_ikm(recipient, &info, b"", &plain.bytes()?, ikm_e)?;
    sign_open(
        provider, host_key, key, created_at, expires_at, device_id, &kid, sealed,
    )
}

/// The host signs the resolved hint (`reason` the `approval_closed` reason).
pub fn resolved_hint(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    key: &ApprovalKey,
    created_at: u64,
    expires_at: u64,
    reason: &str,
    resolved_at: u64,
) -> Result<SignedObject> {
    let mut o = Map::new();
    o.insert("type".into(), json!("atem-push-hint"));
    o.insert("v".into(), json!(1));
    o.insert("state".into(), json!("resolved"));
    key.fields(&mut o);
    o.insert("created_at".into(), json!(created_at));
    o.insert("expires_at".into(), json!(expires_at));
    o.insert("reason".into(), json!(reason));
    o.insert("resolved_at".into(), json!(resolved_at));
    SignedObject::sign(provider, host_key, Value::Object(o))
}

/// The host signs a seen for `device_id`.
pub fn seen(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    key: &ApprovalKey,
    created_at: u64,
    device_id: &str,
    seen_at: u64,
) -> Result<SignedObject> {
    let mut o = Map::new();
    o.insert("type".into(), json!("atem-seen"));
    o.insert("v".into(), json!(1));
    key.fields(&mut o);
    o.insert("created_at".into(), json!(created_at));
    o.insert("device_id".into(), json!(device_id));
    o.insert("seen_at".into(), json!(seen_at));
    SignedObject::sign(provider, host_key, Value::Object(o))
}

/// Who verifies a hint: the clock rules differ (§R9.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verifier {
    /// Refuses `created_at > now + 300 s`; a hint stale after `expires_at
    /// + 300 s` is not shown.
    Client,
    /// At first receipt, refuses an open whose `created_at` is more than
    /// 120 s from its clock (a resolved is still accepted).
    Relay,
}

/// Why a hint or seen is refused: the relay's `push_hint` refusal codes
/// (§R9.11) plus the structural ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not a well-formed hint/seen (exact fields, §R9.1).
    Malformed(&'static str),
    /// Another account, genesis, host or trust generation than the
    /// verifier's log (or a host it doesn't hold).
    Binding,
    BadSignature,
    /// `expires_at ≤ created_at`, or a lifetime over 15 min.
    InvalidTimes,
    Skew,
    Stale,
    /// An open hint without its sealed part, or whose `enc`/`ct` aren't the
    /// ones `sealed_hash` names.
    BadSealed,
    /// The same identity with other bytes (the first stays).
    Duplicate,
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Malformed(_) => "malformed",
            Refusal::Binding => "binding",
            Refusal::BadSignature => "bad_signature",
            Refusal::InvalidTimes => "invalid_times",
            Refusal::Skew => "skew",
            Refusal::Stale => "stale",
            Refusal::BadSealed => "bad_sealed",
            Refusal::Duplicate => "duplicate",
        }
    }
}

/// A verified hint.
#[derive(Debug, Clone, PartialEq, Eq)]
///
/// Its fields are private: only [`Hint::verify`] makes one, so a hint can
/// only be opened (its decryption `info` built from its fields) after its
/// signature verified.
pub struct Hint {
    object: SignedObject,
    key: ApprovalKey,
    created_at: u64,
    expires_at: u64,
    state: HintState,
}

impl Hint {
    pub fn object(&self) -> &SignedObject {
        &self.object
    }
    pub fn key(&self) -> &ApprovalKey {
        &self.key
    }
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn state(&self) -> &HintState {
        &self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintState {
    Open {
        device_id: String,
        enc_kid: String,
        sealed_hash: Hash32,
    },
    Resolved {
        reason: String,
        resolved_at: u64,
    },
}

const KEY_FIELDS: [&str; 7] = [
    "account_id",
    "genesis_hash",
    "host_id",
    "host_trust_gen",
    "session_id",
    "process_gen",
    "approval_id",
];

fn exact(o: &Map<String, Value>, extra: &[&str]) -> std::result::Result<(), Refusal> {
    let n = 2 + KEY_FIELDS.len() + extra.len();
    let known =
        |k: &str| ["type", "v"].contains(&k) || KEY_FIELDS.contains(&k) || extra.contains(&k);
    if o.len() != n || !o.keys().all(|k| known(k)) {
        return Err(Refusal::Malformed("fields"));
    }
    Ok(())
}

/// The signature with the newest `add_host` key of the body's host, and the
/// binding to the verifier's log (account, genesis, host trust generation).
fn check_host(
    object: &SignedObject,
    key: &ApprovalKey,
    log: &Membership,
) -> std::result::Result<(), Refusal> {
    check_host_signed(object, key, log).map_err(|(r, _)| r)
}

/// `check_host`, also telling whether the signature had verified when it
/// refused (only a binding refusal after it can name an identity).
fn check_host_signed(
    object: &SignedObject,
    key: &ApprovalKey,
    log: &Membership,
) -> std::result::Result<(), (Refusal, bool)> {
    let host = log.host(&key.host_id).ok_or((Refusal::Binding, false))?;
    // The signature first: a tampered field fails here whatever it says.
    object
        .verify(&host.host_key)
        .map_err(|_| (Refusal::BadSignature, false))?;
    if key.account_id != log.account_id()
        || key.genesis_hash != log.genesis_hash().to_hex()
        || key.host_trust_gen != host.host_trust_gen
    {
        return Err((Refusal::Binding, true));
    }
    Ok(())
}

/// A refusal, and the identity when the signature had verified (boxed:
/// an identity is a handful of strings).
pub type Reported = (Refusal, Option<Box<Identity>>);

fn exact_or(o: &Map<String, Value>, extra: &[&str]) -> std::result::Result<(), Reported> {
    exact(o, extra).map_err(|r| (r, None))
}

fn identity_of(key: &ApprovalKey, state: &HintState) -> Identity {
    match state {
        HintState::Open { device_id, .. } => Identity::Open {
            key: key.clone(),
            device_id: device_id.clone(),
        },
        HintState::Resolved { .. } => Identity::Resolved { key: key.clone() },
    }
}

fn u64_of(o: &Map<String, Value>, k: &'static str) -> std::result::Result<u64, Refusal> {
    o.get(k)
        .and_then(Value::as_u64)
        .ok_or(Refusal::Malformed(k))
}

impl Hint {
    /// §R9.9 verification with the verifier's log and clock (`now_ms`),
    /// in this order: exact fields, signature by the host's newest key,
    /// binding, `expires_at > created_at` and ≤ 15 min, skew (the
    /// verifier's rule), staleness. The sealed part is checked after the
    /// identity's duplicate check ([`HintBook::offer`]), so a hint is
    /// refused for its times, or as a conflicting duplicate, whatever it
    /// carries.
    pub fn verify(
        object: &SignedObject,
        log: &Membership,
        now_ms: u64,
        verifier: Verifier,
    ) -> std::result::Result<Hint, Refusal> {
        Self::verify_reporting(object, log, now_ms, verifier).map_err(|(r, _)| r)
    }

    /// [`Hint::verify`], also naming the hint's identity in a refusal once
    /// its signature verified (times, skew, staleness, binding): the relay
    /// acknowledges every hint it can identify, refused ones included
    /// (§R9.9), so the host stops resending them.
    pub fn verify_reporting(
        object: &SignedObject,
        log: &Membership,
        now_ms: u64,
        verifier: Verifier,
    ) -> std::result::Result<Hint, Reported> {
        let unidentified = |r: Refusal| (r, None);
        if object.body_type() != "atem-push-hint" {
            return Err(unidentified(Refusal::Malformed("type")));
        }
        let o = object
            .body()
            .as_object()
            .ok_or(unidentified(Refusal::Malformed("body")))?;
        let state = o.get("state").and_then(Value::as_str);
        match state {
            Some("open") => exact_or(
                o,
                &[
                    "state",
                    "created_at",
                    "expires_at",
                    "recipient",
                    "sealed_hash",
                ],
            )?,
            Some("resolved") => exact_or(
                o,
                &["state", "created_at", "expires_at", "reason", "resolved_at"],
            )?,
            _ => return Err(unidentified(Refusal::Malformed("state"))),
        }
        let key = ApprovalKey::read(o).map_err(|_| unidentified(Refusal::Malformed("identity")))?;
        let created_at = u64_of(o, "created_at").map_err(unidentified)?;
        let expires_at = u64_of(o, "expires_at").map_err(unidentified)?;
        let state = if state == Some("open") {
            let r = o
                .get("recipient")
                .and_then(Value::as_object)
                .filter(|r| r.len() == 2)
                .ok_or(unidentified(Refusal::Malformed("recipient")))?;
            let device_id = r
                .get("device_id")
                .and_then(Value::as_str)
                .ok_or(unidentified(Refusal::Malformed("recipient.device_id")))?;
            let enc_kid = r
                .get("enc_kid")
                .and_then(Value::as_str)
                .filter(|k| {
                    k.len() == 16 && k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                })
                .ok_or(unidentified(Refusal::Malformed("recipient.enc_kid")))?;
            HintState::Open {
                device_id: device_id.to_owned(),
                enc_kid: enc_kid.to_owned(),
                sealed_hash: o
                    .get("sealed_hash")
                    .and_then(Value::as_str)
                    .and_then(|h| Hash32::from_hex(h).ok())
                    .ok_or(unidentified(Refusal::Malformed("sealed_hash")))?,
            }
        } else {
            HintState::Resolved {
                reason: o
                    .get("reason")
                    .and_then(Value::as_str)
                    .ok_or(unidentified(Refusal::Malformed("reason")))?
                    .to_owned(),
                resolved_at: u64_of(o, "resolved_at").map_err(unidentified)?,
            }
        };
        check_host_signed(object, &key, log)
            .map_err(|(r, signed)| (r, signed.then(|| Box::new(identity_of(&key, &state)))))?;
        let identified = |r: Refusal| (r, Some(Box::new(identity_of(&key, &state))));
        if expires_at <= created_at || expires_at - created_at > MAX_HINT_LIFETIME_MS {
            return Err(identified(Refusal::InvalidTimes));
        }
        let open = matches!(state, HintState::Open { .. });
        match verifier {
            Verifier::Client if created_at > now_ms.saturating_add(CLIENT_SKEW_MS) => {
                return Err(identified(Refusal::Skew));
            }
            Verifier::Relay if open && created_at.abs_diff(now_ms) > RELAY_SKEW_MS => {
                return Err(identified(Refusal::Skew));
            }
            _ => {}
        }
        if expires_at.saturating_add(CLIENT_SKEW_MS) <= now_ms {
            return Err(identified(Refusal::Stale));
        }
        Ok(Hint {
            object: object.clone(),
            key,
            created_at,
            expires_at,
            state,
        })
    }

    /// An open hint carries its sealed part, the one `sealed_hash` names
    /// (a resolved hint carries none). Checked by [`HintBook::offer`] after
    /// the identity's duplicate check, and by [`Hint::open`].
    pub fn check_sealed(&self) -> std::result::Result<(), Refusal> {
        match (&self.state, self.object.sealed()) {
            (HintState::Open { sealed_hash, .. }, Some(sealed))
                if Hash32::of_enc(&[&sealed.enc, &sealed.ct]) == *sealed_hash =>
            {
                Ok(())
            }
            (HintState::Resolved { .. }, None) => Ok(()),
            _ => Err(Refusal::BadSealed),
        }
    }

    pub fn identity(&self) -> Identity {
        match &self.state {
            HintState::Open { device_id, .. } => Identity::Open {
                key: self.key.clone(),
                device_id: device_id.clone(),
            },
            HintState::Resolved { .. } => Identity::Resolved {
                key: self.key.clone(),
            },
        }
    }

    /// The recipient opens its sealed part with its `enc_key` behind
    /// `provider` (`enc_key_id`), as `device_id`. A hint for another device
    /// or another `enc_key` (its `enc_kid`) is refused before opening.
    pub fn open(
        &self,
        provider: &dyn KeyProvider,
        enc_key_id: &KeyId,
        device_id: &str,
    ) -> Result<HintPlain> {
        let HintState::Open {
            device_id: recipient,
            enc_kid: kid,
            ..
        } = &self.state
        else {
            return Err(Error::Malformed("a resolved hint has no sealed part"));
        };
        if recipient != device_id {
            return Err(Error::Malformed("not this device's hint"));
        }
        let ours = enc_kid(&provider.public_key(enc_key_id)?)?;
        if !crate::encoding::ct_eq(ours.as_bytes(), kid.as_bytes()) {
            return Err(Error::Malformed("not this enc_key's hint"));
        }
        self.check_sealed().map_err(|_| Error::OpenFailed)?;
        let sealed = self.object.sealed().ok_or(Error::OpenFailed)?;
        let info = seal_info(&self.key, self.created_at, self.expires_at, device_id, kid)?;
        let plain = provider.hpke_open(enc_key_id, &sealed.enc, &sealed.ct, &info, b"")?;
        HintPlain::parse(&plain)
    }
}

/// A verified seen.
#[derive(Debug, Clone, PartialEq, Eq)]
///
/// Only [`Seen::verify`] makes one (private fields).
pub struct Seen {
    object: SignedObject,
    key: ApprovalKey,
    created_at: u64,
    device_id: String,
    seen_at: u64,
}

impl Seen {
    pub fn object(&self) -> &SignedObject {
        &self.object
    }
    pub fn key(&self) -> &ApprovalKey {
        &self.key
    }
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn seen_at(&self) -> u64 {
        self.seen_at
    }
}

impl Seen {
    /// Exact fields, the host's signature and the binding.
    pub fn verify(object: &SignedObject, log: &Membership) -> std::result::Result<Seen, Refusal> {
        if object.body_type() != "atem-seen" {
            return Err(Refusal::Malformed("type"));
        }
        let o = object
            .body()
            .as_object()
            .ok_or(Refusal::Malformed("body"))?;
        exact(o, &["created_at", "device_id", "seen_at"])?;
        let key = ApprovalKey::read(o).map_err(|_| Refusal::Malformed("identity"))?;
        check_host(object, &key, log)?;
        Ok(Seen {
            object: object.clone(),
            created_at: u64_of(o, "created_at")?,
            device_id: o
                .get("device_id")
                .and_then(Value::as_str)
                .ok_or(Refusal::Malformed("device_id"))?
                .to_owned(),
            seen_at: u64_of(o, "seen_at")?,
            key,
        })
    }

    pub fn identity(&self) -> Identity {
        Identity::Seen {
            key: self.key.clone(),
            device_id: self.device_id.clone(),
        }
    }

    /// Within the open's window: `seen_at ∈ [created_at − 300 s,
    /// created_at + 900 s + 300 s]`, and the same `created_at`.
    pub fn in_window(&self, open_created_at: u64) -> bool {
        self.created_at == open_created_at
            && self.seen_at >= open_created_at.saturating_sub(CLIENT_SKEW_MS)
            && self.seen_at <= open_created_at + MAX_HINT_LIFETIME_MS + CLIENT_SKEW_MS
    }
}

// ------------------------------------------------------------- the book

/// What happened to a hint offered to a [`HintBook`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// New: show it (client) / schedule it (relay).
    Accepted,
    /// The same bytes again.
    Idempotent,
    /// An open for an approval already resolved: ignored (a resolved
    /// dominates, whatever order they arrive in).
    IgnoredAfterResolved,
}

/// Accepted hints by full identity (clients dedup and the relay's store).
#[derive(Debug, Clone, Default)]
pub struct HintBook {
    hints: BTreeMap<Identity, Hint>,
    resolved: BTreeSet<ApprovalKey>,
}

impl HintBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offers a verified hint. The same identity with other bytes is
    /// [`Refusal::Duplicate`] (the first stays); a new one must carry its
    /// sealed part ([`Hint::check_sealed`]).
    pub fn offer(&mut self, hint: Hint) -> std::result::Result<Accepted, Refusal> {
        let identity = hint.identity();
        // A resolved dominates its opens, whatever order they arrive in.
        if matches!(hint.state, HintState::Open { .. }) && self.resolved.contains(&hint.key) {
            return Ok(Accepted::IgnoredAfterResolved);
        }
        if let Some(stored) = self.hints.get(&identity) {
            return if stored.object == hint.object {
                Ok(Accepted::Idempotent)
            } else {
                Err(Refusal::Duplicate)
            };
        }
        hint.check_sealed()?;
        match &hint.state {
            HintState::Resolved { .. } => {
                self.resolved.insert(hint.key.clone());
            }
            HintState::Open { .. } => {}
        }
        self.hints.insert(identity, hint);
        Ok(Accepted::Accepted)
    }

    /// The accepted hint with exactly these bytes, if any.
    pub fn stored(&self, object: &SignedObject) -> Option<&Hint> {
        self.hints.values().find(|h| h.object == *object)
    }

    pub fn is_resolved(&self, key: &ApprovalKey) -> bool {
        self.resolved.contains(key)
    }

    /// The accepted open hints of an approval.
    pub fn opens(&self, key: &ApprovalKey) -> Vec<&Hint> {
        self.hints
            .values()
            .filter(|h| h.key == *key && matches!(h.state, HintState::Open { .. }))
            .collect()
    }

    /// Forgets hints whose `expires_at + 300 s` passed (a client's memory
    /// bound; a relay keeps its own retention).
    pub fn prune(&mut self, now_ms: u64) {
        let expired: BTreeSet<ApprovalKey> = self
            .hints
            .values()
            .filter(|h| h.expires_at + CLIENT_SKEW_MS <= now_ms)
            .map(|h| h.key.clone())
            .collect();
        self.hints.retain(|_, h| !expired.contains(&h.key));
        self.resolved.retain(|k| !expired.contains(k));
    }
}

// --------------------------------------------------------- the schedule

/// What kind of device a recipient is (the relay knows its devices).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    Desktop,
    Mobile,
}

/// A recipient as the schedule sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientInfo {
    pub class: DeviceClass,
    /// A desktop Astation of this device is connected (in-app card instead
    /// of a desktop OS push).
    pub connected: bool,
    /// A mobile device that opted in to immediate pushes.
    pub immediate_mobile: bool,
}

/// One stage of §R9.9's schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// In-app card to a connected client (not a provider push), at
    /// `created_at`.
    InApp,
    /// Desktop OS push at `created_at` when no desktop Astation is connected.
    DesktopOs,
    /// Mobile push at `created_at`, only when opted in.
    MobileImmediate,
    /// Mobile push at `created_at + 60 s` if no resolved and no seen.
    Mobile,
}

impl Stage {
    pub const fn is_provider_push(self) -> bool {
        !matches!(self, Stage::InApp)
    }

    pub const fn kind(self) -> &'static str {
        match self {
            Stage::InApp => "in_app",
            Stage::DesktopOs => "desktop_os",
            Stage::MobileImmediate | Stage::Mobile => "mobile",
        }
    }
}

/// The stages for one recipient and when each is due (from the signed
/// `created_at` only).
pub fn stages(created_at: u64, recipient: RecipientInfo) -> Vec<(Stage, u64)> {
    let mut out = Vec::new();
    match recipient.class {
        DeviceClass::Desktop if recipient.connected => out.push((Stage::InApp, created_at)),
        DeviceClass::Desktop => out.push((Stage::DesktopOs, created_at)),
        DeviceClass::Mobile => {
            if recipient.connected {
                out.push((Stage::InApp, created_at));
            }
            if recipient.immediate_mobile {
                out.push((Stage::MobileImmediate, created_at));
            }
            out.push((Stage::Mobile, created_at + MOBILE_STAGE_MS));
        }
    }
    out
}

/// The provider guard: `expires_at − 15 s`.
pub fn guard(expires_at: u64) -> u64 {
    expires_at.saturating_sub(GUARD_MARGIN_MS)
}

/// Whether a stage is sent at `now`: due, before the guard (a stage due at
/// or after it is never sent; one already due when the open is accepted
/// late is sent at once while still before it), not cancelled by a
/// resolved, and, for the mobile stage, no seen. `InApp` isn't a provider
/// send and isn't guarded.
pub fn send_now(
    stage: Stage,
    due: u64,
    now: u64,
    expires_at: u64,
    resolved: bool,
    seen: bool,
) -> bool {
    if resolved || now < due {
        return false;
    }
    if stage == Stage::Mobile && seen {
        return false;
    }
    !stage.is_provider_push() || (due < guard(expires_at) && now < guard(expires_at))
}

/// The next time something may become due for this recipient (a timer),
/// `None` when nothing is left.
pub fn next_due(
    created_at: u64,
    expires_at: u64,
    recipient: RecipientInfo,
    sent: &BTreeSet<Stage>,
    now: u64,
) -> Option<u64> {
    stages(created_at, recipient)
        .into_iter()
        .filter(|(s, due)| !sent.contains(s) && (*due < guard(expires_at) || !s.is_provider_push()))
        .map(|(_, due)| due.max(now))
        .min()
}

// ------------------------------------------------- reference relay

/// One provider push (or a replacement after the resolved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    pub device_id: String,
    /// `desktop_os`, `mobile`, `in_app` or `replace`.
    pub kind: &'static str,
    /// When the stage became due (absolute, relay clock): its time from the
    /// signed `created_at`, or the open's acceptance if that was later (a
    /// late receipt sends a due stage at once); for `replace`, the time it
    /// was sent.
    pub due_at: u64,
    /// `approval_id` (collapse id / tag).
    pub collapse_id: String,
}

/// The relay's verdict on a received hint or seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Idempotent,
    IgnoredAfterResolved,
    /// A seen applied to its open.
    Applied,
    /// A seen with no open yet, stored.
    Pending,
    Refused(Refusal),
}

impl Verdict {
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::Accepted => "accepted",
            Verdict::Idempotent => "idempotent",
            Verdict::IgnoredAfterResolved => "ignored_after_resolved",
            Verdict::Applied => "applied",
            Verdict::Pending => "pending",
            Verdict::Refused(r) => r.code(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ApprovalState {
    created_at: u64,
    expires_at: u64,
    /// Recipient → when its open was accepted (relay clock).
    recipients: BTreeMap<String, u64>,
    seen: bool,
    resolved: bool,
    /// (device, stage) sent once, across replicas.
    sent: BTreeSet<(String, Stage)>,
    replaced: bool,
}

/// A reference relay over its durable store (a value the caller persists
/// and shares between replicas; "set-if-absent" is a map insert here).
/// Every send is decided by [`stages`]/[`send_now`] from the signed
/// `created_at`, never from receipt time.
#[derive(Debug, Clone, Default)]
pub struct RelayLedger {
    book: HintBook,
    approvals: BTreeMap<ApprovalKey, ApprovalState>,
    /// Seens with no open yet, by identity, with their arrival order.
    pending: BTreeMap<Identity, (u64, Seen)>,
    applied_seens: BTreeSet<Identity>,
    order: u64,
}

impl RelayLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// A hint arrives (`push_hint`); every hint is acknowledged whatever
    /// the verdict (the ack names its identity when it could be read).
    pub fn receive_hint(
        &mut self,
        object: &SignedObject,
        log: &Membership,
        now: u64,
    ) -> (Verdict, Option<Identity>) {
        // A resend of bytes already accepted (a lost ack, a reconnect) is
        // idempotent whenever it arrives: the skew bound applies at first
        // receipt only. The bytes are the verified ones.
        if let Some(stored) = self.book.stored(object) {
            let identity = stored.identity();
            let verdict = match stored.state {
                HintState::Open { .. } if self.book.is_resolved(&stored.key) => {
                    Verdict::IgnoredAfterResolved
                }
                _ => Verdict::Idempotent,
            };
            return (verdict, Some(identity));
        }
        let hint = match Hint::verify_reporting(object, log, now, Verifier::Relay) {
            Ok(h) => h,
            Err((r, identity)) => return (Verdict::Refused(r), identity.map(|i| *i)),
        };
        let identity = hint.identity();
        let key = hint.key.clone();
        let (created_at, expires_at) = (hint.created_at, hint.expires_at);
        let state = hint.state.clone();
        let verdict = match self.book.offer(hint) {
            Err(r) => return (Verdict::Refused(r), Some(identity)),
            Ok(Accepted::Idempotent) => Verdict::Idempotent,
            Ok(Accepted::IgnoredAfterResolved) => Verdict::IgnoredAfterResolved,
            Ok(Accepted::Accepted) => Verdict::Accepted,
        };
        if verdict == Verdict::Accepted {
            let approval = self.approvals.entry(key.clone()).or_insert(ApprovalState {
                created_at,
                expires_at,
                ..Default::default()
            });
            match state {
                HintState::Open { device_id, .. } => {
                    approval.recipients.insert(device_id.clone(), now);
                    // A pending seen for this approval applies at once.
                    let matching: Vec<Identity> = self
                        .pending
                        .iter()
                        .filter(|(id, (_, s))| {
                            *id.key() == key && s.device_id == device_id && s.in_window(created_at)
                        })
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in matching {
                        self.pending.remove(&id);
                        self.applied_seens.insert(id);
                        approval.seen = true;
                    }
                }
                HintState::Resolved { .. } => approval.resolved = true,
            }
        }
        (verdict, Some(identity))
    }

    /// A seen arrives (`push_seen`).
    pub fn receive_seen(
        &mut self,
        object: &SignedObject,
        log: &Membership,
        now: u64,
    ) -> (Verdict, Option<Identity>) {
        let seen = match Seen::verify(object, log) {
            Ok(s) => s,
            Err(r) => return (Verdict::Refused(r), None),
        };
        let identity = seen.identity();
        if self.book.is_resolved(&seen.key) {
            return (Verdict::IgnoredAfterResolved, Some(identity));
        }
        if self.applied_seens.contains(&identity) {
            return (Verdict::Idempotent, Some(identity));
        }
        let open = self
            .book
            .opens(&seen.key)
            .into_iter()
            .find(|h| matches!(&h.state, HintState::Open { device_id, .. } if *device_id == seen.device_id))
            .map(|h| h.created_at);
        match open {
            Some(created_at) if seen.in_window(created_at) => {
                self.applied_seens.insert(identity.clone());
                if let Some(a) = self.approvals.get_mut(&seen.key) {
                    a.seen = true;
                }
                (Verdict::Applied, Some(identity))
            }
            Some(_) => (Verdict::Refused(Refusal::InvalidTimes), Some(identity)),
            None => {
                if !self.pending.contains_key(&identity) {
                    self.order += 1;
                    self.pending
                        .insert(identity.clone(), (self.order, seen.clone()));
                    let account: Vec<(u64, Identity)> = self
                        .pending
                        .iter()
                        .filter(|(id, _)| id.key().account_id == seen.key.account_id)
                        .map(|(id, (o, _))| (*o, id.clone()))
                        .collect();
                    if account.len() > MAX_PENDING_SEENS
                        && let Some((_, oldest)) = account.iter().min_by_key(|(o, _)| *o)
                    {
                        self.pending.remove(oldest);
                    }
                }
                self.expire(now);
                (Verdict::Pending, Some(identity))
            }
        }
    }

    fn expire(&mut self, now: u64) {
        self.pending
            .retain(|_, (_, s)| now < s.created_at + PENDING_SEEN_MS);
    }

    /// The pushes due at `now`, each sent once (recorded in the store, so a
    /// replica taking over never repeats one). `device(id)` tells the
    /// relay's knowledge of a recipient.
    pub fn due(&mut self, now: u64, device: &dyn Fn(&str) -> RecipientInfo) -> Vec<Push> {
        self.expire(now);
        let mut pushes = Vec::new();
        for (key, a) in &mut self.approvals {
            if a.resolved {
                if !a.replaced {
                    a.replaced = true;
                    for d in a.recipients.keys() {
                        pushes.push(Push {
                            device_id: d.clone(),
                            kind: "replace",
                            due_at: now,
                            collapse_id: key.approval_id.clone(),
                        });
                    }
                }
                continue;
            }
            for (d, accepted_at) in &a.recipients {
                for (stage, due) in stages(a.created_at, device(d)) {
                    if !stage.is_provider_push() || a.sent.contains(&(d.clone(), stage)) {
                        continue;
                    }
                    if send_now(stage, due, now, a.expires_at, a.resolved, a.seen) {
                        a.sent.insert((d.clone(), stage));
                        pushes.push(Push {
                            device_id: d.clone(),
                            kind: stage.kind(),
                            // A stage already due when the open was accepted
                            // (a late receipt) is due at the acceptance.
                            due_at: due.max(*accepted_at),
                            collapse_id: key.approval_id.clone(),
                        });
                    }
                }
            }
        }
        pushes
    }

    /// The earliest time [`RelayLedger::due`] may return something.
    pub fn next_wake(&self, now: u64, device: &dyn Fn(&str) -> RecipientInfo) -> Option<u64> {
        self.approvals
            .values()
            .filter(|a| !a.resolved)
            .flat_map(|a| {
                a.recipients.keys().filter_map(move |d| {
                    let sent: BTreeSet<Stage> = a
                        .sent
                        .iter()
                        .filter(|(x, _)| x == d)
                        .map(|(_, s)| *s)
                        .collect();
                    stages(a.created_at, device(d))
                        .into_iter()
                        .filter(|(s, due)| {
                            s.is_provider_push()
                                && !sent.contains(s)
                                && *due < guard(a.expires_at)
                                && !(*s == Stage::Mobile && a.seen)
                        })
                        .map(|(_, due)| due.max(now))
                        .min()
                })
            })
            .min()
    }
}

// ------------------------------------------------------- the host side

/// What the host answers an `approval_seen` with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeenOutcome {
    /// The first seen of this device: answer `seen` and send this signed
    /// object (`push_seen`) until acknowledged.
    Signed(SignedObject),
    /// A later one: answer `seen`, never re-signed (the first one's bytes
    /// are what the outbox resends).
    Repeat,
    /// The attachment has no `control`.
    Forbidden,
    /// Not pending for that exact session and process (closed, or another
    /// process).
    StaleTarget,
}

/// One approval's push state on the host (§R9.9).
#[derive(Debug, Clone)]
pub struct HostApproval {
    pub key: ApprovalKey,
    pub created_at: u64,
    pub expires_at: u64,
    closed: bool,
    seen_by: BTreeMap<String, SignedObject>,
}

impl HostApproval {
    pub fn new(key: ApprovalKey, created_at: u64, expires_at: u64) -> Self {
        HostApproval {
            key,
            created_at,
            expires_at,
            closed: false,
            seen_by: BTreeMap::new(),
        }
    }

    /// The open hints, one per recipient of `log` ([`recipients`]).
    pub fn open_hints(
        &self,
        provider: &dyn KeyProvider,
        host_key: &KeyId,
        log: &Membership,
        plain: &HintPlain,
    ) -> Result<Vec<SignedObject>> {
        recipients(log)
            .iter()
            .map(|(device, enc_key)| {
                open_hint(
                    provider,
                    host_key,
                    &self.key,
                    self.created_at,
                    self.expires_at,
                    device,
                    enc_key,
                    plain,
                )
            })
            .collect()
    }

    /// An `approval_seen` from `device_id` for `(session_id, process_gen)`
    /// on an attachment with or without `control`.
    #[allow(clippy::too_many_arguments)]
    pub fn seen(
        &mut self,
        provider: &dyn KeyProvider,
        host_key: &KeyId,
        device_id: &str,
        has_control: bool,
        session_id: &str,
        process_gen: &str,
        seen_at: u64,
    ) -> Result<SeenOutcome> {
        if !has_control {
            return Ok(SeenOutcome::Forbidden);
        }
        if self.closed || session_id != self.key.session_id || process_gen != self.key.process_gen {
            return Ok(SeenOutcome::StaleTarget);
        }
        if self.seen_by.contains_key(device_id) {
            return Ok(SeenOutcome::Repeat);
        }
        let object = seen(
            provider,
            host_key,
            &self.key,
            self.created_at,
            device_id,
            seen_at,
        )?;
        self.seen_by.insert(device_id.into(), object.clone());
        Ok(SeenOutcome::Signed(object))
    }

    /// The approval closed: the resolved hint (sent until acknowledged).
    pub fn close(
        &mut self,
        provider: &dyn KeyProvider,
        host_key: &KeyId,
        reason: &str,
        resolved_at: u64,
    ) -> Result<SignedObject> {
        self.closed = true;
        resolved_hint(
            provider,
            host_key,
            &self.key,
            self.created_at,
            self.expires_at,
            reason,
            resolved_at,
        )
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

#[derive(Debug, Clone)]
struct Pending {
    object: SignedObject,
    next_at: u64,
    live_until: u64,
    /// Queue order: a resend lists its hints as first sent.
    order: u64,
}

/// The host's reliable delivery to the relay (§R9.9): every hint and seen
/// is kept and resent (the same bytes) every 10 s and at each reconnect
/// until the relay acknowledges its identity, the approval's resolved hint
/// is acknowledged, or `expires_at + 300 s` passes. In memory only: a broker
/// restart ends the approvals and their resends. Hints due together travel
/// in one `push_hint` message; each seen in its own `push_seen`.
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    pending: BTreeMap<Identity, Pending>,
    order: u64,
}

impl Outbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues hints and returns the `push_hint` message to send now (all of
    /// them in one message).
    pub fn send_hints(&mut self, hints: &[Hint], now: u64) -> Value {
        for h in hints {
            self.order += 1;
            self.pending.insert(
                h.identity(),
                Pending {
                    object: h.object.clone(),
                    next_at: now + RESEND_MS,
                    live_until: h.expires_at + CLIENT_SKEW_MS,
                    order: self.order,
                },
            );
        }
        push_hint_message(&hints.iter().map(|h| h.object.clone()).collect::<Vec<_>>())
    }

    /// Queues a seen; returns the `push_seen` message to send now.
    pub fn send_seen(&mut self, seen: &Seen, expires_at: u64, now: u64) -> Value {
        self.order += 1;
        self.pending.insert(
            seen.identity(),
            Pending {
                object: seen.object.clone(),
                next_at: now + RESEND_MS,
                live_until: expires_at + CLIENT_SKEW_MS,
                order: self.order,
            },
        );
        push_seen_message(&seen.object)
    }

    /// A `push_ack`: each named identity is done; an acknowledged resolved
    /// hint ends everything of its approval.
    pub fn on_ack(&mut self, acks: &[Identity]) {
        for ack in acks {
            self.pending.remove(ack);
            if let Identity::Resolved { key } = ack {
                self.pending.retain(|id, _| id.key() != key);
            }
        }
    }

    fn messages(&mut self, now: u64, all: bool) -> Vec<Value> {
        self.pending.retain(|_, p| now < p.live_until);
        let mut due: Vec<(&Identity, &mut Pending)> = self
            .pending
            .iter_mut()
            .filter(|(_, p)| all || now >= p.next_at)
            .collect();
        due.sort_by_key(|(_, p)| p.order);
        let mut hints = Vec::new();
        let mut out = Vec::new();
        for (id, p) in due {
            p.next_at = now + RESEND_MS;
            match id {
                Identity::Seen { .. } => out.push(push_seen_message(&p.object)),
                _ => hints.push(p.object.clone()),
            }
        }
        if !hints.is_empty() {
            out.insert(0, push_hint_message(&hints));
        }
        out
    }

    /// The messages due for a resend at `now` (every 10 s).
    pub fn tick(&mut self, now: u64) -> Vec<Value> {
        self.messages(now, false)
    }

    /// The link reconnected: everything unacknowledged, now.
    pub fn reconnect(&mut self, now: u64) -> Vec<Value> {
        self.messages(now, true)
    }

    /// The earliest resend time.
    pub fn next_at(&self) -> Option<u64> {
        self.pending.values().map(|p| p.next_at).min()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }
}

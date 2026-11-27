//! A member's signed verifier report (session-v1 R9.2 "How a verifier
//! reports itself"; agreed for implementation on Astation #101, comment
//! 7082464613): how a verifier that isn't a host (a native app, an SDK
//! process, a service bot) tells a signer which device-list verifier its
//! loaded core runs. Hosts report theirs in the r9 `welcome`.
//!
//! A minter (Astation's signer, or a Station on its behalf) issues and
//! stores a single-use challenge `{signer, slot, origin, connection, nonce,
//! issued_at, expires_at}` ([`ReportChallenge`]); the reporter answers with
//! a signed object in R9.1's form whose body is
//! `{"type":"atem-verifier-report","v":1,"account_id","genesis_hash",
//! "head":{"seq","hash"},"signer","slot","process","challenge":{"origin",
//! "connection","nonce","issued_at","expires_at"},"verifier":{"version",
//! "actions"}}`, signed over `enc(["atem-verifier-report-v1", jcs(body)])`
//! by the signer's own key: a current native member's `auth_key`
//! (`member:<device_id>`) or a current, unexpired service's own key
//! (`service:<device_id>`). Nothing else signs one: no browser grant, host,
//! `recovery` or delegation.
//!
//! - the reporter builds and signs: [`verifier_report_body`] takes nothing
//!   that matters from its caller (the inventory is
//!   [`VerifierInventory::ours`], the head the reporter's own verified log,
//!   the `process` this loaded core's [`process_generation`]) and refuses a
//!   challenge for another Station, signer or slot; [`sign_verifier_report`]
//!   signs it through a [`KeyProvider`], or a signer that answers later
//!   signs [`VerifierReportBody::signing_input`] and hands the signature to
//!   [`VerifierReportBody::with_signature`];
//! - the minter verifies with [`verify_verifier_report`] against its log at
//!   its current head and the challenge it stored.
//!
//! What this primitive enforces is the echoed challenge, a lease of at
//! most 30 s and `now < expires_at` on the caller's clock. Single use, the
//! minter's own monotonic deadline, which slots exist, two processes in one
//! slot, and every lifecycle rule are the consumer's (Astation's), as is
//! whether a report at an ancestor head (`at_head: false`) is enough.
//! Freshness is the minter's too: the builder doesn't compare `issued_at`
//! with the reporter's clock, so a challenge whose `issued_at` is far from
//! it would still be signed; such a challenge is the minter's never to
//! mint, and its stored expectation and its own monotonic deadline bound
//! how long a report counts.
//!
//! [`signer`] is the second kind on the same core: a native manager's
//! signed report of its control-record signing journal, for a Station
//! recovering from a rollback (host-work-v1 §11.1 "The signer report";
//! agreed with Astation, #114 comment 7089435073), re-exported here.
use std::sync::OnceLock;

use serde_json::{Map, Value, json};

use crate::canonical::{self, Numbers};
use crate::domain::{SignLabel, SigningInput};
use crate::encoding::{Hash32, b64u, b64u_decode_array, ct_eq};
use crate::error::Error;
use crate::keys::{PublicKey, normalize_signature};
use crate::membership::entry::id_ok;
use crate::membership::{Head, MemberKind, MemberStatus, Membership, VerifierInventory};
use crate::provider::{KeyId, KeyProvider};
use crate::signed::{self, MAX_BODY_BYTES, SignedObject};
use crate::station_route::normalize_relay;

pub mod signer;

pub use signer::{
    JOURNAL_ID_BYTES, JournalSummary, JournalView, MAX_GENERATION, OutOfPlan, PlanRecord,
    RecoveryPlan, SIGNER_REPORT_TYPE, SIGNER_VERIFY_ORDER, SignerReportBody, SignerReportChallenge,
    VerifiedSignerReport, sign_signer_report, signer_report_body, signer_report_plan_record,
    verify_signer_report,
};

/// The body's `type`.
pub const REPORT_TYPE: &str = "atem-verifier-report";
/// The challenge nonce: 32 random bytes, base64url without padding.
pub const NONCE_BYTES: usize = 32;
/// A loaded core's process generation: 16 random bytes, base64url.
pub const PROCESS_BYTES: usize = 16;
/// A challenge's lease: `0 < expires_at − issued_at ≤ 30000` ms.
pub const MAX_LEASE_MS: u64 = 30_000;
/// A challenge's JSON at most (its fields are bounded well below).
pub const MAX_CHALLENGE_BYTES: usize = MAX_BODY_BYTES;
/// `account_id` is 1 to this many bytes (a device list's own bound).
pub const MAX_ACCOUNT_ID_BYTES: usize = 128;

/// The verifier's refusal codes in the order its checks run: the first
/// that fails is the code ([`verify_verifier_report`]).
pub const VERIFY_ORDER: [&str; 12] = [
    "malformed",
    "frozen",
    "wrong_account",
    "unknown_signer",
    "signer_expired",
    "bad_signature",
    "stale_log",
    "fork",
    "signer_mismatch",
    "slot_mismatch",
    "challenge_mismatch",
    "expired",
];

/// The body's fields (`sig` sits beside the body).
const BODY_FIELDS: [&str; 10] = [
    "type",
    "v",
    "account_id",
    "genesis_hash",
    "head",
    "signer",
    "slot",
    "process",
    "challenge",
    "verifier",
];
/// The body's `challenge`: the minter's challenge but its signer and slot,
/// which sit at the top.
const ECHO_FIELDS: [&str; 5] = ["origin", "connection", "nonce", "issued_at", "expires_at"];
/// The challenge a minter issues and stores.
const CHALLENGE_FIELDS: [&str; 7] = [
    "signer",
    "slot",
    "origin",
    "connection",
    "nonce",
    "issued_at",
    "expires_at",
];

/// Why a report, a binding proof, a challenge or a build is refused.
/// `code()` is the stable name; the verifiers' codes come in
/// [`VERIFY_ORDER`] and [`SIGNER_VERIFY_ORDER`], and a Station binding's
/// in [`BINDING_VERIFY_ORDER`] (its verifier) and [`BINDING_BUILD_ORDER`]
/// (the manager's builder; both Atem's proposal, for Astation's
/// agreement, #120 comment 7207827118).
///
/// [`BINDING_VERIFY_ORDER`]: crate::station_binding::BINDING_VERIFY_ORDER
/// [`BINDING_BUILD_ORDER`]: crate::station_binding::BINDING_BUILD_ORDER
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportRefusal {
    /// Not exactly a report or a challenge (strict I-JSON, exact fields at
    /// every level, no `null`, no `kit_sig`, the grammars, the lease, the
    /// bounds), or a signer report's journal body that isn't one of the
    /// plan's records by its signer; the text names the part.
    Malformed(&'static str),
    /// The log is frozen (a conflict, §R9.4): it reports and verifies
    /// nothing.
    Frozen,
    /// `account_id` or `genesis_hash` isn't the log's.
    WrongAccount,
    /// `signer` isn't a current native member (`member:`) or a current
    /// service (`service:`) at the log's head: removed or never added,
    /// pending, `recovery`, a host, a grant, or a member of the other kind.
    /// A signer report's: anything but a current native member. A Station
    /// binding's: a `member:` that isn't a current native member (removed
    /// or never added, pending, `recovery`, a service named as a member);
    /// any other kind (`service:`, `host:`, `browser:`) is outside its
    /// grammar, `member:<device_id>` only, and so `Malformed`, unlike the
    /// reports (Atem's reading of that grammar).
    UnknownSigner,
    /// A signer report's signer is a current native member that never
    /// held `manage` at any `seq` of the log; a Station binding's doesn't
    /// hold `manage` at the head (the signer's own in the builder, the
    /// verifier's in the verifier).
    NotAManager,
    /// A service whose `expires_at` is at or before `now_ms`.
    SignerExpired,
    /// `sig` doesn't verify under the signer's key at the log's head (a
    /// body signed under another label, by another key, or changed after
    /// signing).
    BadSignature,
    /// `head` is beyond the log's head: the verifier is behind.
    StaleLog,
    /// `head.seq` is on the log's chain but its hash isn't.
    Fork,
    /// The report's (or the builder's) `signer` isn't the challenge's.
    SignerMismatch,
    /// The report's (or the builder's) `slot` isn't the challenge's.
    SlotMismatch,
    /// Another `origin`, `connection`, `nonce`, `issued_at` or
    /// `expires_at` than the challenge the minter stored; a Station
    /// binding's body other than its stored challenge (compared on `jcs`).
    ChallengeMismatch,
    /// A signer report's `recovery` differs from the stored challenge's in
    /// any field.
    RecoveryMismatch,
    /// A signer report's exported records aren't exactly its `records`:
    /// one that isn't a signed control record of the plan by its signer,
    /// one whose signature doesn't verify under the signer's key, a
    /// duplicate, or a count or `records_hash` other than the report's;
    /// the text names which.
    RecordsMismatch(&'static str),
    /// `now_ms` is at or after the challenge's `expires_at`.
    Expired,
    /// The builder only: the challenge's `origin` isn't the reporter's
    /// configured Station.
    OriginMismatch,
    /// A Station binding's builder only: the challenge's `issuer`,
    /// `subject` or `auth_time` isn't what the app was told.
    BindingMismatch,
    /// The signer only: the key provider failed or declined (a key that
    /// can't sign without interaction returns `Cancelled`).
    Signing(Error),
}

impl ReportRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            ReportRefusal::Malformed(_) => "malformed",
            ReportRefusal::Frozen => "frozen",
            ReportRefusal::WrongAccount => "wrong_account",
            ReportRefusal::UnknownSigner => "unknown_signer",
            ReportRefusal::NotAManager => "not_a_manager",
            ReportRefusal::SignerExpired => "signer_expired",
            ReportRefusal::BadSignature => "bad_signature",
            ReportRefusal::StaleLog => "stale_log",
            ReportRefusal::Fork => "fork",
            ReportRefusal::SignerMismatch => "signer_mismatch",
            ReportRefusal::SlotMismatch => "slot_mismatch",
            ReportRefusal::ChallengeMismatch => "challenge_mismatch",
            ReportRefusal::RecoveryMismatch => "recovery_mismatch",
            ReportRefusal::RecordsMismatch(_) => "records_mismatch",
            ReportRefusal::Expired => "expired",
            ReportRefusal::OriginMismatch => "origin_mismatch",
            ReportRefusal::BindingMismatch => "binding_mismatch",
            ReportRefusal::Signing(_) => "signing_failed",
        }
    }
}

impl std::fmt::Display for ReportRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportRefusal::Malformed(what) => write!(f, "malformed ({what})"),
            ReportRefusal::RecordsMismatch(what) => write!(f, "records_mismatch ({what})"),
            ReportRefusal::Signing(e) => write!(f, "signing_failed ({e})"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for ReportRefusal {}

pub(crate) fn malformed(what: &'static str) -> ReportRefusal {
    ReportRefusal::Malformed(what)
}

// ------------------------------------------------------------- grammars

/// Who signs a report, as its `signer` names it. The reader takes any r9
/// principal name whose id is an opaque id, so that a host, a grant or
/// `recovery` is refused as `unknown_signer`, not as `malformed`; only a
/// member and a service can sign.
pub(crate) enum Signer<'a> {
    Member(&'a str),
    Service(&'a str),
    Other,
}

pub(crate) fn read_signer(text: &str) -> Option<Signer<'_>> {
    let (kind, id) = text.split_once(':')?;
    if !id_ok(id) {
        return None;
    }
    Some(match kind {
        "member" => Signer::Member(id),
        "service" => Signer::Service(id),
        "host" | "browser" => Signer::Other,
        _ => return None,
    })
}

/// A challenge's signer, and a reporter's: `member:<id>` or `service:<id>`.
fn signer_ok(text: &str) -> bool {
    matches!(
        read_signer(text),
        Some(Signer::Member(_) | Signer::Service(_))
    )
}

/// A Station's exact origin, as `normalize_relay` writes it.
pub(crate) fn origin_ok(origin: &str) -> bool {
    normalize_relay(origin).as_deref() == Ok(origin)
}

pub(crate) fn lease_ok(issued_at: u64, expires_at: u64) -> bool {
    expires_at > issued_at && expires_at - issued_at <= MAX_LEASE_MS
}

pub(crate) fn int_field(o: &Map<String, Value>, key: &'static str) -> Result<u64, ReportRefusal> {
    o.get(key)
        .and_then(Value::as_u64)
        .filter(|n| *n <= canonical::MAX_SAFE_INTEGER)
        .ok_or(malformed(key))
}

pub(crate) fn str_field<'a>(
    o: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, ReportRefusal> {
    o.get(key).and_then(Value::as_str).ok_or(malformed(key))
}

/// Exactly `fields`, each once (a strict parse already refused duplicates).
pub(crate) fn exact<'a>(
    value: &'a Value,
    fields: &[&str],
    what: &'static str,
) -> Result<&'a Map<String, Value>, ReportRefusal> {
    let o = value.as_object().ok_or(malformed(what))?;
    if o.len() != fields.len() || !o.keys().all(|k| fields.contains(&k.as_str())) {
        return Err(malformed(what));
    }
    Ok(o)
}

/// The fields a challenge and a body's echo share.
struct Echo {
    origin: String,
    connection: u64,
    nonce: [u8; NONCE_BYTES],
    issued_at: u64,
    expires_at: u64,
}

impl Echo {
    fn read(o: &Map<String, Value>) -> Result<Echo, ReportRefusal> {
        let origin = str_field(o, "origin")?;
        if !origin_ok(origin) {
            return Err(malformed("origin"));
        }
        let connection = int_field(o, "connection")?;
        if connection == 0 {
            return Err(malformed("connection"));
        }
        let nonce = str_field(o, "nonce")
            .ok()
            .and_then(|n| b64u_decode_array::<NONCE_BYTES>(n).ok())
            .ok_or(malformed("nonce"))?;
        let issued_at = int_field(o, "issued_at")?;
        let expires_at = int_field(o, "expires_at")?;
        if !lease_ok(issued_at, expires_at) {
            return Err(malformed("lease"));
        }
        Ok(Echo {
            origin: origin.to_owned(),
            connection,
            nonce,
            issued_at,
            expires_at,
        })
    }

    fn same(&self, other: &Echo) -> bool {
        self.origin == other.origin
            && self.connection == other.connection
            && ct_eq(&self.nonce, &other.nonce)
            && self.issued_at == other.issued_at
            && self.expires_at == other.expires_at
    }
}

// ------------------------------------------------------------ challenge

/// The challenge a minter issues and stores, and the verifier's
/// expectation: `{signer, slot, origin, connection, nonce, issued_at,
/// expires_at}`. In a report, `signer` and `slot` are the body's top-level
/// fields and the rest is its `challenge`. Built only through
/// [`ReportChallenge::new`] or [`ReportChallenge::parse`], so every field
/// follows its grammar.
#[derive(Clone, PartialEq, Eq)]
pub struct ReportChallenge {
    signer: String,
    slot: String,
    echo_origin: String,
    connection: u64,
    nonce: [u8; NONCE_BYTES],
    issued_at: u64,
    expires_at: u64,
}

impl std::fmt::Debug for ReportChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportChallenge({})", self.to_json())
    }
}

impl ReportChallenge {
    /// A challenge with a fresh random nonce (the minter's side):
    /// `signer` `member:<id>` or `service:<id>`; `slot` 1–128 bytes of
    /// `[A-Za-z0-9._:-]`; `origin` the minter's Station (normalized here;
    /// anything `normalize_relay` refuses is malformed); `connection` the
    /// slot's generation, 1 to 2^53 − 1; times in ms, `0 < expires_at −
    /// issued_at ≤ 30000`.
    pub fn new(
        signer: &str,
        slot: &str,
        origin: &str,
        connection: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ReportRefusal> {
        Self::read(&Value::Object(Self::fresh_fields(
            signer, slot, origin, connection, issued_at, expires_at,
        )?))
    }

    /// The seven fields of a new challenge, its nonce fresh from the OS
    /// CSPRNG and its origin normalized (a signer report's challenge adds
    /// its recovery).
    fn fresh_fields(
        signer: &str,
        slot: &str,
        origin: &str,
        connection: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Map<String, Value>, ReportRefusal> {
        let mut nonce = [0u8; NONCE_BYTES];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let origin = normalize_relay(origin).map_err(|_| malformed("origin"))?;
        let fields = json!({
            "signer": signer, "slot": slot, "origin": origin, "connection": connection,
            "nonce": b64u(&nonce), "issued_at": issued_at, "expires_at": expires_at,
        });
        Ok(fields.as_object().expect("an object").clone())
    }

    /// Exactly the challenge: one strict I-JSON parse (no duplicate keys,
    /// escaped ones included; integers only), these seven fields and no
    /// other, no `null`, each field's grammar.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReportRefusal> {
        Self::read(&strict_challenge(bytes)?)
    }

    fn read(value: &Value) -> Result<Self, ReportRefusal> {
        Self::read_fields(exact(value, &CHALLENGE_FIELDS, "challenge fields")?)
    }

    /// The seven fields of `o` (its field set the caller's to check).
    fn read_fields(o: &Map<String, Value>) -> Result<Self, ReportRefusal> {
        let signer = str_field(o, "signer")?;
        if !signer_ok(signer) {
            return Err(malformed("signer"));
        }
        let slot = str_field(o, "slot")?;
        if !id_ok(slot) {
            return Err(malformed("slot"));
        }
        let echo = Echo::read(o)?;
        Ok(ReportChallenge {
            signer: signer.to_owned(),
            slot: slot.to_owned(),
            echo_origin: echo.origin,
            connection: echo.connection,
            nonce: echo.nonce,
            issued_at: echo.issued_at,
            expires_at: echo.expires_at,
        })
    }

    /// `{"signer","slot","origin","connection","nonce","issued_at",
    /// "expires_at"}`: what the minter stores and carries.
    pub fn to_json(&self) -> Value {
        json!({
            "signer": self.signer,
            "slot": self.slot,
            "origin": self.echo_origin,
            "connection": self.connection,
            "nonce": b64u(&self.nonce),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        })
    }

    pub fn signer(&self) -> &str {
        &self.signer
    }

    pub fn slot(&self) -> &str {
        &self.slot
    }

    pub fn origin(&self) -> &str {
        &self.echo_origin
    }

    pub fn connection(&self) -> u64 {
        self.connection
    }

    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn echo(&self) -> Echo {
        Echo {
            origin: self.echo_origin.clone(),
            connection: self.connection,
            nonce: self.nonce,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    /// The body's `challenge`: the echo of every field but the signer and
    /// slot, which sit at the body's top.
    fn echo_json(&self) -> Value {
        json!({
            "origin": self.echo_origin,
            "connection": self.connection,
            "nonce": b64u(&self.nonce),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        })
    }
}

/// A challenge text, one strict I-JSON parse within
/// [`MAX_CHALLENGE_BYTES`].
pub(crate) fn strict_challenge(bytes: &[u8]) -> Result<Value, ReportRefusal> {
    canonical::parse_strict(bytes, MAX_CHALLENGE_BYTES, Numbers::IntegersOnly).map_err(
        |e| match e {
            canonical::StrictError::TooLarge => malformed("too large"),
            _ => malformed("not strict JSON"),
        },
    )
}

// -------------------------------------------------------------- process

/// This loaded core's process generation: 16 bytes from the operating
/// system's CSPRNG, drawn once per process image (once per WASM instance)
/// and the same for every report it builds. No API sets it; read it for
/// logs. It tells two processes that share a member key apart; it proves
/// nothing about how many processes hold the key. Per image: a child
/// forked without `exec` after the first draw shares its parent's (a
/// native app never forks; an SDK consumer that forks workers can't tell
/// them apart by it).
pub fn process_generation() -> [u8; PROCESS_BYTES] {
    static PROCESS: OnceLock<[u8; PROCESS_BYTES]> = OnceLock::new();
    *PROCESS.get_or_init(|| {
        let mut process = [0u8; PROCESS_BYTES];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut process);
        process
    })
}

// ----------------------------------------------------------------- body

/// Whose report a signer is, and with which key, at `log`'s head: a
/// current native member for `member:`, a current service for `service:`
/// (unexpired at `now_ms`). The key is the member's `auth_key` as the list
/// pins it, with its algorithm.
fn signer_key(
    log: &Membership,
    signer: &str,
    now_ms: u64,
) -> Result<(SignerKind, PublicKey), ReportRefusal> {
    let (id, kind) = match read_signer(signer) {
        Some(Signer::Member(id)) => (id, SignerKind::Native),
        Some(Signer::Service(id)) => (id, SignerKind::Service),
        _ => return Err(ReportRefusal::UnknownSigner),
    };
    let state = log
        .member(id)
        .filter(|state| state.status == MemberStatus::Active)
        .ok_or(ReportRefusal::UnknownSigner)?;
    match (&state.member.kind, kind) {
        (MemberKind::Native { .. }, SignerKind::Native) => {}
        (MemberKind::Service { expires_at, .. }, SignerKind::Service) => {
            if now_ms >= *expires_at {
                return Err(ReportRefusal::SignerExpired);
            }
        }
        _ => return Err(ReportRefusal::UnknownSigner),
    }
    Ok((kind, state.member.auth_key.clone()))
}

/// A body a member's key signs, built by the core and held unchanged: a
/// signature attached with [`with_signature`](Self::with_signature) is over
/// exactly this body, under its own label. A report's and a Station
/// binding's (`station_binding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldBody {
    label: SignLabel,
    value: Value,
    jcs: String,
    head: Head,
    signer_key: PublicKey,
}

impl HeldBody {
    /// `value` checked as a signed body of `label` (R9.1: its `jcs` at
    /// most 4,096 bytes, no `null`, the arrays its label allows).
    pub(crate) fn new(
        label: SignLabel,
        value: Value,
        head: Head,
        signer_key: PublicKey,
    ) -> Result<Self, ReportRefusal> {
        let (checked, jcs) = signed::check_body(&value).map_err(|_| malformed("body"))?;
        if checked != label {
            return Err(malformed("type"));
        }
        Ok(HeldBody {
            label,
            value,
            jcs,
            head,
            signer_key,
        })
    }

    pub(crate) fn signing_input(&self) -> SigningInput {
        SigningInput::new(self.label, self.jcs.as_bytes())
    }

    /// The body object, read only.
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }

    /// `jcs(body)`, read only.
    pub(crate) fn jcs(&self) -> &str {
        &self.jcs
    }

    /// The signer's key, with its algorithm.
    pub(crate) fn signer_key(&self) -> &PublicKey {
        &self.signer_key
    }

    /// The signed object: this body with `sig` (P-256 64-byte `r‖s`,
    /// either S, normalized to low S; or Ed25519), once it verifies under
    /// the signer's key over this body's signing input.
    pub(crate) fn with_signature(&self, sig: &[u8]) -> Result<SignedObject, ReportRefusal> {
        let sig = normalize_signature(self.signer_key.alg(), sig.to_vec())
            .map_err(|_| ReportRefusal::BadSignature)?;
        self.signer_key
            .verify(&self.signing_input(), &sig)
            .map_err(|_| ReportRefusal::BadSignature)?;
        let object = SignedObject::from_value(&json!({"body": self.value, "sig": b64u(&sig)}))
            .map_err(|_| malformed("report"))?;
        debug_assert_eq!(object.jcs(), self.jcs);
        Ok(object)
    }
}

/// A report's body, built by [`verifier_report_body`] from the reporter's
/// own log, inventory and process, with the signer's key at that log's
/// head. Immutable: nothing outside this module changes a field, so a
/// signature attached with [`with_signature`](Self::with_signature) is
/// over exactly this body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierReportBody {
    held: HeldBody,
    process: [u8; PROCESS_BYTES],
}

impl VerifierReportBody {
    /// The body object.
    pub fn to_json(&self) -> Value {
        self.held.value.clone()
    }

    /// `jcs(body)`.
    pub fn jcs(&self) -> &str {
        &self.held.jcs
    }

    /// `enc(["atem-verifier-report-v1", jcs(body)])`: what the signer's key
    /// signs.
    pub fn signing_input(&self) -> SigningInput {
        self.held.signing_input()
    }

    /// The head of the reporter's log the body names.
    pub fn head(&self) -> Head {
        self.held.head
    }

    /// The process generation the body names ([`process_generation`]).
    pub fn process(&self) -> [u8; PROCESS_BYTES] {
        self.process
    }

    /// The signer's key at the log's head, with its algorithm.
    pub fn signer_key(&self) -> &PublicKey {
        &self.held.signer_key
    }

    /// The report: this body with `sig` (P-256 64-byte `r‖s`, either S,
    /// normalized to low S; or Ed25519), once it verifies under the signer's
    /// key over this body's signing input. A signature over any other body,
    /// under any other label or by any other key is `bad_signature`.
    pub fn with_signature(&self, sig: &[u8]) -> Result<SignedObject, ReportRefusal> {
        self.held.with_signature(sig)
    }
}

/// The builder's checks both reports share, in this order: `signer`
/// (by `signer_allowed`), `slot` and `station` in their grammar (`malformed`);
/// `log` not frozen (`frozen`); the challenge's `origin` the configured
/// Station normalized (`origin_mismatch`), its `signer` the reporter
/// (`signer_mismatch`), its `slot` the reporter's (`slot_mismatch`), its
/// lease in range (`malformed`; a read challenge always is).
fn check_build(
    log: &Membership,
    challenge: &ReportChallenge,
    signer: &str,
    slot: &str,
    station: &str,
    signer_allowed: fn(&str) -> bool,
) -> Result<(), ReportRefusal> {
    if !signer_allowed(signer) {
        return Err(malformed("signer"));
    }
    if !id_ok(slot) {
        return Err(malformed("slot"));
    }
    let station = normalize_relay(station).map_err(|_| malformed("station"))?;
    if log.frozen().is_some() {
        return Err(ReportRefusal::Frozen);
    }
    if challenge.origin() != station {
        return Err(ReportRefusal::OriginMismatch);
    }
    if challenge.signer() != signer {
        return Err(ReportRefusal::SignerMismatch);
    }
    if challenge.slot() != slot {
        return Err(ReportRefusal::SlotMismatch);
    }
    if !lease_ok(challenge.issued_at(), challenge.expires_at()) {
        return Err(malformed("lease"));
    }
    Ok(())
}

/// The fields both reports' bodies share, as the builder writes them for
/// `challenge` at `log`'s head (the caller adds `type`, `v` and its own).
fn common_body(
    log: &Membership,
    challenge: &ReportChallenge,
    process: &[u8; PROCESS_BYTES],
) -> Map<String, Value> {
    let body = json!({
        "account_id": log.account_id(),
        "genesis_hash": log.genesis_hash().to_hex(),
        "head": log.head().to_json(),
        "signer": challenge.signer(),
        "slot": challenge.slot(),
        "process": b64u(process),
        "challenge": challenge.echo_json(),
    });
    body.as_object().expect("an object").clone()
}

/// The body a reporter signs for `challenge`, as `signer` (`member:<id>` or
/// `service:<id>`, the reporter itself) in `slot` (its configured slot),
/// configured with the Station `station`, at `now_ms` on its clock.
///
/// The caller supplies none of what the body claims: `account_id`,
/// `genesis_hash` and `head` are `log`'s, `verifier` is
/// [`VerifierInventory::ours`], `process` is [`process_generation`], and
/// the challenge is echoed exactly. Refused, in this order: `signer`,
/// `slot` or `station` outside their grammar (`malformed`); `log` frozen
/// (`frozen`); the challenge's `origin` other than `station` normalized
/// (`origin_mismatch`), its `signer` other than `signer`
/// (`signer_mismatch`), its `slot` other than `slot` (`slot_mismatch`);
/// `signer` not a current native member or service at the head
/// (`unknown_signer`), a service expired at `now_ms` (`signer_expired`);
/// the challenge expired at `now_ms` (`expired`).
pub fn verifier_report_body(
    log: &Membership,
    challenge: &ReportChallenge,
    signer: &str,
    slot: &str,
    station: &str,
    now_ms: u64,
) -> Result<VerifierReportBody, ReportRefusal> {
    check_build(log, challenge, signer, slot, station, signer_ok)?;
    let (_, signer_key) = signer_key(log, signer, now_ms)?;
    if now_ms >= challenge.expires_at() {
        return Err(ReportRefusal::Expired);
    }
    let process = process_generation();
    let mut value = common_body(log, challenge, &process);
    value.insert("type".into(), json!(REPORT_TYPE));
    value.insert("v".into(), json!(1));
    value.insert("verifier".into(), VerifierInventory::ours().to_json());
    let held = HeldBody::new(
        SignLabel::VerifierReport,
        Value::Object(value),
        log.head(),
        signer_key,
    )?;
    Ok(VerifierReportBody { held, process })
}

/// Signs `body` with `key` (the signer's own key behind `provider`) and
/// returns the report. The provider sees purpose `VerifierReport` in the
/// bindings: it signs only a key that needs no interaction, else it
/// declines (`signing_failed`). A key that isn't the signer's key at the
/// log's head is `bad_signature`; nothing is created, rekeyed or enrolled.
pub fn sign_verifier_report(
    provider: &dyn KeyProvider,
    key: &KeyId,
    body: &VerifierReportBody,
) -> Result<SignedObject, ReportRefusal> {
    let sig = crate::provider::sign(provider, key, &body.signing_input())
        .map_err(ReportRefusal::Signing)?;
    body.with_signature(&sig)
}

// --------------------------------------------------------- verification

/// Which kind of member signed a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKind {
    /// `member:<device_id>`: a native member.
    Native,
    /// `service:<device_id>`: a service.
    Service,
}

/// A verified report: what the minter's consumer decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReport {
    /// `member:<device_id>` or `service:<device_id>`.
    pub signer: String,
    pub kind: SignerKind,
    pub slot: String,
    pub process: [u8; PROCESS_BYTES],
    pub connection: u64,
    /// The head the reporter signed at: the verifier's head or an ancestor.
    pub head: Head,
    /// Whether `head` is the verifier's head (a consumer that needs the
    /// same membership requires it).
    pub at_head: bool,
    /// The reporter's verifier, read for its shape only (an action this
    /// build doesn't know is kept).
    pub inventory: VerifierInventory,
    /// The challenge's `expires_at`.
    pub expires_at: u64,
}

/// What both reports' bodies say beside their own fields, read exactly.
struct Common {
    account_id: String,
    genesis_hash: Hash32,
    head: Head,
    signer: String,
    slot: String,
    process: [u8; PROCESS_BYTES],
    echo: Echo,
}

impl Common {
    /// The shared fields of `o`, whose field set and `type` the caller
    /// checked.
    fn read(o: &Map<String, Value>) -> Result<Common, ReportRefusal> {
        let account_id = str_field(o, "account_id")?;
        if account_id.is_empty() || account_id.len() > MAX_ACCOUNT_ID_BYTES {
            return Err(malformed("account_id"));
        }
        let genesis_hash = str_field(o, "genesis_hash")
            .ok()
            .and_then(|h| Hash32::from_hex(h).ok())
            .ok_or(malformed("genesis_hash"))?;
        let head = o
            .get("head")
            .and_then(Head::from_json)
            .ok_or(malformed("head"))?;
        let signer = str_field(o, "signer")?;
        if read_signer(signer).is_none() {
            return Err(malformed("signer"));
        }
        let slot = str_field(o, "slot")?;
        if !id_ok(slot) {
            return Err(malformed("slot"));
        }
        let process = str_field(o, "process")
            .ok()
            .and_then(|p| b64u_decode_array::<PROCESS_BYTES>(p).ok())
            .ok_or(malformed("process"))?;
        let echo = o.get("challenge").ok_or(malformed("challenge"))?;
        let echo = Echo::read(exact(echo, &ECHO_FIELDS, "challenge")?)?;
        Ok(Common {
            account_id: account_id.to_owned(),
            genesis_hash,
            head,
            signer: signer.to_owned(),
            slot: slot.to_owned(),
            process,
            echo,
        })
    }

    /// The log's checks before the signer's ([`check_account`]).
    fn check_log(&self, log: &Membership) -> Result<(), ReportRefusal> {
        check_account(log, &self.account_id, self.genesis_hash)
    }

    /// The checks after the signer's key, in this order: `sig` by `key`
    /// (`bad_signature`), `head` the log's head or an ancestor
    /// (`stale_log` beyond it, `fork` off it), `signer` and `slot` the
    /// expected ones (`signer_mismatch`, `slot_mismatch`), every echoed
    /// challenge field the expected one (`challenge_mismatch`). Whether
    /// `head` is the log's own.
    fn check_signed(
        &self,
        log: &Membership,
        object: &SignedObject,
        key: &PublicKey,
        expected: &ReportChallenge,
    ) -> Result<bool, ReportRefusal> {
        object
            .verify(key)
            .map_err(|_| ReportRefusal::BadSignature)?;
        let at_head = check_head(log, self.head)?;
        if self.signer != expected.signer() {
            return Err(ReportRefusal::SignerMismatch);
        }
        if self.slot != expected.slot() {
            return Err(ReportRefusal::SlotMismatch);
        }
        if !self.echo.same(&expected.echo()) {
            return Err(ReportRefusal::ChallengeMismatch);
        }
        Ok(at_head)
    }
}

/// The log's checks a signed body's account goes through before its
/// signer's: the log not frozen (`frozen`), `account_id` and
/// `genesis_hash` the log's (`wrong_account`).
pub(crate) fn check_account(
    log: &Membership,
    account_id: &str,
    genesis_hash: Hash32,
) -> Result<(), ReportRefusal> {
    if log.frozen().is_some() {
        return Err(ReportRefusal::Frozen);
    }
    if account_id != log.account_id() || genesis_hash != log.genesis_hash() {
        return Err(ReportRefusal::WrongAccount);
    }
    Ok(())
}

/// `head` the log's head or an ancestor on its chain (`stale_log` beyond
/// it, `fork` off it); whether it is the log's head.
pub(crate) fn check_head(log: &Membership, head: Head) -> Result<bool, ReportRefusal> {
    let ours = log.head();
    if head.seq > ours.seq {
        return Err(ReportRefusal::StaleLog);
    }
    match log.entry(head.seq) {
        Some(entry) if entry.hash() == head.hash => Ok(head == ours),
        _ => Err(ReportRefusal::Fork),
    }
}

/// The signed-object layer's refusal, as the report's `malformed` part.
pub(crate) fn object_malformed(e: Error) -> ReportRefusal {
    malformed(match e {
        Error::Strict(canonical::StrictError::TooLarge) | Error::TooLarge => "too large",
        Error::Strict(_) => "not strict JSON",
        Error::NullValue => "null",
        Error::UnknownType => "type",
        Error::ArrayNotCanonical => "array",
        Error::KitSigUnexpected | Error::KitSigMissing => "kit_sig",
        Error::Malformed(what) => what,
        _ => "report",
    })
}

/// A report as received, `{"body","sig"}`, read as a signed object of
/// `label` (R9.1: strict I-JSON within 16 KiB, its body's `jcs` within
/// 4,096 bytes, no `null`, no `kit_sig`, only the arrays its label allows).
pub(crate) fn read_report(
    report_json: &[u8],
    label: SignLabel,
) -> Result<SignedObject, ReportRefusal> {
    let object = SignedObject::parse(report_json).map_err(object_malformed)?;
    if object.label() != label {
        return Err(malformed("type"));
    }
    Ok(object)
}

/// Verifies a report (`{"body","sig"}` as received) against `log` at its
/// current head and the challenge the minter stored, at `now_ms` on the
/// verifier's clock. Membership and keys are read at the verifier's head,
/// never the report's. In this order, the first failure is the code
/// ([`VERIFY_ORDER`]): exactly a report (`malformed`); the log not frozen
/// (`frozen`); `account_id` and `genesis_hash` the log's (`wrong_account`);
/// `signer` a current native member or service (`unknown_signer`), a
/// service unexpired at `now_ms` (`signer_expired`); `sig` by the signer's
/// key under its pinned algorithm (`bad_signature`); `head` the log's head
/// or an ancestor (`stale_log` beyond it, `fork` off it); `signer` and
/// `slot` the expected ones (`signer_mismatch`, `slot_mismatch`); every
/// challenge field the expected one (`challenge_mismatch`); `now_ms` before
/// `expires_at` (`expired`). A report that verifies cryptographically for
/// another member or slot is refused.
pub fn verify_verifier_report(
    log: &Membership,
    report_json: &[u8],
    expected: &ReportChallenge,
    now_ms: u64,
) -> Result<VerifiedReport, ReportRefusal> {
    let object = read_report(report_json, SignLabel::VerifierReport)?;
    let o = exact(object.body(), &BODY_FIELDS, "body fields")?;
    if o.get("type").and_then(Value::as_str) != Some(REPORT_TYPE) {
        return Err(malformed("type"));
    }
    let body = Common::read(o)?;
    let inventory = o
        .get("verifier")
        .ok_or(malformed("verifier"))
        .and_then(|v| VerifierInventory::from_json(v).map_err(|_| malformed("verifier")))?;
    body.check_log(log)?;
    let (kind, key) = signer_key(log, &body.signer, now_ms)?;
    let at_head = body.check_signed(log, &object, &key, expected)?;
    if now_ms >= expected.expires_at() {
        return Err(ReportRefusal::Expired);
    }
    Ok(VerifiedReport {
        signer: body.signer,
        kind,
        slot: body.slot,
        process: body.process,
        connection: body.echo.connection,
        head: body.head,
        at_head,
        inventory,
        expires_at: body.echo.expires_at,
    })
}

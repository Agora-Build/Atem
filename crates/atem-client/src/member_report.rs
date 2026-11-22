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

/// Why a report, a challenge or a build is refused. `code()` is the
/// stable name; the verifier's codes come in [`VERIFY_ORDER`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportRefusal {
    /// Not exactly a report or a challenge (strict I-JSON, exact fields at
    /// every level, no `null`, no `kit_sig`, the grammars, the lease, the
    /// bounds); the text names the part.
    Malformed(&'static str),
    /// The log is frozen (a conflict, §R9.4): it reports and verifies
    /// nothing.
    Frozen,
    /// `account_id` or `genesis_hash` isn't the log's.
    WrongAccount,
    /// `signer` isn't a current native member (`member:`) or a current
    /// service (`service:`) at the log's head: removed or never added,
    /// pending, `recovery`, a host, a grant, or a member of the other kind.
    UnknownSigner,
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
    /// `expires_at` than the challenge the minter stored.
    ChallengeMismatch,
    /// `now_ms` is at or after the challenge's `expires_at`.
    Expired,
    /// The builder only: the challenge's `origin` isn't the reporter's
    /// configured Station.
    OriginMismatch,
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
            ReportRefusal::SignerExpired => "signer_expired",
            ReportRefusal::BadSignature => "bad_signature",
            ReportRefusal::StaleLog => "stale_log",
            ReportRefusal::Fork => "fork",
            ReportRefusal::SignerMismatch => "signer_mismatch",
            ReportRefusal::SlotMismatch => "slot_mismatch",
            ReportRefusal::ChallengeMismatch => "challenge_mismatch",
            ReportRefusal::Expired => "expired",
            ReportRefusal::OriginMismatch => "origin_mismatch",
            ReportRefusal::Signing(_) => "signing_failed",
        }
    }
}

impl std::fmt::Display for ReportRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportRefusal::Malformed(what) => write!(f, "malformed ({what})"),
            ReportRefusal::Signing(e) => write!(f, "signing_failed ({e})"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for ReportRefusal {}

fn malformed(what: &'static str) -> ReportRefusal {
    ReportRefusal::Malformed(what)
}

// ------------------------------------------------------------- grammars

/// Who signs a report, as its `signer` names it. The reader takes any r9
/// principal name whose id is an opaque id, so that a host, a grant or
/// `recovery` is refused as `unknown_signer`, not as `malformed`; only a
/// member and a service can sign.
enum Signer<'a> {
    Member(&'a str),
    Service(&'a str),
    Other,
}

fn read_signer(text: &str) -> Option<Signer<'_>> {
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
fn origin_ok(origin: &str) -> bool {
    normalize_relay(origin).as_deref() == Ok(origin)
}

fn lease_ok(issued_at: u64, expires_at: u64) -> bool {
    expires_at > issued_at && expires_at - issued_at <= MAX_LEASE_MS
}

fn int_field(o: &Map<String, Value>, key: &'static str) -> Result<u64, ReportRefusal> {
    o.get(key)
        .and_then(Value::as_u64)
        .filter(|n| *n <= canonical::MAX_SAFE_INTEGER)
        .ok_or(malformed(key))
}

fn str_field<'a>(o: &'a Map<String, Value>, key: &'static str) -> Result<&'a str, ReportRefusal> {
    o.get(key).and_then(Value::as_str).ok_or(malformed(key))
}

/// Exactly `fields`, each once (a strict parse already refused duplicates).
fn exact<'a>(
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
        let mut nonce = [0u8; NONCE_BYTES];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let origin = normalize_relay(origin).map_err(|_| malformed("origin"))?;
        let fields = json!({
            "signer": signer, "slot": slot, "origin": origin, "connection": connection,
            "nonce": b64u(&nonce), "issued_at": issued_at, "expires_at": expires_at,
        });
        Self::read(&fields)
    }

    /// Exactly the challenge: one strict I-JSON parse (no duplicate keys,
    /// escaped ones included; integers only), these seven fields and no
    /// other, no `null`, each field's grammar.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReportRefusal> {
        let value = canonical::parse_strict(bytes, MAX_CHALLENGE_BYTES, Numbers::IntegersOnly)
            .map_err(|e| match e {
                canonical::StrictError::TooLarge => malformed("too large"),
                _ => malformed("not strict JSON"),
            })?;
        Self::read(&value)
    }

    fn read(value: &Value) -> Result<Self, ReportRefusal> {
        let o = exact(value, &CHALLENGE_FIELDS, "challenge fields")?;
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

/// A report's body, built by [`verifier_report_body`] from the reporter's
/// own log, inventory and process, with the signer's key at that log's
/// head. Immutable: nothing outside this module changes a field, so a
/// signature attached with [`with_signature`](Self::with_signature) is
/// over exactly this body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierReportBody {
    value: Value,
    jcs: String,
    head: Head,
    process: [u8; PROCESS_BYTES],
    signer_key: PublicKey,
}

impl VerifierReportBody {
    /// The body object.
    pub fn to_json(&self) -> Value {
        self.value.clone()
    }

    /// `jcs(body)`.
    pub fn jcs(&self) -> &str {
        &self.jcs
    }

    /// `enc(["atem-verifier-report-v1", jcs(body)])`: what the signer's key
    /// signs.
    pub fn signing_input(&self) -> SigningInput {
        SigningInput::new(SignLabel::VerifierReport, self.jcs.as_bytes())
    }

    /// The head of the reporter's log the body names.
    pub fn head(&self) -> Head {
        self.head
    }

    /// The process generation the body names ([`process_generation`]).
    pub fn process(&self) -> [u8; PROCESS_BYTES] {
        self.process
    }

    /// The signer's key at the log's head, with its algorithm.
    pub fn signer_key(&self) -> &PublicKey {
        &self.signer_key
    }

    /// The report: this body with `sig` (P-256 64-byte `r‖s`, either S,
    /// normalized to low S; or Ed25519), once it verifies under the signer's
    /// key over this body's signing input. A signature over any other body,
    /// under any other label or by any other key is `bad_signature`.
    pub fn with_signature(&self, sig: &[u8]) -> Result<SignedObject, ReportRefusal> {
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
    if !signer_ok(signer) {
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
    let (_, signer_key) = signer_key(log, signer, now_ms)?;
    if now_ms >= challenge.expires_at() {
        return Err(ReportRefusal::Expired);
    }
    let head = log.head();
    let process = process_generation();
    let value = json!({
        "type": REPORT_TYPE,
        "v": 1,
        "account_id": log.account_id(),
        "genesis_hash": log.genesis_hash().to_hex(),
        "head": head.to_json(),
        "signer": signer,
        "slot": slot,
        "process": b64u(&process),
        "challenge": {
            "origin": challenge.origin(),
            "connection": challenge.connection(),
            "nonce": b64u(challenge.nonce()),
            "issued_at": challenge.issued_at(),
            "expires_at": challenge.expires_at(),
        },
        "verifier": VerifierInventory::ours().to_json(),
    });
    let (label, jcs) = signed::check_body(&value).map_err(|_| malformed("body"))?;
    debug_assert_eq!(label, SignLabel::VerifierReport);
    Ok(VerifierReportBody {
        value,
        jcs,
        head,
        process,
        signer_key,
    })
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

/// What a body says, read exactly.
struct Read {
    account_id: String,
    genesis_hash: Hash32,
    head: Head,
    signer: String,
    slot: String,
    process: [u8; PROCESS_BYTES],
    echo: Echo,
    inventory: VerifierInventory,
}

impl Read {
    fn body(body: &Value) -> Result<Read, ReportRefusal> {
        let o = exact(body, &BODY_FIELDS, "body fields")?;
        if o.get("type").and_then(Value::as_str) != Some(REPORT_TYPE) {
            return Err(malformed("type"));
        }
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
        let echo = Echo::read(exact(&o["challenge"], &ECHO_FIELDS, "challenge")?)?;
        let inventory = o
            .get("verifier")
            .ok_or(malformed("verifier"))
            .and_then(|v| VerifierInventory::from_json(v).map_err(|_| malformed("verifier")))?;
        Ok(Read {
            account_id: account_id.to_owned(),
            genesis_hash,
            head,
            signer: signer.to_owned(),
            slot: slot.to_owned(),
            process,
            echo,
            inventory,
        })
    }
}

/// The signed-object layer's refusal, as the report's `malformed` part.
fn object_malformed(e: Error) -> ReportRefusal {
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
    let object = SignedObject::parse(report_json).map_err(object_malformed)?;
    if object.label() != SignLabel::VerifierReport {
        return Err(malformed("type"));
    }
    let body = Read::body(object.body())?;
    if log.frozen().is_some() {
        return Err(ReportRefusal::Frozen);
    }
    if body.account_id != log.account_id() || body.genesis_hash != log.genesis_hash() {
        return Err(ReportRefusal::WrongAccount);
    }
    let (kind, key) = signer_key(log, &body.signer, now_ms)?;
    object
        .verify(&key)
        .map_err(|_| ReportRefusal::BadSignature)?;
    let ours = log.head();
    if body.head.seq > ours.seq {
        return Err(ReportRefusal::StaleLog);
    }
    match log.entry(body.head.seq) {
        Some(entry) if entry.hash() == body.head.hash => {}
        _ => return Err(ReportRefusal::Fork),
    }
    if body.signer != expected.signer() {
        return Err(ReportRefusal::SignerMismatch);
    }
    if body.slot != expected.slot() {
        return Err(ReportRefusal::SlotMismatch);
    }
    if !body.echo.same(&expected.echo()) {
        return Err(ReportRefusal::ChallengeMismatch);
    }
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
        at_head: body.head == ours,
        inventory: body.inventory,
        expires_at: body.echo.expires_at,
    })
}

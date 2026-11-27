//! A native manager's Station binding proof (`atem-station-binding-v1`;
//! delegated host-work design III.5 (b) "Creating it", Atem's answer on
//! #120 comment 7207827118): the signed proof that binds, transfers or
//! unbinds an R9 account's Agora.Build owner at a Station. It decides which
//! Agora.Build account's state controls whether that Station serves the
//! account's hosts.
//!
//! The Station mints the whole body, a single-use challenge
//! ([`StationBindingChallenge`]), stores it and hands it to the manager's
//! app; the manager signs exactly what was minted, with a fresh owner
//! confirmation every time. The proof is R9.1's signed object `{"body":
//! <the challenge>, "sig"}` (no `kit_sig`), signed over
//! `enc(["atem-station-binding-v1", jcs(body)])` by a current native
//! member's `auth_key` (`member:<device_id>`) holding `manage`, Ed25519
//! (`verify_strict`) or P-256/SHA-256 with a 64-byte low-S `r‖s`, under the
//! algorithm the device list pins for it. The body's fifteen fields:
//!
//! - `type` `atem-station-binding`, `v` 1;
//! - `action`: `bind`, `transfer` or `unbind` ([`BindingAction`]);
//! - `origin`: the Station, exactly as `station_route::normalize_relay`
//!   writes it;
//! - `issuer`, `subject`: the Agora.Build token's exact `iss` and `sub`, 1
//!   to 256 bytes of printable ASCII (0x21–0x7E), compared byte for byte;
//! - `auth_time`: the token's `auth_time`, Unix **seconds**, 0 to 2^53 − 1,
//!   with `auth_time × 1000 ≤ issued_at`;
//! - `account_id` (1–128 bytes of `[A-Za-z0-9._:-]`), `genesis_hash`
//!   (lowercase hex), `head` `{seq, hash}`: the R9 account at the Station's
//!   applied head;
//! - `signer`: `member:<device_id>` only;
//! - `expected_binding`: `{"state":"never_bound"}`, or `{"state": "bound" |
//!   "unbound" | "released", "binding_id", "version", "owner"}`
//!   ([`ExpectedBinding`]): the record the Station holds;
//! - `nonce`: 32 bytes, base64url; `issued_at`, `expires_at`: ms, `0 <
//!   expires_at − issued_at ≤ 30000`.
//!
//! Per action ([`BindingAction`]): a `bind` names `never_bound`, `unbound`
//! or `released` (a rebind the prior record's id, state and version); a
//! `transfer` names `bound` and the intended new owner as `subject`
//! (`subject ≠ owner`); an `unbind` names `bound` and the current owner as
//! `subject` (`subject = owner`). An unbind needs the same proof as a bind
//! or a transfer (owner decision 2026-11-27): it suspends every host of the
//! R9 account at that Station, so a stolen Agora.Build session alone can't
//! do it. Strict I-JSON, exact fields at every level, no `null`, no
//! duplicate keys (escaped ones included), a challenge text at most 4,096
//! bytes, the body's `jcs` at most 4,096 bytes and the proof at most 16 KiB.
//!
//! - **The manager's app** builds with [`station_binding_request`], which
//!   takes nothing that matters from its caller: it checks every field of
//!   the challenge against its own log, its own `member:` id, its
//!   configured Station and the Agora.Build sign-in it was told
//!   ([`AuthClaims`]), then holds the challenge as the body; it signs
//!   through a [`KeyProvider`] ([`sign_station_binding`]) or hands a later
//!   signature to [`StationBindingRequest::finish`].
//! - **The Station** verifies with [`verify_station_binding`] against its
//!   log at its current head and the challenge it stored, and requires
//!   `at_head`.
//!
//! What stays the Station's: the token's validation (`aud` = origin, `iss`,
//! `sub`, `exp`, `auth_time` equal to the body's), the nonce store and
//! single use, a transfer's consent, the disabled-account and
//! `binding_attempt` rules, the commit-time recheck (head current, signer
//! still `manage`, the record's state, `binding_id` and `version` equal to
//! `expected_binding`, committed with its route invalidations and the
//! `binding_changed` intent) and exact retries.
//!
//! **Atem's proposals, for Astation's agreement** (asked in the post):
//! `owner` is named in the `unbound` and `released` states too, not only in
//! `bound`; and the builder compares a transfer's `subject`, like every
//! action's, with the `subject` the app supplies in [`AuthClaims`] (the new
//! owner it was shown).
use serde_json::{Map, Value, json};

use crate::canonical;
use crate::domain::{SignLabel, SigningInput};
use crate::encoding::{Hash32, b64u, b64u_decode_array, ct_eq};
use crate::keys::PublicKey;
use crate::member_report::{
    HeldBody, NONCE_BYTES, ReportRefusal, Signer, check_account, check_head, exact, int_field,
    lease_ok, malformed, origin_ok, read_report, read_signer, str_field, strict_challenge,
};
use crate::membership::entry::id_ok;
use crate::membership::{Head, MemberKind, MemberStatus, Membership};
use crate::provider::{KeyId, KeyProvider};
use crate::signed::{MAX_BODY_BYTES, SignedObject};
use crate::station_route::normalize_relay;

/// The body's `type`.
pub const BINDING_TYPE: &str = "atem-station-binding";
/// `issuer`, `subject` and `owner` are 1 to this many bytes of printable
/// ASCII (0x21–0x7E).
pub const MAX_CLAIM_BYTES: usize = 256;

/// The verifier's refusal codes in the order its checks run: the first
/// that fails is the code ([`verify_station_binding`]).
pub const BINDING_VERIFY_ORDER: [&str; 10] = [
    "malformed",
    "frozen",
    "wrong_account",
    "unknown_signer",
    "not_a_manager",
    "bad_signature",
    "stale_log",
    "fork",
    "challenge_mismatch",
    "expired",
];

/// The builder's refusal codes in the order its checks run
/// ([`station_binding_request`]).
pub const BINDING_BUILD_ORDER: [&str; 11] = [
    "malformed",
    "frozen",
    "wrong_account",
    "origin_mismatch",
    "signer_mismatch",
    "unknown_signer",
    "not_a_manager",
    "stale_log",
    "fork",
    "binding_mismatch",
    "expired",
];

/// The body's fields, which are the challenge's.
const FIELDS: [&str; 15] = [
    "type",
    "v",
    "action",
    "origin",
    "issuer",
    "subject",
    "auth_time",
    "account_id",
    "genesis_hash",
    "head",
    "signer",
    "expected_binding",
    "nonce",
    "issued_at",
    "expires_at",
];
const RECORD_FIELDS: [&str; 4] = ["state", "binding_id", "version", "owner"];

// ------------------------------------------------------------- grammars

/// An `issuer`, `subject` or `owner`: 1 to 256 bytes of printable ASCII.
fn claim_ok(text: &str) -> bool {
    (1..=MAX_CLAIM_BYTES).contains(&text.len()) && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// A binding's signer: `member:<id>` only.
fn member_signer_ok(text: &str) -> bool {
    matches!(read_signer(text), Some(Signer::Member(_)))
}

/// What a binding does at the Station.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingAction {
    /// Binds a never-bound, unbound or released R9 account to `subject`.
    Bind,
    /// Moves a bound R9 account to `subject`, its intended new owner.
    Transfer,
    /// Unbinds a bound R9 account; `subject` is its current owner.
    Unbind,
}

impl BindingAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            BindingAction::Bind => "bind",
            BindingAction::Transfer => "transfer",
            BindingAction::Unbind => "unbind",
        }
    }

    /// The action an exact name stands for.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "bind" => BindingAction::Bind,
            "transfer" => BindingAction::Transfer,
            "unbind" => BindingAction::Unbind,
            _ => return None,
        })
    }
}

/// The service-ownership record a Station holds for an R9 account, as a
/// challenge names it: its `binding_id` (1–128 bytes of `[A-Za-z0-9._:-]`),
/// its `version` (1 to 2^53 − 1) and its `owner`, the exact `sub` of the
/// Agora.Build account it names (the owner, or the owner let go).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    pub binding_id: String,
    pub version: u64,
    pub owner: String,
}

impl BindingRecord {
    fn check(&self) -> Result<(), ReportRefusal> {
        if !id_ok(&self.binding_id) {
            return Err(malformed("expected_binding.binding_id"));
        }
        if !(1..=canonical::MAX_SAFE_INTEGER).contains(&self.version) {
            return Err(malformed("expected_binding.version"));
        }
        if !claim_ok(&self.owner) {
            return Err(malformed("expected_binding.owner"));
        }
        Ok(())
    }
}

/// The record the Station expects to change (`expected_binding`): none yet,
/// or one in its state. `owner` is named in every recorded state (Atem's
/// proposal, for Astation's agreement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedBinding {
    /// `{"state":"never_bound"}`.
    NeverBound,
    Bound(BindingRecord),
    Unbound(BindingRecord),
    Released(BindingRecord),
}

impl ExpectedBinding {
    /// `never_bound`, `bound`, `unbound` or `released`.
    pub fn state(&self) -> &'static str {
        match self {
            ExpectedBinding::NeverBound => "never_bound",
            ExpectedBinding::Bound(_) => "bound",
            ExpectedBinding::Unbound(_) => "unbound",
            ExpectedBinding::Released(_) => "released",
        }
    }

    /// The record, in every state but `never_bound`.
    pub fn record(&self) -> Option<&BindingRecord> {
        match self {
            ExpectedBinding::NeverBound => None,
            ExpectedBinding::Bound(r)
            | ExpectedBinding::Unbound(r)
            | ExpectedBinding::Released(r) => Some(r),
        }
    }

    /// `{"state":"never_bound"}` or `{"state","binding_id","version",
    /// "owner"}`.
    pub fn to_json(&self) -> Value {
        match self.record() {
            None => json!({"state": self.state()}),
            Some(r) => json!({
                "state": self.state(),
                "binding_id": r.binding_id,
                "version": r.version,
                "owner": r.owner,
            }),
        }
    }

    /// Exactly one of the two forms, each field in its grammar (`malformed`
    /// otherwise).
    pub fn from_json(value: &Value) -> Result<Self, ReportRefusal> {
        let o = value.as_object().ok_or(malformed("expected_binding"))?;
        let state = str_field(o, "state").map_err(|_| malformed("expected_binding.state"))?;
        if state == "never_bound" {
            exact(value, &["state"], "expected_binding")?;
            return Ok(ExpectedBinding::NeverBound);
        }
        let o = exact(value, &RECORD_FIELDS, "expected_binding")?;
        let record = BindingRecord {
            binding_id: str_field(o, "binding_id")
                .map_err(|_| malformed("expected_binding.binding_id"))?
                .to_owned(),
            version: int_field(o, "version").map_err(|_| malformed("expected_binding.version"))?,
            owner: str_field(o, "owner")
                .map_err(|_| malformed("expected_binding.owner"))?
                .to_owned(),
        };
        record.check()?;
        Ok(match state {
            "bound" => ExpectedBinding::Bound(record),
            "unbound" => ExpectedBinding::Unbound(record),
            "released" => ExpectedBinding::Released(record),
            _ => return Err(malformed("expected_binding.state")),
        })
    }
}

/// The Agora.Build sign-in a binding names, from the token the Station
/// verified: its exact `iss` and `sub` (1–256 bytes of printable ASCII) and
/// its `auth_time` in Unix seconds. The app hands the builder what it was
/// told: its own token's for a bind or an unbind, and for a transfer the
/// new owner it was shown (Atem's proposal, for Astation's agreement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthClaims {
    pub issuer: String,
    pub subject: String,
    pub auth_time: u64,
}

impl AuthClaims {
    fn check(&self) -> Result<(), ReportRefusal> {
        if !claim_ok(&self.issuer) {
            return Err(malformed("issuer"));
        }
        if !claim_ok(&self.subject) {
            return Err(malformed("subject"));
        }
        if self.auth_time > canonical::MAX_SAFE_INTEGER {
            return Err(malformed("auth_time"));
        }
        Ok(())
    }
}

// ------------------------------------------------------------ challenge

/// The challenge a Station mints and stores, which is also the body the
/// manager signs: exactly its fifteen fields, each in its grammar, and the
/// per-action rules. Built only through [`StationBindingChallenge::new`]
/// or [`StationBindingChallenge::parse`].
#[derive(Clone, PartialEq, Eq)]
pub struct StationBindingChallenge {
    action: BindingAction,
    origin: String,
    claims: AuthClaims,
    account_id: String,
    genesis_hash: Hash32,
    head: Head,
    signer: String,
    expected_binding: ExpectedBinding,
    nonce: [u8; NONCE_BYTES],
    issued_at: u64,
    expires_at: u64,
    /// The object as read, and its `jcs`.
    value: Value,
    jcs: String,
}

impl std::fmt::Debug for StationBindingChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StationBindingChallenge({})", self.jcs)
    }
}

impl StationBindingChallenge {
    /// A challenge with a fresh nonce (the Station's side): 32 bytes from
    /// the operating system's CSPRNG, `origin` normalized here (anything
    /// `normalize_relay` refuses is malformed), every other field as given
    /// and checked as [`parse`](Self::parse) checks it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action: BindingAction,
        origin: &str,
        claims: &AuthClaims,
        account_id: &str,
        genesis_hash: Hash32,
        head: Head,
        signer: &str,
        expected_binding: ExpectedBinding,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ReportRefusal> {
        let mut nonce = [0u8; NONCE_BYTES];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let origin = normalize_relay(origin).map_err(|_| malformed("origin"))?;
        Self::read(&json!({
            "type": BINDING_TYPE,
            "v": 1,
            "action": action.as_str(),
            "origin": origin,
            "issuer": claims.issuer,
            "subject": claims.subject,
            "auth_time": claims.auth_time,
            "account_id": account_id,
            "genesis_hash": genesis_hash.to_hex(),
            "head": head.to_json(),
            "signer": signer,
            "expected_binding": expected_binding.to_json(),
            "nonce": b64u(&nonce),
            "issued_at": issued_at,
            "expires_at": expires_at,
        }))
    }

    /// Exactly the challenge: one strict I-JSON parse of at most 4,096
    /// bytes (no duplicate keys, escaped ones included; integers only), the
    /// fifteen fields and no other at any level, no `null`, each field's
    /// grammar and the per-action rules.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReportRefusal> {
        Self::read(&strict_challenge(bytes)?)
    }

    /// A challenge, or a proof's body, read exactly.
    pub(crate) fn read(value: &Value) -> Result<Self, ReportRefusal> {
        let o = exact(value, &FIELDS, "fields")?;
        if str_field(o, "type")? != BINDING_TYPE {
            return Err(malformed("type"));
        }
        if int_field(o, "v")? != 1 {
            return Err(malformed("v"));
        }
        let action =
            BindingAction::from_name(str_field(o, "action")?).ok_or(malformed("action"))?;
        let origin = str_field(o, "origin")?;
        if !origin_ok(origin) {
            return Err(malformed("origin"));
        }
        let claims = AuthClaims {
            issuer: str_field(o, "issuer")?.to_owned(),
            subject: str_field(o, "subject")?.to_owned(),
            auth_time: int_field(o, "auth_time")?,
        };
        claims.check()?;
        let account_id = str_field(o, "account_id")?;
        if !id_ok(account_id) {
            return Err(malformed("account_id"));
        }
        let genesis_hash = Self::hash(o, "genesis_hash")?;
        let head = o
            .get("head")
            .and_then(Head::from_json)
            .ok_or(malformed("head"))?;
        let signer = str_field(o, "signer")?;
        if !member_signer_ok(signer) {
            return Err(malformed("signer"));
        }
        let expected_binding = ExpectedBinding::from_json(
            o.get("expected_binding")
                .ok_or(malformed("expected_binding"))?,
        )?;
        let nonce = str_field(o, "nonce")
            .ok()
            .and_then(|n| b64u_decode_array::<NONCE_BYTES>(n).ok())
            .ok_or(malformed("nonce"))?;
        let issued_at = int_field(o, "issued_at")?;
        let expires_at = int_field(o, "expires_at")?;
        if !lease_ok(issued_at, expires_at) {
            return Err(malformed("lease"));
        }
        // The token's sign-in, in seconds, at or before the challenge.
        if claims
            .auth_time
            .checked_mul(1000)
            .is_none_or(|ms| ms > issued_at)
        {
            return Err(malformed("auth_time"));
        }
        match (action, &expected_binding) {
            (
                BindingAction::Bind,
                ExpectedBinding::NeverBound
                | ExpectedBinding::Unbound(_)
                | ExpectedBinding::Released(_),
            ) => {}
            (BindingAction::Transfer, ExpectedBinding::Bound(r)) if r.owner != claims.subject => {}
            (BindingAction::Unbind, ExpectedBinding::Bound(r)) if r.owner == claims.subject => {}
            _ => return Err(malformed("action")),
        }
        let jcs = canonical::jcs(value).map_err(|_| malformed("fields"))?;
        if jcs.len() > MAX_BODY_BYTES {
            return Err(malformed("too large"));
        }
        Ok(StationBindingChallenge {
            action,
            origin: origin.to_owned(),
            claims,
            account_id: account_id.to_owned(),
            genesis_hash,
            head,
            signer: signer.to_owned(),
            expected_binding,
            nonce,
            issued_at,
            expires_at,
            value: value.clone(),
            jcs,
        })
    }

    fn hash(o: &Map<String, Value>, key: &'static str) -> Result<Hash32, ReportRefusal> {
        str_field(o, key)
            .ok()
            .and_then(|h| Hash32::from_hex(h).ok())
            .ok_or(malformed(key))
    }

    /// The challenge object: what the Station stores and carries, and the
    /// body the manager signs.
    pub fn to_json(&self) -> Value {
        self.value.clone()
    }

    /// `jcs(challenge)`: what the verifier compares a proof's body with.
    pub fn jcs(&self) -> &str {
        &self.jcs
    }

    pub fn action(&self) -> BindingAction {
        self.action
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The Agora.Build sign-in it names: `issuer`, `subject`, `auth_time`.
    pub fn claims(&self) -> &AuthClaims {
        &self.claims
    }

    pub fn issuer(&self) -> &str {
        &self.claims.issuer
    }

    pub fn subject(&self) -> &str {
        &self.claims.subject
    }

    pub fn auth_time(&self) -> u64 {
        self.claims.auth_time
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    pub fn head(&self) -> Head {
        self.head
    }

    pub fn signer(&self) -> &str {
        &self.signer
    }

    pub fn expected_binding(&self) -> &ExpectedBinding {
        &self.expected_binding
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
}

// --------------------------------------------------------------- signer

/// A binding's signer at `log`'s head: a current native member
/// (`unknown_signer` otherwise: removed or never added, pending, a service
/// named as a member, `recovery`) holding `manage` at that head
/// (`not_a_manager`), with its `auth_key` as the list pins it.
fn manager_at_head(log: &Membership, signer: &str) -> Result<PublicKey, ReportRefusal> {
    let Some(Signer::Member(id)) = read_signer(signer) else {
        return Err(ReportRefusal::UnknownSigner);
    };
    let state = log
        .member(id)
        .filter(|state| state.status == MemberStatus::Active)
        .ok_or(ReportRefusal::UnknownSigner)?;
    if !matches!(state.member.kind, MemberKind::Native { .. }) {
        return Err(ReportRefusal::UnknownSigner);
    }
    if !state.member.is_manager() {
        return Err(ReportRefusal::NotAManager);
    }
    Ok(state.member.auth_key.clone())
}

/// A binding waiting for its signature, built by
/// [`station_binding_request`]: the challenge it checked, held as the body.
/// Immutable: a signature attached with [`finish`](Self::finish) is over
/// exactly this body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationBindingRequest {
    challenge: StationBindingChallenge,
    held: HeldBody,
}

impl StationBindingRequest {
    /// The challenge the body is (for the confirmation: the Station, the
    /// action, the R9 account, the Agora.Build accounts).
    pub fn challenge(&self) -> &StationBindingChallenge {
        &self.challenge
    }

    /// The body object.
    pub fn to_json(&self) -> Value {
        self.held.value.clone()
    }

    /// `jcs(body)`: the challenge's `jcs`.
    pub fn body_json(&self) -> &str {
        &self.held.jcs
    }

    /// `enc(["atem-station-binding-v1", jcs(body)])`: what the manager's
    /// key signs, with a fresh confirmation.
    pub fn signing_input(&self) -> SigningInput {
        self.held.signing_input()
    }

    /// The signer's key at the log's head, with its algorithm.
    pub fn signer_key(&self) -> &PublicKey {
        &self.held.signer_key
    }

    /// The proof: this body with `sig` (P-256 64-byte `r‖s`, either S,
    /// normalized to low S; or Ed25519), once it verifies under the
    /// signer's key over this body's signing input. A signature over any
    /// other body, under any other label or by any other key is
    /// `bad_signature`.
    pub fn finish(&self, sig: &[u8]) -> Result<SignedObject, ReportRefusal> {
        self.held.with_signature(sig)
    }
}

/// The request a manager signs for `challenge`, as `signer` (`member:<id>`,
/// the app itself) configured with the Station `station`, told the
/// Agora.Build sign-in `expected`, at `now_ms` on its clock.
///
/// The caller supplies none of what the body claims: the body is the
/// challenge, and every field is checked first. Refused, in this order
/// ([`BINDING_BUILD_ORDER`]): `signer` not `member:<id>`, `station` not an
/// origin, `expected` outside its grammar (`malformed`); `log` frozen
/// (`frozen`); the challenge's `account_id` or `genesis_hash` not the log's
/// (`wrong_account`); its `origin` not `station` normalized
/// (`origin_mismatch`); its `signer` not `signer` (`signer_mismatch`);
/// `signer` not a current native member (`unknown_signer`) or without
/// `manage` at the log's head (`not_a_manager`); its `head` beyond the
/// log's (`stale_log`: fetch first) or off its chain (`fork`); its
/// `issuer`, `subject` or `auth_time` not `expected`'s
/// (`binding_mismatch`); `now_ms` at or after its `expires_at`
/// (`expired`).
pub fn station_binding_request(
    log: &Membership,
    challenge: &StationBindingChallenge,
    signer: &str,
    station: &str,
    expected: &AuthClaims,
    now_ms: u64,
) -> Result<StationBindingRequest, ReportRefusal> {
    if !member_signer_ok(signer) {
        return Err(malformed("signer"));
    }
    let station = normalize_relay(station).map_err(|_| malformed("station"))?;
    expected.check()?;
    check_account(log, challenge.account_id(), challenge.genesis_hash())?;
    if challenge.origin() != station {
        return Err(ReportRefusal::OriginMismatch);
    }
    if challenge.signer() != signer {
        return Err(ReportRefusal::SignerMismatch);
    }
    let key = manager_at_head(log, signer)?;
    check_head(log, challenge.head())?;
    if challenge.claims() != expected {
        return Err(ReportRefusal::BindingMismatch);
    }
    if now_ms >= challenge.expires_at() {
        return Err(ReportRefusal::Expired);
    }
    let held = HeldBody::new(
        SignLabel::StationBinding,
        challenge.to_json(),
        challenge.head(),
        key,
    )?;
    debug_assert_eq!(held.jcs, challenge.jcs());
    Ok(StationBindingRequest {
        challenge: challenge.clone(),
        held,
    })
}

/// Signs `request` with `key` (the manager's own key behind `provider`) and
/// returns the proof. The provider sees purpose `StationBinding` in the
/// bindings: a fresh confirmation every time, never in the background; a
/// provider that declines is `signing_failed`. A key that isn't the
/// signer's key at the log's head is `bad_signature`.
pub fn sign_station_binding(
    provider: &dyn KeyProvider,
    key: &KeyId,
    request: &StationBindingRequest,
) -> Result<SignedObject, ReportRefusal> {
    let sig = crate::provider::sign(provider, key, &request.signing_input())
        .map_err(ReportRefusal::Signing)?;
    request.finish(&sig)
}

// --------------------------------------------------------- verification

/// A verified binding proof: what the Station's commit decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStationBinding {
    pub action: BindingAction,
    /// `member:<device_id>`.
    pub signer: String,
    /// The head the manager signed at: the verifier's head or an ancestor.
    pub head: Head,
    /// Whether `head` is the verifier's head. The Station requires it.
    pub at_head: bool,
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub issuer: String,
    pub subject: String,
    pub auth_time: u64,
    pub expected_binding: ExpectedBinding,
    pub nonce: [u8; NONCE_BYTES],
    pub expires_at: u64,
}

/// Verifies a proof (`{"body","sig"}` as received) against `log` at its
/// current head and the challenge the Station stored, at `now_ms` on its
/// clock. Membership and keys are read at the verifier's head, never the
/// proof's. In this order, the first failure is the code
/// ([`BINDING_VERIFY_ORDER`]): exactly a proof whose body reads as a
/// challenge (`malformed`); the log not frozen (`frozen`); `account_id` and
/// `genesis_hash` the log's (`wrong_account`); `signer` a current native
/// member (`unknown_signer`) holding `manage` at the verifier's head
/// (`not_a_manager`); `sig` by its `auth_key` under its pinned algorithm,
/// low S (`bad_signature`); `head` the log's head or an ancestor
/// (`stale_log` beyond it, `fork` off it); the body the stored challenge,
/// compared on `jcs` (`challenge_mismatch`); `now_ms` before `expires_at`
/// (`expired`).
pub fn verify_station_binding(
    log: &Membership,
    proof_json: &[u8],
    expected: &StationBindingChallenge,
    now_ms: u64,
) -> Result<VerifiedStationBinding, ReportRefusal> {
    let object = read_report(proof_json, SignLabel::StationBinding)?;
    let body = StationBindingChallenge::read(object.body())?;
    check_account(log, body.account_id(), body.genesis_hash())?;
    let key = manager_at_head(log, body.signer())?;
    object
        .verify(&key)
        .map_err(|_| ReportRefusal::BadSignature)?;
    let at_head = check_head(log, body.head())?;
    if !ct_eq(body.jcs().as_bytes(), expected.jcs().as_bytes()) {
        return Err(ReportRefusal::ChallengeMismatch);
    }
    if now_ms >= expected.expires_at() {
        return Err(ReportRefusal::Expired);
    }
    Ok(VerifiedStationBinding {
        action: body.action,
        signer: body.signer,
        head: body.head,
        at_head,
        account_id: body.account_id,
        genesis_hash: body.genesis_hash,
        issuer: body.claims.issuer,
        subject: body.claims.subject,
        auth_time: body.claims.auth_time,
        expected_binding: body.expected_binding,
        nonce: body.nonce,
        expires_at: body.expires_at,
    })
}

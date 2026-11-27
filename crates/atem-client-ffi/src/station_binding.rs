//! A native manager's Station binding proof (`atem_client::station_binding`;
//! delegated host-work III.5 (b), Atem's answer on #120 comment
//! 7207827118): the signed proof that binds, transfers or unbinds an R9
//! account's Agora.Build owner at a Station. It decides which Agora.Build
//! account's state controls whether that Station serves the account's
//! hosts; an unbind needs the same proof as a bind (owner decision
//! 2026-11-27; Auth/Portal's agreement pending, Portal #41 comment
//! 7208892757).
//!
//! - **The Station** mints the whole body, a single-use challenge, with
//!   `station_binding_challenge` (a fresh nonce; canonical JSON: store it,
//!   carry it) and verifies the answer with `verify_station_binding`
//!   against its log at its current head and the challenge it stored: a
//!   `VerifiedStationBinding` (**require `at_head`**), or `Report{code}`
//!   with the first failure in the order of Atem's answer (#120 comment
//!   7207827118, for Astation's agreement). Its token checks, the
//!   nonce's single use, a transfer's consent and the commit-time recheck
//!   stay its own.
//! - **The manager's app** reads the challenge it received
//!   (`parse_station_binding_challenge`, for the confirmation) and signs it
//!   with `sign_station_binding` (its own key through the app's provider),
//!   or, when its key answers later, builds a `StationBindingRequest`, has
//!   the input of its `sign_request()` signed and hands the signature to
//!   `finish`.
//!
//! The request takes nothing that matters from its caller: the body is the
//! challenge, and the core checks every field first against the app's
//! log, its own `member:` id, its configured Station and the Agora.Build
//! sign-in it was told (`AuthClaims`). **Never fill `expected` from the
//! challenge or anything the Station sent**: take it from the app's own
//! token, or, for a transfer, from what the user chose before the
//! challenge was fetched; else `binding_mismatch` can never fire. The
//! request takes no intended action: before it prompts, the app compares
//! the challenge's `action` (and, for a transfer, its
//! `expected_binding.owner`) with what the user started. A `service:`,
//! `host:` or `browser:` signer is `Report{malformed}` (the grammar is
//! `member:<device_id>` only), unlike the reports' `unknown_signer`. The
//! provider sees purpose
//! `StationBinding`: **a fresh confirmation every time**, never the
//! 5-minute reuse, never in the background; an owner who cancels gives
//! `signing_failed`. Show the Station (`origin`), the action, the R9
//! account (`account_id`), the Agora.Build account in `subject` (for a
//! transfer, the old owner too, `expected_binding.owner`), and the line
//! "This decides which Agora.Build account's state controls whether
//! <Station> serves this account's hosts." Fetch the challenge right before
//! the prompt: its lease is at most 30 s.
//!
//! Three points are Atem's proposals, for Astation's agreement: `owner` is
//! named in the `unbound` and `released` states too; a transfer's
//! `subject` is compared with the `subject` the app supplies (the new owner
//! it was shown), as every action's is; and both refusal orders are those
//! of Atem's answer.
use std::sync::Arc;

use atem_client::KeyId;
use atem_client::encoding::{Hash32, b64u};
use atem_client::member_report::ReportRefusal;
use atem_client::membership::Head;
use atem_client::provider::KeyProvider;
use atem_client::station_binding::{
    self as core, AuthClaims as CoreClaims, BindingAction as CoreAction, BindingRecord,
    ExpectedBinding as CoreExpected, StationBindingChallenge as CoreChallenge,
    VerifiedStationBinding as CoreVerified,
};

use crate::encoding::canonical;
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, object_json};
use crate::types::{
    AuthClaims, BindingAction, ExpectedBinding, LogHead, SignRequest, StationBindingChallenge,
    VerifiedStationBinding,
};

impl From<BindingAction> for CoreAction {
    fn from(a: BindingAction) -> Self {
        match a {
            BindingAction::Bind => CoreAction::Bind,
            BindingAction::Transfer => CoreAction::Transfer,
            BindingAction::Unbind => CoreAction::Unbind,
        }
    }
}

impl From<CoreAction> for BindingAction {
    fn from(a: CoreAction) -> Self {
        match a {
            CoreAction::Bind => BindingAction::Bind,
            CoreAction::Transfer => BindingAction::Transfer,
            CoreAction::Unbind => BindingAction::Unbind,
        }
    }
}

impl From<&ExpectedBinding> for CoreExpected {
    fn from(e: &ExpectedBinding) -> Self {
        let record = |binding_id: &String, version: &u64, owner: &String| BindingRecord {
            binding_id: binding_id.clone(),
            version: *version,
            owner: owner.clone(),
        };
        match e {
            ExpectedBinding::NeverBound => CoreExpected::NeverBound,
            ExpectedBinding::Bound {
                binding_id,
                version,
                owner,
            } => CoreExpected::Bound(record(binding_id, version, owner)),
            ExpectedBinding::Unbound {
                binding_id,
                version,
                owner,
            } => CoreExpected::Unbound(record(binding_id, version, owner)),
            ExpectedBinding::Released {
                binding_id,
                version,
                owner,
            } => CoreExpected::Released(record(binding_id, version, owner)),
        }
    }
}

impl From<&CoreExpected> for ExpectedBinding {
    fn from(e: &CoreExpected) -> Self {
        match e {
            CoreExpected::NeverBound => ExpectedBinding::NeverBound,
            CoreExpected::Bound(r) => ExpectedBinding::Bound {
                binding_id: r.binding_id.clone(),
                version: r.version,
                owner: r.owner.clone(),
            },
            CoreExpected::Unbound(r) => ExpectedBinding::Unbound {
                binding_id: r.binding_id.clone(),
                version: r.version,
                owner: r.owner.clone(),
            },
            CoreExpected::Released(r) => ExpectedBinding::Released {
                binding_id: r.binding_id.clone(),
                version: r.version,
                owner: r.owner.clone(),
            },
        }
    }
}

impl From<&AuthClaims> for CoreClaims {
    fn from(c: &AuthClaims) -> Self {
        CoreClaims {
            issuer: c.issuer.clone(),
            subject: c.subject.clone(),
            auth_time: c.auth_time,
        }
    }
}

fn malformed(what: &'static str) -> AtemError {
    AtemError::from(ReportRefusal::Malformed(what))
}

/// A fresh challenge (the Station's side) as canonical JSON: the action,
/// the Station's `origin` (normalized here), the Agora.Build sign-in it
/// verified (`claims`), the R9 account at its applied head (`account_id`,
/// `genesis_hash`, `head`), the manager (`signer`, `member:<device_id>`),
/// the record it expects to change, and the lease `0 < expires_at −
/// issued_at ≤ 30000` ms; the nonce is 32 bytes from the operating
/// system's CSPRNG. Anything outside its grammar or the per-action rules
/// is `Report{malformed}`. Store it: verification compares the proof's
/// body with exactly this challenge, and only the Station can make it
/// single use.
#[cfg_attr(feature = "uniffi", uniffi::export)]
#[allow(clippy::too_many_arguments)]
pub fn station_binding_challenge(
    action: BindingAction,
    origin: String,
    claims: AuthClaims,
    account_id: String,
    genesis_hash: String,
    head: LogHead,
    signer: String,
    expected_binding: ExpectedBinding,
    issued_at: u64,
    expires_at: u64,
) -> Result<String> {
    let genesis_hash = Hash32::from_hex(&genesis_hash).map_err(|_| malformed("genesis_hash"))?;
    let head = Head {
        seq: head.seq,
        hash: Hash32::from_hex(&head.hash).map_err(|_| malformed("head"))?,
    };
    if head.seq == 0 {
        return Err(malformed("head"));
    }
    let challenge = CoreChallenge::new(
        action.into(),
        &origin,
        &(&claims).into(),
        &account_id,
        genesis_hash,
        head,
        &signer,
        (&expected_binding).into(),
        issued_at,
        expires_at,
    )?;
    canonical(&challenge.to_json())
}

fn challenge_info(c: &CoreChallenge) -> StationBindingChallenge {
    StationBindingChallenge {
        action: c.action().into(),
        origin: c.origin().into(),
        issuer: c.issuer().into(),
        subject: c.subject().into(),
        auth_time: c.auth_time(),
        account_id: c.account_id().into(),
        genesis_hash: c.genesis_hash().to_hex(),
        head: c.head().into(),
        signer: c.signer().into(),
        expected_binding: c.expected_binding().into(),
        nonce: b64u(c.nonce()),
        issued_at: c.issued_at(),
        expires_at: c.expires_at(),
    }
}

/// A challenge's fields, read as the app and the Station read it (strict
/// I-JSON of at most 4,096 bytes, exactly its fifteen fields, each field's
/// grammar and the per-action rules): `Report{malformed}` otherwise.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_station_binding_challenge(challenge_json: String) -> Result<StationBindingChallenge> {
    Ok(challenge_info(&CoreChallenge::parse(
        challenge_json.as_bytes(),
    )?))
}

/// A binding proof waiting for its signature (an immutable handle). Built
/// from the app's log, the challenge it received, its own identity
/// (`signer`), its configured Station (`origin`), the Agora.Build sign-in
/// it was told (`expected`, never filled from the challenge), the key that will sign (`key_id`) and its
/// clock: the core checks the challenge then and holds it as the body.
/// `sign_request()` is what the key signs (purpose `StationBinding`, a
/// fresh confirmation, built inside the core from the held body);
/// `finish(signature)` attaches a signature to that body once it verifies
/// under the signer's key at the log's head, so a signature over any other
/// body, or by any other key, is `Report{bad_signature}`. Nothing changes
/// the held body.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct StationBindingRequest {
    request: core::StationBindingRequest,
    key_id: String,
}

impl StationBindingRequest {
    /// The request checked under the log's lock, which is released on
    /// return.
    pub(crate) fn build(
        log: &MembershipLog,
        challenge_json: &str,
        signer: &str,
        origin: &str,
        expected: &AuthClaims,
        key_id: String,
        now_ms: u64,
    ) -> Result<Self> {
        let challenge = CoreChallenge::parse(challenge_json.as_bytes())?;
        let request = core::station_binding_request(
            &log.lock(),
            &challenge,
            signer,
            origin,
            &expected.into(),
            now_ms,
        )?;
        Ok(StationBindingRequest { request, key_id })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl StationBindingRequest {
    /// The request for `challenge_json` as `signer` (`member:<id>`, this
    /// app) with the Station `origin` configured, told the sign-in
    /// `expected`, at `now_ms`. Refused (`Report{code}`), in this order: a
    /// challenge that doesn't read, a `signer` that isn't `member:<id>`, an
    /// `origin` or `expected` outside its grammar (`malformed`); the log
    /// frozen (`frozen`); a challenge for another R9 account
    /// (`wrong_account`), another Station (`origin_mismatch`) or another
    /// signer (`signer_mismatch`); a signer that isn't a current native
    /// member (`unknown_signer`) or holds no `manage` at the log's head
    /// (`not_a_manager`); a head beyond the log's (`stale_log`: fetch
    /// first) or off its chain (`fork`); an `issuer`, `subject` or
    /// `auth_time` other than `expected` (`binding_mismatch`); the
    /// challenge expired (`expired`).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(
        log: Arc<MembershipLog>,
        challenge_json: String,
        signer: String,
        origin: String,
        expected: AuthClaims,
        key_id: String,
        now_ms: u64,
    ) -> Result<Arc<Self>> {
        Self::build(
            &log,
            &challenge_json,
            &signer,
            &origin,
            &expected,
            key_id,
            now_ms,
        )
        .map(Arc::new)
    }

    /// What `key_id` signs: purpose `StationBinding` (a fresh confirmation),
    /// label `atem-station-binding-v1`, `input` its signing input and
    /// `body_json` the held body (the challenge's canonical JSON).
    pub fn sign_request(&self) -> SignRequest {
        crate::provider::sign_request(
            &KeyId::new(self.key_id.clone()),
            &self.request.signing_input(),
        )
    }

    /// The held body (canonical JSON), read only.
    pub fn body_json(&self) -> String {
        self.request.body_json().to_owned()
    }

    /// The challenge the body is, for the confirmation.
    pub fn challenge(&self) -> StationBindingChallenge {
        challenge_info(self.request.challenge())
    }

    /// The proof (canonical JSON, `{"body":<held body>,"sig":…}`) with
    /// `signature` (P-256 64-byte `r‖s`, either S, normalized to low S; or
    /// Ed25519) once it verifies under the signer's key over the held body
    /// (`Report{bad_signature}` otherwise).
    pub fn finish(&self, signature: Vec<u8>) -> Result<String> {
        Ok(object_json(&self.request.finish(&signature)?))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_station_binding_with(
    provider: &dyn KeyProvider,
    log: &MembershipLog,
    challenge_json: &str,
    signer: &str,
    origin: &str,
    expected: &AuthClaims,
    key_id: String,
    now_ms: u64,
) -> Result<String> {
    // Built first: no binding lock is held while the owner confirms.
    let request = StationBindingRequest::build(
        log,
        challenge_json,
        signer,
        origin,
        expected,
        key_id,
        now_ms,
    )?;
    let proof = core::sign_station_binding(
        provider,
        &KeyId::new(request.key_id.clone()),
        &request.request,
    )?;
    Ok(object_json(&proof))
}

/// `StationBindingRequest::new`, signed at once by `key_id` through the
/// app's provider (purpose `StationBinding`, a fresh confirmation): the
/// proof as canonical JSON. The request's refusals, then
/// `Report{signing_failed}` when the provider declines (the owner
/// cancelled) or fails, and `Report{bad_signature}` when `key_id` isn't the
/// signer's key in the log.
#[cfg(feature = "uniffi")]
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_station_binding(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    log: Arc<MembershipLog>,
    challenge_json: String,
    signer: String,
    origin: String,
    expected: AuthClaims,
    key_id: String,
    now_ms: u64,
) -> Result<String> {
    sign_station_binding_with(
        &crate::provider::Platform(provider),
        &log,
        &challenge_json,
        &signer,
        &origin,
        &expected,
        key_id,
        now_ms,
    )
}

/// Verifies `proof_json` against `log` at its current head and the
/// challenge the Station stored (`expected_challenge_json`, as
/// `station_binding_challenge` made it), at `now_ms` on the Station's
/// clock. Membership and keys are read at the verifier's head. A refusal is
/// `Report{code}`, the first failure of `malformed`, `frozen`,
/// `wrong_account`, `unknown_signer`, `not_a_manager` (no `manage` at the
/// verifier's head), `bad_signature`, `stale_log`, `fork`,
/// `challenge_mismatch` (the body isn't the stored challenge, compared on
/// its canonical JSON), `expired`. An expected challenge that doesn't read
/// is the caller's input: `Invalid{malformed}`. The Station requires
/// `at_head`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_station_binding(
    log: Arc<MembershipLog>,
    proof_json: String,
    expected_challenge_json: String,
    now_ms: u64,
) -> Result<VerifiedStationBinding> {
    let expected = CoreChallenge::parse(expected_challenge_json.as_bytes())
        .map_err(|e| AtemError::malformed(&format!("expected challenge: {e}")))?;
    let verified =
        core::verify_station_binding(&log.lock(), proof_json.as_bytes(), &expected, now_ms)?;
    Ok(verified_info(verified))
}

fn verified_info(v: CoreVerified) -> VerifiedStationBinding {
    VerifiedStationBinding {
        action: v.action.into(),
        signer: v.signer,
        head: v.head.into(),
        at_head: v.at_head,
        account_id: v.account_id,
        genesis_hash: v.genesis_hash.to_hex(),
        issuer: v.issuer,
        subject: v.subject,
        auth_time: v.auth_time,
        expected_binding: (&v.expected_binding).into(),
        nonce: b64u(&v.nonce),
        expires_at: v.expires_at,
    }
}

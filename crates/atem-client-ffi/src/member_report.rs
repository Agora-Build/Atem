//! A member's signed verifier report (`atem_client::member_report`;
//! session-v1 R9.2 "How a verifier reports itself", agreed for
//! implementation on Astation #101): how a native app, an SDK process or a
//! service bot tells a signer which device-list verifier its loaded core
//! runs. Hosts report theirs in the r9 `welcome`.
//!
//! - **The minter** (the signer, or a Station on its behalf) issues a
//!   single-use challenge with `verifier_report_challenge` (a fresh nonce;
//!   canonical JSON: store it, carry it), and verifies the answer with
//!   `verify_verifier_report` against its log at its current head and the
//!   challenge it stored: a `VerifiedReport`, or `Report{code}` with the
//!   first failure in the agreed order.
//! - **The reporter** answers with `sign_verifier_report` (its own key
//!   through the app's provider), or, when its key answers later
//!   (WebCrypto, a KMS), builds a `VerifierReportRequest`, has the input of
//!   its `sign_request()` signed and hands the signature to `finish`.
//!
//! Nothing that matters comes from the caller: the head, account and
//! genesis are the reporter's log's, the inventory is this binding's
//! `verifier_inventory()`, and the process is `verifier_report_process()`,
//! drawn once per loaded core (per process image, per WASM instance). No
//! call takes an inventory, a process or a body back. The provider sees
//! purpose `VerifierReport`, which never prompts: it signs only a key that
//! needs no interaction, else it returns `ProviderError::Cancelled` and the
//! report fails (`signing_failed`); nothing creates, rekeys or enrolls a
//! key. A provider signs such a request without a prompt only once it
//! checked that its `label` is `atem-verifier-report-v1`, and never another
//! label so. The process is per loaded image: a child forked without
//! `exec` shares its parent's.
//!
//! [`signer`] is a native manager's signed report of its control-record
//! signing journal on the same core (host-work-v1 §11.1 "The signer
//! report", Astation #114 item 4).
use std::sync::Arc;

use atem_client::KeyId;
use atem_client::encoding::b64u;
use atem_client::member_report::{
    self as core, ReportChallenge, SignerKind, VerifiedReport as CoreVerified, VerifierReportBody,
};
use atem_client::provider::KeyProvider;

use crate::encoding::canonical;
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, object_json};
use crate::types::{
    ReportSignerKind, SignRequest, VerifiedReport, VerifierInventory, VerifierReportChallenge,
};

pub mod signer;

/// A fresh challenge (the minter's side) as canonical JSON: `signer`
/// (`member:<id>` or `service:<id>`), `slot` (1–128 bytes of
/// `[A-Za-z0-9._:-]`), `origin` (the minter's Station, normalized here),
/// `connection` (the slot's generation, 1 to 2^53 − 1), and the lease
/// `0 < expires_at − issued_at ≤ 30000` ms; the nonce is 32 bytes from the
/// operating system's CSPRNG. Anything else is `Report{malformed}`. Store
/// it: verification compares the report with exactly this challenge, and
/// only the minter can make it single use.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verifier_report_challenge(
    signer: String,
    slot: String,
    origin: String,
    connection: u64,
    issued_at: u64,
    expires_at: u64,
) -> Result<String> {
    let challenge =
        ReportChallenge::new(&signer, &slot, &origin, connection, issued_at, expires_at)?;
    canonical(&challenge.to_json())
}

/// A challenge's fields, read as the reporter and the verifier read it
/// (strict I-JSON of at most 4,096 bytes, exactly its seven fields, each
/// field's grammar): `Report{malformed}` otherwise.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_verifier_report_challenge(challenge_json: String) -> Result<VerifierReportChallenge> {
    let c = ReportChallenge::parse(challenge_json.as_bytes())?;
    Ok(VerifierReportChallenge {
        signer: c.signer().into(),
        slot: c.slot().into(),
        origin: c.origin().into(),
        connection: c.connection(),
        nonce: b64u(c.nonce()),
        issued_at: c.issued_at(),
        expires_at: c.expires_at(),
    })
}

/// This loaded core's process generation (base64url, 16 bytes): the
/// `process` of every report it builds, for logs. Set by nothing.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verifier_report_process() -> String {
    b64u(&core::process_generation())
}

/// A report waiting for its signature (an immutable handle). Built from
/// the reporter's log, the challenge it received, its own identity
/// (`signer`), its configured `slot` and Station (`origin`), the key that
/// will sign (`key_id`) and its clock: the core builds the body then and
/// holds it. `sign_request()` is what the key signs (purpose
/// `VerifierReport`, built inside the core from the held body);
/// `finish(signature)` attaches a signature to that body once it verifies
/// under the signer's key at the log's head, so a signature over any other
/// body, or by any other key, is `Report{bad_signature}`. Nothing changes
/// the held body; finishing twice gives the same report.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct VerifierReportRequest {
    body: VerifierReportBody,
    key_id: String,
}

impl VerifierReportRequest {
    /// The body built under the log's lock, which is released on return.
    pub(crate) fn build(
        log: &MembershipLog,
        challenge_json: &str,
        signer: &str,
        slot: &str,
        origin: &str,
        key_id: String,
        now_ms: u64,
    ) -> Result<Self> {
        let challenge = ReportChallenge::parse(challenge_json.as_bytes())?;
        let body =
            core::verifier_report_body(&log.lock(), &challenge, signer, slot, origin, now_ms)?;
        Ok(VerifierReportRequest { body, key_id })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl VerifierReportRequest {
    /// The request for `challenge_json` as `signer` (`member:<id>` or
    /// `service:<id>`, this reporter) in `slot` with the Station `origin`
    /// configured, at `now_ms`. Refused (`Report{code}`): a challenge that
    /// doesn't read, or a `signer`, `slot` or `origin` outside their grammar
    /// (`malformed`); the log frozen (`frozen`); a challenge for another
    /// Station (`origin_mismatch`), signer (`signer_mismatch`) or slot
    /// (`slot_mismatch`); a signer that isn't a current native member or
    /// service (`unknown_signer`), a service expired (`signer_expired`); the
    /// challenge expired (`expired`).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(
        log: Arc<MembershipLog>,
        challenge_json: String,
        signer: String,
        slot: String,
        origin: String,
        key_id: String,
        now_ms: u64,
    ) -> Result<Arc<Self>> {
        Self::build(
            &log,
            &challenge_json,
            &signer,
            &slot,
            &origin,
            key_id,
            now_ms,
        )
        .map(Arc::new)
    }

    /// What `key_id` signs: purpose `VerifierReport` (no confirmation),
    /// label `atem-verifier-report-v1`, `input` its signing input and
    /// `body_json` the held body.
    pub fn sign_request(&self) -> SignRequest {
        crate::provider::sign_request(&KeyId::new(self.key_id.clone()), &self.body.signing_input())
    }

    /// The held body (canonical JSON), read only.
    pub fn body_json(&self) -> String {
        self.body.jcs().to_owned()
    }

    /// The report (canonical JSON, `{"body":<held body>,"sig":…}`) with
    /// `signature` (P-256 64-byte `r‖s`, either S, normalized to low S; or
    /// Ed25519) once it verifies under the signer's key over the held body
    /// (`Report{bad_signature}` otherwise).
    pub fn finish(&self, signature: Vec<u8>) -> Result<String> {
        Ok(object_json(&self.body.with_signature(&signature)?))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_verifier_report_with(
    provider: &dyn KeyProvider,
    log: &MembershipLog,
    challenge_json: &str,
    signer: &str,
    slot: &str,
    origin: &str,
    key_id: String,
    now_ms: u64,
) -> Result<String> {
    // Built first: no binding lock is held while the provider signs.
    let request =
        VerifierReportRequest::build(log, challenge_json, signer, slot, origin, key_id, now_ms)?;
    let report =
        core::sign_verifier_report(provider, &KeyId::new(request.key_id.clone()), &request.body)?;
    Ok(object_json(&report))
}

/// `VerifierReportRequest::new`, signed at once by `key_id` through the
/// app's provider (purpose `VerifierReport`, which never prompts): the
/// report as canonical JSON. The request's refusals, then
/// `Report{signing_failed}` when the provider declines or fails, and
/// `Report{bad_signature}` when `key_id` isn't the signer's key in the log.
#[cfg(feature = "uniffi")]
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_verifier_report(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    log: Arc<MembershipLog>,
    challenge_json: String,
    signer: String,
    slot: String,
    origin: String,
    key_id: String,
    now_ms: u64,
) -> Result<String> {
    sign_verifier_report_with(
        &crate::provider::Platform(provider),
        &log,
        &challenge_json,
        &signer,
        &slot,
        &origin,
        key_id,
        now_ms,
    )
}

/// Verifies `report_json` against `log` at its current head and the
/// challenge the minter stored (`expected_challenge_json`, as
/// `verifier_report_challenge` made it), at `now_ms` on the verifier's
/// clock. Membership and keys are read at the verifier's head. A refusal is
/// `Report{code}`, the first failure of `malformed`, `frozen`,
/// `wrong_account`, `unknown_signer`, `signer_expired`, `bad_signature`,
/// `stale_log`, `fork`, `signer_mismatch`, `slot_mismatch`,
/// `challenge_mismatch`, `expired`: a report valid for another member or
/// slot fails. An expected challenge that doesn't read is the caller's
/// input: `Invalid{malformed}`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_verifier_report(
    log: Arc<MembershipLog>,
    report_json: String,
    expected_challenge_json: String,
    now_ms: u64,
) -> Result<VerifiedReport> {
    let expected = ReportChallenge::parse(expected_challenge_json.as_bytes())
        .map_err(|e| AtemError::malformed(&format!("expected challenge: {e}")))?;
    let verified =
        core::verify_verifier_report(&log.lock(), report_json.as_bytes(), &expected, now_ms)?;
    Ok(verified_info(verified))
}

fn verified_info(v: CoreVerified) -> VerifiedReport {
    VerifiedReport {
        signer: v.signer,
        kind: match v.kind {
            SignerKind::Native => ReportSignerKind::Native,
            SignerKind::Service => ReportSignerKind::Service,
        },
        slot: v.slot,
        process: b64u(&v.process),
        connection: v.connection,
        head: v.head.into(),
        at_head: v.at_head,
        inventory: VerifierInventory::from(&v.inventory),
        expires_at: v.expires_at,
    }
}

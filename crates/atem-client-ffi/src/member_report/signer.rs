//! A native manager's signed report of its control-record signing journal
//! (`atem_client::member_report`'s signer report; host-work-v1 §11.1 "The
//! signer report", agreed with Astation, #114 comment 7089435073), for a
//! Station recovering from a rollback. Version 2: the report commits to its
//! journal's process roster (Astation #114 comment 7208700195); v1 is
//! refused as `Report{malformed}`.
//!
//! - **The minter** (the Station) issues a single-use challenge with
//!   `signer_report_challenge` (a fresh nonce, the recovery it collects
//!   for; canonical JSON: store it, carry it), and verifies the answer with
//!   `verify_signer_report` against its log at its current head, the
//!   challenge it stored, the signed records and the roster exported with
//!   the report: a `VerifiedSignerReport`, or `Report{code}` with the first
//!   failure in the agreed order.
//! - **The reporter**, under its journal adapter's lock and barrier (B1 to
//!   B6, the app's), hands the journal's own bodies and process roster
//!   (`SignerJournalView`: every process generation attached to the
//!   journal, this loaded core's own among them) to `sign_signer_report`
//!   (its own key through the app's provider), or,
//!   when its key answers later, builds a `SignerReportRequest`, has the
//!   input of its `sign_request()` signed and hands the signature to
//!   `finish`. It selects the plan's records and drafts, and checks its
//!   barrier before drafting or signing, with `signer_report_plan_record`:
//!   the rule the request reads a journal's bodies by, typed.
//!
//! Nothing that matters comes from the caller: the head, account and
//! genesis are the reporter's log's, the process is
//! `verifier_report_process()`, the challenge and its recovery are echoed,
//! and the counts and set hashes are computed from the bodies. No call
//! takes a hash, a process or a body back. The provider sees purpose
//! `SignerReport`: a fresh confirmation of the body (the plan, the origin,
//! the counts, and that the barrier holds this device's stops until the
//! plan ends), never in the background; an owner who cancels gives
//! `signing_failed`.
//!
//! Five points the agreed text leaves open (a `member:`-only challenge
//! signer, the builder's `now_ms`, a service's plan records `revoke` and
//! `interrupt_running` only, one body both a record and a draft, `since`
//! compared with nothing) are Atem's readings, agreed with Astation on
//! #114 comment 7093796254 (the core module's doc lists them).
//!
//! The report proves its signature and that the export matches it:
//! consistency only, never completeness of anything outside the journal. A
//! body the journal holds as `signing` with no saved signature is in its
//! `records` and can't be exported as signed, so its report stays
//! `records_mismatch`. A verified roster says the signer attested that
//! these processes attached to journal `id` (your adapter's word under B6,
//! as strong as `records`): a displaced process P of member M is accounted
//! for by a verified report R iff R's signer is M and P is in R's
//! `processes`.
use std::sync::Arc;

use atem_client::KeyId;
use atem_client::encoding::{b64u, b64u_decode_array};
use atem_client::member_report::{
    self as core, JOURNAL_ID_BYTES, JournalSummary, JournalView, PlanRecord, RecoveryPlan,
    ReportRefusal, SignerReportBody, SignerReportChallenge as CoreChallenge,
    VerifiedSignerReport as CoreVerified,
};
use atem_client::provider::KeyProvider;
use serde_json::json;

use crate::encoding::canonical;
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, object_json};
use crate::types::{
    SignRequest, SignerJournalView, SignerPlanRecord, SignerReportChallenge, SignerReportJournal,
    SignerReportRecovery, VerifiedSignerReport,
};

/// The recovery, read with the core's own grammar (`Report{malformed}`).
fn recovery_of(r: &SignerReportRecovery) -> Result<RecoveryPlan> {
    Ok(RecoveryPlan::from_json(&json!({
        "generation": r.generation,
        "plan_id": r.plan_id,
        "candidate_feed_id": r.candidate_feed_id,
        "source_hash": r.source_hash,
        "evidence_hash": r.evidence_hash,
    }))?)
}

fn recovery_info(r: &RecoveryPlan) -> SignerReportRecovery {
    SignerReportRecovery {
        generation: r.generation().to_string(),
        plan_id: r.plan_id().into(),
        candidate_feed_id: r.candidate_feed_id().into(),
        source_hash: r.source_hash().to_hex(),
        evidence_hash: r.evidence_hash().to_hex(),
    }
}

/// The journal view, its `id` 16 bytes of base64url (`Report{malformed}`
/// otherwise; the core checks the rest, the roster included).
fn journal_of(j: &SignerJournalView) -> Result<JournalView> {
    let id = b64u_decode_array::<JOURNAL_ID_BYTES>(&j.id)
        .map_err(|_| AtemError::from(ReportRefusal::Malformed("journal.id")))?;
    Ok(JournalView {
        id,
        since: j.since,
        revision: j.revision,
        records: j.records.clone(),
        drafts: j.drafts.clone(),
        processes: j.processes.clone(),
    })
}

fn journal_info(j: &JournalSummary) -> SignerReportJournal {
    SignerReportJournal {
        id: b64u(&j.id),
        since: j.since,
        revision: j.revision,
        records: j.records,
        records_hash: j.records_hash.to_hex(),
        drafts: j.drafts,
        drafts_hash: j.drafts_hash.to_hex(),
        processes: j.processes,
        processes_hash: j.processes_hash.to_hex(),
    }
}

/// A fresh challenge (the minter's side) as canonical JSON: `signer`
/// (`member:<device_id>`, a native member), `slot` (1–128 bytes of
/// `[A-Za-z0-9._:-]`), `origin` (the minter's Station, normalized here),
/// `connection` (1 to 2^53 − 1), the lease `0 < expires_at − issued_at ≤
/// 30000` ms and the `recovery` it collects for; the nonce is 32 bytes
/// from the operating system's CSPRNG. Anything else is
/// `Report{malformed}`. Store it: verification compares the report with
/// exactly this challenge, and only the minter can make it single use.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn signer_report_challenge(
    signer: String,
    slot: String,
    origin: String,
    connection: u64,
    issued_at: u64,
    expires_at: u64,
    recovery: SignerReportRecovery,
) -> Result<String> {
    let challenge = CoreChallenge::new(
        &signer,
        &slot,
        &origin,
        connection,
        issued_at,
        expires_at,
        recovery_of(&recovery)?,
    )?;
    canonical(&challenge.to_json())
}

/// A challenge's fields, read as the reporter and the verifier read it
/// (strict I-JSON of at most 4,096 bytes, exactly its eight fields, each
/// field's grammar): `Report{malformed}` otherwise.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_signer_report_challenge(challenge_json: String) -> Result<SignerReportChallenge> {
    let c = CoreChallenge::parse(challenge_json.as_bytes())?;
    Ok(SignerReportChallenge {
        signer: c.signer().into(),
        slot: c.slot().into(),
        origin: c.origin().into(),
        connection: c.connection(),
        nonce: b64u(c.nonce()),
        issued_at: c.issued_at(),
        expires_at: c.expires_at(),
        recovery: recovery_info(c.recovery()),
    })
}

/// The plan predicate (Astation's ask, #114 comment 7093796254): whether
/// `body_json`, a control record's body as your journal holds it, is one
/// of the plan's records for `member` (`member:<device_id>`) at `origin`
/// (the challenge's, exactly as `normalize_relay` writes it), the account
/// and genesis `log`'s. It is the core's one rule, the one
/// `SignerReportRequest` reads a journal's bodies by: a body answered
/// `InPlan` is one the request takes in `records` or `drafts`; anything
/// else refuses the request. So your adapter selects its records and
/// drafts, and checks its barrier before drafting or signing, by the
/// builder's own rule. In this order: another account, genesis or signer
/// (another member, or the principal's own key) is `NotInPlan{reason}`;
/// this member's `cover`, `hold` or `release` is `Report{malformed}` (a
/// native manager signs none, so your journal never holds one; never skip
/// it); a service's `revoke` or `interrupt_running` at another origin is
/// `NotInPlan{another_origin}`; a `host:` principal's
/// `interrupt_running`, which names no origin, is `InPlan` at every
/// origin. `Report{malformed}` too for a `member` that isn't
/// `member:<id>`, an `origin` not in its exact form, and a body that isn't
/// a control record's (read as the request reads one). Bodies only: the
/// list's freeze and the member's standing change no answer. Which bodies
/// are `InPlan` is the agreed B2 rule with reading (c); Atem's reading,
/// agreed with Astation (Astation #114 comment 7209301522): another account,
/// genesis or signer as `NotInPlan{reason}` (never `Report{malformed}`),
/// the order account, genesis, signer, action, origin, and the four
/// reason codes.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn signer_report_plan_record(
    log: Arc<MembershipLog>,
    body_json: String,
    member: String,
    origin: String,
) -> Result<SignerPlanRecord> {
    let answer = core::signer_report_plan_record(&log.lock(), &body_json, &member, &origin)?;
    Ok(match answer {
        PlanRecord::InPlan => SignerPlanRecord::InPlan,
        PlanRecord::NotInPlan(why) => SignerPlanRecord::NotInPlan {
            reason: why.code().into(),
        },
    })
}

/// A signer report waiting for its signature (an immutable handle). Built
/// from the reporter's log, the challenge it received, its own identity
/// (`signer`), its configured `slot` and Station (`origin`), its journal's
/// view (`journal`), the key that will sign (`key_id`) and its clock: the
/// core builds the body then and holds it. `sign_request()` is what the key
/// signs (purpose `SignerReport`, a fresh confirmation, built inside the
/// core from the held body); `finish(signature)` attaches a signature to
/// that body once it verifies under the signer's key at the log's head, so
/// a signature over any other body, or by any other key, is
/// `Report{bad_signature}`. Nothing changes the held body.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SignerReportRequest {
    body: SignerReportBody,
    key_id: String,
}

impl SignerReportRequest {
    /// The body built under the log's lock, which is released on return.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        log: &MembershipLog,
        challenge_json: &str,
        signer: &str,
        slot: &str,
        origin: &str,
        journal: &SignerJournalView,
        key_id: String,
        now_ms: u64,
    ) -> Result<Self> {
        let challenge = CoreChallenge::parse(challenge_json.as_bytes())?;
        let journal = journal_of(journal)?;
        let body = core::signer_report_body(
            &log.lock(),
            &challenge,
            signer,
            slot,
            origin,
            &journal,
            now_ms,
        )?;
        Ok(SignerReportRequest { body, key_id })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SignerReportRequest {
    /// The request for `challenge_json` as `signer` (`member:<id>`, this
    /// reporter) in `slot` with the Station `origin` configured, from
    /// `journal`, at `now_ms`. Refused (`Report{code}`): a challenge that
    /// doesn't read, a `signer` that isn't `member:<id>`, a `slot` or
    /// `origin` outside its grammar (`malformed`); the log frozen
    /// (`frozen`); a challenge for another Station (`origin_mismatch`),
    /// signer (`signer_mismatch`) or slot (`slot_mismatch`); a signer that
    /// isn't a current native member (`unknown_signer`) or never held
    /// `manage` (`not_a_manager`); the challenge expired (`expired`); then
    /// the journal: an `id` that isn't 16 bytes of base64url, `since` 0 or
    /// `revision` beyond 2^53 − 1, a body that isn't one of the plan's
    /// records by this member, a body twice in a set, then a roster without
    /// this loaded core's own process (`verifier_report_process()`), with
    /// an id that isn't 16 bytes of base64url, an id twice, or more than
    /// 4,096 ids (`malformed`).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log: Arc<MembershipLog>,
        challenge_json: String,
        signer: String,
        slot: String,
        origin: String,
        journal: SignerJournalView,
        key_id: String,
        now_ms: u64,
    ) -> Result<Arc<Self>> {
        Self::build(
            &log,
            &challenge_json,
            &signer,
            &slot,
            &origin,
            &journal,
            key_id,
            now_ms,
        )
        .map(Arc::new)
    }

    /// What `key_id` signs: purpose `SignerReport` (a fresh confirmation),
    /// label `atem-signer-report-v2`, `input` its signing input and
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
pub(crate) fn sign_signer_report_with(
    provider: &dyn KeyProvider,
    log: &MembershipLog,
    challenge_json: &str,
    signer: &str,
    slot: &str,
    origin: &str,
    journal: &SignerJournalView,
    key_id: String,
    now_ms: u64,
) -> Result<String> {
    // Built first: no binding lock is held while the owner confirms.
    let request = SignerReportRequest::build(
        log,
        challenge_json,
        signer,
        slot,
        origin,
        journal,
        key_id,
        now_ms,
    )?;
    let report =
        core::sign_signer_report(provider, &KeyId::new(request.key_id.clone()), &request.body)?;
    Ok(object_json(&report))
}

/// `SignerReportRequest::new`, signed at once by `key_id` through the
/// app's provider (purpose `SignerReport`, a fresh confirmation): the
/// report as canonical JSON. The request's refusals, then
/// `Report{signing_failed}` when the provider declines (the owner
/// cancelled) or fails, and `Report{bad_signature}` when `key_id` isn't
/// the signer's key in the log.
#[cfg(feature = "uniffi")]
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_signer_report(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    log: Arc<MembershipLog>,
    challenge_json: String,
    signer: String,
    slot: String,
    origin: String,
    journal: SignerJournalView,
    key_id: String,
    now_ms: u64,
) -> Result<String> {
    sign_signer_report_with(
        &crate::provider::Platform(provider),
        &log,
        &challenge_json,
        &signer,
        &slot,
        &origin,
        &journal,
        key_id,
        now_ms,
    )
}

/// Verifies `report_json` against `log` at its current head, the challenge
/// the minter stored (`expected_challenge_json`, as
/// `signer_report_challenge` made it), the signed records exported with
/// the report (`exported_records_json`, each `{"body","sig"}`) and its
/// exported roster (`exported_processes`, each process generation
/// base64url), at `now_ms` on the verifier's clock. Membership and keys
/// are read at the verifier's head. A refusal is `Report{code}`, the first
/// failure of `malformed`, `frozen`, `wrong_account`, `unknown_signer`,
/// `not_a_manager`, `bad_signature`, `stale_log`, `fork`,
/// `signer_mismatch`, `slot_mismatch`, `challenge_mismatch`,
/// `recovery_mismatch`, `records_mismatch`, `processes_mismatch` (an
/// exported roster that isn't exactly the report's: a malformed id, a
/// duplicate, another count or `processes_hash`, or one without the
/// report's own `process`), `expired`. A v1 report is `malformed`. An
/// expected challenge that doesn't read is the caller's input:
/// `Invalid{malformed}`. Consistency only: never completeness of anything
/// outside the journal.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_signer_report(
    log: Arc<MembershipLog>,
    report_json: String,
    expected_challenge_json: String,
    exported_records_json: Vec<String>,
    exported_processes: Vec<String>,
    now_ms: u64,
) -> Result<VerifiedSignerReport> {
    let expected = CoreChallenge::parse(expected_challenge_json.as_bytes())
        .map_err(|e| AtemError::malformed(&format!("expected challenge: {e}")))?;
    let verified = core::verify_signer_report(
        &log.lock(),
        report_json.as_bytes(),
        &expected,
        &exported_records_json,
        &exported_processes,
        now_ms,
    )?;
    Ok(verified_info(verified))
}

fn verified_info(v: CoreVerified) -> VerifiedSignerReport {
    VerifiedSignerReport {
        signer: v.signer,
        slot: v.slot,
        process: b64u(&v.process),
        connection: v.connection,
        head: v.head.into(),
        at_head: v.at_head,
        recovery: recovery_info(&v.recovery),
        journal: journal_info(&v.journal),
        records: v.records.iter().map(|r| object_json(r.object())).collect(),
        processes: v.processes.iter().map(|p| b64u(p)).collect(),
    }
}

//! A native manager's signed report of its control-record signing journal
//! (host-work-v1 §11.1 "The signer report"; Astation #114 item 4, agreed
//! for implementation on #114 comment 7089435073): the second report kind
//! on the verifier report's core.
//!
//! When a Station recovers from a rollback it publishes a replacement feed
//! (§11.1 "Resets"). Before that, every native manager that could have
//! signed one of the plan's stops reports its signing journal, so the
//! snapshot holds every stop that manager can have signed. The author's own
//! device holds a durable barrier from its report until the plan ends (B1
//! to B6). The journal, its lock, the barrier, the report's exposure and
//! the publication are the adapter's (Astation's); this module is the
//! shared primitive only:
//!
//! - the minter (the Station) issues and stores a single-use
//!   [`SignerReportChallenge`]: the verifier report's challenge `{signer,
//!   slot, origin, connection, nonce, issued_at, expires_at}`, its signer a
//!   `member:<id>`, plus the plan it collects for, `recovery{generation,
//!   plan_id, candidate_feed_id, source_hash, evidence_hash}`;
//! - the reporter's adapter, under its journal lock, hands
//!   [`signer_report_body`] the journal's own bodies ([`JournalView`]): the
//!   plan's records in `signing` or `signed`, and its drafts. The builder
//!   reads each strictly and computes the counts and the set hashes itself
//!   (the caller supplies no hash). The body
//!   `{"type":"atem-signer-report","v":1,"account_id","genesis_hash",
//!   "head":{"seq","hash"},"signer","slot","process","challenge":{"origin",
//!   "connection","nonce","issued_at","expires_at"},"recovery":{…},
//!   "journal":{"id","since","revision","records","records_hash","drafts",
//!   "drafts_hash"}}` is signed over `enc(["atem-signer-report-v1",
//!   jcs(body)])` by the manager's own `auth_key`, with a fresh
//!   confirmation ([`sign_signer_report`], or
//!   [`SignerReportBody::with_signature`] for a key that answers later);
//! - the Station verifies it with [`verify_signer_report`] against its log
//!   at its current head, the challenge it stored and the signed records
//!   exported with the report.
//!
//! **The plan's records** (B2): a control-record body this member signs
//! (`signer` `member:<id>`), of this account and genesis, that is a
//! service's `revoke` or `interrupt_running` naming the challenge's origin,
//! or a host sender's `interrupt_running` (`host:<host_id>`), which names no
//! origin: any Station of the account may carry it. A service's records at
//! another origin aren't the plan's. [`signer_report_plan_record`] exposes
//! that rule, typed ([`PlanRecord`], [`OutOfPlan`]), so an adapter selects
//! its records and drafts, and checks its barrier, by the builder's own
//! rule (Astation's ask on #114 comment 7093796254): one implementation,
//! which the builder and the verifier's export check call too. Its typed
//! answer's reasons and order are Atem's reading, for Astation's
//! confirmation (asked on Astation #114).
//!
//! **Atem's readings, agreed with Astation, #114 comment 7093796254** (the
//! agreed text left them open; each is fail-closed):
//! - (a) a challenge's `signer` is `member:<id>` only: a `service:` one is
//!   `malformed` when read (a report body naming a service, a host, a
//!   grant or `recovery` is `unknown_signer`, as agreed);
//! - (b) the builder also takes `now_ms` and refuses an expired challenge,
//!   as the verifier report's builder does;
//! - (c) a service's records of the plan are its `revoke` and
//!   `interrupt_running` only: this member's `cover`, `hold` or `release`
//!   body refuses the build (`malformed`), never skipped;
//! - (d) one body may be both a record and a draft: only a body twice in
//!   one set is refused;
//! - (e) `journal.since` is compared with nothing, `head.seq` included.
//!
//! **The set hashes.** `records_hash = SHA-256(enc(["atem-signer-report-
//! records-v1", d1…dn]))`, each `d` the 32 bytes of `SHA-256(jcs(body))`,
//! sorted by bytes; `drafts_hash` the same with `atem-signer-report-drafts-
//! v1`. A body's digest doesn't depend on its signature.
//!
//! **What it proves.** That this manager's key signed this report for this
//! challenge and plan, and that the exported records are exactly its
//! `records`: each a signed control record of the plan by this member,
//! verified under its `auth_key`, once, their count and `records_hash` the
//! report's. **It is consistency only, never completeness of anything
//! outside the journal**: an old or unaccounted-for process, a range before
//! `since`, a changed journal `id` and a rolled-back protected store stay
//! the adapter's and the owner's unresolved obligations (Astation's rules
//! on #114). A body the journal holds as `signing` with no saved signature
//! is in `records` and can't be exported as signed, so the report stays
//! refused (`records_mismatch`): Astation's conservative rule, with no
//! permissive path.
use serde_json::{Map, Value, json};

use super::{
    Common, HeldBody, PROCESS_BYTES, ReportChallenge, ReportRefusal, Signer, check_build,
    common_body, exact, int_field, malformed, origin_ok, process_generation, read_report,
    read_signer, str_field, strict_challenge,
};
use crate::canonical::{self, MAX_SAFE_INTEGER, Numbers};
use crate::control::record::{
    ControlAction, ControlBody, ControlPrincipal, ControlRecord, ControlSigner,
};
use crate::domain::{SIGNER_REPORT_DRAFTS, SIGNER_REPORT_RECORDS, SignLabel, SigningInput};
use crate::encoding::{Hash32, b64u, b64u_decode_array};
use crate::keys::PublicKey;
use crate::membership::{Head, MemberKind, MemberStatus, Membership};
use crate::provider::{KeyId, KeyProvider};
use crate::session::wire::is_uuid_v4;
use crate::signed::{MAX_OBJECT_BYTES, SignedObject, check_body};

/// The body's `type`.
pub const SIGNER_REPORT_TYPE: &str = "atem-signer-report";
/// A journal's `id`: 16 random bytes made with the journal, base64url.
pub const JOURNAL_ID_BYTES: usize = 16;
/// A recovery's `generation` at most, 2^63 − 1 (at least 1), written as a
/// canonical decimal string.
pub const MAX_GENERATION: u64 = i64::MAX as u64;
/// The decimal digits of [`MAX_GENERATION`].
const MAX_GENERATION_DIGITS: usize = 19;

/// The verifier's refusal codes in the order its checks run: the first
/// that fails is the code ([`verify_signer_report`]).
pub const SIGNER_VERIFY_ORDER: [&str; 14] = [
    "malformed",
    "frozen",
    "wrong_account",
    "unknown_signer",
    "not_a_manager",
    "bad_signature",
    "stale_log",
    "fork",
    "signer_mismatch",
    "slot_mismatch",
    "challenge_mismatch",
    "recovery_mismatch",
    "records_mismatch",
    "expired",
];

/// The body's fields (`sig` sits beside the body).
const BODY_FIELDS: [&str; 11] = [
    "type",
    "v",
    "account_id",
    "genesis_hash",
    "head",
    "signer",
    "slot",
    "process",
    "challenge",
    "recovery",
    "journal",
];
const RECOVERY_FIELDS: [&str; 5] = [
    "generation",
    "plan_id",
    "candidate_feed_id",
    "source_hash",
    "evidence_hash",
];
const JOURNAL_FIELDS: [&str; 7] = [
    "id",
    "since",
    "revision",
    "records",
    "records_hash",
    "drafts",
    "drafts_hash",
];
/// The challenge a minter issues and stores: the verifier report's seven
/// fields and the recovery.
const CHALLENGE_FIELDS: [&str; 8] = [
    "signer",
    "slot",
    "origin",
    "connection",
    "nonce",
    "issued_at",
    "expires_at",
    "recovery",
];

/// A signer report's signer, and its challenge's: `member:<id>` only.
fn member_signer_ok(text: &str) -> bool {
    matches!(read_signer(text), Some(Signer::Member(_)))
}

// ------------------------------------------------------------- recovery

/// The recovery a report is for, as the minter stored it in the challenge
/// and the report echoes it: the recovery `generation` (1 to 2^63 − 1,
/// written as a canonical decimal string: no sign, no leading zero), the
/// plan (`plan_id`) and its candidate feed (`candidate_feed_id`), both UUID
/// v4, and the commitments the collection is based on (`source_hash`,
/// `evidence_hash`, lowercase hex SHA-256). Built only through
/// [`RecoveryPlan::new`] or a reader, so every field follows its grammar.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    generation: u64,
    plan_id: String,
    candidate_feed_id: String,
    source_hash: Hash32,
    evidence_hash: Hash32,
}

impl std::fmt::Debug for RecoveryPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryPlan({})", self.to_json())
    }
}

impl RecoveryPlan {
    /// The recovery, each field in its grammar (`malformed` otherwise).
    pub fn new(
        generation: u64,
        plan_id: &str,
        candidate_feed_id: &str,
        source_hash: Hash32,
        evidence_hash: Hash32,
    ) -> Result<Self, ReportRefusal> {
        if !(1..=MAX_GENERATION).contains(&generation) {
            return Err(malformed("recovery.generation"));
        }
        if !is_uuid_v4(plan_id) {
            return Err(malformed("recovery.plan_id"));
        }
        if !is_uuid_v4(candidate_feed_id) {
            return Err(malformed("recovery.candidate_feed_id"));
        }
        Ok(RecoveryPlan {
            generation,
            plan_id: plan_id.to_owned(),
            candidate_feed_id: candidate_feed_id.to_owned(),
            source_hash,
            evidence_hash,
        })
    }

    /// Exactly the five fields, each in its grammar, as a challenge and a
    /// report carry them (`malformed` otherwise).
    pub fn from_json(value: &Value) -> Result<Self, ReportRefusal> {
        let o = exact(value, &RECOVERY_FIELDS, "recovery")?;
        let generation = str_field(o, "generation")
            .ok()
            .and_then(read_generation)
            .ok_or(malformed("recovery.generation"))?;
        let text =
            |key: &'static str, name: &'static str| str_field(o, key).map_err(|_| malformed(name));
        let hash = |key: &'static str, name: &'static str| {
            str_field(o, key)
                .ok()
                .and_then(|h| Hash32::from_hex(h).ok())
                .ok_or(malformed(name))
        };
        Self::new(
            generation,
            text("plan_id", "recovery.plan_id")?,
            text("candidate_feed_id", "recovery.candidate_feed_id")?,
            hash("source_hash", "recovery.source_hash")?,
            hash("evidence_hash", "recovery.evidence_hash")?,
        )
    }

    /// `{"generation":"<decimal>","plan_id","candidate_feed_id",
    /// "source_hash","evidence_hash"}`.
    pub fn to_json(&self) -> Value {
        json!({
            "generation": self.generation.to_string(),
            "plan_id": self.plan_id,
            "candidate_feed_id": self.candidate_feed_id,
            "source_hash": self.source_hash.to_hex(),
            "evidence_hash": self.evidence_hash.to_hex(),
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn candidate_feed_id(&self) -> &str {
        &self.candidate_feed_id
    }

    pub fn source_hash(&self) -> Hash32 {
        self.source_hash
    }

    pub fn evidence_hash(&self) -> Hash32 {
        self.evidence_hash
    }
}

/// A canonical decimal: 1 to 19 ASCII digits, no leading zero, at most
/// [`MAX_GENERATION`].
fn read_generation(text: &str) -> Option<u64> {
    let digits = text.as_bytes();
    if digits.is_empty()
        || digits.len() > MAX_GENERATION_DIGITS
        || digits[0] == b'0'
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|g| (1..=MAX_GENERATION).contains(g))
}

// ------------------------------------------------------------ challenge

/// The challenge a minter issues and stores for a signer report, and the
/// verifier's expectation: the verifier report's challenge, its `signer` a
/// native member (`member:<id>`), with the `recovery` the report is for.
/// Read strictly within 4,096 bytes, exactly these eight fields; in a
/// report, `signer` and `slot` are the body's top-level fields, `recovery`
/// its own, and the rest its `challenge`.
#[derive(Clone, PartialEq, Eq)]
pub struct SignerReportChallenge {
    base: ReportChallenge,
    recovery: RecoveryPlan,
}

impl std::fmt::Debug for SignerReportChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignerReportChallenge({})", self.to_json())
    }
}

impl SignerReportChallenge {
    /// A challenge with a fresh random nonce (the minter's side): `signer`
    /// `member:<id>`; `slot` 1–128 bytes of `[A-Za-z0-9._:-]`; `origin` the
    /// minter's Station (normalized here); `connection` 1 to 2^53 − 1;
    /// `0 < expires_at − issued_at ≤ 30000` ms; the `recovery` it collects
    /// for.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer: &str,
        slot: &str,
        origin: &str,
        connection: u64,
        issued_at: u64,
        expires_at: u64,
        recovery: RecoveryPlan,
    ) -> Result<Self, ReportRefusal> {
        let mut fields =
            ReportChallenge::fresh_fields(signer, slot, origin, connection, issued_at, expires_at)?;
        fields.insert("recovery".into(), recovery.to_json());
        Self::read(&Value::Object(fields))
    }

    /// Exactly the challenge: one strict I-JSON parse of at most 4,096
    /// bytes (no duplicate keys, escaped ones included; integers only),
    /// these eight fields and no other at either level, no `null`, each
    /// field's grammar.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReportRefusal> {
        Self::read(&strict_challenge(bytes)?)
    }

    fn read(value: &Value) -> Result<Self, ReportRefusal> {
        let o = exact(value, &CHALLENGE_FIELDS, "challenge fields")?;
        let base = ReportChallenge::read_fields(o)?;
        if !member_signer_ok(base.signer()) {
            return Err(malformed("signer"));
        }
        let recovery = RecoveryPlan::from_json(o.get("recovery").ok_or(malformed("recovery"))?)?;
        Ok(SignerReportChallenge { base, recovery })
    }

    /// `{"signer","slot","origin","connection","nonce","issued_at",
    /// "expires_at","recovery":{…}}`: what the minter stores and carries.
    pub fn to_json(&self) -> Value {
        let mut value = self.base.to_json();
        value["recovery"] = self.recovery.to_json();
        value
    }

    pub fn signer(&self) -> &str {
        self.base.signer()
    }

    pub fn slot(&self) -> &str {
        self.base.slot()
    }

    pub fn origin(&self) -> &str {
        self.base.origin()
    }

    pub fn connection(&self) -> u64 {
        self.base.connection()
    }

    pub fn nonce(&self) -> &[u8; super::NONCE_BYTES] {
        self.base.nonce()
    }

    pub fn issued_at(&self) -> u64 {
        self.base.issued_at()
    }

    pub fn expires_at(&self) -> u64 {
        self.base.expires_at()
    }

    pub fn recovery(&self) -> &RecoveryPlan {
        &self.recovery
    }
}

// -------------------------------------------------------------- journal

/// What the adapter's journal holds for the plan, as it hands the builder
/// under its exclusive lock (B1): its `id` (16 random bytes made with the
/// journal, never changed), `since` (the device-list `seq` at its
/// creation, at least 1), `revision` (the count of every append ever made,
/// 0 to 2^53 − 1), and the bodies themselves, each a control-record body's
/// JSON: `records`, the plan's records it put into `signing` or `signed`
/// (a body in `signing` with no saved signature included), and `drafts`,
/// its unsigned drafts of the plan's records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalView {
    pub id: [u8; JOURNAL_ID_BYTES],
    pub since: u64,
    pub revision: u64,
    pub records: Vec<String>,
    pub drafts: Vec<String>,
}

/// A report's `journal` as signed: the journal's identity, range and
/// revision, and each set's count and hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSummary {
    pub id: [u8; JOURNAL_ID_BYTES],
    pub since: u64,
    pub revision: u64,
    pub records: u64,
    pub records_hash: Hash32,
    pub drafts: u64,
    pub drafts_hash: Hash32,
}

impl JournalSummary {
    /// `{"id","since","revision","records","records_hash","drafts",
    /// "drafts_hash"}`.
    pub fn to_json(&self) -> Value {
        json!({
            "id": b64u(&self.id),
            "since": self.since,
            "revision": self.revision,
            "records": self.records,
            "records_hash": self.records_hash.to_hex(),
            "drafts": self.drafts,
            "drafts_hash": self.drafts_hash.to_hex(),
        })
    }

    /// Exactly the seven fields, each in its grammar.
    fn read(value: &Value) -> Result<Self, ReportRefusal> {
        let o = exact(value, &JOURNAL_FIELDS, "journal")?;
        let id = str_field(o, "id")
            .ok()
            .and_then(|id| b64u_decode_array::<JOURNAL_ID_BYTES>(id).ok())
            .ok_or(malformed("journal.id"))?;
        let int =
            |key: &'static str, name: &'static str| int_field(o, key).map_err(|_| malformed(name));
        let since = int("since", "journal.since")?;
        if since == 0 {
            return Err(malformed("journal.since"));
        }
        let hash = |key: &'static str, name: &'static str| {
            str_field(o, key)
                .ok()
                .and_then(|h| Hash32::from_hex(h).ok())
                .ok_or(malformed(name))
        };
        Ok(JournalSummary {
            id,
            since,
            revision: int("revision", "journal.revision")?,
            records: int("records", "journal.records")?,
            records_hash: hash("records_hash", "journal.records_hash")?,
            drafts: int("drafts", "journal.drafts")?,
            drafts_hash: hash("drafts_hash", "journal.drafts_hash")?,
        })
    }
}

/// Whether a control-record body is one of the plan's records for a member
/// and an origin (B2): [`signer_report_plan_record`]'s answer, the rule the
/// builder reads a journal's bodies by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanRecord {
    /// One of the plan's records: the builder takes it in `records` or
    /// `drafts`, and the plan's barrier (B2) holds it: while held, the
    /// adapter refuses to draft or sign it.
    InPlan,
    /// A control record outside the plan: the adapter leaves it out of this
    /// plan's report (handed to the builder it is `malformed`), and this
    /// plan's barrier doesn't hold it.
    NotInPlan(OutOfPlan),
}

/// Why a control-record body isn't one of the plan's records, in the order
/// the predicate checks (the reasons, their codes and that order are
/// Atem's reading, for Astation's confirmation, asked on Astation #114).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutOfPlan {
    /// Another `account_id` than the list's.
    AnotherAccount,
    /// Another `genesis_hash` than the list's.
    AnotherGenesis,
    /// Another `signer` than the member: another member, or the
    /// principal's own key.
    AnotherSigner,
    /// A service's `revoke` or `interrupt_running` naming another origin.
    AnotherOrigin,
}

impl OutOfPlan {
    /// Every reason, in the order the predicate checks.
    pub const ALL: [OutOfPlan; 4] = [
        OutOfPlan::AnotherAccount,
        OutOfPlan::AnotherGenesis,
        OutOfPlan::AnotherSigner,
        OutOfPlan::AnotherOrigin,
    ];

    /// The reason's code, as the bindings and the vectors write it.
    pub fn code(self) -> &'static str {
        match self {
            OutOfPlan::AnotherAccount => "another_account",
            OutOfPlan::AnotherGenesis => "another_genesis",
            OutOfPlan::AnotherSigner => "another_signer",
            OutOfPlan::AnotherOrigin => "another_origin",
        }
    }
}

/// Who and where the plan's records are: by `member:<member>`, of this
/// account and genesis, a service's naming `origin`.
struct Plan<'a> {
    account_id: &'a str,
    genesis_hash: Hash32,
    member: &'a str,
    origin: &'a str,
}

/// A journal body read strictly (strict I-JSON within 16 KiB, exactly a
/// control-record body, R9.1's rules): the body and its `jcs`, or `None`.
fn read_journal_body(text: &str) -> Option<(ControlBody, String)> {
    let value =
        canonical::parse_strict(text.as_bytes(), MAX_OBJECT_BYTES, Numbers::IntegersOnly).ok()?;
    let (_, jcs) = check_body(&value).ok()?;
    let body = ControlBody::from_json(&value).ok()?;
    Some((body, jcs))
}

impl Plan<'_> {
    /// The plan predicate (B2), the one rule of the builder, the verifier's
    /// export check and [`signer_report_plan_record`]. In this order: of
    /// another account, genesis or signer, it isn't the plan's; this
    /// member's `cover`, `hold` or `release` is refused (`malformed`:
    /// reading (c), a native manager signs none); a service's `revoke` or
    /// `interrupt_running` is the plan's when it names the origin, and a
    /// host sender's `interrupt_running` (no origin) always.
    fn judge(&self, body: &ControlBody) -> Result<PlanRecord, ReportRefusal> {
        let out = |why| Ok(PlanRecord::NotInPlan(why));
        if body.account_id != self.account_id {
            return out(OutOfPlan::AnotherAccount);
        }
        if body.genesis_hash != self.genesis_hash {
            return out(OutOfPlan::AnotherGenesis);
        }
        if !matches!(&body.signer, ControlSigner::Member(id) if id == self.member) {
            return out(OutOfPlan::AnotherSigner);
        }
        match (&body.principal, body.action, &body.feed) {
            (
                ControlPrincipal::Service(_),
                ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. },
                Some(feed),
            ) if feed.origin == self.origin => Ok(PlanRecord::InPlan),
            (
                ControlPrincipal::Service(_),
                ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. },
                Some(_),
            ) => out(OutOfPlan::AnotherOrigin),
            (ControlPrincipal::Host(_), ControlAction::InterruptRunning { .. }, None) => {
                Ok(PlanRecord::InPlan)
            }
            _ => Err(malformed("body.action")),
        }
    }

    /// Whether `body` is one of the plan's records ([`Plan::judge`]).
    fn holds(&self, body: &ControlBody) -> bool {
        matches!(self.judge(body), Ok(PlanRecord::InPlan))
    }

    /// Each body of a journal set read strictly as one of the plan's
    /// records ([`read_journal_body`], [`Plan::judge`]): their digests,
    /// sorted. A body twice in the set (its `jcs` the same, however
    /// written) or any other body is `malformed`, naming the set.
    fn digests(
        &self,
        bodies: &[String],
        set: &'static str,
    ) -> Result<Vec<[u8; 32]>, ReportRefusal> {
        let mut digests = Vec::with_capacity(bodies.len());
        for text in bodies {
            let (body, jcs) = read_journal_body(text).ok_or(malformed(set))?;
            if !self.holds(&body) {
                return Err(malformed(set));
            }
            digests.push(Hash32::of(jcs.as_bytes()).0);
        }
        sorted_once(digests).ok_or(malformed(set))
    }
}

/// The plan predicate (B2; Astation's ask on #114 comment 7093796254):
/// whether `body_json`, a control-record body as an adapter's journal
/// holds it, is one of the plan's records for `member` (`member:<id>`) at
/// `origin` (the challenge's, exactly as `normalize_relay` writes it), the
/// account and genesis `log`'s. The builder reads a journal's bodies by
/// exactly this rule: what it answers [`PlanRecord::InPlan`] the builder
/// takes in `records` or `drafts`, anything else refuses the build
/// (`malformed`). So an adapter selects its records and drafts, and checks
/// its barrier before drafting or signing, by the builder's own rule.
///
/// The body is read as the builder reads it (strict I-JSON within 16 KiB,
/// exactly a control-record body), then judged in this order: another
/// account (`another_account`), genesis (`another_genesis`) or signer
/// (`another_signer`: another member, or the principal's own key) is
/// [`PlanRecord::NotInPlan`]; this member's `cover`, `hold` or `release`
/// is refused (`malformed`: a native manager signs none, so the journal
/// never holds one; never skipped); a service's `revoke` or
/// `interrupt_running` at another origin is `another_origin`; then it is
/// in the plan (a `host:` principal's `interrupt_running`, which names no
/// origin, at every origin). Refused (`malformed`): `member` not
/// `member:<id>`, `origin` not in its exact form, a body that isn't a
/// control record's. Bodies only: the list's freeze and the member's
/// standing (removed, demoted, never a manager) change no answer; the
/// builder refuses those itself.
///
/// Which bodies are in the plan is the agreed B2 rule with agreed reading
/// (c). **Atem's reading, for Astation's confirmation (asked on Astation
/// #114):** a body of another account, genesis or signer is
/// [`PlanRecord::NotInPlan`] with a reason, never `malformed` (the builder
/// refuses it either way); the order account, genesis, signer, action,
/// origin; and the four reason codes ([`OutOfPlan::code`]).
pub fn signer_report_plan_record(
    log: &Membership,
    body_json: &str,
    member: &str,
    origin: &str,
) -> Result<PlanRecord, ReportRefusal> {
    let Some(Signer::Member(id)) = read_signer(member) else {
        return Err(malformed("member"));
    };
    if !origin_ok(origin) {
        return Err(malformed("origin"));
    }
    let (body, _) = read_journal_body(body_json).ok_or(malformed("body"))?;
    Plan {
        account_id: log.account_id(),
        genesis_hash: log.genesis_hash(),
        member: id,
        origin,
    }
    .judge(&body)
}

/// `digests` sorted by bytes, or `None` when one is there twice.
fn sorted_once(mut digests: Vec<[u8; 32]>) -> Option<Vec<[u8; 32]>> {
    digests.sort_unstable();
    (!digests.windows(2).any(|w| w[0] == w[1])).then_some(digests)
}

/// `SHA-256(enc([label, d1…dn]))` over `digests`, sorted.
fn set_hash(label: &str, digests: &[[u8; 32]]) -> Hash32 {
    let mut fields: Vec<&[u8]> = Vec::with_capacity(digests.len() + 1);
    fields.push(label.as_bytes());
    fields.extend(digests.iter().map(|d| &d[..]));
    Hash32::of_enc(&fields)
}

// ----------------------------------------------------------------- body

/// A signer report's signer at `log`'s head: a current native member
/// (`unknown_signer` otherwise: removed or never added, pending, a service,
/// a host, a grant, `recovery`) that held `manage` at some `seq` of the log
/// (`not_a_manager`), with its `auth_key` as the list pins it.
fn manager_key(log: &Membership, signer: &str) -> Result<PublicKey, ReportRefusal> {
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
    if !log.was_manager(id) {
        return Err(ReportRefusal::NotAManager);
    }
    Ok(state.member.auth_key.clone())
}

/// A signer report's body, built by [`signer_report_body`] from the
/// reporter's own log, process and journal, with the signer's key at that
/// log's head. Immutable: a signature attached with
/// [`with_signature`](Self::with_signature) is over exactly this body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerReportBody {
    held: HeldBody,
    journal: JournalSummary,
}

impl SignerReportBody {
    /// The body object.
    pub fn to_json(&self) -> Value {
        self.held.value.clone()
    }

    /// `jcs(body)`.
    pub fn jcs(&self) -> &str {
        &self.held.jcs
    }

    /// `enc(["atem-signer-report-v1", jcs(body)])`: what the manager's key
    /// signs, with a fresh confirmation.
    pub fn signing_input(&self) -> SigningInput {
        self.held.signing_input()
    }

    /// The head of the reporter's log the body names.
    pub fn head(&self) -> Head {
        self.held.head
    }

    /// The process generation the body names ([`process_generation`]).
    pub fn process(&self) -> [u8; PROCESS_BYTES] {
        self.held.process
    }

    /// The signer's key at the log's head, with its algorithm.
    pub fn signer_key(&self) -> &PublicKey {
        &self.held.signer_key
    }

    /// The body's `journal`: the counts and set hashes the builder computed.
    pub fn journal(&self) -> &JournalSummary {
        &self.journal
    }

    /// The report: this body with `sig` (P-256 64-byte `r‖s`, either S,
    /// normalized to low S; or Ed25519), once it verifies under the
    /// signer's key over this body's signing input. A signature over any
    /// other body, under any other label or by any other key is
    /// `bad_signature`.
    pub fn with_signature(&self, sig: &[u8]) -> Result<SignedObject, ReportRefusal> {
        self.held.with_signature(sig)
    }
}

/// The body a native manager signs for `challenge`, as `signer`
/// (`member:<id>`, the reporter itself) in `slot` (its configured slot),
/// configured with the Station `station`, from `journal` (what its journal
/// holds for the plan, under the adapter's lock), at `now_ms` on its clock.
///
/// The caller supplies none of what the body claims but the journal's
/// identity, range and revision: `account_id`, `genesis_hash` and `head`
/// are `log`'s, `process` is [`process_generation`], the challenge and its
/// recovery are echoed exactly, and the counts and set hashes are computed
/// here from the bodies. Refused, in this order: `signer` not
/// `member:<id>`, `slot` or `station` outside their grammar (`malformed`);
/// `log` frozen (`frozen`); the challenge for another Station than
/// `station` normalized (`origin_mismatch`), another signer
/// (`signer_mismatch`), another slot (`slot_mismatch`); `signer` not a
/// current native member (`unknown_signer`) or one that never held
/// `manage` (`not_a_manager`); the challenge expired at `now_ms`
/// (`expired`); then the journal: `since` 0 or `revision` beyond 2^53 − 1,
/// a body that isn't one of the plan's records by this member (another
/// account, genesis, signer or origin, a cover, hold or release, anything
/// that isn't a control-record body), or a body twice in one set
/// (`malformed`).
pub fn signer_report_body(
    log: &Membership,
    challenge: &SignerReportChallenge,
    signer: &str,
    slot: &str,
    station: &str,
    journal: &JournalView,
    now_ms: u64,
) -> Result<SignerReportBody, ReportRefusal> {
    check_build(
        log,
        &challenge.base,
        signer,
        slot,
        station,
        member_signer_ok,
    )?;
    let signer_key = manager_key(log, signer)?;
    if now_ms >= challenge.expires_at() {
        return Err(ReportRefusal::Expired);
    }
    if !(1..=MAX_SAFE_INTEGER).contains(&journal.since) {
        return Err(malformed("journal.since"));
    }
    if journal.revision > MAX_SAFE_INTEGER {
        return Err(malformed("journal.revision"));
    }
    let plan = Plan {
        account_id: log.account_id(),
        genesis_hash: log.genesis_hash(),
        member: signer.strip_prefix("member:").unwrap_or_default(),
        origin: challenge.origin(),
    };
    let records = plan.digests(&journal.records, "journal.records")?;
    let drafts = plan.digests(&journal.drafts, "journal.drafts")?;
    let summary = JournalSummary {
        id: journal.id,
        since: journal.since,
        revision: journal.revision,
        records: records.len() as u64,
        records_hash: set_hash(SIGNER_REPORT_RECORDS, &records),
        drafts: drafts.len() as u64,
        drafts_hash: set_hash(SIGNER_REPORT_DRAFTS, &drafts),
    };
    let process = process_generation();
    let mut value: Map<String, Value> = common_body(log, &challenge.base, &process);
    value.insert("type".into(), json!(SIGNER_REPORT_TYPE));
    value.insert("v".into(), json!(1));
    value.insert("recovery".into(), challenge.recovery.to_json());
    value.insert("journal".into(), summary.to_json());
    let held = HeldBody::new(
        SignLabel::SignerReport,
        Value::Object(value),
        log.head(),
        process,
        signer_key,
    )?;
    Ok(SignerReportBody {
        held,
        journal: summary,
    })
}

/// Signs `body` with `key` (the manager's own key behind `provider`) and
/// returns the report. The provider sees purpose `SignerReport` in the
/// bindings: a fresh confirmation of the body, never in the background; a
/// provider that declines is `signing_failed`. A key that isn't the
/// signer's key at the log's head is `bad_signature`.
pub fn sign_signer_report(
    provider: &dyn KeyProvider,
    key: &KeyId,
    body: &SignerReportBody,
) -> Result<SignedObject, ReportRefusal> {
    let sig = crate::provider::sign(provider, key, &body.signing_input())
        .map_err(ReportRefusal::Signing)?;
    body.with_signature(&sig)
}

// --------------------------------------------------------- verification

/// A verified signer report: what the Station's recovery decides on. It
/// proves the report's signature and that the exported records match it,
/// and nothing about what lies outside the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignerReport {
    /// `member:<device_id>`.
    pub signer: String,
    pub slot: String,
    pub process: [u8; PROCESS_BYTES],
    pub connection: u64,
    /// The head the reporter signed at: the verifier's head or an ancestor.
    pub head: Head,
    /// Whether `head` is the verifier's head.
    pub at_head: bool,
    /// The recovery the report is for (the stored challenge's).
    pub recovery: RecoveryPlan,
    /// The report's journal: its identity, range, revision, counts and set
    /// hashes.
    pub journal: JournalSummary,
    /// The exported records, each verified, in the order given: exactly the
    /// report's `records`.
    pub records: Vec<ControlRecord>,
}

/// The exported records checked against the report's `records`: their
/// count first (before any record is parsed or verified), then each a
/// signed control record of the plan by this member, its signature
/// verified under `key` (low S), none twice, and their set hash the
/// journal's. Any failure is `records_mismatch`, naming which.
fn exported_records<R: AsRef<[u8]>>(
    exported: &[R],
    journal: &JournalSummary,
    plan: &Plan<'_>,
    key: &PublicKey,
) -> Result<Vec<ControlRecord>, ReportRefusal> {
    // The cheap check first: the exported list isn't signed, so a list of
    // the wrong length is refused before any record is parsed or verified.
    if exported.len() as u64 != journal.records {
        return Err(ReportRefusal::RecordsMismatch("count"));
    }
    let mut records = Vec::with_capacity(exported.len());
    let mut digests = Vec::with_capacity(exported.len());
    for bytes in exported {
        let record = ControlRecord::parse(bytes.as_ref())
            .map_err(|_| ReportRefusal::RecordsMismatch("not a control record"))?;
        if !plan.holds(record.body()) {
            return Err(ReportRefusal::RecordsMismatch("not a record of the plan"));
        }
        record
            .object()
            .verify(key)
            .map_err(|_| ReportRefusal::RecordsMismatch("signature"))?;
        digests.push(Hash32::of(record.object().jcs().as_bytes()).0);
        records.push(record);
    }
    let digests = sorted_once(digests).ok_or(ReportRefusal::RecordsMismatch("duplicate"))?;
    if set_hash(SIGNER_REPORT_RECORDS, &digests) != journal.records_hash {
        return Err(ReportRefusal::RecordsMismatch("records_hash"));
    }
    Ok(records)
}

/// Verifies a signer report (`{"body","sig"}` as received) against `log`
/// at its current head, the challenge the minter stored, and the signed
/// records exported with it (`exported`, each `{"body","sig"}`), at
/// `now_ms` on the verifier's clock. Membership and keys are read at the
/// verifier's head, never the report's. In this order, the first failure
/// is the code ([`SIGNER_VERIFY_ORDER`]): exactly a report (`malformed`);
/// the log not frozen (`frozen`); `account_id` and `genesis_hash` the log's
/// (`wrong_account`); `signer` a current native member (`unknown_signer`:
/// services, hosts, `recovery` and grants included) that held `manage` at
/// some `seq` of the log (`not_a_manager`); `sig` by its `auth_key` under
/// its pinned algorithm (`bad_signature`); `head` the log's head or an
/// ancestor (`stale_log` beyond it, `fork` off it); `signer` and `slot` the
/// expected ones (`signer_mismatch`, `slot_mismatch`); every echoed
/// challenge field the expected one (`challenge_mismatch`); every
/// `recovery` field the expected one (`recovery_mismatch`); the exported
/// records exactly the report's `records` (`records_mismatch`: one that
/// isn't a signed control record of the plan by this member, one whose
/// signature doesn't verify under its key, a duplicate, another count or
/// `records_hash`); `now_ms` before `expires_at` (`expired`).
///
/// A body the journal holds as `signing` with no saved signature counts in
/// `records` and can't be exported: such a report is `records_mismatch`
/// until its signature is recovered. **Consistency only**: the report
/// proves what this journal holds, never that the journal is all this
/// member signed.
pub fn verify_signer_report<R: AsRef<[u8]>>(
    log: &Membership,
    report_json: &[u8],
    expected: &SignerReportChallenge,
    exported: &[R],
    now_ms: u64,
) -> Result<VerifiedSignerReport, ReportRefusal> {
    let object = read_report(report_json, SignLabel::SignerReport)?;
    let o = exact(object.body(), &BODY_FIELDS, "body fields")?;
    if o.get("type").and_then(Value::as_str) != Some(SIGNER_REPORT_TYPE) {
        return Err(malformed("type"));
    }
    let body = Common::read(o)?;
    let recovery = RecoveryPlan::from_json(o.get("recovery").ok_or(malformed("recovery"))?)?;
    let journal = JournalSummary::read(o.get("journal").ok_or(malformed("journal"))?)?;
    body.check_log(log)?;
    let key = manager_key(log, &body.signer)?;
    let at_head = body.check_signed(log, &object, &key, &expected.base)?;
    if recovery != expected.recovery {
        return Err(ReportRefusal::RecoveryMismatch);
    }
    let plan = Plan {
        account_id: log.account_id(),
        genesis_hash: log.genesis_hash(),
        member: body.signer.strip_prefix("member:").unwrap_or_default(),
        origin: &body.echo.origin,
    };
    let records = exported_records(exported, &journal, &plan, &key)?;
    if now_ms >= expected.expires_at() {
        return Err(ReportRefusal::Expired);
    }
    Ok(VerifiedSignerReport {
        signer: body.signer.clone(),
        slot: body.slot,
        process: body.process,
        connection: body.echo.connection,
        head: body.head,
        at_head,
        recovery,
        journal,
        records,
    })
}

//! atem-session v1 wire types (§1–§7) and the strict decoder.
//!
//! `decode` runs in three layers:
//! 1. `canonical::parse_strict` — size bound before anything is allocated,
//!    UTF-8, duplicate keys at any depth, lone surrogates, unsafe integers;
//! 2. serde into the typed messages below — integers are `u64`, so a fraction,
//!    exponent, negative or string where an integer is required is refused, and
//!    every required field must be present (unknown fields are ignored);
//! 3. `validate` — the §1 representation rules (UUID v4, `session_id`, opaque
//!    ids, counter range, bounds) and per-op rules (`lease_epoch` presence,
//!    payload shape per kind).
//!
//! Every decode failure is `unsupported_version` (§7: out-of-range
//! representation); `DecodeError::id` carries the request id when it could be
//! read, so the host can still answer with `re`.
//!
//! Contract r6 §0 has no legacy paths: the removed families (`agentInput`,
//! `agentPrompt`, `voiceCommand`, `voiceToggle`, `userCommand`), terminal-v1
//! `control`/`controller`/`list`/`sessions` and any terminal-v1 or chat-v1 request without its
//! `binding` or with a `lease_id` fail with `DecodeError::removed` set, so the
//! host answers `unsupported_version` and does nothing. terminal-v1 requests
//! decode into `TerminalRequest` (terminal ids are session ids).

use super::canonical::{self, MAX_SAFE_INTEGER, Numbers};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub const VERSION: u64 = 1;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_PROMPT_BYTES: usize = 32_768;
pub const MAX_REQUEST_IDS: usize = 64;
pub const MAX_DETAIL_BYTES: usize = 512;
pub const MAX_OPAQUE_ID_BYTES: usize = 128;
/// Approvals (r7): `tool` 1–128 bytes, `summary` ≤ 512 bytes, each offered
/// rule's `label`/`scope` 1–256 bytes, ≤ 8 rules, a deny `message` ≤ 512 bytes.
pub const MAX_APPROVAL_TOOL_BYTES: usize = 128;
pub const MAX_APPROVAL_SUMMARY_BYTES: usize = 512;
pub const MAX_RULE_TEXT_BYTES: usize = 256;
pub const MAX_ALWAYS_RULES: usize = 8;
pub const MAX_APPROVAL_MESSAGE_BYTES: usize = 512;
/// Atem session rules (r7.2) a session holds at once.
pub const MAX_SESSION_RULES: usize = 32;
/// In-flight requests per attachment (enforced by the host; excess → `busy`).
pub const MAX_IN_FLIGHT: usize = 64;

// ── Representation helpers (§1) ───────────────────────────────────────────

/// Lowercase canonical UUID v4 (`8-4-4-4-12`, version 4, RFC 4122 variant).
pub fn is_uuid_v4(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

/// `ses-` + exactly 12 chars of `[a-z2-7]`.
pub fn is_session_id(s: &str) -> bool {
    s.strip_prefix("ses-").is_some_and(|rest| {
        rest.len() == 12
            && rest
                .bytes()
                .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
    })
}

/// 1–128 bytes of `[A-Za-z0-9._:-]`.
pub fn is_opaque_id(s: &str) -> bool {
    (1..=MAX_OPAQUE_ID_BYTES).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// SHA-256, lowercase hex, 64 chars.
pub fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn check(ok: bool, what: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("invalid {what}"))
    }
}

fn uuid(s: &str, what: &str) -> Result<(), String> {
    check(is_uuid_v4(s), what)
}

/// Counters and times: JSON integers 0 ≤ n ≤ 2^53−1 (§1).
fn safe(n: u64, what: &str) -> Result<(), String> {
    check(n <= MAX_SAFE_INTEGER, what)
}

/// Display text: bounded, and no control characters (C0, DEL, C1) except
/// the ones `allowed` (none for one-line text).
fn text(s: &str, min: usize, max: usize, allowed: &[char], what: &str) -> Result<(), String> {
    let clean = s.chars().all(|c| !c.is_control() || allowed.contains(&c));
    check((min..=max).contains(&s.len()) && clean, what)
}

fn detail(d: &Option<String>) -> Result<(), String> {
    check(
        d.as_ref().is_none_or(|d| d.len() <= MAX_DETAIL_BYTES),
        "detail",
    )
}

// ── Codes and enums ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedVersion,
    Unauthorized,
    Forbidden,
    StaleTarget,
    UnknownSession,
    LeaseHeld,
    StaleLease,
    RequestIdReused,
    ReceiptLimit,
    SessionClosed,
    Busy,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Native,
    Browser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    View,
    /// Leases and every lease-scoped mutation, including approval answers.
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Running,
    Exited,
    Interrupted,
    RecoveryRequired,
    Closed,
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    Ready,
    Working,
    Waiting,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseChangeReason {
    Granted,
    Takeover,
    LocalInput,
    Expired,
    Released,
    Revoked,
    ProcessEnded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Prompt,
    Interrupt,
    Stop,
    /// The answer to a pending approval (r7).
    Approval,
    /// Revokes one of the session's Atem session rules (r7.2).
    ApprovalRuleRevoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    AllowOnce,
    /// Applies one of the rules the agent offered (`rule_id`).
    AllowAlways,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalCloseReason {
    /// The lease holder's answer was handed to the agent.
    AnsweredRemote,
    AnsweredTerminal,
    Interrupted,
    TimedOut,
    /// Atem gave the prompt back to the agent's own terminal prompt ("no
    /// decision"): local input to a Codex session (which hides its prompt
    /// while the hook waits), or a runtime restart.
    Released,
    ProcessEnded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Accepted,
    Executing,
    Completed,
    Rejected,
    OutcomeUnknown,
}

// ── Target and binding (§2) ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
    pub session_id: String,
    pub process_gen: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub target: Target,
    pub attachment_gen: String,
    /// Required for mutations, absent for reads.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_epoch: Option<u64>,
}

/// Whether a binding belongs to a read (no `lease_epoch`), a mutation
/// (required), or a submission the lease doesn't govern (`lease_epoch`
/// optional and ignored: a rule revocation, r7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingUse {
    Read,
    Mutation,
    LeaseIgnored,
}

// ── Descriptors and receipts ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Controller {
    pub controller_session: String,
    pub lease_epoch: u64,
}

/// A session descriptor (§4). Every field is required; `controller` is `null`
/// when no lease is held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    pub session_id: String,
    pub process_gen: String,
    pub provider: String,
    pub cwd_label: String,
    pub state: SessionState,
    pub activity: Activity,
    pub activity_since: u64,
    #[serde(deserialize_with = "nullable")]
    pub controller: Option<Controller>,
    pub capabilities: Vec<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub request_id: String,
    pub target: Target,
    pub kind: ReceiptKind,
    pub state: ReceiptState,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub detail: Option<String>,
    pub updated_at: u64,
}

/// One "always allow" rule the agent itself suggested, shown before the tap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlwaysRule {
    pub rule_id: String,
    pub label: String,
    pub scope: String,
}

/// `approval_request` (r7): an agent permission prompt the lease holder may
/// answer, bound to one session and process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub session_id: String,
    pub process_gen: String,
    pub tool: String,
    /// Redacted: the command's first line or the file path, never full inputs.
    pub summary: String,
    pub created_at: u64,
    pub always_rules: Vec<AlwaysRule>,
}

/// The payload of a `kind:"approval"` submission. Exactly these fields:
/// `rule_id` iff `allow_always`, `message` only with `deny`; `acquire:
/// true` takes the session's lease for the answering attachment together
/// with the answer (its binding then carries no `lease_epoch`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAnswer {
    pub approval_id: String,
    pub decision: ApprovalDecision,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub rule_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub message: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub acquire: Option<bool>,
}

impl ApprovalAnswer {
    /// The answer takes the lease with it.
    pub fn acquires(&self) -> bool {
        self.acquire == Some(true)
    }

    /// The validated answer in an approval payload.
    pub fn parse(payload: &Value) -> Result<Self, String> {
        let a: Self =
            serde_json::from_value(payload.clone()).map_err(|e| format!("approval: {e}"))?;
        uuid(&a.approval_id, "approval_id")?;
        match (a.decision, &a.rule_id) {
            (ApprovalDecision::AllowAlways, Some(r)) => check(is_opaque_id(r), "rule_id")?,
            (ApprovalDecision::AllowAlways, None) => return Err("rule_id missing".into()),
            (_, Some(_)) => return Err("rule_id only with allow_always".into()),
            (_, None) => {}
        }
        match (a.decision, &a.message) {
            (ApprovalDecision::Deny, Some(m)) => {
                text(m, 0, MAX_APPROVAL_MESSAGE_BYTES, &['\n'], "message")?
            }
            (_, Some(_)) => return Err("message only with deny".into()),
            (_, None) => {}
        }
        Ok(a)
    }
}

/// The payload of a `kind:"approval_rule_revoke"` submission (r7.2):
/// exactly `{rule_id}`, an opaque id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRevoke {
    pub rule_id: String,
}

impl RuleRevoke {
    pub fn parse(payload: &Value) -> Result<Self, String> {
        let r: Self = serde_json::from_value(payload.clone())
            .map_err(|e| format!("approval_rule_revoke: {e}"))?;
        check(is_opaque_id(&r.rule_id), "rule_id")?;
        Ok(r)
    }
}

/// The active Atem session rules of a session (r7.2): ≤ 32, unique ids,
/// one-line labels and scopes.
pub fn validate_session_rules(rules: &[AlwaysRule]) -> Result<(), String> {
    check(rules.len() <= MAX_SESSION_RULES, "rules count")?;
    validate_rules(rules)
}

fn validate_rules(rules: &[AlwaysRule]) -> Result<(), String> {
    for (i, r) in rules.iter().enumerate() {
        check(is_opaque_id(&r.rule_id), "rule_id")?;
        check(
            rules[..i].iter().all(|o| o.rule_id != r.rule_id),
            "duplicate rule_id",
        )?;
        text(&r.label, 1, MAX_RULE_TEXT_BYTES, &[], "rule label")?;
        text(&r.scope, 1, MAX_RULE_TEXT_BYTES, &[], "rule scope")?;
    }
    Ok(())
}

/// The bounds of what an approval shows (r7): one-line `tool` and
/// `summary`, ≤ 8 rules with unique ids and one-line labels and scopes.
pub fn validate_approval_info(
    tool: &str,
    summary: &str,
    always_rules: &[AlwaysRule],
) -> Result<(), String> {
    text(tool, 1, MAX_APPROVAL_TOOL_BYTES, &[], "tool")?;
    text(summary, 0, MAX_APPROVAL_SUMMARY_BYTES, &[], "summary")?;
    check(always_rules.len() <= MAX_ALWAYS_RULES, "always_rules count")?;
    validate_rules(always_rules)
}

impl ApprovalRequest {
    fn validate(&self) -> Result<(), String> {
        uuid(&self.approval_id, "approval_id")?;
        check(is_session_id(&self.session_id), "session_id")?;
        uuid(&self.process_gen, "process_gen")?;
        safe(self.created_at, "created_at")?;
        validate_approval_info(&self.tool, &self.summary, &self.always_rules)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    pub controller_session: String,
}

// ── Ops (§3–§7) ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Hello {
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        resume: Option<Resume>,
    },
    Challenge {
        nonce: String,
    },
    ResumeProof {
        proof: String,
    },
    Welcome {
        account_id: String,
        atem_device_id: String,
        host_trust_gen: u64,
        runtime_gen: String,
        controller_session: String,
        attachment_gen: String,
        client_kind: ClientKind,
        permissions: Vec<Permission>,
        authorization_ms_left: u64,
        server_time: u64,
    },
    List {},
    Sessions {
        runtime_gen: String,
        runtime_epoch: u64,
        seq: u64,
        sessions: Vec<Descriptor>,
    },
    SessionChanged {
        runtime_gen: String,
        runtime_epoch: u64,
        seq: u64,
        descriptor: Descriptor,
    },
    Acquire {
        binding: Binding,
        takeover: bool,
    },
    Renew {
        binding: Binding,
    },
    Release {
        binding: Binding,
    },
    Lease {
        binding: Binding,
        ms_left: u64,
    },
    LeaseReleased {},
    LeaseChanged {
        session_id: String,
        process_gen: String,
        #[serde(deserialize_with = "nullable")]
        controller: Option<Controller>,
        lease_epoch: u64,
        reason: LeaseChangeReason,
    },
    Submit {
        binding: Binding,
        request_id: String,
        kind: ReceiptKind,
        payload: Value,
    },
    Receipt(Receipt),
    ReceiptQuery {
        binding: Binding,
        request_ids: Vec<String>,
    },
    Receipts {
        receipts: Vec<Receipt>,
    },
    ApprovalRequest(ApprovalRequest),
    ApprovalClosed {
        approval_id: String,
        reason: ApprovalCloseReason,
    },
    /// The session's active Atem session rules (r7.2), whenever they change
    /// and after each `sessions` snapshot (when there are any).
    ApprovalRules {
        session_id: String,
        process_gen: String,
        rules: Vec<AlwaysRule>,
    },
    Error {
        code: ErrorCode,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        detail: Option<String>,
    },
}

/// `{"type":"session","data":{"v":1,"op":…,"id":…,"re"?:…}}`.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionMessage {
    pub id: String,
    pub re: Option<String>,
    pub op: Op,
}

/// A message of another family (`terminal`, `agentChat`, `agentInput`, …).
/// `data` is kept as received minus `binding`, which is parsed and validated
/// when present (§2: terminal-v1 and chat-v1 carry it as `data.binding`).
#[derive(Debug, Clone, PartialEq)]
pub struct FamilyMessage {
    pub family: String,
    /// `None` for messages without `data` (e.g. `{"type":"projectListRequest"}`).
    pub data: Option<Value>,
    pub binding: Option<Binding>,
    /// A terminal-v1 request, typed (`None` for every other message).
    pub request: Option<TerminalRequest>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Envelope {
    Session(SessionMessage),
    Family(FamilyMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub code: ErrorCode,
    /// The request's `id`, when it could be read (to answer with `re`).
    pub id: Option<String>,
    /// Internal reason, for logs only; never sent to a peer.
    pub reason: String,
    /// Set when the message is a form the contract removed (r6 §0).
    pub removed: Option<RemovedOp>,
}

/// A message type (and op) removed by contract r6 §0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedOp {
    pub family: String,
    pub op: Option<String>,
}

/// Families removed outright (r6 §0): every remote mutation is session-v1.
pub const REMOVED_FAMILIES: &[&str] = &[
    "agentInput",
    "agentPrompt",
    "voiceCommand",
    "voiceToggle",
    "userCommand",
];

/// terminal-v1 requests from a client (§2). Each carries `data.binding`
/// (read for subscribe/unsubscribe/ack, mutation for input/resize/stop);
/// there is no `lease_id`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TerminalRequest {
    Subscribe {
        terminal_id: String,
        generation: String,
    },
    Unsubscribe {
        terminal_id: String,
        generation: String,
        stream_id: String,
    },
    Ack {
        terminal_id: String,
        generation: String,
        stream_id: String,
        offset: u64,
    },
    Input {
        terminal_id: String,
        generation: String,
        stream_id: String,
        sequence: u64,
        bytes: String,
    },
    Resize {
        terminal_id: String,
        generation: String,
        stream_id: String,
        rows: u16,
        cols: u16,
    },
    Stop {
        terminal_id: String,
        generation: String,
        stream_id: String,
    },
}

impl TerminalRequest {
    fn ids(&self) -> (&str, &str) {
        match self {
            TerminalRequest::Subscribe {
                terminal_id,
                generation,
            }
            | TerminalRequest::Unsubscribe {
                terminal_id,
                generation,
                ..
            }
            | TerminalRequest::Ack {
                terminal_id,
                generation,
                ..
            }
            | TerminalRequest::Input {
                terminal_id,
                generation,
                ..
            }
            | TerminalRequest::Resize {
                terminal_id,
                generation,
                ..
            }
            | TerminalRequest::Stop {
                terminal_id,
                generation,
                ..
            } => (terminal_id, generation),
        }
    }

    fn validate(&self) -> Result<(), String> {
        let (terminal_id, generation) = self.ids();
        check(is_session_id(terminal_id), "terminal_id")?;
        uuid(generation, "generation")?;
        if let TerminalRequest::Input { bytes, .. } = self {
            use base64::{Engine, engine::general_purpose::STANDARD};
            check(STANDARD.decode(bytes).is_ok(), "bytes")?;
        }
        Ok(())
    }
}

impl Target {
    fn validate(&self) -> Result<(), String> {
        check(is_opaque_id(&self.account_id), "account_id")?;
        check(is_opaque_id(&self.atem_device_id), "atem_device_id")?;
        safe(self.host_trust_gen, "host_trust_gen")?;
        check(is_session_id(&self.session_id), "session_id")?;
        uuid(&self.process_gen, "process_gen")
    }
}

impl Binding {
    fn validate_shape(&self) -> Result<(), String> {
        self.target.validate()?;
        uuid(&self.attachment_gen, "attachment_gen")?;
        self.lease_epoch.map_or(Ok(()), |e| safe(e, "lease_epoch"))
    }

    /// Representation rules plus §2: `lease_epoch` is required for mutations
    /// and absent for reads; a submission the lease doesn't govern may carry
    /// one or not (r7.3), and it is never checked.
    pub fn validate(&self, use_: BindingUse) -> Result<(), String> {
        self.validate_shape()?;
        match (use_, self.lease_epoch) {
            (BindingUse::Read, Some(_)) => Err("lease_epoch on a read".into()),
            (BindingUse::Mutation, None) => Err("lease_epoch missing on a mutation".into()),
            _ => Ok(()),
        }
    }

    /// terminal-v1 `terminal_id` / chat-v1 `agentId` must equal
    /// `target.session_id`, and the family's `generation` (when it has one)
    /// `target.process_gen`; a disagreement is `stale_target` (§2).
    pub fn check_family_ids(
        &self,
        session_id: &str,
        generation: Option<&str>,
    ) -> Result<(), ErrorCode> {
        let gen_ok = generation.is_none_or(|g| g == self.target.process_gen);
        if session_id == self.target.session_id && gen_ok {
            Ok(())
        } else {
            Err(ErrorCode::StaleTarget)
        }
    }
}

impl Controller {
    fn validate(&self) -> Result<(), String> {
        uuid(&self.controller_session, "controller_session")?;
        safe(self.lease_epoch, "controller.lease_epoch")
    }
}

impl Descriptor {
    fn validate(&self) -> Result<(), String> {
        check(is_session_id(&self.session_id), "session_id")?;
        uuid(&self.process_gen, "process_gen")?;
        safe(self.activity_since, "activity_since")?;
        safe(self.created_at, "created_at")?;
        self.controller
            .as_ref()
            .map_or(Ok(()), Controller::validate)
    }
}

impl Receipt {
    fn validate(&self) -> Result<(), String> {
        uuid(&self.request_id, "request_id")?;
        self.target.validate()?;
        detail(&self.detail)?;
        safe(self.updated_at, "updated_at")
    }
}

/// A submission's binding is a mutation's (`lease_epoch` required), except
/// an approval answer with `acquire: true`, which takes the lease with it,
/// and a rule revocation, which needs only `control` (r7.3: `lease_epoch`
/// optional and ignored).
pub fn submit_binding_use(kind: ReceiptKind, payload: &Value) -> BindingUse {
    let acquire = payload.get("acquire") == Some(&Value::Bool(true));
    match kind {
        ReceiptKind::ApprovalRuleRevoke => BindingUse::LeaseIgnored,
        ReceiptKind::Approval if acquire => BindingUse::Read,
        _ => BindingUse::Mutation,
    }
}

/// The chat-v1 `submit` field carrying a rule revocation (r7.2), named
/// like its session-v1 kind.
pub const RULE_REVOKE_FIELD: &str = "approval_rule_revoke";

/// v1 payload shapes (§6): `prompt` is exactly `{"text": string}` (≤ 32 768
/// bytes), `interrupt`/`stop` exactly `{}`, `approval` an `ApprovalAnswer`
/// (r7), `approval_rule_revoke` exactly `{"rule_id"}` (r7.2). The
/// canonical form is ≤ 64 KiB.
fn validate_payload(kind: ReceiptKind, payload: &Value) -> Result<(), String> {
    let canonical = canonical::jcs(payload).map_err(|e| format!("payload: {e:?}"))?;
    check(canonical.len() <= MAX_PAYLOAD_BYTES, "payload size")?;
    let obj = payload.as_object();
    match kind {
        ReceiptKind::Prompt => match obj.and_then(|o| o.get("text")) {
            Some(Value::String(t)) if obj.is_some_and(|o| o.len() == 1) => {
                check(t.len() <= MAX_PROMPT_BYTES, "prompt text size")
            }
            _ => Err("prompt payload must be {\"text\": string}".into()),
        },
        ReceiptKind::Interrupt | ReceiptKind::Stop => {
            check(obj.is_some_and(|o| o.is_empty()), "payload (must be {})")
        }
        ReceiptKind::Approval => ApprovalAnswer::parse(payload).map(|_| ()),
        ReceiptKind::ApprovalRuleRevoke => RuleRevoke::parse(payload).map(|_| ()),
    }
}

impl Op {
    fn validate(&self) -> Result<(), String> {
        use BindingUse::{Mutation, Read};
        match self {
            Op::Hello { resume } => resume.as_ref().map_or(Ok(()), |r| {
                uuid(&r.controller_session, "controller_session")
            }),
            Op::Challenge { nonce } => {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                let len = URL_SAFE_NO_PAD.decode(nonce).map(|b| b.len());
                check(len == Ok(32), "nonce")
            }
            Op::ResumeProof { proof } => check(!proof.is_empty(), "proof"),
            Op::Welcome {
                account_id,
                atem_device_id,
                host_trust_gen,
                runtime_gen,
                controller_session,
                attachment_gen,
                authorization_ms_left,
                server_time,
                ..
            } => {
                check(is_opaque_id(account_id), "account_id")?;
                check(is_opaque_id(atem_device_id), "atem_device_id")?;
                safe(*host_trust_gen, "host_trust_gen")?;
                uuid(runtime_gen, "runtime_gen")?;
                uuid(controller_session, "controller_session")?;
                uuid(attachment_gen, "attachment_gen")?;
                safe(*authorization_ms_left, "authorization_ms_left")?;
                safe(*server_time, "server_time")
            }
            Op::List {} | Op::LeaseReleased {} => Ok(()),
            Op::Sessions {
                runtime_gen,
                runtime_epoch,
                seq,
                sessions,
            } => {
                uuid(runtime_gen, "runtime_gen")?;
                safe(*runtime_epoch, "runtime_epoch")?;
                safe(*seq, "seq")?;
                sessions.iter().try_for_each(Descriptor::validate)
            }
            Op::SessionChanged {
                runtime_gen,
                runtime_epoch,
                seq,
                descriptor,
            } => {
                uuid(runtime_gen, "runtime_gen")?;
                safe(*runtime_epoch, "runtime_epoch")?;
                safe(*seq, "seq")?;
                descriptor.validate()
            }
            Op::Acquire { binding, .. } => binding.validate(Read),
            Op::Renew { binding } | Op::Release { binding } => binding.validate(Mutation),
            Op::Lease { binding, ms_left } => {
                binding.validate(Mutation)?;
                safe(*ms_left, "ms_left")
            }
            Op::LeaseChanged {
                session_id,
                process_gen,
                controller,
                lease_epoch,
                ..
            } => {
                check(is_session_id(session_id), "session_id")?;
                uuid(process_gen, "process_gen")?;
                safe(*lease_epoch, "lease_epoch")?;
                controller.as_ref().map_or(Ok(()), Controller::validate)
            }
            Op::Submit {
                binding,
                request_id,
                kind,
                payload,
            } => {
                binding.validate(submit_binding_use(*kind, payload))?;
                uuid(request_id, "request_id")?;
                validate_payload(*kind, payload)
            }
            Op::Receipt(r) => r.validate(),
            Op::ReceiptQuery {
                binding,
                request_ids,
            } => {
                binding.validate(Read)?;
                check(request_ids.len() <= MAX_REQUEST_IDS, "request_ids count")?;
                request_ids.iter().try_for_each(|r| uuid(r, "request_id"))
            }
            Op::Receipts { receipts } => receipts.iter().try_for_each(Receipt::validate),
            Op::ApprovalRequest(r) => r.validate(),
            Op::ApprovalClosed { approval_id, .. } => uuid(approval_id, "approval_id"),
            Op::ApprovalRules {
                session_id,
                process_gen,
                rules,
            } => {
                check(is_session_id(session_id), "session_id")?;
                uuid(process_gen, "process_gen")?;
                validate_session_rules(rules)
            }
            Op::Error { detail: d, .. } => detail(d),
        }
    }
}

impl FamilyMessage {
    fn field(&self, name: &str) -> Option<&str> {
        self.data.as_ref()?.get(name)?.as_str()
    }

    /// Applies `Binding::check_family_ids` with this family's own id fields
    /// (terminal-v1 `terminal_id`/`generation`, chat-v1 `agentId`/`generation`).
    /// Messages without a binding (host messages, other families) have
    /// nothing to compare.
    pub fn check_binding_ids(&self) -> Result<(), ErrorCode> {
        let Some(b) = &self.binding else {
            return Ok(());
        };
        let id_field = match self.family.as_str() {
            "terminal" => "terminal_id",
            "agentChat" => "agentId",
            _ => return Ok(()),
        };
        let id = self.field(id_field).ok_or(ErrorCode::StaleTarget)?;
        b.check_family_ids(id, self.field("generation"))
    }
}

fn fail(id: Option<String>, reason: impl Into<String>) -> DecodeError {
    DecodeError {
        code: ErrorCode::UnsupportedVersion,
        id,
        reason: reason.into(),
        removed: None,
    }
}

fn removed(family: &str, op: Option<&str>) -> DecodeError {
    DecodeError {
        removed: Some(RemovedOp {
            family: family.to_string(),
            op: op.map(str::to_string),
        }),
        ..fail(None, "removed by contract r6")
    }
}

/// Strictly decodes one wire message (see the module docs).
pub fn decode(bytes: &[u8]) -> Result<Envelope, DecodeError> {
    // `parse_strict` checks the size bound before allocating anything.
    let root = canonical::parse_strict(bytes, MAX_MESSAGE_BYTES, Numbers::AllowFractions)
        .map_err(|e| fail(None, format!("{e:?}")))?;
    let Value::Object(mut root) = root else {
        return Err(fail(None, "message is not an object"));
    };
    let family = match root.remove("type") {
        Some(Value::String(t)) => t,
        _ => return Err(fail(None, "missing type")),
    };
    let data = root.remove("data");
    if family == "session" {
        match data {
            Some(Value::Object(d)) => decode_session(d).map(Envelope::Session),
            _ => Err(fail(None, "session data must be an object")),
        }
    } else {
        decode_family(family, data).map(Envelope::Family)
    }
}

fn decode_session(data: Map<String, Value>) -> Result<SessionMessage, DecodeError> {
    let id = match data.get("id") {
        Some(Value::String(s)) if is_uuid_v4(s) => Some(s.clone()),
        _ => None,
    };
    if data.get("v").and_then(Value::as_u64) != Some(VERSION) {
        return Err(fail(id, "unsupported v"));
    }
    let Some(id) = id else {
        return Err(fail(None, "missing or invalid id"));
    };
    let re = match data.get("re") {
        None => None,
        Some(Value::String(s)) if is_uuid_v4(s) => Some(s.clone()),
        Some(_) => return Err(fail(Some(id), "invalid re")),
    };
    let op: Op = serde_json::from_value(Value::Object(data))
        .map_err(|e| fail(Some(id.clone()), e.to_string()))?;
    op.validate().map_err(|e| fail(Some(id.clone()), e))?;
    Ok(SessionMessage { id, re, op })
}

fn decode_family(family: String, mut data: Option<Value>) -> Result<FamilyMessage, DecodeError> {
    if REMOVED_FAMILIES.contains(&family.as_str()) {
        return Err(removed(&family, None));
    }
    let binding = match data.as_mut() {
        Some(Value::Object(m)) => m
            .remove("binding")
            .map(serde_json::from_value::<Binding>)
            .transpose()
            .map_err(|e| fail(None, format!("binding: {e}")))?,
        _ => None,
    };
    let request = match family.as_str() {
        "terminal" => check_terminal(data.as_ref(), binding.as_ref())?,
        "agentChat" => {
            check_chat(data.as_ref(), binding.as_ref())?;
            None
        }
        _ if binding.is_some() => {
            return Err(fail(None, format!("{family} cannot carry a binding")));
        }
        _ => None,
    };
    Ok(FamilyMessage {
        family,
        data,
        binding,
        request,
    })
}

fn family_head(data: Option<&Value>) -> Result<(&Map<String, Value>, &str), DecodeError> {
    let Some(Value::Object(m)) = data else {
        return Err(fail(None, "data must be an object"));
    };
    if m.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(fail(None, "unsupported v"));
    }
    match m.get("op") {
        Some(Value::String(op)) => Ok((m, op)),
        _ => Err(fail(None, "missing op")),
    }
}

/// The binding a terminal-v1/chat-v1 request must carry: absent is the
/// removed unbound form; present, it must fit how the op uses it.
fn require_binding(
    family: &str,
    op: &str,
    binding: Option<&Binding>,
    use_: BindingUse,
) -> Result<(), DecodeError> {
    let b = binding.ok_or_else(|| removed(family, Some(op)))?;
    b.validate(use_)
        .map_err(|e| fail(None, format!("binding: {e}")))
}

/// terminal-v1. Requests decode into `TerminalRequest` with their binding;
/// host messages must decode with `terminal_share` types and carry none.
/// terminal-v1 `list`/`sessions` are removed: session-v1 `list` is the only
/// registry (r6 §0).
fn check_terminal(
    data: Option<&Value>,
    binding: Option<&Binding>,
) -> Result<Option<TerminalRequest>, DecodeError> {
    let (m, op) = family_head(data)?;
    let use_ = match op {
        "control" | "controller" | "list" | "sessions" => {
            return Err(removed("terminal", Some(op)));
        }
        "subscribe" | "unsubscribe" | "ack" => BindingUse::Read,
        "input" | "resize" | "stop" => BindingUse::Mutation,
        _ => {
            if binding.is_some() {
                return Err(fail(None, format!("terminal {op} cannot carry a binding")));
            }
            serde_json::from_value::<crate::terminal_share::Envelope>(Value::Object(m.clone()))
                .map_err(|e| fail(None, format!("terminal: {e}")))?;
            return Ok(None);
        }
    };
    if m.contains_key("lease_id") {
        return Err(removed("terminal", Some(op)));
    }
    require_binding("terminal", op, binding, use_)?;
    let req: TerminalRequest = serde_json::from_value(Value::Object(m.clone()))
        .map_err(|e| fail(None, format!("terminal: {e}")))?;
    req.validate()
        .map_err(|e| fail(None, format!("terminal: {e}")))?;
    Ok(Some(req))
}

/// chat-v1: requests (`open`, `close`, `submit`) carry their binding and must
/// pass `chat::wire::parse_inbound`; `agentId` is a session id and a submit's
/// `requestId` is the §6 `request_id` (UUID v4). Host messages carry none.
fn check_chat(data: Option<&Value>, binding: Option<&Binding>) -> Result<(), DecodeError> {
    let (m, op) = family_head(data)?;
    let env: crate::chat::wire::ChatEnvelope = serde_json::from_value(Value::Object(m.clone()))
        .map_err(|e| fail(None, format!("agentChat: {e}")))?;
    let use_ = match op {
        "open" | "close" => BindingUse::Read,
        // An approval answer (r7) may take the lease with it.
        // A rule revocation (r7.3) needs no lease: `lease_epoch` optional.
        "submit" => match (m.get(RULE_REVOKE_FIELD), m.get("approval")) {
            (Some(revoke), _) => submit_binding_use(ReceiptKind::ApprovalRuleRevoke, revoke),
            (None, Some(answer)) => submit_binding_use(ReceiptKind::Approval, answer),
            (None, None) => BindingUse::Mutation,
        },
        _ if binding.is_some() => {
            return Err(fail(None, format!("agentChat {op} cannot carry a binding")));
        }
        _ => return Ok(()),
    };
    require_binding("agentChat", op, binding, use_)?;
    let bad = |e: String| fail(None, format!("agentChat: {e}"));
    crate::chat::wire::parse_inbound(&env).map_err(bad)?;
    check(is_session_id(&env.agent_id), "agentId").map_err(bad)?;
    if op == "submit" {
        let field = |name| {
            env.body
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
        };
        uuid(field("requestId"), "requestId").map_err(bad)?;
        uuid(field("generation"), "generation").map_err(bad)?;
        if let Some(answer) = env.body.get("approval") {
            ApprovalAnswer::parse(answer).map_err(bad)?;
        }
        if let Some(revoke) = env.body.get(RULE_REVOKE_FIELD) {
            RuleRevoke::parse(revoke).map_err(bad)?;
        }
    }
    Ok(())
}

/// The wire JSON of `env`.
pub fn to_value(env: &Envelope) -> Value {
    match env {
        Envelope::Session(msg) => {
            let Value::Object(mut data) =
                serde_json::to_value(&msg.op).expect("session op serializes")
            else {
                unreachable!("an op serializes to an object")
            };
            data.insert("v".into(), Value::from(VERSION));
            data.insert("id".into(), Value::String(msg.id.clone()));
            if let Some(re) = &msg.re {
                data.insert("re".into(), Value::String(re.clone()));
            }
            serde_json::json!({"type": "session", "data": data})
        }
        Envelope::Family(f) => {
            let mut root = Map::new();
            root.insert("type".into(), Value::String(f.family.clone()));
            let mut data = f.data.clone();
            if let (Some(Value::Object(m)), Some(b)) = (data.as_mut(), &f.binding) {
                m.insert(
                    "binding".into(),
                    serde_json::to_value(b).expect("binding serializes"),
                );
            }
            if let Some(d) = data {
                root.insert("data".into(), d);
            }
            Value::Object(root)
        }
    }
}

pub fn encode(env: &Envelope) -> Vec<u8> {
    serde_json::to_vec(&to_value(env)).expect("wire value serializes")
}

// ── serde helpers ─────────────────────────────────────────────────────────

/// Optional field: absent → `None`; present must be a value (`null` refused).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// Required field that may be `null` (no `default`, so absence is an error).
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

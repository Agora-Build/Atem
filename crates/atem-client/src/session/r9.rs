//! The r9 session messages of §R9.8.
//!
//! The `hello` is the `finish` plaintext: `{"type":"session","data":{"v":1,
//! "op":"hello","id":…,"revision":9,"proof":{"principal":…,"sig":…},
//! "membership":{"head":…,"entries":[…],"more"?:true},"grant"?:…}}`. The
//! client never assembles it: [`crate::channel::Signed::finish_hello`] builds
//! it with [`hello_bytes`] around the `sig_c` it just made, so the proof can't
//! disagree with the transcript. It is sent as `jcs` (the bytes hashed into
//! `th4`), and its `entries` array is exactly the encoding
//! [`crate::channel::carriage::carried_bytes`] measures.
//!
//! The host reads it with [`Hello::parse`] (the proof it needs to derive the
//! record keys; a hello without a readable proof is the clear
//! `handshake_failed`), then [`Hello::check`] (revision 9, the membership and
//! grant fields) whose refusal is the encrypted first record.
use serde_json::{Map, Value, json};

use crate::SignedObject;
use crate::canonical::{StrictValue, jcs};
use crate::channel::carriage::Carriage;
use crate::channel::{ClientProof, MAX_PLAINTEXT, Principal};
use crate::control::{ApplicationResult, ControlRecord, EffectKind, EffectResult};
use crate::encoding::{b64u, b64u_decode};
use crate::membership::Head;
use crate::session::wire::is_uuid_v4;

/// The revision an r9 `hello` must carry and `welcome` echoes.
pub const REVISION: u64 = 9;

/// The features an r9 host advertises: the nine of r8 plus r9's six.
pub const R9_FEATURES: &[&str] = &[
    "membership.carry",
    "push.sealed",
    "approval.seen",
    "grant.revoke",
    "recovery.wait",
    crate::session::host_policy::FEATURE,
];

/// The `hello`'s bytes (`jcs`): what the client seals as `finish` and the
/// host hashes into `th4`. `grant` only for a browser.
pub fn hello_bytes(
    id: &str,
    principal: &Principal,
    sig_c: &[u8],
    carriage: &Carriage,
    grant: Option<&SignedObject>,
) -> Vec<u8> {
    let mut membership = Map::new();
    membership.insert("head".into(), carriage.head.to_json());
    membership.insert(
        "entries".into(),
        Value::Array(carriage.entries.iter().map(SignedObject::to_json).collect()),
    );
    if carriage.more {
        membership.insert("more".into(), Value::Bool(true));
    }
    let mut data = Map::new();
    data.insert("v".into(), json!(1));
    data.insert("op".into(), json!("hello"));
    data.insert("id".into(), json!(id));
    data.insert("revision".into(), json!(REVISION));
    data.insert(
        "proof".into(),
        json!({"principal": principal.to_json(), "sig": b64u(sig_c)}),
    );
    data.insert("membership".into(), Value::Object(membership));
    if let Some(grant) = grant {
        data.insert("grant".into(), grant.to_json());
    }
    let hello = json!({"type": "session", "data": Value::Object(data)});
    jcs(&hello)
        .expect("a hello holds strings, small integers and signed objects")
        .into_bytes()
}

/// The `hello.membership` the host reads.
#[derive(Debug, Clone)]
pub struct HelloMembership {
    /// The head the client reports (its own).
    pub head: Head,
    /// The carried entries as received (`Membership::evaluate` parses them).
    pub entries: Vec<StrictValue>,
    pub more: bool,
}

/// Why a `hello` is refused once its proof was read (the host's encrypted
/// first record: a session `error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloRefusal {
    /// No `revision: 9` (`unsupported_version`, with `revision: 9`, §R9.8),
    /// or a form r9 removed (`resume`).
    UnsupportedVersion,
    /// A field rule broken (`invalid_request`): `membership` missing or
    /// malformed, `id` not a string, a grant beside a non-browser.
    InvalidRequest(&'static str),
}

impl HelloRefusal {
    /// The session `error` the host sends as its first record.
    pub fn to_error(&self, re: Option<&str>) -> SessionError {
        match self {
            HelloRefusal::UnsupportedVersion => SessionError {
                re: re.map(str::to_owned),
                revision: Some(REVISION),
                ..SessionError::new(code::UNSUPPORTED_VERSION)
            },
            HelloRefusal::InvalidRequest(what) => SessionError {
                re: re.map(str::to_owned),
                detail: Some((*what).to_owned()),
                ..SessionError::new(code::INVALID_REQUEST)
            },
        }
    }
}

/// A `hello` as the host received it.
#[derive(Debug, Clone)]
pub struct Hello {
    /// `data.id` (the `welcome`'s `re`), when it is a string.
    pub id: Option<String>,
    /// `data.revision` when it is an integer.
    pub revision: Option<u64>,
    /// What the host keys the channel with (whatever `sig_c` is worth).
    pub proof: ClientProof,
    /// `None` when absent or malformed ([`Hello::check`] refuses it).
    pub membership: Option<HelloMembership>,
    /// The signed grant (a browser's).
    pub grant: Option<SignedObject>,
    resume: bool,
    membership_present: bool,
    id_present: bool,
}

impl Hello {
    /// Reads a `hello`. `None` when no proof can be read (not strict JSON,
    /// not a session `hello`, no `proof{principal, sig}`, or a browser
    /// principal without a readable grant): the host can't derive `th4` and
    /// answers the clear `handshake_failed` ([`crate::channel::Opened::malformed`]).
    pub fn parse(bytes: &[u8]) -> Option<Hello> {
        let root = StrictValue::parse(bytes, MAX_PLAINTEXT).ok()?;
        if root.value().get("type")?.as_str()? != "session" {
            return None;
        }
        let data = root.get("data")?;
        let object = data.value().as_object()?;
        if object.get("op")?.as_str()? != "hello" || object.get("v")?.as_u64()? != 1 {
            return None;
        }
        let grant = match data.get("grant") {
            Some(g) => Some(SignedObject::from_strict(&g).ok()?),
            None => None,
        };
        let proof = data.get("proof")?;
        let proof_object = proof.value().as_object()?;
        if proof_object.len() != 2 {
            return None;
        }
        let principal =
            Principal::from_json(proof.get("principal")?.value(), grant.as_ref()).ok()?;
        let sig_c = b64u_decode(proof_object.get("sig")?.as_str()?).ok()?;
        let membership = data.get("membership").and_then(|m| {
            let object = m.value().as_object()?;
            let allowed = object
                .keys()
                .all(|k| matches!(k.as_str(), "head" | "entries" | "more"));
            if !allowed {
                return None;
            }
            let head = Head::from_json(object.get("head")?)?;
            let entries = m.get("entries")?.items()?;
            let more = match object.get("more") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return None,
            };
            Some(HelloMembership {
                head,
                entries,
                more,
            })
        });
        Some(Hello {
            id: object.get("id").and_then(Value::as_str).map(str::to_owned),
            id_present: object.contains_key("id"),
            revision: object.get("revision").and_then(Value::as_u64),
            proof: ClientProof { principal, sig_c },
            membership_present: object.contains_key("membership"),
            membership,
            grant,
            resume: object.contains_key("resume"),
        })
    }

    /// The field rules once the channel is keyed: `revision: 9` first (so a
    /// revision-8 hello is `unsupported_version` whatever else it carries),
    /// no `resume`, a string `id`, and a well-formed `membership`.
    pub fn check(&self) -> Result<&HelloMembership, HelloRefusal> {
        if self.revision != Some(REVISION) || self.resume {
            return Err(HelloRefusal::UnsupportedVersion);
        }
        if !self.id_present || self.id.is_none() {
            return Err(HelloRefusal::InvalidRequest("hello.id"));
        }
        if !self.membership_present {
            return Err(HelloRefusal::InvalidRequest("hello.membership"));
        }
        self.membership
            .as_ref()
            .ok_or(HelloRefusal::InvalidRequest("hello.membership"))
    }
}

/// Session error codes used in r9 (§R9.11 and r8's).
pub mod code {
    pub const HANDSHAKE_FAILED: &str = "handshake_failed";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const FORBIDDEN: &str = "forbidden";
    pub const MEMBERSHIP_INVALID: &str = "membership_invalid";
    pub const MEMBERSHIP_INCOMPLETE: &str = "membership_incomplete";
    pub const RECOVERY_PENDING: &str = "recovery_pending";
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const ACCOUNT_FROZEN: &str = "account_frozen";
    pub const BUSY: &str = "busy";
    pub const STALE_TARGET: &str = "stale_target";
    pub const UNKNOWN_SESSION: &str = "unknown_session";
}

/// A session `error` with r9's fields (§R9.11): `head`, `index`, `detail`
/// and `need_before` for `membership_invalid`; `head` for
/// `membership_incomplete`; `entry_hash`/`effective_at` for
/// `recovery_pending`; `revision` for `unsupported_version`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionError {
    pub id: Option<String>,
    pub re: Option<String>,
    pub code: String,
    pub detail: Option<String>,
    pub revision: Option<u64>,
    pub head: Option<Head>,
    pub index: Option<u64>,
    pub need_before: Option<u64>,
    pub entry_hash: Option<crate::Hash32>,
    pub effective_at: Option<u64>,
    /// r8 §F: the lease holder a `lease_held` names (a confirmed takeover
    /// sends it back as `expected_controller`).
    pub controller: Option<crate::session::wire::Controller>,
}

impl SessionError {
    /// A new error with a fresh message `id` (every session message has
    /// one, so r8's decoder and machines read it too).
    pub fn new(code: &str) -> Self {
        SessionError {
            id: Some(crate::session::new_id()),
            code: code.to_owned(),
            ..Default::default()
        }
    }

    /// The wire message.
    pub fn to_json(&self) -> Value {
        let mut data = Map::new();
        data.insert("v".into(), json!(1));
        data.insert("op".into(), json!("error"));
        if let Some(id) = &self.id {
            data.insert("id".into(), json!(id));
        }
        if let Some(re) = &self.re {
            data.insert("re".into(), json!(re));
        }
        data.insert("code".into(), json!(self.code));
        if let Some(detail) = &self.detail {
            data.insert("detail".into(), json!(detail));
        }
        if let Some(revision) = self.revision {
            data.insert("revision".into(), json!(revision));
        }
        if let Some(head) = &self.head {
            data.insert("head".into(), head.to_json());
        }
        if let Some(index) = self.index {
            data.insert("index".into(), json!(index));
        }
        if let Some(need_before) = self.need_before {
            data.insert("need_before".into(), json!(need_before));
        }
        if let Some(hash) = &self.entry_hash {
            data.insert("entry_hash".into(), json!(hash.to_hex()));
        }
        if let Some(at) = self.effective_at {
            data.insert("effective_at".into(), json!(at));
        }
        if let Some(c) = &self.controller {
            data.insert(
                "controller".into(),
                json!({"controller_session": c.controller_session, "lease_epoch": c.lease_epoch}),
            );
        }
        json!({"type": "session", "data": Value::Object(data)})
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_json().to_string().into_bytes()
    }

    /// Reads a session `error` (`data.op == "error"`); `None` for anything
    /// else. Unknown fields are ignored (§1); known ones must be well typed.
    pub fn from_data(data: &Value) -> Option<SessionError> {
        let object = data.as_object()?;
        if object.get("op")?.as_str()? != "error" {
            return None;
        }
        let opt_str = |k: &str| -> Option<Option<String>> {
            match object.get(k) {
                None => Some(None),
                Some(v) => Some(Some(v.as_str()?.to_owned())),
            }
        };
        let opt_u64 = |k: &str| -> Option<Option<u64>> {
            match object.get(k) {
                None => Some(None),
                Some(v) => Some(Some(v.as_u64()?)),
            }
        };
        Some(SessionError {
            id: opt_str("id")?,
            re: opt_str("re")?,
            code: object.get("code")?.as_str()?.to_owned(),
            detail: opt_str("detail")?,
            revision: opt_u64("revision")?,
            head: match object.get("head") {
                None => None,
                Some(h) => Some(Head::from_json(h)?),
            },
            index: opt_u64("index")?,
            need_before: opt_u64("need_before")?,
            entry_hash: match object.get("entry_hash") {
                None => None,
                Some(h) => Some(crate::Hash32::from_hex(h.as_str()?).ok()?),
            },
            effective_at: opt_u64("effective_at")?,
            controller: match object.get("controller") {
                None | Some(Value::Null) => None,
                Some(c) => Some(crate::session::wire::Controller {
                    controller_session: c.get("controller_session")?.as_str()?.to_owned(),
                    lease_epoch: c.get("lease_epoch")?.as_u64()?,
                }),
            },
        })
    }
}

// ---------------------------------------------------------------- welcome

/// One entry of `pending_recovery` (§R9.5, §R9.8): what is pending on the
/// host, `effective_at` on the host's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRecovery {
    pub entry_hash: crate::Hash32,
    pub seq: u64,
    /// `recovery_add` or `set_recovery_key`.
    pub action: String,
    /// The member for `recovery_add`, the requesting manager for
    /// `set_recovery_key`.
    pub subject: String,
    pub effective_at: u64,
}

impl PendingRecovery {
    pub fn to_json(&self) -> Value {
        json!({"entry_hash": self.entry_hash.to_hex(), "seq": self.seq, "action": self.action,
               "subject": self.subject, "effective_at": self.effective_at})
    }

    pub fn from_json(value: &Value) -> Option<PendingRecovery> {
        let o = value.as_object()?;
        Some(PendingRecovery {
            entry_hash: crate::Hash32::from_hex(o.get("entry_hash")?.as_str()?).ok()?,
            seq: o.get("seq")?.as_u64()?,
            action: o.get("action")?.as_str()?.to_owned(),
            subject: o.get("subject")?.as_str()?.to_owned(),
            effective_at: o.get("effective_at")?.as_u64()?,
        })
    }

    /// The host's own list ([`crate::membership::Membership::pending_recovery`]).
    pub fn of(summary: &crate::membership::PendingSummary) -> PendingRecovery {
        PendingRecovery {
            entry_hash: summary.entry_hash,
            seq: summary.seq,
            action: summary.action.to_owned(),
            subject: summary.subject.clone(),
            effective_at: summary.effective_at,
        }
    }
}

fn pending_list(value: &Value) -> Option<Vec<PendingRecovery>> {
    value
        .as_array()?
        .iter()
        .map(PendingRecovery::from_json)
        .collect()
}

/// The r9 `welcome` (§R9.8): r8's fields with `revision: 9`, plus the
/// principal, its kind, permissions and scope, the head after the carriage,
/// `pending_recovery` (always present), `channel_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    pub id: String,
    pub re: Option<String>,
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
    pub runtime_gen: String,
    pub controller_session: String,
    pub attachment_gen: String,
    pub client_kind: crate::principal::ClientKind,
    pub permissions: Vec<crate::principal::Permission>,
    pub authorization_ms_left: u64,
    pub server_time: u64,
    pub revision: u64,
    pub features: Vec<String>,
    pub principal: String,
    pub scope: Option<crate::principal::ScopeView>,
    pub head: Head,
    pub pending_recovery: Vec<PendingRecovery>,
    pub channel_id: String,
}

impl Welcome {
    pub fn to_json(&self) -> Value {
        let mut data = json!({
            "v": 1, "op": "welcome", "id": self.id,
            "account_id": self.account_id, "atem_device_id": self.atem_device_id,
            "host_trust_gen": self.host_trust_gen, "runtime_gen": self.runtime_gen,
            "controller_session": self.controller_session, "attachment_gen": self.attachment_gen,
            "client_kind": self.client_kind.as_str(),
            "permissions": self.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            "authorization_ms_left": self.authorization_ms_left, "server_time": self.server_time,
            "revision": self.revision, "features": self.features,
            "principal": self.principal, "head": self.head.to_json(),
            "pending_recovery": self.pending_recovery.iter().map(PendingRecovery::to_json).collect::<Vec<_>>(),
            "channel_id": self.channel_id,
        });
        if let Some(re) = &self.re {
            data["re"] = json!(re);
        }
        if let Some(scope) = &self.scope {
            data["scope"] = scope.to_json();
        }
        json!({"type": "session", "data": data})
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_json().to_string().into_bytes()
    }

    /// Reads a `welcome`'s `data` (unknown fields ignored, §1; every field
    /// above required, `scope` optional). The client's checks against its
    /// own state are [`crate::connect`]'s.
    pub fn from_data(data: &Value) -> Result<Welcome, &'static str> {
        use crate::principal::{ClientKind, Permission, ScopeView};
        let o = data.as_object().ok_or("welcome")?;
        if o.get("op").and_then(Value::as_str) != Some("welcome") {
            return Err("op");
        }
        let s = |k: &'static str| -> Result<String, &'static str> {
            o.get(k).and_then(Value::as_str).map(str::to_owned).ok_or(k)
        };
        let n = |k: &'static str| -> Result<u64, &'static str> {
            o.get(k).and_then(Value::as_u64).ok_or(k)
        };
        let permissions = o
            .get("permissions")
            .and_then(Value::as_array)
            .ok_or("permissions")?
            .iter()
            .map(|p| match p.as_str() {
                Some("view") => Ok(Permission::View),
                Some("control") => Ok(Permission::Control),
                _ => Err("permissions"),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let features = o
            .get("features")
            .and_then(Value::as_array)
            .ok_or("features")?
            .iter()
            .map(|f| f.as_str().map(str::to_owned).ok_or("features"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Welcome {
            id: s("id")?,
            re: match o.get("re") {
                None => None,
                Some(v) => Some(v.as_str().ok_or("re")?.to_owned()),
            },
            account_id: s("account_id")?,
            atem_device_id: s("atem_device_id")?,
            host_trust_gen: n("host_trust_gen")?,
            runtime_gen: s("runtime_gen")?,
            controller_session: s("controller_session")?,
            attachment_gen: s("attachment_gen")?,
            client_kind: ClientKind::parse(&s("client_kind")?).ok_or("client_kind")?,
            permissions,
            authorization_ms_left: n("authorization_ms_left")?,
            server_time: n("server_time")?,
            revision: n("revision")?,
            features,
            principal: s("principal")?,
            scope: match o.get("scope") {
                None => None,
                Some(v) => Some(ScopeView::from_json(v).ok_or("scope")?),
            },
            head: o.get("head").and_then(Head::from_json).ok_or("head")?,
            pending_recovery: o
                .get("pending_recovery")
                .and_then(pending_list)
                .ok_or("pending_recovery")?,
            channel_id: s("channel_id")?,
        })
    }
}

// ------------------------------------------------- the new session ops

fn session(data: Value) -> Value {
    json!({"type": "session", "data": data})
}

/// `membership{entries}` (C→H): entries carried on an open channel.
pub fn membership_op(id: &str, entries: &[SignedObject]) -> Value {
    session(json!({"v": 1, "op": "membership", "id": id,
        "entries": entries.iter().map(SignedObject::to_json).collect::<Vec<_>>()}))
}

/// `membership_head{re?, head, pending_recovery}` (H→C): the reply to
/// `membership`, or an event when the head moves or a pending entry changes.
pub fn membership_head(
    id: &str,
    re: Option<&str>,
    head: Head,
    pending: &[PendingRecovery],
) -> Value {
    let mut data = json!({"v": 1, "op": "membership_head", "id": id, "head": head.to_json(),
        "pending_recovery": pending.iter().map(PendingRecovery::to_json).collect::<Vec<_>>()});
    if let Some(re) = re {
        data["re"] = json!(re);
    }
    session(data)
}

/// `revoke_grant{grant_id}` (C→H).
pub fn revoke_grant(id: &str, grant_id: &str) -> Value {
    session(json!({"v": 1, "op": "revoke_grant", "id": id, "grant_id": grant_id}))
}

/// `grant_revoked{re}` (H→C).
pub fn grant_revoked(id: &str, re: &str) -> Value {
    session(json!({"v": 1, "op": "grant_revoked", "id": id, "re": re}))
}

/// `approval_seen{binding, approval_id}` (C→H, §R9.9): send only when the
/// card was rendered in a focused foreground window and the user was active
/// in the last 60 s.
pub fn approval_seen(id: &str, binding: &Value, approval_id: &str) -> Value {
    session(
        json!({"v": 1, "op": "approval_seen", "id": id, "binding": binding,
        "approval_id": approval_id}),
    )
}

/// `seen{re}` (H→C).
pub fn seen(id: &str, re: &str) -> Value {
    session(json!({"v": 1, "op": "seen", "id": id, "re": re}))
}

/// The most records one `control_records` message carries.
pub const MAX_CONTROL_RECORDS: usize = 64;
/// The most bytes one `control_records` message is: its plaintext, as sealed.
pub const MAX_CONTROL_RECORDS_BYTES: usize = 256 * 1024;
/// Why a `control_records` message holding a service's record is refused.
const NOT_A_HOST_RECORD: &str = "not a host principal's record";

/// `control_records{records}` (C→H, feature [`SENDERS_FEATURE`]): control
/// records carried to the host on an open channel, the signed objects as
/// they are. It is for native members, as `membership` is for entries, and
/// the host answers one [`ControlRecordsResult`]. It carries **host
/// principals' records only** (`host:<host_id>`, a native manager's
/// `interrupt_running`): a service's record travels only in its Station's
/// feed, and a message holding one is refused whole.
///
/// **Carriage order.** A carrier sends `membership` up to its head before
/// `control_records` on a channel: a record is verified against the device
/// list the host has applied. One whose principal or native signer isn't
/// in that list yet waits (`pending`, `principal_unknown` or
/// `signer_unknown`), but one signed by a native the list holds without
/// `manage`, a promotion the host hasn't applied yet included, is refused
/// (`signer_not_allowed`), not held for the entry to come; delivering the
/// same record again after `membership` brought the host to the promotion
/// is enough (a refused record takes no `record_id`).
///
/// **A carrier gets no authority from carrying** ("trust the signature, not
/// the sender", account-trust §3.5): the host verifies each record against
/// its own device list and applies it as I.5.5 says, whoever sent it. A
/// message is one to 64 records and at most 256 KiB: [`MAX_CONTROL_RECORDS`]
/// and [`MAX_CONTROL_RECORDS_BYTES`]. Nothing here advertises the op: a
/// client never sends it to a host that didn't list the feature, and a host
/// that didn't refuses it.
///
/// `Err` for what the host would refuse: none, too many, a service's
/// record, over the size.
///
/// [`SENDERS_FEATURE`]: crate::session::host_work::SENDERS_FEATURE
pub fn control_records_op(id: &str, records: &[ControlRecord]) -> Result<Value, &'static str> {
    if records.is_empty() {
        return Err("no records");
    }
    if records.len() > MAX_CONTROL_RECORDS {
        return Err("too many records");
    }
    if !records.iter().all(|r| r.principal().is_host()) {
        return Err(NOT_A_HOST_RECORD);
    }
    let message = session(json!({"v": 1, "op": "control_records", "id": id,
        "records": records.iter().map(|r| r.object().to_json()).collect::<Vec<_>>()}));
    if message.to_string().len() > MAX_CONTROL_RECORDS_BYTES {
        return Err("message too large");
    }
    Ok(message)
}

/// A `control_records` message as the host reads it: the records, parsed
/// (structure only; verifying and applying them is the host's, I.5.4 and
/// I.5.5), in the order sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecordsRequest {
    pub id: String,
    pub records: Vec<ControlRecord>,
}

impl ControlRecordsRequest {
    /// Reads a received plaintext, strictly (I-JSON, no duplicate keys,
    /// integers only): exactly `{"type":"session","data":{"v":1,"op":
    /// "control_records","id":<UUID v4>,"records":[…]}}`, one to 64 records
    /// of at most 256 KiB in all. Each record must parse as a control
    /// record of a host principal (`host:<host_id>`); one that doesn't, or a
    /// service's record, spoils the message, and nothing is read partly.
    /// `Err` is a short reason, fit for the error's `detail`.
    pub fn decode(plain: &[u8]) -> Result<Self, &'static str> {
        let root = StrictValue::parse(plain, MAX_CONTROL_RECORDS_BYTES).map_err(|e| match e {
            crate::canonical::StrictError::TooLarge => "message too large",
            _ => "not strict JSON",
        })?;
        const SHAPE: &str = "not a control_records message";
        let shape = |ok: bool| if ok { Ok(()) } else { Err(SHAPE) };
        let value = root.value();
        shape(value.as_object().is_some_and(|o| o.len() == 2) && value["type"] == "session")?;
        let data = value["data"].as_object().ok_or(SHAPE)?;
        shape(
            data.len() == 4
                && data.get("v").and_then(Value::as_u64) == Some(1)
                && data.get("op").and_then(Value::as_str) == Some("control_records"),
        )?;
        let id = data
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_uuid_v4(id))
            .ok_or(SHAPE)?
            .to_owned();
        let items = root
            .get("data")
            .and_then(|d| d.get("records"))
            .and_then(|r| r.items())
            .ok_or(SHAPE)?;
        if items.is_empty() {
            return Err("no records");
        }
        if items.len() > MAX_CONTROL_RECORDS {
            return Err("too many records");
        }
        let records = items
            .iter()
            .map(|item| {
                let record = SignedObject::from_strict(item)
                    .ok()
                    .and_then(|object| ControlRecord::from_signed(object).ok())
                    .ok_or("not a control record")?;
                if record.principal().is_host() {
                    Ok(record)
                } else {
                    Err(NOT_A_HOST_RECORD)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ControlRecordsRequest { id, records })
    }
}

/// One record's result in a `control_records_result`: the record's, and
/// each effect it carries with its own (I.5.8, "results and counts are per
/// effect"). The words are [`ApplicationResult::code`] and
/// [`EffectKind::code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordResult {
    pub record_id: String,
    pub result: ApplicationResult,
    /// Every effect the record carries, once each.
    pub effects: Vec<EffectResult>,
}

impl RecordResult {
    fn to_json(&self) -> Value {
        json!({"record_id": self.record_id, "result": self.result.code(),
            "effects": self.effects.iter().map(|e| json!({
                "effect": e.effect.code(), "result": e.result.code()})).collect::<Vec<_>>()})
    }

    fn from_json(value: &Value) -> Result<Self, &'static str> {
        let o = value
            .as_object()
            .filter(|o| o.len() == 3)
            .ok_or("results")?;
        let record_id = o
            .get("record_id")
            .and_then(Value::as_str)
            .filter(|id| is_uuid_v4(id))
            .ok_or("record_id")?
            .to_owned();
        let result = o
            .get("result")
            .and_then(Value::as_str)
            .and_then(ApplicationResult::from_code)
            .ok_or("result")?;
        let mut effects: Vec<EffectResult> = Vec::new();
        for item in o
            .get("effects")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
            .ok_or("effects")?
        {
            let e = item.as_object().filter(|e| e.len() == 2).ok_or("effects")?;
            let effect = e
                .get("effect")
                .and_then(Value::as_str)
                .and_then(EffectKind::from_code)
                .ok_or("effects")?;
            let result = e
                .get("result")
                .and_then(Value::as_str)
                .and_then(ApplicationResult::from_code)
                .ok_or("effects")?;
            if effects.iter().any(|seen| seen.effect == effect) {
                return Err("effects");
            }
            effects.push(EffectResult { effect, result });
        }
        Ok(RecordResult {
            record_id,
            result,
            effects,
        })
    }
}

/// `control_records_result{re, results}` (H→C): the answer to one
/// `control_records`, one result per record, in the order sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecordsResult {
    pub id: String,
    /// The `id` of the `control_records` it answers.
    pub re: String,
    pub results: Vec<RecordResult>,
}

impl ControlRecordsResult {
    /// Reads a `control_records_result`'s `data`: exactly its fields, the
    /// words of the vocabulary, UUID v4 ids, and one to 64 results.
    pub fn from_data(data: &Value) -> Result<Self, &'static str> {
        let o = data.as_object().ok_or("data")?;
        if o.get("op").and_then(Value::as_str) != Some("control_records_result") {
            return Err("op");
        }
        if o.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("v");
        }
        if o.len() != 5 {
            return Err("fields");
        }
        let uuid = |k: &'static str| -> Result<String, &'static str> {
            o.get(k)
                .and_then(Value::as_str)
                .filter(|s| is_uuid_v4(s))
                .map(str::to_owned)
                .ok_or(k)
        };
        let results = o
            .get("results")
            .and_then(Value::as_array)
            .filter(|a| (1..=MAX_CONTROL_RECORDS).contains(&a.len()))
            .ok_or("results")?
            .iter()
            .map(RecordResult::from_json)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ControlRecordsResult {
            id: uuid("id")?,
            re: uuid("re")?,
            results,
        })
    }

    /// The wire message.
    pub fn to_json(&self) -> Value {
        session(
            json!({"v": 1, "op": "control_records_result", "id": self.id, "re": self.re,
            "results": self.results.iter().map(RecordResult::to_json).collect::<Vec<_>>()}),
        )
    }

    /// Whether this answers the request `request_id` that carried
    /// `record_ids`: its `re`, and one result per record, in order.
    pub fn answers(&self, request_id: &str, record_ids: &[String]) -> bool {
        self.re == request_id
            && self.results.len() == record_ids.len()
            && self
                .results
                .iter()
                .zip(record_ids)
                .all(|(result, id)| &result.record_id == id)
    }
}

/// `control_records_result{re, results}` (H→C).
pub fn control_records_result(id: &str, re: &str, results: &[RecordResult]) -> Value {
    ControlRecordsResult {
        id: id.into(),
        re: re.into(),
        results: results.to_vec(),
    }
    .to_json()
}

/// `host_enc_key_get{}` (C→H, feature [`SENDERS_FEATURE`]; delegated
/// host-work design II.4.1, session-v1 R9.14): a native manager asks the
/// host for the encryption key it vouches for, to draft the `host_enc_key`
/// device-list entry. The host answers one [`HostEncKey`]. Only native
/// members holding `manage` at the host's head get it (the channel admits
/// no service or browser; `manage` is checked when the host handles it).
/// Nothing here advertises the op.
///
/// [`SENDERS_FEATURE`]: crate::session::host_work::SENDERS_FEATURE
pub fn host_enc_key_get(id: &str) -> Value {
    session(json!({"v": 1, "op": "host_enc_key_get", "id": id}))
}

/// A `host_enc_key_get` as the host reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEncKeyGet {
    pub id: String,
}

impl HostEncKeyGet {
    /// Reads a received plaintext, strictly (I-JSON, no duplicate keys):
    /// exactly `{"type":"session","data":{"v":1,"op":"host_enc_key_get",
    /// "id":<UUID v4>}}`. `Err` is a short reason, fit for the error's
    /// `detail`.
    pub fn decode(plain: &[u8]) -> Result<Self, &'static str> {
        const SHAPE: &str = "not a host_enc_key_get message";
        let root = StrictValue::parse(plain, MAX_PLAINTEXT).map_err(|_| "not strict JSON")?;
        let value = root.value();
        let data = value
            .as_object()
            .filter(|o| o.len() == 2 && value["type"] == "session")
            .and_then(|_| value["data"].as_object())
            .filter(|d| {
                d.len() == 3
                    && d.get("v").and_then(Value::as_u64) == Some(1)
                    && d.get("op").and_then(Value::as_str) == Some("host_enc_key_get")
            })
            .ok_or(SHAPE)?;
        let id = data
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_uuid_v4(id))
            .ok_or(SHAPE)?;
        Ok(HostEncKeyGet { id: id.to_owned() })
    }
}

/// `host_enc_key{re, host_id, host_trust_gen, enc_key, enc_sig}` (H→C): the
/// answer to one `host_enc_key_get`. The host's X25519 key for its current
/// trust generation and the host's `enc_sig` over it, by its `host_key`
/// (the newest `add_host`'s), in the `host_enc_key` entry's own forms: what
/// a manager needs to draft the entry ([`HostEncKey::action`]). The binding
/// verifies on its own, so the channel needs no trust: the device-list
/// verifier checks it against the chain (`bad_enc_sig`,
/// `host_trust_gen_not_current`), and `check_change` says first when the
/// key was set before (`enc_key_reused`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEncKey {
    pub id: String,
    /// The `id` of the `host_enc_key_get` it answers.
    pub re: String,
    /// The host's `atem_device_id` (its `host_id` in the device list).
    pub host_id: String,
    pub host_trust_gen: u64,
    /// X25519.
    pub enc_key: crate::keys::PublicKey,
    /// 64 bytes: Ed25519 by the host's `host_key` over
    /// [`crate::membership::host_enc_sig_input`].
    pub enc_sig: Vec<u8>,
}

impl HostEncKey {
    /// Reads a `host_enc_key`'s `data`: exactly its fields, UUID v4 ids, an
    /// id-grammar `host_id`, a generation of 1 or more, an X25519 key and a
    /// 64-byte signature.
    pub fn from_data(data: &Value) -> Result<Self, &'static str> {
        let o = data.as_object().ok_or("data")?;
        if o.get("op").and_then(Value::as_str) != Some("host_enc_key") {
            return Err("op");
        }
        if o.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("v");
        }
        // `v`, `op`, `id`, `re`, `host_id`, `host_trust_gen`, `enc_key`,
        // `enc_sig`.
        if o.len() != 8 {
            return Err("fields");
        }
        let uuid = |k: &'static str| -> Result<String, &'static str> {
            o.get(k)
                .and_then(Value::as_str)
                .filter(|s| is_uuid_v4(s))
                .map(str::to_owned)
                .ok_or(k)
        };
        let host_id = o
            .get("host_id")
            .and_then(Value::as_str)
            .filter(|id| crate::membership::entry::id_ok(id))
            .ok_or("host_id")?
            .to_owned();
        let host_trust_gen = o
            .get("host_trust_gen")
            .and_then(Value::as_u64)
            .filter(|g| (1..=crate::canonical::MAX_SAFE_INTEGER).contains(g))
            .ok_or("host_trust_gen")?;
        let enc_key = o
            .get("enc_key")
            .and_then(|k| crate::keys::PublicKey::from_json_as(k, crate::keys::Alg::X25519).ok())
            .ok_or("enc_key")?;
        let enc_sig = o
            .get("enc_sig")
            .and_then(Value::as_str)
            .and_then(|s| crate::encoding::b64u_decode_array::<64>(s).ok())
            .ok_or("enc_sig")?
            .to_vec();
        Ok(HostEncKey {
            id: uuid("id")?,
            re: uuid("re")?,
            host_id,
            host_trust_gen,
            enc_key,
            enc_sig,
        })
    }

    /// The wire message.
    pub fn to_json(&self) -> Value {
        session(
            json!({"v": 1, "op": "host_enc_key", "id": self.id, "re": self.re,
            "host_id": self.host_id, "host_trust_gen": self.host_trust_gen,
            "enc_key": self.enc_key.to_json(), "enc_sig": b64u(&self.enc_sig)}),
        )
    }

    /// Whether this answers the request `request_id` on a channel to
    /// `host_id` at `host_trust_gen` (the welcome's `atem_device_id` and
    /// `host_trust_gen`): a key of another host or generation is no answer.
    pub fn answers(&self, request_id: &str, host_id: &str, host_trust_gen: u64) -> bool {
        self.re == request_id && self.host_id == host_id && self.host_trust_gen == host_trust_gen
    }

    /// The `host_enc_key` action a manager drafts from it
    /// ([`crate::membership::host_enc_key`]); `retire_previous` after a
    /// suspected compromise, `signed_at` the time it signs.
    pub fn action(
        &self,
        retire_previous: bool,
        signed_at: u64,
    ) -> Result<crate::membership::Action, crate::membership::Invalid> {
        crate::membership::host_enc_key(
            &self.host_id,
            self.host_trust_gen,
            &self.enc_key,
            &self.enc_sig,
            retire_previous,
            signed_at,
        )
    }
}

/// A session-family message a client received, r9's own ops read here; the
/// rest goes to r8's decoder ([`crate::session::wire::decode`]).
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    Welcome(Box<Welcome>),
    /// A session `error` with r9's fields (also for r8's codes).
    Error(SessionError),
    MembershipHead {
        re: Option<String>,
        head: Head,
        pending_recovery: Vec<PendingRecovery>,
    },
    GrantRevoked {
        re: String,
    },
    Seen {
        re: String,
    },
    HostPolicyResult(Box<crate::session::host_policy::HostPolicyResult>),
    HostWorkResult(Box<crate::session::host_work::Response>),
    HostPolicyChanged(Box<crate::session::host_policy::HostPolicyChanged>),
    /// A `control_records_result` (H→C).
    ControlRecordsResult(ControlRecordsResult),
    /// A `host_enc_key` (H→C), the answer to `host_enc_key_get`.
    HostEncKey(Box<HostEncKey>),
    /// Any other message (r8's session ops, terminal-v1, chat-v1).
    Other,
}

impl Incoming {
    /// Classifies a record's plaintext. `Err` for something that isn't a
    /// readable session-family message, or an r9 op with bad fields.
    pub fn parse(plain: &[u8]) -> Result<Incoming, &'static str> {
        let root = crate::canonical::parse_strict(
            plain,
            MAX_PLAINTEXT,
            crate::canonical::Numbers::AllowFractions,
        )
        .map_err(|_| "not strict JSON")?;
        if root.get("type").and_then(Value::as_str) != Some("session") {
            return Ok(Incoming::Other);
        }
        let data = root.get("data").ok_or("data")?;
        let re = || data.get("re").and_then(Value::as_str).map(str::to_owned);
        Ok(match data.get("op").and_then(Value::as_str).ok_or("op")? {
            "welcome" => Incoming::Welcome(Box::new(Welcome::from_data(data)?)),
            "error" => Incoming::Error(SessionError::from_data(data).ok_or("error")?),
            "membership_head" => Incoming::MembershipHead {
                re: re(),
                head: data.get("head").and_then(Head::from_json).ok_or("head")?,
                pending_recovery: data
                    .get("pending_recovery")
                    .and_then(pending_list)
                    .ok_or("pending_recovery")?,
            },
            "grant_revoked" => Incoming::GrantRevoked {
                re: re().ok_or("re")?,
            },
            "seen" => Incoming::Seen {
                re: re().ok_or("re")?,
            },
            "host_policy_result" => Incoming::HostPolicyResult(Box::new(
                crate::session::host_policy::HostPolicyResult::from_data(data)?,
            )),
            "host_work_result" => Incoming::HostWorkResult(Box::new(
                crate::session::host_work::Response::from_data(data)?,
            )),
            "host_policy_changed" => Incoming::HostPolicyChanged(Box::new(
                crate::session::host_policy::HostPolicyChanged::from_data(data)?,
            )),
            "control_records_result" => {
                Incoming::ControlRecordsResult(ControlRecordsResult::from_data(data)?)
            }
            "host_enc_key" => Incoming::HostEncKey(Box::new(HostEncKey::from_data(data)?)),
            _ => Incoming::Other,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `control_records` and its result (delegated host-work design II.3.1,
    /// plan Task 12).
    mod control_records {
        use super::*;

        const ID: &str = "aaaaaaaa-0000-4000-8000-0000000000c1";
        const RE: &str = "aaaaaaaa-0000-4000-8000-0000000000c2";

        /// A host principal's `interrupt_running`, number `n` (the record id
        /// varies; the signature is of the right shape, which the parse
        /// never verifies).
        fn record(n: u64) -> ControlRecord {
            let body = json!({
                "type": "atem-host-work-control", "v": 1,
                "account_id": "acct-test-1", "genesis_hash": "11".repeat(32),
                "principal": "host:host-a", "signer": "member:dev-mac",
                "action": "interrupt_running", "revoke_seq": 7,
                "record_id": format!("0b9a8c7d-6e5f-4a3b-9c2d-{n:012x}"),
                "issued_at": 1_793_620_800_000u64,
                "about": {"by": "owner"},
            });
            ControlRecord::parse(
                json!({"body": body, "sig": b64u(&[7u8; 64])})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap()
        }

        fn records(count: u64) -> Vec<ControlRecord> {
            (1..=count).map(record).collect()
        }

        /// A service's record (a native manager's revoke of `service:svc-1`),
        /// number `n`: well formed, but its place is its Station's feed.
        fn service_record(n: u64) -> ControlRecord {
            let body = json!({
                "type": "atem-host-work-control", "v": 1,
                "account_id": "acct-test-1", "genesis_hash": "11".repeat(32),
                "origin": "https://station-dev.agora.build",
                "feed_id": "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
                "principal": "service:svc-1", "principal_key": "22".repeat(32),
                "signer": "member:dev-mac",
                "action": "revoke", "interrupt_running": true,
                "record_id": format!("0b9a8c7d-6e5f-4a3b-9c2d-{n:012x}"),
                "issued_at": 1_793_620_800_000u64,
                "about": {"integration_id": "i-01jc5zq9x8w7v6t5s4r3q2p1n0", "by": "owner"},
            });
            ControlRecord::parse(
                json!({"body": body, "sig": b64u(&[7u8; 64])})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap()
        }

        fn ids(records: &[ControlRecord]) -> Vec<String> {
            records.iter().map(|r| r.record_id().to_owned()).collect()
        }

        fn effect(effect: EffectKind, result: ApplicationResult) -> EffectResult {
            EffectResult { effect, result }
        }

        fn results_for(records: &[ControlRecord]) -> Vec<RecordResult> {
            records
                .iter()
                .enumerate()
                .map(|(i, r)| match i % 3 {
                    0 => RecordResult {
                        record_id: r.record_id().to_owned(),
                        result: ApplicationResult::Applied,
                        effects: vec![effect(EffectKind::Interrupt, ApplicationResult::Applied)],
                    },
                    1 => RecordResult {
                        record_id: r.record_id().to_owned(),
                        result: ApplicationResult::Pending,
                        effects: vec![
                            effect(EffectKind::Revocation, ApplicationResult::Duplicate),
                            effect(EffectKind::Interrupt, ApplicationResult::Pending),
                        ],
                    },
                    _ => RecordResult {
                        record_id: r.record_id().to_owned(),
                        result: ApplicationResult::Refused,
                        effects: vec![effect(EffectKind::Interrupt, ApplicationResult::Refused)],
                    },
                })
                .collect()
        }

        fn bytes(message: &Value) -> Vec<u8> {
            message.to_string().into_bytes()
        }

        /// The message, as sent and as the host reads it.
        #[test]
        fn control_records_round_trip() {
            let sent = records(3);
            let message = control_records_op(ID, &sent).unwrap();
            assert_eq!(message["type"], "session");
            let data = &message["data"];
            assert_eq!(data["v"], 1);
            assert_eq!(data["op"], "control_records");
            assert_eq!(data["id"], ID);
            assert_eq!(data.as_object().unwrap().len(), 4);
            for (wire, record) in data["records"].as_array().unwrap().iter().zip(&sent) {
                assert_eq!(wire, &record.object().to_json(), "the signed object as is");
            }
            // The host reads exactly what was sent, in order.
            let plain = bytes(&message);
            assert!(plain.len() <= MAX_CONTROL_RECORDS_BYTES);
            let read = ControlRecordsRequest::decode(&plain).unwrap();
            assert_eq!(read.id, ID);
            assert_eq!(read.records, sent);
            // The client classifies its own op as nothing it reads.
            assert_eq!(Incoming::parse(&plain), Ok(Incoming::Other));

            // The result: one per record, per-effect results; written and
            // read again, bound to the request.
            let results = results_for(&sent);
            let reply = control_records_result(RE, ID, &results);
            assert_eq!(reply["type"], "session");
            assert_eq!(reply["data"]["op"], "control_records_result");
            assert_eq!(reply["data"]["v"], 1);
            assert_eq!(reply["data"]["id"], RE);
            assert_eq!(reply["data"]["re"], ID);
            assert_eq!(
                reply["data"]["results"][1],
                json!({
                    "record_id": sent[1].record_id(),
                    "result": "pending",
                    "effects": [
                        {"effect": "revocation", "result": "duplicate"},
                        {"effect": "interrupt", "result": "pending"},
                    ],
                })
            );
            let Ok(Incoming::ControlRecordsResult(got)) = Incoming::parse(&bytes(&reply)) else {
                panic!("a control_records_result");
            };
            assert_eq!(got.id, RE);
            assert_eq!(got.re, ID);
            assert_eq!(got.results, results);
            assert!(got.answers(ID, &ids(&sent)));
            assert_eq!(got.to_json(), reply);
            // Not another request, not the same records in another order,
            // not fewer or more.
            assert!(!got.answers(RE, &ids(&sent)));
            let mut swapped = ids(&sent);
            swapped.swap(0, 1);
            assert!(!got.answers(ID, &swapped));
            assert!(!got.answers(ID, &ids(&sent)[..2]));
            let mut more = ids(&sent);
            more.push(record(9).record_id().to_owned());
            assert!(!got.answers(ID, &more));
        }

        /// At most 64 records, and at least one: 65 are refused by the
        /// builder and by the host's reading, and an empty message too.
        #[test]
        fn sixty_five_records_refused() {
            let all = records(65);
            let ok = control_records_op(ID, &all[..64]).unwrap();
            assert_eq!(
                ControlRecordsRequest::decode(&bytes(&ok))
                    .unwrap()
                    .records
                    .len(),
                64
            );
            assert_eq!(
                control_records_op(ID, &all).unwrap_err(),
                "too many records"
            );
            // A message built by hand with 65.
            let mut over = ok.clone();
            over["data"]["records"]
                .as_array_mut()
                .unwrap()
                .push(all[64].object().to_json());
            assert_eq!(
                ControlRecordsRequest::decode(&bytes(&over)).unwrap_err(),
                "too many records"
            );
            // None is no message.
            assert_eq!(control_records_op(ID, &[]).unwrap_err(), "no records");
            let mut none = ok;
            none["data"]["records"] = json!([]);
            assert_eq!(
                ControlRecordsRequest::decode(&bytes(&none)).unwrap_err(),
                "no records"
            );
        }

        /// The message is at most 256 KiB as sealed (its plaintext): the
        /// limit itself passes, one byte more is refused, whatever the
        /// count.
        #[test]
        fn over_256_kib_refused() {
            let message = control_records_op(ID, &records(2)).unwrap();
            let mut plain = bytes(&message);
            plain.resize(MAX_CONTROL_RECORDS_BYTES, b' ');
            assert_eq!(
                ControlRecordsRequest::decode(&plain).unwrap().records.len(),
                2
            );
            plain.push(b' ');
            assert_eq!(
                ControlRecordsRequest::decode(&plain).unwrap_err(),
                "message too large"
            );
        }

        /// What else the host refuses: not strict JSON, another shape, a
        /// record that isn't a control record. Nothing is read partly.
        #[test]
        fn control_records_decode_is_strict() {
            let good = control_records_op(ID, &records(2)).unwrap();
            assert!(ControlRecordsRequest::decode(&bytes(&good)).is_ok());
            let refused = |message: &Value, why: &str| {
                assert_eq!(
                    ControlRecordsRequest::decode(&bytes(message)).unwrap_err(),
                    why,
                    "{message}"
                );
            };
            let edit = |f: &dyn Fn(&mut Value)| {
                let mut m = good.clone();
                f(&mut m);
                m
            };
            let shape = "not a control_records message";
            refused(&edit(&|m| m["data"]["v"] = json!(2)), shape);
            refused(&edit(&|m| m["data"]["op"] = json!("membership")), shape);
            refused(&edit(&|m| m["data"]["id"] = json!("not-a-uuid")), shape);
            refused(&edit(&|m| m["data"]["extra"] = json!(1)), shape);
            refused(&edit(&|m| m["extra"] = json!(1)), shape);
            refused(&edit(&|m| m["type"] = json!("terminal")), shape);
            refused(&edit(&|m| m["data"]["records"] = json!({})), shape);
            refused(
                &edit(&|m| {
                    m["data"].as_object_mut().unwrap().remove("records");
                }),
                shape,
            );
            // One that isn't a control record spoils the message.
            let bad = "not a control record";
            refused(&edit(&|m| m["data"]["records"][1] = json!("x")), bad);
            refused(
                &edit(&|m| m["data"]["records"][1]["body"]["action"] = json!("pause")),
                bad,
            );
            refused(&edit(&|m| m["data"]["records"][1]["extra"] = json!(1)), bad);
            // A device-list entry is no control record.
            refused(
                &edit(&|m| {
                    m["data"]["records"][1]["body"]["type"] = json!("atem-membership-entry");
                }),
                bad,
            );
            // Not strict JSON: a duplicate key, a fraction, garbage.
            let text = String::from_utf8(bytes(&good)).unwrap();
            let dup = text.replacen("\"v\":1", "\"v\":1,\"v\":1", 1);
            assert_eq!(
                ControlRecordsRequest::decode(dup.as_bytes()).unwrap_err(),
                "not strict JSON"
            );
            let frac = text.replacen("\"revoke_seq\":7", "\"revoke_seq\":7.5", 1);
            assert_eq!(
                ControlRecordsRequest::decode(frac.as_bytes()).unwrap_err(),
                "not strict JSON"
            );
            assert_eq!(
                ControlRecordsRequest::decode(b"{").unwrap_err(),
                "not strict JSON"
            );
        }

        /// Host principals' records only: a service's record travels in its
        /// Station's feed, never on a channel. The builder refuses one, and
        /// the host's reading refuses the whole message (nothing of it is
        /// applied), alone or beside host principals' records.
        #[test]
        fn a_service_record_is_refused_whole() {
            let why = "not a host principal's record";
            assert_eq!(
                control_records_op(ID, &[service_record(1)]).unwrap_err(),
                why
            );
            let mixed = [record(1), service_record(2), record(3)];
            assert_eq!(control_records_op(ID, &mixed).unwrap_err(), why);
            // Built by hand: refused whole when read.
            let mut message = control_records_op(ID, &records(3)).unwrap();
            message["data"]["records"][1] = service_record(2).object().to_json();
            assert_eq!(
                ControlRecordsRequest::decode(&bytes(&message)).unwrap_err(),
                why
            );
            message["data"]["records"] = json!([service_record(1).object().to_json()]);
            assert_eq!(
                ControlRecordsRequest::decode(&bytes(&message)).unwrap_err(),
                why
            );
        }

        fn parse_result(data: &Value) -> Result<ControlRecordsResult, &'static str> {
            match Incoming::parse(&bytes(&json!({"type": "session", "data": data})))? {
                Incoming::ControlRecordsResult(r) => Ok(r),
                other => panic!("not a result: {other:?}"),
            }
        }

        /// The result's words are the four results and the five effects,
        /// exact; a result is exactly the fields of the form.
        #[test]
        fn result_vocabulary_strict() {
            let sent = records(2);
            let good = control_records_result(RE, ID, &results_for(&sent))["data"].clone();
            assert!(parse_result(&good).is_ok());
            // Every result word on every effect word is read.
            for result in ["applied", "duplicate", "pending", "refused"] {
                for kind in ["revocation", "interrupt", "hold", "release", "cover"] {
                    let mut d = good.clone();
                    d["results"][0]["result"] = json!(result);
                    d["results"][0]["effects"] = json!([{"effect": kind, "result": result}]);
                    let r = parse_result(&d).unwrap();
                    assert_eq!(r.results[0].result.code(), result);
                    assert_eq!(r.results[0].effects[0].effect.code(), kind);
                }
            }
            // Anything else is refused: other words, case, types.
            let refused = |f: &dyn Fn(&mut Value)| {
                let mut d = good.clone();
                f(&mut d);
                assert!(parse_result(&d).is_err(), "{d}");
            };
            for word in ["done", "Applied", "APPLIED", "ok", "failed", "", "applied "] {
                refused(&|d| d["results"][0]["result"] = json!(word));
                refused(&|d| d["results"][0]["effects"][0]["result"] = json!(word));
            }
            for word in ["stop", "Interrupt", "revoke", "pause", "", "interrupt "] {
                refused(&|d| d["results"][0]["effects"][0]["effect"] = json!(word));
            }
            refused(&|d| d["results"][0]["result"] = json!(1));
            refused(&|d| d["results"][0]["result"] = json!(null));
            refused(&|d| d["results"][0]["effects"][0]["effect"] = json!(null));
            // The form: every field, no more, the right types.
            refused(&|d| d["v"] = json!(2));
            refused(&|d| d["extra"] = json!(1));
            refused(&|d| {
                d.as_object_mut().unwrap().remove("re");
            });
            refused(&|d| d["re"] = json!("not-a-uuid"));
            refused(&|d| d["id"] = json!("not-a-uuid"));
            refused(&|d| d["results"][0]["extra"] = json!(1));
            refused(&|d| d["results"][0]["effects"][0]["extra"] = json!(1));
            refused(&|d| {
                d["results"][0].as_object_mut().unwrap().remove("effects");
            });
            refused(&|d| {
                d["results"][0].as_object_mut().unwrap().remove("record_id");
            });
            refused(&|d| d["results"][0]["record_id"] = json!("not-a-uuid"));
            refused(&|d| d["results"][0]["effects"] = json!([]));
            // An effect appears once.
            refused(&|d| {
                d["results"][0]["effects"] = json!([
                    {"effect": "interrupt", "result": "applied"},
                    {"effect": "interrupt", "result": "duplicate"},
                ]);
            });
            refused(&|d| d["results"] = json!([]));
            refused(&|d| d["results"] = json!({}));
            // At most one per record of a message of 64.
            let many = results_for(&records(65));
            refused(&|d| {
                d["results"] = serde_json::to_value(
                many.iter().map(|r| json!({
                    "record_id": r.record_id,
                    "result": r.result.code(),
                    "effects": r.effects.iter()
                        .map(|e| json!({"effect": e.effect.code(), "result": e.result.code()}))
                        .collect::<Vec<_>>(),
                })).collect::<Vec<_>>()).unwrap()
            });
        }
    }

    /// `host_enc_key_get` and its answer (delegated host-work design II.4.1:
    /// the manager gets `{enc_pub, enc_sig}` from the host over its channel).
    mod host_enc_key_get {
        use super::*;
        use crate::keys::{Alg, PublicKey};

        const ID: &str = "aaaaaaaa-0000-4000-8000-0000000000e1";
        const REPLY: &str = "aaaaaaaa-0000-4000-8000-0000000000e2";

        fn bytes(message: &Value) -> Vec<u8> {
            message.to_string().into_bytes()
        }

        fn answer() -> HostEncKey {
            HostEncKey {
                id: REPLY.into(),
                re: ID.into(),
                host_id: "host-a".into(),
                host_trust_gen: 2,
                enc_key: PublicKey::new(Alg::X25519, &[9u8; 32]).unwrap(),
                enc_sig: vec![7u8; 64],
            }
        }

        fn parse_answer(data: &Value) -> Result<HostEncKey, &'static str> {
            match Incoming::parse(&bytes(&json!({"type": "session", "data": data})))? {
                Incoming::HostEncKey(answer) => Ok(*answer),
                other => panic!("not a host_enc_key: {other:?}"),
            }
        }

        /// The request and its answer, as built, sent and read on each end.
        #[test]
        fn host_enc_key_get_round_trip() {
            // C→H: exactly `v`, `op` and `id`.
            let request = host_enc_key_get(ID);
            assert_eq!(request["type"], "session");
            assert_eq!(
                request["data"],
                json!({"v": 1, "op": "host_enc_key_get", "id": ID})
            );
            assert_eq!(
                HostEncKeyGet::decode(&bytes(&request)),
                Ok(HostEncKeyGet { id: ID.into() })
            );
            // H→C: what a manager needs to draft the `host_enc_key` entry,
            // in the entry's own forms (`enc_key{alg, pub}`, `enc_sig`).
            let sent = answer().to_json();
            assert_eq!(sent["type"], "session");
            assert_eq!(
                sent["data"],
                json!({"v": 1, "op": "host_enc_key", "id": REPLY, "re": ID,
                    "host_id": "host-a", "host_trust_gen": 2,
                    "enc_key": {"alg": "x25519", "pub": b64u(&[9u8; 32])},
                    "enc_sig": b64u(&[7u8; 64])})
            );
            let Ok(Incoming::HostEncKey(read)) = Incoming::parse(&bytes(&sent)) else {
                panic!("a host_enc_key");
            };
            assert_eq!(*read, answer());
            // It answers the request it names, from the host the channel
            // reaches, at that host's trust generation.
            assert!(read.answers(ID, "host-a", 2));
            assert!(!read.answers(REPLY, "host-a", 2));
            assert!(!read.answers(ID, "host-b", 2));
            assert!(!read.answers(ID, "host-a", 1));
            // It drafts the entry the manager signs (the binding is the
            // verifier's to check against the chain).
            assert_eq!(
                read.action(false, 1_793_620_800_000),
                Ok(crate::membership::Action::HostEncKey {
                    host_id: "host-a".into(),
                    host_trust_gen: 2,
                    enc_key: PublicKey::new(Alg::X25519, &[9u8; 32]).unwrap(),
                    enc_sig: vec![7u8; 64],
                    retire_previous: false,
                })
            );
        }

        /// The host reads the request strictly: exactly its fields, a UUID v4
        /// id, strict JSON, as every r9 session op.
        #[test]
        fn the_request_is_read_strictly() {
            let good = host_enc_key_get(ID);
            let refused = |f: &dyn Fn(&mut Value)| {
                let mut m = good.clone();
                f(&mut m);
                assert!(HostEncKeyGet::decode(&bytes(&m)).is_err(), "{m}");
            };
            refused(&|m| m["data"]["extra"] = json!(1));
            refused(&|m| m["data"]["v"] = json!(2));
            refused(&|m| m["data"]["op"] = json!("host_enc_key"));
            refused(&|m| m["data"]["id"] = json!("not-a-uuid"));
            refused(&|m| m["data"]["id"] = json!(null));
            refused(&|m| {
                m["data"].as_object_mut().unwrap().remove("id");
            });
            refused(&|m| m["type"] = json!("terminal"));
            refused(&|m| m["extra"] = json!(1));
            let dup = format!(
                r#"{{"type":"session","data":{{"v":1,"op":"host_enc_key_get","id":"{ID}","id":"{REPLY}"}}}}"#
            );
            assert!(HostEncKeyGet::decode(dup.as_bytes()).is_err());
            assert!(HostEncKeyGet::decode(b"{").is_err());
        }

        /// The answer is read as strictly: every field, no more, `null`
        /// nowhere, an X25519 key and a 64-byte signature, a generation of 1
        /// or more.
        #[test]
        fn the_answer_is_read_strictly() {
            let good = answer().to_json()["data"].clone();
            assert!(parse_answer(&good).is_ok());
            let refused = |f: &dyn Fn(&mut Value)| {
                let mut d = good.clone();
                f(&mut d);
                assert!(parse_answer(&d).is_err(), "{d}");
            };
            refused(&|d| d["extra"] = json!(1));
            refused(&|d| d["v"] = json!(2));
            for field in [
                "id",
                "re",
                "host_id",
                "host_trust_gen",
                "enc_key",
                "enc_sig",
            ] {
                refused(&|d| {
                    d.as_object_mut().unwrap().remove(field);
                });
                refused(&|d| d[field] = json!(null));
            }
            refused(&|d| d["re"] = json!("not-a-uuid"));
            refused(&|d| d["id"] = json!("not-a-uuid"));
            refused(&|d| d["host_id"] = json!(""));
            refused(&|d| d["host_id"] = json!("host a"));
            refused(&|d| d["host_id"] = json!("h".repeat(129)));
            refused(&|d| d["host_trust_gen"] = json!(0));
            refused(&|d| d["host_trust_gen"] = json!("2"));
            refused(&|d| d["enc_key"]["alg"] = json!("ed25519"));
            refused(&|d| d["enc_key"]["pub"] = json!(b64u(&[9u8; 31])));
            refused(&|d| d["enc_key"]["extra"] = json!(1));
            refused(&|d| d["enc_key"] = json!(b64u(&[9u8; 32])));
            refused(&|d| d["enc_sig"] = json!(b64u(&[7u8; 63])));
            refused(&|d| d["enc_sig"] = json!(b64u(&[7u8; 65])));
            refused(&|d| d["enc_sig"] = json!("not base64url!"));
        }
    }

    /// r8 §F: a `lease_held` names the holder; the client keeps it (a
    /// confirmed takeover sends it back as `expected_controller`), and the
    /// wire form the bindings hand to apps carries it.
    #[test]
    fn a_lease_held_error_keeps_its_controller() {
        let data = json!({"v": 1, "op": "error", "id": "aaaaaaaa-0000-4000-8000-000000000001",
            "re": "aaaaaaaa-0000-4000-8000-000000000002", "code": "lease_held",
            "controller": {"controller_session": "cccccccc-0000-4000-8000-000000000003",
                           "lease_epoch": 4}});
        let e = SessionError::from_data(&data).unwrap();
        let c = e.controller.clone().unwrap();
        assert_eq!(c.controller_session, "cccccccc-0000-4000-8000-000000000003");
        assert_eq!(c.lease_epoch, 4);
        assert_eq!(e.to_json()["data"]["controller"], data["controller"]);
        // Absent or null: none; mistyped: not an error message we read.
        let mut none = data.clone();
        none["controller"] = Value::Null;
        assert!(SessionError::from_data(&none).unwrap().controller.is_none());
        none.as_object_mut().unwrap().remove("controller");
        assert!(SessionError::from_data(&none).unwrap().controller.is_none());
        let mut bad = data.clone();
        bad["controller"]["lease_epoch"] = json!("4");
        assert!(SessionError::from_data(&bad).is_none());
    }
}

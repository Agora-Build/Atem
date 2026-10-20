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
use crate::encoding::{b64u, b64u_decode};
use crate::membership::Head;

/// The revision an r9 `hello` must carry and `welcome` echoes.
pub const REVISION: u64 = 9;

/// The features an r9 host advertises: the nine of r8 plus r9's five.
pub const R9_FEATURES: &[&str] = &[
    "membership.carry",
    "push.sealed",
    "approval.seen",
    "grant.revoke",
    "recovery.wait",
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
            _ => Incoming::Other,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

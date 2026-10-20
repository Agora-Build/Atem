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
}

impl SessionError {
    pub fn new(code: &str) -> Self {
        SessionError {
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
        })
    }
}

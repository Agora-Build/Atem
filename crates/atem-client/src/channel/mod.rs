//! The `atem-ch1` channel (§R9.7): SIGMA-I over X25519, HKDF-SHA256 and
//! ChaCha20-Poly1305, in both roles, sans-I/O. Messages in and out are the
//! transport's JSON text frames as bytes; the caller moves them, keeps the
//! timers (every call takes the monotonic time in milliseconds) and closes
//! the transport when a call says so.
//!
//! ```text
//! client (Initiator)                         host (Responder)
//!   start ──────────── init ───────────────▶ on_init
//!   on_frame ◀──────── accept (head, sig_h) ─┘
//!   sign (sig_c over th3), then build the hello
//!   finish ─────────── finish (hello) ─────▶ on_finish → Opened (hello bytes)
//!                                            key(proof) → Keyed
//!                                            (carriage, principal, then)
//!                                            admit(auth key) / refuse(error)
//!   Channel ◀───────── rec 0 (welcome|error) ┘
//! ```
//!
//! - [`transcript`]: `th2` ([`HostAccept`], the one implementation, also used
//!   by the restore), `th3`, `th4`, the key schedule and the `finish` seal;
//! - [`wire`]: the strict frame parser and encoders;
//! - [`initiator`], [`responder`]: the two state machines (typestates: each
//!   step consumes the previous state, so nothing runs twice);
//! - [`record`]: [`Channel`], the records with per-direction counters and
//!   the limits;
//! - [`carriage`]: how the client's log relates to the host's signed head,
//!   and what its `hello` carries (§R9.3's table).
//!
//! Errors: before `finish` opens, a refusal is a clear `error` frame
//! (advisory to the client, never authority); after it opens, the host's
//! refusal is its first record (a session `error` the caller writes,
//! [`responder::Keyed::refuse`]); a failed record closes the channel with no
//! reply. Every secret (ephemerals, `ss`, `hs`, `k_fin`, record keys) is
//! wiped when its state is dropped.
use serde_json::{Value, json};

use crate::SignedObject;
use crate::canonical::jcs;
use crate::encoding::Hash32;
use crate::error::{Error, Result};

pub mod carriage;
pub mod initiator;
pub mod record;
pub mod responder;
pub mod transcript;
pub mod wire;

pub use carriage::{Carriage, HeadRelation};
pub use initiator::{Accepted, AwaitAccept, Initiator, Signed};
pub use record::{Channel, Direction, Role};
pub use responder::{
    AwaitFinish, HostContext, InitLimiter, Keyed, Opened, Refusal, Refused, Responder,
};
pub use transcript::{HeadError, HostAccept, HostHead};

/// Largest plaintext of a record or of the `finish` (the `hello`): one
/// session-family message, ≤ 1 MiB (§R9.7 "Records").
pub const MAX_PLAINTEXT: usize = 1 << 20;
/// `accept` within 10 s of `init`, `finish` within 10 s of `accept`.
pub const HANDSHAKE_STEP_MS: u64 = 10_000;
/// A native principal's channel lifetime; service and browser channels end
/// at their expiry ([`Channel::limit_lifetime`]).
pub const NATIVE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
/// Records per direction (counters 0 … 2^32 − 1).
pub const MAX_RECORDS: u64 = 1 << 32;
/// Plaintext bytes per direction.
pub const MAX_DIRECTION_BYTES: u64 = 1 << 36;
/// The host answers at most one `init` a second per transport.
pub const INIT_INTERVAL_MS: u64 = 1_000;

/// Who the client says it is (§R9.7 step 5): `{"kind":"native"|"service",
/// "device_id":…}` or `{"kind":"browser","grant_id":…}`; a browser also binds
/// its grant's `grant_hash` into `th3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    Native {
        device_id: String,
    },
    Service {
        device_id: String,
    },
    Browser {
        grant_id: String,
        grant_hash: Hash32,
    },
}

impl Principal {
    /// The browser principal of a signed `atem-browser-grant` (its
    /// `grant_id` and `grant_hash`; the grant's validity is the host's
    /// admission, §R9.6).
    pub fn browser(grant: &SignedObject) -> Result<Self> {
        let grant_hash = grant.grant_hash().ok_or(Error::UnknownType)?;
        let grant_id = grant
            .body()
            .get("grant_id")
            .and_then(Value::as_str)
            .ok_or(Error::Malformed("grant_id"))?;
        Ok(Principal::Browser {
            grant_id: grant_id.to_owned(),
            grant_hash,
        })
    }

    /// The `hello.proof.principal` object as received, exactly
    /// `{kind, device_id}` or `{kind, grant_id}`; a browser's needs the
    /// grant it names (same `grant_id`).
    pub fn from_json(value: &Value, grant: Option<&SignedObject>) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or(Error::Malformed("principal must be an object"))?;
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(Error::Malformed("principal kind"))?;
        let id_field = if kind == "browser" {
            "grant_id"
        } else {
            "device_id"
        };
        if object.len() != 2 {
            return Err(Error::Malformed("principal has exactly kind and one id"));
        }
        let id = object
            .get(id_field)
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or(Error::Malformed("principal id"))?
            .to_owned();
        match (kind, grant) {
            ("native", None) => Ok(Principal::Native { device_id: id }),
            ("service", None) => Ok(Principal::Service { device_id: id }),
            ("browser", Some(grant)) => {
                let principal = Principal::browser(grant)?;
                match &principal {
                    Principal::Browser { grant_id, .. } if *grant_id == id => Ok(principal),
                    _ => Err(Error::Malformed("principal grant_id is not the grant's")),
                }
            }
            ("browser", None) => Err(Error::Malformed("a browser principal needs its grant")),
            ("native" | "service", Some(_)) => Err(Error::Malformed("only a browser has a grant")),
            _ => Err(Error::Malformed("unknown principal kind")),
        }
    }

    /// The wire object (`proof.principal`).
    pub fn to_json(&self) -> Value {
        match self {
            Principal::Native { device_id } => json!({"kind": "native", "device_id": device_id}),
            Principal::Service { device_id } => json!({"kind": "service", "device_id": device_id}),
            Principal::Browser { grant_id, .. } => json!({"kind": "browser", "grant_id": grant_id}),
        }
    }

    /// `jcs(principal)`, the `th3` input.
    pub fn jcs(&self) -> String {
        jcs(&self.to_json()).expect("a principal has only strings")
    }

    /// `grant_hash` for a browser, else none (an empty `th3` field).
    pub fn grant_hash(&self) -> Option<Hash32> {
        match self {
            Principal::Browser { grant_hash, .. } => Some(*grant_hash),
            _ => None,
        }
    }

    /// `member:<id>`, `service:<id>` or `browser:<grant_id>` (§R9.6).
    pub fn name(&self) -> String {
        match self {
            Principal::Native { device_id } => format!("member:{device_id}"),
            Principal::Service { device_id } => format!("service:{device_id}"),
            Principal::Browser { grant_id, .. } => format!("browser:{grant_id}"),
        }
    }
}

/// What `client`'s `hello.proof` carries: the principal and `sig_c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProof {
    pub principal: Principal,
    pub sig_c: Vec<u8>,
}

/// Why a `handshake_failed` (never sent: the wire carries only the code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Not a well-formed handshake message, or one out of order.
    Malformed,
    /// X25519 gave the all-zero output (a low-order peer ephemeral).
    ZeroSharedSecret,
    /// The `finish` didn't open under `k_fin`.
    FinishTag,
    /// A handshake step took longer than 10 s.
    Timeout,
    /// `sig_h` doesn't verify with the host key of the client's log.
    BadHostSignature,
    /// `sig_c` doesn't verify with the principal's key.
    BadClientSignature,
}

/// A record limit (§R9.7 "Limits"): the side that reaches one sends
/// nothing more and closes; the client reconnects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Records,
    Bytes,
    Lifetime,
}

/// The codes a clear `error` frame carries (§R9.7, §R9.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearCode {
    HandshakeFailed,
    StaleTarget,
    AccountFrozen,
    Busy,
}

impl ClearCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ClearCode::HandshakeFailed => "handshake_failed",
            ClearCode::StaleTarget => "stale_target",
            ClearCode::AccountFrozen => "account_frozen",
            ClearCode::Busy => "busy",
        }
    }

    pub fn parse(code: &str) -> Option<Self> {
        Some(match code {
            "handshake_failed" => ClearCode::HandshakeFailed,
            "stale_target" => ClearCode::StaleTarget,
            "account_frozen" => ClearCode::AccountFrozen,
            "busy" => ClearCode::Busy,
            _ => return None,
        })
    }
}

/// Why a channel step failed. After any of these the channel is over: the
/// caller sends the reply the step returned, if any, and closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// `handshake_failed`.
    HandshakeFailed(Failure),
    /// `stale_target`: the `init` named another genesis, host or trust
    /// generation.
    StaleTarget,
    /// `account_frozen`: the host is frozen.
    AccountFrozen,
    /// `busy`: the `init` rate, or the host couldn't sign.
    Busy,
    /// A clear `error` frame from the peer: **advisory**, never authority to
    /// repin a host, change a log or persist a freeze (§R9.7). `code` is
    /// what it said (one of [`ClearCode`] when known).
    Advisory { code: String },
    /// The client's verified log has no current host by that id (§R9.7
    /// step 1); nothing was sent.
    UnknownHost,
    /// A record that failed (tag, counter, direction, shape) or a frame out
    /// of place on an open channel: closed without a reply, keys wiped.
    RecordRejected,
    /// A record limit was reached.
    Limit(Limit),
    /// A plaintext over 1 MiB offered to `seal`/`finish` (nothing sent; the
    /// channel stays open for `seal`).
    TooLarge,
    /// The channel is closed.
    Closed,
}

impl ChannelError {
    /// The stable name: the wire code where there is one.
    pub fn code(&self) -> &str {
        match self {
            ChannelError::HandshakeFailed(_) => "handshake_failed",
            ChannelError::StaleTarget => "stale_target",
            ChannelError::AccountFrozen => "account_frozen",
            ChannelError::Busy => "busy",
            ChannelError::Advisory { code } => code,
            ChannelError::UnknownHost => "unknown_host",
            ChannelError::RecordRejected => "record_rejected",
            ChannelError::Limit(_) => "limit",
            ChannelError::TooLarge => "too_large",
            ChannelError::Closed => "closed",
        }
    }
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::HandshakeFailed(why) => write!(f, "handshake_failed ({why:?})"),
            ChannelError::Advisory { code } => write!(f, "the peer said {code} (advisory)"),
            ChannelError::Limit(limit) => write!(f, "channel limit reached: {limit:?}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for ChannelError {}

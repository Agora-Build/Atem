//! One error type for every binding call. Each variant names the layer that
//! refused; `code` is the stable machine name (the crate's own codes, the
//! wire error codes of §R9.11 and r8), `detail` is for logs and humans and
//! may change.
use atem_client::channel::ChannelError;
use atem_client::connect::ConnectError;
use atem_client::membership::Invalid;
use atem_client::membership::publish::PublishError;
use atem_client::restore::RestoreError;

use crate::types::NextStep;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum AtemError {
    /// Input that isn't what it must be: not strict JSON, a bad key or
    /// signature, an unknown type (`atem_client::Error::code`: `malformed`,
    /// `bad_signature`, `high_s`, `wrong_alg`, `kit_tag_mismatch`, …).
    Invalid { code: String, detail: String },
    /// A membership entry or chain the verifier refuses
    /// (`membership_invalid` details: `bad_signature`, `gap`,
    /// `signer_not_manager`, …); `index` is the entry's position in what
    /// was passed, when known.
    Membership {
        code: String,
        detail: String,
        index: Option<u64>,
    },
    /// The channel failed (`handshake_failed`, `stale_target`,
    /// `account_frozen`, `busy`, `record_rejected`, `limit`, `closed`,
    /// `signing_failed`, `unknown_host`, …). Close the transport.
    Channel { code: String, detail: String },
    /// The host refused the hello (its encrypted first record): the session
    /// error's `code`/`detail`, its JSON, and what to do next.
    Refused {
        code: String,
        detail: Option<String>,
        error_json: String,
        next: NextStep,
    },
    /// A welcome that contradicts what the client verified; `check` names
    /// it (`revision`, `re`, `channel_id`, `principal`, `account_id`,
    /// `host`, `head`). The channel was dropped.
    BadWelcome { check: String },
    /// A request this attachment can't make now (`unknown session`,
    /// `no lease`, `too many requests in flight`, `not attached`, …).
    Request { detail: String },
    /// The restore stopped (`kit_tag_mismatch`, `genesis_mismatch`,
    /// `membership_invalid`, `no_host_reachable`, `log_behind_host`,
    /// `kit_not_current`, `no_backup`, `backup_hash_mismatch`,
    /// `backup_invalid`).
    Restore { code: String, detail: String },
    /// An append can't start or continue (`outstanding`, `not_on_head`,
    /// `nothing_prepared`, `sign`).
    Publish { code: String, detail: String },
    /// A push hint or seen refused (`malformed`, `binding`,
    /// `bad_signature`, `invalid_times`, `skew`, `stale`, `bad_sealed`,
    /// `duplicate`).
    Push { code: String, detail: String },
    /// The object was used out of order (a step already taken, a state it
    /// isn't in).
    State { detail: String },
}

impl AtemError {
    /// The stable code of any variant.
    pub fn code(&self) -> String {
        match self {
            AtemError::Invalid { code, .. }
            | AtemError::Membership { code, .. }
            | AtemError::Channel { code, .. }
            | AtemError::Refused { code, .. }
            | AtemError::Restore { code, .. }
            | AtemError::Publish { code, .. }
            | AtemError::Push { code, .. } => code.clone(),
            AtemError::BadWelcome { .. } => "bad_welcome".into(),
            AtemError::Request { .. } => "request".into(),
            AtemError::State { .. } => "state".into(),
        }
    }

    pub(crate) fn state(detail: &str) -> Self {
        AtemError::State {
            detail: detail.into(),
        }
    }

    pub(crate) fn request(detail: &str) -> Self {
        AtemError::Request {
            detail: detail.into(),
        }
    }

    pub(crate) fn malformed(detail: &str) -> Self {
        AtemError::Invalid {
            code: "malformed".into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn membership(reason: &Invalid, index: Option<usize>) -> Self {
        AtemError::Membership {
            code: "membership_invalid".into(),
            detail: reason.code().into(),
            index: index.map(|i| i as u64),
        }
    }
}

impl std::fmt::Display for AtemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AtemError::Invalid { code, detail }
            | AtemError::Channel { code, detail }
            | AtemError::Restore { code, detail }
            | AtemError::Publish { code, detail }
            | AtemError::Push { code, detail } => write!(f, "{code}: {detail}"),
            AtemError::Membership { detail, index, .. } => match index {
                Some(i) => write!(f, "membership_invalid at {i}: {detail}"),
                None => write!(f, "membership_invalid: {detail}"),
            },
            AtemError::Refused { code, detail, .. } => {
                write!(f, "refused: {code} {}", detail.as_deref().unwrap_or(""))
            }
            AtemError::BadWelcome { check } => write!(f, "bad welcome: {check}"),
            AtemError::Request { detail } => write!(f, "request: {detail}"),
            AtemError::State { detail } => write!(f, "state: {detail}"),
        }
    }
}

impl std::error::Error for AtemError {}

impl From<atem_client::Error> for AtemError {
    fn from(e: atem_client::Error) -> Self {
        AtemError::Invalid {
            code: e.code().into(),
            detail: e.to_string(),
        }
    }
}

impl From<ChannelError> for AtemError {
    fn from(e: ChannelError) -> Self {
        AtemError::Channel {
            code: e.code().into(),
            detail: e.to_string(),
        }
    }
}

impl From<ConnectError> for AtemError {
    fn from(e: ConnectError) -> Self {
        match e {
            ConnectError::Channel(c) => c.into(),
            ConnectError::Carry(c) => AtemError::Channel {
                code: "cannot_carry".into(),
                detail: format!("{c:?}"),
            },
            ConnectError::Refused { error, next } => AtemError::Refused {
                code: error.code.clone(),
                detail: error.detail.clone(),
                error_json: error.to_json().to_string(),
                next: NextStep::from(&next),
            },
            ConnectError::BadWelcome(check) => AtemError::BadWelcome {
                check: check.into(),
            },
            ConnectError::Malformed(what) => AtemError::malformed(what),
            ConnectError::Request(what) => AtemError::request(what),
        }
    }
}

impl From<RestoreError> for AtemError {
    fn from(e: RestoreError) -> Self {
        let detail = match &e {
            RestoreError::ChainInvalid { index, reason } => {
                format!("entry {index}: {}", reason.code())
            }
            RestoreError::Withheld { hosts } => format!("waiting for a host: {}", hosts.join(", ")),
            other => other.code().to_string(),
        };
        AtemError::Restore {
            code: e.code().into(),
            detail,
        }
    }
}

impl From<PublishError> for AtemError {
    fn from(e: PublishError) -> Self {
        let (code, detail) = match e {
            PublishError::Outstanding => ("outstanding", "one append in flight per device".into()),
            PublishError::NotOnHead => {
                ("not_on_head", "the body doesn't chain from the head".into())
            }
            PublishError::NothingPrepared => ("nothing_prepared", "nothing is prepared".into()),
            PublishError::Sign(reason) => ("sign", reason.code().to_string()),
        };
        AtemError::Publish {
            code: code.into(),
            detail,
        }
    }
}

impl From<atem_client::push::Refusal> for AtemError {
    fn from(r: atem_client::push::Refusal) -> Self {
        AtemError::Push {
            code: r.code().into(),
            detail: format!("{r:?}"),
        }
    }
}

impl From<Invalid> for AtemError {
    fn from(reason: Invalid) -> Self {
        AtemError::membership(&reason, None)
    }
}

pub type Result<T> = std::result::Result<T, AtemError>;

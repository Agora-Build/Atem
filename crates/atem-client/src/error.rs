//! One error type for the crate. `code()` is the stable name a caller maps to
//! a wire error or detail (e.g. `array_not_canonical` is the detail of a
//! `membership_invalid`, §R9.2).
use crate::canonical::{CanonicalError, StrictError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not strict I-JSON (`parse_strict`).
    Strict(StrictError),
    /// Outside the `jcs` domain (a float or an unsafe integer).
    Canonical(CanonicalError),
    /// A signed body whose `jcs` is over 4096 bytes, or an oversized input.
    TooLarge,
    /// `null` anywhere in a signed body (absent = omitted, §R9.1).
    NullValue,
    /// A missing, extra or mistyped field; the text names it.
    Malformed(&'static str),
    /// A body `type` that has no signing label.
    UnknownType,
    /// A set that isn't sorted by bytes, an array with a duplicate, a
    /// sequence of the wrong length, or an array where none may be (§R9.2).
    ArrayNotCanonical,
    /// A `set_recovery_key` with `kit: "current"` and no `kit_sig` (§R9.5).
    KitSigMissing,
    /// A `kit_sig` beside a body that takes none.
    KitSigUnexpected,
    /// A public key of the wrong length or not on its curve.
    BadKey,
    /// A small-order (weak) Ed25519 public key.
    WeakKey,
    /// A key used with an algorithm other than the one pinned for it.
    WrongAlg,
    /// A P-256 signature with a high S (§R9.1: low S required).
    HighS,
    /// The signature doesn't verify.
    BadSignature,
    /// X25519 produced the all-zero output (a low-order peer key).
    ZeroSharedSecret,
    /// An HPKE ciphertext that didn't open (wrong key, `info` or tampering).
    OpenFailed,
    /// A K-backup envelope or plaintext that is malformed or doesn't open.
    BackupInvalid,
    /// A Recovery Kit whose tag doesn't match its contents ("damaged or
    /// mistyped"; the restore fixtures' `kit_tag_mismatch`).
    KitTagMismatch,
    /// A log whose genesis isn't the kit's (§R9.5 restore step 2).
    GenesisMismatch,
    /// The key provider has no key by that id.
    UnknownKey,
    /// The key provider failed (platform error, cancelled confirmation).
    Provider(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Strict(_) => "not_strict_json",
            Error::Canonical(_) => "not_canonical",
            Error::TooLarge => "too_large",
            Error::NullValue => "null_value",
            Error::Malformed(_) => "malformed",
            Error::UnknownType => "unknown_type",
            Error::ArrayNotCanonical => "array_not_canonical",
            Error::KitSigMissing => "kit_sig_missing",
            Error::KitSigUnexpected => "kit_sig_unexpected",
            Error::BadKey => "bad_key",
            Error::WeakKey => "weak_key",
            Error::WrongAlg => "wrong_alg",
            Error::HighS => "high_s",
            Error::BadSignature => "bad_signature",
            Error::ZeroSharedSecret => "zero_shared_secret",
            Error::OpenFailed => "open_failed",
            Error::BackupInvalid => "backup_invalid",
            Error::KitTagMismatch => "kit_tag_mismatch",
            Error::GenesisMismatch => "genesis_mismatch",
            Error::UnknownKey => "unknown_key",
            Error::Provider(_) => "provider_error",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Strict(e) => write!(f, "not strict JSON: {e:?}"),
            Error::Canonical(e) => write!(f, "outside the canonical domain: {e:?}"),
            Error::Malformed(what) => write!(f, "malformed: {what}"),
            Error::Provider(what) => write!(f, "key provider: {what}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for Error {}

impl From<StrictError> for Error {
    fn from(e: StrictError) -> Self {
        Error::Strict(e)
    }
}

impl From<CanonicalError> for Error {
    fn from(e: CanonicalError) -> Self {
        Error::Canonical(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

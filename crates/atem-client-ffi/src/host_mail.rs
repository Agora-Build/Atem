//! Mail between hosts (delegated host-work design II.4.2, II.4.4;
//! `designs/protocol/atem-host-work-v1.md` §11.5): the `atem-envelope` a host
//! sender seals to the receiving host (a request, a cancel or a complete) and
//! the `atem-result` the host that ran the work sends back (a status, a
//! refusal or a result). **Planned:** no host advertises `host.senders`, and
//! nothing sends these yet.
//!
//! Host role only (feature `host`, never in an app build, like `sign_seen`):
//! sealing signs with a host's `host_key`, opening uses its host encryption
//! key, and both are the host's. The bindings carry them so the Swift,
//! Kotlin and WASM conformance suites run the shared vectors
//! (`r9-vectors-host-envelope`) through the same code the host runs.
//!
//! - **Seal**: `seal_envelope` and `seal_result` take the body's fields
//!   (`MailFieldsData`: both hosts, `enc_kid`, `id`, the times,
//!   `signed_at_head`), the plaintext as JSON (one of the shapes, read by the
//!   receiver's own strict parse: no `null`, exactly its fields; its
//!   canonical form is what is sealed) and the recipient's host encryption
//!   key, and return the object's wire JSON (canonical). The provider signs
//!   with `host_key_id` under purpose `HostSigning`. A plaintext over its
//!   bound (a request's Message 240 KiB, every other plaintext 240 KiB) is
//!   refused before anything is sealed.
//! - **Judge**: `open_envelope` (the receiver's checks 1 to 6) and
//!   `accept_result` (the sending host's check of a result against its
//!   outbox row) return a verdict for every signed object. An error is only
//!   for bytes that don't parse as a signed object: for example not strict
//!   JSON (a duplicate key, a float, a `null`), over 512 KiB, not an object,
//!   no `body` or `sig`, a `sig`, `enc` or `ct` that isn't base64url, an
//!   unknown top-level field, a `kit_sig`, `enc` without `ct`, a body
//!   without a known `type` or with `v` other than 1, an array in a mail
//!   body, or a body over 4,096 bytes; or anything else the signed-object
//!   parse refuses. The host refuses those bytes
//!   too, under the SHA-256 of the bytes as fetched (host-work-v1 §11.5).
//!   The receiver passes its own trust generation (from its pairing) and the
//!   keys it accepts now (`MailRecipientData.keys`: its current key, and the
//!   previous one only inside its 24 h window unless `retire_previous`
//!   retired it).
#[cfg(feature = "uniffi")]
use std::sync::Arc;

use atem_client::canonical::{Numbers, StrictValue, jcs, parse_strict};
use atem_client::encoding::{Hash32, hex_decode_array};
use atem_client::host_mail::{
    self, EnvelopePlain, EnvelopeVerdict, ExpectedResult, HostRef, MAX_MAIL_OBJECT_BYTES,
    MailFields, Recipient, ResultPlain, ResultVerdict,
};
use atem_client::membership::Head;
use atem_client::provider::{KeyId, KeyProvider};
use atem_client::{Error, SignedObject};

use crate::encoding::safe_int;
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, object_json};
use crate::types::{LogHead, PublicKeyData};

record! {
    /// A host at a trust generation (a body's `sender` or `recipient`).
    pub struct MailHostData {
        pub host_id: String,
        pub host_trust_gen: u64,
    }
}

record! {
    /// An envelope's or a result's body before the seal names its
    /// `sealed_hash`.
    pub struct MailFieldsData {
        pub account_id: String,
        /// The account's genesis hash (64 lowercase hex).
        pub genesis_hash: String,
        /// The host that signs and sends.
        pub sender: MailHostData,
        /// The host the object is sealed to.
        pub recipient: MailHostData,
        /// The short id of the recipient's host encryption key (16 hex).
        pub enc_kid: String,
        /// The object's id (UUID v4): an envelope's is its request's
        /// `message_id`.
        pub id: String,
        pub created_at: u64,
        pub expires_at: u64,
        /// The head of the sender's own device list when it signs.
        pub signed_at_head: LogHead,
    }
}

record! {
    /// A key the receiver accepts mail sealed to: its id in the provider and
    /// its `enc_kid` (16 hex).
    pub struct MailKeyData {
        pub key_id: String,
        pub enc_kid: String,
    }
}

record! {
    /// This host as the receiver: its `host_id`, its current trust generation
    /// and the keys that may open mail now.
    pub struct MailRecipientData {
        pub host_id: String,
        /// The host's own trust generation, from its pairing, never one read
        /// from its device list (which may lag behind its own new
        /// `add_host`).
        pub host_trust_gen: u64,
        pub keys: Vec<MailKeyData>,
    }
}

record! {
    /// The sending host's outbox row for one message to one host: the host
    /// (and generation) the envelopes went to, the request's `message_id`,
    /// the ids of the cancel and complete envelopes sent for it, and the
    /// task ids of its recorded resolution.
    pub struct MailOutboxData {
        pub recipient: MailHostData,
        pub message_id: String,
        pub cancel_complete_ids: Vec<String>,
        pub task_ids: Vec<String>,
    }
}

data_enum! {
    /// The receiver's verdict on an envelope.
    pub enum EnvelopeVerdictInfo {
        /// Checks 1 to 6 passed: the plaintext (canonical JSON) and the
        /// sender's principal, `host:<host_id>`. The host-work checks of a
        /// message (route, project, ops, target) are the host's.
        Open { plain_json: String, sender: String },
        /// Signed at a head beyond this host's list (which may hold the
        /// sender's newer standing, or the key it is sealed to, a key this
        /// host hasn't applied yet), the body's times passed (and the
        /// signature too, when the list holds the claimed generation):
        /// judge it again after each device-list advance and each change of
        /// the keys it accepts.
        Pending { host_id: String, host_trust_gen: u64 },
        /// Refused before the copy was shown to be the sender's (its
        /// signature, and the sealed part it names); `evidence` (hex) is what
        /// the host keeps it under. Nothing is reported, and it claims no id.
        Refused { reason: String, evidence: String },
        /// Refused after the signature verified and the sealed part matched:
        /// the host reports it to the sender (a status naming `object_id`,
        /// `refused: invalid_request`), and it claims the id.
        RefusedAuthenticated { object_id: String, reason: String },
        /// A local failure (the key provider): nothing is decided; retry.
        Unavailable { code: String, detail: String },
    }
}

data_enum! {
    /// The sending host's verdict on a result.
    pub enum ResultVerdictInfo {
        /// It answers the row and its sender is a current, authorized host.
        Accepted { plain_json: String, sender: String },
        /// It verified and answers the row, but its sender is revoked or
        /// removed: kept as data, never delivered; `reason` is the return
        /// grant's detail (`result not delivered: sender revoked` or
        /// `… sender removed`).
        NotDelivered {
            plain_json: String,
            sender: String,
            reason: String,
        },
        /// As `EnvelopeVerdictInfo::Pending`.
        Pending { host_id: String, host_trust_gen: u64 },
        /// As `EnvelopeVerdictInfo::Refused`.
        Refused { reason: String, evidence: String },
        /// As `EnvelopeVerdictInfo::RefusedAuthenticated` (nothing is
        /// reported back for a result).
        RefusedAuthenticated { object_id: String, reason: String },
        /// As `EnvelopeVerdictInfo::Unavailable`.
        Unavailable { code: String, detail: String },
    }
}

impl MailHostData {
    fn host_ref(&self) -> Result<HostRef> {
        Ok(HostRef {
            host_id: self.host_id.clone(),
            host_trust_gen: safe_int(self.host_trust_gen, "host_trust_gen")?,
        })
    }
}

impl MailFieldsData {
    fn to_fields(&self) -> Result<MailFields> {
        let fields = MailFields {
            account_id: self.account_id.clone(),
            genesis_hash: Hash32::from_hex(&self.genesis_hash)?,
            sender: self.sender.host_ref()?,
            recipient: self.recipient.host_ref()?,
            enc_kid: self.enc_kid.clone(),
            id: self.id.clone(),
            created_at: safe_int(self.created_at, "created_at")?,
            expires_at: safe_int(self.expires_at, "expires_at")?,
            signed_at_head: Head {
                seq: safe_int(self.signed_at_head.seq, "signed_at_head.seq")?,
                hash: Hash32::from_hex(&self.signed_at_head.hash)?,
            },
        };
        fields.check()?;
        Ok(fields)
    }
}

impl MailRecipientData {
    fn to_recipient(&self) -> Result<Recipient> {
        let keys = self
            .keys
            .iter()
            .map(|k| {
                let kid = hex_decode_array::<8>(&k.enc_kid)
                    .map_err(|_| AtemError::malformed("enc_kid is 16 lowercase hex"))?;
                Ok((KeyId::new(k.key_id.clone()), kid))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Recipient {
            host_id: self.host_id.clone(),
            host_trust_gen: safe_int(self.host_trust_gen, "host_trust_gen")?,
            keys,
        })
    }
}

impl MailOutboxData {
    fn to_expected(&self) -> Result<ExpectedResult> {
        Ok(ExpectedResult {
            recipient: self.recipient.host_ref()?,
            message_id: self.message_id.clone(),
            cancel_complete_ids: self.cancel_complete_ids.clone(),
            task_ids: self.task_ids.clone(),
        })
    }
}

/// A plaintext's canonical bytes from the caller's JSON (at most a mailbox
/// call's size; its own bound is the plaintext parse's).
fn plaintext(plain_json: &str) -> Result<Vec<u8>> {
    let value = parse_strict(
        plain_json.as_bytes(),
        MAX_MAIL_OBJECT_BYTES,
        Numbers::IntegersOnly,
    )
    .map_err(Error::from)?;
    Ok(jcs(&value)
        .map_err(|_| AtemError::malformed("plaintext outside canonical JSON"))?
        .into_bytes())
}

/// A mailbox object's wire JSON as a signed object (at most 512 KiB).
fn mail_object(object_json: &str) -> Result<SignedObject> {
    let value =
        StrictValue::parse(object_json.as_bytes(), MAX_MAIL_OBJECT_BYTES).map_err(Error::from)?;
    Ok(SignedObject::from_strict(&value)?)
}

/// A verdict's plaintext as the canonical JSON it was read from. An error
/// (none for a plaintext the core just read) decides nothing.
fn plain_text(
    bytes: atem_client::Result<zeroize::Zeroizing<Vec<u8>>>,
) -> std::result::Result<String, (String, String)> {
    match bytes {
        Ok(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
        Err(e) => Err((e.code().into(), e.to_string())),
    }
}

impl From<EnvelopeVerdict> for EnvelopeVerdictInfo {
    fn from(v: EnvelopeVerdict) -> Self {
        match v {
            EnvelopeVerdict::Open { plain, sender } => match plain_text(plain.to_bytes()) {
                Ok(plain_json) => EnvelopeVerdictInfo::Open { plain_json, sender },
                Err((code, detail)) => EnvelopeVerdictInfo::Unavailable { code, detail },
            },
            EnvelopeVerdict::Pending {
                host_id,
                host_trust_gen,
            } => EnvelopeVerdictInfo::Pending {
                host_id,
                host_trust_gen,
            },
            EnvelopeVerdict::Refused { reason, evidence } => EnvelopeVerdictInfo::Refused {
                reason: reason.into(),
                evidence: evidence.to_hex(),
            },
            EnvelopeVerdict::RefusedAuthenticated { object_id, reason } => {
                EnvelopeVerdictInfo::RefusedAuthenticated {
                    object_id,
                    reason: reason.into(),
                }
            }
            EnvelopeVerdict::Unavailable { error } => EnvelopeVerdictInfo::Unavailable {
                code: error.code().into(),
                detail: error.to_string(),
            },
        }
    }
}

impl From<ResultVerdict> for ResultVerdictInfo {
    fn from(v: ResultVerdict) -> Self {
        let unavailable = |(code, detail)| ResultVerdictInfo::Unavailable { code, detail };
        match v {
            ResultVerdict::Accepted { plain, sender } => match plain_text(plain.to_bytes()) {
                Ok(plain_json) => ResultVerdictInfo::Accepted { plain_json, sender },
                Err(e) => unavailable(e),
            },
            ResultVerdict::NotDelivered {
                plain,
                sender,
                reason,
            } => match plain_text(plain.to_bytes()) {
                Ok(plain_json) => ResultVerdictInfo::NotDelivered {
                    plain_json,
                    sender,
                    reason: reason.into(),
                },
                Err(e) => unavailable(e),
            },
            ResultVerdict::Pending {
                host_id,
                host_trust_gen,
            } => ResultVerdictInfo::Pending {
                host_id,
                host_trust_gen,
            },
            ResultVerdict::Refused { reason, evidence } => ResultVerdictInfo::Refused {
                reason: reason.into(),
                evidence: evidence.to_hex(),
            },
            ResultVerdict::RefusedAuthenticated { object_id, reason } => {
                ResultVerdictInfo::RefusedAuthenticated {
                    object_id,
                    reason: reason.into(),
                }
            }
            ResultVerdict::Unavailable { error } => ResultVerdictInfo::Unavailable {
                code: error.code().into(),
                detail: error.to_string(),
            },
        }
    }
}

/// The ephemeral's ikm of a known-answer vector: 32 bytes.
#[cfg(feature = "test-vectors")]
fn ikm(ikm_e: &[u8]) -> Result<[u8; 32]> {
    ikm_e
        .try_into()
        .map_err(|_| AtemError::malformed("ikm_e is 32 bytes"))
}

pub(crate) fn seal_envelope_with(
    provider: &dyn KeyProvider,
    host_key_id: &str,
    fields: &MailFieldsData,
    plain_json: &str,
    recipient_enc: &PublicKeyData,
) -> Result<String> {
    let plain = EnvelopePlain::parse(&plaintext(plain_json)?)?;
    let object = host_mail::seal_envelope(
        provider,
        &KeyId::new(host_key_id),
        &fields.to_fields()?,
        &plain,
        &recipient_enc.to_key()?,
    )?;
    Ok(object_json(&object))
}

pub(crate) fn seal_result_with(
    provider: &dyn KeyProvider,
    host_key_id: &str,
    fields: &MailFieldsData,
    plain_json: &str,
    recipient_enc: &PublicKeyData,
) -> Result<String> {
    let plain = ResultPlain::parse(&plaintext(plain_json)?)?;
    let object = host_mail::seal_result(
        provider,
        &KeyId::new(host_key_id),
        &fields.to_fields()?,
        &plain,
        &recipient_enc.to_key()?,
    )?;
    Ok(object_json(&object))
}

#[cfg(feature = "test-vectors")]
pub(crate) fn seal_envelope_with_ikm_with(
    provider: &dyn KeyProvider,
    host_key_id: &str,
    fields: &MailFieldsData,
    plain_json: &str,
    recipient_enc: &PublicKeyData,
    ikm_e: &[u8],
) -> Result<String> {
    let plain = EnvelopePlain::parse(&plaintext(plain_json)?)?;
    let object = host_mail::seal_envelope_with_ikm(
        provider,
        &KeyId::new(host_key_id),
        &fields.to_fields()?,
        &plain,
        &recipient_enc.to_key()?,
        &ikm(ikm_e)?,
    )?;
    Ok(object_json(&object))
}

#[cfg(feature = "test-vectors")]
pub(crate) fn seal_result_with_ikm_with(
    provider: &dyn KeyProvider,
    host_key_id: &str,
    fields: &MailFieldsData,
    plain_json: &str,
    recipient_enc: &PublicKeyData,
    ikm_e: &[u8],
) -> Result<String> {
    let plain = ResultPlain::parse(&plaintext(plain_json)?)?;
    let object = host_mail::seal_result_with_ikm(
        provider,
        &KeyId::new(host_key_id),
        &fields.to_fields()?,
        &plain,
        &recipient_enc.to_key()?,
        &ikm(ikm_e)?,
    )?;
    Ok(object_json(&object))
}

pub(crate) fn open_envelope_with(
    object_json: &str,
    log: &MembershipLog,
    me: &MailRecipientData,
    provider: &dyn KeyProvider,
    now_ms: u64,
) -> Result<EnvelopeVerdictInfo> {
    let object = mail_object(object_json)?;
    let me = me.to_recipient()?;
    // A copy of the log: no binding lock is held while the provider opens.
    let list = log.lock().clone();
    Ok(host_mail::open_envelope(&object, &list, &me, provider, now_ms).into())
}

pub(crate) fn accept_result_with(
    object_json: &str,
    log: &MembershipLog,
    me: &MailRecipientData,
    outbox: &MailOutboxData,
    provider: &dyn KeyProvider,
    now_ms: u64,
) -> Result<ResultVerdictInfo> {
    let object = mail_object(object_json)?;
    let me = me.to_recipient()?;
    let outbox = outbox.to_expected()?;
    let list = log.lock().clone();
    Ok(host_mail::accept_result(&object, &list, &me, &outbox, provider, now_ms).into())
}

/// Seals `plain_json` (`{"kind":"request","message":…}`, `{"kind":"cancel",
/// "task_id":…}` or `{"kind":"complete","task_id":…,"result":…}`) to the
/// recipient host's encryption key `recipient_enc` (its `enc_kid` must be
/// `fields.enc_kid`) and signs the body with `host_key_id` (an Ed25519
/// `host_key`, purpose `HostSigning`): the `atem-envelope`'s wire JSON.
#[cfg(feature = "uniffi")]
#[uniffi::export]
pub fn seal_envelope(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    host_key_id: String,
    fields: MailFieldsData,
    plain_json: String,
    recipient_enc: PublicKeyData,
) -> Result<String> {
    seal_envelope_with(
        &crate::provider::Platform(provider),
        &host_key_id,
        &fields,
        &plain_json,
        &recipient_enc,
    )
}

/// As `seal_envelope`, an `atem-result` (`{"kind":"status","message_id":…,
/// "recipients":[…]}`, `{"kind":"status","object_id":…,"refused":…}` or
/// `{"kind":"result","task_id":…,"reply":…}`).
#[cfg(feature = "uniffi")]
#[uniffi::export]
pub fn seal_result(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    host_key_id: String,
    fields: MailFieldsData,
    plain_json: String,
    recipient_enc: PublicKeyData,
) -> Result<String> {
    seal_result_with(
        &crate::provider::Platform(provider),
        &host_key_id,
        &fields,
        &plain_json,
        &recipient_enc,
    )
}

/// `seal_envelope` with the HPKE ephemeral `DeriveKeyPair(ikm_e)`, for the
/// known-answer vectors only (feature `test-vectors`).
#[cfg(all(feature = "uniffi", feature = "test-vectors"))]
#[uniffi::export]
pub fn seal_envelope_with_ikm(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    host_key_id: String,
    fields: MailFieldsData,
    plain_json: String,
    recipient_enc: PublicKeyData,
    ikm_e: Vec<u8>,
) -> Result<String> {
    seal_envelope_with_ikm_with(
        &crate::provider::Platform(provider),
        &host_key_id,
        &fields,
        &plain_json,
        &recipient_enc,
        &ikm_e,
    )
}

/// `seal_result` with the HPKE ephemeral `DeriveKeyPair(ikm_e)` (known-answer
/// vectors only).
#[cfg(all(feature = "uniffi", feature = "test-vectors"))]
#[uniffi::export]
pub fn seal_result_with_ikm(
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    host_key_id: String,
    fields: MailFieldsData,
    plain_json: String,
    recipient_enc: PublicKeyData,
    ikm_e: Vec<u8>,
) -> Result<String> {
    seal_result_with_ikm_with(
        &crate::provider::Platform(provider),
        &host_key_id,
        &fields,
        &plain_json,
        &recipient_enc,
        &ikm_e,
    )
}

/// The receiver's checks 1 to 6 of an envelope that arrived in its mailbox,
/// against its device list `log`, as `me` (opening with a key of
/// `me.keys` in `provider`) at `now_ms`.
#[cfg(feature = "uniffi")]
#[uniffi::export]
pub fn open_envelope(
    object_json: String,
    log: Arc<MembershipLog>,
    me: MailRecipientData,
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    now_ms: u64,
) -> Result<EnvelopeVerdictInfo> {
    open_envelope_with(
        &object_json,
        &log,
        &me,
        &crate::provider::Platform(provider),
        now_ms,
    )
}

/// The sending host's check of a result against its outbox row `outbox`.
#[cfg(feature = "uniffi")]
#[uniffi::export]
pub fn accept_result(
    object_json: String,
    log: Arc<MembershipLog>,
    me: MailRecipientData,
    outbox: MailOutboxData,
    provider: Arc<dyn crate::provider::AppKeyProvider>,
    now_ms: u64,
) -> Result<ResultVerdictInfo> {
    accept_result_with(
        &object_json,
        &log,
        &me,
        &outbox,
        &crate::provider::Platform(provider),
        now_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trust generation enters the core only as a safe integer, as every
    /// other generation input does.
    #[test]
    fn a_receiver_generation_above_2_53_is_refused() {
        let me = |host_trust_gen| MailRecipientData {
            host_id: "host-b".into(),
            host_trust_gen,
            keys: vec![],
        };
        assert!(me(1).to_recipient().is_ok());
        let err = me(1 << 53).to_recipient().unwrap_err();
        assert_eq!(err.code(), "not_canonical");
    }

    /// A verdict whose plaintext can't be written back is no Open or
    /// Accepted with an empty plaintext: nothing is decided.
    #[test]
    fn a_plaintext_that_does_not_serialize_is_unavailable() {
        let bad_envelope = EnvelopePlain::Cancel {
            task_id: "not a task id".into(),
        };
        let got = EnvelopeVerdictInfo::from(EnvelopeVerdict::Open {
            plain: bad_envelope,
            sender: "host:host-a".into(),
        });
        assert!(
            matches!(got, EnvelopeVerdictInfo::Unavailable { .. }),
            "{got:?}"
        );
        let bad_result = || ResultPlain::Refusal {
            object_id: "not an id".into(),
            refused: "not a code".into(),
        };
        let accepted = ResultVerdictInfo::from(ResultVerdict::Accepted {
            plain: bad_result(),
            sender: "host:host-b".into(),
        });
        assert!(
            matches!(accepted, ResultVerdictInfo::Unavailable { .. }),
            "{accepted:?}"
        );
        let kept = ResultVerdictInfo::from(ResultVerdict::NotDelivered {
            plain: bad_result(),
            sender: "host:host-b".into(),
            reason: "result not delivered: sender revoked",
        });
        assert!(
            matches!(kept, ResultVerdictInfo::Unavailable { .. }),
            "{kept:?}"
        );
    }
}

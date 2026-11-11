//! The signed body of an envelope or a result, and the plaintexts that are
//! sealed beside it (delegated host-work design II.4.2, II.4.4).
//!
//! Every field is read exactly: no unknown field, no `null`, hashes in
//! lowercase hex, an `enc_kid` of 16 lowercase hex characters, ids in the
//! device list's grammar. What the body *says* (that the sender is
//! authorized, that its generation is current, that the times make sense) is
//! the receiver's to judge: a body that parses is a well-formed claim.
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::MAX_MAIL_OBJECT_BYTES;
use crate::canonical::{self, MAX_SAFE_INTEGER, Numbers, jcs};
use crate::domain::{self, SignLabel};
use crate::encoding::{Hash32, hex_decode_array};
use crate::error::{Error, Result};
use crate::host_principal::host_principal;
use crate::membership::Head;
use crate::membership::entry::id_ok;
use crate::session::host_work::{ContextSnapshot, ReplyState, ResultReply};
use crate::session::messages::{MAX_MESSAGE_BYTES, Message, RecipientReceipt, recipients_valid};
use crate::session::wire::{is_uuid_v4, is_uuid_v5};
use crate::signed::SealedPart;
use crate::signed::SignedObject;

/// host-work-v1 §7's error codes: the only ones a refusal names (new
/// `detail` texts, never new codes).
pub const REFUSAL_CODES: [&str; 6] = [
    "forbidden",
    "unauthorized",
    "stale_target",
    "invalid_request",
    "request_id_reused",
    "busy",
];

/// Which of the two objects: they have one shape and differ in direction, so
/// they differ in `type`, signing label and seal label (III.1): an object of
/// one direction can't be taken for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailKind {
    /// `atem-envelope`: the sender asks (request, cancel, complete).
    Envelope,
    /// `atem-result`: the host that ran the work answers (status, result).
    Result,
}

impl MailKind {
    /// The body's `type`.
    pub const fn body_type(self) -> &'static str {
        match self {
            MailKind::Envelope => "atem-envelope",
            MailKind::Result => "atem-result",
        }
    }

    /// The label of the signing input, `enc([label, jcs(body)])`.
    pub const fn sign_label(self) -> SignLabel {
        match self {
            MailKind::Envelope => SignLabel::Envelope,
            MailKind::Result => SignLabel::Result,
        }
    }

    /// The first field of the seal's HPKE `info`.
    pub const fn seal_domain(self) -> &'static str {
        match self {
            MailKind::Envelope => domain::ENVELOPE_SEAL,
            MailKind::Result => domain::RESULT_SEAL,
        }
    }

    /// The kind whose signing label this is.
    pub const fn of_label(label: SignLabel) -> Option<MailKind> {
        match label {
            SignLabel::Envelope => Some(MailKind::Envelope),
            SignLabel::Result => Some(MailKind::Result),
            _ => None,
        }
    }
}

/// A host in the device list at a trust generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRef {
    /// The `atem_device_id` of its `add_host`.
    pub host_id: String,
    /// The generation of its newest `add_host` (at least 1).
    pub host_trust_gen: u64,
}

impl HostRef {
    /// `host:<host_id>`: the principal a request's Message names as its
    /// sender ([`crate::host_principal`]).
    pub fn principal(&self) -> String {
        host_principal(&self.host_id)
    }

    fn check(&self) -> Result<()> {
        // The device list's id grammar, as `host:<id>` is read.
        if !id_ok(&self.host_id) {
            return Err(Error::Malformed("host_id"));
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&self.host_trust_gen) {
            return Err(Error::Malformed("host_trust_gen"));
        }
        Ok(())
    }

    fn to_map(&self) -> Map<String, Value> {
        let mut o = Map::new();
        o.insert("host_id".into(), json!(self.host_id));
        o.insert("host_trust_gen".into(), json!(self.host_trust_gen));
        o
    }

    /// A body's `sender` or `recipient` object: `host_id` and
    /// `host_trust_gen`, and exactly the `extra` fields besides.
    fn read(host: &Map<String, Value>, extra: &[&str]) -> Result<Self> {
        let mut keys = vec!["host_id", "host_trust_gen"];
        keys.extend_from_slice(extra);
        exact(host, &keys)?;
        Ok(HostRef {
            host_id: str_of(host, "host_id")?.to_owned(),
            host_trust_gen: u64_of(host, "host_trust_gen")?,
        })
    }
}

/// An envelope's or a result's body before the seal names its
/// `sealed_hash`: what a sender chooses (II.4.2). [`MailBody`] is these plus
/// the hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailFields {
    pub account_id: String,
    /// The account's genesis hash.
    pub genesis_hash: Hash32,
    /// The host that signs and sends.
    pub sender: HostRef,
    /// The host the object is sealed to.
    pub recipient: HostRef,
    /// The short id of the recipient's `enc_key` (§R9.9, [`crate::keys::enc_kid`]).
    pub enc_kid: String,
    /// The object's id (UUID v4): an envelope's is its request's `message_id`.
    pub id: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// The head of the sender's own device list when it signed (II.4.2),
    /// under the signature.
    pub signed_at_head: Head,
}

impl MailFields {
    /// The grammar of every field (R9.1, II.4.2). The times' order, length
    /// and freshness are the receiver's checks, not the grammar's.
    pub fn check(&self) -> Result<()> {
        if !(1..=128).contains(&self.account_id.len()) {
            return Err(Error::Malformed("account_id"));
        }
        self.sender.check()?;
        self.recipient.check()?;
        hex_decode_array::<8>(&self.enc_kid).map_err(|_| Error::Malformed("enc_kid"))?;
        if !is_uuid_v4(&self.id) {
            return Err(Error::Malformed("id"));
        }
        if self.created_at > MAX_SAFE_INTEGER || self.expires_at > MAX_SAFE_INTEGER {
            return Err(Error::Malformed("time"));
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&self.signed_at_head.seq) {
            return Err(Error::Malformed("signed_at_head"));
        }
        Ok(())
    }
}

/// The signed body of an envelope or a result (`type` `atem-envelope` or
/// `atem-result`; [`MailKind`] names which).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailBody {
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub sender: HostRef,
    pub recipient: HostRef,
    pub enc_kid: String,
    pub id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub signed_at_head: Head,
    /// `SHA-256(enc([enc, ct]))`: names the sealed part beside the body.
    pub sealed_hash: Hash32,
}

const BODY_KEYS: [&str; 11] = [
    "type",
    "v",
    "account_id",
    "genesis_hash",
    "sender",
    "recipient",
    "id",
    "created_at",
    "expires_at",
    "signed_at_head",
    "sealed_hash",
];

impl MailBody {
    pub fn from_fields(fields: MailFields, sealed_hash: Hash32) -> Self {
        MailBody {
            account_id: fields.account_id,
            genesis_hash: fields.genesis_hash,
            sender: fields.sender,
            recipient: fields.recipient,
            enc_kid: fields.enc_kid,
            id: fields.id,
            created_at: fields.created_at,
            expires_at: fields.expires_at,
            signed_at_head: fields.signed_at_head,
            sealed_hash,
        }
    }

    /// The body without its `sealed_hash`.
    pub fn fields(&self) -> MailFields {
        MailFields {
            account_id: self.account_id.clone(),
            genesis_hash: self.genesis_hash,
            sender: self.sender.clone(),
            recipient: self.recipient.clone(),
            enc_kid: self.enc_kid.clone(),
            id: self.id.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            signed_at_head: self.signed_at_head,
        }
    }

    /// The body as JSON, of `kind`'s `type`; the recipient carries the
    /// `enc_kid`.
    pub fn to_value(&self, kind: MailKind) -> Value {
        let mut recipient = self.recipient.to_map();
        recipient.insert("enc_kid".into(), json!(self.enc_kid));
        let mut o = Map::new();
        o.insert("type".into(), json!(kind.body_type()));
        o.insert("v".into(), json!(1));
        o.insert("account_id".into(), json!(self.account_id));
        o.insert("genesis_hash".into(), json!(self.genesis_hash.to_hex()));
        o.insert("sender".into(), Value::Object(self.sender.to_map()));
        o.insert("recipient".into(), Value::Object(recipient));
        o.insert("id".into(), json!(self.id));
        o.insert("created_at".into(), json!(self.created_at));
        o.insert("expires_at".into(), json!(self.expires_at));
        o.insert("signed_at_head".into(), self.signed_at_head.to_json());
        o.insert("sealed_hash".into(), json!(self.sealed_hash.to_hex()));
        Value::Object(o)
    }

    /// Reads the body of a mailbox object (II.4.2, step 1): the label is an
    /// envelope's or a result's, the body has exactly its fields in their
    /// grammar, and the sealed part beside it is an encapsulated key (32
    /// bytes) and a ciphertext at least a tag long (16). Nothing is verified
    /// or opened.
    pub fn from_object(object: &SignedObject) -> Result<(MailKind, MailBody)> {
        let kind = MailKind::of_label(object.label())
            .ok_or(Error::Malformed("not an envelope or a result"))?;
        let sealed = object.sealed().ok_or(Error::Malformed(
            "an envelope or a result carries enc and ct",
        ))?;
        if sealed.enc.len() != 32 || sealed.ct.len() < 16 {
            return Err(Error::Malformed("enc is 32 bytes and ct holds a tag"));
        }
        let o = object.body().as_object().ok_or(Error::Malformed("body"))?;
        exact(o, &BODY_KEYS)?;
        let hash = |key: &'static str| {
            Hash32::from_hex(str_of(o, key)?).map_err(|_| Error::Malformed(key))
        };
        let host = |key: &'static str| {
            o.get(key)
                .and_then(Value::as_object)
                .ok_or(Error::Malformed(key))
        };
        let recipient = host("recipient")?;
        let fields = MailFields {
            account_id: str_of(o, "account_id")?.to_owned(),
            genesis_hash: hash("genesis_hash")?,
            sender: HostRef::read(host("sender")?, &[])?,
            recipient: HostRef::read(recipient, &["enc_kid"])?,
            enc_kid: str_of(recipient, "enc_kid")?.to_owned(),
            id: str_of(o, "id")?.to_owned(),
            created_at: u64_of(o, "created_at")?,
            expires_at: u64_of(o, "expires_at")?,
            signed_at_head: Head::from_json(&o["signed_at_head"])
                .ok_or(Error::Malformed("signed_at_head"))?,
        };
        fields.check()?;
        Ok((kind, MailBody::from_fields(fields, hash("sealed_hash")?)))
    }

    /// Whether `sealed_hash` names this sealed part: `SHA-256(enc([enc,
    /// ct]))`, so a changed byte of either, or a byte moved from one to the
    /// other, doesn't match.
    pub fn names(&self, sealed: &SealedPart) -> bool {
        Hash32::of_enc(&[&sealed.enc, &sealed.ct]) == self.sealed_hash
    }
}

fn exact(o: &Map<String, Value>, keys: &[&str]) -> Result<()> {
    if o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)) {
        Ok(())
    } else {
        Err(Error::Malformed("fields"))
    }
}

fn str_of<'a>(o: &'a Map<String, Value>, key: &'static str) -> Result<&'a str> {
    o.get(key)
        .and_then(Value::as_str)
        .ok_or(Error::Malformed(key))
}

fn u64_of(o: &Map<String, Value>, key: &'static str) -> Result<u64> {
    o.get(key)
        .and_then(Value::as_u64)
        .ok_or(Error::Malformed(key))
}

/// A task's id: a recipient's UUID v4, or the UUID v5 of a selector's fixed
/// resolution (collaboration §5).
fn task_id_ok(id: &str) -> bool {
    is_uuid_v4(id) || is_uuid_v5(id)
}

/// What the object's sealed part decodes to: `jcs` of one JSON object whose
/// `kind` says which, read back exactly.
fn plain_object(bytes: &[u8]) -> Result<Map<String, Value>> {
    match canonical::parse_strict(bytes, MAX_MAIL_OBJECT_BYTES, Numbers::IntegersOnly)? {
        Value::Object(o) => Ok(o),
        _ => Err(Error::Malformed("plaintext")),
    }
}

/// Bytes are the plaintext's own canonical form, and nothing else.
fn canonical_only(bytes: &[u8], expected: &[u8]) -> Result<()> {
    if bytes == expected {
        Ok(())
    } else {
        Err(Error::Malformed("plaintext not canonical"))
    }
}

fn take<T: serde::de::DeserializeOwned>(
    o: &mut Map<String, Value>,
    key: &'static str,
) -> Result<T> {
    o.remove(key)
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or(Error::Malformed(key))
}

fn value_of<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| Error::Malformed("plaintext"))
}

/// The plaintext of an envelope (II.4.2): `{"kind":"request","message":…}`,
/// `{"kind":"cancel","task_id":…}` or `{"kind":"complete","task_id":…,
/// "result":…}`, as `jcs`.
// A request carries a whole Message and the others a task id: a plaintext
// lives only while it is sealed or just opened, so the size gap costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopePlain {
    /// A host-work-v1 §5 Message, whole, as every host gets it. Its sender,
    /// ids and times must equal the body's, and the message must be a host
    /// sender's ([`Message::valid_from_host`]); both are the receiver's checks.
    Request { message: Message },
    /// Cancel the task of that id.
    Cancel { task_id: String },
    /// The sender completes the task with a result snapshot.
    Complete {
        task_id: String,
        result: ContextSnapshot,
    },
}

impl EnvelopePlain {
    /// What a sender may seal and a receiver reads: ids in their grammar, a
    /// Message of at most [`MAX_MESSAGE_BYTES`] (its own validity is the
    /// receiver's), a snapshot as `work_complete` takes one.
    fn check(&self) -> Result<()> {
        match self {
            EnvelopePlain::Request { message } => {
                let size = serde_json::to_vec(message).map_err(|_| Error::Malformed("message"))?;
                if size.len() > MAX_MESSAGE_BYTES {
                    return Err(Error::TooLarge);
                }
            }
            EnvelopePlain::Cancel { task_id } => {
                if !task_id_ok(task_id) {
                    return Err(Error::Malformed("task_id"));
                }
            }
            EnvelopePlain::Complete { task_id, result } => {
                if !task_id_ok(task_id) || !result.valid() {
                    return Err(Error::Malformed("complete"));
                }
            }
        }
        Ok(())
    }

    fn to_value(&self) -> Result<Value> {
        Ok(match self {
            EnvelopePlain::Request { message } => {
                json!({"kind": "request", "message": value_of(message)?})
            }
            EnvelopePlain::Cancel { task_id } => json!({"kind": "cancel", "task_id": task_id}),
            EnvelopePlain::Complete { task_id, result } => {
                json!({"kind": "complete", "task_id": task_id, "result": value_of(result)?})
            }
        })
    }

    /// `jcs` of the plaintext, wiped when dropped.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.check()?;
        Ok(Zeroizing::new(jcs(&self.to_value()?)?.into_bytes()))
    }

    /// Exactly what [`to_bytes`](Self::to_bytes) writes (II.4.2, step 6):
    /// strict I-JSON, one of the three shapes with exactly its fields, and
    /// nothing but the canonical form.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut o = plain_object(bytes)?;
        let kind = str_of(&o, "kind")?.to_owned();
        let plain = match kind.as_str() {
            "request" => {
                exact(&o, &["kind", "message"])?;
                EnvelopePlain::Request {
                    message: take(&mut o, "message")?,
                }
            }
            "cancel" => {
                exact(&o, &["kind", "task_id"])?;
                EnvelopePlain::Cancel {
                    task_id: take(&mut o, "task_id")?,
                }
            }
            "complete" => {
                exact(&o, &["kind", "task_id", "result"])?;
                EnvelopePlain::Complete {
                    task_id: take(&mut o, "task_id")?,
                    result: take(&mut o, "result")?,
                }
            }
            _ => return Err(Error::Malformed("kind")),
        };
        plain.check()?;
        canonical_only(bytes, &plain.to_bytes()?)?;
        Ok(plain)
    }
}

/// The plaintext of a result (II.4.4): `{"kind":"status","message_id":…,
/// "recipients":[…]}`, `{"kind":"status","object_id":…,"refused":…}` or
/// `{"kind":"result","task_id":…,"reply":…}`, as `jcs`.
///
/// These reuse host-work-v1's own wire shapes, so they carry the `null`s
/// those emit (`work.result: null`); R9.1's ban on `null` is for signed
/// bodies, which have none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultPlain {
    /// This host's receipts for the message's recipients (host-work-v1 §5
    /// "Publish"), at acceptance and at each later change of a task's state.
    Status {
        message_id: String,
        recipients: Vec<RecipientReceipt>,
    },
    /// An authenticated object this host refused at II.4.2's checks 5 or 6:
    /// one of host-work-v1 §7's codes ([`REFUSAL_CODES`]).
    Refusal { object_id: String, refused: String },
    /// The agent's reply, as `reply_query` returns it once `submitted`.
    Result { task_id: String, reply: ResultReply },
}

impl ResultPlain {
    fn check(&self) -> Result<()> {
        let ok = match self {
            ResultPlain::Status {
                message_id,
                recipients,
            } => is_uuid_v4(message_id) && recipients_valid(recipients),
            ResultPlain::Refusal { object_id, refused } => {
                is_uuid_v4(object_id) && REFUSAL_CODES.contains(&refused.as_str())
            }
            ResultPlain::Result { task_id, reply } => {
                task_id_ok(task_id) && reply.valid() && reply.state == ReplyState::Submitted
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::Malformed("result"))
        }
    }

    fn to_value(&self) -> Result<Value> {
        Ok(match self {
            ResultPlain::Status {
                message_id,
                recipients,
            } => json!({"kind": "status", "message_id": message_id,
                        "recipients": value_of(recipients)?}),
            ResultPlain::Refusal { object_id, refused } => {
                json!({"kind": "status", "object_id": object_id, "refused": refused})
            }
            ResultPlain::Result { task_id, reply } => {
                json!({"kind": "result", "task_id": task_id, "reply": value_of(reply)?})
            }
        })
    }

    /// `jcs` of the plaintext, wiped when dropped.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.check()?;
        Ok(Zeroizing::new(jcs(&self.to_value()?)?.into_bytes()))
    }

    /// Exactly what [`to_bytes`](Self::to_bytes) writes (II.4.2 step 6 for
    /// the receiver of a result): the two `status` shapes are told apart by
    /// their fields, and nothing but the canonical form is accepted.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut o = plain_object(bytes)?;
        let kind = str_of(&o, "kind")?.to_owned();
        let plain = match kind.as_str() {
            "status" if o.contains_key("object_id") => {
                exact(&o, &["kind", "object_id", "refused"])?;
                ResultPlain::Refusal {
                    object_id: take(&mut o, "object_id")?,
                    refused: take(&mut o, "refused")?,
                }
            }
            "status" => {
                exact(&o, &["kind", "message_id", "recipients"])?;
                ResultPlain::Status {
                    message_id: take(&mut o, "message_id")?,
                    recipients: take(&mut o, "recipients")?,
                }
            }
            "result" => {
                exact(&o, &["kind", "task_id", "reply"])?;
                ResultPlain::Result {
                    task_id: take(&mut o, "task_id")?,
                    reply: take(&mut o, "reply")?,
                }
            }
            _ => return Err(Error::Malformed("kind")),
        };
        plain.check()?;
        canonical_only(bytes, &plain.to_bytes()?)?;
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::canonical::jcs;
    use crate::encoding::{Hash32, b64u};
    use crate::error::Error;
    use crate::host_mail::test_support::*;
    use crate::session::host_work::ReplyState;
    use crate::session::messages::{Delivery, RecipientReceipt, WorkProgress};
    use crate::signed::SignedObject;

    /// A well-formed envelope body, as the wire object a parser sees.
    fn object(edit: impl FnOnce(&mut Value)) -> Result<SignedObject> {
        let r = Rig::new();
        let body = MailBody::from_fields(r.fields(), Hash32([0x33; 32]));
        let mut value = json!({
            "body": body.to_value(MailKind::Envelope),
            "sig": b64u(&[1u8; 64]),
            "enc": b64u(&[2u8; 32]),
            "ct": b64u(&[3u8; 40]),
        });
        edit(&mut value);
        SignedObject::from_value(&value)
    }

    fn body_of(edit: impl FnOnce(&mut Value)) -> Result<(MailKind, MailBody)> {
        MailBody::from_object(&object(edit)?)
    }

    #[test]
    fn the_body_round_trips_and_names_its_kind() {
        let r = Rig::new();
        let f = r.fields();
        let body = MailBody::from_fields(f.clone(), Hash32([0x33; 32]));
        assert_eq!(body.fields(), f);
        let (kind, read) = body_of(|_| {}).unwrap();
        assert_eq!(kind, MailKind::Envelope);
        assert_eq!(read, body);
        assert_eq!(read.sender.principal(), "host:host-a");

        // Result bodies are the same shape under their own type.
        let (kind, read) = body_of(|v| v["body"]["type"] = json!("atem-result")).unwrap();
        assert_eq!(kind, MailKind::Result);
        assert_eq!(read, body);
        assert_eq!(
            MailKind::of_label(MailKind::Result.sign_label()),
            Some(MailKind::Result)
        );
        assert_eq!(MailKind::Envelope.body_type(), "atem-envelope");
        assert_eq!(MailKind::Result.body_type(), "atem-result");
    }

    #[test]
    fn a_body_is_read_strictly() {
        type Edit = Box<dyn Fn(&mut Value)>;
        let bad: Vec<(&str, Edit)> = vec![
            ("extra field", Box::new(|v| v["body"]["note"] = json!("x"))),
            (
                "no id",
                Box::new(|v| {
                    v["body"].as_object_mut().unwrap().remove("id");
                }),
            ),
            (
                "extra sender field",
                Box::new(|v| v["body"]["sender"]["enc_kid"] = json!("0123456789abcdef")),
            ),
            (
                "no kid",
                Box::new(|v| {
                    v["body"]["recipient"]
                        .as_object_mut()
                        .unwrap()
                        .remove("enc_kid");
                }),
            ),
            (
                "top-level kid",
                Box::new(|v| v["body"]["enc_kid"] = json!("0123456789abcdef")),
            ),
            (
                "upper-case kid",
                Box::new(|v| v["body"]["recipient"]["enc_kid"] = json!("0123456789ABCDEF")),
            ),
            (
                "short kid",
                Box::new(|v| v["body"]["recipient"]["enc_kid"] = json!("0123456789abcde")),
            ),
            (
                "upper-case genesis",
                Box::new(|v| v["body"]["genesis_hash"] = json!("AA".repeat(32))),
            ),
            (
                "short sealed_hash",
                Box::new(|v| v["body"]["sealed_hash"] = json!("aa")),
            ),
            (
                "id not a v4",
                Box::new(|v| v["body"]["id"] = json!(REPLY_ID)),
            ),
            (
                "generation 0",
                Box::new(|v| v["body"]["sender"]["host_trust_gen"] = json!(0)),
            ),
            (
                "generation a string",
                Box::new(|v| v["body"]["recipient"]["host_trust_gen"] = json!("3")),
            ),
            (
                "host id with a space",
                Box::new(|v| v["body"]["sender"]["host_id"] = json!("host a")),
            ),
            (
                "empty account",
                Box::new(|v| v["body"]["account_id"] = json!("")),
            ),
            (
                "account too long",
                Box::new(|v| v["body"]["account_id"] = json!("a".repeat(129))),
            ),
            (
                "time as text",
                Box::new(|v| v["body"]["created_at"] = json!("1")),
            ),
            (
                "time beyond 2^53",
                Box::new(|v| v["body"]["expires_at"] = json!(9_007_199_254_740_992u64)),
            ),
            (
                "head seq 0",
                Box::new(|v| v["body"]["signed_at_head"]["seq"] = json!(0)),
            ),
            (
                "head extra",
                Box::new(|v| v["body"]["signed_at_head"]["x"] = json!(1)),
            ),
            (
                "no head",
                Box::new(|v| {
                    v["body"].as_object_mut().unwrap().remove("signed_at_head");
                }),
            ),
        ];
        for (name, edit) in bad {
            let got = object(|v| edit(v)).and_then(|o| MailBody::from_object(&o));
            assert!(got.is_err(), "{name}: {got:?}");
        }
        // `null` is no value, an absent field is omitted (R9.1).
        assert_eq!(
            object(|v| v["body"]["id"] = Value::Null),
            Err(Error::NullValue)
        );
        // The times' order and length are the receiver's checks (II.4.2
        // step 5), not the parse's: a bad time is an authenticated object.
        assert!(body_of(|v| v["body"]["expires_at"] = json!(1)).is_ok());
        assert!(body_of(|v| v["body"]["created_at"] = json!(1)).is_ok());
    }

    #[test]
    fn a_mail_object_needs_a_well_formed_sealed_part() {
        for edit in [
            (|v: &mut Value| {
                v.as_object_mut().unwrap().remove("enc");
                v.as_object_mut().unwrap().remove("ct");
            }) as fn(&mut Value),
            |v| v["enc"] = json!(b64u(&[2u8; 31])),
            |v| v["enc"] = json!(b64u(&[2u8; 33])),
            |v| v["ct"] = json!(b64u(&[3u8; 15])),
        ] {
            let got = object(edit).and_then(|o| MailBody::from_object(&o));
            assert!(matches!(got, Err(Error::Malformed(_))), "{got:?}");
        }
        // 16 bytes is an empty plaintext's tag: the shortest.
        assert!(body_of(|v| v["ct"] = json!(b64u(&[3u8; 16]))).is_ok());
        // Not a mail object: another label.
        let seen =
            SignedObject::from_value(&json!({"body": {"type": "atem-seen", "v": 1}, "sig": "AA"}))
                .unwrap();
        assert!(matches!(
            MailBody::from_object(&seen),
            Err(Error::Malformed(_))
        ));
    }

    fn envelope_plains() -> Vec<EnvelopePlain> {
        let r = Rig::new();
        let f = r.fields();
        vec![
            EnvelopePlain::Request {
                message: message(&f),
            },
            EnvelopePlain::Cancel {
                task_id: ID2.into(),
            },
            EnvelopePlain::Cancel {
                task_id: REPLY_ID.into(),
            },
            EnvelopePlain::Complete {
                task_id: ID2.into(),
                result: snapshot(0, 10),
            },
        ]
    }

    #[test]
    fn envelope_plaintexts_are_jcs_and_read_back_exactly() {
        for plain in envelope_plains() {
            let bytes = plain.to_bytes().unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(jcs(&value).unwrap().as_bytes(), &bytes[..]);
            assert_eq!(EnvelopePlain::parse(&bytes).unwrap(), plain);
        }
        let cancel = EnvelopePlain::Cancel {
            task_id: ID2.into(),
        };
        assert_eq!(
            &cancel.to_bytes().unwrap()[..],
            format!(r#"{{"kind":"cancel","task_id":"{ID2}"}}"#).as_bytes()
        );
    }

    #[test]
    fn envelope_plaintexts_are_read_strictly() {
        let cancel = |extra: &str| format!(r#"{{"kind":"cancel","task_id":"{ID2}"{extra}}}"#);
        assert!(EnvelopePlain::parse(cancel("").as_bytes()).is_ok());
        let snap = snapshot(0, 10);
        let complete = |snap: &Value| {
            jcs(&json!({"kind": "complete", "task_id": ID2, "result": snap})).unwrap()
        };
        assert!(
            EnvelopePlain::parse(complete(&serde_json::to_value(&snap).unwrap()).as_bytes())
                .is_ok()
        );
        let mut bad_digest = serde_json::to_value(&snap).unwrap();
        bad_digest["digest"] = json!("00".repeat(32));
        let mut a_result = serde_json::to_value(&snap).unwrap();
        a_result["kind"] = json!("result");
        let message_json = serde_json::to_value(message(&Rig::new().fields())).unwrap();
        let cases: Vec<(&str, String)> = vec![
            ("extra field", cancel(r#","x":1"#)),
            ("not canonical: spaces", cancel("").replace(':', ": ")),
            (
                "not canonical: order",
                format!(r#"{{"task_id":"{ID2}","kind":"cancel"}}"#),
            ),
            (
                "unknown kind",
                format!(r#"{{"kind":"retract","task_id":"{ID2}"}}"#),
            ),
            (
                "a result's kind",
                format!(r#"{{"kind":"status","message_id":"{ID}","recipients":[]}}"#),
            ),
            ("task id not a uuid", cancel("").replace(ID2, "task-1")),
            (
                "null task",
                r#"{"kind":"cancel","task_id":null}"#.to_string(),
            ),
            ("a snapshot whose digest is wrong", complete(&bad_digest)),
            ("a Result snapshot", complete(&a_result)),
            ("request without a message", r#"{"kind":"request"}"#.into()),
            (
                "request with a task id",
                jcs(&json!({"kind":"request","message":message_json,"task_id":ID2})).unwrap(),
            ),
            (
                "a message with a field of its own",
                jcs(&json!({"kind":"request","message":{"x":1}})).unwrap(),
            ),
            ("not JSON", "cancel".into()),
            ("two values", format!("{}{}", cancel(""), cancel(""))),
            ("a float", cancel("").replace(ID2, "1.5")),
        ];
        for (name, text) in cases {
            let got = EnvelopePlain::parse(text.as_bytes());
            assert!(got.is_err(), "{name}: {got:?}");
        }
        // The same rules apply when building.
        assert!(
            EnvelopePlain::Cancel {
                task_id: "x".into()
            }
            .to_bytes()
            .is_err()
        );
        // A message with a mark or attachments still parses: refusing it is
        // the receiver's (step 7), which names the reason.
        let mut m = message(&Rig::new().fields());
        m.sender = "member:phone".into();
        let plain = EnvelopePlain::Request { message: m };
        assert_eq!(
            EnvelopePlain::parse(&plain.to_bytes().unwrap()).unwrap(),
            plain
        );
    }

    fn receipt(id: &str, delivery: Delivery) -> RecipientReceipt {
        RecipientReceipt {
            recipient_id: id.into(),
            delivery,
        }
    }

    fn result_plains() -> Vec<ResultPlain> {
        vec![
            ResultPlain::Status {
                message_id: ID.into(),
                recipients: vec![
                    receipt(ID2, Delivery::Stored),
                    receipt(
                        ID,
                        Delivery::Refused {
                            code: "forbidden".into(),
                        },
                    ),
                ],
            },
            ResultPlain::Status {
                message_id: ID.into(),
                recipients: vec![receipt(
                    ID2,
                    Delivery::Work {
                        work: WorkProgress {
                            task_id: ID2.into(),
                            receipt_id: ID.into(),
                            state: crate::session::host_work::WorkState::Queued,
                            detail: "waiting for a ready agent".into(),
                            result: None,
                        },
                    },
                )],
            },
            ResultPlain::Refusal {
                object_id: ID.into(),
                refused: "invalid_request".into(),
            },
            ResultPlain::Result {
                task_id: ID2.into(),
                reply: reply(0),
            },
            ResultPlain::Result {
                task_id: REPLY_ID.into(),
                reply: reply(1),
            },
        ]
    }

    #[test]
    fn result_plaintexts_are_jcs_and_read_back_exactly() {
        for plain in result_plains() {
            let bytes = plain.to_bytes().unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(jcs(&value).unwrap().as_bytes(), &bytes[..]);
            assert_eq!(ResultPlain::parse(&bytes).unwrap(), plain);
        }
        // The design's two status shapes share `kind: "status"`.
        let refusal = ResultPlain::Refusal {
            object_id: ID.into(),
            refused: "invalid_request".into(),
        };
        assert_eq!(
            &refusal.to_bytes().unwrap()[..],
            format!(r#"{{"kind":"status","object_id":"{ID}","refused":"invalid_request"}}"#)
                .as_bytes()
        );
    }

    #[test]
    fn result_plaintexts_are_read_strictly() {
        let refusal =
            |code: &str| format!(r#"{{"kind":"status","object_id":"{ID}","refused":"{code}"}}"#);
        // Only host-work-v1 section 7's codes.
        for code in [
            "forbidden",
            "unauthorized",
            "stale_target",
            "invalid_request",
            "request_id_reused",
            "busy",
        ] {
            assert!(
                ResultPlain::parse(refusal(code).as_bytes()).is_ok(),
                "{code}"
            );
        }
        for code in ["", "denied", "Invalid_request", "invalid_request "] {
            assert!(
                ResultPlain::parse(refusal(code).as_bytes()).is_err(),
                "{code:?}"
            );
        }
        let status = |recipients: Value| {
            jcs(&json!({"kind": "status", "message_id": ID, "recipients": recipients})).unwrap()
        };
        let ok = serde_json::to_value(vec![receipt(ID2, Delivery::Stored)]).unwrap();
        assert!(ResultPlain::parse(status(ok.clone()).as_bytes()).is_ok());
        let twice = serde_json::to_value(vec![
            receipt(ID2, Delivery::Stored),
            receipt(ID2, Delivery::Stored),
        ])
        .unwrap();
        let none = json!([]);
        let many = serde_json::to_value(
            (0..33)
                .map(|i| {
                    receipt(
                        &format!("6f1c2a4e-3b7d-4e8a-9c01-2d5f7a9b3c{i:02}"),
                        Delivery::Stored,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let bad_code = serde_json::to_value(vec![receipt(
            ID2,
            Delivery::Refused {
                code: "busy".into(),
            },
        )])
        .unwrap();
        for (name, recipients) in [
            ("duplicate ids", twice),
            ("no recipients", none),
            ("33 recipients", many),
            ("a code a receipt can't carry", bad_code),
        ] {
            let got = ResultPlain::parse(status(recipients).as_bytes());
            assert!(got.is_err(), "{name}: {got:?}");
        }
        // Both shapes at once, or neither.
        let both = jcs(&json!({"kind":"status","message_id":ID,"recipients":ok,"object_id":ID,"refused":"busy"})).unwrap();
        assert!(ResultPlain::parse(both.as_bytes()).is_err());
        assert!(ResultPlain::parse(br#"{"kind":"status"}"#).is_err());
        assert!(
            ResultPlain::parse(br#"{"kind":"status","object_id":"x","refused":"busy"}"#).is_err()
        );

        // A result: only a submitted, valid reply.
        let result =
            |reply: Value| jcs(&json!({"kind": "result", "task_id": ID2, "reply": reply})).unwrap();
        let good = serde_json::to_value(reply(0)).unwrap();
        assert!(ResultPlain::parse(result(good.clone()).as_bytes()).is_ok());
        let mut publishing = reply(0);
        publishing.state = ReplyState::Publishing;
        publishing.submitted_at = None;
        let mut bad_digest = good.clone();
        bad_digest["digest"] = json!("zz");
        let mut extra = good.clone();
        extra["x"] = json!(1);
        for (name, reply) in [
            (
                "a reply not yet submitted",
                serde_json::to_value(&publishing).unwrap(),
            ),
            ("a bad digest", bad_digest),
            ("an extra field", extra),
        ] {
            let got = ResultPlain::parse(result(reply).as_bytes());
            assert!(got.is_err(), "{name}: {got:?}");
        }
        assert!(
            ResultPlain::Result {
                task_id: "t".into(),
                reply: reply(0)
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            ResultPlain::Result {
                task_id: ID2.into(),
                reply: publishing
            }
            .to_bytes()
            .is_err()
        );
    }
}

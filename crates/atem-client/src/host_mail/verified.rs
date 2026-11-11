//! A mailbox object whose signature verified: the only thing that can be
//! opened (delegated host-work design II.4.2: the signature, step 4, comes
//! before the open, step 6).
//!
//! HPKE base mode is unauthenticated and the seal's `info` is built from the
//! body's public fields, so anyone can write a body, seal a plaintext of their
//! choosing to the recipient's `enc_key` and name it by `sealed_hash`. Only the
//! signature says who sent it. [`unseal_envelope`](super::unseal_envelope) and
//! [`unseal_result`](super::unseal_result) therefore take a [`VerifiedMail`],
//! as [`push::Hint`](crate::push::Hint) makes opening before verification
//! impossible for a push hint.
use super::body::{MailBody, MailKind};
use crate::error::{Error, Result};
use crate::keys::{Alg, PublicKey};
use crate::signed::SignedObject;

/// An envelope or a result whose `sig` verified with the sender's Ed25519
/// `host_key`. Its fields are private to this module and
/// [`verify`](Self::verify) is the only way to make one (no `Default`, no
/// `Deserialize`, no `From`), so code that holds one has a verified object.
///
/// Which key to verify with is the receiver's decision, made from its own
/// device list (II.4.2 steps 2 and 3: the sender's newest `add_host`
/// `host_key`, never one the object names); this type only proves the
/// signature was checked with the key given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMail {
    object: SignedObject,
    kind: MailKind,
    body: MailBody,
}

impl VerifiedMail {
    /// Reads `object` as a mailbox object (II.4.2 step 1: its label, the
    /// body's exact fields, a sealed part of the right shape) and verifies its
    /// signature with `sender_key`, which must be an Ed25519 key (a host's
    /// `host_key`, R9.2, R9.6). A signature by another key, a changed body or
    /// a re-typed one is [`Error::BadSignature`]; a key of another algorithm
    /// is [`Error::WrongAlg`].
    pub fn verify(object: &SignedObject, sender_key: &PublicKey) -> Result<VerifiedMail> {
        let (kind, body) = MailBody::from_object(object)?;
        if sender_key.alg() != Alg::Ed25519 {
            return Err(Error::WrongAlg);
        }
        object.verify(sender_key)?;
        Ok(VerifiedMail {
            object: object.clone(),
            kind,
            body,
        })
    }

    /// Which object it is: an envelope or a result.
    pub fn kind(&self) -> MailKind {
        self.kind
    }

    /// The signed body, as the signature covers it.
    pub fn body(&self) -> &MailBody {
        &self.body
    }

    /// The verified object, with its sealed part.
    pub fn object(&self) -> &SignedObject {
        &self.object
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::encoding::b64u;
    use crate::error::Error;
    use crate::host_mail::test_support::*;
    use crate::host_mail::{
        EnvelopePlain, MailKind, ResultPlain, parse_object, seal_envelope, seal_result,
        unseal_envelope, unseal_result,
    };
    use crate::keys::Alg;
    use crate::provider::KeyId;
    use crate::signed::SignedObject;
    use crate::software::SoftwareKeys;

    fn request(r: &Rig) -> SignedObject {
        let f = r.fields();
        let plain = EnvelopePlain::Request {
            message: message(&f),
        };
        seal_envelope(&r.sender, &r.host_key, &f, &plain, &r.enc_pub).unwrap()
    }

    /// `object` as the wire has it, with `edit` applied to the JSON.
    fn edited(object: &SignedObject, edit: impl FnOnce(&mut serde_json::Value)) -> SignedObject {
        let mut value = object.to_json();
        edit(&mut value);
        SignedObject::from_value(&value).unwrap()
    }

    #[test]
    fn a_valid_object_verifies_and_then_opens() {
        let r = Rig::new();
        let f = r.fields();
        let object = request(&r);
        let verified = VerifiedMail::verify(&object, &r.host_key_public()).unwrap();
        assert_eq!(verified.kind(), MailKind::Envelope);
        assert_eq!(verified.body().fields(), f);
        assert_eq!(verified.object(), &object);
        // Over the wire and back, as a receiver gets it.
        let parsed = parse_object(object.to_json().to_string().as_bytes()).unwrap();
        let verified = VerifiedMail::verify(&parsed, &r.host_key_public()).unwrap();
        assert_eq!(
            unseal_envelope(&r.receiver, &r.enc_key, &verified).unwrap(),
            EnvelopePlain::Request {
                message: message(&f)
            }
        );

        let status = ResultPlain::Refusal {
            object_id: ID2.into(),
            refused: "invalid_request".into(),
        };
        let result = seal_result(&r.sender, &r.host_key, &f, &status, &r.enc_pub).unwrap();
        let verified = VerifiedMail::verify(&result, &r.host_key_public()).unwrap();
        assert_eq!(verified.kind(), MailKind::Result);
        assert_eq!(
            unseal_result(&r.receiver, &r.enc_key, &verified).unwrap(),
            status
        );
    }

    #[test]
    fn a_junk_signature_fails_at_verify() {
        let r = Rig::new();
        let object = request(&r);
        let key = r.host_key_public();
        for sig in [b64u(&[1u8; 64]), b64u(&[0u8; 64]), b64u(&[1u8; 63])] {
            let junk = edited(&object, |v| v["sig"] = json!(sig));
            assert_eq!(
                VerifiedMail::verify(&junk, &key).map(|_| ()),
                Err(Error::BadSignature),
                "{sig}"
            );
        }
        // The real one, for contrast.
        assert!(VerifiedMail::verify(&object, &key).is_ok());
    }

    #[test]
    fn only_the_senders_key_verifies_what_the_sender_signed() {
        let r = Rig::new();
        let object = request(&r);
        let key = r.host_key_public();
        // Another host's key.
        let mut other = SoftwareKeys::new();
        let other_pub = other.generate(KeyId::new("other"), Alg::Ed25519).unwrap();
        assert_eq!(
            VerifiedMail::verify(&object, &other_pub).map(|_| ()),
            Err(Error::BadSignature)
        );
        // Not an Ed25519 key, whatever its algorithm could verify.
        let mut keys = SoftwareKeys::new();
        let p256 = keys.generate(KeyId::new("p"), Alg::P256).unwrap();
        for wrong in [&r.enc_pub, &p256] {
            assert_eq!(
                VerifiedMail::verify(&object, wrong).map(|_| ()),
                Err(Error::WrongAlg)
            );
        }
        // A changed body, and a body re-typed as the other direction's.
        let moved = edited(&object, |v| v["body"]["created_at"] = json!(1));
        assert_eq!(
            VerifiedMail::verify(&moved, &key).map(|_| ()),
            Err(Error::BadSignature)
        );
        let retyped = edited(&object, |v| v["body"]["type"] = json!("atem-result"));
        assert_eq!(
            VerifiedMail::verify(&retyped, &key).map(|_| ()),
            Err(Error::BadSignature)
        );
        // Not a mail object, or one with no sealed part.
        let seen =
            SignedObject::from_value(&json!({"body": {"type": "atem-seen", "v": 1}, "sig": "AA"}))
                .unwrap();
        assert!(matches!(
            VerifiedMail::verify(&seen, &key),
            Err(Error::Malformed(_))
        ));
        let bare = edited(&object, |v| {
            v.as_object_mut().unwrap().remove("enc");
            v.as_object_mut().unwrap().remove("ct");
        });
        assert!(matches!(
            VerifiedMail::verify(&bare, &key),
            Err(Error::Malformed(_))
        ));
    }

    /// HPKE base mode is unauthenticated and `info` is public: anyone can
    /// write a body, seal a plaintext of their choosing to the recipient and
    /// name it by `sealed_hash`. Only the signature says who did. Whatever
    /// they sign with, or with a junk signature, `verify` stops it before any
    /// path that opens.
    #[test]
    fn what_anyone_can_seal_to_the_recipient_cannot_pass_for_the_sender() {
        let r = Rig::new();
        let f = r.fields();
        let key = r.host_key_public();
        let plain = EnvelopePlain::Cancel {
            task_id: ID2.into(),
        };
        let mut attacker = SoftwareKeys::new();
        attacker
            .generate(KeyId::new("attacker"), Alg::Ed25519)
            .unwrap();
        let forged =
            seal_envelope(&attacker, &KeyId::new("attacker"), &f, &plain, &r.enc_pub).unwrap();
        // A well-formed object that names the sender as the sender...
        assert!(parse_object(forged.to_json().to_string().as_bytes()).is_ok());
        // ...signed by the attacker, or by nobody.
        assert_eq!(
            VerifiedMail::verify(&forged, &key).map(|_| ()),
            Err(Error::BadSignature)
        );
        let unsigned = edited(&forged, |v| v["sig"] = json!(b64u(&[7u8; 64])));
        assert_eq!(
            VerifiedMail::verify(&unsigned, &key).map(|_| ()),
            Err(Error::BadSignature)
        );
    }
}

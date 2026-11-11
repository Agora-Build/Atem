//! Seal, sign, unseal (delegated host-work design II.4.2, II.4.4).
//!
//! The seal is RFC 9180 base mode with R9.9's suite (DHKEM(X25519,
//! HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305) and empty AAD, to the
//! recipient host's `enc_key` (the `host_enc_key` of its device list), with
//! an `info` that binds both hosts, the ids and the times, so a copy another
//! host strips and re-signs as its own doesn't open. The body then names the
//! sealed part by `sealed_hash = SHA-256(enc([enc, ct]))` and is signed by
//! the sender's `host_key` (Ed25519).
use zeroize::Zeroizing;

use super::MAX_MAIL_OBJECT_BYTES;
use super::body::{EnvelopePlain, MailBody, MailFields, MailKind, ResultPlain};
use super::verified::VerifiedMail;
use crate::encoding::{ct_eq, enc, u64_field};
use crate::error::{Error, Result};
use crate::hpke;
use crate::keys::{Alg, PublicKey, enc_kid};
use crate::provider::{KeyId, KeyProvider};
use crate::signed::{SealedPart, SignedObject};

/// `info = enc([seal label, account_id, genesis_hash, sender.host_id,
/// u64(sender.host_trust_gen), recipient.host_id,
/// u64(recipient.host_trust_gen), enc_kid, id, u64(created_at),
/// u64(expires_at)])`, with the label of `kind`'s seal
/// (`atem-envelope-seal-v1` or `atem-result-seal-v1`), `genesis_hash` as its
/// 32 raw bytes and `enc_kid` as its 16 hex characters (as R9.9's `info`).
/// `signed_at_head` is under the signature alone.
pub fn seal_info(kind: MailKind, fields: &MailFields) -> Vec<u8> {
    enc(&[
        kind.seal_domain().as_bytes(),
        fields.account_id.as_bytes(),
        fields.genesis_hash.as_bytes(),
        fields.sender.host_id.as_bytes(),
        &u64_field(fields.sender.host_trust_gen),
        fields.recipient.host_id.as_bytes(),
        &u64_field(fields.recipient.host_trust_gen),
        fields.enc_kid.as_bytes(),
        fields.id.as_bytes(),
        &u64_field(fields.created_at),
        &u64_field(fields.expires_at),
    ])
}

/// Seals `plaintext` to `recipient_enc` with `seal` (`recipient, info,
/// plaintext`: a fresh ephemeral, or a given one for the known-answer
/// vectors), names it in the body and signs the body with `host_key` behind
/// `provider`.
fn seal_bytes(
    kind: MailKind,
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    fields: &MailFields,
    plaintext: &[u8],
    recipient_enc: &PublicKey,
    seal: impl FnOnce(&[u8; 32], &[u8], &[u8]) -> Result<hpke::Sealed>,
) -> Result<SignedObject> {
    fields.check()?;
    // The object is bounded on the wire: a plaintext that can't fit is
    // refused before any work (the exact size is checked once it is built).
    if plaintext.len() > MAX_MAIL_OBJECT_BYTES {
        return Err(Error::TooLarge);
    }
    // No verifier takes any other key for a host's signature (R9.2, R9.6).
    if provider.public_key(host_key)?.alg() != Alg::Ed25519 {
        return Err(Error::WrongAlg);
    }
    // `enc_kid` names the key sealed to, or the object could never open.
    if !ct_eq(
        enc_kid(recipient_enc)?.as_bytes(),
        fields.enc_kid.as_bytes(),
    ) {
        return Err(Error::Malformed("enc_kid is not the recipient key's"));
    }
    let recipient = recipient_enc.as_32().ok_or(Error::BadKey)?;
    let sealed = seal(recipient, &seal_info(kind, fields), plaintext)?;
    let body = MailBody::from_fields(fields.clone(), sealed.hash()).to_value(kind);
    let object = SignedObject::sign(provider, host_key, body)?.with_sealed(SealedPart {
        enc: sealed.enc.to_vec(),
        ct: sealed.ct,
    });
    if serde_json::to_vec(&object.to_json()).map_or(true, |b| b.len() > MAX_MAIL_OBJECT_BYTES) {
        return Err(Error::TooLarge);
    }
    Ok(object)
}

/// The one open behind [`unseal_envelope`] and [`unseal_result`] (whose docs
/// carry the rules): the plaintext bytes of a verified mailbox object of
/// `kind`.
fn unseal_bytes(
    kind: MailKind,
    provider: &dyn KeyProvider,
    enc_key_id: &KeyId,
    mail: &VerifiedMail,
) -> Result<Zeroizing<Vec<u8>>> {
    if mail.kind() != kind {
        return Err(Error::Malformed("not this kind of object"));
    }
    let body = mail.body();
    let ours = enc_kid(&provider.public_key(enc_key_id)?)?;
    if !ct_eq(ours.as_bytes(), body.enc_kid.as_bytes()) {
        return Err(Error::Malformed("not this enc_key's object"));
    }
    let sealed = mail.object().sealed().ok_or(Error::OpenFailed)?;
    if !body.names(sealed) {
        return Err(Error::OpenFailed);
    }
    provider.hpke_open(
        enc_key_id,
        &sealed.enc,
        &sealed.ct,
        &seal_info(kind, &body.fields()),
        b"",
    )
}

/// An `atem-envelope` (II.4.2): `plain` sealed to the recipient host's
/// `enc_key` (`recipient_enc`, whose [`enc_kid`] `fields.enc_kid` must be),
/// signed by `host_key` (the sender's Ed25519 key behind `provider`).
///
/// Builds only what a receiver can read: it doesn't judge what the receiver
/// decides (the sender's authorization, `signed_at_head`, the times, that the
/// Message's sender, id and times equal the body's, or that the Message is a
/// host sender's).
pub fn seal_envelope(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    fields: &MailFields,
    plain: &EnvelopePlain,
    recipient_enc: &PublicKey,
) -> Result<SignedObject> {
    seal_bytes(
        MailKind::Envelope,
        provider,
        host_key,
        fields,
        &plain.to_bytes()?,
        recipient_enc,
        |recipient, info, plaintext| hpke::seal(recipient, info, b"", plaintext),
    )
}

/// An `atem-result` (II.4.4): the same shape under the result labels.
pub fn seal_result(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    fields: &MailFields,
    plain: &ResultPlain,
    recipient_enc: &PublicKey,
) -> Result<SignedObject> {
    seal_bytes(
        MailKind::Result,
        provider,
        host_key,
        fields,
        &plain.to_bytes()?,
        recipient_enc,
        |recipient, info, plaintext| hpke::seal(recipient, info, b"", plaintext),
    )
}

/// [`seal_envelope`] with the HPKE ephemeral `DeriveKeyPair(ikm_e)`, for
/// known-answer vectors only (feature `test-vectors`, never in shipped
/// builds): the same `ikm_e` gives byte-identical objects (the signature is
/// deterministic). `ikm_e` must be secret and never reused outside a vector.
#[cfg(feature = "test-vectors")]
pub fn seal_envelope_with_ikm(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    fields: &MailFields,
    plain: &EnvelopePlain,
    recipient_enc: &PublicKey,
    ikm_e: &[u8; 32],
) -> Result<SignedObject> {
    seal_bytes(
        MailKind::Envelope,
        provider,
        host_key,
        fields,
        &plain.to_bytes()?,
        recipient_enc,
        |recipient, info, plaintext| hpke::seal_with_ikm(recipient, info, b"", plaintext, ikm_e),
    )
}

/// [`seal_result`] with the HPKE ephemeral `DeriveKeyPair(ikm_e)` (known-answer
/// vectors only, like [`seal_envelope_with_ikm`]).
#[cfg(feature = "test-vectors")]
pub fn seal_result_with_ikm(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    fields: &MailFields,
    plain: &ResultPlain,
    recipient_enc: &PublicKey,
    ikm_e: &[u8; 32],
) -> Result<SignedObject> {
    seal_bytes(
        MailKind::Result,
        provider,
        host_key,
        fields,
        &plain.to_bytes()?,
        recipient_enc,
        |recipient, info, plaintext| hpke::seal_with_ikm(recipient, info, b"", plaintext, ikm_e),
    )
}

/// The inverse of [`seal_envelope`], with the recipient's `enc_key` behind
/// `provider` (`enc_key_id`): the strictly parsed plaintext (II.4.2 step 6).
///
/// It takes a [`VerifiedMail`], which only [`VerifiedMail::verify`] makes: an
/// object whose signature verified with the sender's Ed25519 key (step 4,
/// with the key the receiver took from its device list in step 3). HPKE base
/// mode is unauthenticated and `info` is public, so anyone can seal a
/// plaintext of their choosing to the recipient; an unverified object can't
/// be opened. The object's label must be an envelope's, its `enc_kid` must
/// name this key (else it is refused before opening), its `sealed_hash` must
/// name `enc` and `ct` (the hash is under the signature, so a substituted
/// sealed part is refused), and the `info` rebuilt from the body must open
/// it.
///
/// Opening an object that wasn't verified doesn't compile:
///
/// ```compile_fail,E0308
/// use atem_client::host_mail::unseal_envelope;
/// use atem_client::{KeyId, KeyProvider, SignedObject};
///
/// fn open(provider: &dyn KeyProvider, key: &KeyId, object: &SignedObject) {
///     let _ = unseal_envelope(provider, key, object);
/// }
/// ```
///
/// and the same, with the signature verified first, does:
///
/// ```
/// use atem_client::host_mail::{VerifiedMail, unseal_envelope};
/// use atem_client::{KeyId, KeyProvider, PublicKey, SignedObject};
///
/// fn open(
///     provider: &dyn KeyProvider,
///     key: &KeyId,
///     object: &SignedObject,
///     sender: &PublicKey,
/// ) -> atem_client::Result<()> {
///     let verified = VerifiedMail::verify(object, sender)?;
///     let _plain = unseal_envelope(provider, key, &verified)?;
///     Ok(())
/// }
/// ```
pub fn unseal_envelope(
    provider: &dyn KeyProvider,
    enc_key_id: &KeyId,
    mail: &VerifiedMail,
) -> Result<EnvelopePlain> {
    EnvelopePlain::parse(&unseal_bytes(
        MailKind::Envelope,
        provider,
        enc_key_id,
        mail,
    )?)
}

/// The inverse of [`seal_result`]: the same rules as [`unseal_envelope`], for
/// a verified result's label and seal.
pub fn unseal_result(
    provider: &dyn KeyProvider,
    enc_key_id: &KeyId,
    mail: &VerifiedMail,
) -> Result<ResultPlain> {
    ResultPlain::parse(&unseal_bytes(MailKind::Result, provider, enc_key_id, mail)?)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::canonical::jcs;
    use crate::domain::{self, SignLabel};
    use crate::encoding::{Hash32, dec, enc, u64_field};
    use crate::error::Error;
    use crate::host_mail::VerifiedMail;
    use crate::host_mail::test_support::*;
    use crate::host_mail::{
        EnvelopePlain, MAX_MAIL_OBJECT_BYTES, MAX_PLAINTEXT_BYTES, MailBody, MailFields, MailKind,
        ResultPlain, parse_object,
    };
    use crate::keys::{Alg, enc_kid};
    use crate::provider::{KeyId, KeyProvider};
    use crate::session::messages::MAX_MESSAGE_BYTES;
    use crate::signed::{SealedPart, SignedObject};
    use crate::software::SoftwareKeys;

    fn verified(r: &Rig, object: &SignedObject) -> VerifiedMail {
        VerifiedMail::verify(object, &r.host_key_public()).unwrap()
    }

    fn request(f: &MailFields) -> EnvelopePlain {
        EnvelopePlain::Request {
            message: message(f),
        }
    }

    fn envelope(r: &Rig, f: &MailFields, plain: &EnvelopePlain) -> SignedObject {
        seal_envelope(&r.sender, &r.host_key, f, plain, &r.enc_pub).unwrap()
    }

    fn wire(object: &SignedObject) -> Vec<u8> {
        object.to_json().to_string().into_bytes()
    }

    /// The same body (rebuilt from `fields`) re-signed by the sender, with
    /// the sealed part of `object` kept.
    fn resigned(
        r: &Rig,
        kind: MailKind,
        object: &SignedObject,
        fields: MailFields,
    ) -> SignedObject {
        let (_, body) = MailBody::from_object(object).unwrap();
        let body = MailBody::from_fields(fields, body.sealed_hash);
        SignedObject::sign(&r.sender, &r.host_key, body.to_value(kind))
            .unwrap()
            .with_sealed(object.sealed().unwrap().clone())
    }

    #[test]
    fn envelope_seal_open_round_trip() {
        let r = Rig::new();
        let f = r.fields();
        let plains = [
            request(&f),
            EnvelopePlain::Cancel {
                task_id: ID2.into(),
            },
            EnvelopePlain::Complete {
                task_id: ID2.into(),
                result: snapshot(0, 100),
            },
        ];
        for plain in plains {
            let object = envelope(&r, &f, &plain);
            assert_eq!(object.label(), SignLabel::Envelope);
            assert_eq!(object.body_type(), "atem-envelope");

            // Over the wire and back: the mailbox's strict parse.
            let parsed = parse_object(&wire(&object)).unwrap();
            assert_eq!(parsed, object);
            let (kind, body) = MailBody::from_object(&parsed).unwrap();
            assert_eq!(kind, MailKind::Envelope);
            assert_eq!(body.fields(), f);

            // Signed by the sender's host key, with nothing else.
            parsed.verify(&r.host_key_public()).unwrap();
            assert_eq!(
                parsed.verify(&r.enc_pub),
                Err(Error::WrongAlg),
                "an X25519 key never verifies"
            );

            // Opened with the recipient's key, and only with it.
            assert_eq!(
                unseal_envelope(&r.receiver, &r.enc_key, &verified(&r, &parsed)).unwrap(),
                plain
            );
            let mut other = SoftwareKeys::new();
            other.generate(r.enc_key.clone(), Alg::X25519).unwrap();
            assert!(unseal_envelope(&other, &r.enc_key, &verified(&r, &parsed)).is_err());
        }
    }

    #[test]
    fn the_body_is_the_designs_example() {
        let r = Rig::new();
        let f = r.fields();
        let object = envelope(&r, &f, &request(&f));
        let sealed = object.sealed().unwrap();
        assert_eq!(
            object.body(),
            &json!({
                "type": "atem-envelope", "v": 1,
                "account_id": "acct-test-1",
                "genesis_hash": "11".repeat(32),
                "sender": {"host_id": "host-a", "host_trust_gen": 2},
                "recipient": {"host_id": "host-b", "host_trust_gen": 3,
                              "enc_kid": enc_kid(&r.enc_pub).unwrap()},
                "id": ID, "created_at": CREATED_AT, "expires_at": EXPIRES_AT,
                "signed_at_head": {"seq": 31, "hash": "22".repeat(32)},
                "sealed_hash": hex_of(&Sha256::digest(enc(&[&sealed.enc, &sealed.ct]))),
            })
        );
        let wire: Value = serde_json::from_slice(&wire(&object)).unwrap();
        let mut keys: Vec<&str> = wire
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["body", "ct", "enc", "sig"]);
        // The signing input is enc([label, jcs(body)]).
        assert_eq!(
            object.signing_input().as_bytes(),
            enc(&[b"atem-envelope-v1", jcs(object.body()).unwrap().as_bytes()])
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        crate::encoding::hex(bytes)
    }

    #[test]
    fn the_info_is_the_designs_layout() {
        let r = Rig::new();
        let f = r.fields();
        let kid = enc_kid(&r.enc_pub).unwrap();
        for (kind, label) in [
            (MailKind::Envelope, "atem-envelope-seal-v1"),
            (MailKind::Result, "atem-result-seal-v1"),
        ] {
            assert_eq!(
                seal_info(kind, &f),
                enc(&[
                    label.as_bytes(),
                    b"acct-test-1",
                    &[0x11; 32],
                    b"host-a",
                    &u64_field(2),
                    b"host-b",
                    &u64_field(3),
                    kid.as_bytes(),
                    ID.as_bytes(),
                    &u64_field(CREATED_AT),
                    &u64_field(EXPIRES_AT),
                ])
            );
        }
    }

    #[test]
    fn info_binds_every_field() {
        let r = Rig::new();
        let f = r.fields();
        let object = envelope(&r, &f, &request(&f));
        let sealed = object.sealed().unwrap();
        let other_hash = Hash32([0x12; 32]);
        #[allow(clippy::type_complexity)]
        let changes: Vec<(&str, Box<dyn Fn(&mut MailFields)>)> = vec![
            (
                "account_id",
                Box::new(|f| f.account_id = "acct-test-2".into()),
            ),
            (
                "genesis_hash",
                Box::new(move |f| f.genesis_hash = other_hash),
            ),
            (
                "sender.host_id",
                Box::new(|f| f.sender.host_id = "host-x".into()),
            ),
            (
                "sender.host_trust_gen",
                Box::new(|f| f.sender.host_trust_gen = 3),
            ),
            (
                "recipient.host_id",
                Box::new(|f| f.recipient.host_id = "host-c".into()),
            ),
            (
                "recipient.host_trust_gen",
                Box::new(|f| f.recipient.host_trust_gen = 4),
            ),
            (
                "enc_kid",
                Box::new(|f| f.enc_kid = "0123456789abcdef".into()),
            ),
            ("id", Box::new(|f| f.id = ID2.into())),
            ("created_at", Box::new(|f| f.created_at += 1)),
            ("expires_at", Box::new(|f| f.expires_at += 1)),
        ];
        assert_eq!(changes.len(), 10, "the layout's ten fields");
        for (name, change) in changes {
            let mut changed = f.clone();
            change(&mut changed);
            assert_ne!(changed, f, "{name}");
            // The ciphertext doesn't open under the changed info.
            assert_eq!(
                r.receiver.hpke_open(
                    &r.enc_key,
                    &sealed.enc,
                    &sealed.ct,
                    &seal_info(MailKind::Envelope, &changed),
                    b""
                ),
                Err(Error::OpenFailed),
                "{name}"
            );
            // Nor does an object whose (re-signed) body says so.
            let forged = resigned(&r, MailKind::Envelope, &object, changed);
            forged.verify(&r.host_key_public()).unwrap();
            assert!(
                unseal_envelope(&r.receiver, &r.enc_key, &verified(&r, &forged)).is_err(),
                "{name}"
            );
        }

        // The one body field the info leaves out is under the signature
        // alone: changing it breaks that, not the seal.
        let mut moved = f.clone();
        moved.signed_at_head.seq += 1;
        let forged = resigned(&r, MailKind::Envelope, &object, moved.clone());
        assert!(unseal_envelope(&r.receiver, &r.enc_key, &verified(&r, &forged)).is_ok());
        let (_, body) = MailBody::from_object(&object).unwrap();
        let mut value = object.to_json();
        value["body"] = MailBody::from_fields(moved, body.sealed_hash).to_value(MailKind::Envelope);
        let edited = SignedObject::from_value(&value).unwrap();
        assert_eq!(
            edited.verify(&r.host_key_public()),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn sealed_hash_covers_enc_and_ct() {
        let r = Rig::new();
        let f = r.fields();
        let object = envelope(&r, &f, &request(&f));
        let sealed = object.sealed().unwrap().clone();
        let (_, body) = MailBody::from_object(&object).unwrap();
        // SHA-256(enc([enc, ct])).
        let expect: [u8; 32] = Sha256::digest(enc(&[&sealed.enc, &sealed.ct])).into();
        assert_eq!(body.sealed_hash, Hash32(expect));
        assert!(body.names(&sealed));

        // A flipped bit in either part: the signature (over the body) still
        // verifies, `sealed_hash` no longer names the parts and nothing opens.
        for which in ["enc", "ct"] {
            let mut part = sealed.clone();
            match which {
                "enc" => part.enc[0] ^= 1,
                _ => part.ct[0] ^= 1,
            }
            assert!(!body.names(&part), "{which}");
            let tampered = object.clone().with_sealed(part);
            tampered.verify(&r.host_key_public()).unwrap();
            // Not the sender's copy: it never becomes a `VerifiedMail`, so
            // nothing can open it.
            assert_eq!(
                VerifiedMail::verify(&tampered, &r.host_key_public()).map(|_| ()),
                Err(Error::OpenFailed),
                "{which}"
            );
        }
        // HPKE base mode is unauthenticated and `info` is public: anyone can
        // seal another plaintext to the recipient under the body's own
        // `info`. It opens, and only `sealed_hash` (under the signature)
        // says it isn't the sender's.
        let other = EnvelopePlain::Cancel {
            task_id: ID2.into(),
        };
        let forged = crate::hpke::seal(
            r.enc_pub.as_32().unwrap(),
            &seal_info(MailKind::Envelope, &f),
            b"",
            &other.to_bytes().unwrap(),
        )
        .unwrap();
        let swapped = object.clone().with_sealed(SealedPart {
            enc: forged.enc.to_vec(),
            ct: forged.ct.clone(),
        });
        swapped.verify(&r.host_key_public()).unwrap();
        assert!(
            r.receiver
                .hpke_open(
                    &r.enc_key,
                    &forged.enc,
                    &forged.ct,
                    &seal_info(MailKind::Envelope, &f),
                    b""
                )
                .is_ok(),
            "the forged part does open"
        );
        assert_eq!(
            VerifiedMail::verify(&swapped, &r.host_key_public()).map(|_| ()),
            Err(Error::OpenFailed)
        );
        // Moving a byte from one part to the other changes the hash too:
        // each part is length-prefixed.
        let mut shifted = sealed.clone();
        shifted.enc.push(shifted.ct.remove(0));
        assert!(!body.names(&shifted));
        // A missing sealed part is no mail object at all.
        let mut bare = object.to_json();
        bare.as_object_mut().unwrap().remove("enc");
        bare.as_object_mut().unwrap().remove("ct");
        assert!(matches!(
            parse_object(bare.to_string().as_bytes()),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn result_and_envelope_labels_not_interchangeable() {
        let r = Rig::new();
        let f = r.fields();
        // Distinct signing labels and seal domains.
        assert_ne!(SignLabel::Envelope.as_str(), SignLabel::Result.as_str());
        assert_ne!(domain::ENVELOPE_SEAL, domain::RESULT_SEAL);
        assert_eq!(MailKind::Envelope.sign_label(), SignLabel::Envelope);
        assert_eq!(MailKind::Result.sign_label(), SignLabel::Result);
        assert_eq!(MailKind::Envelope.seal_domain(), domain::ENVELOPE_SEAL);
        assert_eq!(MailKind::Result.seal_domain(), domain::RESULT_SEAL);
        let info = |kind| seal_info(kind, &f);
        assert_ne!(info(MailKind::Envelope), info(MailKind::Result));
        assert_eq!(
            dec(&info(MailKind::Result)).unwrap()[0],
            b"atem-result-seal-v1"
        );

        // The same fields sealed both ways: neither opens under the other's
        // info.
        let status = ResultPlain::Refusal {
            object_id: ID2.into(),
            refused: "invalid_request".into(),
        };
        let result = seal_result(&r.sender, &r.host_key, &f, &status, &r.enc_pub).unwrap();
        let envelope = envelope(&r, &f, &request(&f));
        assert_eq!(result.label(), SignLabel::Result);
        let (envelope_sealed, result_sealed) =
            (envelope.sealed().unwrap(), result.sealed().unwrap());
        for (sealed, wrong) in [
            (envelope_sealed, MailKind::Result),
            (result_sealed, MailKind::Envelope),
        ] {
            assert_eq!(
                r.receiver
                    .hpke_open(&r.enc_key, &sealed.enc, &sealed.ct, &info(wrong), b""),
                Err(Error::OpenFailed)
            );
        }

        // One object's body re-typed as the other's: the signature was made
        // under the other label.
        for (object, retyped) in [(&envelope, "atem-result"), (&result, "atem-envelope")] {
            let mut value = object.to_json();
            value["body"]["type"] = json!(retyped);
            let swapped = SignedObject::from_value(&value).unwrap();
            assert_eq!(
                swapped.verify(&r.host_key_public()),
                Err(Error::BadSignature),
                "{retyped}"
            );
            object.verify(&r.host_key_public()).unwrap();
        }

        // And each opener refuses the other's object before it opens it.
        assert!(unseal_result(&r.receiver, &r.enc_key, &verified(&r, &envelope)).is_err());
        assert!(unseal_envelope(&r.receiver, &r.enc_key, &verified(&r, &result)).is_err());
        assert_eq!(
            unseal_result(&r.receiver, &r.enc_key, &verified(&r, &result)).unwrap(),
            status
        );
    }

    #[test]
    fn result_round_trip() {
        let r = Rig::new();
        let f = r.fields();
        let plains = [
            ResultPlain::Status {
                message_id: ID.into(),
                recipients: vec![crate::session::messages::RecipientReceipt {
                    recipient_id: ID2.into(),
                    delivery: crate::session::messages::Delivery::Stored,
                }],
            },
            ResultPlain::Refusal {
                object_id: ID.into(),
                refused: "invalid_request".into(),
            },
            ResultPlain::Result {
                task_id: ID2.into(),
                reply: reply(1),
            },
        ];
        for plain in plains {
            let object = seal_result(&r.sender, &r.host_key, &f, &plain, &r.enc_pub).unwrap();
            let parsed = parse_object(&wire(&object)).unwrap();
            parsed.verify(&r.host_key_public()).unwrap();
            assert_eq!(MailBody::from_object(&parsed).unwrap().0, MailKind::Result);
            assert_eq!(
                unseal_result(&r.receiver, &r.enc_key, &verified(&r, &parsed)).unwrap(),
                plain
            );
        }
    }

    /// `object` as wire bytes padded with trailing white space (which a
    /// strict parse allows) to exactly `len` bytes.
    fn padded(object: &SignedObject, len: usize) -> Vec<u8> {
        let mut bytes = wire(object);
        assert!(bytes.len() <= len);
        bytes.resize(len, b' ');
        bytes
    }

    #[test]
    fn message_bound_240_kib_and_object_bound_512_kib() {
        let r = Rig::new();
        let f = r.fields();
        assert_eq!(MAX_MESSAGE_BYTES, 240 * 1024);
        assert_eq!(MAX_MAIL_OBJECT_BYTES, 512 * 1024);

        // A Message of exactly 240 KiB is valid, seals, and the object
        // (about 330 KB after base64url) fits the 512 KiB bound.
        let at = message_of_size(&f, MAX_MESSAGE_BYTES);
        assert!(at.valid_from_host("host-a"));
        let plain = EnvelopePlain::Request { message: at };
        let object = envelope(&r, &f, &plain);
        let bytes = wire(&object);
        assert!(bytes.len() > 320_000 && bytes.len() < MAX_MAIL_OBJECT_BYTES);
        let parsed = parse_object(&bytes).unwrap();
        assert_eq!(
            unseal_envelope(&r.receiver, &r.enc_key, &verified(&r, &parsed)).unwrap(),
            plain
        );

        // One byte more is refused: by the seal, and by the plaintext's
        // strict parse (a sender that skipped the seal's check).
        let over = message_of_size(&f, MAX_MESSAGE_BYTES + 1);
        assert!(!over.valid_from_host("host-a"));
        let over = EnvelopePlain::Request { message: over };
        assert_eq!(
            seal_envelope(&r.sender, &r.host_key, &f, &over, &r.enc_pub),
            Err(Error::TooLarge)
        );
        let Value::Object(mut raw) = serde_json::to_value(match &over {
            EnvelopePlain::Request { message } => message,
            _ => unreachable!(),
        })
        .map(|m| json!({"kind": "request", "message": m}))
        .unwrap() else {
            unreachable!()
        };
        let raw = jcs(&Value::Object(std::mem::take(&mut raw))).unwrap();
        assert_eq!(EnvelopePlain::parse(raw.as_bytes()), Err(Error::TooLarge));

        // The object bound is on the wire bytes, whatever they hold.
        assert!(parse_object(&padded(&object, MAX_MAIL_OBJECT_BYTES)).is_ok());
        assert!(matches!(
            parse_object(&padded(&object, MAX_MAIL_OBJECT_BYTES + 1)),
            Err(Error::Strict(crate::canonical::StrictError::TooLarge))
        ));

        // A result's plaintext has the same bound, so every sealed object
        // fits a 512 KiB mailbox call: exactly at it seals, one byte over
        // doesn't (a reply carries up to eight 128 KiB snapshots, so the
        // bound bites well before the object's).
        assert_eq!(MAX_PLAINTEXT_BYTES, MAX_MESSAGE_BYTES);
        let at = result_of_size(MAX_PLAINTEXT_BYTES);
        let object = seal_result(&r.sender, &r.host_key, &f, &at, &r.enc_pub).unwrap();
        assert!(wire(&object).len() > 320_000 && wire(&object).len() < MAX_MAIL_OBJECT_BYTES);
        assert_eq!(
            unseal_result(&r.receiver, &r.enc_key, &verified(&r, &object)).unwrap(),
            at
        );
        let over = result_of_size(MAX_PLAINTEXT_BYTES + 1);
        assert_eq!(
            seal_result(&r.sender, &r.host_key, &f, &over, &r.enc_pub),
            Err(Error::TooLarge)
        );
        assert_eq!(over.to_bytes(), Err(Error::TooLarge));
        // The plaintext's strict parse refuses it too (a sender that
        // skipped the seal's check).
        let ResultPlain::Result {
            task_id,
            reply: over_reply,
        } = &over
        else {
            unreachable!()
        };
        let raw = jcs(&json!({"kind": "result", "task_id": task_id,
                              "reply": serde_json::to_value(over_reply).unwrap()}))
        .unwrap();
        assert_eq!(raw.len(), MAX_PLAINTEXT_BYTES + 1);
        assert_eq!(ResultPlain::parse(raw.as_bytes()), Err(Error::TooLarge));
        // And three snapshots of the largest size, a valid reply, are over.
        let three = ResultPlain::Result {
            task_id: ID2.into(),
            reply: reply(3),
        };
        assert_eq!(
            seal_result(&r.sender, &r.host_key, &f, &three, &r.enc_pub),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn the_seal_refuses_what_could_not_be_opened_or_verified() {
        let r = Rig::new();
        let f = r.fields();
        let plain = request(&f);

        // `enc_kid` must name the key it is sealed to.
        let mut wrong = f.clone();
        wrong.enc_kid = "0123456789abcdef".into();
        assert!(matches!(
            seal_envelope(&r.sender, &r.host_key, &wrong, &plain, &r.enc_pub),
            Err(Error::Malformed(_))
        ));
        // The recipient's key is X25519.
        let mut keys = SoftwareKeys::new();
        let ed = keys.generate(KeyId::new("ed"), Alg::Ed25519).unwrap();
        assert_eq!(
            seal_envelope(&r.sender, &r.host_key, &f, &plain, &ed),
            Err(Error::WrongAlg)
        );
        // The signer is an Ed25519 `host_key`.
        keys.generate(KeyId::new("p256"), Alg::P256).unwrap();
        assert_eq!(
            seal_envelope(&keys, &KeyId::new("p256"), &f, &plain, &r.enc_pub),
            Err(Error::WrongAlg)
        );
        // Fields that no verifier would parse.
        for change in [
            (|f: &mut MailFields| f.id = "not-a-uuid".into()) as fn(&mut MailFields),
            |f| f.sender.host_trust_gen = 0,
            |f| f.sender.host_id = "has space".into(),
            |f| f.account_id = String::new(),
            |f| f.signed_at_head.seq = 0,
        ] {
            let mut bad = f.clone();
            change(&mut bad);
            assert!(matches!(
                seal_envelope(&r.sender, &r.host_key, &bad, &plain, &r.enc_pub),
                Err(Error::Malformed(_))
            ));
        }
        // A key this provider doesn't hold.
        assert_eq!(
            seal_envelope(&r.sender, &KeyId::new("nope"), &f, &plain, &r.enc_pub),
            Err(Error::UnknownKey)
        );
    }

    #[test]
    fn open_checks_whose_key_and_which_object() {
        let r = Rig::new();
        let f = r.fields();
        let object = envelope(&r, &f, &request(&f));
        // Another X25519 key behind the same id: its `enc_kid` isn't the
        // object's, refused before anything is opened.
        let mut other = SoftwareKeys::new();
        other.generate(r.enc_key.clone(), Alg::X25519).unwrap();
        assert!(matches!(
            unseal_envelope(&other, &r.enc_key, &verified(&r, &object)),
            Err(Error::Malformed(_))
        ));
        // A signing key isn't an encryption key.
        assert_eq!(
            unseal_envelope(&r.sender, &r.host_key, &verified(&r, &object)),
            Err(Error::WrongAlg)
        );
        // A status that parses as a body but whose reply is not a Result's.
        let status = ResultPlain::Refusal {
            object_id: ID.into(),
            refused: "invalid_request".into(),
        };
        let sealed = seal_result(&r.sender, &r.host_key, &f, &status, &r.enc_pub).unwrap();
        assert!(unseal_envelope(&r.receiver, &r.enc_key, &verified(&r, &sealed)).is_err());
    }

    #[test]
    fn a_status_with_no_result_seals_without_null() {
        use crate::session::host_work::WorkState;
        use crate::session::messages::{Delivery, RecipientReceipt, WorkProgress};
        let r = Rig::new();
        let f = r.fields();
        let plain = ResultPlain::Status {
            message_id: ID.into(),
            recipients: vec![RecipientReceipt {
                recipient_id: ID2.into(),
                delivery: Delivery::Work {
                    work: WorkProgress {
                        task_id: ID2.into(),
                        receipt_id: ID.into(),
                        state: WorkState::Queued,
                        detail: "waiting for a ready agent".into(),
                        result: None,
                    },
                },
            }],
        };
        // The wire type says `"result":null` (host-work-v1 section 5); the
        // sealed plaintext leaves the member out.
        assert!(
            serde_json::to_string(match &plain {
                ResultPlain::Status { recipients, .. } => recipients,
                _ => unreachable!(),
            })
            .unwrap()
            .contains("\"result\":null")
        );
        let bytes = plain.to_bytes().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("null"));
        let object = seal_result(&r.sender, &r.host_key, &f, &plain, &r.enc_pub).unwrap();
        let parsed = parse_object(&wire(&object)).unwrap();
        assert_eq!(
            unseal_result(&r.receiver, &r.enc_key, &verified(&r, &parsed)).unwrap(),
            plain
        );
        // The same for a reply with every member present.
        let result = ResultPlain::Result {
            task_id: ID2.into(),
            reply: reply(1),
        };
        assert!(!String::from_utf8_lossy(&result.to_bytes().unwrap()).contains("null"));
    }

    /// Deterministic seals for the known-answer vectors (`test-vectors`).
    #[cfg(feature = "test-vectors")]
    #[test]
    fn the_same_ikm_gives_byte_identical_objects() {
        let r = Rig::new();
        let f = r.fields();
        let ikm = [5u8; 32];
        let plain = request(&f);
        let a =
            seal_envelope_with_ikm(&r.sender, &r.host_key, &f, &plain, &r.enc_pub, &ikm).unwrap();
        let b =
            seal_envelope_with_ikm(&r.sender, &r.host_key, &f, &plain, &r.enc_pub, &ikm).unwrap();
        assert_eq!(a, b);
        assert_eq!(wire(&a), wire(&b));
        // Another ikm is another ephemeral: another `enc`, `ct`, hash and
        // signature; a fresh random seal differs from both.
        let c = seal_envelope_with_ikm(&r.sender, &r.host_key, &f, &plain, &r.enc_pub, &[6u8; 32])
            .unwrap();
        assert_ne!(a.sealed().unwrap().enc, c.sealed().unwrap().enc);
        assert_ne!(a.sig(), c.sig());
        assert_ne!(a, envelope(&r, &f, &plain));
        // They are ordinary objects: signed, and they open to the plaintext.
        a.verify(&r.host_key_public()).unwrap();
        assert_eq!(
            unseal_envelope(&r.receiver, &r.enc_key, &verified(&r, &a)).unwrap(),
            plain
        );

        let status = ResultPlain::Refusal {
            object_id: ID2.into(),
            refused: "invalid_request".into(),
        };
        let x =
            seal_result_with_ikm(&r.sender, &r.host_key, &f, &status, &r.enc_pub, &ikm).unwrap();
        let y =
            seal_result_with_ikm(&r.sender, &r.host_key, &f, &status, &r.enc_pub, &ikm).unwrap();
        assert_eq!(x, y);
        assert_eq!(
            unseal_result(&r.receiver, &r.enc_key, &verified(&r, &x)).unwrap(),
            status
        );
        // The same ikm, recipient and plaintext bytes under the two kinds'
        // `info`: one ephemeral (the ikm's), two ciphertexts, so the seal
        // domain separates them.
        let recipient = r.enc_pub.as_32().unwrap();
        let bytes = b"the same plaintext bytes";
        let under =
            |kind| hpke::seal_with_ikm(recipient, &seal_info(kind, &f), b"", bytes, &ikm).unwrap();
        let (envelope, result) = (under(MailKind::Envelope), under(MailKind::Result));
        assert_eq!(envelope.enc, result.enc);
        assert_ne!(envelope.ct, result.ct);
        assert_eq!(envelope, under(MailKind::Envelope));
    }
}

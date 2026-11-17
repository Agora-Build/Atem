//! A sending host for the binary tests (the delegated host-work design
//! Part II; host-work-v1 §11.5): a host of the test's device list that
//! seals envelopes and results to a receiving host with the shared core
//! (`atem_client::host_mail::{seal_envelope, seal_result}`) and puts them
//! into that host's mailbox through the fake Station
//! ([`FakeStation::put`]), as a sending host's runtime does over its own
//! link. It is no runtime: no outbox, no resends of its own (a test puts an
//! object again).
//!
//! What it makes: valid objects (a request, a cancel, a result), forged
//! ones (signed with a key that isn't its `host_key`), ones for another
//! recipient (addressed to another host, or naming the receiver but sealed
//! to another key), and, made for a later trust generation of the sender
//! (its re-verified `add_host`), objects of a newer sender generation.

use super::r9log::{TestLog, secret};
use super::station::FakeStation;
use atem_client::encoding::{Hash32, b64u_decode};
use atem_client::host_mail::mailbox::{MailboxPut, MailboxToHost, PutRefusal};
use atem_client::host_mail::{
    EnvelopePlain, HostRef, MailFields, ResultPlain, seal_envelope, seal_result,
};
use atem_client::host_principal::host_principal;
use atem_client::membership::Head;
use atem_client::session::host_work::HostTarget;
use atem_client::session::messages::{Destination, Message, MessageKind, Recipient};
use atem_client::{Alg, KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use std::path::Path;

/// How long an object lives (its `expires_at` after now).
const LIFE_MS: u64 = 60 * 60 * 1000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A receiving host as a sender seals to it: its id, its trust generation
/// and its encryption key (X25519).
#[derive(Debug, Clone)]
pub struct Receiver {
    pub host_id: String,
    pub host_trust_gen: u64,
    pub enc_pub: PublicKey,
}

impl Receiver {
    /// The receiving host `host_id` whose runtime made its encryption key
    /// in the profile `config` (`pairing/host_enc_key`, with `host.senders`
    /// on): its generation and public half, as a sender learns them from
    /// the device list. `None` until the file is there and reads.
    pub fn of(config: &Path, host_id: &str) -> Option<Receiver> {
        let text = std::fs::read(config.join("pairing/host_enc_key")).ok()?;
        let file: serde_json::Value = serde_json::from_slice(&text).ok()?;
        let public = b64u_decode(file["pub"].as_str()?).ok()?;
        Some(Receiver {
            host_id: host_id.to_owned(),
            host_trust_gen: file["host_trust_gen"].as_u64()?,
            enc_pub: PublicKey::new(Alg::X25519, &public).ok()?,
        })
    }

    /// Another host (`host_id` in `host_trust_gen`) with a key of its own
    /// (from `label`).
    pub fn other(host_id: &str, host_trust_gen: u64, label: &str) -> Receiver {
        let mut keys = SoftwareKeys::new();
        let key = KeyId::new("enc");
        keys.insert_x25519(key.clone(), &secret(label));
        Receiver {
            host_id: host_id.to_owned(),
            host_trust_gen,
            enc_pub: keys.public_key(&key).unwrap(),
        }
    }
}

/// A sending host: its id and trust generation in the device list, and its
/// `host_key` (the Ed25519 key of its `add_host` there).
pub struct SenderHost {
    pub host_id: String,
    pub host_trust_gen: u64,
    account: String,
    genesis: Hash32,
    keys: SoftwareKeys,
}

impl SenderHost {
    /// `host_id` in `host_trust_gen` of `log`'s account, its `host_key`
    /// from `seed` (what `log.add_host(host_id, host_trust_gen, seed)`
    /// names).
    pub fn new(log: &TestLog, host_id: &str, host_trust_gen: u64, seed: &[u8; 32]) -> SenderHost {
        let mut keys = SoftwareKeys::new();
        keys.insert_ed25519(Self::key(), seed);
        SenderHost {
            host_id: host_id.to_owned(),
            host_trust_gen,
            account: log.account.clone(),
            genesis: log.genesis_hash(),
            keys,
        }
    }

    fn key() -> KeyId {
        KeyId::new("host_key")
    }

    /// An object's body fields to `to`, signed at `signed_at` (a head that
    /// holds this host's `add_host`): a fresh id, made a second ago, alive
    /// for an hour.
    pub fn fields(&self, to: &Receiver, signed_at: Head) -> MailFields {
        let now = now_ms();
        MailFields {
            account_id: self.account.clone(),
            genesis_hash: self.genesis,
            sender: HostRef {
                host_id: self.host_id.clone(),
                host_trust_gen: self.host_trust_gen,
            },
            recipient: HostRef {
                host_id: to.host_id.clone(),
                host_trust_gen: to.host_trust_gen,
            },
            enc_kid: atem_client::keys::enc_kid(&to.enc_pub).unwrap(),
            id: uuid(),
            created_at: now - 1_000,
            expires_at: now + LIFE_MS,
            signed_at_head: signed_at,
        }
    }

    /// A request to `to`: a Message of this host's to a host notice there,
    /// `text`.
    pub fn request(&self, to: &Receiver, signed_at: Head, text: &str) -> SignedObject {
        let fields = self.fields(to, signed_at);
        let message = Message {
            message_id: fields.id.clone(),
            workflow_id: uuid(),
            sender: host_principal(&self.host_id),
            kind: MessageKind::Request,
            reply_to: None,
            from_session: None,
            created_at: fields.created_at,
            expires_at: fields.expires_at,
            recipients: vec![Recipient {
                recipient_id: uuid(),
                host: HostTarget {
                    account_id: self.account.clone(),
                    atem_device_id: to.host_id.clone(),
                    host_trust_gen: to.host_trust_gen,
                },
                destination: Destination::Host,
            }],
            text: text.to_owned(),
            context: vec![],
            mark: None,
        };
        self.seal(&fields, &EnvelopePlain::Request { message }, to)
    }

    /// A cancel of a task of `to`'s.
    pub fn cancel(&self, to: &Receiver, signed_at: Head) -> SignedObject {
        let fields = self.fields(to, signed_at);
        self.seal(&fields, &EnvelopePlain::Cancel { task_id: uuid() }, to)
    }

    /// A result to `to` (a refusal of one of its objects).
    pub fn result(&self, to: &Receiver, signed_at: Head) -> SignedObject {
        let fields = self.fields(to, signed_at);
        let plain = ResultPlain::Refusal {
            object_id: uuid(),
            refused: "invalid_request".into(),
        };
        seal_result(&self.keys, &Self::key(), &fields, &plain, &to.enc_pub).unwrap()
    }

    /// A cancel to `to` signed with a key that isn't this host's
    /// `host_key`: forged.
    pub fn forged(&self, to: &Receiver, signed_at: Head) -> SignedObject {
        let mut other = SoftwareKeys::new();
        other.insert_ed25519(Self::key(), &secret("a forger's key"));
        let fields = self.fields(to, signed_at);
        let plain = EnvelopePlain::Cancel { task_id: uuid() };
        seal_envelope(&other, &Self::key(), &fields, &plain, &to.enc_pub).unwrap()
    }

    /// A cancel naming `to` but sealed to `other`'s key (its `enc_kid`
    /// `other`'s): for another recipient.
    pub fn sealed_to(&self, to: &Receiver, other: &Receiver, signed_at: Head) -> SignedObject {
        let mut fields = self.fields(to, signed_at);
        fields.enc_kid = atem_client::keys::enc_kid(&other.enc_pub).unwrap();
        let plain = EnvelopePlain::Cancel { task_id: uuid() };
        seal_envelope(&self.keys, &Self::key(), &fields, &plain, &other.enc_pub).unwrap()
    }

    fn seal(&self, fields: &MailFields, plain: &EnvelopePlain, to: &Receiver) -> SignedObject {
        seal_envelope(&self.keys, &Self::key(), fields, plain, &to.enc_pub).unwrap()
    }

    /// `object` put through `station` as this host's call (a fresh
    /// `request_id`, the shared builder's message): the Station's answer,
    /// checked to answer the put (none: dropped, or lost).
    pub fn put(&self, station: &mut FakeStation, object: &SignedObject) -> Option<MailboxToHost> {
        let put = MailboxPut::new(uuid(), object.clone());
        let bytes = put.to_json().expect("a put the shared builder makes");
        let answer = station.put(
            &self.host_id,
            self.host_trust_gen,
            bytes.to_string().as_bytes(),
        )?;
        let answer = MailboxToHost::decode(answer.as_bytes()).expect("the Station's answer reads");
        match &answer {
            MailboxToHost::Stored(stored) => assert_eq!(stored.answers(&put), Ok(())),
            MailboxToHost::PutRefused(refused) => assert_eq!(refused.answers(&put), Ok(())),
            other => panic!("not an answer to a put: {other:?}"),
        }
        Some(answer)
    }

    /// [`SenderHost::put`], stored (`mailbox_stored`).
    #[track_caller]
    pub fn put_stored(&self, station: &mut FakeStation, object: &SignedObject) {
        let answer = self.put(station, object);
        assert!(
            matches!(answer, Some(MailboxToHost::Stored(_))),
            "{answer:?}"
        );
    }

    /// [`SenderHost::put`], refused: its code.
    #[track_caller]
    pub fn put_refused(&self, station: &mut FakeStation, object: &SignedObject) -> PutRefusal {
        match self.put(station, object) {
            Some(MailboxToHost::PutRefused(refused)) => refused.code,
            other => panic!("not refused: {other:?}"),
        }
    }
}

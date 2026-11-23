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
//! With an encryption key of its own ([`SenderHost::with_enc`], its
//! `host_enc_key` entry signed into the test's list), it opens the status
//! objects a receiving host sends back ([`SenderHost::open`]) and checks
//! them as a sending host does ([`SenderHost::accept`]); playing the host
//! that ran the work for a runtime that sent it some, it opens that
//! runtime's envelopes ([`SenderHost::open_envelope`]) and sends statuses
//! and results back ([`SenderHost::result_of`]).

use super::r9log::{TestLog, secret};
use super::station::FakeStation;
use atem_client::encoding::{Hash32, b64u_decode};
use atem_client::host_mail::mailbox::{MailboxPut, MailboxToHost, PutRefusal};
use atem_client::host_mail::{
    EnvelopePlain, ExpectedResult, HostRef, MailFields, ResultPlain, ResultVerdict, VerifiedMail,
    accept_result, seal_envelope, seal_result, unseal_envelope, unseal_result,
};
use atem_client::host_principal::host_principal;
use atem_client::membership::Head;
use atem_client::membership::Membership;
use atem_client::membership::entry::Action;
use atem_client::session::host_work::{ContextSnapshot, HostTarget};
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
        // Its current key: a v2 file's `current`, a v1 file's only key.
        let current = if file["v"] == 1 {
            &file
        } else {
            &file["current"]
        };
        let public = b64u_decode(current["pub"].as_str()?).ok()?;
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

    fn enc() -> KeyId {
        KeyId::new("enc_key")
    }

    /// With an encryption key (X25519, from `seed`): what its `host_enc_key`
    /// entry names ([`SenderHost::enc_key_action`]) and statuses are sealed
    /// to.
    pub fn with_enc(mut self, seed: &[u8; 32]) -> SenderHost {
        self.keys.insert_x25519(Self::enc(), seed);
        self
    }

    /// Its encryption key's secret (from [`SenderHost::with_enc`]'s seed)
    /// written as the receiving host's runtime makes it, in the profile
    /// `config` (`pairing/host_enc_key` as its current key, and the record
    /// `pairing/host_enc_generated`), before the runtime starts: a host
    /// whose list sets that key with [`SenderHost::enc_key_action`] (only a
    /// key the committed list set opens mail).
    pub fn write_enc_key(config: &Path, host_trust_gen: u64, seed: &[u8; 32]) {
        use atem_client::encoding::b64u;
        let mut keys = SoftwareKeys::new();
        keys.insert_x25519(Self::enc(), seed);
        let public = keys.public_key(&Self::enc()).unwrap();
        let kid = atem_client::keys::enc_kid(&public).unwrap();
        let pairing = config.join("pairing");
        let write = |name: &str, text: String| {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::create_dir_all(&pairing).unwrap();
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(pairing.join(name))
                .unwrap();
            f.write_all(text.as_bytes()).unwrap();
        };
        write(
            "host_enc_key",
            serde_json::json!({"v": 2, "host_trust_gen": host_trust_gen,
                "current": {"secret": b64u(seed), "pub": b64u(public.as_32().unwrap())}})
            .to_string(),
        );
        write(
            "host_enc_generated",
            serde_json::json!({"v": 2, "host_trust_gen": host_trust_gen, "kids": [kid],
                "retired": []})
            .to_string(),
        );
    }

    /// Its `host_enc_key` entry's action (its `enc_sig` by its `host_key`),
    /// for a native manager to sign into the list.
    pub fn enc_key_action(&self) -> Action {
        let enc_key = self.keys.public_key(&Self::enc()).unwrap();
        let sig = atem_client::membership::sign_host_enc_key(
            &self.keys,
            &Self::key(),
            &self.account,
            &self.genesis,
            &self.host_id,
            self.host_trust_gen,
            enc_key.as_32().unwrap(),
        )
        .unwrap();
        atem_client::membership::host_enc_key(
            &self.host_id,
            self.host_trust_gen,
            &enc_key,
            &sig,
            false,
            0,
        )
        .unwrap()
    }

    /// A Message of this host's to `to`, one `select` recipient
    /// (`selectors`, `budget`), `text`: fresh ids, made a second ago,
    /// alive an hour.
    pub fn message(&self, to: &Receiver, selectors: &[&str], budget: u32, text: &str) -> Message {
        let now = now_ms();
        Message {
            message_id: uuid(),
            workflow_id: uuid(),
            sender: host_principal(&self.host_id),
            kind: MessageKind::Request,
            reply_to: None,
            from_session: None,
            created_at: now - 1_000,
            expires_at: now + LIFE_MS,
            recipients: vec![Recipient {
                recipient_id: uuid(),
                host: HostTarget {
                    account_id: self.account.clone(),
                    atem_device_id: to.host_id.clone(),
                    host_trust_gen: to.host_trust_gen,
                },
                destination: Destination::Select {
                    selectors: selectors.iter().map(|s| s.to_string()).collect(),
                    budget,
                    launch: false,
                },
            }],
            text: text.to_owned(),
            context: vec![],
            mark: None,
        }
    }

    /// `message` (this host's) as a request to `to`, signed at `signed_at`:
    /// the body's id and times are the Message's.
    pub fn request_of(&self, to: &Receiver, signed_at: Head, message: &Message) -> SignedObject {
        let mut fields = self.fields(to, signed_at);
        fields.id = message.message_id.clone();
        fields.created_at = message.created_at;
        fields.expires_at = message.expires_at;
        let plain = EnvelopePlain::Request {
            message: message.clone(),
        };
        self.seal(&fields, &plain, to)
    }

    /// A `cancel` of task `task_id`, or with `result` its `complete`, to
    /// `to`.
    pub fn stop(
        &self,
        to: &Receiver,
        signed_at: Head,
        task_id: &str,
        result: Option<ContextSnapshot>,
    ) -> SignedObject {
        let fields = self.fields(to, signed_at);
        let plain = match result {
            Some(result) => EnvelopePlain::Complete {
                task_id: task_id.to_owned(),
                result,
            },
            None => EnvelopePlain::Cancel {
                task_id: task_id.to_owned(),
            },
        };
        self.seal(&fields, &plain, to)
    }

    /// A result object a receiving host sent back to this host, verified
    /// with `from` (that host's `host_key`) and opened with this host's
    /// encryption key ([`SenderHost::with_enc`]).
    pub fn open(&self, object: &SignedObject, from: &PublicKey) -> ResultPlain {
        let verified = VerifiedMail::verify(object, from).expect("signed by the receiving host");
        unseal_result(&self.keys, &Self::enc(), &verified).expect("sealed to this host")
    }

    /// An envelope a sending host put into this host's mailbox, verified
    /// with `from` (that host's `host_key`) and opened with this host's
    /// encryption key.
    pub fn open_envelope(&self, object: &SignedObject, from: &PublicKey) -> EnvelopePlain {
        let verified = VerifiedMail::verify(object, from).expect("signed by the sending host");
        unseal_envelope(&self.keys, &Self::enc(), &verified).expect("sealed to this host")
    }

    /// `plain` (a status, or a task's reply) back to `to`, the host whose
    /// work this host ran, signed at `signed_at`.
    pub fn result_of(&self, to: &Receiver, signed_at: Head, plain: &ResultPlain) -> SignedObject {
        let fields = self.fields(to, signed_at);
        seal_result(&self.keys, &Self::key(), &fields, plain, &to.enc_pub).unwrap()
    }

    /// The shared core's check of `object`, a result from the host this
    /// host's outbox row `expected` went to, on `list` (the sending host's
    /// `accept_result`, II.4.4).
    pub fn accept(
        &self,
        object: &SignedObject,
        list: &Membership,
        expected: &ExpectedResult,
    ) -> ResultVerdict {
        let enc_pub = self.keys.public_key(&Self::enc()).unwrap();
        let me = atem_client::host_mail::Recipient {
            host_id: self.host_id.clone(),
            host_trust_gen: self.host_trust_gen,
            keys: vec![(
                Self::enc(),
                atem_client::keys::enc_kid_bytes(&enc_pub).unwrap(),
            )],
            generated: vec![],
        };
        accept_result(object, list, &me, expected, &self.keys, now_ms())
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

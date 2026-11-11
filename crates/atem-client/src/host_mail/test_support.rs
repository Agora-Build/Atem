//! Fixtures the `host_mail` tests share (test builds only).
use crate::encoding::Hash32;
use crate::host_mail::{HostRef, MailFields};
use crate::host_principal::host_principal;
use crate::keys::{PublicKey, enc_kid};
use crate::membership::Head;
use crate::provider::{KeyId, KeyProvider};
use crate::session::host_work::{
    ContextKind, ContextSnapshot, HostTarget, ReplyState, ResultReply, digest,
};
use crate::session::messages::{Destination, Message, MessageKind, Recipient};
use crate::software::SoftwareKeys;

/// UUID v4s.
pub(crate) const ID: &str = "6f1c2a4e-3b7d-4e8a-9c01-2d5f7a9b3c4e";
pub(crate) const ID2: &str = "7a2d3b5f-4c8e-4f9b-8d12-3e6a8b0c4d5f";
/// A UUID v5 (the id of a task's reply).
pub(crate) const REPLY_ID: &str = "9b1deb4d-3b7d-5bad-9bdd-2b0d7b3dcb6d";

pub(crate) const CREATED_AT: u64 = 1_793_620_800_000;
pub(crate) const EXPIRES_AT: u64 = 1_793_707_200_000;

/// The sending host A with its `host_key`, and the receiving host B with
/// its `enc_key`, each behind its own provider (fixed keys, so two rigs
/// agree).
pub(crate) struct Rig {
    pub sender: SoftwareKeys,
    pub receiver: SoftwareKeys,
    pub host_key: KeyId,
    pub enc_key: KeyId,
    pub enc_pub: PublicKey,
}

impl Rig {
    pub fn new() -> Self {
        let mut sender = SoftwareKeys::new();
        let host_key = KeyId::new("host-key");
        sender.insert_ed25519(host_key.clone(), &[7u8; 32]);
        let mut receiver = SoftwareKeys::new();
        let enc_key = KeyId::new("enc-key");
        receiver.insert_x25519(enc_key.clone(), &[9u8; 32]);
        let enc_pub = receiver.public_key(&enc_key).unwrap();
        Rig {
            sender,
            receiver,
            host_key,
            enc_key,
            enc_pub,
        }
    }

    /// Host A (`host-a`, generation 2) to host B (`host-b`, generation 3).
    pub fn fields(&self) -> MailFields {
        MailFields {
            account_id: "acct-test-1".into(),
            genesis_hash: Hash32([0x11; 32]),
            sender: HostRef {
                host_id: "host-a".into(),
                host_trust_gen: 2,
            },
            recipient: HostRef {
                host_id: "host-b".into(),
                host_trust_gen: 3,
            },
            enc_kid: enc_kid(&self.enc_pub).unwrap(),
            id: ID.into(),
            created_at: CREATED_AT,
            expires_at: EXPIRES_AT,
            signed_at_head: Head {
                seq: 31,
                hash: Hash32([0x22; 32]),
            },
        }
    }

    pub fn host_key_public(&self) -> PublicKey {
        self.sender.public_key(&self.host_key).unwrap()
    }
}

/// A valid Message from host A to a host notice on host B.
pub(crate) fn message(fields: &MailFields) -> Message {
    Message {
        message_id: fields.id.clone(),
        workflow_id: ID2.into(),
        sender: host_principal(&fields.sender.host_id),
        kind: MessageKind::Request,
        reply_to: None,
        from_session: None,
        created_at: fields.created_at,
        expires_at: fields.expires_at,
        recipients: vec![Recipient {
            recipient_id: ID2.into(),
            host: HostTarget {
                account_id: fields.account_id.clone(),
                atem_device_id: fields.recipient.host_id.clone(),
                host_trust_gen: fields.recipient.host_trust_gen,
            },
            destination: Destination::Host,
        }],
        text: "Review the contract".into(),
        context: vec![],
        mark: None,
    }
}

/// A Memory snapshot whose text is `len` bytes.
pub(crate) fn snapshot(index: usize, len: usize) -> ContextSnapshot {
    let text = "a".repeat(len);
    ContextSnapshot {
        kind: ContextKind::Memory,
        id: format!("ctx-{index}"),
        version: 1,
        digest: digest(text.as_bytes()),
        text,
    }
}

/// A valid Message that serializes to exactly `target` bytes (three
/// snapshots, the last one sized to fit).
pub(crate) fn message_of_size(fields: &MailFields, target: usize) -> Message {
    let build = |last: usize| {
        let mut m = message(fields);
        m.context = vec![
            snapshot(0, 80 * 1024),
            snapshot(1, 80 * 1024),
            snapshot(2, last),
        ];
        m
    };
    let len = |m: &Message| serde_json::to_vec(m).unwrap().len();
    let probe = 80 * 1024;
    let last = probe + target - len(&build(probe));
    let m = build(last);
    assert_eq!(len(&m), target);
    m
}

/// A submitted reply carrying `contexts` snapshots of 128 KiB each.
pub(crate) fn reply(contexts: usize) -> ResultReply {
    let text = "Done: the contract reads well.".to_owned();
    ResultReply {
        result_id: REPLY_ID.into(),
        state: ReplyState::Submitted,
        digest: digest(text.as_bytes()),
        text,
        context: (0..contexts).map(|i| snapshot(i, 128 * 1024)).collect(),
        submitted_at: Some(CREATED_AT + 60_000),
        dropped: false,
    }
}

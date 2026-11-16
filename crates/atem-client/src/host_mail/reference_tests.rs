//! The reference mailbox, one rule at a time (host-work-v1 §11.5, "The
//! mailbox calls").
use serde_json::{Map, Value, json};

use super::*;
use crate::canonical::MAX_SAFE_INTEGER;
use crate::control::relay::Heads;
use crate::host_mail::mailbox::{MAX_MAILBOX_MESSAGE_BYTES, MailboxSyncResult, MailboxToHost};
use crate::host_mail::test_support::{CREATED_AT, EXPIRES_AT, Rig};
use crate::host_mail::{EnvelopePlain, MailFields, seal_envelope_with_ikm};
use crate::membership::Head;
use crate::session::wire::is_uuid_v4;

const ACCOUNT: &str = "acct-test-1";
/// `Rig::fields`'s genesis.
const GENESIS: Hash32 = Hash32([0x11; 32]);
const SEED: [u8; 32] = [0x5e; 32];
/// Within every test object's lifetime.
const NOW: u64 = CREATED_AT + 60_000;

/// A lowercase UUID v4 numbered `n`.
fn uuid(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// The link of `host_id` at `host_trust_gen`, of this device list.
fn link(host_id: &str, host_trust_gen: u64) -> LinkAssociation {
    LinkAssociation {
        account_id: ACCOUNT.into(),
        genesis_hash: GENESIS,
        host_id: host_id.into(),
        host_trust_gen,
        connection_id: "conn-1".into(),
    }
}

/// `Rig::fields`'s hosts: host-a at generation 2 sends to host-b at 3.
fn a() -> LinkAssociation {
    link("host-a", 2)
}

fn b() -> LinkAssociation {
    link("host-b", 3)
}

fn c() -> LinkAssociation {
    link("host-c", 1)
}

fn current() -> CurrentHosts {
    CurrentHosts::new([
        ("host-a".to_owned(), 2),
        ("host-b".to_owned(), 3),
        ("host-c".to_owned(), 1),
    ])
}

/// A cancel envelope from host A to host B with body id `uuid(id)`; `edit`
/// changes its fields before it is sealed; `task` makes other bytes under
/// the same key.
fn object_with(id: u64, task: u64, edit: impl FnOnce(&mut MailFields)) -> SignedObject {
    let rig = Rig::new();
    let mut fields = rig.fields();
    fields.id = uuid(id);
    edit(&mut fields);
    seal_envelope_with_ikm(
        &rig.sender,
        &rig.host_key,
        &fields,
        &EnvelopePlain::Cancel {
            task_id: uuid(1000 + task),
        },
        &rig.enc_pub,
        &[5u8; 32],
    )
    .unwrap()
}

fn object(id: u64) -> SignedObject {
    object_with(id, 0, |_| {})
}

/// The object's compact JSON length: what it is charged.
fn size(object: &SignedObject) -> u64 {
    object.to_json().to_string().len() as u64
}

/// The Station side of a test: the mailbox it adopts after every
/// transition, its clock and fresh call ids.
struct Station {
    m: ReferenceMailbox,
    now: u64,
    calls: u64,
}

impl Station {
    fn new() -> Self {
        Self::with(Quotas::default())
    }

    fn with(quotas: Quotas) -> Self {
        Station {
            m: ReferenceMailbox::new(ACCOUNT, GENESIS, quotas, SEED)
                .unwrap()
                .list_moved(current()),
            now: NOW,
            calls: 0,
        }
    }

    fn request_id(&mut self) -> String {
        self.calls += 1;
        format!("{:08x}-0000-4000-8000-000000000000", self.calls)
    }

    /// Sends `bytes` from `caller`; every answer reads back with the
    /// host's reader, and a transition leaves the mailbox it was called on
    /// as it was.
    fn send(&mut self, caller: &LinkAssociation, bytes: &[u8]) -> (Option<Value>, Outcome) {
        let before = self.m.clone();
        let t = self.m.call(caller, bytes, self.now).unwrap();
        assert_eq!(self.m, before, "a transition changes nothing in place");
        if let Some(answer) = &t.answer {
            MailboxToHost::decode(answer.to_string().as_bytes()).expect("the answer reads back");
        }
        self.m = t.next;
        (t.answer, t.outcome)
    }

    fn put_bytes(&mut self, object: &SignedObject) -> (String, Vec<u8>) {
        let request_id = self.request_id();
        let put = MailboxPut {
            request_id: request_id.clone(),
            object: object.clone(),
        };
        (request_id, put.to_json().unwrap().to_string().into_bytes())
    }

    /// A put of `object` by `caller`: what happened, and the answer checked
    /// against the builder's.
    fn put(&mut self, caller: &LinkAssociation, object: &SignedObject) -> Outcome {
        let (request_id, bytes) = self.put_bytes(object);
        let (answer, outcome) = self.send(caller, &bytes);
        let id = MailBody::from_object(object).unwrap().1.id;
        let want = match &outcome {
            Outcome::Stored { .. } | Outcome::AlreadyStored { .. } => {
                Some(MailboxStored { request_id, id }.to_json().unwrap())
            }
            Outcome::PutRefused(code) => Some(
                MailboxPutRefused {
                    request_id,
                    id,
                    code: *code,
                }
                .to_json()
                .unwrap(),
            ),
            Outcome::Dropped(_) => None,
            other => panic!("a put's outcome: {other:?}"),
        };
        assert_eq!(answer, want);
        outcome
    }

    fn sync(
        &mut self,
        caller: &LinkAssociation,
        mailbox_id: &str,
        after: u64,
    ) -> (Option<Value>, Outcome) {
        let call = MailboxSync {
            request_id: self.request_id(),
            mailbox_id: mailbox_id.into(),
            after,
        };
        let (answer, outcome) = self.send(caller, call.to_json().unwrap().to_string().as_bytes());
        if let Some(answer) = &answer
            && let Ok(page) = MailboxSyncResult::decode(answer.to_string().as_bytes())
        {
            assert_eq!(page.answers(&call), Ok(()));
        }
        (answer, outcome)
    }

    /// A page the caller's own mailbox gives: its `through` and the
    /// position of its object.
    fn page(
        &mut self,
        caller: &LinkAssociation,
        after: u64,
    ) -> (u64, Option<u64>, MailboxSyncResult) {
        let own = self
            .m
            .mailbox(&caller.host_id, caller.host_trust_gen)
            .unwrap();
        let (answer, outcome) = self.sync(caller, &own.mailbox_id, after);
        let page = MailboxSyncResult::decode(answer.unwrap().to_string().as_bytes()).unwrap();
        let Outcome::Page {
            through, position, ..
        } = outcome
        else {
            panic!("{outcome:?}");
        };
        assert_eq!(page.through, through);
        assert_eq!(page.objects.first().map(|e| e.position), position);
        (through, position, page)
    }

    fn done(
        &mut self,
        caller: &LinkAssociation,
        mailbox_id: &str,
        position: u64,
    ) -> (Option<Value>, Outcome) {
        let call = MailboxDone {
            request_id: self.request_id(),
            mailbox_id: mailbox_id.into(),
            position,
        };
        let (answer, outcome) = self.send(caller, call.to_json().unwrap().to_string().as_bytes());
        if let Outcome::Done { .. } = outcome {
            let want = MailboxDoneResult {
                request_id: call.request_id.clone(),
                mailbox_id: call.mailbox_id.clone(),
                position,
            };
            assert_eq!(answer, Some(want.to_json().unwrap()));
        }
        (answer, outcome)
    }

    /// The caller's mailbox head, as its `heads` announces it.
    fn heads(&mut self, caller: &LinkAssociation) -> MailboxHead {
        let t = self.m.heads(caller, &base_heads(), true, self.now).unwrap();
        self.m = t.next;
        let Outcome::Heads {
            mailbox: Some(head),
        } = t.outcome
        else {
            panic!("{:?}", t.outcome);
        };
        head
    }

    fn mailbox_of(&self, caller: &LinkAssociation) -> MailboxHead {
        self.m
            .mailbox(&caller.host_id, caller.host_trust_gen)
            .unwrap()
    }

    fn positions(&self, caller: &LinkAssociation) -> Vec<u64> {
        self.m
            .stored(&caller.host_id, caller.host_trust_gen)
            .iter()
            .map(|s| s.position)
            .collect()
    }
}

fn base_heads() -> Heads {
    Heads {
        feeds: vec![],
        membership: Head {
            seq: 10,
            hash: Hash32([0x22; 32]),
        },
    }
}

fn forbidden_sync() -> Value {
    MailboxCallRefused {
        call: MailboxRefusedCall::Sync,
        code: RefusalCode::Forbidden,
    }
    .to_json()
    .unwrap()
}

fn forbidden_done() -> Value {
    MailboxCallRefused {
        call: MailboxRefusedCall::Done,
        code: RefusalCode::Forbidden,
    }
    .to_json()
    .unwrap()
}

// ---------------------------------------------------------------- puts

#[test]
fn a_put_is_stored_at_the_next_position_of_its_recipients_mailbox() {
    let mut st = Station::new();
    assert_eq!(st.m.mailbox("host-b", 3), None);
    assert_eq!(st.put(&a(), &object(1)), Outcome::Stored { position: 1 });
    assert_eq!(st.put(&a(), &object(2)), Outcome::Stored { position: 2 });
    let mailbox = st.mailbox_of(&b());
    assert!(is_uuid_v4(&mailbox.mailbox_id));
    assert_eq!(mailbox.head, 2);
    let stored = st.m.stored("host-b", 3);
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].sender, "host-a");
    assert_eq!(stored[0].id, uuid(1));
    assert_eq!(stored[0].object_hash, object_hash(&object(1)));
    assert_eq!(stored[0].bytes, size(&object(1)));
    assert_eq!(stored[0].expires_at, EXPIRES_AT);
    // The sender's own mailbox isn't touched.
    assert_eq!(st.m.mailbox("host-a", 2), None);
}

#[test]
fn the_same_object_again_is_answered_stored_and_charged_once() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    let usage = st.m.sender_usage("host-a");
    assert_eq!(
        usage,
        Usage {
            objects: 1,
            bytes: size(&object(1))
        }
    );
    // A retry with a fresh request id.
    assert_eq!(
        st.put(&a(), &object(1)),
        Outcome::AlreadyStored { position: 1 }
    );
    // A copy serialized again (whitespace, another key order) is the same
    // object: identical bytes are compared in canonical form.
    let wire = object(1).to_json();
    let mut reordered = Map::new();
    for key in ["sig", "ct", "body", "enc"] {
        reordered.insert(key.to_owned(), wire[key].clone());
    }
    let request_id = st.request_id();
    let text = format!(
        "{{ \"object\" : {} , \"request_id\":\"{request_id}\",\"op\":\"mailbox_put\",\"type\":\"relay\"}}",
        serde_json::to_string_pretty(&Value::Object(reordered)).unwrap()
    );
    let (answer, outcome) = st.send(&a(), text.as_bytes());
    assert_eq!(outcome, Outcome::AlreadyStored { position: 1 });
    assert_eq!(
        answer,
        Some(
            MailboxStored {
                request_id,
                id: uuid(1)
            }
            .to_json()
            .unwrap()
        )
    );
    assert_eq!(st.m.sender_usage("host-a"), usage);
    assert_eq!(st.m.receiver_usage("host-b", 3), usage);
    assert_eq!(st.m.account_usage(), usage);
    assert_eq!(st.mailbox_of(&b()).head, 1);
}

#[test]
fn other_bytes_under_the_same_key_are_id_reused_and_the_first_stays() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    let other = object_with(1, 7, |_| {});
    assert_ne!(object_hash(&other), object_hash(&object(1)));
    assert_eq!(
        st.put(&a(), &other),
        Outcome::PutRefused(PutRefusal::IdReused)
    );
    let stored = st.m.stored("host-b", 3);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].object_hash, object_hash(&object(1)));
    // Re-signed at a newer head, the same sealed part: other bytes too.
    let resigned = object_with(1, 0, |f| f.signed_at_head.seq += 1);
    assert_eq!(
        st.put(&a(), &resigned),
        Outcome::PutRefused(PutRefusal::IdReused)
    );
    assert_eq!(st.m.sender_usage("host-a").objects, 1);
}

#[test]
fn the_key_is_the_calling_host_and_the_id_within_the_recipients_mailbox() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    // The same id from another sending host: another key.
    let from_c = object_with(1, 0, |f| {
        f.sender.host_id = "host-c".into();
        f.sender.host_trust_gen = 1;
    });
    assert_eq!(st.put(&c(), &from_c), Outcome::Stored { position: 2 });
    // The same id to another receiving host (one message's envelopes to
    // several hosts share it): another mailbox.
    let to_c = object_with(1, 0, |f| {
        f.recipient.host_id = "host-c".into();
        f.recipient.host_trust_gen = 1;
    });
    assert_eq!(st.put(&a(), &to_c), Outcome::Stored { position: 1 });
    assert_eq!(st.positions(&b()), [1, 2]);
    assert_eq!(st.positions(&c()), [1]);
}

#[test]
fn the_key_is_free_again_after_done_and_a_resend_is_charged_again() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    let mailbox = st.heads(&b());
    st.done(&b(), &mailbox.mailbox_id, 1);
    assert_eq!(st.m.sender_usage("host-a"), Usage::default());
    // The sender's identical resend is a new delivery: a new position,
    // charged again; the receiving host takes it as a duplicate.
    assert_eq!(st.put(&a(), &object(1)), Outcome::Stored { position: 2 });
    assert_eq!(st.m.sender_usage("host-a").objects, 1);
    // Other bytes under that key are stored too, once the first is gone.
    st.done(&b(), &mailbox.mailbox_id, 2);
    let other = object_with(1, 7, |_| {});
    assert_eq!(st.put(&a(), &other), Outcome::Stored { position: 3 });
}

#[test]
fn the_key_is_free_again_after_expiry() {
    let mut st = Station::new();
    let short = object_with(1, 0, |f| f.expires_at = NOW + 1_000);
    st.put(&a(), &short);
    st.now = NOW + 1_000;
    // Expired with its own `expires_at`: the same bytes are `expired` now;
    // other bytes with a later expiry are stored under the freed key.
    assert_eq!(
        st.put(&a(), &short),
        Outcome::PutRefused(PutRefusal::Expired)
    );
    assert_eq!(st.m.stored("host-b", 3), vec![]);
    assert_eq!(st.put(&a(), &object(1)), Outcome::Stored { position: 2 });
}

#[test]
fn only_a_current_host_puts_and_only_its_own_objects() {
    let mut st = Station::new();
    // The object's sender is host-a: host-c may not put it.
    assert_eq!(
        st.put(&c(), &object(1)),
        Outcome::PutRefused(PutRefusal::Forbidden)
    );
    // Another account's or another root's object, from the right host.
    let other_account = object_with(2, 0, |f| f.account_id = "acct-test-2".into());
    assert_eq!(
        st.put(&a(), &other_account),
        Outcome::PutRefused(PutRefusal::Forbidden)
    );
    let other_root = object_with(3, 0, |f| f.genesis_hash = Hash32([0x33; 32]));
    assert_eq!(
        st.put(&a(), &other_root),
        Outcome::PutRefused(PutRefusal::Forbidden)
    );
    // A caller that isn't a current host at its link's generation.
    assert_eq!(
        st.put(&link("host-a", 1), &object(4)),
        Outcome::PutRefused(PutRefusal::Forbidden)
    );
    st.m =
        st.m.list_moved(CurrentHosts::new([("host-b".to_owned(), 3)]));
    assert_eq!(
        st.put(&a(), &object(5)),
        Outcome::PutRefused(PutRefusal::Forbidden)
    );
    // The sender's generation in the body is the receiver's to judge.
    st.m = st.m.list_moved(current());
    let older = object_with(6, 0, |f| f.sender.host_trust_gen = 1);
    assert_eq!(st.put(&a(), &older), Outcome::Stored { position: 1 });
    assert_eq!(st.m.account_usage().objects, 1);
}

#[test]
fn a_recipient_that_isnt_a_current_host_at_that_generation_is_forbidden() {
    let mut st = Station::new();
    for edit in [
        |f: &mut MailFields| f.recipient.host_trust_gen = 2,
        |f: &mut MailFields| f.recipient.host_trust_gen = 4,
        |f: &mut MailFields| f.recipient.host_id = "host-z".into(),
    ] {
        assert_eq!(
            st.put(&a(), &object_with(1, 0, edit)),
            Outcome::PutRefused(PutRefusal::Forbidden)
        );
    }
    assert_eq!(st.m.mailbox("host-b", 2), None);
    assert_eq!(st.m.mailbox("host-z", 3), None);
    // Removed from the Station's copy of the list: forbidden from then on.
    st.put(&a(), &object(2));
    st.m =
        st.m.list_moved(CurrentHosts::new([("host-a".to_owned(), 2)]));
    assert_eq!(
        st.put(&a(), &object(3)),
        Outcome::PutRefused(PutRefusal::Forbidden)
    );
    // What it holds stays until done or expiry.
    assert_eq!(st.positions(&b()), [1]);
}

#[test]
fn invalid_times_are_expired() {
    let mut st = Station::new();
    let day = MAX_LIFETIME_MS;
    for (n, (created_at, expires_at)) in [
        // Passed: at or past `expires_at`.
        (NOW - 10_000, NOW),
        (NOW - 10_000, NOW - 1),
        // Not after `created_at`.
        (NOW + 5_000, NOW + 5_000),
        (NOW + 5_000, NOW + 4_999),
        // More than 24 h after it.
        (NOW - 1, NOW - 1 + day + 1),
    ]
    .into_iter()
    .enumerate()
    {
        let o = object_with(n as u64 + 1, 0, |f| {
            f.created_at = created_at;
            f.expires_at = expires_at;
        });
        assert_eq!(
            st.put(&a(), &o),
            Outcome::PutRefused(PutRefusal::Expired),
            "{created_at} {expires_at}"
        );
    }
    // Exactly 24 h, and a `created_at` ahead of the clock: stored (the
    // receiver judges how far ahead).
    let day_long = object_with(10, 0, |f| {
        f.created_at = NOW - 1;
        f.expires_at = NOW - 1 + day;
    });
    assert_eq!(st.put(&a(), &day_long), Outcome::Stored { position: 1 });
    let ahead = object_with(11, 0, |f| {
        f.created_at = NOW + 3_600_000;
        f.expires_at = NOW + 7_200_000;
    });
    assert_eq!(st.put(&a(), &ahead), Outcome::Stored { position: 2 });
}

#[test]
fn quotas_count_objects_and_encoded_bytes_per_sender_receiver_and_account() {
    let one = size(&object(1));
    let roomy = Quota {
        objects: 100,
        bytes: 100 * one,
    };
    // Per sending host, in objects.
    let mut st = Station::with(Quotas {
        sender: Quota {
            objects: 2,
            bytes: roomy.bytes,
        },
        receiver: roomy,
        account: roomy,
    });
    st.put(&a(), &object(1));
    st.put(&a(), &object(2));
    assert_eq!(
        st.put(&a(), &object(3)),
        Outcome::PutRefused(PutRefusal::Quota)
    );
    // Another sending host isn't held by host-a's quota.
    let from_c = object_with(3, 0, |f| {
        f.sender.host_id = "host-c".into();
        f.sender.host_trust_gen = 1;
    });
    assert_eq!(st.put(&c(), &from_c), Outcome::Stored { position: 3 });
    // A quota refusal stores nothing and is charged nothing.
    assert_eq!(st.m.sender_usage("host-a").objects, 2);

    // Per sending host, in bytes: the object's compact JSON.
    let mut st = Station::with(Quotas {
        sender: Quota {
            objects: 100,
            bytes: 2 * one,
        },
        receiver: roomy,
        account: roomy,
    });
    st.put(&a(), &object(1));
    st.put(&a(), &object(2));
    assert_eq!(st.m.sender_usage("host-a").bytes, 2 * one);
    assert_eq!(
        st.put(&a(), &object(3)),
        Outcome::PutRefused(PutRefusal::Quota)
    );

    // Per receiving host: its mailbox.
    let mut st = Station::with(Quotas {
        sender: roomy,
        receiver: Quota {
            objects: 1,
            bytes: roomy.bytes,
        },
        account: roomy,
    });
    st.put(&a(), &object(1));
    assert_eq!(
        st.put(&a(), &object(2)),
        Outcome::PutRefused(PutRefusal::Quota)
    );
    let to_c = object_with(2, 0, |f| {
        f.recipient.host_id = "host-c".into();
        f.recipient.host_trust_gen = 1;
    });
    assert_eq!(st.put(&a(), &to_c), Outcome::Stored { position: 1 });

    // Per account: every mailbox of this device list.
    let mut st = Station::with(Quotas {
        sender: roomy,
        receiver: roomy,
        account: Quota {
            objects: 100,
            bytes: one + size(&to_c) - 1,
        },
    });
    st.put(&a(), &object(1));
    assert_eq!(st.put(&a(), &to_c), Outcome::PutRefused(PutRefusal::Quota));
    assert_eq!(
        st.m.account_usage(),
        Usage {
            objects: 1,
            bytes: one
        }
    );
}

#[test]
fn the_contracts_starting_figures_are_the_default() {
    let q = Quotas::default();
    let mib = 1024 * 1024;
    assert_eq!(
        q.sender,
        Quota {
            objects: 128,
            bytes: 32 * mib
        }
    );
    assert_eq!(
        q.receiver,
        Quota {
            objects: 256,
            bytes: 64 * mib
        }
    );
    assert_eq!(
        q.account,
        Quota {
            objects: 1024,
            bytes: 256 * mib
        }
    );
    // 128 objects from one sending host, then `quota`.
    let mut st = Station::new();
    for n in 1..=128 {
        assert_eq!(st.put(&a(), &object(n)), Outcome::Stored { position: n });
    }
    assert_eq!(
        st.put(&a(), &object(129)),
        Outcome::PutRefused(PutRefusal::Quota)
    );
}

#[test]
fn a_stored_retry_is_never_charged_twice_even_at_the_limit() {
    let mut st = Station::with(Quotas {
        sender: Quota {
            objects: 1,
            bytes: 1 << 20,
        },
        ..Quotas::default()
    });
    st.put(&a(), &object(1));
    // Full, yet the same object again is answered stored.
    assert_eq!(
        st.put(&a(), &object(1)),
        Outcome::AlreadyStored { position: 1 }
    );
    assert_eq!(
        st.put(&a(), &object(2)),
        Outcome::PutRefused(PutRefusal::Quota)
    );
    assert_eq!(st.m.sender_usage("host-a").objects, 1);
}

#[test]
fn a_call_the_station_cant_read_is_dropped_unanswered_and_counted() {
    let mut st = Station::new();
    let good = MailboxPut {
        request_id: uuid(1),
        object: object(1),
    }
    .to_json()
    .unwrap();
    let mut no_id = good.clone();
    no_id["object"]["body"]
        .as_object_mut()
        .unwrap()
        .remove("id");
    let mut short_enc = good.clone();
    short_enc["object"]["enc"] = json!(crate::encoding::b64u(&[0u8; 31]));
    let mut short_ct = good.clone();
    short_ct["object"]["ct"] = json!(crate::encoding::b64u(&[0u8; 15]));
    let mut upper = good.clone();
    upper["request_id"] = json!("55AA5BAB-E253-4B6C-A83F-C86E6B028AA1");
    let answer = MailboxStored {
        request_id: uuid(1),
        id: uuid(1),
    }
    .to_json()
    .unwrap();
    let texts = [
        b"not json".to_vec(),
        no_id.to_string().into_bytes(),
        short_enc.to_string().into_bytes(),
        short_ct.to_string().into_bytes(),
        upper.to_string().into_bytes(),
        // A Station's own message, sent to it.
        answer.to_string().into_bytes(),
        vec![b' '; MAX_MAILBOX_MESSAGE_BYTES + 1],
    ];
    for (n, text) in texts.iter().enumerate() {
        let (answer, outcome) = st.send(&a(), text);
        assert_eq!(answer, None, "{n}");
        assert!(
            matches!(outcome, Outcome::Dropped(Dropped::Unread(_))),
            "{n}: {outcome:?}"
        );
        assert_eq!(st.m.dropped(), n as u64 + 1);
    }
    let (_, outcome) = st.send(&a(), &texts[6]);
    assert_eq!(
        outcome,
        Outcome::Dropped(Dropped::Unread(RelayError::TooLarge))
    );
    // Nothing was stored or minted.
    assert_eq!(st.m.mailbox("host-b", 3), None);
    assert_eq!(st.m.account_usage(), Usage::default());
}

/// An object whose compact JSON is exactly `target` bytes: `object(1)`'s
/// ciphertext grown (the Station never opens it).
fn object_of_size(target: usize) -> SignedObject {
    let wire = object(1).to_json();
    let ct = crate::encoding::b64u_decode(wire["ct"].as_str().unwrap()).unwrap();
    let mut grown = wire.clone();
    // 4 base64url characters per 3 bytes, then down to the target.
    let mut extra = (target - wire.to_string().len()) / 4 * 3;
    loop {
        let mut more = ct.clone();
        more.resize(ct.len() + extra, 0);
        grown["ct"] = json!(crate::encoding::b64u(&more));
        let len = grown.to_string().len();
        if len <= target {
            break;
        }
        extra -= 1;
    }
    SignedObject::from_value(&grown).unwrap()
}

#[test]
fn an_object_no_page_could_carry_is_dropped() {
    // The bound: a page with every field at its largest and one object of
    // MAX_SERVED_OBJECT_BYTES is exactly 512 KiB.
    let largest = MAX_SAFE_INTEGER;
    let wrapper = MailboxSyncResult {
        request_id: uuid(1),
        mailbox_id: uuid(2),
        after: largest - 1,
        head: largest,
        through: largest,
        objects: vec![MailboxEntry::new(largest, &object(1))],
    }
    .to_json()
    .unwrap()
    .to_string()
    .len()
        - size(&object(1)) as usize;
    assert_eq!(MAX_SERVED_OBJECT_BYTES + wrapper, MAX_MAILBOX_MESSAGE_BYTES);
    // A put's own fields are 178 bytes fewer.
    let put_wrapper = MailboxPut {
        request_id: uuid(1),
        object: object(1),
    }
    .to_json()
    .unwrap()
    .to_string()
    .len()
        - size(&object(1)) as usize;
    assert_eq!(wrapper - put_wrapper, 178);

    let mut st = Station::new();
    // Sizes are reached to within base64's 4-character steps: the largest
    // object at or under the bound is stored and served, one over it isn't.
    let under = object_of_size(MAX_SERVED_OBJECT_BYTES);
    assert!(size(&under) as usize <= MAX_SERVED_OBJECT_BYTES);
    assert!(size(&under) as usize > MAX_SERVED_OBJECT_BYTES - 4);
    assert_eq!(st.put(&a(), &under), Outcome::Stored { position: 1 });
    let mailbox = st.heads(&b());
    let (_, position, page) = st.page(&b(), 0);
    assert_eq!(position, Some(1));
    assert_eq!(page.objects[0].parse_object().unwrap(), under);
    st.done(&b(), &mailbox.mailbox_id, 1);

    let over = object_of_size(MAX_SERVED_OBJECT_BYTES + 8);
    assert!(size(&over) as usize > MAX_SERVED_OBJECT_BYTES);
    let (_, bytes) = st.put_bytes(&over);
    assert!(bytes.len() <= MAX_MAILBOX_MESSAGE_BYTES, "a put carries it");
    let (answer, outcome) = st.send(&a(), &bytes);
    assert_eq!(answer, None);
    assert_eq!(outcome, Outcome::Dropped(Dropped::Unserved));
    assert_eq!(st.m.dropped(), 1);
    assert_eq!(st.m.account_usage(), Usage::default());
}

// ---------------------------------------------------------------- pages

#[test]
fn a_page_lists_at_most_one_object_and_its_through_covers_removed_positions() {
    let mut st = Station::new();
    for n in 1..=5 {
        st.put(&a(), &object(n));
    }
    let mailbox = st.heads(&b());
    assert_eq!(mailbox.head, 5);
    st.done(&b(), &mailbox.mailbox_id, 2);
    st.done(&b(), &mailbox.mailbox_id, 3);
    // Stored: 1, 4, 5.
    let (through, position, page) = st.page(&b(), 0);
    assert_eq!((through, position, page.head), (3, Some(1), 5));
    assert_eq!(page.objects[0].parse_object().unwrap(), object(1));
    assert_eq!(
        page.objects[0].bytes(),
        object(1).to_json().to_string().as_bytes()
    );
    let at = |st: &mut Station, after| {
        let (through, position, _) = st.page(&b(), after);
        (through, position)
    };
    assert_eq!(at(&mut st, 1), (4, Some(4)));
    assert_eq!(at(&mut st, 3), (4, Some(4)));
    assert_eq!(at(&mut st, 4), (5, Some(5)));
    // Read to the head: nothing, `through` at the head.
    let (through, position, page) = st.page(&b(), 5);
    assert_eq!((through, position, page.head), (5, None, 5));
    // Only removed positions after the cursor: one page covers them all.
    st.done(&b(), &mailbox.mailbox_id, 4);
    st.done(&b(), &mailbox.mailbox_id, 5);
    assert_eq!(at(&mut st, 1), (5, None));
    // An empty mailbox's page.
    let own = st.heads(&c());
    assert_eq!(own.head, 0);
    assert_eq!(st.page(&c(), 0).0, 0);
}

#[test]
fn a_page_covers_expired_positions_too() {
    let mut st = Station::new();
    st.put(&a(), &object_with(1, 0, |f| f.expires_at = NOW + 1_000));
    st.put(&a(), &object_with(2, 0, |f| f.expires_at = NOW + 1_000));
    st.put(&a(), &object(3));
    st.heads(&b());
    st.now = NOW + 1_000;
    let (through, position, _) = st.page(&b(), 0);
    assert_eq!((through, position), (3, Some(3)));
}

#[test]
fn a_call_after_the_head_gets_the_reset_page() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    let mailbox = st.heads(&b());
    let (answer, outcome) = st.sync(&b(), &mailbox.mailbox_id, 7);
    assert_eq!(
        outcome,
        Outcome::Page {
            through: 1,
            position: None,
            reset: true
        }
    );
    let page = MailboxSyncResult::decode(answer.unwrap().to_string().as_bytes()).unwrap();
    assert!(page.is_reset());
    assert_eq!((page.after, page.head, page.through), (7, 1, 1));
}

#[test]
fn only_the_mailboxs_own_host_syncs_it() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    let b_box = st.heads(&b());
    // Host C, and host-a, naming host-b's mailbox.
    st.heads(&c());
    for caller in [c(), a()] {
        let (answer, outcome) = st.sync(&caller, &b_box.mailbox_id, 0);
        assert_eq!(answer, Some(forbidden_sync()));
        assert_eq!(outcome, Outcome::Refused(MailboxRefusedCall::Sync));
    }
    // host-b at another generation: another mailbox.
    let (answer, _) = st.sync(&link("host-b", 2), &b_box.mailbox_id, 0);
    assert_eq!(answer, Some(forbidden_sync()));
    // An id no mailbox has.
    let (answer, _) = st.sync(&b(), &uuid(99), 0);
    assert_eq!(answer, Some(forbidden_sync()));
    // Its own.
    assert_eq!(st.page(&b(), 0).1, Some(1));
}

// ---------------------------------------------------------------- done

#[test]
fn done_removes_the_object_and_answers_the_same_when_nothing_is_there() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    st.put(&a(), &object(2));
    let mailbox = st.heads(&b());
    let (_, outcome) = st.done(&b(), &mailbox.mailbox_id, 1);
    assert_eq!(outcome, Outcome::Done { removed: true });
    assert_eq!(st.positions(&b()), [2]);
    assert_eq!(
        st.m.receiver_usage("host-b", 3),
        Usage {
            objects: 1,
            bytes: size(&object(2))
        }
    );
    // Again, and at a position beyond the head: the same answer.
    assert_eq!(
        st.done(&b(), &mailbox.mailbox_id, 1).1,
        Outcome::Done { removed: false }
    );
    assert_eq!(
        st.done(&b(), &mailbox.mailbox_id, 9).1,
        Outcome::Done { removed: false }
    );
    // The head doesn't move back.
    assert_eq!(st.mailbox_of(&b()).head, 2);
}

#[test]
fn only_the_mailboxs_own_host_marks_done() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    let mailbox = st.heads(&b());
    st.heads(&c());
    for caller in [a(), c(), link("host-b", 2)] {
        let (answer, outcome) = st.done(&caller, &mailbox.mailbox_id, 1);
        assert_eq!(answer, Some(forbidden_done()));
        assert_eq!(outcome, Outcome::Refused(MailboxRefusedCall::Done));
    }
    assert_eq!(st.positions(&b()), [1]);
}

// -------------------------------------------------------------- expiry

#[test]
fn expiry_follows_the_injected_clock() {
    let mut st = Station::new();
    st.put(&a(), &object_with(1, 0, |f| f.expires_at = NOW + 1_000));
    st.put(&a(), &object(2));
    let at = st.m.clone();
    assert_eq!(at.tick(NOW + 999).stored("host-b", 3).len(), 2);
    let later = at.tick(NOW + 1_000);
    assert_eq!(later.stored("host-b", 3).len(), 1);
    assert_eq!(later.sender_usage("host-a").objects, 1);
    assert_eq!(
        at.stored("host-b", 3).len(),
        2,
        "tick returns the next state"
    );
    // Every call applies its own clock first.
    st.now = NOW + 1_000;
    assert_eq!(st.heads(&b()).head, 2);
    assert_eq!(st.positions(&b()), [2]);
}

// -------------------------------------------------------------- resets

#[test]
fn a_reset_under_a_new_id_loses_what_the_mailbox_held() {
    let mut st = Station::new();
    st.put(&a(), &object(1));
    st.put(&a(), &object(2));
    let old = st.heads(&b());
    st.m = st.m.reset("host-b", 3, Reset::NewMailbox).unwrap();
    let new = st.heads(&b());
    assert_ne!(new.mailbox_id, old.mailbox_id);
    assert!(is_uuid_v4(&new.mailbox_id));
    assert_eq!(new.head, 0);
    assert_eq!(st.m.account_usage(), Usage::default());
    // The old id is refused, never answered on the new mailbox.
    let (answer, _) = st.sync(&b(), &old.mailbox_id, 2);
    assert_eq!(answer, Some(forbidden_sync()));
    let (answer, _) = st.done(&b(), &old.mailbox_id, 1);
    assert_eq!(answer, Some(forbidden_done()));
    // The senders' resends come back from position 1, charged again.
    assert_eq!(st.put(&a(), &object(2)), Outcome::Stored { position: 1 });
    assert_eq!(st.page(&b(), 0).1, Some(1));
    // A mailbox never minted can't be reset.
    assert_eq!(
        st.m.reset("host-z", 1, Reset::NewMailbox),
        Err(ModelError::NoSuchReset)
    );
}

#[test]
fn a_reset_under_the_same_id_takes_the_head_back() {
    let mut st = Station::new();
    for n in 1..=4 {
        st.put(&a(), &object(n));
    }
    let before = st.heads(&b());
    // The host read to 4.
    st.m =
        st.m.reset("host-b", 3, Reset::HeadBack { head: 2 })
            .unwrap();
    let after = st.heads(&b());
    assert_eq!(after.mailbox_id, before.mailbox_id);
    assert_eq!(after.head, 2);
    assert_eq!(st.positions(&b()), [1, 2]);
    assert_eq!(st.m.sender_usage("host-a").objects, 2);
    // The host's cursor is past the head: the reset page.
    let (_, outcome) = st.sync(&b(), &before.mailbox_id, 4);
    assert_eq!(
        outcome,
        Outcome::Page {
            through: 2,
            position: None,
            reset: true
        }
    );
    // The lost objects' keys are free: a resend is stored at the next
    // position, after the head.
    assert_eq!(st.put(&a(), &object(3)), Outcome::Stored { position: 3 });
    // Only below the head.
    for head in [3, 4] {
        assert_eq!(
            st.m.reset("host-b", 3, Reset::HeadBack { head }),
            Err(ModelError::NoSuchReset)
        );
    }
}

// ---------------------------------------------------------------- heads

#[test]
fn heads_announce_the_callers_own_mailbox_only_with_host_senders() {
    let st = Station::new();
    // Without `host.senders`: §11.4's heads, nothing minted.
    let t = st.m.heads(&b(), &base_heads(), false, NOW).unwrap();
    assert_eq!(t.answer, Some(base_heads().to_json().unwrap()));
    assert_eq!(t.outcome, Outcome::Heads { mailbox: None });
    assert_eq!(t.next.mailbox("host-b", 3), None);
    // With it: the caller's own mailbox, minted now.
    let t = st.m.heads(&b(), &base_heads(), true, NOW).unwrap();
    let head = t.next.mailbox("host-b", 3).unwrap();
    assert_eq!(head.head, 0);
    let want = HeadsWithMailbox {
        heads: base_heads(),
        mailbox: Some(head.clone()),
    }
    .to_json()
    .unwrap();
    assert_eq!(t.answer, Some(want.clone()));
    let read = crate::control::relay::Heads::decode_with(
        want.to_string().as_bytes(),
        crate::control::relay::Accept { mailbox: true },
    )
    .unwrap();
    assert_eq!(read.mailbox, Some(head.clone()));
    // Each host its own.
    let t2 = t.next.heads(&c(), &base_heads(), true, NOW).unwrap();
    let Outcome::Heads {
        mailbox: Some(other),
    } = t2.outcome
    else {
        panic!()
    };
    assert_ne!(other.mailbox_id, head.mailbox_id);
    // A heads the builder refuses is the Station's mistake.
    let mut bad = base_heads();
    bad.membership.seq = 0;
    assert!(matches!(
        st.m.heads(&b(), &bad, true, NOW),
        Err(ModelError::Heads(_))
    ));
}

// ---------------------------------------------------------- the model

#[test]
fn mailbox_ids_are_minted_from_the_seed_and_never_reused() {
    let id = |n| mailbox_id(&SEED, ACCOUNT, &GENESIS, "host-b", 3, n);
    let ids: Vec<String> = (0..4).map(id).collect();
    assert!(ids.iter().all(|i| is_uuid_v4(i)));
    let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(distinct.len(), 4);
    // Another seed, account, root, host or generation: another id.
    for other in [
        mailbox_id(&[0x5f; 32], ACCOUNT, &GENESIS, "host-b", 3, 0),
        mailbox_id(&SEED, "acct-test-2", &GENESIS, "host-b", 3, 0),
        mailbox_id(&SEED, ACCOUNT, &Hash32([0x12; 32]), "host-b", 3, 0),
        mailbox_id(&SEED, ACCOUNT, &GENESIS, "host-c", 3, 0),
        mailbox_id(&SEED, ACCOUNT, &GENESIS, "host-b", 4, 0),
    ] {
        assert_ne!(other, ids[0]);
    }
    // The model mints them in order: the first, then one per new mailbox.
    let mut st = Station::new();
    assert_eq!(st.heads(&b()).mailbox_id, ids[0]);
    st.m = st.m.reset("host-b", 3, Reset::NewMailbox).unwrap();
    assert_eq!(st.heads(&b()).mailbox_id, ids[1]);
    st.m = st.m.reset("host-b", 3, Reset::NewMailbox).unwrap();
    assert_eq!(st.heads(&b()).mailbox_id, ids[2]);
    // A known answer, with the derivation written out.
    let digest = Hash32::of(&enc(&[
        b"atem-reference-mailbox-id-v1",
        &SEED,
        ACCOUNT.as_bytes(),
        &GENESIS.0,
        b"host-b",
        &3u64.to_be_bytes(),
        &0u64.to_be_bytes(),
    ]));
    let mut raw = digest.0;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    let hex = crate::encoding::hex(&raw[..16]);
    let want = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    assert_eq!(ids[0], want);
}

#[test]
fn the_caller_is_a_complete_association_of_this_device_list() {
    let st = Station::new();
    let bytes = MailboxSync {
        request_id: uuid(1),
        mailbox_id: uuid(2),
        after: 0,
    }
    .to_json()
    .unwrap()
    .to_string();
    let mut incomplete = b();
    incomplete.connection_id = String::new();
    assert_eq!(
        st.m.call(&incomplete, bytes.as_bytes(), NOW),
        Err(ModelError::IncompleteLink)
    );
    let mut other = b();
    other.account_id = "acct-test-2".into();
    assert_eq!(
        st.m.call(&other, bytes.as_bytes(), NOW),
        Err(ModelError::OtherAccount)
    );
    other = b();
    other.genesis_hash = Hash32([0x12; 32]);
    assert_eq!(
        st.m.heads(&other, &base_heads(), true, NOW),
        Err(ModelError::OtherAccount)
    );
    // An account id out of its grammar.
    assert_eq!(
        ReferenceMailbox::new("", GENESIS, Quotas::default(), SEED),
        Err(ModelError::Malformed("account_id"))
    );
    let new = ReferenceMailbox::new(ACCOUNT, GENESIS, Quotas::default(), SEED).unwrap();
    assert_eq!(new.account_id(), ACCOUNT);
    assert_eq!(new.genesis_hash(), GENESIS);
    assert_eq!(new.quotas(), Quotas::default());
    assert_eq!(new.hosts(), &CurrentHosts::default());
}

//! `designs/protocol/fixtures/r9-vectors-mailbox-calls.json`: the mailbox
//! calls of host-work-v1 §11.5 ("The mailbox calls"), as the shared core's
//! builders write them and its readers read them, `object_hash` known
//! answers, `heads`' mailbox head, and scenarios run against the Station's
//! reference mailbox (`host_mail::reference::ReferenceMailbox`).
//!
//! `write_mailbox_call_vectors` (ignored) writes the file from
//! `mailbox_call_vectors`, which runs every scenario through the reference
//! mailbox and checks each outcome against the one written here by hand. The
//! other tests read the file: that it is what the generator makes now, that
//! every call is built byte for byte from its fields and read back to them,
//! that every invalid text is refused with its code, the `heads` forms, the
//! `object_hash` answers, and every scenario's events run against a fresh
//! reference mailbox, answer, outcome and state. `scripts/check-r9-vectors.py`
//! checks the file independently, with a model of its own.
mod support;

use std::collections::BTreeSet;

use atem_client::control::{
    Accept, Heads, HeadsWithMailbox, LinkAssociation, MailboxHead, RefusalCode, RelayError,
};
use atem_client::encoding::{Hash32, enc, hex};
use atem_client::host_mail::mailbox::{
    MAX_MAILBOX_MESSAGE_BYTES, MailboxCallRefused, MailboxDone, MailboxDoneResult, MailboxEntry,
    MailboxPut, MailboxPutRefused, MailboxRefusedCall, MailboxStored, MailboxSync,
    MailboxSyncResult, MailboxToHost, MailboxToStation, PutRefusal,
};
use atem_client::host_mail::reference::{
    CurrentHosts, Dropped, MAX_LIFETIME_MS, MAX_SERVED_OBJECT_BYTES, Outcome, Quota, Quotas,
    ReferenceMailbox, Reset,
};
use atem_client::host_mail::{
    EnvelopePlain, HostRef, MailFields, ResultPlain, object_hash, seal_envelope_with_ikm,
    seal_result_with_ikm,
};
use atem_client::keys::enc_kid;
use atem_client::membership::Head;
use atem_client::{KeyId, KeyProvider, SignedObject, SoftwareKeys};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{fixtures_dir, genesis_hash, load, unhex32};

const FILE: &str = "r9-vectors-mailbox-calls";
const ACCOUNT: &str = "acct-test-1";
const CONNECTION: &str = "conn-1";
const T0: u64 = 1_793_620_800_000;
const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;
/// §11.4's bound, which `heads` keeps.
const HEADS_MAX_BYTES: usize = 256 * 1024;

/// SHA-256 of `enc(["atem-r9-test-ikm", "mailbox-calls " + label])`: the
/// ephemerals, ids and seed of this file.
fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(enc(&[
        b"atem-r9-test-ikm",
        format!("mailbox-calls {label}").as_bytes(),
    ]))
    .into()
}

/// A lowercase UUID v4 from `derived(label)`.
fn uuid4(label: &str) -> String {
    let mut b = derived(label);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn seed() -> [u8; 32] {
    derived("seed")
}

fn s<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is not a string in {v}"))
}

fn u(v: &Value, field: &str) -> u64 {
    v[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} is not a number in {v}"))
}

fn text(value: &Value) -> String {
    value.to_string()
}

// ------------------------------------------------------------ objects

/// The hosts' keys of `r9-vectors-keys`: each host signs with its
/// `host_key`; objects are sealed to `host-a-enc-1` or `host-b-enc-1`.
struct Keys {
    provider: SoftwareKeys,
}

impl Keys {
    fn load() -> Self {
        let keys = load("r9-vectors-keys")["keys"].clone();
        let mut provider = SoftwareKeys::new();
        for host in ["host-a", "host-b", "host-evil"] {
            let secret = unhex32(s(&keys[host]["host_key"], "secret_hex"));
            provider.insert_ed25519(KeyId::new(host), &secret);
        }
        for enc in ["host-a-enc-1", "host-b-enc-1"] {
            let secret = unhex32(s(&keys[enc]["enc"], "secret_hex"));
            provider.insert_x25519(KeyId::new(enc), &secret);
        }
        Keys { provider }
    }
}

/// One object of the file: who sends it, to whom, its id's label and the
/// label of its sealed part (the ephemeral and the plaintext's ids), and a
/// change of its fields.
struct Spec {
    label: &'static str,
    note: &'static str,
    from: &'static str,
    to: (&'static str, u64),
    id: &'static str,
    seal: &'static str,
    edit: fn(&mut MailFields),
}

fn no_edit(_: &mut MailFields) {}

const SPECS: &[Spec] = &[
    Spec {
        label: "o1",
        note: "a cancel envelope from host-a to host-b",
        from: "host-a",
        to: ("host-b", 1),
        id: "o1",
        seal: "o1",
        edit: no_edit,
    },
    Spec {
        label: "o2",
        note: "another of host-a's envelopes to host-b",
        from: "host-a",
        to: ("host-b", 1),
        id: "o2",
        seal: "o2",
        edit: no_edit,
    },
    Spec {
        label: "o3",
        note: "another of host-a's envelopes to host-b",
        from: "host-a",
        to: ("host-b", 1),
        id: "o3",
        seal: "o3",
        edit: no_edit,
    },
    Spec {
        label: "o4",
        note: "another of host-a's envelopes to host-b",
        from: "host-a",
        to: ("host-b", 1),
        id: "o4",
        seal: "o4",
        edit: no_edit,
    },
    Spec {
        label: "o5",
        note: "another of host-a's envelopes to host-b",
        from: "host-a",
        to: ("host-b", 1),
        id: "o5",
        seal: "o5",
        edit: no_edit,
    },
    Spec {
        label: "o1_other",
        note: "o1's id from host-a with another sealed part: other bytes under o1's key",
        from: "host-a",
        to: ("host-b", 1),
        id: "o1",
        seal: "o1 other",
        edit: no_edit,
    },
    Spec {
        label: "o1_resigned",
        note: "o1's sealed part signed again at a newer head (signed_at_head.seq 11): other bytes under o1's key",
        from: "host-a",
        to: ("host-b", 1),
        id: "o1",
        seal: "o1",
        edit: |f| f.signed_at_head.seq = 11,
    },
    Spec {
        label: "e1",
        note: "an envelope from host-evil, a current host of the account, to host-b",
        from: "host-evil",
        to: ("host-b", 1),
        id: "e1",
        seal: "e1",
        edit: no_edit,
    },
    Spec {
        label: "e2",
        note: "another of host-evil's envelopes to host-b",
        from: "host-evil",
        to: ("host-b", 1),
        id: "e2",
        seal: "e2",
        edit: no_edit,
    },
    Spec {
        label: "e_o1",
        note: "host-evil's envelope to host-b with o1's id: another sender's key",
        from: "host-evil",
        to: ("host-b", 1),
        id: "o1",
        seal: "e o1",
        edit: no_edit,
    },
    Spec {
        label: "e_to_a",
        note: "host-evil's envelope to host-a",
        from: "host-evil",
        to: ("host-a", 1),
        id: "e3",
        seal: "e3",
        edit: no_edit,
    },
    Spec {
        label: "r1",
        note: "an atem-result from host-b to host-a: a refusal of o1",
        from: "host-b",
        to: ("host-a", 1),
        id: "r1",
        seal: "r1",
        edit: no_edit,
    },
    Spec {
        label: "short",
        note: "host-a to host-b, expiring 10 minutes after its created_at",
        from: "host-a",
        to: ("host-b", 1),
        id: "short",
        seal: "short",
        edit: |f| f.expires_at = T0 + 10 * MINUTE,
    },
    Spec {
        label: "day",
        note: "host-a to host-b, expiring exactly 24 hours after its created_at",
        from: "host-a",
        to: ("host-b", 1),
        id: "day",
        seal: "day",
        edit: |f| f.expires_at = T0 + MAX_LIFETIME_MS,
    },
    Spec {
        label: "long",
        note: "host-a to host-b, expiring 24 hours and 1 ms after its created_at",
        from: "host-a",
        to: ("host-b", 1),
        id: "long",
        seal: "long",
        edit: |f| f.expires_at = T0 + MAX_LIFETIME_MS + 1,
    },
    Spec {
        label: "equal",
        note: "host-a to host-b, expires_at equal to created_at (2 hours ahead)",
        from: "host-a",
        to: ("host-b", 1),
        id: "equal",
        seal: "equal",
        edit: |f| {
            f.created_at = T0 + 2 * HOUR;
            f.expires_at = T0 + 2 * HOUR;
        },
    },
    Spec {
        label: "before",
        note: "host-a to host-b, expires_at an hour before created_at",
        from: "host-a",
        to: ("host-b", 1),
        id: "before",
        seal: "before",
        edit: |f| {
            f.created_at = T0 + 2 * HOUR;
            f.expires_at = T0 + HOUR;
        },
    },
    Spec {
        label: "other_account",
        note: "host-a to host-b, naming another account",
        from: "host-a",
        to: ("host-b", 1),
        id: "other account",
        seal: "other account",
        edit: |f| f.account_id = "acct-test-2".into(),
    },
    Spec {
        label: "other_root",
        note: "host-a to host-b, naming another genesis",
        from: "host-a",
        to: ("host-b", 1),
        id: "other root",
        seal: "other root",
        edit: |f| f.genesis_hash = Hash32([0x33; 32]),
    },
    Spec {
        label: "to_b2",
        note: "host-a to host-b at generation 2, which isn't current",
        from: "host-a",
        to: ("host-b", 2),
        id: "to b2",
        seal: "to b2",
        edit: no_edit,
    },
    Spec {
        label: "to_z",
        note: "host-a to host-z, no host of the account",
        from: "host-a",
        to: ("host-z", 1),
        id: "to z",
        seal: "to z",
        edit: no_edit,
    },
    Spec {
        label: "sender_gen_2",
        note: "host-a to host-b, its body naming host-a at generation 2",
        from: "host-a",
        to: ("host-b", 1),
        id: "sender gen 2",
        seal: "sender gen 2",
        edit: |f| f.sender.host_trust_gen = 2,
    },
];

fn head() -> Head {
    Head {
        seq: 10,
        hash: Hash32(derived("signed_at_head")),
    }
}

fn make(keys: &Keys, spec: &Spec) -> SignedObject {
    let enc_name = if spec.to.0 == "host-a" {
        "host-a-enc-1"
    } else {
        "host-b-enc-1"
    };
    let enc_pub = keys.provider.public_key(&KeyId::new(enc_name)).unwrap();
    let mut fields = MailFields {
        account_id: ACCOUNT.into(),
        genesis_hash: genesis_hash(),
        sender: HostRef {
            host_id: spec.from.into(),
            host_trust_gen: 1,
        },
        recipient: HostRef {
            host_id: spec.to.0.into(),
            host_trust_gen: spec.to.1,
        },
        enc_kid: enc_kid(&enc_pub).unwrap(),
        id: uuid4(&format!("id {}", spec.id)),
        created_at: T0,
        expires_at: T0 + HOUR,
        signed_at_head: head(),
    };
    (spec.edit)(&mut fields);
    let signer = KeyId::new(spec.from);
    let ikm = derived(&format!("seal {}", spec.seal));
    if spec.label == "r1" {
        let plain = ResultPlain::Refusal {
            object_id: uuid4("id o1"),
            refused: "invalid_request".into(),
        };
        seal_result_with_ikm(&keys.provider, &signer, &fields, &plain, &enc_pub, &ikm)
    } else {
        let plain = EnvelopePlain::Cancel {
            task_id: uuid4(&format!("task {}", spec.seal)),
        };
        seal_envelope_with_ikm(&keys.provider, &signer, &fields, &plain, &enc_pub, &ikm)
    }
    .unwrap()
}

/// Every object, by label.
struct Objects(Vec<(&'static str, &'static str, SignedObject)>);

impl Objects {
    fn make() -> Self {
        let keys = Keys::load();
        Objects(
            SPECS
                .iter()
                .map(|spec| (spec.label, spec.note, make(&keys, spec)))
                .collect(),
        )
    }

    fn get(&self, label: &str) -> &SignedObject {
        &self
            .0
            .iter()
            .find(|(l, _, _)| *l == label)
            .unwrap_or_else(|| panic!("no object {label}"))
            .2
    }

    fn file(&self) -> Value {
        Value::Array(
            self.0
                .iter()
                .map(|(label, note, object)| {
                    json!({
                        "label": label,
                        "note": note,
                        "object": object.to_json(),
                        "object_hash": object_hash(object).to_hex(),
                        "bytes": object.to_json().to_string().len(),
                    })
                })
                .collect(),
        )
    }
}

/// The object as a page or a put writes it, with its keys in another order
/// and spaces: the same object (`object_hash` is of its canonical form).
fn respaced(object: &SignedObject) -> String {
    let wire = object.to_json();
    let mut parts = Vec::new();
    for key in ["sig", "ct", "body", "enc"] {
        parts.push(format!("\n  \"{key}\" : {}", wire[key]));
    }
    format!("{{{} }}", parts.join(" ,"))
}

// --------------------------------------------------------------- calls

const R1: &str = "55aa5bab-e253-4b6c-a83f-c86e6b028aa1";
const R2: &str = "3e9fd05f-183e-4b70-be0e-3ffa66120f48";
const R3: &str = "e5df8ab5-b35a-40f6-8536-8e17b8634743";
const MAILBOX: &str = "9d2f6c1e-3b4a-4c5d-8e6f-7a8b9c0d1e2f";

/// A valid message: its name, `op`, who reads it, a note, its fields and
/// the message the builders make from them.
fn call_case(name: &str, direction: &str, note: &str, fields: Value, wire: Value) -> Value {
    json!({
        "name": name,
        "op": wire["op"],
        "direction": direction,
        "note": note,
        "fields": fields,
        "wire": text(&wire),
    })
}

fn calls(objects: &Objects) -> Vec<Value> {
    let o1 = objects.get("o1");
    let r1 = objects.get("r1");
    let id = |label: &str| s(&objects.get(label).to_json()["body"], "id").to_owned();
    let mut out = Vec::new();
    for (name, object, note) in [
        (
            "mailbox_put",
            o1,
            "host-a puts its cancel envelope to host-b; request_id names this call (a fresh lowercase UUID v4 for every call)",
        ),
        (
            "mailbox_put_result",
            r1,
            "host-b puts an atem-result to host-a: the Station takes both kinds, reading the body only",
        ),
    ] {
        let put = MailboxPut {
            request_id: R1.into(),
            object: object.clone(),
        };
        out.push(call_case(
            name,
            "to_station",
            note,
            json!({"request_id": R1, "object": object.to_json()}),
            put.to_json().unwrap(),
        ));
    }
    let stored = MailboxStored {
        request_id: R1.into(),
        id: id("o1"),
    };
    out.push(call_case(
        "mailbox_stored",
        "to_host",
        "the put is durably stored in host-b's mailbox (also the answer to a put of the same object, already stored)",
        json!({"request_id": R1, "id": id("o1")}),
        stored.to_json().unwrap(),
    ));
    for code in PutRefusal::ALL {
        let refused = MailboxPutRefused {
            request_id: R1.into(),
            id: id("o1"),
            code,
        };
        out.push(call_case(
            &format!("mailbox_put_refused_{}", code.code()),
            "to_host",
            "a refusal naming the put: its request_id and its object's id",
            json!({"request_id": R1, "id": id("o1"), "code": code.code()}),
            refused.to_json().unwrap(),
        ));
    }
    let sync = MailboxSync {
        request_id: R2.into(),
        mailbox_id: MAILBOX.into(),
        after: 9,
    };
    out.push(call_case(
        "mailbox_sync",
        "to_station",
        "host-b reads its own mailbox, the one the last heads announced, after position 9",
        json!({"request_id": R2, "mailbox_id": MAILBOX, "after": 9}),
        sync.to_json().unwrap(),
    ));
    let page = |after: u64, head: u64, through: u64, entries: Vec<(u64, &SignedObject)>| {
        MailboxSyncResult {
            request_id: R2.into(),
            mailbox_id: MAILBOX.into(),
            after,
            head,
            through,
            objects: entries
                .iter()
                .map(|(position, object)| MailboxEntry::new(*position, object))
                .collect(),
        }
    };
    for (name, note, page) in [
        (
            "mailbox_sync_result",
            "position 10 holds no object (done or expired), 11 holds o1: the cursor moves to 11, through",
            page(9, 12, 11, vec![(11, o1)]),
        ),
        (
            "mailbox_sync_result_read_to_the_head",
            "nothing after 12: objects empty, through the head",
            page(12, 12, 12, vec![]),
        ),
        (
            "mailbox_sync_result_reset",
            "the mailbox went back under the same id: head 3 below after 12, no objects, through equal to head",
            page(12, 3, 3, vec![]),
        ),
    ] {
        let fields = json!({
            "request_id": R2,
            "mailbox_id": MAILBOX,
            "after": page.after,
            "head": page.head,
            "through": page.through,
            "objects": page.objects.iter()
                .map(|e| json!({"position": e.position, "object": e.raw()}))
                .collect::<Vec<_>>(),
        });
        out.push(call_case(
            name,
            "to_host",
            note,
            fields,
            page.to_json().unwrap(),
        ));
    }
    let done = MailboxDone {
        request_id: R3.into(),
        mailbox_id: MAILBOX.into(),
        position: 11,
    };
    out.push(call_case(
        "mailbox_done",
        "to_station",
        "host-b is through with the object at position 11 of its own mailbox",
        json!({"request_id": R3, "mailbox_id": MAILBOX, "position": 11}),
        done.to_json().unwrap(),
    ));
    let done_result = MailboxDoneResult {
        request_id: R3.into(),
        mailbox_id: MAILBOX.into(),
        position: 11,
    };
    out.push(call_case(
        "mailbox_done_result",
        "to_host",
        "the done, echoed; the same when nothing was there",
        json!({"request_id": R3, "mailbox_id": MAILBOX, "position": 11}),
        done_result.to_json().unwrap(),
    ));
    for call in [MailboxRefusedCall::Sync, MailboxRefusedCall::Done] {
        let refused = MailboxCallRefused {
            call,
            code: RefusalCode::Forbidden,
        };
        out.push(call_case(
            call.op(),
            "to_host",
            "exactly code forbidden, naming a call kind, never a request",
            json!({"code": "forbidden"}),
            refused.to_json().unwrap(),
        ));
    }
    out
}

/// A call's message from its fields, by the builders.
fn build(op: &str, f: &Value) -> Value {
    let object = |v: &Value| SignedObject::parse(text(v).as_bytes()).unwrap();
    match op {
        "mailbox_put" => MailboxPut {
            request_id: s(f, "request_id").into(),
            object: object(&f["object"]),
        }
        .to_json(),
        "mailbox_stored" => MailboxStored {
            request_id: s(f, "request_id").into(),
            id: s(f, "id").into(),
        }
        .to_json(),
        "mailbox_put_refused" => MailboxPutRefused {
            request_id: s(f, "request_id").into(),
            id: s(f, "id").into(),
            code: PutRefusal::from_code(s(f, "code")).unwrap(),
        }
        .to_json(),
        "mailbox_sync" => MailboxSync {
            request_id: s(f, "request_id").into(),
            mailbox_id: s(f, "mailbox_id").into(),
            after: u(f, "after"),
        }
        .to_json(),
        "mailbox_sync_result" => MailboxSyncResult {
            request_id: s(f, "request_id").into(),
            mailbox_id: s(f, "mailbox_id").into(),
            after: u(f, "after"),
            head: u(f, "head"),
            through: u(f, "through"),
            objects: f["objects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| MailboxEntry::new(u(e, "position"), &object(&e["object"])))
                .collect(),
        }
        .to_json(),
        "mailbox_done" => MailboxDone {
            request_id: s(f, "request_id").into(),
            mailbox_id: s(f, "mailbox_id").into(),
            position: u(f, "position"),
        }
        .to_json(),
        "mailbox_done_result" => MailboxDoneResult {
            request_id: s(f, "request_id").into(),
            mailbox_id: s(f, "mailbox_id").into(),
            position: u(f, "position"),
        }
        .to_json(),
        refused => MailboxCallRefused {
            call: [MailboxRefusedCall::Sync, MailboxRefusedCall::Done]
                .into_iter()
                .find(|c| c.op() == refused)
                .unwrap_or_else(|| panic!("no builder for {refused}")),
            code: RefusalCode::from_code(s(f, "code")).unwrap(),
        }
        .to_json(),
    }
    .unwrap()
}

/// What a message reads as, in the file's `fields` form.
fn describe_to_station(m: &MailboxToStation) -> Value {
    match m {
        MailboxToStation::Put(p) => {
            json!({"request_id": p.request_id, "object": p.object.to_json()})
        }
        MailboxToStation::Sync(c) => {
            json!({"request_id": c.request_id, "mailbox_id": c.mailbox_id, "after": c.after})
        }
        MailboxToStation::Done(d) => {
            json!({"request_id": d.request_id, "mailbox_id": d.mailbox_id, "position": d.position})
        }
    }
}

fn describe_to_host(m: &MailboxToHost) -> Value {
    match m {
        MailboxToHost::Stored(a) => json!({"request_id": a.request_id, "id": a.id}),
        MailboxToHost::PutRefused(a) => {
            json!({"request_id": a.request_id, "id": a.id, "code": a.code.code()})
        }
        MailboxToHost::SyncResult(p) => json!({
            "request_id": p.request_id,
            "mailbox_id": p.mailbox_id,
            "after": p.after,
            "head": p.head,
            "through": p.through,
            "objects": p.objects.iter()
                .map(|e| json!({"position": e.position, "object": e.raw()}))
                .collect::<Vec<_>>(),
        }),
        MailboxToHost::DoneResult(d) => {
            json!({"request_id": d.request_id, "mailbox_id": d.mailbox_id, "position": d.position})
        }
        MailboxToHost::SyncRefused(code) | MailboxToHost::DoneRefused(code) => {
            json!({"code": code.code()})
        }
    }
}

/// The reader `direction` names, and what it reads.
fn read(direction: &str, bytes: &[u8]) -> Result<Value, RelayError> {
    match direction {
        "to_station" => MailboxToStation::decode(bytes).map(|m| describe_to_station(&m)),
        "to_host" => MailboxToHost::decode(bytes).map(|m| describe_to_host(&m)),
        other => panic!("no reader {other}"),
    }
}

// ------------------------------------------------------------- invalid

/// A text of `bytes` bytes: `prefix`, `count` times `fill`, `suffix`.
fn fill_recipe(prefix: &str, fill: &str, count: usize, suffix: &str) -> Value {
    let bytes = prefix.len() + fill.len() * count + suffix.len();
    json!({"prefix": prefix, "fill": fill, "count": count, "suffix": suffix, "bytes": bytes})
}

fn from_recipe(recipe: &Value) -> String {
    format!(
        "{}{}{}",
        s(recipe, "prefix"),
        s(recipe, "fill").repeat(u(recipe, "count") as usize),
        s(recipe, "suffix")
    )
}

/// A put of `o1` exactly `bytes` long: its `ct` a run of `A`s (zero bytes in
/// base64url), and a space after the message when a run of that length
/// isn't base64url. Its object is far over what a page can carry.
fn big_put(objects: &Objects, request_id: &str, bytes: usize) -> Value {
    let mut wire = MailboxPut {
        request_id: request_id.into(),
        object: objects.get("o1").clone(),
    }
    .to_json()
    .unwrap();
    wire["object"]["ct"] = json!("@");
    let whole = text(&wire);
    let (prefix, suffix) = whole.split_once('@').unwrap();
    let mut suffix = suffix.to_owned();
    let mut count = bytes - prefix.len() - suffix.len();
    if count % 4 == 1 {
        count -= 1;
        suffix.push(' ');
    }
    let recipe = fill_recipe(prefix, "A", count, &suffix);
    assert_eq!(from_recipe(&recipe).len(), bytes);
    recipe
}

fn invalid_case(name: &str, op: &str, reader: &str, code: &str, wire: String) -> Value {
    json!({"name": name, "op": op, "reader": reader, "code": code, "wire": wire})
}

fn invalid(objects: &Objects, calls: &[Value]) -> Vec<Value> {
    let wire_of = |name: &str| -> Value {
        let case = calls.iter().find(|c| c["name"] == name).unwrap();
        serde_json::from_str(s(case, "wire")).unwrap()
    };
    let changed = |name: &str, edit: &dyn Fn(&mut Value)| -> String {
        let mut wire = wire_of(name);
        edit(&mut wire);
        text(&wire)
    };
    let mut out = Vec::new();
    let mut add = |name: &str, op: &str, reader: &str, code: &str, wire: String| {
        out.push(invalid_case(name, op, reader, code, wire));
    };
    let v5 = "80160896-4fcd-5e6e-adac-98bac5497321";
    let put = "mailbox_put";
    let st = "to_station";
    let ho = "to_host";
    // mailbox_put
    add(
        "put_unknown_field",
        put,
        st,
        "unknown_field",
        changed(put, &|w| w["extra"] = json!(1)),
    );
    add(
        "put_request_id_missing",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            w.as_object_mut().unwrap().remove("request_id");
        }),
    );
    add(
        "put_request_id_null",
        put,
        st,
        "malformed",
        changed(put, &|w| w["request_id"] = Value::Null),
    );
    add(
        "put_request_id_upper_case",
        put,
        st,
        "malformed",
        changed(put, &|w| w["request_id"] = json!(R1.to_uppercase())),
    );
    add(
        "put_request_id_not_uuid_v4",
        put,
        st,
        "malformed",
        changed(put, &|w| w["request_id"] = json!(v5)),
    );
    add(
        "put_object_missing",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            w.as_object_mut().unwrap().remove("object");
        }),
    );
    add(
        "put_object_not_an_object",
        put,
        st,
        "malformed",
        changed(put, &|w| w["object"] = json!("o1")),
    );
    add(
        "put_object_two_objects",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            let o = w["object"].clone();
            w["object"] = json!([o.clone(), o]);
        }),
    );
    add(
        "put_object_without_its_sealed_part",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            let o = w["object"].as_object_mut().unwrap();
            o.remove("enc");
            o.remove("ct");
        }),
    );
    add(
        "put_object_body_unknown_field",
        put,
        st,
        "malformed",
        changed(put, &|w| w["object"]["body"]["note"] = json!("x")),
    );
    add(
        "put_object_body_without_id",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            w["object"]["body"].as_object_mut().unwrap().remove("id");
        }),
    );
    add(
        "put_object_of_another_type",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            w["object"]["body"]["type"] = json!("atem-membership-entry")
        }),
    );
    add(
        "put_object_enc_31_bytes",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            w["object"]["enc"] = json!(atem_client::encoding::b64u(&[7u8; 31]))
        }),
    );
    add(
        "put_object_ct_15_bytes",
        put,
        st,
        "malformed",
        changed(put, &|w| {
            w["object"]["ct"] = json!(atem_client::encoding::b64u(&[7u8; 15]))
        }),
    );
    add("put_duplicate_key", put, st, "not_strict", {
        let t = text(&wire_of(put));
        t.replacen("\"op\":", &format!("\"request_id\":\"{R2}\",\"op\":"), 1)
    });
    add(
        "put_not_a_relay_message",
        put,
        st,
        "wrong_message",
        changed(put, &|w| w["type"] = json!("session")),
    );
    add(
        "put_read_by_the_host",
        put,
        ho,
        "wrong_message",
        text(&wire_of(put)),
    );
    // mailbox_sync
    let sync = "mailbox_sync";
    add(
        "sync_unknown_field",
        sync,
        st,
        "unknown_field",
        changed(sync, &|w| w["extra"] = json!(1)),
    );
    add(
        "sync_after_missing",
        sync,
        st,
        "malformed",
        changed(sync, &|w| {
            w.as_object_mut().unwrap().remove("after");
        }),
    );
    add(
        "sync_after_negative",
        sync,
        st,
        "malformed",
        changed(sync, &|w| w["after"] = json!(-1)),
    );
    add(
        "sync_after_a_fraction",
        sync,
        st,
        "not_strict",
        text(&wire_of(sync)).replace("\"after\":9", "\"after\":9.0"),
    );
    add(
        "sync_after_unsafe",
        sync,
        st,
        "not_strict",
        text(&wire_of(sync)).replace("\"after\":9", "\"after\":9007199254740992"),
    );
    add(
        "sync_mailbox_id_upper_case",
        sync,
        st,
        "malformed",
        changed(sync, &|w| w["mailbox_id"] = json!(MAILBOX.to_uppercase())),
    );
    add(
        "sync_mailbox_id_not_a_uuid",
        sync,
        st,
        "malformed",
        changed(sync, &|w| w["mailbox_id"] = json!("mailbox-1")),
    );
    add(
        "sync_read_by_the_host",
        sync,
        ho,
        "wrong_message",
        text(&wire_of(sync)),
    );
    // mailbox_done
    let done = "mailbox_done";
    add(
        "done_unknown_field",
        done,
        st,
        "unknown_field",
        changed(done, &|w| w["extra"] = json!(1)),
    );
    add(
        "done_position_zero",
        done,
        st,
        "malformed",
        changed(done, &|w| w["position"] = json!(0)),
    );
    add(
        "done_position_missing",
        done,
        st,
        "malformed",
        changed(done, &|w| {
            w.as_object_mut().unwrap().remove("position");
        }),
    );
    // The Station's messages.
    let stored = "mailbox_stored";
    add(
        "stored_unknown_field",
        stored,
        ho,
        "unknown_field",
        changed(stored, &|w| w["extra"] = json!(1)),
    );
    add(
        "stored_id_missing",
        stored,
        ho,
        "malformed",
        changed(stored, &|w| {
            w.as_object_mut().unwrap().remove("id");
        }),
    );
    add(
        "stored_id_not_uuid_v4",
        stored,
        ho,
        "malformed",
        changed(stored, &|w| w["id"] = json!(v5)),
    );
    add(
        "stored_read_by_the_station",
        stored,
        st,
        "wrong_message",
        text(&wire_of(stored)),
    );
    let refused = "mailbox_put_refused_quota";
    add(
        "put_refused_code_unknown",
        "mailbox_put_refused",
        ho,
        "malformed",
        changed(refused, &|w| w["code"] = json!("busy")),
    );
    add(
        "put_refused_code_upper_case",
        "mailbox_put_refused",
        ho,
        "malformed",
        changed(refused, &|w| w["code"] = json!("Quota")),
    );
    add(
        "put_refused_id_missing",
        "mailbox_put_refused",
        ho,
        "malformed",
        changed(refused, &|w| {
            w.as_object_mut().unwrap().remove("id");
        }),
    );
    let page = "mailbox_sync_result";
    let op_page = "mailbox_sync_result";
    add(
        "page_unknown_field",
        op_page,
        ho,
        "unknown_field",
        changed(page, &|w| w["extra"] = json!(1)),
    );
    add(
        "page_two_objects",
        op_page,
        ho,
        "too_large",
        changed(page, &|w| {
            let item = w["objects"][0].clone();
            let mut first = item.clone();
            first["position"] = json!(10);
            w["objects"] = json!([first, item]);
        }),
    );
    add(
        "page_object_at_after",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| w["objects"][0]["position"] = json!(9)),
    );
    add(
        "page_object_past_through",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| w["objects"][0]["position"] = json!(12)),
    );
    add(
        "page_position_zero",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| {
            w["after"] = json!(0);
            w["objects"][0]["position"] = json!(0);
        }),
    );
    add(
        "page_through_past_head",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| {
            w["through"] = json!(13);
        }),
    );
    add(
        "page_through_below_after",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| {
            w["through"] = json!(8);
            w["objects"] = json!([]);
        }),
    );
    add(
        "page_reset_through_not_head",
        op_page,
        ho,
        "malformed",
        changed("mailbox_sync_result_reset", &|w| w["through"] = json!(12)),
    );
    add(
        "page_reset_with_an_object",
        op_page,
        ho,
        "malformed",
        changed("mailbox_sync_result_reset", &|w| {
            w["objects"] = json!([{"position": 3, "object": objects.get("o1").to_json()}]);
        }),
    );
    add(
        "page_item_unknown_field",
        op_page,
        ho,
        "unknown_field",
        changed(page, &|w| w["objects"][0]["extra"] = json!(1)),
    );
    add(
        "page_item_without_object",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| {
            w["objects"][0].as_object_mut().unwrap().remove("object");
        }),
    );
    add(
        "page_objects_missing",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| {
            w.as_object_mut().unwrap().remove("objects");
        }),
    );
    add(
        "page_head_missing",
        op_page,
        ho,
        "malformed",
        changed(page, &|w| {
            w.as_object_mut().unwrap().remove("head");
        }),
    );
    add(
        "page_not_strict_inside_an_object",
        op_page,
        ho,
        "not_strict",
        {
            let t = text(&wire_of(page));
            t.replacen("\"sealed_hash\":", "\"v\":1,\"sealed_hash\":", 1)
        },
    );
    let done_result = "mailbox_done_result";
    add(
        "done_result_unknown_field",
        done_result,
        ho,
        "unknown_field",
        changed(done_result, &|w| w["extra"] = json!(1)),
    );
    add(
        "done_result_position_zero",
        done_result,
        ho,
        "malformed",
        changed(done_result, &|w| w["position"] = json!(0)),
    );
    let sync_refused = "mailbox_sync_refused";
    add(
        "sync_refused_names_a_request",
        sync_refused,
        ho,
        "unknown_field",
        changed(sync_refused, &|w| w["request_id"] = json!(R2)),
    );
    add(
        "sync_refused_names_a_mailbox",
        sync_refused,
        ho,
        "unknown_field",
        changed(sync_refused, &|w| w["mailbox_id"] = json!(MAILBOX)),
    );
    add(
        "sync_refused_code_quota",
        sync_refused,
        ho,
        "malformed",
        changed(sync_refused, &|w| w["code"] = json!("quota")),
    );
    add(
        "done_refused_code_busy",
        "mailbox_done_refused",
        ho,
        "malformed",
        changed("mailbox_done_refused", &|w| w["code"] = json!("busy")),
    );
    add("not_json", put, st, "not_strict", "not json".into());
    out
}

/// The texts at and over the bound, as recipes.
fn bounds(objects: &Objects) -> Vec<Value> {
    let at = big_put(objects, R1, MAX_MAILBOX_MESSAGE_BYTES);
    let over = big_put(objects, R1, MAX_MAILBOX_MESSAGE_BYTES + 1);
    let page_over = {
        let wire = MailboxDoneResult {
            request_id: R3.into(),
            mailbox_id: MAILBOX.into(),
            position: 11,
        }
        .to_json()
        .unwrap();
        let whole = text(&wire);
        // Spaces after the message: a done result of 524,289 bytes.
        fill_recipe(&whole, " ", MAX_MAILBOX_MESSAGE_BYTES + 1 - whole.len(), "")
    };
    vec![
        json!({
            "name": "put_at_the_bound",
            "op": "mailbox_put",
            "reader": "to_station",
            "note": "a put of exactly 524,288 bytes: read (its object's ct a run of zero bytes; the Station never opens it)",
            "wire_fill": at,
            "accepts": true,
        }),
        json!({
            "name": "put_over_the_bound",
            "op": "mailbox_put",
            "reader": "to_station",
            "note": "a byte more: refused before any parse",
            "wire_fill": over,
            "code": "too_large",
        }),
        json!({
            "name": "answer_over_the_bound",
            "op": "mailbox_done_result",
            "reader": "to_host",
            "note": "a host's reader keeps the same bound",
            "wire_fill": page_over,
            "code": "too_large",
        }),
    ]
}

// ---------------------------------------------------------------- heads

fn heads_base() -> Heads {
    Heads {
        feeds: vec![],
        membership: Head {
            seq: 10,
            hash: Hash32(derived("membership head")),
        },
    }
}

fn heads_cases() -> Vec<Value> {
    let with = |mailbox: Option<MailboxHead>| {
        HeadsWithMailbox {
            heads: heads_base(),
            mailbox,
        }
        .to_json()
        .unwrap()
    };
    let announced = with(Some(MailboxHead {
        mailbox_id: MAILBOX.into(),
        head: 12,
    }));
    let changed = |edit: &dyn Fn(&mut Value)| {
        let mut w = announced.clone();
        edit(&mut w);
        text(&w)
    };
    let accepted = |name: &str, reader: &str, note: &str, wire: String, mailbox: Option<Value>| {
        let mut case = json!({"name": name, "reader": reader, "note": note, "wire": wire});
        case["accepts"] = match mailbox {
            Some(m) => json!({"mailbox": m}),
            None => json!({}),
        };
        case
    };
    let refused = |name: &str, reader: &str, note: &str, wire: String, code: &str| json!({"name": name, "reader": reader, "note": note, "wire": wire, "code": code});
    let at_bound = {
        let whole = text(&announced);
        let (prefix, suffix) = whole.split_at(whole.find("[]").unwrap() + 1);
        let count = HEADS_MAX_BYTES - whole.len();
        let recipe = fill_recipe(prefix, " ", count, suffix);
        assert_eq!(from_recipe(&recipe).len(), HEADS_MAX_BYTES);
        recipe
    };
    let over_bound = {
        let mut r = at_bound.clone();
        r["count"] = json!(u(&r, "count") + 1);
        r["bytes"] = json!(HEADS_MAX_BYTES + 1);
        r
    };
    let fill_case = |name: &str, note: &str, recipe: Value, outcome: Value| {
        let mut case =
            json!({"name": name, "reader": "mailbox", "note": note, "wire_fill": recipe});
        for (k, v) in outcome.as_object().unwrap() {
            case[k] = v.clone();
        }
        case
    };
    vec![
        accepted(
            "heads_with_its_mailbox",
            "mailbox",
            "a host whose welcome lists host.senders reads its own mailbox's id and head",
            text(&announced),
            Some(json!({"mailbox_id": MAILBOX, "head": 12})),
        ),
        accepted(
            "heads_with_an_empty_mailbox",
            "mailbox",
            "head 0: nothing stored yet",
            changed(&|w| w["mailbox"]["head"] = json!(0)),
            Some(json!({"mailbox_id": MAILBOX, "head": 0})),
        ),
        accepted(
            "heads_without_a_mailbox",
            "mailbox",
            "optional at that reader: no mailbox announced, so host senders' gate stays closed",
            text(&with(None)),
            None,
        ),
        accepted(
            "heads_without_a_mailbox_read_strictly",
            "strict",
            "§11.4's heads, as every other host reads it",
            text(&with(None)),
            None,
        ),
        refused(
            "heads_with_a_mailbox_read_strictly",
            "strict",
            "§11.4's strict reader, every host's without host.senders, refuses the field",
            text(&announced),
            "unknown_field",
        ),
        refused(
            "mailbox_unknown_field",
            "mailbox",
            "exactly {mailbox_id, head}",
            changed(&|w| w["mailbox"]["extra"] = json!(1)),
            "unknown_field",
        ),
        refused(
            "mailbox_id_upper_case",
            "mailbox",
            "a lowercase UUID v4",
            changed(&|w| w["mailbox"]["mailbox_id"] = json!(MAILBOX.to_uppercase())),
            "malformed",
        ),
        refused(
            "mailbox_id_not_uuid_v4",
            "mailbox",
            "a lowercase UUID v4",
            changed(&|w| {
                w["mailbox"]["mailbox_id"] = json!("80160896-4fcd-5e6e-adac-98bac5497321")
            }),
            "malformed",
        ),
        refused(
            "mailbox_head_negative",
            "mailbox",
            "an integer from 0",
            changed(&|w| w["mailbox"]["head"] = json!(-1)),
            "malformed",
        ),
        refused(
            "mailbox_head_missing",
            "mailbox",
            "both fields",
            changed(&|w| {
                w["mailbox"].as_object_mut().unwrap().remove("head");
            }),
            "malformed",
        ),
        refused(
            "mailbox_null",
            "mailbox",
            "omitted, never null",
            changed(&|w| w["mailbox"] = Value::Null),
            "malformed",
        ),
        refused(
            "mailbox_not_an_object",
            "mailbox",
            "an object",
            changed(&|w| w["mailbox"] = json!(MAILBOX)),
            "malformed",
        ),
        fill_case(
            "heads_at_the_bound",
            "a heads with a mailbox of exactly 262,144 bytes (spaces in its feeds): read",
            at_bound,
            json!({"accepts": {"mailbox": {"mailbox_id": MAILBOX, "head": 12}}}),
        ),
        fill_case(
            "heads_over_the_bound",
            "a byte more: heads keeps §11.4's 256 KiB bound, mailbox or not",
            over_bound,
            json!({"code": "too_large"}),
        ),
    ]
}

/// A heads case read by its reader: the mailbox it announces (`Value::Null`
/// for none) or the code it refuses with.
fn read_heads(reader: &str, bytes: &[u8]) -> Result<Value, RelayError> {
    let accept = Accept {
        mailbox: reader == "mailbox",
    };
    match reader {
        "mailbox" | "strict" => Heads::decode_with(bytes, accept).map(|read| {
            read.mailbox
                .map(|m| json!({"mailbox_id": m.mailbox_id, "head": m.head}))
                .unwrap_or(Value::Null)
        }),
        other => panic!("no reader {other}"),
    }
}

// --------------------------------------------------------- object_hash

fn object_hash_cases(objects: &Objects) -> Vec<Value> {
    let o1 = objects.get("o1");
    let mut out = Vec::new();
    for (name, note, label) in [
        (
            "o1",
            "SHA-256(enc([jcs(body), sig, enc, ct])), sig, enc and ct as decoded bytes",
            "o1",
        ),
        (
            "o1_other",
            "another sealed part under o1's key: another object",
            "o1_other",
        ),
        (
            "o1_resigned",
            "o1's sealed part under a re-signed body: another object",
            "o1_resigned",
        ),
        ("r1", "an atem-result", "r1"),
    ] {
        let object = objects.get(label);
        out.push(json!({
            "name": name,
            "note": note,
            "object_text": text(&object.to_json()),
            "object_hash": object_hash(object).to_hex(),
        }));
    }
    let respaced_text = respaced(o1);
    assert_eq!(
        object_hash(&SignedObject::parse(respaced_text.as_bytes()).unwrap()),
        object_hash(o1)
    );
    out.push(json!({
        "name": "o1_serialized_again",
        "note": "o1 with its keys in another order and spaces: the same object, compared in canonical form",
        "object_text": respaced_text,
        "object_hash": object_hash(o1).to_hex(),
    }));
    out
}

// ------------------------------------------------------------ scenarios

fn link(host_id: &str, host_trust_gen: u64) -> LinkAssociation {
    LinkAssociation {
        account_id: ACCOUNT.into(),
        genesis_hash: genesis_hash(),
        host_id: host_id.into(),
        host_trust_gen,
        connection_id: CONNECTION.into(),
    }
}

fn host_json(host_id: &str, host_trust_gen: u64) -> Value {
    json!({"host_id": host_id, "host_trust_gen": host_trust_gen})
}

fn quotas_json(q: &Quotas) -> Value {
    let one = |q: Quota| json!({"objects": q.objects, "bytes": q.bytes});
    json!({"sender": one(q.sender), "receiver": one(q.receiver), "account": one(q.account)})
}

fn quotas_of(v: &Value) -> Quotas {
    let one = |q: &Value| Quota {
        objects: u(q, "objects"),
        bytes: u(q, "bytes"),
    };
    Quotas {
        sender: one(&v["sender"]),
        receiver: one(&v["receiver"]),
        account: one(&v["account"]),
    }
}

fn hosts_of(v: &Value) -> CurrentHosts {
    CurrentHosts::new(
        v.as_array()
            .unwrap()
            .iter()
            .map(|h| (s(h, "host_id").to_owned(), u(h, "host_trust_gen"))),
    )
}

fn outcome_json(o: &Outcome) -> Value {
    match o {
        Outcome::Stored { position } => json!({"outcome": "stored", "position": position}),
        Outcome::AlreadyStored { position } => {
            json!({"outcome": "already_stored", "position": position})
        }
        Outcome::PutRefused(code) => json!({"outcome": "put_refused", "code": code.code()}),
        Outcome::Dropped(Dropped::Unread(e)) => json!({"outcome": "dropped", "why": e.code()}),
        Outcome::Dropped(Dropped::Unserved) => json!({"outcome": "dropped", "why": "unserved"}),
        Outcome::Page {
            through,
            position,
            reset,
        } => {
            let mut v = json!({"outcome": "page", "through": through, "reset": reset});
            if let Some(p) = position {
                v["position"] = json!(p);
            }
            v
        }
        Outcome::Done { removed } => json!({"outcome": "done", "removed": removed}),
        Outcome::Refused(call) => json!({"outcome": "refused", "op": call.op()}),
        Outcome::Heads { mailbox } => {
            let mut v = json!({"outcome": "heads"});
            if let Some(m) = mailbox {
                v["mailbox"] = json!({"mailbox_id": m.mailbox_id, "head": m.head});
            }
            v
        }
    }
}

fn state_json(m: &ReferenceMailbox) -> Value {
    let mailboxes: Vec<Value> = m
        .receivers()
        .map(|(host_id, host_trust_gen)| {
            let head = m.mailbox(host_id, host_trust_gen).unwrap();
            json!({
                "host_id": host_id,
                "host_trust_gen": host_trust_gen,
                "mailbox_id": head.mailbox_id,
                "head": head.head,
                "stored": m.stored(host_id, host_trust_gen).iter().map(|v| json!({
                    "position": v.position,
                    "sender": v.sender,
                    "id": v.id,
                    "object_hash": v.object_hash.to_hex(),
                    "bytes": v.bytes,
                    "expires_at": v.expires_at,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({"dropped": m.dropped(), "mailboxes": mailboxes})
}

/// A scenario being written: the reference mailbox it runs on and the
/// events so far, each with the outcome written here by hand, checked
/// against the mailbox's.
struct Scenario<'a> {
    objects: &'a Objects,
    number: u64,
    calls: u64,
    file: Value,
    m: ReferenceMailbox,
}

const A: (&str, u64) = ("host-a", 1);
const B: (&str, u64) = ("host-b", 1);
const EVIL: (&str, u64) = ("host-evil", 1);

impl<'a> Scenario<'a> {
    fn new(objects: &'a Objects, number: u64, name: &str, note: &str, quotas: Quotas) -> Self {
        let hosts = [A, B, EVIL];
        let m = ReferenceMailbox::new(ACCOUNT, genesis_hash(), quotas, seed())
            .unwrap()
            .list_moved(CurrentHosts::new(
                hosts.iter().map(|(h, g)| (h.to_string(), *g)),
            ));
        let file = json!({
            "name": name,
            "note": note,
            "quotas": quotas_json(&quotas),
            "hosts": hosts.iter().map(|(h, g)| host_json(h, *g)).collect::<Vec<_>>(),
            "events": [],
        });
        Scenario {
            objects,
            number,
            calls: 0,
            file,
            m,
        }
    }

    fn request_id(&mut self) -> String {
        self.calls += 1;
        format!("{:08x}-0000-4000-8000-{:012x}", self.number, self.calls)
    }

    fn push(&mut self, mut event: Value, note: &str) {
        if !note.is_empty() {
            event["note"] = json!(note);
        }
        event["state"] = state_json(&self.m);
        self.file["events"].as_array_mut().unwrap().push(event);
    }

    /// A call's bytes from `caller` at `at`, with its expected outcome.
    fn call_bytes(
        &mut self,
        at: u64,
        caller: (&str, u64),
        call: Value,
        bytes: &[u8],
        expect: Value,
        note: &str,
    ) {
        let t = self.m.call(&link(caller.0, caller.1), bytes, at).unwrap();
        assert_eq!(
            outcome_json(&t.outcome),
            expect,
            "{}: {note}",
            self.file["name"]
        );
        self.m = t.next;
        let mut event = json!({"event": "call", "at": at, "caller": host_json(caller.0, caller.1)});
        for (k, v) in call.as_object().unwrap() {
            event[k] = v.clone();
        }
        event["expect"] = expect;
        if let Some(answer) = t.answer {
            event["answer"] = json!(text(&answer));
        }
        self.push(event, note);
    }

    fn call(&mut self, at: u64, caller: (&str, u64), text: String, expect: Value, note: &str) {
        let bytes = text.clone().into_bytes();
        self.call_bytes(at, caller, json!({"call": text}), &bytes, expect, note);
    }

    fn call_fill(
        &mut self,
        at: u64,
        caller: (&str, u64),
        recipe: Value,
        expect: Value,
        note: &str,
    ) {
        let bytes = from_recipe(&recipe).into_bytes();
        self.call_bytes(
            at,
            caller,
            json!({"call_fill": recipe}),
            &bytes,
            expect,
            note,
        );
    }

    fn put(&mut self, at: u64, caller: (&str, u64), label: &str, expect: Value, note: &str) {
        let put = MailboxPut {
            request_id: self.request_id(),
            object: self.objects.get(label).clone(),
        };
        self.call(at, caller, text(&put.to_json().unwrap()), expect, note);
    }

    fn sync(
        &mut self,
        at: u64,
        caller: (&str, u64),
        mailbox_id: &str,
        after: u64,
        expect: Value,
        note: &str,
    ) {
        let sync = MailboxSync {
            request_id: self.request_id(),
            mailbox_id: mailbox_id.into(),
            after,
        };
        self.call(at, caller, text(&sync.to_json().unwrap()), expect, note);
    }

    fn done(
        &mut self,
        at: u64,
        caller: (&str, u64),
        mailbox_id: &str,
        position: u64,
        expect: Value,
        note: &str,
    ) {
        let done = MailboxDone {
            request_id: self.request_id(),
            mailbox_id: mailbox_id.into(),
            position,
        };
        self.call(at, caller, text(&done.to_json().unwrap()), expect, note);
    }

    /// The caller's mailbox id now (minted if needed by a heads first).
    fn mailbox_id(&self, host: (&str, u64)) -> String {
        self.m.mailbox(host.0, host.1).unwrap().mailbox_id
    }

    fn heads(
        &mut self,
        at: u64,
        caller: (&str, u64),
        host_senders: bool,
        expect_head: Option<u64>,
        note: &str,
    ) {
        let t = self
            .m
            .heads(&link(caller.0, caller.1), &heads_base(), host_senders, at)
            .unwrap();
        let got = match &t.outcome {
            Outcome::Heads { mailbox } => mailbox.as_ref().map(|m| m.head),
            other => panic!("{other:?}"),
        };
        assert_eq!(got, expect_head, "{}: {note}", self.file["name"]);
        let expect = outcome_json(&t.outcome);
        self.m = t.next;
        let event = json!({
            "event": "heads",
            "at": at,
            "caller": host_json(caller.0, caller.1),
            "host_senders": host_senders,
            "expect": expect,
            "answer": text(&t.answer.unwrap()),
        });
        self.push(event, note);
    }

    fn reset(&mut self, host: (&str, u64), reset: Reset, note: &str) {
        self.m = self.m.reset(host.0, host.1, reset).unwrap();
        let reset = match reset {
            Reset::NewMailbox => json!("new_mailbox"),
            Reset::HeadBack { head } => json!({"head_back": head}),
        };
        let event =
            json!({"event": "reset", "host_id": host.0, "host_trust_gen": host.1, "reset": reset});
        self.push(event, note);
    }

    fn hosts(&mut self, hosts: &[(&str, u64)], note: &str) {
        self.m = self.m.list_moved(CurrentHosts::new(
            hosts.iter().map(|(h, g)| (h.to_string(), *g)),
        ));
        let event = json!({
            "event": "hosts",
            "hosts": hosts.iter().map(|(h, g)| host_json(h, *g)).collect::<Vec<_>>(),
        });
        self.push(event, note);
    }

    fn tick(&mut self, at: u64, note: &str) {
        self.m = self.m.tick(at);
        self.push(json!({"event": "tick", "at": at}), note);
    }

    fn finish(self) -> Value {
        self.file
    }
}

fn stored(position: u64) -> Value {
    json!({"outcome": "stored", "position": position})
}

fn already(position: u64) -> Value {
    json!({"outcome": "already_stored", "position": position})
}

fn put_refused(code: &str) -> Value {
    json!({"outcome": "put_refused", "code": code})
}

fn page(through: u64, position: Option<u64>) -> Value {
    let mut v = json!({"outcome": "page", "through": through, "reset": false});
    if let Some(p) = position {
        v["position"] = json!(p);
    }
    v
}

fn reset_page(through: u64) -> Value {
    json!({"outcome": "page", "through": through, "reset": true})
}

fn done(removed: bool) -> Value {
    json!({"outcome": "done", "removed": removed})
}

fn refused(op: &str) -> Value {
    json!({"outcome": "refused", "op": op})
}

fn dropped(why: &str) -> Value {
    json!({"outcome": "dropped", "why": why})
}

fn scenarios(objects: &Objects) -> Vec<Value> {
    let at = |minutes: u64| T0 + minutes * MINUTE;
    let mut out = Vec::new();
    let roomy = Quota {
        objects: 1024,
        bytes: 1 << 30,
    };

    // 1
    let mut sc = Scenario::new(
        objects,
        1,
        "put_then_the_same_object_again",
        "a put is stored at the next position of its recipient's mailbox; the same object again, under a fresh request_id or serialized again, is answered mailbox_stored and charged once",
        Quotas::default(),
    );
    sc.heads(at(1), B, true, Some(0), "host-b's heads mints its mailbox");
    sc.put(at(1), A, "o1", stored(1), "");
    sc.put(
        at(2),
        A,
        "o1",
        already(1),
        "a retry with a fresh request_id",
    );
    let again = format!(
        "{{\"type\":\"relay\",\"op\":\"mailbox_put\",\"request_id\":\"{}\",\"object\":{}}}",
        sc.request_id(),
        respaced(objects.get("o1"))
    );
    sc.call(
        at(3),
        A,
        again,
        already(1),
        "o1 serialized again (keys in another order, spaces): the same object_hash",
    );
    sc.heads(at(3), B, true, Some(1), "");
    let mailbox = sc.mailbox_id(B);
    sc.sync(at(4), B, &mailbox, 0, page(1, Some(1)), "");
    out.push(sc.finish());

    // 2
    let mut sc = Scenario::new(
        objects,
        2,
        "other_bytes_under_the_same_key",
        "another object under (host-a, o1's id) is id_reused and the first stays; the same id from another sending host is another key",
        Quotas::default(),
    );
    sc.put(at(1), A, "o1", stored(1), "");
    sc.put(
        at(2),
        A,
        "o1_other",
        put_refused("id_reused"),
        "another sealed part",
    );
    sc.put(
        at(3),
        A,
        "o1_resigned",
        put_refused("id_reused"),
        "the same sealed part signed again: other bytes",
    );
    sc.put(
        at(4),
        EVIL,
        "e_o1",
        stored(2),
        "host-evil's object with o1's id",
    );
    sc.put(at(5), A, "o1", already(1), "the first stays");
    out.push(sc.finish());

    // 3
    let one = objects.get("o1").to_json().to_string().len() as u64;
    let mut sc = Scenario::new(
        objects,
        3,
        "quotas_per_sending_host_receiving_host_and_account",
        "quotas of 2 objects per sending host, 3 per receiving host and 4 per account (bytes roomy): each refuses `quota`, a stored retry is never charged twice even at the limit, and done frees the quota",
        Quotas {
            sender: Quota {
                objects: 2,
                bytes: roomy.bytes,
            },
            receiver: Quota {
                objects: 3,
                bytes: roomy.bytes,
            },
            account: Quota {
                objects: 4,
                bytes: roomy.bytes,
            },
        },
    );
    sc.put(at(1), A, "o1", stored(1), "");
    sc.put(at(1), A, "o2", stored(2), "");
    sc.put(
        at(2),
        A,
        "o3",
        put_refused("quota"),
        "host-a holds 2 objects: its sending quota",
    );
    sc.put(
        at(2),
        A,
        "o1",
        already(1),
        "a stored retry at the limit: answered stored, charged nothing",
    );
    sc.put(at(3), EVIL, "e1", stored(3), "another sending host");
    sc.put(
        at(3),
        EVIL,
        "e2",
        put_refused("quota"),
        "host-b's mailbox holds 3: its receiving quota",
    );
    sc.put(
        at(4),
        B,
        "r1",
        stored(1),
        "host-b to host-a: the account's 4th object",
    );
    sc.put(
        at(4),
        EVIL,
        "e_to_a",
        put_refused("quota"),
        "the account holds 4",
    );
    sc.heads(at(5), B, true, Some(3), "");
    let mailbox = sc.mailbox_id(B);
    sc.done(at(5), B, &mailbox, 1, done(true), "done frees o1's quota");
    sc.put(at(6), A, "o3", stored(4), "");
    out.push(sc.finish());

    // 4
    let mut sc = Scenario::new(
        objects,
        4,
        "quota_in_encoded_bytes",
        "a sending host's quota of twice o1's encoded size (its compact JSON): the third object of the same size is refused",
        Quotas {
            sender: Quota {
                objects: 100,
                bytes: 2 * one,
            },
            receiver: roomy,
            account: roomy,
        },
    );
    sc.put(at(1), A, "o1", stored(1), "");
    sc.put(at(1), A, "o2", stored(2), "");
    sc.put(at(2), A, "o3", put_refused("quota"), "");
    out.push(sc.finish());

    // 5
    let mut sc = Scenario::new(
        objects,
        5,
        "pages_over_removed_and_expired_positions",
        "a page lists at most one object, and its fixed through covers every position marked done or expired up to the next stored object, or the head",
        Quotas::default(),
    );
    for (n, label) in ["o1", "o2", "o3", "o4", "short", "o5"].iter().enumerate() {
        sc.put(at(1), A, label, stored(n as u64 + 1), "");
    }
    sc.heads(at(1), B, true, Some(6), "");
    let mailbox = sc.mailbox_id(B);
    sc.done(at(2), B, &mailbox, 2, done(true), "");
    sc.done(at(2), B, &mailbox, 3, done(true), "");
    sc.sync(
        at(3),
        B,
        &mailbox,
        0,
        page(3, Some(1)),
        "o1, then 2 and 3 done",
    );
    sc.sync(at(3), B, &mailbox, 3, page(4, Some(4)), "");
    sc.sync(
        at(10),
        B,
        &mailbox,
        4,
        page(6, Some(6)),
        "`short` (position 5) expired at minute 10",
    );
    sc.sync(at(11), B, &mailbox, 6, page(6, None), "read to the head");
    sc.sync(
        at(11),
        B,
        &mailbox,
        9,
        reset_page(6),
        "a cursor past the head gets the reset page",
    );
    out.push(sc.finish());

    // 6
    let mut sc = Scenario::new(
        objects,
        6,
        "only_the_mailboxs_own_host_syncs_and_marks_done",
        "sync and done name only the caller's own mailbox (forbidden otherwise, nothing served or removed); done answers the same when nothing is there",
        Quotas::default(),
    );
    sc.put(at(1), A, "o1", stored(1), "");
    sc.put(at(1), A, "o2", stored(2), "");
    sc.heads(at(2), B, true, Some(2), "");
    sc.heads(
        at(2),
        EVIL,
        true,
        Some(0),
        "host-evil has a mailbox of its own",
    );
    let mailbox = sc.mailbox_id(B);
    sc.done(
        at(3),
        EVIL,
        &mailbox,
        1,
        refused("mailbox_done_refused"),
        "host-evil names host-b's mailbox",
    );
    sc.sync(
        at(3),
        EVIL,
        &mailbox,
        0,
        refused("mailbox_sync_refused"),
        "",
    );
    sc.sync(
        at(3),
        A,
        &mailbox,
        0,
        refused("mailbox_sync_refused"),
        "the sending host neither",
    );
    let unknown = uuid4("unknown mailbox");
    sc.sync(
        at(3),
        B,
        &unknown,
        0,
        refused("mailbox_sync_refused"),
        "an id no mailbox has",
    );
    sc.done(at(4), B, &mailbox, 1, done(true), "");
    sc.done(
        at(4),
        B,
        &mailbox,
        1,
        done(false),
        "again: nothing there, the same answer",
    );
    sc.done(
        at(4),
        B,
        &mailbox,
        9,
        done(false),
        "beyond the head: the same answer",
    );
    sc.sync(at(5), B, &mailbox, 0, page(2, Some(2)), "");
    out.push(sc.finish());

    // 7
    let mut sc = Scenario::new(
        objects,
        7,
        "reset_under_a_new_mailbox_id",
        "a Station that can't vouch for a mailbox's positions mints a new one: what it held is lost, the old id is refused forbidden, and the senders' resends are stored again from position 1",
        Quotas::default(),
    );
    sc.put(at(1), A, "o1", stored(1), "");
    sc.put(at(1), A, "o2", stored(2), "");
    sc.heads(at(1), B, true, Some(2), "");
    let old = sc.mailbox_id(B);
    sc.sync(at(2), B, &old, 0, page(1, Some(1)), "");
    sc.reset(B, Reset::NewMailbox, "a lost store");
    sc.heads(at(3), B, true, Some(0), "the new id");
    let new = sc.mailbox_id(B);
    sc.sync(
        at(3),
        B,
        &old,
        1,
        refused("mailbox_sync_refused"),
        "the old id: never answered on the new mailbox",
    );
    sc.done(at(3), B, &old, 1, refused("mailbox_done_refused"), "");
    sc.sync(at(3), B, &new, 0, page(0, None), "");
    sc.put(at(4), A, "o1", stored(1), "host-a's resend, charged again");
    sc.sync(at(4), B, &new, 0, page(1, Some(1)), "");
    out.push(sc.finish());

    // 8
    let mut sc = Scenario::new(
        objects,
        8,
        "reset_with_the_head_back_under_the_same_id",
        "a mailbox gone back under its id (a Station's fault): what it stored after the new head is lost, a cursor past the head gets the reset page, and the next object is stored after the head",
        Quotas::default(),
    );
    for (n, label) in ["o1", "o2", "o3", "o4"].iter().enumerate() {
        sc.put(at(1), A, label, stored(n as u64 + 1), "");
    }
    sc.heads(at(1), B, true, Some(4), "");
    let mailbox = sc.mailbox_id(B);
    sc.sync(
        at(2),
        B,
        &mailbox,
        3,
        page(4, Some(4)),
        "the host has read to 4",
    );
    sc.reset(
        B,
        Reset::HeadBack { head: 2 },
        "back to head 2 under the same id",
    );
    sc.heads(
        at(3),
        B,
        true,
        Some(2),
        "the same id, head 2: below the host's cursor",
    );
    sc.sync(at(3), B, &mailbox, 4, reset_page(2), "");
    sc.sync(
        at(3),
        B,
        &mailbox,
        0,
        page(1, Some(1)),
        "the host reads from 0",
    );
    sc.put(at(4), A, "o3", stored(3), "o3's key was freed with it");
    out.push(sc.finish());

    // 9
    let mut sc = Scenario::new(
        objects,
        9,
        "undecided_overflow_marked_done_is_read_again",
        "the receiver's back-pressure (rule 5, Atem's refinement agreed with Astation): an object the host drops undecided over its pending limits is marked done all the same, so the sender's identical resend is stored again, at a new position, charged again, and read again",
        Quotas::default(),
    );
    sc.put(at(1), A, "o1", stored(1), "");
    sc.heads(at(1), B, true, Some(1), "");
    let mailbox = sc.mailbox_id(B);
    sc.sync(at(2), B, &mailbox, 0, page(1, Some(1)), "");
    sc.done(
        at(2),
        B,
        &mailbox,
        1,
        done(true),
        "dropped undecided over the pending limits, and marked done",
    );
    sc.put(
        at(12),
        A,
        "o1",
        stored(2),
        "host-a's resend 10 minutes later: a new delivery",
    );
    sc.heads(at(12), B, true, Some(2), "");
    sc.sync(
        at(12),
        B,
        &mailbox,
        1,
        page(2, Some(2)),
        "read again, judged anew",
    );
    out.push(sc.finish());

    // 10
    let mut sc = Scenario::new(
        objects,
        10,
        "undecided_overflow_left_undone_is_never_read_again",
        "what rule 5's refinement avoids: left behind the cursor without a done, the object keeps its key, so the sender's identical resend is answered stored at the old position and never read again until it expires",
        Quotas::default(),
    );
    sc.put(at(1), A, "o1", stored(1), "");
    sc.heads(at(1), B, true, Some(1), "");
    let mailbox = sc.mailbox_id(B);
    sc.sync(at(2), B, &mailbox, 0, page(1, Some(1)), "no done follows");
    sc.put(
        at(12),
        A,
        "o1",
        already(1),
        "host-a's resend: the same object, still stored",
    );
    sc.sync(
        at(12),
        B,
        &mailbox,
        1,
        page(1, None),
        "nothing after the cursor",
    );
    sc.tick(at(60), "o1's expires_at");
    sc.put(at(60), A, "o1", put_refused("expired"), "");
    out.push(sc.finish());

    // 11
    let mut sc = Scenario::new(
        objects,
        11,
        "expiry_by_the_clock",
        "an object is removed at its expires_at, its key and quota freed; a put at or past its expires_at, or with expires_at not after created_at or more than 24 hours after it, is expired",
        Quotas::default(),
    );
    sc.put(at(1), A, "short", stored(1), "expires at minute 10");
    sc.tick(at(10) - 1, "a millisecond before");
    sc.tick(at(10), "removed");
    sc.put(
        at(10),
        A,
        "short",
        put_refused("expired"),
        "the clock at its expires_at",
    );
    sc.put(
        at(10),
        A,
        "long",
        put_refused("expired"),
        "24 hours and 1 ms",
    );
    sc.put(
        at(10),
        A,
        "equal",
        put_refused("expired"),
        "expires_at equal to created_at",
    );
    sc.put(
        at(10),
        A,
        "before",
        put_refused("expired"),
        "expires_at before created_at",
    );
    sc.put(at(10), A, "day", stored(2), "exactly 24 hours");
    out.push(sc.finish());

    // 12
    let mut sc = Scenario::new(
        objects,
        12,
        "forbidden_puts",
        "a put comes from a current host of the account with its own objects, to a current host at the generation the object names; any other is forbidden",
        Quotas::default(),
    );
    sc.put(
        at(1),
        EVIL,
        "o1",
        put_refused("forbidden"),
        "host-a's object, put by host-evil",
    );
    sc.put(at(1), A, "other_account", put_refused("forbidden"), "");
    sc.put(at(1), A, "other_root", put_refused("forbidden"), "");
    sc.put(
        at(1),
        A,
        "to_b2",
        put_refused("forbidden"),
        "host-b isn't current at generation 2",
    );
    sc.put(at(1), A, "to_z", put_refused("forbidden"), "");
    sc.put(
        at(1),
        ("host-a", 2),
        "o1",
        put_refused("forbidden"),
        "a link of host-a at generation 2, which isn't current",
    );
    sc.put(
        at(1),
        A,
        "sender_gen_2",
        stored(1),
        "the body's sender generation is the receiver's to judge (rule 1 names the host)",
    );
    sc.hosts(
        &[A, EVIL],
        "host-b removed from the Station's copy of the list",
    );
    sc.put(at(2), A, "o2", put_refused("forbidden"), "");
    out.push(sc.finish());

    // 13
    let mut sc = Scenario::new(
        objects,
        13,
        "calls_the_station_drops",
        "a call the shared core's reader refuses gets no answer: the Station drops and counts it, and the sender retires it at its deadline; so does a put whose object no page could carry",
        Quotas::default(),
    );
    sc.call(at(1), A, "not json".into(), dropped("not_strict"), "");
    let mut no_id = MailboxPut {
        request_id: sc.request_id(),
        object: objects.get("o1").clone(),
    }
    .to_json()
    .unwrap();
    no_id["object"]["body"]
        .as_object_mut()
        .unwrap()
        .remove("id");
    sc.call(
        at(1),
        A,
        text(&no_id),
        dropped("malformed"),
        "no id in its body",
    );
    let mut short_enc = MailboxPut {
        request_id: sc.request_id(),
        object: objects.get("o1").clone(),
    }
    .to_json()
    .unwrap();
    short_enc["object"]["enc"] = json!(atem_client::encoding::b64u(&[7u8; 31]));
    sc.call(
        at(1),
        A,
        text(&short_enc),
        dropped("malformed"),
        "a sealed part of the wrong shape",
    );
    let answer = MailboxStored {
        request_id: sc.request_id(),
        id: uuid4("id o1"),
    }
    .to_json()
    .unwrap();
    sc.call(
        at(1),
        A,
        text(&answer),
        dropped("wrong_message"),
        "a Station's message, sent to it",
    );
    let request_id = sc.request_id();
    let at_bound = big_put(objects, &request_id, MAX_MAILBOX_MESSAGE_BYTES);
    sc.call_fill(at(1), A, at_bound, dropped("unserved"), "a put of exactly 524,288 bytes: read, but no page could carry its object (Atem's reading, for Astation's agreement)");
    let request_id = sc.request_id();
    let over = big_put(objects, &request_id, MAX_MAILBOX_MESSAGE_BYTES + 1);
    sc.call_fill(at(1), A, over, dropped("too_large"), "");
    sc.put(at(2), A, "o1", stored(1), "nothing was stored before");
    out.push(sc.finish());

    // 14
    let mut sc = Scenario::new(
        objects,
        14,
        "heads_with_and_without_host_senders",
        "heads carries the caller's own mailbox only for a host whose welcome lists host.senders",
        Quotas::default(),
    );
    sc.heads(
        at(1),
        B,
        false,
        None,
        "without host.senders: §11.4's heads, no mailbox minted",
    );
    sc.heads(at(1), B, true, Some(0), "");
    sc.put(at(2), A, "o1", stored(1), "");
    sc.heads(at(2), B, true, Some(1), "");
    sc.heads(at(2), EVIL, true, Some(0), "each host its own");
    sc.heads(at(2), B, false, None, "");
    out.push(sc.finish());

    out
}

// ----------------------------------------------------------------- file

const NOTE: &str = "The mailbox calls of host-work-v1 §11.5 (rules 1 to 11, agreed with Astation 2026-11-16) as the shared core's builders write them and its readers read them, and scenarios run against the Station's reference mailbox (atem_client::host_mail::reference::ReferenceMailbox). `objects`: the mailbox objects the calls carry ({label, note, object, object_hash, bytes}; `bytes` is the object's compact JSON, what a page carries and the quotas count), atem-envelope and atem-result objects sealed and signed by host-a, host-b and host-evil with their r9-vectors-keys host keys (the Station reads the body only and never verifies or opens). `object_hash`: known answers of SHA-256(enc([jcs(body), sig, enc, ct])), sig, enc and ct as decoded bytes, over `object_text` (a copy serialized again is the same object). `calls`: every valid message {name, op, direction, note, fields, wire}: `wire` is the exact text (compact, keys in RFC 8785 order, the builders' order), `direction` the reader that reads it (to_station: a host's call; to_host: a Station's answer; the other refuses it as wrong_message), `fields` what it reads as (a page's object as a value). `invalid`: texts a reader refuses {name, op, reader, code, wire}, one fault each, with the code the reader gives: too_large (over `max_message_bytes`, before any parse), not_strict, wrong_message, unknown_field or malformed. `bounds`: texts at and over the bound as `wire_fill` recipes ({prefix, fill, count, suffix, bytes}: prefix, count times fill, suffix), `accepts` or a `code`. `heads`: the calling host's mailbox head in heads (rule 6), read with the mailbox (`reader: mailbox`, a host whose welcome lists host.senders) or strictly (`reader: strict`, every other host): `accepts.mailbox` (absent: none announced) or a `code`; heads keeps its 256 KiB bound (`max_heads_bytes`). `scenarios`: event sequences against a fresh reference mailbox of the device list (`link.account_id`, `link.genesis_hash`) with the scenario's `quotas` and current `hosts`, seeded with `seed_hex`: each mailbox_id is the first 16 bytes of SHA-256(enc([\"atem-reference-mailbox-id-v1\", seed, account_id, genesis_hash (32 bytes), host_id, u64(host_trust_gen), u64(n)])) as a lowercase UUID v4 (version 4, variant 10), n counting the mailboxes minted for that receiving host from 0 (a Station mints a random one; the seed makes the vectors reproducible). Events: `call` (the bytes `call`, or the `call_fill` recipe, received at `at` ms on the link of `caller`, of `link`'s account, genesis and connection), `heads` (`heads_base` sent to `caller` at `at`, with `host_senders`), `reset` (of a receiving host's mailbox: `new_mailbox`, or `head_back` to a head under the same id), `hosts` (the Station's copy of the device list moved to these current hosts) and `tick` (the clock at `at`). Each call or heads gives `expect` (the outcome: stored or already_stored at a position, put_refused with a code, dropped with why: a reader's code or `unserved`, page with its through, position and reset, done with removed, refused with the refusal's op, heads with the mailbox announced) and `answer` (the exact text sent back; none when dropped). Every event gives `state` after it: dropped calls, and each mailbox minted (receiving host, mailbox_id, head, stored objects: position, sender, id, object_hash, bytes, expires_at). The model's rules: every transition first removes each object whose expires_at is at or before its time; a call the reader refuses is dropped and counted; a put whose object's compact JSON is over `max_served_object_bytes` (no page could carry it at any position) is dropped too (Atem's reading, for Astation's agreement); a put is forbidden unless the caller is a current host at its link's generation, the body's sender host, of the link's account and genesis, and the recipient a current host at the generation it names; expired at or past its expires_at, with expires_at not after created_at, or more than `max_lifetime_ms` after it; then the key (calling host, body id) in the recipient's mailbox: the same object_hash is already_stored (charged nothing), another id_reused; then the quotas per sending host (its objects in every mailbox), receiving host (its mailbox) and account (every mailbox), objects and bytes; then stored at head + 1, which mints the recipient's mailbox if it has none. A sync or done naming anything but the caller's own mailbox is refused; a page lists the first stored object after `after` and its through is the position before the next stored object, or the head; with `after` past the head it is the reset page; a done removes what is at its position, if anything. A heads with host_senders mints the caller's mailbox if it has none. A reset to a new mailbox mints the next id and loses everything the old one held; head_back loses what was stored after that head and stores the next object after it.";

fn mailbox_call_vectors() -> Value {
    let objects = Objects::make();
    let calls = calls(&objects);
    let invalid = invalid(&objects, &calls);
    let file = json!({
        "name": FILE,
        "kind": "vectors",
        "requires": "r9",
        "note": NOTE,
        "max_message_bytes": MAX_MAILBOX_MESSAGE_BYTES,
        "max_heads_bytes": HEADS_MAX_BYTES,
        "max_served_object_bytes": MAX_SERVED_OBJECT_BYTES,
        "max_lifetime_ms": MAX_LIFETIME_MS,
        "link": {
            "account_id": ACCOUNT,
            "genesis_hash": genesis_hash().to_hex(),
            "connection_id": CONNECTION,
        },
        "seed_hex": hex(&seed()),
        "heads_base": text(&heads_base().to_json().unwrap()),
        "objects": objects.file(),
        "object_hash": object_hash_cases(&objects),
        "calls": calls,
        "invalid": invalid,
        "bounds": bounds(&objects),
        "heads": heads_cases(),
        "scenarios": scenarios(&objects),
    });
    // Every invalid text is refused as the case says, while it is written.
    for case in file["invalid"].as_array().unwrap() {
        let got = read(s(case, "reader"), s(case, "wire").as_bytes()).map(drop);
        assert!(
            same_code(got.clone(), s(case, "code")),
            "{}: {got:?}",
            case["name"]
        );
    }
    file
}

/// Codes compared by name (`Malformed` carries the field).
fn same_code(got: Result<(), RelayError>, code: &str) -> bool {
    matches!(got, Err(e) if e.code() == code)
}

fn file() -> Value {
    load(FILE)
}

// --------------------------------------------------------------- tests

/// Writes the file from `mailbox_call_vectors`.
#[test]
#[ignore = "writes the mailbox-calls vectors"]
fn write_mailbox_call_vectors() {
    let mut text = serde_json::to_string_pretty(&mailbox_call_vectors()).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join(format!("{FILE}.json")), text).unwrap();
}

#[test]
fn mailbox_calls_file_is_what_the_shared_core_makes() {
    let file = file();
    assert_eq!(file["name"], FILE);
    assert_eq!(file["kind"], "vectors");
    assert_eq!(file["requires"], "r9");
    let keys: BTreeSet<&str> = file
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "name",
            "kind",
            "requires",
            "note",
            "max_message_bytes",
            "max_heads_bytes",
            "max_served_object_bytes",
            "max_lifetime_ms",
            "link",
            "seed_hex",
            "heads_base",
            "objects",
            "object_hash",
            "calls",
            "invalid",
            "bounds",
            "heads",
            "scenarios",
        ])
    );
    assert_eq!(
        file,
        mailbox_call_vectors(),
        "regenerate with write_mailbox_call_vectors"
    );
}

#[test]
fn mailbox_calls_build_and_read_byte_for_byte() {
    let file = file();
    assert_eq!(
        u(&file, "max_message_bytes") as usize,
        MAX_MAILBOX_MESSAGE_BYTES
    );
    let mut ops = BTreeSet::new();
    for case in file["calls"].as_array().unwrap() {
        let name = s(case, "name");
        let op = s(case, "op");
        let wire = s(case, "wire");
        assert_eq!(text(&build(op, &case["fields"])), wire, "{name}: built");
        let direction = s(case, "direction");
        assert_eq!(
            read(direction, wire.as_bytes()).unwrap(),
            case["fields"],
            "{name}: read"
        );
        let other = if direction == "to_station" {
            "to_host"
        } else {
            "to_station"
        };
        assert_eq!(
            read(other, wire.as_bytes()),
            Err(RelayError::WrongMessage),
            "{name}"
        );
        ops.insert(op.to_owned());
    }
    assert_eq!(
        ops,
        atem_client::host_mail::mailbox::op::ALL
            .iter()
            .map(|op| op.to_string())
            .collect(),
        "every call and answer has a case"
    );
    // The put refusals: one case per code.
    let codes: BTreeSet<&str> = file["calls"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["op"] == "mailbox_put_refused")
        .map(|c| s(&c["fields"], "code"))
        .collect();
    assert_eq!(
        codes,
        BTreeSet::from(["quota", "id_reused", "expired", "forbidden"])
    );
}

#[test]
fn mailbox_calls_refuse_the_invalid_texts() {
    let file = file();
    for case in file["invalid"].as_array().unwrap() {
        let got = read(s(case, "reader"), s(case, "wire").as_bytes()).map(drop);
        assert!(
            same_code(got.clone(), s(case, "code")),
            "{}: {got:?}",
            case["name"]
        );
    }
    for case in file["bounds"].as_array().unwrap() {
        let name = s(case, "name");
        let wire = from_recipe(&case["wire_fill"]);
        assert_eq!(wire.len() as u64, u(&case["wire_fill"], "bytes"), "{name}");
        let got = read(s(case, "reader"), wire.as_bytes()).map(drop);
        match case.get("code") {
            Some(code) => assert!(same_code(got, code.as_str().unwrap()), "{name}"),
            None => assert_eq!(got, Ok(()), "{name}"),
        }
    }
}

#[test]
fn mailbox_heads_forms() {
    let file = file();
    assert_eq!(u(&file, "max_heads_bytes") as usize, HEADS_MAX_BYTES);
    for case in file["heads"].as_array().unwrap() {
        let name = s(case, "name");
        let wire = match case.get("wire_fill") {
            Some(recipe) => from_recipe(recipe),
            None => s(case, "wire").to_owned(),
        };
        let got = read_heads(s(case, "reader"), wire.as_bytes());
        match case.get("code") {
            Some(code) => assert!(same_code(got.map(drop), code.as_str().unwrap()), "{name}"),
            None => assert_eq!(
                got.unwrap(),
                case["accepts"]
                    .get("mailbox")
                    .cloned()
                    .unwrap_or(Value::Null),
                "{name}"
            ),
        }
    }
}

#[test]
fn mailbox_object_hash_known_answers() {
    let file = file();
    for case in file["object_hash"].as_array().unwrap() {
        let object = SignedObject::parse(s(case, "object_text").as_bytes()).unwrap();
        assert_eq!(
            object_hash(&object).to_hex(),
            s(case, "object_hash"),
            "{}",
            case["name"]
        );
    }
    for v in file["objects"].as_array().unwrap() {
        let object = SignedObject::parse(text(&v["object"]).as_bytes()).unwrap();
        assert_eq!(object_hash(&object).to_hex(), s(v, "object_hash"));
        assert_eq!(object.to_json().to_string().len() as u64, u(v, "bytes"));
    }
    // The served bound: a page with every field at its largest and an
    // object of exactly that many bytes is 512 KiB.
    assert_eq!(
        u(&file, "max_served_object_bytes") as usize,
        MAX_SERVED_OBJECT_BYTES
    );
}

/// Every scenario's events, from the file, against a fresh reference
/// mailbox: each answer, outcome and state as the file says.
#[test]
fn mailbox_scenarios_against_the_reference_mailbox() {
    let file = file();
    let link_of = |caller: &Value| LinkAssociation {
        account_id: s(&file["link"], "account_id").into(),
        genesis_hash: Hash32::from_hex(s(&file["link"], "genesis_hash")).unwrap(),
        host_id: s(caller, "host_id").into(),
        host_trust_gen: u(caller, "host_trust_gen"),
        connection_id: s(&file["link"], "connection_id").into(),
    };
    let base = Heads::decode(s(&file, "heads_base").as_bytes()).unwrap();
    let seed: [u8; 32] = unhex32(s(&file, "seed_hex"));
    let mut events = 0;
    for sc in file["scenarios"].as_array().unwrap() {
        let name = s(sc, "name");
        let mut m = ReferenceMailbox::new(
            s(&file["link"], "account_id"),
            Hash32::from_hex(s(&file["link"], "genesis_hash")).unwrap(),
            quotas_of(&sc["quotas"]),
            seed,
        )
        .unwrap()
        .list_moved(hosts_of(&sc["hosts"]));
        for (n, e) in sc["events"].as_array().unwrap().iter().enumerate() {
            let what = format!("{name} event {n}");
            match s(e, "event") {
                "call" => {
                    let bytes = match e.get("call") {
                        Some(call) => call.as_str().unwrap().as_bytes().to_vec(),
                        None => from_recipe(&e["call_fill"]).into_bytes(),
                    };
                    let t = m.call(&link_of(&e["caller"]), &bytes, u(e, "at")).unwrap();
                    assert_eq!(outcome_json(&t.outcome), e["expect"], "{what}");
                    assert_eq!(
                        t.answer.as_ref().map(text),
                        e.get("answer").map(|a| a.as_str().unwrap().to_owned()),
                        "{what}"
                    );
                    m = t.next;
                }
                "heads" => {
                    let t = m
                        .heads(
                            &link_of(&e["caller"]),
                            &base,
                            e["host_senders"].as_bool().unwrap(),
                            u(e, "at"),
                        )
                        .unwrap();
                    assert_eq!(outcome_json(&t.outcome), e["expect"], "{what}");
                    assert_eq!(text(&t.answer.unwrap()), s(e, "answer"), "{what}");
                    m = t.next;
                }
                "reset" => {
                    let reset = match &e["reset"] {
                        Value::String(r) if r == "new_mailbox" => Reset::NewMailbox,
                        other => Reset::HeadBack {
                            head: u(other, "head_back"),
                        },
                    };
                    m = m
                        .reset(s(e, "host_id"), u(e, "host_trust_gen"), reset)
                        .unwrap();
                }
                "hosts" => m = m.list_moved(hosts_of(&e["hosts"])),
                "tick" => m = m.tick(u(e, "at")),
                other => panic!("{what}: no event {other}"),
            }
            assert_eq!(state_json(&m), e["state"], "{what}: state");
            events += 1;
        }
    }
    assert!(events >= 80, "{events} events");
}

/// What the scenarios cover: every outcome of the reference mailbox, every
/// put refusal, every event kind.
#[test]
fn mailbox_scenarios_cover_every_outcome() {
    let file = file();
    let mut outcomes = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for sc in file["scenarios"].as_array().unwrap() {
        for e in sc["events"].as_array().unwrap() {
            kinds.insert(s(e, "event").to_owned());
            if let Some(expect) = e.get("expect") {
                let mut key = s(expect, "outcome").to_owned();
                for detail in ["code", "why", "op"] {
                    if let Some(d) = expect.get(detail) {
                        key = format!("{key} {}", d.as_str().unwrap());
                    }
                }
                if expect.get("reset") == Some(&json!(true)) {
                    key.push_str(" reset");
                }
                outcomes.insert(key);
            }
        }
    }
    for want in [
        "stored",
        "already_stored",
        "put_refused quota",
        "put_refused id_reused",
        "put_refused expired",
        "put_refused forbidden",
        "dropped not_strict",
        "dropped malformed",
        "dropped wrong_message",
        "dropped too_large",
        "dropped unserved",
        "page",
        "page reset",
        "done",
        "refused mailbox_sync_refused",
        "refused mailbox_done_refused",
        "heads",
    ] {
        assert!(outcomes.contains(want), "no scenario gives {want}");
    }
    assert_eq!(
        kinds,
        BTreeSet::from(["call", "heads", "reset", "hosts", "tick"].map(String::from))
    );
}

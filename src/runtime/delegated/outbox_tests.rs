// The put engine's rows (host-work-v1 §11.5 rule 3; design II.4.4): an
// object enqueued in its caller's transaction, the Station's answers, the
// two policies, quota backoff, expiry, settling and pruning. Objects are
// sealed with the shared core: envelopes (repeat) and a status (until
// stored) from host `a` to host `b`.
use super::*;
use crate::runtime::host_work::Store;
use atem_client::encoding::Hash32;
use atem_client::host_mail::{EnvelopePlain, MailFields, ResultPlain, seal_envelope, seal_result};
use atem_client::membership::Head;
use atem_client::{KeyId, KeyProvider, SoftwareKeys};

const T0: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;
/// The link generation and committed head the puts go at.
pub(crate) const AT: Place = Place {
    link_gen: 1,
    head_seq: 5,
};

pub(crate) fn host(id: &str) -> HostRef {
    HostRef {
        host_id: id.into(),
        host_trust_gen: 1,
    }
}

fn keys() -> SoftwareKeys {
    let mut keys = SoftwareKeys::new();
    keys.insert_ed25519(KeyId::new("a"), &[7; 32]);
    keys.insert_x25519(KeyId::new("b-enc"), &[9; 32]);
    keys
}

fn fields(to: &str, id: &str, expires_at: u64) -> MailFields {
    let enc = keys().public_key(&KeyId::new("b-enc")).unwrap();
    MailFields {
        account_id: "acct".into(),
        genesis_hash: Hash32([1; 32]),
        sender: host("a"),
        recipient: host(to),
        enc_kid: atem_client::keys::enc_kid(&enc).unwrap(),
        id: id.into(),
        created_at: T0,
        expires_at,
        signed_at_head: Head {
            seq: 3,
            hash: Hash32([2; 32]),
        },
    }
}

/// A cancel envelope from `a` to `to`, its id `id`: its exact bytes.
pub(crate) fn envelope(to: &str, id: &str, expires_at: u64) -> Vec<u8> {
    let keys = keys();
    let enc = keys.public_key(&KeyId::new("b-enc")).unwrap();
    let plain = EnvelopePlain::Cancel {
        task_id: uuid::Uuid::new_v4().to_string(),
    };
    seal_envelope(
        &keys,
        &KeyId::new("a"),
        &fields(to, id, expires_at),
        &plain,
        &enc,
    )
    .unwrap()
    .to_json()
    .to_string()
    .into_bytes()
}

/// A status result from `a` to `to` (a refusal of an object of `to`'s).
fn status(to: &str, id: &str, expires_at: u64) -> Vec<u8> {
    let keys = keys();
    let enc = keys.public_key(&KeyId::new("b-enc")).unwrap();
    let plain = ResultPlain::Refusal {
        object_id: uuid::Uuid::new_v4().to_string(),
        refused: "invalid_request".into(),
    };
    seal_result(
        &keys,
        &KeyId::new("a"),
        &fields(to, id, expires_at),
        &plain,
        &enc,
    )
    .unwrap()
    .to_json()
    .to_string()
    .into_bytes()
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    prepare(&store).unwrap();
    (dir, store)
}

fn put(store: &Store, bytes: &[u8], to: &str, policy: Policy) -> Result<i64> {
    let tx = store.db.unchecked_transaction()?;
    let n = enqueue(&tx, bytes, &host(to), policy)?;
    tx.commit()?;
    Ok(n)
}

fn due_now(store: &Store, now: u64) -> Vec<i64> {
    due(store, &host("a"), now, AT, &[], 16)
        .unwrap()
        .into_iter()
        .map(|d| d.n)
        .collect()
}

fn state(store: &Store, n: i64) -> (String, Option<String>) {
    let s = row_state(&store.db, n).unwrap().unwrap();
    (s.state, s.code)
}

/// An object is durable with its caller's transaction, its exact bytes
/// kept; the same object again is the same row, other bytes under its key
/// are refused, and it goes only to its own recipient.
#[test]
fn an_object_is_enqueued_in_its_callers_transaction() {
    let (_dir, store) = store();
    let id = uuid::Uuid::new_v4().to_string();
    let bytes = envelope("b", &id, T0 + HOUR);
    {
        let tx = store.db.unchecked_transaction().unwrap();
        enqueue(&tx, &bytes, &host("b"), Policy::Repeat).unwrap();
        // Rolled back with its transaction: nothing to put.
    }
    assert_eq!(due_now(&store, T0), Vec::<i64>::new());
    let n = put(&store, &bytes, "b", Policy::Repeat).unwrap();
    let rows = due(&store, &host("a"), T0, AT, &[], 16).unwrap();
    assert_eq!(
        rows,
        [Due {
            n,
            bytes: bytes.clone()
        }]
    );
    assert_eq!(put(&store, &bytes, "b", Policy::Repeat).unwrap(), n);
    let other = envelope("b", &id, T0 + HOUR);
    assert_eq!(
        put(&store, &other, "b", Policy::Repeat)
            .unwrap_err()
            .to_string(),
        "id_reused"
    );
    assert!(put(&store, &bytes, "c", Policy::Repeat).is_err());
    assert!(put(&store, b"junk", "b", Policy::Repeat).is_err());
    // Another sender's rows aren't this host's to put, nor this host's of an
    // older trust generation (review L6); live ones wait.
    let newer = HostRef {
        host_id: "a".into(),
        host_trust_gen: 2,
    };
    assert!(due(&store, &newer, T0, AT, &[], 16).unwrap().is_empty());
    assert!(due(&store, &host("b"), T0, AT, &[], 16).unwrap().is_empty());
    assert!(
        due(&store, &host("a"), T0, AT, &[n], 16)
            .unwrap()
            .is_empty()
    );
}

/// `mailbox_stored`: an envelope is put again with the same bytes every 10
/// minutes until settled; a status or result never again.
#[test]
fn stored_repeats_an_envelope_and_finishes_a_status() {
    let (_dir, store) = store();
    let envelope = put(
        &store,
        &envelope("b", &new_id(), T0 + HOUR),
        "b",
        Policy::Repeat,
    )
    .unwrap();
    let result = put(
        &store,
        &status("b", &new_id(), T0 + HOUR),
        "b",
        Policy::UntilStored,
    )
    .unwrap();
    for n in [envelope, result] {
        stored(&store, n, T0).unwrap();
    }
    assert_eq!(state(&store, envelope), ("stored".into(), None));
    assert_eq!(state(&store, result), ("done".into(), None));
    assert_eq!(due_now(&store, T0 + RESEND_MS - 1), Vec::<i64>::new());
    assert_eq!(due_now(&store, T0 + RESEND_MS), [envelope]);
    stored(&store, envelope, T0 + RESEND_MS).unwrap();
    assert_eq!(due_now(&store, T0 + 2 * RESEND_MS), [envelope]);
    let tx = store.db.unchecked_transaction().unwrap();
    settle(&tx, envelope).unwrap();
    tx.commit().unwrap();
    assert_eq!(state(&store, envelope), ("done".into(), None));
    assert_eq!(due_now(&store, T0 + 3 * RESEND_MS), Vec::<i64>::new());
}

/// `quota` puts it again after a backoff that doubles from 30 s to 10
/// minutes (reset once stored); every other code refuses it for good.
#[test]
fn quota_backs_off_and_other_refusals_are_final() {
    let (_dir, store) = store();
    let n = put(
        &store,
        &envelope("b", &new_id(), T0 + 2 * HOUR),
        "b",
        Policy::Repeat,
    )
    .unwrap();
    let mut now = T0;
    for wait in [30_000, 60_000, 120_000, 240_000, 480_000, 600_000, 600_000] {
        refused(&store, n, PutRefusal::Quota, now, AT).unwrap();
        assert_eq!(due_now(&store, now + wait - 1), Vec::<i64>::new(), "{wait}");
        assert_eq!(due_now(&store, now + wait), [n], "{wait}");
        now += wait;
    }
    assert_eq!(state(&store, n), ("queued".into(), Some("quota".into())));
    stored(&store, n, now).unwrap();
    assert_eq!(state(&store, n), ("stored".into(), None));
    refused(&store, n, PutRefusal::Quota, now + RESEND_MS, AT).unwrap();
    assert_eq!(due_now(&store, now + RESEND_MS + 30_000), [n]);
    for code in [PutRefusal::IdReused, PutRefusal::Expired] {
        let n = put(
            &store,
            &envelope("b", &new_id(), T0 + HOUR),
            "b",
            Policy::Repeat,
        )
        .unwrap();
        refused(&store, n, code, T0, AT).unwrap();
        assert_eq!(
            state(&store, n),
            ("refused".into(), Some(code.code().into()))
        );
        assert!(!due_now(&store, T0 + HOUR - 1).contains(&n));
        // A later answer changes nothing.
        stored(&store, n, T0).unwrap();
        assert_eq!(state(&store, n).0, "refused");
    }
}

/// An object not settled by its expiry is `expired` and put no more; a
/// final row's bytes go a day after its expiry, the row stays.
#[test]
fn an_unsettled_object_expires_and_its_bytes_are_pruned() {
    let (_dir, store) = store();
    let n = put(
        &store,
        &envelope("b", &new_id(), T0 + HOUR),
        "b",
        Policy::Repeat,
    )
    .unwrap();
    let done = put(
        &store,
        &status("b", &new_id(), T0 + HOUR),
        "b",
        Policy::UntilStored,
    )
    .unwrap();
    stored(&store, done, T0).unwrap();
    assert_eq!(
        due_now(&store, T0 + HOUR),
        Vec::<i64>::new(),
        "past its expiry"
    );
    assert_eq!(expire(&store, T0 + HOUR - 1).unwrap(), 0);
    assert_eq!(expire(&store, T0 + HOUR).unwrap(), 1);
    assert_eq!(state(&store, n), ("expired".into(), None));
    assert_eq!(state(&store, done), ("done".into(), None));
    let bytes = |n: i64| -> usize {
        store
            .db
            .query_row(
                "SELECT length(bytes) FROM mail_outbox WHERE n=?1",
                [n],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(prune(&store, T0 + HOUR + KEEP_BYTES_MS - 1).unwrap(), 0);
    assert_eq!(prune(&store, T0 + HOUR + KEEP_BYTES_MS).unwrap(), 2);
    assert_eq!((bytes(n), bytes(done)), (0, 0));
    assert!(row_state(&store.db, n).unwrap().is_some());
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `forbidden` is final on the link generation it came on (host-work-v1
/// §11.5 rule 3, ruling R41): the row isn't put again there, but is on a
/// later generation, or once this host's device list moved, until its
/// object expires; a store ends the hold.
#[test]
fn forbidden_holds_a_row_until_the_link_or_the_list_moves() {
    let (_dir, store) = store();
    let n = put(
        &store,
        &envelope("b", &new_id(), T0 + HOUR),
        "b",
        Policy::Repeat,
    )
    .unwrap();
    let due_at = |place: Place| -> Vec<i64> {
        due(&store, &host("a"), T0, place, &[], 16)
            .unwrap()
            .into_iter()
            .map(|d| d.n)
            .collect()
    };
    refused(&store, n, PutRefusal::Forbidden, T0, AT).unwrap();
    assert_eq!(
        state(&store, n),
        ("queued".into(), Some("forbidden".into()))
    );
    assert_eq!(
        due_at(AT),
        Vec::<i64>::new(),
        "final on this link generation"
    );
    let later = Place { link_gen: 2, ..AT };
    let moved = Place { head_seq: 6, ..AT };
    assert_eq!(due_at(later), [n]);
    assert_eq!(due_at(moved), [n]);
    stored(&store, n, T0).unwrap();
    refused(&store, n, PutRefusal::Quota, T0 + RESEND_MS, later).unwrap();
    assert_eq!(
        due(&store, &host("a"), T0 + RESEND_MS + 30_000, AT, &[], 16)
            .unwrap()
            .len(),
        1,
        "the hold ended with the store"
    );
    refused(&store, n, PutRefusal::Forbidden, T0 + RESEND_MS, AT).unwrap();
    assert_eq!(
        state(&store, n),
        ("stored".into(), Some("forbidden".into()))
    );
    expire(&store, T0 + HOUR).unwrap();
    assert_eq!(state(&store, n).0, "expired");
}

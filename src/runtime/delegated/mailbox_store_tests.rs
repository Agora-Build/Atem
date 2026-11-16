// The receiving host's mailbox in its host-work store (host-work-v1 §11.5,
// "The mailbox calls", rules 4, 5 and 7; design II.4.2, II.4.3): the
// cursor bound to the host's identity, the durable reset mark, each page's
// one transaction (its objects' decisions, the cursor and the dones owed),
// the verdicts' rows, duplicates, the pending limits and the dones.
use super::*;
use crate::runtime::host_work::Store;
use atem_client::encoding::Hash32;
use atem_client::host_mail::mailbox::{MailboxEntry, MailboxSyncResult};
use atem_client::session::host_work::HostTarget;

const MAILBOX: &str = "9d2f6c1e-3b4a-4c5d-8e6f-7a8b9c0d1e2f";
const MAILBOX_2: &str = "3e9fd05f-183e-4b70-be0e-3ffa66120f48";
const REQUEST: &str = "55aa5bab-e253-4b6c-a83f-c86e6b028aa1";

fn identity(host_trust_gen: u64) -> HostIdentity {
    HostIdentity {
        host: HostTarget {
            account_id: "acct-m".into(),
            atem_device_id: "host".into(),
            host_trust_gen,
        },
        genesis: Some(Hash32([9; 32])),
        host_key: None,
    }
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    prepare(&store).unwrap();
    (dir, store)
}

/// A page of `mailbox` after `after`: `head`, scanned `through`, `objects`.
fn page(
    mailbox: &str,
    after: u64,
    head: u64,
    through: u64,
    objects: Vec<MailboxEntry>,
) -> MailboxSyncResult {
    MailboxSyncResult {
        request_id: REQUEST.into(),
        mailbox_id: mailbox.into(),
        after,
        head,
        through,
        objects,
    }
}

/// The store's cursor for identity 1.
fn cursor(store: &Store) -> Option<(String, u64)> {
    read(store, &identity(1)).unwrap().cursor
}

/// Rule 4: a page commits from the store's own cursor only (a
/// continuation of another cursor or mailbox applies nothing), moving it
/// to `through`; a store never read takes a read from 0. The cursor is
/// bound to the host's identity: under another, the state doesn't load
/// (fail closed).
#[test]
fn a_page_commits_from_the_stores_own_cursor() {
    let (_dir, store) = store();
    assert_eq!(cursor(&store), None);
    assert_eq!(
        commit_page(&store, &identity(1), &page(MAILBOX, 1, 3, 3, vec![]), None).unwrap(),
        Commit::Stale,
        "never read: only a read from 0"
    );
    assert!(matches!(
        commit_page(&store, &identity(1), &page(MAILBOX, 0, 3, 2, vec![]), None).unwrap(),
        Commit::Committed(_)
    ));
    assert_eq!(cursor(&store), Some((MAILBOX.into(), 2)));
    for stale in [
        page(MAILBOX, 0, 3, 3, vec![]),
        page(MAILBOX_2, 2, 3, 3, vec![]),
    ] {
        assert_eq!(
            commit_page(&store, &identity(1), &stale, None).unwrap(),
            Commit::Stale
        );
    }
    assert!(matches!(
        commit_page(&store, &identity(1), &page(MAILBOX, 2, 3, 3, vec![]), None).unwrap(),
        Commit::Committed(_)
    ));
    assert_eq!(cursor(&store), Some((MAILBOX.into(), 3)));
    assert!(read(&store, &identity(2)).is_err(), "another identity's");
    assert_eq!(
        commit_page(&store, &identity(2), &page(MAILBOX, 3, 3, 3, vec![]), None).unwrap(),
        Commit::Stale
    );
}

/// Rule 7: a reset is marked durably before anything is asked for it: the
/// store's cursor rewritten to the announced mailbox at position 0 (the
/// same mailbox too, when its head went below the cursor), surviving a
/// reopen.
#[test]
fn a_reset_mark_is_durable() {
    let (dir, store) = store();
    commit_page(&store, &identity(1), &page(MAILBOX, 0, 5, 5, vec![]), None).unwrap();
    mark_reset(&store, &identity(1), MAILBOX_2).unwrap();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(cursor(&store), Some((MAILBOX_2.into(), 0)));
    mark_reset(&store, &identity(1), MAILBOX_2).unwrap();
    assert_eq!(cursor(&store), Some((MAILBOX_2.into(), 0)));
}

// ------------------------------------------------- the objects' decisions

use crate::session_protocol::membership::r9log::{TestLog, secret};
use atem_client::host_mail::receive::reason;
use atem_client::host_mail::{EnvelopePlain, HostRef, MailFields, Recipient, seal_envelope};
use atem_client::membership::Head;
use atem_client::{KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};

const HOUR: u64 = 3_600_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// This host (`host`, generation 1) and host B (`host-b`, generation 1)
/// in one device list; B's `host_key` and this host's encryption key.
struct Mail {
    log: TestLog,
    sender: SoftwareKeys,
    keys: SoftwareKeys,
    enc_pub: PublicKey,
    recipient: Recipient,
}

impl Mail {
    fn new() -> Mail {
        let mut log = TestLog::genesis("acct-m", &secret("mail astation"));
        log.add_host("host", 1, &secret("mail host"));
        log.add_host("host-b", 1, &secret("mail host b"));
        let mut sender = SoftwareKeys::new();
        sender.insert_ed25519(KeyId::new("host-b"), &secret("mail host b"));
        let mut keys = SoftwareKeys::new();
        keys.insert_x25519(KeyId::new("enc"), &secret("mail host enc"));
        let enc_pub = keys.public_key(&KeyId::new("enc")).unwrap();
        let kid = atem_client::keys::enc_kid_bytes(&enc_pub).unwrap();
        Mail {
            log,
            sender,
            keys,
            enc_pub,
            recipient: Recipient {
                host_id: "host".into(),
                host_trust_gen: 1,
                keys: vec![(KeyId::new("enc"), kid)],
                generated: vec![],
            },
        }
    }

    fn cx(&self) -> DecideCx<'_> {
        DecideCx {
            list: &self.log.log,
            recipient: &self.recipient,
            provider: &self.keys,
            now_ms: now_ms(),
            limits: Limits::default(),
        }
    }

    /// B's object to this host, signed at `head`, from `sender` (claimed).
    fn fields(&self, sender: &str, head: Head, expires_at: u64) -> MailFields {
        MailFields {
            account_id: self.log.account.clone(),
            genesis_hash: self.log.genesis_hash(),
            sender: HostRef {
                host_id: sender.into(),
                host_trust_gen: 1,
            },
            recipient: HostRef {
                host_id: "host".into(),
                host_trust_gen: 1,
            },
            enc_kid: atem_client::keys::enc_kid(&self.enc_pub).unwrap(),
            id: uuid(),
            created_at: now_ms() - 1_000,
            expires_at,
            signed_at_head: head,
        }
    }

    fn seal(&self, fields: &MailFields) -> SignedObject {
        let plain = EnvelopePlain::Cancel { task_id: uuid() };
        seal_envelope(
            &self.sender,
            &KeyId::new("host-b"),
            fields,
            &plain,
            &self.enc_pub,
        )
        .unwrap()
    }

    /// A cancel from B at this list's head, valid for an hour.
    fn cancel(&self) -> SignedObject {
        self.seal(&self.fields("host-b", self.log.log.head(), now_ms() + HOUR))
    }

    /// One signed by `sender` at a head beyond this list's: it waits.
    fn beyond(&self, sender: &str) -> SignedObject {
        let head = self.log.log.head();
        let beyond = Head {
            seq: head.seq + 5,
            hash: Hash32([7; 32]),
        };
        self.seal(&self.fields(sender, beyond, now_ms() + HOUR))
    }
}

/// The store's mailbox, read since a cursor at `MAILBOX`'s `at`.
struct Box {
    _dir: tempfile::TempDir,
    store: Store,
    at: u64,
}

impl Box {
    fn new() -> Box {
        let (dir, store) = store();
        Box {
            _dir: dir,
            store,
            at: 0,
        }
    }

    /// The next position holds `object` (any JSON): its page committed.
    fn put(&mut self, mail: &Mail, object: &serde_json::Value) -> Commit {
        self.put_with(&mail.cx(), object)
    }

    /// [`Box::put`], decided with `cx`.
    fn put_with(&mut self, cx: &DecideCx, object: &serde_json::Value) -> Commit {
        let bytes = object.to_string();
        let page = MailboxSyncResult {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            after: self.at,
            head: self.at + 1,
            through: self.at + 1,
            objects: vec![entry(self.at + 1, &bytes)],
        };
        let commit = commit_page(&self.store, &identity(1), &page, Some(cx)).unwrap();
        if matches!(commit, Commit::Committed(_)) {
            self.at += 1;
        }
        commit
    }

    fn count(&self, table: &str) -> u64 {
        self.store
            .db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    fn owed(&self) -> Vec<u64> {
        owed_dones(&self.store, &identity(1)).unwrap()
    }
}

/// A page's object at `position`, its bytes `text` (read as a page carries
/// it: through the shared reader).
fn entry(position: u64, text: &str) -> MailboxEntry {
    let page = format!(
        r#"{{"type":"relay","op":"mailbox_sync_result","request_id":"{REQUEST}","mailbox_id":"{MAILBOX}","after":{},"head":{position},"through":{position},"objects":[{{"position":{position},"object":{text}}}]}}"#,
        position - 1
    );
    MailboxSyncResult::decode(page.as_bytes())
        .unwrap()
        .objects
        .remove(0)
}

/// The decision a commit recorded for its one object.
fn decided(commit: Commit) -> Decision {
    match commit {
        Commit::Committed(c) => c.decided.into_iter().next().expect("an object"),
        other => panic!("not committed: {other:?}"),
    }
}

/// Design II.4.2, §11.5's verdicts: an opened cancel is an inbox row (and
/// its claim); a refusal before the copy is shown to be the sender's is a
/// refusal row with its evidence (`object_hash`) and the exact bytes as
/// fetched, nothing reported; one after it (expired) is a refusal row to
/// report and its claim; bytes that don't parse are refused under the
/// SHA-256 of the bytes; an object signed beyond this host's head waits.
/// Every one but the waiting one is owed a done, in its page's commit.
#[test]
fn each_verdict_has_its_row() {
    let mail = Mail::new();
    let mut b = Box::new();
    let open = mail.cancel();
    assert_eq!(decided(b.put(&mail, &open.to_json())), Decision::Opened);
    assert_eq!(b.count("mailbox_inbox"), 1);
    assert_eq!(read(&b.store, &identity(1)).unwrap().inbox, 1);
    let (sender, object_id, kind): (String, String, String) = b
        .store
        .db
        .query_row(
            "SELECT sender_host, object_id, kind FROM mailbox_inbox",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let body = atem_client::host_mail::MailBody::from_object(&open)
        .unwrap()
        .1;
    assert_eq!(
        (sender.as_str(), object_id, kind.as_str()),
        ("host-b", body.id, "cancel")
    );

    // Not this host's account: refused before verification.
    let mut fields = mail.fields("host-b", mail.log.log.head(), now_ms() + HOUR);
    fields.account_id = "acct-other".into();
    let pin = mail.seal(&fields);
    let text = pin.to_json().to_string();
    assert_eq!(
        decided(b.put(&mail, &pin.to_json())),
        Decision::Refused(reason::PIN_MISMATCH)
    );
    let (evidence, bytes, report): (String, Vec<u8>, i64) = b
        .store
        .db
        .query_row(
            "SELECT evidence, bytes, report FROM mailbox_refused WHERE reason=?1",
            [reason::PIN_MISMATCH],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(evidence, atem_client::host_mail::object_hash(&pin).to_hex());
    assert_eq!(bytes, text.as_bytes());
    assert_eq!(report, 0);

    // The sender's own copy, expired: refused authenticated, to report.
    let mut fields = mail.fields("host-b", mail.log.log.head(), now_ms() - 1);
    fields.created_at = now_ms() - HOUR;
    let expired = mail.seal(&fields);
    assert_eq!(
        decided(b.put(&mail, &expired.to_json())),
        Decision::Refused(reason::EXPIRED)
    );
    let (object_id, report): (String, i64) = b
        .store
        .db
        .query_row(
            "SELECT object_id, report FROM mailbox_refused WHERE reason=?1",
            [reason::EXPIRED],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((object_id, report), (fields.id.clone(), 1));
    assert_eq!(b.count("mailbox_claims"), 2);

    // Bytes that don't parse as a signed object.
    let junk = serde_json::json!({"not": "an object"});
    assert_eq!(
        decided(b.put(&mail, &junk)),
        Decision::Refused(reason::MALFORMED)
    );
    let evidence: String = b
        .store
        .db
        .query_row(
            "SELECT evidence FROM mailbox_refused WHERE reason=?1",
            [reason::MALFORMED],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(evidence, Hash32::of(junk.to_string().as_bytes()).to_hex());

    // Signed beyond this host's head: kept, no done.
    assert_eq!(
        decided(b.put(&mail, &mail.beyond("host-c").to_json())),
        Decision::Pending
    );
    assert_eq!(b.count("mailbox_pending"), 1);
    assert_eq!(b.owed(), [1, 2, 3, 4], "every position but the waiting one");
    assert_eq!(b.count("mailbox_inbox"), 1);
}

/// §11.5 "Which copies claim an id": the sender's object again (another
/// position) is a duplicate with the first verdict, done again and nothing
/// recorded; its id with another sealed part is refused as a reused id
/// (kept as evidence, the first verdict standing); an unauthenticated
/// refusal's bytes again are a duplicate of that refusal; a waiting
/// object again is held once.
#[test]
fn duplicates_keep_the_first_verdict() {
    let mail = Mail::new();
    let mut b = Box::new();
    let open = mail.cancel();
    assert_eq!(decided(b.put(&mail, &open.to_json())), Decision::Opened);
    assert_eq!(decided(b.put(&mail, &open.to_json())), Decision::Duplicate);
    // The same id, another sealed part (a new seal of other text).
    let body = atem_client::host_mail::MailBody::from_object(&open)
        .unwrap()
        .1;
    let mut fields = body.fields();
    fields.expires_at -= 1;
    let reused = mail.seal(&fields);
    assert_eq!(
        decided(b.put(&mail, &reused.to_json())),
        Decision::Refused(ID_REUSED)
    );
    assert_eq!(b.count("mailbox_inbox"), 1);
    assert_eq!(
        decided(b.put(&mail, &reused.to_json())),
        Decision::Duplicate
    );
    let junk = serde_json::json!([1, 2]);
    assert_eq!(
        decided(b.put(&mail, &junk)),
        Decision::Refused(reason::MALFORMED)
    );
    assert_eq!(decided(b.put(&mail, &junk)), Decision::Duplicate);
    assert_eq!(b.count("mailbox_refused"), 2);
    let waits = mail.beyond("host-c");
    assert_eq!(decided(b.put(&mail, &waits.to_json())), Decision::Pending);
    assert_eq!(decided(b.put(&mail, &waits.to_json())), Decision::Pending);
    assert_eq!(b.count("mailbox_pending"), 1, "held once");
    let position: u64 = b
        .store
        .db
        .query_row("SELECT position FROM mailbox_pending", [], |r| r.get(0))
        .unwrap();
    assert_eq!(position, 8, "at its latest position");
    assert_eq!(b.owed(), [1, 2, 3, 4, 5, 6]);
}

/// Rule 4 and Astation's ask (#120): an object's decision, its row, the
/// cursor and the done owed commit in one transaction, before any done is
/// sent. A crash after the commit (the store reopened) keeps the owed
/// done; the page delivered again from the old cursor is stale, so
/// nothing applies twice. An object that can't be decided now (the key
/// provider failed) commits nothing at all; once answered, a done is no
/// longer owed; a reset drops the dones owed to the old mailbox.
#[test]
fn one_transaction_for_the_decision_the_cursor_and_the_dones() {
    let mail = Mail::new();
    let mut b = Box::new();
    let open = mail.cancel();
    assert_eq!(decided(b.put(&mail, &open.to_json())), Decision::Opened);
    let dir = b._dir.path().to_path_buf();
    let reopened = Store::open(&dir).unwrap();
    assert_eq!(owed_dones(&reopened, &identity(1)).unwrap(), [1]);
    let again = MailboxSyncResult {
        request_id: REQUEST.into(),
        mailbox_id: MAILBOX.into(),
        after: 0,
        head: 1,
        through: 1,
        objects: vec![entry(1, &open.to_json().to_string())],
    };
    assert_eq!(
        commit_page(&reopened, &identity(1), &again, Some(&mail.cx())).unwrap(),
        Commit::Stale
    );
    assert_eq!(b.count("mailbox_inbox"), 1, "nothing applied twice");

    // The key provider fails (no key behind the kid): nothing commits.
    let broken = DecideCx {
        provider: &SoftwareKeys::new(),
        ..mail.cx()
    };
    assert_eq!(
        b.put_with(&broken, &mail.cancel().to_json()),
        Commit::Undecided
    );
    assert_eq!(
        read(&b.store, &identity(1)).unwrap().cursor,
        Some((MAILBOX.into(), 1))
    );
    assert_eq!((b.count("mailbox_inbox"), b.owed()), (1, vec![1]));

    // Never owed under another identity (the state is identity 1's).
    assert!(owed_dones(&b.store, &identity(2)).unwrap().is_empty());
    done_answered(&b.store, &identity(1), MAILBOX, 1).unwrap();
    assert!(b.owed().is_empty());
    decided(b.put(&mail, &mail.cancel().to_json()));
    assert_eq!(b.owed(), [2]);
    mark_reset(&b.store, &identity(1), MAILBOX_2).unwrap();
    assert!(b.owed().is_empty(), "dropped with the old mailbox");
}

/// Design II.4.2's limits: at most 64 waiting objects per claimed
/// `(host_id, host_trust_gen)` and 256 in all; one over either is dropped
/// undecided (no verdict, no row, no id) and still marked done (Atem's
/// refinement, agreed 2026-11-16).
#[test]
fn the_pending_limits_and_overflow_marked_done() {
    let mail = Mail::new();
    let mut b = Box::new();
    for n in 0..MAX_PENDING_PER_SENDER {
        assert_eq!(
            decided(b.put(&mail, &mail.beyond("host-x").to_json())),
            Decision::Pending,
            "{n}"
        );
    }
    assert_eq!(
        decided(b.put(&mail, &mail.beyond("host-x").to_json())),
        Decision::Overflow
    );
    assert_eq!(b.owed(), [MAX_PENDING_PER_SENDER as u64 + 1]);
    for pair in 1..MAX_PENDING / MAX_PENDING_PER_SENDER {
        for _ in 0..MAX_PENDING_PER_SENDER {
            decided(b.put(&mail, &mail.beyond(&format!("host-x{pair}")).to_json()));
        }
    }
    assert_eq!(b.count("mailbox_pending"), MAX_PENDING as u64);
    assert_eq!(
        decided(b.put(&mail, &mail.beyond("host-y").to_json())),
        Decision::Overflow
    );
    assert_eq!(b.count("mailbox_pending"), MAX_PENDING as u64);
    assert_eq!(b.count("mailbox_claims") + b.count("mailbox_refused"), 0);
    assert_eq!(b.owed().len(), 2);
}

/// Design II.4.2: a waiting object is judged again after the device list
/// advances: decided then, its row written and its done owed (its position
/// in the mailbox read now) in one transaction, and no longer waiting.
#[test]
fn a_waiting_object_is_judged_again_when_the_list_advances() {
    let mut mail = Mail::new();
    let mut b = Box::new();
    // Host C signs at a head this host doesn't hold yet: its `add_host`.
    mail.log.add_host("host-c", 1, &secret("mail host c"));
    let mut sender = SoftwareKeys::new();
    sender.insert_ed25519(KeyId::new("host-b"), &secret("mail host c"));
    let fields = mail.fields("host-c", mail.log.log.head(), now_ms() + HOUR);
    let object = seal_envelope(
        &sender,
        &KeyId::new("host-b"),
        &fields,
        &EnvelopePlain::Cancel { task_id: uuid() },
        &mail.enc_pub,
    )
    .unwrap();
    // This host's list stops before C's `add_host`.
    let short = short_list(&mail.log);
    let full = std::mem::replace(&mut mail.log.log, short);
    assert_eq!(decided(b.put(&mail, &object.to_json())), Decision::Pending);
    assert_eq!(
        rejudge_pending(&b.store, &identity(1), &mail.cx()).unwrap(),
        Vec::new(),
        "the list didn't move: it still waits"
    );
    mail.log.log = full;
    assert_eq!(
        rejudge_pending(&b.store, &identity(1), &mail.cx()).unwrap(),
        vec![Decision::Opened]
    );
    assert_eq!(
        (b.count("mailbox_pending"), b.count("mailbox_inbox")),
        (0, 1)
    );
    assert_eq!(b.owed(), [1]);
}

/// `log`'s device list without its last entry.
fn short_list(log: &TestLog) -> atem_client::membership::Membership {
    atem_client::membership::Membership::verify_chain(
        &log.account,
        &log.genesis_hash(),
        &log.entries[..log.entries.len() - 1],
        &log.now,
    )
    .unwrap()
    .membership
}

/// Host C's cancel to this host, signed at the head of `mail`'s list after
/// C's `add_host`; this host's list stops before it (the returned full
/// list goes back in later).
fn waiting_from_c(mail: &mut Mail) -> (SignedObject, atem_client::membership::Membership) {
    mail.log.add_host("host-c", 1, &secret("mail host c"));
    let mut sender = SoftwareKeys::new();
    sender.insert_ed25519(KeyId::new("host-c"), &secret("mail host c"));
    let fields = mail.fields("host-c", mail.log.log.head(), now_ms() + HOUR);
    let object = seal_envelope(
        &sender,
        &KeyId::new("host-c"),
        &fields,
        &EnvelopePlain::Cancel { task_id: uuid() },
        &mail.enc_pub,
    )
    .unwrap();
    let short = short_list(&mail.log);
    let full = std::mem::replace(&mut mail.log.log, short);
    (object, full)
}

/// Review finding 1 (rule 5): a reset detaches every waiting object from
/// its position. One whose mailbox went back under the same id and that
/// the read from 0 doesn't list again owes no done when it is decided
/// (its old position may hold another object now); one the read lists
/// again is re-pointed and owes a done at its new position.
#[test]
fn a_reset_detaches_waiting_objects_from_their_positions() {
    let mut mail = Mail::new();
    let mut b = Box::new();
    let (object, full) = waiting_from_c(&mut mail);
    assert_eq!(decided(b.put(&mail, &object.to_json())), Decision::Pending);
    mark_reset(&b.store, &identity(1), MAILBOX).unwrap();
    b.at = 0;
    let short = std::mem::replace(&mut mail.log.log, full);
    assert_eq!(
        rejudge_pending(&b.store, &identity(1), &mail.cx()).unwrap(),
        vec![Decision::Opened]
    );
    assert!(b.owed().is_empty(), "never seen again: no done");

    // Listed again after the reset, at another position: owed there.
    let mut mail = Mail::new();
    let mut b = Box::new();
    let (object, full) = waiting_from_c(&mut mail);
    assert_eq!(decided(b.put(&mail, &object.to_json())), Decision::Pending);
    mark_reset(&b.store, &identity(1), MAILBOX).unwrap();
    b.at = 0;
    decided(b.put(&mail, &serde_json::json!("junk")));
    assert_eq!(decided(b.put(&mail, &object.to_json())), Decision::Pending);
    mail.log.log = full;
    assert_eq!(
        rejudge_pending(&b.store, &identity(1), &mail.cx()).unwrap(),
        vec![Decision::Opened]
    );
    assert_eq!(b.owed(), [1, 2]);
    drop(short);
}

/// Review finding 6: a waiting row whose bytes no longer parse is refused
/// (`malformed`, under the SHA-256 of its bytes) and no longer waits; its
/// done is owed in the mailbox read now.
#[test]
fn a_waiting_row_that_doesnt_parse_is_refused() {
    let mail = Mail::new();
    let b = Box::new();
    commit_page(
        &b.store,
        &identity(1),
        &page(MAILBOX, 0, 1, 1, vec![]),
        None,
    )
    .unwrap();
    b.store
        .db
        .execute(
            "INSERT INTO mailbox_pending(object_hash, host_id, host_trust_gen, mailbox_id,
                position, expires_at, bytes) VALUES('ff', 'host-x', 1, ?1, 1, 0, x'7b')",
            [MAILBOX],
        )
        .unwrap();
    assert_eq!(
        rejudge_pending(&b.store, &identity(1), &mail.cx()).unwrap(),
        vec![Decision::Refused(reason::MALFORMED)]
    );
    assert_eq!((b.count("mailbox_pending"), b.owed()), (0, vec![1]));
    let evidence: String = b
        .store
        .db
        .query_row("SELECT evidence FROM mailbox_refused", [], |r| r.get(0))
        .unwrap();
    assert_eq!(evidence, Hash32::of(b"{").to_hex());
}

/// Review finding 4: the sender's own copy refused once it verifies, whose
/// same bytes were refused before it could (signed beyond this host's
/// head, its `created_at` too far ahead), upgrades that evidence row to
/// one to report, naming the sender and the id it claims.
#[test]
fn a_refusal_of_the_senders_copy_upgrades_its_evidence() {
    let mut mail = Mail::new();
    let mut b = Box::new();
    mail.log.add_native("dev-phone", &["view"]);
    let mut fields = mail.fields("host-b", mail.log.log.head(), now_ms() + HOUR);
    fields.created_at = now_ms() + 10 * 60_000;
    let ahead = mail.seal(&fields);
    let short = short_list(&mail.log);
    let full = std::mem::replace(&mut mail.log.log, short);
    assert_eq!(
        decided(b.put(&mail, &ahead.to_json())),
        Decision::Refused(reason::CREATED_TOO_FAR_AHEAD)
    );
    mail.log.log = full;
    assert_eq!(
        decided(b.put(&mail, &ahead.to_json())),
        Decision::Refused(reason::CREATED_TOO_FAR_AHEAD)
    );
    let (count, report, sender, object_id): (u64, i64, String, String) = b
        .store
        .db
        .query_row(
            "SELECT count(*), max(report), max(sender_host), max(object_id) FROM mailbox_refused",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((count, report, sender.as_str()), (1, 1, "host-b"));
    assert_eq!(object_id, fields.id);
    assert_eq!(
        decided(b.put(&mail, &ahead.to_json())),
        Decision::Duplicate,
        "its claim stands"
    );
}

/// Review finding 2: refusals keep their exact bytes within a budget,
/// those not reported dropped first, oldest first (their evidence hash
/// kept: the same bytes again are still a duplicate).
#[test]
fn the_evidence_keeps_its_bytes_within_a_budget() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            evidence_bytes: 2_000,
            ..Limits::default()
        },
        ..mail.cx()
    };
    let junk = |c: char| serde_json::json!(c.to_string().repeat(698));
    let kept = |b: &Box| -> Vec<i64> {
        let mut q = b
            .store
            .db
            .prepare("SELECT report FROM mailbox_refused WHERE bytes IS NOT NULL ORDER BY n")
            .unwrap();
        q.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    decided(b.put_with(&cx, &junk('a')));
    decided(b.put_with(&cx, &junk('b')));
    assert_eq!(kept(&b), [0, 0]);
    let mut fields = mail.fields("host-b", mail.log.log.head(), cx.now_ms - 1);
    fields.created_at = now_ms() - HOUR;
    assert_eq!(
        decided(b.put_with(&cx, &mail.seal(&fields).to_json())),
        Decision::Refused(reason::EXPIRED)
    );
    assert_eq!(kept(&b), [0, 1], "the oldest dropped");
    decided(b.put_with(&cx, &junk('c')));
    decided(b.put_with(&cx, &junk('d')));
    assert_eq!(kept(&b), [1, 0], "the one to report kept");
    let total: u64 = b
        .store
        .db
        .query_row("SELECT sum(length(bytes)) FROM mailbox_refused", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(total <= 2_000, "{total}");
    assert_eq!(decided(b.put_with(&cx, &junk('a'))), Decision::Duplicate);
}

/// Review finding 2: claims and refusals are pruned a margin
/// ([`KEEP_MARGIN_MS`]) after their object's expiry: until then a late copy
/// is a duplicate; after, it is judged anew.
#[test]
fn claims_and_evidence_are_pruned_a_margin_after_their_expiry() {
    let mail = Mail::new();
    let mut b = Box::new();
    let open = mail.cancel();
    let expires_at = atem_client::host_mail::MailBody::from_object(&open)
        .unwrap()
        .1
        .expires_at;
    decided(b.put(&mail, &open.to_json()));
    decided(b.put(&mail, &serde_json::json!("junk")));
    let late = expires_at + KEEP_MARGIN_MS;
    assert_eq!(prune(&b.store, late - 1).unwrap(), 0);
    let cx = DecideCx {
        now_ms: late - 1,
        ..mail.cx()
    };
    assert_eq!(
        decided(b.put_with(&cx, &open.to_json())),
        Decision::Duplicate
    );
    assert_eq!(prune(&b.store, late).unwrap(), 1, "the claim");
    assert_eq!(b.count("mailbox_claims"), 0);
    // Review O3: a copy that late is done as expired, not judged: it
    // claims nothing and reports nothing.
    let cx = DecideCx {
        now_ms: late,
        ..mail.cx()
    };
    assert_eq!(
        decided(b.put_with(&cx, &open.to_json())),
        Decision::Refused(reason::EXPIRED)
    );
    assert_eq!(b.count("mailbox_claims"), 0, "no claim");
    let report: i64 = b
        .store
        .db
        .query_row(
            "SELECT report FROM mailbox_refused WHERE reason=?1",
            [reason::EXPIRED],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(report, 0, "nothing reported");
    assert!(prune(&b.store, now_ms() + 3 * KEEP_MARGIN_MS).unwrap() >= 2);
    assert_eq!(b.count("mailbox_refused") + b.count("mailbox_claims"), 0);
}

/// Ruling R28: an `atem-result` in this host's mailbox is never judged as
/// an envelope: it is kept durably for the sending host's own check (its
/// exact bytes, `object_hash`, sender, id and position), committed with
/// the cursor and owing its done, never counted as inbox (it starts no
/// work); the same object again is a duplicate; one over the results'
/// limits is left on the Station, not done (ruling R31).
#[test]
fn a_result_is_kept_and_marked_done() {
    use atem_client::host_mail::{ResultPlain, seal_result};
    let mail = Mail::new();
    let mut b = Box::new();
    let result = |mail: &Mail| {
        let fields = mail.fields("host-b", mail.log.log.head(), now_ms() + HOUR);
        let plain = ResultPlain::Refusal {
            object_id: uuid(),
            refused: "invalid_request".into(),
        };
        let object = seal_result(
            &mail.sender,
            &KeyId::new("host-b"),
            &fields,
            &plain,
            &mail.enc_pub,
        )
        .unwrap();
        (object, fields.id)
    };
    let (object, id) = result(&mail);
    let text = object.to_json().to_string();
    assert_eq!(decided(b.put(&mail, &object.to_json())), Decision::Result);
    let (hash, sender, object_id, position, bytes): (String, String, String, u64, Vec<u8>) = b
        .store
        .db
        .query_row(
            "SELECT object_hash, sender_host, object_id, position, bytes FROM mailbox_results",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(hash, atem_client::host_mail::object_hash(&object).to_hex());
    assert_eq!((sender.as_str(), object_id, position), ("host-b", id, 1));
    assert_eq!(bytes, text.as_bytes());
    assert_eq!(b.count("mailbox_refused"), 0, "never refused wrong_kind");
    assert_eq!(read(&b.store, &identity(1)).unwrap().inbox, 0);
    assert_eq!(b.owed(), [1]);
    assert_eq!(
        decided(b.put(&mail, &object.to_json())),
        Decision::Duplicate
    );
    let cx = DecideCx {
        limits: Limits {
            results: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    assert_eq!(
        decided(b.put_with(&cx, &result(&mail).0.to_json())),
        Decision::Skipped
    );
    assert_eq!((b.count("mailbox_results"), b.owed()), (1, vec![1, 2]));
}

/// A result from `sender` (claimed: kept results aren't verified here).
fn result_from(mail: &Mail, sender: &str) -> SignedObject {
    use atem_client::host_mail::{ResultPlain, seal_result};
    let fields = mail.fields(sender, mail.log.log.head(), now_ms() + HOUR);
    let plain = ResultPlain::Refusal {
        object_id: uuid(),
        refused: "invalid_request".into(),
    };
    seal_result(
        &mail.sender,
        &KeyId::new("host-b"),
        &fields,
        &plain,
        &mail.enc_pub,
    )
    .unwrap()
}

/// Ruling R31 (review O1): a result over the results' limits is never
/// marked done and never dropped: no row, no claim, no done; its page
/// commits (the cursor moves on) with the lowest skipped position, which
/// survives a restart. Once room frees, the cursor is rewound durably to
/// just before it, and the re-read keeps it and owes its done.
#[test]
fn a_result_over_its_limits_waits_on_the_station_until_room_frees() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            results: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    let first = result_from(&mail, "host-b");
    let second = result_from(&mail, "host-b");
    assert_eq!(decided(b.put_with(&cx, &first.to_json())), Decision::Result);
    assert_eq!(
        decided(b.put_with(&cx, &second.to_json())),
        Decision::Skipped
    );
    decided(b.put_with(&cx, &serde_json::json!("junk")));
    assert_eq!(b.owed(), [1, 3], "no done for the skipped one");
    assert_eq!(b.count("mailbox_results"), 1);
    let dir = b._dir.path().to_path_buf();
    let reopened = Store::open(&dir).unwrap();
    let observed = read(&reopened, &identity(1)).unwrap();
    assert!(
        observed.skipped && !observed.rewind_due,
        "kept across a restart"
    );
    assert_eq!(observed.cursor, Some((MAILBOX.into(), 3)));
    assert!(
        !rewind_if_room(&b.store, &identity(1), cx.now_ms).unwrap(),
        "no room yet"
    );
    // Room frees (the sending host's check took the first).
    b.store
        .db
        .execute("DELETE FROM mailbox_results", [])
        .unwrap();
    assert!(read(&b.store, &identity(1)).unwrap().rewind_due);
    assert!(rewind_if_room(&b.store, &identity(1), cx.now_ms).unwrap());
    let observed = read(&b.store, &identity(1)).unwrap();
    assert_eq!(observed.cursor, Some((MAILBOX.into(), 1)));
    assert!(!observed.skipped);
    b.at = 1;
    assert_eq!(
        decided(b.put_with(&cx, &second.to_json())),
        Decision::Result
    );
    assert_eq!(b.owed(), [1, 2, 3]);
}

/// Ruling R31: each sender host has its own share of both inboxes: one
/// filling its share leaves the next of its objects on the Station
/// (skipped), and another sender's still fit.
#[test]
fn one_sender_filling_its_share_doesnt_block_another() {
    let mut mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            results_per_sender: 1,
            inbox_per_sender: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    assert_eq!(
        decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json())),
        Decision::Result
    );
    assert_eq!(
        decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json())),
        Decision::Skipped
    );
    assert_eq!(
        decided(b.put_with(&cx, &result_from(&mail, "host-c").to_json())),
        Decision::Result
    );
    // The inbox: B's second open waits; C's first fits.
    mail.log.add_host("host-c", 1, &secret("mail host c"));
    let cx = DecideCx {
        limits: Limits {
            inbox_per_sender: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    assert_eq!(
        decided(b.put_with(&cx, &mail.cancel().to_json())),
        Decision::Opened
    );
    let second = mail.cancel();
    assert_eq!(
        decided(b.put_with(&cx, &second.to_json())),
        Decision::Skipped
    );
    let mut c = SoftwareKeys::new();
    c.insert_ed25519(KeyId::new("host-c"), &secret("mail host c"));
    let fields = mail.fields("host-c", mail.log.log.head(), now_ms() + HOUR);
    let from_c = seal_envelope(
        &c,
        &KeyId::new("host-c"),
        &fields,
        &EnvelopePlain::Cancel { task_id: uuid() },
        &mail.enc_pub,
    )
    .unwrap();
    assert_eq!(
        decided(b.put_with(&cx, &from_c.to_json())),
        Decision::Opened
    );
    assert_eq!(
        b.count("mailbox_claims"),
        2,
        "the skipped one claims nothing"
    );
    assert_eq!(read(&b.store, &identity(1)).unwrap().inbox, 2);
}

/// Review O4: the evidence budget drops unauthenticated bytes first: a
/// reused id's (the sender's own signature over two sealed parts, its
/// sender and id recorded, unreported) outlives junk.
#[test]
fn a_reused_ids_evidence_outlives_junk() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            evidence_bytes: 2_000,
            ..Limits::default()
        },
        ..mail.cx()
    };
    let open = mail.cancel();
    decided(b.put_with(&cx, &open.to_json()));
    let body = atem_client::host_mail::MailBody::from_object(&open)
        .unwrap()
        .1;
    let mut fields = body.fields();
    fields.expires_at -= 1;
    assert_eq!(
        decided(b.put_with(&cx, &mail.seal(&fields).to_json())),
        Decision::Refused(ID_REUSED)
    );
    for c in ['a', 'b', 'c'] {
        decided(b.put_with(&cx, &serde_json::json!(c.to_string().repeat(698))));
    }
    let (sender, report, kept): (String, i64, bool) = b
        .store
        .db
        .query_row(
            "SELECT sender_host, report, bytes IS NOT NULL FROM mailbox_refused WHERE reason=?1",
            [ID_REUSED],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((sender.as_str(), report, kept), ("host-b", 0, true));
}

/// Review O5: unauthenticated refusal rows are capped by count, the oldest
/// dropped first (the same bytes again are refused again, unreported);
/// authenticated ones don't count.
#[test]
fn unauthenticated_refusals_are_capped_by_count() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            unauthenticated: 2,
            ..Limits::default()
        },
        ..mail.cx()
    };
    for c in ['a', 'b', 'c'] {
        assert_eq!(
            decided(b.put_with(&cx, &serde_json::json!(c.to_string()))),
            Decision::Refused(reason::MALFORMED)
        );
    }
    assert_eq!(b.count("mailbox_refused"), 2);
    assert_eq!(
        decided(b.put_with(&cx, &serde_json::json!("a"))),
        Decision::Refused(reason::MALFORMED),
        "the oldest went: refused again"
    );
    let mut fields = mail.fields("host-b", mail.log.log.head(), cx.now_ms - 1);
    fields.created_at = cx.now_ms - HOUR;
    decided(b.put_with(&cx, &mail.seal(&fields).to_json()));
    assert_eq!(
        b.count("mailbox_refused"),
        3,
        "the reported one not counted"
    );
}

/// Review P2: a later skip keeps the room freed since an earlier one: the
/// rewind stays due.
#[test]
fn a_later_skip_keeps_the_room_freed_since_an_earlier_one() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            results: 2,
            inbox_per_sender: 0,
            ..Limits::default()
        },
        ..mail.cx()
    };
    for _ in 0..2 {
        assert_eq!(
            decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json())),
            Decision::Result
        );
    }
    assert_eq!(
        decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json())),
        Decision::Skipped
    );
    b.store
        .db
        .execute("DELETE FROM mailbox_results WHERE position=1", [])
        .unwrap();
    assert!(read(&b.store, &identity(1)).unwrap().rewind_due);
    assert_eq!(
        decided(b.put_with(&cx, &mail.cancel().to_json())),
        Decision::Skipped
    );
    assert!(
        read(&b.store, &identity(1)).unwrap().rewind_due,
        "still due"
    );
    assert!(rewind_if_room(&b.store, &identity(1), cx.now_ms).unwrap());
    assert_eq!(
        read(&b.store, &identity(1)).unwrap().cursor,
        Some((MAILBOX.into(), 2))
    );
}

/// Review P3: the lowest skipped position is kept across pages, and the
/// rewind goes to just before it.
#[test]
fn the_lowest_skipped_position_is_kept() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            results: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json()));
    assert_eq!(
        decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json())),
        Decision::Skipped
    );
    decided(b.put_with(&cx, &serde_json::json!("junk")));
    assert_eq!(
        decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json())),
        Decision::Skipped
    );
    b.store
        .db
        .execute("DELETE FROM mailbox_results", [])
        .unwrap();
    assert!(rewind_if_room(&b.store, &identity(1), cx.now_ms).unwrap());
    assert_eq!(
        read(&b.store, &identity(1)).unwrap().cursor,
        Some((MAILBOX.into(), 1))
    );
}

/// Review P3: the inbox's total holds every sender (another sender's
/// object waits though its own share is empty), and an inbox object left
/// on the Station owes no done.
#[test]
fn the_inbox_total_holds_every_sender() {
    let mut mail = Mail::new();
    mail.log.add_host("host-c", 1, &secret("mail host c"));
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            inbox: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    assert_eq!(
        decided(b.put_with(&cx, &mail.cancel().to_json())),
        Decision::Opened
    );
    let mut c = SoftwareKeys::new();
    c.insert_ed25519(KeyId::new("host-c"), &secret("mail host c"));
    let fields = mail.fields("host-c", mail.log.log.head(), now_ms() + HOUR);
    let from_c = seal_envelope(
        &c,
        &KeyId::new("host-c"),
        &fields,
        &EnvelopePlain::Cancel { task_id: uuid() },
        &mail.enc_pub,
    )
    .unwrap();
    assert_eq!(
        decided(b.put_with(&cx, &from_c.to_json())),
        Decision::Skipped
    );
    assert_eq!(b.owed(), [1], "no done for the one left on the Station");
    assert!(read(&b.store, &identity(1)).unwrap().skipped);
}

/// Review P3: the results' bytes in all hold too.
#[test]
fn the_results_bytes_hold() {
    let mail = Mail::new();
    let mut b = Box::new();
    let first = result_from(&mail, "host-b");
    let size = first.to_json().to_string().len() as u64;
    let cx = DecideCx {
        limits: Limits {
            result_bytes: size + 10,
            ..Limits::default()
        },
        ..mail.cx()
    };
    assert_eq!(decided(b.put_with(&cx, &first.to_json())), Decision::Result);
    assert_eq!(
        decided(b.put_with(&cx, &result_from(&mail, "host-c").to_json())),
        Decision::Skipped
    );
}

/// Review P3: a reset forgets every position left on the Station (they
/// belonged to the old read): no skip, no rewind into the new mailbox.
#[test]
fn a_reset_forgets_the_skip() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            results: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json()));
    decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json()));
    assert!(read(&b.store, &identity(1)).unwrap().skipped);
    mark_reset(&b.store, &identity(1), MAILBOX_2).unwrap();
    b.store
        .db
        .execute("DELETE FROM mailbox_results", [])
        .unwrap();
    let observed = read(&b.store, &identity(1)).unwrap();
    assert!(!observed.skipped && !observed.rewind_due);
    assert!(!rewind_if_room(&b.store, &identity(1), cx.now_ms).unwrap());
    assert_eq!(observed.cursor, Some((MAILBOX_2.into(), 0)));
}

/// Review P4: a skip ends with its object: once `D` passes the expiry of
/// the objects left on the Station (the Station has dropped them), the
/// rewind is due whatever the room, and the re-read finds nothing there.
#[test]
fn a_skip_ends_once_its_object_expires() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        limits: Limits {
            results: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    decided(b.put_with(&cx, &result_from(&mail, "host-b").to_json()));
    let second = result_from(&mail, "host-b");
    let expires_at = atem_client::host_mail::MailBody::from_object(&second)
        .unwrap()
        .1
        .expires_at;
    decided(b.put_with(&cx, &second.to_json()));
    let observed = read(&b.store, &identity(1)).unwrap();
    assert_eq!(observed.skip_expires, Some(expires_at));
    assert!(!rewind_if_room(&b.store, &identity(1), expires_at - 1).unwrap());
    assert!(rewind_if_room(&b.store, &identity(1), expires_at).unwrap());
    let observed = read(&b.store, &identity(1)).unwrap();
    assert!(!observed.skipped);
    assert_eq!(observed.cursor, Some((MAILBOX.into(), 1)));
}

/// Review P5: a cursor table of an earlier shape gets the columns it
/// lacks when the tables are made.
#[test]
fn an_older_cursor_table_gets_its_new_columns() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store
        .db
        .execute_batch(
            "CREATE TABLE mailbox_cursor (one INTEGER PRIMARY KEY CHECK (one = 1),
                identity TEXT NOT NULL, mailbox_id TEXT NOT NULL, cursor INTEGER NOT NULL)
                WITHOUT ROWID;",
        )
        .unwrap();
    prepare(&store).unwrap();
    let tx = store.immediate().unwrap();
    set_cursor(&tx, &identity(1), MAILBOX, 4).unwrap();
    tx.commit().unwrap();
    let observed = read(&store, &identity(1)).unwrap();
    assert_eq!(observed.cursor, Some((MAILBOX.into(), 4)));
    assert!(!observed.skipped);
}

/// Review P6: a result already expired on `D` can never be delivered
/// (design II.4.4: one that expired unread isn't delivered), so it is done
/// as expired whatever the room, never skipped. Skipped, it would be due
/// again at once (its skip ends at its expiry, already passed) and read
/// again without pause.
#[test]
fn an_expired_result_is_done_as_expired_never_skipped() {
    let mail = Mail::new();
    let mut b = Box::new();
    let cx = DecideCx {
        now_ms: now_ms() + 2 * HOUR,
        limits: Limits {
            results: 1,
            ..Limits::default()
        },
        ..mail.cx()
    };
    let kept = result_from(&mail, "host-b");
    let expired = result_from(&mail, "host-b");
    // The first fills the results' room; it expired too, so it isn't kept.
    assert_eq!(
        decided(b.put_with(&cx, &kept.to_json())),
        Decision::Refused(EXPIRED)
    );
    assert_eq!(
        decided(b.put_with(&cx, &expired.to_json())),
        Decision::Refused(EXPIRED),
        "never skipped, room or not"
    );
    assert_eq!(b.owed(), [1, 2], "both done: neither is read again");
    assert_eq!(b.count("mailbox_results"), 0);
}

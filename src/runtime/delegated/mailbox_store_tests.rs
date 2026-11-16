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

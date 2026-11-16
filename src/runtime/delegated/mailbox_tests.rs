// The mailbox client on the host's Station link (host-work-v1 §11.5, "The
// mailbox calls", rules 4 to 8; design II.4.3): one live sync per link
// generation, matched to its page by `request_id`, the captured link and
// identity; drained and mismatched pages; resets; pacing; refusals; the
// owed dones; the gate's mailbox part. Pure: the store's committed cursor
// is handed in (`observe`), as the bridge reads it.
use super::*;
use crate::runtime::delegated::station::{LinkKind, StationLink};
use atem_client::encoding::Hash32;
use atem_client::host_mail::mailbox::MailboxSyncResult;
use atem_client::session::host_work::HostTarget;

const MAILBOX: &str = "9d2f6c1e-3b4a-4c5d-8e6f-7a8b9c0d1e2f";
const MAILBOX_2: &str = "3e9fd05f-183e-4b70-be0e-3ffa66120f48";
const SEC: u64 = 1_000;

fn identity(host_trust_gen: u64) -> HostIdentity {
    HostIdentity {
        host: HostTarget {
            account_id: "acct".into(),
            atem_device_id: "host".into(),
            host_trust_gen,
        },
        genesis: Some(Hash32([9; 32])),
    }
}

fn link(link_gen: u64, socket: u64) -> StationLink {
    StationLink {
        link_gen,
        socket,
        kind: LinkKind::Routed,
        origin: Some("https://s.test".into()),
    }
}

fn head(mailbox_id: &str, head: u64) -> Option<MailboxHead> {
    Some(MailboxHead {
        mailbox_id: mailbox_id.into(),
        head,
    })
}

/// A client on link 1 (socket 1) at `now`, its store loaded with `cursor`
/// under identity 1.
fn client(now: u64, cursor: Option<(&str, u64)>) -> MailboxClient {
    let mut c = MailboxClient::default();
    c.on_link(Some(&link(1, 1)));
    c.tick(now);
    c.observe(Some(observed(cursor)));
    c
}

fn observed(cursor: Option<(&str, u64)>) -> Observed {
    Observed {
        identity: identity(1),
        cursor: cursor.map(|(id, at)| (id.to_string(), at)),
        inbox: 0,
    }
}

/// The page answering `call`: `head`, scanned `through`, no object.
fn page(call: &MailboxSync, head: u64, through: u64) -> MailboxSyncResult {
    MailboxSyncResult {
        request_id: call.request_id.clone(),
        mailbox_id: call.mailbox_id.clone(),
        after: call.after,
        head,
        through,
        objects: Vec::new(),
    }
}

/// The sync the client sends now (one at most), marked sent.
fn sent(c: &mut MailboxClient) -> Option<MailboxSync> {
    let out = c.take_outgoing();
    assert!(out.sync.len() <= 1);
    out.sync.into_iter().next()
}

/// Applies `page` as the bridge does: committed with its cursor.
fn commit(c: &mut MailboxClient, p: MailboxSyncResult) {
    match c.on_page(Ok(p.clone())) {
        PageCheck::Apply(applying) => {
            c.observe(Some(observed(Some((&p.mailbox_id, p.through)))));
            c.committed(applying);
        }
        other => panic!("not applied: {other:?}"),
    }
}

/// Rule 8: one sync live per link generation, with a fresh lowercase UUID
/// v4 per call; a page applies only as the live call's answer; the next
/// call (another id) goes once it is answered and the host is still
/// behind; a new link generation retires the live call and asks again.
#[test]
fn one_live_sync_per_link_generation() {
    let mut c = client(10 * SEC, None);
    c.on_heads(head(MAILBOX, 2));
    let first = sent(&mut c).expect("asked at heads");
    assert_eq!((first.mailbox_id.as_str(), first.after), (MAILBOX, 0));
    assert!(atem_client::session::wire::is_uuid_v4(&first.request_id));
    assert_eq!(first.request_id, first.request_id.to_lowercase());
    c.tick(12 * SEC);
    c.on_heads(head(MAILBOX, 2));
    assert_eq!(sent(&mut c), None, "one live call");
    commit(&mut c, page(&first, 2, 1));
    let next = sent(&mut c).expect("still behind: asked at once");
    assert_eq!(next.after, 1);
    assert_ne!(next.request_id, first.request_id);
    // A new link generation: the live call retired, asked again (new id).
    c.on_link(Some(&link(2, 1)));
    c.on_heads(head(MAILBOX, 2));
    let again = sent(&mut c).unwrap();
    assert_eq!(again.after, 1);
    assert_ne!(again.request_id, next.request_id);
    // The retired call's page is drained: nothing applies.
    assert_eq!(c.on_page(Ok(page(&next, 2, 2))), PageCheck::Drained);
    commit(&mut c, page(&again, 2, 2));
    assert_eq!(sent(&mut c), None, "read to its head");
    assert!(c.open());
}

/// Rule 8: a page with an id the host never sent, with the live id that
/// doesn't answer the live call (another mailbox or `after`), or one the
/// reader refused, is a Station fault: nothing applies and the gate stays
/// closed until a page asked after it reads. A page of a call asked on
/// another socket or under another identity is drained.
#[test]
fn late_and_mismatched_pages() {
    let mut c = client(10 * SEC, Some((MAILBOX, 2)));
    c.on_heads(head(MAILBOX, 3));
    let call = sent(&mut c).unwrap();
    let mut never = page(&call, 3, 3);
    never.request_id = "b06daa5d-9f48-4512-8a98-c6d98b159d8e".into();
    assert_eq!(c.on_page(Ok(never)), PageCheck::Fault("unsolicited"));
    assert!(!c.open());
    // The live call is untouched by an unsolicited page.
    let mut other = page(&call, 3, 3);
    other.mailbox_id = MAILBOX_2.into();
    assert_eq!(
        c.on_page(Ok(other)),
        PageCheck::Fault("mismatched_mailbox_id")
    );
    // Retired with its fault: asked again after the pause, a fresh id.
    c.tick(10 * SEC + 30 * SEC);
    let call = sent(&mut c).unwrap();
    let mut after = page(&call, 3, 3);
    after.after = 1;
    assert_eq!(c.on_page(Ok(after)), PageCheck::Fault("mismatched_after"));
    c.tick(70 * SEC);
    let call = sent(&mut c).unwrap();
    assert_eq!(
        c.on_page(Err(atem_client::control::RelayError::NotStrict)),
        PageCheck::Fault("not_strict")
    );
    assert!(!c.open());
    c.tick(100 * SEC);
    let fresh = sent(&mut c).unwrap();
    // A page with the earlier, retired id: drained.
    assert_eq!(c.on_page(Ok(page(&call, 3, 3))), PageCheck::Drained);
    commit(&mut c, page(&fresh, 3, 3));
    assert!(c.open(), "a page asked after the fault read");

    // Asked under identity 1, answered once the host is identity 2.
    let mut c = client(10 * SEC, Some((MAILBOX, 2)));
    c.on_heads(head(MAILBOX, 3));
    let call = sent(&mut c).unwrap();
    c.observe(Some(Observed {
        identity: identity(2),
        ..observed(Some((MAILBOX, 2)))
    }));
    assert_eq!(c.on_page(Ok(page(&call, 3, 3))), PageCheck::Drained);
}

/// Rule 7: an announced mailbox other than the one read, or a head below
/// the cursor (in `heads` or a page), is a reset: nothing is asked until
/// it is marked durably (the store's cursor rewritten), then the
/// announced mailbox is read from 0 and the gate stays closed until it is
/// read to its head.
#[test]
fn a_reset_reads_the_announced_mailbox_from_zero() {
    let mut c = client(10 * SEC, Some((MAILBOX, 5)));
    c.on_heads(head(MAILBOX_2, 2));
    assert_eq!(c.reset_due(), Some(MAILBOX_2.to_string()));
    assert_eq!(sent(&mut c), None, "nothing before the mark");
    assert!(!c.open());
    // Written: the store's cursor is the new mailbox at 0.
    c.observe(Some(observed(Some((MAILBOX_2, 0)))));
    c.reset_written();
    assert_eq!(c.reset_due(), None);
    let call = sent(&mut c).unwrap();
    assert_eq!((call.mailbox_id.as_str(), call.after), (MAILBOX_2, 0));
    commit(&mut c, page(&call, 2, 2));
    assert!(c.open());

    // The same mailbox, its head below the cursor.
    let mut c = client(10 * SEC, Some((MAILBOX, 5)));
    c.on_heads(head(MAILBOX, 3));
    assert_eq!(c.reset_due(), Some(MAILBOX.to_string()));

    // A page whose head is below its `after`.
    let mut c = client(10 * SEC, Some((MAILBOX, 5)));
    c.on_heads(head(MAILBOX, 6));
    let call = sent(&mut c).unwrap();
    let back = MailboxSyncResult {
        head: 1,
        through: 1,
        ..page(&call, 1, 1)
    };
    assert_eq!(c.on_page(Ok(back)), PageCheck::Reset);
    assert_eq!(c.reset_due(), Some(MAILBOX.to_string()));
    assert!(!c.open());
}

/// Rule 8's pacing: a sync a `heads` starts goes at most once a second;
/// none for 30 s after a page that moved nothing while the host is still
/// behind; after a `mailbox_sync_refused`, none until a `heads` 30 s or
/// more later, and the gate stays closed until a page asked after it
/// reads; a call unanswered for 35 s is retired and asked again with a
/// fresh id.
#[test]
fn pacing_refusals_and_timeouts() {
    let mut c = client(10 * SEC, Some((MAILBOX, 2)));
    c.on_heads(head(MAILBOX, 4));
    let call = sent(&mut c).unwrap();
    commit(&mut c, page(&call, 4, 2));
    assert_eq!(sent(&mut c), None, "moved nothing: paused");
    c.tick(10 * SEC + 29 * SEC);
    c.on_heads(head(MAILBOX, 4));
    assert_eq!(sent(&mut c), None);
    c.tick(10 * SEC + 30 * SEC);
    let call = sent(&mut c).expect("the pause is over");
    // Unanswered for 35 s: retired, asked again.
    c.tick(40 * SEC + 35 * SEC);
    let retry = sent(&mut c).expect("asked again");
    assert_ne!(retry.request_id, call.request_id);
    assert_eq!(c.on_page(Ok(page(&call, 4, 4))), PageCheck::Drained);
    // Refused: the live call retired, nothing before a heads past 30 s.
    c.on_sync_refused();
    assert!(!c.open());
    assert_eq!(c.on_page(Ok(page(&retry, 4, 4))), PageCheck::Drained);
    c.tick(75 * SEC + 10 * SEC);
    c.on_heads(head(MAILBOX, 4));
    assert_eq!(sent(&mut c), None, "within the backoff");
    c.tick(75 * SEC + 30 * SEC);
    assert_eq!(sent(&mut c), None, "only a heads asks after a refusal");
    c.on_heads(head(MAILBOX, 4));
    let call = sent(&mut c).unwrap();
    commit(&mut c, page(&call, 4, 4));
    assert!(c.open());
}

/// The gate's mailbox part (design II.5): open only with a link, a
/// mailbox announced and read to its head on this generation, no
/// refusal, fault or reset waiting, and the inbox drained; a `heads`
/// that names no mailbox closes it.
#[test]
fn the_gate_part_follows_the_read() {
    let mut c = client(10 * SEC, Some((MAILBOX, 3)));
    assert!(!c.open(), "no heads yet");
    c.on_heads(head(MAILBOX, 3));
    assert!(c.open());
    c.observe(Some(Observed {
        inbox: 1,
        ..observed(Some((MAILBOX, 3)))
    }));
    assert!(!c.open(), "an inbox row waits for admission");
    c.observe(Some(observed(Some((MAILBOX, 3)))));
    c.on_heads(None);
    assert!(!c.open(), "no mailbox announced");
    c.on_heads(head(MAILBOX, 4));
    assert!(!c.open(), "behind");
    c.observe(None);
    c.on_heads(head(MAILBOX, 3));
    assert!(!c.open(), "the store isn't loaded");
    c.observe(Some(observed(Some((MAILBOX, 3)))));
    assert!(c.open());
    c.on_link(None);
    assert!(!c.open());
}

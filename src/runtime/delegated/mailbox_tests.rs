// The mailbox client on the host's Station link (host-work-v1 §11.5, "The
// mailbox calls", rules 4 to 8; design II.4.3): one live sync per link
// generation, matched to its page by `request_id`, the captured link and
// identity; drained and mismatched pages; resets; pacing; refusals; the
// owed dones; the gate's mailbox part. Pure: the store's committed cursor
// is handed in (`observe`), as the bridge reads it.
use super::*;
use crate::runtime::delegated::station::{LinkKind, StationLink};
use atem_client::encoding::Hash32;
use atem_client::host_mail::mailbox::{MailboxDone, MailboxDoneResult, MailboxSyncResult};
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
        host_key: None,
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
        owed: Vec::new(),
        owed_count: 0,
        skipped: false,
        skipped_inbox: false,
        read_to: cursor.map_or(0, |(_, at)| at),
        waiting_for_room: 0,
        rewind_due: false,
        skip_expires: None,
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

/// The dones owed `owed` (positions), as the store holds them.
fn owing(c: &mut MailboxClient, cursor: (&str, u64), owed: impl IntoIterator<Item = u64>) {
    let owed: Vec<u64> = owed.into_iter().collect();
    c.observe(Some(Observed {
        owed_count: owed.len() as u64,
        owed,
        ..observed(Some(cursor))
    }));
}

fn positions(dones: &[MailboxDone]) -> Vec<u64> {
    dones.iter().map(|d| d.position).collect()
}

fn answer(done: &MailboxDone) -> MailboxDoneResult {
    MailboxDoneResult {
        request_id: done.request_id.clone(),
        mailbox_id: done.mailbox_id.clone(),
        position: done.position,
    }
}

/// Rules 5 and 8: a done goes only for a position the store owes (written
/// with its page's commit), in the mailbox a `heads` on this link
/// generation announced; at most 8 live, each with a fresh id; one
/// answered (its `request_id`, `mailbox_id` and `position`) is no longer
/// owed; an answer that doesn't match, or names an id never sent, changes
/// nothing; one unanswered for 35 s goes again with a fresh id; a
/// `mailbox_done_refused` retires every live done and none goes again on
/// that link generation; the next sends them all again.
#[test]
fn dones_go_after_their_commit_and_again_until_answered() {
    let mut c = client(10 * SEC, Some((MAILBOX, 12)));
    owing(&mut c, (MAILBOX, 12), 1..=10);
    assert!(c.take_outgoing().dones.is_empty(), "no heads: unconfirmed");
    c.on_heads(head(MAILBOX, 12));
    let live = c.take_outgoing().dones;
    assert_eq!(positions(&live), (1..=8).collect::<Vec<_>>());
    let ids: std::collections::BTreeSet<_> = live.iter().map(|d| &d.request_id).collect();
    assert_eq!(ids.len(), 8);
    assert!(live.iter().all(|d| d.mailbox_id == MAILBOX));
    assert!(c.take_outgoing().dones.is_empty(), "sent once");
    let mut other = answer(&live[1]);
    other.position = 9;
    assert_eq!(c.on_done_result(other), None);
    let mut never = answer(&live[1]);
    never.request_id = "b06daa5d-9f48-4512-8a98-c6d98b159d8e".into();
    assert_eq!(c.on_done_result(never), None);
    assert_eq!(
        c.on_done_result(answer(&live[0])),
        Some((MAILBOX.to_string(), 1))
    );
    assert_eq!(c.on_done_result(answer(&live[0])), None, "retired");
    // The bridge removed it from the store.
    owing(&mut c, (MAILBOX, 12), 2..=10);
    assert_eq!(positions(&c.take_outgoing().dones), [9]);
    // Unanswered for 35 s: sent again, with fresh ids.
    c.tick(10 * SEC + 35 * SEC);
    let again = c.take_outgoing().dones;
    assert_eq!(positions(&again), (2..=9).collect::<Vec<_>>());
    assert!(again.iter().all(|d| !ids.contains(&d.request_id)));
    // Refused: every live done retired; none on this link generation.
    c.on_done_refused();
    c.tick(10 * SEC + 80 * SEC);
    assert!(c.take_outgoing().dones.is_empty());
    assert_eq!(c.on_done_result(answer(&again[0])), None);
    c.on_link(Some(&link(2, 1)));
    c.on_heads(head(MAILBOX, 12));
    assert_eq!(
        positions(&c.take_outgoing().dones),
        (2..=9).collect::<Vec<_>>()
    );
    // A reset waiting: nothing goes to the old mailbox.
    c.on_link(Some(&link(3, 1)));
    c.on_heads(head(MAILBOX_2, 1));
    assert!(c.take_outgoing().dones.is_empty());
}

/// Rule 8, "An identity change": every live mailbox call is retired
/// (their answers drained) and nothing more is synced or marked done on
/// that socket; a link on a new socket syncs and marks done again.
#[test]
fn an_identity_change_retires_every_mailbox_call() {
    let mut c = client(10 * SEC, Some((MAILBOX, 2)));
    owing(&mut c, (MAILBOX, 2), [1]);
    c.on_heads(head(MAILBOX, 3));
    let out = c.take_outgoing();
    let (sync, done) = (out.sync[0].clone(), out.dones[0].clone());
    c.on_identity_moved();
    assert_eq!(c.on_page(Ok(page(&sync, 3, 3))), PageCheck::Drained);
    assert_eq!(c.on_done_result(answer(&done)), None);
    c.tick(60 * SEC);
    c.on_heads(head(MAILBOX, 3));
    c.on_link(Some(&link(2, 1)));
    c.on_heads(head(MAILBOX, 3));
    assert_eq!(c.take_outgoing(), Outgoing::default(), "the same socket");
    assert!(!c.open());
    c.on_link(Some(&link(3, 2)));
    c.on_heads(head(MAILBOX, 3));
    let out = c.take_outgoing();
    assert_eq!((out.sync.len(), positions(&out.dones)), (1, vec![1]));
}

/// Rule 4: a page's head is the Station's word, as fresh as a `heads`'s: a
/// page read past the head the last `heads` announced is no reset (its
/// cursor beyond the announced head), and the gate needs that much read.
#[test]
fn a_page_beyond_the_announced_head_is_no_reset() {
    let mut c = client(10 * SEC, None);
    c.on_heads(head(MAILBOX, 2));
    let call = sent(&mut c).unwrap();
    commit(&mut c, page(&call, 6, 5));
    assert_eq!(c.reset_due(), None);
    assert!(!c.open(), "behind the page's head");
    let call = sent(&mut c).expect("asked at once");
    assert_eq!(call.after, 5);
}

/// Review finding 5: a reset retires the live dones to the old mailbox
/// (their answers drained), and the new mailbox's owed dones go at their
/// own positions.
#[test]
fn a_reset_retires_the_live_dones() {
    let mut c = client(10 * SEC, Some((MAILBOX, 2)));
    owing(&mut c, (MAILBOX, 2), [1, 2]);
    c.on_heads(head(MAILBOX, 2));
    let old = c.take_outgoing().dones;
    assert_eq!(positions(&old), [1, 2]);
    c.on_heads(head(MAILBOX_2, 1));
    assert_eq!(c.reset_due(), Some(MAILBOX_2.to_string()));
    assert_eq!(c.on_done_result(answer(&old[0])), None, "drained");
    owing(&mut c, (MAILBOX_2, 0), [1]);
    c.reset_written();
    let out = c.take_outgoing();
    assert_eq!(out.dones.len(), 1);
    assert_eq!(
        (out.dones[0].mailbox_id.as_str(), out.dones[0].position),
        (MAILBOX_2, 1)
    );
}

/// Review finding 7 (rule 8: §11.4's alerts and refusals): each mailbox
/// fault, `mailbox_sync_refused` and `mailbox_done_refused` is counted for
/// `atem status` (how many, the latest) and gets a runtime.log line at most
/// once an hour per kind.
#[test]
fn mailbox_faults_and_refusals_are_hourly_alerts() {
    let mut c = client(10 * SEC, Some((MAILBOX, 2)));
    c.on_heads(head(MAILBOX, 3));
    let call = sent(&mut c).unwrap();
    let mut never = page(&call, 3, 3);
    never.request_id = "b06daa5d-9f48-4512-8a98-c6d98b159d8e".into();
    c.on_page(Ok(never.clone()));
    c.on_page(Ok(never.clone()));
    c.on_sync_refused();
    c.on_done_refused();
    c.on_done_refused();
    let lines = c.take_lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines.iter().any(|l| l.contains("mailbox_sync (forbidden)")));
    assert!(lines.iter().any(|l| l.contains("mailbox_done (forbidden)")));
    assert!(
        lines
            .iter()
            .all(|l| l.ends_with("at most one such line an hour"))
    );
    let (n, latest) = c.alerts();
    assert_eq!(n, 5);
    assert!(latest.unwrap().contains("mailbox_done"));
    c.tick(10 * SEC + 3_600 * SEC);
    c.on_page(Ok(never));
    let lines = c.take_lines();
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("1 more since the last such line"),
        "{lines:?}"
    );
}

/// Ruling R31: a request, cancel or complete left on the Station for want
/// of room keeps the gate's mailbox part closed (not yet committed); once
/// the store rewinds its cursor to just before it, the live call is retired
/// and the re-read asked at once from there.
#[test]
fn a_rewind_rereads_from_the_skipped_position() {
    let mut c = client(10 * SEC, Some((MAILBOX, 5)));
    c.on_heads(head(MAILBOX, 6));
    let live = sent(&mut c).unwrap();
    c.observe(Some(Observed {
        skipped: true,
        skipped_inbox: true,
        ..observed(Some((MAILBOX, 5)))
    }));
    c.on_heads(head(MAILBOX, 5));
    assert!(!c.open(), "a skipped object isn't committed");
    assert!(c.closed().unwrap().contains("room"), "{:?}", c.closed());
    c.observe(Some(observed(Some((MAILBOX, 2)))));
    c.cursor_rewound();
    let call = sent(&mut c).expect("asked at once");
    assert_eq!(call.after, 2);
    assert_eq!(c.on_page(Ok(page(&live, 6, 6))), PageCheck::Drained);
}

/// Review O5: while more than [`MAX_OWED_DONES`] dones are owed, no page is
/// asked (the dones still go); at or below it, pages are asked again.
#[test]
fn many_owed_dones_hold_the_sync() {
    let mut c = client(10 * SEC, Some((MAILBOX, 300)));
    let over = MAX_OWED_DONES + 1;
    c.observe(Some(Observed {
        owed: (1..=64).collect(),
        owed_count: over,
        ..observed(Some((MAILBOX, 300)))
    }));
    c.on_heads(head(MAILBOX, 400));
    let out = c.take_outgoing();
    assert!(out.sync.is_empty(), "held");
    assert_eq!(out.dones.len(), MAX_LIVE_DONES);
    c.observe(Some(Observed {
        owed: (9..=64).collect(),
        owed_count: MAX_OWED_DONES,
        ..observed(Some((MAILBOX, 300)))
    }));
    c.tick(12 * SEC);
    assert_eq!(c.take_outgoing().sync.len(), 1);
}

/// Ruling R35: an object left on the Station for want of room holds the
/// gate's mailbox part only when it is a request, cancel or complete (a
/// result starts no work). The rewind's re-read keeps the mailbox read to
/// the furthest position read (`read_to`), so it closes nothing on its
/// own; a page whose head is below that position is a reset (the mailbox
/// went back), and so is such a `heads`.
#[test]
fn only_a_skipped_request_cancel_or_complete_holds_the_gate() {
    let mut c = client(10 * SEC, Some((MAILBOX, 6)));
    c.on_heads(head(MAILBOX, 6));
    c.observe(Some(Observed {
        skipped: true,
        ..observed(Some((MAILBOX, 6)))
    }));
    assert!(c.open(), "a result left there: {:?}", c.closed());
    c.observe(Some(Observed {
        skipped: true,
        skipped_inbox: true,
        ..observed(Some((MAILBOX, 6)))
    }));
    assert!(c.closed().unwrap().contains("room"), "{:?}", c.closed());
    // The rewind for a result: re-read from 2, the gate open throughout.
    c.observe(Some(Observed {
        read_to: 6,
        ..observed(Some((MAILBOX, 2)))
    }));
    c.cursor_rewound();
    let call = sent(&mut c).expect("asked at once");
    assert_eq!(call.after, 2);
    assert!(c.open(), "{:?}", c.closed());
    // Past the furthest position read, the gate waits as ever.
    c.on_heads(head(MAILBOX, 7));
    assert_eq!(c.closed().as_deref(), Some("reading the mailbox (6 of 7)"));
    // A page whose head is below it: the mailbox went back.
    assert_eq!(c.on_page(Ok(page(&call, 5, 2))), PageCheck::Reset);
    // And a `heads` naming such a head.
    let mut c = client(10 * SEC, Some((MAILBOX, 2)));
    c.observe(Some(Observed {
        read_to: 6,
        ..observed(Some((MAILBOX, 2)))
    }));
    c.on_heads(head(MAILBOX, 5));
    assert_eq!(c.reset_due().as_deref(), Some(MAILBOX));
}

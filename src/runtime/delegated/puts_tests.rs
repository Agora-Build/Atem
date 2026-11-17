// The live puts on the Station link (host-work-v1 §11.5 rule 8): at most
// 8 live, answers matched by `request_id` and `id`, retirement after 35 s,
// at a new link generation and at an identity change.
use super::*;
use crate::runtime::delegated::outbox::Place;
use crate::runtime::delegated::outbox::tests::{AT, envelope};
use crate::runtime::delegated::station::LinkKind;
use atem_client::host_mail::mailbox::PutRefusal;

const T: u64 = 1_800_000_000_000 + 3_600_000;

fn link(link_gen: u64, socket: u64) -> StationLink {
    StationLink {
        link_gen,
        socket,
        kind: LinkKind::Relay,
        origin: None,
    }
}

fn rows(n: std::ops::Range<i64>) -> Vec<Due> {
    n.map(|n| Due {
        n,
        bytes: envelope("b", &uuid::Uuid::new_v4().to_string(), T),
    })
    .collect()
}

fn stored(put: &MailboxPut) -> MailboxStored {
    MailboxStored {
        request_id: put.request_id.clone(),
        id: put.mail().unwrap().1.id,
    }
}

fn client() -> PutClient {
    let mut c = PutClient::default();
    c.on_link(Some(&link(1, 1)));
    c.on_heads(true);
    c.tick(1_000);
    c
}

/// Puts wait for the Station's association of the link (review M1): a
/// `heads` on this link generation announcing this host's mailbox, as the
/// mailbox's own calls do; none on a new generation or after an identity
/// change until its own `heads`, none while the latest announces none.
#[test]
fn puts_wait_for_a_heads_announcing_the_mailbox() {
    let mut c = PutClient::default();
    c.on_link(Some(&link(1, 1)));
    assert!(c.take(rows(0..1), AT).is_empty(), "no heads yet");
    c.on_heads(false);
    assert!(c.take(rows(0..1), AT).is_empty(), "no mailbox served");
    c.on_heads(true);
    assert_eq!(c.take(rows(0..1), AT).len(), 1);
    c.on_link(Some(&link(2, 1)));
    assert!(
        c.take(rows(1..2), AT).is_empty(),
        "a new generation waits for its heads"
    );
    c.on_heads(true);
    assert_eq!(c.take(rows(1..2), AT).len(), 1);
    c.on_heads(false);
    assert!(
        c.take(rows(2..3), AT).is_empty(),
        "the latest heads announces none"
    );
    c.on_heads(true);
    c.on_identity_moved();
    c.on_heads(true);
    assert!(
        c.take(rows(2..3), AT).is_empty(),
        "nothing on a moved socket"
    );
    c.on_link(Some(&link(3, 2)));
    assert!(
        c.take(rows(2..3), AT).is_empty(),
        "a new socket waits for its heads"
    );
    c.on_heads(true);
    assert_eq!(c.take(rows(2..3), AT).len(), 1);
}

/// Eight live at most, each with a fresh id and the row's exact bytes; a
/// row's answer frees its place.
#[test]
fn at_most_eight_puts_are_live() {
    let mut c = client();
    let due = rows(0..10);
    let puts = c.take(due.clone(), AT);
    assert_eq!(puts.len(), MAX_LIVE_PUTS);
    for (put, row) in puts.iter().zip(&due) {
        assert_eq!(put.object.to_json().to_string().into_bytes(), row.bytes);
        assert!(atem_client::session::wire::is_uuid_v4(&put.request_id));
    }
    let ids: std::collections::BTreeSet<_> = puts.iter().map(|p| &p.request_id).collect();
    assert_eq!(ids.len(), MAX_LIVE_PUTS);
    assert_eq!(c.live_rows(), (0..8).collect::<Vec<_>>());
    assert!(c.take(rows(8..10), AT).is_empty());
    assert_eq!(c.on_stored(&stored(&puts[0])), Answer::Row(0, AT));
    assert_eq!(c.take(rows(8..10), AT).len(), 1);
}

/// An answer applies only to a live put with its `request_id` and `id`;
/// a retired put's is drained, an unknown one unsolicited.
#[test]
fn answers_apply_only_to_their_live_put() {
    let mut c = client();
    let puts = c.take(rows(0..2), AT);
    let mut other = stored(&puts[0]);
    other.id = uuid::Uuid::new_v4().to_string();
    assert_eq!(c.on_stored(&other), Answer::Unsolicited);
    let refused = MailboxPutRefused {
        request_id: puts[1].request_id.clone(),
        id: puts[1].mail().unwrap().1.id,
        code: PutRefusal::Quota,
    };
    assert_eq!(c.on_refused(&refused), Answer::Row(1, AT));
    assert_eq!(c.on_refused(&refused), Answer::Drained);
    let mut unknown = stored(&puts[0]);
    unknown.request_id = uuid::Uuid::new_v4().to_string();
    assert_eq!(c.on_stored(&unknown), Answer::Unsolicited);
    assert_eq!(c.on_stored(&stored(&puts[0])), Answer::Row(0, AT));
}

/// A put unanswered for 35 s is retired: its row goes again with a fresh
/// id; the first put's late answer is drained.
#[test]
fn an_unanswered_put_goes_again_with_a_fresh_id() {
    let mut c = client();
    let due = rows(0..1);
    let first = c.take(due.clone(), AT).remove(0);
    c.tick(1_000 + 34_999);
    assert!(c.take(due.clone(), AT).is_empty(), "still live");
    c.tick(1_000 + 35_000);
    assert!(c.live_rows().is_empty());
    let again = c.take(due, AT).remove(0);
    assert_ne!(again.request_id, first.request_id);
    assert_eq!(again.object, first.object);
    assert_eq!(c.on_stored(&stored(&first)), Answer::Drained);
    assert_eq!(c.on_stored(&stored(&again)), Answer::Row(0, AT));
}

/// A new link generation retires every live put; an identity change too,
/// and nothing more goes on that socket until a new one.
#[test]
fn a_new_link_or_identity_retires_the_puts() {
    let mut c = client();
    let first = c.take(rows(0..1), AT).remove(0);
    c.on_link(Some(&link(2, 1)));
    c.on_heads(true);
    assert!(c.live_rows().is_empty());
    assert_eq!(c.on_stored(&stored(&first)), Answer::Drained);
    let second = c.take(rows(0..1), AT).remove(0);
    c.on_identity_moved();
    assert_eq!(c.on_stored(&stored(&second)), Answer::Drained);
    assert!(c.take(rows(0..1), AT).is_empty(), "nothing on that socket");
    c.on_link(Some(&link(3, 1)));
    assert!(c.take(rows(0..1), AT).is_empty(), "the same socket");
    c.on_link(Some(&link(4, 2)));
    c.on_heads(true);
    assert_eq!(c.take(rows(0..1), AT).len(), 1);
    c.on_link(None);
    assert!(c.take(rows(0..1), AT).is_empty(), "no link");
    // A put never handed to the link isn't live; its id answers nothing.
    c.on_link(Some(&link(5, 3)));
    c.on_heads(true);
    let unsent = c.take(rows(0..1), AT).remove(0);
    c.unsent(&unsent.request_id);
    assert!(c.live_rows().is_empty());
    assert_eq!(c.on_stored(&stored(&unsent)), Answer::Unsolicited);
}

/// A due row whose bytes no longer read is never put and is reported, so
/// the store refuses it and it leaves the due rows (review L4).
#[test]
fn a_row_whose_bytes_dont_read_is_reported_not_put() {
    let mut c = client();
    let mut due = rows(0..2);
    due[0].bytes = b"not an object".to_vec();
    let puts = c.take(due, AT);
    assert_eq!(puts.len(), 1);
    assert_eq!(c.live_rows(), [1]);
    assert_eq!(c.take_unreadable(), [0]);
    assert!(c.take_unreadable().is_empty(), "taken");
}

/// An answer carries where its put went (review L-N2), whatever the link
/// or the list is by the time it comes.
#[test]
fn an_answer_carries_where_its_put_went() {
    let mut c = client();
    let went = Place {
        link_gen: 1,
        head_seq: 9,
    };
    let put = c.take(rows(0..1), went).remove(0);
    assert_eq!(c.on_stored(&stored(&put)), Answer::Row(0, went));
}

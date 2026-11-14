// The acknowledgments' book (Task 36; host-work-v1 §11.4
// "Acknowledgments", wire rules 9 and 10; design I.5.8): results as a
// record's transaction gives them, written in a transaction of an
// in-memory database, sent on links the tests make, at `D` the tests give.
use super::*;
use crate::runtime::delegated::station::LinkKind;
use crate::session_protocol::membership::r9log::{auth, secret};
use atem_client::control::{
    ControlAbout, ControlBody, ControlFeed, PendingReason, Why, build_control, principal_key_of,
};
use atem_client::{KeyProvider, SoftwareKeys};

const ORIGIN: &str = "https://station-dev.agora.build";
const FEED: &str = "11111111-1111-4111-8111-111111111111";
const BOT: &str = "svc-bot";
/// When the tests' records are issued.
const ISSUED: u64 = 1_800_000_000_000;
const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;

/// A record of `service:<service>` in the own feed, signed by `signer` (a
/// key the test makes: these tests read records, never verify them).
fn record(
    service: &str,
    signer: ControlSigner,
    action: ControlAction,
    issued_at: u64,
) -> ControlRecord {
    let mut keys = SoftwareKeys::new();
    keys.insert_ed25519(auth("k"), &secret("acks k"));
    let public = keys.public_key(&auth("k")).unwrap();
    let body = ControlBody {
        account_id: "acct".into(),
        genesis_hash: Hash32([1; 32]),
        feed: Some(ControlFeed {
            origin: ORIGIN.into(),
            feed_id: FEED.into(),
        }),
        principal: ControlPrincipal::Service(service.into()),
        principal_key: Some(principal_key_of(&public).unwrap()),
        signer,
        action,
        record_id: uuid::Uuid::new_v4().to_string(),
        issued_at,
        about: ControlAbout {
            integration_id: Some(format!("i-{service}")),
            by: "owner".into(),
        },
    };
    ControlRecord::from_signed(build_control(&keys, &auth("k"), &body).unwrap()).unwrap()
}

/// The bot's own revoke (signed with its key).
fn own_revoke(interrupt_running: bool, issued_at: u64) -> ControlRecord {
    record(
        BOT,
        ControlSigner::Principal,
        ControlAction::Revoke { interrupt_running },
        issued_at,
    )
}

/// What applying a record gave: each effect's result and reason, as the
/// state writes them (a reason exactly beside `pending` or `refused`).
fn applied(effects: &[(EffectKind, ApplicationResult, Option<Why>)]) -> Applied {
    let effects: Vec<EffectResult> = effects
        .iter()
        .map(|(effect, result, why)| EffectResult {
            effect: *effect,
            result: *result,
            why: why.map(EffectWhy::Known),
        })
        .collect();
    Applied {
        record_result: ApplicationResult::of_effects(&effects),
        why: effects.iter().find_map(|e| match &e.why {
            Some(EffectWhy::Known(why)) => Some(*why),
            _ => None,
        }),
        effects,
        actions: Vec::new(),
        evidence: false,
    }
}

fn in_force(effect: EffectKind) -> Applied {
    applied(&[(effect, ApplicationResult::Applied, None)])
}

fn at(seq: u64) -> FeedPos {
    FeedPos {
        origin: ORIGIN.into(),
        feed_id: FEED.into(),
        feed_seq: seq,
    }
}

/// The link's generation `n`, on its own socket.
fn link(n: u64) -> StationLink {
    StationLink {
        link_gen: n,
        socket: n,
        kind: LinkKind::Relay,
        origin: Some(ORIGIN.into()),
    }
}

fn claim() -> Claim {
    Claim {
        account_id: "acct".into(),
        genesis_hash: Hash32([1; 32]),
        host_id: "host".into(),
        host_trust_gen: 1,
    }
}

/// The book of a fresh database.
fn fresh() -> (Connection, AckBook) {
    let db = Connection::open_in_memory().unwrap();
    let book = AckBook::load(&db).unwrap();
    (db, book)
}

/// `results` written in a transaction that commits; the book adopted then.
fn commit(db: &Connection, book: &mut AckBook, results: &[Acked]) {
    let tx = db.unchecked_transaction().unwrap();
    let mut next = book.clone();
    next.on_committed(&tx, results).unwrap();
    tx.commit().unwrap();
    *book = next;
}

/// The acks due on `link` at `D` = `now`, the feed read to `cursor`, handed
/// to it and marked sent: their results.
fn send(
    db: &Connection,
    book: &mut AckBook,
    link: &StationLink,
    cursor: u64,
    now: u64,
) -> Vec<Vec<AckResult>> {
    let due = book.due(link, Some((FEED, cursor)), &claim(), Some(now));
    let tx = db.unchecked_transaction().unwrap();
    book.sent(&tx, link, Some(now), &due).unwrap();
    tx.commit().unwrap();
    due.into_iter().map(|d| d.ack.results).collect()
}

/// The record ids of the results the acks carry, in order.
fn ids(acks: &[Vec<AckResult>]) -> Vec<String> {
    acks.iter()
        .flatten()
        .map(|r| match r {
            AckResult::Record { record_id, .. } => record_id.clone(),
            AckResult::Entry { .. } => panic!("no entry results in step 4"),
        })
        .collect()
}

/// The table's rows: key, `resend_until_ms`, `sent_gen`.
fn table(db: &Connection) -> Vec<(String, Option<i64>, Option<i64>)> {
    let mut q = db
        .prepare("SELECT key, resend_until_ms, sent_gen FROM control_acks ORDER BY rowid")
        .unwrap();
    q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// §11.4 "When a host acknowledges", wire rules 3, 9 and 10 (O5): an ack
/// carries each record's result exactly as its application gave it, every
/// effect the record carries in the record's order, each not in force with
/// the state's reason and never one beside `applied` or `duplicate`; under
/// the host's claim, naming the feed and the cursor given. The shared
/// core's writer takes it and its reader reads back the same ack. The rows
/// are durable: a book loaded again owes the same. A record applied again
/// is owed with its new result (a `duplicate`), never the old one.
#[test]
fn results_carry_exactly_the_records_effects() {
    use atem_client::control::ControlAck;
    let (db, mut book) = fresh();
    let cover = record(BOT, ControlSigner::Principal, ControlAction::Cover, ISSUED);
    let revoke = own_revoke(true, ISSUED + 1);
    let release = record(
        BOT,
        ControlSigner::Principal,
        ControlAction::Release,
        ISSUED + 2,
    );
    let interrupt = record(
        "svc-other",
        ControlSigner::Principal,
        ControlAction::InterruptRunning { revoke_seq: None },
        ISSUED + 3,
    );
    let results = [
        (&cover, in_force(EffectKind::Cover)),
        (
            &revoke,
            applied(&[
                (EffectKind::Revocation, ApplicationResult::Duplicate, None),
                (EffectKind::Interrupt, ApplicationResult::Applied, None),
            ]),
        ),
        (
            &release,
            applied(&[(
                EffectKind::Release,
                ApplicationResult::Refused,
                Some(Why::NotAfterHold),
            )]),
        ),
        (
            &interrupt,
            applied(&[(
                EffectKind::Interrupt,
                ApplicationResult::Pending,
                Some(Why::Pending(PendingReason::NotRevoked)),
            )]),
        ),
    ];
    let acked: Vec<Acked> = results
        .iter()
        .enumerate()
        .map(|(i, (record, applied))| Acked::of(record, applied, Some(&at(i as u64 + 1))))
        .collect();
    commit(&db, &mut book, &acked);
    let expected: Vec<AckResult> = results
        .iter()
        .map(|(record, applied)| AckResult::Record {
            record_id: record.record_id().to_owned(),
            effects: applied.effects.clone(),
        })
        .collect();
    let due = book.due(&link(1), Some((FEED, 4)), &claim(), Some(ISSUED));
    assert_eq!(due.len(), 1);
    let ack = &due[0].ack;
    assert_eq!(ack.results, expected);
    assert_eq!(
        (
            ack.account_id.as_str(),
            ack.genesis_hash,
            ack.host_id.as_str(),
            ack.host_trust_gen
        ),
        ("acct", Hash32([1; 32]), "host", 1)
    );
    assert_eq!(
        (ack.origin.as_str(), ack.feed_id.as_str(), ack.cursor),
        (ORIGIN, FEED, 4)
    );
    let wire = ack.to_json().unwrap().to_string();
    assert_eq!(&ControlAck::decode(wire.as_bytes()).unwrap(), ack);
    assert!(wire.contains(r#""why":"not_after_hold""#), "{wire}");
    assert!(wire.contains(r#""why":"not_revoked""#), "{wire}");
    // Durable: a book loaded again owes the same.
    let again = AckBook::load(&db).unwrap();
    assert_eq!(
        again.due(&link(1), Some((FEED, 4)), &claim(), Some(ISSUED)),
        due
    );
    // Sent; then the revoke served again: owed with this result.
    send(&db, &mut book, &link(1), 4, ISSUED);
    let duplicate = applied(&[
        (EffectKind::Revocation, ApplicationResult::Duplicate, None),
        (EffectKind::Interrupt, ApplicationResult::Duplicate, None),
    ]);
    commit(
        &db,
        &mut book,
        &[Acked::of(&revoke, &duplicate, Some(&at(5)))],
    );
    let due = book.due(&link(1), Some((FEED, 5)), &claim(), Some(ISSUED));
    assert_eq!(
        due.into_iter().map(|d| d.ack.results).collect::<Vec<_>>(),
        [vec![AckResult::Record {
            record_id: revoke.record_id().to_owned(),
            effects: duplicate.effects,
        }]]
    );
}

/// §11.4: the result of a service's own revoke (signed with its key), in
/// force, is sent again on every connection and every 10 minutes on `D`
/// while connected, until its `issued_at` plus 25 hours; then it leaves the
/// book. A restart is a connection: the book loaded again owes it at once.
#[test]
fn own_revoke_results_resent_every_10_minutes_until_issued_at_plus_25h() {
    let (db, mut book) = fresh();
    let revoke = own_revoke(false, ISSUED);
    let acked = Acked::of(&revoke, &in_force(EffectKind::Revocation), Some(&at(1)));
    assert_eq!(acked.resend, Resend::Until(ISSUED + RESEND_FOR_MS));
    assert_eq!(RESEND_FOR_MS, 25 * HOUR);
    assert_eq!(RESEND_EVERY_MS, 10 * MIN);
    commit(&db, &mut book, &[acked]);
    let id = vec![revoke.record_id().to_owned()];
    let d0 = ISSUED + MIN;
    assert_eq!(ids(&send(&db, &mut book, &link(1), 1, d0)), id);
    assert!(send(&db, &mut book, &link(1), 1, d0 + 9 * MIN).is_empty());
    assert_eq!(ids(&send(&db, &mut book, &link(1), 1, d0 + 10 * MIN)), id);
    assert!(send(&db, &mut book, &link(1), 1, d0 + 19 * MIN).is_empty());
    // A new connection: at once.
    assert_eq!(ids(&send(&db, &mut book, &link(2), 1, d0 + 11 * MIN)), id);
    // A restart (the book loaded again): at its first connection.
    let mut again = AckBook::load(&db).unwrap();
    assert_eq!(ids(&send(&db, &mut again, &link(1), 1, d0 + 12 * MIN)), id);
    // `D` went back (a lowering): sent again rather than never.
    assert_eq!(ids(&send(&db, &mut again, &link(1), 1, d0)), id);
    // Its last resend before the deadline; none at it, and it leaves the
    // book and its table.
    let last = ISSUED + RESEND_FOR_MS - 1;
    assert_eq!(ids(&send(&db, &mut again, &link(1), 1, last)), id);
    assert!(send(&db, &mut again, &link(3), 1, ISSUED + RESEND_FOR_MS).is_empty());
    assert!(table(&db).is_empty(), "{:?}", table(&db));
    assert_eq!(again.dump()["results"], 0);
    // One first owed past its deadline (an old revoke read late) still
    // goes once, then leaves.
    let late = own_revoke(false, ISSUED);
    commit(
        &db,
        &mut again,
        &[Acked::of(
            &late,
            &in_force(EffectKind::Revocation),
            Some(&at(2)),
        )],
    );
    let after = ISSUED + 2 * RESEND_FOR_MS;
    assert_eq!(
        ids(&send(&db, &mut again, &link(3), 2, after)),
        [late.record_id()]
    );
    assert!(table(&db).is_empty());
}

/// §11.4: any other in-force result of a stop (a native's revoke, an
/// `interrupt_running`), which no deadline bounds, goes once per
/// connection, a restart's first one included; results not in force, and
/// those of a `cover`, `hold` or `release`, go once and leave the book.
/// A principal's first [`RESENT_PER_PRINCIPAL`] in-force results are kept
/// for resending: a fifth goes once.
#[test]
fn other_in_force_results_once_per_connection() {
    let (db, mut book) = fresh();
    let native = record(
        BOT,
        ControlSigner::Member("dev-mac".into()),
        ControlAction::Revoke {
            interrupt_running: false,
        },
        ISSUED,
    );
    let interrupt = record(
        BOT,
        ControlSigner::Principal,
        ControlAction::InterruptRunning { revoke_seq: None },
        ISSUED + 1,
    );
    let cover = record(
        "svc-two",
        ControlSigner::Principal,
        ControlAction::Cover,
        ISSUED + 2,
    );
    let hold = record(
        "svc-two",
        ControlSigner::Principal,
        ControlAction::Hold,
        ISSUED + 3,
    );
    let waiting = record(
        "svc-two",
        ControlSigner::Member("dev-mac".into()),
        ControlAction::Revoke {
            interrupt_running: false,
        },
        ISSUED + 4,
    );
    let pending = applied(&[(
        EffectKind::Revocation,
        ApplicationResult::Pending,
        Some(Why::Pending(PendingReason::SignerUnknown)),
    )]);
    let acked = [
        Acked::of(&native, &in_force(EffectKind::Revocation), Some(&at(1))),
        Acked::of(&interrupt, &in_force(EffectKind::Interrupt), Some(&at(2))),
        Acked::of(&cover, &in_force(EffectKind::Cover), Some(&at(3))),
        Acked::of(&hold, &in_force(EffectKind::Hold), Some(&at(4))),
        Acked::of(&waiting, &pending, Some(&at(5))),
    ];
    let kinds: Vec<Resend> = acked.iter().map(|a| a.resend).collect();
    assert_eq!(
        kinds,
        [
            Resend::PerConnection,
            Resend::PerConnection,
            Resend::Once,
            Resend::Once,
            Resend::Once
        ]
    );
    commit(&db, &mut book, &acked);
    let all: Vec<String> = [&native, &interrupt, &cover, &hold, &waiting]
        .iter()
        .map(|r| r.record_id().to_owned())
        .collect();
    assert_eq!(ids(&send(&db, &mut book, &link(1), 5, ISSUED)), all);
    let kept = vec![
        native.record_id().to_owned(),
        interrupt.record_id().to_owned(),
    ];
    let stored: Vec<String> = table(&db).into_iter().map(|(key, _, _)| key).collect();
    assert_eq!(stored, kept, "those sent once left");
    // The same connection, an hour on: nothing.
    assert!(send(&db, &mut book, &link(1), 5, ISSUED + HOUR).is_empty());
    // The next connection: once each, and again not on it.
    assert_eq!(ids(&send(&db, &mut book, &link(2), 5, ISSUED + HOUR)), kept);
    assert!(send(&db, &mut book, &link(2), 5, ISSUED + 2 * HOUR).is_empty());
    // A restart's first connection, a day on: once each.
    let mut again = AckBook::load(&db).unwrap();
    assert_eq!(
        ids(&send(&db, &mut again, &link(1), 5, ISSUED + 30 * HOUR)),
        kept
    );
    assert!(send(&db, &mut again, &link(1), 5, ISSUED + 31 * HOUR).is_empty());

    // The bound: a principal's first four in-force results are kept.
    let (db, mut book) = fresh();
    let revokes: Vec<ControlRecord> = (0..5)
        .map(|n| {
            record(
                BOT,
                ControlSigner::Member(format!("dev-{n}")),
                ControlAction::Revoke {
                    interrupt_running: false,
                },
                ISSUED + n,
            )
        })
        .collect();
    let duplicate = applied(&[(EffectKind::Revocation, ApplicationResult::Duplicate, None)]);
    for (n, revoke) in revokes.iter().enumerate() {
        commit(
            &db,
            &mut book,
            &[Acked::of(revoke, &duplicate, Some(&at(n as u64 + 1)))],
        );
    }
    assert_eq!(ids(&send(&db, &mut book, &link(1), 5, ISSUED)).len(), 5);
    let first: Vec<String> = revokes[..RESENT_PER_PRINCIPAL]
        .iter()
        .map(|r| r.record_id().to_owned())
        .collect();
    assert_eq!(ids(&send(&db, &mut book, &link(2), 5, ISSUED)), first);
}

/// Decision 20, §11.4 "Refusals": `control_ack_refused` advances nothing in
/// the book: no result is taken as delivered or dropped, its table is
/// unchanged, and no resend's schedule moves. Nothing more goes on the
/// connection it came on (the next ack there would be refused too), not
/// even a new commit's result or an own revoke's 10 minutes; at the next
/// connection everything owed goes, as without the refusal.
#[test]
fn an_ack_refusal_advances_nothing() {
    let (db, mut book) = fresh();
    let revoke = own_revoke(false, ISSUED);
    let native = record(
        "svc-two",
        ControlSigner::Member("dev-mac".into()),
        ControlAction::Revoke {
            interrupt_running: false,
        },
        ISSUED,
    );
    commit(
        &db,
        &mut book,
        &[
            Acked::of(&revoke, &in_force(EffectKind::Revocation), Some(&at(1))),
            Acked::of(&native, &in_force(EffectKind::Revocation), Some(&at(2))),
        ],
    );
    assert_eq!(ids(&send(&db, &mut book, &link(1), 2, ISSUED)).len(), 2);
    let stored = table(&db);
    let before = book.clone();
    book.on_refused();
    assert_eq!(table(&db), stored);
    assert_eq!(
        book.rows, before.rows,
        "nothing taken as delivered or moved"
    );
    assert_eq!(book.acked, before.acked);
    // Nothing more on that connection: the 10 minutes passed, a new
    // commit's result and its cursor.
    let hold = record(
        "svc-two",
        ControlSigner::Principal,
        ControlAction::Hold,
        ISSUED + 1,
    );
    commit(
        &db,
        &mut book,
        &[Acked::of(&hold, &in_force(EffectKind::Hold), Some(&at(3)))],
    );
    assert!(send(&db, &mut book, &link(1), 3, ISSUED + 20 * MIN).is_empty());
    assert_eq!(table(&db).len(), 3, "the hold still owed");
    // The next connection: all of it.
    assert_eq!(
        ids(&send(&db, &mut book, &link(2), 3, ISSUED + 21 * MIN)),
        [revoke.record_id(), native.record_id(), hold.record_id()]
    );
}

/// §11.4 "the ack of the cursor itself goes on": a commit that moved the
/// cursor with no result (a page of no record) is acknowledged once, with
/// none; a result read from a feed of another Station (one the host left)
/// goes nowhere and leaves the book; one read at no position (a record
/// carried over a channel) names the own Station's feed (wire rule 9).
#[test]
fn the_cursor_goes_on_and_feedless_results_name_the_own_feed() {
    let (db, mut book) = fresh();
    let first = send(&db, &mut book, &link(1), 3, ISSUED);
    assert_eq!(first, [Vec::<AckResult>::new()], "the cursor");
    assert!(send(&db, &mut book, &link(1), 3, ISSUED).is_empty());
    assert_eq!(send(&db, &mut book, &link(1), 4, ISSUED).len(), 1);
    let elsewhere = own_revoke(false, ISSUED);
    let carried = record(
        BOT,
        ControlSigner::Member("dev-mac".into()),
        ControlAction::InterruptRunning { revoke_seq: None },
        ISSUED,
    );
    let other = FeedPos {
        origin: "https://station-other.agora.build".into(),
        ..at(9)
    };
    commit(
        &db,
        &mut book,
        &[
            Acked::of(&elsewhere, &in_force(EffectKind::Revocation), Some(&other)),
            Acked::of(&carried, &in_force(EffectKind::Interrupt), None),
        ],
    );
    let due = book.due(&link(1), Some((FEED, 4)), &claim(), Some(ISSUED));
    assert_eq!(due.len(), 1);
    assert_eq!(
        (due[0].ack.origin.as_str(), due[0].ack.feed_id.as_str()),
        (ORIGIN, FEED)
    );
    assert_eq!(ids(&[due[0].ack.results.clone()]), [carried.record_id()]);
    send(&db, &mut book, &link(1), 4, ISSUED);
    let stored: Vec<String> = table(&db).into_iter().map(|(key, _, _)| key).collect();
    assert_eq!(stored, [carried.record_id()], "the other Station's left");
}

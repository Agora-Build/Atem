// The control feed store (design I.5.4, I.5.5; host-work-v1 §11.1): a
// host-work store in a temp directory, a test account's device list with
// a bot (a service on this host), records the bot's Station signs with the
// bot's key, and a manual clock.
use super::*;
use crate::session_protocol::membership::r9log::{TestLog, auth, secret};
use atem_client::control::{ApplicationResult, ControlAction, EffectKind, HostAction, Why};
use atem_client::membership::HostNow;
use atem_client::session::host_work::HostTarget;
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://station-dev.agora.build";
const FEED: &str = "11111111-1111-4111-8111-111111111111";
const BOT: &str = "service:svc-bot";
const HOUR: u64 = 3_600_000;
const MIN: u64 = 60_000;

/// A store, the device list, the feed store on a manual clock.
struct Rig {
    _dir: tempfile::TempDir,
    store: Store,
    log: TestLog,
    feeds: FeedStore,
    clock: Arc<Mutex<HostNow>>,
    issued: u64,
}

fn host() -> HostTarget {
    HostTarget {
        account_id: "acct-f".into(),
        atem_device_id: "host".into(),
        host_trust_gen: 1,
    }
}

/// A service grant's expiry: a day from now.
fn expiry() -> u64 {
    crate::session_protocol::membership::r9log::host_now().wall_ms + 24 * HOUR
}

/// The Mac, this host and the bot (a service on this host).
fn list() -> TestLog {
    let mut log = TestLog::genesis("acct-f", &secret("feeds astation"));
    log.add_host("host", 1, &secret("feeds host"));
    log.add_service(
        "svc-bot",
        &["host"],
        None,
        &["notify", "prompt", "view"],
        expiry(),
    );
    log
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.bind(&host()).unwrap();
    let log = list();
    let clock = Arc::new(Mutex::new(HostNow {
        wall_ms: 1_800_000_000_000,
        mono_ms: 10 * HOUR,
        boot_id: "boot".into(),
    }));
    let feeds = load(&store, &log, &clock);
    Rig {
        _dir: dir,
        store,
        log,
        feeds,
        clock,
        issued: 1_700_000_000_000,
    }
}

/// The feed store as `store` holds it, on `clock`, its own Station
/// [`ORIGIN`].
fn load(store: &Store, log: &TestLog, clock: &Arc<Mutex<HostNow>>) -> FeedStore {
    let clock = clock.clone();
    let mut feeds = FeedStore::load(store, &log.log)
        .unwrap()
        .with_clock(move || clock.lock().unwrap().clone());
    feeds.set_own_origin(Some(ORIGIN.into()));
    feeds
}

/// The list as it serves.
fn serving(log: &TestLog) -> ListState {
    ListState {
        membership: Arc::new(log.log.clone()),
        frozen: false,
        held: false,
        faulted: false,
        unpaired: false,
        deferred: None,
    }
}

impl Rig {
    /// A record of `service:<service>` signed with `key`'s key (the
    /// service's own, or another, which gives a bad signature), under
    /// `record_id` (a fresh one when none), issued after every earlier one.
    fn signed(
        &mut self,
        service: &str,
        key: &str,
        action: ControlAction,
        record_id: Option<&str>,
    ) -> ControlRecord {
        self.issued += 1_000;
        let record_id = record_id.map_or_else(|| uuid::Uuid::new_v4().to_string(), String::from);
        signed_record(
            &self.log,
            service,
            key,
            action,
            record_id,
            (ORIGIN, FEED),
            self.issued,
        )
    }

    /// The bot's own record.
    fn bot(&mut self, action: ControlAction) -> ControlRecord {
        self.signed("svc-bot", "svc-bot", action, None)
    }

    /// A record of the bot that fails verification (`bad_signature`).
    fn forged(&mut self) -> ControlRecord {
        self.log
            .keys
            .insert_ed25519(auth("svc-forger"), &secret("forger"));
        self.signed("svc-bot", "svc-forger", ControlAction::Hold, None)
    }

    /// `rec` read at `seq` of the feed, in its own transaction, committed.
    fn apply_at(&mut self, rec: &ControlRecord, seq: u64) -> Applied {
        let list = serving(&self.log);
        let tx = self.feeds.begin(&self.store).unwrap();
        let applied = self.feeds.apply(&tx, rec, &list, at(seq), 0).unwrap();
        self.feeds.commit(tx).unwrap();
        applied
    }

    /// The pending records re-verified against the list, committed.
    fn reverify(&mut self) -> Vec<Reapplied> {
        let list = serving(&self.log);
        let tx = self.feeds.begin(&self.store).unwrap();
        let again = self.feeds.reverify_pending(&tx, &list, 0).unwrap();
        self.feeds.commit(tx).unwrap();
        again
    }

    fn pass(&self, ms: u64) {
        let mut now = self.clock.lock().unwrap();
        now.mono_ms += ms;
        now.wall_ms += ms;
    }

    /// What another connection reads of the store now (committed only).
    fn stored(&self) -> Stored {
        let db = rusqlite::Connection::open(self.store.state.join("host-work.sqlite")).unwrap();
        let rows = |sql: &str| -> Vec<(String, String)> {
            let mut st = db.prepare(sql).unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let count = |kind: &str| -> u64 {
            db.query_row(
                "SELECT count FROM control_counts WHERE kind=?1",
                [kind],
                |r| r.get(0),
            )
            .unwrap_or(0)
        };
        let ns = |table: &str| -> Vec<u64> {
            let mut st = db
                .prepare(&format!("SELECT n FROM {table} ORDER BY n"))
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        Stored {
            parts: rows("SELECT principal, part FROM control_principals ORDER BY principal"),
            cursors: rows(
                "SELECT origin || ' ' || feed_id, cast(cursor AS TEXT) FROM control_feeds",
            ),
            pending: rows("SELECT principal, record_id FROM control_pending ORDER BY n"),
            evidence: ns("control_evidence"),
            evidence_count: count("evidence"),
            pending_count: count("pending"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Stored {
    parts: Vec<(String, String)>,
    cursors: Vec<(String, String)>,
    pending: Vec<(String, String)>,
    evidence: Vec<u64>,
    evidence_count: u64,
    pending_count: u64,
}

fn at(seq: u64) -> FeedPos {
    at_feed(FEED, seq)
}

fn at_feed(feed_id: &str, seq: u64) -> FeedPos {
    FeedPos {
        origin: ORIGIN.into(),
        feed_id: feed_id.into(),
        feed_seq: seq,
    }
}

fn cursor_row(seq: u64) -> Vec<(String, String)> {
    vec![(format!("{ORIGIN} {FEED}"), seq.to_string())]
}

fn bot_feed() -> FeedRef {
    FeedRef {
        origin: ORIGIN.into(),
        feed_id: FEED.into(),
    }
}

/// Design I.5.5, host-work-v1 §11.1 ("Application"): a record's touched
/// part and the cursor are written in one `BEGIN IMMEDIATE` transaction,
/// nothing of it visible before the commit (to another connection, or as
/// the store's standing), and all of it after; a reload reads the same.
#[test]
fn a_record_applies_in_one_transaction_with_the_cursor() {
    let mut rig = rig();
    let cover = rig.bot(ControlAction::Cover);
    let applied = rig.apply_at(&cover, 1);
    assert_eq!(applied.record_result, ApplicationResult::Applied);
    assert_eq!(
        rig.feeds.standing(BOT).coverage,
        Some(bot_feed()),
        "a cover covers"
    );
    let stored = rig.stored();
    assert_eq!(stored.cursors, cursor_row(1));
    assert_eq!(stored.parts.len(), 1);
    assert_eq!(stored.parts[0].0, BOT);

    // A hold, in its transaction: nothing of it before the commit.
    let hold = rig.bot(ControlAction::Hold);
    let list = serving(&rig.log);
    let tx = rig.feeds.begin(&rig.store).unwrap();
    let applied = rig.feeds.apply(&tx, &hold, &list, at(2), 0).unwrap();
    assert_eq!(applied.actions, [HostAction::Hold(BOT.into())]);
    assert!(
        !rig.feeds.standing(BOT).held,
        "adopted only after the commit"
    );
    assert_eq!(rig.stored(), stored, "another connection sees nothing yet");
    rig.feeds.commit(tx).unwrap();
    assert!(rig.feeds.standing(BOT).held);
    let after = rig.stored();
    assert_eq!(after.cursors, cursor_row(2));
    assert_ne!(after.parts, stored.parts, "the touched part, written");

    // The store as it reloads: the same state, cursor and standings.
    let again = load(&rig.store, &rig.log, &rig.clock);
    assert_eq!(again.cursor(ORIGIN, FEED), Some(2));
    assert_eq!(again.standings(), rig.feeds.standings());
    assert!(again.standing(BOT).held);
    // A duplicate touches no part, and still moves the cursor.
    let applied = rig.apply_at(&hold, 3);
    assert_eq!(applied.record_result, ApplicationResult::Duplicate);
    assert_eq!(rig.stored().parts, after.parts);
    assert_eq!(rig.stored().cursors, cursor_row(3));
}

/// Design I.5.5, host-work-v1 §11.1: a transaction that fails (here, the
/// cursor's write) loses no effect: the store keeps the state it applied
/// on, nothing is written, and the record applied again gives the same
/// results and actions; so does one whose transaction is dropped.
#[test]
fn a_failed_transaction_loses_no_effect_and_reapplies_the_same() {
    let mut rig = rig();
    let cover = rig.bot(ControlAction::Cover);
    rig.apply_at(&cover, 1);
    let before = rig.stored();
    let standings = rig.feeds.standings();
    let revoke = rig.bot(ControlAction::Revoke {
        interrupt_running: true,
    });
    let list = serving(&rig.log);

    // The cursor's write fails.
    rig.store
        .db
        .execute_batch(
            "CREATE TEMP TRIGGER fail_cursor BEFORE UPDATE ON control_feeds
            BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
    let tx = rig.feeds.begin(&rig.store).unwrap();
    assert!(rig.feeds.apply(&tx, &revoke, &list, at(2), 0).is_err());
    drop(tx);
    assert_eq!(rig.feeds.standings(), standings, "nothing adopted");
    assert_eq!(rig.stored(), before, "nothing written");
    rig.store
        .db
        .execute_batch("DROP TRIGGER fail_cursor")
        .unwrap();

    // A transaction dropped before its commit: the same.
    let tx = rig.feeds.begin(&rig.store).unwrap();
    let first = rig.feeds.apply(&tx, &revoke, &list, at(2), 0).unwrap();
    drop(tx);
    assert_eq!(rig.feeds.standings(), standings);
    assert_eq!(rig.stored(), before);

    // Applied again: the same results and actions, now in force.
    let again = rig.apply_at(&revoke, 2);
    assert_eq!(again, first);
    assert_eq!(again.record_result, ApplicationResult::Applied);
    assert_eq!(
        again.actions,
        [
            HostAction::Revoke(BOT.into()),
            HostAction::Interrupt {
                principal: BOT.into(),
                revocation: revoke.record_id().into(),
            }
        ]
    );
    assert_eq!(
        rig.feeds.standing(BOT).revoked.as_deref(),
        Some(revoke.record_id())
    );
    assert_eq!(rig.stored().cursors, cursor_row(2));
    // A begin discards whatever an earlier transaction left staged.
    let hold = rig.bot(ControlAction::Hold);
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.apply(&tx, &hold, &list, at(3), 0).unwrap();
    drop(tx);
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.commit(tx).unwrap();
    assert!(
        !rig.feeds.standing(BOT).held,
        "the dropped hold never adopted"
    );
}

/// Design I.5.4 (a principal not in the applied list yet: stored as
/// pending, verified again after every device-list advance), host-work-v1
/// §11.1: the record waits, durably, the cursor past it; re-verified
/// against the same list it still waits; after the advance that adds its
/// principal it applies and leaves the pending store. A reload in between
/// keeps it.
#[test]
fn pending_records_are_reverified_after_each_device_list_advance() {
    let mut rig = rig();
    // The new bot's key, before the list holds it.
    rig.log
        .keys
        .insert_ed25519(auth("svc-new"), &secret("svc-new auth"));
    let hold = rig.signed("svc-new", "svc-new", ControlAction::Hold, None);
    let applied = rig.apply_at(&hold, 1);
    assert_eq!(applied.record_result, ApplicationResult::Pending);
    assert_eq!(applied.why.unwrap().code(), "principal_unknown");
    let stored = rig.stored();
    assert_eq!(
        stored.pending,
        [("service:svc-new".into(), hold.record_id().into())]
    );
    assert_eq!(stored.cursors, cursor_row(1), "the cursor moves past it");
    assert_eq!(rig.feeds.pending_len(), 1);

    // No advance: it still waits.
    assert!(rig.reverify().is_empty());
    assert_eq!(rig.stored().pending, stored.pending);

    // A reload keeps it.
    rig.feeds = load(&rig.store, &rig.log, &rig.clock);
    assert_eq!(rig.feeds.pending_len(), 1);

    // The advance that adds its principal.
    rig.log.add_service(
        "svc-new",
        &["host"],
        None,
        &["notify", "prompt", "view"],
        expiry(),
    );
    let again = rig.reverify();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].record, hold);
    assert_eq!(again[0].pos, Some(at(1)));
    assert_eq!(again[0].applied.record_result, ApplicationResult::Applied);
    assert_eq!(
        again[0].applied.actions,
        [HostAction::Hold("service:svc-new".into())]
    );
    assert!(rig.feeds.standing("service:svc-new").held);
    assert!(rig.stored().pending.is_empty());
    assert_eq!(rig.feeds.pending_len(), 0);
    assert_eq!(rig.stored().pending_count, 1, "counted once");
    let again = load(&rig.store, &rig.log, &rig.clock);
    assert!(again.standing("service:svc-new").held);
    assert_eq!(again.pending_len(), 0);
}

/// Design I.5.4 ("Bounds"): pending records keep a count and the 32 most
/// recent (whatever comes, storage stays bounded); each is written with the
/// record's transaction, so a pending stop past the cursor survives a
/// crash.
#[test]
fn pending_records_keep_a_count_and_the_32_most_recent() {
    let mut rig = rig();
    let mut ids = Vec::new();
    let mut last = None;
    for seq in 1..=40 {
        let service = format!("svc-unknown-{seq}");
        rig.log
            .keys
            .insert_ed25519(auth(&service), &secret(&format!("{service} auth")));
        let rec = rig.signed(&service, &service, ControlAction::Hold, None);
        ids.push(rec.record_id().to_string());
        assert_eq!(
            rig.apply_at(&rec, seq).record_result,
            ApplicationResult::Pending
        );
        last = Some(rec);
    }
    let stored = rig.stored();
    assert_eq!(stored.pending_count, 40);
    let kept: Vec<String> = stored.pending.iter().map(|(_, id)| id.clone()).collect();
    assert_eq!(kept, ids[8..], "the 32 most recent, oldest first");
    assert_eq!(rig.feeds.pending_count(), 40);
    assert_eq!(rig.feeds.pending_len(), KEPT);
    // The same record again is kept once.
    let list = serving(&rig.log);
    let last = last.unwrap();
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.apply(&tx, &last, &list, at(41), 0).unwrap();
    rig.feeds.commit(tx).unwrap();
    assert_eq!(rig.stored().pending, stored.pending);
    assert_eq!(rig.stored().pending_count, 40);
}

/// Design I.5.4 ("Bounds"; R9.3's bound): evidence keeps a count and the
/// 32 most recent records, persisted at most once a minute: the first is
/// written with its record, those within the minute counted in memory and
/// written by the next write after it; a reload reads the count.
#[test]
fn evidence_keeps_a_count_and_the_32_most_recent() {
    let mut rig = rig();
    let first = rig.forged();
    let applied = rig.apply_at(&first, 1);
    assert_eq!(applied.record_result, ApplicationResult::Refused);
    assert!(applied.evidence);
    assert_eq!(applied.why.unwrap().code(), "bad_signature");
    let stored = rig.stored();
    assert_eq!(stored.evidence, [1]);
    assert_eq!(stored.evidence_count, 1);
    assert_eq!(stored.cursors, cursor_row(1), "the cursor moves past it");

    // 39 more within the minute: counted in memory, not written.
    for seq in 2..=40 {
        let rec = rig.forged();
        rig.pass(1_000);
        assert!(rig.apply_at(&rec, seq).evidence);
    }
    assert_eq!(rig.feeds.evidence_count(), 40);
    let stored = rig.stored();
    assert_eq!(stored.evidence, [1], "at most once a minute");
    assert_eq!(stored.evidence_count, 1);
    assert_eq!(stored.cursors, cursor_row(40));
    // Not yet a minute since the write: nothing.
    rig.feeds.tick(&rig.store).unwrap();
    assert_eq!(rig.stored().evidence_count, 1);

    // A minute after it: the count and the 32 most recent.
    rig.pass(MIN);
    rig.feeds.tick(&rig.store).unwrap();
    let stored = rig.stored();
    assert_eq!(stored.evidence_count, 40);
    assert_eq!(stored.evidence, (9..=40).collect::<Vec<u64>>());
    rig.feeds.tick(&rig.store).unwrap();
    assert_eq!(rig.stored(), stored, "nothing more to write");
    let again = load(&rig.store, &rig.log, &rig.clock);
    assert_eq!(again.evidence_count(), 40);

    // Another a minute later is written with its record.
    rig.pass(MIN);
    let rec = rig.forged();
    rig.apply_at(&rec, 41);
    let stored = rig.stored();
    assert_eq!(stored.evidence_count, 41);
    assert_eq!(stored.evidence, (10..=41).collect::<Vec<u64>>());
}

/// R9.3, R9.4 and design I.5.4 ("A record is never applied while the
/// host's device list is frozen or the host is held after a write
/// fault"): with the list frozen, held, faulted or unpaired, a record
/// applies nothing and isn't consumed (no part, cursor, pending record or
/// evidence written; nothing adopted), and pending records aren't
/// re-verified.
#[test]
fn nothing_applies_while_the_list_is_frozen_or_held() {
    let mut rig = rig();
    let cover = rig.bot(ControlAction::Cover);
    rig.apply_at(&cover, 1);
    rig.log
        .keys
        .insert_ed25519(auth("svc-new"), &secret("svc-new auth"));
    let waiting = rig.signed("svc-new", "svc-new", ControlAction::Hold, None);
    rig.apply_at(&waiting, 2);
    rig.log.add_service(
        "svc-new",
        &["host"],
        None,
        &["notify", "prompt", "view"],
        expiry(),
    );
    let before = rig.stored();
    let standings = rig.feeds.standings();
    let hold = rig.bot(ControlAction::Hold);
    let forged = rig.forged();
    for how in ["frozen", "held", "faulted", "unpaired"] {
        let mut list = serving(&rig.log);
        match how {
            "frozen" => list.frozen = true,
            "held" => list.held = true,
            "faulted" => list.faulted = true,
            _ => list.unpaired = true,
        }
        let tx = rig.feeds.begin(&rig.store).unwrap();
        for rec in [&hold, &forged] {
            let err = rig.feeds.apply(&tx, rec, &list, at(3), 0).unwrap_err();
            assert!(err.downcast_ref::<ListNotServing>().is_some(), "{how}");
        }
        assert!(
            rig.feeds
                .reverify_pending(&tx, &list, 0)
                .unwrap()
                .is_empty(),
            "{how}"
        );
        rig.feeds.commit(tx).unwrap();
        assert_eq!(rig.stored(), before, "{how}");
        assert_eq!(rig.feeds.standings(), standings, "{how}");
        assert_eq!(rig.feeds.pending_len(), 1, "{how}");
        assert_eq!(rig.feeds.evidence_count(), 0, "{how}");
        assert!(rig.feeds.take_lines().is_empty(), "{how}: no alert");
    }
    // Serving again: both apply.
    assert_eq!(
        rig.apply_at(&hold, 3).record_result,
        ApplicationResult::Applied
    );
    assert_eq!(rig.reverify().len(), 1);
}

/// Design I.5.4 ("Alerts for failed or conflicting records are
/// rate-limited to one an hour per source, with the count: per origin for
/// a feed, and per carrying principal"), Decision 12 (local, runtime.log):
/// the first record kept as evidence alerts at once; the rest within the
/// hour (a forgery, another body under a counted record id) are counted
/// and reported in one line when the hour has passed; another source has
/// its own hour. Lines come only after the commit.
#[test]
fn refused_and_conflicting_records_alert_at_most_hourly() {
    let mut rig = rig();
    let list = serving(&rig.log);
    let forged = rig.forged();
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.apply(&tx, &forged, &list, at(1), 0).unwrap();
    assert!(rig.feeds.take_lines().is_empty(), "not before the commit");
    rig.feeds.commit(tx).unwrap();
    let lines = rig.feeds.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains(ORIGIN), "{}", lines[0]);
    assert!(lines[0].contains("bad_signature"), "{}", lines[0]);
    assert!(!lines[0].contains(forged.object().to_json()["sig"].as_str().unwrap()));

    // Within the hour: another forgery, and a release under the id of a
    // hold that counted (a conflicting record): counted, not alerted.
    rig.pass(10 * MIN);
    let forged = rig.forged();
    assert!(rig.apply_at(&forged, 2).evidence);
    let hold = rig.bot(ControlAction::Hold);
    rig.apply_at(&hold, 3);
    let id = hold.record_id().to_string();
    let conflicting = rig.signed("svc-bot", "svc-bot", ControlAction::Release, Some(&id));
    let applied = rig.apply_at(&conflicting, 4);
    assert!(applied.evidence);
    assert_eq!(applied.why, Some(Why::Collision));
    assert_eq!(applied.effects[0].effect, EffectKind::Release);
    // Pending and plain refusals aren't alerted.
    assert!(rig.feeds.take_lines().is_empty());
    rig.feeds.tick(&rig.store).unwrap();
    assert!(rig.feeds.take_lines().is_empty());

    // Another source (a carrier) has its own hour.
    let forged = rig.forged();
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds
        .apply_carried(&tx, &forged, &list, "member:dev-phone", 0)
        .unwrap();
    rig.feeds.commit(tx).unwrap();
    let lines = rig.feeds.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("member:dev-phone"), "{}", lines[0]);

    // The hour passed: one line for the feed, with the count.
    rig.pass(HOUR);
    rig.feeds.tick(&rig.store).unwrap();
    let lines = rig.feeds.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains(ORIGIN), "{}", lines[0]);
    assert!(lines[0].contains(" 2 "), "the two counted: {}", lines[0]);
    rig.feeds.tick(&rig.store).unwrap();
    assert!(rig.feeds.take_lines().is_empty(), "nothing more to report");
    // The next one after the hour alerts at once again.
    rig.pass(HOUR);
    let forged = rig.forged();
    rig.apply_at(&forged, 5);
    assert_eq!(rig.feeds.take_lines().len(), 1);
    // One counted within the hour, and the next after it with no tick in
    // between: one line, both counted.
    rig.pass(10 * MIN);
    let forged = rig.forged();
    rig.apply_at(&forged, 6);
    assert!(rig.feeds.take_lines().is_empty());
    rig.pass(HOUR);
    let forged = rig.forged();
    rig.apply_at(&forged, 7);
    let lines = rig.feeds.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains(" 2 "), "none lost: {}", lines[0]);
}

/// host-work-v1 §11.1 ("Host rule: a position's `origin` is the host's own
/// configured Station origin, never one taken from a page or a record";
/// ruling N3): a position naming another origin, or any position while the
/// host has no Station, is refused before anything is written; positions
/// are made with the host's own origin.
#[test]
fn a_position_is_always_the_hosts_own_stations() {
    let mut rig = rig();
    assert_eq!(rig.feeds.position(FEED, 7), Some(at(7)));
    let cover = rig.bot(ControlAction::Cover);
    let list = serving(&rig.log);
    let before = rig.stored();
    let other = FeedPos {
        origin: "https://other.example".into(),
        feed_id: FEED.into(),
        feed_seq: 1,
    };
    let tx = rig.feeds.begin(&rig.store).unwrap();
    let err = rig.feeds.apply(&tx, &cover, &list, other, 0).unwrap_err();
    assert!(err.downcast_ref::<NotOwnStation>().is_some());
    rig.feeds.commit(tx).unwrap();
    assert_eq!(rig.stored(), before);
    assert_eq!(rig.feeds.standing(BOT).coverage, None);

    rig.feeds.set_own_origin(None);
    assert_eq!(rig.feeds.position(FEED, 1), None);
    let tx = rig.feeds.begin(&rig.store).unwrap();
    let err = rig.feeds.apply(&tx, &cover, &list, at(1), 0).unwrap_err();
    assert!(err.downcast_ref::<NotOwnStation>().is_some());
    drop(tx);
    rig.feeds.set_own_origin(Some(ORIGIN.into()));
    assert_eq!(
        rig.apply_at(&cover, 1).record_result,
        ApplicationResult::Applied
    );
}

/// Bindings §9 step 3 (ruling T4e): the parts of another device list (an
/// earlier pairing's leftovers) never load: each is logged and its row
/// deleted, while the current list's parts beside them load with their
/// stops.
#[test]
fn an_earlier_lists_parts_are_logged_and_deleted_at_load() {
    let mut rig = rig();
    let hold = rig.bot(ControlAction::Hold);
    rig.apply_at(&hold, 1);
    // The same service id in another list (another genesis), its part
    // left in the store.
    let mut old = TestLog::genesis("acct-f", &secret("an earlier astation"));
    old.add_host("host", 1, &secret("feeds host"));
    old.add_service(
        "svc-old",
        &["host"],
        None,
        &["notify", "prompt", "view"],
        expiry(),
    );
    let mut other = self::rig();
    other.log = old;
    other.feeds = load(&other.store, &other.log, &other.clock);
    let old_hold = other.signed("svc-old", "svc-old", ControlAction::Hold, None);
    other.apply_at(&old_hold, 1);
    let (principal, part) = other.stored().parts[0].clone();
    rig.store
        .db
        .execute(
            "INSERT INTO control_principals(principal,part) VALUES(?1,?2)",
            [&principal, &part],
        )
        .unwrap();
    assert_eq!(rig.stored().parts.len(), 2);

    let mut again = load(&rig.store, &rig.log, &rig.clock);
    assert!(again.standing(BOT).held, "the current list's stop loads");
    assert!(!again.standing("service:svc-old").held, "never loaded");
    let parts = rig.stored().parts;
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].0, BOT);
    let lines = again.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("service:svc-old"), "{}", lines[0]);
}

/// Bindings §9 step 3 (ruling PR2b): a part of the current list that
/// doesn't read fails the load (the caller keeps delegated work stopped),
/// and nothing is deleted: never an empty state in its place.
#[test]
fn a_damaged_part_of_the_current_list_fails_the_load() {
    let mut rig = rig();
    let hold = rig.bot(ControlAction::Hold);
    rig.apply_at(&hold, 1);
    let (principal, part) = rig.stored().parts[0].clone();
    let mut value: serde_json::Value = serde_json::from_str(&part).unwrap();
    value["held"] = "yes".into();
    for damaged in [value.to_string(), "{not json".to_string()] {
        rig.store
            .db
            .execute(
                "UPDATE control_principals SET part=?2 WHERE principal=?1",
                [&principal, &damaged],
            )
            .unwrap();
        assert!(FeedStore::load(&rig.store, &rig.log.log).is_err());
        assert_eq!(rig.stored().parts, [(principal.clone(), damaged)]);
    }
    // A pending record that doesn't read fails it too.
    rig.store
        .db
        .execute(
            "UPDATE control_principals SET part=?2 WHERE principal=?1",
            [&principal, &part],
        )
        .unwrap();
    FeedStore::load(&rig.store, &rig.log.log).unwrap();
    rig.store
        .db
        .execute(
            "INSERT INTO control_pending(principal,record_id,record,pos,source,reason,at_ms)
            VALUES('service:x','id','{}',NULL,'feed:x','principal_unknown',1)",
            [],
        )
        .unwrap();
    assert!(FeedStore::load(&rig.store, &rig.log.log).is_err());
}

/// Decision 16: the standings go to the publisher when they commit (and
/// when asked, as the bridge does once they load), never before.
#[test]
fn standings_are_published_at_commit() {
    let mut rig = rig();
    let seen: Arc<Mutex<Vec<BTreeMap<String, SenderStanding>>>> = Arc::default();
    let s = seen.clone();
    rig.feeds
        .set_publisher(Box::new(move |standings| s.lock().unwrap().push(standings)));
    assert!(seen.lock().unwrap().is_empty());
    rig.feeds.publish();
    assert_eq!(seen.lock().unwrap().len(), 1, "when asked");
    assert!(seen.lock().unwrap()[0].is_empty());
    let cover = rig.bot(ControlAction::Cover);
    let list = serving(&rig.log);
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.apply(&tx, &cover, &list, at(1), 0).unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1, "not before the commit");
    rig.feeds.commit(tx).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1][BOT].coverage, Some(bot_feed()));
}

/// Task 33's page reader: a record that doesn't parse is kept as evidence
/// (its parse code the reason) and the cursor moves past it.
#[test]
fn a_record_that_doesnt_parse_is_evidence_past_the_cursor() {
    let mut rig = rig();
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds
        .unparsed(&tx, "{\"body\":{}}", "malformed", at(1))
        .unwrap();
    rig.feeds.commit(tx).unwrap();
    let stored = rig.stored();
    assert_eq!(stored.cursors, cursor_row(1));
    assert_eq!(stored.evidence, [1]);
    assert_eq!(rig.feeds.take_lines().len(), 1);
}

/// Task 32 review m6: a step that fails fails the whole transaction:
/// `commit` rolls it back (what applied before the failure too), adopts
/// nothing, and the records applied again give the same results.
#[test]
fn a_commit_after_a_failed_step_rolls_the_transaction_back() {
    let mut rig = rig();
    let cover = rig.bot(ControlAction::Cover);
    let hold = rig.bot(ControlAction::Hold);
    let list = serving(&rig.log);
    let before = rig.stored();
    // The cursor's second write fails (the first is an insert).
    rig.store
        .db
        .execute_batch(
            "CREATE TEMP TRIGGER fail_cursor BEFORE UPDATE ON control_feeds
            BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
    let tx = rig.feeds.begin(&rig.store).unwrap();
    let covered = rig.feeds.apply(&tx, &cover, &list, at(1), 0).unwrap();
    assert!(rig.feeds.apply(&tx, &hold, &list, at(2), 0).is_err());
    assert!(rig.feeds.commit(tx).is_err(), "rolled back, not committed");
    assert_eq!(rig.stored(), before, "the cover's writes too");
    assert_eq!(rig.feeds.standing(BOT), SenderStanding::default());
    assert!(rig.feeds.take_lines().is_empty());
    rig.store
        .db
        .execute_batch("DROP TRIGGER fail_cursor")
        .unwrap();
    assert_eq!(rig.apply_at(&cover, 1), covered);
    assert_eq!(
        rig.apply_at(&hold, 2).record_result,
        ApplicationResult::Applied
    );
    assert!(rig.feeds.standing(BOT).held);
}

/// Task 32 review m6, design I.5.4 ("apply again after ... every revocation
/// applied"): two records of a service the list doesn't hold yet wait, an
/// `interrupt_running` before its `revoke`. After the advance one
/// re-verification applies both: the interrupt, older, waits for the
/// revoke (`not_revoked`) and applies once it did.
#[test]
fn a_revoke_that_applies_lets_a_waiting_interrupt_apply_in_the_same_reverify() {
    let mut rig = rig();
    rig.log
        .keys
        .insert_ed25519(auth("svc-new"), &secret("svc-new auth"));
    let interrupt = rig.signed(
        "svc-new",
        "svc-new",
        ControlAction::InterruptRunning { revoke_seq: None },
        None,
    );
    let revoke = rig.signed(
        "svc-new",
        "svc-new",
        ControlAction::Revoke {
            interrupt_running: false,
        },
        None,
    );
    assert_eq!(
        rig.apply_at(&interrupt, 1).record_result,
        ApplicationResult::Pending
    );
    assert_eq!(
        rig.apply_at(&revoke, 2).record_result,
        ApplicationResult::Pending
    );
    rig.log.add_service(
        "svc-new",
        &["host"],
        None,
        &["notify", "prompt", "view"],
        expiry(),
    );
    let again = rig.reverify();
    let records: Vec<&ControlRecord> = again.iter().map(|r| &r.record).collect();
    assert_eq!(records, [&revoke, &interrupt]);
    assert!(
        again
            .iter()
            .all(|r| r.applied.record_result == ApplicationResult::Applied)
    );
    assert_eq!(
        again[1].applied.actions,
        [HostAction::Interrupt {
            principal: "service:svc-new".into(),
            revocation: revoke.record_id().into(),
        }]
    );
    let standing = rig.feeds.mem.state.standing("service:svc-new");
    assert!(standing.interrupted.contains(revoke.record_id()));
    assert_eq!(rig.feeds.pending_len(), 0);
    assert!(rig.stored().pending.is_empty());
}

/// Task 32 review m3: a transaction dropped before its commit leaves
/// nothing staged, whatever the caller does next: its records are never
/// adopted by a later commit, and nothing builds on them.
#[test]
fn a_dropped_transaction_leaves_nothing_staged() {
    let mut rig = rig();
    let hold = rig.bot(ControlAction::Hold);
    let cover = rig.bot(ControlAction::Cover);
    let list = serving(&rig.log);
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.apply(&tx, &hold, &list, at(1), 0).unwrap();
    drop(tx);
    rig.feeds.tick(&rig.store).unwrap();
    assert!(!rig.feeds.standing(BOT).held);
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.apply(&tx, &cover, &list, at(1), 0).unwrap();
    rig.feeds.commit(tx).unwrap();
    assert!(
        !rig.feeds.standing(BOT).held,
        "the dropped hold never adopted"
    );
    assert_eq!(rig.feeds.standing(BOT).coverage, Some(bot_feed()));
    assert_eq!(rig.stored().cursors, cursor_row(1));
}

/// Task 32 review m4: the store keeps one feed per origin, the one it
/// read last (a reset's new feed replaces the old one's cursor, in the
/// transaction that reads it): feeds minted by a carrier, even with
/// records that don't parse, never add rows.
#[test]
fn one_feed_per_origin_is_kept() {
    let mut rig = rig();
    let cover = rig.bot(ControlAction::Cover);
    rig.apply_at(&cover, 3);
    let reset = "33333333-3333-4333-8333-333333333333";
    let tx = rig.feeds.begin(&rig.store).unwrap();
    rig.feeds.advance(&tx, at_feed(reset, 0)).unwrap();
    rig.feeds.commit(tx).unwrap();
    assert_eq!(
        rig.stored().cursors,
        [(format!("{ORIGIN} {reset}"), "0".to_string())]
    );
    assert_eq!(rig.feeds.cursor(ORIGIN, FEED), None);
    assert_eq!(rig.feeds.cursor(ORIGIN, reset), Some(0));
    for n in 0..5 {
        let minted = uuid::Uuid::new_v4().to_string();
        let tx = rig.feeds.begin(&rig.store).unwrap();
        rig.feeds
            .unparsed(&tx, "not a record", "not_strict_json", at_feed(&minted, n))
            .unwrap();
        rig.feeds.commit(tx).unwrap();
        assert_eq!(rig.stored().cursors.len(), 1);
    }
    let again = load(&rig.store, &rig.log, &rig.clock);
    assert_eq!(again.mem.cursors.len(), 1);
    assert_eq!(rig.feeds.mem.cursors.len(), 1);
}

/// Task 32 review m8: the `control_*` tables come with the feeds (their
/// first load), never with the store: with the hook off, as on main, a
/// store has none.
#[test]
fn the_control_tables_come_with_the_feeds() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let tables = |store: &Store| -> u32 {
        store
            .db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'control%'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(tables(&store), 0);
    FeedStore::load(&store, &list().log).unwrap();
    assert_eq!(tables(&store), 5);
}

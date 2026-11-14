//! `HostClock` in the runtime: its record in the host-work store (written
//! once a minute, at every event and at an orderly stop), a restart in the
//! same boot, the debug hook's readings, the `atem status` line, the
//! `runtime.log` lines, and a damaged record (kept aside, never fresh).

use super::*;
use crate::runtime::host_clock::os::unknown_machine;
use crate::runtime::test_hooks::{HookClock, TEST_MACHINE, parse_host_clock};
use rusqlite::types::Value;
use std::sync::Mutex;

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;
/// The true time when a test starts (2027-01-15), in ms.
const T: u64 = 1_800_000_000_000;
const M: [u8; 16] = [0x11; 16];
const ORIGIN: &str = "https://station-dev.agora.build";

/// §11.6's exact texts.
const ENABLE: &str = "host clock ahead of its record; enable time synchronization (chrony with rtcsync, or systemd-timesyncd)";
const WAITING: &str = "host clock ahead of its record; waiting for a synchronized clock";

/// The OS a test drives: what the clock reads now.
#[derive(Clone)]
struct Os(Arc<Mutex<OsReading>>);

impl Os {
    fn new(wall_ms: u64, boot_ms: u64, boot_id: &str, synced: Synced) -> Os {
        Os(Arc::new(Mutex::new(reading(
            wall_ms, boot_ms, boot_id, synced,
        ))))
    }

    fn reader(&self) -> Reader {
        let now = self.0.clone();
        Arc::new(move || Some(now.lock().unwrap().clone()))
    }

    fn now(&self) -> OsReading {
        self.0.lock().unwrap().clone()
    }

    fn wall(&self) -> u64 {
        self.now().wall_ms
    }

    /// Time passes: the wall clock and the boot-time counter move `ms` on.
    fn pass(&self, ms: u64) {
        let mut r = self.0.lock().unwrap();
        r.wall_ms += ms;
        r.boot_ns += ms * 1_000_000;
    }

    /// The wall clock is set to `wall_ms`, the OS reporting `synced`.
    fn set_wall(&self, wall_ms: u64, synced: Synced) {
        let mut r = self.0.lock().unwrap();
        r.wall_ms = wall_ms;
        r.synced = synced;
    }

    /// A reboot: another boot id, its counter at `boot_ms`.
    fn reboot(&self, boot_id: &str, wall_ms: u64, boot_ms: u64, synced: Synced) {
        *self.0.lock().unwrap() = reading(wall_ms, boot_ms, boot_id, synced);
    }
}

fn reading(wall_ms: u64, boot_ms: u64, boot_id: &str, synced: Synced) -> OsReading {
    OsReading {
        wall_ms,
        boot_ns: boot_ms * 1_000_000,
        boot_id: boot_id.into(),
        machine: M,
        timens_boot_ns: 0,
        synced,
    }
}

fn open_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

/// The clock state the store holds.
fn stored(store: &Store) -> ClockState {
    match store.load_clock().unwrap() {
        Some(Value::Text(text)) => ClockState::from_json(&text).unwrap(),
        other => panic!("no clock state stored: {other:?}"),
    }
}

/// The copies kept aside (none while the table doesn't exist: it is made
/// with the first copy).
fn aside(store: &Store) -> Vec<Value> {
    if !table_exists(store, "clock_aside") {
        return Vec::new();
    }
    let mut q = store
        .db
        .prepare("SELECT state FROM clock_aside ORDER BY rowid")
        .unwrap();
    q.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn table_exists(store: &Store, name: &str) -> bool {
    store
        .db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [name],
            |r| r.get(0),
        )
        .unwrap()
}

/// Writes to `table` fail until `fail_writes(.., false)`.
fn fail_writes(store: &Store, table: &str, on: bool) {
    let sql = if on {
        format!(
            "CREATE TRIGGER fail_{table}_insert BEFORE INSERT ON {table}
                BEGIN SELECT RAISE(ABORT, 'injected write fault'); END;
            CREATE TRIGGER fail_{table}_update BEFORE UPDATE ON {table}
                BEGIN SELECT RAISE(ABORT, 'injected write fault'); END;"
        )
    } else {
        format!("DROP TRIGGER fail_{table}_insert; DROP TRIGGER fail_{table}_update;")
    };
    store.db.execute_batch(&sql).unwrap();
}

/// The `runtime.log` lines written on this thread since the last call.
fn logged() -> Vec<String> {
    LOGGED.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

fn lowered(e: &ClockEvent) -> bool {
    matches!(e, ClockEvent::LoweredAtSync { .. })
}

#[test]
fn record_persists_once_a_minute_on_events_and_at_shutdown() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    // Loading writes nothing; the first reading is written.
    assert_eq!(store.load_clock().unwrap(), None);
    assert!(clock.tick(&store).is_empty());
    let first = stored(&store);
    assert_eq!(first, clock.state);

    // Readings within the minute move the record in memory only.
    for _ in 0..59 {
        os.pass(SEC);
        assert!(clock.tick(&store).is_empty());
        assert_eq!(stored(&store), first);
    }
    assert_ne!(clock.state, first);
    // A minute of boot time after the last write, it is written.
    os.pass(SEC);
    clock.tick(&store);
    assert_eq!(stored(&store), clock.state);

    // An event is written at once: an unsynchronized jump of two minutes
    // arms an anchor.
    os.pass(SEC);
    os.set_wall(os.wall() + 2 * MIN, Synced::No);
    assert_eq!(clock.tick(&store), vec![ClockEvent::AnchorArmed]);
    let armed = stored(&store);
    assert_eq!(armed, clock.state);

    // A reading without one isn't written...
    os.pass(5 * SEC);
    assert!(clock.tick(&store).is_empty());
    assert_eq!(stored(&store), armed);
    let unwritten = clock.state.clone();
    assert_ne!(unwritten, armed);
    // ...until the orderly stop, which takes a last reading and writes it.
    os.pass(SEC);
    clock.close(&store);
    assert_eq!(stored(&store), clock.state);
    assert_ne!(clock.state, unwritten);
    assert_eq!(clock.now().h_ms, os.wall());
}

#[test]
fn a_mark_set_or_cleared_is_written_at_once() {
    let (_dir, store) = open_store();
    // A fresh record whose first reading isn't synchronized carries the mark.
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    assert!(stored(&store).mark());
    // Seconds later the OS reports its clock synchronized with nothing
    // ahead: no event, and the mark's removal is written at once (§11.6:
    // stored with the record).
    os.pass(5 * SEC);
    os.set_wall(os.wall(), Synced::Yes);
    assert!(clock.tick(&store).is_empty());
    assert!(!clock.state.mark());
    assert_eq!(stored(&store), clock.state);
}

#[test]
fn a_restart_in_the_same_boot_continues_the_record() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    os.pass(30 * SEC);
    clock.tick(&store);
    clock.close(&store);
    drop(clock);

    // Restarted ten seconds later in the same boot, the wall clock set back
    // an hour: `H` is the record plus the boot time since it, not the wall
    // clock, and nothing of a new boot happens (no mark, no lowering).
    os.pass(10 * SEC);
    os.set_wall(os.wall() - HOUR, Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    assert_eq!(clock.now().h_ms, T + 40 * SEC);
    let events = clock.tick(&store);
    assert!(
        matches!(events[..], [ClockEvent::WentBack { wall_ms, h_ms }]
            if wall_ms == T + 40 * SEC - HOUR && h_ms + 5 >= T + 40 * SEC),
        "{events:?}"
    );
    assert!(!clock.state.mark());
    let h = clock.now().h_ms;
    assert!(
        (T + 40 * SEC - 5..=T + 40 * SEC).contains(&h),
        "followed down at most 500 ppm of 10 s: {h}"
    );
    assert_eq!(stored(&store), clock.state, "the alert is an event");

    // A record started afresh would have taken the wall clock.
    let (_other_dir, other) = open_store();
    let fresh = HostClock::with_reader(&other, os.reader());
    assert_eq!(fresh.now().h_ms, T + 40 * SEC - HOUR);
}

#[test]
fn a_hook_reboot_with_synced_lowers_once() {
    let (dir, store) = open_store();
    let hook = dir.path().join("host-clock");
    let write = |text: String| {
        let tmp = hook.with_extension("tmp");
        std::fs::write(&tmp, text).unwrap();
        std::fs::rename(&tmp, &hook).unwrap();
    };
    // What the runtime's hook reads (`ATEM_TEST_HOST_CLOCK`'s format).
    let reader: Reader = {
        let hook = hook.clone();
        Arc::new(move || {
            std::fs::read_to_string(&hook)
                .ok()
                .and_then(|text| parse_host_clock(&text, 0, 0))
                .map(HookClock::reading)
        })
    };
    // Boot a, its wall clock two hours ahead of the true time `T`
    // (three-field files: synchronized, the test machine).
    write(format!("{} {} boot-a", T + 2 * HOUR, 50 * SEC));
    let mut clock = HostClock::with_reader(&store, reader.clone());
    clock.tick(&store);
    os_reading_is_the_hooks(&clock);

    // Rebooted onto the true time, synchronized at its first reading: the
    // record is lowered to the wall clock, once, and the mark's removal is
    // written with it.
    write(format!("{T} {} boot-b", 20 * SEC));
    let events = clock.tick(&store);
    assert_eq!(
        events.iter().filter(|e| lowered(e)).count(),
        1,
        "{events:?}"
    );
    assert_eq!(clock.now().h_ms, T);
    let after = stored(&store);
    assert_eq!(after, clock.state);
    assert!(!after.mark());

    // Later readings don't lower again, nor does a restart in the same boot
    // with the wall clock half an hour back (the went-back alert instead).
    write(format!("{} {} boot-b", T + MIN, 80 * SEC));
    assert!(!clock.tick(&store).iter().any(lowered));
    clock.close(&store);
    let mut clock = HostClock::with_reader(&store, reader);
    write(format!("{} {} boot-b", T + MIN - 30 * MIN, 90 * SEC));
    let events = clock.tick(&store);
    assert!(!events.iter().any(lowered), "{events:?}");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ClockEvent::WentBack { .. }))
    );
}

/// The hook's three fields read as the test machine, synchronized, its
/// counter the monotonic value.
fn os_reading_is_the_hooks(clock: &HostClock) {
    let r = clock.last.clone().unwrap();
    assert_eq!(
        (r.machine, r.synced, r.boot_ns, r.timens_boot_ns),
        (TEST_MACHINE, Synced::Yes, 50 * SEC * 1_000_000, 0)
    );
}

#[test]
fn status_names_the_fix_when_deadlines_are_held_back() {
    assert_eq!(AHEAD_ENABLE_SYNC, ENABLE);
    assert_eq!(AHEAD_WAITING, WAITING);
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    assert_eq!(
        clock.status_line(),
        None,
        "a healthy clock holds nothing back"
    );

    // Rebooted with the wall clock 30 minutes behind the record and no
    // synchronized reading yet: the mark holds deadlines back, and the
    // status says why and names the fix, per platform.
    os.reboot("boot-b", T - 30 * MIN, 20 * SEC, Synced::No);
    clock.tick(&store);
    assert!(clock.state.mark());
    let here = if cfg!(target_os = "macos") {
        WAITING
    } else {
        ENABLE
    };
    assert_eq!(clock.status_line().as_deref(), Some(here));
    let r = clock.last.clone().unwrap();
    assert_eq!(
        status_text(&clock.state, &r, false).as_deref(),
        Some(ENABLE)
    );
    assert_eq!(
        status_text(&clock.state, &r, true).as_deref(),
        Some(WAITING)
    );
    // So does a reading with no report at all.
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::Unknown);
    clock.tick(&store);
    assert_eq!(clock.status_line().as_deref(), Some(here));

    // The first synchronized reading lowers it: nothing held back, and the
    // lowering is shown.
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::Yes);
    assert!(clock.tick(&store).iter().any(lowered));
    let line = clock.status_line().unwrap();
    assert!(line.starts_with("host clock lowered"), "{line}");

    // With the mark gone, a wall clock more than 10 minutes below `H` is the
    // went-back alert's state: it holds deadlines back too, shown beside the
    // lowering.
    os.pass(SEC);
    os.set_wall(os.wall() - 30 * MIN, Synced::Yes);
    clock.tick(&store);
    let line = clock.status_line().unwrap();
    assert!(
        line.starts_with(&format!("{WENT_BACK}; host clock lowered")),
        "{line}"
    );
    assert_eq!(WENT_BACK, "host clock went back");

    // A reboot whose record is less than 10 minutes ahead holds nothing
    // back worth a line, mark or not.
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    os.reboot("boot-b", T - 5 * MIN, 20 * SEC, Synced::No);
    clock.tick(&store);
    assert!(clock.state.mark());
    assert_eq!(clock.status_line(), None);
}

#[test]
fn a_repair_shows_in_status_with_its_values_for_a_day() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    os.pass(SEC);
    os.set_wall(os.wall() + 2 * MIN, Synced::No);
    clock.tick(&store);
    os.pass(SEC);
    os.set_wall(os.wall() - 2 * MIN, Synced::No);
    let events = clock.tick(&store);
    let [ClockEvent::Repaired { old, new }] = events[..] else {
        panic!("{events:?}");
    };
    let line = clock.status_line().unwrap();
    assert!(line.starts_with("host clock repaired"), "{line}");
    assert!(
        line.contains(&utc(old.0)) && line.contains(&utc(new.0)),
        "{line}"
    );
    // Kept with the record: a restart shows it too.
    assert_eq!(stored(&store), clock.state);
    let restarted = HostClock::with_reader(&store, os.reader());
    assert_eq!(restarted.status_line(), Some(line.clone()));
    // Shown for 24 hours on `D`, then gone.
    os.pass(DAY - MIN);
    clock.tick(&store);
    assert_eq!(clock.status_line(), Some(line));
    os.pass(MIN);
    clock.tick(&store);
    assert_eq!(clock.status_line(), None);
}

#[test]
fn a_lowering_across_a_reboot_shows_in_status_for_a_day() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    os.reboot("boot-b", T - HOUR, 20 * SEC, Synced::Yes);
    let events = clock.tick(&store);
    let Some(ClockEvent::LoweredAtSync { old, new }) = events.iter().find(|e| lowered(e)) else {
        panic!("{events:?}");
    };
    let line = clock.status_line().unwrap();
    assert!(line.starts_with("host clock lowered"), "{line}");
    assert!(
        line.contains(&utc(old.0)) && line.contains(&utc(new.0)),
        "{line}"
    );
    assert_eq!(stored(&store), clock.state);
    os.pass(DAY - MIN);
    clock.tick(&store);
    assert_eq!(clock.status_line(), Some(line));
    os.pass(MIN);
    clock.tick(&store);
    assert_eq!(clock.status_line(), None);
}

#[test]
fn the_follow_down_shows_nothing_in_status() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    for back in [10 * SEC, 5 * MIN] {
        os.pass(SEC);
        os.set_wall(os.wall() - back, Synced::Yes);
        assert!(clock.tick(&store).is_empty());
        assert_eq!(clock.status_line(), None);
    }
    assert_eq!(clock.state.last_change(), None);
}

#[test]
fn repairs_and_lowerings_write_one_log_line() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    logged();
    clock.tick(&store);
    assert_eq!(logged(), Vec::<String>::new());

    // The follow-down writes none: the wall clock set back 10 s.
    os.pass(SEC);
    os.set_wall(os.wall() - 10 * SEC, Synced::Yes);
    assert!(clock.tick(&store).is_empty());
    assert_eq!(logged(), Vec::<String>::new());

    // A jump (its anchor writes none), then its undo: the repair writes one
    // line with the old and new values.
    os.pass(SEC);
    os.set_wall(os.wall() + 2 * MIN, Synced::No);
    assert_eq!(clock.tick(&store), vec![ClockEvent::AnchorArmed]);
    assert_eq!(logged(), Vec::<String>::new());
    os.pass(SEC);
    os.set_wall(os.wall() - 2 * MIN, Synced::No);
    let events = clock.tick(&store);
    let [ClockEvent::Repaired { old, new }] = events[..] else {
        panic!("{events:?}");
    };
    assert!(new.0 < old.0);
    let lines = logged();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("repaired"), "{}", lines[0]);
    assert!(lines[0].contains(&utc(old.0)), "{}", lines[0]);
    assert!(lines[0].contains(&utc(new.0)), "{}", lines[0]);

    // A reboot an hour behind, synchronized at once: the lowering writes one
    // line with the old and new values (its guard none).
    os.reboot("boot-b", os.wall() - HOUR, 20 * SEC, Synced::Yes);
    let events = clock.tick(&store);
    let Some(ClockEvent::LoweredAtSync { old, new }) = events.iter().find(|e| lowered(e)) else {
        panic!("{events:?}");
    };
    let lines = logged();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("lowered"), "{}", lines[0]);
    assert!(lines[0].contains(&utc(old.0)), "{}", lines[0]);
    assert!(lines[0].contains(&utc(new.0)), "{}", lines[0]);
    assert_eq!(utc(T), "2027-01-15T08:00:00.000Z");
}

#[test]
fn host_clock_hook_reads_the_extended_fields() {
    let hex = "00112233445566778899aabbccddeeff";
    let machine = atem_client::encoding::hex_decode_array::<16>(hex).unwrap();
    let fixed = parse_host_clock(&format!("1000 2000 boot-x 3000 0 {hex} 5"), 0, 0).unwrap();
    assert_eq!(
        fixed,
        HookClock {
            wall_ms: 1000,
            mono_ms: 2000,
            boot_id: "boot-x".into(),
            boot_ms: 3000,
            synced: Synced::No,
            machine,
            timens_boot_ms: 5,
        }
    );
    assert_eq!(
        fixed.reading(),
        OsReading {
            wall_ms: 1000,
            boot_ns: 3_000_000_000,
            boot_id: "boot-x".into(),
            machine,
            timens_boot_ns: 5_000_000,
            synced: Synced::No,
        }
    );
    for (field, synced) in [
        ("1", Synced::Yes),
        ("0", Synced::No),
        ("-", Synced::Unknown),
    ] {
        let text = format!("1000 2000 boot-x 3000 {field} {hex} 0");
        assert_eq!(parse_host_clock(&text, 0, 0).unwrap().synced, synced);
    }
    // Offsets: the wall clock, the monotonic clock and the boot-time counter
    // from the system's (the counter's from its monotonic clock, and may be
    // negative); the rest as given.
    let moved = parse_host_clock(
        &format!("offsets -500 20 boot-y -40 1 {hex} -7"),
        10_000,
        100,
    );
    assert_eq!(
        moved,
        Some(HookClock {
            wall_ms: 9_500,
            mono_ms: 120,
            boot_id: "boot-y".into(),
            boot_ms: 60,
            synced: Synced::Yes,
            machine,
            timens_boot_ms: -7,
        })
    );
    // A field that doesn't read makes no reading at all.
    for bad in [
        "1000 2000 boot-x x".to_string(),
        "1000 2000 boot-x 3000 2".into(),
        "1000 2000 boot-x 3000 1 nothex".into(),
        format!("1000 2000 boot-x 3000 1 {}", hex.to_uppercase()),
        format!("1000 2000 boot-x 3000 1 {hex} x"),
        format!("1000 2000 boot-x 3000 1 {hex} 0 extra"),
    ] {
        assert_eq!(parse_host_clock(&bad, 0, 0), None, "{bad}");
    }
}

#[test]
fn three_field_hook_files_still_read() {
    // Today's writers: the device list's clock reads the same three values,
    // and the delegated clock's fields default (the counter the monotonic
    // value, synchronized, the test machine, no namespace offset).
    let three = parse_host_clock("1000 2000 boot-x", 0, 0).unwrap();
    assert_eq!(
        three,
        HookClock {
            wall_ms: 1000,
            mono_ms: 2000,
            boot_id: "boot-x".into(),
            boot_ms: 2000,
            synced: Synced::Yes,
            machine: TEST_MACHINE,
            timens_boot_ms: 0,
        }
    );
    // The test machine isn't the one every machine without an id shares,
    // whose boot changes the clock never carries boot time across; the
    // binary tests' helper (`tests/support/host_clock.rs`) writes it so.
    assert_ne!(TEST_MACHINE, unknown_machine());
    assert_eq!(
        atem_client::encoding::hex(&TEST_MACHINE),
        "6174656d2d746573742d686f73742d31"
    );
    let offsets = parse_host_clock("offsets -500 20 boot-y", 10_000, 100).unwrap();
    assert_eq!(
        (
            offsets.wall_ms,
            offsets.mono_ms,
            offsets.boot_id.as_str(),
            offsets.boot_ms
        ),
        (9_500, 120, "boot-y", 120)
    );
    // Trailing fields default one by one.
    let four = parse_host_clock("1000 2000 boot-x 3000", 0, 0).unwrap();
    assert_eq!(
        (four.boot_ms, four.synced, four.machine, four.timens_boot_ms),
        (3000, Synced::Yes, TEST_MACHINE, 0)
    );
    assert_eq!(parse_host_clock("1000 2000", 0, 0), None);
    assert_eq!(parse_host_clock("offsets -1001 0 boot", 1000, 0), None);
}

#[test]
fn a_damaged_host_clock_record_is_kept_aside_and_never_fresh() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    // A record that isn't a clock state (a torn write, another build's).
    let torn = Value::Text(r#"{"record":"#.into());
    store
        .db
        .execute("INSERT INTO clock(id,state) VALUES(1,?1)", [&torn])
        .unwrap();
    logged();
    let mut clock = HostClock::with_reader(&store, os.reader());
    assert!(clock.damaged());
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED));
    let lines = logged();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("kept aside"), "{}", lines[0]);
    assert!(lines[0].contains("host-work.sqlite"), "{}", lines[0]);
    assert_eq!(aside(&store), vec![torn.clone()]);

    // Unsynchronized readings: nothing is written over it, and the status
    // stays.
    clock.tick(&store);
    os.pass(2 * MIN);
    clock.tick(&store);
    clock.close(&store);
    assert_eq!(store.load_clock().unwrap(), Some(torn.clone()));
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED));

    // A restart reads it damaged again, and keeps no second copy.
    let mut clock = HostClock::with_reader(&store, os.reader());
    assert!(clock.damaged());
    assert_eq!(aside(&store), vec![torn.clone()]);
    logged();

    // The first synchronized reading starts afresh: written, one line, the
    // copy kept.
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::Yes);
    clock.tick(&store);
    assert!(!clock.damaged());
    assert_eq!(stored(&store), clock.state);
    assert_eq!(clock.status_line(), None);
    let lines = logged();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("afresh"), "{}", lines[0]);
    assert_eq!(aside(&store), vec![torn.clone()]);
    assert!(clock.station(ORIGIN, os.wall(), &store));

    // A value that isn't text is damaged too, and so is a NULL.
    for value in [Value::Blob(vec![0, 0xff]), Value::Null] {
        store
            .db
            .execute("UPDATE clock SET state=?1 WHERE id=1", [&value])
            .unwrap();
        let clock = HostClock::with_reader(&store, os.reader());
        assert!(clock.damaged());
        assert_eq!(aside(&store).last(), Some(&value));
    }
}

#[test]
fn a_host_clock_moved_to_a_new_store_keeps_its_record_or_its_damage() {
    // A healthy clock writes its record into the new store at once.
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    let (_new_dir, new) = open_store();
    clock.moved(&new);
    assert_eq!(stored(&new), clock.state);

    // A damaged one carries its damage, so a restart over the new store
    // doesn't start afresh either.
    let (_dir, store) = open_store();
    let torn = Value::Text("{".into());
    store
        .db
        .execute("INSERT INTO clock(id,state) VALUES(1,?1)", [&torn])
        .unwrap();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let mut clock = HostClock::with_reader(&store, os.reader());
    let (_new_dir, new) = open_store();
    clock.moved(&new);
    assert_eq!(new.load_clock().unwrap(), Some(torn.clone()));
    assert!(HostClock::with_reader(&new, os.reader()).damaged());
}

#[test]
fn a_station_time_is_written_before_it_counts() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    // Within the cap: the floor is taken and written at once.
    os.pass(SEC);
    assert!(clock.station(ORIGIN, os.wall() + 5 * MIN, &store));
    assert_eq!(stored(&store), clock.state);
    assert_eq!(clock.now().d_ms, os.wall() + 5 * MIN);
    // Beyond it: not taken, and the reading's effects written all the same.
    os.pass(SEC);
    assert!(!clock.station(ORIGIN, os.wall() + 11 * MIN, &store));
    assert_eq!(stored(&store), clock.state);
    let lines = logged();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Station clock ahead of this host")),
        "{lines:?}"
    );
}

/// A clock whose stored record is torn, read with `os`.
fn damaged_clock(os: &Os) -> (tempfile::TempDir, Store, HostClock, Value) {
    let (dir, store) = open_store();
    let torn = Value::Text(r#"{"record":"#.into());
    store
        .db
        .execute("INSERT INTO clock(id,state) VALUES(1,?1)", [&torn])
        .unwrap();
    let clock = HostClock::with_reader(&store, os.reader());
    assert!(clock.damaged());
    logged();
    (dir, store, clock, torn)
}

#[test]
fn a_damaged_record_starts_afresh_at_a_station_time_within_the_cap() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store, mut clock, torn) = damaged_clock(&os);
    os.pass(SEC);
    let st = os.wall() + 5 * MIN;
    // `H` is the reading's own (§11.6: `H` never includes `station_time`),
    // the floor the Station time: `D` = max(w, st). Written.
    assert!(clock.station(ORIGIN, st, &store));
    assert!(!clock.damaged());
    assert_eq!(
        clock.now(),
        DelegatedNow {
            h_ms: os.wall(),
            d_ms: st
        }
    );
    assert_eq!(stored(&store), clock.state);
    // No once-per-boot lowering is armed by it: the Station time bounds it.
    assert!(!clock.state.mark());
    assert_eq!(clock.status_line(), None);
    let lines = logged();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("afresh") && lines[0].contains(&utc(st)) && lines[0].contains(ORIGIN),
        "{}",
        lines[0]
    );
    assert_eq!(aside(&store), vec![torn]);
}

#[test]
fn a_station_time_past_the_cap_keeps_a_damaged_record_waiting_and_alerts_hourly() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store, mut clock, torn) = damaged_clock(&os);
    let alerts = |lines: Vec<String>| {
        lines
            .iter()
            .filter(|l| l.contains("Station clock ahead of this host"))
            .count()
    };
    for (after, alerted) in [(SEC, 1), (MIN, 0), (HOUR, 1)] {
        os.pass(after);
        assert!(!clock.station(ORIGIN, os.wall() + 11 * MIN, &store));
        assert!(clock.damaged());
        assert_eq!(alerts(logged()), alerted);
    }
    assert_eq!(store.load_clock().unwrap(), Some(torn));
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED));
}

#[test]
fn a_synchronized_reading_still_starts_a_damaged_record_afresh() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store, mut clock, _torn) = damaged_clock(&os);
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::Yes);
    clock.tick(&store);
    assert!(!clock.damaged());
    assert_eq!(clock.now().h_ms, os.wall());
    assert_eq!(stored(&store), clock.state);
}

#[test]
fn a_station_time_below_the_reading_starts_a_damaged_record_at_the_reading() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store, mut clock, _torn) = damaged_clock(&os);
    os.pass(SEC);
    assert!(clock.station(ORIGIN, os.wall() - 3 * MIN, &store));
    assert!(!clock.damaged());
    assert_eq!(
        clock.now(),
        DelegatedNow {
            h_ms: os.wall(),
            d_ms: os.wall()
        }
    );
    assert_eq!(stored(&store), clock.state);
    // The record is the reading's: a wall clock then set back a minute is
    // followed down from it, not from the Station's time.
    let start = os.wall();
    os.pass(SEC);
    os.set_wall(os.wall() - MIN, Synced::No);
    clock.tick(&store);
    let h = clock.now().h_ms;
    assert!((start + SEC - 1..=start + SEC).contains(&h), "{h}");
}

/// The review's trace (PR 4, I1): after a damaged record starts at a Station
/// time, the cap is the reading's `w` + 10 minutes, not that time's: a head
/// at the old `H` + 10 minutes − 1 s isn't taken, one at `w` + 10 minutes − 1
/// s is.
#[test]
fn a_station_start_keeps_the_station_time_out_of_h_and_the_cap() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store, mut clock, _torn) = damaged_clock(&os);
    os.pass(SEC);
    let w = os.wall();
    assert!(clock.station(ORIGIN, w + 5 * MIN, &store));
    assert!(!clock.station(ORIGIN, w + 5 * MIN + 10 * MIN - SEC, &store));
    assert_eq!(
        clock.now(),
        DelegatedNow {
            h_ms: w,
            d_ms: w + 5 * MIN
        }
    );
    assert!(clock.station(ORIGIN, w + 10 * MIN - SEC, &store));
    assert_eq!(
        clock.now(),
        DelegatedNow {
            h_ms: w,
            d_ms: w + 599 * SEC
        }
    );
}

/// PR 4 is inert on main (T11b): a store gains only the `clock` table;
/// `clock_aside` is made with the first copy kept aside.
#[test]
fn the_store_makes_clock_aside_only_to_keep_a_copy() {
    let (_dir, store) = open_store();
    assert!(table_exists(&store, "clock"));
    assert!(!table_exists(&store, "clock_aside"));
    assert_eq!(aside(&store), Vec::<Value>::new());
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store, _clock, torn) = damaged_clock(&os);
    assert!(table_exists(&store, "clock_aside"));
    assert_eq!(aside(&store), vec![torn]);
}

/// The retire's crash window (PR 4, M2): the old store is moved aside before
/// the clock writes into the new one. A new store with no row takes the
/// newest retired store's record, read only, and writes it at once, a
/// damaged one as damaged (kept aside in the new store too).
#[test]
fn a_new_store_without_a_row_takes_the_retired_stores_record() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    // Healthy.
    let dir = tempfile::tempdir().unwrap();
    let old = Store::open(dir.path()).unwrap();
    let mut clock = HostClock::with_reader(&old, os.reader());
    clock.tick(&old);
    let kept = stored(&old);
    old.retire(T).unwrap();
    let new = Store::open(dir.path()).unwrap();
    assert_eq!(new.load_clock().unwrap(), None);
    logged();
    let clock = HostClock::with_reader(&new, os.reader());
    assert!(!clock.damaged());
    assert_eq!(clock.state, kept);
    assert_eq!(stored(&new), kept);
    let lines = logged();
    assert!(lines.iter().any(|l| l.contains("retired-")), "{lines:?}");
    // Damaged: carried as damage.
    let dir = tempfile::tempdir().unwrap();
    let old = Store::open(dir.path()).unwrap();
    let torn = Value::Text("{".into());
    old.put_clock(&torn).unwrap();
    old.retire(T).unwrap();
    let new = Store::open(dir.path()).unwrap();
    let clock = HostClock::with_reader(&new, os.reader());
    assert!(clock.damaged());
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED));
    assert_eq!(new.load_clock().unwrap(), Some(torn.clone()));
    assert_eq!(aside(&new), vec![torn]);
    // Retired stores with no record, or from before the `clock` table: a
    // fresh clock.
    let dir = tempfile::tempdir().unwrap();
    let old = Store::open(dir.path()).unwrap();
    old.retire(T).unwrap();
    let older = Store::open(dir.path()).unwrap();
    older.db.execute_batch("DROP TABLE clock").unwrap();
    older.retire(T + 1).unwrap();
    let new = Store::open(dir.path()).unwrap();
    let clock = HostClock::with_reader(&new, os.reader());
    assert!(!clock.damaged());
    assert_eq!(new.load_clock().unwrap(), None);
}

/// A carry into a new store that fails (PR 4, M2) is tried again at each
/// reading; until it is written and kept aside the status says so, and
/// nothing starts the clock afresh.
#[test]
fn a_failed_carry_is_retried_at_each_reading() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, _store, mut clock, torn) = damaged_clock(&os);
    let (_new_dir, new) = open_store();
    fail_writes(&new, "clock", true);
    clock.moved(&new);
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED_UNKEPT));
    for synced in [Synced::No, Synced::Yes] {
        os.pass(SEC);
        os.set_wall(os.wall(), synced);
        clock.tick(&new);
        assert!(clock.damaged());
        assert_eq!(new.load_clock().unwrap(), None);
    }
    assert!(!clock.station(ORIGIN, os.wall(), &new));
    fail_writes(&new, "clock", false);
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::No);
    clock.tick(&new);
    assert_eq!(new.load_clock().unwrap(), Some(torn.clone()));
    assert_eq!(aside(&new), vec![torn]);
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED));
}

/// A damaged record that couldn't be kept aside (PR 4, M3) says so, starts
/// nothing afresh, and is tried again at each reading: the copy, and a store
/// that couldn't be read at all.
#[test]
fn a_damaged_record_not_kept_aside_retries_at_each_reading() {
    // The copy fails.
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store) = open_store();
    let torn = Value::Text("{".into());
    store.put_clock(&torn).unwrap();
    store
        .db
        .execute_batch("CREATE TABLE clock_aside (at_ms INTEGER NOT NULL, state)")
        .unwrap();
    fail_writes(&store, "clock_aside", true);
    let mut clock = HostClock::with_reader(&store, os.reader());
    assert!(clock.damaged());
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED_UNKEPT));
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::Yes);
    clock.tick(&store);
    assert!(clock.damaged(), "no synchronized reading starts it unkept");
    assert!(!clock.station(ORIGIN, os.wall(), &store));
    fail_writes(&store, "clock_aside", false);
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::No);
    clock.tick(&store);
    assert_eq!(aside(&store), vec![torn.clone()]);
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED));
    assert_eq!(store.load_clock().unwrap(), Some(torn.clone()));

    // The store can't be read (here: a `clock` table of another shape).
    let (_dir, store) = open_store();
    store
        .db
        .execute_batch("DROP TABLE clock; CREATE TABLE clock (id INTEGER PRIMARY KEY)")
        .unwrap();
    let mut clock = HostClock::with_reader(&store, os.reader());
    assert!(clock.damaged());
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED_UNKEPT));
    // Readable again, with a damaged record: kept aside then.
    store
        .db
        .execute_batch("DROP TABLE clock; CREATE TABLE clock (id INTEGER PRIMARY KEY, state TEXT)")
        .unwrap();
    store.put_clock(&torn).unwrap();
    os.pass(SEC);
    clock.tick(&store);
    assert_eq!(aside(&store), vec![torn]);
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED));
}

/// A write that fails (PR 4, M4; the Task 33 gate's input): one log line
/// however many readings retry it, no `station_time` counts until it is
/// written, and the next reading after the fault writes.
#[test]
fn a_failed_write_is_logged_once_retried_and_counts_no_station_time() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    let written = stored(&store);
    logged();
    fail_writes(&store, "clock", true);
    os.pass(SEC);
    assert!(!clock.station(ORIGIN, os.wall() + 5 * MIN, &store));
    for _ in 0..3 {
        os.pass(SEC);
        clock.tick(&store);
    }
    let lines = logged();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("couldn't be written"), "{}", lines[0]);
    assert_eq!(stored(&store), written);
    fail_writes(&store, "clock", false);
    os.pass(SEC);
    clock.tick(&store);
    assert_eq!(stored(&store), clock.state);
    assert!(clock.station(ORIGIN, os.wall() + 5 * MIN, &store));
}

/// PR 4 re-review N3: of two retired stores, the numerically newest
/// (`retired-10` over `retired-9`, whatever the directory's order) is the
/// one whose record a new store takes.
#[test]
fn the_newest_retired_store_wins() {
    // Two records, each a clock's in a store of its own.
    let kept: Vec<ClockState> = [T, T + HOUR]
        .into_iter()
        .map(|wall| {
            let (_dir, store) = open_store();
            let os = Os::new(wall, 100 * SEC, "boot-a", Synced::Yes);
            let mut clock = HostClock::with_reader(&store, os.reader());
            clock.tick(&store);
            stored(&store)
        })
        .collect();
    assert_ne!(kept[0], kept[1]);
    let dir = tempfile::tempdir().unwrap();
    for (at, state) in [(9, &kept[0]), (10, &kept[1])] {
        let store = Store::open(dir.path()).unwrap();
        store.save_clock(state).unwrap();
        store.retire(at).unwrap();
    }
    let new = Store::open(dir.path()).unwrap();
    let os = Os::new(T + 2 * HOUR, 100 * SEC, "boot-a", Synced::Yes);
    let clock = HostClock::with_reader(&new, os.reader());
    assert!(!clock.damaged());
    assert_eq!(clock.state, kept[1], "retired-10 is the newest");
    assert_eq!(stored(&new), kept[1]);
}

/// PR 4 re-review N1, N3: a newest retired store that can't be read keeps
/// the clock damaged (fail closed: it may hold the record), and its line
/// names that file, not the new store; a readable older one isn't taken
/// in its place.
#[test]
fn an_unreadable_retired_store_keeps_the_clock_damaged_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let old = Store::open(dir.path()).unwrap();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&old, os.reader());
    clock.tick(&old);
    old.retire(9).unwrap();
    std::fs::write(
        dir.path().join("host-work.sqlite.retired-10"),
        b"not a database at all, not even close to one",
    )
    .unwrap();
    let new = Store::open(dir.path()).unwrap();
    logged();
    let clock = HostClock::with_reader(&new, os.reader());
    assert!(clock.damaged());
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED_UNKEPT));
    let lines = logged();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("host-work.sqlite.retired-10"),
        "{}",
        lines[0]
    );
    assert!(!lines[0].contains("sqlite.retired-9"), "{}", lines[0]);
    assert_eq!(new.load_clock().unwrap(), None, "nothing written over it");
}

/// PR 4 re-review N2: while a damaged record isn't kept aside, a Station
/// time within the cap is no start and leaves nothing behind: `D` stays the
/// reading's, and once the record is kept and a synchronized reading starts
/// the clock afresh, the floor holds none of it.
#[test]
fn a_damaged_record_not_kept_aside_takes_no_station_time() {
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::No);
    let (_dir, store) = open_store();
    store.put_clock(&Value::Text("{".into())).unwrap();
    store
        .db
        .execute_batch("CREATE TABLE clock_aside (at_ms INTEGER NOT NULL, state)")
        .unwrap();
    fail_writes(&store, "clock_aside", true);
    let mut clock = HostClock::with_reader(&store, os.reader());
    assert_eq!(clock.status_line().as_deref(), Some(DAMAGED_UNKEPT));
    os.pass(SEC);
    let w = os.wall();
    assert!(!clock.station(ORIGIN, w + 9 * MIN, &store));
    assert_eq!(clock.now().d_ms, w, "the Station time is not in D");
    fail_writes(&store, "clock_aside", false);
    os.pass(SEC);
    os.set_wall(os.wall(), Synced::Yes);
    clock.tick(&store);
    assert!(!clock.damaged());
    let now = clock.now();
    assert_eq!(now.d_ms, os.wall(), "nothing of it was kept");
    assert_eq!(stored(&store), clock.state);
}

/// Task 19 review M5 (PR 4 review D1): with no reading (the debug hook's
/// file has none) the clock never reads the OS, whose machine and boot
/// aren't the hook's: `now()` is the last reading's, else the record's own.
#[test]
fn without_a_reading_now_never_reads_the_os() {
    let (_dir, store) = open_store();
    let os = Os::new(T, 100 * SEC, "boot-a", Synced::Yes);
    let mut clock = HostClock::with_reader(&store, os.reader());
    clock.tick(&store);
    let at = clock.now();
    assert_eq!(at.h_ms, T);
    // The hook's file empties: the last reading stands.
    clock.read = Arc::new(|| None);
    assert_eq!(clock.now(), at);
    // A new run with no reading at all: the record's own `H`.
    let fresh = HostClock::with_reader(&store, Arc::new(|| None));
    assert_eq!(fresh.now().h_ms, T, "never the OS's time");
    assert_eq!(fresh.reading().map(|n| n.h_ms), Some(T));
    // No record either: no reading.
    let (_dir, empty) = open_store();
    assert_eq!(
        HostClock::with_reader(&empty, Arc::new(|| None)).reading(),
        None
    );
}

//! The delegated lifecycle's clock (host-work-v1 §11.6 "Clocks", design
//! I.6.5, owner decision 2026-11-10): automatic, host-local, with no command
//! and no network time. `os` takes the OS's readings; `state` applies §11.6's
//! rules to them; `HostClock` runs that state in the runtime.
//!
//! `HostClock` lives beside the host-work store (`host_work::Store`, table
//! `clock`), held by the runtime's host bridge (`Option<HostClock>`). Nothing
//! outside tests constructs it until the delegated lifecycle does, behind
//! `host.delegated` (step 4, Task 19): until then the host writes no clock
//! row, no clock line and no status, as main does.
//!
//! - **Readings.** The pass observes one a second (`tick`), and a Station's
//!   `station_time` is observed with one (`station`). In debug builds
//!   `ATEM_TEST_HOST_CLOCK` replaces the OS's readings (`test_hooks`); release
//!   builds always read the OS.
//! - **Persistence** (§11.6: "at least once a minute and at shutdown"; I.6.1):
//!   the record is written at its first reading in a run, then once a minute
//!   of boot time, at every event, when the mark changes, at a boot change,
//!   with every `station_time` (before it counts), and at an orderly stop
//!   (`close`). A write that fails is logged once and tried again at every
//!   reading.
//! - **Deadlines** compare with `now().d_ms` (`D`).
//! - **Reports.** Every repair and every lowering writes one `runtime.log`
//!   line with the old and new values, and so does each owner alert (step 4
//!   Decision 12: "host clock went back", "Station clock ahead of this
//!   host"); the follow-down, anchors and guards write none. `atem status`
//!   gets `status_line`: §11.6's text while the clock holds deadlines back,
//!   and the latest repair or lowering with its values for a day of `D`
//!   (ruling T11c), the two side by side when both apply.
//! - **A damaged record** (one that isn't a clock state) is never taken for
//!   a fresh one, which would lose the record and re-arm the lowering: it is
//!   kept aside (`clock_aside`), one `runtime.log` line and the status say so,
//!   delegated work waits (`damaged`), and nothing is written over it until
//!   the first of (ruling T11a): a reading the OS reports synchronized (the
//!   clock starts afresh from it, as a profile's first synchronized reading
//!   would), or a Station's `station_time` within the cap of the reading
//!   (`H` = `max(reading, station_time)`, the floor taken from it, no
//!   lowering armed). Delegated work comes only from senders a Station's
//!   feed covers, so a working delegated host gets one; the 10-minute cap
//!   bounds a forged one, as for any floor. One beyond the cap keeps it
//!   waiting, with the origin's "Station clock ahead" alert.

// Its macOS confirmation reader and the Linux composition's parts are read
// by tests only.
#[allow(dead_code)]
pub mod os;
pub mod state;

use self::os::{OsReading, Synced};
use self::state::{Change, ChangeKind, ClockEvent, ClockState, StationStep, Step};
use crate::runtime::host_work::Store;
use rusqlite::types::Value;
use std::sync::Arc;

/// The record is written at least this often, on the boot-time counter.
const PERSIST_EVERY_NS: u64 = 60_000_000_000;

/// `D` more than this ahead of the wall clock holds deadlines back worth a
/// status line (the lowering's threshold, and the went-back alert's).
const AHEAD_MS: u64 = state::WENT_BACK_MS;

/// §11.6: the mark holds deadlines back where the OS's synchronized flag
/// never clears.
pub const AHEAD_ENABLE_SYNC: &str = "host clock ahead of its record; enable time synchronization (chrony with rtcsync, or systemd-timesyncd)";
/// §11.6: the mark holds deadlines back on macOS, whose sync report isn't
/// confirmed.
pub const AHEAD_WAITING: &str = "host clock ahead of its record; waiting for a synchronized clock";
/// §11.6's owner alert, while the wall clock is more than 10 minutes below
/// `H` with no mark.
pub const WENT_BACK: &str = "host clock went back";
/// A damaged record: kept aside, delegated work waits.
pub const DAMAGED: &str = "host clock record damaged and kept aside; delegated work waits for a synchronized clock or a Station time";

/// The delegated clock now: `H` and `D` (§11.6), in ms since the epoch.
// Read by the delegated deadline checks (step 4, Tasks 19–22, 26, 28, 36).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegatedNow {
    pub h_ms: u64,
    /// Every delegated deadline is compared with it.
    pub d_ms: u64,
}

/// Where readings come from: `None` while the debug hook's file has none.
type Reader = Arc<dyn Fn() -> Option<OsReading> + Send + Sync>;

/// The OS's reading, or the debug hook's (`ATEM_TEST_HOST_CLOCK`).
fn system_reading() -> Option<OsReading> {
    match crate::runtime::test_hooks::host_clock_reading() {
        Some(hook) => hook,
        None => Some(os::read()),
    }
}

pub struct HostClock {
    state: ClockState,
    /// The latest reading observed.
    last: Option<OsReading>,
    read: Reader,
    /// The reading the record was last written at, in this run.
    saved: Option<OsReading>,
    /// A write failed: logged once, tried again at every reading.
    unsaved: bool,
    damaged: Option<Damaged>,
}

/// A stored record that isn't a clock state.
struct Damaged {
    /// As stored (`None`: the store couldn't be read).
    value: Option<Value>,
    /// Kept aside: a synchronized reading may start afresh over it.
    aside: bool,
}

impl HostClock {
    /// The clock as `store` recorded it (none: a fresh one; a damaged one:
    /// see the module doc).
    // Constructed by the delegated lifecycle behind `host.delegated` (step 4,
    // Task 19); only tests construct it before.
    #[allow(dead_code)]
    pub fn load(store: &Store) -> Self {
        Self::with_reader(store, Arc::new(system_reading))
    }

    fn with_reader(store: &Store, read: Reader) -> Self {
        let last = read();
        let mut clock = HostClock {
            state: ClockState::default(),
            last,
            read,
            saved: None,
            unsaved: false,
            damaged: None,
        };
        match store.load_clock() {
            Ok(None) => {}
            Ok(Some(Value::Text(text))) => match ClockState::from_json(&text) {
                Ok(state) => clock.state = state,
                Err(e) => clock.damage(store, Some(Value::Text(text)), &e.to_string()),
            },
            Ok(Some(value)) => clock.damage(store, Some(value), "not text"),
            Err(e) => clock.damage(store, None, &format!("{e:#}")),
        }
        clock
    }

    fn damage(&mut self, store: &Store, value: Option<Value>, why: &str) {
        let at_ms = self.last.as_ref().map_or(0, |r| r.wall_ms);
        let aside = value.is_some()
            && store
                .keep_clock_aside(at_ms)
                .map_err(|e| log(format!("its damaged record couldn't be kept aside ({e:#})")))
                .is_ok();
        log(format!(
            "its record in {} can't be read ({why}); {}, and delegated work waits for a synchronized clock or a Station time within the cap",
            store.state.join("host-work.sqlite").display(),
            if aside {
                "kept aside (table clock_aside)"
            } else {
                "not kept aside, so nothing is written over it"
            },
        ));
        self.damaged = Some(Damaged { value, aside });
    }

    /// One reading (once a second on the pass): §11.6's rules, the record
    /// written when due, `runtime.log` lines for repairs, lowerings and
    /// alerts. What happened.
    pub fn tick(&mut self, store: &Store) -> Vec<ClockEvent> {
        self.observe(store, false)
    }

    /// At an orderly stop: a last reading, written.
    pub fn close(&mut self, store: &Store) {
        self.observe(store, true);
    }

    fn observe(&mut self, store: &Store, force: bool) -> Vec<ClockEvent> {
        let Some(r) = (self.read)() else {
            return Vec::new();
        };
        let mark = self.state.mark();
        let Step { next, events } = self.state.observe(&r);
        self.state = next;
        log_events(&events);
        let due = force
            || !events.is_empty()
            || mark != self.state.mark()
            || self.unsaved
            || self.persist_due(&r);
        self.last = Some(r.clone());
        match &self.damaged {
            Some(d) if d.aside && r.synced == Synced::Yes => {
                self.damaged = None;
                log(
                    "starts afresh at a synchronized reading; its damaged record stays kept aside"
                        .into(),
                );
                self.persist(store, &r);
            }
            Some(_) => {}
            None if due => {
                self.persist(store, &r);
            }
            None => {}
        }
        events
    }

    /// A Station's `station_time` from `origin`'s heads, observed with a
    /// reading: taken into the floor up to `H` + 10 minutes. Written before
    /// it counts, whatever the cap said (the reading's effects are in it):
    /// false when beyond the cap (the origin's gate closes) and when the
    /// write failed. While the record is damaged, one within the cap of the
    /// reading starts the clock afresh from it (`ClockState::station_afresh`)
    /// and counts once written; one beyond keeps it waiting (false).
    // Called on a Station's heads (step 4, Task 33).
    #[allow(dead_code)]
    pub fn station(&mut self, origin: &str, station_time_ms: u64, store: &Store) -> bool {
        let Some(r) = (self.read)() else {
            return false;
        };
        let aside = self.damaged.as_ref().map(|d| d.aside);
        let StationStep {
            next,
            within_cap,
            events,
        } = match aside {
            Some(true) => self.state.station_afresh(origin, station_time_ms, &r),
            _ => self.state.station(origin, station_time_ms, &r),
        };
        self.state = next;
        log_events(&events);
        self.last = Some(r.clone());
        match aside {
            None => self.persist(store, &r) && within_cap,
            Some(true) if within_cap => {
                self.damaged = None;
                log(format!(
                    "starts afresh at the Station time {} from {origin} (the wall clock read {}); its damaged record stays kept aside",
                    utc(station_time_ms),
                    utc(r.wall_ms)
                ));
                self.persist(store, &r)
            }
            Some(_) => false,
        }
    }

    /// `H` and `D` at a reading taken now.
    // Called by the delegated deadline checks (step 4, Tasks 19–22, 26, 28,
    // 36).
    #[allow(dead_code)]
    pub fn now(&self) -> DelegatedNow {
        let r = (self.read)()
            .or_else(|| self.last.clone())
            .unwrap_or_else(os::read);
        DelegatedNow {
            h_ms: self.state.h_ms(&r),
            d_ms: self.state.deadline_ms(&r),
        }
    }

    /// The `atem status` line, as of the latest reading: §11.6's text while
    /// the clock holds deadlines back, and the latest repair or lowering
    /// within a day of `D` (see `status_text`).
    pub fn status_line(&self) -> Option<String> {
        if self.damaged.is_some() {
            return Some(DAMAGED.to_string());
        }
        status_text(&self.state, self.last.as_ref()?, cfg!(target_os = "macos"))
    }

    /// The stored record was damaged and the clock hasn't started afresh:
    /// delegated work waits.
    // Read by the delegated start check and admission (step 4, Tasks 18
    // and 19).
    #[allow(dead_code)]
    pub fn damaged(&self) -> bool {
        self.damaged.is_some()
    }

    /// The store was moved aside for a new host identity and `store` opened
    /// in its place: the clock is the host's, so its record goes on in the
    /// new store at once (a damaged one as it was, so it stays damaged).
    pub fn moved(&mut self, store: &Store) {
        self.saved = None;
        match &self.damaged {
            None => {
                if let Some(r) = self.last.clone() {
                    self.persist(store, &r);
                }
            }
            Some(d) => {
                let value = d.value.clone().unwrap_or(Value::Null);
                let at_ms = self.last.as_ref().map_or(0, |r| r.wall_ms);
                let kept = store
                    .put_clock(&value)
                    .and_then(|()| store.keep_clock_aside(at_ms));
                if let Err(e) = kept {
                    log(format!(
                        "its damaged record couldn't be carried into the new store ({e:#})"
                    ));
                }
            }
        }
    }

    /// A minute of boot time since the last write, or another boot.
    fn persist_due(&self, r: &OsReading) -> bool {
        self.saved.as_ref().is_none_or(|s| {
            s.boot_id != r.boot_id
                || s.machine != r.machine
                || s.timens_boot_ns != r.timens_boot_ns
                || r.boot_ns < s.boot_ns
                || r.boot_ns - s.boot_ns >= PERSIST_EVERY_NS
        })
    }

    fn persist(&mut self, store: &Store, r: &OsReading) -> bool {
        match store.save_clock(&self.state) {
            Ok(()) => {
                self.unsaved = false;
                self.saved = Some(r.clone());
                true
            }
            Err(e) => {
                if !self.unsaved {
                    log(format!(
                        "its record couldn't be written ({e:#}); trying again at every reading"
                    ));
                }
                self.unsaved = true;
                false
            }
        }
    }
}

/// The status line for `state` at reading `r` (see `status_line`): what
/// holds deadlines back (`held_back`), then, after `; `, the latest repair or
/// lowering while `D` is less than a day past it (§11.6: `atem status` shows
/// it; ruling T11c).
fn status_text(state: &ClockState, r: &OsReading, macos: bool) -> Option<String> {
    let change = state
        .last_change()
        .filter(|c| state.deadline_ms(r).saturating_sub(c.at_ms) < state::CHANGE_SHOWN_MS)
        .map(change_text);
    match (held_back(state, r, macos), change) {
        (Some(held), Some(change)) => Some(format!("{held}; {change}")),
        (Some(held), None) => Some(held.to_string()),
        (None, change) => change,
    }
}

/// With the mark and no synchronized reading, `D` more than 10 minutes ahead
/// of the wall clock is held back until the lowering, and the text names the
/// fix (`macos`: waiting for its report); without the mark, `H` that far
/// ahead is the went-back alert's state.
fn held_back(state: &ClockState, r: &OsReading, macos: bool) -> Option<&'static str> {
    let ahead = |v: u64| v > r.wall_ms.saturating_add(AHEAD_MS);
    if state.mark() && r.synced != Synced::Yes && ahead(state.deadline_ms(r)) {
        return Some(if macos {
            AHEAD_WAITING
        } else {
            AHEAD_ENABLE_SYNC
        });
    }
    ahead(state.h_ms(r)).then_some(WENT_BACK)
}

/// A repair or lowering as `atem status` shows it, with its values.
fn change_text(change: &Change) -> String {
    let what = match change.kind {
        ChangeKind::Repaired => "repaired a forward jump undone",
        ChangeKind::Lowered => "lowered to the wall clock at a boot's first synchronized reading",
    };
    format!(
        "host clock {what} at {}: {}",
        utc(change.at_ms),
        values(&change.old, &change.new)
    )
}

/// `wall_hw <old> -> <new>[, floor <old> -> <new>]`.
fn values(old: &(u64, Option<u64>), new: &(u64, Option<u64>)) -> String {
    let floor = |v: Option<u64>| v.map_or_else(|| "none".to_string(), utc);
    let mut text = format!("wall_hw {} -> {}", utc(old.0), utc(new.0));
    if old.1.is_some() || new.1.is_some() {
        text.push_str(&format!(", floor {} -> {}", floor(old.1), floor(new.1)));
    }
    text
}

/// The `runtime.log` line of an event: repairs and lowerings with the old
/// and new values (§11.6), the owner alerts (Decision 12); none for the
/// rest.
fn log_line(event: &ClockEvent) -> Option<String> {
    match event {
        ClockEvent::Repaired { old, new } => Some(format!(
            "repaired a forward jump undone: {}",
            values(old, new)
        )),
        ClockEvent::LoweredAtSync { old, new } => Some(format!(
            "lowered to the wall clock at this boot's first synchronized reading: {}",
            values(old, new)
        )),
        ClockEvent::WentBack { wall_ms, h_ms } => Some(format!(
            "host clock went back: the wall clock reads {}, more than 10 minutes below the host's time {}; deadlines keep the host's time",
            utc(*wall_ms),
            utc(*h_ms)
        )),
        ClockEvent::StationAhead {
            origin,
            station_time_ms,
            cap_ms,
        } => Some(format!(
            "Station clock ahead of this host: {origin} sent {}, beyond {}; not taken, and its revocation gate stays closed",
            utc(*station_time_ms),
            utc(*cap_ms)
        )),
        ClockEvent::AnchorArmed | ClockEvent::AnchorDropped | ClockEvent::Guarded(_) => None,
    }
}

fn log_events(events: &[ClockEvent]) {
    for line in events.iter().filter_map(log_line) {
        log(line);
    }
}

#[cfg(test)]
thread_local! {
    /// Lines written on this thread (tests read them).
    static LOGGED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// One `runtime.log` line (the runtime's stderr).
fn log(line: String) {
    eprintln!("atem runtime: host clock: {line}");
    #[cfg(test)]
    LOGGED.with(|l| l.borrow_mut().push(line));
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn utc(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX);
    let s = secs.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}.{:03}Z",
        crate::memory::model::format_date(secs),
        s / 3600,
        s / 60 % 60,
        s % 60,
        ms % 1000
    )
}

#[cfg(test)]
#[path = "clock_tests.rs"]
mod tests;

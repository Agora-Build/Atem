//! The delegated lifecycle's clock state (host-work-v1 §11.6 "Clocks",
//! design I.6.5; owner decision 2026-11-10; step 4 Decision 17): the
//! `wall_hw` record, the clock floor, the anchor of a jump, the mark after a
//! reboot and the guards across a boot change. Sans-I/O: it takes the OS's
//! readings (`os::OsReading`) and returns the next state and what happened,
//! so every rule runs on synthetic readings. `HostClock` persists it and
//! feeds it the OS's readings.
//!
//! The rules (§11.6):
//! - **One boot.** Boot-time differences are taken within one boot only: the
//!   same boot id, machine identity and boot-time namespace offset
//!   (`crossing`). A changed offset within a boot (a CRIU restore) is a boot
//!   change with Δ = 0 (Decision 17).
//! - **`H`** is `max(wall clock, the record's prediction)`: in its boot the
//!   record plus the boot time since it; after a boot change the record plus
//!   this boot's boot time so far, only when Decision 17's guards pass, else
//!   its bare value (`observe`'s first reading of a boot records that, at
//!   least the wall clock).
//! - **The update** (`update`): the reading when it is at or above the
//!   prediction, else `max(w, p − ρ·Δ)`, the follow-down at 500 ppm.
//! - **The anchor** (rules 1–4 of "Automatic repair"): an unsynchronized
//!   reading more than 60 s above the prediction copies the record and the
//!   floor as they stood; a later reading within 60 s of the anchor's record
//!   prediction lowers both (never raises them, never below the reading, the
//!   anchor's predictions or the Station raise kept with it); the OS's sync
//!   at a reading outside the band drops it.
//! - **The mark** (`lower_at_sync`): from a new boot until the first reading
//!   the OS reports synchronized, at which `wall_hw` and the floor, when
//!   either is more than 10 minutes ahead of the wall clock, are lowered to
//!   it, once.
//! - **The floor** (`station`): a `station_time` up to `H` + 10 minutes;
//!   above the floor it raises it, below it the floor follows it down at
//!   500 ppm.
//! - **Deadlines** compare with `D = max(H, the floor's prediction)`.
//!
//! The fallbacks of the OS readings (ruling T9b): a boot id the OS can't give
//! (`os::UNKNOWN_BOOT_PREFIX`, one per process) and a machine with no id
//! readable (`os::unknown_machine`, one for all such machines) carry no boot
//! time across a boot change, since neither can show the record predates the
//! boot, and an unknown boot sets no mark, since it can't count boots.

use super::os::{OsReading, Synced, UNKNOWN_BOOT_PREFIX, unknown_machine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The follow-down rate `ρ`, in parts per million: 0.5 ms a second, 43.2 s
/// a day (NTP's and the kernel's `MAXFREQ`).
pub const RHO_PPM: u64 = 500;
/// A reading this far above the prediction is a forward jump; one this
/// close to an anchor's record prediction undoes it.
pub const JUMP_MS: u64 = 60_000;
/// How far above `H` a `station_time` is still taken.
pub const CAP_MS: u64 = 600_000;
/// A wall clock more than this below `H` raises "host clock went back".
pub const WENT_BACK_MS: u64 = 600_000;
/// An owner alert's least spacing, on `H`.
pub const ALERT_EVERY_MS: u64 = 3_600_000;

/// At a boot's first synchronized reading, `wall_hw` or the floor more than
/// this ahead of the wall clock is lowered to it.
const LOWER_AHEAD_MS: u64 = 600_000;
/// Decision 17 (b): a record predates this boot when it is at most this far
/// above the wall clock's reading of the boot's start (`w − b`).
const BEFORE_BOOT_SLACK_MS: u64 = 60_000;
/// The origins whose last "Station clock ahead" alert is kept.
const MAX_ORIGINS: usize = 16;

/// Values on the host's clock are kept in ns since the epoch (`i128`); a
/// stamp stores the millisecond and puts the rest into its boot time.
const NS_PER_MS: i128 = 1_000_000;

fn ns(ms: u64) -> i128 {
    i128::from(ms) * NS_PER_MS
}

fn to_ms(ns: i128) -> u64 {
    u64::try_from(ns.max(0) / NS_PER_MS).unwrap_or(u64::MAX)
}

/// The follow-down allowed over `since`, the boot time since a stamp: 500
/// ppm of it less 1 ms, since a stamp's boot time can lie up to 1 ms before
/// the update it records (`Stamp::at`), so the allowance is never more than
/// 500 ppm of the boot time since that update.
fn follow_down(since: i128) -> i128 {
    (since - NS_PER_MS).max(0) * i128::from(RHO_PPM) / 1_000_000
}

/// A boot id the OS couldn't give (`os::boot_session_id`'s fallback).
fn unknown_boot(id: &str) -> bool {
    id.starts_with(UNKNOWN_BOOT_PREFIX)
}

/// A value on the host's clock and the boot time it holds at: the `wall_hw`
/// record, the floor, and the anchor's copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stamp {
    /// The value at `boot_ns`, in ms since the epoch.
    pub value_ms: u64,
    pub boot_id: String,
    /// The boot-time counter, meaningful within `boot_id`, `machine` and
    /// `timens_boot_ns` only.
    pub boot_ns: u64,
    /// `os::machine_identity` (Decision 17).
    #[serde(with = "machine_hex")]
    pub machine: [u8; 16],
    /// The boot-time namespace offset the counter included (Decision 17).
    pub timens_boot_ns: i64,
}

impl Stamp {
    /// `value` (ns) at reading `r`, exactly: the value's part below a
    /// millisecond moves the stamp's boot time back, so the stamp predicts
    /// `value` at `r` and from then on, and no update rounds the record.
    fn at(value: i128, r: &OsReading) -> Stamp {
        let value = value.max(0);
        let below_ms = u64::try_from(value % NS_PER_MS).unwrap_or(0);
        Stamp {
            value_ms: to_ms(value),
            boot_id: r.boot_id.clone(),
            // A counter under 1 ms (never, after a boot) rounds down instead.
            boot_ns: r.boot_ns.saturating_sub(below_ms),
            machine: r.machine,
            timens_boot_ns: r.timens_boot_ns,
        }
    }

    fn value(&self) -> i128 {
        ns(self.value_ms)
    }

    /// The boot time from the stamp to `r`, within its boot (never negative:
    /// a counter read a hair lower counts as no time).
    fn since(&self, r: &OsReading) -> i128 {
        (i128::from(r.boot_ns) - i128::from(self.boot_ns)).max(0)
    }

    fn same_boot_as(&self, other: &Stamp) -> bool {
        self.boot_id == other.boot_id
            && self.machine == other.machine
            && self.timens_boot_ns == other.timens_boot_ns
    }
}

/// How a stamp's boot time relates to a reading's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Crossing {
    /// The same boot: the boot time since the stamp counts.
    Same,
    /// A boot change the guards pass: the stamp predicts its value plus this
    /// boot's boot time so far.
    Carry,
    /// A boot change no boot time crosses: the stamp's bare value.
    Bare(GuardWhy),
}

/// One boot (§11.6), with Decision 17's guards and the fallbacks' (T9b).
fn crossing(s: &Stamp, r: &OsReading) -> Crossing {
    let same_id = s.boot_id == r.boot_id;
    if same_id && s.machine == r.machine && s.timens_boot_ns == r.timens_boot_ns {
        return Crossing::Same;
    }
    // (a) the record's machine.
    if s.machine != r.machine {
        return Crossing::Bare(GuardWhy::OtherMachine);
    }
    // Within a boot, a changed namespace offset is a new boot with Δ = 0:
    // the record was made in this boot, so it doesn't predate it.
    if same_id {
        return Crossing::Bare(GuardWhy::NamespaceChanged);
    }
    if unknown_boot(&s.boot_id) || unknown_boot(&r.boot_id) {
        return Crossing::Bare(GuardWhy::UnknownBoot);
    }
    if r.machine == unknown_machine() {
        return Crossing::Bare(GuardWhy::UnknownMachine);
    }
    // (c) the counter starts at this boot.
    if r.timens_boot_ns != 0 {
        return Crossing::Bare(GuardWhy::TimeNamespace);
    }
    // (b) the record predates this boot on the wall clock.
    if s.value() > ns(r.wall_ms) - i128::from(r.boot_ns) + ns(BEFORE_BOOT_SLACK_MS) {
        return Crossing::Bare(GuardWhy::NotBeforeThisBoot);
    }
    Crossing::Carry
}

/// A stamp's prediction at `r`.
fn predict(s: &Stamp, how: Crossing, r: &OsReading) -> i128 {
    match how {
        Crossing::Same => s.value() + s.since(r),
        Crossing::Carry => s.value() + i128::from(r.boot_ns),
        Crossing::Bare(_) => s.value(),
    }
}

/// A pending jump's anchor: the record and the floor as they stood before
/// the jump, and the highest Station raise since. Its copies never change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    record: Stamp,
    floor: Option<Stamp>,
    station: Option<Stamp>,
}

/// The host's delegated clock (§11.6): what `HostClock` persists.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockState {
    /// `wall_hw`.
    record: Option<Stamp>,
    /// The latest `station_time` taken (or what the follow-down, a repair or
    /// a lowering made of it).
    floor: Option<Stamp>,
    anchor: Option<Anchor>,
    /// From a new boot until its first synchronized reading.
    mark: bool,
    /// `H` at the last "host clock went back".
    last_went_back_alert_ms: Option<u64>,
    /// `H` at the last "Station clock ahead of this host", per origin.
    last_ahead_alert_ms: BTreeMap<String, u64>,
}

/// What a reading or a `station_time` did, for `runtime.log`, `atem status`
/// and the owner's alerts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockEvent {
    /// The wall clock is more than 10 minutes below `H` (at most hourly).
    WentBack {
        wall_ms: u64,
        h_ms: u64,
    },
    /// A `station_time` above `H` + 10 minutes: not taken, and the origin's
    /// gate closes (at most one alert an hour per origin).
    StationAhead {
        origin: String,
        station_time_ms: u64,
        cap_ms: u64,
    },
    AnchorArmed,
    AnchorDropped,
    /// A jump undone: `(wall_hw, floor)` as they predicted at the reading,
    /// and after.
    Repaired {
        old: (u64, Option<u64>),
        new: (u64, Option<u64>),
    },
    /// The once-per-boot lowering: `(wall_hw, floor)` just before it (after
    /// the reading's update, or its boot's first reading), and after.
    LoweredAtSync {
        old: (u64, Option<u64>),
        new: (u64, Option<u64>),
    },
    /// A boot change no boot time crossed.
    Guarded(GuardWhy),
}

/// Why no boot time crossed a boot change (Decision 17; the last two are the
/// OS readings' fallbacks, ruling T9b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardWhy {
    /// (a) The record is another machine's: a moved profile.
    OtherMachine,
    /// (b) The record doesn't predate this boot on the wall clock: one
    /// machine id baked into many nodes (or a wall clock behind at boot).
    NotBeforeThisBoot,
    /// (c) The counter carries a boot-time namespace offset.
    TimeNamespace,
    /// The offset changed within a boot (a CRIU restore).
    NamespaceChanged,
    /// A boot id the OS couldn't give, on either side.
    UnknownBoot,
    /// A machine with no id readable, which all such machines share.
    UnknownMachine,
}

/// The state after a reading, and what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub next: ClockState,
    pub events: Vec<ClockEvent>,
}

/// The state after a `station_time`, whether it was within the cap (else the
/// origin's gate closes), and what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationStep {
    pub next: ClockState,
    pub within_cap: bool,
    pub events: Vec<ClockEvent>,
}

impl ClockState {
    /// A reading: the record's update (or a boot's first reading), the
    /// anchor's rules, the lowering at a boot's first synchronized reading,
    /// and the went-back alert, as one evaluation.
    pub fn observe(&self, r: &OsReading) -> Step {
        let mut next = self.clone();
        let mut events = Vec::new();
        match &self.record {
            Some(record) => match crossing(record, r) {
                Crossing::Same => next.update(record, r, &mut events),
                how => next.enter_boot(Some((record, how)), r, &mut events),
            },
            None => next.enter_boot(None, r, &mut events),
        }
        next.lower_at_sync(r, &mut events);
        next.went_back(r, &mut events);
        Step { next, events }
    }

    /// A `station_time` from `origin`'s heads, read at `r` (which is also
    /// observed first): taken up to `H` + 10 minutes; a raise above the
    /// floor's prediction, or a follow-down toward a lower one.
    pub fn station(&self, origin: &str, station_time_ms: u64, r: &OsReading) -> StationStep {
        let Step {
            mut next,
            mut events,
        } = self.observe(r);
        let h = next.h_ns(r);
        let cap = h + ns(CAP_MS);
        let st = ns(station_time_ms);
        if st > cap {
            let h_ms = to_ms(h);
            if alert_due(next.last_ahead_alert_ms.get(origin).copied(), h_ms) {
                events.push(ClockEvent::StationAhead {
                    origin: origin.to_string(),
                    station_time_ms,
                    cap_ms: to_ms(cap),
                });
                next.note_ahead_alert(origin, h_ms);
            }
            return StationStep {
                next,
                within_cap: false,
                events,
            };
        }
        let floor = next
            .floor
            .as_ref()
            .map(|f| (f.since(r), predict(f, Crossing::Same, r)));
        match floor {
            Some((since, now)) if st <= now => {
                // At most 500 ppm of the boot time since the floor last
                // changed, never below the Station's time.
                let lowered = st.max(now - follow_down(since));
                if lowered != now {
                    next.floor = Some(Stamp::at(lowered, r));
                }
            }
            _ => {
                next.floor = Some(Stamp::at(st, r));
                // Kept with a pending anchor: the raise with the highest
                // prediction since it was taken.
                if let Some(anchor) = next.anchor.as_mut() {
                    let higher = anchor
                        .station
                        .as_ref()
                        .is_none_or(|kept| st > predict(kept, Crossing::Same, r));
                    if higher {
                        anchor.station = Some(Stamp::at(st, r));
                    }
                }
            }
        }
        StationStep {
            next,
            within_cap: true,
            events,
        }
    }

    /// `H` at `r`.
    pub fn h_ms(&self, r: &OsReading) -> u64 {
        to_ms(self.h_ns(r))
    }

    /// `D = max(H, floor + boot time since the floor)` at `r`: the clock every
    /// delegated deadline is compared with.
    pub fn deadline_ms(&self, r: &OsReading) -> u64 {
        to_ms(self.deadline_ns(r))
    }

    /// The record carries the mark: no synchronized reading yet in its boot.
    pub fn mark(&self) -> bool {
        self.mark
    }

    fn h_ns(&self, r: &OsReading) -> i128 {
        let w = ns(r.wall_ms);
        self.record
            .as_ref()
            .map_or(w, |record| w.max(predict(record, crossing(record, r), r)))
    }

    fn deadline_ns(&self, r: &OsReading) -> i128 {
        let h = self.h_ns(r);
        self.floor_ns(r).map_or(h, |floor| h.max(floor))
    }

    /// The floor's prediction at `r`: across a boot change with the record's
    /// verdict when it shares the record's boot (Decision 17 guards both
    /// alike), else with its own.
    fn floor_ns(&self, r: &OsReading) -> Option<i128> {
        let floor = self.floor.as_ref()?;
        Some(predict(floor, self.floor_crossing(floor, r), r))
    }

    fn floor_crossing(&self, floor: &Stamp, r: &OsReading) -> Crossing {
        match &self.record {
            Some(record) if floor.same_boot_as(record) => crossing(record, r),
            _ => crossing(floor, r),
        }
    }

    /// A reading in the record's boot: rules 1–4 and the follow-down.
    fn update(&mut self, record: &Stamp, r: &OsReading, events: &mut Vec<ClockEvent>) {
        let w = ns(r.wall_ms);
        let since = record.since(r);
        let p = record.value() + since;
        let updated = if w >= p {
            w
        } else {
            w.max(p - follow_down(since))
        };
        let synced = r.synced == Synced::Yes;
        // The floor is in this boot (only a state written elsewhere could
        // put it in another).
        self.rebase_floor(r, events);

        if let Some(anchor) = self.anchor.clone() {
            if crossing(&anchor.record, r) != Crossing::Same {
                self.anchor = None;
                events.push(ClockEvent::AnchorDropped);
            } else {
                let a = predict(&anchor.record, Crossing::Same, r);
                if (w - a).abs() <= ns(JUMP_MS) {
                    // Rule 3: undone. Both lowered, never raised.
                    self.repair(&anchor, a, p, updated, r, events);
                    return;
                }
                if synced {
                    // Rule 4: the OS made the jumped trajectory its time.
                    self.anchor = None;
                    events.push(ClockEvent::AnchorDropped);
                }
            }
        }
        // Rule 1: a forward jump the OS doesn't report synchronized anchors
        // the record and the floor as they stood; a further one keeps the
        // first anchor.
        if self.anchor.is_none() && w > p + ns(JUMP_MS) && !synced {
            self.anchor = Some(Anchor {
                record: record.clone(),
                floor: self.floor.clone(),
                station: None,
            });
            events.push(ClockEvent::AnchorArmed);
        }
        self.record = Some(Stamp::at(updated, r));
    }

    /// Rule 3: `wall_hw` to `max(w, the anchor's record prediction)` and the
    /// floor to `max(w, the anchor's floor prediction, the Station raise kept
    /// with it)`, each only ever lowered, stamped now; the anchor dropped.
    fn repair(
        &mut self,
        anchor: &Anchor,
        a: i128,
        p: i128,
        updated: i128,
        r: &OsReading,
        events: &mut Vec<ClockEvent>,
    ) {
        let w = ns(r.wall_ms);
        let record = updated.min(w.max(a));
        let old_floor = self.floor.as_ref().map(|f| predict(f, Crossing::Same, r));
        let new_floor = old_floor.map(|now| {
            let target = [anchor.floor.as_ref(), anchor.station.as_ref()]
                .into_iter()
                .flatten()
                .map(|s| predict(s, Crossing::Same, r))
                .fold(w, i128::max);
            now.min(target)
        });
        if new_floor != old_floor
            && let Some(floor) = new_floor
        {
            self.floor = Some(Stamp::at(floor, r));
        }
        self.record = Some(Stamp::at(record, r));
        self.anchor = None;
        events.push(ClockEvent::Repaired {
            old: (to_ms(p), old_floor.map(to_ms)),
            new: (to_ms(record), new_floor.map(to_ms)),
        });
    }

    /// The first reading of a boot (or the first ever): no jump and no
    /// anchor; it records `max(w, wall_hw + this boot's boot time so far)`,
    /// or `max(w, wall_hw)` when the guards keep boot time from crossing;
    /// the floor predicts across the same way; a new boot sets the mark.
    fn enter_boot(
        &mut self,
        from: Option<(&Stamp, Crossing)>,
        r: &OsReading,
        events: &mut Vec<ClockEvent>,
    ) {
        let w = ns(r.wall_ms);
        if let Some((_, Crossing::Bare(why))) = from {
            events.push(ClockEvent::Guarded(why));
        }
        if let Some(floor) = self.floor.take() {
            let how = match from {
                Some((record, how)) if floor.same_boot_as(record) => how,
                _ => crossing(&floor, r),
            };
            note_guard(how, events);
            self.floor = Some(Stamp::at(predict(&floor, how, r), r));
        }
        let carried = from.map(|(record, how)| predict(record, how, r));
        self.record = Some(Stamp::at(carried.map_or(w, |v| v.max(w)), r));
        if self.anchor.take().is_some() {
            events.push(ClockEvent::AnchorDropped);
        }
        // The mark goes with a boot Atem can tell is new: the first reading
        // ever, or another boot id, both the OS's. A changed namespace in the
        // same boot, or an id the OS couldn't give, leaves it as it was.
        let new_boot = match from {
            None => true,
            Some((record, _)) => {
                record.boot_id != r.boot_id
                    && !unknown_boot(&record.boot_id)
                    && !unknown_boot(&r.boot_id)
            }
        };
        if new_boot {
            self.mark = true;
        }
    }

    /// A floor in another boot than `r`'s (never, from this state's own
    /// transitions) is moved to it, its prediction kept.
    fn rebase_floor(&mut self, r: &OsReading, events: &mut Vec<ClockEvent>) {
        if let Some(floor) = &self.floor {
            let how = self.floor_crossing(floor, r);
            if how != Crossing::Same {
                note_guard(how, events);
                self.floor = Some(Stamp::at(predict(floor, how, r), r));
            }
        }
    }

    /// While the mark is set, a synchronized reading lowers `wall_hw` and the
    /// floor to the wall clock when either is more than 10 minutes ahead of
    /// it (a floor below it stays), and the mark goes.
    fn lower_at_sync(&mut self, r: &OsReading, events: &mut Vec<ClockEvent>) {
        if !self.mark || r.synced != Synced::Yes {
            return;
        }
        self.mark = false;
        let w = ns(r.wall_ms);
        let record = self
            .record
            .as_ref()
            .map_or(w, |s| predict(s, Crossing::Same, r));
        let floor = self.floor.as_ref().map(|s| predict(s, Crossing::Same, r));
        let ahead = |v: i128| v > w + ns(LOWER_AHEAD_MS);
        if !ahead(record) && !floor.is_some_and(ahead) {
            return;
        }
        let new_record = record.min(w);
        let new_floor = floor.map(|f| f.min(w));
        self.record = Some(Stamp::at(new_record, r));
        if new_floor != floor
            && let Some(f) = new_floor
        {
            self.floor = Some(Stamp::at(f, r));
        }
        events.push(ClockEvent::LoweredAtSync {
            old: (to_ms(record), floor.map(to_ms)),
            new: (to_ms(new_record), new_floor.map(to_ms)),
        });
    }

    /// A wall clock more than 10 minutes below `H`: the alert, at most one an
    /// hour. Nothing is revived.
    fn went_back(&mut self, r: &OsReading, events: &mut Vec<ClockEvent>) {
        let h = self.h_ns(r);
        if ns(r.wall_ms) >= h - ns(WENT_BACK_MS) {
            return;
        }
        let h_ms = to_ms(h);
        if alert_due(self.last_went_back_alert_ms, h_ms) {
            events.push(ClockEvent::WentBack {
                wall_ms: r.wall_ms,
                h_ms,
            });
            self.last_went_back_alert_ms = Some(h_ms);
        }
    }

    fn note_ahead_alert(&mut self, origin: &str, h_ms: u64) {
        self.last_ahead_alert_ms.insert(origin.to_string(), h_ms);
        while self.last_ahead_alert_ms.len() > MAX_ORIGINS {
            let oldest = self
                .last_ahead_alert_ms
                .iter()
                .filter(|(o, _)| o.as_str() != origin)
                .min_by_key(|(_, at)| **at)
                .map(|(o, _)| o.clone());
            match oldest {
                Some(o) => self.last_ahead_alert_ms.remove(&o),
                None => break,
            };
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("the clock state serializes")
    }

    pub fn from_json(text: &str) -> Result<ClockState, serde_json::Error> {
        serde_json::from_str(text)
    }
}

fn note_guard(how: Crossing, events: &mut Vec<ClockEvent>) {
    if let Crossing::Bare(why) = how {
        let event = ClockEvent::Guarded(why);
        if !events.contains(&event) {
            events.push(event);
        }
    }
}

/// An owner alert is due when none was raised, an hour of `H` has passed
/// since the last, or `H` itself went back since (a repair, a lowering or a
/// guarded boot: the last alert's time is on a trajectory `H` left).
fn alert_due(last_ms: Option<u64>, h_ms: u64) -> bool {
    last_ms.is_none_or(|last| h_ms < last || h_ms - last >= ALERT_EVERY_MS)
}

/// The machine identity as 32 lowercase hex digits.
mod machine_hex {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(machine: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&atem_client::encoding::hex(machine))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let text = String::deserialize(d)?;
        atem_client::encoding::hex_decode_array(&text)
            .map_err(|_| D::Error::custom("machine: 32 lowercase hex digits"))
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;

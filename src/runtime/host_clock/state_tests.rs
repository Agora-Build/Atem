//! §11.6 "Clocks" on synthetic readings: every worked case and attack it walks
//! through, and its invariants after every step of every test (`check`).

use super::*;
use crate::runtime::host_clock::os::{UNKNOWN_BOOT_PREFIX, unknown_machine};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;

const MS: i128 = 1_000_000;
const SEC: i128 = 1_000 * MS;
const MIN: i128 = 60 * SEC;
const HOUR: i128 = 60 * MIN;
const DAY: i128 = 24 * HOUR;
/// The true time when a test starts (2027-01-15), in ns.
const T0: i128 = 1_800_000_000_000 * MS;
const M1: [u8; 16] = [0x11; 16];
const M2: [u8; 16] = [0x22; 16];
const ORIGIN: &str = "https://station-dev.agora.build";
const OTHER: &str = "https://station.agora.build";

/// 500 ppm of `dt`, rounded up: no update follows down more.
fn rho(dt: i128) -> i128 {
    (dt.max(0) * 500 + 999_999) / 1_000_000
}

fn count(events: &[ClockEvent], f: impl Fn(&ClockEvent) -> bool) -> usize {
    events.iter().filter(|e| f(e)).count()
}

fn armed(e: &ClockEvent) -> bool {
    matches!(e, ClockEvent::AnchorArmed)
}

fn dropped(e: &ClockEvent) -> bool {
    matches!(e, ClockEvent::AnchorDropped)
}

fn repaired(e: &ClockEvent) -> bool {
    matches!(e, ClockEvent::Repaired { .. })
}

fn lowered(e: &ClockEvent) -> bool {
    matches!(e, ClockEvent::LoweredAtSync { .. })
}

fn went_back(e: &ClockEvent) -> bool {
    matches!(e, ClockEvent::WentBack { .. })
}

fn ahead(e: &ClockEvent) -> bool {
    matches!(e, ClockEvent::StationAhead { .. })
}

fn guard(events: &[ClockEvent]) -> Option<GuardWhy> {
    events.iter().find_map(|e| match e {
        ClockEvent::Guarded(why) => Some(*why),
        _ => None,
    })
}

fn any_synced(rng: &mut StdRng) -> Synced {
    match rng.gen_range(0..3) {
        0 => Synced::Yes,
        1 => Synced::No,
        _ => Synced::Unknown,
    }
}

fn unsynced(rng: &mut StdRng) -> Synced {
    if rng.gen_bool(0.5) {
        Synced::No
    } else {
        Synced::Unknown
    }
}

/// What the invariants carry from one reading to the next.
#[derive(Debug, Default, Clone)]
struct Track {
    /// The counter at the previous reading.
    counter: i128,
    /// The record's trajectory from the boot's first reading (or its
    /// lowering), walked down by the follow-down alone: the record never ends
    /// below it, repairs included.
    low: i128,
    /// The highest reading carried forward on the counter: the record never
    /// ends above it.
    high: i128,
    /// The boots a lowering happened in.
    lowered: HashSet<String>,
}

/// §11.6's invariants for one reading: `old` observed `r` and became `new`
/// with `events`.
fn check(
    old: &ClockState,
    r: &OsReading,
    events: &[ClockEvent],
    new: &ClockState,
    track: &mut Track,
) {
    let w = ns(r.wall_ms);
    assert!(count(events, repaired) <= 1 && count(events, lowered) <= 1);
    let was_repaired = count(events, repaired) == 1;
    let was_lowered = count(events, lowered) == 1;
    let record = new.record.as_ref().expect("a reading leaves a record");

    // No comparison crosses a boot: every stamp is in this reading's boot.
    assert_eq!(crossing(record, r), Crossing::Same, "the record's boot");
    if let Some(floor) = &new.floor {
        assert_eq!(crossing(floor, r), Crossing::Same, "the floor's boot");
    }
    if let Some(anchor) = &new.anchor {
        for s in [
            Some(&anchor.record),
            anchor.floor.as_ref(),
            anchor.station.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            assert_eq!(crossing(s, r), Crossing::Same, "the anchor's boot");
        }
    }

    let now = predict(record, Crossing::Same, r);
    // The record never ends below the reading (an update takes at least it;
    // no repair or lowering goes below it).
    assert!(now >= w, "record {now} below the reading {w}");
    let floor_before = old.floor_ns(r);
    let floor_now = new.floor.as_ref().map(|f| predict(f, Crossing::Same, r));
    // H and D.
    assert_eq!(new.h_ns(r), now);
    assert_eq!(new.deadline_ns(r), floor_now.map_or(now, |f| f.max(now)));

    // The mark: set by a boot Atem knows is new, cleared by a synchronized
    // reading, and at most one lowering a boot.
    let new_boot = match &old.record {
        None => true,
        Some(o) => o.boot_id != r.boot_id && !unknown_boot(&o.boot_id) && !unknown_boot(&r.boot_id),
    };
    let spent = old.spent_boots.contains(&Boot::of(r));
    if r.synced == Synced::Yes {
        assert!(!new.mark, "a synchronized reading clears the mark");
    } else if new_boot && !spent {
        assert!(new.mark, "a new boot sets the mark");
    }
    if new.mark && !old.mark {
        assert!(
            new_boot && !spent,
            "only a new boot not yet spent sets the mark"
        );
    }
    // A boot's first synchronized reading with the mark spends its lowering;
    // in a boot already spent, a carried mark spends and lowers nothing.
    if r.synced == Synced::Yes && !spent && (old.mark || new_boot) {
        assert_eq!(new.spent_boots.last(), Some(&Boot::of(r)));
    }
    if spent {
        assert_eq!(new.spent_boots, old.spent_boots);
    }
    assert!(new.spent_boots.len() <= MAX_SPENT_BOOTS);
    let distinct: HashSet<&Boot> = new.spent_boots.iter().collect();
    assert_eq!(distinct.len(), new.spent_boots.len(), "a boot spent twice");
    if was_lowered {
        assert_eq!(
            r.synced,
            Synced::Yes,
            "a lowering needs a synchronized reading"
        );
        assert!(old.mark || new_boot, "a lowering needs the mark");
        assert!(!spent, "a lowering in a boot already spent");
        assert!(
            track.lowered.insert(r.boot_id.clone()),
            "a second lowering in boot {}",
            r.boot_id
        );
        assert_eq!(now, w, "a lowering puts the record on the wall clock");
        if let Some(f) = floor_now {
            assert!(f <= w, "and the floor at most on it");
            assert!(f >= floor_before.expect("a floor").min(w));
        }
    }

    match &old.record {
        Some(old_record) if crossing(old_record, r) == Crossing::Same => {
            let since = old_record.since(r);
            let p = predict(old_record, Crossing::Same, r);
            let dt = i128::from(r.boot_ns) - track.counter;
            assert!(dt >= 0, "the counter went back within a boot");
            track.low += dt - rho(dt);
            track.high = (track.high + dt).max(w);
            // The record only takes readings: never above one carried forward.
            assert!(
                now <= p.max(w),
                "record above the reading and the prediction"
            );
            assert!(
                now <= track.high,
                "record above every reading carried forward"
            );
            if was_lowered {
                track.low = now;
            } else {
                if !was_repaired {
                    assert!(
                        now >= p - rho(since),
                        "followed down {} ns over {since} ns",
                        p - now
                    );
                }
                assert!(
                    now >= track.low,
                    "record {} ns below its pre-jump trajectory",
                    track.low - now
                );
            }
            match (&old.anchor, &new.anchor) {
                (None, Some(a)) => {
                    assert!(w > p + ns(JUMP_MS), "an anchor without a jump");
                    assert_ne!(r.synced, Synced::Yes, "a synchronized jump makes no anchor");
                    assert_eq!(&a.record, old_record, "the anchor copies the record");
                    assert_eq!(a.floor, old.floor, "and the floor, as they stood");
                    assert!(a.station.is_none());
                    assert_eq!(count(events, armed), 1);
                }
                (Some(oa), Some(na)) => {
                    // The copies never change, so their predictions never
                    // decrease.
                    assert_eq!(oa, na);
                    assert_eq!(count(events, armed), 0);
                }
                (Some(oa), None) => {
                    let a = predict(&oa.record, Crossing::Same, r);
                    if was_repaired {
                        assert!((w - a).abs() <= ns(JUMP_MS), "a repair outside the band");
                    } else {
                        assert_eq!(r.synced, Synced::Yes, "only the OS's sync ends an anchor");
                        assert!((w - a).abs() > ns(JUMP_MS));
                        assert_eq!(count(events, dropped), 1);
                    }
                }
                (None, None) => assert!(!was_repaired),
            }
            if was_repaired {
                let oa = old.anchor.as_ref().expect("a repair needs an anchor");
                let a = predict(&oa.record, Crossing::Same, r);
                if !was_lowered {
                    if a <= p {
                        // Lowered to max(w, a): never below the anchor's
                        // record prediction or the reading.
                        assert_eq!(now, a.max(w), "a repair lands on max(w, a)");
                    } else {
                        // Nothing to lower: the update stands.
                        assert!(now >= (p - rho(since)).max(w) && now <= p.max(w));
                    }
                }
                if let (Some(before), Some(after)) = (floor_before, floor_now) {
                    let copies = [oa.floor.as_ref(), oa.station.as_ref()]
                        .into_iter()
                        .flatten()
                        .map(|s| predict(s, Crossing::Same, r))
                        .fold(w, i128::max);
                    if !was_lowered {
                        assert!(after <= before, "a repair raised the floor");
                        assert!(after >= before.min(copies), "the floor below its copy");
                    }
                }
                if !was_lowered {
                    let event = events.iter().find(|e| repaired(e)).expect("the event");
                    assert_eq!(
                        event,
                        &ClockEvent::Repaired {
                            old: (to_ms(w.max(p)), floor_before.map(to_ms)),
                            new: (to_ms(now), floor_now.map(to_ms)),
                        }
                    );
                    // It reads as what happened: nothing rises.
                    let ClockEvent::Repaired { old, new } = event else {
                        unreachable!()
                    };
                    assert!(new.0 <= old.0 && new.1 <= old.1);
                }
            } else if !was_lowered {
                assert_eq!(floor_now, floor_before, "a reading never moves the floor");
            }
        }
        Some(old_record) => {
            // A boot change: nothing compared across it.
            assert!(new.anchor.is_none(), "an anchor across a boot");
            assert_eq!(count(events, dropped), usize::from(old.anchor.is_some()));
            assert_eq!(count(events, armed), 0, "a boot's first reading is no jump");
            let carried = match guard(events) {
                Some(_) => old_record.value(),
                None => {
                    let carried = old_record.value() + i128::from(r.boot_ns);
                    // Decision 17 (b): only a record that predates the boot
                    // carries, so it stays within 60 s of the wall clock.
                    assert!(carried <= w + ns(BEFORE_BOOT_SLACK_MS));
                    carried
                }
            };
            if !was_lowered {
                assert_eq!(now, carried.max(w));
                assert_eq!(
                    floor_now, floor_before,
                    "the floor predicts across as before"
                );
            }
            track.low = now;
            track.high = now;
        }
        None => {
            assert_eq!(now, w, "the first reading ever is the wall clock");
            track.low = now;
            track.high = now;
        }
    }
    track.counter = i128::from(r.boot_ns);

    for e in events {
        if let ClockEvent::WentBack { wall_ms, h_ms } = e {
            assert_eq!(*wall_ms, r.wall_ms);
            assert_eq!(*h_ms, to_ms(now));
            assert!(w < now - ns(WENT_BACK_MS));
        }
    }
    // Persisted and read back unchanged.
    assert_eq!(
        &ClockState::from_json(&new.to_json()).expect("the state reads back"),
        new
    );
}

/// §11.6's invariants for a `station_time`: the reading as `observe` alone,
/// then the floor.
fn check_station(
    old: &ClockState,
    origin: &str,
    st_ms: u64,
    r: &OsReading,
    step: &StationStep,
    track: &mut Track,
) {
    let seen = old.observe(r);
    check(old, r, &seen.events, &seen.next, track);
    assert_eq!(step.events[..seen.events.len()], seen.events[..]);
    let extra = &step.events[seen.events.len()..];
    let mid = &seen.next;
    let new = &step.next;
    let h = mid.h_ns(r);
    let st = ns(st_ms);
    assert_eq!(step.within_cap, st <= h + ns(CAP_MS));
    // A Station time touches only the floor, the raise an anchor keeps and
    // the alerts of Station clocks ahead.
    assert_eq!(new.record, mid.record);
    assert_eq!(new.mark, mid.mark);
    assert_eq!(new.last_went_back_alert_ms, mid.last_went_back_alert_ms);
    assert_eq!(
        new.anchor.as_ref().map(|a| (&a.record, &a.floor)),
        mid.anchor.as_ref().map(|a| (&a.record, &a.floor))
    );
    let before = mid.floor.as_ref().map(|f| predict(f, Crossing::Same, r));
    let after = new.floor.as_ref().map(|f| predict(f, Crossing::Same, r));
    if !step.within_cap {
        assert_eq!(new.floor, mid.floor);
        assert_eq!(new.anchor, mid.anchor);
        assert!(extra.len() <= 1);
        for e in extra {
            assert_eq!(
                e,
                &ClockEvent::StationAhead {
                    origin: origin.to_string(),
                    station_time_ms: st_ms,
                    cap_ms: to_ms(h + ns(CAP_MS)),
                }
            );
        }
    } else {
        assert!(extra.is_empty());
        assert!(new.last_ahead_alert_ms == mid.last_ahead_alert_ms);
        match before {
            Some(f) if st <= f => {
                // A lower time: down by at most 500 ppm of the boot time since
                // the floor last changed, never below the time.
                let since = mid.floor.as_ref().expect("a floor").since(r);
                let after = after.expect("a floor");
                assert!(after <= f && after >= st && after >= f - rho(since));
                assert_eq!(new.anchor, mid.anchor);
            }
            _ => {
                // A raise: the floor takes it; a pending anchor keeps the one
                // with the highest prediction.
                assert_eq!(after, Some(st));
                if let (Some(ma), Some(na)) = (&mid.anchor, &new.anchor) {
                    let kept = predict(na.station.as_ref().expect("kept"), Crossing::Same, r);
                    let earlier = ma.station.as_ref().map(|s| predict(s, Crossing::Same, r));
                    assert_eq!(kept, earlier.map_or(st, |e| e.max(st)));
                }
            }
        }
    }
    assert_eq!(
        new.deadline_ns(r),
        after.map_or(new.h_ns(r), |f| f.max(new.h_ns(r)))
    );
    assert_eq!(
        &ClockState::from_json(&new.to_json()).expect("reads back"),
        new
    );
}

/// A host and its true time: readings made from both, every step checked.
struct Host {
    state: ClockState,
    boots: u32,
    boot_id: String,
    /// The boot-time counter, ns.
    counter: i128,
    /// The true time, ns since the epoch.
    truth: i128,
    /// The wall clock minus the true time.
    wall_off: i128,
    /// The counter's rate error against the true time.
    ppm: i128,
    machine: [u8; 16],
    timens: i64,
    synced: Synced,
    events: Vec<ClockEvent>,
    track: Track,
}

impl Host {
    /// A host up 30 s, its wall clock on the true time, no record yet.
    fn new(synced: Synced) -> Host {
        Host {
            state: ClockState::default(),
            boots: 0,
            boot_id: "boot-0".to_string(),
            counter: 30 * SEC,
            truth: T0,
            wall_off: 0,
            ppm: 0,
            machine: M1,
            timens: 0,
            synced,
            events: Vec::new(),
            track: Track::default(),
        }
    }

    fn wall(&self) -> i128 {
        self.truth + self.wall_off
    }

    fn reading(&self) -> OsReading {
        OsReading {
            wall_ms: to_ms(self.wall()),
            boot_ns: u64::try_from(self.counter).expect("a counter"),
            boot_id: self.boot_id.clone(),
            machine: self.machine,
            timens_boot_ns: self.timens,
            synced: self.synced,
        }
    }

    fn observe(&mut self) -> Vec<ClockEvent> {
        let r = self.reading();
        let step = self.state.observe(&r);
        check(&self.state, &r, &step.events, &step.next, &mut self.track);
        self.state = step.next;
        self.events.extend(step.events.iter().cloned());
        step.events
    }

    /// A `station_time` (ns); whether it was within the cap.
    fn station(&mut self, origin: &str, st: i128) -> bool {
        let r = self.reading();
        let st_ms = to_ms(st);
        let step = self.state.station(origin, st_ms, &r);
        check_station(&self.state, origin, st_ms, &r, &step, &mut self.track);
        self.state = step.next;
        self.events.extend(step.events);
        step.within_cap
    }

    fn advance(&mut self, dt: i128) {
        self.truth += dt;
        self.counter += dt + dt * self.ppm / 1_000_000;
    }

    /// Readings every `every` for `span`.
    fn run(&mut self, span: i128, every: i128) {
        let mut left = span;
        while left > 0 {
            let dt = every.min(left);
            self.advance(dt);
            self.observe();
            left -= dt;
        }
    }

    fn set_wall(&mut self, wall: i128) {
        self.wall_off = wall - self.truth;
    }

    /// Off for `down`, then up `uptime` before the next reading. The wall
    /// clock keeps its offset (an RTC).
    fn reboot(&mut self, down: i128, uptime: i128) {
        self.boots += 1;
        self.boot_id = format!("boot-{}", self.boots);
        self.truth += down + uptime;
        self.counter = uptime;
    }

    /// The store opened on another node, up `uptime`, `gap` after the last
    /// reading here.
    fn move_to(&mut self, machine: [u8; 16], boot_id: &str, uptime: i128, gap: i128) {
        self.machine = machine;
        self.boot_id = boot_id.to_string();
        self.truth += gap;
        self.counter = uptime;
    }

    /// A runtime restart within the boot: the state as it was persisted.
    fn restart(&mut self) {
        self.state = ClockState::from_json(&self.state.to_json()).expect("reads back");
    }

    fn h(&self) -> i128 {
        self.state.h_ns(&self.reading())
    }

    fn d(&self) -> i128 {
        self.state.deadline_ns(&self.reading())
    }

    /// The record's prediction now.
    fn record(&self) -> i128 {
        let r = self.reading();
        let record = self.state.record.as_ref().expect("a record");
        predict(record, crossing(record, &r), &r)
    }

    fn floor(&self) -> Option<i128> {
        self.state.floor_ns(&self.reading())
    }

    /// The pending anchor's record prediction now.
    fn anchor(&self) -> Option<i128> {
        let r = self.reading();
        self.state
            .anchor
            .as_ref()
            .map(|a| predict(&a.record, Crossing::Same, &r))
    }

    fn seen(&self, f: impl Fn(&ClockEvent) -> bool) -> usize {
        count(&self.events, f)
    }
}

/// A host past its boot's first synchronized reading, with readings for
/// `minutes` minutes.
fn settled_host(minutes: i128) -> Host {
    let mut host = Host::new(Synced::Yes);
    host.observe();
    assert!(!host.state.mark());
    host.run(minutes * MIN, MIN);
    host
}

#[test]
fn healthy_mac_20ppm_lead_stays_within_1_2ms() {
    // A Mac whose counter runs 20 ppm fast against `timed`'s wall clock:
    // each minute the prediction gains 1.2 ms, and the follow-down allows
    // 30 ms, so every update brings the record back onto the wall clock.
    let mut host = Host::new(Synced::Unknown);
    host.ppm = 20;
    host.observe();
    for _ in 0..30 * 24 * 60 {
        host.advance(MIN);
        let lead = host.h() - host.wall();
        assert!(lead <= 1_200_000, "a lead of {lead} ns");
        host.observe();
        assert_eq!(host.h(), host.wall(), "back on the wall clock");
    }
    assert_eq!(host.seen(went_back), 0, "never the alert");
}

#[test]
fn follow_down_walks_back_at_most_500ppm() {
    // Any fall of the wall clock against the counter is followed down at most
    // 500 ppm of the boot time since the previous update, however readings
    // are spaced.
    let mut rng = StdRng::seed_from_u64(1);
    let mut host = settled_host(1);
    host.wall_off = -30 * DAY;
    for _ in 0..2_000 {
        let dt = rng.gen_range(SEC..=HOUR);
        host.advance(dt);
        let p = host.h();
        host.observe();
        let fell = p - host.record();
        assert!(fell <= rho(dt), "fell {fell} ns over {dt} ns");
        // Short of 500 ppm by the margin of a stamp's millisecond at most.
        assert!(fell >= rho(dt) - rho(MS) - 1, "fell {fell} ns over {dt} ns");
    }

    // A day at one reading a minute: 43.2 s.
    let mut host = settled_host(1);
    host.wall_off = -HOUR;
    let (start, t) = (host.record(), host.truth);
    host.run(DAY, MIN);
    let walked = start + (host.truth - t) - host.record();
    assert!((43_199 * MS..=43_200 * MS).contains(&walked), "{walked}");

    // An hour at one reading a second: 1.8 s, the stamps' sub-millisecond
    // values kept (no rounding at each update).
    let mut host = settled_host(1);
    host.wall_off = -HOUR;
    let (start, t) = (host.record(), host.truth);
    host.run(HOUR, SEC);
    let walked = start + (host.truth - t) - host.record();
    assert!((1_798 * MS..=1_800 * MS).contains(&walked), "{walked}");
}

#[test]
fn small_steps_back_attack_ends_within_the_follow_down() {
    // §11.6, worked through: back 50 s a minute for 30 minutes, to T, T + 2
    // min (a jump), then T or T − 25 min. Here with random step sizes,
    // lengths and choices.
    for seed in 0..40 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(rng.gen_range(1..=60));
        let t0 = host.truth;
        let walked = |host: &Host| rho(host.truth - t0);
        // 1. Back `step` a minute.
        let step = if seed == 0 {
            50 * SEC
        } else {
            rng.gen_range(1..=59) * SEC
        };
        let minutes = if seed == 0 { 30 } else { rng.gen_range(5..=60) };
        host.synced = any_synced(&mut rng);
        for _ in 0..minutes {
            host.advance(MIN);
            host.wall_off -= step;
            host.observe();
            assert!(host.record() >= host.truth - walked(&host));
            assert!(host.record() <= host.truth);
        }
        assert_eq!(host.seen(armed), 0, "no reading ahead of the prediction");
        if step * minutes > 11 * MIN {
            assert!(host.seen(went_back) >= 1, "past 10 minutes, the alert");
        }
        // 2. To T: no jump, the record takes it.
        let skip_2 = rng.gen_bool(0.5);
        if !skip_2 {
            host.advance(MIN);
            host.wall_off = 0;
            host.observe();
            assert_eq!(host.record(), host.truth);
        }
        // 3. T + 2 min, unsynchronized: anchored on the record's trajectory.
        host.advance(MIN);
        host.synced = unsynced(&mut rng);
        host.wall_off = 2 * MIN;
        assert_eq!(count(&host.observe(), armed), 1);
        assert_eq!(host.record(), host.truth + 2 * MIN);
        host.run(rng.gen_range(1..=30) * MIN, MIN);
        // 4. Back to T: repaired. Or to T − 25 min: no repair.
        host.advance(MIN);
        if rng.gen_bool(0.5) {
            host.wall_off = 0;
            host.synced = any_synced(&mut rng);
            assert_eq!(count(&host.observe(), repaired), 1);
            assert!(host.record() <= host.truth);
            if !skip_2 {
                assert_eq!(host.record(), host.truth);
            }
        } else {
            let p = host.h();
            host.wall_off = -25 * MIN;
            assert_eq!(count(&host.observe(), repaired), 0);
            assert!(host.state.anchor.is_some());
            assert!(host.record() >= p - rho(MIN));
            assert!(host.h() - host.wall() > ns(WENT_BACK_MS));
        }
        // Either way, nothing ends more than the follow-down below T.
        assert!(host.record() >= host.truth - walked(&host));
        assert!(host.d() >= host.truth - walked(&host));
    }
}

#[test]
fn jump_undone_within_60s_repairs_to_the_anchor() {
    for seed in 0..40 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(1);
        if rng.gen_bool(0.5) {
            let st = host.truth - rng.gen_range(0..=5 * 60_000) * MS;
            assert!(host.station(ORIGIN, st));
        }
        host.run(rng.gen_range(1..=120) * MIN, MIN);
        // A forward jump the OS doesn't report synchronized.
        host.advance(MIN);
        host.synced = unsynced(&mut rng);
        host.wall_off += rng.gen_range(60_001..=30 * 86_400_000) * MS;
        assert_eq!(count(&host.observe(), armed), 1);
        assert_eq!(host.record(), host.wall(), "the record takes the jump");
        host.run(rng.gen_range(1..=2 * 24 * 60) * MIN, 10 * MIN);
        // Undone within 60 s of the anchor's record prediction.
        host.advance(MIN);
        let a = host.anchor().expect("pending");
        assert_eq!(
            a, host.truth,
            "the record's trajectory from before the jump"
        );
        let off = rng.gen_range(-60_000..=60_000) * MS;
        host.set_wall(a + off);
        host.synced = any_synced(&mut rng);
        let floor = host.floor();
        assert_eq!(count(&host.observe(), repaired), 1);
        assert_eq!(host.record(), (a + off).max(a));
        assert!(host.state.anchor.is_none());
        assert_eq!(host.floor(), floor, "the floor took no jumped reading");
    }
}

#[test]
fn undo_more_than_60s_below_the_anchor_is_no_repair() {
    for seed in 0..40 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(5);
        host.advance(MIN);
        host.synced = unsynced(&mut rng);
        let jump = rng.gen_range(60_001..=3 * 86_400_000) * MS;
        host.wall_off += jump;
        assert_eq!(count(&host.observe(), armed), 1);
        host.run(rng.gen_range(1..=600) * MIN, 10 * MIN);
        host.advance(MIN);
        let a = host.anchor().expect("pending");
        let p = host.h();
        // More than 60 s below it (a clock set back), or above it.
        let off = if rng.gen_bool(0.7) {
            -(60_000 + rng.gen_range(1..=10 * 86_400_000)) * MS
        } else {
            (60_000 + rng.gen_range(1..=86_400_000)) * MS
        };
        host.set_wall(a + off);
        let events = host.observe();
        assert_eq!(count(&events, repaired), 0);
        assert!(host.state.anchor.is_some(), "the anchor stays");
        assert!(host.record() >= p - rho(MIN));
        if off < 0 && p - host.wall() > 11 * MIN && host.seen(went_back) == 1 {
            assert_eq!(count(&events, went_back), 1, "the alert, and no repair");
        }
    }
}

#[test]
fn synchronized_jump_makes_no_anchor_and_drops_a_pending_one() {
    // The OS's own step, reported synchronized with the jumped reading: no
    // anchor, and the jump stands.
    let mut host = settled_host(10);
    host.advance(MIN);
    host.wall_off += 2 * HOUR;
    let events = host.observe();
    assert_eq!(count(&events, armed), 0);
    assert_eq!(host.record(), host.wall());
    host.advance(MIN);
    host.wall_off = 0;
    host.synced = Synced::No;
    assert_eq!(count(&host.observe(), repaired), 0, "nothing to repair");
    assert!(host.record() >= host.truth + 2 * HOUR - rho(MIN));

    // A pending anchor, then the OS's report at a reading outside its band:
    // dropped.
    let mut host = settled_host(10);
    host.synced = Synced::No;
    host.advance(MIN);
    host.wall_off += 2 * HOUR;
    assert_eq!(count(&host.observe(), armed), 1);
    host.run(5 * MIN, MIN);
    host.advance(MIN);
    host.synced = Synced::Yes;
    let events = host.observe();
    assert_eq!(count(&events, dropped), 1);
    assert_eq!(count(&events, repaired), 0);
    assert!(host.state.anchor.is_none());
    assert_eq!(host.record(), host.truth + 2 * HOUR);
    host.advance(MIN);
    host.synced = Synced::No;
    host.wall_off = 0;
    assert_eq!(count(&host.observe(), repaired), 0, "the jump stands");

    // A synchronized jump while one is pending drops it and makes none.
    let mut host = settled_host(10);
    host.synced = Synced::Unknown;
    host.advance(MIN);
    host.wall_off += HOUR;
    assert_eq!(count(&host.observe(), armed), 1);
    host.advance(MIN);
    host.synced = Synced::Yes;
    host.wall_off += HOUR;
    let events = host.observe();
    assert_eq!((count(&events, dropped), count(&events, armed)), (1, 0));
}

#[test]
fn os_forward_step_then_set_back_leaves_no_stale_anchor() {
    // §11.6, worked through: a Linux host booted three hours slow (no RTC).
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = Host::new(Synced::No);
        host.wall_off = -3 * HOUR;
        host.observe();
        host.run(rng.gen_range(1..=30) * MIN, MIN);
        // 1. The daemon's first sync steps forward three hours; the kernel
        // marks the clock unsynchronized at the step: an anchor on S.
        host.advance(MIN);
        host.wall_off = 0;
        assert_eq!(count(&host.observe(), armed), 1);
        // 2. Its next report clears the mark: at Atem's next reading, outside
        // the band and synchronized, the anchor is dropped.
        host.advance(rng.gen_range(1..=120) * SEC);
        host.synced = Synced::Yes;
        assert_eq!(count(&host.observe(), dropped), 1);
        assert_eq!(host.record(), host.truth);
        let settled = host.truth;
        // 3. Set back toward S, or slewed down through S's band.
        host.synced = if rng.gen_bool(0.5) {
            Synced::Yes
        } else {
            Synced::No
        };
        if rng.gen_bool(0.5) {
            host.advance(MIN);
            let to = host.truth - 3 * HOUR + rng.gen_range(-60_000..=60_000) * MS;
            host.set_wall(to);
            host.observe();
        } else {
            while host.wall_off > -3 * HOUR - 2 * MIN {
                host.advance(MIN);
                host.wall_off -= rng.gen_range(1..=59) * SEC;
                host.observe();
                assert!(host.record() >= host.truth - rho(host.truth - settled));
            }
        }
        host.run(rng.gen_range(1..=48) * HOUR, 10 * MIN);
        assert_eq!(host.seen(repaired), 0, "no stale anchor to repair to S");
        assert!(host.record() >= host.truth - rho(host.truth - settled));
        assert!(host.seen(went_back) >= 1);
    }
}

#[test]
fn station_raise_kept_with_the_anchor_survives_the_repair() {
    let mut host = settled_host(1);
    assert!(host.station(ORIGIN, host.truth + 5 * MIN));
    host.run(10 * MIN, MIN);
    host.synced = Synced::No;
    host.advance(MIN);
    host.wall_off += 2 * HOUR;
    assert_eq!(count(&host.observe(), armed), 1);
    // Two raises while the anchor is pending, the second one only the jumped
    // H's wider cap lets in: the anchor keeps the higher.
    host.advance(MIN);
    assert!(host.station(ORIGIN, host.truth + 2 * HOUR + 3 * MIN));
    host.advance(MIN);
    assert!(host.station(ORIGIN, host.truth + 2 * HOUR + 9 * MIN));
    host.advance(MIN);
    assert!(host.station(ORIGIN, host.truth + 2 * HOUR + 4 * MIN));
    host.run(30 * MIN, MIN);
    host.advance(MIN);
    let r = host.reading();
    let anchor = host.state.anchor.clone().expect("pending");
    let kept = predict(anchor.station.as_ref().expect("kept"), Crossing::Same, &r);
    let copy = predict(anchor.floor.as_ref().expect("copied"), Crossing::Same, &r);
    assert_eq!(copy, host.truth + 5 * MIN);
    let floor = host.floor().expect("a floor");
    assert!(floor <= kept && floor >= kept - rho(HOUR));
    host.set_wall(host.anchor().expect("pending"));
    assert_eq!(count(&host.observe(), repaired), 1);
    assert_eq!(host.record(), host.truth);
    // The repair never undoes the Station's own lead: the floor stays.
    assert_eq!(host.floor(), Some(floor));
    assert!(host.floor().expect("a floor") > host.truth + 2 * HOUR);
    assert_eq!(host.d(), floor);
}

#[test]
fn first_reading_of_a_boot_is_no_jump() {
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(10);
        let x = host.record();
        let down = rng.gen_range(1..=365 * 24 * 60) * MIN;
        let uptime = rng.gen_range(1..=3 * 86_400) * SEC;
        host.reboot(down, uptime);
        host.synced = unsynced(&mut rng);
        let events = host.observe();
        assert_eq!(count(&events, armed), 0, "no jump, no anchor");
        assert_eq!(host.record(), host.wall().max(x + uptime));
        // The boot's later readings are compared within it.
        host.advance(MIN);
        host.wall_off += 2 * MIN;
        assert_eq!(count(&host.observe(), armed), 1);
        // A runtime restarted within the boot is the same boot: the anchor
        // stays and is repaired.
        host.restart();
        host.advance(MIN);
        host.set_wall(host.anchor().expect("kept over the restart"));
        assert_eq!(count(&host.observe(), repaired), 1);
    }
}

#[test]
fn mac_reboot_three_days_then_step_back_is_no_repair() {
    // §11.6, worked through (and here with random downtimes and targets): a
    // Mac shuts down at X, stays off, boots, and later someone steps the
    // clock back to X + 30 s.
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = Host::new(Synced::Unknown);
        host.observe();
        host.run(rng.gen_range(1..=600) * MIN, MIN);
        let x = host.record();
        let down = if seed == 0 {
            3 * DAY
        } else {
            rng.gen_range(1..=365 * 24) * HOUR
        };
        host.reboot(down, rng.gen_range(10..=600) * SEC);
        let events = host.observe();
        assert_eq!(count(&events, armed), 0);
        assert_eq!(host.record(), host.truth, "max(X + 3 days, X + boot time)");
        let first = host.truth;
        host.run(rng.gen_range(1..=24 * 60) * MIN, 10 * MIN);
        host.advance(MIN);
        host.set_wall(x + 30 * SEC);
        host.observe();
        host.run(rng.gen_range(1..=72) * HOUR, 10 * MIN);
        assert_eq!(host.seen(repaired), 0, "nothing is repaired");
        // H stays within 43.2 s a day of the true time.
        assert!(host.h() >= host.truth - rho(host.truth - first));
        assert!(host.seen(went_back) >= 1);
    }
}

#[test]
fn reboot_lowering_happens_once_at_the_first_synchronized_reading() {
    let mut host = settled_host(30);
    assert!(host.station(ORIGIN, host.truth));
    host.run(10 * MIN, MIN);
    // The clock booted an hour ahead, unsynchronized: taken, with the mark.
    host.reboot(5 * MIN, 20 * SEC);
    host.wall_off = HOUR;
    host.synced = Synced::No;
    host.observe();
    assert!(host.state.mark());
    assert_eq!(host.record(), host.wall());
    host.run(20 * MIN, MIN);
    // The daemon steps it back; the kernel marks it unsynchronized.
    host.advance(MIN);
    host.wall_off = 0;
    assert_eq!(count(&host.observe(), lowered), 0);
    assert!(host.record() > host.truth + 59 * MIN);
    // Its next report: the boot's first synchronized reading lowers both.
    host.advance(10 * SEC);
    host.synced = Synced::Yes;
    let before = (host.record(), host.floor());
    let events = host.observe();
    // The old values are wall_hw and the floor just before the lowering: the
    // record after this reading's update (followed down over 10 s).
    let followed = before.0 - follow_down(10 * SEC);
    assert_eq!(
        events.iter().find(|e| lowered(e)),
        Some(&ClockEvent::LoweredAtSync {
            old: (to_ms(followed), before.1.map(to_ms)),
            new: (
                to_ms(host.wall()),
                before.1.map(|f| to_ms(f.min(host.wall())))
            ),
        })
    );
    assert_eq!(host.h(), host.truth);
    assert!(!host.state.mark());
    // Once: a later step back, synchronized, is followed down only.
    let settled = host.truth;
    host.advance(MIN);
    host.wall_off = -HOUR;
    host.run(3 * HOUR, MIN);
    assert_eq!(host.seen(lowered), 1);
    assert!(host.record() >= host.truth - rho(host.truth - settled));
    assert!(host.seen(went_back) >= 3);

    // A boot's first reading that is also its first synchronized one: the
    // record and the lowering are one evaluation, before any comparison.
    host.reboot(5 * MIN, 20 * SEC);
    let events = host.observe();
    assert_eq!(guard(&events), Some(GuardWhy::NotBeforeThisBoot));
    assert_eq!(count(&events, lowered), 1);
    assert_eq!(count(&events, went_back), 0, "a lowering raises no alert");
    assert_eq!(host.h(), host.wall());
    assert_eq!(host.seen(lowered), 2);
}

#[test]
fn reboot_mark_persists_until_synchronized() {
    let mut host = settled_host(60);
    host.reboot(10 * MIN, 30 * SEC);
    host.synced = Synced::No;
    host.observe();
    assert!(host.state.mark());
    for i in 0..100 {
        host.synced = if i % 2 == 0 {
            Synced::No
        } else {
            Synced::Unknown
        };
        host.advance(MIN);
        host.observe();
        if i % 10 == 0 {
            host.restart();
        }
        assert!(host.state.mark());
        assert!(host.state.to_json().contains("\"mark\":true"));
    }
    host.advance(MIN);
    host.wall_off = -HOUR;
    host.observe();
    assert!(host.state.mark(), "a set-back doesn't clear it");
    host.advance(MIN);
    host.synced = Synced::Yes;
    assert_eq!(count(&host.observe(), lowered), 1);
    assert!(!host.state.mark());
    host.restart();
    host.synced = Synced::No;
    host.advance(MIN);
    host.observe();
    assert!(!host.state.mark(), "a restart in the boot is no reboot");
}

#[test]
fn unknown_sync_never_lowers_across_a_reboot() {
    // macOS until its report is confirmed.
    let mut host = Host::new(Synced::Unknown);
    host.observe();
    host.run(HOUR, MIN);
    host.wall_off = -HOUR;
    host.run(HOUR, MIN);
    host.reboot(10 * MIN, 30 * SEC);
    let events = host.observe();
    assert_eq!(guard(&events), Some(GuardWhy::NotBeforeThisBoot));
    assert!(host.record() > host.wall() + 10 * MIN);
    let first = (host.truth, host.record());
    host.run(3 * DAY, 10 * MIN);
    assert_eq!(host.seen(lowered), 0);
    assert!(host.state.mark());
    assert!(host.record() >= first.1 + (host.truth - first.0) - rho(host.truth - first.0));
}

#[test]
fn moved_profile_on_another_machine_predicts_bare_values() {
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(1);
        assert!(host.station(ORIGIN, host.truth));
        host.run(rng.gen_range(1..=600) * MIN, MIN);
        let x = host.record();
        let floor_value = ns(host.state.floor.as_ref().expect("a floor").value_ms);
        let uptime = rng.gen_range(60..=30 * 86_400) * SEC;
        host.synced = unsynced(&mut rng);
        host.move_to(M2, "node-b", uptime, rng.gen_range(0..=600) * SEC);
        let events = host.observe();
        assert_eq!(guard(&events), Some(GuardWhy::OtherMachine));
        assert_eq!(
            host.record(),
            host.wall().max(x),
            "not X + this node's uptime"
        );
        assert_eq!(host.floor(), Some(floor_value));
        assert!(
            host.h() <= host.truth && host.d() <= host.truth,
            "never ahead"
        );
        assert!(host.state.mark(), "another node's boot is a new boot");
    }
}

#[test]
fn baked_machine_id_record_not_before_this_boot_predicts_bare_values() {
    // One /etc/machine-id baked into every node: the store opens on a node
    // that booted before the record was made.
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(rng.gen_range(1..=600));
        let x = host.record();
        let uptime = rng.gen_range(122..=30 * 86_400) * SEC;
        let gap = rng.gen_range(0..=(uptime / SEC - 61)) * SEC;
        host.move_to(M1, "node-b", uptime, gap);
        let events = host.observe();
        assert_eq!(guard(&events), Some(GuardWhy::NotBeforeThisBoot));
        assert_eq!(host.record(), host.wall().max(x));
        assert!(host.h() <= host.truth);
    }
    // At the boundary (the record 60 s after the boot's start on the wall
    // clock) it still carries, at most 60 s ahead of the wall clock.
    let mut host = settled_host(10);
    let x = host.record();
    host.move_to(M1, "node-b", 10 * MIN, 9 * MIN);
    let events = host.observe();
    assert_eq!(guard(&events), None);
    assert_eq!(host.record(), x + 10 * MIN);
    assert_eq!(host.record(), host.wall() + MIN);
}

#[test]
fn boottime_namespace_offset_predicts_bare_values() {
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(rng.gen_range(1..=600));
        let x = host.record();
        let uptime = rng.gen_range(60..=30 * 86_400) * SEC;
        host.reboot(rng.gen_range(0..=86_400) * SEC, uptime);
        // The counter reads this boot's boot time plus the offset.
        let offset = if rng.gen_bool(0.5) {
            rng.gen_range(1..=30 * 86_400) * SEC
        } else {
            -rng.gen_range(1..uptime / SEC) * SEC
        };
        host.timens = i64::try_from(offset).expect("an offset");
        host.counter += offset;
        let events = host.observe();
        assert_eq!(guard(&events), Some(GuardWhy::TimeNamespace));
        assert_eq!(host.record(), host.wall().max(x));
        assert!(host.h() <= host.truth);
    }
}

#[test]
fn namespace_offset_change_within_a_boot_is_a_new_boot() {
    // A CRIU restore in the same boot: the counter is made to go on from the
    // checkpoint through a time-namespace offset.
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(rng.gen_range(1..=600));
        let anchored = rng.gen_bool(0.5);
        if anchored {
            host.synced = Synced::No;
            host.advance(MIN);
            host.wall_off += 2 * HOUR;
            assert_eq!(count(&host.observe(), armed), 1);
        }
        let mark = host.state.mark();
        let value = ns(host.state.record.as_ref().expect("a record").value_ms);
        let pause = rng.gen_range(1..=2 * 86_400) * SEC;
        host.truth += pause;
        host.counter += rng.gen_range(0..=SEC);
        host.timens = -i64::try_from(pause).expect("an offset");
        host.restart();
        let events = host.observe();
        assert_eq!(guard(&events), Some(GuardWhy::NamespaceChanged));
        assert_eq!(count(&events, dropped), usize::from(anchored));
        assert_eq!(host.record(), host.wall().max(value), "Δ = 0");
        assert_eq!(host.state.mark(), mark, "the same kernel boot");
        assert!(host.h() <= host.wall().max(host.truth));
        // Its later readings are compared within the new namespace.
        host.synced = Synced::No;
        host.advance(MIN);
        host.wall_off += HOUR;
        assert_eq!(count(&host.observe(), armed), 1);
    }
}

#[test]
fn went_back_past_10_minutes_alerts_at_most_hourly() {
    let mut host = settled_host(60);
    let h = host.h();
    // Exactly 10 minutes below H: no alert ("more than").
    host.set_wall(h - 10 * MIN);
    assert_eq!(count(&host.observe(), went_back), 0);
    host.set_wall(h - 10 * MIN - MS);
    assert_eq!(
        host.observe(),
        vec![ClockEvent::WentBack {
            wall_ms: to_ms(h - 10 * MIN - MS),
            h_ms: to_ms(h),
        }]
    );
    // Still behind for five hours: at most one an hour, on H.
    host.advance(MIN);
    host.wall_off = -HOUR;
    host.run(5 * HOUR, MIN);
    let alerts: Vec<u64> = host
        .events
        .iter()
        .filter_map(|e| match e {
            ClockEvent::WentBack { h_ms, .. } => Some(*h_ms),
            _ => None,
        })
        .collect();
    assert_eq!(alerts.len(), 5, "{alerts:?}");
    for pair in alerts.windows(2) {
        assert!((ALERT_EVERY_MS..ALERT_EVERY_MS + 60_000).contains(&(pair[1] - pair[0])));
    }
}

#[test]
fn station_time_within_the_cap_raises_the_floor() {
    let mut host = settled_host(1);
    assert!(host.station(ORIGIN, host.h() + 2 * MIN));
    assert_eq!(host.floor(), Some(host.truth + 2 * MIN));
    host.advance(5 * MIN);
    assert_eq!(
        host.floor(),
        Some(host.truth + 2 * MIN),
        "plus the boot time since"
    );
    // Up to H + 10 minutes exactly.
    let h = host.h();
    assert!(host.station(ORIGIN, h + 10 * MIN));
    assert_eq!(host.floor(), Some(h + 10 * MIN));
    assert_eq!(host.d(), h + 10 * MIN);
    host.run(HOUR, MIN);
    assert_eq!(host.d(), host.truth + 10 * MIN);
}

#[test]
fn station_time_beyond_the_cap_leaves_the_floor_and_alerts_hourly() {
    let mut host = settled_host(1);
    assert!(host.station(ORIGIN, host.truth));
    let floor = host.floor();
    let h = host.h();
    assert!(!host.station(ORIGIN, h + 10 * MIN + MS));
    assert_eq!(host.floor(), floor);
    assert_eq!(
        host.events.last(),
        Some(&ClockEvent::StationAhead {
            origin: ORIGIN.to_string(),
            station_time_ms: to_ms(h + 10 * MIN + MS),
            cap_ms: to_ms(h + 10 * MIN),
        })
    );
    // Within the hour: no second alert for the origin.
    host.advance(30 * MIN);
    assert!(!host.station(ORIGIN, host.h() + 11 * MIN));
    assert_eq!(host.seen(ahead), 1);
    // Another origin has its own.
    assert!(!host.station(OTHER, host.h() + 11 * MIN));
    assert_eq!(host.seen(ahead), 2);
    // An hour on, the alert again.
    host.advance(31 * MIN);
    assert!(!host.station(ORIGIN, host.h() + 11 * MIN));
    assert_eq!(host.seen(ahead), 3);
    // A head within the cap is taken again (the gate is the caller's).
    assert!(host.station(ORIGIN, host.h() + 5 * MIN));
    assert_eq!(host.floor(), Some(host.truth + 5 * MIN));
}

#[test]
fn nine_minute_heads_dont_walk_the_floor() {
    // A Station whose heads ride 9 minutes ahead of this host's deadline
    // clock: the cap is on H, which never includes station_time.
    let mut host = settled_host(1);
    for i in 0..1_000 {
        host.advance(30 * SEC);
        let st = if i % 2 == 0 { host.d() } else { host.h() } + 9 * MIN;
        host.station(ORIGIN, st);
        assert!(host.floor().expect("a floor") <= host.h() + 10 * MIN);
        assert!(host.d() <= host.truth + 9 * MIN);
    }
}

#[test]
fn floor_follows_a_lower_station_time_down_at_500ppm() {
    let mut host = settled_host(1);
    assert!(host.station(ORIGIN, host.truth + 5 * MIN));
    let (start, t) = (host.floor().expect("a floor"), host.truth);
    // The Station's clock steps back an hour: a head a minute for a day.
    for _ in 0..24 * 60 {
        host.advance(MIN);
        assert!(host.station(ORIGIN, host.truth - HOUR));
        let walked = start + (host.truth - t) - host.floor().expect("a floor");
        assert!(walked <= rho(host.truth - t));
    }
    let walked = start + (host.truth - t) - host.floor().expect("a floor");
    assert!((43_199 * MS..=43_200 * MS).contains(&walked), "{walked}");
    assert!(host.d() >= host.h());
}

#[test]
fn deadline_clock_is_max_of_h_and_floor_plus_elapsed_within_a_boot() {
    let mut host = settled_host(1);
    assert!(host.station(ORIGIN, host.h() + 7 * MIN));
    let (floor, t) = (host.floor().expect("a floor"), host.truth);
    host.run(2 * HOUR, MIN);
    assert_eq!(
        host.d(),
        floor + (host.truth - t),
        "the floor plus the boot time since"
    );
    assert_eq!(host.h(), host.truth);
    // The wall clock set back: H holds, and D with it.
    host.advance(MIN);
    host.wall_off = -HOUR;
    host.observe();
    assert_eq!(host.d(), floor + (host.truth - t));
    // Jumped past the floor: D is H.
    host.advance(MIN);
    host.wall_off = HOUR;
    host.synced = Synced::No;
    host.observe();
    assert_eq!(host.d(), host.h());
    assert!(host.h() > host.floor().expect("a floor"));

    // After a reboot: the floor plus this boot's boot time so far, before and
    // after the boot's first reading.
    let mut host = settled_host(30);
    assert!(host.station(ORIGIN, host.h() + 10 * MIN));
    let value = ns(host.state.floor.as_ref().expect("a floor").value_ms);
    host.reboot(2 * MIN, 40 * SEC);
    assert_eq!(host.d(), value + 40 * SEC);
    host.observe();
    assert_eq!(host.d(), value + 40 * SEC);
    host.run(HOUR, MIN);
    assert_eq!(host.d(), value + 40 * SEC + HOUR);
    // A guarded boot: the floor's bare value.
    let value = ns(host.state.floor.as_ref().expect("a floor").value_ms);
    host.move_to(M2, "node-b", 3 * DAY, 0);
    assert_eq!(host.floor(), Some(value));
    host.observe();
    assert_eq!(host.floor(), Some(value));
}

#[test]
fn no_repair_or_lowering_goes_below_the_wall_clock() {
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        // A repair whose reading is above the anchor takes the reading.
        let mut host = settled_host(5);
        host.synced = unsynced(&mut rng);
        host.advance(MIN);
        host.wall_off += rng.gen_range(61..=86_400) * SEC;
        host.observe();
        host.run(rng.gen_range(1..=600) * MIN, 10 * MIN);
        host.advance(MIN);
        let a = host.anchor().expect("pending");
        host.set_wall(a + rng.gen_range(0..=60_000) * MS);
        assert_eq!(count(&host.observe(), repaired), 1);
        assert_eq!(host.record(), host.wall());

        // A repair after the record walked below the anchor's trajectory:
        // lowered, never raised to the anchor, never below the reading.
        let mut host = settled_host(5);
        host.synced = Synced::No;
        host.advance(MIN);
        host.wall_off = 2 * MIN;
        host.observe();
        host.advance(MIN);
        host.wall_off = -30 * MIN;
        host.observe();
        host.run(5 * DAY, 10 * MIN);
        host.advance(MIN);
        let a = host.anchor().expect("still pending");
        assert!(host.h() < a - MIN);
        host.set_wall(a + rng.gen_range(-59_000..=59_000) * MS);
        assert_eq!(count(&host.observe(), repaired), 1);
        assert_eq!(host.record(), host.wall());

        // A lowering: onto the wall clock exactly; a floor below it stays.
        let mut host = settled_host(5);
        assert!(host.station(ORIGIN, host.truth - HOUR));
        host.wall_off = -2 * HOUR;
        host.run(HOUR, MIN);
        host.reboot(5 * MIN, 30 * SEC);
        host.synced = Synced::No;
        host.observe();
        host.advance(MIN);
        host.synced = Synced::Yes;
        let floor = host.floor();
        assert_eq!(count(&host.observe(), lowered), 1);
        assert_eq!(host.record(), host.wall());
        assert_eq!(
            host.floor(),
            floor,
            "a floor below the wall clock isn't raised"
        );
    }
}

#[test]
fn invariants_hold_over_random_reading_sequences() {
    for seed in 0..300 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = Host::new(any_synced(&mut rng));
        host.observe();
        for _ in 0..200 {
            host.synced = any_synced(&mut rng);
            match rng.gen_range(0..100) {
                0..=29 => host.advance(rng.gen_range(1..=600) * SEC),
                30..=34 => host.advance(rng.gen_range(1..=48) * HOUR),
                35..=42 => host.wall_off -= rng.gen_range(1..=59_999) * MS,
                43..=47 => host.wall_off -= rng.gen_range(1..=3 * 86_400) * SEC,
                48..=52 => host.wall_off += rng.gen_range(1..=59_999) * MS,
                53..=59 => host.wall_off += rng.gen_range(61..=10 * 86_400) * SEC,
                60..=63 => host.wall_off = 0,
                64..=69 => {
                    if let Some(a) = host.anchor() {
                        host.set_wall(a + rng.gen_range(-70_000..=70_000) * MS);
                    }
                }
                70..=79 => {
                    let base = if rng.gen_bool(0.5) {
                        host.h()
                    } else {
                        host.truth
                    };
                    let origin = if rng.gen_bool(0.8) { ORIGIN } else { OTHER };
                    let st = base + rng.gen_range(-20 * 60_000..=20 * 60_000) * MS;
                    host.station(origin, st);
                    continue;
                }
                80..=84 => {
                    host.reboot(
                        rng.gen_range(0..=30 * 86_400) * SEC,
                        rng.gen_range(1..=7 * 86_400) * SEC,
                    );
                    if rng.gen_bool(0.2) {
                        host.boot_id = format!("{UNKNOWN_BOOT_PREFIX}{}", host.boots);
                    }
                    if rng.gen_bool(0.1) {
                        host.machine = [M1, M2, unknown_machine()][rng.gen_range(0..3)];
                    }
                    host.timens = if rng.gen_bool(0.1) {
                        let offset = rng.gen_range(1..=86_400) * SEC;
                        host.counter += offset;
                        i64::try_from(offset).expect("an offset")
                    } else {
                        0
                    };
                }
                85..=88 => host.restart(),
                89..=91 => {
                    // CRIU: a new offset within the boot.
                    let real = host.counter - i128::from(host.timens);
                    let offset = rng.gen_range(-real / SEC + 1..=86_400) * SEC;
                    host.counter = real + offset;
                    host.timens = i64::try_from(offset).expect("an offset");
                }
                92..=93 => {
                    // The fallbacks flipping within a process.
                    host.machine = if host.machine == M1 {
                        unknown_machine()
                    } else {
                        M1
                    };
                }
                _ => {
                    // A slew: the wall clock drifting against the counter.
                    let dt = rng.gen_range(1..=3_600) * SEC;
                    host.advance(dt);
                    host.wall_off += dt * rng.gen_range(-5_000..=5_000) / 1_000_000;
                }
            }
            host.observe();
        }
    }
}

#[test]
fn state_json_round_trips() {
    let stamp = |value_ms: u64, boot: &str| Stamp {
        value_ms,
        boot_id: boot.to_string(),
        boot_ns: 123_456_789,
        machine: M1,
        timens_boot_ns: -5,
    };
    let state = ClockState {
        record: Some(stamp(1_800_000_000_000, "boot-a")),
        floor: Some(stamp(1_800_000_000_100, "boot-a")),
        anchor: Some(Anchor {
            record: stamp(1_799_999_000_000, "boot-a"),
            floor: Some(stamp(1_799_999_000_100, "boot-a")),
            station: Some(stamp(1_799_999_900_000, "boot-a")),
        }),
        mark: true,
        last_went_back_alert_ms: Some(1_800_000_000_000),
        last_ahead_alert_ms: [(ORIGIN.to_string(), 1_800_000_000_001)].into(),
        spent_boots: vec![Boot {
            machine: M2,
            boot_id: "boot-b".to_string(),
        }],
        last_change: Some(Change {
            kind: ChangeKind::Repaired,
            old: (1_800_000_120_000, Some(1_800_000_000_100)),
            new: (1_800_000_000_000, None),
            at_ms: 1_800_000_000_000,
        }),
    };
    let text = state.to_json();
    assert!(text.contains(
        r#""last_change":{"kind":"repaired","old":[1800000120000,1800000000100],"new":[1800000000000,null],"at_ms":1800000000000}"#
    ));
    assert_eq!(ClockState::from_json(&text).expect("reads back"), state);
    assert!(text.contains(&format!("\"machine\":\"{}\"", "11".repeat(16))));
    assert!(text.contains(&format!(
        "\"spent_boots\":[{{\"machine\":\"{}\",\"boot_id\":\"boot-b\"}}]",
        "22".repeat(16)
    )));
    let fresh = ClockState::default();
    assert_eq!(
        ClockState::from_json(&fresh.to_json()).expect("reads back"),
        fresh
    );
    // Strict: no unknown field, the machine as 32 lowercase hex digits.
    assert!(ClockState::from_json(&text.replacen("\"mark\"", "\"extra\":1,\"mark\"", 1)).is_err());
    assert!(ClockState::from_json(&text.replace(&"11".repeat(16), &"1".repeat(31))).is_err());
    assert!(ClockState::from_json(&text.replace(&"11".repeat(16), &"AB".repeat(16))).is_err());
    assert!(ClockState::from_json("{}").is_err());
    // The change too: no unknown field, a known kind, two values each.
    assert!(ClockState::from_json(&text.replace("\"at_ms\"", "\"extra\":1,\"at_ms\"")).is_err());
    assert!(ClockState::from_json(&text.replace("\"repaired\"", "\"moved\"")).is_err());
    assert!(
        ClockState::from_json(&text.replace("[1800000000000,null]", "[1800000000000]")).is_err()
    );
}

#[test]
fn forward_back_cycles_never_end_below_the_pre_jump_trajectory() {
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(1);
        if rng.gen_bool(0.5) {
            assert!(host.station(ORIGIN, host.truth + rng.gen_range(0..=600) * SEC));
        }
        let t0 = host.truth;
        for _ in 0..rng.gen_range(5..=30) {
            host.advance(rng.gen_range(1..=60) * MIN);
            host.synced = unsynced(&mut rng);
            host.wall_off += rng.gen_range(61..=3 * 86_400) * SEC;
            host.observe();
            host.run(rng.gen_range(1..=600) * MIN, 10 * MIN);
            host.advance(MIN);
            host.synced = any_synced(&mut rng);
            match rng.gen_range(0..3) {
                0 => {
                    if let Some(a) = host.anchor() {
                        host.set_wall(a + rng.gen_range(-60_000..=60_000) * MS);
                    }
                }
                1 => host.wall_off = 0,
                _ => host.wall_off = -rng.gen_range(1..=86_400) * SEC,
            }
            host.observe();
            assert!(host.record() >= host.truth - rho(host.truth - t0));
            assert!(host.d() >= host.truth - rho(host.truth - t0));
        }
    }
}

#[test]
fn set_back_before_a_jump_ends_within_the_follow_down() {
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(1);
        let t0 = host.truth;
        // Set back first, so the record walks down...
        host.advance(MIN);
        host.synced = any_synced(&mut rng);
        host.wall_off = -rng.gen_range(1..=3 * 86_400) * SEC;
        host.observe();
        host.run(rng.gen_range(1..=2 * 24 * 60) * MIN, 10 * MIN);
        // ...then a jump, anchored on the walked-down record...
        host.advance(MIN);
        host.synced = unsynced(&mut rng);
        host.wall_off = rng.gen_range(61..=86_400) * SEC;
        assert_eq!(count(&host.observe(), armed), 1);
        assert!(host.anchor().expect("pending") >= host.truth - rho(host.truth - t0));
        host.run(rng.gen_range(1..=600) * MIN, 10 * MIN);
        // ...then undone into its band, or back to the set-back clock.
        host.advance(MIN);
        if rng.gen_bool(0.5) {
            let a = host.anchor().expect("pending");
            host.set_wall(a + rng.gen_range(-60_000..=60_000) * MS);
            assert_eq!(count(&host.observe(), repaired), 1);
        } else {
            host.wall_off = -rng.gen_range(2..=3 * 86_400) * SEC;
            host.observe();
        }
        assert!(host.record() >= host.truth - rho(host.truth - t0));
        assert!(host.d() >= host.truth - rho(host.truth - t0));
    }
}

#[test]
fn forward_creep_under_60s_is_taken_and_followed_down_never_repaired() {
    // Steps forward under 60 s each are no jump: the record takes them (the
    // early direction), and setting the clock back repairs nothing.
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(1);
        host.synced = any_synced(&mut rng);
        let step = rng.gen_range(1..=59) * SEC;
        let minutes = rng.gen_range(10..=120);
        for _ in 0..minutes {
            host.advance(MIN);
            host.wall_off += step;
            host.observe();
            assert_eq!(host.record(), host.wall());
        }
        assert_eq!(host.seen(armed), 0);
        let crept = host.truth + step * minutes;
        host.advance(MIN);
        host.wall_off = 0;
        host.observe();
        let back = host.truth;
        host.run(rng.gen_range(1..=48) * HOUR, 10 * MIN);
        assert_eq!(host.seen(repaired), 0);
        assert!(host.record() >= host.truth, "early, never late");
        let followed = crept + MIN + (host.truth - back) - rho(host.truth - back + MIN);
        assert!(host.record() >= followed.min(host.wall()).max(host.truth));
        if step * minutes > 11 * MIN {
            assert!(host.seen(went_back) >= 1);
        }
    }
}

#[test]
fn reboot_between_a_jump_and_its_undo_is_no_repair() {
    for seed in 0..30 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(10);
        host.synced = unsynced(&mut rng);
        host.advance(MIN);
        host.wall_off += rng.gen_range(61..=3 * 86_400) * SEC;
        assert_eq!(count(&host.observe(), armed), 1);
        host.run(rng.gen_range(1..=600) * MIN, 10 * MIN);
        // Undone while off or at boot: the anchor goes with its boot.
        host.reboot(
            rng.gen_range(1..=10 * 24 * 60) * MIN,
            rng.gen_range(10..=600) * SEC,
        );
        host.wall_off = 0;
        let events = host.observe();
        assert_eq!(count(&events, dropped), 1);
        assert_eq!(count(&events, repaired), 0);
        assert!(host.record() >= host.truth, "early, never late");
        assert!(host.record() <= host.truth.max(host.record()));
        host.run(rng.gen_range(1..=600) * MIN, 10 * MIN);
        assert_eq!(host.seen(repaired), 0);
        assert!(host.record() >= host.truth);
        // Linux: the boot's first synchronized reading lowers a lead of more
        // than 10 minutes, once.
        host.advance(MIN);
        host.synced = Synced::Yes;
        let lead = host.h() - host.wall();
        let events = host.observe();
        assert_eq!(count(&events, lowered), usize::from(lead > 10 * MIN));
        assert!(host.record() >= host.truth);
    }
}

#[test]
fn unknown_boot_id_adds_no_boot_time_and_keeps_the_mark() {
    // Ruling T9b: a host whose boot id can't be read gets an id per process,
    // so a runtime restart reads as a boot change. Its counter goes on, and
    // a record made within 60 s of the boot would pass Decision 17 (b): no
    // boot time crosses it, so H can't get ahead of the true time.
    let unknown = |n: u32| format!("{UNKNOWN_BOOT_PREFIX}{n}");
    let mut host = Host::new(Synced::Yes);
    host.boot_id = unknown(0);
    host.observe();
    host.advance(10 * SEC);
    host.observe();
    let value = ns(host.state.record.as_ref().expect("a record").value_ms);
    host.restart();
    host.boot_id = unknown(1);
    host.advance(5 * SEC);
    host.synced = Synced::No;
    let events = host.observe();
    assert_eq!(guard(&events), Some(GuardWhy::UnknownBoot));
    assert_eq!(host.record(), host.wall().max(value));
    assert!(host.h() <= host.truth);
    assert!(!host.state.mark(), "the lowering can't be counted per boot");
    // A pending anchor goes; nothing is compared across.
    host.advance(MIN);
    host.wall_off += HOUR;
    assert_eq!(count(&host.observe(), armed), 1);
    host.boot_id = unknown(2);
    host.advance(SEC);
    let events = host.observe();
    assert_eq!(count(&events, dropped), 1);
    assert_eq!(guard(&events), Some(GuardWhy::UnknownBoot));
    // A real reboot on such a host: no boot time, no mark.
    host.reboot(HOUR, 40 * SEC);
    host.boot_id = unknown(3);
    host.wall_off = 0;
    let events = host.observe();
    assert_eq!(guard(&events), Some(GuardWhy::UnknownBoot));
    assert!(!host.state.mark());
    // From an unknown id to a readable one alike.
    host.boot_id = "boot-9".to_string();
    host.advance(SEC);
    assert_eq!(guard(&host.observe()), Some(GuardWhy::UnknownBoot));
    assert!(!host.state.mark());
}

#[test]
fn unknown_machine_id_adds_no_boot_time() {
    // Ruling T9b: a machine with no id readable hashes the empty id, which
    // every such machine shares. A store moved between two of them 10 s
    // after its last record, onto a node up 40 s, would pass Decision 17
    // (b): no boot time crosses.
    let mut host = Host::new(Synced::Yes);
    host.machine = unknown_machine();
    host.observe();
    host.run(10 * MIN, MIN);
    let x = host.record();
    host.synced = Synced::No;
    host.move_to(unknown_machine(), "node-b", 40 * SEC, 10 * SEC);
    let events = host.observe();
    assert_eq!(guard(&events), Some(GuardWhy::UnknownMachine));
    assert_eq!(host.record(), host.wall().max(x));
    assert!(host.h() <= host.truth);
    assert!(host.state.mark(), "a readable new boot id: a new boot");
    // A real reboot of such a host: late by the uptime before the first
    // reading, at most.
    host.run(HOUR, MIN);
    host.wall_off = -5 * MIN;
    host.run(MIN, MIN);
    let value = ns(host.state.record.as_ref().expect("a record").value_ms);
    host.reboot(2 * MIN, 30 * SEC);
    let events = host.observe();
    assert_eq!(guard(&events), Some(GuardWhy::UnknownMachine));
    assert_eq!(host.record(), host.wall().max(value));
    assert!(host.record() >= host.truth - 30 * SEC - 2 * MIN - 5 * MIN);
}

#[test]
fn first_reading_ever_records_the_wall_clock_and_marks_the_boot() {
    let mut host = Host::new(Synced::No);
    host.wall_off = 3 * HOUR;
    let r = host.reading();
    assert_eq!(host.state.h_ms(&r), r.wall_ms);
    assert_eq!(host.state.deadline_ms(&r), r.wall_ms);
    host.observe();
    assert_eq!(host.record(), host.wall());
    assert!(host.state.mark());
    // The OS's first synchronized report lowers the clock that came up ahead.
    host.advance(MIN);
    host.wall_off = 0;
    host.observe();
    host.advance(SEC);
    host.synced = Synced::Yes;
    assert_eq!(count(&host.observe(), lowered), 1);
    assert_eq!(host.h(), host.truth);
    // Synchronized at once: no mark.
    let mut host = Host::new(Synced::Yes);
    host.observe();
    assert!(!host.state.mark());
}

/// A host whose record, after a 61 s jump the anchor took and a clock set 2
/// hours back, was followed down a minute at a time until it is less than one
/// minute's follow-down (30 ms) above the anchor's record prediction.
fn walked_to_the_anchor() -> Host {
    let mut host = settled_host(5);
    host.synced = Synced::No;
    host.advance(MIN);
    host.wall_off += 61 * SEC;
    assert_eq!(count(&host.observe(), armed), 1);
    host.advance(MIN);
    host.wall_off = -2 * HOUR;
    host.observe();
    while host.record() - host.anchor().expect("pending") >= 30 * MS {
        host.advance(MIN);
        host.observe();
    }
    assert!(host.record() > host.anchor().expect("pending"));
    host.advance(MIN);
    let (p, a) = (host.h(), host.anchor().expect("pending"));
    assert!(
        p - follow_down(MIN) < a && a <= p,
        "the case: p − ρΔ < a ≤ p"
    );
    host
}

#[test]
fn a_repair_never_lands_below_the_anchor_prediction_after_a_follow_down() {
    // Review probe P1: a 61 s jump, the runtime stopped two days in the same
    // boot, then the clock set to a − 30 s. That reading's follow-down (86.4 s)
    // alone would end 25.4 s below a; the repair lands on max(w, a).
    let mut host = settled_host(10);
    host.synced = Synced::No;
    host.advance(MIN);
    host.wall_off += 61 * SEC;
    assert_eq!(count(&host.observe(), armed), 1);
    host.advance(2 * DAY);
    let a = host.anchor().expect("pending");
    host.set_wall(a - 30 * SEC);
    assert_eq!(count(&host.observe(), repaired), 1);
    assert_eq!(host.record(), a);

    // Random jumps and gaps whose follow-down passes the anchor.
    for seed in 0..40 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut host = settled_host(5);
        host.synced = unsynced(&mut rng);
        host.advance(MIN);
        let jump = rng.gen_range(61..=600) * SEC;
        host.wall_off += jump;
        assert_eq!(count(&host.observe(), armed), 1);
        host.advance(jump * 2_000 + rng.gen_range(0..=86_400) * SEC);
        let a = host.anchor().expect("pending");
        let off = rng.gen_range(-60_000..=60_000) * MS;
        host.set_wall(a + off);
        assert_eq!(count(&host.observe(), repaired), 1);
        assert_eq!(host.record(), (a + off).max(a));
    }

    // At a reading a minute: undone below the anchor, it lands on it.
    let mut host = walked_to_the_anchor();
    let a = host.anchor().expect("pending");
    host.set_wall(a - 30 * SEC);
    assert_eq!(count(&host.observe(), repaired), 1);
    assert_eq!(host.record(), a);

    // Undone above the record's prediction: the record takes the reading, and
    // the event reads no rise (review Minor 3).
    let mut host = walked_to_the_anchor();
    let p = host.h();
    host.set_wall(p + 10 * SEC);
    let events = host.observe();
    let w = ns(host.reading().wall_ms);
    assert_eq!(host.record(), w);
    assert_eq!(
        events.iter().find(|e| repaired(e)),
        Some(&ClockEvent::Repaired {
            old: (to_ms(w), None),
            new: (to_ms(w), None),
        })
    );
}

#[test]
fn a_profile_back_on_a_machine_gets_no_second_lowering_in_its_boot() {
    // Review probe P2: a profile shared by machines A and B (one runtime at a
    // time) moved A -> B -> A -> B. B's clock runs two hours behind; its one
    // kernel boot gets one lowering, at its first synchronized reading.
    let mut host = Host::new(Synced::Yes);
    host.observe();
    host.run(HOUR, MIN);
    let a_start = T0 - 30 * SEC;
    let b_start = T0 - 5 * DAY;
    for round in 0..3 {
        host.synced = Synced::No;
        host.machine = M2;
        host.boot_id = "b-boot".to_string();
        host.counter = host.truth - b_start;
        host.wall_off = -2 * HOUR;
        let events = host.observe();
        assert_eq!(guard(&events), Some(GuardWhy::OtherMachine));
        assert_eq!(host.state.mark(), round == 0, "round {round}");
        host.advance(MIN);
        host.synced = Synced::Yes;
        assert_eq!(count(&host.observe(), lowered), usize::from(round == 0));
        host.run(HOUR, MIN);
        // Back on A, whose boot's first synchronized reading passed at its
        // first reading.
        host.synced = Synced::No;
        host.machine = M1;
        host.boot_id = "boot-0".to_string();
        host.counter = host.truth - a_start;
        host.wall_off = 0;
        host.observe();
        assert!(!host.state.mark());
        host.advance(MIN);
        host.synced = Synced::Yes;
        host.run(HOUR, MIN);
    }
    assert_eq!(host.seen(lowered), 1);
    assert!(
        host.seen(went_back) >= 2,
        "B's clock behind: the alert instead"
    );

    // The list keeps the latest eight boots.
    for _ in 0..10 {
        host.reboot(MIN, 30 * SEC);
        host.observe();
    }
    let kept: Vec<&str> = host
        .state
        .spent_boots
        .iter()
        .map(|b| b.boot_id.as_str())
        .collect();
    assert_eq!(
        kept,
        [
            "boot-3", "boot-4", "boot-5", "boot-6", "boot-7", "boot-8", "boot-9", "boot-10"
        ]
    );
}

#[test]
fn a_mark_carried_from_another_boot_gives_no_second_lowering_in_a_spent_boot() {
    // Re-review probe: A's boot spends its lowering; the profile visits B,
    // whose boot sets the mark but never gets a synchronized reading; back on
    // A, the mark it carries lowers nothing.
    let mut host = Host::new(Synced::No);
    host.wall_off = 2 * HOUR;
    host.observe();
    host.advance(MIN);
    host.wall_off = 0;
    host.synced = Synced::Yes;
    assert_eq!(count(&host.observe(), lowered), 1, "A's own lowering");
    host.run(HOUR, MIN);
    let a = Boot::of(&host.reading());
    assert_eq!(host.state.spent_boots, vec![a.clone()]);
    // B: one unsynchronized reading, its clock two hours ahead.
    let a_start = T0 - 30 * SEC;
    let b_start = T0 - 5 * DAY;
    host.synced = Synced::No;
    host.machine = M2;
    host.boot_id = "b-boot".to_string();
    host.counter = host.truth - b_start;
    host.wall_off = 2 * HOUR;
    host.observe();
    assert!(host.state.mark(), "B's boot sets the mark");
    // Back on A, synchronized, its clock on time: no second lowering in A's
    // boot, the alert instead, and A not spent twice.
    host.advance(MIN);
    host.machine = M1;
    host.boot_id = "boot-0".to_string();
    host.counter = host.truth - a_start;
    host.wall_off = 0;
    host.synced = Synced::Yes;
    let events = host.observe();
    assert_eq!(guard(&events), Some(GuardWhy::OtherMachine));
    assert_eq!(count(&events, lowered), 0);
    assert_eq!(count(&events, went_back), 1);
    assert!(!host.state.mark());
    assert_eq!(host.state.spent_boots, vec![a.clone()]);
    host.run(HOUR, MIN);
    assert_eq!(host.seen(lowered), 1);
    // B's own boot still has its lowering, at its first synchronized reading.
    host.synced = Synced::No;
    host.machine = M2;
    host.boot_id = "b-boot".to_string();
    host.counter = host.truth - b_start;
    host.wall_off = -2 * HOUR;
    host.observe();
    assert!(host.state.mark());
    host.advance(MIN);
    host.synced = Synced::Yes;
    assert_eq!(count(&host.observe(), lowered), 1, "B's own lowering");
    let b = Boot::of(&host.reading());
    assert_eq!(host.state.spent_boots, vec![a, b]);
}

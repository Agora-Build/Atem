//! The host clock a binary test moves (`ATEM_TEST_HOST_CLOCK`, debug
//! builds): the real wall and monotonic clocks plus offsets the test sets,
//! on this boot. The file holds the offsets (`offsets <wall_ms> <mono_ms>
//! <boot_id>`) and the runtime adds them to its own clocks at every read,
//! so a move is in force once its write returns and the clocks go on
//! without one. The delegated clock (host-work-v1 §11.6) reads the same
//! file; `set_delegated` adds its optional fields (boot-time counter, sync
//! report, machine, namespace offset), else it takes their defaults, and
//! `set_boot_ms` moves its boot-time counter alone. `set_boot_id` changes
//! the boot (a reboot, for both clocks).
//!
//! (The tests wrote the clocks themselves, every 20 ms from a thread, and a
//! move only stored the new offsets: a write landing late under load let
//! the runtime act on the old clock (CI run 43132553930), and a late
//! thread held the clock back.)

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// One host pass: what a move leaves the runtime to run on the moved clocks.
const PASS: Duration = Duration::from_millis(100);

pub struct HostClock {
    /// The file to pass as `ATEM_TEST_HOST_CLOCK`.
    pub path: PathBuf,
    /// What the file says; held while it is written.
    offsets: Mutex<Offsets>,
}

struct Offsets {
    /// The wall offset (negative: behind).
    wall: i64,
    mono: u64,
    boot: String,
    delegated: Option<Delegated>,
}

/// The delegated clock's optional fields of `ATEM_TEST_HOST_CLOCK`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegated {
    /// Its boot-time counter: the real monotonic clock plus this (it may be
    /// negative).
    pub boot_ms: i64,
    /// The OS's sync report (`None`: no report).
    pub synced: Option<bool>,
    /// The machine identity, 32 lowercase hex digits.
    pub machine_hex: String,
    /// The boot-time namespace offset.
    pub timens_boot_ms: i64,
}

impl Delegated {
    /// What the runtime takes when the fields are left out, at monotonic
    /// offset `mono_ms`: the counter is the monotonic clock, synchronized,
    /// the test machine (`test_hooks::TEST_MACHINE`), no namespace offset.
    pub fn defaults(mono_ms: u64) -> Delegated {
        Delegated {
            boot_ms: mono_ms as i64,
            synced: Some(true),
            machine_hex: "6174656d2d746573742d686f73742d31".into(),
            timens_boot_ms: 0,
        }
    }
}

fn real_wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The real `CLOCK_MONOTONIC`, in ms: what the runtime adds the offsets to.
fn real_mono_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for the call to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

impl HostClock {
    /// The real clocks, in `dir`/`name`.
    pub fn start(dir: &Path, name: &str) -> HostClock {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "boot".into());
        let clock = HostClock {
            path: dir.join(name),
            offsets: Mutex::new(Offsets {
                wall: 0,
                mono: 0,
                boot,
                delegated: None,
            }),
        };
        clock.apply(|_| {});
        clock
    }

    /// Changes the offsets and writes them (atomically) before returning.
    fn apply(&self, change: impl FnOnce(&mut Offsets)) {
        let mut offsets = self.offsets.lock().unwrap();
        change(&mut offsets);
        let tmp = self.path.with_extension("tmp");
        let mut text = format!("offsets {} {} {}", offsets.wall, offsets.mono, offsets.boot);
        if let Some(d) = &offsets.delegated {
            let synced = match d.synced {
                Some(true) => "1",
                Some(false) => "0",
                None => "-",
            };
            text.push_str(&format!(
                " {} {synced} {} {}",
                d.boot_ms, d.machine_hex, d.timens_boot_ms
            ));
        }
        std::fs::write(&tmp, text).unwrap();
        std::fs::rename(&tmp, &self.path).unwrap();
    }

    /// Sets the wall clock `wall_ms` from the real one (negative: behind)
    /// and the monotonic clock `mono_ms` ahead of the real one, then waits
    /// one host pass.
    pub fn set(&self, wall_ms: i64, mono_ms: u64) {
        self.apply(|o| (o.wall, o.mono) = (wall_ms, mono_ms));
        std::thread::sleep(PASS);
    }

    /// Sets the wall clock `ms` from the real one (negative: behind), then
    /// waits one host pass.
    pub fn set_wall(&self, ms: i64) {
        self.apply(|o| o.wall = ms);
        std::thread::sleep(PASS);
    }

    /// Moves the monotonic clock `ms` on (it never goes back), then waits
    /// for a host pass (with slack, as before).
    pub fn add_mono(&self, ms: u64) {
        self.apply(|o| o.mono += ms);
        std::thread::sleep(4 * PASS);
    }

    /// Sets the delegated clock's fields (`None`: their defaults), then
    /// waits one host pass.
    pub fn set_delegated(&self, delegated: Option<Delegated>) {
        self.apply(|o| o.delegated = delegated);
        std::thread::sleep(PASS);
    }

    /// Sets the delegated clock's boot-time counter to read `boot_ms` now
    /// (an offset from the real monotonic clock, so it goes on from there),
    /// its other fields as they were (else their defaults), then waits one
    /// host pass. The wall clock, and so the device list's host clock,
    /// stays as it is.
    pub fn set_boot_ms(&self, boot_ms: u64) {
        let offset = boot_ms as i64 - real_mono_ms() as i64;
        self.apply(|o| {
            let fields = o
                .delegated
                .take()
                .unwrap_or_else(|| Delegated::defaults(o.mono));
            o.delegated = Some(Delegated {
                boot_ms: offset,
                ..fields
            });
        });
        std::thread::sleep(PASS);
    }

    /// Sets the boot id (a reboot, as both clocks read one), then waits one
    /// host pass.
    pub fn set_boot_id(&self, id: &str) {
        self.apply(|o| o.boot = id.to_string());
        std::thread::sleep(PASS);
    }

    /// The host's wall clock now.
    pub fn wall(&self) -> u64 {
        (real_wall_ms() as i64 + self.offsets.lock().unwrap().wall) as u64
    }
}

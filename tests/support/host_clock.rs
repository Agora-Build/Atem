//! The host clock a binary test moves (`ATEM_TEST_HOST_CLOCK`, debug
//! builds): the real wall and monotonic clocks plus offsets the test sets,
//! on this boot. The file holds the offsets (`offsets <wall_ms> <mono_ms>
//! <boot_id>`) and the runtime adds them to its own clocks at every read,
//! so a move is in force once its write returns and the clocks go on
//! without one.
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
    boot: String,
    /// The wall offset (negative: behind) and the monotonic one; held while
    /// the file is written.
    offsets: Mutex<(i64, u64)>,
}

fn real_wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl HostClock {
    /// The real clocks, in `dir`/`name`.
    pub fn start(dir: &Path, name: &str) -> HostClock {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "boot".into());
        let clock = HostClock {
            path: dir.join(name),
            boot,
            offsets: Mutex::new((0, 0)),
        };
        clock.apply(|_| {});
        clock
    }

    /// Changes the offsets and writes them (atomically) before returning.
    fn apply(&self, change: impl FnOnce(&mut (i64, u64))) {
        let mut offsets = self.offsets.lock().unwrap();
        change(&mut offsets);
        let tmp = self.path.with_extension("tmp");
        let text = format!("offsets {} {} {}", offsets.0, offsets.1, self.boot);
        std::fs::write(&tmp, text).unwrap();
        std::fs::rename(&tmp, &self.path).unwrap();
    }

    /// Sets the wall clock `wall_ms` from the real one (negative: behind)
    /// and the monotonic clock `mono_ms` ahead of the real one, then waits
    /// one host pass.
    pub fn set(&self, wall_ms: i64, mono_ms: u64) {
        self.apply(|o| *o = (wall_ms, mono_ms));
        std::thread::sleep(PASS);
    }

    /// Sets the wall clock `ms` from the real one (negative: behind), then
    /// waits one host pass.
    pub fn set_wall(&self, ms: i64) {
        self.apply(|o| o.0 = ms);
        std::thread::sleep(PASS);
    }

    /// Moves the monotonic clock `ms` on (it never goes back), then waits
    /// for a host pass (with slack, as before).
    pub fn add_mono(&self, ms: u64) {
        self.apply(|o| o.1 += ms);
        std::thread::sleep(4 * PASS);
    }

    /// The host's wall clock now.
    pub fn wall(&self) -> u64 {
        (real_wall_ms() as i64 + self.offsets.lock().unwrap().0) as u64
    }
}

//! The recovery wait (§R9.5 "Timing"): 24 h on the host's own clock from
//! first sight, ending only when **both** the monotonic time and the wall
//! time have elapsed. Nothing inside an entry counts (`signed_at` is display
//! only). Pure functions of the clock readings the caller passes in.
//!
//! Monotonic readings are in milliseconds (`CLOCK_MONOTONIC`, the clock of
//! §3's deadlines) with the boot they belong to. Within one boot the wait
//! counts from its anchor; after a reboot (another `boot_id`) it continues
//! from the last persisted `mono_waited_ms`, so time while the machine was
//! off never counts.

/// The wait: 86 400 000 ms.
pub const RECOVERY_WAIT_MS: u64 = 86_400_000;

/// One reading of the host's clocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNow {
    /// Wall clock, ms since the epoch.
    pub wall_ms: u64,
    /// `CLOCK_MONOTONIC`, ms.
    pub mono_ms: u64,
    /// The boot the monotonic reading belongs to (Linux
    /// `/proc/sys/kernel/random/boot_id`, macOS `kern.bootsessionuuid`).
    pub boot_id: String,
}

/// A pending entry's wait, as the host records it (`membership.json`'s
/// `recovery[]`, §R9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitClock {
    /// Wall time of first sight (the commit that appended the entry).
    pub first_seen_wall: u64,
    /// The boot `mono_anchor_ms` belongs to.
    pub boot_id: String,
    /// The monotonic reading (this boot) the wait counts from: first sight,
    /// or after a reboot the reading then minus the time already waited
    /// (negative when the new boot is younger than the wait).
    pub mono_anchor_ms: i64,
    /// Monotonic time waited, as last persisted (at least once a minute and
    /// at shutdown; `observe` updates it).
    pub mono_waited_ms: u64,
}

impl WaitClock {
    /// The wait starts at first sight.
    pub fn start(now: &HostNow) -> Self {
        WaitClock {
            first_seen_wall: now.wall_ms,
            boot_id: now.boot_id.clone(),
            mono_anchor_ms: mono(now),
            mono_waited_ms: 0,
        }
    }

    /// Monotonic time waited at `now`. Another boot adds nothing beyond what
    /// was persisted.
    pub fn waited_ms(&self, now: &HostNow) -> u64 {
        if now.boot_id == self.boot_id {
            let since = (mono(now) - self.mono_anchor_ms).max(0) as u64;
            since.max(self.mono_waited_ms)
        } else {
            self.mono_waited_ms
        }
    }

    /// Takes a reading: records the time waited and, on another boot,
    /// re-anchors so the wait continues from what was persisted.
    pub fn observe(&mut self, now: &HostNow) {
        let waited = self.waited_ms(now);
        if now.boot_id != self.boot_id {
            self.boot_id = now.boot_id.clone();
            self.mono_anchor_ms = mono(now) - waited as i64;
        }
        self.mono_waited_ms = waited;
    }

    /// Both sides have elapsed.
    pub fn elapsed(&self, now: &HostNow) -> bool {
        self.waited_ms(now) >= RECOVERY_WAIT_MS
            && now.wall_ms >= self.first_seen_wall.saturating_add(RECOVERY_WAIT_MS)
    }

    /// `effective_at = now_wall + max(86 400 000 − mono_waited,
    /// first_seen_wall + 86 400 000 − now_wall)`: an estimate on the host's
    /// clock, recomputed on every report (never earlier than now).
    pub fn effective_at(&self, now: &HostNow) -> u64 {
        let wait = RECOVERY_WAIT_MS as i128;
        let mono_left = wait - self.waited_ms(now) as i128;
        let wall_left = self.first_seen_wall as i128 + wait - now.wall_ms as i128;
        let left = mono_left.max(wall_left).max(0);
        (now.wall_ms as i128 + left) as u64
    }
}

fn mono(now: &HostNow) -> i64 {
    now.mono_ms.min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(wall_ms: u64, mono_ms: u64, boot: &str) -> HostNow {
        HostNow {
            wall_ms,
            mono_ms,
            boot_id: boot.into(),
        }
    }

    const W0: u64 = 1_793_177_601_000;

    #[test]
    fn the_wait_needs_both_clocks() {
        let clock = WaitClock::start(&at(W0, 5_000, "b1"));
        assert_eq!(
            clock.effective_at(&at(W0, 5_000, "b1")),
            W0 + RECOVERY_WAIT_MS
        );
        // A forward wall jump alone ends nothing.
        let jumped = at(W0 + 10 * RECOVERY_WAIT_MS, 5_000, "b1");
        assert!(!clock.elapsed(&jumped));
        assert_eq!(
            clock.effective_at(&jumped),
            jumped.wall_ms + RECOVERY_WAIT_MS
        );
        // A backward wall step delays it.
        let back = at(W0 - 1_000, 5_000 + RECOVERY_WAIT_MS, "b1");
        assert!(!clock.elapsed(&back));
        assert_eq!(clock.effective_at(&back), W0 + RECOVERY_WAIT_MS);
        assert!(clock.elapsed(&at(W0 + RECOVERY_WAIT_MS, 5_000 + RECOVERY_WAIT_MS, "b1")));
        assert!(!clock.elapsed(&at(W0 + RECOVERY_WAIT_MS, 4_999 + RECOVERY_WAIT_MS, "b1")));
    }

    #[test]
    fn time_while_the_machine_was_off_never_counts() {
        let mut clock = WaitClock::start(&at(W0, 1_000_000, "b1"));
        clock.observe(&at(W0 + 3_600_000, 1_000_000 + 3_600_000, "b1"));
        assert_eq!(clock.mono_waited_ms, 3_600_000);
        // Rebooted a day later: the new boot's clock starts near zero.
        let after = at(W0 + 2 * RECOVERY_WAIT_MS, 10_000, "b2");
        assert_eq!(clock.waited_ms(&after), 3_600_000);
        assert!(!clock.elapsed(&after));
        clock.observe(&after);
        assert_eq!(clock.boot_id, "b2");
        let later = at(after.wall_ms + 1_000, 11_000, "b2");
        assert_eq!(clock.waited_ms(&later), 3_601_000);
        let done = at(after.wall_ms, 10_000 + RECOVERY_WAIT_MS - 3_600_000, "b2");
        assert!(clock.elapsed(&done));
    }

    #[test]
    fn a_restart_within_one_boot_keeps_counting_from_first_sight() {
        let clock = WaitClock::start(&at(W0, 50, "b1"));
        // Nothing persisted since (mono_waited_ms 0): same boot, the anchor
        // still counts the whole time.
        assert!(clock.elapsed(&at(W0 + RECOVERY_WAIT_MS, 50 + RECOVERY_WAIT_MS, "b1")));
    }
}

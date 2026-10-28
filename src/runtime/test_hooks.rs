//! Clock and PTY-fault hooks for the shared atem-session fixtures run
//! against the real runtime (`tests/runtime_fixtures_binary.rs`). They exist
//! only in debug builds and only act when the environment names them;
//! release builds compile every hook to a no-op.
//!
//! - `ATEM_TEST_CLOCK_FILE=<file>`: the session host's monotonic clock reads
//!   the decimal milliseconds in `<file>` instead of the time since the
//!   broker started (a missing or unreadable file reads as 0). The fixture
//!   harness only ever raises it, so the clock stays monotonic and moves
//!   only when a fixture advances it.
//! - `ATEM_TEST_PTY_FAULTS=<dir>`, read by workers at the PTY write boundary:
//!   - `<dir>/hold` exists: fenced writes wait, before their input-epoch
//!     check, until it is removed;
//!   - `<dir>/fail_next_enqueue`: the next paste (a dispatched prompt) is
//!     refused before anything is queued;
//!   - `<dir>/fail_next_partial`: the next paste writes the first half of
//!     its bytes, then fails.
//!
//!   A fault marker is removed when it is used, and its name is appended to
//!   `<dir>/used`.
//! - `ATEM_TEST_MEMBERSHIP_FAULTS=<dir>`, read by the runtime's device-list
//!   store (`session_protocol::membership`, §R9.3):
//!   - `<dir>/fail_next` (`<file>:<step>`, e.g. `state:temp_fsync`,
//!     `carriage:temp_write`, `intent:rename`, `freeze:directory_fsync`):
//!     the next write of that file fails at that step;
//!   - `<dir>/crash_after_commit`: the runtime kills itself right after the next
//!     `membership.json` write is durable, before its fences;
//!   - `<dir>/carry.json` (`{"entries": [...]}`): the runtime applies it as
//!     a carriage of its own relay fetch (§R9.3: no more trust than any
//!     carrier) at its next pass; the outcome is appended to
//!     `<dir>/carried`.
//!
//!   A marker is removed when it is used, and its name appended to
//!   `<dir>/used`.
//! - `ATEM_TEST_HOST_CLOCK=<file>` (`<wall_ms> <mono_ms> <boot_id>`): the
//!   device list's host clock (§R9.5) instead of the system's wall clock,
//!   `CLOCK_MONOTONIC` and boot id, so a test can simulate a reboot.
//! - `ATEM_TEST_BUILD=<id>`: this process reports `<id>` as its build
//!   (`cred_agent::build_id`), so a binary test can run a runtime that looks
//!   like another atem build.
//!
//! For the r9 fixtures against the real runtime (`tests/r9_runner/`):
//! - `ATEM_TEST_PTY_FAULTS=<dir>`, read by the broker too: while
//!   `<dir>/hold_dispatch` exists, accepted work stays queued (the
//!   fixtures' `hold_dispatch`).
//! - `ATEM_TEST_NO_INIT_LIMIT=1`: `init`s aren't limited to one a second
//!   per link (the fixtures connect clients back to back on a host clock
//!   that only they move; the envelope fixtures, which check the limit,
//!   leave it on).
//! - `ATEM_TEST_PROJECT_HASHES=<file>` (`{"<project key>": {"<kid>":
//!   "h1.<kid>.<hash>"}}`): the service `projects` scopes' keyed hashes
//!   come from this table instead of the cred agent (the fixtures name
//!   project hashes, never a `K`); everything else of the scope check is
//!   the runtime's own.
//! - `ATEM_TEST_SESSION_ID=<ses-…>` in a `launch` request's environment:
//!   the session gets that id (the fixtures' signed browser grants name
//!   their session).
//! - `ATEM_TEST_STATE_DUMP=<file>`: after each pass the broker writes the
//!   state the fixtures assert (device list, leases, receipts, control
//!   generations, channels, and the pass number) to `<file>` (JSON,
//!   replaced atomically).

#[cfg(debug_assertions)]
mod imp {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    fn env_path(name: &str, cell: &'static OnceLock<Option<PathBuf>>) -> Option<&'static PathBuf> {
        cell.get_or_init(|| std::env::var_os(name).map(PathBuf::from))
            .as_ref()
    }

    fn clock_file() -> Option<&'static PathBuf> {
        static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
        env_path("ATEM_TEST_CLOCK_FILE", &CELL)
    }

    pub fn build() -> Option<String> {
        std::env::var("ATEM_TEST_BUILD").ok()
    }

    fn faults_dir() -> Option<&'static PathBuf> {
        static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
        env_path("ATEM_TEST_PTY_FAULTS", &CELL)
    }

    pub fn clock_ms() -> Option<u64> {
        let file = clock_file()?;
        Some(
            std::fs::read_to_string(file)
                .ok()
                .and_then(|text| text.trim().parse().ok())
                .unwrap_or(0),
        )
    }

    pub fn hold_writes() {
        let Some(dir) = faults_dir() else { return };
        let hold = dir.join("hold");
        while hold.exists() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn membership_dir() -> Option<&'static PathBuf> {
        static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
        env_path("ATEM_TEST_MEMBERSHIP_FAULTS", &CELL)
    }

    fn used(dir: &std::path::Path, name: &str) {
        use std::io::Write;
        if let Ok(mut used) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("used"))
        {
            let _ = writeln!(used, "{name}");
        }
    }

    /// Takes `<dir>/<name>`'s content (the marker is removed).
    pub fn take_membership(name: &str) -> Option<String> {
        let dir = membership_dir()?;
        let path = dir.join(name);
        let text = std::fs::read_to_string(&path).ok()?;
        std::fs::remove_file(&path).ok()?;
        used(dir, name);
        Some(text)
    }

    pub fn membership_log(line: &str) {
        use std::io::Write;
        let Some(dir) = membership_dir() else { return };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("carried"))
        {
            let _ = writeln!(f, "{line}");
        }
    }

    pub fn host_clock() -> Option<(u64, u64, String)> {
        static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
        let file = env_path("ATEM_TEST_HOST_CLOCK", &CELL)?;
        let text = std::fs::read_to_string(file).ok()?;
        let mut parts = text.split_whitespace();
        let wall = parts.next()?.parse().ok()?;
        let mono = parts.next()?.parse().ok()?;
        let boot = parts.next()?.to_string();
        Some((wall, mono, boot))
    }

    pub fn hold_dispatch() -> Option<bool> {
        faults_dir().map(|dir| dir.join("hold_dispatch").exists())
    }

    pub fn no_init_limit() -> bool {
        static CELL: OnceLock<bool> = OnceLock::new();
        *CELL.get_or_init(|| std::env::var_os("ATEM_TEST_NO_INIT_LIMIT").is_some())
    }

    pub fn project_hashes() -> Option<&'static PathBuf> {
        static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
        env_path("ATEM_TEST_PROJECT_HASHES", &CELL)
    }

    pub fn state_dump() -> Option<&'static PathBuf> {
        static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
        env_path("ATEM_TEST_STATE_DUMP", &CELL)
    }

    pub fn take_fault(name: &str) -> bool {
        use std::io::Write;
        let Some(dir) = faults_dir() else {
            return false;
        };
        if std::fs::remove_file(dir.join(name)).is_err() {
            return false;
        }
        if let Ok(mut used) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("used"))
        {
            let _ = writeln!(used, "{name}");
        }
        true
    }
}

/// The fixture clock in milliseconds, when one is configured.
pub fn clock_ms() -> Option<u64> {
    #[cfg(debug_assertions)]
    return imp::clock_ms();
    #[cfg(not(debug_assertions))]
    None
}

/// The build this process reports instead of its own, when one is set.
pub fn build() -> Option<String> {
    #[cfg(debug_assertions)]
    return imp::build();
    #[cfg(not(debug_assertions))]
    None
}

/// Waits while fenced PTY writes are held.
pub fn hold_writes() {
    #[cfg(debug_assertions)]
    imp::hold_writes();
}

/// The next paste is refused before it is queued.
pub fn fail_next_enqueue() -> bool {
    #[cfg(debug_assertions)]
    return imp::take_fault("fail_next_enqueue");
    #[cfg(not(debug_assertions))]
    false
}

/// The next paste is written only in part, then fails.
pub fn fail_next_partial() -> bool {
    #[cfg(debug_assertions)]
    return imp::take_fault("fail_next_partial");
    #[cfg(not(debug_assertions))]
    false
}

/// The next device-list write fault (`<file>:<step>`), once.
pub fn membership_fault() -> Option<String> {
    #[cfg(debug_assertions)]
    return imp::take_membership("fail_next");
    #[cfg(not(debug_assertions))]
    None
}

/// The next host-policy write fault (§R9.8a; `file:step`, the files
/// `host_policy`/`host_policy_pending`): its own hook, so a device-list
/// write never takes it.
pub fn policy_fault() -> Option<String> {
    #[cfg(debug_assertions)]
    return imp::take_membership("fail_next_policy");
    #[cfg(not(debug_assertions))]
    None
}

/// The runtime kills itself right after the next durable `membership.json`.
#[cfg_attr(test, allow(dead_code))]
pub fn crash_after_membership_commit() -> bool {
    #[cfg(debug_assertions)]
    return imp::take_membership("crash_after_commit").is_some();
    #[cfg(not(debug_assertions))]
    false
}

/// A carriage to apply as the runtime's own relay fetch (`carry.json`).
pub fn membership_carry() -> Option<String> {
    #[cfg(debug_assertions)]
    return imp::take_membership("carry.json");
    #[cfg(not(debug_assertions))]
    None
}

/// Records a test carriage's outcome (`<dir>/carried`).
pub fn membership_carried(_line: &str) {
    #[cfg(debug_assertions)]
    imp::membership_log(_line);
}

/// The test host clock: wall ms, monotonic ms and boot id.
pub fn host_clock() -> Option<(u64, u64, String)> {
    #[cfg(debug_assertions)]
    return imp::host_clock();
    #[cfg(not(debug_assertions))]
    None
}

/// The device-list hooks are set (`ATEM_TEST_MEMBERSHIP_FAULTS`).
pub fn membership_hooks() -> bool {
    #[cfg(debug_assertions)]
    return std::env::var_os("ATEM_TEST_MEMBERSHIP_FAULTS").is_some();
    #[cfg(not(debug_assertions))]
    false
}

/// Whether accepted work stays queued (`<pty faults>/hold_dispatch`);
/// `None` when the PTY fault hooks aren't set (the host's own hold stays).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn hold_dispatch() -> Option<bool> {
    #[cfg(debug_assertions)]
    return imp::hold_dispatch();
    #[cfg(not(debug_assertions))]
    None
}

/// `init`s aren't rate-limited per link (`ATEM_TEST_NO_INIT_LIMIT`).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn no_init_limit() -> bool {
    #[cfg(debug_assertions)]
    return imp::no_init_limit();
    #[cfg(not(debug_assertions))]
    false
}

/// The project-hash table replacing the cred agent's keyed hashes
/// (`ATEM_TEST_PROJECT_HASHES`).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn project_hashes() -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    return imp::project_hashes().cloned();
    #[cfg(not(debug_assertions))]
    None
}

/// Where the broker writes the state the fixtures assert
/// (`ATEM_TEST_STATE_DUMP`).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn state_dump() -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    return imp::state_dump().cloned();
    #[cfg(not(debug_assertions))]
    None
}

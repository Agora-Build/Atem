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

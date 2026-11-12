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
//!   - `<dir>/hold_approvals` exists: the worker's approvals pass (reading
//!     requests, hooks that ended) is skipped until it is removed;
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
//!   `CLOCK_MONOTONIC` and boot id, so a test can simulate a reboot. Or
//!   `offsets <wall_ms> <mono_ms> <boot_id>`: the system's wall clock and
//!   `CLOCK_MONOTONIC` plus those offsets (the wall's may be negative), at
//!   every read, so a test moves the clocks with one write and they go on
//!   between writes.
//! - `ATEM_TEST_BUILD=<id>`: this process reports `<id>` as its build
//!   (`cred_agent::build_id`), so a binary test can run a runtime that looks
//!   like another atem build.
//! - `ATEM_TEST_CONTEXT_DIR=<dir>`: context snapshots for isolated binary
//!   tests, named by sha256(reference).json. Never active in release builds.
//!
//! For the r9 fixtures against the real runtime (`tests/r9_runner/`):
//! - `ATEM_TEST_PTY_FAULTS=<dir>`, read by the broker too: while
//!   `<dir>/hold_dispatch` exists, accepted work stays queued (the
//!   fixtures' `hold_dispatch`); while `<dir>/hold_launches` exists, no
//!   reserved launch is handed to the launcher (it stays pending).
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
//!
//! Delegated host work (step 4, Decision 10; nothing is advertised or on
//! without it):
//! - `ATEM_TEST_HOST_FEATURES=host.delegated[,host.alerts]`, read once when
//!   the runtime starts (`host_features`): the features a test or dev host
//!   runs. `host.alerts` without `host.delegated` is ignored, and
//!   `host.senders` or an unknown name refuses the value, both with a
//!   runtime.log line; a refused value turns nothing on. `RuntimeClient`
//!   never passes it to a runtime it starts (`runtime_env_from` drops every
//!   `ATEM_TEST_*`), so only a runtime started with it in its own
//!   environment has it; a release build never reads it.
//! - `ATEM_TEST_HOST_WORK_DRIVE=<dir>` (the delegated fixtures, with
//!   `host.delegated` on): the test plays host-work's side of delegated
//!   tasks (session-v1 R9.14). Once host-work's internal attachment exists,
//!   each pass takes the command files in `<dir>` in name order (removing
//!   each; a name it doesn't know, such as a `*.tmp` being written, is left
//!   alone) and appends one JSON line per command to `<dir>/done`, naming
//!   its `file`:
//!   - `submit-<n>.json` `{session_id, request_id, task_id, sender, text}`:
//!     host-work submits the attempt's prompt on its internal attachment
//!     (acquiring the lease, with the attempt's provenance), as its
//!     dispatcher will: `{code, detail?}` when refused, else the receipt
//!     after the step, `{state, detail?}`;
//!   - `verdict.json` `{"verdict": "go"|"withdraw"}`: what host-work's start
//!     check answers from then on (`go` at each runtime start; the hook
//!     installs the check);
//!   - `withdraw-<n>.json` (as `submit`'s): host-work withdraws the attempt
//!     (its immutable values from those fields): `{withdrawal}`
//!     (`rejected`, `listed`, `reused`, `list_full`, `started`, `halted`);
//!   - `interrupt-<n>.json` `{session_id, request_id, revoke_only?}`: the
//!     interrupt with host authority, through the bridge (so with the
//!     chat's half of the turn check), or its revoke-only call:
//!     `{interrupt}` (`written`, `revoked`, `not_current_turn`,
//!     `not_executing`, `halted`); each write's outcome follows on its own
//!     line, `{report: request_id, outcome}` (`ok`, `consumed`, `dropped`,
//!     `no_effect`, `error_after_queue`).
//!
//!   A command that doesn't parse: `{file, error}`. `RuntimeClient` never
//!   passes it on (as every `ATEM_TEST_*`); release builds compile it out.

/// The delegated host-work features this runtime runs (session-v1 R9.14,
/// host-work-v1 §11.6): off unless the debug-only hook turns them on
/// (`host_features`). `alerts` is never on without `delegated`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostFeatures {
    /// `host.delegated`: the host-work principal, delegated tasks.
    pub delegated: bool,
    /// `host.alerts`: owner alerts (`alert_list`).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub alerts: bool,
}

impl HostFeatures {
    /// A hook value: comma-separated feature names (spaces around them
    /// ignored; empty: none). `host.alerts` without `host.delegated` is
    /// ignored; `host.senders` (never in step 4) or an unknown name refuses
    /// the whole value.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn parse(value: &str) -> Result<Self, String> {
        Self::read(value).map(|(features, _)| features)
    }

    /// [`HostFeatures::parse`], and whether `host.alerts` was named and
    /// ignored for want of `host.delegated`.
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    fn read(value: &str) -> Result<(Self, bool), String> {
        use atem_client::session::host_work::{ALERTS_FEATURE, DELEGATED_FEATURE, SENDERS_FEATURE};
        let value = value.trim();
        let (mut delegated, mut alerts) = (false, false);
        if !value.is_empty() {
            for name in value.split(',').map(str::trim) {
                match name {
                    n if n == DELEGATED_FEATURE => delegated = true,
                    n if n == ALERTS_FEATURE => alerts = true,
                    n if n == SENDERS_FEATURE => {
                        return Err(format!("{SENDERS_FEATURE} is not available"));
                    }
                    n => return Err(format!("unknown feature {n:?}")),
                }
            }
        }
        Ok((
            Self {
                delegated,
                alerts: alerts && delegated,
            },
            alerts && !delegated,
        ))
    }
}

/// One attempt as host-work names it to the drive hook
/// (`ATEM_TEST_HOST_WORK_DRIVE`): its session, its request id and the
/// task it attempts, the task's sender and the prompt's text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub struct DriveAttempt {
    pub session_id: String,
    pub request_id: String,
    pub task_id: String,
    pub sender: String,
    pub text: String,
}

/// What a drive command asks of host-work's side.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub enum DriveAction {
    Submit(DriveAttempt),
    /// The start check's answer: go (`true`) or withdraw.
    Verdict(bool),
    Withdraw(DriveAttempt),
    Interrupt {
        session_id: String,
        request_id: String,
        revoke_only: bool,
    },
    /// The file didn't parse (why).
    Unreadable(String),
}

/// A drive command file and what it asks (`host_work_drive`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub struct DriveCommand {
    pub file: String,
    pub action: DriveAction,
}

/// The drive command a file named `name` holding `text` is; `None` for a
/// name that isn't a command's (`submit-*.json`, `verdict.json`,
/// `withdraw-*.json`, `interrupt-*.json`).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn parse_drive(name: &str, text: &str) -> Option<DriveCommand> {
    let kind = if name == "verdict.json" {
        "verdict"
    } else {
        ["submit", "withdraw", "interrupt"].into_iter().find(|k| {
            name.strip_prefix(k)
                .and_then(|r| r.strip_prefix('-'))
                .and_then(|r| r.strip_suffix(".json"))
                .is_some_and(|n| !n.is_empty() && !n.contains('.'))
        })?
    };
    let action = drive_action(kind, text).unwrap_or_else(DriveAction::Unreadable);
    Some(DriveCommand {
        file: name.to_string(),
        action,
    })
}

fn drive_action(kind: &str, text: &str) -> Result<DriveAction, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let field = |name: &str| {
        v.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("{name} missing"))
    };
    let attempt = || -> Result<DriveAttempt, String> {
        Ok(DriveAttempt {
            session_id: field("session_id")?,
            request_id: field("request_id")?,
            task_id: field("task_id")?,
            sender: field("sender")?,
            text: field("text")?,
        })
    };
    Ok(match kind {
        "submit" => DriveAction::Submit(attempt()?),
        "withdraw" => DriveAction::Withdraw(attempt()?),
        "verdict" => match field("verdict")?.as_str() {
            "go" => DriveAction::Verdict(true),
            "withdraw" => DriveAction::Verdict(false),
            other => return Err(format!("unknown verdict {other:?}")),
        },
        _ => DriveAction::Interrupt {
            session_id: field("session_id")?,
            request_id: field("request_id")?,
            revoke_only: v
                .get("revoke_only")
                .map(|r| r.as_bool().ok_or("revoke_only must be a bool"))
                .transpose()?
                .unwrap_or(false),
        },
    })
}

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

    pub fn approvals_held() -> bool {
        faults_dir().is_some_and(|dir| dir.join("hold_approvals").exists())
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
        let first = parts.next()?;
        let (wall, mono) = if first == "offsets" {
            let wall: i64 = parts.next()?.parse().ok()?;
            let mono: u64 = parts.next()?.parse().ok()?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_millis() as i64;
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `ts` is a valid timespec for the call to fill.
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            let real_mono = ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000;
            (
                u64::try_from(now.checked_add(wall)?).ok()?,
                real_mono.checked_add(mono)?,
            )
        } else {
            (first.parse().ok()?, parts.next()?.parse().ok()?)
        };
        let boot = parts.next()?.to_string();
        Some((wall, mono, boot))
    }

    pub fn hold_dispatch() -> Option<bool> {
        faults_dir().map(|dir| dir.join("hold_dispatch").exists())
    }

    pub fn launches_held() -> bool {
        faults_dir().is_some_and(|dir| dir.join("hold_launches").exists())
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

    pub fn host_features() -> super::HostFeatures {
        static CELL: OnceLock<super::HostFeatures> = OnceLock::new();
        *CELL.get_or_init(|| {
            let Some(value) = std::env::var_os("ATEM_TEST_HOST_FEATURES") else {
                return Default::default();
            };
            let read = value
                .to_str()
                .ok_or_else(|| "not UTF-8".to_string())
                .and_then(super::HostFeatures::read);
            match read {
                Ok((features, ignored)) => {
                    if ignored {
                        eprintln!(
                            "atem runtime: ATEM_TEST_HOST_FEATURES: host.alerts needs host.delegated; ignored"
                        );
                    }
                    if features.delegated {
                        eprintln!(
                            "atem runtime: ATEM_TEST_HOST_FEATURES (debug build): host.delegated on{}",
                            if features.alerts { ", host.alerts on" } else { "" }
                        );
                    }
                    features
                }
                Err(error) => {
                    eprintln!(
                        "atem runtime: ATEM_TEST_HOST_FEATURES refused ({error}); nothing turned on"
                    );
                    Default::default()
                }
            }
        })
    }

    fn drive_dir() -> Option<&'static PathBuf> {
        static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
        env_path("ATEM_TEST_HOST_WORK_DRIVE", &CELL)
    }

    pub fn host_work_drive_on() -> bool {
        drive_dir().is_some()
    }

    /// The command files in the drive directory, in name order, each
    /// removed as it is taken.
    pub fn host_work_drive() -> Vec<super::DriveCommand> {
        let Some(dir) = drive_dir() else {
            return Vec::new();
        };
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        let mut commands = Vec::new();
        for name in names {
            let path = dir.join(&name);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Some(command) = super::parse_drive(&name, &text) else {
                continue;
            };
            if std::fs::remove_file(&path).is_ok() {
                commands.push(command);
            }
        }
        commands
    }

    pub fn host_work_driven(line: &serde_json::Value) {
        use std::io::Write;
        let Some(dir) = drive_dir() else { return };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("done"))
        {
            let _ = writeln!(f, "{line}");
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

/// The delegated host-work features (`ATEM_TEST_HOST_FEATURES`, read once:
/// Decision 10 of step 4). Release builds: always off.
pub fn host_features() -> HostFeatures {
    #[cfg(debug_assertions)]
    return imp::host_features();
    #[cfg(not(debug_assertions))]
    HostFeatures::default()
}

/// The drive hook is set (`ATEM_TEST_HOST_WORK_DRIVE`). Release builds:
/// never.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn host_work_drive_on() -> bool {
    #[cfg(debug_assertions)]
    return imp::host_work_drive_on();
    #[cfg(not(debug_assertions))]
    false
}

/// The drive hook's command files, taken in name order (each removed).
/// Release builds: none, and nothing is read.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn host_work_drive() -> Vec<DriveCommand> {
    #[cfg(debug_assertions)]
    return imp::host_work_drive();
    #[cfg(not(debug_assertions))]
    Vec::new()
}

/// Appends a drive result line to `<dir>/done`.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn host_work_driven(_line: &serde_json::Value) {
    #[cfg(debug_assertions)]
    imp::host_work_driven(_line);
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

/// The worker's approvals pass is held.
pub fn approvals_held() -> bool {
    #[cfg(debug_assertions)]
    return imp::approvals_held();
    #[cfg(not(debug_assertions))]
    false
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

/// Reserved launches stay pending (`<pty faults>/hold_launches`).
#[cfg(debug_assertions)]
pub fn launches_held() -> bool {
    imp::launches_held()
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

pub fn context_dir() -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    return std::env::var_os("ATEM_TEST_CONTEXT_DIR").map(std::path::PathBuf::from);
    #[cfg(not(debug_assertions))]
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(delegated: bool, alerts: bool) -> HostFeatures {
        HostFeatures { delegated, alerts }
    }

    /// Decision 10: `host.delegated[,host.alerts]`; `host.alerts` alone is
    /// ignored; `host.senders` (never advertised in step 4) and any unknown
    /// name refuse the whole value, so nothing is turned on.
    #[test]
    fn host_features_parse_refuses_host_senders_and_unknown_names() {
        assert_eq!(HostFeatures::parse(""), Ok(on(false, false)));
        assert_eq!(HostFeatures::parse("host.delegated"), Ok(on(true, false)));
        assert_eq!(
            HostFeatures::parse("host.delegated,host.alerts"),
            Ok(on(true, true))
        );
        assert_eq!(
            HostFeatures::parse(" host.alerts , host.delegated "),
            Ok(on(true, true))
        );
        assert_eq!(HostFeatures::parse("host.alerts"), Ok(on(false, false)));
        for refused in [
            "host.senders",
            "host.delegated,host.senders",
            "host.senders,host.delegated,host.alerts",
            "host.delegate",
            "HOST.DELEGATED",
            "host.delegated,",
            "host.delegated;host.alerts",
            "host.reply",
            "host.work",
        ] {
            let error = HostFeatures::parse(refused).expect_err(refused);
            assert!(!error.is_empty(), "{refused}");
        }
        assert!(
            HostFeatures::parse("host.delegated,host.senders")
                .unwrap_err()
                .contains("host.senders")
        );
    }

    /// The drive hook's file names and contents (`ATEM_TEST_HOST_WORK_DRIVE`):
    /// commands by name, anything else left alone, a command that doesn't
    /// parse reported as unreadable.
    #[test]
    fn drive_commands_parse_by_name() {
        let attempt = r#"{"session_id": "ses-aaaaaaaaaaaa", "request_id": "r1",
            "task_id": "t1", "sender": "member:dev-phone", "text": "run the tests"}"#;
        let want = DriveAttempt {
            session_id: "ses-aaaaaaaaaaaa".into(),
            request_id: "r1".into(),
            task_id: "t1".into(),
            sender: "member:dev-phone".into(),
            text: "run the tests".into(),
        };
        let action = |name: &str, text: &str| parse_drive(name, text).map(|c| c.action);
        assert_eq!(
            parse_drive("submit-1.json", attempt),
            Some(DriveCommand {
                file: "submit-1.json".into(),
                action: DriveAction::Submit(want.clone()),
            })
        );
        assert_eq!(
            action("withdraw-12.json", attempt),
            Some(DriveAction::Withdraw(want))
        );
        assert_eq!(
            action("verdict.json", r#"{"verdict": "withdraw"}"#),
            Some(DriveAction::Verdict(false))
        );
        assert_eq!(
            action("verdict.json", r#"{"verdict": "go"}"#),
            Some(DriveAction::Verdict(true))
        );
        assert_eq!(
            action(
                "interrupt-3.json",
                r#"{"session_id": "s", "request_id": "r", "revoke_only": true}"#
            ),
            Some(DriveAction::Interrupt {
                session_id: "s".into(),
                request_id: "r".into(),
                revoke_only: true,
            })
        );
        assert_eq!(
            action(
                "interrupt-4.json",
                r#"{"session_id": "s", "request_id": "r"}"#
            ),
            Some(DriveAction::Interrupt {
                session_id: "s".into(),
                request_id: "r".into(),
                revoke_only: false,
            })
        );
        // Not commands: left alone (a file being written, the results).
        for name in [
            "submit-1.json.tmp",
            "submit-.json",
            "submit-1.txt",
            "done",
            "verdict.json.tmp",
            "submits-1.json",
        ] {
            assert_eq!(parse_drive(name, attempt), None, "{name}");
        }
        // Commands that don't parse.
        for (name, text) in [
            ("submit-1.json", "{"),
            ("submit-1.json", r#"{"session_id": "s"}"#),
            ("verdict.json", r#"{"verdict": "maybe"}"#),
            (
                "interrupt-1.json",
                r#"{"session_id": "s", "request_id": "r", "revoke_only": 1}"#,
            ),
        ] {
            assert!(
                matches!(action(name, text), Some(DriveAction::Unreadable(_))),
                "{name} {text}"
            );
        }
    }

    /// Release builds compile the drive hook out: nothing is read or
    /// removed.
    #[cfg(not(debug_assertions))]
    #[test]
    fn host_work_drive_is_off_in_release() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("verdict.json");
        std::fs::write(&file, r#"{"verdict": "go"}"#).unwrap();
        // SAFETY: no other test reads or writes this variable, and release
        // builds never read it at all.
        unsafe { std::env::set_var("ATEM_TEST_HOST_WORK_DRIVE", dir.path()) };
        assert!(!host_work_drive_on());
        assert!(host_work_drive().is_empty());
        host_work_driven(&serde_json::json!({"file": "verdict.json"}));
        assert!(file.exists());
        assert!(!dir.path().join("done").exists());
    }

    /// Release builds compile the hook out: the variable turns nothing on.
    #[cfg(not(debug_assertions))]
    #[test]
    fn host_features_are_off_in_release() {
        // SAFETY: no other test reads or writes this variable, and release
        // builds never read it at all.
        unsafe { std::env::set_var("ATEM_TEST_HOST_FEATURES", "host.delegated,host.alerts") };
        assert_eq!(host_features(), HostFeatures::default());
        assert!(!host_features().delegated && !host_features().alerts);
    }
}

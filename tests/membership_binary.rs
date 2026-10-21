//! The r9 device list in the real `atem runtime` process (§R9.3–§R9.5):
//! a temp profile pinned to the vectors' log, carriages applied as the
//! runtime's own relay fetch, and the debug-only hooks
//! (`ATEM_TEST_MEMBERSHIP_FAULTS`, `ATEM_TEST_HOST_CLOCK`;
//! `src/runtime/test_hooks.rs`) to fail a write step, abort the process
//! between the commit and its fences, or move the host clock across a
//! simulated reboot. Every check reads the real files the runtime wrote.
//!
//! The hooks exist only in debug builds; under `--release` these tests are
//! ignored.
mod support;

use atem_client::canonical::StrictValue;
use atem_client::encoding::Hash32;
use atem_client::membership::{Entry, HostNow, Membership};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(15);
const WALL0: u64 = 1_793_264_000_000;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("designs/protocol/fixtures")
}

/// The vectors' entries by label (wire objects).
fn vector(label: &str) -> Value {
    let file: Value = serde_json::from_slice(
        &std::fs::read(fixtures().join("r9-vectors-membership-log.json")).unwrap(),
    )
    .unwrap();
    for list in ["log", "others"] {
        for v in file[list].as_array().unwrap() {
            if v["label"] == label {
                return v["entry"].clone();
            }
        }
    }
    panic!("no vector {label}")
}

fn hash(label: &str) -> String {
    StrictValue::parse(vector(label).to_string().as_bytes(), usize::MAX)
        .map(|s| Entry::from_strict(&s).unwrap().hash().to_hex())
        .unwrap()
}

fn private(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

struct Box_ {
    sandbox: support::Sandbox,
    faults: PathBuf,
    clock: PathBuf,
    runtime: Option<Child>,
    starts: u32,
}

impl Box_ {
    /// A profile whose device list is pinned at E1..E6 (as `atem pair`
    /// will write it), its fences applied.
    fn new() -> Box_ {
        let sandbox = support::Sandbox::new();
        let config = sandbox.config();
        let pairing = config.join("pairing");
        let journal = config.join("runtime").join("journal");
        private(&pairing);
        private(&config.join("runtime"));
        private(&journal);
        let entries: Vec<Entry> = ["E1", "E2", "E3", "E4", "E5", "E6"]
            .iter()
            .map(|l| {
                Entry::from_strict(
                    &StrictValue::parse(vector(l).to_string().as_bytes(), usize::MAX).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let now = HostNow {
            wall_ms: WALL0,
            mono_ms: 1_000,
            boot_id: "boot-1".into(),
        };
        let genesis = Hash32::from_hex(&hash("E1")).unwrap();
        let m = Membership::verify_chain("acct-test-1", &genesis, &entries, &now)
            .unwrap()
            .membership;
        let mut state = m.to_stored();
        state["v"] = json!(1);
        state["host"] = json!({"host_id": "host-a", "host_trust_gen": 1});
        let write = |path: PathBuf, text: String| {
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write(pairing.join("membership.json"), state.to_string());
        write(
            journal.join("membership_applied"),
            json!({"seq": 6, "hash": hash("E6")}).to_string(),
        );
        let faults = sandbox.dir.path().join("faults");
        std::fs::create_dir_all(&faults).unwrap();
        let clock = sandbox.dir.path().join("host-clock");
        Box_ {
            sandbox,
            faults,
            clock,
            runtime: None,
            starts: 0,
        }
    }

    fn pairing(&self) -> PathBuf {
        self.sandbox.config().join("pairing")
    }

    fn journal(&self) -> PathBuf {
        self.sandbox.config().join("runtime").join("journal")
    }

    fn mark(&self, name: &str, text: &str) {
        std::fs::write(self.faults.join(name), text).unwrap();
    }

    fn carry(&self, labels: &[&str]) {
        let entries: Vec<Value> = labels.iter().map(|l| vector(l)).collect();
        self.mark("carry.json", &json!({ "entries": entries }).to_string());
    }

    fn set_clock(&self, wall: u64, mono: u64, boot: &str) {
        std::fs::write(&self.clock, format!("{wall} {mono} {boot}")).unwrap();
    }

    fn log(&self) -> String {
        (0..self.starts)
            .map(|i| {
                std::fs::read_to_string(self.sandbox.dir.path().join(format!("runtime-{i}.log")))
                    .unwrap_or_default()
            })
            .collect()
    }

    fn start(&mut self, host_clock: bool) {
        let log = std::fs::File::create(
            self.sandbox
                .dir
                .path()
                .join(format!("runtime-{}.log", self.starts)),
        )
        .unwrap();
        self.starts += 1;
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", "ws://127.0.0.1:1/ws")
            .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
            .env("ATEM_TEST_MEMBERSHIP_FAULTS", &self.faults);
        if host_clock {
            command.env("ATEM_TEST_HOST_CLOCK", &self.clock);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.runtime = Some(child);
        let config = self.sandbox.config();
        self.until("the runtime to listen", || {
            config.join("runtime.socket").exists()
                && std::fs::read_to_string(config.join("runtime.lock"))
                    .is_ok_and(|pid| !pid.trim().is_empty())
        });
    }

    /// SIGTERM: an orderly stop.
    fn stop(&mut self) {
        let mut child = self.runtime.take().unwrap();
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + WAIT;
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the runtime didn't stop");
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = std::fs::remove_file(self.sandbox.config().join("runtime.socket"));
    }

    /// Waits for the runtime to exit on its own; its status.
    fn exited(&mut self) -> std::process::ExitStatus {
        let mut child = self.runtime.take().unwrap();
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let _ = std::fs::remove_file(self.sandbox.config().join("runtime.socket"));
                return status;
            }
            assert!(Instant::now() < deadline, "the runtime didn't exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[track_caller]
    fn until(&self, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The outcome lines of the test carriages.
    fn carried(&self) -> Vec<String> {
        std::fs::read_to_string(self.faults.join("carried"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn read(&self, path: PathBuf) -> Option<Value> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    fn state(&self) -> Value {
        self.read(self.pairing().join("membership.json")).unwrap()
    }

    fn head_seq(&self) -> u64 {
        self.state()["head"]["seq"].as_u64().unwrap()
    }

    fn applied_seq(&self) -> u64 {
        self.read(self.journal().join("membership_applied"))
            .unwrap()["seq"]
            .as_u64()
            .unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.pairing().join(name).exists()
    }

    /// The durable principal record (`principals`: `<len> <crc> <json>`).
    fn principal(&self, principal: &str) -> Option<Value> {
        let text = std::fs::read_to_string(self.journal().join("principals")).ok()?;
        let json = text.splitn(3, ' ').nth(2)?.trim_end();
        let file: Value = serde_json::from_str(json).ok()?;
        let p = file["principals"].get(principal)?.clone();
        Some(p)
    }
}

impl Drop for Box_ {
    fn drop(&mut self) {
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

const SVC: &str = "service:svc-discord";

/// The runtime is killed (SIGKILL, by a hook) right after `membership.json`
/// with the removal E7 is durable, before any fence. The next runtime
/// replays the carriage record and the fences after `membership_applied`
/// before any remote admission, writes the bot's fence once (naming
/// entry 7), and isn't held (a plain crash records no fault). Later starts
/// never raise it again.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_runtime_killed_between_commit_and_fences_replays_them_at_start() {
    let mut b = Box_::new();
    b.mark("crash_after_commit", "");
    b.carry(&["E7"]);
    b.start(false);
    let status = b.exited();
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{}", b.log());
    assert_eq!(b.head_seq(), 7, "the commit was durable");
    assert!(b.exists("membership.intent") && b.exists("membership.carriage"));
    assert_eq!(b.applied_seq(), 6, "no fence was applied");
    assert!(b.principal(SVC).is_none());

    b.start(false);
    // The start's whole replay is done once the runtime logs it (the
    // applied head is written before the leftover intent is removed).
    b.until("the fences replayed", || b.log().contains("replayed"));
    assert_eq!(b.applied_seq(), 7);
    let fence = b.principal(SVC).unwrap();
    assert_eq!(fence["control"], false);
    assert_eq!(fence["control_gen"], 2);
    assert_eq!(fence["fence_seq"], 7);
    assert!(!b.exists("membership.intent") && !b.exists("membership.carriage"));
    assert!(!b.exists("membership.fault"), "a crash records no fault");
    assert!(b.log().contains("replayed"), "{}", b.log());
    assert!(!b.log().contains("held ("));
    b.stop();
    assert_eq!(
        b.state()["checkpoint"]["runtime_epoch"],
        2,
        "clean checkpoint"
    );

    b.start(false);
    std::thread::sleep(Duration::from_millis(500));
    b.stop();
    assert_eq!(b.principal(SVC).unwrap()["control_gen"], 2, "raised once");
}

/// A device-list write step fails in the runtime: the run fails closed
/// (the fault is recorded, the journal halts so the stop isn't clean,
/// local use goes on) and every later carriage is refused unread. The
/// next runtime replays the carriage record (when it was durable) and is
/// held until a manager reconciles.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_write_fault_in_the_runtime_halts_and_the_next_start_is_held() {
    // (marker, the carriage record was durable, membership.json holds E7
    // right after the fault: an uncertain rename)
    for (marker, recorded, renamed) in [
        ("state:temp_write", true, false),
        ("state:temp_fsync", true, false),
        ("state:rename", true, false),
        ("state:directory_fsync", true, true),
        ("intent:temp_write", true, false),
        ("intent:directory_fsync", true, false),
        ("carriage:temp_fsync", false, false),
    ] {
        let mut b = Box_::new();
        b.mark("fail_next", marker);
        b.carry(&["E7"]);
        b.start(false);
        b.until("the carriage", || !b.carried().is_empty());
        assert!(
            b.carried()[0].starts_with("NotRecorded"),
            "{marker}: {:?}",
            b.carried()
        );
        assert!(b.exists("membership.fault"), "{marker}");
        assert_eq!(b.exists("membership.carriage"), recorded, "{marker}");
        assert_eq!(b.head_seq(), if renamed { 7 } else { 6 }, "{marker}");
        let fault = b.read(b.pairing().join("membership.fault")).unwrap();
        assert_eq!(fault["runtime_epoch"], 1, "{marker}");
        // Faulted for the run: the next carriage is refused unread.
        b.carry(&["E7"]);
        b.until("the second carriage", || b.carried().len() == 2);
        assert!(b.carried()[1].starts_with("Refused"), "{marker}");
        // Local use goes on: the runtime still serves its socket.
        let (out, err, ok) = b.sandbox.atem(&["agent", "list"]);
        assert!(ok, "{marker}: {out}{err}");
        b.stop();
        assert!(
            b.log().contains("not closed cleanly"),
            "{marker}: the halted journal writes no clean close\n{}",
            b.log()
        );

        b.start(false);
        b.until("the restart", || b.log().contains("held ("));
        if recorded {
            assert_eq!(b.head_seq(), 7, "{marker}: replayed");
            b.until("the replayed fence", || b.principal(SVC).is_some());
            assert_eq!(b.principal(SVC).unwrap()["control_gen"], 2, "{marker}");
        } else {
            assert_eq!(b.head_seq(), 6, "{marker}: never evaluated");
        }
        assert!(!b.exists("membership.carriage"), "{marker}");
        assert!(
            b.exists("membership.fault"),
            "{marker}: held until reconciled"
        );
        b.stop();
    }
}

/// A recovery entry carried to the runtime waits 24 h on the host clock:
/// the time waited is persisted while it runs and at the stop; after a
/// simulated reboot (another boot id, the monotonic clock restarted, the
/// wall clock far ahead) only the persisted time counts, so it takes
/// effect only once 24 h of host time have passed in total, and that is
/// written to `membership.json`.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_pending_recovery_waits_on_the_host_clock_across_a_reboot() {
    let hour = 3_600_000u64;
    let mut b = Box_::new();
    b.set_clock(WALL0, 1_000, "boot-1");
    b.carry(&["R7"]);
    b.start(true);
    b.until("the carriage", || !b.carried().is_empty());
    assert!(b.carried()[0].starts_with("Committed"), "{:?}", b.carried());
    let record = |b: &Box_| b.state()["recovery"][0].clone();
    assert_eq!(record(&b)["state"], "pending");
    assert_eq!(record(&b)["boot_id"], "boot-1");
    // 10 h of host time: the pass persists it (at least once a minute).
    b.set_clock(WALL0 + 10 * hour, 1_000 + 10 * hour, "boot-1");
    b.until("the time waited", || {
        record(&b)["mono_waited_ms"].as_u64() == Some(10 * hour)
    });
    b.stop();

    // A reboot: 30 h off, a new boot whose clock starts at 5 s.
    b.set_clock(WALL0 + 40 * hour, 5_000, "boot-2");
    b.start(true);
    // The device list opens (and reads the host clock) after the socket
    // listens: move the clock only once it has.
    b.until("the device list to open", || {
        b.log().matches("host_channel_key is missing").count() >= 2
    });
    b.set_clock(WALL0 + 40 * hour + 13 * hour, 5_000 + 13 * hour, "boot-2");
    b.until("the time waited after the reboot", || {
        record(&b)["mono_waited_ms"].as_u64() == Some(23 * hour)
    });
    assert_eq!(record(&b)["state"], "pending", "23 h of host time");
    b.set_clock(
        WALL0 + 40 * hour + 14 * hour,
        5_000 + 14 * hour + 1,
        "boot-2",
    );
    b.until("the recovery in effect", || record(&b)["state"] == "active");
    assert_eq!(record(&b)["reason"], "wait_ended");
    b.stop();
}

/// Re-review N3: the hold an observed write fault put on the host isn't
/// lifted by losing one of its two records: with `membership.fault` (or
/// its mirror, `runtime/journal/membership_fault`) removed, `atem status`
/// still says held and the next runtime starts held.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn losing_one_fault_record_keeps_the_runtime_held() {
    for lost in ["pairing", "journal"] {
        let mut b = Box_::new();
        b.mark("fail_next", "state:temp_write");
        b.carry(&["E7"]);
        b.start(false);
        b.until("the carriage", || !b.carried().is_empty());
        assert!(b.exists("membership.fault"), "{lost}");
        assert!(b.journal().join("membership_fault").exists(), "{lost}");
        b.stop();
        let path = match lost {
            "pairing" => b.pairing().join("membership.fault"),
            _ => b.journal().join("membership_fault"),
        };
        std::fs::remove_file(&path).unwrap();
        let (out, err, _) = b.sandbox.atem(&["status"]);
        assert!(
            out.contains("held (a device-list write fault"),
            "{lost}: {out}{err}"
        );
        b.start(false);
        b.until("the restart", || b.log().contains("held ("));
        b.stop();
    }
}

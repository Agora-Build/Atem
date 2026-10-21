//! The revoked grants journal's quarantine (atem-session-v1.md §R9.6) in the
//! real `atem runtime` process: a temp profile with a pinned device list,
//! the runtime's link to a fake Astation, a phone and browsers that are the
//! shared core (`atem_client::connect`) in the channel envelope on that
//! link, the device list's host clock moved by the test
//! (`ATEM_TEST_HOST_CLOCK`, debug builds), and the runtime restarted over
//! the same journal. A damaged `revoked_grants` refuses every browser grant
//! until the wall clock passed the recorded end and the process saw the
//! whole window on its monotonic clock; a revocation written meanwhile, or
//! a restart, never drops that.
#![cfg(target_os = "linux")]

mod support;

use atem_client::connect::{Attached, Event as CEvent, Identity};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::{Router, client_ms, write_pin};
use support::r9log::{self, TestLog, auth, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-revoked";
const HOST: &str = "host-revoked";
const MIN: u64 = 60_000;
/// Grant lifetime + `issued_at` skew (the quarantine's length).
const WINDOW: u64 = 65 * MIN;
const UNREADABLE: &str = "revoked grants unreadable";

/// The device list's host clock (`ATEM_TEST_HOST_CLOCK`): the real wall
/// clock plus a signed offset and the real monotonic clock plus an offset,
/// both moved by the test, one boot id; rewritten every 20 ms.
struct HostClock {
    path: PathBuf,
    wall_offset: Arc<AtomicI64>,
    mono_offset: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

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
    fn start(dir: &Path) -> HostClock {
        let path = dir.join("host-clock");
        let wall_offset = Arc::new(AtomicI64::new(0));
        let mono_offset = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let write = {
            let path = path.clone();
            let wall_offset = wall_offset.clone();
            let mono_offset = mono_offset.clone();
            move || {
                let wall = r9log::host_now().wall_ms as i64 + wall_offset.load(Ordering::SeqCst);
                let mono = real_mono_ms() + mono_offset.load(Ordering::SeqCst);
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, format!("{wall} {mono} boot-revoked")).unwrap();
                std::fs::rename(&tmp, &path).unwrap();
            }
        };
        write();
        let s = stop.clone();
        std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                write();
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        HostClock {
            path,
            wall_offset,
            mono_offset,
            stop,
        }
    }

    /// Sets the wall clock `ms` from the real one (negative: behind).
    fn set_wall(&self, ms: i64) {
        self.wall_offset.store(ms, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
    }

    /// Moves the monotonic clock `ms` on (it never goes back).
    fn add_mono(&self, ms: u64) {
        self.mono_offset.fetch_add(ms, Ordering::SeqCst);
        // A pass (100 ms) sees it.
        std::thread::sleep(Duration::from_millis(400));
    }

    fn wall(&self) -> u64 {
        (r9log::host_now().wall_ms as i64 + self.wall_offset.load(Ordering::SeqCst)) as u64
    }
}

impl Drop for HostClock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    runtime: Option<Child>,
    log: TestLog,
    clock: HostClock,
}

impl Rig {
    /// A verified pairing as `HOST` and its device list (the Mac genesis,
    /// this host and a phone with `control`).
    fn new() -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("revoked host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("revoked astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native("dev-phone", &["control", "view"]);
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        let clock = HostClock::start(sandbox.dir.path());
        Rig {
            sandbox,
            astation: FakeAstation::start(),
            runtime: None,
            log,
            clock,
        }
    }

    fn journal(&self) -> PathBuf {
        self.sandbox.config().join("runtime").join("journal")
    }

    fn revoked_file(&self) -> PathBuf {
        self.journal().join("revoked_grants")
    }

    fn start(&mut self) {
        let config = self.sandbox.config();
        let _ = std::fs::remove_file(config.join("runtime.socket"));
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.sandbox.dir.path().join("runtime.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", &self.astation.url)
            .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
            .env("ATEM_TEST_HOST_CLOCK", &self.clock.path)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.runtime = Some(child);
        within("the runtime to listen", || {
            config.join("runtime.socket").exists()
        });
    }

    /// Stops the runtime: SIGKILL (`kill`) or SIGTERM (an orderly stop).
    fn stop(&mut self, kill: bool) {
        let mut child = self.runtime.take().expect("a runtime");
        if kill {
            let _ = child.kill();
        } else {
            // SAFETY: signalling the child this test started.
            unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        }
        let _ = child.wait();
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    fn revoked_text(&self) -> String {
        String::from_utf8_lossy(&std::fs::read(self.revoked_file()).unwrap_or_default())
            .into_owned()
    }

    /// The damaged copies kept aside.
    fn kept_aside(&self) -> Vec<PathBuf> {
        let mut kept: Vec<PathBuf> = std::fs::read_dir(self.journal())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("revoked_grants.damaged-")
            })
            .collect();
        kept.sort();
        kept
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A grant from the phone for a browser on this host, issued now on the
/// host's clock, `life` ms long.
fn grant(log: &mut TestLog, clock: &HostClock, grant_id: &str, life: u64) -> Identity {
    let wall = clock.wall();
    let (grant, key) = log.grant(
        "dev-phone",
        grant_id,
        HOST,
        1,
        None,
        &["view"],
        wall,
        wall + life,
    );
    Identity::browser(grant, key).unwrap()
}

fn phone() -> Identity {
    Identity::native("dev-phone", auth("dev-phone"))
}

/// Inits are answered one a second per link (§R9.7a).
fn next_init() {
    std::thread::sleep(Duration::from_millis(1_100));
}

/// A browser on `handle` with `identity` is refused `busy` "revoked grants
/// unreadable".
fn quarantined(router: &mut Router<'_>, rig: &Rig, handle: &str, identity: &Identity) {
    next_init();
    let refused = router
        .connect(handle, &rig.log, HOST, identity)
        .err()
        .unwrap_or_else(|| panic!("{handle} was admitted during the quarantine"));
    assert_eq!(
        refused,
        ("busy".into(), Some(UNREADABLE.into())),
        "{handle}"
    );
}

fn revoke(router: &mut Router<'_>, handle: &str, phone: &mut Attached, grant_id: &str) {
    let (_, frame) = phone.revoke_grant(grant_id, client_ms()).unwrap();
    let events = router.round(handle, phone, &frame).expect("a reply");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, CEvent::GrantRevoked { .. })),
        "{events:?}"
    );
}

const GA: &str = "aaaaaaaa-1111-4111-8111-0000000000a1";
const GB: &str = "aaaaaaaa-1111-4111-8111-0000000000b2";

/// The finding's sequence: grant A revoked and still valid; the file
/// damaged; a restart quarantines and keeps the damaged file aside; the
/// phone revokes B during the quarantine (recorded, with the quarantine);
/// restarts inside the window keep refusing A (and every browser grant);
/// once the wall clock passed the recorded end, a restart still refuses
/// until that process saw the whole window on its monotonic clock; then a
/// grant that was never revoked is admitted again.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_revocation_survives_a_damaged_file_a_later_revocation_and_restarts() {
    let mut rig = Rig::new();
    rig.start();
    // 50 min: A is still valid at every restart inside the window.
    let a = grant(&mut rig.log, &rig.clock, GA, 50 * MIN);
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-1", &rig.log, HOST, &phone())
            .expect("the phone");
        next_init();
        router
            .connect("a-1", &rig.log, HOST, &a)
            .expect("A before its revocation");
        revoke(&mut router, "ph-1", &mut ph, GA);
        next_init();
        assert_eq!(
            router.connect("a-2", &rig.log, HOST, &a).unwrap_err().0,
            "unauthorized"
        );
    }
    assert!(rig.revoked_text().contains(GA), "{}", rig.revoked_text());
    rig.stop(true);
    std::fs::write(rig.revoked_file(), b"\x00damaged").unwrap();

    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-2", &rig.log, HOST, &phone())
            .expect("the phone (members are unaffected)");
        quarantined(&mut router, &rig, "a-3", &a);
        let c = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000c3",
            50 * MIN,
        );
        quarantined(&mut router, &rig, "c-1", &c);
        // The damaged bytes are kept aside, never replaced.
        let kept = rig.kept_aside();
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(std::fs::read(&kept[0]).unwrap(), b"\x00damaged");
        assert_eq!(
            std::fs::metadata(&kept[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        within("the quarantine recorded", || {
            rig.revoked_text().contains("\"quarantine\"")
        });
        // A revocation during the quarantine succeeds and is recorded.
        revoke(&mut router, "ph-2", &mut ph, GB);
        let text = rig.revoked_text();
        assert!(
            text.contains(GB) && text.contains("\"quarantine\""),
            "{text}"
        );
    }
    rig.stop(false);

    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        quarantined(&mut router, &rig, "a-4", &a);
    }
    // Inside the window: 30 min on both clocks, then a restart.
    rig.clock.set_wall(30 * MIN as i64);
    rig.clock.add_mono(30 * MIN);
    rig.stop(true);
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        quarantined(&mut router, &rig, "a-5", &a);
    }
    // Past the recorded end on the wall clock, but this process hasn't
    // seen the window on its monotonic clock: still refused.
    rig.clock.set_wall(70 * MIN as i64);
    rig.stop(true);
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        let d = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000d4",
            50 * MIN,
        );
        quarantined(&mut router, &rig, "d-1", &d);
        rig.clock.add_mono(WINDOW + MIN);
        next_init();
        let d = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000d5",
            50 * MIN,
        );
        router
            .connect("d-2", &rig.log, HOST, &d)
            .expect("a grant never revoked, after the quarantine");
        next_init();
        assert!(
            router.connect("a-6", &rig.log, HOST, &a).is_err(),
            "A expired"
        );
    }
    within("the record dropped", || {
        !rig.revoked_text().contains("\"quarantine\"")
    });
    assert!(rig.revoked_text().contains(GB), "{}", rig.revoked_text());
    assert_eq!(rig.kept_aside().len(), 1);
    let log = rig.runtime_log();
    assert!(log.contains("revoked_grants is unreadable"), "{log}");
}

/// A wall clock set back across a restart can't shorten the quarantine:
/// the record's end holds even after the new process saw the whole window
/// on its monotonic clock; the quarantine ends once the wall clock passes
/// the recorded end.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_wall_clock_set_back_across_a_restart_cant_shorten_the_quarantine() {
    let mut rig = Rig::new();
    std::fs::create_dir_all(rig.journal()).unwrap();
    std::fs::write(rig.revoked_file(), b"{not json").unwrap();
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-1", &rig.log, HOST, &phone())
            .expect("the phone");
        let b = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000e1",
            50 * MIN,
        );
        quarantined(&mut router, &rig, "b-1", &b);
        // A revocation during the quarantine rewrites the file.
        revoke(&mut router, "ph-1", &mut ph, GB);
    }
    let text = rig.revoked_text();
    let record: serde_json::Value = serde_json::from_str(&text).unwrap();
    let until = record["quarantine"]["until"].as_u64().expect("the record");
    let started = record["quarantine"]["started_at"].as_u64().unwrap();
    assert_eq!(until - started, WINDOW);
    rig.stop(false);

    // Two hours back; the new process sees the whole window and more on
    // its monotonic clock.
    rig.clock.set_wall(-120 * MIN as i64);
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        let b = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000e2",
            50 * MIN,
        );
        // Refused (the process has taken the quarantine by then), and
        // still refused once it saw the whole window and more.
        quarantined(&mut router, &rig, "b-2", &b);
        rig.clock.add_mono(WINDOW + 5 * MIN);
        quarantined(&mut router, &rig, "b-2b", &b);
        // The wall clock passes the recorded end.
        let ahead = until - r9log::host_now().wall_ms + MIN;
        rig.clock.set_wall(ahead as i64);
        std::thread::sleep(Duration::from_millis(300));
        next_init();
        let b = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000e3",
            50 * MIN,
        );
        router
            .connect("b-3", &rig.log, HOST, &b)
            .expect("admitted once the wall clock passed the recorded end");
    }
}

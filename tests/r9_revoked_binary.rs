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

/// Astation's trace (comment 6307612632): A issued at 12:00 for an hour
/// and revoked at 12:01; the file damaged at 12:02 (quarantined until
/// 13:07); the wall clock set back to 10:00, the rewritten file damaged
/// again and the runtime restarted; 66 min later on both clocks (wall
/// 11:06) the quarantine must not have lifted, and when the wall clock
/// returns to 12:10, A (still within its validity, its entry lost with the
/// second damage) must still be refused. A native revocation during it is
/// recorded; after the original end a fresh browser is admitted and a
/// native revocation fences it live.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_second_damage_after_the_clock_went_back_keeps_the_earlier_end() {
    let mut rig = Rig::new();
    rig.start();
    // 12:00: A, an hour long.
    let a = grant(&mut rig.log, &rig.clock, GA, 60 * MIN);
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-1", &rig.log, HOST, &phone())
            .expect("the phone");
        next_init();
        router
            .connect("a-1", &rig.log, HOST, &a)
            .expect("A before its revocation");
        // 12:01: revoked.
        rig.clock.set_wall(MIN as i64);
        revoke(&mut router, "ph-1", &mut ph, GA);
    }
    rig.stop(true);
    // 12:02: the first damage.
    std::fs::write(rig.revoked_file(), b"\x00damaged once").unwrap();
    rig.clock.set_wall(2 * MIN as i64);
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        quarantined(&mut router, &rig, "a-2", &a);
        within("the first quarantine recorded", || {
            rig.revoked_text().contains("\"quarantine\"")
        });
    }
    let record: serde_json::Value = serde_json::from_str(&rig.revoked_text()).unwrap();
    let first_end = record["quarantine"]["until"].as_u64().unwrap();
    rig.stop(true);

    // 10:00: the wall clock set back; the rewritten file damaged again.
    rig.clock.set_wall(-120 * MIN as i64);
    std::fs::write(rig.revoked_file(), b"\x00damaged twice").unwrap();
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-2", &rig.log, HOST, &phone())
            .expect("the phone (members are unaffected)");
        let b = grant(&mut rig.log, &rig.clock, GB, 50 * MIN);
        quarantined(&mut router, &rig, "b-1", &b);
        within("the second quarantine recorded", || {
            rig.revoked_text().contains("\"quarantine\"")
        });
        // The second record keeps the first end.
        let record: serde_json::Value = serde_json::from_str(&rig.revoked_text()).unwrap();
        assert!(
            record["quarantine"]["until"].as_u64().unwrap() >= first_end,
            "{record}"
        );
        // A native revocation during it is recorded.
        revoke(&mut router, "ph-2", &mut ph, GB);
        assert!(rig.revoked_text().contains(GB), "{}", rig.revoked_text());

        // 11:06: 66 min later on both clocks. The second quarantine alone
        // would have ended; a fresh grant is still refused.
        rig.clock.set_wall(-54 * MIN as i64);
        rig.clock.add_mono(66 * MIN);
        let c = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000c6",
            50 * MIN,
        );
        quarantined(&mut router, &rig, "c-1", &c);

        // 12:10: the wall clock is back. A is still within its validity
        // and its entry was lost with the damage: refused.
        rig.clock.set_wall(10 * MIN as i64);
        quarantined(&mut router, &rig, "a-3", &a);
        let c = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000c7",
            50 * MIN,
        );
        quarantined(&mut router, &rig, "c-2", &c);

        // Past the first end (13:07): a fresh grant is admitted and a
        // native revocation fences it live.
        rig.clock
            .set_wall((first_end - r9log::host_now().wall_ms + MIN) as i64);
        let d_id = "aaaaaaaa-1111-4111-8111-0000000000d8";
        let d = grant(&mut rig.log, &rig.clock, d_id, 50 * MIN);
        next_init();
        let mut live = router
            .connect("d-1", &rig.log, HOST, &d)
            .expect("a grant never revoked, after the first end");
        revoke(&mut router, "ph-2", &mut ph, d_id);
        let mut fenced = false;
        while let Ok(events) = router.events("d-1", &mut live) {
            fenced |= events.iter().any(|e| {
                matches!(e, CEvent::Fenced(e) | CEvent::Error(e)
                    if e.code == "unauthorized"
                        && e.detail.as_deref() == Some("grant revoked"))
            });
        }
        assert!(fenced, "the live browser is fenced by the revocation");
        next_init();
        assert_eq!(
            router.connect("d-2", &rig.log, HOST, &d).unwrap_err().0,
            "unauthorized"
        );
        // A has expired by then; still refused.
        next_init();
        assert!(router.connect("a-4", &rig.log, HOST, &a).is_err());
    }
    assert_eq!(rig.kept_aside().len(), 2, "{:?}", rig.kept_aside());
}

/// A live browser on `handle` is fenced by the phone's revocation of
/// `grant_id` ("grant revoked"), and refused after that (with
/// `again_code` when given).
#[allow(clippy::too_many_arguments)]
fn revoke_live(
    router: &mut Router<'_>,
    rig: &Rig,
    ph_handle: &str,
    ph: &mut Attached,
    handle: &str,
    live: &mut Attached,
    grant_id: &str,
    identity: &Identity,
    again_code: Option<&str>,
) {
    revoke(router, ph_handle, ph, grant_id);
    let mut fenced = false;
    while let Ok(events) = router.events(handle, live) {
        fenced |= events.iter().any(|e| {
            matches!(e, CEvent::Fenced(e) | CEvent::Error(e)
                if e.code == "unauthorized"
                    && e.detail.as_deref() == Some("grant revoked"))
        });
    }
    assert!(fenced, "the live browser is fenced by the revocation");
    next_init();
    let Err(again) = router.connect(&format!("{handle}-again"), &rig.log, HOST, identity) else {
        panic!("{handle} admitted again after its revocation");
    };
    if let Some(code) = again_code {
        assert_eq!(again.0, code);
    }
}

/// Astation's comment 6308222846: A issued at 12:00 for an hour and
/// revoked at 12:01; the runtime stopped and only `revoked_grants` lost
/// (the sidecar and the rest of the journal kept); at 12:03 A must be
/// refused (quarantined), and native revocations and live fencing keep
/// working. The same loss during an active quarantine, after the wall
/// clock went back, keeps the earlier end.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_lost_revoked_grants_next_to_its_sidecar_refuses_the_revoked_grant() {
    let mut rig = Rig::new();
    rig.start();
    let a = grant(&mut rig.log, &rig.clock, GA, 60 * MIN);
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-1", &rig.log, HOST, &phone())
            .expect("the phone");
        rig.clock.set_wall(MIN as i64);
        revoke(&mut router, "ph-1", &mut ph, GA);
    }
    assert!(rig.journal().join("revoked_quarantine").exists());
    rig.stop(true);
    std::fs::remove_file(rig.revoked_file()).unwrap();

    // 12:03.
    rig.clock.set_wall(3 * MIN as i64);
    rig.start();
    let first_end;
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-2", &rig.log, HOST, &phone())
            .expect("the phone (members are unaffected)");
        quarantined(&mut router, &rig, "a-1", &a);
        revoke(&mut router, "ph-2", &mut ph, GB);
        let record: serde_json::Value = serde_json::from_str(&rig.revoked_text()).unwrap();
        first_end = record["quarantine"]["until"].as_u64().expect("the record");
        assert!(rig.revoked_text().contains(GB), "{}", rig.revoked_text());
    }
    rig.stop(true);

    // During that quarantine: the wall clock an hour back, the main file
    // lost again. The earlier end holds past the window on both clocks.
    rig.clock.set_wall(-57 * MIN as i64);
    std::fs::remove_file(rig.revoked_file()).unwrap();
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-3", &rig.log, HOST, &phone())
            .expect("the phone");
        quarantined(&mut router, &rig, "a-2", &a);
        within("the second quarantine recorded", || {
            rig.revoked_text().contains("\"quarantine\"")
        });
        let record: serde_json::Value = serde_json::from_str(&rig.revoked_text()).unwrap();
        assert!(
            record["quarantine"]["until"].as_u64().unwrap() >= first_end,
            "{record}"
        );
        rig.clock.set_wall(10 * MIN as i64);
        rig.clock.add_mono(66 * MIN);
        quarantined(&mut router, &rig, "a-3", &a);

        // Past the first end: a fresh grant is admitted and fenced live
        // by a native revocation.
        rig.clock
            .set_wall((first_end - r9log::host_now().wall_ms + MIN) as i64);
        let d_id = "aaaaaaaa-1111-4111-8111-0000000000d9";
        let d = grant(&mut rig.log, &rig.clock, d_id, 50 * MIN);
        next_init();
        let mut live = router
            .connect("d-1", &rig.log, HOST, &d)
            .expect("a grant never revoked, after the first end");
        revoke_live(
            &mut router,
            &rig,
            "ph-3",
            &mut ph,
            "d-1",
            &mut live,
            d_id,
            &d,
            Some("unauthorized"),
        );
    }
    let log = rig.runtime_log();
    assert!(
        log.contains("revoked_grants is unreadable or missing"),
        "{log}"
    );
}

/// The sidecar lost while `revoked_grants` is kept: fail closed, browser
/// grants are quarantined (the bound rebuilt from what is left).
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_lost_sidecar_next_to_revoked_grants_is_quarantined() {
    let mut rig = Rig::new();
    rig.start();
    let a = grant(&mut rig.log, &rig.clock, GA, 50 * MIN);
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-1", &rig.log, HOST, &phone())
            .expect("the phone");
        revoke(&mut router, "ph-1", &mut ph, GA);
    }
    rig.stop(true);
    std::fs::remove_file(rig.journal().join("revoked_quarantine")).unwrap();
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-2", &rig.log, HOST, &phone())
            .expect("the phone");
        quarantined(&mut router, &rig, "a-1", &a);
        let c = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000c1",
            50 * MIN,
        );
        quarantined(&mut router, &rig, "c-1", &c);
        revoke(&mut router, "ph-2", &mut ph, GB);
    }
    assert!(rig.journal().join("revoked_quarantine").exists());
    let log = rig.runtime_log();
    assert!(
        log.contains("revoked_quarantine is unreadable or missing"),
        "{log}"
    );
}

/// Re-review N1a: a grant revoked while it isn't live and the wall clock
/// is two hours behind the high-water mark is kept for the window after
/// the trusted time; when the clock returns (across a restart), it is
/// still refused.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_revocation_while_the_clock_is_behind_outlives_the_rollback() {
    let mut rig = Rig::new();
    rig.start();
    let a = grant(&mut rig.log, &rig.clock, GA, 50 * MIN);
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-1", &rig.log, HOST, &phone())
            .expect("the phone");
        // W: another revocation sets the high-water mark.
        revoke(&mut router, "ph-1", &mut ph, GB);
        rig.clock.set_wall(-120 * MIN as i64);
        revoke(&mut router, "ph-1", &mut ph, GA);
    }
    rig.stop(false);
    rig.clock.set_wall(10 * MIN as i64);
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        router
            .connect("ph-2", &rig.log, HOST, &phone())
            .expect("the phone");
        next_init();
        assert_eq!(
            router.connect("a-1", &rig.log, HOST, &a).unwrap_err().0,
            "unauthorized"
        );
    }
}

/// Re-review N1b: A admitted live at W; the wall clock two hours back;
/// A revoked (kept until its expiry, W + 50); one damage and a restart.
/// After the window on both clocks, and when the wall clock is back at
/// W + 10, A is still refused: the quarantine lasts until its true end.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_live_revocation_during_a_rollback_outlives_one_damage() {
    let mut rig = Rig::new();
    rig.start();
    let a = grant(&mut rig.log, &rig.clock, GA, 50 * MIN);
    {
        let mut router = Router::new(&rig.astation);
        let mut ph = router
            .connect("ph-1", &rig.log, HOST, &phone())
            .expect("the phone");
        next_init();
        let mut live = router
            .connect("a-1", &rig.log, HOST, &a)
            .expect("A before its revocation");
        rig.clock.set_wall(-120 * MIN as i64);
        // Refused "host clock went back" meanwhile.
        revoke_live(
            &mut router,
            &rig,
            "ph-1",
            &mut ph,
            "a-1",
            &mut live,
            GA,
            &a,
            None,
        );
    }
    rig.stop(true);
    std::fs::write(rig.revoked_file(), b"\x00damaged").unwrap();
    rig.start();
    {
        let mut router = Router::new(&rig.astation);
        router
            .connect("ph-2", &rig.log, HOST, &phone())
            .expect("the phone");
        quarantined(&mut router, &rig, "a-2", &a);
        rig.clock.add_mono(WINDOW + MIN);
        // W - 54 (A isn't valid yet on this clock): a fresh grant is
        // refused; the quarantine alone (W - 55) would have ended.
        rig.clock.set_wall(-54 * MIN as i64);
        let c = grant(
            &mut rig.log,
            &rig.clock,
            "aaaaaaaa-1111-4111-8111-0000000000c2",
            50 * MIN,
        );
        quarantined(&mut router, &rig, "c-1", &c);
        rig.clock.set_wall(10 * MIN as i64);
        quarantined(&mut router, &rig, "a-3", &a);
    }
}

//! Sealed push hints and seen (atem-session-v1.md §R9.9) in the real
//! `atem runtime` process: a temp profile with a pinned device list (the
//! Mac genesis, this host, a phone, and a bot without the `approval` op),
//! the runtime's link to a fake Astation that also plays the relay (it
//! reads what Atem sends as `{"type":"relay",…}` and answers `push_ack`),
//! a fake Claude Code (`tests/fixtures/approvals/fake-agent.py`, the real
//! PermissionRequest hook), and clients that are the shared core
//! (`atem_client::connect`) in the channel envelope on that link. Every
//! hint is verified and opened the way a device does (`atem_client::push`).
#![cfg(target_os = "linux")]

mod support;

use atem_client::SignedObject;
use atem_client::connect::{Attached, Event as CEvent, Identity};
use atem_client::push::{self, Hint, HintState, Identity as PushId, Seen, Verifier};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::{Out, Router, client_ms, write_pin};
use support::r9log::{self, MAC, TestLog, auth, enc, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-push";
const HOST: &str = "host-push";
const WAIT: Duration = Duration::from_secs(20);

/// The device list's host clock (`ATEM_TEST_HOST_CLOCK`): the real wall
/// clock plus an offset the test moves, the real monotonic clock and boot
/// id, rewritten every 20 ms (atomically).
struct HostClock {
    path: PathBuf,
    offset: Arc<AtomicU64>,
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
        let offset = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "boot".into());
        let write = {
            let path = path.clone();
            let offset = offset.clone();
            move || {
                let wall = r9log::host_now().wall_ms + offset.load(Ordering::SeqCst);
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, format!("{wall} {} {boot}", real_mono_ms())).unwrap();
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
        HostClock { path, offset, stop }
    }

    /// Moves the host's wall clock `ms` ahead of the real one.
    fn jump(&self, ms: u64) {
        self.offset.store(ms, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
    }

    fn wall(&self) -> u64 {
        r9log::host_now().wall_ms + self.offset.load(Ordering::SeqCst)
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
    clock: Option<HostClock>,
}

impl Rig {
    /// A verified pairing as `HOST` and its device list: the Mac (genesis,
    /// control and manage), this host, a phone (control) and a bot
    /// (`prompt` and `view`: no `approval`) and an approver service
    /// (`approval` and `view`). `held`: a recorded device-list
    /// write fault (the start is held, §R9.3). `host_clock`: the runtime
    /// reads the test's host clock.
    fn new(held: bool, host_clock: bool) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("push host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("push astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native("dev-phone", &["control", "view"]);
        log.add_service(
            "svc-bot",
            &[HOST],
            None,
            &["prompt", "view"],
            r9log::host_now().wall_ms + 3_600_000,
        );
        log.add_service(
            "svc-appr",
            &[HOST],
            None,
            &["approval", "view"],
            r9log::host_now().wall_ms + 3_600_000,
        );
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        if held {
            std::fs::write(
                sandbox.config().join("pairing").join("membership.fault"),
                br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
            )
            .unwrap();
        }
        let clock = host_clock.then(|| HostClock::start(sandbox.dir.path()));
        let mut rig = Rig {
            sandbox,
            astation: FakeAstation::start(),
            runtime: None,
            log,
            clock,
        };
        rig.start();
        rig
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.sandbox.dir.path().join("runtime.log")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", &self.astation.url)
            .env("ASTATION_RELAY_URL", "http://127.0.0.1:1");
        if let Some(clock) = &self.clock {
            command.env("ATEM_TEST_HOST_CLOCK", &clock.path);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.runtime = Some(child);
        let config = self.sandbox.config();
        within("the runtime to listen", || {
            config.join("runtime.socket").exists()
        });
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    fn status(&self) -> String {
        let (out, err, _) = self.sandbox.atem(&["status"]);
        format!("{out}{err}")
    }

    /// A Claude session running the fake agent, detached: its id and the
    /// fake's control directory.
    fn agent(&self) -> (String, PathBuf) {
        let fake = self.sandbox.dir.path().join("fake");
        std::fs::create_dir_all(&fake).unwrap();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        if perms.mode() & 0o111 != 0o111 {
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }
        let mut frontend = self.sandbox.spawn(
            &["agent", "launch", "claude"],
            &self.sandbox.home,
            &[
                ("CLAUDE_CLI_BIN", script.to_str().unwrap()),
                ("FAKE_DIR", fake.to_str().unwrap()),
            ],
        );
        agent_event(&fake, "started");
        let sid = frontend.detach();
        self.sandbox.track();
        (sid, fake)
    }

    /// Hints verified as a device does now (the host's own clock).
    fn hints(&self, message: &Value) -> Vec<Hint> {
        assert_eq!(message["type"], "relay", "{message}");
        assert_eq!(message["op"], "push_hint", "{message}");
        let now = self
            .clock
            .as_ref()
            .map_or_else(|| r9log::host_now().wall_ms, HostClock::wall);
        message["hints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                let o = SignedObject::parse(h.to_string().as_bytes()).unwrap();
                Hint::verify(&o, &self.log.log, now, Verifier::Client).unwrap()
            })
            .collect()
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

fn agent_event(fake: &Path, line: &str) {
    let events = fake.join("events");
    within(&format!("the agent's {line:?}"), || {
        std::fs::read_to_string(&events)
            .unwrap_or_default()
            .lines()
            .any(|l| l.trim_end() == line)
    });
}

/// The fake agent's tool call `n` needing permission.
fn ask(fake: &Path, n: u32) {
    let request = json!({"tool_name": "Bash",
        "tool_input": {"command": "npm test -- --token-free", "description": "run the tests"}});
    let tmp = fake.join(format!("tmp-ask-{n}"));
    std::fs::write(&tmp, request.to_string()).unwrap();
    std::fs::rename(&tmp, fake.join(format!("ask-{n}.json"))).unwrap();
}

fn mac() -> Identity {
    Identity::native(MAC, auth(MAC))
}

fn phone() -> Identity {
    Identity::native("dev-phone", auth("dev-phone"))
}

fn bot() -> Identity {
    Identity::service("svc-bot", auth("svc-bot"))
}

fn next_init() {
    std::thread::sleep(Duration::from_millis(1_100));
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The next relay message (`push_hint` or `push_seen`) within `wait`.
fn relay(router: &mut Router, wait: Duration) -> Option<Value> {
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let v = router.other_within(left)?;
        if v["type"] == "relay" {
            return Some(v);
        }
    }
}

fn expect_relay(router: &mut Router, wait: Duration) -> Value {
    relay(router, wait).expect("a relay message")
}

fn ack(router: &Router, identities: &[PushId]) {
    router.send_raw(push::push_ack(identities).to_string());
}

/// One device's channel: its handle, the shared core's attachment, and
/// what it received but no step took yet.
struct Dev {
    h: String,
    a: Attached,
    backlog: Vec<Value>,
}

fn data_of(e: &CEvent) -> Option<Value> {
    let mut v = match e {
        CEvent::Session(m) => atem_client::session::wire::to_value(
            &atem_client::session::wire::Envelope::Session(m.clone()),
        )["data"]
            .clone(),
        CEvent::Error(e) | CEvent::Fenced(e) => {
            serde_json::from_slice::<Value>(&e.to_bytes()).ok()?["data"].clone()
        }
        CEvent::Seen { re, .. } => json!({"op": "seen", "re": re}),
        CEvent::MembershipHead { re, head, .. } => {
            json!({"op": "membership_head", "re": re, "head": {"seq": head.seq}})
        }
        _ => return None,
    };
    v["__type"] = json!("session");
    Some(v)
}

impl Dev {
    fn connect(
        router: &mut Router,
        h: &str,
        transport: &str,
        log: &TestLog,
        who: &Identity,
    ) -> Dev {
        let a = router
            .connect_via(h, transport, log, HOST, who)
            .unwrap_or_else(|e| panic!("{h} refused: {e:?}"));
        Dev {
            h: h.into(),
            a,
            backlog: Vec::new(),
        }
    }

    fn send(&mut self, router: &mut Router, msg: Value) {
        let frame = self.a.send(&msg, client_ms()).unwrap();
        router.frame(&self.h, &frame);
    }

    fn wait(&mut self, router: &mut Router, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(at) = self.backlog.iter().position(&pred) {
                return self.backlog.remove(at);
            }
            assert!(Instant::now() < deadline, "{}: {:?}", self.h, self.backlog);
            match router.next(&self.h) {
                Out::Frame(f) => {
                    let events = self.a.on_frame(&f, client_ms()).unwrap();
                    self.backlog.extend(events.iter().filter_map(data_of));
                }
                Out::Close(r) => panic!("{} closed ({r:?}): {:?}", self.h, self.backlog),
            }
        }
    }

    fn read(&self, sid: &str) -> Value {
        json!({"target": self.a.target(sid).expect("listed"),
               "attachment_gen": self.a.welcome().attachment_gen})
    }

    fn list(&mut self, router: &mut Router, sid: &str) {
        self.send(
            router,
            json!({"type": "session", "data": {"v": 1, "op": "list", "id": uuid()}}),
        );
        let sessions = self.wait(router, |v| v["op"] == "sessions");
        assert!(
            sessions["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["session_id"] == sid),
            "{}: {sessions}",
            self.h
        );
    }

    /// `approval_seen` for `ap`: the reply (`seen` or an error).
    fn seen(&mut self, router: &mut Router, sid: &str, ap: &str) -> Value {
        let id = uuid();
        self.send(
            router,
            json!({"type": "session", "data": {"v": 1, "op": "approval_seen", "id": id,
                "binding": self.read(sid), "approval_id": ap}}),
        );
        self.wait(router, move |v| v["re"] == id.as_str())
    }
}

/// The phone and the Mac (and the bot) connected, the agent's tool call
/// asked: the approval id the Mac saw, and the first `push_hint`.
/// (Also the Mac's `approval_request`.)
fn approval(
    rig: &Rig,
    router: &mut Router,
    sid: &str,
    fake: &Path,
) -> (Dev, Dev, String, Value, Value) {
    let log = &rig.log;
    let mut m = Dev::connect(router, "mac", "direct", log, &mac());
    next_init();
    let mut p = Dev::connect(router, "phone", "relay", log, &phone());
    m.list(router, sid);
    p.list(router, sid);
    ask(fake, 1);
    let request = m.wait(router, |v| v["op"] == "approval_request");
    let ap = request["approval_id"].as_str().unwrap().to_string();
    p.wait(router, |v| v["op"] == "approval_request");
    let hint = expect_relay(router, WAIT);
    (m, p, ap, hint, request)
}

/// §R9.9: an approval opens and one `push_hint` reaches the relay over
/// Atem's link, with an open hint sealed per native member with control:
/// the phone's atem-client verifies its own (host channel key, account,
/// genesis, host, trust generation, `created_at`/`expires_at` 600 s apart)
/// and opens tool and summary with its `enc_key`; the Mac, another control
/// device, opens its own part and not the phone's. The bot (no `approval`
/// op) gets none, nothing is in clear on the wire, and no r8
/// `push_approval` is ever sent.
#[test]
fn an_approval_reaches_the_relay_sealed_for_the_phone_and_the_mac() {
    let rig = Rig::new(false, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    next_init();
    let (_m, _p, ap, message, request) = {
        let log = &rig.log;
        let mut bt = Dev::connect(&mut router, "bot", "relay", log, &bot());
        next_init();
        let r = approval(&rig, &mut router, &sid, &fake);
        bt.list(&mut router, &sid);
        r
    };
    let text = message.to_string();
    assert!(!text.contains("npm test"), "clear text on the wire: {text}");
    assert!(!text.contains("push_approval"));
    let hs = rig.hints(&message);
    let devices: Vec<String> = hs
        .iter()
        .map(|h| match h.state() {
            HintState::Open { device_id, .. } => device_id.clone(),
            _ => panic!("an open hint"),
        })
        .collect();
    assert_eq!(devices, [MAC, "dev-phone"], "the bot gets none");
    for h in &hs {
        let k = h.key();
        assert_eq!(
            (k.account_id.as_str(), k.host_id.as_str(), k.host_trust_gen),
            (ACCOUNT, HOST, 1)
        );
        assert_eq!(k.genesis_hash, rig.log.genesis_hash().to_hex());
        assert_eq!(
            (k.session_id.as_str(), k.approval_id.as_str()),
            (sid.as_str(), ap.as_str())
        );
        // One clock: the card's `created_at` is the hint's.
        assert_eq!(json!(h.created_at()), request["created_at"]);
        assert_eq!(h.expires_at() - h.created_at(), 600_000);
    }
    let keys = &rig.log.keys;
    let phone_plain = hs[1].open(keys, &enc("dev-phone"), "dev-phone").unwrap();
    assert_eq!(phone_plain.tool, "Bash");
    assert!(phone_plain.summary.contains("npm test"), "{phone_plain:?}");
    let mac_plain = hs[0].open(keys, &enc(MAC), MAC).unwrap();
    assert_eq!(mac_plain, phone_plain);
    assert!(hs[0].open(keys, &enc("dev-phone"), "dev-phone").is_err());
    // The answer closes it: a resolved hint follows (and no r8 push).
    std::fs::write(fake.join("terminal-yes-1"), "").unwrap();
    let resolved = expect_relay(&mut router, WAIT);
    let r = rig.hints(&resolved);
    assert!(matches!(
        r[0].state(),
        HintState::Resolved { reason, .. } if reason == "answered_terminal"
    ));
    let log = rig.runtime_log();
    assert!(log.contains("sealed hint(s)"), "{log}");
    // Nothing of the tool call is logged in clear.
    assert!(!log.contains("npm test"), "{log}");
    assert!(!log.contains(&phone_plain.summary), "{log}");
}

/// §R9.9 reliable delivery: a lost `push_ack` means the same bytes again
/// every 10 s; once the relay acknowledges the phone's hint only the
/// Mac's goes on; `atem status` shows what waits; a reconnect sends what
/// is unacknowledged at once (the same bytes); acknowledged, nothing more.
#[test]
fn a_lost_ack_is_resent_and_a_reconnect_resends() {
    let rig = Rig::new(false, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let (_m, _p, _ap, first, _) = approval(&rig, &mut router, &sid, &fake);
    let at = Instant::now();
    // The ack is lost: the same bytes after 10 s.
    let again = expect_relay(&mut router, Duration::from_secs(15));
    let waited = at.elapsed();
    assert_eq!(again, first, "the same bytes");
    assert!(waited >= Duration::from_secs(8), "{waited:?}");
    within("atem status to show the waiting hints", || {
        rig.status()
            .contains("push: 2 waiting for the relay's acknowledgment")
    });
    let hs = rig.hints(&first);
    ack(&router, &[hs[1].identity()]);
    let mac_only = expect_relay(&mut router, Duration::from_secs(15));
    assert_eq!(mac_only["hints"], json!([first["hints"][0]]));

    // The link drops and comes back: at once, the Mac's hint again.
    rig.astation.close(router.link);
    drop(router);
    let mut router = Router::new(&rig.astation);
    let back = Instant::now();
    let resent = expect_relay(&mut router, Duration::from_secs(15));
    assert!(
        back.elapsed() < Duration::from_secs(5),
        "sent at the reconnect, not at the next 10 s: {:?}",
        back.elapsed()
    );
    assert_eq!(resent["hints"], json!([first["hints"][0]]));
    ack(&router, &[hs[0].identity()]);
    assert_eq!(relay(&mut router, Duration::from_secs(12)), None);
}

/// §R9.9 seen: the phone's first `approval_seen` (it holds `control`, the
/// approval is pending for that session and process) is answered `seen`
/// and becomes a host-signed `push_seen` for `dev-phone`; a repeat is
/// answered `seen` and never re-signed (every later `push_seen` is the
/// first one's bytes); a lost ack resends it; acknowledged, nothing more.
#[test]
fn a_seen_from_the_phone_is_delivered_once_and_deduplicated() {
    let rig = Rig::new(false, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let (_m, mut p, ap, first, _) = approval(&rig, &mut router, &sid, &fake);
    let hs = rig.hints(&first);
    ack(&router, &hs.iter().map(Hint::identity).collect::<Vec<_>>());
    let reply = p.seen(&mut router, &sid, &ap);
    assert_eq!(reply["op"], "seen", "{reply}");
    let sent = expect_relay(&mut router, WAIT);
    assert_eq!(sent["op"], "push_seen", "{sent}");
    let o = SignedObject::parse(sent["seen"].to_string().as_bytes()).unwrap();
    let seen = Seen::verify(&o, &rig.log.log).unwrap();
    assert_eq!(seen.device_id(), "dev-phone");
    assert_eq!(seen.key(), hs[0].key());
    assert_eq!(seen.created_at(), hs[0].created_at());
    assert!(seen.in_window(hs[0].created_at()));
    // A repeat: `seen`, not signed again.
    let reply = p.seen(&mut router, &sid, &ap);
    assert_eq!(reply["op"], "seen", "{reply}");
    // Lost ack: the first seen's bytes, 10 s later.
    let resent = expect_relay(&mut router, Duration::from_secs(15));
    assert_eq!(resent, sent, "never re-signed");
    ack(&router, &[seen.identity()]);
    assert_eq!(relay(&mut router, Duration::from_secs(12)), None);
}

/// §R9.9: a seen after the approval resolved reopens nothing: the phone
/// answers (lease-free), the resolved hint (`answered_remote`) reaches the
/// relay, and a later `approval_seen` is `stale_target` with nothing sent.
#[test]
fn a_seen_after_resolution_changes_nothing() {
    let rig = Rig::new(false, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let (_m, mut p, ap, first, _) = approval(&rig, &mut router, &sid, &fake);
    let hs = rig.hints(&first);
    ack(&router, &hs.iter().map(Hint::identity).collect::<Vec<_>>());
    p.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid(),
            "binding": p.read(&sid), "kind": "approval", "request_id": uuid(),
            "payload": {"approval_id": ap, "decision": "deny", "message": "not now"}}}),
    );
    let resolved = expect_relay(&mut router, WAIT);
    let r = rig.hints(&resolved);
    assert!(matches!(
        r[0].state(),
        HintState::Resolved { reason, .. } if reason == "answered_remote"
    ));
    agent_event(&fake, "answer 1 deny not now");
    let reply = p.seen(&mut router, &sid, &ap);
    assert_eq!(reply["code"], "stale_target", "{reply}");
    ack(&router, &[r[0].identity()]);
    assert_eq!(relay(&mut router, Duration::from_secs(12)), None);
}

/// §R9.9 with §R9.3/§R9.4: no hint while the device list is held (a
/// recorded fault, no manager reconciled yet) or frozen (a conflicting
/// entry by a manager), and none for an approval opened then.
#[test]
fn no_hint_while_held_or_frozen() {
    // Held.
    let rig = Rig::new(true, false);
    let (_sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    ask(&fake, 1);
    agent_event(&fake, "asked 1");
    assert_eq!(relay(&mut router, Duration::from_secs(12)), None, "held");
    assert!(
        rig.runtime_log().contains("no hint (device list held)"),
        "{}",
        rig.runtime_log()
    );
    drop(router);
    drop(rig);

    // Frozen.
    let mut rig = Rig::new(false, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let mut m = Dev::connect(&mut router, "mac", "direct", &rig.log, &mac());
    m.list(&mut router, &sid);
    let conflict = rig.log.conflicting_add("dev-x");
    let entry = SignedObject::parse(conflict.to_string().as_bytes()).unwrap();
    let (_, frame) = m.a.send_membership(&[entry], client_ms()).unwrap();
    router.frame(&m.h, &frame);
    within("the freeze", || {
        rig.status().contains("Device list:    frozen (")
    });
    ask(&fake, 1);
    agent_event(&fake, "asked 1");
    assert_eq!(relay(&mut router, Duration::from_secs(12)), None, "frozen");
    assert!(
        rig.runtime_log().contains("no hint (device list frozen)"),
        "{}",
        rig.runtime_log()
    );
}

/// The guard on Atem's side (§R9.9: no provider send at or after
/// `expires_at − 15 s`, so Atem sends nothing that could cause one): the
/// approval's open hints aren't acknowledged; the host clock moves to
/// within 15 s of its expiry; the due resend doesn't go, a reconnect
/// sends nothing, and the phone's seen is answered but never signed. The
/// resolved hint still goes when the approval ends.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_late_approval_within_15_s_of_expiry_is_suppressed() {
    let rig = Rig::new(false, true);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let (_m, mut p, ap, first, _) = approval(&rig, &mut router, &sid, &fake);
    let hs = rig.hints(&first);
    // 585 s after its creation: at the guard (600 s − 15 s), past the
    // 10 s resend.
    let created = hs[0].created_at();
    let to = created + 585_000;
    rig.clock
        .as_ref()
        .unwrap()
        .jump(to - r9log::host_now().wall_ms);
    assert_eq!(
        relay(&mut router, Duration::from_secs(12)),
        None,
        "no resend"
    );
    let reply = p.seen(&mut router, &sid, &ap);
    assert_eq!(reply["op"], "seen", "{reply}");
    rig.astation.close(router.link);
    drop(router);
    let mut router = Router::new(&rig.astation);
    assert_eq!(
        relay(&mut router, Duration::from_secs(5)),
        None,
        "nothing at the reconnect"
    );
    assert!(
        rig.runtime_log()
            .contains("no longer sent (within 15 s of its expiry)"),
        "{}",
        rig.runtime_log()
    );
    std::fs::write(fake.join("terminal-yes-1"), "").unwrap();
    let resolved = expect_relay(&mut router, WAIT);
    assert!(matches!(
        rig.hints(&resolved)[0].state(),
        HintState::Resolved { .. }
    ));
}

/// §R9.9 (contract clarification): a service with the `approval` op sees
/// the approval and may say it saw it — answered `seen` — but it is never
/// a hint recipient, so no hint is sealed to it and its seen signs
/// nothing.
#[test]
fn a_services_seen_is_answered_and_it_gets_no_hint() {
    let rig = Rig::new(false, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let mut svc = Dev::connect(
        &mut router,
        "svc",
        "relay",
        &rig.log,
        &Identity::service("svc-appr", auth("svc-appr")),
    );
    svc.list(&mut router, &sid);
    next_init();
    let (_m, _p, ap, first, _) = approval(&rig, &mut router, &sid, &fake);
    svc.wait(&mut router, |v| v["op"] == "approval_request");
    let hs = rig.hints(&first);
    let devices: Vec<String> = hs
        .iter()
        .map(|h| match h.state() {
            HintState::Open { device_id, .. } => device_id.clone(),
            _ => panic!("an open hint"),
        })
        .collect();
    assert_eq!(devices, [MAC, "dev-phone"], "no hint for a service");
    ack(&router, &hs.iter().map(Hint::identity).collect::<Vec<_>>());
    let reply = svc.seen(&mut router, &sid, &ap);
    assert_eq!(reply["op"], "seen", "{reply}");
    assert_eq!(
        relay(&mut router, Duration::from_secs(12)),
        None,
        "a service's seen is never signed"
    );
}

/// §R9.9/§R9.6: the Mac removes the phone while the phone's open hint is
/// unacknowledged: the phone's sealed part is never sent again (the next
/// resend and a reconnect carry the Mac's only); the resolved hint still
/// goes.
#[test]
fn a_device_removed_mid_approval_gets_no_more_hints() {
    let mut rig = Rig::new(false, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let (mut m, _p, _ap, first, _) = approval(&rig, &mut router, &sid, &fake);
    assert_eq!(rig.hints(&first).len(), 2);
    let removal = rig.log.remove("dev-phone");
    let entry = SignedObject::parse(removal.to_string().as_bytes()).unwrap();
    let (_, frame) = m.a.send_membership(&[entry], client_ms()).unwrap();
    router.frame(&m.h, &frame);
    m.wait(&mut router, |v| {
        v["op"] == "membership_head" && !v["re"].is_null()
    });
    let again = expect_relay(&mut router, Duration::from_secs(15));
    assert_eq!(again["hints"], json!([first["hints"][0]]), "the Mac's only");
    rig.astation.close(router.link);
    drop(router);
    let mut router = Router::new(&rig.astation);
    let resent = expect_relay(&mut router, Duration::from_secs(15));
    assert_eq!(
        resent["hints"],
        json!([first["hints"][0]]),
        "the Mac's only"
    );
    assert!(
        rig.runtime_log()
            .contains("dev-phone is no longer a recipient; its hint is not sent again"),
        "{}",
        rig.runtime_log()
    );
    std::fs::write(fake.join("terminal-yes-1"), "").unwrap();
    let resolved = expect_relay(&mut router, WAIT);
    assert!(matches!(
        rig.hints(&resolved)[0].state(),
        HintState::Resolved { .. }
    ));
}

/// A suspend: the host's wall clock moves 700 s while its monotonic clock
/// doesn't (`ATEM_TEST_HOST_CLOCK`), as after a laptop's lid was closed.
/// An approval opened then still gets its sealed hints, stamped with the
/// wall clock: `created_at` is the card's and now (never the session
/// host's own suspend-blind wall), `expires_at` 600 s later.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn after_a_suspend_an_approval_still_gets_its_hints() {
    let rig = Rig::new(false, true);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let clock = rig.clock.as_ref().unwrap();
    clock.jump(700_000);
    let before = clock.wall();
    let (_m, _p, _ap, first, request) = approval(&rig, &mut router, &sid, &fake);
    let after = clock.wall();
    let hs = rig.hints(&first);
    assert_eq!(hs.len(), 2);
    for h in &hs {
        assert_eq!(json!(h.created_at()), request["created_at"]);
        assert!(
            before <= h.created_at() && h.created_at() <= after,
            "{before} <= {} <= {after}",
            h.created_at()
        );
        assert_eq!(h.expires_at() - h.created_at(), 600_000);
    }
    assert!(
        !rig.runtime_log().contains("no hint"),
        "{}",
        rig.runtime_log()
    );
}

/// The r8 display times after a suspend: the host clock's wall time jumps
/// an hour while its monotonic clock goes on (`ATEM_TEST_HOST_CLOCK`, as
/// after a laptop's lid was closed). The session host's wall is the host
/// clock's at every pass, so `welcome.server_time`, a receipt's
/// `updated_at` and a descriptor's `activity_since` show the time now, not
/// an hour behind; a descriptor's `created_at` keeps the time it was
/// registered.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn after_a_suspend_displayed_times_follow_the_wall_clock() {
    let rig = Rig::new(false, true);
    let (sid, _fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let clock = rig.clock.as_ref().unwrap();
    let within = |got: &Value, before: u64, after: u64, what: &str| {
        let got = got.as_u64().unwrap_or_else(|| panic!("{what}: {got}"));
        // The session host's monotonic clock is read at most one pass
        // (100 ms) before the wall it is added to.
        assert!(
            before.saturating_sub(1_000) <= got && got <= after + 1_000,
            "{what}: {before} <= {got} <= {after}"
        );
        got
    };
    let started = clock.wall();
    let before = clock.wall();
    let mut m = Dev::connect(&mut router, "mac", "direct", &rig.log, &mac());
    let after = clock.wall();
    within(
        &json!(m.a.welcome().server_time),
        before,
        after,
        "server_time before the suspend",
    );
    m.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "list", "id": uuid()}}),
    );
    let sessions = m.wait(&mut router, |v| v["op"] == "sessions");
    let created = sessions["sessions"][0]["created_at"].clone();
    within(&created, started - 120_000, after, "created_at");

    clock.jump(3_600_000);
    next_init();
    let before = clock.wall();
    let mut p = Dev::connect(&mut router, "phone", "relay", &rig.log, &phone());
    let after = clock.wall();
    within(
        &json!(p.a.welcome().server_time),
        before,
        after,
        "server_time after the suspend",
    );
    p.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "list", "id": uuid()}}),
    );
    let sessions = p.wait(&mut router, |v| v["op"] == "sessions");
    assert_eq!(
        sessions["sessions"][0]["created_at"], created,
        "created_at keeps the registration's time"
    );
    let before = clock.wall();
    p.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid(),
            "binding": p.read(&sid), "kind": "prompt", "request_id": uuid(), "acquire": true,
            "payload": {"text": "run the tests"}}}),
    );
    let receipt = p.wait(&mut router, |v| v["op"] == "receipt");
    let after = clock.wall();
    assert_eq!(receipt["state"], "accepted", "{receipt}");
    within(&receipt["updated_at"], before, after, "receipt updated_at");
    let working = p.wait(&mut router, |v| {
        v["op"] == "session_changed" && v["descriptor"]["activity"] == "working"
    });
    within(
        &working["descriptor"]["activity_since"],
        before,
        clock.wall(),
        "activity_since",
    );
}

/// §R9.6, §R9.7 (review I2 of Task 9a): a native channel's 24 h lifetime
/// holds on the host's wall clock too ("wall and monotonic, whichever
/// first"). The host clock's wall moves 23 h while its monotonic clock
/// goes on (a suspend): the phone's channel stays; at 24 h of wall time
/// Atem closes it, though the monotonic clock is seconds in.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn a_native_channel_ends_at_24_h_of_wall_time_across_a_suspend() {
    let rig = Rig::new(false, true);
    let (sid, _fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let clock = rig.clock.as_ref().unwrap();
    let mut p = Dev::connect(&mut router, "phone", "relay", &rig.log, &phone());
    p.list(&mut router, &sid);
    clock.jump(23 * 3_600_000);
    let until = Instant::now() + Duration::from_millis(1_500);
    while Instant::now() < until {
        if !router.quiet("phone", Duration::from_millis(100)) {
            match router.next("phone") {
                Out::Frame(f) => {
                    p.a.on_frame(&f, client_ms()).unwrap();
                }
                Out::Close(reason) => panic!("closed before 24 h ({reason:?})"),
            }
        }
    }
    p.list(&mut router, &sid);
    clock.jump(24 * 3_600_000 + 1_000);
    let deadline = Instant::now() + WAIT;
    loop {
        match router.next("phone") {
            Out::Close(reason) => {
                assert_eq!(reason.as_deref(), Some("expired"), "{reason:?}");
                break;
            }
            Out::Frame(_) => assert!(Instant::now() < deadline, "never closed"),
        }
    }
}

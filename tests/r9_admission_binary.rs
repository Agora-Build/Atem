//! r9 admission in the real `atem runtime` process (atem-session-v1.md
//! Appendix r9, §R9.7a): a temp profile with a pinned device list, the
//! runtime's link to a fake Astation, and clients that are the shared core
//! (`atem_client::connect`) carried in the channel envelope on that link:
//! a phone (native, P-256), a bot (service, Ed25519, scoped and expiring)
//! and a browser (a phone-issued grant), several at once.
#![cfg(target_os = "linux")]

mod support;

use atem_client::connect::{Event as CEvent, Identity};
use serde_json::{Value, json};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::{Out, Router, client_ms, write_pin};
use support::r9log::{self, MAC, TestLog, auth, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-r9";
const HOST: &str = "host-r9";

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    runtime: Option<Child>,
    log: TestLog,
    host_seed: [u8; 32],
}

impl Rig {
    /// A verified pairing as `HOST`; `pin` writes the device list (with the
    /// Mac genesis, this host, a phone and a bot) before the runtime starts.
    fn new(pin: bool, more: impl FnOnce(&mut TestLog)) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("binary host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("binary astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native("dev-phone", &["control", "view"]);
        log.add_service(
            "svc-bot",
            &[HOST],
            None,
            &["prompt", "view"],
            r9log::host_now().wall_ms + 3_600_000,
        );
        more(&mut log);
        if pin {
            write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        }
        let astation = FakeAstation::start();
        Rig {
            sandbox,
            astation,
            runtime: None,
            log,
            host_seed,
        }
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.sandbox.dir.path().join("runtime.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", &self.astation.url)
            .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
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

    /// A session of a fixture agent, detached: its id.
    fn session(&self) -> String {
        let agent = self.sandbox.script(
            "agent fixture",
            "echo AGENT_READY\nwhile IFS= read -r line; do echo \"got:$line\"; done",
        );
        let mut frontend = self.sandbox.spawn(
            &["agent", "launch", "claude"],
            &self.sandbox.home,
            &[("CLAUDE_CLI_BIN", agent.to_str().unwrap())],
        );
        frontend.shows("AGENT_READY");
        let sid = frontend.detach();
        self.sandbox.track();
        sid
    }

    fn status(&self) -> String {
        let (out, err, _) = self.sandbox.atem(&["status"]);
        format!("{out}{err}")
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

fn phone() -> Identity {
    Identity::native("dev-phone", auth("dev-phone"))
}

fn bot() -> Identity {
    Identity::service("svc-bot", auth("svc-bot"))
}

/// Inits are answered one a second per link (§R9.7a).
fn next_init() {
    std::thread::sleep(Duration::from_millis(1_100));
}

fn signed(value: &Value) -> atem_client::SignedObject {
    atem_client::SignedObject::parse(value.to_string().as_bytes()).unwrap()
}

/// A phone, a bot and a browser share the runtime's one link, each on its
/// own channel and attachment; the router closing one channel leaves the
/// others; a removal carried by the phone fences the bot's live channel;
/// out-of-scope, expired and tampered principals are refused; the link's
/// r8 hello is refused once a device list exists.
#[test]
fn clients_share_the_link_and_are_fenced_one_by_one() {
    let wall = r9log::host_now().wall_ms;
    let mut rig = Rig::new(true, |log| {
        log.add_service("svc-old", &[HOST], None, &["view"], wall + 3_000);
        log.add_service(
            "svc-scoped",
            &[HOST],
            Some(&["ses-zzzzzzzzzzzz"]),
            &["view"],
            wall + 3_600_000,
        );
    });
    rig.start();
    let sid = rig.session();
    let wall = r9log::host_now().wall_ms;
    let (grant, key) = rig.log.grant(
        "dev-phone",
        "aaaaaaaa-1111-4111-8111-00000000000b",
        HOST,
        1,
        None,
        &["view"],
        wall,
        wall + 600_000,
    );
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;

    // Each kind is admitted with the welcome §R9.8 names.
    let mut ph = router
        .connect("ph", log, HOST, &phone())
        .expect("the phone");
    assert_eq!(ph.welcome().principal, "member:dev-phone");
    assert_eq!(ph.welcome().head, log.log.head());
    assert!(ph.welcome().pending_recovery.is_empty());
    next_init();
    let mut bt = router.connect("bot", log, HOST, &bot()).expect("the bot");
    assert_eq!(bt.welcome().principal, "service:svc-bot");
    assert!(bt.welcome().authorization_ms_left <= 3_600_000);
    next_init();
    let mut br = router
        .connect("br", log, HOST, &Identity::browser(grant, key).unwrap())
        .expect("the browser");
    assert_eq!(br.welcome().permissions.len(), 1);
    for (h, a) in [("ph", &mut ph), ("bot", &mut bt), ("br", &mut br)] {
        assert!(router.list(h, a).contains(&sid), "{h} sees the session");
    }

    // The browser goes away: only its channel ends.
    router.close("br");
    assert!(router.list("ph", &mut ph).contains(&sid));
    assert!(router.list("bot", &mut bt).contains(&sid));

    // The link itself can't come in through r8 any more.
    router.send_raw(
        json!({"type": "session", "data": {"v": 1, "op": "hello",
            "id": "aaaaaaaa-0000-4000-8000-0000000000a1", "revision": 8}})
        .to_string(),
    );
    let refused = router.next_other();
    assert_eq!(refused["data"]["code"], "unsupported_version", "{refused}");
    assert_eq!(refused["data"]["revision"], 9);

    // A scoped service sees nothing outside its scope; a session that
    // doesn't exist and one out of scope are both unknown_session.
    next_init();
    let mut sc = router
        .connect(
            "sc",
            log,
            HOST,
            &Identity::service("svc-scoped", auth("svc-scoped")),
        )
        .expect("the scoped bot");
    assert!(router.list("sc", &mut sc).is_empty());
    let w = sc.welcome().clone();
    let target = |sid: &str| {
        json!({"target": {"account_id": w.account_id, "atem_device_id": w.atem_device_id,
                "host_trust_gen": w.host_trust_gen, "session_id": sid,
                "process_gen": "22222222-2222-4222-8222-222222222222"},
               "attachment_gen": w.attachment_gen})
    };
    for s in [sid.as_str(), "ses-zzzzzzzzzzzz"] {
        let open = json!({"type": "agentChat", "data": {"v": 1, "op": "open",
            "conversationId": "cccccccc-0000-4000-8000-000000000001", "agentId": s,
            "binding": target(s)}});
        let frame = sc.send(&open, client_ms()).unwrap();
        let events = router.round("sc", &mut sc, &frame).unwrap();
        let code = events.iter().find_map(|e| match e {
            CEvent::Family(f) => f.data.as_ref().map(|d| d["code"].clone()),
            _ => None,
        });
        assert_eq!(code, Some(json!("unknown_session")), "{s}: {events:?}");
    }

    // Expired, tampered: refused.
    std::thread::sleep(Duration::from_millis(3_100));
    assert_eq!(
        router
            .connect(
                "old",
                log,
                HOST,
                &Identity::service("svc-old", auth("svc-old"))
            )
            .unwrap_err(),
        ("unauthorized".to_string(), Some("expired".to_string()))
    );
    next_init();
    let (code, _) = router
        .connect(
            "bad",
            log,
            HOST,
            &Identity::native("dev-phone", auth("svc-bot")),
        )
        .unwrap_err();
    assert_eq!(code, "handshake_failed");

    // The phone carries the bot's removal: the bot's live channel is
    // fenced at once (its error, then Atem's close); the phone goes on.
    let removal = rig.log.remove("svc-bot");
    let (_, frame) = ph
        .send_membership(&[signed(&removal)], client_ms())
        .unwrap();
    let events = router.round("ph", &mut ph, &frame).unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, CEvent::MembershipHead { re: Some(_), .. })),
        "{events:?}"
    );
    let fenced = router.events("bot", &mut bt).unwrap();
    assert!(
        fenced
            .iter()
            .any(|e| matches!(e, CEvent::Fenced(e) | CEvent::Error(e)
            if e.code == "unauthorized" && e.detail.as_deref() == Some("removed"))),
        "{fenced:?}"
    );
    assert!(matches!(router.next("bot"), Out::Close(_)));
    assert!(router.list("ph", &mut ph).contains(&sid));
    next_init();
    assert_eq!(
        router.connect("bot-2", &rig.log, HOST, &bot()).unwrap_err(),
        ("unauthorized".to_string(), Some("removed".to_string()))
    );
    let runtime_log = rig.runtime_log();
    assert!(
        runtime_log.contains("welcomed member:dev-phone"),
        "{runtime_log}"
    );
}

/// Held, frozen and failed device lists refuse r9 with the right error,
/// and `atem status` / `atem agent list` say why.
#[test]
fn held_frozen_and_failed_lists_refuse_r9_and_say_so() {
    // Failed: a damaged list.
    let mut rig = Rig::new(true, |_| {});
    std::fs::write(
        rig.sandbox.config().join("pairing").join("membership.json"),
        b"{}",
    )
    .unwrap();
    rig.start();
    let mut router = Router::new(&rig.astation);
    assert_eq!(
        router
            .connect("c1", &rig.log, HOST, &phone())
            .unwrap_err()
            .0,
        "busy"
    );
    let status = rig.status();
    assert!(status.contains("Device list:    failed ("), "{status}");
    let (list, _, _) = rig.sandbox.atem(&["agent", "list"]);
    assert!(list.contains("Device list: failed"), "{list}");
    drop(router);
    drop(rig);

    // Held: a recorded write fault; only a managing device at the head
    // reconciles.
    let mut rig = Rig::new(true, |_| {});
    std::fs::write(
        rig.sandbox
            .config()
            .join("pairing")
            .join("membership.fault"),
        br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
    )
    .unwrap();
    rig.start();
    let mut router = Router::new(&rig.astation);
    assert_eq!(
        router.connect("c1", &rig.log, HOST, &phone()).unwrap_err(),
        (
            "busy".to_string(),
            Some("device list not reconciled".to_string())
        )
    );
    let status = rig.status();
    assert!(status.contains("Device list:    held ("), "{status}");
    next_init();
    let mut mac = router
        .connect("mac", &rig.log, HOST, &Identity::native(MAC, auth(MAC)))
        .expect("the Mac reconciles");
    let status = rig.status();
    assert!(
        status.contains("Device list:    pinned at seq 4"),
        "{status}"
    );

    // Frozen: a conflicting entry by a current manager.
    let conflict = rig.log.conflicting_add("dev-x");
    let (_, frame) = mac
        .send_membership(&[signed(&conflict)], client_ms())
        .unwrap();
    let _ = router.round("mac", &mut mac, &frame);
    within("the freeze", || {
        rig.status().contains("Device list:    frozen (")
    });
    next_init();
    assert_eq!(
        router
            .connect("c2", &rig.log, HOST, &phone())
            .unwrap_err()
            .0,
        "account_frozen"
    );
}

/// A pending recovery shows in the welcome and in `atem status`.
#[test]
fn a_pending_recovery_shows_in_the_welcome_and_atem_status() {
    let mut rig = Rig::new(true, |log| {
        log.recovery_add("dev-newmac");
    });
    rig.start();
    let mut router = Router::new(&rig.astation);
    let ph = router
        .connect("ph", &rig.log, HOST, &phone())
        .expect("the phone");
    let pending = &ph.welcome().pending_recovery;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0].subject, "dev-newmac");
    let status = rig.status();
    assert!(
        status.contains("recovery pending: dev-newmac (recovery_add) takes effect at "),
        "{status}"
    );
    let (list, _, _) = rig.sandbox.atem(&["agent", "list"]);
    assert!(list.contains("recovery pending: dev-newmac"), "{list}");
    next_init();
    assert_eq!(
        router
            .connect(
                "new",
                &rig.log,
                HOST,
                &Identity::native("dev-newmac", auth("dev-newmac"))
            )
            .unwrap_err()
            .0,
        "recovery_pending"
    );
}

/// A device list pinned while the runtime runs is picked up: before it,
/// r9 is refused (`stale_target`: nothing pinned) and r8 still welcomes the
/// link; after it, the phone is admitted and the link's r8 hello refused.
#[test]
fn a_pin_while_the_runtime_runs_is_picked_up() {
    let mut rig = Rig::new(false, |_| {});
    rig.start();
    let mut router = Router::new(&rig.astation);
    assert_eq!(
        router
            .connect("c1", &rig.log, HOST, &phone())
            .unwrap_err()
            .0,
        "stale_target"
    );
    router.send_raw(
        json!({"type": "session", "data": {"v": 1, "op": "hello",
            "id": "aaaaaaaa-0000-4000-8000-0000000000b1", "revision": 8}})
        .to_string(),
    );
    assert_eq!(router.next_other()["data"]["op"], "welcome");
    write_pin(&rig.sandbox.config(), &rig.log, HOST, 1, &rig.host_seed);
    let deadline = Instant::now() + Duration::from_secs(10);
    let ph = loop {
        next_init();
        match router.connect("c2", &rig.log, HOST, &phone()) {
            Ok(ph) => break ph,
            Err(e) => assert!(Instant::now() < deadline, "never admitted: {e:?}"),
        }
        router.close("c2");
    };
    assert_eq!(ph.welcome().principal, "member:dev-phone");
    router.send_raw(
        json!({"type": "session", "data": {"v": 1, "op": "hello",
            "id": "aaaaaaaa-0000-4000-8000-0000000000b2", "revision": 8}})
        .to_string(),
    );
    let refused = loop {
        let v = router.next_other();
        if v["data"]["op"] == "error" {
            break v;
        }
    };
    assert_eq!(refused["data"]["code"], "unsupported_version", "{refused}");
    let runtime_log = rig.runtime_log();
    assert!(
        runtime_log.contains("device list: opened at seq 4"),
        "{runtime_log}"
    );
}

//! Two hosts both enrolled in one account's device list (atem-session-v1.md
//! §R9.3, §R9.4), each a real `atem runtime` on its own temp profile with
//! its own fake Astation link, its own `host_channel_key` and its own
//! session. Supplementary to the shared fixture
//! `r9-chain-relay-cas-failure-freezes-both-hosts`, whose host B is outside
//! the vectors' log (its channel replies are not expressible there): here
//! the list is signed in the test with `atem-client` and test keys (no
//! vector bytes), names `host-a` and `host-b`, and the clients are the
//! shared core (`atem_client::connect`) in the channel envelope.
//!
//! The relay's CAS fails: two honest entries by the current manager take
//! the same `seq`. Each host first applies a different one, then the other
//! arrives and each freezes: every channel there is fenced
//! `account_frozen` and closed, the queued prompt of a fenced principal is
//! rejected (r8 §H, "control revoked") and never reaches the agent, the
//! freeze is durable and a new channel is refused.
//!
//! Debug builds only (`hold_dispatch`, the state dump); CI runs it in the
//! Test workflow's debug step.
#![cfg(target_os = "linux")]

mod support;

use atem_client::connect::{Attached, Event as CEvent, Identity};
use atem_client::membership::Head;
use atem_client::session::wire::Op;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::{Out, Router, client_ms, write_pin};
use support::r9log::{MAC, TestLog, auth, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-two-hosts";
const HOST_A: &str = "host-a";
const HOST_B: &str = "host-b";

/// One host: a verified pairing as `host_id`, the shared device list
/// pinned with its own channel key, its runtime and its fake Astation.
struct Host {
    host_id: &'static str,
    sandbox: Sandbox,
    astation: FakeAstation,
    runtime: Option<Child>,
    /// `ATEM_TEST_PTY_FAULTS`: `hold_dispatch` keeps accepted work queued.
    faults: PathBuf,
    /// `ATEM_TEST_STATE_DUMP`, written after each broker pass.
    dump: PathBuf,
}

impl Host {
    fn new(host_id: &'static str, log: &TestLog, seed: &[u8; 32]) -> Host {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, host_id, 1);
        write_pin(&sandbox.config(), log, host_id, 1, seed);
        let faults = sandbox.dir.path().join("pty-faults");
        std::fs::create_dir_all(&faults).unwrap();
        std::fs::write(faults.join("hold_dispatch"), "").unwrap();
        let dump = sandbox.dir.path().join("state.json");
        let mut host = Host {
            host_id,
            sandbox,
            astation: FakeAstation::start(),
            runtime: None,
            faults,
            dump,
        };
        host.start();
        host
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
            .env("ATEM_TEST_PTY_FAULTS", &self.faults)
            .env("ATEM_TEST_STATE_DUMP", &self.dump)
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

    /// A Claude session running the fake agent (chat hooks and a
    /// transcript: a remote prompt is admitted), detached: its id.
    fn session(&self) -> String {
        let fake = self.sandbox.dir.path().join("fake");
        std::fs::create_dir_all(&fake).unwrap();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let mut frontend = self.sandbox.spawn(
            &["agent", "launch", "claude"],
            &self.sandbox.home,
            &[
                ("CLAUDE_CLI_BIN", script.to_str().unwrap()),
                ("FAKE_DIR", fake.to_str().unwrap()),
            ],
        );
        let events = fake.join("events");
        within("the fake agent to start", || {
            std::fs::read_to_string(&events)
                .unwrap_or_default()
                .lines()
                .any(|l| l.trim_end() == "started")
        });
        let sid = frontend.detach();
        self.sandbox.track();
        sid
    }

    fn state(&self) -> Value {
        std::fs::read_to_string(&self.dump)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null)
    }

    /// Waits until the state dump satisfies `ok`.
    fn until_state(&self, what: &str, ok: impl Fn(&Value) -> bool) -> Value {
        let mut last = Value::Null;
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            last = self.state();
            if ok(&last) {
                return last;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "{}: {what}: the state is {last}\n{}",
            self.host_id,
            self.runtime_log()
        );
    }

    fn status(&self) -> String {
        let (out, err, _) = self.sandbox.atem(&["status"]);
        format!("{out}{err}")
    }

    fn head_json(head: &Head) -> Value {
        json!({"seq": head.seq, "hash": head.hash.to_hex()})
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn mac() -> Identity {
    Identity::native(MAC, auth(MAC))
}

fn phone() -> Identity {
    Identity::native("dev-phone", auth("dev-phone"))
}

/// Inits are answered one a second per link (§R9.7a).
fn next_init() {
    std::thread::sleep(Duration::from_millis(1_100));
}

fn signed(value: &Value) -> atem_client::SignedObject {
    atem_client::SignedObject::parse(value.to_string().as_bytes()).unwrap()
}

/// Connects `identity` to `host` and checks the live welcome against the
/// list both hosts pinned.
fn admit(
    router: &mut Router,
    handle: &str,
    log: &TestLog,
    host: &Host,
    identity: &Identity,
    principal: &str,
) -> Attached {
    let attached = router
        .connect(handle, log, host.host_id, identity)
        .unwrap_or_else(|e| {
            panic!(
                "{principal} on {}: {e:?}\n{}",
                host.host_id,
                host.runtime_log()
            )
        });
    let w = attached.welcome();
    assert_eq!(w.revision, 9);
    assert_eq!(w.principal, principal);
    assert_eq!(w.account_id, ACCOUNT);
    assert_eq!(w.atem_device_id, host.host_id);
    assert_eq!(w.host_trust_gen, 1);
    assert_eq!(w.head, log.log.head(), "{principal} on {}", host.host_id);
    assert_eq!(w.permissions.len(), 2, "{principal}: control and view");
    attached
}

/// A prompt that acquires the lease and stays queued (dispatch held):
/// its request id, once accepted.
fn queue_prompt(
    router: &mut Router,
    handle: &str,
    attached: &mut Attached,
    sid: &str,
    host: &Host,
) -> String {
    assert!(router.list(handle, attached).contains(&sid.to_string()));
    let request = uuid::Uuid::new_v4().to_string();
    let (_, frame) = attached
        .submit_prompt(sid, &request, "run the tests", client_ms())
        .unwrap();
    router.frame(handle, &frame);
    for _ in 0..8 {
        let events = router
            .events(handle, attached)
            .unwrap_or_else(|r| panic!("{handle}: closed {r:?}\n{}", host.runtime_log()));
        for e in &events {
            match e {
                CEvent::Session(m) => {
                    if let Op::Receipt(r) = &m.op
                        && r.request_id == request
                    {
                        let state = serde_json::to_value(r.state).unwrap();
                        assert_eq!(state, "accepted", "{r:?}");
                        return request;
                    }
                }
                CEvent::Error(e) => panic!("{handle}: {e:?}"),
                _ => {}
            }
        }
    }
    panic!("{handle}: no receipt for the prompt");
}

/// Reads `handle` until Atem fences it `account_frozen` and closes it.
fn fenced_frozen(router: &mut Router, handle: &str, attached: &mut Attached) {
    let mut fenced = false;
    while let Out::Frame(f) = router.next(handle) {
        for e in attached.on_frame(&f, client_ms()).unwrap_or_default() {
            if let CEvent::Fenced(e) | CEvent::Error(e) = e
                && e.code == "account_frozen"
            {
                fenced = true;
            }
        }
    }
    assert!(fenced, "{handle}: fenced account_frozen before the close");
}

/// Carries `entry` on `handle`; the head in the reply.
fn carry(router: &mut Router, handle: &str, attached: &mut Attached, entry: &Value) -> Head {
    let (re, frame) = attached
        .send_membership(&[signed(entry)], client_ms())
        .unwrap();
    router.frame(handle, &frame);
    loop {
        match router.next(handle) {
            Out::Frame(f) => {
                for e in attached.on_frame(&f, client_ms()).unwrap() {
                    if let CEvent::MembershipHead {
                        re: Some(r), head, ..
                    } = e
                        && r == re
                    {
                        return head;
                    }
                }
            }
            Out::Close(r) => panic!("{handle} closed: {r:?}"),
        }
    }
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn both_enrolled_hosts_admit_then_freeze_on_conflicting_carriage() {
    // The list: the Mac (genesis, manager), host A and host B with their
    // own channel keys, a phone (control).
    let seed_a = secret("two hosts: host-a seed");
    let seed_b = secret("two hosts: host-b seed");
    let mut log = TestLog::genesis(ACCOUNT, &secret("two hosts: astation"));
    log.add_host(HOST_A, 1, &seed_a);
    log.add_host(HOST_B, 1, &seed_b);
    log.add_native("dev-phone", &["control", "view"]);
    let a = Host::new(HOST_A, &log, &seed_a);
    let b = Host::new(HOST_B, &log, &seed_b);
    let pinned = log.log.head();
    assert_eq!(pinned.seq, 4);
    let sid_a = a.session();
    let sid_b = b.session();

    // Live admission and the welcome on both hosts, each through its own
    // link and channel key.
    let mut ra = Router::new(&a.astation);
    let mut rb = Router::new(&b.astation);
    let mut a_mac = admit(&mut ra, "a-mac", &log, &a, &mac(), "member:dev-mac");
    let mut b_phone = admit(&mut rb, "b-phone", &log, &b, &phone(), "member:dev-phone");
    next_init();
    let mut a_phone = admit(&mut ra, "a-phone", &log, &a, &phone(), "member:dev-phone");
    let mut b_mac = admit(&mut rb, "b-mac", &log, &b, &mac(), "member:dev-mac");
    // A channel to the wrong host fails the handshake (the key the list
    // names for host-b is not host A's).
    next_init();
    let (code, _) = ra.connect("a-as-b", &log, HOST_B, &phone()).unwrap_err();
    assert_eq!(code, "stale_target", "a channel for host-b on host A");

    // Queued work on both hosts: the phone's prompt on A, the Mac's on B
    // (each acquiring the lease with its acceptance, r8 §F).
    let prompt_a = queue_prompt(&mut ra, "a-phone", &mut a_phone, &sid_a, &a);
    let prompt_b = queue_prompt(&mut rb, "b-mac", &mut b_mac, &sid_b, &b);

    // The relay's CAS fails: X and Y both take seq 5, both signed by the
    // Mac (a current manager). A gets X first, B gets Y first.
    let x = log.add_native("dev-x", &["view"]);
    let y = log.conflicting_add("dev-y");
    let x_head = log.log.head();
    assert_eq!(x_head.seq, 5);
    assert_eq!(carry(&mut ra, "a-mac", &mut a_mac, &x), x_head);
    let y_head = carry(&mut rb, "b-phone", &mut b_phone, &y);
    assert_eq!(y_head.seq, 5);
    assert_ne!(y_head.hash, x_head.hash);
    a.until_state("head X", |s| {
        s["membership"]["head"] == Host::head_json(&x_head)
    });
    b.until_state("head Y", |s| {
        s["membership"]["head"] == Host::head_json(&y_head)
    });

    // The other branch reaches each host: each freezes. Every channel
    // there is fenced account_frozen and closed.
    let (_, frame) = a_phone.send_membership(&[signed(&y)], client_ms()).unwrap();
    ra.frame("a-phone", &frame);
    fenced_frozen(&mut ra, "a-phone", &mut a_phone);
    fenced_frozen(&mut ra, "a-mac", &mut a_mac);
    let (_, frame) = b_mac.send_membership(&[signed(&x)], client_ms()).unwrap();
    rb.frame("b-mac", &frame);
    fenced_frozen(&mut rb, "b-mac", &mut b_mac);
    fenced_frozen(&mut rb, "b-phone", &mut b_phone);

    for (host, prompt, head) in [(&a, &prompt_a, &x_head), (&b, &prompt_b, &y_head)] {
        // The freeze, durable, at the host's own branch (nothing merged).
        let state = host.until_state("frozen", |s| s["membership"]["frozen"] == true);
        assert_eq!(
            state["membership"]["head"],
            Host::head_json(head),
            "{}",
            host.host_id
        );
        assert!(
            host.sandbox
                .config()
                .join("pairing")
                .join("membership.freeze")
                .exists(),
            "{}: membership.freeze",
            host.host_id
        );
        // The queued prompt: rejected by the fence, never dispatched.
        let state = host.until_state("the queued prompt rejected", |s| {
            s["receipts"][prompt.as_str()]["state"] == "rejected"
        });
        assert_eq!(
            state["receipts"][prompt.as_str()]["detail"],
            "control revoked",
            "{}",
            host.host_id
        );
        assert_eq!(state["attachments"], 0, "{}", host.host_id);
        let status = host.status();
        assert!(
            status.contains("Device list:    frozen ("),
            "{}: {status}",
            host.host_id
        );
    }
    // The agents never got the prompts, and still run.
    for (host, sid) in [(&a, &sid_a), (&b, &sid_b)] {
        let input = host.sandbox.dir.path().join("fake").join("input");
        let typed = String::from_utf8_lossy(&std::fs::read(input).unwrap_or_default()).to_string();
        assert!(
            !typed.contains("run the tests"),
            "{}: {typed:?}",
            host.host_id
        );
        let (list, _, _) = host.sandbox.atem(&["agent", "list"]);
        let row = list
            .lines()
            .find(|l| l.contains(sid.as_str()))
            .unwrap_or_default()
            .to_string();
        assert!(row.contains("running"), "{}: {list}", host.host_id);
    }
    // A new channel is refused on both.
    next_init();
    assert_eq!(
        ra.connect("a-new", &log, HOST_A, &mac()).unwrap_err().0,
        "account_frozen"
    );
    assert_eq!(
        rb.connect("b-new", &log, HOST_B, &phone()).unwrap_err().0,
        "account_frozen"
    );
}

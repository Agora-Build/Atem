//! Several devices at once (atem-session-v1.md §R9.10) in the real
//! `atem runtime` process: a temp profile with a pinned device list, the
//! runtime's link to a fake Astation, a fake Claude Code
//! (`tests/fixtures/approvals/fake-agent.py`: chat hooks, a transcript and
//! the real PermissionRequest hook), and clients that are the shared core
//! (`atem_client::connect`) in the channel envelope on that link: the Mac
//! (the genesis member, through Astation's :8080, `direct`), a phone
//! (native, through the relay), a bot (a service with `prompt` and `view`
//! only) and a browser (a phone-issued `view` grant).
#![cfg(target_os = "linux")]

mod support;

use atem_client::connect::{Attached, Event as CEvent, Identity};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::{Out, Router, client_ms, write_pin};
use support::r9log::{self, MAC, TestLog, auth, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-md";
const HOST: &str = "host-md";
const WAIT: Duration = Duration::from_secs(20);

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    runtime: Option<Child>,
    log: TestLog,
    /// The workers' PTY write faults (`ATEM_TEST_PTY_FAULTS`): `hold`.
    faults: PathBuf,
}

impl Rig {
    /// A verified pairing as `HOST` and its device list: the Mac (genesis),
    /// this host, a phone (control) and a bot (prompt and view, an hour).
    fn new() -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("multi-device host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("multi-device astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native("dev-phone", &["control", "view"]);
        log.add_service(
            "svc-bot",
            &[HOST],
            None,
            &["prompt", "view"],
            r9log::host_now().wall_ms + 3_600_000,
        );
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        let faults = sandbox.dir.path().join("pty-faults");
        std::fs::create_dir_all(&faults).unwrap();
        let mut rig = Rig {
            sandbox,
            astation: FakeAstation::start(),
            runtime: None,
            log,
            faults,
        };
        rig.start();
        rig
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
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.faults.join("hold"));
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Waits until the fake agent's events show `line`.
fn agent_event(fake: &Path, line: &str) {
    let events = fake.join("events");
    within(&format!("the agent's {line:?}"), || {
        std::fs::read_to_string(&events)
            .unwrap_or_default()
            .lines()
            .any(|l| l.trim_end() == line)
    });
}

/// Waits until the fake agent's terminal delivered `text`.
fn agent_input(fake: &Path, text: &str) {
    let input = fake.join("input");
    within(&format!("the agent to read {text:?}"), || {
        String::from_utf8_lossy(&std::fs::read(&input).unwrap_or_default()).contains(text)
    });
}

/// The fake agent's next tool call `n` needing permission.
fn ask(fake: &Path, n: u32) {
    let request = json!({"tool_name": "Bash",
        "tool_input": {"command": "npm test", "description": "run the tests"}});
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

/// Inits are answered one a second per link (§R9.7a).
fn next_init() {
    std::thread::sleep(Duration::from_millis(1_100));
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// One device's channel: its handle, the shared core's attachment, and
/// what it received but no step took yet.
struct Dev {
    h: String,
    a: Attached,
    backlog: Vec<Value>,
}

/// An event as wire JSON (`data`, with its envelope type under `__type`).
fn data_of(e: &CEvent) -> Option<Value> {
    let mut v = match e {
        CEvent::Session(m) => atem_client::session::wire::to_value(
            &atem_client::session::wire::Envelope::Session(m.clone()),
        )["data"]
            .clone(),
        CEvent::Family(f) => {
            let mut d = f.data.clone()?;
            d["__type"] = json!(f.family);
            return Some(d);
        }
        CEvent::Error(e) | CEvent::Fenced(e) => {
            serde_json::from_slice::<Value>(&e.to_bytes()).ok()?["data"].clone()
        }
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

    /// The next message (from the backlog first) `pred` accepts; others
    /// stay in the backlog. Panics on the channel's close.
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

    /// Everything that arrives within `wait` (the backlog included).
    fn gather(&mut self, router: &mut Router, wait: Duration) -> Vec<Value> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if router.quiet(&self.h, Duration::from_millis(100)) {
                continue;
            }
            match router.next(&self.h) {
                Out::Frame(f) => {
                    let events = self.a.on_frame(&f, client_ms()).unwrap();
                    self.backlog.extend(events.iter().filter_map(data_of));
                }
                Out::Close(_) => break,
            }
        }
        std::mem::take(&mut self.backlog)
    }

    /// The read binding of `sid` (the registry named its target).
    fn read(&self, sid: &str) -> Value {
        json!({"target": self.a.target(sid).expect("listed"),
               "attachment_gen": self.a.welcome().attachment_gen})
    }

    fn lease(&self, sid: &str, epoch: u64) -> Value {
        let mut b = self.read(sid);
        b["lease_epoch"] = json!(epoch);
        b
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

    fn acquire(&mut self, router: &mut Router, sid: &str, takeover: Option<&Value>) -> Value {
        let mut data = json!({"v": 1, "op": "acquire", "id": uuid(), "binding": self.read(sid),
            "takeover": takeover.is_some()});
        if let Some(c) = takeover {
            data["expected_controller"] = c.clone();
        }
        self.send(router, json!({"type": "session", "data": data}));
        self.wait(router, |v| v["op"] == "lease" || v["op"] == "error")
    }

    /// Subscribes to `sid`'s terminal: the stream id.
    fn subscribe(&mut self, router: &mut Router, sid: &str, pg: &str) -> Value {
        self.send(
            router,
            json!({"type": "terminal", "data": {"v": 1, "op": "subscribe", "terminal_id": sid,
                "generation": pg, "binding": self.read(sid)}}),
        );
        self.wait(router, |v| {
            v["__type"] == "terminal" && v["op"] == "attached"
        })["stream_id"]
            .clone()
    }

    fn input(
        &mut self,
        router: &mut Router,
        sid: &str,
        pg: &str,
        stream: &Value,
        epoch: u64,
        seq: u64,
        bytes: &[u8],
    ) {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        self.send(
            router,
            json!({"type": "terminal", "data": {"v": 1, "op": "input", "terminal_id": sid,
                "generation": pg, "stream_id": stream, "sequence": seq, "bytes": b64,
                "binding": self.lease(sid, epoch)}}),
        );
    }

    /// Opens a chat-v1 conversation on `sid` and waits until its agent is
    /// ready (the fake's SessionStart was seen).
    fn open_chat(&mut self, router: &mut Router, sid: &str) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            let conversation = uuid();
            self.send(
                router,
                json!({"type": "agentChat", "data": {"v": 1, "op": "open",
                    "conversationId": conversation, "agentId": sid, "binding": self.read(sid)}}),
            );
            let c = conversation.clone();
            let reply = self.wait(router, move |v| {
                v["__type"] == "agentChat"
                    && v["conversationId"] == c.as_str()
                    && (v["op"] == "opened" || v["op"] == "error")
            });
            if reply["op"] == "opened" && reply["status"]["state"] == "ready" {
                return conversation;
            }
            assert!(
                Instant::now() < deadline,
                "chat never became ready: {reply}"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

fn pg_of(dev: &Dev, sid: &str) -> String {
    dev.a.target(sid).unwrap().process_gen.clone()
}

/// R9.10: the Mac and a phone online at once. One lease for the session:
/// the Mac's Send acquires it (the acceptance and the grant in one step),
/// the phone hears it granted and its own Send is `lease_held`, naming the
/// Mac as controller; the Mac's prompt completes at the turn's end, and
/// receipts stay r8's (the phone reads the Mac's by id). A browser with a
/// view grant sees the session but can't take the lease.
#[test]
fn the_mac_and_a_phone_online_share_one_lease_and_see_the_receipts() {
    let mut rig = Rig::new();
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut m = Dev::connect(&mut router, "mac", "direct", log, &mac());
    assert_eq!(m.a.welcome().principal, format!("member:{MAC}"));
    next_init();
    let mut p = Dev::connect(&mut router, "phone", "relay", log, &phone());
    m.list(&mut router, &sid);
    p.list(&mut router, &sid);
    m.open_chat(&mut router, &sid);

    let rid = uuid();
    m.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid(),
            "binding": m.read(&sid), "kind": "prompt", "request_id": rid, "acquire": true,
            "payload": {"text": "run the tests"}}}),
    );
    let accepted = m.wait(&mut router, |v| {
        v["op"] == "receipt" && v["state"] == "accepted"
    });
    assert_eq!(accepted["lease"]["lease_epoch"], 1, "{accepted}");
    let granted = p.wait(&mut router, |v| v["op"] == "lease_changed");
    assert_eq!(granted["reason"], "granted", "{granted}");
    assert_eq!(granted["controller"]["lease_epoch"], 1);

    p.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid(),
            "binding": p.read(&sid), "kind": "prompt", "request_id": uuid(), "acquire": true,
            "payload": {"text": "also lint"}}}),
    );
    let held = p.wait(&mut router, |v| v["op"] == "error");
    assert_eq!(held["code"], "lease_held", "{held}");
    assert_eq!(held["controller"]["lease_epoch"], 1, "{held}");

    // The turn ends: the Mac's receipt completes.
    let r = rid.clone();
    m.wait(&mut router, move |v| {
        v["op"] == "receipt" && v["request_id"] == r.as_str() && v["state"] == "executing"
    });
    std::fs::write(fake.join("complete"), "").unwrap();
    let r = rid.clone();
    let done = m.wait(&mut router, move |v| {
        v["op"] == "receipt" && v["request_id"] == r.as_str() && v["state"] == "completed"
    });
    assert_eq!(done["detail"], "done", "{done}");
    // The phone reads it by id (receipts are r8's: no per-principal view).
    p.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "receipt_query", "id": uuid(),
            "binding": p.read(&sid), "request_ids": [rid]}}),
    );
    let receipts = p.wait(&mut router, |v| v["op"] == "receipts");
    assert_eq!(receipts["receipts"][0]["state"], "completed", "{receipts}");

    // A browser with a view grant sees the session, never the lease.
    next_init();
    let wall = r9log::host_now().wall_ms;
    let (grant, key) = rig.log.grant(
        "dev-phone",
        "aaaaaaaa-2222-4222-8222-000000000001",
        HOST,
        1,
        None,
        &["view"],
        wall,
        wall + 600_000,
    );
    let mut b = Dev::connect(
        &mut router,
        "browser",
        "relay",
        &rig.log,
        &Identity::browser(grant, key).unwrap(),
    );
    b.list(&mut router, &sid);
    let refused = b.acquire(&mut router, &sid, None);
    assert_eq!(refused["code"], "forbidden", "{refused}");
    let rt = rig.runtime_log();
    assert!(
        rt.contains("welcomed member:dev-mac (native, direct)"),
        "{rt}"
    );
    assert!(
        rt.contains("welcomed member:dev-phone (native, relay)"),
        "{rt}"
    );
}

/// R9.10 takeover: the phone's plain acquire is `lease_held`; a confirmed
/// takeover naming the Mac's controller moves the lease (epoch 2), the Mac
/// hears `takeover` and its input under the old epoch is `stale_lease`
/// (it keeps its attachment and view: no fence), the phone's input is
/// written. A lease nobody renews ends after 15 s: the Mac then acquires
/// without a takeover (a new epoch).
#[test]
fn a_confirmed_takeover_moves_the_lease_between_devices_and_an_unrenewed_one_expires() {
    let rig = Rig::new();
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut m = Dev::connect(&mut router, "mac", "direct", log, &mac());
    next_init();
    let mut p = Dev::connect(&mut router, "phone", "relay", log, &phone());
    m.list(&mut router, &sid);
    p.list(&mut router, &sid);
    let pg = pg_of(&m, &sid);
    let lease = m.acquire(&mut router, &sid, None);
    assert_eq!(lease["op"], "lease", "{lease}");
    assert_eq!(lease["binding"]["lease_epoch"], 1);
    let m_stream = m.subscribe(&mut router, &sid, &pg);

    let held = p.acquire(&mut router, &sid, None);
    assert_eq!(held["code"], "lease_held", "{held}");
    let controller = held["controller"].clone();
    let taken = p.acquire(&mut router, &sid, Some(&controller));
    assert_eq!(taken["op"], "lease", "{taken}");
    assert_eq!(taken["binding"]["lease_epoch"], 2);
    let lost = m.wait(&mut router, |v| {
        v["op"] == "lease_changed" && v["lease_epoch"] == 2
    });
    assert_eq!(lost["reason"], "takeover", "{lost}");

    m.input(&mut router, &sid, &pg, &m_stream, 1, 0, b"OLD-HOLDER\r");
    let stale = m.wait(&mut router, |v| {
        v["__type"] == "terminal" && v["op"] == "error"
    });
    assert_eq!(stale["code"], "stale_lease", "{stale}");
    m.list(&mut router, &sid);

    let p_stream = p.subscribe(&mut router, &sid, &pg);
    p.input(&mut router, &sid, &pg, &p_stream, 2, 0, b"NEW-HOLDER\r");
    p.wait(&mut router, |v| {
        v["__type"] == "terminal" && v["op"] == "written"
    });
    agent_input(&fake, "NEW-HOLDER");
    let typed = std::fs::read_to_string(fake.join("input")).unwrap_or_default();
    assert!(!typed.contains("OLD-HOLDER"), "{typed}");

    // Nobody renews: after 15 s the lease is gone, a plain acquire works.
    std::thread::sleep(Duration::from_millis(16_000));
    let again = m.acquire(&mut router, &sid, None);
    assert_eq!(again["op"], "lease", "{again}");
    // A new epoch above the takeover's (the expiry moved it too).
    assert!(
        again["binding"]["lease_epoch"].as_u64().unwrap() > 2,
        "{again}"
    );
}

/// R9.10 / r8 §G: an approval opened while the Mac holds the lease goes to
/// every attachment with control (the Mac's and the phone's, and a card in
/// the phone's chat); the phone answers without the lease, first answer
/// wins: the agent gets the phone's deny, the Mac's late answer is
/// `stale_target`, both hear `approval_closed` `answered_remote`, and the
/// Mac still holds the lease. A bot without the `approval` op gets no
/// approval and no card in its chat, and can't answer (`forbidden`).
#[test]
fn an_approval_is_answered_by_one_device_while_another_holds_the_lease() {
    let rig = Rig::new();
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut m = Dev::connect(&mut router, "mac", "direct", log, &mac());
    next_init();
    let mut p = Dev::connect(&mut router, "phone", "relay", log, &phone());
    next_init();
    let mut bt = Dev::connect(&mut router, "bot", "relay", log, &bot());
    for d in [&mut m, &mut p, &mut bt] {
        d.list(&mut router, &sid);
    }
    let lease = m.acquire(&mut router, &sid, None);
    assert_eq!(lease["binding"]["lease_epoch"], 1, "{lease}");
    p.open_chat(&mut router, &sid);
    bt.open_chat(&mut router, &sid);
    p.gather(&mut router, Duration::from_millis(300));
    bt.gather(&mut router, Duration::from_millis(300));

    ask(&fake, 1);
    let request = m.wait(&mut router, |v| v["op"] == "approval_request");
    let ap = request["approval_id"].as_str().unwrap().to_string();
    assert_eq!(request["tool"], "Bash");
    p.wait(&mut router, |v| v["op"] == "approval_request");
    let card = format!("approval-{ap}");
    let c = card.clone();
    p.wait(&mut router, move |v| {
        v["__type"] == "agentChat" && v["op"] == "message" && v["messageId"] == c.as_str()
    });
    // The bot: no approval, no card.
    let seen = bt.gather(&mut router, Duration::from_millis(1_500));
    assert!(
        !seen
            .iter()
            .any(|v| v["op"] == "approval_request" || v.to_string().contains(&card)),
        "{seen:?}"
    );
    bt.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid(),
            "binding": bt.read(&sid), "kind": "approval", "request_id": uuid(),
            "payload": {"approval_id": ap, "decision": "allow_once"}}}),
    );
    let forbidden = bt.wait(&mut router, |v| v["op"] == "error");
    assert_eq!(forbidden["code"], "forbidden", "{forbidden}");

    // The phone answers, lease-free.
    let rid = uuid();
    p.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid(),
            "binding": p.read(&sid), "kind": "approval", "request_id": rid,
            "payload": {"approval_id": ap, "decision": "deny", "message": "not now"}}}),
    );
    let r = rid.clone();
    p.wait(&mut router, move |v| {
        v["op"] == "receipt" && v["request_id"] == r.as_str() && v["state"] == "accepted"
    });
    // The Mac's late answer, under its lease.
    m.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid(),
            "binding": m.lease(&sid, 1), "kind": "approval", "request_id": uuid(),
            "payload": {"approval_id": ap, "decision": "allow_once"}}}),
    );
    let late = m.wait(&mut router, |v| v["op"] == "error");
    assert_eq!(late["code"], "stale_target", "{late}");
    agent_event(&fake, "answer 1 deny not now");
    let r = rid.clone();
    p.wait(&mut router, move |v| {
        v["op"] == "receipt" && v["request_id"] == r.as_str() && v["state"] == "completed"
    });
    for d in [&mut m, &mut p] {
        let closed = d.wait(&mut router, |v| v["op"] == "approval_closed");
        assert_eq!(closed["reason"], "answered_remote", "{closed}");
    }
    // The Mac's lease is untouched.
    m.send(
        &mut router,
        json!({"type": "session", "data": {"v": 1, "op": "renew", "id": uuid(),
            "binding": m.lease(&sid, 1)}}),
    );
    let renewed = m.wait(&mut router, |v| v["op"] == "lease" || v["op"] == "error");
    assert_eq!(renewed["op"], "lease", "{renewed}");
    assert_eq!(renewed["binding"]["lease_epoch"], 1);
}

/// A removal carried by one device fences another device's live
/// attachments while it holds the lease: the phone (two attachments, one
/// holding the lease, its terminal input queued at the worker's writer)
/// is removed by the Mac's carried entry. Both phone attachments get
/// `unauthorized` "removed" and Atem's close, the Mac hears the lease
/// revoked, the bot is untouched, and the queued input is dropped at the
/// write boundary, never written. The phone can't come back.
#[test]
fn a_removal_carried_by_one_device_fences_anothers_attachments_and_drops_its_queued_input() {
    let mut rig = Rig::new();
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut m = Dev::connect(&mut router, "mac", "direct", log, &mac());
    next_init();
    let mut p1 = Dev::connect(&mut router, "phone-1", "relay", log, &phone());
    next_init();
    let mut p2 = Dev::connect(&mut router, "phone-2", "relay", log, &phone());
    next_init();
    let mut bt = Dev::connect(&mut router, "bot", "relay", log, &bot());
    for d in [&mut m, &mut p1, &mut p2, &mut bt] {
        d.list(&mut router, &sid);
    }
    let pg = pg_of(&p1, &sid);
    let lease = p1.acquire(&mut router, &sid, None);
    assert_eq!(lease["binding"]["lease_epoch"], 1, "{lease}");
    let stream = p1.subscribe(&mut router, &sid, &pg);
    // The phone types; the worker holds the write before its epoch check.
    std::fs::write(rig.faults.join("hold"), "").unwrap();
    p1.input(&mut router, &sid, &pg, &stream, 1, 0, b"QUEUED-BYTES\r");
    std::thread::sleep(Duration::from_millis(500));

    let removal = rig.log.remove("dev-phone");
    let entry = atem_client::SignedObject::parse(removal.to_string().as_bytes()).unwrap();
    let (_, frame) = m.a.send_membership(&[entry], client_ms()).unwrap();
    router.frame(&m.h, &frame);
    m.wait(&mut router, |v| {
        v["op"] == "membership_head" && !v["re"].is_null()
    });
    let revoked = m.wait(&mut router, |v| {
        v["op"] == "lease_changed" && v["reason"] == "revoked"
    });
    assert!(revoked["controller"].is_null(), "{revoked}");
    for p in [&mut p1, &mut p2] {
        let seen = p.gather(&mut router, Duration::from_millis(800));
        assert!(
            seen.iter()
                .any(|v| v["code"] == "unauthorized" && v["detail"] == "removed"),
            "{}: {seen:?}",
            p.h
        );
    }
    // Both channels are gone; the bot goes on.
    bt.list(&mut router, &sid);
    std::fs::remove_file(rig.faults.join("hold")).unwrap();
    std::thread::sleep(Duration::from_millis(1_500));
    let typed = std::fs::read_to_string(fake.join("input")).unwrap_or_default();
    assert!(
        !typed.contains("QUEUED-BYTES"),
        "the queued input was written: {typed}"
    );
    next_init();
    assert_eq!(
        router
            .connect("phone-3", &rig.log, HOST, &phone())
            .err()
            .map(|e| e.0),
        Some("unauthorized".to_string())
    );
}

/// R9.10 Mac off: Atem's link went to the Mac's Astation (:8080); it drops.
/// Every channel on it ends and nothing is carried: the link comes back
/// (here as the relay), the Mac's old lease is left to expire (no restore),
/// a frame for an old handle gets `unknown_channel`, and the phone,
/// connecting over the relay on its own (host key, head and fences need
/// neither the Mac nor the cred agent), takes the lease once it expired and
/// types into the session.
#[test]
fn the_macs_link_drops_and_the_phone_goes_on_over_the_relay() {
    let rig = Rig::new();
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut m = Dev::connect(&mut router, "mac", "direct", log, &mac());
    next_init();
    let mut p = Dev::connect(&mut router, "phone", "relay", log, &phone());
    m.list(&mut router, &sid);
    p.list(&mut router, &sid);
    let lease = m.acquire(&mut router, &sid, None);
    assert_eq!(lease["binding"]["lease_epoch"], 1, "{lease}");
    let dropped_at = Instant::now();

    // The Mac's Astation goes away with Atem's link.
    rig.astation.close(router.link);
    drop(router);
    let mut router = Router::new(&rig.astation);
    let mut p = Dev::connect(&mut router, "phone-relay", "relay", log, &phone());
    p.list(&mut router, &sid);
    let pg = pg_of(&p, &sid);
    // A frame for a handle of the old link: unknown here.
    router.frame(
        "mac",
        br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    );
    assert!(matches!(router.next("mac"), Out::Close(Some(r)) if r == "unknown_channel"));
    // The Mac's lease isn't restored to anyone; it expires.
    let held = p.acquire(&mut router, &sid, None);
    assert_eq!(held["code"], "lease_held", "{held}");
    let left = Duration::from_millis(16_000).saturating_sub(dropped_at.elapsed());
    std::thread::sleep(left);
    let lease = p.acquire(&mut router, &sid, None);
    assert_eq!(lease["op"], "lease", "{lease}");
    let stream = p.subscribe(&mut router, &sid, &pg);
    p.input(
        &mut router,
        &sid,
        &pg,
        &stream,
        lease["binding"]["lease_epoch"].as_u64().unwrap(),
        0,
        b"FROM-PHONE\r",
    );
    p.wait(&mut router, |v| {
        v["__type"] == "terminal" && v["op"] == "written"
    });
    agent_input(&fake, "FROM-PHONE");
    drop(m);
    let rt = rig.runtime_log();
    assert!(
        rt.contains("the link dropped; every channel on it closed"),
        "{rt}"
    );
}

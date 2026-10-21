//! The headless multi-device harness (atem-session-v1.md Appendix r9), for
//! Astation's team: one real `atem runtime` host on a temp profile (a
//! verified pairing, a pinned device list, a fake Claude Code session) and
//! N simulated clients that are the shared core (`atem_client::connect`)
//! in the §R9.7a channel envelope on the runtime's link to a fake Astation,
//! which also plays the relay. It walks every client through admission, a
//! lease, a prompt, an approval with sealed push hints (§R9.9) and a seen,
//! checks each step and prints a transcript. Never part of a release build
//! (a test target).
//!
//! Limits: Linux only (the sandbox cleans up through `/proc`; on macOS
//! the target compiles to nothing); the agent is the fake Claude Code only
//! (no fake Codex yet); the flow is fixed, with no entry point for
//! Astation's own router or relay (the fake Astation plays both).
//!
//! A prebuilt copy (no source build needed) is the CI artifact
//! `atem-r9-harness-NONPRODUCTION-<version>-linux-x86_64`
//! (`scripts/package-atem-r9-harness.sh`; its `run-harness.sh` sets
//! `ATEM_HARNESS_ATEM_BIN` and `ATEM_HARNESS_FAKE_AGENT` to the packaged
//! `atem` and fake agent).
//!
//! Run (Linux; debug or release build):
//!
//! ```text
//! cargo test --test r9_harness -- --nocapture
//! ATEM_HARNESS_PHONES=3 ATEM_HARNESS_BOTS=2 ATEM_HARNESS_BROWSERS=2 \
//!     cargo test --test r9_harness -- --nocapture
//! ```
//!
//! - phones (`dev-phone-<n>`, native, `control`+`view`): `ATEM_HARNESS_PHONES`
//!   (default 2, at least 1);
//! - bots (`svc-bot-<n>`, services with `prompt`+`view`, no `approval`):
//!   `ATEM_HARNESS_BOTS` (default 1);
//! - browsers (`view` grants for the session, issued by `dev-phone-1`):
//!   `ATEM_HARNESS_BROWSERS` (default 1).
//!
//! The Mac (`dev-mac`, the genesis manager) is in the device list and gets
//! its own sealed hint, but doesn't connect. `ATEM_HARNESS_OUT=<file>`
//! also writes the transcript there (one JSON object per line: `step`,
//! `client`, what was sent or received). The keys are deterministic test
//! keys (`tests/support/r9log.rs`), so a run can be replayed against the
//! same device list.
#![cfg(target_os = "linux")]

mod support;

use atem_client::SignedObject;
use atem_client::connect::{Attached, Event as CEvent, Identity};
use atem_client::push::{self, Hint, HintState, Seen, Verifier};
use serde_json::{Value, json};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::{Out, Router, client_ms, write_pin};
use support::r9log::{self, MAC, TestLog, auth, enc, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-harness";
const HOST: &str = "host-harness";
const WAIT: Duration = Duration::from_secs(20);

fn count(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(default)
}

/// The transcript: stderr, and `ATEM_HARNESS_OUT` when set.
struct Transcript(Option<std::fs::File>);

impl Transcript {
    fn note(&mut self, step: &str, client: &str, what: Value) {
        eprintln!("harness {step:<10} {client:<14} {what}");
        if let Some(f) = &mut self.0 {
            let _ = writeln!(
                f,
                "{}",
                json!({"step": step, "client": client, "what": what})
            );
        }
    }
}

/// One client's channel.
struct Dev {
    name: String,
    a: Attached,
    backlog: Vec<Value>,
}

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
        CEvent::Seen { re, .. } => json!({"op": "seen", "re": re}),
        _ => return None,
    };
    v["__type"] = json!("session");
    Some(v)
}

impl Dev {
    fn send(&mut self, router: &mut Router, msg: Value) {
        let frame = self.a.send(&msg, client_ms()).unwrap();
        router.frame(&self.name, &frame);
    }

    fn wait(&mut self, router: &mut Router, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(at) = self.backlog.iter().position(&pred) {
                return self.backlog.remove(at);
            }
            assert!(
                Instant::now() < deadline,
                "{}: {:?}",
                self.name,
                self.backlog
            );
            match router.next(&self.name) {
                Out::Frame(f) => {
                    let events = self.a.on_frame(&f, client_ms()).unwrap();
                    self.backlog.extend(events.iter().filter_map(data_of));
                }
                Out::Close(r) => panic!("{} closed ({r:?}): {:?}", self.name, self.backlog),
            }
        }
    }

    /// Everything that arrives within `wait`.
    fn gather(&mut self, router: &mut Router, wait: Duration) -> Vec<Value> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if router.quiet(&self.name, Duration::from_millis(100)) {
                continue;
            }
            if let Out::Frame(f) = router.next(&self.name) {
                let events = self.a.on_frame(&f, client_ms()).unwrap();
                self.backlog.extend(events.iter().filter_map(data_of));
            }
        }
        std::mem::take(&mut self.backlog)
    }

    fn binding(&self, sid: &str, lease: Option<u64>) -> Value {
        let mut b = json!({"target": self.a.target(sid).expect("listed"),
                           "attachment_gen": self.a.welcome().attachment_gen});
        if let Some(epoch) = lease {
            b["lease_epoch"] = json!(epoch);
        }
        b
    }

    /// `op` with `fields` and a fresh id; the reply to it.
    fn request(&mut self, router: &mut Router, op: &str, fields: Value) -> Value {
        let id = uuid::Uuid::new_v4().to_string();
        let mut data = json!({"v": 1, "op": op, "id": id});
        for (k, v) in fields.as_object().unwrap() {
            data[k] = v.clone();
        }
        self.send(router, json!({"type": "session", "data": data}));
        self.wait(router, move |v| v["re"] == id.as_str())
    }
}

/// The next relay message Atem sent (`push_hint`, `push_seen`).
fn relay(router: &mut Router) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let v = router.other_within(left).expect("a relay message");
        if v["type"] == "relay" {
            return v;
        }
    }
}

fn hints(message: &Value, log: &TestLog) -> Vec<Hint> {
    assert_eq!(message["op"], "push_hint", "{message}");
    message["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let o = SignedObject::parse(h.to_string().as_bytes()).unwrap();
            Hint::verify(&o, &log.log, r9log::host_now().wall_ms, Verifier::Client).unwrap()
        })
        .collect()
}

#[test]
fn harness() {
    let (phones, bots, browsers) = (
        count("ATEM_HARNESS_PHONES", 2).max(1),
        count("ATEM_HARNESS_BOTS", 1),
        count("ATEM_HARNESS_BROWSERS", 1),
    );
    let mut t =
        Transcript(std::env::var_os("ATEM_HARNESS_OUT").map(|p| std::fs::File::create(p).unwrap()));

    // The host: a verified pairing and its device list.
    let sandbox = Sandbox::new();
    write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
    let host_seed = secret("harness host seed");
    let mut log = TestLog::genesis(ACCOUNT, &secret("harness astation"));
    log.add_host(HOST, 1, &host_seed);
    let phone_ids: Vec<String> = (1..=phones).map(|n| format!("dev-phone-{n}")).collect();
    for p in &phone_ids {
        log.add_native(p, &["control", "view"]);
    }
    let bot_ids: Vec<String> = (1..=bots).map(|n| format!("svc-bot-{n}")).collect();
    for b in &bot_ids {
        log.add_service(
            b,
            &[HOST],
            None,
            &["prompt", "view"],
            r9log::host_now().wall_ms + 3_600_000,
        );
    }
    write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
    let astation = FakeAstation::start();
    let runtime_log = sandbox.dir.path().join("runtime.log");
    let out = std::fs::File::create(&runtime_log).unwrap();
    let mut runtime: Child = Command::new(support::atem_bin())
        .arg("runtime")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &sandbox.home)
        .env("XDG_RUNTIME_DIR", &sandbox.run)
        .env("ASTATION_WS", &astation.url)
        .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
        .stdin(Stdio::null())
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .spawn()
        .unwrap();
    let config = sandbox.config();
    within("the runtime to listen", || {
        config.join("runtime.socket").exists()
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(
            &sandbox, &astation, &mut log, &phone_ids, &bot_ids, browsers, &mut t,
        )
    }));
    let _ = runtime.kill();
    let _ = runtime.wait();
    if let Err(e) = result {
        eprintln!(
            "--- runtime log ---\n{}",
            std::fs::read_to_string(&runtime_log).unwrap_or_default()
        );
        std::panic::resume_unwind(e);
    }
}

/// A Claude session running the fake agent: its id and control directory.
fn agent(sandbox: &Sandbox) -> (String, PathBuf) {
    let fake = sandbox.dir.path().join("fake");
    std::fs::create_dir_all(&fake).unwrap();
    // The fake Claude Code: the source tree's, or the packaged copy.
    let script = std::env::var_os("ATEM_HARNESS_FAKE_AGENT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approvals/fake-agent.py")
        });
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    if perms.mode() & 0o111 != 0o111 {
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    let mut frontend = sandbox.spawn(
        &["agent", "launch", "claude"],
        &sandbox.home,
        &[
            ("CLAUDE_CLI_BIN", script.to_str().unwrap()),
            ("FAKE_DIR", fake.to_str().unwrap()),
        ],
    );
    let events = fake.join("events");
    within("the agent to start", || {
        std::fs::read_to_string(&events).is_ok_and(|e| e.contains("started"))
    });
    let sid = frontend.detach();
    sandbox.track();
    (sid, fake)
}

fn ask(fake: &Path) {
    let request = json!({"tool_name": "Bash",
        "tool_input": {"command": "npm test", "description": "run the tests"}});
    let tmp = fake.join("tmp-ask-1");
    std::fs::write(&tmp, request.to_string()).unwrap();
    std::fs::rename(&tmp, fake.join("ask-1.json")).unwrap();
}

fn run(
    sandbox: &Sandbox,
    astation: &FakeAstation,
    log: &mut TestLog,
    phone_ids: &[String],
    bot_ids: &[String],
    browsers: usize,
    t: &mut Transcript,
) {
    let (sid, fake) = agent(sandbox);
    let mut router = Router::new(astation);
    // Browsers' grants name the session (issued by the first phone).
    let mut identities: Vec<(String, Identity)> = phone_ids
        .iter()
        .map(|p| (p.clone(), Identity::native(p, auth(p))))
        .chain(
            bot_ids
                .iter()
                .map(|b| (b.clone(), Identity::service(b, auth(b)))),
        )
        .collect();
    let now = r9log::host_now().wall_ms;
    for n in 1..=browsers {
        let grant_id = uuid::Uuid::new_v4().to_string();
        let (grant, key) = log.grant(
            &phone_ids[0],
            &grant_id,
            HOST,
            1,
            Some(&sid),
            &["view"],
            now,
            now + 3_600_000,
        );
        identities.push((
            format!("browser-{n}"),
            Identity::browser(grant, key).unwrap(),
        ));
    }

    // 1. Admission: every client's handshake and hello (one init a second
    // per link, §R9.7a).
    let mut devs: Vec<Dev> = Vec::new();
    for (i, (name, who)) in identities.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(1_100));
        }
        let transport = if name.starts_with("browser") {
            "direct"
        } else {
            "relay"
        };
        let a = router
            .connect_via(name, transport, log, HOST, who)
            .unwrap_or_else(|e| panic!("{name} refused: {e:?}"));
        let w = a.welcome();
        t.note(
            "admission",
            name,
            json!({"principal": w.principal, "client_kind": w.client_kind.as_str(),
                   "permissions": w.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                   "head_seq": w.head.seq}),
        );
        devs.push(Dev {
            name: name.clone(),
            a,
            backlog: Vec::new(),
        });
    }
    // Everyone subscribes to the registry and sees the session.
    for d in &mut devs {
        let sessions = d.request(&mut router, "list", json!({}));
        let listed: Vec<Value> = sessions["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["session_id"].clone())
            .collect();
        assert_eq!(listed, [json!(sid)], "{}: {sessions}", d.name);
        t.note("list", &d.name, json!({"sessions": listed}));
    }

    // The agent's chat is ready (its SessionStart came) before a prompt.
    let deadline = Instant::now() + WAIT;
    loop {
        let sessions = devs[0].request(&mut router, "list", json!({}));
        if sessions["sessions"][0]["activity"] == "ready" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent never became ready: {sessions}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // 2. The lease: the first phone acquires; the other phones hear it.
    let binding = devs[0].binding(&sid, None);
    let lease = devs[0].request(
        &mut router,
        "acquire",
        json!({"binding": binding, "takeover": false}),
    );
    assert_eq!(lease["op"], "lease", "{lease}");
    let epoch = lease["binding"]["lease_epoch"].as_u64().unwrap();
    t.note("lease", &devs[0].name, json!({"lease_epoch": epoch}));
    for d in devs.iter_mut().skip(1).take(phone_ids.len() - 1) {
        let changed = d.wait(&mut router, |v| v["op"] == "lease_changed");
        assert_eq!(changed["reason"], "granted", "{}: {changed}", d.name);
        t.note(
            "lease",
            &d.name,
            json!({"lease_changed": changed["reason"]}),
        );
    }

    // 3. A prompt under the lease completes at the turn's end; a bot's
    // prompt is lease_held while the phone holds it.
    let request_id = uuid::Uuid::new_v4().to_string();
    let binding = devs[0].binding(&sid, Some(epoch));
    let accepted = devs[0].request(
        &mut router,
        "submit",
        json!({"binding": binding, "kind": "prompt", "request_id": request_id,
               "payload": {"text": "run the tests"}}),
    );
    assert_eq!(accepted["state"], "accepted", "{accepted}");
    t.note("prompt", &devs[0].name, json!({"receipt": "accepted"}));
    let paste = fake.join("input");
    within("the prompt to reach the agent", || {
        String::from_utf8_lossy(&std::fs::read(&paste).unwrap_or_default())
            .contains("run the tests")
    });
    std::fs::write(fake.join("complete"), "turn-1").unwrap();
    let rid = request_id.clone();
    let done = devs[0].wait(&mut router, move |v| {
        v["op"] == "receipt" && v["request_id"] == rid.as_str() && v["state"] == "completed"
    });
    t.note(
        "prompt",
        &devs[0].name,
        json!({"receipt": done["state"], "detail": done["detail"]}),
    );
    let first_bot = phone_ids.len();
    if let Some(bot) = devs
        .get_mut(first_bot)
        .filter(|d| d.name.starts_with("svc"))
    {
        let binding = bot.binding(&sid, None);
        let refused = bot.request(
            &mut router,
            "submit",
            json!({"binding": binding, "kind": "prompt", "request_id": uuid::Uuid::new_v4().to_string(),
                   "acquire": true, "payload": {"text": "status?"}}),
        );
        assert_eq!(refused["code"], "lease_held", "{refused}");
        t.note("prompt", &bot.name, json!({"error": refused["code"]}));
    }

    // 4. An approval: every phone gets the card, bots and browsers none;
    // the relay gets one sealed hint per native member with control (the
    // Mac and every phone), each opened only with its device's key.
    ask(&fake);
    let mut ap = String::new();
    for d in devs.iter_mut().take(phone_ids.len()) {
        let request = d.wait(&mut router, |v| v["op"] == "approval_request");
        ap = request["approval_id"].as_str().unwrap().to_string();
        t.note("approval", &d.name, json!({"approval_request": ap}));
    }
    for d in devs.iter_mut().skip(phone_ids.len()) {
        let got = d.gather(&mut router, Duration::from_millis(500));
        assert!(
            !got.iter().any(|v| v["op"] == "approval_request"),
            "{}: {got:?}",
            d.name
        );
    }
    let message = relay(&mut router);
    let hs = hints(&message, log);
    let mut recipients = vec![MAC.to_string()];
    recipients.extend(phone_ids.iter().cloned());
    recipients.sort();
    let mut got: Vec<String> = hs
        .iter()
        .map(|h| match h.state() {
            HintState::Open { device_id, .. } => device_id.clone(),
            _ => panic!("an open hint"),
        })
        .collect();
    got.sort();
    assert_eq!(got, recipients);
    for h in &hs {
        let HintState::Open { device_id, .. } = h.state() else {
            unreachable!()
        };
        let plain = h.open(&log.keys, &enc(device_id), device_id).unwrap();
        assert_eq!(plain.tool, "Bash");
        t.note(
            "push",
            device_id,
            json!({"hint": "open", "approval_id": h.key().approval_id, "tool": plain.tool}),
        );
    }
    router.send_raw(push::push_ack(&hs.iter().map(Hint::identity).collect::<Vec<_>>()).to_string());

    // 5. A seen from the last phone: answered, signed once for the relay.
    let last = phone_ids.len() - 1;
    let binding = devs[last].binding(&sid, None);
    let reply = devs[last].request(
        &mut router,
        "approval_seen",
        json!({"binding": binding, "approval_id": ap}),
    );
    assert_eq!(reply["op"], "seen", "{reply}");
    let sent = relay(&mut router);
    assert_eq!(sent["op"], "push_seen", "{sent}");
    let seen = Seen::verify(
        &SignedObject::parse(sent["seen"].to_string().as_bytes()).unwrap(),
        &log.log,
    )
    .unwrap();
    assert_eq!(seen.device_id(), phone_ids[last]);
    t.note(
        "seen",
        &devs[last].name,
        json!({"push_seen": seen.device_id()}),
    );
    router.send_raw(push::push_ack(&[seen.identity()]).to_string());
    // A view-only browser's seen is refused.
    if let Some(b) = devs.iter_mut().find(|d| d.name.starts_with("browser")) {
        let binding = b.binding(&sid, None);
        let reply = b.request(
            &mut router,
            "approval_seen",
            json!({"binding": binding, "approval_id": ap}),
        );
        assert_eq!(reply["code"], "forbidden", "{reply}");
        t.note("seen", &b.name, json!({"error": reply["code"]}));
    }

    // 6. The first phone answers (lease-free): completed, closed for every
    // phone, and a resolved hint.
    let binding = devs[0].binding(&sid, None);
    let rid = uuid::Uuid::new_v4().to_string();
    let accepted = devs[0].request(
        &mut router,
        "submit",
        json!({"binding": binding, "kind": "approval", "request_id": rid,
               "payload": {"approval_id": ap, "decision": "allow_once"}}),
    );
    assert_eq!(accepted["state"], "accepted", "{accepted}");
    let r = rid.clone();
    devs[0].wait(&mut router, move |v| {
        v["op"] == "receipt" && v["request_id"] == r.as_str() && v["state"] == "completed"
    });
    for d in devs.iter_mut().take(phone_ids.len()) {
        let closed = d.wait(&mut router, |v| v["op"] == "approval_closed");
        assert_eq!(closed["reason"], "answered_remote", "{closed}");
        t.note(
            "answer",
            &d.name,
            json!({"approval_closed": closed["reason"]}),
        );
    }
    let resolved = hints(&relay(&mut router), log);
    assert!(matches!(
        resolved[0].state(),
        HintState::Resolved { reason, .. } if reason == "answered_remote"
    ));
    t.note(
        "push",
        "relay",
        json!({"hint": "resolved", "reason": "answered_remote"}),
    );
}

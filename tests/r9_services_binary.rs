//! r9 services (atem-session-v1.md §R9.6) in the real `atem runtime`
//! process: the scoped bots an Agora.Build integration (a Station agent
//! module, a Discord bridge, a custom app) connects as. A temp profile with
//! a pinned device list whose services are enrolled with the shared core's
//! builders (`atem_client::membership::service_add` and friends), the
//! runtime's link to a fake Astation, a fake Claude Code
//! (`tests/fixtures/approvals/fake-agent.py`) and clients that are the
//! shared core in the channel envelope on that link.
//!
//! Each test is one focused scenario: approvals reaching a service with
//! the `approval` op; session and host restrictions; live renewal and
//! narrowing; a grant's revocation beside a service; `K` rotation with a
//! service attached; a service refused as the reconciler of a held host;
//! and the current contract that a service with control may `revoke_grant`
//! a browser companion.
#![cfg(target_os = "linux")]

mod support;

use atem_client::connect::{Attached, Event as CEvent, Identity};
use atem_client::membership::{ChangeRefusal, ServiceScope, check_change};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::{Out, Router, client_ms, write_pin};
use support::r9log::{self, MAC, TestLog, auth, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-svc";
const HOST: &str = "host-svc";
const WAIT: Duration = Duration::from_secs(20);
const HOUR: u64 = 3_600_000;

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    runtime: Option<Child>,
    log: TestLog,
    /// The project-hash table in place of the cred agent
    /// (`ATEM_TEST_PROJECT_HASHES`, debug builds), when set.
    projects: Option<PathBuf>,
}

/// What the device list holds besides the Mac and this host.
fn services(log: &mut TestLog, wall: u64) {
    log.add_native("dev-phone", &["control", "view"]);
    log.enroll_service(
        "svc-bot",
        &ServiceScope::new([HOST]).ops(["prompt"]),
        wall + HOUR,
    );
    log.enroll_service(
        "svc-appr",
        &ServiceScope::new([HOST]).ops(["approval"]),
        wall + HOUR,
    );
    log.enroll_service("svc-view", &ServiceScope::new([HOST]), wall + HOUR);
}

impl Rig {
    /// A verified pairing as `HOST` and its device list: the Mac (genesis),
    /// this host, a phone (control), `svc-bot` (`prompt`), `svc-appr`
    /// (`approval`) and `svc-view` (`view` only), then `more`. `held`: a
    /// recorded device-list write fault (the start is held, §R9.3).
    fn new(more: impl FnOnce(&mut TestLog), projects: Option<PathBuf>, held: bool) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("services host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("services astation"));
        log.add_host(HOST, 1, &host_seed);
        services(&mut log, r9log::host_now().wall_ms);
        more(&mut log);
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        if held {
            std::fs::write(
                sandbox.config().join("pairing").join("membership.fault"),
                br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
            )
            .unwrap();
        }
        let mut rig = Rig {
            sandbox,
            astation: FakeAstation::start(),
            runtime: None,
            log,
            projects,
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
            .envs(
                self.projects
                    .iter()
                    .map(|p| ("ATEM_TEST_PROJECT_HASHES", p)),
            )
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

    fn status(&self) -> String {
        let (out, err, _) = self.sandbox.atem(&["status"]);
        format!("{out}{err}")
    }

    /// A Claude session running the fake agent, detached: its id and the
    /// fake's control directory. Its launch project is `local:home`.
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

fn service(id: &str) -> Identity {
    Identity::service(id, auth(id))
}

/// Inits are answered one a second per link (§R9.7a).
fn next_init() {
    std::thread::sleep(Duration::from_millis(1_100));
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn signed(value: &Value) -> atem_client::SignedObject {
    atem_client::SignedObject::parse(value.to_string().as_bytes()).unwrap()
}

fn permissions(a: &Attached) -> Vec<&'static str> {
    a.welcome().permissions.iter().map(|p| p.as_str()).collect()
}

/// One device's channel: its handle, the shared core's attachment, and
/// what it received but no step took yet.
struct Dev {
    h: String,
    a: Attached,
    backlog: Vec<Value>,
}

/// An event as wire JSON (`data`, with its envelope type under `__type`;
/// a fence as `__fenced`).
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
        CEvent::Fenced(e) => {
            let mut d = serde_json::from_slice::<Value>(&e.to_bytes()).ok()?["data"].clone();
            d["__fenced"] = json!(true);
            d
        }
        CEvent::Error(e) => serde_json::from_slice::<Value>(&e.to_bytes()).ok()?["data"].clone(),
        CEvent::GrantRevoked { re } => json!({"op": "grant_revoked", "re": re}),
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
    fn connect(router: &mut Router, h: &str, log: &TestLog, who: &Identity) -> Dev {
        let a = router
            .connect(h, log, HOST, who)
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

    /// The fence this channel gets (its last record), then Atem's close.
    fn fenced(&mut self, router: &mut Router) -> Value {
        let fence = self.wait(router, |v| v["__fenced"] == true);
        assert!(
            matches!(router.next(&self.h), Out::Close(_)),
            "{}: closed after its fence",
            self.h
        );
        fence
    }

    /// The read binding of `sid` (the registry named its target).
    fn read(&self, sid: &str) -> Value {
        json!({"target": self.a.target(sid).expect("listed"),
               "attachment_gen": self.a.welcome().attachment_gen})
    }

    /// The session ids of a fresh `list`.
    fn sessions(&mut self, router: &mut Router) -> Vec<String> {
        self.send(
            router,
            json!({"type": "session", "data": {"v": 1, "op": "list", "id": uuid()}}),
        );
        let sessions = self.wait(router, |v| v["op"] == "sessions");
        sessions["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["session_id"].as_str().unwrap().to_string())
            .collect()
    }

    /// Lists until `sid` shows (a project hash may still be on its way:
    /// the runtime asks the hasher off its pass).
    fn sees(&mut self, router: &mut Router, sid: &str) {
        let deadline = Instant::now() + WAIT;
        while !self.sessions(router).iter().any(|s| s == sid) {
            assert!(Instant::now() < deadline, "{} never saw {sid}", self.h);
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// A session request with `id`: its reply (or error).
    fn request(&mut self, router: &mut Router, mut data: Value) -> Value {
        let id = uuid();
        data["v"] = json!(1);
        data["id"] = json!(id);
        self.send(router, json!({"type": "session", "data": data}));
        self.wait(router, move |v| v["re"] == id.as_str())
    }

    /// An approval answer (lease-free, r8 §G): the first reply to it.
    fn answer(&mut self, router: &mut Router, sid: &str, ap: &str, rid: &str) -> Value {
        let binding = self.read(sid);
        self.request(
            router,
            json!({"op": "submit", "binding": binding, "kind": "approval", "request_id": rid,
                "payload": {"approval_id": ap, "decision": "allow_once"}}),
        )
    }

    /// The Mac carries `entries` on its channel: Atem's new head.
    fn carry(&mut self, router: &mut Router, entries: &[Value]) {
        let entries: Vec<_> = entries.iter().map(signed).collect();
        let (re, frame) = self.a.send_membership(&entries, client_ms()).unwrap();
        router.frame(&self.h, &frame);
        let head = self.wait(router, move |v| {
            v["op"] == "membership_head" && v["re"] == re.as_str()
        });
        assert!(head["head"]["seq"].is_u64(), "{head}");
    }
}

/// §R9.6 + r8 §G: an approval reaches a service whose ops have `approval`
/// (`approval_request` on its attachment), whatever lease anyone holds; it
/// marks the card seen (`seen`, nothing signed for a service) and answers
/// it lease-free: the receipt completes, the agent gets the allow, and the
/// Mac hears `approval_closed` `answered_remote`. A service with control
/// but without `approval` (`svc-bot`) gets no request and its answer is
/// `forbidden`; a view-only one likewise.
#[test]
fn an_approval_reaches_a_service_with_the_approval_op_which_answers_it() {
    let rig = Rig::new(|_| {}, None, false);
    let (sid, fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut m = Dev::connect(&mut router, "mac", log, &mac());
    next_init();
    let mut appr = Dev::connect(&mut router, "appr", log, &service("svc-appr"));
    assert_eq!(permissions(&appr.a), ["control", "view"]);
    next_init();
    let mut bot = Dev::connect(&mut router, "bot", log, &service("svc-bot"));
    next_init();
    let mut view = Dev::connect(&mut router, "view", log, &service("svc-view"));
    assert_eq!(permissions(&view.a), ["view"]);
    for d in [&mut m, &mut appr, &mut bot, &mut view] {
        d.sees(&mut router, &sid);
    }

    ask(&fake, 1);
    let request = appr.wait(&mut router, |v| v["op"] == "approval_request");
    let ap = request["approval_id"].as_str().unwrap().to_string();
    assert_eq!(request["tool"], "Bash", "{request}");
    m.wait(&mut router, |v| v["op"] == "approval_request");
    for d in [&mut bot, &mut view] {
        let seen = d.gather(&mut router, Duration::from_millis(1_500));
        assert!(
            !seen.iter().any(|v| v["op"] == "approval_request"),
            "{}: {seen:?}",
            d.h
        );
        let refused = d.answer(&mut router, &sid, &ap, &uuid());
        assert_eq!(refused["code"], "forbidden", "{}: {refused}", d.h);
    }

    // Seen (a focused card on the bot's side): answered, never signed.
    let binding = appr.read(&sid);
    let seen = appr.request(
        &mut router,
        json!({"op": "approval_seen", "binding": binding, "approval_id": ap}),
    );
    assert_eq!(seen["op"], "seen", "{seen}");

    // The answer, without any lease.
    let rid = uuid();
    let accepted = appr.answer(&mut router, &sid, &ap, &rid);
    assert_eq!(accepted["op"], "receipt", "{accepted}");
    assert_eq!(accepted["state"], "accepted", "{accepted}");
    agent_event(&fake, "answer 1 allow");
    let r = rid.clone();
    appr.wait(&mut router, move |v| {
        v["op"] == "receipt" && v["request_id"] == r.as_str() && v["state"] == "completed"
    });
    let closed = m.wait(&mut router, |v| v["op"] == "approval_closed");
    assert_eq!(closed["reason"], "answered_remote", "{closed}");
    // The Mac's late answer is stale.
    let late = m.answer(&mut router, &sid, &ap, &uuid());
    assert_eq!(late["code"], "stale_target", "{late}");
}

/// §R9.6 restrictions: a service whose `hosts` don't name this host is
/// refused at admission (`unauthorized` "out of scope"); one restricted to
/// a session sees only that session (here enrolled live, carried by the
/// Mac after the session started), and one restricted to another session
/// sees nothing and gets `unknown_session` for this one.
#[test]
fn session_and_host_restrictions_scope_what_a_service_sees() {
    let wall = r9log::host_now().wall_ms;
    let mut rig = Rig::new(
        |log| {
            log.enroll_service(
                "svc-elsewhere",
                &ServiceScope::new(["host-other"]).ops(["prompt"]),
                wall + HOUR,
            );
            log.enroll_service(
                "svc-other-session",
                &ServiceScope::new([HOST]).sessions(Some(["ses-zzzzzzzzzzzz"])),
                wall + HOUR,
            );
        },
        None,
        false,
    );
    let (sid, _fake) = rig.agent();
    let (sid2, _fake2) = {
        // A second session (another fake dir).
        let fake = rig.sandbox.dir.path().join("fake2");
        std::fs::create_dir_all(&fake).unwrap();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let mut frontend = rig.sandbox.spawn(
            &["agent", "launch", "claude"],
            &rig.sandbox.home,
            &[
                ("CLAUDE_CLI_BIN", script.to_str().unwrap()),
                ("FAKE_DIR", fake.to_str().unwrap()),
            ],
        );
        agent_event(&fake, "started");
        let sid2 = frontend.detach();
        rig.sandbox.track();
        (sid2, fake)
    };
    let mut router = Router::new(&rig.astation);
    assert_eq!(
        router
            .connect("elsewhere", &rig.log, HOST, &service("svc-elsewhere"))
            .unwrap_err(),
        ("unauthorized".to_string(), Some("out of scope".to_string()))
    );

    // The Mac enrolls a bot for the first session only, on its channel.
    next_init();
    let mut m = Dev::connect(&mut router, "mac", &rig.log, &mac());
    let add = rig.log.enroll_service(
        "svc-one",
        &ServiceScope::new([HOST])
            .ops(["prompt"])
            .sessions(Some([sid.as_str()])),
        wall + HOUR,
    );
    m.carry(&mut router, &[add]);
    next_init();
    let mut one = Dev::connect(&mut router, "one", &rig.log, &service("svc-one"));
    let w = one.a.welcome().scope.clone().expect("a service's scope");
    assert_eq!(w.sessions, Some(vec![sid.clone()]), "{w:?}");
    within("both sessions to be listed for the Mac", || {
        let s = m.sessions(&mut router);
        s.contains(&sid) && s.contains(&sid2)
    });
    assert_eq!(one.sessions(&mut router), std::slice::from_ref(&sid));

    next_init();
    let mut other = Dev::connect(
        &mut router,
        "other",
        &rig.log,
        &service("svc-other-session"),
    );
    assert!(other.sessions(&mut router).is_empty());
    // A target it can't see, with the Mac's binding: unknown_session.
    let mut target = m.read(&sid);
    target["attachment_gen"] = json!(other.a.welcome().attachment_gen);
    let refused = other.request(
        &mut router,
        json!({"op": "receipt_query", "binding": target, "request_ids": [uuid()]}),
    );
    assert_eq!(refused["code"], "unknown_session", "{refused}");
}

/// §R9.3 step 4 with services: any `set_roles` fences the service's live
/// channel (`unauthorized` "roles changed"), and it comes back under the
/// new grant. A renewal (the shared core's `service_renewal`) carried at
/// once is applied by the host although `check_change` advises waiting
/// (the 24 h pace is the signers', D23: hosts refuse nothing new); the new
/// attachment's `authorization_ms_left` follows the later expiry. A
/// narrowing (`service_narrowing`) to `view` only comes back without
/// `control`: prompts and leases are `forbidden`.
#[test]
fn live_renewal_and_narrowing_fence_the_service_and_readmit_it_under_the_new_grant() {
    let mut rig = Rig::new(|_| {}, None, false);
    let (sid, _fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let mut m = Dev::connect(&mut router, "mac", &rig.log, &mac());
    next_init();
    let mut bot = Dev::connect(&mut router, "bot", &rig.log, &service("svc-bot"));
    assert!(bot.a.welcome().authorization_ms_left <= HOUR);
    bot.sees(&mut router, &sid);

    // Renewal: two hours more.
    let wall = r9log::host_now().wall_ms;
    let renewal = rig.log.renew_service("svc-bot", wall + 3 * HOUR);
    let pre = {
        // The log before the renewal: the advisory guard's verdict on it.
        let mut entries = rig.log.entries.clone();
        entries.pop();
        atem_client::membership::Membership::verify_chain(
            ACCOUNT,
            &rig.log.genesis_hash(),
            &entries,
            &r9log::host_now(),
        )
        .unwrap()
        .membership
    };
    let action = atem_client::membership::Entry::parse_bytes(renewal.to_string().as_bytes())
        .unwrap()
        .action;
    assert!(
        matches!(
            check_change(&pre, &action, wall),
            Err(ChangeRefusal::ServiceChangeTooSoon { .. })
        ),
        "the signer's guard advises waiting"
    );
    m.carry(&mut router, &[renewal]);
    let fence = bot.fenced(&mut router);
    assert_eq!(fence["code"], "unauthorized", "{fence}");
    assert_eq!(fence["detail"], "roles changed", "{fence}");
    next_init();
    let mut bot = Dev::connect(&mut router, "bot-2", &rig.log, &service("svc-bot"));
    assert!(
        bot.a.welcome().authorization_ms_left > 2 * HOUR,
        "{}",
        bot.a.welcome().authorization_ms_left
    );
    assert_eq!(permissions(&bot.a), ["control", "view"]);
    bot.sees(&mut router, &sid);

    // Narrowing: view only, the expiry unchanged.
    let narrowing = rig
        .log
        .narrow_service("svc-bot", &ServiceScope::new([HOST]), None);
    m.carry(&mut router, &[narrowing]);
    let fence = bot.fenced(&mut router);
    assert_eq!(fence["detail"], "roles changed", "{fence}");
    next_init();
    let mut bot = Dev::connect(&mut router, "bot-3", &rig.log, &service("svc-bot"));
    assert_eq!(permissions(&bot.a), ["view"]);
    bot.sees(&mut router, &sid);
    let binding = bot.read(&sid);
    let acquire = bot.request(
        &mut router,
        json!({"op": "acquire", "binding": binding, "takeover": false}),
    );
    assert_eq!(acquire["code"], "forbidden", "{acquire}");
    let binding = bot.read(&sid);
    let prompt = bot.request(
        &mut router,
        json!({"op": "submit", "binding": binding, "kind": "prompt", "request_id": uuid(),
            "acquire": true, "payload": {"text": "hello"}}),
    );
    assert_eq!(prompt["code"], "forbidden", "{prompt}");
}

/// §R9.6 grant revocation beside a service: the phone revokes the grant
/// of a browser it issued; the browser is fenced (`unauthorized` "grant
/// revoked") and refused again, while a service attached on the same link
/// is untouched (still listed, still answering).
#[test]
fn a_grant_revocation_fences_the_browser_and_leaves_the_service_alone() {
    let mut rig = Rig::new(|_| {}, None, false);
    let (sid, _fake) = rig.agent();
    let wall = r9log::host_now().wall_ms;
    let grant_id = "bbbbbbbb-1111-4111-8111-000000000001";
    let (grant, key) = rig.log.grant(
        "dev-phone",
        grant_id,
        HOST,
        1,
        None,
        &["view"],
        wall,
        wall + 600_000,
    );
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut p = Dev::connect(&mut router, "phone", log, &phone());
    next_init();
    let mut bot = Dev::connect(&mut router, "bot", log, &service("svc-bot"));
    next_init();
    let browser = Identity::browser(grant.clone(), key.clone()).unwrap();
    let mut br = Dev::connect(&mut router, "browser", log, &browser);
    for d in [&mut p, &mut bot, &mut br] {
        d.sees(&mut router, &sid);
    }

    let revoked = p.request(
        &mut router,
        json!({"op": "revoke_grant", "grant_id": grant_id}),
    );
    assert_eq!(revoked["op"], "grant_revoked", "{revoked}");
    let fence = br.fenced(&mut router);
    assert_eq!(fence["detail"], "grant revoked", "{fence}");
    // The service goes on.
    assert!(
        !bot.gather(&mut router, Duration::from_millis(500))
            .iter()
            .any(|v| v["__fenced"] == true)
    );
    bot.sees(&mut router, &sid);
    next_init();
    assert_eq!(
        router
            .connect(
                "browser-2",
                log,
                HOST,
                &Identity::browser(grant, key).unwrap()
            )
            .unwrap_err(),
        (
            "unauthorized".to_string(),
            Some("grant revoked".to_string())
        )
    );
}

/// §R9.6 and §R9.13 item 4 (`K` rotation with a service attached): the
/// project-hash table stands in for the cred agent
/// (`ATEM_TEST_PROJECT_HASHES`), its hashes made by the shared core's
/// `project_hash` over the session's launch project (`local:home`). A
/// service scoped to the old generation's hash sees the session; a new
/// generation is installed (both retained) and the service stays attached
/// and in scope; the Mac re-issues the scope with both generations'
/// hashes, then narrows it to the new one (each `set_roles` fences and
/// readmits the service, which keeps seeing the session); the old
/// generation is dropped and the service still sees it.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "debug-only test hooks")]
fn k_rotation_with_a_service_attached_re_issues_its_scope() {
    use atem_client::backup::BackupKey;
    use atem_client::project::{local_project_key, project_hash};
    let key = |kid: &str, byte: u8| BackupKey {
        kid: kid.into(),
        k: zeroize::Zeroizing::new([byte; 32]),
    };
    let project = local_project_key("home");
    let old = project_hash(&key("aaaa0001", 1), &project).unwrap();
    let new = project_hash(&key("bbbb0002", 2), &project).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let table = dir.path().join("projects.json");
    let write = |kids: &[(&str, &str)]| {
        let mut by_kid = serde_json::Map::new();
        for (kid, hash) in kids {
            by_kid.insert(kid.to_string(), json!(hash));
        }
        let tmp = dir.path().join("projects.tmp");
        std::fs::write(&tmp, json!({project.clone(): by_kid}).to_string()).unwrap();
        std::fs::rename(&tmp, &table).unwrap();
    };
    write(&[("aaaa0001", &old)]);
    let wall = r9log::host_now().wall_ms;
    let o = old.clone();
    let mut rig = Rig::new(
        move |log| {
            log.enroll_service(
                "svc-proj",
                &ServiceScope::new([HOST])
                    .ops(["prompt"])
                    .projects(Some([o.as_str()])),
                wall + HOUR,
            );
        },
        Some(table.clone()),
        false,
    );
    let (sid, _fake) = rig.agent();
    let mut router = Router::new(&rig.astation);
    let mut m = Dev::connect(&mut router, "mac", &rig.log, &mac());
    next_init();
    let mut svc = Dev::connect(&mut router, "proj", &rig.log, &service("svc-proj"));
    svc.sees(&mut router, &sid);

    // A new generation installed, the old one retained: nothing changes
    // for the attached service.
    write(&[("aaaa0001", &old), ("bbbb0002", &new)]);
    assert!(
        !svc.gather(&mut router, Duration::from_millis(500))
            .iter()
            .any(|v| v["__fenced"] == true)
    );
    svc.sees(&mut router, &sid);

    // Re-issued with both generations' hashes (a widening: a set_roles).
    let both = rig.log.set_service(
        "svc-proj",
        &ServiceScope::new([HOST])
            .ops(["prompt"])
            .projects(Some([old.as_str(), new.as_str()])),
        wall + HOUR,
    );
    m.carry(&mut router, &[both]);
    assert_eq!(svc.fenced(&mut router)["detail"], "roles changed");
    next_init();
    let mut svc = Dev::connect(&mut router, "proj-2", &rig.log, &service("svc-proj"));
    svc.sees(&mut router, &sid);

    // Narrowed to the new generation only (never paced).
    let current = atem_client::membership::service_grant(&rig.log.log, "svc-proj")
        .unwrap()
        .0
        .clone();
    let narrowing = rig.log.narrow_service(
        "svc-proj",
        &ServiceScope::of(&current).projects(Some([new.as_str()])),
        None,
    );
    m.carry(&mut router, &[narrowing]);
    assert_eq!(svc.fenced(&mut router)["detail"], "roles changed");
    next_init();
    let mut svc = Dev::connect(&mut router, "proj-3", &rig.log, &service("svc-proj"));
    svc.sees(&mut router, &sid);

    // The old generation dropped: the scope no longer needs it.
    write(&[("bbbb0002", &new)]);
    std::thread::sleep(Duration::from_millis(500));
    svc.sees(&mut router, &sid);
}

/// §R9.3 "Held": only a managing native device reconciles a held host. A
/// service (`svc-bot`, with control) connecting to a held host is refused
/// `busy` "device list not reconciled" and the hold and its fault record
/// stay; the Mac then reconciles and the service is admitted.
#[test]
fn a_service_is_refused_as_the_reconciler_of_a_held_host() {
    let rig = Rig::new(|_| {}, None, true);
    let mut router = Router::new(&rig.astation);
    let fault = rig
        .sandbox
        .config()
        .join("pairing")
        .join("membership.fault");
    for (h, id) in [("bot", "svc-bot"), ("appr", "svc-appr")] {
        assert_eq!(
            router.connect(h, &rig.log, HOST, &service(id)).unwrap_err(),
            (
                "busy".to_string(),
                Some("device list not reconciled".to_string())
            ),
            "{id}"
        );
        next_init();
    }
    assert!(fault.exists());
    let status = rig.status();
    assert!(status.contains("Device list:    held ("), "{status}");
    let _m = Dev::connect(&mut router, "mac", &rig.log, &mac());
    assert!(!fault.exists());
    next_init();
    let bot = Dev::connect(&mut router, "bot-2", &rig.log, &service("svc-bot"));
    assert_eq!(bot.a.welcome().principal, "service:svc-bot");
}

/// Pins the current contract (§R9.6 "Browser grant": `revoke_grant` is "a
/// session op from the issuer or any member with `control`", and a
/// service with any control op has `control`): a service with control on
/// a host its scope names may revoke a browser companion's grant that a
/// phone issued; the browser is fenced. A view-only service may not
/// (`forbidden`). A change to this rule must change this test on purpose.
#[test]
fn a_service_with_control_may_revoke_a_browser_grant_current_contract() {
    let mut rig = Rig::new(|_| {}, None, false);
    let (sid, _fake) = rig.agent();
    let wall = r9log::host_now().wall_ms;
    let grant_id = "bbbbbbbb-2222-4222-8222-000000000002";
    let (grant, key) = rig.log.grant(
        "dev-phone",
        grant_id,
        HOST,
        1,
        None,
        &["view"],
        wall,
        wall + 600_000,
    );
    let mut router = Router::new(&rig.astation);
    let log = &rig.log;
    let mut view = Dev::connect(&mut router, "view", log, &service("svc-view"));
    next_init();
    let mut bot = Dev::connect(&mut router, "bot", log, &service("svc-bot"));
    next_init();
    let mut br = Dev::connect(
        &mut router,
        "browser",
        log,
        &Identity::browser(grant, key).unwrap(),
    );
    br.sees(&mut router, &sid);

    let refused = view.request(
        &mut router,
        json!({"op": "revoke_grant", "grant_id": grant_id}),
    );
    assert_eq!(refused["code"], "forbidden", "{refused}");
    let revoked = bot.request(
        &mut router,
        json!({"op": "revoke_grant", "grant_id": grant_id}),
    );
    assert_eq!(revoked["op"], "grant_revoked", "{revoked}");
    let fence = br.fenced(&mut router);
    assert_eq!(fence["detail"], "grant revoked", "{fence}");
}

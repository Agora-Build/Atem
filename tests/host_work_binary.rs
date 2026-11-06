//! Real runtime, encrypted r9 clients and fake CLIs, entirely in temp profiles.
#![cfg(target_os = "linux")]
mod support;

use atem_client::connect::{Attached, Event, Identity};
use atem_client::membership::ServiceScope;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::astation::{ASTATION, FakeAstation, write_verified_pairing};
use support::r9::{Out, Router, client_ms, write_pin};
use support::r9log::{self, MAC, TestLog, auth, secret};
use support::{Sandbox, within};

const HOST: &str = "host-work";
const ACCOUNT: &str = "acct-work";
fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    log: TestLog,
    runtime: Option<Child>,
    fake: PathBuf,
    /// Debug-build context snapshots (`ATEM_TEST_CONTEXT_DIR`) for replies
    /// that carry context; set before `start`.
    context_hook: bool,
}

impl Rig {
    fn new(provider: &str) -> Self {
        Self::configured(provider, |_| {})
    }

    fn configured(provider: &str, configure: impl FnOnce(&mut TestLog)) -> Self {
        let mut rig = Self::prepared(provider, configure);
        rig.start();
        rig
    }

    fn configured_as(provider: &str, verified: bool) -> Self {
        let mut rig = Self::prepared_as(provider, verified, |_| {});
        rig.start();
        rig
    }

    fn prepared(provider: &str, configure: impl FnOnce(&mut TestLog)) -> Self {
        Self::prepared_as(provider, true, configure)
    }

    /// `verified: false` pairs the host without verifying it: no device list.
    fn prepared_as(provider: &str, verified: bool, configure: impl FnOnce(&mut TestLog)) -> Self {
        let sandbox = Sandbox::new();
        if verified {
            write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        } else {
            support::profile::write_pairing(&sandbox.config(), ASTATION, 1);
        }
        let mut log = TestLog::genesis(ACCOUNT, &secret("work astation"));
        let host_seed = secret("work host");
        log.add_host(HOST, 1, &host_seed);
        log.enroll_service(
            "svc-work",
            &ServiceScope::new([HOST]).ops(["launch", "message", "notify", "prompt", "view"]),
            r9log::host_now().wall_ms + 3_600_000,
        );
        log.enroll_service(
            "svc-view",
            &ServiceScope::new([HOST]).ops(["view"]),
            r9log::host_now().wall_ms + 3_600_000,
        );
        log.add_native("unapproved", &["view", "control"]);
        log.add_native("messenger", &["view"]);
        configure(&mut log);
        if verified {
            write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        }
        let fake = sandbox.dir.path().join("fake");
        std::fs::create_dir_all(&fake).unwrap();
        let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let env_name = if provider == "claude" {
            "CLAUDE_CLI_BIN"
        } else {
            "CODEX_CLI_BIN"
        };
        let env_file = sandbox.dir.path().join("provider.json");
        private(
            &env_file,
            &json!({env_name:bin, "FAKE_DIR":fake, "PROVIDER_TEST_KEY":"isolated-test-value"})
                .to_string(),
        );
        private(
            &sandbox.config().join("runtime.toml"),
            &format!(
                r#"
version = 1
enabled = true
[[profiles]]
id = "backend"
revision = 1
label = "Backend"
provider = {provider:?}
cwd = {cwd:?}
project = "local:home"
args = ["--profile", "oss"]
principals = ["member:{MAC}", "service:svc-work", "service:svc-restricted"]
env_names = [{env_name:?}, "FAKE_DIR", "PROVIDER_TEST_KEY"]
env_file = {env_file:?}
[[routes]]
id = "backend"
revision = 1
profile_id = "backend"
principals = ["member:{MAC}", "service:svc-work", "service:svc-restricted"]
"#,
                cwd = sandbox.home.to_str().unwrap(),
                env_file = env_file.to_str().unwrap()
            ),
        );
        Self {
            sandbox,
            astation: FakeAstation::start(),
            log,
            runtime: None,
            fake,
            context_hook: false,
        }
    }

    fn start(&mut self) {
        let output = std::fs::File::create(self.sandbox.dir.path().join("runtime.log")).unwrap();
        let context = self.sandbox.dir.path().join("context");
        std::fs::create_dir_all(&context).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        if self.context_hook {
            command.env("ATEM_TEST_CONTEXT_DIR", &context);
        }
        self.runtime = Some(
            command
                .arg("runtime")
                .env("HOME", &self.sandbox.home)
                .env("XDG_RUNTIME_DIR", &self.sandbox.run)
                .env("PATH", "/usr/bin:/bin")
                .env("ASTATION_WS", &self.astation.url)
                .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
                .env("ATEM_RUNTIME_IDLE_SECS", "1")
                .env("ATEM_TEST_NO_INIT_LIMIT", "1")
                .stdin(Stdio::null())
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        );
        within("runtime socket", || {
            self.sandbox.config().join("runtime.socket").exists()
        });
    }

    fn restart(&mut self) {
        self.sandbox.track();
        let mut child = self.runtime.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        self.start();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.sandbox.track();
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Dev {
    handle: String,
    a: Attached,
    backlog: Vec<Value>,
}
impl Dev {
    fn new(r: &mut Router, log: &TestLog, id: &str, service: bool) -> Self {
        let identity = if service {
            Identity::service(id, auth(id))
        } else {
            Identity::native(id, auth(id))
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        let (handle, a) = loop {
            let handle = uuid();
            match r.connect(&handle, log, HOST, &identity) {
                Ok(a) => break (handle, a),
                Err((code, _)) if code == "busy" && Instant::now() < deadline => {
                    // Release builds enforce one handshake per second.
                    r.close(&handle);
                    std::thread::sleep(Duration::from_millis(1100));
                }
                Err(error) => panic!("host-work client admission failed: {error:?}"),
            }
        };
        Self {
            handle,
            a,
            backlog: Vec::new(),
        }
    }
    fn request(&mut self, r: &mut Router, mut data: Value) -> Value {
        let id = uuid();
        data["v"] = json!(1);
        data["id"] = json!(id);
        let frame = self
            .a
            .send(&json!({"type":"session","data":data}), client_ms())
            .unwrap();
        r.frame(&self.handle, &frame);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(at) = self.backlog.iter().position(|v| v["re"] == id) {
                return self.backlog.remove(at);
            }
            assert!(
                Instant::now() < deadline,
                "request timed out: {:?}",
                self.backlog
            );
            match r.next(&self.handle) {
                Out::Close(reason) => panic!("channel closed: {reason:?}"),
                Out::Frame(frame) => {
                    for e in self.a.on_frame(&frame, client_ms()).unwrap() {
                        let value = match e {
                            Event::Family(f) => f.data,
                            Event::Session(m) => Some(
                                atem_client::session::wire::to_value(
                                    &atem_client::session::wire::Envelope::Session(m),
                                )["data"]
                                    .clone(),
                            ),
                            Event::Error(e) => Some(
                                serde_json::from_slice::<Value>(&e.to_bytes()).unwrap()["data"]
                                    .clone(),
                            ),
                            _ => None,
                        };
                        if let Some(v) = value {
                            self.backlog.push(v);
                        }
                    }
                }
            }
        }
    }
    fn launch(&mut self, r: &mut Router, rid: &str) -> Value {
        self.request(r, json!({"op":"host_launch","host":host(),"request_id":rid,
            "profile_id":"backend","profile_revision":1,"expires_at":r9log::host_now().wall_ms+60_000}))
    }
    fn launched(&mut self, r: &mut Router, rid: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let value = self.request(
                r,
                json!({"op":"host_launch_query","host":host(),"request_id":rid}),
            );
            if value["result"]["launch"]["state"] == "started" {
                return value["result"]["launch"].clone();
            }
            assert!(Instant::now() < deadline, "launch failed: {value}");
            std::thread::sleep(Duration::from_millis(40));
        }
    }
    fn carry(&mut self, r: &mut Router, entry: Value) {
        let signed = atem_client::SignedObject::parse(entry.to_string().as_bytes()).unwrap();
        let (id, frame) = self.a.send_membership(&[signed], client_ms()).unwrap();
        r.frame(&self.handle, &frame);
        loop {
            let Out::Frame(frame) = r.next(&self.handle) else {
                panic!("membership channel closed");
            };
            let events = self.a.on_frame(&frame, client_ms()).unwrap();
            if events
                .iter()
                .any(|e| matches!(e, Event::MembershipHead { re: Some(re), .. } if re == &id))
            {
                return;
            }
        }
    }
}

fn host() -> Value {
    json!({"account_id":ACCOUNT,"atem_device_id":HOST,"host_trust_gen":1})
}
fn task(launch: &Value, text: &str) -> Value {
    let context = "API contract version one";
    let mut target = host();
    target["session_id"] = launch["session_id"].clone();
    target["process_gen"] = launch["process_gen"].clone();
    json!({"task_id":uuid(),"workflow_id":uuid(),"target":target,"expires_at":r9log::host_now().wall_ms+60_000,
        "prompt":text,"context":[{"kind":"vault","id":"contract","version":1,
        "digest":atem_client::session::host_work::digest(context.as_bytes()),"text":context}]})
}
fn enqueue(dev: &mut Dev, r: &mut Router, task: &Value) -> Value {
    dev.request(r, json!({"op":"work_enqueue","host":host(),"route_id":"backend","route_revision":1,"task":task}))
}
fn notice(sender: &str, text: &str, destinations: Vec<Value>) -> Value {
    let now = r9log::host_now().wall_ms;
    json!({"message_id":uuid(),"workflow_id":uuid(),"sender":sender,
        "created_at":now,"expires_at":now+60_000,"text":text,"context":[],
        "recipients":destinations.into_iter().map(|destination| json!({"recipient_id":uuid(),"host":host(),"destination":destination})).collect::<Vec<_>>()})
}
fn publish(dev: &mut Dev, r: &mut Router, message: &Value) -> Value {
    dev.request(
        r,
        json!({"op":"message_publish","host":host(),"message":message}),
    )
}
fn message_status(dev: &mut Dev, r: &mut Router, message: &Value) -> Value {
    dev.request(
        r,
        json!({"op":"message_query","host":host(),"message_id":message["message_id"]}),
    )["result"]["message"]
        .clone()
}
fn work(dev: &mut Dev, r: &mut Router, tid: &Value) -> Value {
    dev.request(r, json!({"op":"work_query","host":host(),"task_id":tid}))["result"]["work"].clone()
}

fn wait_state(dev: &mut Dev, r: &mut Router, tid: &Value, expected: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = work(dev, r, tid);
        if status["state"] == expected {
            return status;
        }
        assert!(Instant::now() < deadline, "expected {expected}: {status}");
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn wait_detail(dev: &mut Dev, r: &mut Router, tid: &Value, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = work(dev, r, tid);
        if status["state"] == "blocked"
            && status["detail"]
                .as_str()
                .unwrap_or_default()
                .contains(expected)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected blocked for {expected}: {status}"
        );
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn screenshot() -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aS1kAAAAASUVORK5CYII="
    ).unwrap()
}

fn upload(dev: &mut Dev, r: &mut Router, reference: &Value, offset: usize, bytes: &[u8]) -> Value {
    use base64::Engine;
    dev.request(
        r,
        json!({"op":"attachment_put","host":host(),"attachment":reference,
        "offset":offset,"data":base64::engine::general_purpose::STANDARD.encode(bytes)}),
    )
}

/// One local protocol request to the runtime; its `reply` (or `error`).
fn local_request(rig: &Rig, mut request: Value, reply: &str) -> Value {
    use std::io::{BufRead, BufReader, Write};
    let path = std::fs::read_to_string(rig.sandbox.config().join("runtime.socket")).unwrap();
    let socket = std::os::unix::net::UnixStream::connect(path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut write = socket.try_clone().unwrap();
    writeln!(
        write,
        "{}",
        json!({"v":1,"op":"hello","protocol":1,"build":"test"})
    )
    .unwrap();
    request["v"] = json!(1);
    writeln!(write, "{request}").unwrap();
    for line in BufReader::new(socket).lines() {
        let message: Value = serde_json::from_str(&line.unwrap()).unwrap();
        if message["op"] == "error" || message["op"] == reply {
            return message;
        }
    }
    panic!("no {reply} response");
}

/// `argv` run by the fake agent of `fake` as its own child (`run-<n>.json`).
fn agent_run(fake: &Path, n: u32, args: &[&str]) -> Value {
    let argv: Vec<_> = std::iter::once(env!("CARGO_BIN_EXE_atem"))
        .chain(args.iter().copied())
        .collect();
    private(
        &fake.join(format!("run-{n}.tmp")),
        &json!({ "argv": argv }).to_string(),
    );
    std::fs::rename(
        fake.join(format!("run-{n}.tmp")),
        fake.join(format!("run-{n}.json")),
    )
    .unwrap();
    let out = fake.join(format!("run-{n}.out"));
    within("agent child command", || out.exists());
    serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap()
}

/// A task from a service (not a local agent) takes `atem message reply`
/// from its target session; another session's reply is refused. The reply
/// never completes it.
#[test]
fn a_service_task_takes_a_reply_from_its_target_session_only() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let first = task(&launch, "Answer with atem message reply");
    enqueue(&mut dev, &mut r, &first);
    within("the service's prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Answer with atem message reply")
    });
    // Another agent session of the same runtime, with its own fake directory.
    let other = rig.sandbox.dir.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let mut env = rig.sandbox.env();
    env.push((
        "CLAUDE_CLI_BIN".into(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py")
            .display()
            .to_string(),
    ));
    env.push(("FAKE_DIR".into(), other.display().to_string()));
    let launched = local_request(
        &rig,
        json!({"op":"launch","provider":"claude","cwd":rig.sandbox.home,"env":env,"rows":24,"cols":80}),
        "launched",
    );
    assert_eq!(launched["op"], "launched", "{launched}");
    within("the other agent", || other.join("events").exists());
    let tid = first["task_id"].as_str().unwrap();
    let intruder = agent_run(&other, 1, &["message", "reply", "--task", tid, "not mine"]);
    assert_ne!(intruder["code"], 0, "{intruder}");
    assert!(
        intruder["stderr"].as_str().unwrap().contains("mismatch"),
        "{intruder}"
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while work(&mut dev, &mut r, &first["task_id"])["detail"] != "in the agent's turn" {
        assert!(
            Instant::now() < deadline,
            "the task's turn was never stored"
        );
        std::thread::sleep(Duration::from_millis(40));
    }
    let reply = agent_run(&rig.fake, 1, &["message", "reply", "the service's answer"]);
    assert_eq!(reply["code"], 0, "{reply}");
    assert!(
        reply["stdout"]
            .as_str()
            .unwrap()
            .contains("reply submitted"),
        "{reply}"
    );
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    let status = wait_state(&mut dev, &mut r, &first["task_id"], "awaiting_result");
    assert_eq!(status["detail"], "reply submitted", "{status}");
    let retry = agent_run(
        &rig.fake,
        2,
        &["message", "reply", "--task", tid, "the service's answer"],
    );
    assert_eq!(retry["code"], 0, "{retry}");
    assert_eq!(retry["stdout"], reply["stdout"]);
    // Its sender completes it with work_complete, not the local command.
    let (_, err, ok) = rig.sandbox.atem(&["message", "complete", tid]);
    assert!(!ok && err.contains("work_complete"), "{err}");
}

/// A remote sender's task awaiting its result expires at its deadline like
/// any other, so it holds no queue slot past it.
#[test]
fn a_service_task_awaiting_its_result_expires_at_its_deadline() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let mut short = task(&launch, "Short-lived work");
    short["expires_at"] = json!(r9log::host_now().wall_ms + 4_000);
    enqueue(&mut dev, &mut r, &short);
    within("the service's prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Short-lived work")
    });
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    wait_state(&mut dev, &mut r, &short["task_id"], "awaiting_result");
    let status = wait_state(&mut dev, &mut r, &short["task_id"], "expired");
    assert_eq!(status["detail"], "expired awaiting a result", "{status}");
}

fn reply_query(dev: &mut Dev, r: &mut Router, tid: &Value) -> Value {
    dev.request(r, json!({"op":"reply_query","host":host(),"task_id":tid}))
}

/// A service's task whose agent is in its turn: launched, enqueued and
/// waiting for the reply. Returns the task.
fn task_in_its_turn(rig: &Rig, r: &mut Router, dev: &mut Dev, text: &str) -> Value {
    let rid = uuid();
    dev.launch(r, &rid);
    let launch = dev.launched(r, &rid);
    let t = task(&launch, text);
    enqueue(dev, r, &t);
    within("the service's prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains(text)
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    while work(dev, r, &t["task_id"])["detail"] != "in the agent's turn" {
        assert!(
            Instant::now() < deadline,
            "the task's turn was never stored"
        );
        std::thread::sleep(Duration::from_millis(40));
    }
    t
}

/// The `result <id>` the CLI printed for a reply.
fn result_id_of(run: &Value) -> String {
    run["stdout"]
        .as_str()
        .unwrap()
        .rsplit("result ")
        .next()
        .unwrap()
        .trim()
        .to_string()
}

/// The sender of a task reads the reply its agent submitted with
/// `reply_query` (feature `host.reply`), with the authority `work_query`
/// needs and nobody else's; reading it never completes the task.
#[test]
fn a_service_reads_its_tasks_reply_with_reply_query() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    assert!(dev.a.welcome().features.iter().any(|f| f == "host.reply"));
    assert!(!dev.a.welcome().features.iter().any(|f| f == "host.select"));
    let first = task_in_its_turn(&rig, &mut r, &mut dev, "Answer with atem message reply");
    let tid = &first["task_id"];
    // No reply yet: an answer, not an error.
    let none = reply_query(&mut dev, &mut r, tid);
    assert_eq!(none["op"], "host_work_result", "{none}");
    assert_eq!(
        none["result"],
        json!({"kind":"reply","reply":null}),
        "{none}"
    );
    // The agent replies in its turn.
    let run = agent_run(&rig.fake, 1, &["message", "reply", "the service's answer"]);
    assert_eq!(run["code"], 0, "{run}");
    let result_id = result_id_of(&run);
    let response = reply_query(&mut dev, &mut r, tid);
    assert_eq!(response["result"]["kind"], "reply", "{response}");
    let reply = &response["result"]["reply"];
    assert_eq!(reply["result_id"], result_id.as_str(), "{reply}");
    assert_eq!(reply["state"], "submitted", "{reply}");
    assert_eq!(reply["text"], "the service's answer", "{reply}");
    assert_eq!(reply["context"], json!([]), "{reply}");
    assert!(reply["submitted_at"].as_u64().unwrap() > 0, "{reply}");
    assert_eq!(reply["digest"].as_str().unwrap().len(), 64, "{reply}");
    // A reply is not a completion: the task awaits its sender.
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    let status = wait_state(&mut dev, &mut r, tid, "awaiting_result");
    assert_eq!(status["detail"], "reply submitted", "{status}");
    assert_eq!(status["result"], Value::Null, "{status}");
    // The same reply, every time it is asked for.
    assert_eq!(
        reply_query(&mut dev, &mut r, tid)["result"]["reply"],
        *reply
    );
    // Anyone else is answered as work_query answers them: a task that isn't
    // theirs, one that doesn't exist, and a caller without the notify op.
    let mut others = [
        Dev::new(&mut r, &rig.log, MAC, false),
        Dev::new(&mut r, &rig.log, "svc-view", true),
    ];
    let unknown = json!(uuid());
    for (who, name, task_id) in [
        (0, "another sender", tid),
        (0, "an unknown task", &unknown),
        (1, "a caller without notify", tid),
    ] {
        let who = &mut others[who];
        let mut asked = reply_query(who, &mut r, task_id);
        let mut worked = who.request(
            &mut r,
            json!({"op":"work_query","host":host(),"task_id":task_id}),
        );
        assert_eq!(asked["code"], "forbidden", "{name}: {asked}");
        for answer in [&mut asked, &mut worked] {
            let object = answer.as_object_mut().unwrap();
            object.remove("id");
            object.remove("re");
        }
        assert_eq!(asked, worked, "{name}");
    }
    // Its sender completes the task separately, and still reads the reply.
    let result = json!({"kind":"vault","id":"result","version":1,"text":"implemented",
        "digest":atem_client::session::host_work::digest(b"implemented")});
    let done = dev.request(
        &mut r,
        json!({"op":"work_complete","host":host(),"task_id":tid,"result":result}),
    );
    assert_eq!(done["result"]["work"]["state"], "completed", "{done}");
    assert_eq!(done["result"]["work"]["result"], result, "{done}");
    assert_eq!(
        reply_query(&mut dev, &mut r, tid)["result"]["reply"],
        *reply
    );
}

/// A reply with context is `publishing` (no context, no time) until the
/// context is published, then `submitted` with it; it survives a restart.
#[test]
fn a_reply_with_context_reads_publishing_then_submitted_and_survives_a_restart() {
    let mut rig = Rig::prepared("claude", |_| {});
    rig.context_hook = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let first = task_in_its_turn(&rig, &mut r, &mut dev, "Reply with context");
    let tid = &first["task_id"];
    let text = "Context published late.";
    let digest = atem_client::session::host_work::digest(text.as_bytes());
    let name = atem_client::session::host_work::digest(b"v-late:1@1");
    let context = rig.sandbox.dir.path().join("context");
    private(&context.join(format!("{name}.hold")), "");
    private(
        &context.join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-late:1","version":1,"digest":digest,"text":text})
            .to_string(),
    );
    let run = agent_run(
        &rig.fake,
        1,
        &["message", "reply", "--vault", "v-late:1@1", "the answer"],
    );
    assert_eq!(run["code"], 0, "{run}");
    assert!(
        run["stdout"].as_str().unwrap().contains("reply publishing"),
        "{run}"
    );
    let result_id = result_id_of(&run);
    let publishing = reply_query(&mut dev, &mut r, tid)["result"]["reply"].clone();
    assert_eq!(publishing["state"], "publishing", "{publishing}");
    assert_eq!(publishing["result_id"], result_id.as_str(), "{publishing}");
    assert_eq!(publishing["text"], "the answer", "{publishing}");
    assert_eq!(publishing["context"], json!([]), "{publishing}");
    assert_eq!(publishing["submitted_at"], Value::Null, "{publishing}");
    assert_eq!(
        work(&mut dev, &mut r, tid)["detail"],
        "reply received; publishing its context"
    );
    std::fs::remove_file(context.join(format!("{name}.hold"))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let submitted = loop {
        let reply = reply_query(&mut dev, &mut r, tid)["result"]["reply"].clone();
        if reply["state"] == "submitted" {
            break reply;
        }
        assert!(Instant::now() < deadline, "never published: {reply}");
        std::thread::sleep(Duration::from_millis(40));
    };
    assert_eq!(submitted["result_id"], result_id.as_str(), "{submitted}");
    assert_eq!(
        submitted["context"],
        json!([{"kind":"vault","id":"v-late:1","version":1,"digest":digest,"text":text}]),
        "{submitted}"
    );
    assert!(
        submitted["submitted_at"].as_u64().unwrap() > 0,
        "{submitted}"
    );
    // The row is durable: the same reply after the runtime restarts.
    drop(r);
    rig.restart();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    assert_eq!(
        reply_query(&mut dev, &mut r, tid)["result"]["reply"],
        submitted
    );
}

/// A refused reply is read as refused (its reason is the task's detail),
/// and the corrected reply that replaces it keeps the result id.
#[test]
fn a_refused_reply_reads_refused_until_a_corrected_one_replaces_it() {
    let mut rig = Rig::prepared("claude", |_| {});
    rig.context_hook = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let first = task_in_its_turn(&rig, &mut r, &mut dev, "Reply with too much context");
    let tid = first["task_id"].as_str().unwrap();
    let text = "x".repeat(40_000);
    let name = atem_client::session::host_work::digest(b"v-big:1@1");
    private(
        &rig.sandbox
            .dir
            .path()
            .join("context")
            .join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-big:1","version":1,
            "digest":atem_client::session::host_work::digest(text.as_bytes()),"text":text})
        .to_string(),
    );
    let run = agent_run(
        &rig.fake,
        1,
        &[
            "message",
            "reply",
            "--task",
            tid,
            "--vault",
            "v-big:1@1",
            "too much",
        ],
    );
    assert_eq!(run["code"], 0, "{run}");
    let result_id = result_id_of(&run);
    let deadline = Instant::now() + Duration::from_secs(15);
    let refused = loop {
        let reply = reply_query(&mut dev, &mut r, &json!(tid))["result"]["reply"].clone();
        if reply["state"] == "refused" {
            break reply;
        }
        assert!(Instant::now() < deadline, "never refused: {reply}");
        std::thread::sleep(Duration::from_millis(40));
    };
    assert_eq!(refused["result_id"], result_id.as_str(), "{refused}");
    assert_eq!(refused["text"], "too much", "{refused}");
    assert_eq!(refused["context"], json!([]), "{refused}");
    assert_eq!(refused["submitted_at"], Value::Null, "{refused}");
    let detail = work(&mut dev, &mut r, &json!(tid))["detail"].clone();
    assert!(
        detail.as_str().unwrap().contains("over 32 KiB")
            && detail.as_str().unwrap().contains("corrected reply"),
        "{detail}"
    );
    let corrected = agent_run(
        &rig.fake,
        2,
        &["message", "reply", "--task", tid, "a short answer"],
    );
    assert_eq!(corrected["code"], 0, "{corrected}");
    let reply = reply_query(&mut dev, &mut r, &json!(tid))["result"]["reply"].clone();
    assert_eq!(reply["state"], "submitted", "{reply}");
    assert_eq!(reply["result_id"], result_id.as_str(), "{reply}");
    assert_eq!(reply["text"], "a short answer", "{reply}");
    assert_ne!(reply["digest"], refused["digest"], "{reply}");
}

/// A message to an agent is a task named by its recipient id: its sender
/// reads the agent's reply with that id, and nobody else does.
#[test]
fn a_message_sender_reads_the_reply_to_its_message_by_recipient_id() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let target = task(&launch, "unused")["target"].clone();
    let message = notice(
        &format!("member:{MAC}"),
        "Review the backend contract",
        vec![json!({"kind":"agent","route_id":"backend","route_revision":1,"target":target})],
    );
    publish(&mut dev, &mut r, &message);
    let recipient = message["recipients"][0]["recipient_id"].clone();
    within("the message prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Review the backend contract")
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    while work(&mut dev, &mut r, &recipient)["detail"] != "in the agent's turn" {
        assert!(Instant::now() < deadline, "the turn was never stored");
        std::thread::sleep(Duration::from_millis(40));
    }
    let id = recipient.as_str().unwrap();
    let run = agent_run(
        &rig.fake,
        1,
        &["message", "reply", "--task", id, "looks good"],
    );
    assert_eq!(run["code"], 0, "{run}");
    let reply = reply_query(&mut dev, &mut r, &recipient)["result"]["reply"].clone();
    assert_eq!(reply["state"], "submitted", "{reply}");
    assert_eq!(reply["text"], "looks good", "{reply}");
    assert_eq!(reply["result_id"], result_id_of(&run).as_str(), "{reply}");
    let mut service = Dev::new(&mut r, &rig.log, "svc-work", true);
    assert_eq!(
        reply_query(&mut service, &mut r, &recipient)["code"],
        "forbidden"
    );
}

#[test]
fn mark_screenshots_and_messages_share_the_durable_session_queue() {
    let mut rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    assert!(
        dev.a
            .welcome()
            .features
            .iter()
            .any(|f| f == "host.attachments")
    );
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let destination = json!({"kind":"agent","route_id":"backend","route_revision":1,
        "target":task(&launch, "unused")["target"]});
    let bytes = screenshot();
    let reference = json!({"attachment_id":uuid(),"digest":atem_client::session::host_work::digest(&bytes),
        "size":bytes.len(),"media_type":"image/png"});
    let mut mark = notice(&format!("member:{MAC}"), "", vec![destination.clone()]);
    mark["mark"] = json!({"mark_id":"mark_123","url":"http://localhost:3000/","title":"Example page",
        "screenshot":reference,"annotations":[{"tool":"arrow","x":24,"y":10,"text":"Make this red"}]});
    let response = publish(&mut dev, &mut r, &mark);
    assert_eq!(
        response["result"]["message"]["recipients"][0]["delivery"]["state"], "work",
        "{response}"
    );
    let mark_id = &mark["recipients"][0]["recipient_id"];
    wait_detail(&mut dev, &mut r, mark_id, "screenshot");
    let normal = notice(
        &format!("member:{MAC}"),
        "Follow up after mark",
        vec![destination],
    );
    publish(&mut dev, &mut r, &normal);
    let normal_id = &normal["recipients"][0]["recipient_id"];
    wait_detail(&mut dev, &mut r, normal_id, "earlier task");
    assert_eq!(
        upload(&mut dev, &mut r, &reference, 0, &bytes[..32])["result"]["upload"]["received"],
        32
    );
    assert_eq!(
        upload(&mut dev, &mut r, &reference, 0, &bytes[..32])["result"]["upload"]["received"],
        32
    );
    assert_eq!(
        upload(&mut dev, &mut r, &reference, 0, &[0; 32])["code"],
        "request_id_reused"
    );
    // A partial screenshot and both tasks survive a broker restart. The original
    // worker stays alive; no second provider process is started for the mark task.
    drop(r);
    rig.restart();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    wait_detail(&mut dev, &mut r, mark_id, "screenshot");
    let mut other = Dev::new(&mut r, &rig.log, "svc-work", true);
    assert_eq!(
        upload(&mut other, &mut r, &reference, 32, &bytes[32..])["code"],
        "invalid_request"
    );
    let done = upload(&mut dev, &mut r, &reference, 32, &bytes[32..]);
    assert_eq!(done["result"]["upload"]["ready"], true, "{done}");
    within("mark prompt with screenshot", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Read this PNG:")
    });
    let input = std::fs::read_to_string(rig.fake.join("input")).unwrap();
    assert!(input.contains("Make this red"));
    assert!(!input.contains("Follow up after mark"));
    let path = input
        .split("Read this PNG: ")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(Path::new(path).starts_with(rig.sandbox.config().join("runtime/attachments")));
    assert_eq!(rig.sandbox.records().len(), 1);
    let duplicate = publish(&mut dev, &mut r, &mark);
    assert_eq!(
        duplicate["result"]["message"]["message_id"],
        mark["message_id"]
    );
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    wait_state(&mut dev, &mut r, mark_id, "awaiting_result");
    // The sender explicitly releases its normal session lease between turns.
    let binding = json!({"target":task(&launch, "unused")["target"],
        "attachment_gen":dev.a.welcome().attachment_gen});
    let lease = dev.request(
        &mut r,
        json!({"op":"acquire","binding":binding,"takeover":false}),
    );
    assert_eq!(lease["op"], "lease", "{lease}");
    let released = dev.request(&mut r, json!({"op":"release","binding":lease["binding"]}));
    assert_eq!(released["op"], "lease_released");
    within("ordinary message after mark turn", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Follow up after mark")
    });
    let input = std::fs::read_to_string(rig.fake.join("input")).unwrap();
    assert!(input.find("Make this red").unwrap() < input.find("Follow up after mark").unwrap());
    assert_eq!(input.matches("Make this red").count(), 1);
}

#[test]
fn screenshot_uploads_require_message_permission_and_never_execute_input() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let bytes = screenshot();
    let reference = json!({"attachment_id":uuid(),"digest":atem_client::session::host_work::digest(&bytes),
        "size":bytes.len(),"media_type":"image/png"});
    let mut view = Dev::new(&mut r, &rig.log, "svc-view", true);
    assert_eq!(
        upload(&mut view, &mut r, &reference, 0, &bytes)["code"],
        "forbidden"
    );
    let mut member = Dev::new(&mut r, &rig.log, "messenger", false);
    assert_eq!(
        upload(&mut member, &mut r, &reference, 0, &bytes)["result"]["upload"]["ready"],
        true
    );
    assert!(rig.sandbox.records().is_empty());
    assert!(!rig.fake.join("input").exists());
}

#[test]
fn a_missing_screenshot_holds_only_its_target_sessions_queue() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let first_id = uuid();
    dev.launch(&mut r, &first_id);
    let first = dev.launched(&mut r, &first_id);
    let mut t = task(&first, "must wait for image");
    let bytes = screenshot();
    t["attachments"] = json!([{"attachment_id":uuid(),"digest":atem_client::session::host_work::digest(&bytes),
        "size":bytes.len(),"media_type":"image/png"}]);
    enqueue(&mut dev, &mut r, &t);
    wait_detail(&mut dev, &mut r, &t["task_id"], "screenshot");
    let second_id = uuid();
    dev.launch(&mut r, &second_id);
    let second = dev.launched(&mut r, &second_id);
    let other = task(&second, "independent session can run");
    enqueue(&mut dev, &mut r, &other);
    within("other session prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("independent session can run")
    });
    assert!(
        !std::fs::read_to_string(rig.fake.join("input"))
            .unwrap()
            .contains("must wait for image")
    );
}

/// The host identity `runtime/host-work.sqlite` is bound to, if any.
fn bound_identity(rig: &Rig) -> Option<Value> {
    let db =
        rusqlite::Connection::open(rig.sandbox.config().join("runtime/host-work.sqlite")).unwrap();
    db.query_row("SELECT host FROM identity WHERE id=1", [], |r| {
        r.get::<_, String>(0)
    })
    .ok()
    .map(|text| serde_json::from_str(&text).unwrap())
}

fn retired_databases(rig: &Rig) -> Vec<PathBuf> {
    std::fs::read_dir(rig.sandbox.config().join("runtime"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("host-work.sqlite.retired-")
        })
        .collect()
}

#[test]
fn hosting_binds_no_records_before_the_host_is_verified() {
    let rig = Rig::configured_as("claude", false);
    let db = rig.sandbox.config().join("runtime/host-work.sqlite");
    within("host work database", || db.exists());
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(bound_identity(&rig), None);
}

/// `runtime.toml` without the profile's required `project`.
fn break_config(rig: &Rig) -> String {
    let path = rig.sandbox.config().join("runtime.toml");
    let good = std::fs::read_to_string(&path).unwrap();
    let broken = good.replace("project = \"local:home\"\n", "");
    assert_ne!(broken, good);
    private(&path, &broken);
    good
}

fn runtime_log(rig: &Rig) -> String {
    std::fs::read_to_string(rig.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
}

#[test]
fn a_broken_runtime_toml_pauses_hosting_until_it_is_fixed() {
    let rig = Rig::new("claude");
    let pid = rig.sandbox.runtime_pid().unwrap();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let good = break_config(&rig);
    within("the problem in runtime.log", || {
        runtime_log(&rig).contains("missing field `project`")
    });
    assert_eq!(dev.launch(&mut r, &uuid())["code"], "busy");

    private(&rig.sandbox.config().join("runtime.toml"), &good);
    within("hosting resumes", || {
        runtime_log(&rig).contains("runtime.toml is valid again")
    });
    let rid = uuid();
    dev.launch(&mut r, &rid);
    assert_eq!(dev.launched(&mut r, &rid)["state"], "started");
    assert_eq!(rig.sandbox.runtime_pid(), Some(pid), "no restart needed");
}

#[test]
fn runtime_restart_refuses_a_runtime_toml_that_fails_its_check() {
    let rig = Rig::new("claude");
    let pid = rig.sandbox.runtime_pid().unwrap();
    break_config(&rig);
    let (out, err, ok) = rig.sandbox.atem(&["runtime", "restart"]);
    rig.sandbox.track();
    assert!(!ok, "{out}{err}");
    assert!(err.contains("missing field `project`"), "{err}");
    assert!(err.contains("atem runtime restart"), "{err}");
    assert_eq!(rig.sandbox.runtime_pid(), Some(pid), "nothing was stopped");
}

#[test]
fn records_left_by_another_host_identity_are_moved_aside() {
    let mut rig = Rig::prepared("claude", |_| {});
    // What an earlier run left: hosting enabled before this host was
    // verified, under the runtime's `unpaired` identity.
    let runtime = rig.sandbox.config().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stale = json!({"account_id":"unpaired","atem_device_id":"unpaired","host_trust_gen":1});
    let path = runtime.join("host-work.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL);",
    )
    .unwrap();
    db.execute(
        "INSERT INTO identity(id,host) VALUES(1,?1)",
        [stale.to_string()],
    )
    .unwrap();
    drop(db);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    rig.start();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    assert_eq!(dev.launched(&mut r, &rid)["state"], "started");
    assert_eq!(bound_identity(&rig), Some(host()));
    let retired = retired_databases(&rig);
    assert_eq!(retired.len(), 1, "{retired:?}");
    let kept = rusqlite::Connection::open(&retired[0]).unwrap();
    let identity: String = kept
        .query_row("SELECT host FROM identity WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&identity).unwrap(), stale);
    let log = std::fs::read_to_string(rig.sandbox.dir.path().join("runtime.log")).unwrap();
    assert!(log.contains("moved aside"), "{log}");
}

#[test]
fn runtime_start_and_check_require_pairing_before_any_side_effects() {
    let sandbox = Sandbox::new();
    for command in ["start", "check"] {
        let (out, err, ok) = sandbox.atem(&["runtime", command]);
        assert!(!ok, "{command}: {out}{err}");
        assert!(err.contains("atem pair"), "{err}");
        assert!(!sandbox.config().join("runtime.toml").exists());
        assert!(!sandbox.config().join("runtime.lock").exists());
        assert!(sandbox.runtime_pid().is_none());
    }
}

#[test]
fn runtime_start_initializes_once_and_check_does_not_start_a_runtime() {
    let sandbox = Sandbox::new();
    write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
    let (out, err, ok) = sandbox.atem(&["runtime", "check"]);
    assert!(ok, "{out}{err}");
    assert!(sandbox.runtime_pid().is_none());
    assert!(!sandbox.config().join("runtime.toml").exists());
    assert!(
        out.contains(
            "Collaboration: inactive (agent hosting is disabled); per_hour = 30; per_workflow = 8; result_timeout = 30m"
        ),
        "{out}"
    );

    let (out, err, ok) = sandbox.atem(&["runtime", "start"]);
    assert!(ok, "{out}{err}");
    let pid = sandbox.runtime_pid().unwrap();
    assert!(out.contains(&format!("pid {pid}")), "{out}");
    assert!(out.contains("hosting disabled"), "{out}");
    let path = sandbox.config().join("runtime.toml");
    let original = std::fs::read_to_string(&path).unwrap();
    let config: toml::Value = toml::from_str(&original).unwrap();
    assert_eq!(config["enabled"].as_bool(), Some(false));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(sandbox.records().is_empty());

    let (out, err, ok) = sandbox.atem(&["runtime", "start"]);
    assert!(ok, "{out}{err}");
    assert!(out.contains("already running"), "{out}");
    assert_eq!(sandbox.runtime_pid(), Some(pid));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

    private(
        &path,
        "version = 1\nenabled = false\ninvalid_setting = true\n",
    );
    for command in ["start", "check"] {
        let (out, err, ok) = sandbox.atem(&["runtime", command]);
        assert!(!ok, "{command}: {out}{err}");
        assert!(err.contains("invalid runtime.toml"), "{err}");
        assert_eq!(sandbox.runtime_pid(), Some(pid));
    }
    assert!(
        std::fs::read_to_string(path)
            .unwrap()
            .contains("invalid_setting")
    );
}

#[test]
fn runtime_check_lists_collaboration_consent_and_labels() {
    // Launch on message is for Claude Code profiles only (stage 1).
    let rig = Rig::prepared("claude", |_| {});
    let path = rig.sandbox.config().join("runtime.toml");
    let config = std::fs::read_to_string(&path).unwrap();
    private(
        &path,
        &format!(
            "{config}\nlabels = [\"tag:backend\"]\nlaunch = \"on_message\"\nresults = true\nauto_report = \"final_message\"\n[instance]\nlabels = [\"project:atem\"]\n[collab]\nsend = true\nper_hour = 12\nper_workflow = 4\nresult_timeout = \"90s\"\n"
        ),
    );
    let (out, err, ok) = rig.sandbox.atem(&["runtime", "check"]);
    assert!(ok, "{out}{err}");
    for text in [
        "Instance labels: project:atem",
        "Collaboration: enabled; per_hour = 12; per_workflow = 4; result_timeout = 90s",
        "labels: tag:backend; launch: on_message; results: true; auto_report: final_message",
        "may launch:",
        "may send:",
    ] {
        assert!(out.contains(text), "missing {text}: {out}");
    }
    assert!(rig.sandbox.runtime_pid().is_none());
}

#[test]
fn concurrent_runtime_start_commands_share_one_configuration_and_runtime() {
    let sandbox = Sandbox::new();
    write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_atem"))
            .args(["runtime", "start"])
            .env_clear()
            .envs(sandbox.env())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let children = [spawn(), spawn()];
    let outputs = children.map(|child| child.wait_with_output().unwrap());
    sandbox.track();
    let pid = sandbox.runtime_pid().unwrap();
    for output in outputs {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{out}{err}");
        assert!(out.contains(&format!("pid {pid}")), "{out}");
    }
    let text = std::fs::read_to_string(sandbox.config().join("runtime.toml")).unwrap();
    let config: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(config["enabled"].as_bool(), Some(false));
    assert!(sandbox.records().is_empty());
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug ATEM_TEST_BUILD hook")]
fn runtime_start_reuses_an_existing_runtime_of_another_build() {
    let sandbox = Sandbox::new();
    write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
    let mut child = Command::new(env!("CARGO_BIN_EXE_atem"))
        .arg("runtime")
        .env_clear()
        .envs(sandbox.env())
        .env("ATEM_TEST_BUILD", "0.0.1+runtime-start-fixture")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    within("the existing runtime", || sandbox.runtime_pid().is_some());
    sandbox.track();
    let pid = sandbox.runtime_pid().unwrap();
    let (out, err, ok) = sandbox.atem(&["runtime", "start"]);
    assert!(ok, "{out}{err}");
    assert!(out.contains("0.0.1+runtime-start-fixture"), "{out}");
    assert!(out.contains("atem runtime restart"), "{out}");
    assert_eq!(sandbox.runtime_pid(), Some(pid));
}

#[test]
fn runtime_start_supports_remote_launch_and_notifications_with_approved_exports() {
    let rig = Rig::prepared("claude", |_| {});
    let path = rig.sandbox.config().join("runtime.toml");
    let original = std::fs::read_to_string(&path).unwrap();
    let original = original.replace(
        "\"PROVIDER_TEST_KEY\"",
        "\"PROVIDER_TEST_KEY\", \"CUSTOM_BASE_URL\"",
    );
    private(&path, &original);
    let env_file = rig.sandbox.dir.path().join("provider.json");
    let mut env: Value = serde_json::from_slice(&std::fs::read(&env_file).unwrap()).unwrap();
    env.as_object_mut().unwrap().remove("PROVIDER_TEST_KEY");
    private(&env_file, &env.to_string());
    let output = Command::new(env!("CARGO_BIN_EXE_atem"))
        .args(["runtime", "start"])
        .env_clear()
        .envs(rig.sandbox.env())
        .env("ASTATION_WS", &rig.astation.url)
        .env("ATEM_RUNTIME_IDLE_SECS", "1")
        .env("PROVIDER_TEST_KEY", "approved-test-export")
        .env("CUSTOM_BASE_URL", "https://provider.invalid/v1")
        .env("UNAPPROVED_TEST_KEY", "must-not-reach-the-agent")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    rig.sandbox.track();
    assert!(output.status.success(), "{:?}", output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("approved-test-export"));
    let pid = rig.sandbox.runtime_pid().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert!(rig.sandbox.records().is_empty());
    std::thread::sleep(Duration::from_millis(1300));
    assert_eq!(
        rig.sandbox.runtime_pid(),
        Some(pid),
        "enabled hosting survives idle timeout"
    );

    let (out, err, ok) = rig.sandbox.atem(&["runtime", "start"]);
    assert!(ok, "{out}{err}");
    assert_eq!(rig.sandbox.runtime_pid(), Some(pid));
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    rig.sandbox.track();
    let record = &rig.sandbox.records()[0];
    let agent_pid = record["agent_pid"].as_u64().unwrap();
    let env = std::fs::read(format!("/proc/{agent_pid}/environ")).unwrap();
    let env: Vec<&[u8]> = env.split(|b| *b == 0).collect();
    assert!(env.contains(&b"PROVIDER_TEST_KEY=approved-test-export".as_slice()));
    assert!(env.contains(&b"CUSTOM_BASE_URL=https://provider.invalid/v1".as_slice()));
    assert!(
        !env.iter()
            .any(|value| value.starts_with(b"UNAPPROVED_TEST_KEY="))
    );
    let work = task(&launch, "Work delivered through the background runtime");
    assert_eq!(
        enqueue(&mut dev, &mut r, &work)["result"]["work"]["state"],
        "queued"
    );
    within("notification prompt after background startup", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Work delivered through the background runtime")
    });
}

#[test]
fn remote_launch_deduplicates_and_adopts_original_worker_after_restart() {
    for provider in ["claude", "codex"] {
        let mut rig = Rig::new(provider);
        let mut r = Router::new(&rig.astation);
        let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
        assert!(dev.a.welcome().features.iter().any(|f| f == "host.launch"));
        let rid = uuid();
        let expiry = r9log::host_now().wall_ms + 60_000;
        let launch = json!({"op":"host_launch","host":host(),"request_id":rid,"profile_id":"backend","profile_revision":1,"expires_at":expiry});
        dev.request(&mut r, launch.clone());
        let result = dev.launched(&mut r, &rid);
        assert_eq!(
            dev.request(&mut r, launch.clone())["result"]["launch"],
            result
        );
        within("one worker", || rig.sandbox.records().len() == 1);
        rig.sandbox.track();
        let record = rig.sandbox.records()[0].clone();
        let sid = result["session_id"].as_str().unwrap();
        let mut frontend = rig
            .sandbox
            .spawn(&["agent", "attach", sid], &rig.sandbox.home, &[]);
        frontend.shows("READY");
        assert_eq!(frontend.detach(), sid);
        // Arguments belong to the local profile. Provider values never enter the receipt DB.
        let db = std::fs::read(rig.sandbox.config().join("runtime/host-work.sqlite")).unwrap();
        assert!(!String::from_utf8_lossy(&db).contains("isolated-test-value"));
        let pid = record["agent_pid"].as_u64().unwrap();
        let argv = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
        let argv: Vec<&[u8]> = argv.split(|b| *b == 0).collect();
        assert!(
            argv.windows(2)
                .any(|w| w == [b"--profile".as_slice(), b"oss".as_slice()])
        );
        drop(r);
        rig.restart();
        let mut r = Router::new(&rig.astation);
        let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
        assert_eq!(dev.request(&mut r, launch)["result"]["launch"], result);
        assert_eq!(rig.sandbox.records().len(), 1);
        assert_eq!(rig.sandbox.records()[0]["worker_pid"], record["worker_pid"]);
    }
}

#[test]
fn notification_waits_for_readiness_dispatches_once_and_needs_explicit_result() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let first = task(&launch, "Implement backend contract");
    assert_eq!(
        enqueue(&mut dev, &mut r, &first)["result"]["work"]["state"],
        "queued"
    );
    within("one submitted prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Implement backend contract")
    });
    assert_eq!(
        enqueue(&mut dev, &mut r, &first)["result"]["work"]["task_id"],
        first["task_id"]
    );
    let second = task(&launch, "Followup task must wait");
    enqueue(&mut dev, &mut r, &second);
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        work(&mut dev, &mut r, &second["task_id"])["state"],
        "blocked"
    );
    let input = std::fs::read_to_string(rig.fake.join("input")).unwrap();
    assert!(!input.contains("Followup task must wait"));
    assert_eq!(input.matches("Implement backend contract").count(), 1);
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = work(&mut dev, &mut r, &first["task_id"]);
        if status["state"] == "awaiting_result" {
            break;
        }
        assert!(Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let result = json!({"kind":"vault","id":"result","version":1,"text":"implemented","digest":atem_client::session::host_work::digest(b"implemented")});
    let done = dev.request(
        &mut r,
        json!({"op":"work_complete","host":host(),"task_id":first["task_id"],"result":result}),
    );
    assert_eq!(done["result"]["work"]["state"], "completed");
    rig.sandbox.track();
}

#[test]
fn launch_requires_both_scoped_permission_and_local_consent() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    for (id, service) in [("svc-view", true), ("unapproved", false)] {
        let mut dev = Dev::new(&mut r, &rig.log, id, service);
        assert_eq!(dev.launch(&mut r, &uuid())["code"], "forbidden");
    }
    assert!(rig.sandbox.records().is_empty());
    // Explicit hosting survives the ordinary idle timeout with no sessions.
    std::thread::sleep(Duration::from_millis(1_200));
    assert!(rig.sandbox.runtime_pid().is_some());
}

#[test]
fn notifications_preserve_terminal_drafts_and_can_be_cancelled_or_expire() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let sid = launch["session_id"].as_str().unwrap();
    let mut frontend = rig
        .sandbox
        .spawn(&["agent", "attach", sid], &rig.sandbox.home, &[]);
    frontend.shows("READY");
    frontend.send(b"my draft");
    within("draft input", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("my draft")
    });
    let t = task(&launch, "must not overwrite draft");
    enqueue(&mut dev, &mut r, &t);
    wait_detail(&mut dev, &mut r, &t["task_id"], "unsent input");
    let cancelled = dev.request(
        &mut r,
        json!({"op":"work_cancel","host":host(),"task_id":t["task_id"]}),
    );
    assert_eq!(cancelled["result"]["work"]["state"], "cancelled");
    let mut expiry = task(&launch, "expired notification");
    expiry["expires_at"] = json!(r9log::host_now().wall_ms + 300);
    enqueue(&mut dev, &mut r, &expiry);
    wait_state(&mut dev, &mut r, &expiry["task_id"], "expired");
    let input = std::fs::read_to_string(rig.fake.join("input")).unwrap();
    assert!(!input.contains("must not overwrite"));
    assert!(!input.contains("expired notification"));
    assert_eq!(frontend.detach(), sid);
}

#[test]
fn notification_does_not_take_over_a_lease_and_dispatches_after_release() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let mut target = host();
    target["session_id"] = launch["session_id"].clone();
    target["process_gen"] = launch["process_gen"].clone();
    let binding = json!({"target":target,"attachment_gen":dev.a.welcome().attachment_gen});
    let lease = dev.request(
        &mut r,
        json!({"op":"acquire","binding":binding,"takeover":false}),
    );
    assert_eq!(lease["op"], "lease");
    let t = task(&launch, "after explicit release");
    enqueue(&mut dev, &mut r, &t);
    wait_detail(&mut dev, &mut r, &t["task_id"], "lease");
    let released = dev.request(&mut r, json!({"op":"release","binding":lease["binding"]}));
    assert_eq!(released["op"], "lease_released");
    within("dispatch after release", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("after explicit release")
    });
}

#[test]
fn notification_waits_for_approval_without_answering_or_typing_into_it() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    std::fs::write(
        rig.fake.join("ask-1.json"),
        json!({"tool_name":"Bash","tool_input":{"command":"true"}}).to_string(),
    )
    .unwrap();
    within("approval asked", || {
        std::fs::read_to_string(rig.fake.join("events"))
            .unwrap_or_default()
            .contains("asked 1")
    });
    let t = task(&launch, "do not answer approval");
    enqueue(&mut dev, &mut r, &t);
    wait_state(&mut dev, &mut r, &t["task_id"], "blocked");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("do not answer approval")
    );
    assert!(!rig.fake.join("answer-1.json").exists());
}

#[test]
fn narrower_service_scopes_cannot_create_sessions_outside_their_scope() {
    let rig = Rig::configured("claude", |log| {
        log.enroll_service(
            "svc-restricted",
            &ServiceScope::new([HOST])
                .ops(["launch"])
                .sessions(Some(["ses-aaaaaaaaaaaa"])),
            r9log::host_now().wall_ms + 60_000,
        );
    });
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-restricted", true);
    let profiles = dev.request(&mut r, json!({"op":"host_profiles","host":host()}));
    assert_eq!(profiles["result"]["profiles"], json!([]));
    assert_eq!(dev.launch(&mut r, &uuid())["code"], "forbidden");
    assert!(rig.sandbox.records().is_empty());
}

#[test]
fn pending_work_is_fenced_after_a_service_is_narrowed_and_regranted() {
    let mut rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut owner = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    owner.launch(&mut r, &rid);
    let launch = owner.launched(&mut r, &rid);
    let sid = launch["session_id"].as_str().unwrap();
    let mut frontend = rig
        .sandbox
        .spawn(&["agent", "attach", sid], &rig.sandbox.home, &[]);
    frontend.shows("READY");
    frontend.send(b"draft");
    within("draft input", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("draft")
    });
    let mut service = Dev::new(&mut r, &rig.log, "svc-work", true);
    let t = task(&launch, "revoked task");
    enqueue(&mut service, &mut r, &t);
    wait_state(&mut service, &mut r, &t["task_id"], "blocked");
    let narrow = rig
        .log
        .narrow_service("svc-work", &ServiceScope::new([HOST]).ops(["view"]), None);
    owner.carry(&mut r, narrow);
    let grant = rig.log.set_service(
        "svc-work",
        &ServiceScope::new([HOST]).ops(["launch", "notify", "prompt", "view"]),
        r9log::host_now().wall_ms + 3_600_000,
    );
    owner.carry(&mut r, grant);
    let mut service = Dev::new(&mut r, &rig.log, "svc-work", true);
    let response = service.request(
        &mut r,
        json!({"op":"work_query","host":host(),"task_id":t["task_id"]}),
    );
    assert_eq!(response["code"], "forbidden");
    assert!(
        !std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("revoked task")
    );
    assert_eq!(frontend.detach(), sid);
}

#[test]
fn interrupted_notification_is_reconciled_without_a_second_prompt() {
    let mut rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let t = task(&launch, "one prompt across runtime restart");
    enqueue(&mut dev, &mut r, &t);
    within("first prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("one prompt across runtime restart")
    });
    rig.sandbox.track();
    drop(r);
    rig.restart();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-work", true);
    let duplicate = enqueue(&mut dev, &mut r, &t);
    assert_eq!(
        duplicate["result"]["work"]["task_id"], t["task_id"],
        "{duplicate}"
    );
    assert!(matches!(
        duplicate["result"]["work"]["state"].as_str(),
        Some("submitted" | "outcome_unknown" | "failed")
    ));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap()
            .matches("one prompt across runtime restart")
            .count(),
        1
    );
}

#[test]
fn a_reused_launch_or_task_identity_with_different_content_is_refused() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let conflicting = dev.request(&mut r, json!({"op":"host_launch","host":host(),"request_id":rid,
        "profile_id":"backend","profile_revision":1,"expires_at":r9log::host_now().wall_ms+120_000}));
    assert_eq!(conflicting["code"], "request_id_reused");
    let mut t = task(&launch, "original work");
    enqueue(&mut dev, &mut r, &t);
    t["prompt"] = json!("changed work");
    assert_eq!(enqueue(&mut dev, &mut r, &t)["code"], "request_id_reused");
    assert_eq!(rig.sandbox.records().len(), 1);
}

#[test]
fn ordinary_messages_use_account_membership_without_agent_execution_permission() {
    let rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut owner = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    owner.launch(&mut r, &rid);
    let launch = owner.launched(&mut r, &rid);
    let target = task(&launch, "unused")["target"].clone();
    let mut messenger = Dev::new(&mut r, &rig.log, "messenger", false);
    let message = notice(
        "member:messenger",
        "Memory is ready",
        vec![
            json!({"kind":"host"}),
            json!({"kind":"project","route_id":"backend","route_revision":1}),
            json!({"kind":"agent","route_id":"backend","route_revision":1,"target":target}),
        ],
    );
    let response = publish(&mut messenger, &mut r, &message);
    let recipients = &response["result"]["message"]["recipients"];
    assert_eq!(recipients[0]["delivery"]["state"], "stored");
    assert_eq!(recipients[1]["delivery"]["state"], "stored");
    assert_eq!(recipients[2]["delivery"]["state"], "refused");
    assert_eq!(recipients[2]["delivery"]["code"], "forbidden");
    assert_eq!(
        message_status(&mut messenger, &mut r, &message)["sender"],
        "member:messenger"
    );
    assert!(
        !std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Memory is ready")
    );
}

#[test]
fn inline_message_fanout_dispatches_once_and_retains_independent_recipient_results_after_restart() {
    let mut rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    dev.launch(&mut r, &rid);
    let launch = dev.launched(&mut r, &rid);
    let target = task(&launch, "unused")["target"].clone();
    let mut stale = target.clone();
    stale["process_gen"] = json!(uuid());
    let message = notice(
        &format!("member:{MAC}"),
        "Review the backend contract",
        vec![
            json!({"kind":"agent","route_id":"backend","route_revision":1,"target":target}),
            json!({"kind":"agent","route_id":"backend","route_revision":1,"target":stale}),
            json!({"kind":"host"}),
        ],
    );
    let response = publish(&mut dev, &mut r, &message);
    let statuses = &response["result"]["message"]["recipients"];
    assert_eq!(statuses[0]["delivery"]["state"], "work");
    assert_eq!(statuses[1]["delivery"]["state"], "refused");
    assert_eq!(statuses[2]["delivery"]["state"], "stored");
    within("inline message prompt", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Review the backend contract")
    });
    let receipt_id = statuses[0]["delivery"]["work"]["receipt_id"].clone();
    let task_id = message["recipients"][0]["recipient_id"].clone();
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    wait_state(&mut dev, &mut r, &task_id, "awaiting_result");
    let result = json!({"kind":"vault","id":"review-result","version":1,"text":"reviewed","digest":atem_client::session::host_work::digest(b"reviewed")});
    dev.request(
        &mut r,
        json!({"op":"work_complete","host":host(),"task_id":task_id,"result":result}),
    );
    drop(r);
    rig.restart();
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, MAC, false);
    let replay = publish(&mut dev, &mut r, &message);
    let progress = &replay["result"]["message"]["recipients"];
    assert_eq!(progress[0]["delivery"]["work"]["state"], "completed");
    assert_eq!(progress[0]["delivery"]["work"]["receipt_id"], receipt_id);
    let mut reference = result.clone();
    reference.as_object_mut().unwrap().remove("text");
    assert_eq!(progress[0]["delivery"]["work"]["result"], reference);
    assert_eq!(progress[1], statuses[1]);
    assert_eq!(progress[2], statuses[2]);
    assert_eq!(
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap()
            .matches("Review the backend contract")
            .count(),
        1
    );
    assert_eq!(rig.sandbox.records().len(), 1);
}

#[test]
fn messages_bind_sender_content_destinations_and_service_scope() {
    let rig = Rig::configured("claude", |log| {
        log.enroll_service(
            "svc-message",
            &ServiceScope::new([HOST]).ops(["message", "view"]),
            r9log::host_now().wall_ms + 60_000,
        );
        log.enroll_service(
            "svc-scoped-message",
            &ServiceScope::new([HOST])
                .ops(["message", "view"])
                .sessions(Some(["ses-abcdefghijkl"])),
            r9log::host_now().wall_ms + 60_000,
        );
    });
    let mut r = Router::new(&rig.astation);
    let mut dev = Dev::new(&mut r, &rig.log, "svc-message", true);
    let message = notice("service:svc-message", "Ready", vec![json!({"kind":"host"})]);
    let stored = publish(&mut dev, &mut r, &message);
    assert_eq!(
        stored["result"]["message"]["recipients"][0]["delivery"]["state"],
        "stored"
    );
    let mut changed = message.clone();
    changed["text"] = json!("Different instructions");
    assert_eq!(
        publish(&mut dev, &mut r, &changed)["code"],
        "request_id_reused"
    );
    changed = message.clone();
    changed["recipients"][0]["recipient_id"] = json!(uuid());
    assert_eq!(
        publish(&mut dev, &mut r, &changed)["code"],
        "request_id_reused"
    );
    changed = message.clone();
    changed["message_id"] = json!(uuid());
    changed["sender"] = json!(format!("member:{MAC}"));
    assert_eq!(publish(&mut dev, &mut r, &changed)["code"], "forbidden");
    // The sending session, the reply link and kinds other than a request are
    // local-only: a remote envelope with one is invalid. The SDK refuses to
    // send it (the host refuses it at decode, `invalid_request`; the shared
    // vectors cover that), and nothing is recorded.
    let reply_to = json!({"message_id": uuid(), "task_id": uuid()});
    for (field, value, extra) in [
        ("from_session", json!("ses-abcdefghijkl"), None),
        ("reply_to", reply_to.clone(), None),
        ("kind", json!("result"), Some(("reply_to", reply_to))),
    ] {
        let mut local_only = notice("service:svc-message", "Ready", vec![json!({"kind":"host"})]);
        local_only[field] = value;
        if let Some((name, value)) = extra {
            local_only[name] = value;
        }
        let refused = dev
            .a
            .send(
                &json!({"type":"session","data":{"v":1,"id":uuid(),"op":"message_publish",
                    "host":host(),"message":local_only}}),
                client_ms(),
            )
            .unwrap_err();
        assert!(
            format!("{refused:?}").contains("invalid_request"),
            "{field}: {refused:?}"
        );
        assert!(message_status(&mut dev, &mut r, &local_only).is_null());
    }
    let mut other = Dev::new(&mut r, &rig.log, "unapproved", false);
    assert!(
        other.request(
            &mut r,
            json!({"op":"message_query","host":host(),"message_id":message["message_id"]})
        )["result"]
            .is_null()
    );
    let mut scoped = Dev::new(&mut r, &rig.log, "svc-scoped-message", true);
    let message = notice(
        "service:svc-scoped-message",
        "Out of session scope",
        vec![json!({"kind":"host"})],
    );
    assert_eq!(
        publish(&mut scoped, &mut r, &message)["result"]["message"]["recipients"][0]["delivery"]["state"],
        "refused"
    );
    let mut view = Dev::new(&mut r, &rig.log, "svc-view", true);
    assert_eq!(
        publish(
            &mut view,
            &mut r,
            &notice("service:svc-view", "Denied", vec![json!({"kind":"host"})])
        )["code"],
        "forbidden"
    );
    assert!(rig.sandbox.records().is_empty());
}

#[test]
fn message_work_waits_for_drafts_and_stays_fenced_after_sender_authority_changes() {
    let mut rig = Rig::new("claude");
    let mut r = Router::new(&rig.astation);
    let mut owner = Dev::new(&mut r, &rig.log, MAC, false);
    let rid = uuid();
    owner.launch(&mut r, &rid);
    let launch = owner.launched(&mut r, &rid);
    let sid = launch["session_id"].as_str().unwrap();
    let mut frontend = rig
        .sandbox
        .spawn(&["agent", "attach", sid], &rig.sandbox.home, &[]);
    frontend.shows("READY");
    frontend.send(b"draft");
    within("draft", || {
        std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("draft")
    });
    let mut service = Dev::new(&mut r, &rig.log, "svc-work", true);
    let message = notice(
        "service:svc-work",
        "Must remain queued",
        vec![
            json!({"kind":"agent","route_id":"backend","route_revision":1,"target":task(&launch,"unused")["target"]}),
        ],
    );
    publish(&mut service, &mut r, &message);
    wait_detail(
        &mut service,
        &mut r,
        &message["recipients"][0]["recipient_id"],
        "unsent input",
    );
    let narrow = rig
        .log
        .narrow_service("svc-work", &ServiceScope::new([HOST]).ops(["view"]), None);
    owner.carry(&mut r, narrow);
    let grant = rig.log.set_service(
        "svc-work",
        &ServiceScope::new([HOST]).ops(["launch", "message", "notify", "prompt", "view"]),
        r9log::host_now().wall_ms + 3_600_000,
    );
    owner.carry(&mut r, grant);
    let mut service = Dev::new(&mut r, &rig.log, "svc-work", true);
    within("message remains fenced after regrant", || {
        let status = message_status(&mut service, &mut r, &message);
        status["recipients"][0]["delivery"]["work"]["state"] == "blocked"
            && status["recipients"][0]["delivery"]["work"]["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("authorized channel")
    });
    assert_eq!(service.request(&mut r,
        json!({"op":"work_query","host":host(),"task_id":message["recipients"][0]["recipient_id"]}))["code"], "forbidden");
    assert!(
        !std::fs::read_to_string(rig.fake.join("input"))
            .unwrap_or_default()
            .contains("Must remain queued")
    );
    assert_eq!(frontend.detach(), sid);
}

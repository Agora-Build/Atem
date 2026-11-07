//! Local collaboration through the real runtime and real agent-child processes.
#![cfg(target_os = "linux")]
mod support;

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::astation::{FakeAstation, write_verified_pairing};
use support::r9::write_pin;
use support::r9log::{TestLog, secret};
use support::{Sandbox, within};

const HOST: &str = "collab-host";
const ACCOUNT: &str = "collab-account";

fn private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    runtime: Option<Child>,
    config: String,
    context_hook: bool,
}

impl Rig {
    /// A running runtime with three routes.
    fn new() -> Self {
        let mut rig = Self::unstarted();
        rig.start();
        rig
    }

    /// The same sandbox before its runtime starts, to prepare its files.
    fn unstarted() -> Self {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let mut log = TestLog::genesis(ACCOUNT, &secret("collab astation"));
        let seed = secret("collab host");
        log.add_host(HOST, 1, &seed);
        write_pin(&sandbox.config(), &log, HOST, 1, &seed);
        let mut config = "version = 1\nenabled = true\n[instance]\nlabels = [\"project:collab\"]\n[collab]\nsend = true\n".to_string();
        for route in ["a", "b", "c"] {
            let cwd = sandbox.home.join(route);
            std::fs::create_dir_all(&cwd).unwrap();
            config.push_str(&format!(
                r#"
[[profiles]]
id = {route:?}
revision = 1
label = {route:?}
provider = "claude"
cwd = {cwd:?}
project = "local:{route}"
principals = ["member:astation"]
[[routes]]
id = {route:?}
revision = 1
profile_id = {route:?}
labels = ["tag:{route}"]
principals = ["local"]
"#
            ));
        }
        Self {
            sandbox,
            astation: FakeAstation::start(),
            runtime: None,
            config,
            context_hook: false,
        }
    }

    fn start(&mut self) {
        private(&self.sandbox.config().join("runtime.toml"), &self.config);
        let output = std::fs::File::create(self.sandbox.dir.path().join("runtime.log")).unwrap();
        let context = self.sandbox.dir.path().join("context");
        std::fs::create_dir_all(&context).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        if self.context_hook {
            command.env("ATEM_TEST_CONTEXT_DIR", context);
        }
        self.runtime = Some(
            command
                .arg("runtime")
                .envs(self.sandbox.env())
                .env("ASTATION_WS", &self.astation.url)
                .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
                .env("ATEM_TEST_NO_INIT_LIMIT", "1")
                .stdin(Stdio::null())
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        );
        within("collaboration runtime", || {
            self.sandbox.config().join("runtime.socket").exists()
        });
    }

    fn request(&self, mut request: Value, reply: &str) -> Value {
        let path = std::fs::read_to_string(self.sandbox.config().join("runtime.socket")).unwrap();
        let socket = UnixStream::connect(path).unwrap();
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

    fn launch(&self, route: &str, name: &str) -> (String, PathBuf) {
        let fake = self.sandbox.dir.path().join(name);
        std::fs::create_dir_all(&fake).unwrap();
        let mut env = self.sandbox.env();
        env.push((
            "CLAUDE_CLI_BIN".into(),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/approvals/fake-agent.py")
                .display()
                .to_string(),
        ));
        env.push(("FAKE_DIR".into(), fake.display().to_string()));
        let reply = self.request(json!({"op":"launch","provider":"claude","cwd":self.sandbox.home.join(route),"env":env,"rows":24,"cols":80}), "launched");
        assert_eq!(reply["op"], "launched", "{reply}");
        within("fake agent ready", || fake.join("events").exists());
        (reply["session"]["id"].as_str().unwrap().into(), fake)
    }

    fn agent(&self, fake: &Path, number: u32, args: &[&str]) -> Value {
        self.agent_with(env!("CARGO_BIN_EXE_atem"), fake, number, args)
    }

    /// A command run by the agent's own child with the `atem` at `bin`.
    fn agent_with(&self, bin: &str, fake: &Path, number: u32, args: &[&str]) -> Value {
        self.agent_begin(bin, fake, number, args);
        self.agent_end(fake, number)
    }

    /// Hands the agent's child a command without waiting for it, so two
    /// agents can run theirs at the same time.
    fn agent_begin(&self, bin: &str, fake: &Path, number: u32, args: &[&str]) {
        let argv: Vec<_> = std::iter::once(bin).chain(args.iter().copied()).collect();
        private(
            &fake.join(format!("run-{number}.tmp")),
            &json!({"argv":argv}).to_string(),
        );
        std::fs::rename(
            fake.join(format!("run-{number}.tmp")),
            fake.join(format!("run-{number}.json")),
        )
        .unwrap();
    }

    /// What the command begun as `number` printed.
    fn agent_end(&self, fake: &Path, number: u32) -> Value {
        let out = fake.join(format!("run-{number}.out"));
        within("agent child command", || out.exists());
        serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap()
    }

    fn send(&self, fake: &Path, n: u32, selector: &str, text: &str) -> String {
        let output = self.agent(fake, n, &["message", "send", "--to", selector, text]);
        assert_eq!(output["code"], 0, "{output}");
        output["stdout"].as_str().unwrap().trim().to_string()
    }

    /// A send that asks for a launch (`--launch`); the route is named by its
    /// instance address, which `--launch` requires.
    fn send_launch(&self, fake: &Path, n: u32, route: &str, text: &str) -> String {
        let output = self.agent(
            fake,
            n,
            &[
                "message",
                "send",
                "--to",
                &self.address(route),
                "--launch",
                text,
            ],
        );
        assert_eq!(output["code"], 0, "{output}");
        output["stdout"].as_str().unwrap().trim().to_string()
    }

    /// `atem:<atem_id>/<route>`, as `atem message directory` prints it.
    fn address(&self, route: &str) -> String {
        let directory = self.request(
            json!({"op":"message_directory","selector":format!("tag:{route}")}),
            "message_directory",
        );
        format!(
            "atem:{}/{route}",
            directory["rows"][0]["atem_id"].as_str().unwrap()
        )
    }

    /// How many sessions the runtime lists.
    fn sessions(&self) -> usize {
        self.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .len()
    }

    fn status(&self, id: &str) -> Value {
        let reply = self.request(
            json!({"op":"message_status","message_id":id}),
            "message_status",
        );
        assert_eq!(reply["op"], "message_status", "{reply}");
        reply["messages"][0].clone()
    }

    /// `local`'s durable control generation (the session journal's
    /// `principals` file, `<len> <crc> <json>`): a fence raises it.
    fn local_control_gen(&self) -> u64 {
        let path = self.sandbox.config().join("runtime/journal/principals");
        let text = std::fs::read_to_string(path).unwrap();
        let json = text
            .splitn(3, ' ')
            .nth(2)
            .expect("a framed principals file");
        let file: Value = serde_json::from_str(json.trim_end()).unwrap();
        file["principals"]["local"]["control_gen"].as_u64().unwrap()
    }

    /// Replaces `runtime.toml` (the runtime re-reads it about once a second).
    fn write_config(&self, text: &str) {
        let config = self.sandbox.config();
        private(&config.join("runtime.toml.tmp"), text);
        std::fs::rename(config.join("runtime.toml.tmp"), config.join("runtime.toml")).unwrap();
    }

    fn restart(&mut self) {
        assert_eq!(
            self.request(json!({"op":"restart"}), "restarting")["op"],
            "restarting"
        );
        let mut child = self.runtime.take().unwrap();
        within("runtime exit", || child.try_wait().unwrap().is_some());
        self.start();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.sandbox.track();
        if let Some(mut runtime) = self.runtime.take() {
            let _ = runtime.kill();
            let _ = runtime.wait();
        }
    }
}

#[test]
fn an_agent_tags_itself_through_its_own_child() {
    let rig = Rig::new();
    let (a, fake) = rig.launch("a", "a-agent");
    let (b, _) = rig.launch("b", "b-agent");
    let output = rig.agent(&fake, 1, &["agent", "tag", "add", "self:reviewer"]);
    assert_eq!(output["code"], 0, "{output}");
    assert!(output["stdout"].as_str().unwrap().contains(&a));
    let sessions = rig.request(json!({"op":"list"}), "sessions");
    let rows = sessions["sessions"].as_array().unwrap();
    assert_eq!(
        rows.iter().find(|s| s["id"] == a).unwrap()["self_tags"],
        json!(["self:reviewer"])
    );
    assert!(
        rows.iter()
            .find(|s| s["id"] == b)
            .unwrap()
            .get("self_tags")
            .is_none()
    );
    let (out, err, ok) = rig.sandbox.atem(&["agent", "list"]);
    assert!(ok && out.contains("tags: self:reviewer"), "{out}{err}");
    let forbidden = rig.agent(&fake, 2, &["agent", "tag", "add", "tag:auth"]);
    assert_ne!(forbidden["code"], 0);
    assert!(
        forbidden["stderr"]
            .as_str()
            .unwrap()
            .contains("agent labels are self:")
    );
    let (_, err, ok) = rig.sandbox.atem(&["agent", "tag", "list"]);
    assert!(!ok && err.contains("not inside an Atem session"), "{err}");
    for n in 0..15 {
        let tag = format!("self:t{n}");
        let output = rig.agent(&fake, n + 3, &["agent", "tag", "add", &tag]);
        assert_eq!(output["code"], 0, "{output}");
    }
    let output = rig.agent(&fake, 18, &["agent", "tag", "add", "self:overflow"]);
    assert_ne!(output["code"], 0);
    assert!(output["stderr"].as_str().unwrap().contains("at most 16"));
    assert_eq!(
        rig.agent(&fake, 19, &["agent", "tag", "remove", "self:reviewer"])["code"],
        0
    );
}

#[test]
fn one_message_reaches_two_agents_once_each() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b1) = rig.launch("b", "first");
    let (_, b2) = rig.launch("b", "second");
    let id = rig.send(&a, 1, "tag:b", "Review the API contract");
    for fake in [&b1, &b2] {
        within("collaboration prompt", || {
            std::fs::read_to_string(fake.join("input"))
                .unwrap_or_default()
                .contains("Review the API contract")
        });
        private(&fake.join("complete"), "");
    }
    within("two turn receipts", || {
        let status = rig.status(&id);
        status["tasks"]
            .as_array()
            .is_some_and(|t| t.len() == 2 && t.iter().all(|t| t["state"] == "awaiting_result"))
    });
    for fake in [&b1, &b2] {
        let input = std::fs::read_to_string(fake.join("input")).unwrap();
        assert_eq!(
            input.matches("Review the API contract").count(),
            1,
            "{input}"
        );
        assert!(input.contains("atem message reply --task"));
    }
    assert!(std::fs::read(a.join("input")).unwrap().is_empty());
    let directory = rig.request(
        json!({"op":"message_directory","selector":"tag:b"}),
        "message_directory",
    );
    assert_eq!(directory["rows"].as_array().unwrap().len(), 2);
}

/// A message counts once against the workflow however many agents it
/// reaches (`per_workflow` defaults to 8; this one reaches nine).
#[test]
fn one_message_to_nine_agents_counts_once() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let recipients: Vec<_> = (0..9)
        .map(|n| rig.launch("b", &format!("agent-{n}")).1)
        .collect();
    let id = rig.send(&a, 1, "tag:b", "fan out to nine agents");
    for fake in &recipients {
        within("fan-out prompt", || {
            std::fs::read_to_string(fake.join("input"))
                .unwrap_or_default()
                .contains("fan out to nine agents")
        });
    }
    assert_eq!(rig.status(&id)["tasks"].as_array().unwrap().len(), 9);
}

/// Results count against nothing: with the workflow's three messages used up,
/// the reply to the request still goes through, with context.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn replies_count_against_no_workflow_limit() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.config = rig
        .config
        .replace("send = true", "send = true\nper_workflow = 3");
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let _ = rig.launch("c", "third");
    let first = rig.send(&a, 1, "tag:b", "request that will be answered");
    within("first prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("request that will be answered")
    });
    // b's turn belongs to the workflow: its sends use the remaining two.
    rig.send(&b, 1, "tag:c", "child one");
    rig.send(&b, 2, "tag:c", "child two");
    let refused = rig.agent(&b, 3, &["message", "send", "--to", "tag:c", "child three"]);
    assert_ne!(refused["code"], 0, "{refused}");
    assert!(
        refused["stderr"]
            .as_str()
            .unwrap()
            .contains("limit: 3 messages per workflow"),
        "{refused}"
    );
    let task = await_task(&rig, &first, &b);
    let text = "Reply context that has to arrive.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-reply:1@1"));
    private(
        &rig.sandbox
            .dir
            .path()
            .join("context")
            .join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-reply:1","version":1,"digest":digest,"text":text})
            .to_string(),
    );
    let reply = rig.agent(
        &b,
        4,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "--vault",
            "v-reply:1@1",
            "answer with context",
        ],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    within("reply stored", || {
        rig.status(&first)["tasks"][0]["result"]["state"] == "submitted"
    });
    // The reply used none of the limit: the workflow is still exactly full.
    let still = rig.agent(&b, 5, &["message", "send", "--to", "tag:c", "child four"]);
    assert_ne!(still["code"], 0, "{still}");
    assert!(
        still["stderr"]
            .as_str()
            .unwrap()
            .contains("limit: 3 messages per workflow"),
        "{still}"
    );
}

/// 40 000 bytes of context plus the prompt can never be dispatched (32 KiB):
/// the send is refused with that reason and uses none of the hourly budget.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn a_context_over_the_task_bounds_is_refused_and_not_counted() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.config = rig
        .config
        .replace("send = true", "send = true\nper_hour = 1");
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let text = "x".repeat(40_000);
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-big:1@1"));
    private(
        &rig.sandbox
            .dir
            .path()
            .join("context")
            .join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-big:1","version":1,"digest":digest,"text":text}).to_string(),
    );
    let output = rig.agent(
        &a,
        1,
        &[
            "message",
            "send",
            "--to",
            "tag:b",
            "--vault",
            "v-big:1@1",
            "too much context",
        ],
    );
    assert_eq!(output["code"], 0, "{output}");
    let id = output["stdout"].as_str().unwrap().trim();
    within("oversize refusal", || {
        rig.status(id)["delivery"] == "refused"
    });
    let status = rig.status(id);
    assert_eq!(
        status["detail"],
        "the prompt with its context is over 32 KiB"
    );
    assert!(status["tasks"].as_array().unwrap().is_empty());
    assert!(std::fs::read(b.join("input")).unwrap().is_empty());
    // per_hour is 1, and the refused message did not use it.
    rig.send(&a, 2, "tag:b", "fits");
    within("the next send arrives", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("fits")
    });
}

/// Context sends count when they are accepted, after publication; those still
/// publishing bound the sender meanwhile, so a loop of them is refused at send.
#[test]
fn context_sends_still_publishing_count_against_the_hourly_limit() {
    let mut rig = Rig::new();
    rig.config = rig
        .config
        .replace("send = true", "send = true\nper_hour = 1");
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let vault = |n, text| {
        rig.agent(
            &a,
            n,
            &[
                "message",
                "send",
                "--to",
                "tag:b",
                "--vault",
                "v-wait:1@1",
                text,
            ],
        )
    };
    let first = vault(1, "first waits for its relay");
    assert_eq!(first["code"], 0, "{first}");
    let second = vault(2, "second must not queue behind it");
    assert_ne!(second["code"], 0, "{second}");
    assert!(
        second["stderr"]
            .as_str()
            .unwrap()
            .contains("limit: 1 messages per hour"),
        "{second}"
    );
    assert!(std::fs::read(b.join("input")).unwrap().is_empty());
}

/// The result task a reply creates for the origin agent obeys the task bounds:
/// a reply whose context could never be delivered is refused once its context
/// is read, and a corrected reply replaces it.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn a_reply_that_could_never_be_delivered_is_refused_and_can_be_corrected() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "answer with too much context");
    let task = await_task(&rig, &id, &b);
    let text = "x".repeat(40_000);
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-big:1@1"));
    private(
        &rig.sandbox
            .dir
            .path()
            .join("context")
            .join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-big:1","version":1,"digest":digest,"text":text}).to_string(),
    );
    let oversize = rig.agent(
        &b,
        1,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "--vault",
            "v-big:1@1",
            "too much",
        ],
    );
    assert_eq!(oversize["code"], 0, "{oversize}");
    assert!(
        oversize["stdout"]
            .as_str()
            .unwrap()
            .contains("reply publishing"),
        "{oversize}"
    );
    within("oversize reply refused", || {
        rig.status(&id)["tasks"][0]["result"]["state"] == "refused"
    });
    let result = &rig.status(&id)["tasks"][0]["result"];
    assert_eq!(
        result["detail"], "the prompt with its context is over 32 KiB",
        "{result}"
    );
    // The replier's task is still waiting, and the origin saw nothing.
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "awaiting_result");
    assert!(std::fs::read(a.join("input")).unwrap().is_empty());
    // Retrying the refused reply as it was returns the refusal.
    let again = rig.agent(
        &b,
        2,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "--vault",
            "v-big:1@1",
            "too much",
        ],
    );
    assert_ne!(again["code"], 0, "{again}");
    assert!(
        again["stderr"]
            .as_str()
            .unwrap()
            .contains("the prompt with its context is over 32 KiB"),
        "{again}"
    );
    assert_eq!(result_id(&again), result_id(&oversize));
    let smaller = rig.agent(
        &b,
        3,
        &["message", "reply", "--task", &task, "the short answer"],
    );
    assert_eq!(smaller["code"], 0, "{smaller}");
    assert_eq!(result_id(&smaller), result_id(&oversize));
    within("the corrected result arrives", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("the short answer")
    });
    let task = &rig.status(&id)["tasks"][0];
    assert_eq!(task["state"], "awaiting_result", "{task}");
    assert_eq!(task["detail"], "reply submitted", "{task}");
    assert_eq!(task["result"]["state"], "submitted", "{task}");
    assert_eq!(task["result"]["text"], "the short answer", "{task}");
}

/// `build_atem_id` keeps non-ASCII characters, and the selectors that
/// `atem message directory` prints must address the instance again.
#[test]
fn a_directory_selector_for_a_non_ascii_instance_id_sends_back() {
    let mut rig = Rig::unstarted();
    let id = "测试主机-1a2b3c4d-956631ec";
    private(
        &rig.sandbox.config().join("config.toml"),
        &format!("atem_id = {id:?}\n[codex]\nhooks = false\n"),
    );
    rig.start();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let directory = rig.agent(&a, 1, &["message", "directory", "tag:b"]);
    assert_eq!(directory["code"], 0, "{directory}");
    let line = directory["stdout"]
        .as_str()
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    let selector = line.split_whitespace().next().unwrap();
    assert_eq!(selector, format!("atem:{id}/b"), "{line}");
    rig.send(&a, 2, selector, "reach a non-ASCII instance id");
    within("non-ASCII instance prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("reach a non-ASCII instance id")
    });
}

#[test]
fn a_bad_selector_reports_its_own_reason() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let output = rig.agent(
        &a,
        1,
        &[
            "message",
            "send",
            "--to",
            "tag:b",
            "--to",
            "project:ok",
            "--to",
            "tag:Bad",
            "work",
        ],
    );
    assert_ne!(output["code"], 0, "{output}");
    assert!(
        output["stderr"]
            .as_str()
            .unwrap()
            .contains("selector 3: names are 1-32 of a-z, 0-9 and -"),
        "{output}"
    );
}

#[test]
fn sending_is_off_by_default() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace("send = true", "send = false");
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let output = rig.agent(&a, 1, &["message", "send", "--to", "tag:b", "work"]);
    assert_ne!(output["code"], 0, "{output}");
    assert!(
        output["stderr"]
            .as_str()
            .unwrap()
            .contains("collaboration unavailable: set `[collab] send = true` in runtime.toml"),
        "{output}"
    );
}

#[test]
fn a_retry_returns_the_recorded_resolution() {
    let mut rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "original");
    let (_, c) = rig.launch("b", "new-match");
    assert_eq!(
        rig.agent(&b, 1, &["agent", "tag", "add", "self:chosen"])["code"],
        0
    );
    let id = rig.send(&a, 1, "self:chosen", "only the original recipient");
    within("original delivery", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("only the original recipient")
    });
    let before = rig.status(&id);
    rig.restart();
    assert_eq!(
        rig.agent(&c, 1, &["agent", "tag", "add", "self:chosen"])["code"],
        0
    );
    let after = rig.status(&id);
    assert_eq!(before["tasks"][0]["task_id"], after["tasks"][0]["task_id"]);
    assert_eq!(after["tasks"].as_array().unwrap().len(), 1);
    assert!(std::fs::read(c.join("input")).unwrap().is_empty());
    assert_eq!(
        std::fs::read_to_string(b.join("input"))
            .unwrap()
            .matches("only the original recipient")
            .count(),
        1
    );
}

#[test]
fn cancel_works_while_queued_only() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let first = rig.send(&a, 1, "tag:b", "first task");
    within("first prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("first task")
    });
    let second = rig.send(&a, 2, "tag:b", "cancel this task");
    let status = rig.status(&second);
    let task = status["tasks"][0]["task_id"].as_str().unwrap();
    assert_eq!(
        rig.request(
            json!({"op":"message_cancel","task_id":task}),
            "message_cancelled"
        )["op"],
        "message_cancelled"
    );
    let first_status = rig.status(&first);
    let task = first_status["tasks"][0]["task_id"].as_str().unwrap();
    assert_eq!(
        rig.request(
            json!({"op":"message_cancel","task_id":task}),
            "message_cancelled"
        )["op"],
        "error"
    );
    assert_eq!(rig.status(&second)["tasks"][0]["state"], "cancelled");
    assert!(
        !std::fs::read_to_string(b.join("input"))
            .unwrap()
            .contains("cancel this task")
    );
}

#[test]
fn a_send_from_a_task_inherits_its_workflow_and_limit() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let _ = rig.launch("c", "third");
    let first = rig.send(&a, 1, "tag:b", "continue this workflow");
    within("first prompt turn", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("continue this workflow")
    });
    let next = rig.send(&b, 1, "tag:c", "child request");
    assert_eq!(
        rig.status(&first)["workflow_id"],
        rig.status(&next)["workflow_id"]
    );
    for n in 2..=7 {
        rig.send(&b, n, "tag:c", "bounded child request");
    }
    let output = rig.agent(&b, 8, &["message", "send", "--to", "tag:c", "must stop"]);
    assert_ne!(output["code"], 0, "{output}");
    assert!(
        output["stderr"]
            .as_str()
            .unwrap()
            .contains("limit: 8 messages per workflow"),
        "{output}"
    );
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn a_vault_reference_arrives_as_its_exact_text_after_publication_retries() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let output = rig.agent(
        &a,
        1,
        &[
            "message",
            "send",
            "--to",
            "tag:b",
            "--vault",
            "v-contract:1@2",
            "check this exact snapshot",
        ],
    );
    assert_eq!(output["code"], 0, "{output}");
    let id = output["stdout"].as_str().unwrap().trim();
    within("publication retry", || {
        rig.status(id)["detail"]
            .as_str()
            .unwrap_or("")
            .contains("relay unreachable")
    });
    assert_eq!(rig.status(id)["delivery"], "publishing");
    assert!(rig.status(id)["tasks"].as_array().unwrap().is_empty());
    assert!(std::fs::read(b.join("input")).unwrap().is_empty());
    rig.restart();
    let text = "Published contract  with exact spaces\nand a second line.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let reference = format!("{:x}", Sha256::digest(b"v-contract:1@2"));
    private(
        &rig.sandbox
            .dir
            .path()
            .join("context")
            .join(format!("{reference}.json")),
        &json!({"kind":"vault","id":"v-contract:1","version":2,"digest":digest,"text":text})
            .to_string(),
    );
    within("verified context prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains(text)
    });
    let input = std::fs::read_to_string(b.join("input")).unwrap();
    assert!(input.contains(&digest));
    assert_eq!(input.matches(text).count(), 1);
    assert_eq!(rig.status(id)["delivery"], "accepted");
}

#[test]
fn an_unreachable_relay_keeps_the_send_publishing() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let output = rig.agent(
        &a,
        1,
        &[
            "message",
            "send",
            "--to",
            "tag:b",
            "--vault",
            "v-contract:1@2",
            "wait for publication",
        ],
    );
    assert_eq!(output["code"], 0, "{output}");
    let id = output["stdout"].as_str().unwrap().trim();
    within("unreachable relay", || {
        rig.status(id)["detail"]
            .as_str()
            .unwrap_or("")
            .contains("relay unreachable")
    });
    let status = rig.status(id);
    assert_eq!(status["delivery"], "publishing");
    assert!(status["tasks"].as_array().unwrap().is_empty());
    assert!(std::fs::read(b.join("input")).unwrap().is_empty());
}

fn await_task(rig: &Rig, message: &str, fake: &Path) -> String {
    within("task input", || {
        std::fs::read_to_string(fake.join("input"))
            .unwrap_or_default()
            .contains("[Atem task")
    });
    private(&fake.join("complete"), "");
    within("task awaiting result", || {
        rig.status(message)["tasks"][0]["state"] == "awaiting_result"
    });
    rig.status(message)["tasks"][0]["task_id"]
        .as_str()
        .unwrap()
        .into()
}

/// A submitted task's detail once the runtime saw its prompt accepted and
/// stored the turn it became.
const IN_TURN: &str = "in the agent's turn";

/// The task of message `id` sent to `session`.
fn task_of(rig: &Rig, id: &str, session: &str) -> Value {
    rig.status(id)["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["session_id"] == session)
        .cloned()
        .unwrap_or(Value::Null)
}

/// Waits until the task of message `id` sent to `session` (prompt `text`)
/// is in that agent's turn, its turn stored; its task id. The turn stays
/// open (nothing completes it).
fn await_turn(rig: &Rig, id: &str, session: &str, fake: &Path, text: &str) -> String {
    within("task prompt", || {
        std::fs::read_to_string(fake.join("input"))
            .unwrap_or_default()
            .contains(text)
    });
    within("the task's turn", || {
        task_of(rig, id, session)["detail"] == IN_TURN
    });
    task_of(rig, id, session)["task_id"]
        .as_str()
        .unwrap()
        .into()
}

/// The result id `atem message reply` printed (the last id it names).
fn result_id(output: &Value) -> String {
    let text = format!(
        "{}{}",
        output["stdout"].as_str().unwrap(),
        output["stderr"].as_str().unwrap()
    );
    text.split_whitespace()
        .rev()
        .find_map(|word| uuid::Uuid::parse_str(word.trim_matches(|c| c == ';' || c == ')')).ok())
        .expect("a result id")
        .to_string()
}

/// The sending agent completes its task; the reply alone never does.
#[test]
fn a_reply_comes_back_as_data_and_its_sender_completes_the_task() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "explicit result required");
    let task = await_task(&rig, &id, &b);
    let reply = rig.agent(
        &b,
        1,
        &["message", "reply", "--task", &task, "contract verified"],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    assert!(
        reply["stdout"]
            .as_str()
            .unwrap()
            .contains("reply submitted"),
        "{reply}"
    );
    within("result as data", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("contract verified")
    });
    let input = std::fs::read_to_string(a.join("input")).unwrap();
    assert!(
        input.contains(&format!("[atem] result of task {task} from ")),
        "{input}"
    );
    assert!(input.contains(", as data:\ncontract verified"));
    // The result says how to finish the task: the reply alone doesn't.
    assert!(
        input.contains(&format!("Complete it with: atem message complete {task}")),
        "{input}"
    );
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "awaiting_result", "{status}");
    assert_eq!(status["detail"], "reply submitted", "{status}");
    assert_eq!(status["result"]["result_id"], result_id(&reply).as_str());
    // An identical retry returns the recorded reply; another one is refused.
    let retry = rig.agent(
        &b,
        2,
        &["message", "reply", "--task", &task, "contract verified"],
    );
    assert_eq!(retry["code"], 0, "{retry}");
    assert_eq!(result_id(&retry), result_id(&reply));
    let conflict = rig.agent(
        &b,
        3,
        &["message", "reply", "--task", &task, "different result"],
    );
    assert_ne!(conflict["code"], 0);
    assert!(
        conflict["stderr"]
            .as_str()
            .unwrap()
            .contains("request_id_reused"),
        "{conflict}"
    );
    // The same without `--task`: the session's one task that holds a reply.
    let conflict = rig.agent(&b, 5, &["message", "reply", "different result"]);
    assert_ne!(conflict["code"], 0);
    assert!(
        conflict["stderr"]
            .as_str()
            .unwrap()
            .contains("request_id_reused"),
        "{conflict}"
    );
    assert_eq!(
        std::fs::read_to_string(a.join("input"))
            .unwrap()
            .matches("contract verified")
            .count(),
        1
    );
    // Only its sender completes it: not the agent that did the work.
    let not_mine = rig.agent(&b, 4, &["message", "complete", &task]);
    assert_ne!(not_mine["code"], 0, "{not_mine}");
    assert!(
        not_mine["stderr"]
            .as_str()
            .unwrap()
            .contains("only the task's sending session completes it"),
        "{not_mine}"
    );
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "awaiting_result");
    let done = rig.agent(&a, 2, &["message", "complete", &task]);
    assert_eq!(done["code"], 0, "{done}");
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "completed", "{status}");
    assert_eq!(status["result"]["text"], "contract verified", "{status}");
    // Completing again changes nothing.
    assert_eq!(rig.agent(&a, 3, &["message", "complete", &task])["code"], 0);
}

/// From outside any session (the owner's terminal) any local task can be
/// completed, with no reply too; a task that is not waiting can't.
#[test]
fn the_owner_completes_a_task_from_outside_any_session() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let first = rig.send(&a, 1, "tag:b", "never answered");
    let task = await_task(&rig, &first, &b);
    let second = rig.send(&a, 2, "tag:b", "still queued");
    let queued = rig.status(&second)["tasks"][0]["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, err, ok) = rig.sandbox.atem(&["message", "complete", &queued]);
    assert!(!ok && err.contains("awaiting"), "{err}");
    let (out, err, ok) = rig.sandbox.atem(&["message", "complete", &task]);
    assert!(ok, "{out}{err}");
    let status = &rig.status(&first)["tasks"][0];
    assert_eq!(status["state"], "completed", "{status}");
    assert!(status["result"].is_null(), "{status}");
}

/// `atem message send --expires <expires> --to <to> <text>` from the agent
/// at `fake`; the message id.
fn send_expiring(rig: &Rig, fake: &Path, n: u32, to: &str, expires: &str, text: &str) -> String {
    let output = rig.agent(
        fake,
        n,
        &["message", "send", "--expires", expires, "--to", to, text],
    );
    assert_eq!(output["code"], 0, "{output}");
    output["stdout"].as_str().unwrap().trim().to_string()
}

/// The detail of a task awaiting its result whose sender is gone.
const SENDER_GONE: &str = "sender gone; reply kept, not delivered";

/// The same, its sending session running with a changed route.
const SENDER_ROUTE_CHANGED: &str = "sender's route changed; reply kept, not delivered";

/// The user interrupts the agent's turn `turn` (Esc): Claude writes the
/// marker entry into the transcript (`transcript-<n>.jsonl`).
fn interrupt(fake: &Path, n: u32, turn: &str) {
    let entry = json!({"type":"user","uuid":format!("interrupt-{n}"),"promptId":turn,
        "message":{"role":"user","content":[{"type":"text","text":"[Request interrupted by user]"}]}});
    private(
        &fake.join(format!("transcript-{n}.tmp")),
        &entry.to_string(),
    );
    std::fs::rename(
        fake.join(format!("transcript-{n}.tmp")),
        fake.join(format!("transcript-{n}.jsonl")),
    )
    .unwrap();
}

/// A local task awaiting its result whose sender is gone (its process
/// ended) is not cancelled: it keeps waiting ("sender gone; reply kept, not
/// delivered"), takes its agent's reply, stored and never delivered, and
/// the owner completes it from outside any session. It holds no slot: the
/// next task goes on.
#[test]
fn a_task_whose_sender_is_gone_keeps_waiting_and_takes_a_reply() {
    let rig = Rig::new();
    let (sender, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "the sender leaves");
    let task = await_task(&rig, &id, &b);
    let stopped = rig.request(json!({"op":"stop","session_id":sender}), "stopped");
    assert_eq!(stopped["op"], "stopped", "{stopped}");
    within("the sender gone", || {
        rig.status(&id)["tasks"][0]["detail"] == SENDER_GONE
    });
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "awaiting_result");
    let late = rig.agent(&b, 1, &["message", "reply", "--task", &task, "kept anyway"]);
    assert_eq!(late["code"], 0, "{late}");
    within("the reply kept", || {
        let status = &rig.status(&id)["tasks"][0];
        status["result"]["state"] == "submitted" && status["detail"] == SENDER_GONE
    });
    assert_eq!(rig.status(&id)["tasks"][0]["result"]["text"], "kept anyway");
    let (_, c) = rig.launch("c", "next");
    rig.send(&c, 1, "tag:b", "the next task");
    within("the next task", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("the next task")
    });
    let (out, err, ok) = rig.sandbox.atem(&["message", "complete", &task]);
    assert!(ok, "{out}{err}");
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "completed", "{status}");
    assert_eq!(status["result"]["text"], "kept anyway", "{status}");
}

/// The sender leaves while its task is still queued: only the return grant
/// ends. The task still runs, its agent's reply is stored (readable in
/// status, never delivered), and once its turn ended it awaits its result
/// ("sender gone; reply kept, not delivered") until the owner completes it
/// from outside any session; it holds no slot meanwhile.
#[test]
fn a_task_whose_sender_left_while_it_was_queued_still_runs_and_keeps_its_reply() {
    let rig = Rig::new();
    let (sender, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let (_, c) = rig.launch("c", "other");
    rig.send(&c, 1, "tag:b", "keeps the recipient busy");
    within("the recipient busy", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("keeps the recipient busy")
    });
    let id = rig.send(&a, 1, "tag:b", "queued while its sender leaves");
    within("the task waits", || {
        rig.status(&id)["tasks"][0]["state"] == "blocked"
    });
    let task = rig.status(&id)["tasks"][0]["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    let stopped = rig.request(json!({"op":"stop","session_id":sender}), "stopped");
    assert_eq!(stopped["op"], "stopped", "{stopped}");
    std::thread::sleep(Duration::from_millis(1_000));
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "blocked");
    // The recipient's earlier turn ends: the task runs anyway.
    private(&b.join("complete"), "");
    within("the task's prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("queued while its sender leaves")
    });
    within("the task's turn", || {
        rig.status(&id)["tasks"][0]["detail"] == IN_TURN
    });
    let reply = rig.agent(
        &b,
        1,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "an answer nobody takes",
        ],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    private(&b.join("complete"), "");
    within("the task awaits its result", || {
        rig.status(&id)["tasks"][0]["detail"] == SENDER_GONE
    });
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "awaiting_result", "{status}");
    assert_eq!(status["result"]["state"], "submitted", "{status}");
    assert_eq!(
        status["result"]["text"], "an answer nobody takes",
        "{status}"
    );
    assert!(
        !std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("an answer nobody takes")
    );
    rig.send(&c, 2, "tag:b", "the next task");
    within("the next task", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("the next task")
    });
    let (out, err, ok) = rig.sandbox.atem(&["message", "complete", &task]);
    assert!(ok, "{out}{err}");
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "completed", "{status}");
    assert_eq!(status["result"]["text"], "an answer nobody takes");
}

/// A turn that ends interrupted (the user's Esc) leaves its task awaiting
/// its result ("turn interrupted"): it still takes a reply, delivered as
/// usual, and the session's next task goes on. Nothing is resubmitted.
#[test]
fn an_interrupted_turn_awaits_its_result_and_takes_a_reply() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "interrupt this turn");
    let task = await_turn(&rig, &id, &session, &b, "interrupt this turn");
    interrupt(&b, 1, "turn-1");
    within("the task awaits its result", || {
        rig.status(&id)["tasks"][0]["state"] == "awaiting_result"
    });
    assert_eq!(rig.status(&id)["tasks"][0]["detail"], "turn interrupted");
    let reply = rig.agent(&b, 1, &["message", "reply", "--task", &task, "half done"]);
    assert_eq!(reply["code"], 0, "{reply}");
    within("the reply delivered", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("half done")
    });
    let (_, c) = rig.launch("c", "next");
    rig.send(&c, 1, "tag:b", "the next task");
    within("the next task", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("the next task")
    });
    assert_eq!(
        std::fs::read_to_string(b.join("input"))
            .unwrap()
            .matches("interrupt this turn")
            .count(),
        1,
        "never resubmitted"
    );
}

/// An interrupted turn that also gets no reply within the result timeout
/// says both: "turn interrupted without a reply".
#[test]
fn an_interrupted_silent_turn_says_both() {
    let mut rig = Rig::new();
    rig.config = rig
        .config
        .replace("send = true", "send = true\nresult_timeout = \"1s\"");
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "interrupted and silent");
    await_turn(&rig, &id, &session, &b, "interrupted and silent");
    interrupt(&b, 1, "turn-1");
    within("the report", || {
        rig.status(&id)["tasks"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .starts_with("turn interrupted without a reply")
    });
    // Written once: neither fact replaces the other afterwards.
    std::thread::sleep(Duration::from_millis(1_500));
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "awaiting_result", "{status}");
    assert!(
        status["detail"]
            .as_str()
            .unwrap()
            .starts_with("turn interrupted without a reply"),
        "{status}"
    );
}

/// The sending session's route changes while the task it sent awaits its
/// result: the task stays ("sender's route changed; reply kept, not
/// delivered"), its reply is kept, never delivered, and the sending
/// session, still running, completes it.
#[test]
fn a_task_whose_senders_route_changed_keeps_waiting_for_its_sender() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "the sender's route changes");
    let task = await_task(&rig, &id, &b);
    let route = "[[routes]]\nid = \"a\"\nrevision = 1";
    assert!(rig.config.contains(route));
    rig.write_config(
        &rig.config
            .replace(route, "[[routes]]\nid = \"a\"\nrevision = 2"),
    );
    within("the sender's route changed", || {
        rig.status(&id)["tasks"][0]["detail"] == SENDER_ROUTE_CHANGED
    });
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "awaiting_result");
    let reply = rig.agent(
        &b,
        1,
        &["message", "reply", "--task", &task, "kept for its sender"],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    within("the reply kept", || {
        let status = &rig.status(&id)["tasks"][0];
        status["result"]["state"] == "submitted" && status["detail"] == SENDER_ROUTE_CHANGED
    });
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("kept for its sender")
    );
    let done = rig.agent(&a, 2, &["message", "complete", &task]);
    assert_eq!(done["code"], 0, "{done}");
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "completed", "{status}");
    assert_eq!(status["result"]["text"], "kept for its sender", "{status}");
}

/// The task's route changes (a new revision) while its turn runs: only the
/// return grant ends. The turn finishes, the reply is stored and never
/// delivered, and the task then fails ("route changed").
#[test]
fn a_route_change_mid_turn_ends_only_the_return_grant() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "the route changes under it");
    let task = await_turn(&rig, &id, &session, &b, "the route changes under it");
    let route = "[[routes]]\nid = \"b\"\nrevision = 1";
    assert!(rig.config.contains(route));
    rig.write_config(
        &rig.config
            .replace(route, "[[routes]]\nid = \"b\"\nrevision = 2"),
    );
    // The runtime re-reads runtime.toml about once a second.
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(rig.status(&id)["tasks"][0]["detail"], IN_TURN);
    let reply = rig.agent(
        &b,
        1,
        &["message", "reply", "--task", &task, "an answer for nobody"],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    private(&b.join("complete"), "");
    within("the task failed", || {
        rig.status(&id)["tasks"][0]["state"] == "failed"
    });
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["detail"], "route changed", "{status}");
    assert_eq!(status["result"]["state"], "submitted", "{status}");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("an answer for nobody")
    );
}

/// A task awaiting its result expires at its deadline like any other: one
/// nobody answered, and one whose reply already reached its sender (its
/// return grant used). An expired task takes no reply.
#[test]
fn tasks_awaiting_their_result_expire_at_their_deadline() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let silent = send_expiring(&rig, &a, 1, "tag:b", "4s", "nobody answers");
    let task = await_task(&rig, &silent, &b);
    let answered = send_expiring(&rig, &a, 2, "tag:b", "6s", "answer this one");
    within("the second prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("answer this one")
    });
    private(&b.join("complete"), "");
    within("the second task awaits its result", || {
        rig.status(&answered)["tasks"][0]["state"] == "awaiting_result"
    });
    let second = rig.status(&answered)["tasks"][0]["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    let reply = rig.agent(
        &b,
        1,
        &["message", "reply", "--task", &second, "the answer in time"],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    within("the reply delivered", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("the answer in time")
    });
    for id in [&silent, &answered] {
        within("the task expired", || {
            rig.status(id)["tasks"][0]["state"] == "expired"
        });
        let status = &rig.status(id)["tasks"][0];
        assert_eq!(status["detail"], "expired awaiting a result", "{status}");
    }
    assert_eq!(
        rig.status(&answered)["tasks"][0]["result"]["state"],
        "submitted"
    );
    let late = rig.agent(&b, 2, &["message", "reply", "--task", &task, "too late"]);
    assert_ne!(late["code"], 0, "{late}");
    assert!(
        late["stderr"].as_str().unwrap().contains("expired"),
        "{late}"
    );
}

/// A restart in the task's turn leaves its outcome unknown, and with no
/// reply it holds its session's queue only until its deadline: then it
/// expires (nothing is resubmitted) and the session takes the next task.
#[test]
fn a_task_whose_outcome_is_unknown_expires_and_frees_its_session() {
    let mut rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let id = send_expiring(&rig, &a, 1, "tag:b", "12s", "lost in a restart");
    await_turn(&rig, &id, &session, &b, "lost in a restart");
    rig.restart();
    within("outcome unknown after the restart", || {
        rig.status(&id)["tasks"][0]["state"] == "outcome_unknown"
    });
    // The interrupted turn ends; the session is ready, yet the next task
    // waits behind the one whose outcome is unknown.
    private(&b.join("complete"), "");
    let next = rig.send(&a, 2, "tag:b", "the next task");
    within("the next task waits", || {
        rig.status(&next)["tasks"][0]["detail"] == "waiting for an earlier task on this session"
    });
    // Its deadline is up to 12 s after the send.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while rig.status(&id)["tasks"][0]["state"] != "expired" {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the task to expire"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(
        status["detail"], "expired with its outcome unknown",
        "{status}"
    );
    within("the next task", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("the next task")
    });
    assert_eq!(
        std::fs::read_to_string(b.join("input"))
            .unwrap()
            .matches("lost in a restart")
            .count(),
        1,
        "never resubmitted"
    );
}

/// `atem message status` as the agent at `fake` prints it.
fn status_text(rig: &Rig, fake: &Path, n: u32, args: &[&str]) -> String {
    let argv: Vec<&str> = ["message", "status"]
        .into_iter()
        .chain(args.iter().copied())
        .collect();
    let output = rig.agent(fake, n, &argv);
    assert_eq!(output["code"], 0, "{output}");
    output["stdout"].as_str().unwrap().to_string()
}

/// Inside a session, `atem message status` shows the messages it sent and
/// the tasks sent to it, and `atem message cancel` works on its own messages
/// only; from outside any session both cover everything.
#[test]
fn inside_a_session_status_and_cancel_cover_its_own_messages() {
    let rig = Rig::new();
    let (sa, a) = rig.launch("a", "a");
    let (sb, b) = rig.launch("b", "b");
    let (_, c) = rig.launch("c", "c");
    let busy = rig.send(&a, 1, "tag:b", "keeps b busy");
    within("b busy", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("keeps b busy")
    });
    let mine = rig.send(&a, 2, "tag:b", "a's queued task");
    let both = rig.agent(
        &c,
        1,
        &[
            "message",
            "send",
            "--to",
            "tag:a",
            "--to",
            "tag:b",
            "c's message to both",
        ],
    );
    assert_eq!(both["code"], 0, "{both}");
    let both = both["stdout"].as_str().unwrap().trim().to_string();
    let task_id = |id: &str, session: &str| -> String {
        task_of(&rig, id, session)["task_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (busy_task, mine_task) = (task_id(&busy, &sb), task_id(&mine, &sb));
    let (to_a, to_b) = (task_id(&both, &sa), task_id(&both, &sb));

    let in_a = status_text(&rig, &a, 3, &[]);
    for shown in [&busy, &mine, &both, &busy_task, &mine_task, &to_a] {
        assert!(in_a.contains(shown.as_str()), "{shown}: {in_a}");
    }
    assert!(!in_a.contains(&to_b), "{in_a}");
    let in_b = status_text(&rig, &b, 1, &[]);
    for shown in [&busy, &mine, &both, &busy_task, &mine_task, &to_b] {
        assert!(in_b.contains(shown.as_str()), "{shown}: {in_b}");
    }
    assert!(!in_b.contains(&to_a), "{in_b}");
    let in_c = status_text(&rig, &c, 2, &[]);
    for shown in [&both, &to_a, &to_b] {
        assert!(in_c.contains(shown.as_str()), "{shown}: {in_c}");
    }
    for hidden in [&busy, &mine] {
        assert!(!in_c.contains(hidden.as_str()), "{hidden}: {in_c}");
    }
    // Another session's message by its id: nothing.
    assert!(!status_text(&rig, &c, 3, &[&busy]).contains(&busy));
    // From outside any session: every message and every task.
    let all = rig.request(json!({"op":"message_status"}), "message_status");
    let all = all["messages"].to_string();
    for shown in [&busy, &mine, &both, &to_a, &to_b] {
        assert!(all.contains(shown.as_str()), "{shown}: {all}");
    }

    // Cancel: only the session that sent the message, or the owner.
    let refused = rig.agent(&a, 4, &["message", "cancel", &to_b]);
    assert_ne!(refused["code"], 0, "{refused}");
    assert!(
        refused["stderr"]
            .as_str()
            .unwrap()
            .contains("not one of this session's messages"),
        "{refused}"
    );
    assert_eq!(task_of(&rig, &both, &sb)["state"], "blocked");
    let theirs = rig.agent(&c, 4, &["message", "cancel", &to_b]);
    assert_eq!(theirs["code"], 0, "{theirs}");
    assert_eq!(task_of(&rig, &both, &sb)["state"], "cancelled");
    let owner = rig.request(
        json!({"op":"message_cancel","task_id":mine_task}),
        "message_cancelled",
    );
    assert_eq!(owner["op"], "message_cancelled", "{owner}");
    assert_eq!(task_of(&rig, &mine, &sb)["state"], "cancelled");
}

/// The sender completes its task only once the reply is submitted, and
/// completing it stops a delivery already queued: the result is never
/// prompted into the sender afterwards.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn completing_waits_for_publication_and_stops_a_queued_delivery() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let (_, c) = rig.launch("c", "other");
    let id = rig.send(&a, 1, "tag:b", "answer with context");
    let task = await_task(&rig, &id, &b);
    let text = "Context still publishing.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-held:1@1"));
    let context = rig.sandbox.dir.path().join("context");
    private(&context.join(format!("{name}.hold")), "");
    private(
        &context.join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-held:1","version":1,"digest":digest,"text":text})
            .to_string(),
    );
    let reply = rig.agent(
        &b,
        1,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "--vault",
            "v-held:1@1",
            "the held answer",
        ],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    let early = rig.agent(&a, 2, &["message", "complete", &task]);
    assert_ne!(early["code"], 0, "{early}");
    assert!(
        early["stderr"]
            .as_str()
            .unwrap()
            .contains("still publishing"),
        "{early}"
    );
    // The sender is busy with a task of its own, so the delivery queues.
    rig.send(&c, 1, "tag:a", "keeps the sender busy");
    within("the sender busy", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("keeps the sender busy")
    });
    std::fs::remove_file(context.join(format!("{name}.hold"))).unwrap();
    within("the reply submitted", || {
        rig.status(&id)["tasks"][0]["result"]["state"] == "submitted"
    });
    std::thread::sleep(Duration::from_millis(500));
    let done = rig.agent(&a, 3, &["message", "complete", &task]);
    assert_eq!(done["code"], 0, "{done}");
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "completed", "{status}");
    assert_eq!(status["result"]["text"], "the held answer", "{status}");
    private(&a.join("complete"), "");
    std::thread::sleep(Duration::from_millis(1_000));
    assert!(
        !std::fs::read_to_string(a.join("input"))
            .unwrap()
            .contains("the held answer")
    );
}

/// After a restart in the task's turn its outcome is unknown; the owner may
/// still complete it, which ends its return grant: the agent's late reply is
/// refused and nothing reaches the sender.
#[test]
fn a_task_whose_outcome_is_unknown_can_be_completed_and_takes_no_reply_after() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "lost in a restart");
    let task = await_turn(&rig, &id, &session, &b, "lost in a restart");
    rig.restart();
    within("outcome unknown after the restart", || {
        rig.status(&id)["tasks"][0]["state"] == "outcome_unknown"
    });
    let (out, err, ok) = rig.sandbox.atem(&["message", "complete", &task]);
    assert!(ok, "{out}{err}");
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "completed", "{status}");
    assert_eq!(
        status["detail"], "completed by its sender without a reply",
        "{status}"
    );
    let late = rig.agent(
        &b,
        1,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "an answer after completion",
        ],
    );
    assert_ne!(late["code"], 0, "{late}");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("an answer after completion")
    );
}

#[test]
fn without_results_true_a_result_is_status_only() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "status only result");
    let task = await_task(&rig, &id, &b);
    let reply = rig.agent(&b, 1, &["message", "reply", "--task", &task, "stored only"]);
    assert_eq!(reply["code"], 0, "{reply}");
    let status = rig.status(&id);
    assert_eq!(status["tasks"][0]["state"], "awaiting_result");
    assert_eq!(status["tasks"][0]["result"]["state"], "submitted");
    assert_eq!(status["tasks"][0]["result"]["text"], "stored only");
    std::thread::sleep(Duration::from_millis(500));
    assert!(std::fs::read(a.join("input")).unwrap().is_empty());
}

/// One request reaches five agents; each answers in its own turn without
/// `--task`. All five replies are recorded and each reaches the sender once,
/// as data.
#[test]
fn five_agents_reply_in_their_turns_and_every_reply_is_delivered() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let agents: Vec<_> = (0..5)
        .map(|n| rig.launch("b", &format!("agent-{n}")))
        .collect();
    let id = rig.send(&a, 1, "tag:b", "review your part");
    let mut ids = std::collections::BTreeSet::new();
    for (n, (session, fake)) in agents.iter().enumerate() {
        await_turn(&rig, &id, session, fake, "review your part");
        let reply = rig.agent(
            fake,
            1,
            &["message", "reply", &format!("part {n} reviewed")],
        );
        assert_eq!(reply["code"], 0, "{reply}");
        assert!(ids.insert(result_id(&reply)));
    }
    within("five deliveries", || {
        if !a.join("complete").exists() {
            private(&a.join("complete"), "");
        }
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .matches("[atem] result of task")
            .count()
            == 5
    });
    let input = std::fs::read_to_string(a.join("input")).unwrap();
    for n in 0..5 {
        assert_eq!(
            input
                .matches(&format!("as data:\npart {n} reviewed"))
                .count(),
            1,
            "{input}"
        );
    }
    for (_, fake) in &agents {
        private(&fake.join("complete"), "");
    }
    within("five tasks with their replies", || {
        rig.status(&id)["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| {
                t["state"] == "awaiting_result"
                    && t["detail"] == "reply submitted"
                    && t["result"]["state"] == "submitted"
            })
    });
}

/// A reply with context stays bound to its task's turn: its publication may
/// finish after the agent's next turn began.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn a_reply_whose_context_publishes_after_the_next_turn_began_is_kept() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let first = rig.send(&a, 1, "tag:b", "first task");
    let task = await_turn(&rig, &first, &session, &b, "first task");
    let text = "Context published late.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-late:1@1"));
    let context = rig.sandbox.dir.path().join("context");
    // Held: the publication waits until the hold is removed.
    private(&context.join(format!("{name}.hold")), "");
    private(
        &context.join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-late:1","version":1,"digest":digest,"text":text})
            .to_string(),
    );
    let reply = rig.agent(
        &b,
        1,
        &["message", "reply", "--vault", "v-late:1@1", "first answer"],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    assert!(
        reply["stdout"]
            .as_str()
            .unwrap()
            .contains("reply publishing"),
        "{reply}"
    );
    // The turn ends and the next task's turn begins.
    private(&b.join("complete"), "");
    let second = rig.send(&a, 2, "tag:b", "second task");
    await_turn(&rig, &second, &session, &b, "second task");
    std::fs::remove_file(context.join(format!("{name}.hold"))).unwrap();
    within("the reply published", || {
        rig.status(&first)["tasks"][0]["result"]["state"] == "submitted"
    });
    let status = &rig.status(&first)["tasks"][0];
    assert_eq!(status["task_id"], task.as_str());
    assert_eq!(status["detail"], "reply submitted", "{status}");
    assert_eq!(status["result"]["context"][0]["digest"], digest, "{status}");
    within("the reply delivered with its context", || {
        if !a.join("complete").exists() {
            private(&a.join("complete"), "");
        }
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains(text)
    });
}

/// A reply is the replier's once it is stored: its context still publishes,
/// and it still reaches the sender, after the replier's session ended.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn a_reply_publishes_after_its_session_ended() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "answer, then leave");
    let task = await_task(&rig, &id, &b);
    let text = "Context of a session that ended.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-gone:1@1"));
    let context = rig.sandbox.dir.path().join("context");
    private(&context.join(format!("{name}.hold")), "");
    private(
        &context.join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-gone:1","version":1,"digest":digest,"text":text})
            .to_string(),
    );
    let reply = rig.agent(
        &b,
        1,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "--vault",
            "v-gone:1@1",
            "my last answer",
        ],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    let stopped = rig.request(json!({"op":"stop","session_id":session}), "stopped");
    assert_eq!(stopped["op"], "stopped", "{stopped}");
    within("the replier's session ended", || {
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == session.as_str() && s["state"] != "running")
    });
    std::fs::remove_file(context.join(format!("{name}.hold"))).unwrap();
    within("the reply published", || {
        rig.status(&id)["tasks"][0]["result"]["state"] == "submitted"
    });
    within("the reply delivered", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("my last answer")
    });
}

/// The runtime restarts while the task's turn runs: the task's outcome is
/// unknown, yet its stored turn binds the agent's reply, and the return
/// grant still delivers it.
#[test]
fn a_reply_after_a_restart_in_the_tasks_turn_is_recorded_and_delivered() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (session, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "survive a restart");
    await_turn(&rig, &id, &session, &b, "survive a restart");
    rig.restart();
    within("outcome unknown after the restart", || {
        rig.status(&id)["tasks"][0]["state"] == "outcome_unknown"
    });
    let reply = rig.agent(&b, 1, &["message", "reply", "answered across the restart"]);
    assert_eq!(reply["code"], 0, "{reply}");
    within("the reply delivered", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("answered across the restart")
    });
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "awaiting_result", "{status}");
    assert_eq!(status["detail"], "reply submitted", "{status}");
}

/// A pause (here `runtime.toml` that stops loading) refuses new sends only:
/// a reply is stored at once, and reaches the sender when the pause is over.
#[test]
fn a_reply_during_a_pause_is_kept_and_delivered_after_it() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "answer while paused");
    let task = await_task(&rig, &id, &b);
    rig.write_config("version = 1\nenabled = true\n[collab\n");
    // A probe that reaches nobody: refused once the runtime saw the pause.
    let mut n = 10;
    within("the pause", || {
        n += 1;
        rig.agent(&a, n, &["message", "send", "--to", "tag:nobody", "probe"])["code"] != 0
    });
    let reply = rig.agent(
        &b,
        1,
        &["message", "reply", "--task", &task, "kept during the pause"],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    assert_eq!(rig.status(&id)["tasks"][0]["result"]["state"], "submitted");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("kept during the pause")
    );
    rig.write_config(&rig.config);
    within("delivered after the pause", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("kept during the pause")
    });
}

#[test]
fn reply_needs_task_when_two_are_waiting() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let first = rig.send(&a, 1, "tag:b", "first reply");
    let _ = await_task(&rig, &first, &b);
    let second = rig.send(&a, 2, "tag:b", "second reply");
    within("second prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("second reply")
    });
    let task = await_task(&rig, &second, &b);
    let ambiguous = rig.agent(&b, 1, &["message", "reply", "done"]);
    assert_ne!(ambiguous["code"], 0);
    assert!(
        ambiguous["stderr"].as_str().unwrap().contains("use --task"),
        "{ambiguous}"
    );
    assert_eq!(
        rig.agent(&b, 2, &["message", "reply", "--task", &task, "done"])["code"],
        0
    );
}

#[test]
fn a_silent_turn_gets_a_report_not_a_result() {
    let mut rig = Rig::new();
    rig.config = rig
        .config
        .replace("send = true", "send = true\nresult_timeout = \"1s\"");
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "report after a silent turn");
    let _ = await_task(&rig, &id, &b);
    within("silent turn report", || {
        rig.status(&id)["tasks"][0]["detail"] == "turn ended without a reply"
    });
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "awaiting_result");
    assert!(std::fs::read(a.join("input")).unwrap().is_empty());
    assert_eq!(
        rig.agent(&b, 1, &["message", "reply", "late explicit result"])["code"],
        0
    );
    within("the reply delivered", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("late explicit result")
    });
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "awaiting_result", "{status}");
    assert_eq!(status["detail"], "reply submitted", "{status}");
}

#[test]
fn a_final_message_report_stays_status_only_until_an_explicit_reply() {
    let mut rig = Rig::new();
    rig.config = rig
        .config
        .replace("send = true", "send = true\nresult_timeout = \"1s\"")
        .replace(
            "labels = [\"tag:a\"]",
            "labels = [\"tag:a\"]\nresults = true",
        )
        .replace(
            "labels = [\"tag:b\"]",
            "labels = [\"tag:b\"]\nauto_report = \"final_message\"",
        );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "report the assistant text as progress");
    let task = await_task(&rig, &id, &b);
    within("final assistant report", || {
        rig.status(&id)["tasks"][0]["detail"] == "turn ended without a reply: done"
    });
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "awaiting_result");
    assert!(std::fs::read(a.join("input")).unwrap().is_empty());
    assert_eq!(
        rig.agent(
            &b,
            1,
            &["message", "reply", "--task", &task, "explicit reply"]
        )["code"],
        0
    );
    let status = &rig.status(&id)["tasks"][0];
    assert_eq!(status["state"], "awaiting_result", "{status}");
    assert_eq!(status["detail"], "reply submitted", "{status}");
    assert_eq!(status["result"]["text"], "explicit reply", "{status}");
}

/// Spec section 10: the final message a silent-turn report quotes goes
/// through the redactor chat-v1 applies to agent output.
#[test]
fn a_final_message_report_quotes_no_credential_value() {
    const TOKEN: &str = "ghp_Zq8XfE2rT6yU1iO9pA3sD5fG7hJ4kL0mNbVc";
    let mut rig = Rig::new();
    rig.config = rig
        .config
        .replace("send = true", "send = true\nresult_timeout = \"1s\"")
        .replace(
            "labels = [\"tag:b\"]",
            "labels = [\"tag:b\"]\nauto_report = \"final_message\"",
        );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let id = rig.send(&a, 1, "tag:b", "deploy, then say nothing");
    within("task input", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("deploy, then say nothing")
    });
    // The turn's final message (one message: this part, then "done").
    let entry = json!({"type":"assistant","uuid":"a-token","promptId":"turn-1",
        "message":{"id":"msg-turn-1","role":"assistant",
            "content":[{"type":"text","text":format!("deployed with {TOKEN}")}]}});
    private(&b.join("transcript-1.tmp"), &entry.to_string());
    std::fs::rename(b.join("transcript-1.tmp"), b.join("transcript-1.jsonl")).unwrap();
    within("the scripted entry", || {
        std::fs::read_to_string(b.join("events"))
            .unwrap_or_default()
            .contains("transcribed 1")
    });
    private(&b.join("complete"), "");
    within("final assistant report", || {
        rig.status(&id)["tasks"][0]["detail"]
            .as_str()
            .is_some_and(|d| d.starts_with("turn ended without a reply: "))
    });
    let detail = rig.status(&id)["tasks"][0]["detail"].clone();
    let detail = detail.as_str().unwrap();
    assert!(detail.contains("deployed with [redacted]"), "{detail}");
    assert!(!detail.contains(TOKEN), "{detail}");
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_CONTEXT_DIR hook"
)]
fn result_context_is_frozen_and_another_session_cannot_reply() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::new();
    rig.context_hook = true;
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    let (_, c) = rig.launch("c", "intruder");
    let id = rig.send(&a, 1, "tag:b", "return typed context");
    let task = await_task(&rig, &id, &b);
    let intruder = rig.agent(
        &c,
        1,
        &["message", "reply", "--task", &task, "stolen result"],
    );
    assert_ne!(intruder["code"], 0);
    assert!(
        intruder["stderr"].as_str().unwrap().contains("mismatch"),
        "{intruder}"
    );
    let text = "A committed result snapshot.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-result:1@2"));
    private(
        &rig.sandbox
            .dir
            .path()
            .join("context")
            .join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-result:1","version":2,"digest":digest,"text":text})
            .to_string(),
    );
    let args = [
        "message",
        "reply",
        "--task",
        &task,
        "--vault",
        "v-result:1@2",
        "done with context",
    ];
    assert_eq!(rig.agent(&b, 1, &args)["code"], 0);
    within("result context delivered", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains(text)
    });
    let status = rig.status(&id);
    assert_eq!(status["tasks"][0]["result"]["context"][0]["digest"], digest);
    assert_eq!(rig.agent(&b, 2, &args)["code"], 0);
    let different = rig.agent(
        &b,
        3,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "--vault",
            "v-result:1@3",
            "done with context",
        ],
    );
    assert_ne!(different["code"], 0);
    assert!(
        different["stderr"]
            .as_str()
            .unwrap()
            .contains("request_id_reused"),
        "{different}"
    );
    assert_eq!(
        std::fs::read_to_string(a.join("input"))
            .unwrap()
            .matches(text)
            .count(),
        1
    );
}

fn configure_launch(rig: &mut Rig) -> PathBuf {
    let fake = rig.sandbox.dir.path().join("launched-agent");
    std::fs::create_dir_all(&fake).unwrap();
    let env = rig.sandbox.dir.path().join("approved-environment.json");
    private(&env, &json!({"CLAUDE_CLI_BIN":PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approvals/fake-agent.py"),"FAKE_DIR":fake}).to_string());
    rig.config = rig.config.replace(
        "labels = [\"tag:c\"]",
        "labels = [\"tag:c\"]\nlaunch = \"on_message\"",
    );
    rig.config = rig.config.replace(
        "label = \"c\"",
        &format!(
            "label = \"c\"\nenv_names = [\"CLAUDE_CLI_BIN\", \"FAKE_DIR\"]\nenv_file = {env:?}"
        ),
    );
    rig.restart();
    fake
}

#[test]
fn a_message_to_an_empty_route_launches_one_agent() {
    let mut rig = Rig::new();
    let fake = configure_launch(&mut rig);
    let (_, a) = rig.launch("a", "sender");
    let id = rig.send_launch(&a, 1, "c", "start the approved route");
    within("launched agent prompt", || {
        std::fs::read_to_string(fake.join("input"))
            .unwrap_or_default()
            .contains("start the approved route")
    });
    assert_eq!(
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let task = rig.status(&id)["tasks"][0]["task_id"].clone();
    rig.restart();
    assert_eq!(rig.status(&id)["tasks"][0]["task_id"], task);
    assert_eq!(
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        std::fs::read_to_string(fake.join("events"))
            .unwrap()
            .lines()
            .filter(|s| *s == "started")
            .count(),
        1
    );
}

#[test]
fn explicit_launch_uses_the_instance_address_and_keeps_route_consent() {
    let mut rig = Rig::new();
    let fake = configure_launch(&mut rig);
    let (_, a) = rig.launch("a", "sender");
    let directory = rig.request(
        json!({"op":"message_directory","selector":"tag:c"}),
        "message_directory",
    );
    let atem_id = directory["rows"][0]["atem_id"].as_str().unwrap();
    let unapproved = format!("atem:{atem_id}/b");
    let output = rig.agent(
        &a,
        1,
        &[
            "message",
            "send",
            "--to",
            &unapproved,
            "--launch",
            "explicit flag cannot authorize this route",
        ],
    );
    assert_eq!(output["code"], 0, "{output}");
    let id = output["stdout"].as_str().unwrap().trim();
    assert_eq!(rig.status(id)["detail"], "no_match");
    assert_eq!(
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let approved = format!("atem:{atem_id}/c");
    let output = rig.agent(
        &a,
        2,
        &[
            "message",
            "send",
            "--to",
            &approved,
            "--launch",
            "explicit approved launch",
        ],
    );
    assert_eq!(output["code"], 0, "{output}");
    within("explicit launched prompt", || {
        std::fs::read_to_string(fake.join("input"))
            .unwrap_or_default()
            .contains("explicit approved launch")
    });
    assert_eq!(
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// Spec section 5: a route that allows launching starts nothing for a send
/// that doesn't ask, however it is addressed; the route has no match.
#[test]
fn a_route_that_allows_launch_still_needs_the_flag() {
    let mut rig = Rig::new();
    let fake = configure_launch(&mut rig);
    let (_, a) = rig.launch("a", "sender");
    let address = rig.address("c");
    for (n, selector) in [(1, "tag:c"), (2, address.as_str())] {
        let id = rig.send(&a, n, selector, "no flag, no launch");
        let status = rig.status(&id);
        assert_eq!(status["detail"], "no_match", "{selector}: {status}");
        assert!(status["tasks"].as_array().unwrap().is_empty(), "{status}");
    }
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(rig.sessions(), 1);
    assert!(!fake.join("events").exists(), "nothing was started");
}

/// Two senders ask for the same empty route at the same moment: one
/// session starts and both tasks go to it.
#[test]
fn sends_in_quick_succession_share_one_launch() {
    let mut rig = Rig::new();
    let fake = configure_launch(&mut rig);
    let (_, a) = rig.launch("a", "first-sender");
    let (_, b) = rig.launch("b", "second-sender");
    let address = rig.address("c");
    let send = |agent: &Path, text: &str| {
        rig.agent_begin(
            env!("CARGO_BIN_EXE_atem"),
            agent,
            1,
            &["message", "send", "--to", &address, "--launch", text],
        );
    };
    send(&a, "first shared launch");
    send(&b, "second shared launch");
    let ids: Vec<String> = [&a, &b]
        .iter()
        .map(|agent| {
            let output = rig.agent_end(agent, 1);
            assert_eq!(output["code"], 0, "{output}");
            output["stdout"].as_str().unwrap().trim().to_string()
        })
        .collect();
    // Tasks of one session go in order: the second waits for the first turn.
    let input = || std::fs::read_to_string(fake.join("input")).unwrap_or_default();
    within("the first prompt in the launched agent", || {
        input().contains("shared launch")
    });
    std::fs::write(fake.join("complete"), "").unwrap();
    within("both prompts in the one launched agent", || {
        input().contains("first shared launch") && input().contains("second shared launch")
    });
    assert_eq!(rig.sessions(), 3);
    assert_eq!(
        std::fs::read_to_string(fake.join("events"))
            .unwrap()
            .lines()
            .filter(|s| *s == "started")
            .count(),
        1
    );
    let sessions: Vec<_> = ids
        .iter()
        .map(|id| rig.status(id)["tasks"][0]["session_id"].clone())
        .collect();
    assert_eq!(sessions[0], sessions[1], "{sessions:?}");
}

/// Stage 1 launches no Codex session (Codex is not ready until a first
/// prompt is typed, so a launched one never would be), and a route that
/// asks for it is refused at load; a Codex session that already runs and is
/// ready takes queued local tasks as before.
#[test]
fn a_ready_codex_session_still_receives_local_tasks() {
    let mut rig = Rig::unstarted();
    private(
        &rig.sandbox.config().join("config.toml"),
        "[codex]\nhooks = true\n",
    );
    let cwd = rig.sandbox.home.join("d");
    std::fs::create_dir_all(&cwd).unwrap();
    rig.config.push_str(&format!(
        r#"
[[profiles]]
id = "d"
revision = 1
label = "d"
provider = "codex"
cwd = {cwd:?}
project = "local:d"
principals = ["member:astation"]
[[routes]]
id = "d"
revision = 1
profile_id = "d"
labels = ["tag:d"]
principals = ["local"]
"#
    ));
    rig.start();
    let (_, a) = rig.launch("a", "sender");
    let fake = rig.sandbox.dir.path().join("codex-agent");
    std::fs::create_dir_all(&fake).unwrap();
    let mut env = rig.sandbox.env();
    env.push((
        "CODEX_CLI_BIN".into(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/chat/fake-codex.py")
            .display()
            .to_string(),
    ));
    env.push((
        "CODEX_HOME".into(),
        rig.sandbox
            .dir
            .path()
            .join("codex-home")
            .display()
            .to_string(),
    ));
    env.push(("FAKE_DIR".into(), fake.display().to_string()));
    let reply = rig.request(
        json!({"op":"launch","provider":"codex","cwd":cwd,"env":env,"rows":24,"cols":80}),
        "launched",
    );
    assert_eq!(reply["op"], "launched", "{reply}");
    let codex = reply["session"]["id"].as_str().unwrap().to_string();
    let events = |text: &str| {
        std::fs::read_to_string(fake.join("events"))
            .unwrap_or_default()
            .contains(text)
    };
    within("fake codex started", || events("started"));
    // Codex reports nothing before its first prompt, typed in its terminal.
    let mut terminal = rig
        .sandbox
        .spawn(&["agent", "attach", &codex], &rig.sandbox.home, &[]);
    terminal.shows("READY");
    terminal.send(b"first prompt typed by the owner\r");
    within("the first prompt", || events("prompt turn-1 first prompt"));
    std::fs::write(fake.join("complete"), "").unwrap();
    within("the first turn ends", || events("completed turn-1"));
    within("codex is ready", || {
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == codex.as_str() && s["status"] == "ready")
    });
    terminal.detach();
    let id = rig.send(&a, 1, "tag:d", "queued for the ready codex");
    within("the task reaches codex", || {
        events("queued for the ready codex")
    });
    let task = &rig.status(&id)["tasks"][0];
    assert_eq!(task["session_id"], codex.as_str(), "{task}");
}

#[test]
fn runtime_check_refuses_launch_on_message_for_codex() {
    let mut rig = Rig::unstarted();
    rig.config = rig
        .config
        .replace("provider = \"claude\"", "provider = \"codex\"");
    rig.config = rig.config.replace(
        "labels = [\"tag:c\"]",
        "labels = [\"tag:c\"]\nlaunch = \"on_message\"",
    );
    private(&rig.sandbox.config().join("runtime.toml"), &rig.config);
    let (out, err, ok) = rig.sandbox.atem(&["runtime", "check"]);
    assert!(!ok, "{out}{err}");
    assert!(
        format!("{out}{err}")
            .contains("route `c`: launch on message supports Claude Code profiles only for now"),
        "{out}{err}"
    );
}

#[test]
fn launch_stays_off_by_default() {
    let rig = Rig::new();
    let (_, a) = rig.launch("a", "sender");
    let id = rig.send(&a, 1, "tag:c", "no owner launch consent");
    let status = rig.status(&id);
    assert_eq!(status["detail"], "no_match");
    assert!(status["tasks"].as_array().unwrap().is_empty());
    assert_eq!(
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_failed_launch_fails_its_task() {
    let mut rig = Rig::new();
    let _ = configure_launch(&mut rig);
    std::fs::remove_dir(rig.sandbox.home.join("c")).unwrap();
    let (_, a) = rig.launch("a", "sender");
    let id = rig.send_launch(&a, 1, "c", "missing approved cwd");
    within("failed launch task", || {
        rig.status(&id)["tasks"][0]["state"] == "failed"
    });
    assert!(
        rig.status(&id)["tasks"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("launch")
    );
    assert_eq!(
        rig.request(json!({"op":"list"}), "sessions")["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// A local task queued behind a busy agent, then `runtime.toml` changed by
/// `pause` (its `reason` appears wherever the pause is explained): the task
/// waits as `paused: <reason>`, new sends are refused with the reason, a
/// reply from the busy agent's turn is stored (and delivered only after the
/// pause), nothing is fenced (`local`'s control generation stays), and with
/// the file valid again the task dispatches and its return grant still
/// delivers the result.
fn a_pause_waits_and_never_fences(pause: impl FnOnce(&str) -> String, reason: &str) {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    rig.send(&a, 1, "tag:b", "first task keeps the agent busy");
    within("first prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("first task keeps the agent busy")
    });
    let second = rig.send(&a, 2, "tag:b", "second task waits");
    within("second task waits for the busy agent", || {
        rig.status(&second)["tasks"][0]["state"] == "blocked"
    });
    let generation = rig.local_control_gen();

    rig.write_config(&pause(&rig.config));
    within("the pause is reported", || {
        rig.status(&second)["tasks"][0]["detail"]
            .as_str()
            .is_some_and(|d| d.starts_with("paused: "))
    });
    let task = rig.status(&second)["tasks"][0].clone();
    let detail = task["detail"].as_str().unwrap();
    assert!(detail.contains(reason), "{detail}");
    assert!(!detail.contains('\n') && detail.len() < 400, "{detail}");
    assert!(
        matches!(task["state"].as_str(), Some("queued" | "blocked")),
        "{task}"
    );
    let refused = rig.agent(&a, 3, &["message", "send", "--to", "tag:b", "while paused"]);
    assert_ne!(refused["code"], 0, "{refused}");
    assert!(
        refused["stderr"].as_str().unwrap().contains(reason),
        "{refused}"
    );
    assert_eq!(
        rig.local_control_gen(),
        generation,
        "a pause fences nothing"
    );
    // A pause refuses new sends only: the busy agent's reply from its turn
    // (no `--task`: the one task in its turn) is stored, not yet delivered.
    let early = rig.agent(&b, 2, &["message", "reply", "first answer, paused"]);
    assert_eq!(early["code"], 0, "{early}");
    assert!(
        early["stdout"]
            .as_str()
            .unwrap()
            .contains("reply submitted"),
        "{early}"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("first answer, paused")
    );

    // The file is valid again: the first turn ends and the queued task goes.
    rig.write_config(&rig.config);
    private(&b.join("complete"), "");
    within("the queued task after the pause", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("second task waits")
    });
    assert_eq!(rig.local_control_gen(), generation, "nothing was fenced");
    assert!(
        !std::fs::read_to_string(b.join("input"))
            .unwrap()
            .contains("while paused")
    );
    private(&b.join("complete"), "");
    within("second task awaiting its result", || {
        rig.status(&second)["tasks"][0]["state"] == "awaiting_result"
    });
    let task = rig.status(&second)["tasks"][0]["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    let reply = rig.agent(
        &b,
        1,
        &[
            "message",
            "reply",
            "--task",
            &task,
            "result after the pause",
        ],
    );
    assert_eq!(reply["code"], 0, "{reply}");
    within("both results under their old return grants", || {
        if !a.join("complete").exists() {
            private(&a.join("complete"), "");
        }
        let input = std::fs::read_to_string(a.join("input")).unwrap_or_default();
        input.contains("first answer, paused") && input.contains("result after the pause")
    });
    assert_eq!(rig.status(&second)["tasks"][0]["state"], "awaiting_result");
    assert_eq!(rig.status(&second)["tasks"][0]["detail"], "reply submitted");
    assert_eq!(rig.local_control_gen(), generation);
}

#[test]
fn a_runtime_toml_that_stops_loading_pauses_local_work() {
    a_pause_waits_and_never_fences(
        |_| "version = 1\nenabled = true\n[collab\n".to_string(),
        "runtime.toml is not valid",
    );
}

#[test]
fn switching_hosting_off_pauses_local_work() {
    a_pause_waits_and_never_fences(
        |config| config.replacen("enabled = true", "enabled = false", 1),
        "set `enabled = true` in runtime.toml",
    );
}

/// `[collab] send = false` while hosting runs is the owner's setting, not a
/// pause: new sends are refused, while the local tasks already accepted
/// keep dispatching and replies keep reaching their senders.
#[test]
fn switching_send_off_refuses_new_sends_only() {
    let mut rig = Rig::new();
    rig.config = rig.config.replace(
        "labels = [\"tag:a\"]",
        "labels = [\"tag:a\"]\nresults = true",
    );
    rig.restart();
    let (_, a) = rig.launch("a", "sender");
    let (_, b) = rig.launch("b", "recipient");
    rig.send(&a, 1, "tag:b", "first task keeps the agent busy");
    within("first prompt", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("first task keeps the agent busy")
    });
    let second = rig.send(&a, 2, "tag:b", "second task waits");
    within("second task waits for the busy agent", || {
        rig.status(&second)["tasks"][0]["state"] == "blocked"
    });
    let generation = rig.local_control_gen();
    rig.write_config(&rig.config.replacen("send = true", "send = false", 1));
    // A probe that reaches nobody: refused, with the reason, once the
    // runtime saw the setting.
    let mut n = 10;
    within("sending switched off", || {
        n += 1;
        let probe = rig.agent(&a, n, &["message", "send", "--to", "tag:nobody", "probe"]);
        probe["code"] != 0
            && probe["stderr"]
                .as_str()
                .unwrap()
                .contains("set `[collab] send = true` in runtime.toml")
    });
    // The busy agent's reply from its turn is stored and delivered.
    let early = rig.agent(&b, 2, &["message", "reply", "first answer, sending off"]);
    assert_eq!(early["code"], 0, "{early}");
    within("the reply delivered while sending is off", || {
        std::fs::read_to_string(a.join("input"))
            .unwrap_or_default()
            .contains("first answer, sending off")
    });
    // The queued task goes on once the agent is ready.
    private(&b.join("complete"), "");
    within("the queued task while sending is off", || {
        std::fs::read_to_string(b.join("input"))
            .unwrap_or_default()
            .contains("second task waits")
    });
    let task = rig.status(&second)["tasks"][0].clone();
    assert!(
        !task["detail"].as_str().unwrap().starts_with("paused"),
        "{task}"
    );
    assert_eq!(rig.local_control_gen(), generation, "nothing was fenced");
}

/// Agent commands connect to the runtime they run in; they never start one or
/// replace another build's (which would restart it in the middle of the
/// agent's own task).
#[test]
fn agent_commands_never_replace_the_runtime_of_another_build() {
    let rig = Rig::new();
    let (a, fake) = rig.launch("a", "caller");
    let (_, other_fake) = rig.launch("b", "other");
    let runtime = rig.sandbox.runtime_pid().unwrap();
    // A copy has another mtime: another build as far as the runtime can tell.
    let dir = rig.sandbox.dir.path().join("other-build");
    std::fs::create_dir_all(&dir).unwrap();
    let other = dir.join("atem");
    std::fs::copy(env!("CARGO_BIN_EXE_atem"), &other).unwrap();
    let other = other.to_str().unwrap();
    let commands: [&[&str]; 5] = [
        &["agent", "tag", "add", "self:reviewer"],
        &["message", "directory"],
        &["message", "send", "--to", "tag:b", "from another build"],
        &["message", "status"],
        &["agent", "tag", "list"],
    ];
    for (n, args) in commands.into_iter().enumerate() {
        let output = rig.agent_with(other, &fake, n as u32 + 1, args);
        assert_eq!(output["code"], 0, "{args:?}: {output}");
        let stderr = output["stderr"].as_str().unwrap();
        assert!(!stderr.contains("runtime updated"), "{args:?}: {stderr}");
        assert_eq!(rig.sandbox.runtime_pid(), Some(runtime), "{args:?}");
    }
    within("the message reaches the other agent", || {
        std::fs::read_to_string(other_fake.join("input"))
            .unwrap_or_default()
            .contains("from another build")
    });
    let sessions = rig.request(json!({"op":"list"}), "sessions");
    assert!(
        sessions["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == a && s["self_tags"] == json!(["self:reviewer"]))
    );
    assert_eq!(rig.sandbox.runtime_pid(), Some(runtime));
}

/// With no runtime there is nothing to run in: an error, and none is started.
#[test]
fn agent_commands_start_no_runtime() {
    let rig = Rig::unstarted();
    for args in [
        &["message", "directory"][..],
        &["message", "status"],
        &["message", "send", "--to", "tag:b", "nobody listens"],
        &["agent", "tag", "list"],
    ] {
        let (out, err, ok) = rig.sandbox.atem(args);
        assert!(!ok, "{args:?}: {out}{err}");
        assert!(
            err.contains("no Atem runtime is running; agents run inside one"),
            "{args:?}: {err}"
        );
        assert_eq!(rig.sandbox.runtime_pid(), None, "{args:?}");
        assert!(!rig.sandbox.config().join("runtime.socket").exists());
    }
}

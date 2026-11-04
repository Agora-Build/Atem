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
    fn new() -> Self {
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
        let mut rig = Self {
            sandbox,
            astation: FakeAstation::start(),
            runtime: None,
            config,
            context_hook: false,
        };
        rig.start();
        rig
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
        let argv: Vec<_> = std::iter::once(env!("CARGO_BIN_EXE_atem"))
            .chain(args.iter().copied())
            .collect();
        private(
            &fake.join(format!("run-{number}.tmp")),
            &json!({"argv":argv}).to_string(),
        );
        std::fs::rename(
            fake.join(format!("run-{number}.tmp")),
            fake.join(format!("run-{number}.json")),
        )
        .unwrap();
        let out = fake.join(format!("run-{number}.out"));
        within("agent child command", || out.exists());
        serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap()
    }

    fn send(&self, fake: &Path, n: u32, selector: &str, text: &str) -> String {
        let output = self.agent(fake, n, &["message", "send", "--to", selector, text]);
        assert_eq!(output["code"], 0, "{output}");
        output["stdout"].as_str().unwrap().trim().to_string()
    }

    fn status(&self, id: &str) -> Value {
        let reply = self.request(
            json!({"op":"message_status","message_id":id}),
            "message_status",
        );
        assert_eq!(reply["op"], "message_status", "{reply}");
        reply["messages"][0].clone()
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
            .contains("collaboration is off: set [collab] send = true"),
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

#[test]
fn a_reply_comes_back_as_data_and_completes_the_task() {
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
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "completed");
    assert_eq!(
        rig.agent(
            &b,
            2,
            &["message", "reply", "--task", &task, "contract verified"]
        )["code"],
        0
    );
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
    assert_eq!(
        std::fs::read_to_string(a.join("input"))
            .unwrap()
            .matches("contract verified")
            .count(),
        1
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
    assert_eq!(status["tasks"][0]["state"], "completed");
    assert!(
        status["tasks"][0]["result"]
            .to_string()
            .contains("stored only")
    );
    assert!(std::fs::read(a.join("input")).unwrap().is_empty());
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
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "completed");
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
            &["message", "reply", "--task", &task, "explicit completion"]
        )["code"],
        0
    );
    assert_eq!(rig.status(&id)["tasks"][0]["state"], "completed");
}

#[test]
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
    let id = rig.send(&a, 1, "tag:c", "start the approved route");
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
    let id = rig.send(&a, 1, "tag:c", "missing approved cwd");
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

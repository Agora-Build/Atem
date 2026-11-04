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
        };
        rig.start();
        rig
    }

    fn start(&mut self) {
        private(&self.sandbox.config().join("runtime.toml"), &self.config);
        let output = std::fs::File::create(self.sandbox.dir.path().join("runtime.log")).unwrap();
        self.runtime = Some(
            Command::new(env!("CARGO_BIN_EXE_atem"))
                .arg("runtime")
                .env_clear()
                .envs(self.sandbox.env())
                .env("ASTATION_WS", &self.astation.url)
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

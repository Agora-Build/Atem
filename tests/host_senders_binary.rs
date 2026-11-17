//! Two real Atem hosts talking as host senders (the delegated host-work
//! design Part II; host-work-v1 §11.5), end to end, behind the debug-only
//! hook (`host.delegated,host.senders`): host A and host B, each a real
//! runtime on its own temp profile whose pinned device list gives each an
//! encryption key and a shared project (`pair`, every op), each with a fake
//! agent on its route and Astation's local link to a fake Station of its
//! own; the two fake Stations are one Station (the same origin and
//! account), what one host puts for the other moved between them
//! ([`Courier`]). Both Stations are online ([`Pump`]). The hosts' clocks
//! are the real ones, moved only where a test says (its 35 s retries).
#![cfg(target_os = "linux")]
mod support;

use atem_client::membership::{ProjectOp, host_sender_revoke, project_set};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use support::astation::{Event, FakeAstation, write_verified_pairing};
use support::delegated::{HostRig, WAIT, private};
use support::host_clock::HostClock;
use support::r9::write_pin;
use support::r9log::{MAC, TestLog, secret};
use support::sender::SenderHost;
use support::station::{Courier, FakeStation, Pump};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-host-senders";
const A: &str = "host-a";
const B: &str = "host-b";
/// The project both hosts share, granting every op (a launch included).
const PROJECT: &str = "pair";
/// Astation's local link's relay setting: the one Station's origin.
const NO_RELAY: &str = "http://127.0.0.1:1";
/// A call's deadline on a host's monotonic clock (§11.5 rule 8), and a
/// little more.
const RETRY_MS: u64 = 36_000;

/// The debug-only hook on (`host.delegated,host.senders`), or off (as every
/// release build).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hook {
    On,
    Off,
}

/// One of the two hosts: its profile, its runtime, its fake Astation and
/// fake Station, and its clock.
struct Host {
    id: &'static str,
    sandbox: Sandbox,
    astation: FakeAstation,
    station: Arc<Mutex<FakeStation>>,
    pump: Option<Pump>,
    clock: HostClock,
    runtime: Option<Child>,
    link: u64,
    hook: Hook,
}

impl HostRig for Host {
    fn config_dir(&self) -> PathBuf {
        self.sandbox.config()
    }

    fn fake_dir(&self) -> PathBuf {
        self.sandbox.dir.path().join("fake")
    }
}

/// The agent a launch on message started on a host (its own fake
/// directory, `launched`).
struct Launched<'a>(&'a Host);

impl HostRig for Launched<'_> {
    fn config_dir(&self) -> PathBuf {
        self.0.sandbox.config()
    }

    fn fake_dir(&self) -> PathBuf {
        self.0.sandbox.dir.path().join("launched-fake")
    }
}

impl Host {
    /// Host `id` (its `host_key` from `seed`, its encryption key from
    /// `enc`) on `log`'s account: its pairing verified, the list pinned,
    /// its encryption key made (the one `log` signs), agent hosting on with
    /// a route `backend` for the owner, `project:pair` and `local` that
    /// takes results, a route `launcher` that launches on message for
    /// `project:pair`, and `[collab]`'s `send = true` and `collab`.
    fn new(
        id: &'static str,
        seed: &str,
        enc: &str,
        log: &TestLog,
        hook: Hook,
        collab: &str,
    ) -> Host {
        let sandbox = Sandbox::new();
        let config = sandbox.config();
        write_verified_pairing(&config, ACCOUNT, id, 1);
        write_pin(&config, log, id, 1, &secret(seed));
        write_enc_key(&config, &secret(enc));
        let fake = sandbox.dir.path().join("fake");
        let launched_fake = sandbox.dir.path().join("launched-fake");
        let launched_cwd = sandbox.home.join("launched");
        for dir in [&fake, &launched_fake, &launched_cwd] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let env_file = sandbox.dir.path().join("provider.json");
        private(
            &env_file,
            &json!({"CLAUDE_CLI_BIN": bin, "FAKE_DIR": fake}).to_string(),
        );
        let launched_env = sandbox.dir.path().join("launched.json");
        private(
            &launched_env,
            &json!({"CLAUDE_CLI_BIN": bin, "FAKE_DIR": launched_fake}).to_string(),
        );
        let mac = format!("member:{MAC}");
        // A host sender's principals load only with the hook (without it the
        // file doesn't load): with it off, the route is the owner's and
        // `local`'s, and no route launches for a project.
        let (pair, launcher) = match hook {
            Hook::On => (
                format!(r#", "project:{PROJECT}""#),
                format!(
                    r#"
[[routes]]
id = "launcher"
revision = 1
profile_id = "launched"
principals = ["project:{PROJECT}"]
launch = "on_message"
"#
                ),
            ),
            Hook::Off => (String::new(), String::new()),
        };
        let toml = format!(
            r#"
version = 1
enabled = true
[collab]
send = true
{collab}
[[profiles]]
id = "backend"
revision = 1
label = "Backend"
provider = "claude"
cwd = {cwd:?}
project = "local:home"
principals = [{mac:?}]
env_names = ["CLAUDE_CLI_BIN", "FAKE_DIR"]
env_file = {env:?}
[[profiles]]
id = "launched"
revision = 1
label = "Launched"
provider = "claude"
cwd = {launched_cwd:?}
project = "local:launched"
principals = [{mac:?}]
env_names = ["CLAUDE_CLI_BIN", "FAKE_DIR"]
env_file = {launched_env:?}
[[routes]]
id = "backend"
revision = 1
profile_id = "backend"
principals = [{mac:?}{pair}, "local"]
results = true
{launcher}"#,
            cwd = sandbox.home.to_str().unwrap(),
            env = env_file.to_str().unwrap(),
            launched_cwd = launched_cwd.to_str().unwrap(),
            launched_env = launched_env.to_str().unwrap(),
        );
        private(&config.join("runtime.toml"), &toml);
        std::fs::create_dir_all(sandbox.dir.path().join("faults")).unwrap();
        let astation = FakeAstation::start();
        let mut station = FakeStation::new(&astation, NO_RELAY, log, id, 1);
        station.host_lists_senders(hook == Hook::On);
        let clock = HostClock::start(sandbox.dir.path(), "host-clock");
        let mut host = Host {
            id,
            sandbox,
            astation,
            station: Arc::new(Mutex::new(station)),
            pump: None,
            clock,
            runtime: None,
            link: 0,
            hook,
        };
        host.runtime = Some(host.spawn());
        host.link = host.next_link(0);
        host.pump = Some(Pump::every(host.station.clone(), Duration::from_millis(10)));
        host
    }

    /// `atem runtime` with the hook as the host has it, its output in
    /// `runtime.log`.
    fn spawn(&self) -> Child {
        let output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.sandbox.dir.path().join("runtime.log"))
            .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        // A release build compiles the hook out: it runs with it set, and
        // nothing may change.
        if self.hook == Hook::On || !cfg!(debug_assertions) {
            command.env("ATEM_TEST_HOST_FEATURES", "host.delegated,host.senders");
        }
        let _ = std::fs::remove_file(self.sandbox.config().join("runtime.socket"));
        command
            .arg("runtime")
            .env("ATEM_TEST_PTY_FAULTS", self.faults())
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", &self.astation.url)
            .env("ASTATION_RELAY_URL", NO_RELAY)
            .env(
                "ATEM_TEST_STATE_DUMP",
                self.sandbox.dir.path().join("state.json"),
            )
            .env("ATEM_TEST_HOST_CLOCK", &self.clock.path)
            .env("ATEM_TEST_NO_INIT_LIMIT", "1")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap()
    }

    /// The runtime's next link Astation authenticated after `after`.
    fn next_link(&self, after: u64) -> u64 {
        loop {
            match self.astation.events.recv_timeout(WAIT) {
                Ok(Event::Authenticated(link)) if link > after => break link,
                Ok(_) => {}
                Err(_) => panic!("{}: the runtime's link never authenticated", self.id),
            }
        }
    }

    fn faults(&self) -> PathBuf {
        self.sandbox.dir.path().join("faults")
    }

    fn station(&self) -> MutexGuard<'_, FakeStation> {
        self.station.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    /// Waits up to a minute for `done`; a timeout shows the end of the
    /// host's log.
    #[track_caller]
    fn within(&self, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + WAIT;
        while !done() {
            if std::time::Instant::now() >= deadline {
                let log = self.runtime_log();
                let tail: Vec<_> = log.lines().rev().take(30).collect();
                panic!(
                    "{}: timed out waiting for {what}\nlog (newest first):\n{}",
                    self.id,
                    tail.join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The owner launches the fake agent on the `backend` profile's
    /// directory over the runtime's local socket: its session id, once the
    /// agent runs.
    fn launch_agent(&self) -> String {
        use std::io::{BufRead, BufReader, Write};
        let path = std::fs::read_to_string(self.sandbox.config().join("runtime.socket")).unwrap();
        let socket = std::os::unix::net::UnixStream::connect(path.trim()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut write = socket.try_clone().unwrap();
        let fake = self.fake_dir();
        let mut env = self.sandbox.env();
        env.push((
            "CLAUDE_CLI_BIN".into(),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/approvals/fake-agent.py")
                .display()
                .to_string(),
        ));
        env.push(("FAKE_DIR".into(), fake.display().to_string()));
        writeln!(
            write,
            "{}",
            json!({"v":1,"op":"hello","protocol":1,"build":"test"})
        )
        .unwrap();
        let launch = json!({"v":1,"op":"launch","provider":"claude","cwd":self.sandbox.home,
            "env":env,"rows":24,"cols":80});
        writeln!(write, "{launch}").unwrap();
        let mut session = None;
        for line in BufReader::new(socket).lines() {
            let message: Value = serde_json::from_str(&line.unwrap()).unwrap();
            assert_ne!(message["op"], "error", "{message}");
            if message["op"] == "launched" {
                session = message["session"]["id"].as_str().map(str::to_owned);
                break;
            }
        }
        within("fake agent ready", || fake.join("events").exists());
        session.expect("launched")
    }

    /// `args` run by the fake agent's own child (`run-<number>.json`), as
    /// an agent runs a command: what it printed (`code`, `stdout`,
    /// `stderr`).
    fn agent(&self, number: u32, args: &[&str]) -> Value {
        let fake = self.fake_dir();
        let argv: Vec<_> = std::iter::once(env!("CARGO_BIN_EXE_atem"))
            .chain(args.iter().copied())
            .collect();
        private(
            &fake.join(format!("run-{number}.tmp")),
            &json!({ "argv": argv }).to_string(),
        );
        std::fs::rename(
            fake.join(format!("run-{number}.tmp")),
            fake.join(format!("run-{number}.json")),
        )
        .unwrap();
        let out = fake.join(format!("run-{number}.out"));
        within("the agent's command", || out.exists());
        serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap()
    }

    /// `atem message status MESSAGE` from the owner's terminal, until its
    /// output contains every line of `expected` (one ending in `*`: a line
    /// starting with the rest).
    #[track_caller]
    fn message_status(&self, message: &str, expected: &[String]) -> String {
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            let (out, err, _) = self.sandbox.atem(&["message", "status", message]);
            // A line ending in `*` is a prefix (a status carries the
            // detail its task had when its state last changed).
            let shown = |line: &String| match line.strip_suffix('*') {
                Some(prefix) => out.lines().any(|l| l.starts_with(prefix)),
                None => out.lines().any(|l| l == line),
            };
            if expected.iter().all(shown) {
                return out;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{}: atem message status never showed {expected:#?}; it shows:\n{out}{err}",
                self.id
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The host-work store.
    fn db(&self) -> rusqlite::Connection {
        support::delegated::host_db(self)
    }

    /// The task ids of message `message_id`'s tasks here, in order.
    fn tasks_of(&self, message_id: &str) -> Vec<Value> {
        let Ok(db) = rusqlite::Connection::open(self.config_dir().join("runtime/host-work.sqlite"))
        else {
            return Vec::new();
        };
        let Ok(mut q) = db.prepare(
            "SELECT id FROM work WHERE json_extract(record,'$.message.message_id')=?1
            ORDER BY rowid",
        ) else {
            return Vec::new();
        };
        q.query_map([message_id], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|id| json!(id.unwrap()))
            .collect()
    }

    /// Message `message_id`'s one task here, once admitted.
    #[track_caller]
    fn task_of(&self, message_id: &str) -> Value {
        let mut found = Vec::new();
        self.within("the message's task", || {
            found = self.tasks_of(message_id);
            !found.is_empty()
        });
        assert_eq!(found.len(), 1, "{found:?}");
        found.remove(0)
    }

    /// How many rows `table` holds where `filter`.
    fn count(&self, table: &str, filter: &str) -> i64 {
        self.db()
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE {filter}"),
                [],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// The ids of the objects this host put, in the order it put them
    /// (each try).
    fn put_ids(&self) -> Vec<String> {
        use atem_client::host_mail::mailbox::MailboxToStation;
        self.station()
            .mailbox_calls()
            .into_iter()
            .filter_map(|(_, call)| match call {
                MailboxToStation::Put(put) => Some(put.mail().unwrap().1.id),
                _ => None,
            })
            .collect()
    }

    /// The runtime killed (SIGKILL) or ended: gone.
    fn gone(&mut self) {
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.sandbox.track();
    }

    /// A runtime again, on a new link.
    fn start_again(&mut self) {
        self.runtime = Some(self.spawn());
        self.link = self.next_link(self.link);
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        drop(self.pump.take());
        self.gone();
    }
}

/// Writes `config`'s host encryption key for trust generation 1 from
/// `secret` (X25519) and its record of generated key ids, as the runtime
/// makes them at the pin (`pairing/host_enc_key`, `host_enc_generated`):
/// the key the test's device list signs for the host.
fn write_enc_key(config: &std::path::Path, secret: &[u8; 32]) {
    use atem_client::encoding::b64u;
    let mut keys = atem_client::SoftwareKeys::new();
    let id = atem_client::KeyId::new("enc");
    keys.insert_x25519(id.clone(), secret);
    let public = atem_client::KeyProvider::public_key(&keys, &id).unwrap();
    let kid = atem_client::keys::enc_kid(&public).unwrap();
    let pairing = config.join("pairing");
    private(
        &pairing.join("host_enc_key"),
        &json!({"v": 1, "host_trust_gen": 1, "secret": b64u(secret),
                "pub": b64u(public.as_32().unwrap())})
        .to_string(),
    );
    private(
        &pairing.join("host_enc_generated"),
        &json!({"v": 1, "host_trust_gen": 1, "kids": [kid]}).to_string(),
    );
}

/// The two hosts, their shared device list, and the courier between their
/// Stations.
struct Pair {
    log: TestLog,
    a: Host,
    b: Host,
    _courier: Courier,
}

impl Pair {
    /// A and B with the hook as `hook`, each with its fake agent running;
    /// `b_collab` is B's extra `[collab]` lines.
    fn start(hook: Hook, b_collab: &str) -> Pair {
        let mut log = TestLog::genesis(ACCOUNT, &secret("host senders astation"));
        log.add_host(A, 1, &secret("host senders a"));
        log.add_host(B, 1, &secret("host senders b"));
        for (id, seed, enc) in [
            (A, "host senders a", "host senders a enc"),
            (B, "host senders b", "host senders b enc"),
        ] {
            let host = SenderHost::new(&log, id, 1, &secret(seed)).with_enc(&secret(enc));
            log.append(MAC, host.enc_key_action());
        }
        log.append(
            MAC,
            project_set(
                PROJECT,
                [A, B],
                [
                    ProjectOp::Launch,
                    ProjectOp::Message,
                    ProjectOp::Notify,
                    ProjectOp::Prompt,
                ],
                0,
            )
            .unwrap(),
        );
        let a = Host::new(A, "host senders a", "host senders a enc", &log, hook, "");
        let b = Host::new(
            B,
            "host senders b",
            "host senders b enc",
            &log,
            hook,
            b_collab,
        );
        let courier = Courier::start(a.station.clone(), b.station.clone());
        a.launch_agent();
        b.launch_agent();
        Pair {
            log,
            a,
            b,
            _courier: courier,
        }
    }

    /// A's agent sends `text` to `to` (with `--launch` when `launch`): the
    /// message id.
    #[track_caller]
    fn send(&self, number: u32, to: &str, text: &str, launch: bool) -> String {
        let mut args = vec!["message", "send", "--to", to];
        if launch {
            args.push("--launch");
        }
        args.push(text);
        let out = self.a.agent(number, &args);
        assert_eq!(out["code"], 0, "{out}");
        out["stdout"].as_str().unwrap().trim().to_owned()
    }
}

/// A's agent sends to B's agents; B admits it into a task its agent runs,
/// whose reply goes back; A's agent gets it as data (framed as B's result),
/// and A's `atem message status` shows each step. The result's last line,
/// `atem message complete <task>`, run by A's agent, completes the task on
/// B, and A's status shows the complete accepted.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_HOST_CLOCK hooks"
)]
fn a_message_to_another_host_runs_there_and_its_reply_comes_back() {
    let pair = Pair::start(Hook::On, "");
    let id = pair.send(1, &format!("atem:{B}"), "HS_HELLO", false);
    let task = pair.b.task_of(&id);
    let tid = task.as_str().unwrap().to_owned();
    support::delegated::in_turn(&pair.b, &task, "HS_HELLO");
    pair.a.message_status(
        &id,
        &[
            format!("  host {B}  accepted  accepted by the host"),
            format!("    {tid}  submitted  *"),
        ],
    );
    let out = pair
        .b
        .agent(1, &["message", "reply", "--task", &tid, "HS_REPLY"]);
    assert_eq!(out["code"], 0, "{out}");
    support::delegated::complete_turn(&pair.b, &task);
    // A's agent gets B's reply, as data.
    let line = format!("Result of task {tid} from host:{B}, as data");
    pair.a.within("B's reply in A's agent", || {
        let input = support::delegated::input(&pair.a);
        input.contains(&line) && input.contains("HS_REPLY")
    });
    let result_id = atem_client::session::host_work::result_id(&tid);
    pair.a
        .message_status(&id, &[format!("      reply {result_id}: HS_REPLY")]);
    // The result's last line, run by A's agent in that turn.
    let out = pair.a.agent(2, &["message", "complete", &tid]);
    assert_eq!(out["code"], 0, "{out}");
    assert!(
        out["stdout"]
            .as_str()
            .unwrap()
            .contains(&format!("complete sent to host {B}")),
        "{out}"
    );
    support::delegated::wait_stored(
        &pair.b,
        &task,
        "completed",
        "explicit correlated result published",
    );
    let result = support::delegated::stored(&pair.b, &task)["result"].clone();
    assert_eq!(result["kind"], "result", "the reply named: {result}");
    assert_eq!(result["id"], json!(format!("result:{result_id}")));
    pair.a.message_status(
        &id,
        &[
            format!("    {tid}  completed  explicit correlated result published"),
            "      complete  accepted  the host's status shows the task completed".into(),
        ],
    );
    std::fs::write(pair.a.fake_dir().join("complete"), "").unwrap();
}

/// A cancels a task queued on B (behind another task in B's agent's turn):
/// B's task is cancelled, never runs, and A's status shows the cancel
/// accepted. The task in its turn goes on.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_HOST_CLOCK hooks"
)]
fn a_queued_task_on_another_host_is_cancelled() {
    let pair = Pair::start(Hook::On, "");
    let first = pair.send(1, &format!("atem:{B}"), "HS_FIRST", false);
    let t1 = pair.b.task_of(&first);
    support::delegated::in_turn(&pair.b, &t1, "HS_FIRST");
    let second = pair.send(2, &format!("atem:{B}"), "HS_SECOND", false);
    let t2 = pair.b.task_of(&second);
    let tid = t2.as_str().unwrap().to_owned();
    pair.a.message_status(
        &second,
        &[format!(
            "    {tid}  blocked  waiting for an earlier task on this session"
        )],
    );
    let (out, err, ok) = pair.a.sandbox.atem(&["message", "cancel", &tid]);
    assert!(ok, "{out}{err}");
    assert!(out.contains(&format!("cancel sent to host {B}")), "{out}");
    support::delegated::wait_stored(&pair.b, &t2, "cancelled", "cancelled before submission");
    pair.a.message_status(
        &second,
        &[
            format!("    {tid}  cancelled  cancelled before submission"),
            "      cancel  accepted  the host's status shows the task cancelled".into(),
        ],
    );
    support::delegated::complete_turn(&pair.b, &t1);
    std::thread::sleep(Duration::from_millis(500));
    support::delegated::never_ran(&pair.b, &t2, "HS_SECOND");
}

/// A's `--launch` on `atem:<B>/launcher` starts an agent on B: B reserves
/// the launch with the task, starts the route's agent, and the task runs
/// in it once it is ready.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_HOST_CLOCK hooks"
)]
fn a_launch_on_message_starts_an_agent_on_the_other_host() {
    let pair = Pair::start(Hook::On, "");
    let id = pair.send(1, &format!("atem:{B}/launcher"), "HS_LAUNCHED", true);
    let task = pair.b.task_of(&id);
    let launched = Launched(&pair.b);
    pair.b.within("the launched agent", || {
        launched.fake_dir().join("events").exists()
    });
    support::delegated::in_turn(&launched, &task, "HS_LAUNCHED");
    assert!(
        !support::delegated::input(&pair.b).contains("HS_LAUNCHED"),
        "not the route's other agent"
    );
    let record = support::delegated::record(&pair.b, &task);
    assert_eq!(record["route_id"], "launcher");
    let launches = pair.b.count(
        "launches",
        &format!("json_extract(record,'$.principal')='host:{A}'"),
    );
    assert_eq!(launches, 1);
    support::delegated::complete_turn(&launched, &task);
}

/// A lost `mailbox_stored` on either side: A's envelope and B's status
/// are each put again 35 s later (the same object, a fresh call), B admits
/// the message once and A records its status once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_HOST_CLOCK hooks"
)]
fn a_lost_stored_on_either_side_is_put_again_and_applied_once() {
    let pair = Pair::start(Hook::On, "");
    pair.a.station().drop_stored(1);
    pair.b.station().drop_stored(1);
    let id = pair.send(1, "atem:host-b/nowhere", "HS_LOST", false);
    pair.a.within("A's put", || pair.a.put_ids().contains(&id));
    pair.b
        .within("B's status put", || !pair.b.put_ids().is_empty());
    assert_eq!(pair.b.count("messages", &format!("id='{id}'")), 1);
    let status = pair.b.put_ids()[0].clone();
    pair.a.clock.add_mono(RETRY_MS);
    pair.b.clock.add_mono(RETRY_MS);
    let twice = |host: &Host, id: &str| host.put_ids().iter().filter(|p| *p == id).count() == 2;
    pair.a
        .within("A's envelope put again", || twice(&pair.a, &id));
    pair.b
        .within("B's status put again", || twice(&pair.b, &status));
    pair.a.message_status(
        &id,
        &[format!("  host {B}  accepted  accepted by the host")],
    );
    assert_eq!(
        pair.b.count("messages", &format!("id='{id}'")),
        1,
        "admitted once"
    );
    assert_eq!(
        pair.a.count("remote_tasks", &format!("message_id='{id}'")),
        1,
        "its resolution recorded once"
    );
}

/// SIGKILL of B after a request's admission committed (its task and status
/// with it) while the mailbox's done for it is still owed (its answer
/// lost): after B's restart the done goes again, the status is put once,
/// and B holds the message and its task once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_HOST_CLOCK hooks"
)]
fn a_kill_of_the_receiving_host_after_admission_applies_once() {
    use std::os::unix::process::ExitStatusExt;
    let mut pair = Pair::start(Hook::On, "");
    private(&pair.b.faults().join("crash_after_admission_commit"), "");
    pair.b.station().drop_done_results(1);
    let id = pair.send(1, &format!("atem:{B}"), "HS_ONCE", false);
    let deadline = std::time::Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = pair.b.runtime.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no crash\n{}",
            pair.b.runtime_log()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    pair.b.runtime = None;
    pair.b.sandbox.track();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(
        pair.b
            .runtime_log()
            .contains("killed after a host sender's request was admitted")
    );
    assert_eq!(pair.b.count("messages", &format!("id='{id}'")), 1);
    assert!(pair.b.put_ids().is_empty(), "nothing put before the kill");
    pair.b.start_again();
    pair.b.within("the owed done answered", || {
        pair.b.count("mailbox_dones", "1") == 0
    });
    let task = pair.b.task_of(&id);
    let tid = task.as_str().unwrap().to_owned();
    support::delegated::in_turn(&pair.b, &task, "HS_ONCE");
    pair.a
        .message_status(&id, &[format!("    {tid}  submitted  *")]);
    assert_eq!(pair.b.count("messages", &format!("id='{id}'")), 1);
    assert_eq!(pair.b.tasks_of(&id).len(), 1);
    let first = pair.b.put_ids()[0].clone();
    assert_eq!(
        pair.b.put_ids().iter().filter(|p| **p == first).count(),
        1,
        "the status committed with the admission put once"
    );
    support::delegated::complete_turn(&pair.b, &task);
}

/// B's device list revokes A as a sender (A's own list doesn't have the
/// revoke yet): A's unstarted task on B is cancelled (`sender revoked`),
/// the one in its turn goes on, and A's later envelope is refused on B
/// (`revoked_sender`), never admitted, so A's row for it waits unanswered.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_HOST_CLOCK hooks"
)]
fn a_revoked_sender_is_refused_and_its_unstarted_tasks_cancelled() {
    let mut pair = Pair::start(Hook::On, "");
    let first = pair.send(1, &format!("atem:{B}"), "HS_RUNNING", false);
    let t1 = pair.b.task_of(&first);
    support::delegated::in_turn(&pair.b, &t1, "HS_RUNNING");
    let second = pair.send(2, &format!("atem:{B}"), "HS_UNSTARTED", false);
    let t2 = pair.b.task_of(&second);
    pair.log
        .append(MAC, host_sender_revoke(A, false, 0).unwrap());
    pair.b.station().set_log(&pair.log);
    support::delegated::wait_stored(&pair.b, &t2, "cancelled", "sender revoked");
    assert_eq!(
        support::delegated::stored(&pair.b, &t1)["state"],
        "submitted"
    );
    let third = pair.send(3, &format!("atem:{B}"), "HS_REFUSED", false);
    pair.b.within("A's envelope refused", || {
        pair.b.count("mailbox_refused", "reason='revoked_sender'") == 1
    });
    assert_eq!(pair.b.count("messages", &format!("id='{third}'")), 0);
    pair.a.message_status(
        &third,
        &[
            format!("  host {B}  sent  stored in the host's mailbox; put again every 10 minutes until accepted"),
            "    status pending".into(),
        ],
    );
    support::delegated::never_ran(&pair.b, &t2, "HS_UNSTARTED");
    support::delegated::complete_turn(&pair.b, &t1);
    // Its reply (none here) and the task in its turn go on.
    pair.b.gone();
}

/// B's `per_workflow` bounds a chain across hosts: B's agent, in the turn
/// of A's task, sends back to A in that task's workflow; the second send
/// is refused at send, as stage 1 refuses a local one.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_HOST_CLOCK hooks"
)]
fn per_workflow_bounds_a_chain_across_hosts() {
    let pair = Pair::start(Hook::On, "per_workflow = 1");
    let id = pair.send(1, &format!("atem:{B}"), "HS_CHAIN", false);
    let task = pair.b.task_of(&id);
    support::delegated::in_turn(&pair.b, &task, "HS_CHAIN");
    let back = pair.b.agent(
        1,
        &["message", "send", "--to", &format!("atem:{A}"), "HS_BACK"],
    );
    assert_eq!(back["code"], 0, "{back}");
    let again = pair.b.agent(
        2,
        &["message", "send", "--to", &format!("atem:{A}"), "HS_AGAIN"],
    );
    assert_ne!(again["code"], 0, "{again}");
    assert!(
        again["stderr"]
            .as_str()
            .unwrap()
            .contains("limit: 1 messages per workflow"),
        "{again}"
    );
    let workflow: String = pair
        .b
        .db()
        .query_row(
            "SELECT json_extract(record,'$.task.workflow_id') FROM work WHERE id=?1",
            [task.as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    let sent: String = pair
        .b
        .db()
        .query_row(
            "SELECT json_extract(envelope,'$.workflow_id') FROM outbox WHERE message_id=?1",
            [back["stdout"].as_str().unwrap().trim()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sent, workflow, "the task's workflow");
    support::delegated::complete_turn(&pair.b, &task);
}

/// With the hook off on both hosts, `atem message send` to B's selector
/// reaches nothing remote: no envelope is put, B has nothing, and neither
/// host makes host senders' tables.
#[test]
fn with_the_hook_off_a_send_reaches_no_other_host() {
    let pair = Pair::start(Hook::Off, "");
    let out = pair.a.agent(
        1,
        &["message", "send", "--to", &format!("atem:{B}"), "HS_OFF"],
    );
    std::thread::sleep(Duration::from_secs(2));
    assert!(pair.a.put_ids().is_empty(), "{out}");
    assert!(pair.b.put_ids().is_empty());
    assert!(!support::delegated::input(&pair.b).contains("HS_OFF"));
    for host in [&pair.a, &pair.b] {
        assert_eq!(
            host.count(
                "sqlite_master",
                "name IN ('remote_deliveries', 'mail_outbox', 'mailbox_inbox')"
            ),
            0,
            "{}",
            host.id
        );
    }
}

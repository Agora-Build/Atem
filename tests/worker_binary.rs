//! Runs the real `atem worker` (and `atem runtime` as the broker that adopts
//! it) on a temp HOME and runtime dir with a fake agent script. The test
//! itself speaks the worker protocol as a broker would.
#![cfg(target_os = "linux")]
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// `/proc/<pid>/stat` field 22, or `None` when the process is gone.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_ascii_whitespace().nth(19)?.parse().ok()
}

/// Kills, at the end of the test, the processes it started that still run:
/// children by handle, the agent (a grandchild) only while its pid still
/// has the start time it had.
#[derive(Default)]
struct Cleanup {
    children: Vec<Child>,
    agent: Option<(u32, u64)>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some((pid, started)) = self.agent
            && start_time(pid) == Some(started)
        {
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
        for child in &mut self.children {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn within(secs: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

struct Env {
    _dir: tempfile::TempDir,
    home: PathBuf,
    run: PathBuf,
    state: PathBuf,
    agent: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("atem-wb")
            .tempdir_in("/tmp")
            .unwrap();
        let (home, run) = (dir.path().join("home"), dir.path().join("run"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
        let state = home.join(".config").join("atem").join("runtime");
        let agent = dir.path().join("agent.sh");
        std::fs::write(
            &agent,
            "#!/bin/sh\necho ready\nwhile read l; do echo \"got:$l\"; done\necho bye\n",
        )
        .unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            _dir: dir,
            home,
            run,
            state,
            agent,
        }
    }

    fn workers(&self) -> PathBuf {
        self.state.join("workers")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("XDG_RUNTIME_DIR", &self.run)
            // Never reach a real Astation from a test.
            .env("ASTATION_WS", "ws://127.0.0.1:1/ws")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        command
    }

    /// Writes the spawn spec the broker would and starts `atem worker`.
    fn start_worker(&self, sid: &str, process_gen: &str) -> (Child, PathBuf) {
        let socket = self
            .run
            .join("atem")
            .join("workers")
            .join(format!("{sid}.sock"));
        let spec = json!({
            "session_id": sid,
            "process_gen": process_gen,
            "provider": "codex",
            "args": [],
            "cwd": self.home,
            "rows": 24,
            "cols": 80,
            "socket": socket,
        });
        std::fs::create_dir_all(self.state.parent().unwrap()).unwrap();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(self.workers())
            .unwrap();
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.workers().join(format!("{sid}.spec.json")))
            .unwrap()
            .write_all(spec.to_string().as_bytes())
            .unwrap();
        let state = self.state.to_str().unwrap().to_string();
        let child = self
            .command(&["worker", "--state", &state, "--session", sid])
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        (child, socket)
    }

    /// `atem runtime` with its stderr in `log`.
    fn start_runtime(&self, log: &Path) -> Child {
        let log = std::fs::File::create(log).unwrap();
        self.command(&["runtime"]).stderr(log).spawn().unwrap()
    }
}

/// A broker connection speaking the worker protocol.
struct Broker {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    output: String,
}

impl Broker {
    fn connect(socket: &Path) -> Self {
        let mut stream = None;
        assert!(
            within(10, || {
                stream = UnixStream::connect(socket).ok();
                stream.is_some()
            }),
            "the worker didn't listen on {}",
            socket.display()
        );
        let stream = stream.unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self {
            reader: BufReader::new(stream.try_clone().unwrap()),
            stream,
            output: String::new(),
        }
    }

    /// Connects and reads `hello`, connecting again while the worker still
    /// refuses because the broker before is just closing.
    fn adopt(socket: &Path) -> (Self, Value) {
        for _ in 0..20 {
            let mut broker = Self::connect(socket);
            let first = broker.recv();
            if first["op"] == "hello" {
                return (broker, first);
            }
            assert!(
                first["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("another broker")),
                "{first}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the worker kept refusing");
    }

    fn send(&mut self, message: Value) {
        let mut message = message;
        message["v"] = json!(1);
        let line = format!("{message}\n");
        self.stream.write_all(line.as_bytes()).unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).unwrap();
        assert!(n > 0, "the worker closed the connection");
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["v"], 1, "{value}");
        if value["op"] == "output" {
            let bytes = STANDARD.decode(value["bytes"].as_str().unwrap()).unwrap();
            self.output.push_str(&String::from_utf8_lossy(&bytes));
        }
        value
    }

    /// Messages until one matches.
    fn until(&mut self, mut done: impl FnMut(&Value, &str) -> bool) -> Vec<Value> {
        let mut seen = Vec::new();
        loop {
            let message = self.recv();
            let hit = done(&message, &self.output);
            seen.push(message);
            if hit {
                return seen;
            }
        }
    }

    fn write(&mut self, seq: u64, bytes: &[u8], epoch: u64) {
        self.send(json!({"op": "write", "seq": seq, "bytes": STANDARD.encode(bytes), "input_epoch": epoch}));
    }

    fn result(&mut self, seq: u64) -> Value {
        self.until(|m, _| m["op"] == "write_result" && m["seq"] == seq)
            .pop()
            .unwrap()
    }
}

fn alive(pid: u32) -> bool {
    start_time(pid).is_some()
}

fn log_has(log: &Path, text: &str) -> bool {
    std::fs::read_to_string(log).is_ok_and(|log| log.contains(text))
}

#[test]
fn a_worker_owns_its_agent_survives_the_broker_and_is_adopted_by_a_new_one() {
    let env = Env::new();
    let mut cleanup = Cleanup::default();
    let sid = "ses-abcdefgh2345";
    let process_gen = "6f1c2a9e-4b7d-4c3e-9a51-0d2b8e7f6a14";
    let (worker, socket) = env.start_worker(sid, process_gen);
    let worker_pid = worker.id();
    cleanup.children.push(worker);

    // The broker that started it sends the environment, then hears hello.
    let mut broker = Broker::connect(&socket);
    let agent_env = json!([
        ["PATH", "/usr/bin:/bin"],
        ["CODEX_CLI_BIN", env.agent.to_str().unwrap()]
    ]);
    broker.send(json!({"op": "start", "env": agent_env}));
    let hello = broker.recv();
    assert_eq!(hello["op"], "hello", "{hello}");
    assert_eq!(hello["session_id"], sid);
    assert_eq!(hello["process_gen"], process_gen);
    assert_eq!(hello["pid"], worker_pid);
    assert_eq!(hello["start_time"], start_time(worker_pid).unwrap());
    let agent_pid = hello["agent_pid"].as_u64().unwrap() as u32;
    cleanup.agent = Some((agent_pid, start_time(agent_pid).unwrap()));
    // The socket and its directory are private; the spec is gone and the
    // record holds no environment.
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!env.workers().join(format!("{sid}.spec.json")).exists());
    let record_path = env.workers().join(format!("{sid}.json"));
    let record_text = std::fs::read_to_string(&record_path).unwrap();
    assert!(!record_text.contains("CODEX_CLI_BIN"), "{record_text}");
    let record: Value = serde_json::from_str(&record_text).unwrap();
    assert_eq!(record["worker_pid"], worker_pid);
    assert_eq!(record["agent_pid"], agent_pid);
    assert_eq!(record["start_time"], hello["start_time"]);

    // Output reaches the broker.
    broker.until(|_, out| out.contains("ready"));

    // A write of an older epoch is dropped, a current one is written.
    broker.send(json!({"op": "set_input_epoch", "epoch": 5}));
    broker.write(1, b"old\r", 4);
    broker.write(2, b"new\r", 5);
    let dropped = broker.result(1);
    assert_eq!(dropped["ok"], false);
    assert_eq!(dropped["dropped"], true);
    let written = broker.result(2);
    assert_eq!(written["ok"], true, "{written}");
    assert_eq!(written["bytes_written"], 4);
    broker.until(|_, out| out.contains("got:new"));
    assert!(!broker.output.contains("old"), "{:?}", broker.output);

    // The broker goes away: the worker and its agent keep running.
    drop(broker);
    assert!(alive(worker_pid) && alive(agent_pid));

    // A real broker adopts it at start; killing that broker leaves both running.
    let log = env.home.join("runtime-1.log");
    let mut runtime = env.start_runtime(&log);
    assert!(
        within(15, || log_has(&log, &format!("adopted worker {sid}"))),
        "{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    runtime.kill().unwrap();
    runtime.wait().unwrap();
    assert!(alive(worker_pid) && alive(agent_pid));

    // Another broker connects: same session and process, the screen restored.
    let (mut broker, hello) = Broker::adopt(&socket);
    assert_eq!(hello["op"], "hello", "{hello}");
    assert_eq!(hello["session_id"], sid);
    assert_eq!(hello["process_gen"], process_gen);
    assert_eq!(hello["agent_pid"], agent_pid);
    assert_eq!(hello["input_epoch"], 5);
    assert_eq!(hello["dropped"], 1);
    broker.send(json!({"op": "request_screen"}));
    let screen = broker.until(|m, _| m["op"] == "screen").pop().unwrap();
    let restore = STANDARD
        .decode(screen["restore"].as_str().unwrap())
        .unwrap();
    let restore = String::from_utf8_lossy(&restore);
    assert!(
        restore.contains("ready") && restore.contains("got:new"),
        "{restore:?}"
    );
    // A second broker at the same time is refused.
    let mut second = Broker::connect(&socket);
    let refused = second.recv();
    assert_eq!(refused["op"], "error");
    drop(second);
    drop(broker);

    // A forged record (the live worker's pid with another start time) is
    // refused and kept; the genuine one is adopted again.
    let forged_sid = "ses-zzzzzzzz2222";
    let mut forged = record.clone();
    forged["session_id"] = json!(forged_sid);
    forged["start_time"] = json!(record["start_time"].as_u64().unwrap() + 1);
    let forged_path = env.workers().join(format!("{forged_sid}.json"));
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&forged_path)
        .unwrap()
        .write_all(forged.to_string().as_bytes())
        .unwrap();
    let log = env.home.join("runtime-2.log");
    let runtime = env.start_runtime(&log);
    cleanup.children.push(runtime);
    assert!(
        within(15, || log_has(
            &log,
            &format!("{forged_sid}: recovery_required")
        ) && log_has(&log, &format!("adopted worker {sid}"))),
        "{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    assert!(!log_has(&log, &format!("adopted worker {forged_sid}")));
    assert!(forged_path.exists());
    let mut runtime = cleanup.children.pop().unwrap();
    runtime.kill().unwrap();
    runtime.wait().unwrap();

    // The agent exits: the broker hears `exited`, then releases the worker,
    // which exits and removes its record.
    let (mut broker, hello) = Broker::adopt(&socket);
    assert_eq!(hello["op"], "hello");
    broker.write(3, b"\x04", 5);
    let exited = broker.until(|m, _| m["op"] == "exited").pop().unwrap();
    assert!(exited["status"].is_string(), "{exited}");
    broker.send(json!({"op": "stop"}));
    let mut worker = cleanup.children.remove(0);
    assert!(
        within(10, || worker.try_wait().unwrap().is_some()),
        "the worker kept running"
    );
    assert!(worker.wait().unwrap().success());
    assert!(!alive(agent_pid) || start_time(agent_pid) != cleanup.agent.map(|a| a.1));
    assert!(!record_path.exists());
    assert!(!socket.exists());
}

#[test]
fn a_crashed_worker_and_agent_are_reported_interrupted_and_the_record_kept() {
    let env = Env::new();
    let mut cleanup = Cleanup::default();
    let sid = "ses-qqqqqqqq3333";
    let (worker, socket) = env.start_worker(sid, "0b7e4d1c-2f3a-4e5b-8c9d-1a2b3c4d5e6f");
    let worker_pid = worker.id();
    cleanup.children.push(worker);
    let mut broker = Broker::connect(&socket);
    let agent_env = json!([
        ["PATH", "/usr/bin:/bin"],
        ["CODEX_CLI_BIN", env.agent.to_str().unwrap()]
    ]);
    broker.send(json!({"op": "start", "env": agent_env}));
    let hello = broker.recv();
    let agent_pid = hello["agent_pid"].as_u64().unwrap() as u32;
    cleanup.agent = Some((agent_pid, start_time(agent_pid).unwrap()));
    broker.until(|_, out| out.contains("ready"));
    drop(broker);

    // Worker and agent die without a word (a crash): a new broker reports
    // the session interrupted and keeps the record.
    unsafe { libc::kill(worker_pid as libc::pid_t, libc::SIGKILL) };
    let mut worker = cleanup.children.remove(0);
    worker.wait().unwrap();
    unsafe { libc::kill(agent_pid as libc::pid_t, libc::SIGKILL) };
    assert!(within(5, || !alive(agent_pid)));
    let log = env.home.join("runtime.log");
    let runtime = env.start_runtime(&log);
    cleanup.children.push(runtime);
    assert!(
        within(15, || log_has(&log, &format!("{sid}: interrupted"))),
        "{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    assert!(env.workers().join(format!("{sid}.json")).exists());
}

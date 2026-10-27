//! Runs the real `atem runtime` binary on a temp HOME and runtime dir.
#![cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Kills the runtime a test started (by the pid it wrote into its lock).
struct Started(Option<u32>);

impl Drop for Started {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }
}

/// Kills a runtime child still running at the end of a test.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn runtime(home: &Path, run: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_atem"))
        .arg("runtime")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_RUNTIME_DIR", run)
        // Never reach a real Astation from a test.
        .env("ASTATION_WS", "ws://127.0.0.1:1/ws")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn within(secs: u64, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..secs * 10 {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Sends hello and returns the welcome.
fn hello(socket: &Path) -> Option<serde_json::Value> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream
        .write_all(b"{\"v\":1,\"op\":\"hello\",\"protocol\":1,\"build\":\"test\"}\n")
        .ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
    serde_json::from_str(&line).ok()
}

#[test]
fn one_runtime_per_config_dir_with_its_pid_and_a_private_socket() {
    let dir = tempfile::Builder::new()
        .prefix("atem-rb")
        .tempdir_in("/tmp")
        .unwrap();
    let (home, run) = (dir.path().join("home"), dir.path().join("run"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = home.join(".config").join("atem");
    let lock = config.join("runtime.lock");
    let socket = run.join("atem").join("runtime.sock");

    let mut first = runtime(&home, &run);
    let mut started = Started(None);
    assert!(
        within(10, || hello(&socket).is_some()),
        "the runtime didn't start listening"
    );
    let pid: u32 = std::fs::read_to_string(&lock)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    started.0 = Some(pid);
    assert_eq!(pid, first.id());
    let welcome = hello(&socket).unwrap();
    assert_eq!(welcome["op"], "welcome");
    assert_eq!(welcome["protocol"], 1);
    assert_eq!(welcome["pid"], pid);
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(socket.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(
        std::fs::read_to_string(config.join("runtime.socket")).unwrap(),
        socket.display().to_string()
    );

    // A second runtime for the same config dir exits at once, successfully.
    let mut second = runtime(&home, &run);
    assert!(
        within(10, || second.try_wait().unwrap().is_some()),
        "the second runtime kept running"
    );
    assert!(second.wait().unwrap().success());
    assert!(first.try_wait().unwrap().is_none(), "the first one stays");
    assert_eq!(hello(&socket).unwrap()["pid"], pid);

    // SIGTERM: a clean exit clears the pid and removes the socket.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    assert!(
        within(10, || first.try_wait().unwrap().is_some()),
        "the runtime ignored SIGTERM"
    );
    started.0 = None;
    assert_eq!(std::fs::read_to_string(&lock).unwrap().trim(), "");
    assert!(!socket.exists());
    assert!(!config.join("runtime.socket").exists());
}

#[test]
fn an_idle_runtime_exits_by_itself() {
    let dir = tempfile::Builder::new()
        .prefix("atem-rb")
        .tempdir_in("/tmp")
        .unwrap();
    let (home, run) = (dir.path().join("home"), dir.path().join("run"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
    command
        .arg("runtime")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", &run)
        .env("ASTATION_WS", "ws://127.0.0.1:1/ws")
        .env("ATEM_RUNTIME_IDLE_SECS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = Running(command.spawn().unwrap());
    assert!(
        within(15, || child.0.try_wait().unwrap().is_some()),
        "the idle runtime kept running"
    );
    assert!(child.0.wait().unwrap().success());
    // The idle exit is an orderly stop: its journal is closed cleanly for
    // the run's epoch (r8 §H).
    let journal = home.join(".config/atem/runtime/journal");
    let epoch = std::fs::read_to_string(journal.join("runtime_epoch")).unwrap();
    let clean: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal.join("clean_close")).unwrap()).unwrap();
    assert_eq!(
        clean,
        serde_json::json!({"runtime_epoch": epoch.trim().parse::<u64>().unwrap()})
    );
}

/// Whether `listener` gets a connection within `secs`.
fn accepted(listener: &std::net::TcpListener, secs: u64) -> bool {
    listener.set_nonblocking(true).unwrap();
    within(secs, || listener.accept().is_ok())
}

/// An unreadable pairing record is not "no pairing": the runtime never
/// tries the local Astation endpoint (the record might say relay only),
/// logs why, and a restarted runtime does the same. Without a record it
/// does try it (first pairing).
#[test]
fn an_unreadable_pairing_record_never_tries_the_local_astation() {
    for damaged in [true, false] {
        let dir = tempfile::Builder::new()
            .prefix("atem-rb")
            .tempdir_in("/tmp")
            .unwrap();
        let (home, run) = (dir.path().join("home"), dir.path().join("run"));
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = home.join(".config").join("atem");
        let pairing = config.join("pairing");
        std::fs::create_dir_all(&pairing).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&pairing, std::fs::Permissions::from_mode(0o700)).unwrap();
        if damaged {
            std::fs::write(pairing.join("pairing.enc"), b"not a sealed record").unwrap();
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let log = dir.path().join("stderr.log");
        for restart in 0..2 {
            let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
            command
                .arg("runtime")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &home)
                .env("XDG_RUNTIME_DIR", &run)
                .env("ASTATION_WS", &url)
                .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(&log).unwrap());
            let mut child = Running(command.spawn().unwrap());
            let socket = run.join("atem").join("runtime.sock");
            assert!(
                within(10, || hello(&socket).is_some()),
                "the runtime didn't start listening"
            );
            let tried = accepted(&listener, if damaged { 3 } else { 10 });
            assert_eq!(tried, !damaged, "damaged {damaged}, restart {restart}");
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "the runtime keeps running"
            );
            unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) };
            assert!(within(10, || child.0.try_wait().unwrap().is_some()));
            if !damaged {
                break;
            }
            let output = std::fs::read_to_string(&log).unwrap();
            assert!(
                output.contains("the pairing record can't be read; not connecting to Astation"),
                "{output}"
            );
            assert_eq!(
                std::fs::read(pairing.join("pairing.enc")).unwrap(),
                b"not a sealed record",
                "left as it was"
            );
        }
    }
}

/// `/proc/<pid>/stat` field 22, or `None` when the process is gone.
#[cfg(target_os = "linux")]
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_ascii_whitespace().nth(19)?.parse().ok()
}

/// Kills, at the end of a test, the workers and agents its runtimes started
/// that still run: only while a pid still has the start time it had.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct Spawned(Vec<(u32, u64)>);

#[cfg(target_os = "linux")]
impl Spawned {
    fn add(&mut self, pid: u32) {
        if let Some(started) = start_time(pid) {
            self.0.push((pid, started));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Spawned {
    fn drop(&mut self) {
        for (pid, started) in &self.0 {
            if start_time(*pid) == Some(*started) {
                unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
            }
        }
    }
}

/// A local frontend speaking the runtime protocol.
#[cfg(target_os = "linux")]
struct Frontend {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    /// The restore of the last `attached` plus the output after it.
    screen: String,
}

#[cfg(target_os = "linux")]
impl Frontend {
    fn connect(socket: &Path) -> Self {
        let mut stream = None;
        assert!(
            within(10, || {
                stream = UnixStream::connect(socket).ok();
                stream.is_some()
            }),
            "the runtime didn't listen"
        );
        let stream = stream.unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut frontend = Self {
            reader: BufReader::new(stream.try_clone().unwrap()),
            stream,
            screen: String::new(),
        };
        frontend.send(serde_json::json!({"op": "hello", "protocol": 1, "build": "test"}));
        assert_eq!(frontend.recv()["op"], "welcome");
        frontend
    }

    fn send(&mut self, mut message: serde_json::Value) {
        message["v"] = serde_json::json!(1);
        self.stream
            .write_all(format!("{message}\n").as_bytes())
            .unwrap();
    }

    fn recv(&mut self) -> serde_json::Value {
        use base64::Engine;
        let decode = |text: &serde_json::Value| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text.as_str().unwrap())
                .unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).unwrap();
        assert!(n > 0, "the runtime closed the connection");
        let message: serde_json::Value = serde_json::from_str(&line).unwrap();
        match message["op"].as_str() {
            Some("attached") => self.screen = decode(&message["restore"]),
            Some("output") => self.screen.push_str(&decode(&message["bytes"])),
            _ => {}
        }
        message
    }

    /// Messages until `done` holds for one (or the screen); returns it.
    fn until(
        &mut self,
        mut done: impl FnMut(&serde_json::Value, &str) -> bool,
    ) -> serde_json::Value {
        loop {
            let message = self.recv();
            assert_ne!(message["op"], "error", "{message}");
            if done(&message, &self.screen) {
                return message;
            }
        }
    }

    /// Reads until the screen shows `text` (it may already).
    fn shows(&mut self, text: &str) {
        while !self.screen.contains(text) {
            let message = self.recv();
            assert_ne!(message["op"], "error", "{message}");
        }
    }

    fn launch(&mut self, cwd: &Path, agent: &Path) -> String {
        self.send(serde_json::json!({
            "op": "launch", "provider": "codex", "args": [], "cwd": cwd,
            "env": [["PATH", "/usr/bin:/bin"], ["CODEX_CLI_BIN", agent]],
            "rows": 24, "cols": 80,
        }));
        let launched = self.until(|m, _| m["op"] == "launched");
        launched["session"]["id"].as_str().unwrap().to_string()
    }

    fn attach(&mut self, sid: &str) {
        self.send(serde_json::json!({"op": "attach", "session_id": sid, "rows": 24, "cols": 80}));
        self.until(|m, _| m["op"] == "attached");
    }

    fn input(&mut self, sid: &str, text: &str) {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.encode(text);
        self.send(serde_json::json!({"op": "input", "session_id": sid, "bytes": bytes}));
    }

    fn list(&mut self) -> Vec<serde_json::Value> {
        self.send(serde_json::json!({"op": "list"}));
        let sessions = self.until(|m, _| m["op"] == "sessions");
        sessions["sessions"].as_array().unwrap().clone()
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sessions_run_in_workers_that_a_restarted_runtime_adopts() {
    let dir = tempfile::Builder::new()
        .prefix("atem-rb")
        .tempdir_in("/tmp")
        .unwrap();
    let (home, run) = (dir.path().join("home"), dir.path().join("run"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let agent = dir.path().join("agent.sh");
    std::fs::write(
        &agent,
        "#!/bin/sh\necho ready\nwhile read l; do echo \"got:$l\"; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = run.join("atem").join("runtime.sock");
    let workers = home
        .join(".config")
        .join("atem")
        .join("runtime")
        .join("workers");
    let record = |sid: &str| -> serde_json::Value {
        let text = std::fs::read_to_string(workers.join(format!("{sid}.json"))).unwrap();
        serde_json::from_str(&text).unwrap()
    };
    let mut spawned = Spawned::default();

    let mut first = Running(runtime(&home, &run));
    let mut frontend = Frontend::connect(&socket);
    // Two sessions, each in its own worker process (not the runtime).
    let one = frontend.launch(&home, &agent);
    let two = frontend.launch(&home, &agent);
    let (record_one, record_two) = (record(&one), record(&two));
    let worker_one = record_one["worker_pid"].as_u64().unwrap() as u32;
    let worker_two = record_two["worker_pid"].as_u64().unwrap() as u32;
    for record in [&record_one, &record_two] {
        spawned.add(record["worker_pid"].as_u64().unwrap() as u32);
        spawned.add(record["agent_pid"].as_u64().unwrap() as u32);
    }
    assert_ne!(worker_one, worker_two);
    assert!(worker_one != first.0.id() && worker_two != first.0.id());
    assert!(start_time(worker_one).is_some() && start_time(worker_two).is_some());
    frontend.attach(&one);
    frontend.shows("ready");
    frontend.input(&one, "hello\r");
    frontend.shows("got:hello");
    drop(frontend);

    // The runtime dies: the workers and their agents keep running.
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    assert!(start_time(worker_one).is_some() && start_time(worker_two).is_some());

    // The next runtime adopts both; attach restores the screen and input goes on.
    let _second = Running(runtime(&home, &run));
    let mut frontend = Frontend::connect(&socket);
    // `list` waits until the runtime adopted what it found at start.
    let sessions = frontend.list();
    assert_eq!(sessions.len(), 2, "{sessions:?}");
    assert!(
        sessions.iter().all(|s| s["state"] == "running"),
        "{sessions:?}"
    );
    frontend.attach(&one);
    assert!(
        frontend.screen.contains("got:hello"),
        "{:?}",
        frontend.screen
    );
    frontend.input(&one, "again\r");
    frontend.shows("got:again");

    // Stop ends each worker, which removes its record.
    for (sid, worker) in [(&one, worker_one), (&two, worker_two)] {
        frontend.send(serde_json::json!({"op": "stop", "session_id": sid}));
        assert!(
            within(10, || !workers.join(format!("{sid}.json")).exists()),
            "the record of {sid} stayed"
        );
        assert!(
            within(10, || start_time(worker).is_none()),
            "worker {worker} kept running"
        );
        // Its lock and log go with the record.
        for leftover in [format!("{sid}.lock"), format!("{sid}.log")] {
            assert!(
                within(10, || !workers.join(&leftover).exists()),
                "{leftover} stayed"
            );
        }
    }
    let sessions = frontend.list();
    assert!(
        sessions.iter().all(|s| s["state"] == "exited"),
        "{sessions:?}"
    );
}

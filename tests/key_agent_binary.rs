//! Runs the real `atem key-agent` binary on a temp HOME and runtime dir and
//! talks to it over its socket.
#![cfg(unix)]
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_real_agent_starts_locked_and_answers_on_its_socket() {
    let dir = tempfile::Builder::new()
        .prefix("atem-kb")
        .tempdir_in("/tmp")
        .unwrap();
    let (home, runtime) = (dir.path().join("home"), dir.path().join("run"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&runtime).unwrap();
    // The agent only uses a runtime dir that others can't write to.
    std::fs::set_permissions(
        &runtime,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let _agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("key-agent")
            .env("HOME", &home)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = runtime.join("atem").join("agent.sock");
    let mut stream = (0..50)
        .find_map(|_| {
            UnixStream::connect(&socket).ok().or_else(|| {
                std::thread::sleep(Duration::from_millis(100));
                None
            })
        })
        .expect("the agent did not start listening");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(b"{\"op\":\"status\",\"v\":2}\n").unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["reply"]["kind"], "status");
    assert_eq!(reply["reply"]["unlocked"], false);
}

/// `atem key-agent` for `home` with its socket under `runtime`.
fn agent_process(home: &std::path::Path, runtime: &std::path::Path) -> Agent {
    Agent(
        Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("key-agent")
            .env("HOME", home)
            .env("XDG_RUNTIME_DIR", runtime)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

/// Asks the agent at `socket` for its status; `None` if nothing answers.
fn status_at(socket: &std::path::Path) -> Option<serde_json::Value> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(b"{\"op\":\"status\",\"v\":2}\n").ok()?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).ok()?;
    serde_json::from_slice(&buf[..n]).ok()
}

/// Polls `done` every 100 ms for up to `secs` seconds.
fn within(secs: u64, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..secs * 10 {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn an_agent_whose_runtime_dir_was_removed_exits_and_a_new_one_starts() {
    let dir = tempfile::Builder::new()
        .prefix("atem-kb")
        .tempdir_in("/tmp")
        .unwrap();
    let home = dir.path().join("home");
    let (run_a, run_b) = (dir.path().join("ra"), dir.path().join("rb"));
    std::fs::create_dir_all(&home).unwrap();
    for run in [&run_a, &run_b] {
        std::fs::create_dir_all(run).unwrap();
        std::fs::set_permissions(run, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }
    let mut first = agent_process(&home, &run_a);
    let socket_a = run_a.join("atem").join("agent.sock");
    assert!(
        within(5, || status_at(&socket_a).is_some()),
        "the first agent didn't start"
    );
    // logind removes the runtime dir when the user's last session ends; an
    // agent that survives it can't be reached any more and must go.
    std::fs::remove_dir_all(&run_a).unwrap();
    assert!(
        within(10, || first.0.try_wait().unwrap().is_some()),
        "the orphaned agent kept running"
    );
    // A clean exit clears its pid from the lock file.
    let lock = home.join(".config").join("atem").join("key_agent.lock");
    assert_eq!(std::fs::read_to_string(&lock).unwrap().trim(), "");
    // The next session's agent takes over the key files.
    let mut second = agent_process(&home, &run_b);
    let socket_b = run_b.join("atem").join("agent.sock");
    assert!(
        within(10, || status_at(&socket_b).is_some()),
        "the new agent didn't start"
    );
    assert_eq!(status_at(&socket_b).unwrap()["reply"]["unlocked"], false);
    assert!(second.0.try_wait().unwrap().is_none());
}

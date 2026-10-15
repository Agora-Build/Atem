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
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
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
    let pid: u32 = std::fs::read_to_string(&lock).unwrap().trim().parse().unwrap();
    started.0 = Some(pid);
    assert_eq!(pid, first.id());
    let welcome = hello(&socket).unwrap();
    assert_eq!(welcome["op"], "welcome");
    assert_eq!(welcome["protocol"], 1);
    assert_eq!(welcome["pid"], pid);
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(socket.parent().unwrap()).unwrap().permissions().mode() & 0o777;
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
}

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
    stream.write_all(b"{\"op\":\"status\",\"v\":1}\n").unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["reply"]["kind"], "status");
    assert_eq!(reply["reply"]["unlocked"], false);
}

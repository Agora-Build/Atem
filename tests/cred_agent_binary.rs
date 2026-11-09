//! Runs the real `atem cred-agent` binary on a temp HOME and runtime dir and
//! talks to it over its socket.
#![cfg(unix)]
mod support;

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
            .arg("cred-agent")
            .env("HOME", &home)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = support::profile::agent_sock(&runtime);
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

/// `atem cred-agent` for `home` with its socket under `runtime`.
fn agent_process(home: &std::path::Path, runtime: &std::path::Path) -> Agent {
    Agent(
        Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("cred-agent")
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
    let socket_a = support::profile::agent_sock(&run_a);
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
    let lock = support::profile::CredPaths::in_dir(&home.join(".config").join("atem")).agent_lock;
    assert_eq!(std::fs::read_to_string(&lock).unwrap().trim(), "");
    // The next session's agent takes over the key files.
    let mut second = agent_process(&home, &run_b);
    let socket_b = support::profile::agent_sock(&run_b);
    assert!(
        within(10, || status_at(&socket_b).is_some()),
        "the new agent didn't start"
    );
    assert_eq!(status_at(&socket_b).unwrap()["reply"]["unlocked"], false);
    assert!(second.0.try_wait().unwrap().is_none());
}

#[test]
fn the_real_agent_answers_several_requests_on_one_connection() {
    use std::io::BufRead;
    let dir = tempfile::Builder::new()
        .prefix("atem-kb")
        .tempdir_in("/tmp")
        .unwrap();
    let (home, runtime) = (dir.path().join("home"), dir.path().join("run"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(
        &runtime,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let _agent = agent_process(&home, &runtime);
    let socket = support::profile::agent_sock(&runtime);
    assert!(
        within(5, || status_at(&socket).is_some()),
        "the agent didn't start"
    );
    // Clients keep one connection for every request of a process.
    let stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut replies = std::io::BufReader::new(&stream);
    for request in [
        "{\"op\":\"status\",\"v\":2}\n",
        "{\"op\":\"pending_rotation\",\"v\":2}\n",
        "{\"op\":\"status\",\"v\":2}\n",
    ] {
        (&stream).write_all(request.as_bytes()).unwrap();
        let mut line = String::new();
        replies.read_line(&mut line).unwrap();
        let reply: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["ok"], true, "{reply}");
    }
}

/// A `Crypt` frame by hand (src/memory/agent_frame.rs): 0xFF, kind 1, the op
/// count and the body length (little-endian), then the body: the astation id
/// and one keyed hash (tag 3) of `value`, each field a 4-byte length first.
fn keyed_hash_frame(kind: u8, value: &[u8]) -> Vec<u8> {
    let field = |bytes: &[u8]| [&(bytes.len() as u32).to_le_bytes()[..], bytes].concat();
    // 11 bytes: no length byte of the frames these tests send is a newline.
    let body = [field(b"astation-01"), vec![3], field(value)].concat();
    let mut frame = vec![0xFF, kind];
    frame.extend_from_slice(&1u32.to_le_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    frame
}

#[test]
fn the_real_agent_reads_crypt_frames_on_a_connection_whose_status_offered_them() {
    use std::io::BufRead;
    let dir = tempfile::Builder::new()
        .prefix("atem-kb")
        .tempdir_in("/tmp")
        .unwrap();
    let (home, runtime) = (dir.path().join("home"), dir.path().join("run"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(
        &runtime,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let _agent = agent_process(&home, &runtime);
    let socket = support::profile::agent_sock(&runtime);
    assert!(
        within(5, || status_at(&socket).is_some()),
        "the agent didn't start"
    );
    let stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut replies = std::io::BufReader::new(&stream);
    let mut line = String::new();
    // The build check's status offers frames on this connection.
    (&stream)
        .write_all(b"{\"op\":\"status\",\"v\":2}\n")
        .unwrap();
    replies.read_line(&mut line).unwrap();
    let status: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(status["reply"]["frames"], 1, "{status}");
    // A frame: the locked agent's refusal comes back as a JSON frame (kind
    // 2, no results) worded as on a line.
    (&stream)
        .write_all(&keyed_hash_frame(1, b"SECRET"))
        .unwrap();
    let mut head = [0u8; 10];
    replies.read_exact(&mut head).unwrap();
    assert_eq!((head[0], head[1]), (0xFF, 2), "{head:?}");
    assert_eq!(u32::from_le_bytes(head[2..6].try_into().unwrap()), 0);
    let mut body = vec![0u8; u32::from_le_bytes(head[6..10].try_into().unwrap()) as usize];
    replies.read_exact(&mut body).unwrap();
    let refusal: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(refusal["ok"], false, "{refusal}");
    assert!(
        refusal["error"].as_str().unwrap().contains("locked"),
        "{refusal}"
    );
    // JSON lines still go on the same connection.
    line.clear();
    (&stream)
        .write_all(b"{\"op\":\"pending_rotation\",\"v\":2}\n")
        .unwrap();
    replies.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"), "{line}");
    // A malformed frame (unknown kind) closes the connection unanswered.
    (&stream).write_all(&keyed_hash_frame(9, b"x")).unwrap();
    let mut byte = [0u8; 1];
    assert!(matches!(replies.read(&mut byte), Ok(0) | Err(_)));
    // A connection that never agreed reads the same bytes as one line (the
    // frame holds no newline byte of its own): one refusal.
    let other = UnixStream::connect(&socket).unwrap();
    other
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut frame = keyed_hash_frame(1, b"x");
    assert!(!frame.contains(&b'\n'), "{frame:?}");
    frame.push(b'\n');
    (&other).write_all(&frame).unwrap();
    let mut other_replies = std::io::BufReader::new(&other);
    line.clear();
    other_replies.read_line(&mut line).unwrap();
    let reply: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], false, "{reply}");
    assert!(
        reply["error"].as_str().unwrap().contains("not JSON"),
        "{reply}"
    );
    // The next reply answers the next line: nothing else was queued.
    (&other)
        .write_all(b"{\"op\":\"status\",\"v\":2}\n")
        .unwrap();
    line.clear();
    other_replies.read_line(&mut line).unwrap();
    let status: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(status["ok"], true, "{status}");
    assert_eq!(status["reply"]["frames"], 1, "{status}");
    // The agent still serves.
    assert_eq!(status_at(&socket).unwrap()["ok"], true);
}

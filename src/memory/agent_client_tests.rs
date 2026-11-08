//! (test-only) Kept connections to the cred agent: one client per agent in a
//! process (`shared`), one connection kept between requests, the build check
//! on each new connection, which requests go again when a connection drops,
//! the clean error an agent that closes after each reply gets, and what a
//! kept connection retains (designs/e2e-encryption.md "Keys on disk (atem)").
use super::tests::{
    OTHER_DONE, cred_agent_process, eventually, make_private, own_uid, short_dir, sock,
    start_agent, start_scripted_agent, start_stoppable_agent,
};
use super::*;
use std::io::{BufRead, BufReader, Write};

/// Serves `agent` at `socket` on its own thread.
pub(super) fn serve_agent(socket: &Path, agent: Arc<Mutex<CredAgent>>) {
    let (ready, started) = std::sync::mpsc::channel();
    let path = socket.to_path_buf();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = bind(&path).unwrap();
            ready.send(()).unwrap();
            let _ = serve(listener, agent, own_uid()).await;
        });
    });
    started.recv().unwrap();
}

/// A verified device whose agent holds `K` (mode on), served at the
/// returned socket.
pub(super) fn served_device(dir: &Path) -> (crate::memory::fake_astation::UnlockedDevice, PathBuf) {
    use crate::memory::crypto::EncryptionMode;
    let mut device = crate::memory::fake_astation::UnlockedDevice::new(&dir.join("device"));
    device.set_key(EncryptionMode::On, "0123abcd", [7; 32]);
    let socket = sock(&dir.join("run"));
    serve_agent(&socket, device.agent.clone());
    (device, socket)
}

fn seal_one(client: &dyn CredAgentApi) -> Result<Vec<CryptOut>> {
    client.crypt(
        crate::memory::fake_astation::ASTATION_ID,
        vec![CryptOp::seal("mem-1", "content", b"a fact")],
    )
}

/// The `op` of a request line.
pub(super) fn op_of(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v["op"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// One message off `reader`, as the agent reads them: a frame (header and
/// body) when it starts with the frame byte, else a line. `None` at the end.
pub(super) fn read_message(reader: &mut impl BufRead) -> Option<(Vec<u8>, bool)> {
    let first = *reader.fill_buf().ok()?.first()?;
    if first != crate::memory::agent_frame::MAGIC {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).ok()?;
        return Some((line, false));
    }
    let mut frame = vec![0u8; crate::memory::agent_frame::HEADER];
    reader.read_exact(&mut frame).ok()?;
    let len = u32::from_le_bytes(frame[6..10].try_into().unwrap()) as usize;
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    frame.extend_from_slice(&body);
    Some((frame, true))
}

/// Sits between clients and the agent at `upstream`: counts the
/// connections it accepts and the requests it reads (by op; a frame is a
/// `crypt`), and on request closes every open client connection (as the
/// agent does with idle ones) or swallows requests (the next one, or the
/// next ones of an op): reads one, never passes it on, and closes that
/// connection unanswered.
pub(super) struct Proxy {
    pub(super) socket: PathBuf,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
    passed: Arc<Mutex<Vec<String>>>,
    /// The requests that were frames.
    frames: Arc<std::sync::atomic::AtomicUsize>,
    /// The op to swallow (any when `None`) and how many more.
    swallow: Arc<Mutex<(Option<String>, usize)>>,
    live: Arc<Mutex<Vec<UnixStream>>>,
}

impl Proxy {
    pub(super) fn start(dir: &Path, upstream: PathBuf) -> Self {
        use std::sync::atomic::Ordering::SeqCst;
        let socket = dir.join("proxy.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let proxy = Self {
            socket,
            connections: Default::default(),
            seen: Default::default(),
            passed: Default::default(),
            frames: Default::default(),
            swallow: Default::default(),
            live: Default::default(),
        };
        let (connections, seen, passed, frames, swallow, live) = (
            proxy.connections.clone(),
            proxy.seen.clone(),
            proxy.passed.clone(),
            proxy.frames.clone(),
            proxy.swallow.clone(),
            proxy.live.clone(),
        );
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { return };
                connections.fetch_add(1, SeqCst);
                live.lock().unwrap().push(client.try_clone().unwrap());
                let (seen, passed, frames, swallow, upstream) = (
                    seen.clone(),
                    passed.clone(),
                    frames.clone(),
                    swallow.clone(),
                    upstream.clone(),
                );
                std::thread::spawn(move || {
                    let Ok(agent) = UnixStream::connect(&upstream) else {
                        return;
                    };
                    let mut from_client = BufReader::new(&client);
                    let mut from_agent = BufReader::new(&agent);
                    loop {
                        let Some((request, framed)) = read_message(&mut from_client) else {
                            return;
                        };
                        let op = if framed {
                            frames.fetch_add(1, SeqCst);
                            "crypt".to_string()
                        } else {
                            op_of(&String::from_utf8_lossy(&request))
                        };
                        seen.lock().unwrap().push(op.clone());
                        let swallowed = {
                            let mut rule = swallow.lock().unwrap();
                            let hit = rule.1 > 0 && rule.0.as_deref().is_none_or(|want| want == op);
                            if hit {
                                rule.1 -= 1;
                            }
                            hit
                        };
                        if swallowed {
                            let _ = client.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                        passed.lock().unwrap().push(op);
                        let reply = (&agent)
                            .write_all(&request)
                            .ok()
                            .and_then(|_| read_message(&mut from_agent));
                        let Some((reply, _)) = reply else {
                            let _ = client.shutdown(std::net::Shutdown::Both);
                            return;
                        };
                        if (&client).write_all(&reply).is_err() {
                            let _ = client.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                    }
                });
            }
        });
        proxy
    }

    pub(super) fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    pub(super) fn passed(&self) -> Vec<String> {
        self.passed.lock().unwrap().clone()
    }

    /// The requests that went as frames.
    pub(super) fn frames(&self) -> usize {
        self.frames.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn count(ops: &[String], op: &str) -> usize {
        ops.iter().filter(|seen| *seen == op).count()
    }

    /// Closes every client connection open now.
    fn drop_connections(&self) {
        for stream in self.live.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// The next request line is read and dropped with its connection.
    fn swallow_next(&self) {
        *self.swallow.lock().unwrap() = (None, 1);
    }

    /// The next `count` request lines of `op` are each read and dropped
    /// with their connection.
    pub(super) fn swallow_ops(&self, op: &str, count: usize) {
        *self.swallow.lock().unwrap() = (Some(op.to_string()), count);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_whole_sync_uses_one_agent_connection() {
    use crate::memory::adapters::Ctx;
    use crate::memory::api::KnowledgeClient;
    use crate::memory::e2e_tests::{RelayState, stub_relay};
    use crate::memory::model::{Memory, Scope, content_hash};
    use crate::memory::store::{PendingOp, Store};
    use crate::memory::sync::{SyncOptions, run_sync};
    let (_profile, _scope) = crate::test_profile::temp();
    let dir = short_dir();
    let (device, socket) = served_device(dir.path());
    let proxy = Proxy::start(dir.path(), socket);
    let client = Arc::new(CredAgentClient::at(proxy.socket.clone()).checking_build(build_id()));
    let base = stub_relay(Arc::new(Mutex::new(RelayState::empty()))).await;
    let knowledge = KnowledgeClient::new(
        base,
        "atem-1".into(),
        "session-1".into(),
        crate::memory::fake_astation::ASTATION_ID.into(),
    )
    .with_encryption(device.paths.clone(), client.clone());
    let store = Store::open_in_memory().unwrap();
    for n in 0..120 {
        let content = format!("fact number {n}");
        let memory = Memory {
            id: format!("mem-{n}"),
            scope: Scope::Project,
            project: "github.com/agora/atem".into(),
            content_hash: content_hash(&content),
            content,
            confidence: "high".into(),
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            ..Memory::default()
        };
        store.upsert_memory(&memory).unwrap();
        store.enqueue(&PendingOp::AddMemory { memory }).unwrap();
    }
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    let ctx = Ctx {
        home,
        repo: None,
        atem_id: "atem-1".into(),
        allow_tracked: false,
    };
    let out = run_sync(
        &store,
        Some(&knowledge),
        &ctx,
        &SyncOptions { harvest: false },
    )
    .await
    .unwrap();
    assert!(!out.relay_error && !out.offline, "{:?}", out.notes);
    let seen = proxy.seen();
    assert!(
        Proxy::count(&seen, "crypt") >= 2,
        "a push and a pull: {seen:?}"
    );
    assert_eq!(
        proxy.connections(),
        1,
        "one connection for the whole sync: {seen:?}"
    );
    // One build check, then one unlocked check before each chunk sent as
    // sealed ahead (chunks 2 and 3, the second group, sealed while chunk 1
    // was in flight).
    assert_eq!(
        Proxy::count(&seen, "status"),
        1 + 2,
        "one build check and two unlocked checks: {seen:?}"
    );
    assert_eq!(client.traffic().connections(), 1);
}

#[test]
fn contexts_share_the_process_client_and_its_one_build_check() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let proxy = Proxy::start(dir.path(), socket);
    // What `default_agent` hands each `EncryptionContext`.
    let first = shared(CredAgentClient::at(proxy.socket.clone()).checking_build(build_id()));
    let second = shared(CredAgentClient::at(proxy.socket.clone()).checking_build(build_id()));
    assert!(Arc::ptr_eq(&first, &second), "one client per agent");
    for _ in 0..5 {
        assert_eq!(first.pending_rotation().unwrap(), None);
        assert_eq!(second.pending_rotation().unwrap(), None);
    }
    let seen = proxy.seen();
    assert_eq!(proxy.connections(), 1, "{seen:?}");
    assert_eq!(
        Proxy::count(&seen, "status"),
        1,
        "no status probe after the first: {seen:?}"
    );
    assert_eq!(Proxy::count(&seen, "pending_rotation"), 10, "{seen:?}");
    assert_eq!(first.traffic().probes(), 1);
    assert_eq!(first.traffic().requests(), 11, "the check and ten requests");
}

#[test]
fn two_threads_with_their_own_agents_share_no_client() {
    let run = || {
        std::thread::spawn(|| {
            let dir = short_dir();
            let socket = start_agent(dir.path(), own_uid());
            let proxy = Proxy::start(dir.path(), socket);
            let client = shared(CredAgentClient::at(proxy.socket.clone()));
            assert!(Arc::ptr_eq(
                &client,
                &shared(CredAgentClient::at(proxy.socket.clone()))
            ));
            for _ in 0..3 {
                assert!(!client.status().unwrap().unlocked);
            }
            assert_eq!(proxy.connections(), 1);
            assert_eq!(Proxy::count(&proxy.seen(), "status"), 3);
            (Arc::as_ptr(&client) as usize, dir)
        })
    };
    let (a, b) = (run(), run());
    let (a, _dir_a) = a.join().unwrap();
    let (b, _dir_b) = b.join().unwrap();
    assert_ne!(a, b, "two agents, two clients");
}

#[test]
fn a_connection_the_agent_closed_while_idle_is_replaced_before_sending() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let proxy = Proxy::start(dir.path(), socket);
    let client = CredAgentClient::at(proxy.socket.clone());
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(client.pending_rotation().unwrap(), None);
    // The agent drops connections idle for a minute.
    proxy.drop_connections();
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(client.pending_rotation().unwrap(), None);
    proxy.drop_connections();
    // A request that changes the agent goes on a new connection too:
    // nothing had been written on the closed one.
    client.lock_keys().unwrap();
    assert_eq!(proxy.connections(), 3);
    assert_eq!(
        proxy.seen(),
        [
            "pending_rotation",
            "pending_rotation",
            "pending_rotation",
            "pending_rotation",
            "lock"
        ]
    );
    assert_eq!(proxy.passed(), proxy.seen(), "nothing sent twice");
}

#[test]
fn a_connection_reused_after_the_idle_limit_is_replaced() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let proxy = Proxy::start(dir.path(), socket);
    let client = CredAgentClient::at(proxy.socket.clone());
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(client.pending_rotation().unwrap(), None);
    // Idle for half the limit: kept. The clock is moved, never waited for.
    client.idle_for(REUSE_IDLE / 2);
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(proxy.connections(), 1);
    // Idle past the limit (kept well under the agent's own): replaced
    // before anything is written.
    client.idle_for(REUSE_IDLE);
    client.lock_keys().unwrap();
    assert_eq!(proxy.connections(), 2);
    assert_eq!(proxy.passed(), proxy.seen(), "nothing sent twice");
}

#[test]
fn a_stateless_request_whose_connection_drops_unanswered_is_sent_again() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let proxy = Proxy::start(dir.path(), socket);
    let client = CredAgentClient::at(proxy.socket.clone());
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(client.pending_rotation().unwrap(), None);
    // The connection drops after the request was written, before any
    // byte of the reply: the agent never acted, and reading again is safe.
    proxy.swallow_next();
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(proxy.seen(), ["pending_rotation"; 4]);
    assert_eq!(proxy.passed(), ["pending_rotation"; 3]);
    assert_eq!(proxy.connections(), 2);
    assert_eq!(client.traffic().connections(), 2);
}

#[test]
fn a_request_that_changes_the_agent_is_never_sent_again() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let proxy = Proxy::start(dir.path(), socket);
    let client = CredAgentClient::at(proxy.socket.clone());
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(client.pending_rotation().unwrap(), None);
    proxy.swallow_next();
    let error = format!("{:#}", client.lock_keys().err().unwrap());
    assert!(error.contains("closed the connection"), "{error}");
    // Seen once, never passed to the agent, never resent (the status
    // that explains the error asks for the agent's version).
    let (seen, passed) = (proxy.seen(), proxy.passed());
    assert_eq!(Proxy::count(&seen, "lock"), 1, "{seen:?}");
    assert_eq!(Proxy::count(&passed, "lock"), 0, "{passed:?}");
    // The next request works on a new connection.
    client.lock_keys().unwrap();
    assert_eq!(Proxy::count(&proxy.passed(), "lock"), 1);
}

#[test]
fn a_stateless_request_goes_at_most_once_more() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let proxy = Proxy::start(dir.path(), socket);
    let client = CredAgentClient::at(proxy.socket.clone()).checking_build(build_id());
    assert_eq!(client.pending_rotation().unwrap(), None);
    // Dropped on the kept connection, then again on the new (checked) one:
    // written twice, never a third time.
    proxy.swallow_ops("pending_rotation", 2);
    let error = format!("{:#}", client.pending_rotation().err().unwrap());
    assert!(error.contains("closed the connection"), "{error}");
    assert_eq!(Proxy::count(&proxy.seen(), "pending_rotation"), 3);
    assert_eq!(Proxy::count(&proxy.passed(), "pending_rotation"), 1);
}

#[test]
fn a_lock_between_two_requests_on_one_connection_is_seen() {
    let dir = short_dir();
    let (_device, socket) = served_device(dir.path());
    let client = CredAgentClient::at(socket.clone()).checking_build(build_id());
    seal_one(&client).unwrap();
    CredAgentClient::at(socket.clone()).lock_keys().unwrap();
    let error = format!("{:#}", seal_one(&client).err().unwrap());
    assert!(error.contains(crate::memory::cred_agent::LOCKED), "{error}");
    assert_eq!(client.traffic().connections(), 1, "the same connection");
    // `atem cred lock` stops the agent: the client's connection closes
    // and nothing answers any more.
    assert!(CredAgentClient::at(socket.clone()).lock_and_stop().unwrap());
    let error = format!("{:#}", seal_one(&client).err().unwrap());
    assert!(error.contains("isn't running"), "{error}");
}

/// An unlocked agent of another build.
const OTHER_UNLOCKED: &str = r#"{"v":2,"ok":true,"reply":{"kind":"status","unlocked":true,"storage_kid":"0a1b2c3d","escrowed":true,"build":"0.0.0+other"}}"#;

#[test]
fn an_agent_restarted_as_another_build_is_checked_on_the_new_connection() {
    let dir = short_dir();
    let (socket, stopped) = start_stoppable_agent(dir.path());
    let client = CredAgentClient::at(socket.clone()).checking_build(build_id());
    assert!(!client.status().unwrap().older_build);
    assert_eq!(client.older_build_warning(), None);
    assert!(CredAgentClient::at(socket.clone()).lock_and_stop().unwrap());
    stopped.recv_timeout(Duration::from_secs(3)).unwrap();
    // Another build's agent, already unlocked, now serves the socket.
    start_scripted_agent(dir.path(), OTHER_UNLOCKED, OTHER_DONE);
    let status = client.status().unwrap();
    assert!(status.older_build && status.unlocked);
    assert_eq!(
        client.older_build_warning().as_deref(),
        Some(crate::memory::cred_agent::OLDER_BUILD)
    );
    assert_eq!(
        client.traffic().probes(),
        2,
        "checked again after reconnecting"
    );
}

#[test]
fn a_client_reconnects_to_a_restarted_agent_process_and_checks_it_again() {
    let dir = short_dir();
    let home = dir.path().join("home");
    let run = dir.path().join("run");
    std::fs::create_dir_all(&home).unwrap();
    make_private(&run);
    let config = home.join(".config").join("atem");
    let finding = || CredAgentClient::finding(&config, Some(run.clone().into_os_string()), None);
    let first = cred_agent_process(&home, &run, &dir.path().join("a.log"));
    assert!(eventually(|| finding().is_running()));
    let build = finding().status().unwrap().build;
    let client = finding().checking_build(&build);
    for _ in 0..3 {
        assert!(!client.status().unwrap().unlocked);
    }
    assert_eq!(client.traffic().connections(), 1);
    assert_eq!(client.traffic().probes(), 1);
    drop(first);
    let _second = cred_agent_process(&home, &run, &dir.path().join("b.log"));
    assert!(eventually(|| finding().is_running()));
    assert!(!client.status().unwrap().unlocked);
    assert_eq!(client.traffic().connections(), 2);
    assert_eq!(client.traffic().probes(), 2);
    assert_eq!(client.older_build_warning(), None, "the same build");
}

/// An agent that closes every connection after its first reply (no released
/// build does: v0.6.11 to v0.8.3 all serve several requests per
/// connection), answering `status` as this build; the ops of the request
/// lines it read.
fn start_one_reply_agent(dir: &Path) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let socket = sock(&dir.join("run"));
    make_private(socket.parent().unwrap());
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let status = format!(
        r#"{{"v":2,"ok":true,"reply":{{"kind":"status","unlocked":true,"storage_kid":"0a1b2c3d","escrowed":true,"build":"{}"}}}}"#,
        build_id()
    );
    let read = Arc::new(Mutex::new(Vec::new()));
    let seen = read.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            seen.lock().unwrap().push(op_of(&line));
            let reply = if line.contains("\"op\":\"status\"") {
                status.as_str()
            } else if line.contains("\"op\":\"pending_rotation\"") {
                r#"{"v":2,"ok":true,"reply":{"kind":"pending_rotation","rotation":null}}"#
            } else {
                OTHER_DONE
            };
            let _ = (&stream).write_all(format!("{reply}\n").as_bytes());
        }
    });
    (socket, read)
}

#[test]
fn an_agent_that_closes_after_each_reply_gets_a_clean_error() {
    // As `autostart` makes clients: it may start an agent (never needed
    // here) and checks the build on each new connection. The build check
    // takes each connection's only reply, so every request after it fails,
    // promptly, and one that changes the agent is never sent again.
    let dir = short_dir();
    let (socket, read) = start_one_reply_agent(dir.path());
    let client = CredAgentClient::with_launcher(
        socket,
        Box::new(|| -> Result<()> { panic!("an agent answers") }),
    )
    .checking_build(build_id());
    let started = std::time::Instant::now();
    let error = format!("{:#}", client.lock_keys().err().unwrap());
    assert!(error.contains("closed the connection"), "{error}");
    let error = format!("{:#}", client.pending_rotation().err().unwrap());
    assert!(error.contains("closed the connection"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5), "no hang");
    // The agent read build checks (and the statuses that explain the
    // errors) only: the lock never reached it, let alone twice. The
    // stateless request was written twice (once more, as for any agent).
    let read = read.lock().unwrap().clone();
    assert!(read.iter().all(|op| op == "status"), "{read:?}");
    assert_eq!(client.traffic().probes(), 3, "a check per new connection");
}

/// Whether `needle` occurs in `bytes`.
pub(super) fn holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// Reads `bytes` into `lines` the way the agent does: into the chunk, or
/// the rest of the body of a frame being read, as much as it takes.
pub(super) fn feed(lines: &mut Lines, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let buffer = lines.buffer();
        let n = buffer.len().min(bytes.len());
        buffer[..n].copy_from_slice(&bytes[..n]);
        lines.take(n);
        bytes = &bytes[n..];
    }
}

#[test]
fn an_answered_request_leaves_nothing_in_the_agents_connection_buffers() {
    let request = br#"{"op":"load_unlocked","device":"SECRET-DEVICE-KEY","storage_key":"SECRET-STORAGE-KEY","v":2}
"#;
    let mut lines = Lines::new();
    feed(&mut lines, request);
    assert_eq!(&lines.next_line().unwrap()[..], &request[..]);
    assert!(lines.next_line().is_none());
    lines.settle();
    let retained = lines.retained(request.len());
    assert!(
        !holds(&retained, b"SECRET"),
        "{}",
        String::from_utf8_lossy(&retained)
    );
    assert!(retained.iter().all(|byte| *byte == 0));
}

#[test]
fn the_next_requests_first_bytes_stay_and_nothing_of_the_answered_one() {
    let first = br#"{"op":"crypt","astation_id":"a","ops":[{"seal":{"plain":"SECRET-ONE"}}],"v":2}
"#;
    let next = br#"{"op":"status""#;
    let mut lines = Lines::new();
    feed(&mut lines, &[&first[..], &next[..]].concat());
    assert_eq!(&lines.next_line().unwrap()[..], &first[..]);
    assert!(lines.next_line().is_none());
    lines.settle();
    let retained = lines.retained(first.len() + next.len());
    assert!(
        !holds(&retained, b"SECRET-ONE"),
        "{}",
        String::from_utf8_lossy(&retained)
    );
    assert_eq!(&retained[..next.len()], &next[..]);
    feed(&mut lines, b",\"v\":2}\n");
    assert_eq!(
        &lines.next_line().unwrap()[..],
        b"{\"op\":\"status\",\"v\":2}\n"
    );
}

#[test]
fn a_big_answered_request_gives_its_buffer_back() {
    let big = format!(
        "{{\"op\":\"crypt\",\"plain\":\"SECRET-{}\",\"v\":2}}\n",
        "x".repeat(20 << 10)
    );
    let mut lines = Lines::new();
    feed(&mut lines, big.as_bytes());
    assert_eq!(&lines.next_line().unwrap()[..], big.as_bytes());
    lines.settle();
    // The grown buffer went (wiped as it was dropped); the chunk is wiped.
    assert_eq!(lines.pending.0.capacity(), 4096);
    assert!(lines.retained(0).iter().all(|byte| *byte == 0));
}

/// An agent for the key files in `dir`, served on its own thread, whose
/// connections report what they hold once they have answered.
pub(super) fn start_reporting_agent(dir: &Path) -> (PathBuf, HeldLog) {
    let socket = sock(&dir.join("run"));
    let paths = CredPaths::in_dir(dir);
    let held = Arc::new(Mutex::new(Vec::new()));
    let (ready, started) = std::sync::mpsc::channel();
    let (path, log) = (socket.clone(), held.clone());
    std::thread::spawn(move || {
        SETTLED.with(|settled| *settled.borrow_mut() = Some(log));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = bind(&path).unwrap();
            let agent = Arc::new(Mutex::new(CredAgent::new(paths).unwrap()));
            ready.send(()).unwrap();
            let _ = serve(listener, agent, own_uid()).await;
        });
    });
    started.recv().unwrap();
    (socket, held)
}

#[test]
fn the_agent_wipes_what_a_request_left_once_it_has_answered() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let dir = short_dir();
    let (socket, held) = start_reporting_agent(dir.path());
    let client = CredAgentClient::at(socket);
    // Read and answered: the locked agent refuses it.
    let error = format!(
        "{:#}",
        client
            .crypt(
                "astation-1",
                vec![CryptOp::seal("r", "f", b"SECRET-PLAIN-TEXT")]
            )
            .err()
            .unwrap()
    );
    assert!(error.contains(crate::memory::cred_agent::LOCKED), "{error}");
    assert!(eventually(|| !held.lock().unwrap().is_empty()));
    let on_the_wire = STANDARD.encode(b"SECRET-PLAIN-TEXT");
    for bytes in held.lock().unwrap().iter() {
        assert!(
            !holds(bytes, on_the_wire.as_bytes()),
            "{}",
            String::from_utf8_lossy(bytes)
        );
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn a_kept_connection_holds_no_reply_bytes_after_a_request() {
    let dir = short_dir();
    let client = CredAgentClient::at(start_agent(dir.path(), own_uid()));
    assert!(!client.status().unwrap().unlocked);
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(client.kept_unread(), Some(0), "kept, nothing unread");
    // An agent that sends more than one line for a request: the reply is
    // refused and its connection not kept.
    let other = short_dir();
    let doubled = r#"{"v":2,"ok":true,"reply":{"kind":"done"}}
{"v":2,"ok":true,"reply":{"kind":"done"}}"#;
    let client = CredAgentClient::at(start_scripted_agent(other.path(), doubled, doubled));
    assert!(client.lock_keys().is_err());
    assert_eq!(client.kept_unread(), None, "not kept");
}

#[test]
fn clients_that_may_start_an_agent_and_clients_that_never_do_are_shared_apart() {
    let dir = short_dir();
    let paths = CredPaths::in_dir(&dir.path().join("config"));
    let run = dir.path().join("run");
    make_private(&run);
    let never = || CredAgentClient::for_paths(&paths, Some(run.clone().into_os_string()), None);
    let starting = || {
        CredAgentClient::for_paths(
            &paths,
            Some(run.clone().into_os_string()),
            Some(Box::new(|| -> Result<()> { Ok(()) })),
        )
        .waiting(Duration::from_millis(100))
    };
    let first = shared(never());
    assert!(Arc::ptr_eq(&first, &shared(never())));
    assert!(!Arc::ptr_eq(&first, &shared(starting())));
    // `running_agent`'s client never starts one.
    let error = format!("{:#}", first.status().err().unwrap());
    assert!(error.contains("isn't running"), "{error}");
}

// ───────────── the wait for an agent this client started (F7) ─────────────

use std::sync::atomic::{AtomicUsize, Ordering};

/// A launcher that starts an in-process agent for `dir` `delay` from now and
/// returns at once, as spawning a process does; counts its calls.
fn spawning_after(dir: &Path, delay: Duration, launches: &Arc<AtomicUsize>) -> Launcher {
    let (dir, launches) = (dir.to_path_buf(), launches.clone());
    Box::new(move || {
        launches.fetch_add(1, Ordering::SeqCst);
        let dir = dir.clone();
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            start_agent(&dir, own_uid());
        });
        Ok(())
    })
}

/// A launcher that starts nothing; counts its calls.
fn spawning_nothing(launches: &Arc<AtomicUsize>) -> Launcher {
    let launches = launches.clone();
    Box::new(move || {
        launches.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
}

/// A socket file nobody listens on, as a dead agent leaves it.
fn leave_stale_socket(socket: &Path) {
    make_private(socket.parent().unwrap());
    drop(std::os::unix::net::UnixListener::bind(socket).unwrap());
    assert!(socket.exists());
}

/// The time `attempt` takes, best of `runs` (one run stalled by a busy
/// machine doesn't decide).
fn best_of(runs: usize, mut attempt: impl FnMut() -> Duration) -> Duration {
    (0..runs).map(|_| attempt()).min().unwrap()
}

#[test]
fn an_agent_that_comes_up_at_once_is_reached_without_the_old_fixed_wait() {
    // The client used to sleep 100 ms before its first look at an agent it
    // had just started, however quickly it came up.
    let best = best_of(5, || {
        let dir = short_dir();
        let launches = Arc::new(AtomicUsize::new(0));
        let client = CredAgentClient::with_launcher(
            sock(&dir.path().join("run")),
            spawning_after(dir.path(), Duration::ZERO, &launches),
        );
        let started = std::time::Instant::now();
        assert!(!client.status().unwrap().unlocked);
        let took = started.elapsed();
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        took
    });
    // Found by the first poll (5 ms) or, on a busy host, a few polls later;
    // the old wait was at least 100 ms by construction (a 100 ms sleep).
    assert!(
        best < Duration::from_millis(80),
        "first contact took {best:?}"
    );
}

#[test]
fn an_agent_that_starts_slowly_is_waited_for_and_reached_soon_after() {
    // Up about 105 ms after the launch, past the 5 ms polls: with the
    // schedule's polls at 110 and 130 ms (`START_POLLS_MS`: 5 x 8, 10 x 3,
    // 20 x 3, ...) it is found at 110 ms, or at 130 ms if the in-process
    // start takes longer than the 5 ms before that poll; the old fixed polls
    // (100, 200 ms) found it at 200 ms. The 150 ms bound leaves 20 ms over the
    // 130 ms path and 50 ms under the old one; change it with the schedule.
    let delay = Duration::from_millis(105);
    let best = best_of(3, || {
        let dir = short_dir();
        let launches = Arc::new(AtomicUsize::new(0));
        let client = CredAgentClient::with_launcher(
            sock(&dir.path().join("run")),
            spawning_after(dir.path(), delay, &launches),
        );
        let started = std::time::Instant::now();
        assert!(!client.status().unwrap().unlocked);
        let took = started.elapsed();
        assert_eq!(launches.load(Ordering::SeqCst), 1, "one start, one agent");
        assert!(client.is_running());
        took
    });
    assert!(best >= delay, "reached before it listened? {best:?}");
    assert!(best < Duration::from_millis(150), "found after {best:?}");
}

#[test]
fn a_stale_socket_file_is_not_an_agent_and_is_replaced_by_the_one_that_starts() {
    let dir = short_dir();
    let socket = sock(&dir.path().join("run"));
    leave_stale_socket(&socket);
    let launches = Arc::new(AtomicUsize::new(0));
    let client = CredAgentClient::with_launcher(
        socket,
        spawning_after(dir.path(), Duration::from_millis(60), &launches),
    );
    // The refused connections while the file is stale are "not yet".
    assert!(!client.status().unwrap().unlocked);
    assert_eq!(launches.load(Ordering::SeqCst), 1);
}

#[test]
fn no_agent_within_the_wait_is_todays_error_after_that_wait() {
    let dir = short_dir();
    let socket = sock(&dir.path().join("run"));
    leave_stale_socket(&socket);
    let launches = Arc::new(AtomicUsize::new(0));
    let wait = Duration::from_millis(300);
    let client = CredAgentClient::with_launcher(socket.clone(), spawning_nothing(&launches))
        .waiting(wait)
        .logging_to(dir.path().join("agent.log"));
    let started = std::time::Instant::now();
    let error = format!("{:#}", client.status().err().unwrap());
    let took = started.elapsed();
    assert_eq!(
        error,
        format!(
            "the cred agent didn't start; see {}",
            dir.path().join("agent.log").display()
        )
    );
    assert_eq!(
        launches.load(Ordering::SeqCst),
        1,
        "started once, then polled"
    );
    assert!(took >= wait, "gave up after {took:?}");
    assert!(
        took < wait + Duration::from_secs(2),
        "gave up after {took:?}"
    );
    assert!(
        socket.exists(),
        "the stale file is not the client's to remove"
    );
}

#[test]
fn a_running_agent_is_neither_started_again_nor_waited_for() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let launches = Arc::new(AtomicUsize::new(0));
    let client = CredAgentClient::with_launcher(socket, spawning_nothing(&launches))
        .waiting(Duration::from_millis(50));
    for _ in 0..3 {
        assert!(!client.status().unwrap().unlocked);
    }
    // Another client of the same agent, with its own connection.
    let (socket, other) = (sock(&dir.path().join("run")), Arc::new(AtomicUsize::new(0)));
    let second = CredAgentClient::with_launcher(socket, spawning_nothing(&other));
    assert!(!second.status().unwrap().unlocked);
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    assert_eq!(other.load(Ordering::SeqCst), 0);
}

#[test]
fn a_listener_of_another_user_that_appears_is_refused_not_polled_past() {
    let dir = short_dir();
    let launches = Arc::new(AtomicUsize::new(0));
    let client = CredAgentClient::with_launcher(
        sock(&dir.path().join("run")),
        spawning_after(dir.path(), Duration::ZERO, &launches),
    )
    .expecting_uid(own_uid() + 1)
    .waiting(Duration::from_secs(20));
    let started = std::time::Instant::now();
    let error = format!("{:#}", client.status().err().unwrap());
    assert!(error.contains("served by another user"), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "not the end of the wait"
    );
    assert_eq!(launches.load(Ordering::SeqCst), 1);
}

#[test]
fn the_polls_of_a_started_agent_begin_at_5_ms_and_back_off_to_the_old_interval() {
    let pauses: Vec<Duration> = (0..40).map(start_poll_pause).collect();
    assert_eq!(pauses[0], Duration::from_millis(5));
    assert!(
        pauses.windows(2).all(|pair| pair[0] <= pair[1]),
        "{pauses:?}"
    );
    assert_eq!(pauses[pauses.len() - 1], START_POLL_MAX);
    assert_eq!(START_POLL_MAX, Duration::from_millis(100), "the old poll");
    // An agent within its 25 ms startup budget is found within one 5 ms step.
    let mut at = Duration::ZERO;
    for pause in &pauses {
        at += *pause;
        if at <= Duration::from_millis(40) {
            assert_eq!(*pause, Duration::from_millis(5), "{pauses:?}");
        }
    }
}

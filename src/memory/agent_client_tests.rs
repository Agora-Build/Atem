//! (test-only) The cred agent client's connection: one client per agent in
//! a process (`shared`), one connection kept between requests, the build
//! check on each new connection, and which requests go again when a
//! connection drops (designs/e2e-encryption.md "Keys on disk (atem)").
use super::tests::{
    OTHER_DONE, cred_agent_process, eventually, make_private, own_uid, short_dir, sock,
    start_agent, start_scripted_agent, start_stoppable_agent,
};
use super::*;
use std::io::{BufRead, BufReader, Write};

/// Serves `agent` at `socket` on its own thread.
fn serve_agent(socket: &Path, agent: Arc<Mutex<CredAgent>>) {
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
fn served_device(dir: &Path) -> (crate::memory::fake_astation::UnlockedDevice, PathBuf) {
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
fn op_of(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v["op"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Sits between clients and the agent at `upstream`: counts the
/// connections it accepts and the request lines it reads (by op), and on
/// request closes every open client connection (as the agent does with
/// idle ones) or swallows the next request: reads it, never passes it
/// on, and closes that connection unanswered.
struct Proxy {
    socket: PathBuf,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
    passed: Arc<Mutex<Vec<String>>>,
    swallow: Arc<std::sync::atomic::AtomicBool>,
    live: Arc<Mutex<Vec<UnixStream>>>,
}

impl Proxy {
    fn start(dir: &Path, upstream: PathBuf) -> Self {
        use std::sync::atomic::Ordering::SeqCst;
        let socket = dir.join("proxy.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let proxy = Self {
            socket,
            connections: Default::default(),
            seen: Default::default(),
            passed: Default::default(),
            swallow: Default::default(),
            live: Default::default(),
        };
        let (connections, seen, passed, swallow, live) = (
            proxy.connections.clone(),
            proxy.seen.clone(),
            proxy.passed.clone(),
            proxy.swallow.clone(),
            proxy.live.clone(),
        );
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { return };
                connections.fetch_add(1, SeqCst);
                live.lock().unwrap().push(client.try_clone().unwrap());
                let (seen, passed, swallow, upstream) = (
                    seen.clone(),
                    passed.clone(),
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
                        let mut line = String::new();
                        if from_client.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        seen.lock().unwrap().push(op_of(&line));
                        if swallow.swap(false, SeqCst) {
                            let _ = client.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                        passed.lock().unwrap().push(op_of(&line));
                        let mut reply = String::new();
                        if (&agent).write_all(line.as_bytes()).is_err()
                            || from_agent.read_line(&mut reply).unwrap_or(0) == 0
                            || (&client).write_all(reply.as_bytes()).is_err()
                        {
                            let _ = client.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                    }
                });
            }
        });
        proxy
    }

    fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn passed(&self) -> Vec<String> {
        self.passed.lock().unwrap().clone()
    }

    fn count(ops: &[String], op: &str) -> usize {
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
        self.swallow
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
    assert_eq!(
        Proxy::count(&seen, "status"),
        1,
        "one build check: {seen:?}"
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
    // The agent drops connections idle for a minute.
    proxy.drop_connections();
    assert_eq!(client.pending_rotation().unwrap(), None);
    proxy.drop_connections();
    // A request that changes the agent goes on a new connection too:
    // nothing had been written on the closed one.
    client.lock_keys().unwrap();
    assert_eq!(proxy.connections(), 3);
    assert_eq!(
        proxy.seen(),
        ["pending_rotation", "pending_rotation", "lock"]
    );
    assert_eq!(proxy.passed(), proxy.seen(), "nothing sent twice");
}

#[test]
fn a_connection_reused_after_the_idle_limit_is_replaced() {
    let dir = short_dir();
    let socket = start_agent(dir.path(), own_uid());
    let proxy = Proxy::start(dir.path(), socket);
    let client = CredAgentClient::at(proxy.socket.clone()).reusing_for(Duration::from_millis(100));
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(proxy.connections(), 1);
    // Idle past the limit (kept well under the agent's own): replaced
    // before anything is written.
    std::thread::sleep(Duration::from_millis(150));
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
    // The connection drops after the request was written, before any
    // byte of the reply: the agent never acted, and reading again is safe.
    proxy.swallow_next();
    assert_eq!(client.pending_rotation().unwrap(), None);
    assert_eq!(proxy.seen(), ["pending_rotation"; 3]);
    assert_eq!(proxy.passed(), ["pending_rotation"; 2]);
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

/// An agent that closes every connection after its first reply.
fn start_one_reply_agent(dir: &Path) -> PathBuf {
    let socket = sock(&dir.join("run"));
    make_private(socket.parent().unwrap());
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let reply = if line.contains("\"op\":\"status\"") {
                OTHER_UNLOCKED
            } else {
                OTHER_DONE
            };
            let _ = (&stream).write_all(format!("{reply}\n").as_bytes());
        }
    });
    socket
}

#[test]
fn an_agent_that_answers_one_request_per_connection_still_works() {
    let dir = short_dir();
    let client = CredAgentClient::at(start_one_reply_agent(dir.path()));
    for _ in 0..5 {
        assert!(client.status().unwrap().unlocked);
    }
    // Once it has closed the last connection, a request that changes
    // the agent goes on a new one without error.
    std::thread::sleep(Duration::from_millis(50));
    client.lock_keys().unwrap();
    // A connection each (one more when a status raced the close and
    // went again).
    assert!(client.traffic().connections() >= 6);
}

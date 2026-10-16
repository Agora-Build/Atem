//! The runtime's server in this process: a temp socket, fake agents (sh
//! scripts) and the async client.
use super::broker::{InProcess, Launcher};
use super::client::RuntimeClient;
use super::protocol::{
    ClientMsg, LaunchEnv, PROTOCOL, RuntimeMsg, SessionSummary, decode_runtime, unb64,
};
use super::server::{Options, serve};
use crate::app::App;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Unix socket paths are limited to ~100 bytes; keep them short.
fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("atem-rt")
        .tempdir_in("/tmp")
        .unwrap()
}

/// `body` on a current-thread runtime with a `LocalSet` (the App stays on one task).
fn local<F: std::future::Future>(body: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, body)
}

fn own_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// An App with chat and logs under `root` (chat can't be prepared there, so
/// Claude runs its binary as given).
fn app(root: &Path) -> App {
    std::fs::write(root.join("file"), b"").unwrap();
    let mut app = App::new();
    app.chat_root = root.join("file/run");
    app.logs_dir = root.join("logs");
    app
}

/// An executable sh script `name` in `dir`.
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Prints its name and `HOME` (the runtime's own environment must not leak
/// in), then echoes its input.
fn echo_agent(dir: &Path) -> PathBuf {
    script(
        dir,
        "echo-agent",
        "printf 'READY %s HOME=[%s]\\r\\n' \"$FAKE_NAME\" \"$HOME\"\nexec cat",
    )
}

struct Runtime {
    dir: std::rc::Rc<tempfile::TempDir>,
    socket: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// Workers served in this process, with their records under `<root>/state`.
fn launcher(root: &Path) -> Launcher {
    Launcher::InProcess(InProcess {
        state: root.join("state"),
        socket_dir: root.join("ws"),
        chat_root: root.join("file/run"),
    })
}

impl Runtime {
    /// A server for a fresh App on a temp socket (call inside `local`).
    fn start(idle: Duration, uid: u32) -> Self {
        Self::start_in(std::rc::Rc::new(short_dir()), "rt.sock", idle, uid)
    }

    /// A server in `dir` (another broker of the same state dir).
    fn start_in(
        dir: std::rc::Rc<tempfile::TempDir>,
        socket: &str,
        idle: Duration,
        uid: u32,
    ) -> Self {
        let socket = dir.path().join(socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let app = app(dir.path());
        let options = Options {
            idle,
            uid,
            launcher: launcher(dir.path()),
        };
        let server = tokio::task::spawn_local(serve(app, listener, options, async {
            let _ = stopped.await;
        }));
        Self {
            dir,
            socket,
            stop: Some(stop),
            server,
        }
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn new() -> Self {
        Self::start(Duration::from_secs(600), own_uid())
    }

    async fn client(&self) -> RuntimeClient {
        RuntimeClient::connect_at(&self.socket).await.unwrap()
    }

    async fn shutdown(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(10), &mut self.server)
            .await
            .expect("the server stops")
            .unwrap()
            .unwrap();
    }

    fn launch(&self, provider: &str, name: &str, binary: &Path) -> ClientMsg {
        let var = if provider == "claude" {
            "CLAUDE_CLI_BIN"
        } else {
            "CODEX_CLI_BIN"
        };
        ClientMsg::Launch {
            provider: provider.into(),
            args: vec![],
            cwd: self.dir.path().to_path_buf(),
            env: LaunchEnv(vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("FAKE_NAME".into(), name.into()),
                (var.into(), binary.display().to_string()),
            ]),
            rows: 24,
            cols: 80,
        }
    }
}

/// The next message `pick` accepts (others skipped), within ten seconds.
async fn expect<T>(client: &mut RuntimeClient, mut pick: impl FnMut(RuntimeMsg) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let message = client.recv().await.unwrap().expect("the runtime closed");
            if let Some(value) = pick(message) {
                return value;
            }
        }
    })
    .await
    .expect("timed out waiting for a message")
}

async fn launched(client: &mut RuntimeClient) -> SessionSummary {
    expect(client, |m| match m {
        RuntimeMsg::Launched { session } => Some(session),
        RuntimeMsg::Error { text, .. } => panic!("launch failed: {text}"),
        _ => None,
    })
    .await
}

async fn attached(client: &mut RuntimeClient) -> (SessionSummary, Vec<u8>, u64) {
    expect(client, |m| match m {
        RuntimeMsg::Attached {
            session,
            restore,
            offset,
        } => Some((session, unb64(&restore).unwrap(), offset)),
        RuntimeMsg::Error { text, .. } => panic!("attach failed: {text}"),
        _ => None,
    })
    .await
}

/// A frontend's view: the restore, then output in order.
struct View {
    screen: vt100::Parser,
    offset: u64,
    restores: usize,
    output: Vec<u8>,
}

impl View {
    fn new() -> Self {
        Self {
            screen: vt100::Parser::new(24, 80, 0),
            offset: 0,
            restores: 0,
            output: Vec::new(),
        }
    }

    /// Applies `message`; true when it was for this view.
    fn apply(&mut self, message: &RuntimeMsg) -> bool {
        match message {
            RuntimeMsg::Attached {
                session,
                restore,
                offset,
            } => {
                self.screen = vt100::Parser::new(session.rows, session.cols, 0);
                self.screen.process(&unb64(restore).unwrap());
                self.offset = *offset;
                self.restores += 1;
                true
            }
            RuntimeMsg::Output { bytes, offset, .. } => {
                assert_eq!(*offset, self.offset, "output continues the stream");
                let bytes = unb64(bytes).unwrap();
                self.offset += bytes.len() as u64;
                self.screen.process(&bytes);
                self.output.extend_from_slice(&bytes);
                true
            }
            _ => false,
        }
    }

    async fn until(&mut self, client: &mut RuntimeClient, text: &str) {
        let found = tokio::time::timeout(Duration::from_secs(10), async {
            while !self.screen.screen().contents().contains(text) {
                let message = client.recv().await.unwrap().expect("the runtime closed");
                self.apply(&message);
            }
        })
        .await;
        assert!(
            found.is_ok(),
            "{text:?} never showed; screen:\n{}",
            self.screen.screen().contents()
        );
    }
}

#[test]
fn hello_launch_two_sessions_and_list_them() {
    local(async {
        let runtime = Runtime::new();
        let agent = echo_agent(runtime.dir.path());
        let mut client = runtime.client().await;
        assert_eq!(client.welcome.protocol, PROTOCOL);
        assert_eq!(client.welcome.pid, std::process::id());
        assert_eq!(client.welcome.build, crate::memory::key_agent::build_id());
        client
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        let one = launched(&mut client).await;
        client
            .send(&runtime.launch("claude", "two", &agent))
            .await
            .unwrap();
        let two = launched(&mut client).await;
        assert_ne!(one.id, two.id);
        assert!(crate::session::SessionId::parse(&one.id).is_some());
        assert_eq!(
            (one.provider.as_str(), two.provider.as_str()),
            ("codex", "claude")
        );
        assert_eq!(one.cwd, runtime.dir.path());
        assert!(!one.attached && one.exited.is_none());
        client.send(&ClientMsg::List).await.unwrap();
        let sessions = expect(&mut client, |m| match m {
            RuntimeMsg::Sessions { sessions } => Some(sessions),
            _ => None,
        })
        .await;
        let ids: Vec<_> = sessions.iter().map(|s| s.id.clone()).collect();
        assert_eq!(ids, vec![one.id, two.id]);
        runtime.shutdown().await;
    });
}

#[test]
fn attach_restores_then_streams_output_and_input_and_resize_reach_the_pty() {
    local(async {
        let runtime = Runtime::new();
        let agent = echo_agent(runtime.dir.path());
        let mut client = runtime.client().await;
        client
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut client).await;
        client
            .send(&ClientMsg::Attach {
                session_id: session.id.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        let mut view = View::new();
        let message = expect(&mut client, |m| {
            matches!(m, RuntimeMsg::Attached { .. }).then_some(m)
        })
        .await;
        view.apply(&message);
        let RuntimeMsg::Attached { session: info, .. } = &message else {
            unreachable!()
        };
        assert!(info.attached);
        // The launch environment, and only it, reached the agent.
        view.until(&mut client, "READY one HOME=[]").await;
        client
            .send(&ClientMsg::input(&session.id, b"typed locally\r"))
            .await
            .unwrap();
        view.until(&mut client, "typed locally").await;
        // A resize changes the canonical screen; a fresh restore follows.
        client
            .send(&ClientMsg::Resize {
                session_id: session.id.clone(),
                rows: 30,
                cols: 100,
            })
            .await
            .unwrap();
        let (resized, _, _) = attached(&mut client).await;
        assert_eq!((resized.rows, resized.cols), (30, 100));
        // Reclaim answers with a fresh restore too.
        client
            .send(&ClientMsg::Reclaim {
                session_id: session.id.clone(),
            })
            .await
            .unwrap();
        attached(&mut client).await;
        runtime.shutdown().await;
    });
}

#[test]
fn a_second_attach_moves_the_session_and_stop_reports_the_exit() {
    local(async {
        let runtime = Runtime::new();
        let agent = echo_agent(runtime.dir.path());
        let mut first = runtime.client().await;
        let mut second = runtime.client().await;
        first
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut first).await;
        let attach = ClientMsg::Attach {
            session_id: session.id.clone(),
            rows: 24,
            cols: 80,
        };
        first.send(&attach).await.unwrap();
        attached(&mut first).await;
        second.send(&attach).await.unwrap();
        attached(&mut second).await;
        let reason = expect(&mut first, |m| match m {
            RuntimeMsg::Detached { session_id, reason } => {
                assert_eq!(session_id, session.id);
                Some(reason)
            }
            _ => None,
        })
        .await;
        assert_eq!(reason, "attached elsewhere");
        // The detached frontend can't type into it any more.
        first
            .send(&ClientMsg::input(&session.id, b"x"))
            .await
            .unwrap();
        expect(&mut first, |m| match m {
            RuntimeMsg::Error { op, .. } => {
                assert_eq!(op.as_deref(), Some("input"));
                Some(())
            }
            _ => None,
        })
        .await;
        // Stop: the attached frontend hears of the exit.
        first
            .send(&ClientMsg::Stop {
                session_id: session.id.clone(),
            })
            .await
            .unwrap();
        let exited = expect(&mut second, |m| match m {
            RuntimeMsg::Exited {
                session_id,
                generation,
                status,
            } => Some((session_id, generation, status)),
            _ => None,
        })
        .await;
        assert_eq!(exited.0, session.id);
        assert_eq!(exited.1, session.generation);
        second.send(&ClientMsg::List).await.unwrap();
        let sessions = expect(&mut second, |m| match m {
            RuntimeMsg::Sessions { sessions } => Some(sessions),
            _ => None,
        })
        .await;
        assert!(sessions[0].exited.is_some());
        assert_eq!(sessions[0].state, "exited");
        // The broker released the worker: it removed its record.
        let record = record_file(&runtime, &session.id);
        assert!(within(10, || !record.exists()).await, "the record stayed");
        runtime.shutdown().await;
    });
}

#[test]
fn a_slow_frontend_gets_a_fresh_restore_instead_of_unbounded_output() {
    local(async {
        let runtime = Runtime::new();
        let agent = script(
            runtime.dir.path(),
            "flood",
            "read line\nhead -c 6000000 /dev/zero | tr '\\0' 'x'\nprintf '\\r\\nFLOOD DONE\\r\\n'\nexec cat",
        );
        let mut client = runtime.client().await;
        client
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut client).await;
        client
            .send(&ClientMsg::Attach {
                session_id: session.id.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        let mut view = View::new();
        let message = expect(&mut client, |m| {
            matches!(m, RuntimeMsg::Attached { .. }).then_some(m)
        })
        .await;
        view.apply(&message);
        client
            .send(&ClientMsg::input(&session.id, b"go\r"))
            .await
            .unwrap();
        // Don't read while the agent floods.
        tokio::time::sleep(Duration::from_secs(3)).await;
        view.until(&mut client, "FLOOD DONE").await;
        assert!(
            view.restores >= 2,
            "no fresh restore after the backlog overflowed"
        );
        assert!(
            view.output.len() < 6_000_000,
            "every byte was queued: {}",
            view.output.len()
        );
        runtime.shutdown().await;
    });
}

#[test]
fn input_is_never_dropped_while_the_pty_queue_is_full() {
    local(async {
        let runtime = Runtime::new();
        // Raw, no echo: the agent reads nothing for two seconds, then echoes it all.
        let agent = script(
            runtime.dir.path(),
            "sleepy",
            "stty raw -echo\nprintf 'SLEEPING\\r\\n'\nsleep 2\nexec cat",
        );
        let mut client = runtime.client().await;
        client
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut client).await;
        client
            .send(&ClientMsg::Attach {
                session_id: session.id.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        let mut view = View::new();
        view.until(&mut client, "SLEEPING").await;
        let count = 300;
        let writer = async {
            for i in 0..count {
                let mut chunk = format!("M{i:04}").into_bytes();
                chunk.resize(1000, b'.');
                chunk.extend_from_slice(b"\r\n");
                client
                    .send(&ClientMsg::input(&session.id, &chunk))
                    .await
                    .unwrap();
            }
            client
        };
        let mut client = tokio::time::timeout(Duration::from_secs(30), writer)
            .await
            .expect("the runtime kept reading");
        let last = format!("M{:04}", count - 1);
        let found = tokio::time::timeout(Duration::from_secs(20), async {
            while !String::from_utf8_lossy(&view.output).contains(&last) {
                let message = client.recv().await.unwrap().expect("closed");
                view.apply(&message);
                if let RuntimeMsg::Error { text, .. } = &message {
                    panic!("input refused: {text}");
                }
            }
        })
        .await;
        assert!(found.is_ok(), "the last input never arrived");
        let output = String::from_utf8_lossy(&view.output).to_string();
        for i in 0..count {
            assert!(
                output.contains(&format!("M{i:04}")),
                "input {i} was dropped"
            );
        }
        runtime.shutdown().await;
    });
}

/// A raw connection to `socket`: write `line`, read every reply line until EOF.
async fn raw_exchange(socket: &Path, lines: &[&str]) -> Vec<RuntimeMsg> {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let (read, mut write) = stream.into_split();
    for line in lines {
        write.write_all(line.as_bytes()).await.unwrap();
        write.write_all(b"\n").await.unwrap();
    }
    let mut reader = BufReader::new(read);
    let mut replies = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
            replies.push(decode_runtime(&line).unwrap());
            line.clear();
        }
    })
    .await
    .expect("the runtime didn't close the connection");
    replies
}

#[test]
fn hello_comes_first_and_another_protocol_is_refused() {
    local(async {
        let runtime = Runtime::new();
        let replies = raw_exchange(&runtime.socket, &[r#"{"v":1,"op":"list"}"#]).await;
        assert!(
            matches!(&replies[..], [RuntimeMsg::Error { text, .. }] if text.contains("hello")),
            "{replies:?}"
        );
        // Another protocol while a session lives: refused, the runtime stays.
        let agent = echo_agent(runtime.dir.path());
        let mut client = runtime.client().await;
        client
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        launched(&mut client).await;
        let replies = raw_exchange(
            &runtime.socket,
            &[r#"{"v":1,"op":"hello","protocol":2,"build":"other"}"#],
        )
        .await;
        assert!(
            matches!(&replies[..], [RuntimeMsg::Error { text, .. }] if text.contains("stop your sessions")),
            "{replies:?}"
        );
        client.send(&ClientMsg::List).await.unwrap();
        expect(&mut client, |m| {
            matches!(m, RuntimeMsg::Sessions { .. }).then_some(())
        })
        .await;
        runtime.shutdown().await;
    });
}

#[test]
fn another_protocol_restarts_a_runtime_without_sessions() {
    local(async {
        let mut runtime = Runtime::new();
        let replies = raw_exchange(
            &runtime.socket,
            &[r#"{"v":1,"op":"hello","protocol":2,"build":"other"}"#],
        )
        .await;
        assert!(
            matches!(&replies[..], [RuntimeMsg::Error { text, .. }] if text.contains(super::client::RESTARTING)),
            "{replies:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), &mut runtime.server)
            .await
            .expect("the runtime exits for the restart")
            .unwrap()
            .unwrap();
    });
}

#[test]
fn a_peer_of_another_user_is_dropped() {
    local(async {
        // The listener expects another uid than ours: we look like a stranger.
        let runtime = Runtime::start(Duration::from_secs(600), own_uid() + 1);
        let replies = raw_exchange(
            &runtime.socket,
            &[r#"{"v":1,"op":"hello","protocol":1,"build":"x"}"#],
        )
        .await;
        assert!(replies.is_empty(), "{replies:?}");
        runtime.shutdown().await;
    });
}

#[test]
fn an_idle_runtime_exits_and_a_client_keeps_it_up() {
    local(async {
        let mut runtime = Runtime::start(Duration::from_secs(1), own_uid());
        let client = runtime.client().await;
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(
            !runtime.server.is_finished(),
            "exited with a client connected"
        );
        drop(client);
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), &mut runtime.server)
            .await
            .expect("the idle runtime didn't exit")
            .unwrap()
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(900));
    });
}

#[test]
fn connect_or_start_starts_a_runtime_when_none_answers() {
    local(async {
        let dir = short_dir();
        let locator = super::client::Locator {
            socket: dir.path().join("rt.sock"),
            record: dir.path().join("runtime.socket"),
            log: dir.path().join("runtime.log"),
        };
        let socket = locator.socket.clone();
        let root = dir.path().to_path_buf();
        // Kept until the end: dropping it stops the server.
        let (_stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let stopped = std::cell::RefCell::new(Some(stopped));
        let start = || {
            let stopped = stopped.borrow_mut().take().expect("started once");
            let listener = tokio::net::UnixListener::bind(&socket)?;
            tokio::task::spawn_local(serve(
                app(&root),
                listener,
                Options {
                    idle: Duration::from_secs(600),
                    uid: own_uid(),
                    launcher: launcher(&root),
                },
                async {
                    let _ = stopped.await;
                },
            ));
            Ok(())
        };
        assert!(
            RuntimeClient::existing_at(&locator)
                .await
                .unwrap()
                .is_none(),
            "nothing runs yet"
        );
        let client = RuntimeClient::connect_or_start_with(&locator, start, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(client.welcome.pid, std::process::id());
        assert!(
            RuntimeClient::existing_at(&locator)
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn the_runtime_environment_is_sanitized() {
    use std::ffi::OsString;
    let vars = [
        ("PATH", "/bin"),
        ("HOME", "/home/u"),
        ("XDG_RUNTIME_DIR", "/run/user/1"),
        ("ATEM_TERMINAL_PREFIX", "C-a"),
        ("ASTATION_WS", "ws://x"),
        ("RUST_LOG", "debug"),
        ("ANTHROPIC_API_KEY", "secret"),
        ("CLAUDE_CLI_BIN", "/x"),
        ("SSH_AUTH_SOCK", "/tmp/a"),
    ]
    .map(|(k, v)| (OsString::from(k), OsString::from(v)));
    let kept: Vec<String> = super::client::runtime_env_from(vars.into_iter())
        .into_iter()
        .map(|(k, _)| k.into_string().unwrap())
        .collect();
    assert_eq!(
        kept,
        [
            "PATH",
            "HOME",
            "XDG_RUNTIME_DIR",
            "ATEM_TERMINAL_PREFIX",
            "ASTATION_WS",
            "RUST_LOG"
        ]
    );
}

async fn list(client: &mut RuntimeClient) -> Vec<SessionSummary> {
    client.send(&ClientMsg::List).await.unwrap();
    expect(client, |m| match m {
        RuntimeMsg::Sessions { sessions } => Some(sessions),
        _ => None,
    })
    .await
}

async fn attach(client: &mut RuntimeClient, sid: &str) -> View {
    client
        .send(&ClientMsg::Attach {
            session_id: sid.into(),
            rows: 24,
            cols: 80,
        })
        .await
        .unwrap();
    let mut view = View::new();
    let message = expect(client, |m| match m {
        RuntimeMsg::Attached { .. } => Some(m),
        RuntimeMsg::Error { text, .. } => panic!("attach failed: {text}"),
        _ => None,
    })
    .await;
    view.apply(&message);
    view
}

fn record_file(runtime: &Runtime, sid: &str) -> PathBuf {
    super::worker::record_path(&runtime.state(), sid)
}

/// `done` holds within `secs` (polled without blocking the in-process workers).
async fn within(secs: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[test]
fn launch_runs_the_session_in_a_worker_that_records_it() {
    local(async {
        let runtime = Runtime::new();
        let agent = echo_agent(runtime.dir.path());
        let mut client = runtime.client().await;
        client
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut client).await;
        assert_eq!(session.state, "running");
        let record = super::worker::read_record(&record_file(&runtime, &session.id)).unwrap();
        assert_eq!(record.session_id, session.id);
        assert_eq!(record.process_gen, session.generation);
        assert_eq!(record.provider, "codex");
        assert!(record.agent_pid.is_some());
        // The record holds no environment.
        let text = std::fs::read_to_string(record_file(&runtime, &session.id)).unwrap();
        assert!(!text.contains("CODEX_CLI_BIN"), "{text}");
        runtime.shutdown().await;
    });
}

#[test]
fn a_new_broker_adopts_the_running_session_and_attach_restores_it() {
    local(async {
        let first = Runtime::new();
        let agent = echo_agent(first.dir.path());
        let mut client = first.client().await;
        client
            .send(&first.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut client).await;
        let mut view = attach(&mut client, &session.id).await;
        view.until(&mut client, "READY one").await;
        client
            .send(&ClientMsg::input(&session.id, b"before restart\r"))
            .await
            .unwrap();
        view.until(&mut client, "before restart").await;
        drop(client);
        let dir = first.dir.clone();
        first.shutdown().await;

        // The worker outlived the broker: the next one adopts it.
        let second = Runtime::start_in(dir, "rt2.sock", Duration::from_secs(600), own_uid());
        let mut client = second.client().await;
        let sessions = list(&mut client).await;
        assert_eq!(sessions.len(), 1);
        let adopted = &sessions[0];
        assert_eq!(
            (adopted.id.as_str(), adopted.state.as_str()),
            (session.id.as_str(), "running")
        );
        assert_eq!(adopted.generation, session.generation);
        assert_eq!(adopted.provider, "codex");
        assert_eq!(adopted.created_at_ms, session.created_at_ms);
        let mut view = attach(&mut client, &session.id).await;
        // The restore is the worker's screen, from before the restart.
        assert!(
            view.screen.screen().contents().contains("before restart"),
            "{}",
            view.screen.screen().contents()
        );
        client
            .send(&ClientMsg::input(&session.id, b"after restart\r"))
            .await
            .unwrap();
        view.until(&mut client, "after restart").await;
        // Stop ends the worker: its record goes.
        client
            .send(&ClientMsg::Stop {
                session_id: session.id.clone(),
            })
            .await
            .unwrap();
        expect(&mut client, |m| {
            matches!(m, RuntimeMsg::Exited { .. }).then_some(())
        })
        .await;
        let record = record_file(&second, &session.id);
        assert!(within(10, || !record.exists()).await, "the record stayed");
        second.shutdown().await;
    });
}

#[test]
fn an_adopted_worker_whose_agent_exited_is_released_and_its_record_removed() {
    local(async {
        let first = Runtime::new();
        let agent = script(
            first.dir.path(),
            "quitter",
            "printf 'READY\\r\\n'\nread line\nsleep 1\nexit 3",
        );
        let mut client = first.client().await;
        client
            .send(&first.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut client).await;
        let mut view = attach(&mut client, &session.id).await;
        view.until(&mut client, "READY").await;
        client
            .send(&ClientMsg::input(&session.id, b"bye\r"))
            .await
            .unwrap();
        view.until(&mut client, "bye").await;
        drop(client);
        let dir = first.dir.clone();
        first.shutdown().await;
        // The agent exits with no broker: the worker records it and waits.
        let record = super::worker::record_path(&dir.path().join("state"), &session.id);
        assert!(
            within(10, || super::worker::read_record(&record)
                .is_ok_and(|r| r.exited.is_some()))
            .await,
            "the exit was never recorded"
        );

        let second = Runtime::start_in(dir, "rt2.sock", Duration::from_secs(600), own_uid());
        let mut client = second.client().await;
        let sessions = list(&mut client).await;
        assert_eq!(sessions[0].state, "exited");
        assert_eq!(sessions[0].id, session.id);
        assert!(sessions[0].exited.is_some());
        // Released: the worker removed its record and ended.
        assert!(within(10, || !record.exists()).await, "the record stayed");
        second.shutdown().await;
    });
}

#[test]
fn a_record_without_its_worker_is_listed_interrupted_and_stop_removes_it() {
    local(async {
        let runtime = Runtime::new();
        let sid = crate::session::SessionId::new().to_string();
        // A worker pid that is gone.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let record = super::worker_protocol::WorkerRecord {
            session_id: sid.clone(),
            process_gen: uuid::Uuid::new_v4().to_string(),
            provider: "claude".into(),
            cwd: runtime.dir.path().to_path_buf(),
            created_at_ms: 1,
            socket: runtime.dir.path().join("gone.sock"),
            worker_pid: pid,
            start_time: 1,
            agent_pid: None,
            agent_start_time: None,
            exited: None,
        };
        super::worker::write_record(&runtime.state(), &record).unwrap();
        // This broker already scanned at start: another one adopts it.
        let dir = runtime.dir.clone();
        runtime.shutdown().await;
        let runtime = Runtime::start_in(dir, "rt2.sock", Duration::from_secs(600), own_uid());
        let mut client = runtime.client().await;
        let sessions = list(&mut client).await;
        assert_eq!(
            (sessions[0].id.as_str(), sessions[0].state.as_str()),
            (sid.as_str(), "interrupted")
        );
        assert_eq!(sessions[0].provider, "claude");
        client
            .send(&ClientMsg::Attach {
                session_id: sid.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        expect(&mut client, |m| match m {
            RuntimeMsg::Error { op, text } => {
                assert_eq!(op.as_deref(), Some("attach"));
                assert!(text.contains("interrupted"), "{text}");
                Some(())
            }
            _ => None,
        })
        .await;
        client
            .send(&ClientMsg::Stop {
                session_id: sid.clone(),
            })
            .await
            .unwrap();
        expect(&mut client, |m| match m {
            RuntimeMsg::Notice { text } if text.starts_with("Removed") => Some(()),
            _ => None,
        })
        .await;
        assert!(!record_file(&runtime, &sid).exists());
        assert!(list(&mut client).await.is_empty());
        runtime.shutdown().await;
    });
}

#[test]
fn two_sessions_run_concurrently_each_in_its_own_worker() {
    local(async {
        let runtime = Runtime::new();
        let agent = echo_agent(runtime.dir.path());
        let mut one = runtime.client().await;
        let mut two = runtime.client().await;
        one.send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        two.send(&runtime.launch("claude", "two", &agent))
            .await
            .unwrap();
        let (first, second) = (launched(&mut one).await, launched(&mut two).await);
        let records = [&first, &second]
            .map(|s| super::worker::read_record(&record_file(&runtime, &s.id)).unwrap());
        assert_ne!(records[0].agent_pid, records[1].agent_pid);
        let mut view_one = attach(&mut one, &first.id).await;
        let mut view_two = attach(&mut two, &second.id).await;
        view_one.until(&mut one, "READY one").await;
        view_two.until(&mut two, "READY two").await;
        one.send(&ClientMsg::input(&first.id, b"to the first\r"))
            .await
            .unwrap();
        two.send(&ClientMsg::input(&second.id, b"to the second\r"))
            .await
            .unwrap();
        view_one.until(&mut one, "to the first").await;
        view_two.until(&mut two, "to the second").await;
        assert!(
            !view_one
                .screen
                .screen()
                .contents()
                .contains("to the second")
        );
        assert!(!view_two.screen.screen().contents().contains("to the first"));
        runtime.shutdown().await;
    });
}

/// A worker this test plays: its record (this process's pid and start time,
/// so adoption verifies it) and its socket, speaking the worker protocol.
struct FakeWorker {
    sid: String,
    /// Raw lines to send; an empty one closes the connection.
    lines: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// What the broker sent.
    heard: tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
}

impl FakeWorker {
    /// Records a running worker in `root`'s state dir (adopted by the next
    /// broker there) whose output stream is at `offset`.
    fn start(root: &Path, offset: u64) -> Self {
        use super::worker_protocol::{WorkerMsg, WorkerRecord, encode_worker};
        let sid = crate::session::SessionId::new().to_string();
        let process_gen = uuid::Uuid::new_v4().to_string();
        let socket = root.join("ws").join(format!("{sid}.sock"));
        let listener = super::worker::listen(&socket).unwrap();
        let pid = std::process::id();
        let start_time = super::adopt::process_start_time(pid).unwrap();
        let record = WorkerRecord {
            session_id: sid.clone(),
            process_gen: process_gen.clone(),
            provider: "codex".into(),
            cwd: root.to_path_buf(),
            created_at_ms: 7,
            socket,
            worker_pid: pid,
            start_time,
            agent_pid: None,
            agent_start_time: None,
            exited: None,
        };
        super::worker::write_record(&root.join("state"), &record).unwrap();
        let hello = encode_worker(&WorkerMsg::Hello {
            session_id: sid.clone(),
            process_gen,
            pid,
            start_time,
            agent_pid: None,
            offset,
            input_epoch: 0,
            dropped: 0,
            exited: None,
        });
        let (lines, mut to_send) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (heard_tx, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::task::spawn_local(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            write.write_all(hello.as_bytes()).await.unwrap();
            let mut reader = BufReader::new(read);
            let mut line = String::new();
            loop {
                tokio::select! {
                    next = to_send.recv() => match next {
                        Some(bytes) if !bytes.is_empty() => {
                            if write.write_all(&bytes).await.is_err() {
                                return;
                            }
                        }
                        _ => return,
                    },
                    read = reader.read_line(&mut line) => {
                        if !matches!(read, Ok(n) if n > 0) {
                            return;
                        }
                        let _ = heard_tx.send(serde_json::from_str(&line).unwrap());
                        line.clear();
                    }
                }
            }
        });
        Self { sid, lines, heard }
    }

    fn send(&self, message: &super::worker_protocol::WorkerMsg) {
        let line = super::worker_protocol::encode_worker(message);
        self.lines.send(line.into_bytes()).unwrap();
    }

    fn screen(&self, text: &str, offset: u64, rows: u16, cols: u16) {
        self.send(&super::worker_protocol::WorkerMsg::Screen {
            restore: super::worker_protocol::b64(format!("\x1bc{text}").as_bytes()),
            offset,
            rows,
            cols,
        });
    }

    fn output(&self, text: &str, offset: u64) {
        self.send(&super::worker_protocol::WorkerMsg::output(
            text.as_bytes(),
            offset,
        ));
    }

    /// Closes the connection (the worker "process", this one, still runs).
    fn close(&self) {
        let _ = self.lines.send(Vec::new());
    }

    /// The broker's next message with `op` (others skipped), within 10 s.
    async fn heard(&mut self, op: &str) -> serde_json::Value {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let message = self.heard.recv().await.expect("the broker closed");
                if message["op"] == op {
                    return message;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the broker never sent {op}"))
    }
}

/// A runtime started on `dir` after `prepare` put fake workers there.
fn runtime_on(dir: std::rc::Rc<tempfile::TempDir>) -> Runtime {
    Runtime::start_in(dir, "rt.sock", Duration::from_secs(600), own_uid())
}

#[test]
fn list_waits_for_adoption_and_attach_before_the_screen_gets_the_exit_if_the_worker_goes() {
    local(async {
        let dir = std::rc::Rc::new(short_dir());
        let fake = FakeWorker::start(dir.path(), 100);
        let runtime = runtime_on(dir);
        let mut client = runtime.client().await;
        // Held until adoption finished: the adopted session is there.
        let sessions = list(&mut client).await;
        assert_eq!(sessions.len(), 1, "{sessions:?}");
        assert_eq!(sessions[0].state, "running");
        client
            .send(&ClientMsg::Attach {
                session_id: fake.sid.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        // No screen yet; the worker goes away: the frontend hears of it.
        tokio::time::sleep(Duration::from_millis(200)).await;
        fake.close();
        let status = expect(&mut client, |m| match m {
            RuntimeMsg::Exited { status, .. } => Some(status),
            RuntimeMsg::Attached { .. } => panic!("restored without a screen"),
            _ => None,
        })
        .await;
        assert_eq!(status, "interrupted");
        runtime.shutdown().await;
    });
}

#[test]
fn an_adopted_session_takes_the_frontend_size_once_its_screen_arrives() {
    local(async {
        let dir = std::rc::Rc::new(short_dir());
        let mut fake = FakeWorker::start(dir.path(), 100);
        let runtime = runtime_on(dir);
        let mut client = runtime.client().await;
        fake.heard("request_screen").await;
        client
            .send(&ClientMsg::Attach {
                session_id: fake.sid.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        // Unsynced: forwarded even though it equals the placeholder size.
        let resize = fake.heard("resize").await;
        assert_eq!(
            (resize["rows"].as_u64(), resize["cols"].as_u64()),
            (Some(24), Some(80))
        );
        // The screen arrives at the worker's own (old) size: the frontend's
        // size is applied again, and the restore has it.
        fake.screen("WIDE", 100, 50, 200);
        let resize = fake.heard("resize").await;
        assert_eq!(
            (resize["rows"].as_u64(), resize["cols"].as_u64()),
            (Some(24), Some(80))
        );
        let (session, restore, _) = attached(&mut client).await;
        assert_eq!((session.rows, session.cols), (24, 80));
        assert!(String::from_utf8_lossy(&restore).contains("WIDE"));
        runtime.shutdown().await;
    });
}

#[test]
fn an_output_gap_asks_for_the_screen_and_resyncs_the_frontend() {
    local(async {
        let dir = std::rc::Rc::new(short_dir());
        let mut fake = FakeWorker::start(dir.path(), 0);
        let runtime = runtime_on(dir);
        let mut client = runtime.client().await;
        fake.heard("request_screen").await;
        fake.screen("FIRST", 0, 24, 80);
        let mut view = attach(&mut client, &fake.sid).await;
        assert!(view.screen.screen().contents().contains("FIRST"));
        fake.output(" more", 0);
        view.until(&mut client, "FIRST more").await;
        // Bytes 5..100 never came: the broker asks for the screen again.
        fake.output("lost", 100);
        fake.heard("request_screen").await;
        fake.screen("RESYNCED", 200, 24, 80);
        let (_, restore, offset) = attached(&mut client).await;
        assert!(String::from_utf8_lossy(&restore).contains("RESYNCED"));
        assert_eq!(offset, 200);
        runtime.shutdown().await;
    });
}

#[test]
fn stop_after_the_worker_went_away_names_a_worker_that_still_runs() {
    local(async {
        let dir = std::rc::Rc::new(short_dir());
        let mut fake = FakeWorker::start(dir.path(), 0);
        let runtime = runtime_on(dir);
        let mut client = runtime.client().await;
        fake.heard("request_screen").await;
        fake.close();
        let deadline = Instant::now() + Duration::from_secs(10);
        while list(&mut client).await[0].state != "interrupted" {
            assert!(Instant::now() < deadline, "never interrupted");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        client
            .send(&ClientMsg::Stop {
                session_id: fake.sid.clone(),
            })
            .await
            .unwrap();
        // The recorded worker pid (this process) still runs: named, kept.
        let text = expect(&mut client, |m| match m {
            RuntimeMsg::Notice { text } => Some(text),
            RuntimeMsg::Error { text, .. } => Some(text),
            _ => None,
        })
        .await;
        assert!(text.contains(&std::process::id().to_string()), "{text}");
        assert!(record_file(&runtime, &fake.sid).exists());
        assert_eq!(list(&mut client).await.len(), 1);
        runtime.shutdown().await;
    });
}

#[test]
fn an_undecodable_worker_line_is_an_error_and_reading_goes_on() {
    local(async {
        let dir = short_dir();
        let mut fake = FakeWorker::start(dir.path(), 0);
        let record = super::worker::read_record(&super::worker::record_path(
            &dir.path().join("state"),
            &fake.sid,
        ))
        .unwrap();
        let expect_hello = super::adopt::Expect {
            session_id: record.session_id.clone(),
            process_gen: record.process_gen.clone(),
            pid: record.worker_pid,
            start_time: Some(record.start_time),
        };
        let mut handle = super::adopt::WorkerHandle::connect(&record.socket, &expect_hello, None)
            .await
            .unwrap();
        fake.lines.send(b"\xff\xfe not text\n".to_vec()).unwrap();
        fake.output("still here", 0);
        let first = tokio::time::timeout(Duration::from_secs(5), handle.recv())
            .await
            .unwrap();
        assert!(
            matches!(first, Some(super::worker_protocol::WorkerMsg::Error { .. })),
            "{first:?}"
        );
        let second = tokio::time::timeout(Duration::from_secs(5), handle.recv())
            .await
            .unwrap();
        assert!(
            matches!(
                second,
                Some(super::worker_protocol::WorkerMsg::Output { .. })
            ),
            "{second:?}"
        );
        drop(fake.heard.try_recv());
    });
}

#[test]
fn reclaim_tells_the_frontend_its_queued_input_was_dropped() {
    local(async {
        let runtime = Runtime::new();
        // Raw, no echo: reads nothing for two seconds.
        let agent = script(
            runtime.dir.path(),
            "sleepy",
            "stty raw -echo\nprintf 'SLEEPING\\r\\n'\nsleep 2\nexec cat",
        );
        let mut client = runtime.client().await;
        client
            .send(&runtime.launch("codex", "one", &agent))
            .await
            .unwrap();
        let session = launched(&mut client).await;
        let mut view = attach(&mut client, &session.id).await;
        view.until(&mut client, "SLEEPING").await;
        for _ in 0..20 {
            client
                .send(&ClientMsg::input(&session.id, &[b'a'; 16 * 1024]))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        client
            .send(&ClientMsg::Reclaim {
                session_id: session.id.clone(),
            })
            .await
            .unwrap();
        let text = expect(&mut client, |m| match m {
            RuntimeMsg::Notice { text } if text.contains("dropped") => Some(text),
            _ => None,
        })
        .await;
        assert!(
            text.contains("typed bytes were dropped when control changed"),
            "{text}"
        );
        runtime.shutdown().await;
    });
}

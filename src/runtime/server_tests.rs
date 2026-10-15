//! The runtime's server in this process: a temp socket, fake agents (sh
//! scripts) and the async client.
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
    dir: tempfile::TempDir,
    socket: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Runtime {
    /// A server for a fresh App on a temp socket (call inside `local`).
    fn start(idle: Duration, uid: u32) -> Self {
        let dir = short_dir();
        let socket = dir.path().join("rt.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let app = app(dir.path());
        let server = tokio::task::spawn_local(serve(app, listener, Options { idle, uid }, async {
            let _ = stopped.await;
        }));
        Self {
            dir,
            socket,
            stop: Some(stop),
            server,
        }
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

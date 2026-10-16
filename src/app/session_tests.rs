//! Several sessions in one App: session ids, launch cwd/env, terminal addressing,
//! reaping and per-session logs.
use super::{App, AppMode};
use crate::agent_client::AgentKind;
use crate::pty_session::{PtyInput, TestInputReader};
use crate::session::{EXITED_KEEP, LaunchRequest, Provider, Session, SessionId, Sessions};
use crate::terminal_share::Message;
use crate::websocket_client::AstationMessage;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// An App whose agents are `cat`, with chat, logs and chat directories under a
/// temp dir. Claude gets no chat (its directory can't be created), so it stays `cat`.
fn app() -> (App, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"").unwrap();
    let mut app = App::new();
    app.chat_root = root.path().join("file/run");
    app.logs_dir = root.path().join("logs");
    app.claude_client
        .set_command_for_test("cat".into(), Vec::new());
    app.codex_client
        .set_command_for_test("cat".into(), Vec::new());
    (app, root)
}

fn dir(root: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = root.path().join(name);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn request(provider: Provider, cwd: &Path) -> LaunchRequest {
    LaunchRequest {
        provider,
        args: Vec::new(),
        cwd: cwd.to_path_buf(),
        env: None,
        rows: 24,
        cols: 80,
    }
}

/// A live session writing to a test channel, used `offset` seconds from now. It
/// has no process on purpose: routing only needs a live session's input.
fn test_session(
    app: &mut App,
    provider: Provider,
    cwd: &Path,
    offset: u64,
) -> (SessionId, TestInputReader) {
    let (input, reader) = PtyInput::test_channel();
    let mut session = Session::new(provider, 24, 80);
    session.input = Some(input);
    session.cwd = cwd.to_path_buf();
    session.last_used = Instant::now() + Duration::from_secs(offset);
    let id = app.sessions.insert(session).unwrap().id.clone();
    (id, reader)
}

fn written(reader: &mut TestInputReader) -> String {
    std::iter::from_fn(|| reader.try_recv().ok()).collect()
}

fn status(app: &App) -> String {
    app.status_message.clone().unwrap_or_default()
}

async fn wait_for_screen(app: &mut App, id: &SessionId, text: &str) {
    let found = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            app.process_sessions_output();
            let session = app.sessions.get(id).unwrap();
            if session.terminal.screen().contents().contains(text) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let screen = app.sessions.get(id).unwrap().terminal.screen().contents();
    assert!(found.is_ok(), "{text:?} not on the screen: {screen:?}");
}

#[tokio::test]
async fn sessions_have_their_own_ids_in_the_agent_list() {
    let (mut app, root) = app();
    let (a, b) = (dir(&root, "a"), dir(&root, "b"));
    let first = app
        .launch_session(request(Provider::Claude, &a))
        .await
        .unwrap();
    let second = app
        .launch_session(request(Provider::Claude, &b))
        .await
        .unwrap();
    let codex = app
        .launch_session(request(Provider::Codex, &a))
        .await
        .unwrap();
    let ids = [first.clone(), second.clone(), codex.clone()];
    assert_ne!(first, second);
    for id in &ids {
        assert_eq!(SessionId::parse(id.as_str()).as_ref(), Some(id));
    }
    assert_eq!(app.sessions.get(&first).unwrap().cwd, a);
    assert_eq!(app.sessions.get(&second).unwrap().cwd, b);

    let agents = app.agent_registry.all();
    let listed: Vec<&str> = agents.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(listed, ids.iter().map(|id| id.as_str()).collect::<Vec<_>>());
    let kinds: Vec<AgentKind> = agents.iter().map(|a| a.kind.clone()).collect();
    assert_eq!(
        kinds,
        [
            AgentKind::ClaudeCode,
            AgentKind::ClaudeCode,
            AgentKind::Codex
        ]
    );
    let names: Vec<&str> = agents.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["claude-code", "claude-code", "codex"]);
}

#[tokio::test]
async fn the_tui_refuses_remote_terminal_requests_without_effect() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (mut app, root) = app();
    let a = dir(&root, "a");
    let id = app
        .launch_session(request(Provider::Codex, &a))
        .await
        .unwrap();
    let _rx = astation(&mut app).await;
    app.astation_connected = true;
    let generation = app.sessions.get(&id).unwrap().share.generation.clone();
    let requests = [
        Message::Subscribe {
            terminal_id: id.to_string(),
            generation: generation.clone(),
        },
        Message::Input {
            terminal_id: id.to_string(),
            generation: generation.clone(),
            stream_id: "s".into(),
            sequence: 0,
            bytes: STANDARD.encode(b"REMOTE\n"),
        },
        Message::Resize {
            terminal_id: id.to_string(),
            generation: generation.clone(),
            stream_id: "s".into(),
            rows: 30,
            cols: 90,
        },
        Message::Stop {
            terminal_id: id.to_string(),
            generation: generation.clone(),
            stream_id: "s".into(),
        },
    ];
    for request in requests {
        let text = serde_json::to_string(&AstationMessage::Terminal(request.into())).unwrap();
        app.handle_astation_message(AstationMessage::SessionWire(text))
            .await;
    }
    // No effect: nothing was typed, the size is the local one and the process
    // still answers local input.
    let session = app.sessions.get(&id).unwrap();
    assert!(!session.input.as_ref().unwrap().remote_controlled());
    assert_eq!(session.terminal.screen().size(), (24, 80));
    app.send_data(&id, "local\n");
    wait_for_screen(&mut app, &id, "local").await;
    let screen = app.sessions.get(&id).unwrap().terminal.screen().contents();
    assert!(!screen.contains("REMOTE"), "{screen:?}");
    assert!(app.sessions.get(&id).unwrap().is_live());
}

#[test]
fn removed_remote_ops_do_not_parse() {
    for json in [
        r#"{"type":"agentInput","data":{"kind":"text","text":"hi"}}"#,
        r#"{"type":"agentPrompt","data":{"agent_id":"ses-aaaaaaaaaaaa","session_id":"s","text":"hi"}}"#,
        r#"{"type":"userCommand","data":{"command":"ls","context":{}}}"#,
        r#"{"type":"voiceCommand","data":{"text":"hi","is_final":true}}"#,
        r#"{"type":"voice_toggle","data":{"active":false}}"#,
        r#"{"type":"voiceRequest","data":{"session_id":"s","accumulated_text":"hi","relay_url":"https://r"}}"#,
        r#"{"type":"codexTaskResponse","data":{"output":"o","success":true,"timestamp":"0"}}"#,
        r#"{"type":"terminal","data":{"v":1,"op":"list"}}"#,
        r#"{"type":"terminal","data":{"v":1,"op":"control","terminal_id":"ses-aaaaaaaaaaaa","generation":"g","stream_id":"s","take":true}}"#,
    ] {
        assert!(
            serde_json::from_str::<AstationMessage>(json).is_err(),
            "{json} still parses"
        );
    }
}

#[test]
fn local_paste_counts_as_use_only_when_written() {
    let (mut app, root) = app();
    let (id, mut rx) = test_session(&mut app, Provider::Claude, root.path(), 0);
    app.focused = Some(id.clone());
    app.mode = AppMode::Terminal;
    let before = app.sessions.get(&id).unwrap().last_used;
    let input = app.sessions.get(&id).unwrap().input.clone().unwrap();
    input.set_remote(true);
    app.terminal_paste("refused");
    assert_eq!(app.sessions.get(&id).unwrap().last_used, before);
    assert_eq!(written(&mut rx), "");
    input.set_remote(false);
    app.terminal_paste("pasted");
    assert!(app.sessions.get(&id).unwrap().last_used > before);
    assert!(written(&mut rx).contains("pasted"));
}

#[tokio::test]
async fn a_failed_launch_is_returned_and_never_stored() {
    let (mut app, root) = app();
    app.codex_client
        .set_command_for_test("/nonexistent/atem-agent".into(), Vec::new());
    let error = app
        .launch_session(request(Provider::Codex, root.path()))
        .await;
    assert!(error.is_err());
    assert_eq!(app.sessions.iter().count(), 0);
    assert!(app.agent_registry.all().is_empty());
    // The menu shows the error as a status message.
    app.launch_from_menu(Provider::Codex).await;
    assert!(
        status(&app).contains("Unable to start Codex CLI"),
        "{}",
        status(&app)
    );
    assert_eq!(app.sessions.iter().count(), 0);
    assert!(!matches!(app.mode, AppMode::Terminal));
}

#[tokio::test]
async fn the_menu_resumes_the_latest_live_session_and_launches_after_exit() {
    let (mut app, _root) = app();
    app.launch_from_menu(Provider::Codex).await;
    let first = app.focused.clone().unwrap();
    assert!(matches!(app.mode, AppMode::Terminal));
    app.leave_terminal_view();
    app.launch_from_menu(Provider::Codex).await;
    assert_eq!(app.focused.as_ref(), Some(&first));
    assert_eq!(app.sessions.iter().count(), 1);
    app.stop_session(&first);
    tokio::time::timeout(Duration::from_secs(5), async {
        while app.sessions.get(&first).unwrap().is_live() {
            app.process_sessions_output();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    app.launch_from_menu(Provider::Codex).await;
    let second = app.focused.clone().unwrap();
    assert_ne!(second, first);
    assert_eq!(
        app.sessions.iter().count(),
        2,
        "the exited session stays until reaped"
    );
}

#[tokio::test]
async fn a_launch_beyond_16_live_sessions_is_refused_before_spawning() {
    let (mut app, root) = app();
    let marker = root.path().join("spawned");
    app.codex_client.set_command_for_test(
        "/bin/sh".into(),
        vec!["-c".into(), format!("touch '{}'", marker.display())],
    );
    let mut readers = Vec::new();
    for _ in 0..Sessions::MAX_LIVE {
        readers.push(test_session(&mut app, Provider::Claude, root.path(), 0).1);
    }
    let error = app
        .launch_session(request(Provider::Codex, root.path()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("16"), "{error}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!marker.exists(), "nothing was spawned");
    assert_eq!(app.sessions.iter().count(), Sessions::MAX_LIVE);
    assert!(app.agent_registry.all().is_empty());
}

#[tokio::test]
async fn the_launch_environment_is_bounded_and_used_with_the_working_directory() {
    let (mut app, root) = app();
    let marker = root.path().join("spawned");
    app.codex_client.set_command_for_test(
        "/bin/sh".into(),
        vec!["-c".into(), format!("touch '{}'", marker.display())],
    );
    let mut over = request(Provider::Codex, root.path());
    over.env = Some(
        (0..513)
            .map(|i| (OsString::from(format!("V{i}")), OsString::from("x")))
            .collect(),
    );
    assert!(app.launch_session(over).await.is_err());
    let mut over = request(Provider::Codex, root.path());
    over.env = Some(vec![("BIG".into(), "x".repeat(256 * 1024).into())]);
    assert!(app.launch_session(over).await.is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!marker.exists());
    assert_eq!(app.sessions.iter().count(), 0);

    // CODEX_CLI_BIN/CODEX_CLI_ARGS come from the given environment, not Atem's.
    let script = root.path().join("agent.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf 'from=%s cwd=%s args=%s\\n' \"$ATEM_X\" \"$(pwd)\" \"$*\"\nread line\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let work = dir(&root, "work");
    let mut given = request(Provider::Codex, &work);
    given.args = vec!["--c".into()];
    given.env = Some(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("ATEM_X".into(), "yes".into()),
        ("CODEX_CLI_BIN".into(), script.clone().into()),
        ("CODEX_CLI_ARGS".into(), "--a --b".into()),
    ]);
    let id = app.launch_session(given).await.unwrap();
    let expected = format!(
        "from=yes cwd={} args=--a --b --c",
        work.canonicalize().unwrap().display()
    );
    wait_for_screen(&mut app, &id, &expected).await;
    assert!(!marker.exists(), "Atem's own CODEX_CLI_BIN was not used");
}

#[tokio::test]
async fn exited_sessions_are_reaped_ten_minutes_after_exit() {
    let (mut app, root) = app();
    let stopped = app
        .launch_session(request(Provider::Codex, root.path()))
        .await
        .unwrap();
    let running = app
        .launch_session(request(Provider::Codex, root.path()))
        .await
        .unwrap();
    app.focused = Some(stopped.clone());
    app.stop_session(&stopped);
    tokio::time::timeout(Duration::from_secs(5), async {
        while app.sessions.get(&stopped).unwrap().is_live() {
            app.process_sessions_output();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(app.sessions.get(&running).unwrap().is_live());
    let exited_at = app.sessions.get(&stopped).unwrap().exited_at.unwrap();
    app.reap_exited_sessions(exited_at + EXITED_KEEP - Duration::from_secs(1));
    assert!(app.sessions.get(&stopped).is_some());
    assert!(app.agent_registry.get(stopped.as_str()).is_some());
    app.reap_exited_sessions(exited_at + EXITED_KEEP);
    assert!(app.sessions.get(&stopped).is_none());
    assert!(app.agent_registry.get(stopped.as_str()).is_none());
    assert_eq!(app.focused, None);
    assert!(app.sessions.get(&running).is_some());
    assert!(app.agent_registry.get(running.as_str()).is_some());
}

#[tokio::test]
async fn logs_are_kept_per_session_under_the_logs_directory() {
    let (mut app, root) = app();
    let a = dir(&root, "a");
    let (first, _r1) = test_session(&mut app, Provider::Claude, &a, 0);
    let (second, _r2) = test_session(&mut app, Provider::Claude, &a, 0);
    for (id, text) in [(&first, "first output"), (&second, "second output")] {
        app.sessions.get_mut(id).unwrap().raw_log = text.into();
        app.finalize_session(id);
    }
    for (id, text) in [(&first, "first output"), (&second, "second output")] {
        let session = app.sessions.get(id).unwrap();
        let dir = app.logs_dir.join(id.as_str());
        assert_eq!(
            session.log_file.as_deref(),
            Some(dir.join("session.ansi").as_path())
        );
        assert_eq!(
            session.summary_file.as_deref(),
            Some(dir.join("summary.md").as_path())
        );
        let log = std::fs::read_to_string(dir.join("session.ansi")).unwrap();
        assert!(log.starts_with(text), "{log}");
        let summary = std::fs::read_to_string(dir.join("summary.md")).unwrap();
        assert!(
            summary.starts_with("# Claude Code Session Summary"),
            "{summary}"
        );
        // Private: logs may hold anything the agent printed.
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&app.logs_dir), 0o700);
        assert_eq!(mode(&dir.join("session.ansi")), 0o600);
        assert_eq!(mode(&dir.join("summary.md")), 0o600);
    }
    assert!(!a.join("claude_logs").exists());
}

/// A fake Astation that records what Atem sends.
async fn astation(app: &mut App) -> tokio::sync::mpsc::UnboundedReceiver<AstationMessage> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(frame)) = socket.next().await {
            if let WsMessage::Text(text) = frame
                && let Ok(message) = serde_json::from_str::<AstationMessage>(&text)
            {
                let _ = tx.send(message);
            }
        }
    });
    app.astation_client
        .connect_raw(&format!("ws://{address}"))
        .await
        .unwrap();
    rx
}

async fn mark_result(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AstationMessage>,
) -> (String, bool, String) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(AstationMessage::MarkTaskResult {
                task_id,
                success,
                message,
            }) = rx.recv().await
            {
                return (task_id, success, message);
            }
        }
    })
    .await
    .expect("no markTaskResult")
}

#[tokio::test]
async fn mark_tasks_go_to_the_claude_session_of_their_project() {
    let (mut app, root) = app();
    let mut rx = astation(&mut app).await;
    let (a, b) = (dir(&root, "a"), dir(&root, "b"));
    let (_, mut a_rx) = test_session(&mut app, Provider::Claude, &a, 5);
    let (in_b, mut b_rx) = test_session(&mut app, Provider::Claude, &b, 1);
    let (_, mut codex_rx) = test_session(&mut app, Provider::Codex, &b, 9);
    std::fs::create_dir_all(b.join(".chisel/tasks")).unwrap();
    std::fs::write(b.join(".chisel/tasks/t1.json"), r#"{"title":"Project B"}"#).unwrap();

    app.handle_astation_message(AstationMessage::MarkTaskAssignment {
        task_id: "t1".into(),
        received_at_ms: 0,
    })
    .await;
    let prompt = written(&mut b_rx);
    assert!(prompt.contains("Page title: Project B"), "{prompt}");
    assert!(prompt.ends_with("\n\r"));
    assert_eq!(written(&mut a_rx) + &written(&mut codex_rx), "");
    assert_eq!(app.work_items["t1"].session, in_b);
    assert_eq!(app.work_items["t1"].cwd, b);

    // No live Claude session has the task: it fails at once.
    app.handle_astation_message(AstationMessage::MarkTaskAssignment {
        task_id: "t2".into(),
        received_at_ms: 0,
    })
    .await;
    let (task_id, success, message) = mark_result(&mut rx).await;
    assert_eq!(task_id, "t2");
    assert!(!success);
    assert_eq!(
        message,
        "no Claude session for this project; run `atem agent launch claude` there"
    );
    // A task id is a file name, never a path.
    app.handle_astation_message(AstationMessage::MarkTaskAssignment {
        task_id: "../b/.chisel/tasks/t1".into(),
        received_at_ms: 0,
    })
    .await;
    let (_, success, _) = mark_result(&mut rx).await;
    assert!(!success);
    assert_eq!(written(&mut a_rx) + &written(&mut b_rx), "");
}

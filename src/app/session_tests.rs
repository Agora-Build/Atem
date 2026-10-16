//! The App inside the runtime: removed remote ops, and mark tasks routed to
//! the broker's Claude session of their project.
use super::App;
use super::hosted::{Hosted, HostedSession};
use crate::session::{Provider, SessionId};
use crate::websocket_client::AstationMessage;
use std::path::Path;
use std::time::{Duration, Instant};

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

fn hosted(provider: Provider, cwd: &Path, offset: u64) -> HostedSession {
    HostedSession {
        id: SessionId::new(),
        provider,
        cwd: cwd.to_path_buf(),
        live: true,
        remote_controlled: false,
        last_used: Instant::now() + Duration::from_secs(offset),
    }
}

#[tokio::test]
async fn mark_tasks_go_to_the_claude_session_of_their_project() {
    let _profile = crate::test_profile::temp();
    let root = tempfile::tempdir().unwrap();
    let (a, b) = (root.path().join("a"), root.path().join("b"));
    std::fs::create_dir_all(b.join(".chisel/tasks")).unwrap();
    std::fs::create_dir_all(&a).unwrap();
    std::fs::write(b.join(".chisel/tasks/t1.json"), r#"{"title":"Project B"}"#).unwrap();
    let mut app = App::new();
    let mut rx = astation(&mut app).await;
    let in_b = hosted(Provider::Claude, &b, 1);
    app.hosted = Some(Hosted {
        sessions: vec![
            hosted(Provider::Claude, &a, 5),
            in_b.clone(),
            hosted(Provider::Codex, &b, 9),
        ],
        ..Hosted::default()
    });

    app.handle_astation_message(AstationMessage::MarkTaskAssignment {
        task_id: "t1".into(),
        received_at_ms: 0,
    })
    .await;
    // The broker writes the prompt to the Claude session in project B.
    let writes = std::mem::take(&mut app.hosted.as_mut().unwrap().writes);
    assert_eq!(writes.len(), 1);
    let (task_id, sid, prompt) = &writes[0];
    assert_eq!((task_id.as_str(), sid), ("t1", &in_b.id));
    assert!(prompt.contains("Page title: Project B"), "{prompt}");
    assert!(prompt.ends_with("\n\r"));
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
    assert!(app.hosted.as_ref().unwrap().writes.is_empty());
}

#[test]
fn the_menu_tui_hosts_no_sessions_for_mark_tasks() {
    let _profile = crate::test_profile::temp();
    let app = App::new();
    assert!(app.hosted.is_none());
    assert_eq!(app.mark_task_session("t1"), None);
}

/// A fake Astation that sends what the test queues and records every text
/// frame Atem sends, as JSON.
async fn raw_astation(
    app: &mut App,
) -> (
    tokio::sync::mpsc::UnboundedSender<String>,
    tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        loop {
            tokio::select! {
                frame = socket.next() => match frame {
                    Some(Ok(WsMessage::Text(text))) => {
                        if let Ok(value) = serde_json::from_str(&text) {
                            let _ = in_tx.send(value);
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => return,
                },
                Some(text) = out_rx.recv() => {
                    if socket.send(WsMessage::Text(text)).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    app.astation_client
        .connect_raw(&format!("ws://{address}"))
        .await
        .unwrap();
    app.astation_connected = true;
    (out_tx, in_rx)
}

/// Handles what the App received until `n` messages were handled.
async fn handle_received(app: &mut App, n: usize) {
    let mut handled = 0;
    tokio::time::timeout(Duration::from_secs(3), async {
        while handled < n {
            match app.astation_client.recv_message() {
                Some(message) => {
                    app.handle_astation_message(message).await;
                    handled += 1;
                }
                None => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("handled {handled} of {n} messages"));
}

async fn replies(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    n: usize,
) -> Vec<serde_json::Value> {
    let mut got = Vec::new();
    while got.len() < n {
        match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
            Ok(Some(value)) => got.push(value),
            _ => panic!("got {} of {n} replies: {got:?}", got.len()),
        }
    }
    got
}

const REMOVED_OPS: &[&str] = &[
    r#"{"type":"agentInput","data":{"agent_id":null,"kind":"text","text":"rm -rf x"}}"#,
    r#"{"type":"agentInput","data":{"agent_id":"ses-aaaaaaaaaaaa","kind":"key","key":"enter"}}"#,
    r#"{"type":"agentPrompt","data":{"agent_id":"ses-aaaaaaaaaaaa","session_id":null,"text":"hi"}}"#,
    r#"{"type":"voiceCommand","data":{"text":"run the tests","is_final":true}}"#,
    r#"{"type":"voiceToggle","data":{"active":true}}"#,
    r#"{"type":"voice_toggle","data":{"active":true}}"#,
    r#"{"type":"voiceRequest","data":{"session_id":"s","accumulated_text":"hi","relay_url":"https://r"}}"#,
    r#"{"type":"userCommand","data":{"command":"ls","action":"cli_input"}}"#,
    r#"{"type":"codexTaskRequest","data":{"task":"ls"}}"#,
    r#"{"type":"agentListRequest","data":{}}"#,
];

/// r6 §0: every removed op is answered `unsupported_version` with no effect,
/// in the runtime and in the menu TUI.
#[tokio::test]
async fn removed_ops_are_answered_unsupported_with_no_effect() {
    let _profile = crate::test_profile::temp();
    for in_runtime in [true, false] {
        let mut app = App::new();
        if in_runtime {
            app.hosted = Some(Hosted::default());
        }
        let (tx, mut rx) = raw_astation(&mut app).await;
        for op in REMOVED_OPS {
            tx.send(op.to_string()).unwrap();
        }
        handle_received(&mut app, REMOVED_OPS.len()).await;
        for reply in replies(&mut rx, REMOVED_OPS.len()).await {
            assert_eq!(reply["type"], "session", "{reply}");
            assert_eq!(reply["data"]["op"], "error", "{reply}");
            assert_eq!(reply["data"]["code"], "unsupported_version", "{reply}");
            assert!(reply["data"].get("re").is_none(), "{reply}");
        }
        if let Some(hosted) = &app.hosted {
            assert!(hosted.inbox.is_empty() && hosted.writes.is_empty());
        }
        assert!(app.work_items.is_empty());
    }
}

/// The menu TUI serves no sessions and says where they are served.
#[tokio::test]
async fn the_menu_tui_refers_session_messages_to_the_runtime() {
    let _profile = crate::test_profile::temp();
    let mut app = App::new();
    let (tx, mut rx) = raw_astation(&mut app).await;
    tx.send(
        r#"{"type":"session","data":{"v":1,"op":"list","id":"11111111-1111-4111-8111-000000000001"}}"#
            .into(),
    )
    .unwrap();
    handle_received(&mut app, 1).await;
    let reply = replies(&mut rx, 1).await.remove(0);
    assert_eq!(reply["data"]["op"], "error", "{reply}");
    assert_eq!(reply["data"]["code"], "unsupported_version");
    assert_eq!(reply["data"]["re"], "11111111-1111-4111-8111-000000000001");
    assert_eq!(
        reply["data"]["detail"],
        "sessions are served by atem runtime"
    );
}

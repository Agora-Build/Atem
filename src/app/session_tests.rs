//! The App inside the runtime: removed remote ops and the legacy mark refusal.
use super::App;
use super::hosted::Hosted;
use crate::websocket_client::AstationMessage;
use std::time::Duration;

/// The longest a "wait until" helper waits. A passing run never gets near it;
/// a slow runner (the Intel macOS CI one takes ~340 s for ~45 s of tests) needs
/// the slack, and a hung test still ends.
const WAIT: Duration = Duration::from_secs(60);

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
    tokio::time::timeout(WAIT, async {
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
async fn legacy_mark_assignment_requires_the_authenticated_message_path() {
    let _profile = crate::test_profile::temp();
    let mut app = App::new();
    let mut rx = astation(&mut app).await;
    app.hosted = Some(Hosted::default());
    for id in ["mark_123", "../project/.chisel/tasks/t1"] {
        app.handle_astation_message(AstationMessage::MarkTaskAssignment {
            task_id: id.into(),
            received_at_ms: 0,
        })
        .await;
        let (task_id, success, message) = mark_result(&mut rx).await;
        assert_eq!(task_id, id);
        assert!(!success);
        assert_eq!(message, super::MARK_UPGRADE_REQUIRED);
        assert!(app.hosted.as_ref().unwrap().inbox.is_empty());
    }
}

#[test]
fn the_menu_tui_hosts_no_sessions() {
    let _profile = crate::test_profile::temp();
    assert!(App::new().hosted.is_none());
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
    tokio::time::timeout(WAIT, async {
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
        match tokio::time::timeout(WAIT, rx.recv()).await {
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

/// r6 §0: every removed op is answered `unsupported_version` with no effect.
#[tokio::test]
async fn removed_ops_are_answered_unsupported_with_no_effect() {
    let _profile = crate::test_profile::temp();
    let mut app = App::new();
    app.hosted = Some(Hosted::default());
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
    let hosted = app.hosted.as_ref().unwrap();
    assert!(hosted.inbox.is_empty());
}

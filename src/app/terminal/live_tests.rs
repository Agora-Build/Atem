//! Opt-in provider tests: use installed CLIs and their inherited credentials.
use super::*;
use crate::websocket_client::AstationMessage;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const FIRST_PROMPT: &str = "Remember the word lantern for this conversation. Reply only with the uppercase words atem and ready joined by an underscore. Do not use tools or modify files.";
const SECOND_PROMPT: &str = "Reply only with the uppercase spelling of the word I asked you to remember. Do not use tools or modify files.";

fn encode(message: Message) -> WsMessage {
    WsMessage::Text(serde_json::to_string(&AstationMessage::Terminal(message.into())).unwrap())
}

#[tokio::test]
#[ignore = "starts the installed Codex CLI and makes two provider requests"]
async fn live_codex_websocket_conversation() {
    conversation("codex").await;
}

#[tokio::test]
#[ignore = "starts the installed Claude CLI and makes two provider requests"]
async fn live_claude_websocket_conversation() {
    conversation("claude").await;
}

async fn conversation(provider: &'static str) {
    // Never the real $XDG_RUNTIME_DIR/atem or ~/.config/atem/run; dropped after the App.
    let chat_root = tempfile::tempdir().unwrap();
    let mut app = App::new();
    app.chat_root = chat_root.path().join("run");
    let kind = Provider::from_alias(provider).unwrap();
    let id = app.launch_here(kind).await.unwrap();
    app.focused = Some(id.clone());
    app.mode = AppMode::Terminal;
    app.adjust_terminal_size(&id, 40, 120);
    app.leave_terminal_view();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        socket.send(encode(Message::List)).await.unwrap();
        let mut remote = vt100::Parser::new(40, 120, 0);
        let mut identity: Option<(String, String, String)> = None;
        let mut lease: Option<String> = None;
        let mut prompts = 0;
        let mut sequence = 0;
        let mut enter_pending = false;
        let mut written = [false; 4];
        let mut first_reply = false;
        let mut second_reply = false;
        let mut stopped = false;
        let mut frames = 0;
        let mut ready = false;
        let mut startup_reported = false;
        let mut reply_reported = false;
        let mut next_action = Instant::now() + Duration::from_secs(3);
        let started = Instant::now();
        loop {
            tokio::select! {
                incoming = socket.next() => {
                    let Some(incoming) = incoming else {
                        panic!("{provider}: terminal disconnected before both replies and exit");
                    };
                    let WsMessage::Text(json) = incoming.unwrap() else { continue };
                    let AstationMessage::Terminal(envelope) = serde_json::from_str(&json).unwrap()
                    else { continue };
                    match envelope.message {
                        Message::Sessions { sessions, .. } => {
                            let session = sessions.into_iter().find(|s| s.provider == provider).unwrap();
                            socket.send(encode(Message::Subscribe {
                                terminal_id: session.terminal_id,
                                generation: session.generation,
                            })).await.unwrap();
                        }
                        Message::Attached { session, stream_id } => {
                            identity = Some((session.terminal_id.clone(), session.generation.clone(), stream_id.clone()));
                            socket.send(encode(Message::Control {
                                terminal_id: session.terminal_id,
                                generation: session.generation,
                                stream_id,
                                take: true,
                            })).await.unwrap();
                        }
                        Message::Controller { lease_id, .. } => lease = lease_id,
                        Message::Written { sequence, error, .. } => {
                            assert!(error.is_none(), "{provider}: PTY rejected input");
                            assert!(sequence < 4, "unexpected write sequence");
                            written[sequence as usize] = true;
                        }
                        Message::Frame { terminal_id, generation, stream_id, offset, bytes, reset, rows, cols, .. } => {
                            if reset { remote = vt100::Parser::new(rows, cols, 0); }
                            let bytes = STANDARD.decode(bytes).unwrap();
                            remote.process(&bytes);
                            frames += 1;
                            socket.send(encode(Message::Ack {
                                terminal_id, generation, stream_id,
                                offset: offset + bytes.len() as u64,
                            })).await.unwrap();
                            let text = remote.screen().contents();
                            let prompt_marker = if provider == "codex" { '\u{203a}' } else { '\u{276f}' };
                            ready = text.lines().any(|line| {
                                let line = line.trim();
                                line == prompt_marker.to_string()
                                    || (provider == "codex" && line == "\u{203a} Ask Codex to do anything")
                            });
                            assert!(!text.contains("Update available") && !text.contains("Update now"),
                                "{provider}: startup update dialog requires local handling; no input sent");
                            assert!(!text.contains("401 Unauthorized"),
                                "{provider}: provider returned HTTP 401; use the same profile and credentials as a working local CLI");
                            if prompts >= 1 && text.contains("ATEM_READY") && !first_reply {
                                first_reply = true;
                                next_action = Instant::now() + Duration::from_secs(2);
                                println!("{provider}: remote reply 1 = ATEM_READY ({:.1}s)", started.elapsed().as_secs_f64());
                            }
                            if prompts == 2 && text.contains("LANTERN") && !second_reply {
                                second_reply = true;
                                println!("{provider}: remote reply 2 = LANTERN ({:.1}s)", started.elapsed().as_secs_f64());
                            }
                        }
                        Message::Exited { generation, .. } => {
                            assert!(stopped && first_reply && second_reply && written.iter().all(|v| *v),
                                "{provider}: CLI exited before both replies; check startup, login and provider configuration");
                            assert_eq!(generation, identity.as_ref().unwrap().1);
                            println!("{provider}: {frames} remote frames, all input writes acknowledged, same process stopped");
                            socket.close(None).await.unwrap();
                            return;
                        }
                        Message::Error { .. } => panic!("{provider}: terminal protocol rejected a request"),
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if prompts == 0 && !enter_pending && !ready && !startup_reported && started.elapsed() > Duration::from_secs(10) {
                        println!("{provider}: waiting for the CLI input field; check for a startup dialog");
                        startup_reported = true;
                    }
                    if prompts == 1 && !first_reply && !reply_reported && started.elapsed() > Duration::from_secs(20) {
                        println!("{provider}: waiting for a provider reply");
                        reply_reported = true;
                    }
                    if Instant::now() < next_action || lease.is_none() || identity.is_none() { continue; }
                    let (terminal_id, generation, stream_id) = identity.as_ref().unwrap().clone();
                    let lease_id = lease.as_ref().unwrap().clone();
                    if enter_pending {
                        socket.send(encode(Message::Input {
                            terminal_id, generation, stream_id, lease_id, sequence,
                            bytes: STANDARD.encode(b"\r"),
                        })).await.unwrap();
                        sequence += 1;
                        prompts += 1;
                        enter_pending = false;
                        println!("{provider}: remote prompt {prompts} submitted");
                        continue;
                    }
                    let prompt = if prompts == 0 && ready { Some(FIRST_PROMPT) }
                        else if prompts == 1 && first_reply && written[1] { Some(SECOND_PROMPT) }
                        else { None };
                    if let Some(prompt) = prompt {
                        // Human paste and Enter arrive as separate terminal input events.
                        socket.send(encode(Message::Input {
                            terminal_id, generation, stream_id, lease_id,
                            sequence,
                            bytes: STANDARD.encode(format!("\x1b[200~{prompt}\x1b[201~")),
                        })).await.unwrap();
                        sequence += 1;
                        enter_pending = true;
                        next_action = Instant::now() + Duration::from_millis(300);
                    } else if second_reply && written[3] && !stopped {
                        socket.send(encode(Message::Stop { terminal_id, generation, stream_id, lease_id })).await.unwrap();
                        stopped = true;
                    }
                }
            }
        }
    });
    app.astation_client
        .connect_raw(&format!("ws://{address}"))
        .await
        .unwrap();
    // This stand-in tests terminal transport; authentication has separate tests.
    app.astation_connected = true;
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        while !peer.is_finished() {
            if app.astation_client.is_ws_closed() {
                app.disconnect_terminals();
            }
            while let Some(message) = app.astation_client.recv_message() {
                if let AstationMessage::Terminal(envelope) = message {
                    app.handle_terminal_message(envelope);
                }
            }
            app.process_terminal_output(&id);
            app.pump_terminals();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    if result.is_err() {
        peer.abort();
    }
    app.disconnect_terminals();
    let peer_result = peer.await;
    // Remove only the log artifacts this test's process generated on exit.
    let session = app.sessions.get(&id).unwrap();
    for path in [&session.log_file, &session.summary_file]
        .into_iter()
        .flatten()
    {
        let _ = std::fs::remove_file(path);
    }
    assert!(matches!(app.mode, AppMode::MainMenu));
    assert!(
        result.is_ok(),
        "{provider}: no verified two-turn reply within 180 seconds; check CLI startup, login and provider configuration"
    );
    peer_result.unwrap();
}

//! chat-v1 end to end, in process: the real App, a fake `claude` in a PTY
//! (tests/fixtures/chat/fake-claude.sh, which runs Atem's hook command and
//! writes a transcript) and a fake Astation WebSocket peer.
use super::App;
use crate::agent_client::{AgentKind, AgentStatus};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const WAIT: Duration = Duration::from_secs(20);

struct Harness {
    app: App,
    to_atem: mpsc::UnboundedSender<String>,
    from_atem: mpsc::UnboundedReceiver<Value>,
    /// Everything Atem sent so far, in order.
    seen: Vec<Value>,
    root: tempfile::TempDir,
}

fn fake_claude() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chat/fake-claude.sh");
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    if perms.mode() & 0o111 != 0o111 {
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

async fn start() -> Harness {
    let root = tempfile::tempdir().unwrap();
    let mut app = App::new();
    // Never the real $XDG_RUNTIME_DIR/atem or ~/.config/atem/run.
    app.chat_root = root.path().join("run");
    app.claude_client
        .set_command_for_test(fake_claude().to_string_lossy().into_owned(), Vec::new());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (to_atem, mut outgoing) = mpsc::unbounded_channel::<String>();
    let (incoming, from_atem) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        loop {
            tokio::select! {
                message = outgoing.recv() => {
                    let Some(text) = message else { break };
                    if socket.send(WsMessage::Text(text)).await.is_err() { break; }
                }
                received = socket.next() => {
                    let Some(Ok(received)) = received else { break };
                    if let WsMessage::Text(text) = received
                        && let Ok(value) = serde_json::from_str::<Value>(&text)
                    {
                        let _ = incoming.send(value);
                    }
                }
            }
        }
    });
    app.astation_client
        .connect_raw(&format!("ws://{address}"))
        .await
        .unwrap();
    // This stand-in tests chat transport; authentication has separate tests.
    app.astation_connected = true;
    app.ensure_claude_session().await.unwrap();
    Harness {
        app,
        to_atem,
        from_atem,
        seen: Vec::new(),
        root,
    }
}

fn is_chat(v: &Value, op: &str) -> bool {
    v["type"] == "agentChat" && v["data"]["op"] == op
}

impl Harness {
    fn agent_id(&self) -> String {
        self.app
            .agent_registry
            .all()
            .into_iter()
            .find(|a| a.kind == AgentKind::ClaudeCode)
            .unwrap()
            .id
    }

    fn send_chat(&self, op: &str, conversation: &str, extra: Value) {
        let mut data = json!({
            "v": 1, "op": op, "conversationId": conversation, "agentId": self.agent_id(),
        });
        if let Value::Object(extra) = extra {
            data.as_object_mut().unwrap().extend(extra);
        }
        let message = json!({ "type": "agentChat", "data": data });
        self.to_atem.send(message.to_string()).unwrap();
    }

    /// Run the App's loop until `done` matches a message Atem sent (searching
    /// from `from`); returns that message's index in `seen`.
    async fn pump_until(&mut self, from: usize, done: impl Fn(&Value) -> bool) -> usize {
        let deadline = Instant::now() + WAIT;
        let mut checked = from;
        loop {
            while let Some(message) = self.app.astation_client.recv_message() {
                self.app.handle_astation_message(message).await;
            }
            self.app.process_claude_output();
            self.app.poll_chat().await;
            while let Ok(value) = self.from_atem.try_recv() {
                self.seen.push(value);
            }
            while checked < self.seen.len() {
                if done(&self.seen[checked]) {
                    return checked;
                }
                checked += 1;
            }
            assert!(
                Instant::now() < deadline,
                "timed out; Atem sent: {:#?}",
                &self.seen[from..]
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Keep the loop running for `time` (to show nothing more happens).
    async fn pump_for(&mut self, time: Duration) {
        let deadline = Instant::now() + time;
        while Instant::now() < deadline {
            while let Some(message) = self.app.astation_client.recv_message() {
                self.app.handle_astation_message(message).await;
            }
            self.app.process_claude_output();
            self.app.poll_chat().await;
            while let Ok(value) = self.from_atem.try_recv() {
                self.seen.push(value);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_chat(&mut self) {
        let from = self.seen.len();
        self.pump_until(from, |v| {
            v["type"] == "agentListResponse"
                && v["data"]["agents"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["capabilities"] == json!(["chat-v1"]))
        })
        .await;
    }

    /// Open `conversation` and wait for `history` history messages; returns the
    /// `opened` message and the history after it.
    async fn open(&mut self, conversation: &str, history: u64) -> (Value, Vec<Value>) {
        let from = self.seen.len();
        self.send_chat("open", conversation, json!({}));
        let at = self
            .pump_until(from, |v| {
                is_chat(v, "opened") && v["data"]["conversationId"] == conversation
            })
            .await;
        if history > 0 {
            let conversation = conversation.to_string();
            self.pump_until(at + 1, move |v| {
                is_chat(v, "message")
                    && v["data"]["conversationId"] == conversation.as_str()
                    && v["data"]["history"] == true
                    && v["data"]["sequence"] == history
            })
            .await;
        }
        let history = self.seen[at + 1..]
            .iter()
            .filter(|v| v["data"]["conversationId"] == conversation && v["data"]["history"] == true)
            .cloned()
            .collect();
        (self.seen[at].clone(), history)
    }

    /// Submit and run until `complete` for it; returns the conversation's events from the submit on.
    async fn submit_until_complete(
        &mut self,
        conversation: &str,
        generation: &str,
        request_id: &str,
        text: &str,
    ) -> Vec<Value> {
        let from = self.seen.len();
        self.send_chat(
            "submit",
            conversation,
            json!({"generation": generation, "requestId": request_id, "text": text}),
        );
        let rid = request_id.to_string();
        let at = self
            .pump_until(from, move |v| {
                is_chat(v, "complete") && v["data"]["requestId"] == rid.as_str()
            })
            .await;
        // The turn's end also sets status ready, right after `complete`.
        let conv = conversation.to_string();
        self.pump_until(at + 1, move |v| {
            is_chat(v, "status")
                && v["data"]["conversationId"] == conv.as_str()
                && v["data"]["state"] == "ready"
        })
        .await;
        self.seen[from..]
            .iter()
            .filter(|v| v["type"] == "agentChat" && v["data"]["conversationId"] == conversation)
            .cloned()
            .collect()
    }

    fn chat_dirs(&self) -> Vec<PathBuf> {
        let Ok(rd) = std::fs::read_dir(self.root.path().join("run")) else {
            return Vec::new();
        };
        rd.flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("chat-")
            })
            .collect()
    }

    fn transcript_lines(&self) -> Vec<String> {
        let dir = self.root.path().join("run/transcripts");
        let mut lines = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let text = std::fs::read_to_string(entry.path()).unwrap();
            lines.extend(text.lines().map(str::to_string));
        }
        lines
    }

    async fn stop(mut self) {
        // Ctrl+U first: clears a partly typed line in the fake's cooked-mode terminal.
        self.app.send_claude_data("\x15exit\r");
        let deadline = Instant::now() + WAIT;
        while self.app.claude_receiver.is_some() && Instant::now() < deadline {
            self.app.process_claude_output();
            self.app.poll_chat().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            self.app.claude_receiver.is_none(),
            "fake claude did not exit"
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Session logs Atem saves in the working directory when a session with output ends.
        for path in [&self.app.claude_log_file, &self.app.claude_summary_file]
            .into_iter()
            .flatten()
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn sequences(events: &[Value]) -> Vec<u64> {
    events
        .iter()
        .map(|v| v["data"]["sequence"].as_u64().unwrap())
        .collect()
}

fn position(events: &[Value], f: impl Fn(&Value) -> bool) -> usize {
    events
        .iter()
        .position(f)
        .unwrap_or_else(|| panic!("not found in {events:#?}"))
}

#[tokio::test]
async fn agent_list_advertises_chat_v1_after_session_start() {
    let mut h = start().await;
    let agent = h.app.agent_registry.get(&h.agent_id()).unwrap();
    // Registered before Claude's SessionStart could have been read.
    assert!(agent.capabilities.is_empty());
    assert_eq!(agent.status, AgentStatus::Unknown);
    h.wait_for_chat().await;
    let list = h
        .seen
        .iter()
        .rev()
        .find(|v| v["type"] == "agentListResponse")
        .unwrap();
    let claude = &list["data"]["agents"][0];
    assert_eq!(claude["status"], "Idle");
    assert_eq!(claude["capabilities"], json!(["chat-v1"]));
    let agent = h.app.agent_registry.get(&h.agent_id()).unwrap();
    assert_eq!(agent.capabilities, vec!["chat-v1".to_string()]);
    assert_eq!(h.chat_dirs().len(), 1);
    h.stop().await;
}

#[tokio::test]
async fn chat_open_submit_reply_complete() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let (opened, history) = h.open("c1", 0).await;
    assert_eq!(opened["data"]["sequence"], 0);
    assert_eq!(opened["data"]["status"]["state"], "ready");
    assert!(history.is_empty());
    let generation = opened["data"]["generation"].as_str().unwrap().to_string();

    let events = h
        .submit_until_complete("c1", &generation, "r1", "hello there")
        .await;
    for e in &events {
        assert_eq!(e["data"]["generation"], generation.as_str(), "{e}");
    }
    let seq = sequences(&events);
    assert_eq!(
        seq,
        (1..=seq.len() as u64).collect::<Vec<_>>(),
        "{events:#?}"
    );

    let accepted = position(&events, |v| {
        is_chat(v, "accepted") && v["data"]["requestId"] == "r1"
    });
    let user = position(&events, |v| {
        is_chat(v, "message") && v["data"]["role"] == "user"
    });
    let u = &events[user]["data"];
    assert_eq!(u["origin"], "remote");
    assert_eq!(u["requestId"], "r1");
    assert_eq!(u["parts"][0]["markdown"], "hello there");
    let tool = position(&events, |v| {
        is_chat(v, "message") && v["data"]["role"] == "assistant"
    });
    let a = &events[tool]["data"];
    assert_eq!(a["messageId"], "msg-1");
    assert_eq!(a["requestId"], "r1");
    assert_eq!(a["parts"][0]["kind"], "tool");
    assert_eq!(a["parts"][0]["name"], "Bash");
    assert_eq!(a["parts"][0]["summary"], "echo hi");
    let delta = position(&events, |v| is_chat(v, "delta"));
    assert_eq!(events[delta]["data"]["messageId"], "msg-1");
    assert_eq!(events[delta]["data"]["part"]["kind"], "text");
    assert_eq!(events[delta]["data"]["part"]["markdown"], "reply 1");
    let complete = position(&events, |v| is_chat(v, "complete"));
    let c = &events[complete]["data"];
    assert_eq!(c["outcome"], "done");
    assert_eq!(c["requestId"], "r1");
    assert_eq!(c["turnId"], "p-1");
    assert!(user < tool && tool < delta && delta < complete);
    assert!(accepted < complete);
    let last_status = events.iter().rev().find(|v| is_chat(v, "status")).unwrap();
    assert_eq!(last_status["data"]["state"], "ready");
    assert!(
        events
            .iter()
            .any(|v| is_chat(v, "status") && v["data"]["state"] == "working"),
        "{events:#?}"
    );
    h.stop().await;
}

#[tokio::test]
async fn submit_refused_after_local_typing() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let (opened, _) = h.open("c1", 0).await;
    let generation = opened["data"]["generation"].as_str().unwrap().to_string();
    // A key typed in Atem's own terminal view (the local input path).
    h.app.send_claude_data("x");
    let from = h.seen.len();
    h.send_chat(
        "submit",
        "c1",
        json!({"generation": generation, "requestId": "r1", "text": "hello"}),
    );
    let at = h.pump_until(from, |v| is_chat(v, "error")).await;
    let e = &h.seen[at]["data"];
    assert_eq!(e["requestId"], "r1");
    assert!(
        e["text"]
            .as_str()
            .unwrap()
            .starts_with("the terminal has unsent input"),
        "{e}"
    );
    assert_eq!(e["sequence"], 1);
    h.pump_for(Duration::from_millis(300)).await;
    assert!(
        !h.transcript_lines()
            .iter()
            .any(|l| l.contains("\"type\":\"user\"")),
        "nothing was typed"
    );
    h.stop().await;
}

#[tokio::test]
async fn duplicate_request_is_not_executed_twice() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let (opened, _) = h.open("c1", 0).await;
    let generation = opened["data"]["generation"].as_str().unwrap().to_string();
    h.submit_until_complete("c1", &generation, "r1", "only once")
        .await;
    let from = h.seen.len();
    h.send_chat(
        "submit",
        "c1",
        json!({"generation": generation, "requestId": "r1", "text": "only once"}),
    );
    let at = h
        .pump_until(from, |v| {
            is_chat(v, "complete") && v["data"]["requestId"] == "r1"
        })
        .await;
    assert!(h.seen[from..at].iter().any(|v| is_chat(v, "accepted")));
    h.pump_for(Duration::from_millis(500)).await;
    let prompts = h
        .transcript_lines()
        .iter()
        .filter(|l| l.contains("\"content\":\"only once\""))
        .count();
    assert_eq!(prompts, 1, "the prompt was typed once");
    assert!(
        !h.seen[from..]
            .iter()
            .any(|v| is_chat(v, "message") && v["data"]["role"] == "user"),
        "no new user message"
    );
    h.stop().await;
}

#[tokio::test]
async fn reconnect_restores_status_and_history() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let (opened, _) = h.open("c1", 0).await;
    let generation = opened["data"]["generation"].as_str().unwrap().to_string();
    h.submit_until_complete("c1", &generation, "r1", "remember me")
        .await;
    h.send_chat("close", "c1", json!({}));

    let (opened, history) = h.open("c1", 2).await;
    assert_eq!(opened["data"]["generation"], generation.as_str());
    assert_eq!(opened["data"]["sequence"], 0);
    assert_eq!(opened["data"]["status"]["state"], "ready");
    assert_eq!(sequences(&history), vec![1, 2]);
    let user = &history[0]["data"];
    assert_eq!(user["role"], "user");
    assert_eq!(user["origin"], "remote");
    assert_eq!(user["requestId"], "r1");
    assert_eq!(user["parts"][0]["markdown"], "remember me");
    let reply = &history[1]["data"];
    assert_eq!(reply["role"], "assistant");
    assert_eq!(reply["messageId"], "msg-1");
    assert_eq!(reply["parts"].as_array().unwrap().len(), 2);
    assert_eq!(reply["parts"][1]["markdown"], "reply 1");
    h.stop().await;
}

#[tokio::test]
async fn process_exit_reports_unknown() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let (opened, _) = h.open("c1", 0).await;
    let generation = opened["data"]["generation"].as_str().unwrap().to_string();
    assert_eq!(h.chat_dirs().len(), 1);
    let from = h.seen.len();
    h.app.send_claude_data("exit\r");
    let at = h
        .pump_until(from, |v| {
            is_chat(v, "status") && v["data"]["state"] == "unknown"
        })
        .await;
    assert_eq!(h.seen[at]["data"]["generation"], generation.as_str());
    let at = h
        .pump_until(from, |v| {
            v["type"] == "agentListResponse" && v["data"]["agents"][0]["status"] == "Unknown"
        })
        .await;
    assert!(
        h.seen[at]["data"]["agents"][0]
            .get("capabilities")
            .is_none()
    );
    h.pump_until(from, |v| {
        is_chat(v, "error") && v["data"]["text"] == "the agent exited"
    })
    .await;
    assert!(h.chat_dirs().is_empty(), "the chat directory is removed");
    // A prompt for the retired process is refused.
    let from = h.seen.len();
    h.send_chat(
        "submit",
        "c1",
        json!({"generation": generation, "requestId": "r9", "text": "hi"}),
    );
    let at = h.pump_until(from, |v| is_chat(v, "error")).await;
    assert_eq!(h.seen[at]["data"]["requestId"], "r9");
}

#[tokio::test]
async fn unknown_agent_and_bad_requests_get_errors() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let from = h.seen.len();
    let message = json!({"type": "agentChat", "data": {
        "v": 1, "op": "open", "conversationId": "c1", "agentId": "nobody"}});
    h.to_atem.send(message.to_string()).unwrap();
    let at = h.pump_until(from, |v| is_chat(v, "error")).await;
    assert_eq!(
        h.seen[at]["data"]["text"],
        "chat is not available for this agent"
    );
    let from = h.seen.len();
    h.send_chat("submit", "c1", json!({"generation": "g"}));
    let at = h.pump_until(from, |v| is_chat(v, "error")).await;
    assert_eq!(h.seen[at]["data"]["text"], "missing field requestId");
    h.stop().await;
}

#[tokio::test]
async fn disconnect_closes_conversations() {
    let mut h = start().await;
    h.wait_for_chat().await;
    h.open("c1", 0).await;
    assert_eq!(h.app.claude_chat.as_ref().unwrap().conversations.len(), 1);
    h.app.on_astation_disconnect();
    assert!(h.app.claude_chat.as_ref().unwrap().conversations.is_empty());
    h.stop().await;
}

#[tokio::test]
async fn heartbeat_resends_status_with_its_original_since() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let (opened, _) = h.open("c1", 0).await;
    let since = opened["data"]["status"]["since"].clone();
    h.app.claude_chat.as_mut().unwrap().last_heartbeat = Instant::now() - Duration::from_secs(16);
    let from = h.seen.len();
    let at = h.pump_until(from, |v| is_chat(v, "status")).await;
    let status = &h.seen[at]["data"];
    assert_eq!(status["state"], "ready");
    assert_eq!(status["since"], since);
    assert_eq!(status["sequence"], 1);
    h.stop().await;
}

#[tokio::test]
async fn fatal_log_problem_withdraws_chat() {
    let mut h = start().await;
    h.wait_for_chat().await;
    h.open("c1", 0).await;
    // The fake creates its (empty) transcript at start. A user entry without a
    // uuid means the transcript format changed.
    let transcript = std::fs::read_dir(h.root.path().join("run/transcripts"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    std::io::Write::write_all(
        &mut file,
        b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n",
    )
    .unwrap();
    let from = h.seen.len();
    let at = h.pump_until(from, |v| is_chat(v, "error")).await;
    assert_eq!(
        h.seen[at]["data"]["text"],
        "chat is not available for this agent: user transcript entry has no uuid"
    );
    assert_eq!(h.seen[at]["data"]["conversationId"], "c1");
    let close = h.pump_until(from, |v| is_chat(v, "close")).await;
    assert!(at < close);
    assert_eq!(h.seen[close]["data"]["conversationId"], "c1");
    let at = h
        .pump_until(from, |v| {
            v["type"] == "agentListResponse" && v["data"]["agents"][0]["status"] == "Unknown"
        })
        .await;
    assert!(
        h.seen[at]["data"]["agents"][0]
            .get("capabilities")
            .is_none()
    );
    assert!(h.app.claude_chat.as_ref().unwrap().conversations.is_empty());
    // A new open is refused with the reason; the terminal keeps working.
    let from = h.seen.len();
    h.send_chat("open", "c2", json!({}));
    let at = h.pump_until(from, |v| is_chat(v, "error")).await;
    assert_eq!(
        h.seen[at]["data"]["text"],
        "chat is not available for this agent: user transcript entry has no uuid"
    );
    h.stop().await;
}

#[tokio::test]
async fn codex_without_an_adapter_registers_unknown_without_chat() {
    let mut app = App::new();
    let root = tempfile::tempdir().unwrap();
    app.chat_root = root.path().join("run");
    app.codex_client
        .set_command_for_test("cat".into(), Vec::new());
    assert!(app.ensure_codex_session().await.unwrap());
    let codex = app
        .agent_registry
        .all()
        .into_iter()
        .find(|a| a.kind == AgentKind::Codex)
        .unwrap();
    assert_eq!(codex.status, AgentStatus::Unknown);
    assert!(codex.capabilities.is_empty());
    assert!(app.claude_chat.is_none());
    app.poll_chat().await;
    assert_eq!(
        app.agent_registry.get(&codex.id).unwrap().status,
        AgentStatus::Unknown
    );
    assert!(
        !root.path().join("run").exists(),
        "no chat directory for Codex"
    );
}

#[tokio::test]
async fn claude_without_chat_registers_unknown() {
    let mut app = App::new();
    let root = tempfile::tempdir().unwrap();
    // A file where the chat root's parent should be: preparing chat fails.
    std::fs::write(root.path().join("file"), b"").unwrap();
    app.chat_root = root.path().join("file/run");
    app.claude_client
        .set_command_for_test(fake_claude().to_string_lossy().into_owned(), Vec::new());
    assert!(app.ensure_claude_session().await.unwrap());
    assert!(app.claude_chat.is_none(), "Claude started without chat");
    let claude = app
        .agent_registry
        .all()
        .into_iter()
        .find(|a| a.kind == AgentKind::ClaudeCode)
        .unwrap();
    assert_eq!(claude.status, AgentStatus::Unknown);
    assert!(claude.capabilities.is_empty());
    // Without --settings the fake is plain `cat`: end its input.
    app.send_claude_data("\x04");
    let deadline = Instant::now() + WAIT;
    while app.claude_receiver.is_some() && Instant::now() < deadline {
        app.process_claude_output();
        app.poll_chat().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(app.claude_receiver.is_none(), "fake claude did not exit");
}

#[tokio::test]
async fn respawn_tells_open_conversations_to_reopen() {
    let mut h = start().await;
    h.wait_for_chat().await;
    let (opened, _) = h.open("c1", 0).await;
    let old_generation = opened["data"]["generation"].as_str().unwrap().to_string();
    let from = h.seen.len();
    h.app.send_claude_data("exit\r");
    h.pump_until(from, |v| {
        is_chat(v, "status") && v["data"]["state"] == "unknown"
    })
    .await;
    assert!(h.app.claude_receiver.is_none());
    let from = h.seen.len();
    assert!(h.app.ensure_claude_session().await.unwrap());
    let error = h
        .pump_until(from, |v| {
            is_chat(v, "error") && v["data"]["text"] == "the agent was restarted; reopen the chat"
        })
        .await;
    assert_eq!(h.seen[error]["data"]["conversationId"], "c1");
    assert_eq!(h.seen[error]["data"]["generation"], old_generation.as_str());
    let close = h.pump_until(from, |v| is_chat(v, "close")).await;
    assert!(error < close);
    assert_eq!(h.seen[close]["data"]["conversationId"], "c1");
    assert!(h.app.claude_chat.as_ref().unwrap().conversations.is_empty());
    h.wait_for_chat().await;
    let (opened, _) = h.open("c1", 0).await;
    assert_ne!(opened["data"]["generation"], old_generation.as_str());
    assert_eq!(h.chat_dirs().len(), 1, "the old chat directory is gone");
    h.stop().await;
}

#[tokio::test]
async fn opening_restarts_the_heartbeat_clock() {
    let mut h = start().await;
    h.wait_for_chat().await;
    h.app.claude_chat.as_mut().unwrap().last_heartbeat = Instant::now() - Duration::from_secs(16);
    h.open("c1", 0).await;
    let from = h.seen.len();
    h.pump_for(Duration::from_millis(200)).await;
    assert!(
        !h.seen[from..].iter().any(|v| is_chat(v, "status")),
        "no heartbeat right after opened"
    );
    h.stop().await;
}

#[tokio::test]
async fn chat_is_ignored_while_offline_or_suspended() {
    let mut h = start().await;
    h.wait_for_chat().await;
    h.app.astation_connected = false;
    let from = h.seen.len();
    h.send_chat("open", "c1", json!({}));
    h.pump_for(Duration::from_millis(300)).await;
    assert!(!h.seen[from..].iter().any(|v| v["type"] == "agentChat"));
    assert!(h.app.claude_chat.as_ref().unwrap().conversations.is_empty());

    h.app.astation_connected = true;
    h.open("c1", 0).await;
    h.app.suspend_astation();
    assert!(h.app.claude_chat.as_ref().unwrap().conversations.is_empty());
    let from = h.seen.len();
    h.send_chat("open", "c2", json!({}));
    h.pump_for(Duration::from_millis(300)).await;
    assert!(!h.seen[from..].iter().any(|v| v["type"] == "agentChat"));
    assert!(h.app.claude_chat.as_ref().unwrap().conversations.is_empty());
    h.stop().await;
}

#[tokio::test]
async fn launching_codex_sends_the_agent_list() {
    let mut h = start().await;
    h.wait_for_chat().await;
    h.app
        .codex_client
        .set_command_for_test("cat".into(), Vec::new());
    let from = h.seen.len();
    assert!(h.app.ensure_codex_session().await.unwrap());
    let at = h
        .pump_until(from, |v| {
            v["type"] == "agentListResponse"
                && v["data"]["agents"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["kind"] == "Codex")
        })
        .await;
    let codex = h.seen[at]["data"]["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["kind"] == "Codex")
        .unwrap()
        .clone();
    assert_eq!(codex["status"], "Unknown");
    assert!(codex.get("capabilities").is_none());
    h.stop().await;
}

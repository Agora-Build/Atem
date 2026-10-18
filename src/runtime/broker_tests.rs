//! `BrokerSession` over a worker served in this process (a `/bin/sh` agent).

use super::*;
use crate::session::Provider;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

struct Setup {
    _dir: tempfile::TempDir,
    session: BrokerSession,
}

/// A launched session running `body` as its agent.
async fn launch(body: &str) -> Setup {
    let dir = tempfile::Builder::new()
        .prefix("atem-b")
        .tempdir_in("/tmp")
        .unwrap();
    let agent = dir.path().join("agent");
    std::fs::write(&agent, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let launcher = Launcher::InProcess(InProcess {
        state: dir.path().join("state"),
        socket_dir: dir.path().join("ws"),
        chat_root: dir.path().join("chat"),
    });
    let request = SpawnRequest {
        session_id: SessionId::new(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: Provider::Codex,
        args: vec![],
        cwd: dir.path().to_path_buf(),
        rows: 24,
        cols: 80,
    };
    let env = LaunchEnv(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("CODEX_CLI_BIN".into(), agent.display().to_string()),
    ]);
    let (handle, created_at_ms) = launcher.spawn(request.clone(), env).await.unwrap();
    let mut session = BrokerSession::launched(handle, &request, created_at_ms);
    session.tap.open();
    Setup { _dir: dir, session }
}

/// Pumps `session` until `done` holds (10 s at most), collecting tap output.
async fn pump_until(
    session: &mut BrokerSession,
    output: &mut Vec<u8>,
    mut done: impl FnMut(&BrokerSession, &[u8]) -> bool,
) {
    let found = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            session.pump();
            output.extend_from_slice(&session.tap.take().bytes);
            if done(session, output) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        found.is_ok(),
        "not reached; output {:?}",
        String::from_utf8_lossy(output)
    );
}

fn contains(output: &[u8], text: &str) -> bool {
    String::from_utf8_lossy(output).contains(text)
}

#[tokio::test]
async fn input_reaches_the_agent_through_the_worker_under_the_current_epoch() {
    let Setup { mut session, _dir } =
        launch("echo ready; while read l; do echo got:$l; done").await;
    let mut output = Vec::new();
    pump_until(&mut session, &mut output, |_, o| contains(o, "ready")).await;
    assert_eq!(session.input_epoch(), 0, "the worker's epoch at start");
    session.write(b"one\r").unwrap();
    pump_until(&mut session, &mut output, |s, o| {
        contains(o, "got:one") && s.in_flight.is_empty()
    })
    .await;
    // Control changes: a new epoch, and writes go on under it.
    assert_eq!(session.raise_input_epoch().unwrap(), 1);
    session.write(b"two\r").unwrap();
    pump_until(&mut session, &mut output, |s, o| {
        contains(o, "got:two") && s.in_flight.is_empty()
    })
    .await;
    assert_eq!(session.dropped_writes, 0);
    // The mirror follows the output.
    assert!(session.screen.screen().contents().contains("got:two"));
    session.stop().unwrap();
    pump_until(&mut session, &mut output, |s, _| {
        s.state == SessionState::Exited
    })
    .await;
    assert!(session.write(b"late\r").is_err());
}

#[tokio::test]
async fn a_raised_epoch_drops_writes_still_queued_under_the_old_one() {
    // Reads nothing for two seconds, then echoes everything raw.
    let Setup { mut session, _dir } =
        launch("stty raw -echo\nprintf 'SLEEPING\\r\\n'\nsleep 2\nexec cat").await;
    let mut output = Vec::new();
    pump_until(&mut session, &mut output, |_, o| contains(o, "SLEEPING")).await;
    // Far more than the PTY buffer holds: most of it waits in the worker's queue.
    for _ in 0..20 {
        session.write(&[b'a'; 16 * 1024]).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    session.raise_input_epoch().unwrap();
    session.write(b"AFTER").unwrap();
    pump_until(&mut session, &mut output, |s, o| {
        contains(o, "AFTER") && s.in_flight.is_empty()
    })
    .await;
    assert!(
        session.dropped_writes > 0 && session.in_flight.is_empty(),
        "nothing queued under the old epoch was dropped"
    );
    let written = output.iter().filter(|b| **b == b'a').count();
    assert!(written < 20 * 16 * 1024, "every stale byte was written");
    session.stop().unwrap();
}

#[tokio::test]
async fn too_many_writes_in_flight_hold_further_input() {
    let Setup { mut session, _dir } =
        launch("stty raw -echo\nprintf 'SLEEPING\\r\\n'\nsleep 2\nexec cat").await;
    let mut output = Vec::new();
    pump_until(&mut session, &mut output, |_, o| contains(o, "SLEEPING")).await;
    for _ in 0..MAX_IN_FLIGHT {
        assert!(session.can_write());
        session.write(b"x").unwrap();
    }
    assert!(!session.can_write());
    pump_until(&mut session, &mut output, |s, _| s.can_write()).await;
    session.stop().unwrap();
}

/// A Codex worker with Atem's hooks on says what its chat offers from its
/// first `chat_snapshot` on (chat-v1 open, the unavailable list).
#[tokio::test]
async fn the_first_chat_snapshot_names_the_chat_capabilities() {
    let dir = tempfile::Builder::new()
        .prefix("atem-b")
        .tempdir_in("/tmp")
        .unwrap();
    let agent = dir.path().join("agent");
    std::fs::write(&agent, "#!/bin/sh\nexec cat\n").unwrap();
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let launcher = Launcher::InProcess(InProcess {
        state: dir.path().join("state"),
        socket_dir: dir.path().join("ws"),
        chat_root: dir.path().join("chat"),
    });
    let request = SpawnRequest {
        session_id: SessionId::new(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: Provider::Codex,
        args: vec![],
        cwd: dir.path().to_path_buf(),
        rows: 24,
        cols: 80,
    };
    let env = LaunchEnv(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("CODEX_CLI_BIN".into(), agent.display().to_string()),
    ]);
    let (mut handle, _) = launcher.spawn(request, env).await.unwrap();
    assert!(handle.info.chat, "hello says the session has chat");
    let snapshot = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match handle.recv().await.expect("the worker closed") {
                WorkerMsg::ChatSnapshot {
                    chat_v1,
                    unavailable,
                    ..
                } => return (chat_v1, unavailable),
                WorkerMsg::Chat { .. } => panic!("a chat batch before the snapshot"),
                _ => {}
            }
        }
    })
    .await
    .expect("no chat_snapshot");
    assert_eq!(
        snapshot,
        (
            true,
            vec![
                "streaming".to_string(),
                "reasoning".into(),
                "error_details".into()
            ]
        )
    );
    let _ = handle.stop();
}

fn card(
    approval_id: &str,
    state: crate::chat::adapter::ApprovalCardState,
) -> crate::chat::adapter::ApprovalCard {
    crate::chat::adapter::ApprovalCard {
        id: "approval".into(),
        approval_id: approval_id.into(),
        tool: "Bash".into(),
        summary: "npm test".into(),
        always_rules: Vec::new(),
        state,
        rule_id: None,
        note: None,
        reason: None,
    }
}

/// Pumps until `done` holds (10 s at most).
async fn pump_while(session: &mut BrokerSession, mut done: impl FnMut(&mut BrokerSession) -> bool) {
    let reached = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            session.pump();
            if done(session) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(reached.is_ok(), "not reached");
}

/// Lets the launched worker's first messages (its own snapshot) arrive.
async fn settle(session: &mut BrokerSession) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    session.pump();
}

/// The worker's whole retained history (500 messages / 8 MiB) reaches a new
/// broker in lines under the bound, approval cards included; one still
/// pending is closed (the new broker released its approval).
#[tokio::test]
async fn the_chat_snapshot_carries_the_whole_history_and_the_cards() {
    use crate::chat::adapter::{ApprovalCardState, LogItem};
    use crate::chat::session::{MAX_HISTORY_BYTES, MAX_HISTORY_MESSAGES};
    let mut chat = ChatSession::new("g".into(), 0);
    chat.on_event(
        AgentEvent::SessionStarted {
            session_id: "s".into(),
            log_path: PathBuf::from("/x"),
            source: "startup".into(),
            same_log: false,
        },
        1,
        0,
    );
    for i in 0..MAX_HISTORY_MESSAGES - 2 {
        chat.on_log(
            LogItem::UserMessage {
                id: format!("u{i}"),
                turn_id: format!("t{i}"),
                text: format!("{i:05}{}", "x".repeat(16_000)),
                created_at_ms: 5,
            },
            2,
            0,
        );
    }
    chat.approval_card(card("a-done", ApprovalCardState::Denied), 6);
    chat.approval_card(card("a-open", ApprovalCardState::Pending), 7);
    let retained = chat.history(None, MAX_HISTORY_MESSAGES, MAX_HISTORY_BYTES);
    assert_eq!(retained.len(), MAX_HISTORY_MESSAGES);
    let lines = super::super::worker::snapshot_messages(&chat, 0, true, None, Vec::new());
    assert!(lines.len() > 1, "more than one line's worth");
    for line in &lines {
        assert!(
            super::super::worker_protocol::encode_worker(line).len()
                < super::super::worker_protocol::MAX_LINE
        );
    }
    assert!(matches!(lines.last(), Some(WorkerMsg::ChatSnapshot { .. })));

    let Setup { mut session, _dir } = launch("exec cat").await;
    // The launched worker's own (empty) snapshot first.
    settle(&mut session).await;
    let mut pumped = Pumped::default();
    for line in lines {
        session.apply(line, &mut pumped);
    }
    let history = session.chat.history(None, usize::MAX, usize::MAX);
    assert_eq!(history.len(), MAX_HISTORY_MESSAGES);
    assert_eq!(history[0].message_id, "u0");
    let state = |id: &str| {
        history
            .iter()
            .find(|m| m.message_id == id)
            .and_then(|m| match m.parts.as_slice() {
                [crate::chat::adapter::Part::Approval(c)] => Some((c.state, c.note.clone())),
                _ => None,
            })
    };
    assert_eq!(
        state("approval-a-done"),
        Some((ApprovalCardState::Denied, None))
    );
    assert_eq!(
        state("approval-a-open"),
        Some((ApprovalCardState::Closed, Some(CARD_RELEASED.to_string())))
    );
    session.stop().unwrap();
}

/// A `chat` batch with a gap (the worker dropped items before they reached
/// the broker): the broker reloads the whole history from the worker, which
/// brings back what the broker missed; the broker's own card states win
/// over the worker's copies; open conversations must reopen.
#[tokio::test]
async fn a_chat_gap_reloads_the_history_from_the_worker() {
    use crate::chat::adapter::{ApprovalCardState, Part};
    let Setup { mut session, _dir } = launch("exec cat").await;
    settle(&mut session).await;
    let _ = session.take_chat_reset();
    // a1 goes to both; the broker then denies it (the copy to the worker
    // is "in flight", i.e. never sent here).
    session.approval_card(card("a1", ApprovalCardState::Pending), 5);
    session
        .chat
        .approval_card(card("a1", ApprovalCardState::Denied), 6);
    // What the broker missed: in the worker's history only.
    let mut missed = ChatSession::new("x".into(), 0);
    let Out::Message(missed) = missed.approval_card(card("a0", ApprovalCardState::Expired), 4)
    else {
        panic!("a message");
    };
    session.worker.as_ref().unwrap().chat_card(missed).unwrap();
    let mut pumped = Pumped::default();
    session.apply(
        WorkerMsg::Chat {
            events: Vec::new(),
            log: Vec::new(),
            input_count: 0,
            chat_v1: true,
            reason: None,
            unavailable: Vec::new(),
            gap: 3,
        },
        &mut pumped,
    );
    assert_eq!(
        session.take_chat_reset(),
        None,
        "only once the history is back"
    );
    pump_while(&mut session, |s| s.chat_reset.is_some()).await;
    assert_eq!(session.take_chat_reset(), Some(CHAT_INCOMPLETE));
    let history = session.chat.history(None, usize::MAX, usize::MAX);
    let states: Vec<(String, ApprovalCardState)> = history
        .iter()
        .map(|m| match m.parts.as_slice() {
            [Part::Approval(c)] => (m.message_id.clone(), c.state),
            _ => panic!("{m:?}"),
        })
        .collect();
    assert_eq!(
        states,
        [
            ("approval-a1".to_string(), ApprovalCardState::Denied),
            ("approval-a0".to_string(), ApprovalCardState::Expired)
        ],
        "the missed card is back; the broker's a1 state wins"
    );
    session.stop().unwrap();
}

/// A worker that goes away while a reload is pending: conversations reopen
/// on what the broker has, nothing waits for an answer.
#[tokio::test]
async fn a_worker_lost_during_a_reload_ends_the_conversations() {
    let Setup { mut session, _dir } = launch("sleep 1; exit 0").await;
    let Out::Message(part) = ChatSession::new("x".into(), 0).approval_card(
        card("a9", crate::chat::adapter::ApprovalCardState::Expired),
        1,
    ) else {
        panic!("a message");
    };
    session.history_requested = true;
    session.history_parts.push(part);
    // The agent exits, the worker is released and its connection closes.
    pump_while(&mut session, |s| s.worker.is_none()).await;
    assert!(!session.history_requested && session.history_parts.is_empty());
    assert_eq!(session.take_chat_reset(), Some(CHAT_INCOMPLETE));
}

/// Parts beyond their bound are all dropped, and the reload falls back to
/// "incomplete" on what is here (never a history with a hole); the state
/// still catches up.
#[tokio::test]
async fn an_oversized_reload_keeps_the_history_and_says_it_is_incomplete() {
    use crate::chat::adapter::ApprovalCardState;
    let Setup { mut session, _dir } = launch("exec cat").await;
    settle(&mut session).await;
    let _ = session.take_chat_reset();
    session.approval_card(card("keep", ApprovalCardState::Denied), 1);
    let mut source = ChatSession::new("x".into(), 0);
    let mut many = Vec::new();
    for i in 0..(2 * crate::chat::session::MAX_HISTORY_MESSAGES + 1) {
        if let Out::Message(m) =
            source.approval_card(card(&format!("p{i}"), ApprovalCardState::Expired), 1)
        {
            many.push(m);
        }
    }
    let mut pumped = Pumped::default();
    session.history_requested = true;
    for chunk in many.chunks(100) {
        session.apply(
            WorkerMsg::ChatHistoryPart {
                history: chunk.to_vec(),
            },
            &mut pumped,
        );
    }
    let mut snapshot = source.snapshot(0, 0);
    snapshot.history = Vec::new();
    session.apply(WorkerMsg::ChatHistory { snapshot }, &mut pumped);
    assert_eq!(session.take_chat_reset(), Some(CHAT_INCOMPLETE));
    assert!(session.history_parts.is_empty() && !session.history_overflow);
    let ids: Vec<String> = session
        .chat
        .history(None, usize::MAX, usize::MAX)
        .into_iter()
        .map(|m| m.message_id)
        .collect();
    assert_eq!(ids, ["approval-keep"]);
    session.stop().unwrap();
}

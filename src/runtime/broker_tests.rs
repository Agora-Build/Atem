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

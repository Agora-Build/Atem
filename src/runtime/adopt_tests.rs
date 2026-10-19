//! Workers in-process (`worker::serve` on a tokio task, a `/bin/sh` agent)
//! driven through `WorkerHandle`, and adoption of their records.

use super::*;
use crate::runtime::worker::{self, WorkerOptions, record_path};
use crate::runtime::worker_protocol::{ApplyOutcome, WorkerMsg, WorkerSpec, unb64};
use std::time::Duration;

const AGENT: &str = "echo ready; while read l; do echo got:$l; done";

struct Running {
    dir: tempfile::TempDir,
    spec: WorkerSpec,
    served: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Running {
    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn expect(&self) -> Expect {
        Expect {
            session_id: self.spec.session_id.clone(),
            process_gen: self.spec.process_gen.clone(),
            pid: std::process::id(),
            start_time: None,
        }
    }

    fn record(&self) -> WorkerRecord {
        read_record(&record_path(&self.state(), &self.spec.session_id)).unwrap()
    }
}

/// A worker for a `/bin/sh -c AGENT` session served in this process, and the
/// broker connection that started it.
async fn start() -> (Running, WorkerHandle) {
    start_with(AGENT, |_| Vec::new()).await
}

/// `start` with another agent script and more launch environment (given
/// the test's directory).
async fn start_with(
    agent: &str,
    extra_env: impl FnOnce(&Path) -> Vec<(String, String)>,
) -> (Running, WorkerHandle) {
    let dir = tempfile::Builder::new()
        .prefix("atem-w")
        .tempdir_in("/tmp")
        .unwrap();
    let state = dir.path().join("state");
    let sid = SessionId::new();
    let spec = WorkerSpec {
        session_id: sid.to_string(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: "codex".into(),
        args: vec!["-c".into(), agent.into()],
        cwd: dir.path().to_path_buf(),
        rows: 24,
        cols: 80,
        socket: dir.path().join("sock").join(format!("{sid}.sock")),
    };
    let listener = worker::listen(&spec.socket).unwrap();
    let extra = extra_env(dir.path());
    let options = WorkerOptions {
        state: state.clone(),
        pid: std::process::id(),
        start_time: process_start_time(std::process::id()).unwrap(),
        chat_root: dir.path().join("chat"),
        logs: dir.path().join("logs"),
        uid: unsafe { libc::getuid() },
        first_connect: Duration::from_secs(10),
        linger: Duration::from_secs(2),
        claude_approvals: true,
        approval_script: Some(dir.path().join("approval-hook.sh")),
    };
    let served = tokio::spawn(worker::serve(spec.clone(), listener, options));
    let running = Running { dir, spec, served };
    let mut vars: Vec<(String, String)> = vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("CODEX_CLI_BIN".into(), "/bin/sh".into()),
    ];
    vars.extend(extra);
    let env = LaunchEnv(vars);
    let handle = WorkerHandle::connect(&running.spec.socket, &running.expect(), Some(Some(env)))
        .await
        .unwrap();
    (running, handle)
}

/// Messages until `done` holds for one (5 s at most).
async fn until(
    handle: &mut WorkerHandle,
    mut done: impl FnMut(&WorkerMsg) -> bool,
) -> Vec<WorkerMsg> {
    let mut seen = Vec::new();
    let found = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = handle.recv().await {
            let hit = done(&message);
            seen.push(message);
            if hit {
                return true;
            }
        }
        false
    })
    .await;
    assert!(matches!(found, Ok(true)), "not seen; got {seen:?}");
    seen
}

fn output_text(messages: &[WorkerMsg]) -> String {
    messages
        .iter()
        .filter_map(|m| match m {
            WorkerMsg::Output { bytes, .. } => {
                Some(String::from_utf8_lossy(&unb64(bytes).unwrap()).into_owned())
            }
            _ => None,
        })
        .collect()
}

fn has_output(text: &str) -> impl FnMut(&WorkerMsg) -> bool + '_ {
    let mut all = String::new();
    move |m| {
        all.push_str(&output_text(std::slice::from_ref(m)));
        all.contains(text)
    }
}

async fn stop(running: Running, mut handle: WorkerHandle) {
    handle.stop().unwrap();
    until(&mut handle, |m| matches!(m, WorkerMsg::Exited { .. })).await;
    handle.stop().unwrap();
    tokio::time::timeout(Duration::from_secs(5), running.served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn start_time_is_field_22_counted_after_the_command_name() {
    let fields: Vec<String> = (3..=52).map(|n| n.to_string()).collect();
    let line = format!("4242 (atem) {}", fields.join(" "));
    assert_eq!(parse_stat_start_time(&line), Some(22));
    // A command name with spaces and parentheses.
    let line = format!("4242 (a (b) c)) {}", fields.join(" "));
    assert_eq!(parse_stat_start_time(&line), Some(22));
    assert_eq!(parse_stat_start_time("4242 (atem) S 1 2"), None);
    assert_eq!(parse_stat_start_time("garbage"), None);
    let mut bad = fields.clone();
    bad[19] = "x".into();
    assert_eq!(
        parse_stat_start_time(&format!("1 (a) {}", bad.join(" "))),
        None
    );
}

#[cfg(target_os = "linux")]
#[test]
fn start_time_of_a_live_process_is_stable_and_none_once_it_is_gone() {
    let own = std::process::id();
    let first = process_start_time(own).unwrap();
    assert_eq!(process_start_time(own), Some(first));
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    assert_eq!(process_start_time(pid), None);
    assert_eq!(process_start_time(0), None);
}

#[tokio::test]
async fn the_worker_runs_the_agent_and_drops_writes_of_a_stale_epoch() {
    let (running, mut handle) = start().await;
    assert_eq!(handle.info.session_id, running.spec.session_id);
    assert!(handle.info.agent_pid.is_some());
    until(&mut handle, has_output("ready")).await;

    handle.set_epoch(5).unwrap();
    handle.write(1, b"old\r", 4).unwrap();
    handle.write(2, b"new\r", 5).unwrap();
    handle.paste(3, "stale paste", 3).unwrap();
    let mut results = Vec::new();
    let mut text = String::new();
    until(&mut handle, |m| {
        text.push_str(&output_text(std::slice::from_ref(m)));
        if let WorkerMsg::WriteResult { .. } = m {
            results.push(m.clone());
        }
        results.len() == 3 && text.contains("got:new")
    })
    .await;
    assert!(results.contains(&WorkerMsg::WriteResult {
        seq: 1,
        ok: false,
        bytes_written: 0,
        dropped: true,
        error: None,
        no_effect: false,
        consumed: false,
    }));
    assert!(results.contains(&WorkerMsg::WriteResult {
        seq: 2,
        ok: true,
        bytes_written: 4,
        dropped: false,
        error: None,
        no_effect: false,
        consumed: false,
    }));
    assert!(results.iter().any(|r| matches!(
        r,
        WorkerMsg::WriteResult {
            seq: 3,
            dropped: true,
            ..
        }
    )));
    assert!(!text.contains("old"), "{text:?}");
    // A lower set_input_epoch never lowers it.
    handle.set_epoch(1).unwrap();
    handle.write(4, b"x\r", 4).unwrap();
    until(&mut handle, |m| {
        matches!(
            m,
            WorkerMsg::WriteResult {
                seq: 4,
                dropped: true,
                ..
            }
        )
    })
    .await;
    stop(running, handle).await;
}

#[tokio::test]
async fn a_new_broker_adopts_the_worker_after_the_old_one_is_gone() {
    let (running, mut handle) = start().await;
    until(&mut handle, has_output("ready")).await;
    handle.set_epoch(7).unwrap();
    handle.write(1, b"before\r", 7).unwrap();
    until(&mut handle, has_output("got:before")).await;
    let agent = handle.info.agent_pid.unwrap();
    // While a broker is connected, another is refused.
    let refused = WorkerHandle::connect(&running.spec.socket, &running.expect(), None).await;
    assert!(refused.unwrap_err().to_string().contains("another broker"));
    drop(handle);

    assert!(
        process_start_time(agent).is_some(),
        "the agent keeps running"
    );
    let mut adopted = adopt(&running.state()).await;
    assert_eq!(adopted.len(), 1);
    let Adoption::Adopted(mut handle, _) = adopted.remove(0) else {
        panic!("not adopted")
    };
    assert_eq!(handle.info.session_id, running.spec.session_id);
    assert_eq!(handle.info.process_gen, running.spec.process_gen);
    assert_eq!(handle.info.agent_pid, Some(agent));
    assert_eq!(handle.info.input_epoch, 7);
    handle.request_screen().unwrap();
    let seen = until(&mut handle, |m| matches!(m, WorkerMsg::Screen { .. })).await;
    let Some(WorkerMsg::Screen {
        restore, offset, ..
    }) = seen.last()
    else {
        unreachable!()
    };
    let restore = String::from_utf8_lossy(&unb64(restore).unwrap()).into_owned();
    assert!(
        restore.contains("ready") && restore.contains("got:before"),
        "{restore:?}"
    );
    assert_eq!(*offset, handle.info.offset);
    // The epoch survived the broker: an older write is still dropped.
    handle.write(2, b"late\r", 6).unwrap();
    until(&mut handle, |m| {
        matches!(
            m,
            WorkerMsg::WriteResult {
                seq: 2,
                dropped: true,
                ..
            }
        )
    })
    .await;
    handle.write(3, b"after\r", 7).unwrap();
    until(&mut handle, has_output("got:after")).await;
    stop(running, handle).await;
}

#[tokio::test]
async fn a_record_with_another_start_time_or_session_is_never_adopted() {
    let (running, mut handle) = start().await;
    until(&mut handle, has_output("ready")).await;
    drop(handle);
    let path = record_path(&running.state(), &running.spec.session_id);
    let genuine = running.record();

    // A reused pid: the record's start time is not the process's.
    let mut forged = genuine.clone();
    forged.start_time += 1;
    worker::write_record(&running.state(), &forged).unwrap();
    let adopted = adopt(&running.state()).await;
    assert_eq!(adopted.len(), 1);
    assert_eq!(adopted[0].status(), "recovery_required");
    let Adoption::RecoveryRequired { reason, .. } = &adopted[0] else {
        unreachable!()
    };
    assert!(reason.contains("start time"), "{reason}");
    assert!(path.exists(), "the record stays for the user");

    // Another process generation than the worker's hello.
    let mut forged = genuine.clone();
    forged.process_gen = uuid::Uuid::new_v4().to_string();
    worker::write_record(&running.state(), &forged).unwrap();
    let adopted = adopt(&running.state()).await;
    assert_eq!(adopted[0].status(), "recovery_required");
    let Adoption::RecoveryRequired { reason, .. } = &adopted[0] else {
        unreachable!()
    };
    assert!(reason.contains("serves"), "{reason}");
    drop(adopted);

    // A record naming another session than its file.
    let mut forged = genuine.clone();
    forged.session_id = SessionId::new().to_string();
    std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    let adopted = adopt(&running.state()).await;
    assert_eq!(adopted[0].status(), "recovery_required");
    assert_eq!(adopted[0].session_id(), running.spec.session_id);

    // The genuine record is adopted.
    worker::write_record(&running.state(), &genuine).unwrap();
    let mut adopted = adopt(&running.state()).await;
    let Adoption::Adopted(handle, _) = adopted.remove(0) else {
        panic!("not adopted")
    };
    stop(running, handle).await;
}

#[tokio::test]
async fn the_agent_exit_reaches_the_broker_and_releases_the_worker() {
    let (running, mut handle) = start().await;
    until(&mut handle, has_output("ready")).await;
    handle.write(1, b"\x04", 0).unwrap();
    let seen = until(&mut handle, |m| matches!(m, WorkerMsg::Exited { .. })).await;
    assert!(seen.iter().any(|m| matches!(
        m,
        WorkerMsg::WriteResult {
            seq: 1,
            ok: true,
            ..
        }
    )));
    // A write after the exit is refused.
    handle.write(2, b"x", 0).unwrap();
    until(&mut handle, |m| {
        matches!(
            m,
            WorkerMsg::WriteResult {
                seq: 2,
                ok: false,
                dropped: false,
                ..
            }
        )
    })
    .await;
    assert!(running.record().exited.is_some());
    handle.stop().unwrap();
    let state = running.state();
    let sid = running.spec.session_id.clone();
    tokio::time::timeout(Duration::from_secs(5), running.served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        !record_path(&state, &sid).exists(),
        "a heard exit removes the record"
    );
}

#[tokio::test]
async fn an_exit_nobody_heard_stays_in_the_record() {
    let (running, mut handle) = start().await;
    until(&mut handle, has_output("ready")).await;
    let agent = handle.info.agent_pid.unwrap();
    drop(handle);
    // The worker notices the broker is gone before the agent exits.
    tokio::time::sleep(Duration::from_millis(300)).await;
    unsafe { libc::kill(agent as libc::pid_t, libc::SIGKILL) };
    // The worker lingers (2 s here) for a broker, then leaves the record.
    tokio::time::timeout(Duration::from_secs(10), running.served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let record = read_record(&record_path(
        &running.dir.path().join("state"),
        &running.spec.session_id,
    ))
    .unwrap();
    assert!(record.exited.is_some());
}

/// A record of a worker that is gone (a reaped child's pid).
fn gone_record(state: &Path) -> WorkerRecord {
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    WorkerRecord {
        session_id: SessionId::new().to_string(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: "claude".into(),
        cwd: "/".into(),
        created_at_ms: 1,
        socket: state.join("nowhere.sock"),
        worker_pid: pid,
        start_time: 12345,
        agent_pid: None,
        agent_start_time: None,
        exited: None,
    }
}

#[tokio::test]
async fn a_dead_worker_is_interrupted_exited_or_recovery_required_if_its_agent_lives() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");

    let interrupted = gone_record(&state);
    worker::write_record(&state, &interrupted).unwrap();
    let mut exited = gone_record(&state);
    exited.exited = Some("exit status: 0".into());
    worker::write_record(&state, &exited).unwrap();
    // Its agent still runs (this process stands in for it).
    let mut orphan = gone_record(&state);
    orphan.agent_pid = Some(std::process::id());
    orphan.agent_start_time = process_start_time(std::process::id());
    worker::write_record(&state, &orphan).unwrap();
    // An agent pid alone (another start time) proves nothing.
    let mut reused = gone_record(&state);
    reused.agent_pid = Some(std::process::id());
    reused.agent_start_time = Some(1);
    worker::write_record(&state, &reused).unwrap();
    // Not a record.
    std::fs::write(worker::workers_dir(&state).join("notes.json"), b"{}").unwrap();

    let adopted = adopt(&state).await;
    let status = |sid: &str| {
        adopted
            .iter()
            .find(|a| a.session_id() == sid)
            .map(|a| a.status())
            .unwrap()
    };
    assert_eq!(adopted.len(), 4);
    assert_eq!(status(&interrupted.session_id), "interrupted");
    assert_eq!(status(&exited.session_id), "exited");
    assert_eq!(status(&orphan.session_id), "recovery_required");
    assert_eq!(status(&reused.session_id), "interrupted");
    // Records are kept.
    for record in [&interrupted, &exited, &orphan, &reused] {
        assert!(record_path(&state, &record.session_id).exists());
    }
}

#[test]
fn records_and_specs_are_private_files() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let record = gone_record(&state);
    worker::write_record(&state, &record).unwrap();
    let path = record_path(&state, &record.session_id);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(worker::workers_dir(&state))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(read_record(&path).unwrap(), record);
    // Never through a symlink.
    let link = worker::workers_dir(&state).join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_record(&link).is_err());
    let spec = WorkerSpec {
        session_id: record.session_id.clone(),
        process_gen: record.process_gen.clone(),
        provider: "claude".into(),
        args: vec![],
        cwd: "/".into(),
        rows: 24,
        cols: 80,
        socket: "/tmp/x.sock".into(),
    };
    worker::write_spec(&state, &spec).unwrap();
    let text = std::fs::read_to_string(worker::spec_path(&state, &spec.session_id)).unwrap();
    assert!(!text.contains("env"), "{text}");
    assert_eq!(worker::read_spec(&state, &spec.session_id).unwrap(), spec);
    assert!(worker::read_spec(&state, &SessionId::new().to_string()).is_err());
}

#[tokio::test]
async fn a_paste_with_control_characters_is_refused_by_the_worker() {
    let (running, mut handle) = start().await;
    until(&mut handle, has_output("ready")).await;
    handle.paste(1, "x\x1b[201~\rinjected", 0).unwrap();
    let seen = until(&mut handle, |m| {
        matches!(m, WorkerMsg::WriteResult { seq: 1, .. })
    })
    .await;
    assert!(matches!(
        seen.last(),
        Some(WorkerMsg::WriteResult {
            ok: false,
            dropped: false,
            error: Some(_),
            ..
        })
    ));
    handle.write(2, b"after\r", 0).unwrap();
    let seen = until(&mut handle, has_output("got:after")).await;
    assert!(!output_text(&seen).contains("injected"));
    stop(running, handle).await;
}

#[tokio::test]
async fn adoption_waits_out_an_old_broker_that_is_just_closing() {
    let (running, mut handle) = start().await;
    until(&mut handle, has_output("ready")).await;
    // The old broker closes a moment after the new one starts adopting.
    let closing = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(handle);
    });
    let mut adopted = adopt(&running.state()).await;
    closing.await.unwrap();
    let Adoption::Adopted(handle, _) = adopted.remove(0) else {
        panic!("not adopted: {adopted:?}")
    };
    stop(running, handle).await;
}

#[tokio::test]
async fn a_silent_connection_does_not_use_up_the_first_connect_window() {
    let dir = tempfile::Builder::new()
        .prefix("atem-w")
        .tempdir_in("/tmp")
        .unwrap();
    let sid = SessionId::new();
    let spec = WorkerSpec {
        session_id: sid.to_string(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: "codex".into(),
        args: vec!["-c".into(), AGENT.into()],
        cwd: dir.path().to_path_buf(),
        rows: 24,
        cols: 80,
        socket: dir.path().join("sock").join(format!("{sid}.sock")),
    };
    let listener = worker::listen(&spec.socket).unwrap();
    let options = WorkerOptions {
        state: dir.path().join("state"),
        pid: std::process::id(),
        start_time: process_start_time(std::process::id()).unwrap(),
        chat_root: dir.path().join("chat"),
        logs: dir.path().join("logs"),
        uid: unsafe { libc::getuid() },
        first_connect: Duration::from_secs(6),
        linger: Duration::from_secs(2),
        claude_approvals: true,
        approval_script: Some(dir.path().join("approval-hook.sh")),
    };
    let served = tokio::spawn(worker::serve(spec.clone(), listener, options));
    // Connects and says nothing, and stays.
    let _silent = tokio::net::UnixStream::connect(&spec.socket).await.unwrap();
    let running = Running { dir, spec, served };
    let env = LaunchEnv(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("CODEX_CLI_BIN".into(), "/bin/sh".into()),
    ]);
    let mut handle =
        WorkerHandle::connect(&running.spec.socket, &running.expect(), Some(Some(env)))
            .await
            .unwrap();
    until(&mut handle, has_output("ready")).await;
    stop(running, handle).await;
}

#[tokio::test]
async fn synchronous_refusals_report_that_nothing_was_written() {
    let (_running, mut handle) = start().await;
    until(&mut handle, has_output("ready")).await;
    // A paste with control characters is refused before anything is queued.
    handle.paste(1, "bad\u{7}paste", 0).unwrap();
    let mut result = None;
    until(&mut handle, |m| {
        if let WorkerMsg::WriteResult { seq: 1, .. } = m {
            result = Some(m.clone());
        }
        result.is_some()
    })
    .await;
    assert!(
        matches!(
            result,
            Some(WorkerMsg::WriteResult {
                ok: false,
                dropped: false,
                no_effect: true,
                error: Some(_),
                ..
            })
        ),
        "{result:?}"
    );
}

/// A Codex-like agent that, for each line typed, runs the stable hook
/// command from hooks.json with a permission request on stdin (as Codex
/// does), then prints `hook-done`.
const APPROVING_AGENT: &str = "echo ready; while read l; do printf '%s' \"$REQ\" | /bin/sh -c \"$HOOK\"; echo; echo hook-done; done";

const SECRET_REQ: &str = r#"{"hook_event_name":"PermissionRequest","turn_id":"t","tool_name":"Bash","tool_input":{"command":"psql postgres://admin:hunter2pass@db.example/prod -c 'drop table x'"}}"#;

async fn start_approving() -> (Running, WorkerHandle) {
    let (running, mut handle) = start_with(APPROVING_AGENT, |dir| {
        let hook = crate::chat::codex::hook_command(&dir.join("approval-hook.sh"));
        vec![("REQ".into(), SECRET_REQ.into()), ("HOOK".into(), hook)]
    })
    .await;
    until(&mut handle, has_output("ready")).await;
    (running, handle)
}

async fn approval_request(handle: &mut WorkerHandle, seq: u64) -> String {
    handle.write(seq, b"go\r", 0).unwrap();
    let seen = until(handle, |m| matches!(m, WorkerMsg::ApprovalRequest { .. })).await;
    match seen.last().unwrap() {
        WorkerMsg::ApprovalRequest {
            request_id,
            tool,
            summary,
            always_rules,
        } => {
            assert_eq!(tool, "Bash");
            assert_eq!(
                summary,
                "psql postgres://admin:[redacted]@db.example/prod -c 'drop table x'"
            );
            assert!(always_rules.is_empty(), "Codex offers no rule");
            request_id.clone()
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn a_codex_hook_waits_for_the_brokers_decision() {
    let (running, mut handle) = start_approving().await;
    let id = approval_request(&mut handle, 1).await;
    handle
        .approval_decision(
            &id,
            crate::session_protocol::wire::ApprovalDecision::Deny,
            None,
            Some("not on prod".into()),
        )
        .unwrap();
    let mut applied = false;
    let mut printed = false;
    let mut all = String::new();
    until(&mut handle, |m| {
        all.push_str(&output_text(std::slice::from_ref(m)));
        printed |= all.contains(r#""behavior":"deny","message":"not on prod""#);
        if let WorkerMsg::ApprovalApplied {
            request_id,
            outcome,
        } = m
        {
            assert_eq!(
                (request_id.as_str(), *outcome),
                (id.as_str(), ApplyOutcome::Ok)
            );
            applied = true;
        }
        applied && printed && all.contains("hook-done")
    })
    .await;
    // A late answer to the same request is refused.
    handle
        .approval_decision(
            &id,
            crate::session_protocol::wire::ApprovalDecision::AllowOnce,
            None,
            None,
        )
        .unwrap();
    until(&mut handle, |m| {
        matches!(
            m,
            WorkerMsg::ApprovalApplied {
                outcome: ApplyOutcome::NotDelivered,
                ..
            }
        )
    })
    .await;
    stop(running, handle).await;
}

#[tokio::test]
async fn input_to_codex_and_adoption_give_no_decision() {
    let (running, mut handle) = start_approving().await;
    let id = approval_request(&mut handle, 1).await;
    handle.write_until(9, b"x", 0, None, true).unwrap();
    let seen = until(&mut handle, has_output("hook-done")).await;
    assert!(!output_text(&seen).contains("behavior"));
    // The next one: a broker that knows only other approvals (adoption).
    let id2 = approval_request(&mut handle, 2).await;
    assert_ne!(id, id2);
    handle.known_approvals(vec!["other".into()]).unwrap();
    let seen = until(&mut handle, has_output("hook-done")).await;
    assert!(!output_text(&seen).contains("behavior"));
    // No decision was handed over. Closing the reported request `released`
    // is allowed (the broker drops its card): whether it comes before the
    // hook's own exit shows is only a matter of timing.
    assert!(
        seen.iter().all(|m| match m {
            WorkerMsg::ApprovalApplied { .. } => false,
            WorkerMsg::ApprovalClosed { request_id, reason } =>
                (*request_id == id || *request_id == id2)
                    && *reason == crate::session_protocol::wire::ApprovalCloseReason::Released,
            _ => true,
        }),
        "a release hands over no decision: {seen:?}"
    );
    stop(running, handle).await;
}

#[tokio::test]
async fn input_that_releases_a_waiting_hook_is_consumed() {
    let (running, mut handle) = start_approving().await;
    approval_request(&mut handle, 1).await;
    // As the broker sends any input to Codex: releasing the waiting hooks.
    handle.write_until(2, b"zap\r", 0, None, true).unwrap();
    let seen = until(&mut handle, |m| {
        matches!(m, WorkerMsg::WriteResult { seq: 2, .. })
    })
    .await;
    assert_eq!(
        seen.last(),
        Some(&WorkerMsg::WriteResult {
            seq: 2,
            ok: false,
            bytes_written: 0,
            dropped: false,
            no_effect: true,
            consumed: true,
            error: Some(super::super::worker_protocol::APPROVAL_HANDED.into()),
        })
    );
    until(&mut handle, has_output("hook-done")).await;
    // Input with no hook waiting is written as before (the agent's next
    // line asks again).
    handle.write_until(3, b"next\r", 0, None, true).unwrap();
    let seen = until(&mut handle, |m| {
        matches!(m, WorkerMsg::ApprovalRequest { .. })
    })
    .await;
    assert!(seen.iter().any(|m| matches!(
        m,
        WorkerMsg::WriteResult {
            seq: 3,
            ok: true,
            consumed: false,
            ..
        }
    )));
    let all = output_text(&seen);
    assert!(all.contains("next") && !all.contains("zap"), "{all}");
    // A paste that releases one is consumed the same way.
    handle.paste_until(4, "pasted", 0, None, true).unwrap();
    let seen = until(&mut handle, |m| {
        matches!(
            m,
            WorkerMsg::WriteResult {
                seq: 4,
                consumed: true,
                ..
            }
        )
    })
    .await;
    until(&mut handle, has_output("hook-done")).await;
    assert!(!output_text(&seen).contains("pasted"));
    stop(running, handle).await;
}

#[tokio::test]
async fn a_broker_that_goes_away_releases_the_waiting_hook() {
    let (running, mut handle) = start_approving().await;
    approval_request(&mut handle, 1).await;
    drop(handle);
    // The hook got "no decision" and the agent went on; a new broker sees it.
    let mut adopted = adopt(&running.state()).await;
    let Adoption::Adopted(mut handle, _) = adopted.remove(0) else {
        panic!("not adopted")
    };
    // On the screen it restores, or in the output after it: the hook may
    // still be noticing that its broker went away when the screen is cut.
    handle.request_screen().unwrap();
    let mut shown = String::new();
    until(&mut handle, |m| {
        match m {
            WorkerMsg::Screen { restore, .. } => {
                shown = String::from_utf8_lossy(&unb64(restore).unwrap()).into_owned()
            }
            _ if !shown.is_empty() => shown.push_str(&output_text(std::slice::from_ref(m))),
            _ => {}
        }
        shown.contains("hook-done")
    })
    .await;
    stop(running, handle).await;
}

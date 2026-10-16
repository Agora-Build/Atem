//! Workers in-process (`worker::serve` on a tokio task, a `/bin/sh` agent)
//! driven through `WorkerHandle`, and adoption of their records.

use super::*;
use crate::runtime::worker::{self, WorkerOptions, record_path};
use crate::runtime::worker_protocol::{WorkerMsg, WorkerSpec, unb64};
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
        args: vec!["-c".into(), AGENT.into()],
        cwd: dir.path().to_path_buf(),
        rows: 24,
        cols: 80,
        socket: dir.path().join("sock").join(format!("{sid}.sock")),
    };
    let listener = worker::listen(&spec.socket).unwrap();
    let options = WorkerOptions {
        state: state.clone(),
        pid: std::process::id(),
        start_time: process_start_time(std::process::id()).unwrap(),
        chat_root: dir.path().join("chat"),
        uid: unsafe { libc::getuid() },
        first_connect: Duration::from_secs(10),
        linger: Duration::from_secs(2),
    };
    let served = tokio::spawn(worker::serve(spec.clone(), listener, options));
    let running = Running { dir, spec, served };
    let env = LaunchEnv(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("CODEX_CLI_BIN".into(), "/bin/sh".into()),
    ]);
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
        error: None
    }));
    assert!(results.contains(&WorkerMsg::WriteResult {
        seq: 2,
        ok: true,
        bytes_written: 4,
        dropped: false,
        error: None
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
    let Adoption::Adopted(mut handle) = adopted.remove(0) else {
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
    let Adoption::Adopted(handle) = adopted.remove(0) else {
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
    let Adoption::Adopted(handle) = adopted.remove(0) else {
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
        uid: unsafe { libc::getuid() },
        first_connect: Duration::from_secs(6),
        linger: Duration::from_secs(2),
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

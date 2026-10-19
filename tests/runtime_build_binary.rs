//! A runtime of another atem build is replaced by the CLI's build, and
//! `atem runtime restart` restarts it, both keeping the sessions (their
//! workers are adopted); `atem status` and `atem --version` report what
//! runs. Fixture agents only; the other build is faked with
//! `ATEM_TEST_BUILD` (debug builds).
#![cfg(target_os = "linux")]

mod support;

use support::{Sandbox, within};

const FAKE_BUILD: &str = "0.0.1+fake-build";

/// Launches a fixture Codex session through the real CLI, detaches and
/// returns its id.
fn launch_session(sandbox: &Sandbox) -> String {
    let agent = sandbox.script(
        "agent fixture",
        "echo AGENT_READY\nwhile IFS= read -r line; do echo \"got:$line\"; done",
    );
    let mut frontend = sandbox.spawn(
        &["agent", "launch", "codex"],
        &sandbox.home,
        &[("CODEX_CLI_BIN", agent.to_str().unwrap())],
    );
    frontend.shows("AGENT_READY");
    let sid = frontend.detach();
    sandbox.track();
    sid
}

/// Starts `atem runtime` of the fake build in the sandbox (it adopts the
/// sessions' workers) and waits until it serves.
fn start_fake_runtime(sandbox: &Sandbox) {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_atem"));
    command
        .arg("runtime")
        .env_clear()
        .envs(sandbox.env())
        .env("ATEM_TEST_BUILD", FAKE_BUILD)
        .current_dir(&sandbox.home)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().unwrap();
    within("the fake build's runtime", || {
        sandbox.runtime_pid().is_some()
    });
    sandbox.track();
    // Reaped by its own thread; the sandbox kills it if a test fails.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs ATEM_TEST_BUILD, a debug-build hook (src/runtime/test_hooks.rs)"
)]
fn another_builds_runtime_is_replaced_and_restart_keeps_the_sessions() {
    let sandbox = Sandbox::new();
    let sid = launch_session(&sandbox);
    let first = sandbox.kill_runtime();
    start_fake_runtime(&sandbox);
    let fake = sandbox.runtime_pid().unwrap();
    assert_ne!(fake, first);

    // `atem status` and `atem --version` only look: the fake build stays.
    let (out, err, ok) = sandbox.atem(&["status"]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("Local agents:   1 running (codex unknown)"),
        "{out}"
    );
    assert!(out.contains("Relay:          not connected"), "{out}");
    let (out, _, ok) = sandbox.atem(&["--version"]);
    assert!(ok);
    assert!(out.starts_with("atem "), "{out}");
    assert!(out.contains("protocol session r8, local v1"), "{out}");
    assert!(
        out.contains(&format!("runtime    0.0.1 (build {FAKE_BUILD}, pid {fake})  [another build: run atem runtime restart]")),
        "{out}"
    );
    assert!(out.contains("workers    1 running:"), "{out}");
    assert_eq!(sandbox.runtime_pid(), Some(fake), "looking never replaces");

    // A command that uses the runtime replaces it by this build.
    let (out, err, ok) = sandbox.atem(&["agent", "list"]);
    assert!(ok, "{out}{err}");
    assert!(err.contains("Atem's runtime updated to "), "{err}");
    assert!(
        err.contains(&format!("(was {FAKE_BUILD}); sessions kept.")),
        "{err}"
    );
    let replaced = sandbox.runtime_pid().unwrap();
    assert_ne!(replaced, fake);
    sandbox.track();
    let row = out
        .lines()
        .find(|line| line.starts_with(&sid))
        .unwrap_or_else(|| panic!("{sid} isn't listed:\n{out}"));
    assert!(row.contains("running"), "{row}");

    // `atem runtime restart`: a new runtime of this build adopts it again.
    let (out, err, ok) = sandbox.atem(&["runtime", "restart"]);
    assert!(ok, "{out}{err}");
    assert!(out.contains("Atem's runtime restarted as build"), "{out}");
    assert!(out.contains("sessions kept: 1 running."), "{out}");
    let restarted = sandbox.runtime_pid().unwrap();
    assert_ne!(restarted, replaced);
    sandbox.track();
    assert!(
        sandbox
            .list()
            .iter()
            .any(|row| row[0] == sid && row[2] == "running"),
        "{:?}",
        sandbox.list()
    );
    let (_, err, ok) = sandbox.atem(&["agent", "stop", &sid]);
    assert!(ok, "{err}");
}

#[test]
fn restart_without_a_runtime_starts_nothing() {
    let sandbox = Sandbox::new();
    let (out, err, ok) = sandbox.atem(&["runtime", "restart"]);
    assert!(ok, "{out}{err}");
    assert!(out.contains("isn't running"), "{out}");
    assert_eq!(sandbox.runtime_pid(), None);
    let (out, _, ok) = sandbox.atem(&["status"]);
    assert!(ok);
    assert!(out.contains("Authorization:  no runtime running"), "{out}");
    assert_eq!(sandbox.runtime_pid(), None, "status starts no runtime");
    let (out, _, ok) = sandbox.atem(&["-V"]);
    assert!(ok);
    assert_eq!(out.lines().count(), 1, "{out}");
}

#[test]
fn an_attached_frontend_reattaches_across_a_restart() {
    let sandbox = Sandbox::new();
    let agent = sandbox.script(
        "agent fixture",
        "echo AGENT_READY\nwhile IFS= read -r line; do echo \"got:$line\"; done",
    );
    let mut frontend = sandbox.spawn(
        &["agent", "launch", "codex"],
        &sandbox.home,
        &[("CODEX_CLI_BIN", agent.to_str().unwrap())],
    );
    frontend.shows("AGENT_READY");
    sandbox.track();
    let before = sandbox.runtime_pid().unwrap();
    // Another terminal restarts the runtime.
    let (out, err, ok) = sandbox.atem(&["runtime", "restart"]);
    assert!(ok, "{out}{err}");
    within("the new runtime", || {
        sandbox.runtime_pid().is_some_and(|pid| pid != before)
    });
    sandbox.track();
    // The frontend is still on the session, through the new runtime.
    frontend.send(b"after restart\r");
    frontend.shows("got:after restart");
    assert!(
        matches!(frontend.child.try_wait(), Ok(None)),
        "the frontend ended:\n{}",
        frontend.written()
    );
    let sid = frontend.detach();
    let (_, err, ok) = sandbox.atem(&["agent", "stop", &sid]);
    assert!(ok, "{err}");
}

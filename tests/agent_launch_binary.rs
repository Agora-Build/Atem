//! `atem agent launch|attach|list|stop` through the real binary: the
//! frontend starts the runtime, the agent runs in a worker, and detaching
//! leaves the session running. No provider requests: fixture agents only.
#![cfg(target_os = "linux")]

mod support;

use support::{Sandbox, within};

/// A fixture agent that records its arguments, then echoes input lines.
fn recording_agent(sandbox: &Sandbox) -> (std::path::PathBuf, std::path::PathBuf) {
    let argv = sandbox.dir.path().join("argv");
    let agent = sandbox.script(
        "agent fixture",
        "printf '%s\\0' \"$@\" > \"$ATEM_TEST_ARGV.partial\"\nmv \"$ATEM_TEST_ARGV.partial\" \"$ATEM_TEST_ARGV\"\necho AGENT_READY\nwhile IFS= read -r line; do echo \"got:$line\"; done",
    );
    (agent, argv)
}

fn read_argv(path: &std::path::Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap();
    bytes
        .strip_suffix(&[0])
        .expect("Missing final argument delimiter")
        .split(|byte| *byte == 0)
        .map(|value| String::from_utf8(value.to_vec()).unwrap())
        .collect()
}

/// Launches `agent` with `arguments` in a fresh sandbox, calls `running`
/// with the agent's arguments while it runs, detaches, then stops the session.
fn launch_in(
    sandbox: &Sandbox,
    agent: &str,
    defaults: &str,
    arguments: &[&str],
    running: impl FnOnce(&[String]),
) -> Vec<String> {
    let (fixture, argv) = recording_agent(sandbox);
    let prefix = if agent == "codex" { "CODEX" } else { "CLAUDE" };
    let (bin, args) = (format!("{prefix}_CLI_BIN"), format!("{prefix}_CLI_ARGS"));
    let mut command = vec!["agent", "launch", agent];
    command.extend_from_slice(arguments);
    let mut frontend = sandbox.spawn(
        &command,
        &sandbox.home,
        &[
            (&bin, fixture.to_str().unwrap()),
            (&args, defaults),
            ("ATEM_TEST_ARGV", argv.to_str().unwrap()),
        ],
    );
    frontend.shows("AGENT_READY");
    within("the agent's arguments", || argv.exists());
    let values = read_argv(&argv);
    running(&values);
    let sid = frontend.detach();
    sandbox.track();
    let (_, err, ok) = sandbox.atem(&["agent", "stop", &sid]);
    assert!(ok, "stop failed: {err}");
    values
}

fn launch_and_capture(agent: &str, defaults: &str, arguments: &[&str]) -> Vec<String> {
    launch_in(&Sandbox::new(), agent, defaults, arguments, |_| {})
}

#[test]
fn codex_launch_forwards_profile_with_or_without_separator() {
    for arguments in [vec!["--profile", "oss"], vec!["--", "--profile", "oss"]] {
        assert_eq!(
            launch_and_capture("codex", "", &arguments),
            ["--profile", "oss"]
        );
    }
}

#[test]
fn claude_launch_forwards_options_preserving_values_and_env_defaults() {
    for agent in ["claude", "claude-code"] {
        for separator in [false, true] {
            let mut arguments = vec![
                "--model",
                "sonnet",
                "--append-system-prompt",
                "spaces\nand $literal `text`",
                "",
                "--",
                "--literal",
            ];
            let expected = arguments
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            if separator {
                arguments.insert(0, "--");
            }
            let actual = launch_and_capture(agent, "--verbose", &arguments);
            // Chat hooks come first, ahead of the user's `--`.
            assert_eq!(actual[0], "--settings");
            assert_eq!(actual[2], "--session-id");
            assert_eq!(
                actual[4..],
                [vec!["--verbose".to_string()], expected].concat()
            );
        }
    }
}

#[test]
fn claude_launch_adds_chat_hooks_that_outlive_detach_and_go_at_stop() {
    let sandbox = Sandbox::new();
    let (fixture, argv) = recording_agent(&sandbox);
    let mut frontend = sandbox.spawn(
        &["agent", "launch", "claude", "--model", "haiku"],
        &sandbox.home,
        &[
            ("CLAUDE_CLI_BIN", fixture.to_str().unwrap()),
            ("ATEM_TEST_ARGV", argv.to_str().unwrap()),
        ],
    );
    frontend.shows("AGENT_READY");
    within("the agent's arguments", || argv.exists());
    let args = read_argv(&argv);
    assert_eq!(args[0], "--settings");
    let settings = std::path::PathBuf::from(&args[1]);
    assert!(settings.is_file(), "settings.json exists while Claude runs");
    let chat_dir = settings.parent().unwrap().to_path_buf();
    assert_eq!(chat_dir.parent().unwrap(), sandbox.run.join("atem"));
    assert!(
        chat_dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("chat-")
    );
    assert_eq!(args[2], "--session-id");
    assert!(uuid_like(&args[3]), "{}", args[3]);
    assert_eq!(args[4..], ["--model", "haiku"]);

    let sid = frontend.detach();
    assert!(
        chat_dir.exists(),
        "detaching keeps the session and its chat"
    );
    let rows = sandbox.list();
    assert!(
        rows.iter()
            .any(|r| r[0] == sid && r[1] == "claude" && r[2] == "running"),
        "{rows:?}"
    );
    let (_, err, ok) = sandbox.atem(&["agent", "stop", &sid]);
    assert!(ok, "stop failed: {err}");
    within("the chat directory to go", || !chat_dir.exists());
}

#[test]
fn detach_attach_restores_two_sessions_and_stop_ends_them() {
    let sandbox = Sandbox::new();
    let agent = sandbox.script(
        "echo-agent",
        "echo \"READY $FAKE_NAME\"\nwhile IFS= read -r line; do echo \"got:$line\"; done",
    );
    let agent = agent.to_str().unwrap();

    // The first launch starts the runtime; the session runs in a worker.
    let mut first = sandbox.spawn(
        &["agent", "launch", "codex"],
        &sandbox.home,
        &[("CODEX_CLI_BIN", agent), ("FAKE_NAME", "one")],
    );
    first.shows("READY one");
    first.shows("Atem | Codex | Local | Astation \u{2717}");
    first.send(b"hello\r");
    first.shows("got:hello");
    let one = first.detach();
    assert!(
        first.written().contains(&format!(
            "Session {one} is still running. Reattach: atem agent attach {one} \u{b7} Stop: atem agent stop {one}"
        )),
        "{}",
        first.written()
    );
    let runtime = sandbox.runtime_pid().expect("the launch started a runtime");

    // A second launch uses the same runtime.
    let mut second = sandbox.spawn(
        &["agent", "launch", "codex"],
        &sandbox.home,
        &[("CODEX_CLI_BIN", agent), ("FAKE_NAME", "two")],
    );
    second.shows("READY two");
    let two = second.detach();
    assert_ne!(one, two);
    assert_eq!(sandbox.runtime_pid(), Some(runtime));

    let (out, err, ok) = sandbox.atem(&["agent", "list"]);
    assert!(ok, "{err}");
    let header = out.lines().find(|l| l.starts_with("ID")).expect("a header");
    for column in ["ID", "PROVIDER", "STATE", "STATUS", "ATTACHED", "CWD"] {
        assert!(header.contains(column), "{header}");
    }
    assert!(out.contains("protocol 1"), "{out}");
    assert!(out.contains(&format!("pid {runtime}")), "{out}");
    let rows = sandbox.list();
    assert_eq!(rows.len(), 2, "{rows:?}");
    for (row, sid) in rows.iter().zip([&one, &two]) {
        assert_eq!(&row[0], sid);
        assert_eq!(row[1], "codex");
        assert_eq!(row[2], "running");
        assert_eq!(row[4], "no");
        assert_eq!(row[5], sandbox.home.display().to_string());
    }

    // Attach restores the screen; input goes on.
    let mut again = sandbox.spawn(&["agent", "attach", &one], &sandbox.home, &[]);
    again.shows("got:hello");
    assert!(sandbox.list().iter().any(|r| r[0] == one && r[4] == "yes"));
    again.send(b"again\r");
    again.shows("got:again");
    assert_eq!(again.detach(), one);

    // Unknown ids are refused.
    let (_, err, ok) = sandbox.atem(&["agent", "attach", "ses-aaaaaaaaaaaa"]);
    assert!(!ok && err.contains("Unknown session"), "{err}");

    // Stop ends each session: its worker exits and removes its record.
    for sid in [&one, &two] {
        let (_, err, ok) = sandbox.atem(&["agent", "stop", sid]);
        assert!(ok, "{err}");
    }
    within("the workers to end", || sandbox.records().is_empty());
    within("both sessions to be exited", || {
        sandbox.list().iter().all(|r| r[2] == "exited")
    });
}

#[test]
fn prefix_x_stops_the_session_and_shows_its_end() {
    let sandbox = Sandbox::new();
    let agent = sandbox.script(
        "echo-agent",
        "echo READY\nwhile IFS= read -r line; do echo \"got:$line\"; done",
    );
    let mut frontend = sandbox.spawn(
        &["agent", "launch", "codex"],
        &sandbox.home,
        &[("CODEX_CLI_BIN", agent.to_str().unwrap())],
    );
    frontend.shows("READY");
    sandbox.track();
    frontend.send(b"\x1dx");
    // The final screen stays with the exit; any key closes it.
    frontend.shows("Exited");
    assert!(frontend.text().contains("READY"));
    frontend.send(b"\r");
    assert!(frontend.exits());
    within("the worker to end", || sandbox.records().is_empty());
}

#[test]
fn a_killed_runtime_is_restarted_by_the_next_command_and_adopts_the_session() {
    let sandbox = Sandbox::new();
    let agent = sandbox.script(
        "echo-agent",
        "echo READY\nwhile IFS= read -r line; do echo \"got:$line\"; done",
    );
    let mut frontend = sandbox.spawn(
        &["agent", "launch", "codex"],
        &sandbox.home,
        &[("CODEX_CLI_BIN", agent.to_str().unwrap())],
    );
    frontend.shows("READY");
    frontend.send(b"before\r");
    frontend.shows("got:before");
    let sid = frontend.detach();
    sandbox.track();

    let old = sandbox.kill_runtime();
    // The worker survived; the next command starts a runtime that adopts it.
    let rows = sandbox.list();
    assert!(
        rows.iter().any(|r| r[0] == sid && r[2] == "running"),
        "{rows:?}"
    );
    let new = sandbox.runtime_pid().expect("a new runtime");
    assert_ne!(new, old);
    let mut again = sandbox.spawn(&["agent", "attach", &sid], &sandbox.home, &[]);
    again.shows("got:before");
    again.send(b"after\r");
    again.shows("got:after");
    again.detach();
    let (_, err, ok) = sandbox.atem(&["agent", "stop", &sid]);
    assert!(ok, "{err}");
    within("the worker to end", || sandbox.records().is_empty());
}

fn uuid_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.iter().map(|p| p.len()).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
        && s.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

#[test]
fn the_menu_launches_and_attaches_through_the_runtime() {
    let sandbox = Sandbox::new();
    let agent = sandbox.script(
        "echo-agent",
        "echo MENU_READY\nwhile IFS= read -r line; do echo \"got:$line\"; done",
    );
    let mut menu = sandbox.spawn(
        &[],
        &sandbox.home,
        &[("CODEX_CLI_BIN", agent.to_str().unwrap())],
    );
    menu.shows("Launch Codex");
    // Projects, Claude, Codex: the third entry launches Codex in the runtime.
    menu.send(b"\x1b[B\x1b[B\r");
    menu.shows("MENU_READY");
    menu.shows("Atem | Codex | Local");
    menu.send(b"hi\r");
    menu.shows("got:hi");
    // Detaching returns to the menu; the session keeps running.
    menu.send(b"\x1dh");
    menu.shows("is still running");
    let rows = sandbox.list();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0][2], "running");
    let sid = rows[0][0].clone();
    menu.shows("Agent Sessions (1 running)");
    // The agent panel lists it; Enter attaches and restores the screen.
    menu.send(b"\x1b[B\r");
    menu.shows(&sid);
    menu.send(b"\r");
    menu.shows("got:hi");
    menu.send(b"\x1dh");
    menu.shows("is still running");
    menu.send(b"bq");
    assert!(menu.exits(), "the menu failed:\n{}", menu.written());
    sandbox.track();
    // Quitting the menu leaves the session.
    assert!(
        sandbox
            .list()
            .iter()
            .any(|r| r[0] == sid && r[2] == "running")
    );
    let (_, err, ok) = sandbox.atem(&["agent", "stop", &sid]);
    assert!(ok, "{err}");
    within("the worker to end", || sandbox.records().is_empty());
}

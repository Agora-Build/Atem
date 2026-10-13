//! Exercise CLI parsing and TUI launch through the real binary without provider requests.
#![cfg(unix)]

use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Atem(Box<dyn Child + Send + Sync>);

impl Drop for Atem {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn launch_and_capture(agent: &str, defaults: &str, arguments: &[&str]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let fixture = dir.path().join("agent fixture");
    let argv = dir.path().join("argv");
    std::fs::write(
        &fixture,
        "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$ATEM_TEST_ARGV.partial\"\nmv \"$ATEM_TEST_ARGV.partial\" \"$ATEM_TEST_ARGV\"\nIFS= read -r line\n",
    )
    .unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_atem"));
    command.args(["agent", "launch", agent]);
    command.args(arguments);
    // Isolate settings, credentials and Astation connections from the user's sessions.
    command.env_clear();
    command.env("HOME", dir.path());
    command.env("PATH", "/usr/bin:/bin");
    command.env("TERM", "xterm-256color");
    command.env("ASTATION_WS", "ws://127.0.0.1:1/ws");
    command.env("ASTATION_RELAY_URL", "http://127.0.0.1:1");
    command.env("ATEM_TEST_ARGV", &argv);
    let prefix = if agent == "codex" { "CODEX" } else { "CLAUDE" };
    command.env(format!("{prefix}_CLI_BIN"), &fixture);
    command.env(format!("{prefix}_CLI_ARGS"), defaults);
    command.cwd(dir.path());
    let mut atem = Atem(pair.slave.spawn_command(command).unwrap());
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let output = std::thread::spawn(move || {
        let mut startup = Vec::new();
        let mut ready = false;
        let mut buf = [0; 4096];
        // Drain continuously so screen redraws never block Atem's PTY.
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            if !ready {
                startup.extend_from_slice(&buf[..n]);
                if startup.windows(8).any(|w| w == b"\x1b[?2004h") {
                    let _ = ready_tx.send(());
                    ready = true;
                }
            }
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("TUI did not start");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !argv.exists() {
        assert!(
            atem.0.try_wait().unwrap().is_none(),
            "Atem exited before launching the agent"
        );
        assert!(
            Instant::now() < deadline,
            "Agent did not record its arguments"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let bytes = std::fs::read(&argv).unwrap();
    let values = bytes
        .strip_suffix(&[0])
        .expect("Missing final argument delimiter")
        .split(|byte| *byte == 0)
        .map(|value| String::from_utf8(value.to_vec()).unwrap())
        .collect();

    writer.write_all(b"\x1dhq").unwrap(); // Atem prefix, hide, then quit.
    writer.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = atem.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "Atem did not quit");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "Atem exited with {status}");
    output.join().unwrap();
    values
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
            assert_eq!(actual, [vec!["--verbose".to_string()], expected].concat());
        }
    }
}

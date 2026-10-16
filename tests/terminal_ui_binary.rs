//! Verify the full CLI, input decoder, PTY sizing and rendered ANSI without a provider.
#![cfg(target_os = "linux")]
mod support;

use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[track_caller]
fn within(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for terminal state"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn terminal_fixture() {
    let Some(directory) = std::env::var_os("ATEM_TERMINAL_UI_FIXTURE") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    unsafe {
        let mut settings: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(0, &mut settings), 0);
        libc::cfmakeraw(&mut settings);
        assert_eq!(libc::tcsetattr(0, libc::TCSANOW, &settings), 0);
        let flags = libc::fcntl(0, libc::F_GETFL);
        assert_eq!(libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
    let mut previous = (0, 0);
    let mut input = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut size) }, 0);
        let size = (size.ws_row, size.ws_col);
        if size != previous {
            std::fs::write(directory.join("size"), format!("{} {}", size.0, size.1)).unwrap();
            print!(
                "\x1b[?2004h\x1b[2J\x1b[HATEM_FIXTURE \u{4e2d}\u{6587}\r\nSIZE {} {}\x1b[{};1H? for shortcuts\x1b[2;1H\x1b[?25h",
                size.0, size.1, size.0
            );
            std::io::stdout().flush().unwrap();
            previous = size;
        }
        match std::io::stdin().read(&mut buf) {
            Ok(0) => return,
            Ok(count) => {
                input.extend_from_slice(&buf[..count]);
                std::fs::write(directory.join("input"), &input).unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("Fixture input failed: {error}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn compact_terminal_preserves_control_keys_paste_resize_and_copy() {
    let sandbox = support::Sandbox::new();
    let directory = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut atem = sandbox.spawn(
        &["agent", "launch", "codex"],
        directory.path(),
        &[
            ("CODEX_CLI_BIN", exe.to_str().unwrap()),
            ("CODEX_CLI_ARGS", "--exact terminal_fixture --nocapture"),
            (
                "ATEM_TERMINAL_UI_FIXTURE",
                directory.path().to_str().unwrap(),
            ),
        ],
    );
    let screen = atem.screen.clone();
    let bytes = atem.bytes.clone();
    within(|| {
        screen
            .lock()
            .unwrap()
            .screen()
            .contents()
            .contains("ATEM_FIXTURE")
    });
    sandbox.track();
    assert_eq!(
        std::fs::read_to_string(directory.path().join("size")).unwrap(),
        "39 120"
    );
    let text = screen.lock().unwrap().screen().contents();
    assert_eq!(text.matches("Atem |").count(), 1);
    assert_eq!(text.matches("? for shortcuts").count(), 1);
    assert!(!text.contains("Agora.io AI CLI Tool"));

    // Ordinary control keys and one multiline paste must reach the original CLI unchanged.
    let sent = b"\x02\x07\x03\x1b[200~one\n two\x1b[201~";
    atem.send(sent);
    within(|| std::fs::read(directory.path().join("input")).is_ok_and(|value| value == sent));

    atem.resize(30, 90);
    within(|| {
        std::fs::read_to_string(directory.path().join("size")).is_ok_and(|value| value == "29 90")
    });
    within(|| {
        screen
            .lock()
            .unwrap()
            .screen()
            .contents()
            .contains("SIZE 29 90")
    });
    let text = screen.lock().unwrap().screen().contents();
    assert_eq!(text.matches("? for shortcuts").count(), 1);
    assert_eq!(text.matches("Atem |").count(), 1);

    // Copy is an explicit outer clipboard request, not bytes typed into the agent.
    atem.send(b"\x1dc");
    within(|| {
        bytes
            .lock()
            .unwrap()
            .windows(7)
            .any(|value| value == b"\x1b]52;c;")
    });
    assert_eq!(std::fs::read(directory.path().join("input")).unwrap(), sent);

    // Detach leaves the session; stopping it ends the fixture.
    let sid = atem.detach();
    let (_, err, ok) = sandbox.atem(&["agent", "stop", &sid]);
    assert!(ok, "{err}");
    support::within("the worker to end", || sandbox.records().is_empty());
}

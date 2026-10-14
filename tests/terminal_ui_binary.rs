//! Verify the full CLI, input decoder, PTY sizing and rendered ANSI without a provider.
#![cfg(unix)]
use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
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
    let directory = tempfile::tempdir().unwrap();
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_atem"));
    command.args(["agent", "launch", "codex"]);
    command.env_clear();
    command.env("HOME", directory.path());
    command.env("PATH", "/usr/bin:/bin");
    command.env("TERM", "xterm-256color");
    command.env("ASTATION_WS", "ws://127.0.0.1:1/ws");
    command.env("ASTATION_RELAY_URL", "http://127.0.0.1:1");
    command.env("CODEX_CLI_BIN", std::env::current_exe().unwrap());
    command.env("CODEX_CLI_ARGS", "--exact terminal_fixture --nocapture");
    command.env("ATEM_TERMINAL_UI_FIXTURE", directory.path());
    command.cwd(directory.path());
    let mut atem = Atem(pair.slave.spawn_command(command).unwrap());
    drop(pair.slave);
    let screen = Arc::new(Mutex::new(vt100::Parser::new(40, 120, 0)));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let reader_screen = screen.clone();
    let reader_bytes = bytes.clone();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let output = std::thread::spawn(move || {
        let mut buf = [0; 4096];
        while let Ok(count) = reader.read(&mut buf) {
            if count == 0 {
                break;
            }
            reader_screen.lock().unwrap().process(&buf[..count]);
            reader_bytes
                .lock()
                .unwrap()
                .extend_from_slice(&buf[..count]);
        }
    });
    let mut writer = pair.master.take_writer().unwrap();
    within(|| {
        screen
            .lock()
            .unwrap()
            .screen()
            .contents()
            .contains("ATEM_FIXTURE")
    });
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
    writer.write_all(sent).unwrap();
    writer.flush().unwrap();
    within(|| std::fs::read(directory.path().join("input")).is_ok_and(|value| value == sent));

    screen.lock().unwrap().set_size(30, 90);
    pair.master
        .resize(PtySize {
            rows: 30,
            cols: 90,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
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
    writer.write_all(b"\x1dc").unwrap();
    writer.flush().unwrap();
    within(|| {
        bytes
            .lock()
            .unwrap()
            .windows(7)
            .any(|value| value == b"\x1b]52;c;")
    });
    assert_eq!(std::fs::read(directory.path().join("input")).unwrap(), sent);

    writer.write_all(b"\x1dhq").unwrap();
    writer.flush().unwrap();
    within(|| atem.0.try_wait().unwrap().is_some());
    output.join().unwrap();
}

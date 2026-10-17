//! A sandbox for driving the real `atem` binary as a frontend of its own
//! runtime: a temp HOME and runtime dir, `atem` in a PTY, and cleanup that
//! signals only the runtime, workers and agents this sandbox started.
#![allow(dead_code)]

pub mod astation;

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Waits up to ten seconds for `done`.
#[track_caller]
pub fn within(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `/proc/<pid>/stat` field 22 (Linux), `None` once the process is gone.
pub fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_ascii_whitespace().nth(19)?.parse().ok()
}

fn cmdline(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

pub struct Sandbox {
    pub dir: tempfile::TempDir,
    pub home: PathBuf,
    pub run: PathBuf,
    /// (pid, start time) of every process this sandbox's runtime started.
    seen: Mutex<Vec<(u32, u64)>>,
}

impl Sandbox {
    pub fn new() -> Self {
        // Unix socket paths are short: keep the sandbox in /tmp.
        let dir = tempfile::Builder::new()
            .prefix("atem-fe")
            .tempdir_in("/tmp")
            .unwrap();
        let home = dir.path().join("home");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Codex approvals answered "no" up front: `atem agent launch codex`
        // asks only in tests that remove this.
        let config = home.join(".config").join("atem");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("config.toml"),
            "[codex]\napprovals_hook = false\n",
        )
        .unwrap();
        Self {
            dir,
            home,
            run,
            seen: Mutex::new(Vec::new()),
        }
    }

    pub fn config(&self) -> PathBuf {
        self.home.join(".config").join("atem")
    }

    pub fn workers(&self) -> PathBuf {
        self.config().join("runtime").join("workers")
    }

    /// An executable sh script in the sandbox.
    pub fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    /// The environment every `atem` of this sandbox gets: its own HOME and
    /// runtime dir, and no reachable Astation.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("HOME".into(), self.home.display().to_string()),
            ("XDG_RUNTIME_DIR".into(), self.run.display().to_string()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("TERM".into(), "xterm-256color".into()),
            ("ASTATION_WS".into(), "ws://127.0.0.1:1/ws".into()),
            ("ASTATION_RELAY_URL".into(), "http://127.0.0.1:1".into()),
        ]
    }

    /// `atem <args>` without a terminal; its output (stdout, stderr) and status.
    pub fn atem(&self, args: &[&str]) -> (String, String, bool) {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_atem"))
            .args(args)
            .env_clear()
            .envs(self.env())
            .current_dir(&self.home)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        self.track();
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status.success(),
        )
    }

    /// `atem agent list`'s rows (header and build line left out).
    pub fn list(&self) -> Vec<Vec<String>> {
        let (out, err, ok) = self.atem(&["agent", "list"]);
        assert!(ok, "atem agent list failed: {out}{err}");
        out.lines()
            .filter(|line| line.starts_with("ses-"))
            .map(|line| line.split_whitespace().map(str::to_string).collect())
            .collect()
    }

    /// `atem <args>` in a 40x120 PTY started in `cwd`, with `extra` env.
    pub fn spawn(&self, args: &[&str], cwd: &Path, extra: &[(&str, &str)]) -> Frontend {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_atem"));
        command.args(args);
        command.env_clear();
        for (name, value) in self.env() {
            command.env(name, value);
        }
        for (name, value) in extra {
            command.env(name, value);
        }
        command.cwd(cwd);
        let child = pair.slave.spawn_command(command).unwrap();
        drop(pair.slave);
        let screen = Arc::new(Mutex::new(vt100::Parser::new(40, 120, 0)));
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut reader = pair.master.try_clone_reader().unwrap();
        let (reader_screen, reader_bytes) = (screen.clone(), bytes.clone());
        let output = std::thread::spawn(move || {
            let mut buf = [0; 4096];
            // Drain continuously so redraws never block atem.
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                reader_screen.lock().unwrap().process(&buf[..n]);
                reader_bytes.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let writer = pair.master.take_writer().unwrap();
        Frontend {
            child,
            master: pair.master,
            writer,
            screen,
            bytes,
            output: Some(output),
        }
    }

    /// Records the runtime's pid and every worker's and agent's (with their
    /// start times), so cleanup can signal exactly those.
    pub fn track(&self) {
        let mut seen = self.seen.lock().unwrap();
        let mut add = |pid: u32| {
            if let Some(started) = start_time(pid)
                && !seen.contains(&(pid, started))
            {
                seen.push((pid, started));
            }
        };
        if let Some(pid) = self.runtime_pid() {
            add(pid);
        }
        for record in self.records() {
            for key in ["worker_pid", "agent_pid"] {
                if let Some(pid) = record[key].as_u64() {
                    add(pid as u32);
                }
            }
        }
    }

    /// The pid in `runtime.lock` when it names this sandbox's `atem runtime`.
    pub fn runtime_pid(&self) -> Option<u32> {
        let text = std::fs::read_to_string(self.config().join("runtime.lock")).ok()?;
        let pid: u32 = text.trim().parse().ok()?;
        let args = cmdline(pid);
        (args.first().is_some_and(|exe| exe.ends_with("atem"))
            && args.get(1).map(String::as_str) == Some("runtime"))
        .then_some(pid)
    }

    /// The worker records on disk.
    pub fn records(&self) -> Vec<serde_json::Value> {
        let Ok(entries) = std::fs::read_dir(self.workers()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .filter_map(|text| serde_json::from_str(&text).ok())
            .collect()
    }

    /// SIGKILLs this sandbox's runtime (only when the lock names it).
    pub fn kill_runtime(&self) -> u32 {
        self.track();
        let pid = self.runtime_pid().expect("a runtime of this sandbox runs");
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        within("the runtime to die", || {
            start_time(pid).is_none() || zombie(pid)
        });
        pid
    }
}

/// A process that has exited but not been reaped (a detached runtime's
/// parent is init, which reaps it soon).
fn zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let rest = stat[stat.rfind(')')? + 1..].to_string();
            rest.split_ascii_whitespace().next().map(|s| s == "Z")
        })
        .unwrap_or(false)
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.track();
        for (pid, started) in self.seen.lock().unwrap().iter() {
            if start_time(*pid) == Some(*started) {
                unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
            }
        }
    }
}

/// `atem` running in a PTY: its screen as an outer terminal shows it.
pub struct Frontend {
    pub child: Box<dyn Child + Send + Sync>,
    pub master: Box<dyn MasterPty + Send>,
    pub writer: Box<dyn Write + Send>,
    pub screen: Arc<Mutex<vt100::Parser>>,
    pub bytes: Arc<Mutex<Vec<u8>>>,
    output: Option<std::thread::JoinHandle<()>>,
}

impl Frontend {
    pub fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
        self.writer.flush().unwrap();
    }

    pub fn text(&self) -> String {
        self.screen.lock().unwrap().screen().contents()
    }

    /// Everything atem wrote, as text.
    pub fn written(&self) -> String {
        String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned()
    }

    #[track_caller]
    pub fn shows(&self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.text().contains(text) {
            assert!(
                Instant::now() < deadline,
                "the screen never showed {text:?}:\n{}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.screen.lock().unwrap().set_size(rows, cols);
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
    }

    /// Waits for atem to exit; whether it succeeded.
    #[track_caller]
    pub fn exits(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "atem did not exit");
            std::thread::sleep(Duration::from_millis(20));
        };
        if let Some(output) = self.output.take() {
            let _ = output.join();
        }
        status.success()
    }

    /// Prefix `h`: detach. Returns the session id from the line printed.
    #[track_caller]
    pub fn detach(&mut self) -> String {
        self.send(b"\x1dh");
        assert!(
            self.exits(),
            "atem failed when detaching:\n{}",
            self.written()
        );
        detached_id(&self.written()).unwrap_or_else(|| {
            panic!("no detach line in:\n{}", self.written());
        })
    }
}

/// The session id in `Session ses-… is still running. Reattach: …`.
pub fn detached_id(text: &str) -> Option<String> {
    let at = text.find("Session ses-")? + "Session ".len();
    let id: String = text[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    let line = &text[at..];
    (line.contains(" is still running. Reattach: atem agent attach ")
        && line.contains(&format!("Stop: atem agent stop {id}")))
    .then_some(id)
}

impl Drop for Frontend {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

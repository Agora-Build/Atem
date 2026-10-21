//! Shared byte-oriented PTY transport. Terminal data and lifecycle events never mix.
use anyhow::{Result, anyhow, bail};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub const MAX_INPUT: usize = 16 * 1024;
#[cfg(test)]
pub const DEFAULT_ROWS: u16 = 40;
#[cfg(test)]
pub const DEFAULT_COLS: u16 = 120;
pub const SCROLLBACK_ROWS: usize = 2000;

#[derive(Debug)]
pub enum PtyEvent {
    Output(Vec<u8>),
    Exit(String),
    Error(String),
    /// What became of a fenced write (`PtyInput::write_fenced`/`paste_fenced`).
    Fenced {
        sequence: u64,
        outcome: FencedOutcome,
    },
}

/// A fenced write at the write boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencedOutcome {
    /// All of its bytes were written.
    Written(usize),
    /// Its input epoch was older than the current one when its turn came:
    /// nothing was written.
    Dropped,
    Failed(String),
}

/// Most bytes in one fenced write (a paste is written as one request, so a
/// raised epoch drops all of it or none).
pub const MAX_FENCED: usize = 1024 * 1024;

#[derive(Debug)]
struct WriteRequest {
    data: Vec<u8>,
    sequence: Option<u64>,
    /// A fenced write: its input epoch, compared at the write boundary with
    /// the current one (`PtyInput::raise_input_epoch`).
    fence: Option<u64>,
    /// A remote write: dropped at the write boundary once `monotonic_ns()`
    /// reached it (its lease's deadline). Local writes have none.
    not_after: Option<u64>,
    /// Write half of it, then fail (`runtime::test_hooks`, debug builds).
    partial: bool,
}

/// Nanoseconds on `CLOCK_MONOTONIC`, which every process of the machine
/// shares: the base of a remote write's `not_after`. In debug builds the
/// fixture clock (`runtime::test_hooks`) replaces it when one is set.
pub fn monotonic_ns() -> u64 {
    if let Some(ms) = crate::runtime::test_hooks::clock_ms() {
        return ms.saturating_mul(1_000_000);
    }
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for the call to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// An unfenced write (`respond`).
fn write_request(writer: &mut impl Write, request: &WriteRequest) -> Result<(), String> {
    writer
        .write_all(&request.data)
        .and_then(|()| writer.flush())
        .map_err(|e| e.to_string())
}

/// A fenced write at the write boundary: dropped when `fence` is older than
/// the current input epoch, or when its `not_after` has passed.
fn write_fenced_request(
    writer: &mut impl Write,
    current: &AtomicU64,
    fence: u64,
    not_after: Option<u64>,
    data: &[u8],
    partial: bool,
) -> FencedOutcome {
    crate::runtime::test_hooks::hold_writes();
    if fence < current.load(Ordering::SeqCst) {
        return FencedOutcome::Dropped;
    }
    if not_after.is_some_and(|deadline| monotonic_ns() >= deadline) {
        return FencedOutcome::Dropped;
    }
    if partial {
        let _ = writer
            .write_all(&data[..data.len() / 2])
            .and_then(|()| writer.flush());
        return FencedOutcome::Failed("write interrupted (test fault)".into());
    }
    match writer.write_all(data).and_then(|()| writer.flush()) {
        Ok(()) => FencedOutcome::Written(data.len()),
        Err(error) => FencedOutcome::Failed(error.to_string()),
    }
}

#[derive(Clone, Debug)]
pub struct PtyInput {
    tx: mpsc::Sender<WriteRequest>,
    /// Fenced terminal writes queued, shared by clones.
    inputs: Arc<AtomicU64>,
    /// The current input epoch for fenced writes; only ever rises.
    input_epoch: Arc<AtomicU64>,
}

impl PtyInput {
    /// Count of fenced terminal writes, not respond() or pastes.
    pub fn input_count(&self) -> u64 {
        self.inputs.load(Ordering::SeqCst)
    }

    pub fn respond(&self, data: Vec<u8>) -> Result<()> {
        self.enqueue(data)
    }

    /// Raises the input epoch fenced writes are checked against (never
    /// lowers it); returns the current one. A fenced write already queued
    /// with an older epoch is dropped when its turn comes.
    pub fn raise_input_epoch(&self, epoch: u64) -> u64 {
        self.input_epoch
            .fetch_max(epoch, Ordering::SeqCst)
            .max(epoch)
    }

    pub fn input_epoch(&self) -> u64 {
        self.input_epoch.load(Ordering::SeqCst)
    }

    /// Terminal input (counted) written only if `epoch` is still current
    /// (and `not_after`, a remote write's lease deadline, not reached) at
    /// the write boundary; the outcome comes back as `PtyEvent::Fenced`.
    pub fn write_fenced(
        &self,
        data: Vec<u8>,
        epoch: u64,
        sequence: u64,
        not_after: Option<u64>,
    ) -> Result<()> {
        self.enqueue_fenced_request(data, epoch, sequence, not_after, false)?;
        self.inputs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// A bracketed paste plus Enter as one fenced write (not counted as
    /// terminal input).
    /// Control characters other than newline and tab are refused, so no
    /// writer can end the bracketed paste early or submit early.
    pub fn paste_fenced(
        &self,
        text: &str,
        epoch: u64,
        sequence: u64,
        not_after: Option<u64>,
    ) -> Result<()> {
        if text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            bail!("A paste may hold no control characters other than newline and tab");
        }
        let mut bytes = Vec::with_capacity(text.len() + 13);
        bytes.extend_from_slice(b"\x1b[200~");
        bytes.extend_from_slice(text.as_bytes());
        bytes.extend_from_slice(b"\x1b[201~\r");
        if crate::runtime::test_hooks::fail_next_enqueue() {
            bail!("Terminal input was not queued (test fault)");
        }
        let partial = crate::runtime::test_hooks::fail_next_partial();
        self.enqueue_fenced_request(bytes, epoch, sequence, not_after, partial)
    }

    fn enqueue_fenced_request(
        &self,
        data: Vec<u8>,
        epoch: u64,
        sequence: u64,
        not_after: Option<u64>,
        partial: bool,
    ) -> Result<()> {
        if data.is_empty() || data.len() > MAX_FENCED {
            bail!("Input must contain 1..={MAX_FENCED} bytes");
        }
        self.tx
            .try_send(WriteRequest {
                data,
                sequence: Some(sequence),
                fence: Some(epoch),
                not_after,
                partial,
            })
            .map_err(|_| anyhow!("Terminal input queue full or closed; input was not queued"))
    }

    fn enqueue(&self, data: Vec<u8>) -> Result<()> {
        if data.is_empty() || data.len() > MAX_INPUT {
            bail!("Input must contain 1..={MAX_INPUT} bytes");
        }
        self.tx
            .try_send(WriteRequest {
                data,
                sequence: None,
                fence: None,
                not_after: None,
                partial: false,
            })
            .map_err(|_| anyhow!("Terminal input queue full or closed; input was not queued"))
    }

    #[cfg(test)]
    pub fn test_channel() -> (Self, TestInputReader) {
        let (tx, requests) = mpsc::channel::<WriteRequest>(64);
        (
            Self {
                tx,
                inputs: Arc::default(),
                input_epoch: Arc::default(),
            },
            TestInputReader(requests),
        )
    }
}

#[cfg(test)]
pub struct TestInputReader(mpsc::Receiver<WriteRequest>);
#[cfg(test)]
impl TestInputReader {
    pub fn try_recv(&mut self) -> Result<String, mpsc::error::TryRecvError> {
        self.0
            .try_recv()
            .map(|r| String::from_utf8(r.data).unwrap())
    }
}

struct Process {
    master: Mutex<Box<dyn MasterPty + Send>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
}

/// How long a hung-up agent gets to exit on its own before it is killed.
const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

fn stop_child(child: Arc<Mutex<Box<dyn Child + Send + Sync>>>) {
    std::thread::spawn(move || {
        // Serialize reaping and signalling (each under the lock): never signal
        // a recycled PID.
        {
            let mut child = child.lock().unwrap();
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            #[cfg(unix)]
            if let Some(pid) = child.process_id() {
                // The PTY child owns a session/process group. Notify its tools too,
                // and wake any stopped one (as the kernel does at a hangup), which
                // would otherwise keep its SIGHUP pending, stopped, forever.
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGHUP);
                    libc::kill(-(pid as i32), libc::SIGCONT);
                }
            }
        }
        // A clean exit (the agent saves its session, runs its end hooks),
        // else killed.
        let deadline = std::time::Instant::now() + STOP_GRACE;
        loop {
            let mut child = child.lock().unwrap();
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            if std::time::Instant::now() >= deadline {
                // The whole group, before the agent is reaped (its pid, and so
                // the group id, can't be recycled until then): a tool that
                // ignored the hangup would otherwise outlive the session.
                #[cfg(unix)]
                if let Some(pid) = child.process_id() {
                    unsafe {
                        libc::kill(-(pid as i32), libc::SIGKILL);
                    }
                }
                let _ = child.kill();
                return;
            }
            drop(child);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}

impl Drop for Process {
    fn drop(&mut self) {
        stop_child(self.child.clone());
    }
}

#[derive(Clone)]
pub struct PtyHandle(Arc<Process>);

impl std::fmt::Debug for PtyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PtyHandle")
    }
}

impl PtyHandle {
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        if !(2..=200).contains(&rows) || !(2..=400).contains(&cols) {
            bail!("Terminal size must be 2..200 rows and 2..400 columns");
        }
        self.0.master.lock().unwrap().resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
    }

    pub fn stop(&self) -> Result<()> {
        stop_child(self.0.child.clone());
        Ok(())
    }

    /// The agent process's pid (while it can still be asked).
    pub fn process_id(&self) -> Option<u32> {
        self.0.child.lock().ok()?.process_id()
    }
}

#[derive(Debug)]
pub struct PtySession {
    pub sender: PtyInput,
    pub receiver: mpsc::Receiver<PtyEvent>,
    pub resize_handle: PtyHandle,
}

/// What to spawn: `env` `None` inherits Atem's environment; `Some` replaces it.
/// `Debug` never prints the environment.
#[derive(Clone)]
pub struct SpawnSpec {
    pub binary: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: Option<Vec<(OsString, OsString)>>,
    pub rows: u16,
    pub cols: u16,
}

#[cfg(test)]
pub fn spawn(binary: &str, args: &[String]) -> Result<PtySession> {
    spawn_sized(binary, args, DEFAULT_ROWS, DEFAULT_COLS)
}

/// In Atem's working directory with its environment.
#[cfg(test)]
pub fn spawn_sized(binary: &str, args: &[String], rows: u16, cols: u16) -> Result<PtySession> {
    spawn_spec(SpawnSpec {
        binary: binary.into(),
        args: args.to_vec(),
        cwd: std::env::current_dir()?,
        env: None,
        rows,
        cols,
    })
}

/// Prints how many environment entries there are, never their names or values.
pub(crate) struct EnvSummary<'a>(pub &'a Option<Vec<(OsString, OsString)>>);

impl std::fmt::Debug for EnvSummary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(env) => write!(f, "<{} entries>", env.len()),
            None => f.write_str("<inherited>"),
        }
    }
}

impl std::fmt::Debug for SpawnSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnSpec")
            .field("binary", &self.binary)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .field("env", &EnvSummary(&self.env))
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish()
    }
}

pub fn spawn_spec(spec: SpawnSpec) -> Result<PtySession> {
    let SpawnSpec {
        binary,
        args,
        cwd,
        env,
        rows,
        cols,
    } = spec;
    if !(2..=200).contains(&rows) || !(2..=400).contains(&cols) {
        bail!("Terminal size must be 2..200 rows and 2..400 columns");
    }
    let pair = native_pty_system().openpty(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    if !cwd.is_dir() {
        bail!("{} is not a directory", cwd.display());
    }
    let mut command = CommandBuilder::new(binary);
    command.args(args);
    command.cwd(cwd);
    if let Some(env) = env {
        command.env_clear();
        for (name, value) in env {
            command.env(name, value);
        }
    }
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    command.env("TERM_PROGRAM", "Atem");
    command.env("TERM_PROGRAM_VERSION", env!("CARGO_PKG_VERSION"));
    command.env("FORCE_COLOR", "1");
    let child = Arc::new(Mutex::new(pair.slave.spawn_command(command)?));
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;
    let handle = PtyHandle(Arc::new(Process {
        master: Mutex::new(pair.master),
        child: child.clone(),
    }));
    let (tx, mut input) = mpsc::channel::<WriteRequest>(64);
    let (output, receiver) = mpsc::channel(64);
    let writer_output = output.clone();
    let input_epoch = Arc::new(AtomicU64::new(0));
    let writer_epoch = input_epoch.clone();
    std::thread::spawn(move || {
        while let Some(request) = input.blocking_recv() {
            if let (Some(fence), Some(sequence)) = (request.fence, request.sequence) {
                let outcome = write_fenced_request(
                    &mut writer,
                    &writer_epoch,
                    fence,
                    request.not_after,
                    &request.data,
                    request.partial,
                );
                if writer_output
                    .blocking_send(PtyEvent::Fenced { sequence, outcome })
                    .is_err()
                {
                    break;
                }
                continue;
            }
            if let Err(error) = write_request(&mut writer, &request) {
                let _ = writer_output.blocking_send(PtyEvent::Error(error));
            }
        }
    });
    std::thread::spawn(move || {
        let mut buf = [0; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if output
                        .blocking_send(PtyEvent::Output(buf[..n].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                // Linux reports PTY EOF as EIO.
                Err(e) if e.raw_os_error() == Some(5) => break,
                Err(e) => {
                    let _ = output.blocking_send(PtyEvent::Error(e.to_string()));
                    break;
                }
            }
        }
        let status = loop {
            match child.lock().unwrap().try_wait() {
                Ok(Some(status)) => break status.to_string(),
                Err(error) => break error.to_string(),
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };
        let _ = output.blocking_send(PtyEvent::Exit(status));
    });
    Ok(PtySession {
        sender: PtyInput {
            tx,
            inputs: Arc::default(),
            input_epoch,
        },
        receiver,
        resize_handle: handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respond_writes_without_counting_as_terminal_input() {
        let (input, mut queued) = PtyInput::test_channel();
        input.respond(b"\x1b[1;1R".to_vec()).unwrap();
        assert_eq!(input.input_count(), 0);
        let request = queued.0.try_recv().unwrap();
        let mut destination = Vec::new();
        write_request(&mut destination, &request).unwrap();
        assert_eq!(destination, b"\x1b[1;1R");
        assert!(input.respond(Vec::new()).is_err());
        assert!(input.respond(vec![0; MAX_INPUT + 1]).is_err());
    }

    #[test]
    fn a_fenced_write_older_than_the_current_epoch_is_dropped_at_the_writer() {
        let (input, mut queued) = PtyInput::test_channel();
        assert_eq!(input.raise_input_epoch(3), 3);
        input.write_fenced(b"old".to_vec(), 3, 1, None).unwrap();
        input.paste_fenced("hi", 3, 2, None).unwrap();
        // Raised after they were queued: both are dropped when written.
        assert_eq!(input.raise_input_epoch(4), 4);
        // Never lowered.
        assert_eq!(input.raise_input_epoch(2), 4);
        assert_eq!(input.input_epoch(), 4);
        input.write_fenced(b"new".to_vec(), 4, 3, None).unwrap();
        let mut destination = Vec::new();
        let mut outcomes = Vec::new();
        while let Ok(request) = queued.0.try_recv() {
            outcomes.push(write_fenced_request(
                &mut destination,
                &input.input_epoch,
                request.fence.unwrap(),
                request.not_after,
                &request.data,
                request.partial,
            ));
        }
        assert_eq!(
            outcomes,
            [
                FencedOutcome::Dropped,
                FencedOutcome::Dropped,
                FencedOutcome::Written(3)
            ]
        );
        assert_eq!(destination, b"new");
        // Writes count as terminal input; pastes don't.
        assert_eq!(input.input_count(), 2);
        assert!(input.write_fenced(Vec::new(), 4, 4, None).is_err());
        assert!(
            input
                .write_fenced(vec![0; MAX_FENCED + 1], 4, 4, None)
                .is_err()
        );
    }

    #[test]
    fn a_remote_write_past_its_deadline_is_dropped_at_the_writer() {
        let (input, mut queued) = PtyInput::test_channel();
        let now = monotonic_ns();
        let later = now + 60_000_000_000;
        input
            .write_fenced(b"late".to_vec(), 0, 1, Some(now))
            .unwrap();
        input
            .write_fenced(b"on time".to_vec(), 0, 2, Some(later))
            .unwrap();
        input.paste_fenced("late", 0, 3, Some(now - 1)).unwrap();
        input.write_fenced(b"local".to_vec(), 0, 4, None).unwrap();
        let mut destination = Vec::new();
        let mut outcomes = Vec::new();
        while let Ok(request) = queued.0.try_recv() {
            outcomes.push(write_fenced_request(
                &mut destination,
                &input.input_epoch,
                request.fence.unwrap(),
                request.not_after,
                &request.data,
                request.partial,
            ));
        }
        assert_eq!(
            outcomes,
            [
                FencedOutcome::Dropped,
                FencedOutcome::Written(7),
                FencedOutcome::Dropped,
                FencedOutcome::Written(5)
            ]
        );
        assert_eq!(destination, b"on timelocal");
    }

    #[test]
    fn a_fenced_paste_refuses_control_characters_but_newline_and_tab() {
        let (input, mut queued) = PtyInput::test_channel();
        for bad in [
            "end\x1b[201~rm -rf ~\r",
            "a\rb",
            "\x03",
            "\u{9b}201~",
            "\x7f",
        ] {
            assert!(input.paste_fenced(bad, 0, 1, None).is_err(), "{bad:?}");
        }
        assert!(queued.try_recv().is_err(), "nothing was queued");
        input
            .paste_fenced("line one\n\tline two", 0, 2, None)
            .unwrap();
        assert_eq!(
            queued.try_recv().unwrap(),
            "\x1b[200~line one\n\tline two\x1b[201~\r"
        );
    }

    #[test]
    fn a_full_input_queue_refuses_more() {
        let (input, _queued) = PtyInput::test_channel();
        for _ in 0..64 {
            input.respond(b"x".to_vec()).unwrap();
        }
        assert!(input.respond(b"overflow".to_vec()).is_err());
    }

    async fn output_of(mut session: PtySession) -> String {
        let mut output = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), session.receiver.recv())
                .await
                .unwrap()
                .unwrap()
            {
                PtyEvent::Output(bytes) => output.extend(bytes),
                PtyEvent::Exit(_) => break,
                _ => {}
            }
        }
        String::from_utf8(output).unwrap()
    }

    #[tokio::test]
    async fn spawn_spec_uses_the_given_directory_and_environment() {
        let dir = tempfile::tempdir().unwrap();
        let script = "printf '%s|%s|%s|%s' \"$PWD\" \"$ATEM_SPEC\" \"${HOME:-none}\" \"$TERM\"";
        let spec = SpawnSpec {
            binary: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            cwd: dir.path().to_path_buf(),
            env: Some(vec![
                ("ATEM_SPEC".into(), "given".into()),
                ("PATH".into(), "/usr/bin:/bin".into()),
            ]),
            rows: 24,
            cols: 80,
        };
        let output = output_of(spawn_spec(spec.clone()).unwrap()).await;
        let cwd = dir.path().canonicalize().unwrap();
        // Only the given environment, plus the terminal variables.
        assert_eq!(
            output,
            format!("{}|given|none|xterm-256color", cwd.display())
        );
        // None inherits Atem's environment.
        let inherited = SpawnSpec { env: None, ..spec };
        let output = output_of(spawn_spec(inherited).unwrap()).await;
        let home = std::env::var("HOME").unwrap_or_else(|_| "none".into());
        assert_eq!(output, format!("{}||{home}|xterm-256color", cwd.display()));
    }

    #[test]
    fn a_spawn_spec_never_prints_its_environment() {
        let spec = SpawnSpec {
            binary: "claude".into(),
            args: Vec::new(),
            cwd: std::env::temp_dir(),
            env: Some(vec![("API_TOKEN".into(), "s3cr3t-value".into())]),
            rows: 24,
            cols: 80,
        };
        let text = format!("{spec:?}");
        assert!(
            !text.contains("s3cr3t-value") && !text.contains("API_TOKEN"),
            "{text}"
        );
        assert!(text.contains("env: <1 entries>"), "{text}");
    }

    #[test]
    fn spawn_spec_refuses_a_bad_size_or_directory() {
        let spec = SpawnSpec {
            binary: "cat".into(),
            args: Vec::new(),
            cwd: std::env::temp_dir(),
            env: None,
            rows: 1,
            cols: 80,
        };
        assert!(spawn_spec(spec.clone()).is_err());
        let missing = SpawnSpec {
            cwd: "/nonexistent/atem-test-dir".into(),
            rows: 24,
            ..spec
        };
        assert!(spawn_spec(missing).is_err());
    }

    #[tokio::test]
    async fn cli_output_cannot_impersonate_an_exit_event() {
        let mut session = spawn("printf", &["Codex CLI exited with status fake".into()]).unwrap();
        let mut output = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(3), session.receiver.recv())
                .await
                .unwrap()
                .unwrap()
            {
                PtyEvent::Output(bytes) => output.extend(bytes),
                PtyEvent::Exit(_) => break,
                event => panic!("unexpected {event:?}"),
            }
        }
        assert_eq!(output, b"Codex CLI exited with status fake");
    }

    #[tokio::test]
    async fn explicit_stop_terminates_the_child_and_drains_output_before_exit() {
        let mut session = spawn("cat", &[]).unwrap();
        session.sender.respond(b"before stop\n".to_vec()).unwrap();
        while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Output(_)) {}
        session.resize_handle.stop().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Exit(_)) {}
        })
        .await
        .unwrap();
    }

    /// The exit status `stop` leads to for `script` (run by `sh -c`).
    async fn status_after_stop(script: &str) -> String {
        let mut session = spawn("sh", &["-c".into(), script.into()]).unwrap();
        while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Output(_)) {}
        session.resize_handle.stop().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let PtyEvent::Exit(status) = session.receiver.recv().await.unwrap() {
                    return status;
                }
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn stop_lets_the_agent_exit_on_its_own_hangup() {
        // Exits 7 on SIGHUP, as an agent saving its session would exit by itself.
        let status = status_after_stop("trap 'exit 7' HUP; echo up; sleep 30 & wait").await;
        assert!(!status.contains("Killed"), "{status}");
        assert!(status.contains('7'), "{status}");
    }

    #[tokio::test]
    async fn stop_kills_an_agent_that_ignores_its_hangup_after_the_grace() {
        let started = std::time::Instant::now();
        let status = status_after_stop("trap '' HUP; echo up; sleep 30 & wait").await;
        assert!(started.elapsed() >= STOP_GRACE, "{status}");
        assert!(
            status.contains("Killed") || status.contains('9'),
            "{status}"
        );
    }

    /// A tool the agent started that ignores the hangup too is killed with
    /// the agent's process group, never left running after the session.
    #[tokio::test]
    async fn stop_kills_the_agents_tools_with_it() {
        let mut session = spawn(
            "sh",
            &[
                "-c".into(),
                "trap '' HUP; sleep 300 & echo \"tool=$!\"; wait".into(),
            ],
        )
        .unwrap();
        let mut output = String::new();
        let tool: libc::pid_t = loop {
            if let PtyEvent::Output(bytes) = session.receiver.recv().await.unwrap() {
                output.push_str(&String::from_utf8_lossy(&bytes));
                if let Some(pid) = output
                    .split("tool=")
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|pid| pid.parse().ok())
                {
                    break pid;
                }
            }
        };
        // Never leave it behind, even when the test fails.
        struct Kill(libc::pid_t);
        impl Drop for Kill {
            fn drop(&mut self) {
                unsafe { libc::kill(self.0, libc::SIGKILL) };
            }
        }
        let _guard = Kill(tool);
        session.resize_handle.stop().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Exit(_)) {}
        })
        .await
        .unwrap();
        // Killed (a zombie until init reaps it) or already gone.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let gone = loop {
            // A zombie answers `kill(0)` too; on Linux tell it apart, elsewhere
            // init reaps it within the deadline.
            let zombie = cfg!(target_os = "linux")
                && std::fs::read_to_string(format!("/proc/{tool}/stat"))
                    .map(|stat| {
                        stat.rsplit(')')
                            .next()
                            .unwrap_or("")
                            .trim_start()
                            .starts_with('Z')
                    })
                    .unwrap_or(false);
            let alive = unsafe { libc::kill(tool, 0) } == 0 && !zombie;
            if !alive || std::time::Instant::now() >= deadline {
                break !alive;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert!(gone, "the agent's tool {tool} outlived the stopped session");
    }
}

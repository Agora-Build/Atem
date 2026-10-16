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
pub const DEFAULT_ROWS: u16 = 40;
pub const DEFAULT_COLS: u16 = 120;
pub const SCROLLBACK_ROWS: usize = 2000;

#[derive(Debug)]
pub enum PtyEvent {
    Output(Vec<u8>),
    Exit(String),
    Error(String),
    Written {
        sequence: u64,
        result: Result<(), String>,
    },
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

#[derive(Debug, Default)]
struct Authority {
    epoch: u64,
    remote: bool,
}

#[derive(Debug)]
struct WriteRequest {
    data: Vec<u8>,
    epoch: Option<u64>,
    sequence: Option<u64>,
    /// A fenced write: its input epoch, compared at the write boundary with
    /// the current one (`PtyInput::raise_input_epoch`).
    fence: Option<u64>,
}

fn write_request(
    writer: &mut impl Write,
    authority: &Mutex<Authority>,
    request: &WriteRequest,
) -> Result<(), String> {
    let valid = request
        .epoch
        .is_none_or(|epoch| authority.lock().unwrap().epoch == epoch);
    if !valid {
        return Err("Control changed before input was written".into());
    }
    writer
        .write_all(&request.data)
        .and_then(|()| writer.flush())
        .map_err(|e| e.to_string())
}

/// A fenced write at the write boundary: dropped when `fence` is older than
/// the current input epoch.
fn write_fenced_request(
    writer: &mut impl Write,
    current: &AtomicU64,
    fence: u64,
    data: &[u8],
) -> FencedOutcome {
    if fence < current.load(Ordering::SeqCst) {
        return FencedOutcome::Dropped;
    }
    match writer.write_all(data).and_then(|()| writer.flush()) {
        Ok(()) => FencedOutcome::Written(data.len()),
        Err(error) => FencedOutcome::Failed(error.to_string()),
    }
}

#[derive(Clone, Debug)]
pub struct PtyInput {
    tx: mpsc::Sender<WriteRequest>,
    authority: Arc<Mutex<Authority>>,
    /// Successful send()/send_remote() calls, shared by clones.
    inputs: Arc<AtomicU64>,
    /// The current input epoch for fenced writes; only ever rises.
    input_epoch: Arc<AtomicU64>,
}

impl PtyInput {
    pub fn remote_controlled(&self) -> bool {
        self.authority.lock().unwrap().remote
    }

    pub fn set_remote(&self, remote: bool) -> u64 {
        let mut authority = self.authority.lock().unwrap();
        authority.epoch += 1;
        authority.remote = remote;
        authority.epoch
    }

    /// Local/automation writes cannot bypass an active remote controller.
    pub fn send(&self, data: String) -> Result<()> {
        self.send_bytes(data.into_bytes())
    }

    /// `send` for bytes that need not be UTF-8 (a local frontend's keys).
    pub fn send_bytes(&self, data: Vec<u8>) -> Result<()> {
        let authority = self.authority.lock().unwrap();
        if authority.remote {
            bail!("Remote control is active; use Atem's Take Control command");
        }
        self.enqueue(data, Some(authority.epoch), None)?;
        self.inputs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Count of send()/send_remote() calls (terminal input), not respond() or send_paste().
    pub fn input_count(&self) -> u64 {
        self.inputs.load(Ordering::SeqCst)
    }

    /// Bracketed paste plus Enter, queued as consecutive chunks of at most MAX_INPUT bytes
    /// while holding the authority lock, so send()/send_remote() cannot interleave.
    /// Refused while remote-controlled. Does not count as terminal input. On a full
    /// queue the error is returned and nothing is resent.
    pub fn send_paste(&self, text: &str) -> Result<()> {
        let authority = self.authority.lock().unwrap();
        if authority.remote {
            bail!("Remote control is active; use Atem's Take Control command");
        }
        let mut bytes = Vec::with_capacity(text.len() + 13);
        bytes.extend_from_slice(b"\x1b[200~");
        bytes.extend_from_slice(text.as_bytes());
        bytes.extend_from_slice(b"\x1b[201~\r");
        let chunks: Vec<&[u8]> = bytes.chunks(MAX_INPUT).collect();
        // Reserve every slot first: all chunks are queued or none is.
        let permits = self
            .tx
            .try_reserve_many(chunks.len())
            .map_err(|_| anyhow!("Terminal input queue full or closed; input was not queued"))?;
        for (permit, chunk) in permits.zip(chunks) {
            permit.send(WriteRequest {
                data: chunk.to_vec(),
                epoch: Some(authority.epoch),
                sequence: None,
                fence: None,
            });
        }
        Ok(())
    }

    pub fn send_remote(&self, data: Vec<u8>, epoch: u64, sequence: u64) -> Result<()> {
        let authority = self.authority.lock().unwrap();
        if !authority.remote || authority.epoch != epoch {
            bail!("Control lease expired");
        }
        self.enqueue(data, Some(epoch), Some(sequence))?;
        self.inputs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    pub fn respond(&self, data: Vec<u8>) -> Result<()> {
        self.enqueue(data, None, None)
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

    /// Terminal input (counted) written only if `epoch` is still current at
    /// the write boundary; the outcome comes back as `PtyEvent::Fenced`.
    pub fn write_fenced(&self, data: Vec<u8>, epoch: u64, sequence: u64) -> Result<()> {
        self.enqueue_fenced(data, epoch, sequence)?;
        self.inputs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// A bracketed paste plus Enter as one fenced write (not counted as
    /// terminal input, like `send_paste`).
    /// Control characters other than newline and tab are refused, so no
    /// writer can end the bracketed paste early or submit early.
    pub fn paste_fenced(&self, text: &str, epoch: u64, sequence: u64) -> Result<()> {
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
        self.enqueue_fenced(bytes, epoch, sequence)
    }

    fn enqueue_fenced(&self, data: Vec<u8>, epoch: u64, sequence: u64) -> Result<()> {
        if data.is_empty() || data.len() > MAX_FENCED {
            bail!("Input must contain 1..={MAX_FENCED} bytes");
        }
        self.tx
            .try_send(WriteRequest {
                data,
                epoch: None,
                sequence: Some(sequence),
                fence: Some(epoch),
            })
            .map_err(|_| anyhow!("Terminal input queue full or closed; input was not queued"))
    }

    fn enqueue(&self, data: Vec<u8>, epoch: Option<u64>, sequence: Option<u64>) -> Result<()> {
        if data.is_empty() || data.len() > MAX_INPUT {
            bail!("Input must contain 1..={MAX_INPUT} bytes");
        }
        self.tx
            .try_send(WriteRequest {
                data,
                epoch,
                sequence,
                fence: None,
            })
            .map_err(|_| anyhow!("Terminal input queue full or closed; input was not queued"))
    }

    #[cfg(test)]
    pub fn test_channel() -> (Self, TestInputReader) {
        let (tx, requests) = mpsc::channel::<WriteRequest>(64);
        (
            Self {
                tx,
                authority: Arc::default(),
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

fn stop_child(child: Arc<Mutex<Box<dyn Child + Send + Sync>>>) {
    std::thread::spawn(move || {
        let mut child = child.lock().unwrap();
        // Serialize reaping and signalling: never signal a recycled PID.
        if matches!(child.try_wait(), Ok(None)) {
            #[cfg(unix)]
            if let Some(pid) = child.process_id() {
                // The PTY child owns a session/process group. Notify its tools too.
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGHUP);
                }
            }
            let _ = child.kill();
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
    let authority = Arc::new(Mutex::new(Authority::default()));
    let writer_authority = authority.clone();
    let writer_output = output.clone();
    let input_epoch = Arc::new(AtomicU64::new(0));
    let writer_epoch = input_epoch.clone();
    std::thread::spawn(move || {
        while let Some(request) = input.blocking_recv() {
            if let (Some(fence), Some(sequence)) = (request.fence, request.sequence) {
                let outcome =
                    write_fenced_request(&mut writer, &writer_epoch, fence, &request.data);
                if writer_output
                    .blocking_send(PtyEvent::Fenced { sequence, outcome })
                    .is_err()
                {
                    break;
                }
                continue;
            }
            // Recheck at the actual write boundary, not merely when enqueueing.
            let result = write_request(&mut writer, &writer_authority, &request);
            if let Some(sequence) = request.sequence {
                if writer_output
                    .blocking_send(PtyEvent::Written { sequence, result })
                    .is_err()
                {
                    break;
                }
            } else if let Err(error) = result {
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
            authority,
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
    fn send_paste_chunk_boundaries_at_max_input() {
        let (input, mut q) = PtyInput::test_channel();
        input.send_paste(&"a".repeat(MAX_INPUT - 13)).unwrap();
        assert!(q.try_recv().is_ok());
        assert!(q.try_recv().is_err());
        input.send_paste(&"a".repeat(MAX_INPUT - 12)).unwrap();
        assert!(q.try_recv().is_ok());
        assert!(q.try_recv().is_ok());
        assert!(q.try_recv().is_err());
    }

    #[test]
    fn send_paste_is_all_or_nothing() {
        let (input, mut q) = PtyInput::test_channel();
        for _ in 0..63 {
            input.send("x".into()).unwrap();
        }
        // one free slot, three chunks needed
        assert!(input.send_paste(&"a".repeat(32 * 1024)).is_err());
        let mut n = 0;
        while q.try_recv().is_ok() {
            n += 1;
        }
        assert_eq!(n, 63, "no paste chunk may be queued");
    }

    #[test]
    fn input_count_counts_send_and_send_remote_not_respond_or_paste() {
        let (input, _q) = PtyInput::test_channel();
        assert_eq!(input.input_count(), 0);
        input.send("a".into()).unwrap();
        assert_eq!(input.input_count(), 1);
        input.respond(b"y".to_vec()).unwrap();
        input.send_paste("hello").unwrap();
        assert_eq!(input.input_count(), 1);
        let epoch = input.set_remote(true);
        assert!(input.send("b".into()).is_err());
        input.send_remote(b"c".to_vec(), epoch, 1).unwrap();
        assert_eq!(input.clone().input_count(), 2);
    }

    #[test]
    fn send_paste_wraps_in_bracketed_paste() {
        let (input, mut q) = PtyInput::test_channel();
        input.send_paste("hi there").unwrap();
        assert_eq!(q.try_recv().unwrap(), "\x1b[200~hi there\x1b[201~\r");
        assert!(q.try_recv().is_err());
        input.set_remote(true);
        assert!(input.send_paste("x").is_err());
    }

    #[test]
    fn send_paste_chunks_large_text_in_order() {
        let (input, mut q) = PtyInput::test_channel();
        let text = "a".repeat(32 * 1024);
        input.send_paste(&text).unwrap();
        let mut all = String::new();
        let mut n = 0;
        while let Ok(c) = q.try_recv() {
            assert!(c.len() <= MAX_INPUT);
            all.push_str(&c);
            n += 1;
        }
        assert_eq!(n, 3);
        assert_eq!(all, format!("\x1b[200~{text}\x1b[201~\r"));
    }

    #[test]
    fn queued_input_is_checked_again_at_writer_after_handoff() {
        let (input, mut queued) = PtyInput::test_channel();
        let epoch = input.set_remote(true);
        input
            .send_remote(b"old approval\r".to_vec(), epoch, 1)
            .unwrap();
        input.set_remote(false);
        let request = queued.0.try_recv().unwrap();
        let mut destination = Vec::new();
        assert!(write_request(&mut destination, &input.authority, &request).is_err());
        assert!(destination.is_empty());
        input.send("new local input".into()).unwrap();
        let request = queued.0.try_recv().unwrap();
        write_request(&mut destination, &input.authority, &request).unwrap();
        assert_eq!(destination, b"new local input");
    }

    #[test]
    fn a_fenced_write_older_than_the_current_epoch_is_dropped_at_the_writer() {
        let (input, mut queued) = PtyInput::test_channel();
        assert_eq!(input.raise_input_epoch(3), 3);
        input.write_fenced(b"old".to_vec(), 3, 1).unwrap();
        input.paste_fenced("hi", 3, 2).unwrap();
        // Raised after they were queued: both are dropped when written.
        assert_eq!(input.raise_input_epoch(4), 4);
        // Never lowered.
        assert_eq!(input.raise_input_epoch(2), 4);
        assert_eq!(input.input_epoch(), 4);
        input.write_fenced(b"new".to_vec(), 4, 3).unwrap();
        let mut destination = Vec::new();
        let mut outcomes = Vec::new();
        while let Ok(request) = queued.0.try_recv() {
            outcomes.push(write_fenced_request(
                &mut destination,
                &input.input_epoch,
                request.fence.unwrap(),
                &request.data,
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
        assert!(input.write_fenced(Vec::new(), 4, 4).is_err());
        assert!(input.write_fenced(vec![0; MAX_FENCED + 1], 4, 4).is_err());
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
            assert!(input.paste_fenced(bad, 0, 1).is_err(), "{bad:?}");
        }
        assert!(queued.try_recv().is_err(), "nothing was queued");
        input.paste_fenced("line one\n\tline two", 0, 2).unwrap();
        assert_eq!(
            queued.try_recv().unwrap(),
            "\x1b[200~line one\n\tline two\x1b[201~\r"
        );
    }

    #[test]
    fn full_input_queue_rejects_without_partial_paste() {
        let (input, _queued) = PtyInput::test_channel();
        assert!(input.send("x".repeat(MAX_INPUT + 1)).is_err());
        for _ in 0..64 {
            input.send("x".into()).unwrap();
        }
        assert!(input.send("overflow".into()).is_err());
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
        session.sender.send("before stop\n".into()).unwrap();
        while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Output(_)) {}
        session.resize_handle.stop().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Exit(_)) {}
        })
        .await
        .unwrap();
    }
}

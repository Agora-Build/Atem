//! Shared byte-oriented PTY transport. Terminal data and lifecycle events never mix.
use anyhow::{Result, anyhow, bail};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
    /// A chat prompt while prompts were held (`PtyInput::hold_prompts`: an
    /// approval waits, or sits in the agent's own dialog): nothing written.
    Held,
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
    /// A chat prompt (`paste_fenced`): held back at the write boundary while
    /// prompts are held.
    prompt: bool,
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
/// the current input epoch, or when its `not_after` has passed; a chat
/// prompt is held back while `prompts_held`.
fn write_fenced_request(
    writer: &mut impl Write,
    current: &AtomicU64,
    prompts_held: &AtomicBool,
    request: &WriteRequest,
) -> FencedOutcome {
    let Some(fence) = request.fence else {
        return FencedOutcome::Failed("not a fenced write".into());
    };
    let (data, not_after) = (&request.data[..], request.not_after);
    crate::runtime::test_hooks::hold_writes();
    if fence < current.load(Ordering::SeqCst) {
        return FencedOutcome::Dropped;
    }
    if not_after.is_some_and(|deadline| monotonic_ns() >= deadline) {
        return FencedOutcome::Dropped;
    }
    if request.prompt && prompts_held.load(Ordering::SeqCst) {
        return FencedOutcome::Held;
    }
    if request.partial {
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
    /// Chat prompts are held back at the write boundary (`hold_prompts`).
    prompts_held: Arc<AtomicBool>,
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

    /// While `held`, a chat prompt (`paste_fenced`) reaching the write
    /// boundary is not written (`FencedOutcome::Held`), however long it was
    /// queued: an approval waits, or sits in the agent's own dialog, where
    /// the paste's Enter would answer it.
    pub fn hold_prompts(&self, held: bool) {
        self.prompts_held.store(held, Ordering::SeqCst);
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
        self.enqueue_fenced_request(data, epoch, sequence, not_after, false, false)?;
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
        self.enqueue_fenced_request(bytes, epoch, sequence, not_after, partial, true)
    }

    fn enqueue_fenced_request(
        &self,
        data: Vec<u8>,
        epoch: u64,
        sequence: u64,
        not_after: Option<u64>,
        partial: bool,
        prompt: bool,
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
                prompt,
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
                prompt: false,
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
                prompts_held: Arc::default(),
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

impl Process {
    /// Output stopped with ^S (`IXON`) started again, as ^Q would. The
    /// session holds the slave until the child's output was read
    /// ([`SlaveHold`]), so on macOS an agent that exits with its output
    /// stopped waits in the kernel until it is read: a stop never leaves it
    /// there.
    fn restart_output(&self) {
        if let Ok(master) = self.master.lock()
            && let Some(fd) = master.as_raw_fd()
        {
            // SAFETY: `fd` is the master, open while `master` is borrowed.
            unsafe { libc::tcflow(fd, libc::TCOON) };
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.restart_output();
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
        self.0.restart_output();
        stop_child(self.0.child.clone());
        Ok(())
    }

    /// The agent process's pid (while it can still be asked).
    pub fn process_id(&self) -> Option<u32> {
        self.0.child.lock().ok()?.process_id()
    }

    /// The slave's path (tests).
    #[cfg(test)]
    fn tty_name(&self) -> Option<PathBuf> {
        self.0.master.lock().ok()?.tty_name()
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

/// The child's output, every byte it wrote before its exit, comes before
/// its `Exit`, on Linux and macOS alike ([`SlaveHold`]).
pub fn spawn_spec(spec: SpawnSpec) -> Result<PtySession> {
    spawn_with_faults(spec, ReaderFaults::default())
}

/// Keeps a child's last output readable. On macOS, when the slave's last
/// descriptor closes, the kernel waits 0.6 s for the master to read what is
/// left (`ptsclose` drains with `t_timeout = 60` ticks), then discards it,
/// and the master reads EOF: a reader late by that much (a busy host) lost
/// everything a child wrote just before it exited. The session holds a
/// slave descriptor until the child exited and the master has nothing left
/// to read, so the child's exit is never that last close: a session leader's
/// exit (the agent's) drains its terminal with no time limit, then revokes
/// it, and the master reads EOF once it read everything. Linux keeps the
/// output readable after the last close (EIO only once it was read), so
/// there the hold only delays EIO until the exit was seen.
///
/// So on macOS the agent's exit now always goes the way of a session
/// leader's: SIGHUP to the terminal's foreground process group (as Linux
/// does), then the terminal revoked. Before, when nothing else held the
/// slave, the agent's last close dropped the controlling terminal and its
/// exit sent neither; helpers left in its process group now get a hangup
/// when it exits, as they do on Linux and at a stop.
struct SlaveHold {
    /// The parent's slave descriptor (close-on-exec).
    _slave: Box<dyn SlavePty + Send>,
    /// Readable once the child exited ([`watch_exit`]).
    exited: std::io::PipeReader,
}

/// Writes a byte to `exited` once the child `pid` exited. `WNOWAIT` leaves
/// it a zombie, so `Child::try_wait` still reaps it and reads its status;
/// any error (ECHILD: reaped already, by `stop_child` or the reader) counts
/// as exited. Only a reap before this thread's `waitid` and the pid reused
/// for another child of this process in between (pids are recycled after
/// the whole range) could make it wait for the wrong process. It keeps
/// `reading`, a copy of the pipe's read end, until it has written: the
/// write never meets a closed pipe (EPIPE, or SIGPIPE were it not ignored).
///
/// It also keeps `master`, a copy of the master, until it saw the exit, so
/// while this process lives the PTY's index can't be reused before then,
/// whichever path let the slave and the other master copies go first (the
/// reader takes the copy away after a read error, [`MasterHold`]). On macOS
/// a session leader's exit (with the slave held, every agent's) revokes
/// every vnode of its terminal's device number, after its descriptors are
/// closed: had the pair been freed meanwhile, the revoke would hit a newer
/// terminal that took the same `/dev/ttysN` (another session's, or any
/// program's on the Mac). A watcher waiting on a recycled pid (above) would
/// also keep the index until that process exits. `exit_hold` is a test
/// fault: how much longer the copy stays (a child still on its way out).
fn watch_exit(
    pid: u32,
    mut exited: std::io::PipeWriter,
    reading: std::io::PipeReader,
    master: MasterHold,
    exit_hold: Duration,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("atem-pty-exit".into())
        // It only waits and writes a byte.
        .stack_size(64 * 1024)
        .spawn(move || {
            loop {
                // SAFETY: a zeroed `siginfo_t` is valid for `waitid` to fill.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // SAFETY: plain syscall on our own child's pid with a valid out
                // pointer.
                let waited = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOWAIT,
                    )
                };
                if waited == 0
                    || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    break;
                }
            }
            // A byte, not only the closed end: a copy of this end another child
            // inherited (a fork before close-on-exec was set) can't keep the
            // reader waiting.
            let _ = exited.write_all(&[1]);
            drop(reading);
            if !exit_hold.is_zero() {
                std::thread::sleep(exit_hold);
            }
            master.release();
        })?;
    Ok(())
}

/// The exit watcher's copy of the master ([`watch_exit`]), shared with the
/// reader, which takes it away after a read error: nothing reads the master
/// then, and a macOS agent already draining its output at its exit waits
/// until every master copy is closed, so a copy kept until that exit would
/// keep both waiting. So after a read error the index can again be freed
/// before such an agent's revoke, if the session is also dropped first; the
/// worker keeps the session until `Exit`, so it never is. Like this process
/// exiting, which closes every copy, that case is not covered.
#[derive(Clone)]
struct MasterHold(Arc<Mutex<Option<std::fs::File>>>);

impl MasterHold {
    fn new(master: std::fs::File) -> Self {
        MasterHold(Arc::new(Mutex::new(Some(master))))
    }

    /// Closes the copy (idempotent).
    fn release(&self) {
        let copy = self.0.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(copy);
    }
}

/// While the slave is held: waits until the master has something to read
/// (`true`: output, or the EOF/EIO a macOS session leader's exit leads to)
/// or the child exited with nothing left to read (`false`: let the slave
/// go). Output first, so after the exit the master is read dry before the
/// slave goes. `false` too if it can't wait (plain reads, as without a hold).
fn output_before_exit(master: RawFd, exited: RawFd) -> bool {
    let mut fds = [
        libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: exited,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a valid array of two pollfds for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if fds[0].revents != 0 {
            return true;
        }
        if fds[1].revents != 0 {
            return false;
        }
    }
}

/// Tests only: a reader that starts `delay` late (slower than macOS's 0.6 s
/// at the slave's last close), or whose first read fails; an exit watcher
/// that keeps its master copy `exit_hold` longer after it saw the exit (a
/// child still on its way out).
#[derive(Clone, Copy, Default)]
struct ReaderFaults {
    delay: Duration,
    fail_first_read: bool,
    exit_hold: Duration,
}

/// [`spawn_spec`], with the reader's `faults` (none outside tests).
fn spawn_with_faults(spec: SpawnSpec, faults: ReaderFaults) -> Result<PtySession> {
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
    // The reader's own master descriptor (read and polled), the exit pipe
    // and the writer: made before the child, so no failure leaves it behind.
    let master_fd = pair
        .master
        .as_raw_fd()
        .ok_or_else(|| anyhow!("the PTY master has no descriptor"))?;
    // SAFETY: `master_fd` is the master's, open while `pair.master` lives.
    let mut reader =
        std::fs::File::from(unsafe { BorrowedFd::borrow_raw(master_fd) }.try_clone_to_owned()?);
    let (exited, exit_signal) = std::io::pipe()?;
    let reading = exited.try_clone()?;
    let master_hold = MasterHold::new(reader.try_clone()?);
    let mut writer = pair.master.take_writer()?;
    let child = Arc::new(Mutex::new(pair.slave.spawn_command(command)?));
    let pid = child.lock().unwrap().process_id();
    let watching = pid.is_some_and(|pid| {
        watch_exit(
            pid,
            exit_signal,
            reading,
            master_hold.clone(),
            faults.exit_hold,
        )
        .is_ok()
    });
    let hold = if watching {
        Some(SlaveHold {
            _slave: pair.slave,
            exited,
        })
    } else {
        // Atem doesn't hold the slave: the child's exit is normally its last
        // close and revokes nothing, and without a watcher nothing could
        // tell when to let the copy go.
        master_hold.release();
        drop(pair.slave);
        None
    };
    let handle = PtyHandle(Arc::new(Process {
        master: Mutex::new(pair.master),
        child: child.clone(),
    }));
    let (tx, mut input) = mpsc::channel::<WriteRequest>(64);
    let (output, receiver) = mpsc::channel(64);
    let writer_output = output.clone();
    let input_epoch = Arc::new(AtomicU64::new(0));
    let writer_epoch = input_epoch.clone();
    let prompts_held = Arc::new(AtomicBool::new(false));
    let writer_held = prompts_held.clone();
    std::thread::spawn(move || {
        while let Some(request) = input.blocking_recv() {
            if let (Some(_), Some(sequence)) = (request.fence, request.sequence) {
                let outcome =
                    write_fenced_request(&mut writer, &writer_epoch, &writer_held, &request);
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
        if !faults.delay.is_zero() {
            std::thread::sleep(faults.delay);
        }
        let mut fail_read = faults.fail_first_read;
        let mut hold = hold;
        // The receiver takes the events; once it is gone, the output is
        // still read, and dropped.
        let mut listened = true;
        let mut buf = [0; 4096];
        loop {
            if let Some(held) = &hold
                && !output_before_exit(reader.as_raw_fd(), held.exited.as_raw_fd())
            {
                // The child exited and everything it wrote was read: the
                // master ends (EOF/EIO) once no other process holds the
                // slave (its tools).
                hold = None;
            }
            let read = if std::mem::take(&mut fail_read) {
                Err(std::io::Error::other("injected read error"))
            } else {
                reader.read(&mut buf)
            };
            match read {
                Ok(0) => break,
                Ok(n) => {
                    if listened
                        && output
                            .blocking_send(PtyEvent::Output(buf[..n].to_vec()))
                            .is_err()
                    {
                        // Nobody takes the output any more: the slave goes,
                        // and the master is still read to its end, so a
                        // macOS agent whose exit waits for its output to be
                        // read never waits on a reader that stopped.
                        listened = false;
                        hold = None;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                // Linux reports PTY EOF as EIO.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => {
                    if listened {
                        let _ = output.blocking_send(PtyEvent::Error(e.to_string()));
                    }
                    master_hold.release();
                    break;
                }
            }
        }
        // Nothing reads the master any more (after a read error too): the
        // slave and this copy of the master go now, not after `Exit`, so a
        // macOS agent that exits later is the slave's last close again (a
        // drain of at most 0.6 s), never waiting for a reader. (One already
        // draining when a read failed waits until the master closes.)
        drop(hold);
        drop(reader);
        if !listened {
            return;
        }
        let status = loop {
            // The lock only for the look: held through the sleep (a match
            // on the guard's temporary), it would starve `stop_child`, whose
            // signals then wait for luck while the agent runs.
            let polled = child.lock().unwrap().try_wait();
            match polled {
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
            prompts_held,
        },
        receiver,
        resize_handle: handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The longest a "wait until" helper waits. A passing run never gets near
    /// it; a slow runner (the Intel macOS CI one takes ~340 s for ~45 s of
    /// tests) needs the slack, and a hung test still ends.
    const WAIT: std::time::Duration = std::time::Duration::from_secs(60);

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
                &input.prompts_held,
                &request,
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
    fn a_prompt_queued_before_prompts_are_held_is_held_at_the_writer() {
        // Queued while nothing waited; an approval went to the agent's own
        // dialog before its turn at the writer came: none of its bytes.
        let (input, mut queued) = PtyInput::test_channel();
        input.paste_fenced("go on", 0, 1, None).unwrap();
        input.write_fenced(b"y".to_vec(), 0, 2, None).unwrap();
        input.hold_prompts(true);
        let mut destination = Vec::new();
        let mut outcomes = Vec::new();
        while let Ok(request) = queued.0.try_recv() {
            outcomes.push(write_fenced_request(
                &mut destination,
                &input.input_epoch,
                &input.prompts_held,
                &request,
            ));
        }
        // terminal input still goes (whoever types sees the dialog)
        assert_eq!(outcomes, [FencedOutcome::Held, FencedOutcome::Written(1)]);
        assert_eq!(destination, b"y");
        // released again: a prompt is written
        input.hold_prompts(false);
        input.paste_fenced("go on", 0, 3, None).unwrap();
        let request = queued.0.try_recv().unwrap();
        assert_eq!(
            write_fenced_request(
                &mut destination,
                &input.input_epoch,
                &input.prompts_held,
                &request
            ),
            FencedOutcome::Written(18)
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
                &input.prompts_held,
                &request,
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
            match tokio::time::timeout(WAIT, session.receiver.recv())
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
            match tokio::time::timeout(WAIT, session.receiver.recv())
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

    /// The output up to `Exit`; any other event fails.
    async fn all_output_then_exit(mut session: PtySession) -> String {
        let mut output = Vec::new();
        loop {
            match tokio::time::timeout(WAIT, session.receiver.recv())
                .await
                .unwrap()
                .unwrap()
            {
                PtyEvent::Output(bytes) => output.extend(bytes),
                PtyEvent::Exit(_) => return String::from_utf8(output).unwrap(),
                event => panic!("unexpected {event:?}"),
            }
        }
    }

    /// macOS discards what the master hasn't read 0.6 s after the slave's
    /// last close: the session holds the slave until the child exited and
    /// its output was read, so a reader that starts well after a child
    /// wrote and exited still gets every byte, then `Exit`. (On Linux the
    /// output stays readable anyway; this runs the release of the hold.)
    #[tokio::test]
    async fn a_late_reader_still_gets_everything_a_child_wrote_before_it_exited() {
        let spec = SpawnSpec {
            binary: "printf".into(),
            args: vec!["written just before the exit".into()],
            cwd: std::env::temp_dir(),
            env: None,
            rows: 24,
            cols: 80,
        };
        let session = spawn_with_faults(
            spec,
            ReaderFaults {
                delay: Duration::from_millis(1500),
                ..ReaderFaults::default()
            },
        )
        .unwrap();
        assert_eq!(
            all_output_then_exit(session).await,
            "written just before the exit"
        );
    }

    /// The number at the end of a slave's path (`/dev/pts/7`, `/dev/ttys007`).
    fn tty_index(tty: &std::path::Path) -> Option<u32> {
        let name = tty.file_name()?.to_str()?;
        let digits = name.trim_start_matches(|c: char| !c.is_ascii_digit());
        digits.parse().ok()
    }

    /// Opens PTYs for a second and fails if one gets `tty`'s index back. New
    /// PTYs take the lowest free index, so the ones below `tty`'s are kept
    /// open (a few, within descriptor limits) to reach it even when other
    /// tests freed lower ones.
    async fn assert_index_not_reused(tty: &std::path::Path) {
        let ours = tty_index(tty).unwrap();
        let mut below = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            let Ok(pair) = native_pty_system().openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            }) else {
                break;
            };
            let name = pair.master.tty_name().unwrap();
            assert_ne!(
                name, tty,
                "the PTY index was reused before the child's exit was seen"
            );
            if tty_index(&name).is_some_and(|index| index < ours) && below.len() < 32 {
                below.push(pair);
            } else {
                drop(pair);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    /// A spawn whose exit watcher keeps its master copy `WAIT` longer after
    /// it saw the exit: a child still on its way out.
    fn spawn_with_late_exit(binary: &str, args: Vec<String>) -> PtySession {
        let spec = SpawnSpec {
            binary: binary.into(),
            args,
            cwd: std::env::temp_dir(),
            env: None,
            rows: 24,
            cols: 80,
        };
        spawn_with_faults(
            spec,
            ReaderFaults {
                exit_hold: WAIT,
                ..ReaderFaults::default()
            },
        )
        .unwrap()
    }

    /// A PTY's index (`/dev/pts/N`, `/dev/ttysN`) stays allocated until the
    /// child's exit was seen, except after a read error: on macOS a session
    /// leader's exit revokes every vnode of its terminal's device number, so
    /// an index reused before that revoke loses the new terminal (CI: the
    /// next spawn failed with EBADF at `TIOCSCTTY`).
    #[tokio::test]
    async fn a_pty_index_is_not_reused_before_the_exit_is_seen() {
        let session = spawn_with_late_exit("true", Vec::new());
        let tty = session.resize_handle.tty_name().unwrap();
        // Read to `Exit`, then drop the session: every other master copy
        // and the slave hold are gone.
        all_output_then_exit(session).await;
        assert_index_not_reused(&tty).await;
    }

    /// The same once nobody takes the events (the path the CI failure took):
    /// the reader lets the slave go at its first output, before the exit.
    #[tokio::test]
    async fn a_pty_index_is_not_reused_when_nobody_listens() {
        let PtySession {
            sender,
            receiver,
            resize_handle,
        } = spawn_with_late_exit("printf", vec!["x".into()]);
        let tty = resize_handle.tty_name().unwrap();
        drop(receiver);
        // The child writes and exits; its output finds no receiver.
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(sender);
        drop(resize_handle);
        assert_index_not_reused(&tty).await;
    }

    /// How many descriptors of this process are open on `tty`.
    #[cfg(target_os = "linux")]
    fn open_on(tty: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|fd| std::fs::read_link(fd.path()).is_ok_and(|target| target == tty))
            .count()
    }

    /// How many master descriptors of this process are open on the PTY
    /// whose slave is `tty` (Linux: `/proc/self/fdinfo`'s `tty-index`).
    #[cfg(target_os = "linux")]
    fn masters_on(tty: &std::path::Path) -> usize {
        let index = tty.file_name().unwrap().to_string_lossy().into_owned();
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|fd| {
                std::fs::read_link(fd.path())
                    .is_ok_and(|target| target == std::path::Path::new("/dev/ptmx"))
            })
            .filter(|fd| {
                std::fs::read_to_string(format!(
                    "/proc/self/fdinfo/{}",
                    fd.file_name().to_string_lossy()
                ))
                .is_ok_and(|info| {
                    info.lines().any(|line| {
                        line.split_once(':')
                            .is_some_and(|(key, value)| key == "tty-index" && value.trim() == index)
                    })
                })
            })
            .count()
    }

    /// Review I1: after a read error nothing reads the master any more, so
    /// the slave hold goes at once, not after `Exit` (on macOS an agent's
    /// exit would otherwise wait for a reader that is gone); the session
    /// still ends with `Exit`. Linux only: it counts the process's own
    /// descriptors on the slave.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_read_error_lets_the_slave_go_before_the_exit() {
        let spec = SpawnSpec {
            binary: "sh".into(),
            args: vec!["-c".into(), "echo up; exec sleep 300".into()],
            cwd: std::env::temp_dir(),
            env: None,
            rows: 24,
            cols: 80,
        };
        let mut session = spawn_with_faults(
            spec,
            ReaderFaults {
                fail_first_read: true,
                ..ReaderFaults::default()
            },
        )
        .unwrap();
        let tty = session.resize_handle.tty_name().unwrap();
        match tokio::time::timeout(WAIT, session.receiver.recv())
            .await
            .unwrap()
            .unwrap()
        {
            PtyEvent::Error(error) => assert!(error.contains("injected"), "{error}"),
            event => panic!("unexpected {event:?}"),
        }
        // The agent is still running, and this process no longer holds its
        // terminal, nor more than the session's two master copies (the
        // handle's and the writer's): the reader's and the exit watcher's
        // are gone, so nothing keeps a draining agent waiting at its exit.
        let deadline = std::time::Instant::now() + WAIT;
        while open_on(&tty) > 0 || masters_on(&tty) > 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "the slave or the watcher's master copy is still held"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        session.resize_handle.stop().unwrap();
        tokio::time::timeout(WAIT, async {
            while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Exit(_)) {}
        })
        .await
        .unwrap();
    }

    /// Review M1: once nobody takes the events, the master is still read to
    /// its end, so the agent never blocks on output nobody reads (nor, on
    /// macOS, waits at its exit for it to be read).
    #[tokio::test]
    async fn a_session_nobody_listens_to_is_still_read_to_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("done");
        let script = "read go; head -c 400000 /dev/zero; : > \"$1\"";
        let session = spawn(
            "sh",
            &[
                "-c".into(),
                script.into(),
                "sh".into(),
                marker.display().to_string(),
            ],
        )
        .unwrap();
        let PtySession {
            sender,
            receiver,
            resize_handle,
        } = session;
        drop(receiver);
        // Far more than the terminal buffers: it ends only if read.
        sender.respond(b"go\n".to_vec()).unwrap();
        let deadline = std::time::Instant::now() + WAIT;
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the agent's output was never read to its end"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        resize_handle.stop().unwrap();
    }

    /// Many children that write and exit at once, read concurrently: each
    /// one's whole output comes before its `Exit`.
    #[tokio::test]
    async fn every_short_lived_child_has_its_whole_output_before_its_exit() {
        let sessions: Vec<_> = (0..16)
            .map(|i| spawn("printf", &[format!("child {i} wrote this")]).unwrap())
            .collect();
        for (i, session) in sessions.into_iter().enumerate() {
            assert_eq!(
                all_output_then_exit(session).await,
                format!("child {i} wrote this")
            );
        }
    }

    #[tokio::test]
    async fn explicit_stop_terminates_the_child_and_drains_output_before_exit() {
        let mut session = spawn("cat", &[]).unwrap();
        session.sender.respond(b"before stop\n".to_vec()).unwrap();
        while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Output(_)) {}
        session.resize_handle.stop().unwrap();
        tokio::time::timeout(WAIT, async {
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
        tokio::time::timeout(WAIT, async {
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
        tokio::time::timeout(WAIT, async {
            while !matches!(session.receiver.recv().await.unwrap(), PtyEvent::Exit(_)) {}
        })
        .await
        .unwrap();
        // Killed (a zombie until init reaps it) or already gone.
        let deadline = std::time::Instant::now() + WAIT;
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

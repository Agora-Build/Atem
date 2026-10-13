//! Shared byte-oriented PTY transport. Terminal data and lifecycle events never mix.
use anyhow::{Result, anyhow, bail};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
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
}

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

#[derive(Clone, Debug)]
pub struct PtyInput {
    tx: mpsc::Sender<WriteRequest>,
    authority: Arc<Mutex<Authority>>,
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
        let authority = self.authority.lock().unwrap();
        if authority.remote {
            bail!("Remote control is active; use Atem's Take Control command");
        }
        self.enqueue(data.into_bytes(), Some(authority.epoch), None)
    }

    pub fn send_remote(&self, data: Vec<u8>, epoch: u64, sequence: u64) -> Result<()> {
        let authority = self.authority.lock().unwrap();
        if !authority.remote || authority.epoch != epoch {
            bail!("Control lease expired");
        }
        self.enqueue(data, Some(epoch), Some(sequence))
    }

    pub fn respond(&self, data: Vec<u8>) -> Result<()> {
        self.enqueue(data, None, None)
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
}

#[derive(Debug)]
pub struct PtySession {
    pub sender: PtyInput,
    pub receiver: mpsc::Receiver<PtyEvent>,
    pub resize_handle: PtyHandle,
}

pub fn spawn(binary: &str, args: &[String]) -> Result<PtySession> {
    spawn_sized(binary, args, DEFAULT_ROWS, DEFAULT_COLS)
}

pub fn spawn_sized(binary: &str, args: &[String], rows: u16, cols: u16) -> Result<PtySession> {
    if !(2..=200).contains(&rows) || !(2..=400).contains(&cols) {
        bail!("Terminal size must be 2..200 rows and 2..400 columns");
    }
    let pair = native_pty_system().openpty(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    let mut command = CommandBuilder::new(binary);
    command.args(args);
    command.cwd(std::env::current_dir()?);
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
    std::thread::spawn(move || {
        while let Some(request) = input.blocking_recv() {
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
        sender: PtyInput { tx, authority },
        receiver,
        resize_handle: handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn full_input_queue_rejects_without_partial_paste() {
        let (input, _queued) = PtyInput::test_channel();
        assert!(input.send("x".repeat(MAX_INPUT + 1)).is_err());
        for _ in 0..64 {
            input.send("x".into()).unwrap();
        }
        assert!(input.send("overflow".into()).is_err());
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

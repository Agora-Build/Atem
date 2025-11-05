use anyhow::{Result, anyhow};
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Clone)]
pub struct CodexResizeHandle {
    inner: Arc<Mutex<Box<dyn MasterPty + Send>>>,
}

impl std::fmt::Debug for CodexResizeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodexResizeHandle { .. }")
    }
}

impl CodexResizeHandle {
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("Codex PTY is unavailable (resize lock poisoned)"))?;
        guard
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| anyhow!("Failed to resize Codex PTY: {}", err))
    }
}

#[derive(Debug)]
pub struct CodexSession {
    pub sender: UnboundedSender<String>,
    pub receiver: UnboundedReceiver<String>,
    pub resize_handle: CodexResizeHandle,
}

#[derive(Clone, Debug)]
pub struct CodexClient {
    binary: String,
    extra_args: Vec<String>,
}

impl CodexClient {
    pub fn new() -> Self {
        let binary = std::env::var("CODEX_CLI_BIN").unwrap_or_else(|_| "codex".to_string());
        let extra_args = std::env::var("CODEX_CLI_ARGS")
            .map(|raw| raw.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        Self { binary, extra_args }
    }

    pub async fn start_session(&self) -> Result<CodexSession> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| anyhow!("Failed to open PTY: {}", err))?;

        let mut cmd = CommandBuilder::new(&self.binary);
        cmd.args(&self.extra_args);
        cmd.cwd(
            std::env::current_dir()
                .map_err(|err| anyhow!("Failed to read current dir: {}", err))?,
        );

        // Preserve current environment so Codex inherits auth/config.
        cmd.env_clear();
        for (key, value) in std::env::vars() {
            cmd.env(&key, &value);
        }

        if std::env::var("TERM").is_err() {
            cmd.env("TERM", "xterm-256color");
        }

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|err| anyhow!("Failed to spawn Codex CLI: {}", err))?;

        let master = Arc::new(Mutex::new(pair.master));

        let mut reader = {
            let guard = master
                .lock()
                .map_err(|_| anyhow!("Codex PTY is unavailable (reader lock poisoned)"))?;
            guard
                .try_clone_reader()
                .map_err(|err| anyhow!("Failed to clone PTY reader: {}", err))?
        };

        let writer = {
            let guard = master
                .lock()
                .map_err(|_| anyhow!("Codex PTY is unavailable (writer lock poisoned)"))?;
            guard
                .take_writer()
                .map_err(|err| anyhow!("Failed to acquire PTY writer: {}", err))?
        };
        let writer: Arc<Mutex<Box<dyn Write + Send>>> = Arc::new(Mutex::new(writer));

        let (input_tx, mut input_rx) = mpsc::unbounded_channel::<String>();
        let (output_tx, output_rx) = mpsc::unbounded_channel::<String>();
        let writer_for_task = Arc::clone(&writer);
        let output_tx_for_writer = output_tx.clone();

        tokio::spawn(async move {
            while let Some(message) = input_rx.recv().await {
                let writer_for_task = Arc::clone(&writer_for_task);
                let output_tx_for_writer = output_tx_for_writer.clone();
                let message_to_write = message;

                let result = tokio::task::spawn_blocking(move || {
                    writer_for_task
                        .lock()
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "Codex writer lock poisoned",
                            )
                        })
                        .and_then(|mut guard| {
                            guard.write_all(message_to_write.as_bytes())?;
                            guard.flush()
                        })
                })
                .await;

                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        let msg = format!("⚠️ Failed to send input to Codex CLI: {}", err);
                        let _ = output_tx_for_writer.send(msg);
                        break;
                    }
                    Err(join_err) => {
                        let msg = format!("⚠️ Failed to schedule Codex write task: {}", join_err);
                        let _ = output_tx_for_writer.send(msg);
                        break;
                    }
                }
            }
        });

        std::thread::spawn({
            let output_tx_clone = output_tx.clone();
            move || {
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                            if output_tx_clone.send(chunk).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = output_tx_clone
                                .send(format!("⚠️ Failed to read from Codex CLI: {}", err));
                            break;
                        }
                    }
                }
            }
        });

        std::thread::spawn({
            let output_tx_clone = output_tx.clone();
            move || match child.wait() {
                Ok(status) => {
                    let _ =
                        output_tx_clone.send(format!("Codex CLI exited with status {}", status));
                }
                Err(err) => {
                    let _ = output_tx_clone.send(format!("Codex CLI wait error: {}", err));
                }
            }
        });

        Ok(CodexSession {
            sender: input_tx,
            receiver: output_rx,
            resize_handle: CodexResizeHandle {
                inner: Arc::clone(&master),
            },
        })
    }
}

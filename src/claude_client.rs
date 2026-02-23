use anyhow::{Result, anyhow};
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Clone)]
pub struct ClaudeResizeHandle {
    inner: Arc<Mutex<Box<dyn MasterPty + Send>>>,
}

impl std::fmt::Debug for ClaudeResizeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaudeResizeHandle { .. }")
    }
}

impl ClaudeResizeHandle {
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("Claude PTY is unavailable (resize lock poisoned)"))?;
        guard
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| anyhow!("Failed to resize Claude PTY: {}", err))
    }
}

#[derive(Debug)]
pub struct ClaudeSession {
    pub sender: UnboundedSender<String>,
    pub receiver: UnboundedReceiver<String>,
    pub resize_handle: ClaudeResizeHandle,
}

#[derive(Clone, Debug)]
pub struct ClaudeClient {
    binary: String,
    extra_args: Vec<String>,
}

impl ClaudeClient {
    pub fn new() -> Self {
        let binary = std::env::var("CLAUDE_CLI_BIN").unwrap_or_else(|_| "claude".to_string());
        let extra_args = std::env::var("CLAUDE_CLI_ARGS")
            .map(|raw| raw.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        Self { binary, extra_args }
    }

    /// Resolve binary path by searching through PATH directories
    fn resolve_binary_path(&self) -> Result<String> {
        use std::path::PathBuf;

        // If binary is already an absolute path, use it directly
        if std::path::Path::new(&self.binary).is_absolute() {
            return Ok(self.binary.clone());
        }

        // Get PATH environment variable
        let path_env = std::env::var("PATH").unwrap_or_else(|_| {
            // Fallback to common PATH if not set
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin".to_string()
        });

        // Search through each directory in PATH
        for dir in path_env.split(':') {
            let mut candidate = PathBuf::from(dir);
            candidate.push(&self.binary);

            if candidate.exists() && candidate.is_file() {
                // Check if it's executable (on Unix)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = std::fs::metadata(&candidate) {
                        let permissions = metadata.permissions();
                        if permissions.mode() & 0o111 != 0 {
                            return Ok(candidate.to_string_lossy().to_string());
                        }
                    }
                }

                #[cfg(not(unix))]
                {
                    return Ok(candidate.to_string_lossy().to_string());
                }
            }
        }

        // Not found in PATH
        Err(anyhow!(
            "Unable to find '{}' in PATH. Searched directories: {}",
            self.binary,
            path_env
        ))
    }

    pub async fn start_session(&self) -> Result<ClaudeSession> {
        // Resolve binary path first to ensure it exists
        let binary_path = self.resolve_binary_path()
            .map_err(|e| anyhow!("Failed to spawn Claude CLI: {}", e))?;

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| anyhow!("Failed to open PTY: {}", err))?;

        let mut cmd = CommandBuilder::new(&binary_path);
        cmd.args(&self.extra_args);
        cmd.cwd(
            std::env::current_dir()
                .map_err(|err| anyhow!("Failed to read current dir: {}", err))?,
        );

        // Preserve current environment so Claude inherits auth/config.
        cmd.env_clear();
        for (key, value) in std::env::vars() {
            cmd.env(&key, &value);
        }

        if std::env::var("TERM").is_err() {
            cmd.env("TERM", "xterm-256color");
        }

        // Force interactive mode - Claude might check these
        cmd.env("FORCE_COLOR", "1");
        cmd.env("COLORTERM", "truecolor");

        // Explicitly mark as TTY for macOS
        #[cfg(target_os = "macos")]
        {
            cmd.env("TERM_PROGRAM", "Atem");
            cmd.env("TERM_PROGRAM_VERSION", "0.4.45");
        }

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|err| anyhow!("Failed to spawn Claude CLI: {}", err))?;

        let master = Arc::new(Mutex::new(pair.master));

        let mut reader = {
            let guard = master
                .lock()
                .map_err(|_| anyhow!("Claude PTY is unavailable (reader lock poisoned)"))?;
            guard
                .try_clone_reader()
                .map_err(|err| anyhow!("Failed to clone PTY reader: {}", err))?
        };

        let writer = {
            let guard = master
                .lock()
                .map_err(|_| anyhow!("Claude PTY is unavailable (writer lock poisoned)"))?;
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
                            std::io::Error::other("Claude writer lock poisoned")
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
                        let msg = format!("⚠️ Failed to send input to Claude CLI: {}", err);
                        let _ = output_tx_for_writer.send(msg);
                        break;
                    }
                    Err(join_err) => {
                        let msg = format!("⚠️ Failed to schedule Claude write task: {}", join_err);
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
                                .send(format!("⚠️ Failed to read from Claude CLI: {}", err));
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
                        output_tx_clone.send(format!("Claude CLI exited with status {}", status));
                }
                Err(err) => {
                    let _ = output_tx_clone.send(format!("Claude CLI wait error: {}", err));
                }
            }
        });

        Ok(ClaudeSession {
            sender: input_tx,
            receiver: output_rx,
            resize_handle: ClaudeResizeHandle {
                inner: Arc::clone(&master),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_struct_holds_binary_and_args() {
        let client = ClaudeClient {
            binary: "my-claude".to_string(),
            extra_args: vec!["--flag1".to_string(), "--flag2".to_string()],
        };
        assert_eq!(client.binary, "my-claude");
        assert_eq!(client.extra_args, vec!["--flag1", "--flag2"]);
    }

    #[test]
    fn client_default_binary_is_claude() {
        // Verify the fallback value when the env var is absent.
        // We can't safely clear env in parallel tests, so just check
        // that ClaudeClient::new() returns a non-empty binary field.
        let client = ClaudeClient::new();
        assert!(!client.binary.is_empty());
    }

    #[tokio::test]
    async fn session_with_echo_produces_output() {
        // Use 'echo' as a stand-in binary — it prints and exits immediately.
        let client = ClaudeClient {
            binary: "echo".to_string(),
            extra_args: vec!["hello from pty".to_string()],
        };
        let mut session = client.start_session().await.unwrap();

        // Drain all output until channel closes.
        let mut combined = String::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, session.receiver.recv()).await {
                Ok(Some(chunk)) => combined.push_str(&chunk),
                _ => break,
            }
        }
        assert!(
            combined.contains("hello from pty"),
            "expected echo output in: {}",
            combined
        );
    }

    #[tokio::test]
    async fn session_with_cat_receives_sent_input() {
        // 'cat' echoes stdin back to stdout, so we can verify round-trip IO.
        let client = ClaudeClient {
            binary: "cat".to_string(),
            extra_args: vec![],
        };
        let mut session = client.start_session().await.unwrap();

        // Send a line to cat's stdin
        session.sender.send("ping\n".to_string()).unwrap();

        // Read output — should see "ping" echoed back
        let mut combined = String::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, session.receiver.recv()).await {
                Ok(Some(chunk)) => {
                    combined.push_str(&chunk);
                    if combined.contains("ping") {
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            combined.contains("ping"),
            "expected 'ping' in output: {}",
            combined
        );
    }

    #[tokio::test]
    async fn session_reports_exit_on_process_end() {
        let client = ClaudeClient {
            binary: "true".to_string(), // exits immediately with status 0
            extra_args: vec![],
        };
        let mut session = client.start_session().await.unwrap();

        let mut combined = String::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, session.receiver.recv()).await {
                Ok(Some(chunk)) => {
                    combined.push_str(&chunk);
                    if combined.contains("Claude CLI exited") {
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            combined.contains("Claude CLI exited"),
            "expected exit message in: {}",
            combined
        );
    }

    #[tokio::test]
    async fn resize_handle_works() {
        let client = ClaudeClient {
            binary: "cat".to_string(),
            extra_args: vec![],
        };
        let session = client.start_session().await.unwrap();
        // Should not panic or error
        let result = session.resize_handle.resize(50, 100);
        assert!(result.is_ok(), "resize failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn nonexistent_binary_fails() {
        let client = ClaudeClient {
            binary: "/nonexistent/binary/xyz_12345".to_string(),
            extra_args: vec![],
        };
        let result = client.start_session().await;
        assert!(result.is_err());
    }
}

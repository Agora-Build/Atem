use crate::pty_session;
use anyhow::Result;
pub type ClaudeResizeHandle = pty_session::PtyHandle;
pub type ClaudeSession = pty_session::PtySession;

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

    pub fn append_launch_args(&mut self, args: &[String]) {
        self.extra_args.extend_from_slice(args);
    }

    pub async fn start_session(&self) -> Result<ClaudeSession> {
        pty_session::spawn(&self.binary, &self.extra_args)
    }

    /// The arguments every spawn gets (env defaults, then launch arguments).
    pub fn launch_args(&self) -> &[String] {
        &self.extra_args
    }

    /// Spawn with `first` placed before the stored arguments, for this spawn only
    /// (so they stay ahead of a user's `--`).
    pub async fn start_session_sized(
        &self,
        rows: u16,
        cols: u16,
        first: &[String],
    ) -> Result<ClaudeSession> {
        let args = [first, &self.extra_args[..]].concat();
        pty_session::spawn_sized(&self.binary, &args, rows, cols)
    }

    #[cfg(test)]
    pub fn set_command_for_test(&mut self, binary: String, args: Vec<String>) {
        self.binary = binary;
        self.extra_args = args;
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
                Ok(Some(pty_session::PtyEvent::Output(chunk))) => {
                    combined.push_str(&String::from_utf8_lossy(&chunk))
                }
                Ok(Some(_)) => {}
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

        session.sender.send("ping\n".to_string()).unwrap();

        // Read output — should see "ping" echoed back
        let mut combined = String::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, session.receiver.recv()).await {
                Ok(Some(pty_session::PtyEvent::Output(chunk))) => {
                    combined.push_str(&String::from_utf8_lossy(&chunk));
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

        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, session.receiver.recv()).await {
                Ok(Some(pty_session::PtyEvent::Exit(status))) => {
                    assert!(status.contains("0") || status.contains("Success"));
                    break;
                }
                Ok(Some(_)) => {}
                other => panic!("expected a typed exit event: {other:?}"),
            }
        }
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

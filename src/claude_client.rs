#[cfg(test)]
use crate::pty_session;
#[cfg(test)]
use anyhow::Result;
use std::ffi::OsString;
#[cfg(test)]
pub type ClaudeSession = pty_session::PtySession;

#[derive(Clone, Debug)]
pub struct ClaudeClient {
    binary: String,
    extra_args: Vec<String>,
}

impl ClaudeClient {
    /// From Atem's own environment (`CLAUDE_CLI_BIN`, `CLAUDE_CLI_ARGS`).
    pub fn new() -> Self {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// From a launch environment instead of Atem's own.
    pub fn from_env(env: &[(OsString, OsString)]) -> Self {
        Self::from_vars(|name| {
            env.iter()
                .rev()
                .find(|(key, _)| key == name)
                .and_then(|(_, value)| value.to_str().map(str::to_string))
        })
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> Self {
        let binary = var("CLAUDE_CLI_BIN").unwrap_or_else(|| "claude".to_string());
        let extra_args = var("CLAUDE_CLI_ARGS")
            .map(|raw| raw.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        Self { binary, extra_args }
    }

    #[cfg(test)]
    pub async fn start_session(&self) -> Result<ClaudeSession> {
        pty_session::spawn(&self.binary, &self.extra_args)
    }

    pub fn binary(&self) -> &str {
        &self.binary
    }

    /// The arguments every spawn gets first (`CLAUDE_CLI_ARGS`, then appended ones).
    pub fn launch_args(&self) -> &[String] {
        &self.extra_args
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
    fn a_launch_environment_sets_binary_and_default_arguments() {
        let env = [
            (
                OsString::from("CLAUDE_CLI_BIN"),
                OsString::from("/opt/agent"),
            ),
            (
                OsString::from("CLAUDE_CLI_ARGS"),
                OsString::from(" --a  --b "),
            ),
        ];
        let client = ClaudeClient::from_env(&env);
        assert_eq!(client.binary(), "/opt/agent");
        assert_eq!(client.launch_args(), ["--a", "--b"]);
        let client = ClaudeClient::from_env(&[]);
        assert_eq!(client.binary(), "claude");
        assert!(client.launch_args().is_empty());
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

        session.sender.respond(b"ping\n".to_vec()).unwrap();

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

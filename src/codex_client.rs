#[cfg(test)]
use crate::pty_session;
#[cfg(test)]
use anyhow::Result;
use std::ffi::OsString;
#[cfg(test)]
pub type CodexSession = pty_session::PtySession;

#[derive(Clone, Debug)]
pub struct CodexClient {
    binary: String,
    extra_args: Vec<String>,
}

impl CodexClient {
    /// From Atem's own environment (`CODEX_CLI_BIN`, `CODEX_CLI_ARGS`).
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
        let binary = var("CODEX_CLI_BIN").unwrap_or_else(|| "codex".to_string());
        let extra_args = var("CODEX_CLI_ARGS")
            .map(|raw| raw.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        Self { binary, extra_args }
    }

    /// Arguments for every later spawn from this client (`atem agent launch … ARGS`).
    pub fn append_launch_args(&mut self, args: &[String]) {
        self.extra_args.extend_from_slice(args);
    }

    #[cfg(test)]
    pub async fn start_session(&self) -> Result<CodexSession> {
        pty_session::spawn(&self.binary, &self.extra_args)
    }

    pub fn binary(&self) -> &str {
        &self.binary
    }

    /// The arguments every spawn gets first (`CODEX_CLI_ARGS`, then appended ones).
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
        let client = CodexClient {
            binary: "my-codex".to_string(),
            extra_args: vec!["-n".to_string(), "hello".to_string()],
        };
        assert_eq!(client.binary, "my-codex");
        assert_eq!(client.extra_args, vec!["-n", "hello"]);
    }

    #[test]
    fn a_launch_environment_sets_binary_and_default_arguments() {
        let env = [
            (
                OsString::from("CODEX_CLI_BIN"),
                OsString::from("/opt/agent"),
            ),
            (
                OsString::from("CODEX_CLI_ARGS"),
                OsString::from(" --a  --b "),
            ),
        ];
        let client = CodexClient::from_env(&env);
        assert_eq!(client.binary(), "/opt/agent");
        assert_eq!(client.launch_args(), ["--a", "--b"]);
        let client = CodexClient::from_env(&[]);
        assert_eq!(client.binary(), "codex");
        assert!(client.launch_args().is_empty());
    }

    #[test]
    fn client_default_binary_is_codex() {
        let client = CodexClient::new();
        assert!(!client.binary.is_empty());
    }

    #[tokio::test]
    async fn session_with_echo_produces_output() {
        let client = CodexClient {
            binary: "echo".to_string(),
            extra_args: vec!["hello from codex pty".to_string()],
        };
        let mut session = client.start_session().await.unwrap();

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
            combined.contains("hello from codex pty"),
            "expected echo output in: {}",
            combined
        );
    }

    #[tokio::test]
    async fn session_with_cat_receives_sent_input() {
        let client = CodexClient {
            binary: "cat".to_string(),
            extra_args: vec![],
        };
        let mut session = client.start_session().await.unwrap();

        session.sender.send("codex_ping\n".to_string()).unwrap();

        let mut combined = String::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, session.receiver.recv()).await {
                Ok(Some(pty_session::PtyEvent::Output(chunk))) => {
                    combined.push_str(&String::from_utf8_lossy(&chunk));
                    if combined.contains("codex_ping") {
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            combined.contains("codex_ping"),
            "expected 'codex_ping' in output: {}",
            combined
        );
    }

    #[tokio::test]
    async fn session_reports_exit_on_process_end() {
        let client = CodexClient {
            binary: "true".to_string(),
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
        let client = CodexClient {
            binary: "cat".to_string(),
            extra_args: vec![],
        };
        let session = client.start_session().await.unwrap();
        let result = session.resize_handle.resize(50, 100);
        assert!(result.is_ok(), "resize failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn nonexistent_binary_fails() {
        let client = CodexClient {
            binary: "/nonexistent/binary/xyz_12345".to_string(),
            extra_args: vec![],
        };
        let result = client.start_session().await;
        assert!(result.is_err());
    }
}

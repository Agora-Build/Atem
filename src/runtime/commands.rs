//! `atem agent launch|attach|list|stop`: clients of the runtime (started on
//! demand). Launch and attach open the frontend (src/tui/frontend.rs);
//! list and stop print and exit.

use super::client::RuntimeClient;
use super::protocol::{ClientMsg, LaunchEnv, RuntimeMsg, SessionSummary};
use anyhow::{Context, Result, anyhow, bail};
use std::io::IsTerminal;
use std::time::Duration;

/// How long a command waits for the runtime's answer.
const REPLY_WAIT: Duration = Duration::from_secs(10);

/// The next message `pick` accepts; an error answering `op` fails.
async fn reply<T>(
    client: &mut RuntimeClient,
    op: &str,
    mut pick: impl FnMut(RuntimeMsg) -> Option<T>,
) -> Result<T> {
    tokio::time::timeout(REPLY_WAIT, async {
        loop {
            match client.recv().await? {
                None => bail!("the atem runtime closed the connection"),
                Some(RuntimeMsg::Error { text, op: re }) if re.as_deref() == Some(op) => {
                    bail!(text)
                }
                Some(message) => {
                    if let Some(value) = pick(message) {
                        return Ok(value);
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow!("the atem runtime didn't answer"))?
}

/// The runtime's sessions.
pub async fn sessions(client: &mut RuntimeClient) -> Result<Vec<SessionSummary>> {
    client.send(&ClientMsg::List).await?;
    reply(client, "list", |m| match m {
        RuntimeMsg::Sessions { sessions } => Some(sessions),
        _ => None,
    })
    .await
}

/// A provider name `atem agent launch` accepts.
pub fn check_provider(agent: &str) -> Result<()> {
    match agent {
        "claude" | "claude-code" | "codex" => Ok(()),
        other => bail!("Expected claude, claude-code or codex, not {other:?}"),
    }
}

fn require_terminal(what: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("`atem agent {what}` needs a terminal");
    }
    Ok(())
}

/// Launches a session in the runtime at `size` (rows, cols).
pub async fn launch_session(
    client: &mut RuntimeClient,
    agent: &str,
    args: Vec<String>,
    size: (u16, u16),
) -> Result<SessionSummary> {
    let cwd = std::env::current_dir().context("no current directory")?;
    client
        .send(&ClientMsg::Launch {
            provider: agent.to_string(),
            args,
            cwd,
            env: LaunchEnv::current(),
            rows: size.0,
            cols: size.1,
        })
        .await?;
    reply(client, "launch", |m| match m {
        RuntimeMsg::Launched { session } => Some(session),
        _ => None,
    })
    .await
}

/// The size a session gets on this terminal (24x80 when unknown).
fn terminal_size() -> (u16, u16) {
    crossterm::terminal::size()
        .map(|(cols, rows)| {
            crate::tui::frontend::viewport_size(ratatui::layout::Size {
                width: cols,
                height: rows,
            })
        })
        .unwrap_or((24, 80))
}

/// `atem agent launch <provider> [args…]`.
pub async fn launch(agent: &str, args: Vec<String>) -> Result<()> {
    check_provider(agent)?;
    require_terminal("launch")?;
    if agent == "codex" {
        // Asks once whether Astation may answer Codex's approvals, and keeps
        // Atem's hook in ~/.codex/hooks.json (never blocks the launch).
        crate::chat::codex::setup_on_launch();
    }
    let mut client = RuntimeClient::connect_or_start().await?;
    let session = launch_session(&mut client, agent, args, terminal_size()).await?;
    crate::tui::frontend::run_frontend(client, &session.id).await?;
    Ok(())
}

/// `atem agent attach <session-id>`.
pub async fn attach(sid: &str) -> Result<()> {
    let mut client = RuntimeClient::connect_or_start().await?;
    if !sessions(&mut client).await?.iter().any(|s| s.id == sid) {
        bail!("Unknown session {sid}; `atem agent list` shows the sessions");
    }
    require_terminal("attach")?;
    crate::tui::frontend::run_frontend(client, sid).await?;
    Ok(())
}

/// The table `atem agent list` prints.
pub fn format_list(client: &super::client::Welcome, sessions: &[SessionSummary]) -> String {
    let link = if client.astation { "✓" } else { "✗" };
    let mut text = format!(
        "Runtime pid {} \u{b7} protocol {} \u{b7} build {} \u{b7} Astation {link}\n",
        client.pid, client.protocol, client.build
    );
    if let Some(error) = &client.host_error {
        text.push_str(&format!("{error}\n"));
    }
    // r9: a device list that isn't plainly open says so (Failed included:
    // `host_error` doesn't report it).
    if let Some(list) = client
        .device_list
        .as_ref()
        .filter(|l| l.state != "open" || !l.pending_recovery.is_empty())
    {
        text.push_str(&format!("Device list: {}\n", list.text));
        for p in &list.pending_recovery {
            text.push_str(&format!(
                "Device list: recovery pending: {} ({}); see atem status\n",
                p.subject, p.action
            ));
        }
    }
    if sessions.is_empty() {
        text.push_str("No sessions. Start one: atem agent launch claude|codex\n");
        return text;
    }
    text.push_str(&format!(
        "{:<16}  {:<8}  {:<17}  {:<7}  {:<8}  CWD\n",
        "ID", "PROVIDER", "STATE", "STATUS", "ATTACHED"
    ));
    for s in sessions {
        text.push_str(&format!(
            "{:<16}  {:<8}  {:<17}  {:<7}  {:<8}  {}\n",
            s.id,
            s.provider,
            s.state,
            s.status,
            if s.attached { "yes" } else { "no" },
            s.cwd.display()
        ));
        // Why a session isn't running, on its own line.
        if let Some(status) = s.exited.as_ref().filter(|_| s.state != "running") {
            text.push_str(&format!("{:<16}  ({status})\n", ""));
        }
    }
    text
}

/// `atem agent list`.
pub async fn list() -> Result<()> {
    let mut client = RuntimeClient::connect_or_start().await?;
    let sessions = sessions(&mut client).await?;
    print!("{}", format_list(&client.welcome, &sessions));
    Ok(())
}

/// `atem agent stop <session-id>`.
pub async fn stop(sid: &str) -> Result<()> {
    let mut client = RuntimeClient::connect_or_start().await?;
    client
        .send(&ClientMsg::Stop {
            session_id: sid.to_string(),
        })
        .await?;
    let removed = reply(&mut client, "stop", |m| match m {
        RuntimeMsg::Stopped {
            session_id,
            removed,
        } if session_id == sid => Some(removed),
        _ => None,
    })
    .await?;
    if removed {
        println!("Removed {sid}");
    } else {
        println!("Stopping {sid}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(id: &str, state: &str, exited: Option<&str>) -> SessionSummary {
        SessionSummary {
            id: id.into(),
            provider: "claude".into(),
            cwd: "/work/app".into(),
            created_at_ms: 1,
            state: state.into(),
            status: "ready".into(),
            attached: state == "running",
            remote_controlled: false,
            exited: exited.map(str::to_string),
            rows: 24,
            cols: 80,
            generation: "g".into(),
            worker_build: None,
        }
    }

    /// r9: a device list that isn't plainly open (failed included, which
    /// `host_error` doesn't report) and a pending recovery head the list.
    #[test]
    fn the_list_says_when_the_device_list_needs_attention() {
        use crate::runtime::protocol::{DeviceListStatus, PendingRecoveryStatus};
        let mut welcome = super::super::client::Welcome {
            protocol: 1,
            build: "b".into(),
            pid: 42,
            astation: true,
            host_error: None,
            worker_protocol: None,
            device_list: Some(DeviceListStatus {
                state: "failed".into(),
                text: "failed (x is damaged; re-pair this host (atem unpair, then atem pair)); remote access is off".into(),
                label: Some("Remote off".into()),
                ..Default::default()
            }),
        };
        let text = format_list(&welcome, &[]);
        assert!(
            text.contains("Device list: failed (x is damaged; re-pair"),
            "{text}"
        );
        welcome.device_list = Some(DeviceListStatus {
            state: "open".into(),
            text: "pinned at seq 5 (1 remote client)".into(),
            pending_recovery: vec![PendingRecoveryStatus {
                subject: "dev-new".into(),
                action: "recovery_add".into(),
                effective_at: 1,
            }],
            ..Default::default()
        });
        let text = format_list(&welcome, &[]);
        assert!(
            text.contains("recovery pending: dev-new (recovery_add)"),
            "{text}"
        );
        welcome
            .device_list
            .as_mut()
            .unwrap()
            .pending_recovery
            .clear();
        assert!(!format_list(&welcome, &[]).contains("Device list"));
    }

    #[test]
    fn the_list_shows_the_runtime_and_one_row_per_session() {
        let welcome = super::super::client::Welcome {
            protocol: 1,
            build: "0.7.0+1".into(),
            pid: 42,
            astation: false,
            host_error: None,
            worker_protocol: None,
            device_list: None,
        };
        let text = format_list(&welcome, &[]);
        assert!(text.starts_with("Runtime pid 42 \u{b7} protocol 1 \u{b7} build 0.7.0+1"));
        assert!(text.contains("No sessions"));
        let text = format_list(
            &welcome,
            &[
                summary("ses-aaaaaaaaaaaa", "running", None),
                summary("ses-bbbbbbbbbbbb", "exited", Some("exit status 0")),
            ],
        );
        let lines: Vec<&str> = text.lines().collect();
        let header: Vec<&str> = lines[1].split_whitespace().collect();
        assert_eq!(
            header,
            ["ID", "PROVIDER", "STATE", "STATUS", "ATTACHED", "CWD"]
        );
        let row: Vec<&str> = lines[2].split_whitespace().collect();
        assert_eq!(
            row,
            [
                "ses-aaaaaaaaaaaa",
                "claude",
                "running",
                "ready",
                "yes",
                "/work/app"
            ]
        );
        let row: Vec<&str> = lines[3].split_whitespace().collect();
        assert_eq!(
            row,
            [
                "ses-bbbbbbbbbbbb",
                "claude",
                "exited",
                "ready",
                "no",
                "/work/app"
            ]
        );
        assert_eq!(lines[4].trim(), "(exit status 0)");
    }

    #[test]
    fn only_the_three_providers_launch() {
        for agent in ["claude", "claude-code", "codex"] {
            assert!(check_provider(agent).is_ok());
        }
        assert!(check_provider("gemini").is_err());
    }
}

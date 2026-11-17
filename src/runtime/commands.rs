//! `atem agent launch|attach|list|stop`: clients of the runtime (started on
//! demand). Launch and attach open the frontend (src/tui/frontend.rs);
//! list and stop print and exit.

use super::client::RuntimeClient;
use super::collab::results::ReplyState;
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
    pick: impl FnMut(RuntimeMsg) -> Option<T>,
) -> Result<T> {
    reply_within(client, op, REPLY_WAIT, pick).await
}

/// [`reply`], waiting at most `wait`.
async fn reply_within<T>(
    client: &mut RuntimeClient,
    op: &str,
    wait: Duration,
    mut pick: impl FnMut(RuntimeMsg) -> Option<T>,
) -> Result<T> {
    tokio::time::timeout(wait, async {
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

pub async fn tag(action: super::protocol::TagOp, name: Option<String>) -> Result<()> {
    crate::auth::require_pairing("agent collaboration")?;
    let mut client = RuntimeClient::connect_existing().await?;
    client.send(&ClientMsg::Tag { action, name }).await?;
    let (session_id, tags) = reply(&mut client, "tag", |m| match m {
        RuntimeMsg::Tags { session_id, tags } => Some((session_id, tags)),
        _ => None,
    })
    .await?;
    println!("{session_id}: {}", tags.join(", "));
    Ok(())
}

pub async fn message(command: crate::cli::MessageCommands) -> Result<()> {
    use crate::cli::MessageCommands;
    crate::auth::require_pairing("agent collaboration")?;
    let mut client = RuntimeClient::connect_existing().await?;
    let request = match command {
        MessageCommands::Send {
            to,
            text,
            memory,
            vault,
            launch,
            expires,
        } => ClientMsg::MessageSend {
            request: super::collab::SendRequest {
                to,
                text,
                memory,
                vault,
                launch,
                expires_ms: super::host_work::duration_ms(&expires)
                    .ok_or_else(|| anyhow!("expiry must be 1s to 24h"))?,
            },
        },
        MessageCommands::Reply {
            task,
            text,
            memory,
            vault,
        } => ClientMsg::MessageReply {
            request: super::collab::ReplyRequest {
                task_id: task,
                text,
                memory,
                vault,
            },
        },
        MessageCommands::Complete { task_id } => ClientMsg::MessageComplete { task_id },
        MessageCommands::Status { id } => ClientMsg::MessageStatus { message_id: id },
        MessageCommands::Cancel { task_id } => ClientMsg::MessageCancel { task_id },
        MessageCommands::Directory { selector } => ClientMsg::MessageDirectory { selector },
    };
    let op = request.op();
    client.send(&request).await?;
    let response = reply(&mut client, op, |m| match m {
        RuntimeMsg::MessageSent { .. }
        | RuntimeMsg::MessageReplied { .. }
        | RuntimeMsg::MessageCompleted { .. }
        | RuntimeMsg::MessageStatus { .. }
        | RuntimeMsg::MessageCancelled { .. }
        | RuntimeMsg::MessageDirectory { .. } => Some(m),
        _ => None,
    })
    .await?;
    match response {
        RuntimeMsg::MessageSent {
            message_id,
            skipped,
        } => {
            println!("{message_id}");
            // The hosts a `project:` fan-out skipped: on stderr, so the
            // output stays the message id.
            for host in skipped {
                eprintln!("not sent to host {host}");
            }
        }
        RuntimeMsg::MessageReplied {
            task_id,
            result_id,
            state,
            detail,
        } => match state {
            ReplyState::Publishing => {
                println!("{task_id}: reply publishing its context; result {result_id}")
            }
            ReplyState::Submitted => println!("{task_id}: reply submitted; result {result_id}"),
            ReplyState::Refused => bail!(
                "{task_id}: reply refused: {detail}; send a corrected reply (result {result_id})"
            ),
        },
        RuntimeMsg::MessageCompleted { task_id } => println!("{task_id}: completed"),
        RuntimeMsg::MessageCancelled { task_id } => println!("{task_id}: cancelled"),
        RuntimeMsg::MessageDirectory { rows } => {
            for row in rows {
                println!(
                    "atem:{}/{}  {}  {}  local={}",
                    row.atem_id,
                    row.route_id,
                    row.session_id.as_deref().unwrap_or("(no live agent)"),
                    row.labels.join(", "),
                    row.local_consent
                );
            }
        }
        RuntimeMsg::MessageStatus { messages } => {
            for line in status_lines(messages)? {
                println!("{line}");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// How long `atem task resolve` waits: a `done` publishes its snapshot and
/// reads it back first (at most 10 s, as a reply's).
const RESOLVE_WAIT: Duration = Duration::from_secs(30);

/// `atem task list --unknown` and `atem task resolve` (host-work-v1 §11.6
/// "On the host"): the owner's, from a terminal outside any agent session.
/// Like `atem message …` they only connect to a running runtime: never
/// started, never replaced.
pub async fn task(command: crate::cli::TaskCommands) -> Result<()> {
    use super::protocol::LocalResolution;
    use crate::cli::{ResolveCommands, TaskCommands};
    crate::auth::require_pairing("delegated tasks")?;
    let mut client = RuntimeClient::connect_existing_with(NO_RUNTIME_FOR_TASKS).await?;
    match command {
        TaskCommands::List { unknown } => {
            client.send(&ClientMsg::TaskList { unknown }).await?;
            let tasks = reply(&mut client, "task_list", |m| match m {
                RuntimeMsg::TaskList { tasks } => Some(tasks),
                _ => None,
            })
            .await?;
            for task in &tasks {
                println!("{}", unknown_line(task, crate::status::local_datetime));
            }
        }
        TaskCommands::Resolve {
            task_id,
            resolution,
        } => {
            let resolution = match resolution {
                ResolveCommands::Failed { detail } => LocalResolution::Failed { detail },
                ResolveCommands::Done { memory, vault } => LocalResolution::Done { memory, vault },
            };
            client
                .send(&ClientMsg::TaskResolve {
                    task_id,
                    resolution,
                })
                .await?;
            let (task_id, state, by) =
                reply_within(&mut client, "task_resolve", RESOLVE_WAIT, |m| match m {
                    RuntimeMsg::TaskResolved {
                        task_id, state, by, ..
                    } => Some((task_id, state, by)),
                    _ => None,
                })
                .await?;
            println!("{}", resolved_line(&task_id, &state, &by));
        }
    }
    Ok(())
}

/// Why `atem task` found nothing to talk to.
const NO_RUNTIME_FOR_TASKS: &str = "no Atem runtime is running; delegated tasks are listed and resolved through it (`atem runtime start`)";

/// One line of `atem task list --unknown`: the task, its session, its
/// sender, the reason and when (`when` formats the host's Unix ms).
pub fn unknown_line(task: &super::protocol::UnknownTask, when: impl Fn(u64) -> String) -> String {
    format!(
        "{}  {}  {}  {}  {}",
        task.task_id,
        task.session_id,
        task.sender,
        task.reason,
        when(task.at_ms)
    )
}

/// What `atem task resolve` prints: `<task>: resolved as failed|done`, and
/// who resolved it when the same resolution came first from someone else.
pub fn resolved_line(task_id: &str, state: &str, by: &str) -> String {
    let how = if state == "completed" { "done" } else { state };
    if by == "local" {
        format!("{task_id}: resolved as {how}")
    } else {
        format!("{task_id}: resolved as {how} (by {by})")
    }
}

/// What `atem message status` prints for `messages`: each message, its
/// tasks here with their replies, and its rows to other hosts with what
/// came back.
fn status_lines(messages: Vec<super::collab::MessageView>) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for m in messages {
        lines.push(format!(
            "{}  {}  {}  workflow {}",
            m.message_id, m.delivery, m.detail, m.workflow_id
        ));
        for task in m.tasks {
            lines.push(format!(
                "  {}  {}  {}",
                task.task_id,
                serde_json::to_value(task.state)?.as_str().unwrap(),
                task.detail
            ));
            if let Some(result) = task.result {
                lines.push(format!(
                    "    reply {} ({}): {}",
                    result.result_id,
                    serde_json::to_value(result.state)?.as_str().unwrap(),
                    reply_text(&result)
                ));
                if !result.detail.is_empty() {
                    lines.push(format!("    {}", result.detail));
                }
                for reference in result.context {
                    lines.push(format!(
                        "    {:?}:{}@{} sha256 {}",
                        reference.kind, reference.id, reference.version, reference.digest
                    ));
                }
            }
        }
        // What another host sent reaches the terminal with its controls
        // escaped (review L6).
        for host in m.remote {
            let state = match &host.code {
                Some(code) => format!("{} ({})", host.state, escaped(code)),
                None => host.state,
            };
            lines.push(format!("  host {}  {state}  {}", host.host_id, host.detail));
            if host.status_pending {
                lines.push("    status pending".into());
            }
            for task in host.tasks {
                if task.task_id.is_empty() {
                    lines.push(format!(
                        "    recipient {}  {}",
                        task.recipient_id,
                        escaped(&task.state)
                    ));
                    continue;
                }
                lines.push(format!(
                    "    {}  {}  {}",
                    task.task_id,
                    escaped(&task.state),
                    escaped(&task.detail)
                ));
                if let Some(reply) = task.reply {
                    let text = if reply.dropped {
                        "(text no longer kept)".to_string()
                    } else {
                        escaped(&reply.text)
                    };
                    lines.push(format!("      reply {}: {text}", reply.result_id));
                    for reference in reply.context {
                        lines.push(format!(
                            "      {:?}:{}@{} sha256 {}",
                            reference.kind, reference.id, reference.version, reference.digest
                        ));
                    }
                    lines.push(format!("      {}", reply.delivery));
                }
            }
        }
    }
    Ok(lines)
}

/// `text` another host sent, its control characters (C0 other than
/// newline and tab, DEL, C1) escaped (`\u{1b}`), so none reaches the
/// terminal as a sequence.
fn escaped(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// A reply's text as `atem message status` shows it.
fn reply_text(result: &super::collab::ResultView) -> &str {
    if result.dropped {
        "(text no longer kept)"
    } else {
        &result.text
    }
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
        if !s.self_tags.is_empty() {
            text.push_str(&format!(
                "                  tags: {}\n",
                s.self_tags.join(", ")
            ));
        }
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

    /// `atem message status` across hosts: each row to another host (its
    /// state, a refusal's code, why; a row waiting for the Station's
    /// announcement says so), "status pending" before any status, then the
    /// host's resolution: each task with its state and detail, its reply
    /// and whether it was delivered, and a recipient with no task.
    #[test]
    fn status_shows_rows_to_other_hosts_and_what_came_back() {
        use super::super::collab::{
            MessageView, RemoteReplyView, RemoteTaskView, RemoteView, TaskView,
        };
        use atem_client::session::host_work::WorkState;
        let task = |id: &str, state: &str, detail: &str, reply| RemoteTaskView {
            recipient_id: "r-1".into(),
            task_id: id.into(),
            state: state.into(),
            detail: detail.into(),
            reply,
        };
        let view = MessageView {
            message_id: "m-1".into(),
            workflow_id: "w-1".into(),
            delivery: "accepted".into(),
            detail: "to other hosts only".into(),
            tasks: vec![TaskView {
                task_id: "t-local".into(),
                receipt_id: "rc".into(),
                session_id: "ses-aaaaaaaaaaaa".into(),
                route_id: "r".into(),
                state: WorkState::Queued,
                detail: "waiting for a ready agent".into(),
                result: None,
            }],
            remote: vec![
                RemoteView {
                    host_id: "host-b".into(),
                    state: "ready".into(),
                    code: None,
                    detail: "waiting for the Station to announce this host's mailbox".into(),
                    status_pending: true,
                    tasks: vec![],
                },
                RemoteView {
                    host_id: "host-c".into(),
                    state: "accepted".into(),
                    code: None,
                    detail: "accepted by the host".into(),
                    status_pending: false,
                    tasks: vec![
                        task(
                            "t-1",
                            "awaiting_result",
                            "reply submitted",
                            Some(RemoteReplyView {
                                result_id: "res-1".into(),
                                text: "done there".into(),
                                dropped: false,
                                context: vec![],
                                delivered: true,
                                delivery: "delivered".into(),
                            }),
                        ),
                        task(
                            "t-2",
                            "awaiting_result",
                            "reply submitted",
                            Some(RemoteReplyView {
                                result_id: "res-2".into(),
                                text: String::new(),
                                dropped: true,
                                context: vec![],
                                delivered: false,
                                delivery: "result not delivered: sender revoked".into(),
                            }),
                        ),
                    ],
                },
                RemoteView {
                    host_id: "host-d".into(),
                    state: "accepted".into(),
                    code: None,
                    detail: "accepted by the host".into(),
                    status_pending: false,
                    tasks: vec![task("", "no_match", "", None)],
                },
                RemoteView {
                    host_id: "host-e".into(),
                    state: "refused".into(),
                    code: Some("forbidden".into()),
                    detail: "refused by the host (forbidden)".into(),
                    status_pending: false,
                    tasks: vec![],
                },
            ],
        };
        assert_eq!(
            status_lines(vec![view]).unwrap(),
            [
                "m-1  accepted  to other hosts only  workflow w-1",
                "  t-local  queued  waiting for a ready agent",
                "  host host-b  ready  waiting for the Station to announce this host's mailbox",
                "    status pending",
                "  host host-c  accepted  accepted by the host",
                "    t-1  awaiting_result  reply submitted",
                "      reply res-1: done there",
                "      delivered",
                "    t-2  awaiting_result  reply submitted",
                "      reply res-2: (text no longer kept)",
                "      result not delivered: sender revoked",
                "  host host-d  accepted  accepted by the host",
                "    recipient r-1  no_match",
                "  host host-e  refused (forbidden)  refused by the host (forbidden)",
            ]
        );
    }

    /// Review L6: text another host sent (its status's detail, its reply)
    /// reaches the owner's terminal with its control characters escaped
    /// (C0, DEL and C1), never as terminal sequences; newlines and tabs in
    /// a reply stay.
    #[test]
    fn another_hosts_text_is_printed_with_its_controls_escaped() {
        use super::super::collab::{MessageView, RemoteReplyView, RemoteTaskView, RemoteView};
        let view = MessageView {
            message_id: "m-1".into(),
            workflow_id: "w-1".into(),
            delivery: "accepted".into(),
            detail: "to other hosts only".into(),
            tasks: vec![],
            remote: vec![RemoteView {
                host_id: "host-b".into(),
                state: "accepted".into(),
                code: None,
                detail: "accepted by the host".into(),
                status_pending: false,
                tasks: vec![RemoteTaskView {
                    recipient_id: "r-1".into(),
                    task_id: "t-1".into(),
                    state: "awaiting_result".into(),
                    detail: "on B \u{1b}[2J\u{7f}\u{9b}31m".into(),
                    reply: Some(RemoteReplyView {
                        result_id: "res-1".into(),
                        text: "line one\n\tline \u{1b}]0;title\u{7}two".into(),
                        dropped: false,
                        context: vec![],
                        delivered: false,
                        delivery: "delivery pending".into(),
                    }),
                }],
            }],
        };
        let lines = status_lines(vec![view]).unwrap();
        assert_eq!(
            lines[2],
            "    t-1  awaiting_result  on B \\u{1b}[2J\\u{7f}\\u{9b}31m"
        );
        assert_eq!(
            lines[3],
            "      reply res-1: line one\n\tline \\u{1b}]0;title\\u{7}two"
        );
        assert!(
            lines
                .iter()
                .all(|l| !l.chars().any(|c| c.is_control() && c != '\n' && c != '\t'))
        );
    }

    /// A reply whose text the runtime dropped (a day after its task
    /// settled past its deadline) says so rather than show nothing.
    #[test]
    fn a_dropped_reply_says_its_text_is_no_longer_kept() {
        let mut result = super::super::collab::ResultView {
            result_id: uuid::Uuid::new_v4().to_string(),
            state: ReplyState::Submitted,
            detail: String::new(),
            text: "done".into(),
            context: vec![],
            dropped: false,
        };
        assert_eq!(reply_text(&result), "done");
        result.text.clear();
        result.dropped = true;
        assert_eq!(reply_text(&result), "(text no longer kept)");
    }

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
            self_tags: vec![],
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

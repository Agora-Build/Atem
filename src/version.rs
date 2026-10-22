//! `atem --version` (`-V`): this atem's version, build and protocols, then
//! each separately running part — the runtime, the cred agent and the
//! sessions' workers — with its build, only while it runs. They are found by
//! the same passive looks `atem status` uses (`runtime::client::look`,
//! `cred_agent::look`): nothing is started, kept running or written.

use crate::memory::cred_agent::AgentLook;
use crate::runtime::client::{Look, version_of};
use std::collections::BTreeMap;

/// The first line: `atem 0.7.1 (build …) · protocol session r8, local v1`.
pub fn first_line(own: &str) -> String {
    format!(
        "atem {} (build {own}) \u{b7} protocol session r{}, local v{}",
        version_of(own),
        crate::session_protocol::revision::REVISION,
        crate::runtime::protocol::PROTOCOL
    )
}

fn component(label: &str, build: &str, pid: Option<u32>, tag: &str) -> String {
    let pid = pid.map(|pid| format!(", pid {pid}")).unwrap_or_default();
    format!(
        "{label:<10} {} (build {build}{pid})  [{tag}]\n",
        version_of(build)
    )
}

/// The whole text, from what the looks found (`own`: this build).
pub fn render(own: &str, runtime: &Look, agent: &AgentLook) -> String {
    let mut out = format!("{}\n", first_line(own));
    let runtime_differs = matches!(runtime, Look::Running { welcome, .. } if welcome.build != own);
    match runtime {
        Look::NotRunning => {}
        Look::Unreachable(error) => {
            out.push_str(&format!("{:<10} not answering ({error})\n", "runtime"));
        }
        Look::Running { welcome, .. } => {
            let tag = if welcome.build == own {
                "same as CLI"
            } else {
                "another build: run atem runtime restart"
            };
            out.push_str(&component(
                "runtime",
                &welcome.build,
                Some(welcome.pid),
                tag,
            ));
        }
    }
    match agent {
        None => {}
        Some(Err(error)) => {
            out.push_str(&format!("{:<10} not answering ({error})\n", "cred agent"));
        }
        Some(Ok((status, pid))) => {
            let build = status.build.as_str();
            let tag = if build == own {
                "same as CLI"
            } else if !status.unlocked {
                "another build, locked: replaced by this build when next needed"
            } else if runtime_differs {
                "another build: run atem runtime restart, then atem cred lock && atem cred unlock"
            } else {
                "another build: run atem cred lock && atem cred unlock"
            };
            out.push_str(&component("cred agent", build, *pid, tag));
        }
    }
    // The running sessions' workers, grouped by build.
    let mut builds: BTreeMap<Option<&str>, usize> = BTreeMap::new();
    for session in runtime.sessions().iter().filter(|s| s.state == "running") {
        *builds.entry(session.worker_build.as_deref()).or_default() += 1;
    }
    let groups: Vec<String> = builds
        .iter()
        .map(|(build, n)| match build {
            Some(build) => {
                let tag = if *build == own {
                    "same as CLI"
                } else {
                    "another build: kept until its session ends"
                };
                format!(
                    "{n} running: {} (build {build})  [{tag}]",
                    version_of(build)
                )
            }
            None => format!("{n} running: build unknown (started by an older atem)"),
        })
        .collect();
    if !groups.is_empty() {
        out.push_str(&format!("{:<10} {}\n", "workers", groups.join("; ")));
    }
    out
}

/// `atem --version` (blocking: socket I/O).
pub fn text() -> String {
    use crate::runtime::client::{LOOK_TIMEOUT, Locator, look};
    let own = crate::memory::cred_agent::build_id();
    let runtime = look(&Locator::default_paths(), LOOK_TIMEOUT);
    let paths = crate::paths::CredPaths::default_paths();
    let agent = crate::memory::cred_agent::look(&paths, LOOK_TIMEOUT);
    render(own, &runtime, &agent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::cred_agent::AgentStatus;
    use crate::runtime::client::Welcome;
    use crate::runtime::protocol::{RuntimeStatus, SessionSummary};

    const OWN: &str = "0.7.2+100.000000000-5";
    const OLD: &str = "0.7.1+90.000000000-4";

    fn running(build: &str, sessions: Vec<SessionSummary>) -> Look {
        Look::Running {
            welcome: Welcome {
                protocol: 1,
                build: build.into(),
                pid: 42,
                astation: true,
                host_error: None,
                worker_protocol: Some(1),
                device_list: None,
            },
            status: Some(RuntimeStatus {
                sessions,
                ..Default::default()
            }),
        }
    }

    fn session(state: &str, build: Option<&str>) -> SessionSummary {
        SessionSummary {
            id: "ses-aaaaaaaaaaaa".into(),
            provider: "claude".into(),
            cwd: "/w".into(),
            created_at_ms: 1,
            state: state.into(),
            status: "ready".into(),
            attached: false,
            remote_controlled: false,
            exited: None,
            rows: 24,
            cols: 80,
            generation: "g".into(),
            worker_build: build.map(str::to_string),
        }
    }

    fn agent(build: &str, unlocked: bool, pid: Option<u32>) -> AgentLook {
        Some(Ok((
            AgentStatus {
                unlocked,
                storage_kid: None,
                escrowed: true,
                older_build: build != OWN,
                build: build.into(),
            },
            pid,
        )))
    }

    #[test]
    fn nothing_running_is_one_line_with_the_protocols() {
        assert_eq!(
            render(OWN, &Look::NotRunning, &None),
            "atem 0.7.2 (build 0.7.2+100.000000000-5) \u{b7} protocol session r8, local v1\n"
        );
    }

    #[test]
    fn each_running_part_is_shown_with_its_build_and_what_to_do() {
        let runtime = running(
            OWN,
            vec![
                session("running", Some(OWN)),
                session("running", Some(OWN)),
                session("running", Some(OLD)),
                session("running", None),
                session("exited", Some(OLD)),
            ],
        );
        let text = render(OWN, &runtime, &agent(OLD, true, Some(7)));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!(
            lines[1],
            "runtime    0.7.2 (build 0.7.2+100.000000000-5, pid 42)  [same as CLI]"
        );
        assert_eq!(
            lines[2],
            "cred agent 0.7.1 (build 0.7.1+90.000000000-4, pid 7)  [another build: run atem cred lock && atem cred unlock]"
        );
        assert!(lines[3].starts_with("workers    "), "{text}");
        assert!(
            lines[3].contains("2 running: 0.7.2 (build 0.7.2+100.000000000-5)  [same as CLI]"),
            "{text}"
        );
        assert!(
            lines[3].contains("1 running: 0.7.1 (build 0.7.1+90.000000000-4)  [another build"),
            "{text}"
        );
        assert!(lines[3].contains("1 running: build unknown"), "{text}");
    }

    #[test]
    fn a_runtime_of_another_build_points_to_its_restart() {
        let text = render(OWN, &running(OLD, Vec::new()), &agent(OLD, true, None));
        assert!(
            text.contains("runtime    0.7.1 (build 0.7.1+90.000000000-4, pid 42)  [another build: run atem runtime restart]"),
            "{text}"
        );
        assert!(
            text.contains(
                "[another build: run atem runtime restart, then atem cred lock && atem cred unlock]"
            ),
            "{text}"
        );
        assert!(!text.contains("workers"), "{text}");
        // A locked agent of another build is simply replaced when next needed.
        let text = render(OWN, &Look::NotRunning, &agent(OLD, false, None));
        assert!(
            text.contains("replaced by this build when next needed"),
            "{text}"
        );
        // One that doesn't answer says so.
        let text = render(
            OWN,
            &Look::NotRunning,
            &Some(Err("it didn't answer in time".into())),
        );
        assert!(
            text.contains("cred agent not answering (it didn't answer in time)"),
            "{text}"
        );
    }
}

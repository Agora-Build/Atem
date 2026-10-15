//! Claude Code adapter: launch settings, hook events and transcript reading.

pub mod hooks;
pub mod transcript;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::chat::adapter::{AgentAdapter, AgentEvent, Capabilities, LaunchPlan, LogItem};
use hooks::EventReader;
use transcript::TranscriptReader;

const HOOKS_WAIT: Duration = Duration::from_secs(15);
const HOOKS_INACTIVE: &str =
    "Claude hooks are not active: disabled, --bare, or an unsupported version";

pub struct ClaudeAdapter {
    dir: Option<PathBuf>,
    events: Option<EventReader>,
    transcript: Option<TranscriptReader>,
    started_at: Instant,
    session_started: bool,
    withdrawn: Option<String>,
}

impl ClaudeAdapter {
    pub fn new() -> Self {
        Self {
            dir: None,
            events: None,
            transcript: None,
            started_at: Instant::now(),
            session_started: false,
            withdrawn: None,
        }
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
}

fn resumes_or_pins(args: &[String]) -> bool {
    args.iter().any(|a| {
        matches!(
            a.as_str(),
            "--continue" | "-c" | "--resume" | "-r" | "--session-id"
        ) || a.starts_with("--resume=")
            || a.starts_with("--session-id=")
    })
}

impl AgentAdapter for ClaudeAdapter {
    fn prepare_launch(&mut self, args: &[String], dir: &Path) -> anyhow::Result<LaunchPlan> {
        let settings = hooks::write_settings(dir)?;
        self.dir = Some(dir.to_path_buf());
        self.events = Some(EventReader::new(dir.to_path_buf()));
        self.started_at = Instant::now();
        let mut extra_args = vec![
            "--settings".to_string(),
            settings.to_string_lossy().into_owned(),
        ];
        let mut session_id = None;
        if !resumes_or_pins(args) {
            let id = uuid::Uuid::new_v4().to_string();
            extra_args.extend(["--session-id".to_string(), id.clone()]);
            session_id = Some(id);
        }
        Ok(LaunchPlan {
            extra_args,
            session_id,
        })
    }

    fn poll_events(&mut self) -> Vec<AgentEvent> {
        let Some(reader) = self.events.as_mut() else {
            return Vec::new();
        };
        let events = reader.poll();
        for ev in &events {
            if let AgentEvent::SessionStarted { log_path, .. } = ev {
                self.transcript = Some(TranscriptReader::new(log_path.clone()));
                self.session_started = true;
            }
        }
        events
    }

    fn poll_log(&mut self) -> Vec<LogItem> {
        let Some(reader) = self.transcript.as_mut() else {
            return Vec::new();
        };
        let items = reader.poll();
        for item in &items {
            if let LogItem::Problem {
                detail,
                fatal: true,
            } = item
            {
                self.withdrawn.get_or_insert_with(|| detail.clone());
            }
        }
        items
    }

    fn capabilities(&self) -> Capabilities {
        if let Some(reason) = &self.withdrawn {
            return Capabilities {
                chat_v1: false,
                reason: Some(reason.clone()),
            };
        }
        if self.session_started {
            return Capabilities {
                chat_v1: true,
                reason: None,
            };
        }
        let reason = (self.started_at.elapsed() >= HOOKS_WAIT).then(|| HOOKS_INACTIVE.to_string());
        Capabilities {
            chat_v1: false,
            reason,
        }
    }
}

impl Drop for ClaudeAdapter {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn launch(args: &[&str]) -> (tempfile::TempDir, ClaudeAdapter, LaunchPlan) {
        let root = tempfile::tempdir().unwrap();
        let dir = hooks::create_session_dir(root.path()).unwrap();
        let mut a = ClaudeAdapter::new();
        let plan = a.prepare_launch(&s(args), &dir).unwrap();
        (root, a, plan)
    }

    #[test]
    fn prepare_launch_pins_session_id_unless_resuming() {
        let (_r, a, plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        assert_eq!(plan.extra_args[0], "--settings");
        assert_eq!(
            plan.extra_args[1],
            dir.join("settings.json").to_string_lossy()
        );
        assert!(dir.join("settings.json").exists());
        let id = plan.session_id.clone().unwrap();
        assert_eq!(
            plan.extra_args[2..],
            ["--session-id".to_string(), id.clone()]
        );
        assert!(uuid::Uuid::parse_str(&id).is_ok());

        for args in [
            &["--continue"][..],
            &["-c"],
            &["--resume"],
            &["--resume=abc"],
            &["-r", "abc"],
            &["--session-id", "x"],
            &["--session-id=x"],
            &["--model", "haiku", "-c"],
        ] {
            let (_r, _a, plan) = launch(args);
            assert_eq!(plan.extra_args.len(), 2, "{args:?}");
            assert_eq!(plan.session_id, None, "{args:?}");
        }
    }

    #[test]
    fn capabilities_wait_for_session_start_then_withdraw_after_15s() {
        let mut a = ClaudeAdapter::new();
        assert_eq!(
            a.capabilities(),
            Capabilities {
                chat_v1: false,
                reason: None
            }
        );
        a.started_at = Instant::now() - Duration::from_secs(16);
        let c = a.capabilities();
        assert!(!c.chat_v1);
        assert_eq!(c.reason.as_deref(), Some(HOOKS_INACTIVE));
        // a late SessionStart still enables chat
        a.session_started = true;
        assert_eq!(
            a.capabilities(),
            Capabilities {
                chat_v1: true,
                reason: None
            }
        );
        a.withdrawn = Some("format changed".into());
        let c = a.capabilities();
        assert!(!c.chat_v1);
        assert_eq!(c.reason.as_deref(), Some("format changed"));
    }

    fn event(dir: &Path, name: &str, body: &str) {
        fs::write(dir.join("events").join(name), body).unwrap();
    }

    #[test]
    fn session_start_opens_the_transcript_and_clear_switches_it() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chat/claude");
        let t1 = root.path().join("one.jsonl");
        let t2 = root.path().join("two.jsonl");
        fs::copy(fx.join("session-basic.jsonl"), &t1).unwrap();
        fs::copy(fx.join("session-after-clear.jsonl"), &t2).unwrap();
        assert!(a.poll_log().is_empty());

        event(
            &dir,
            "ev.1.json",
            &format!(
                r#"{{"hook_event_name":"SessionStart","session_id":"s1","transcript_path":"{}"}}"#,
                t1.display()
            ),
        );
        let evs = a.poll_events();
        assert!(matches!(evs[0], AgentEvent::SessionStarted { .. }));
        assert!(a.capabilities().chat_v1);
        let items = a.poll_log();
        assert!(
            items
                .iter()
                .any(|i| matches!(i, LogItem::UserMessage { .. }))
        );

        event(
            &dir,
            "ev.2.json",
            &format!(
                r#"{{"hook_event_name":"SessionStart","session_id":"s2","transcript_path":"{}","source":"clear"}}"#,
                t2.display()
            ),
        );
        a.poll_events();
        assert_eq!(a.transcript.as_ref().unwrap().path(), t2);
        let items = a.poll_log();
        assert!(
            items
                .iter()
                .any(|i| matches!(i, LogItem::UserMessage { text, .. } if text == "say hi"))
        );
    }

    #[test]
    fn fatal_problem_withdraws_chat() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let t = root.path().join("bad.jsonl");
        fs::write(
            &t,
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n",
        )
        .unwrap();
        event(
            &dir,
            "ev.1.json",
            &format!(
                r#"{{"hook_event_name":"SessionStart","session_id":"s","transcript_path":"{}"}}"#,
                t.display()
            ),
        );
        a.poll_events();
        let items = a.poll_log();
        assert!(
            items
                .iter()
                .any(|i| matches!(i, LogItem::Problem { fatal: true, .. }))
        );
        let c = a.capabilities();
        assert!(!c.chat_v1);
        assert!(c.reason.is_some());
    }

    #[test]
    fn drop_removes_only_the_session_dir() {
        let (root, a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        drop(a);
        assert!(!dir.exists());
        assert!(root.path().exists());
    }
}

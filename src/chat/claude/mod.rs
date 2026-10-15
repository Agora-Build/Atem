//! Claude Code adapter: launch settings, hook events and transcript reading.

pub mod hooks;
pub mod transcript;

use std::collections::VecDeque;
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
    /// Events not yet returned: a switch to another log waits one poll so the
    /// old log is read to its end first.
    held: VecDeque<AgentEvent>,
    /// The switch at the front of `held` already waited its poll.
    switch_waited: bool,
    /// Log items returned before the reader's own at the next `poll_log`.
    queued: Vec<LogItem>,
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
            held: VecDeque::new(),
            switch_waited: false,
            queued: Vec::new(),
            started_at: Instant::now(),
            session_started: false,
            withdrawn: None,
        }
    }

    #[cfg(test)]
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

impl ClaudeAdapter {
    /// Read the old log to its end (normal items), then open `path`. Content
    /// already there is backfill when the session was resumed rather than
    /// started or cleared (a new or cleared session's log is live from its
    /// first line).
    fn switch_to(&mut self, path: PathBuf, source: &str) {
        if let Some(old) = self.transcript.as_mut() {
            self.queued.extend(old.poll());
        }
        let mut reader = TranscriptReader::new(path);
        if !matches!(source, "startup" | "clear") {
            for item in reader.poll() {
                self.queued.push(match item {
                    LogItem::Problem { .. } => item,
                    item => LogItem::Backfill(Box::new(item)),
                });
            }
        }
        self.transcript = Some(reader);
    }
}

impl AgentAdapter for ClaudeAdapter {
    fn prepare_launch(&mut self, args: &[String], dir: &Path) -> anyhow::Result<LaunchPlan> {
        let named = dir
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("chat-"));
        if !named || !dir.join("events").is_dir() {
            anyhow::bail!("not a chat session directory: {}", dir.display());
        }
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
        let mut incoming = std::mem::take(&mut self.held);
        incoming.extend(reader.poll());
        let mut out = Vec::new();
        while let Some(mut event) = incoming.pop_front() {
            if let AgentEvent::SessionStarted {
                session_id,
                log_path,
                source,
                same_log,
            } = &mut event
            {
                // Claude names the transcript after the session; anything else is
                // not a start of this session's log.
                let expected = format!("{session_id}.jsonl");
                if log_path.file_name() != Some(std::ffi::OsStr::new(&expected)) {
                    self.queued.push(LogItem::Problem {
                        detail: "ignored a session start whose transcript is not named after its session"
                            .into(),
                        fatal: false,
                    });
                    continue;
                }
                let current = self.transcript.as_ref().map(|r| r.path().to_path_buf());
                *same_log = current.as_deref() == Some(log_path.as_path());
                if !*same_log {
                    if current.is_some() && !self.switch_waited {
                        // Give this tick's poll_log the old log's last lines first.
                        self.switch_waited = true;
                        incoming.push_front(event);
                        self.held = incoming;
                        break;
                    }
                    self.switch_waited = false;
                    self.switch_to(log_path.clone(), source);
                }
                self.session_started = true;
            }
            out.push(event);
        }
        out
    }

    fn poll_log(&mut self) -> Vec<LogItem> {
        let mut items = std::mem::take(&mut self.queued);
        if let Some(reader) = self.transcript.as_mut() {
            items.extend(reader.poll());
        }
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
        let t1 = root.path().join("s1.jsonl");
        let t2 = root.path().join("s2.jsonl");
        fs::copy(fx.join("session-basic.jsonl"), &t1).unwrap();
        fs::copy(fx.join("session-after-clear.jsonl"), &t2).unwrap();
        assert!(a.poll_log().is_empty());

        event(
            &dir,
            "ev.1.json",
            &format!(
                r#"{{"hook_event_name":"SessionStart","session_id":"s1","transcript_path":"{}","source":"startup"}}"#,
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
        // held one poll so the old log is read to its end first
        assert!(a.poll_events().is_empty());
        assert!(a.poll_log().is_empty());
        let evs = a.poll_events();
        assert!(
            matches!(&evs[0], AgentEvent::SessionStarted { source, same_log: false, .. }
            if source == "clear")
        );
        assert_eq!(a.transcript.as_ref().unwrap().path(), t2);
        // /clear content is live (never backfill)
        let items = a.poll_log();
        assert!(
            items
                .iter()
                .any(|i| matches!(i, LogItem::UserMessage { text, .. } if text == "say hi"))
        );
        assert!(!items.iter().any(|i| matches!(i, LogItem::Backfill(_))));
    }

    fn start_event(dir: &Path, name: &str, session: &str, path: &Path, source: &str) {
        event(
            dir,
            name,
            &format!(
                r#"{{"hook_event_name":"SessionStart","session_id":"{session}","transcript_path":"{}","source":"{source}"}}"#,
                path.display()
            ),
        );
    }

    fn user_line(uuid: &str, text: &str) -> String {
        format!(
            r#"{{"type":"user","uuid":"{uuid}","promptId":"p-{uuid}","message":{{"role":"user","content":"{text}"}}}}"#
        ) + "\n"
    }

    fn append(path: &Path, text: &str) {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn same_path_start_says_same_log_and_passes_the_source() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let t = root.path().join("s1.jsonl");
        start_event(&dir, "ev.1.json", "s1", &t, "startup");
        let evs = a.poll_events();
        assert!(
            matches!(&evs[..], [AgentEvent::SessionStarted { source, same_log: false, .. }]
            if source == "startup")
        );
        start_event(&dir, "ev.2.json", "s1", &t, "compact");
        let evs = a.poll_events();
        assert!(
            matches!(&evs[..], [AgentEvent::SessionStarted { source, same_log: true, .. }]
            if source == "compact")
        );
    }

    #[test]
    fn switching_logs_reads_the_old_one_to_its_end_first() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let t1 = root.path().join("s1.jsonl");
        let t2 = root.path().join("s2.jsonl");
        append(&t1, &user_line("u1", "one"));
        start_event(&dir, "ev.1.json", "s1", &t1, "startup");
        a.poll_events();
        assert_eq!(a.poll_log().len(), 1);
        // old-log lines written before the switch, and one more after the hold
        append(&t1, &user_line("u2", "two"));
        start_event(&dir, "ev.2.json", "s2", &t2, "clear");
        event(&dir, "ev.3.json", r#"{"hook_event_name":"Stop"}"#);
        assert!(a.poll_events().is_empty(), "held until the old log is read");
        let items = a.poll_log();
        assert!(matches!(&items[..], [LogItem::UserMessage { id, .. }] if id == "u2"));
        append(&t1, &user_line("u3", "three"));
        let evs = a.poll_events();
        assert!(matches!(evs[0], AgentEvent::SessionStarted { .. }));
        assert_eq!(evs[1], AgentEvent::TurnEnded, "later events follow");
        let items = a.poll_log();
        assert!(matches!(&items[..], [LogItem::UserMessage { id, .. }] if id == "u3"));
        assert_eq!(a.transcript.as_ref().unwrap().path(), t2);
    }

    #[test]
    fn resuming_another_session_reads_its_content_as_backfill() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let t1 = root.path().join("s1.jsonl");
        let t2 = root.path().join("s2.jsonl");
        start_event(&dir, "ev.1.json", "s1", &t1, "startup");
        a.poll_events();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chat/claude");
        fs::copy(fx.join("session-basic.jsonl"), &t2).unwrap();
        start_event(&dir, "ev.2.json", "s2", &t2, "resume");
        assert!(a.poll_events().is_empty());
        a.poll_log();
        let evs = a.poll_events();
        assert!(matches!(
            &evs[..],
            [AgentEvent::SessionStarted {
                same_log: false,
                ..
            }]
        ));
        let items = a.poll_log();
        assert!(!items.is_empty());
        assert!(
            items.iter().all(|i| matches!(i, LogItem::Backfill(_))),
            "{items:?}"
        );
        assert!(items.iter().any(|i| matches!(i,
            LogItem::Backfill(b) if matches!(**b, LogItem::TurnEnded { .. }))));
        // what is written after the resume is live
        append(&t2, &user_line("new", "next"));
        let items = a.poll_log();
        assert!(matches!(&items[..], [LogItem::UserMessage { id, .. }] if id == "new"));
    }

    #[test]
    fn session_start_whose_log_does_not_match_its_id_is_ignored() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let good = root.path().join("s1.jsonl");
        start_event(&dir, "ev.1.json", "s1", &good, "startup");
        a.poll_events();
        for (i, path) in [
            root.path().join("other.jsonl"),
            root.path().join("s1.jsonl.bak"),
            root.path().join("xs1.jsonl"),
        ]
        .iter()
        .enumerate()
        {
            start_event(&dir, &format!("ev.{}.json", i + 2), "s1", path, "resume");
            assert!(a.poll_events().is_empty(), "{path:?}");
            assert_eq!(a.transcript.as_ref().unwrap().path(), good);
            let items = a.poll_log();
            assert!(
                matches!(&items[..], [LogItem::Problem { fatal: false, .. }]),
                "{items:?}"
            );
        }
        assert!(a.capabilities().chat_v1);
        // before any valid start, a mismatched one does not enable chat
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        start_event(
            &dir,
            "ev.1.json",
            "s1",
            &root.path().join("s2.jsonl"),
            "startup",
        );
        assert!(a.poll_events().is_empty());
        assert!(!a.capabilities().chat_v1);
    }

    #[test]
    fn same_path_session_start_keeps_the_reader() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chat/claude");
        let t1 = root.path().join("s1.jsonl");
        fs::copy(fx.join("session-basic.jsonl"), &t1).unwrap();
        let start = format!(
            r#"{{"hook_event_name":"SessionStart","session_id":"s1","transcript_path":"{}"}}"#,
            t1.display()
        );
        event(&dir, "ev.1.json", &start);
        a.poll_events();
        assert!(!a.poll_log().is_empty());
        event(&dir, "ev.2.json", &start);
        a.poll_events();
        assert!(a.poll_log().is_empty(), "no replay after same-path start");
    }

    #[test]
    fn prepare_launch_refuses_foreign_dirs_and_drop_leaves_them() {
        let root = tempfile::tempdir().unwrap();
        let plain = root.path().join("other");
        fs::create_dir_all(plain.join("events")).unwrap();
        let mut a = ClaudeAdapter::new();
        assert!(a.prepare_launch(&[], &plain).is_err());
        let noevents = root.path().join("chat-x");
        fs::create_dir_all(&noevents).unwrap();
        assert!(a.prepare_launch(&[], &noevents).is_err());
        assert!(a.dir().is_none());
        drop(a);
        assert!(plain.exists() && noevents.exists());
    }

    #[test]
    fn fatal_problem_withdraws_chat() {
        let (root, mut a, _plan) = launch(&[]);
        let dir = a.dir().unwrap().to_path_buf();
        let t = root.path().join("s.jsonl");
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

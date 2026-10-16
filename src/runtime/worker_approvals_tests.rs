//! The watcher with the real hook script (`sh`), as the agents run it.

use super::*;
use std::io::Write;
use std::process::{Child, Command, Stdio};

struct Session {
    dir: tempfile::TempDir,
}

impl Session {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(approvals::approvals_dir(dir.path())).unwrap();
        approvals::install_script(&dir.path().join(approvals::SCRIPT_NAME)).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The hook as `agent` runs it, with `stdin`; `limit` its own wait.
    fn hook(&self, agent: &str, limit: u64, stdin: &str) -> Child {
        let script = self.path().join(approvals::SCRIPT_NAME);
        let mut child = Command::new("/bin/sh")
            .arg(&script)
            .arg(agent)
            .arg(limit.to_string())
            .env(approvals::ENV, self.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child
    }

    fn post(&self, stdin: &str) {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(approvals::claude_post_command(self.path()))
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(approvals::approvals_dir(self.path()))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

/// What the hook printed (it must end within 5 s).
fn printed(child: Child) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let out = child.wait_with_output().unwrap();
        let _ = tx.send(String::from_utf8(out.stdout).unwrap());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the hook didn't end")
}

/// Polls until at least one event (5 s at most).
fn events(a: &mut Approvals, connected: bool) -> Vec<Event> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = a.poll(connected);
        if !out.is_empty() {
            return out;
        }
        assert!(Instant::now() < deadline, "no event");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Polls until nothing waits any more, returning what that reported.
fn drained(a: &mut Approvals) -> Vec<Event> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    while a.waiting() > 0 {
        out.extend(a.poll(true));
        assert!(Instant::now() < deadline, "still waiting");
        std::thread::sleep(Duration::from_millis(20));
    }
    out
}

const SECRET_BASH: &str = r#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"curl -H 'X-Key: sk-proj-abcdef1234567890ABCDEF' https://api.example\necho two","description":"d"},"permission_suggestions":[{"type":"addRules","rules":[{"toolName":"Bash","ruleContent":"curl:*"}],"behavior":"allow","destination":"localSettings"}]}"#;

fn request_id(event: &Event) -> String {
    match event {
        Event::Request { request_id, .. } => request_id.clone(),
        other => panic!("not a request: {other:?}"),
    }
}

#[test]
fn a_request_is_reported_redacted_and_the_decision_reaches_the_hook() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Claude);
    let hook = s.hook("claude", 30, SECRET_BASH);
    let got = events(&mut a, true);
    assert_eq!(got.len(), 1);
    let Event::Request { request_id, info } = &got[0] else {
        panic!("{got:?}")
    };
    assert_eq!(info.tool, "Bash");
    assert_eq!(
        info.summary,
        "curl -H 'X-Key: [redacted]' https://api.example"
    );
    assert_eq!(info.always_rules.len(), 1);
    assert_eq!(info.always_rules[0].label, "Allow Bash(curl:*)");
    let rule = info.always_rules[0].rule_id.clone();
    assert_eq!(
        a.decide(request_id, ApprovalDecision::AllowAlways, Some(&rule), None),
        None
    );
    assert_eq!(
        printed(hook),
        r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedPermissions":[{"behavior":"allow","destination":"localSettings","rules":[{"ruleContent":"curl:*","toolName":"Bash"}],"type":"addRules"}]}}}"#
    );
    assert_eq!(
        drained(&mut a),
        vec![Event::Applied {
            request_id: request_id.clone(),
            ok: true
        }]
    );
    assert!(s.files().is_empty(), "{:?}", s.files());
}

#[test]
fn deny_and_bad_decisions() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Codex);
    let hook = s.hook("codex", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    let refused = |id: &str| {
        Some(Event::Applied {
            request_id: id.into(),
            ok: false,
        })
    };
    // Codex offers no rule; an unknown request can't be answered.
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowAlways, Some("r0-x"), None),
        refused(&id)
    );
    assert_eq!(
        a.decide("nope", ApprovalDecision::AllowOnce, None, None),
        refused("nope")
    );
    assert_eq!(
        a.decide(&id, ApprovalDecision::Deny, None, Some("not on prod")),
        None
    );
    // Answered once only.
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowOnce, None, None),
        refused(&id)
    );
    assert_eq!(
        printed(hook),
        r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"not on prod"}}}"#
    );
    assert_eq!(
        drained(&mut a),
        vec![Event::Applied {
            request_id: id,
            ok: true
        }]
    );
}

#[test]
fn without_a_broker_the_hook_is_released_at_once() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Codex);
    let hook = s.hook("codex", 30, SECRET_BASH);
    let deadline = Instant::now() + Duration::from_secs(5);
    while a.waiting() == 0 {
        assert!(a.poll(false).is_empty());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
    assert!(s.files().is_empty());
}

#[test]
fn adoption_releases_what_the_new_broker_does_not_know() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Codex);
    let first = s.hook("codex", 30, SECRET_BASH);
    let one = request_id(&events(&mut a, true)[0]);
    let second = s.hook("codex", 30, SECRET_BASH);
    let two = request_id(&events(&mut a, true)[0]);
    a.keep_only(std::slice::from_ref(&two));
    assert_eq!(printed(first), "", "{one} released");
    assert!(a.poll(true).is_empty(), "a release reports nothing");
    a.decide(&two, ApprovalDecision::AllowOnce, None, None);
    assert!(printed(second).contains(r#""behavior":"allow""#));
    assert_eq!(
        drained(&mut a),
        vec![Event::Applied {
            request_id: two,
            ok: true
        }]
    );
}

#[test]
fn release_approvals_answers_every_waiting_hook_with_no_decision() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Codex);
    let hooks: Vec<Child> = (0..2)
        .map(|_| {
            let h = s.hook("codex", 30, SECRET_BASH);
            events(&mut a, true);
            h
        })
        .collect();
    a.release_all();
    for h in hooks {
        assert_eq!(printed(h), "");
    }
    assert!(drained(&mut a).is_empty());
    assert!(s.files().is_empty());
}

#[test]
fn a_killed_hook_is_interrupted_and_a_late_decision_refused() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Claude);
    let mut hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    // Esc: Claude SIGTERMs the waiting hook.
    unsafe { libc::kill(hook.id() as libc::pid_t, libc::SIGTERM) };
    hook.wait().unwrap();
    assert_eq!(
        events(&mut a, true),
        vec![Event::Closed {
            request_id: id.clone(),
            reason: ApprovalCloseReason::Interrupted
        }]
    );
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowOnce, None, None),
        Some(Event::Applied {
            request_id: id,
            ok: false
        })
    );
    assert!(s.files().is_empty(), "{:?}", s.files());
}

#[test]
fn a_hook_at_its_timeout_is_timed_out() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Codex).with_timeout(Duration::from_secs(1));
    let hook = s.hook("codex", 1, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    assert_eq!(printed(hook), "");
    assert_eq!(
        events(&mut a, true),
        vec![Event::Closed {
            request_id: id,
            reason: ApprovalCloseReason::TimedOut
        }]
    );
}

#[test]
fn claude_answered_in_the_terminal_closes_the_request() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Claude);
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    // Another tool ran: not ours.
    s.post(
        r#"{"hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":"/x"}}"#,
    );
    assert!(a.poll(true).is_empty());
    // The same tool and input ran: the terminal allowed it.
    let v: Value = serde_json::from_str(SECRET_BASH).unwrap();
    s.post(
        &serde_json::json!({"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":v["tool_input"]})
            .to_string(),
    );
    assert_eq!(
        events(&mut a, true),
        vec![Event::Closed {
            request_id: id.clone(),
            reason: ApprovalCloseReason::AnsweredTerminal
        }]
    );
    // Its hook was left waiting by Claude: it gets "no decision".
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowOnce, None, None),
        Some(Event::Applied {
            request_id: id,
            ok: false
        })
    );
    assert!(s.files().is_empty(), "{:?}", s.files());
}

#[test]
fn a_turn_that_moved_on_or_an_exit_closes_what_waits() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Claude);
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    assert_eq!(
        a.turn_moved_on(),
        vec![Event::Closed {
            request_id: id,
            reason: ApprovalCloseReason::AnsweredTerminal
        }]
    );
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());

    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    assert_eq!(
        a.process_ended(),
        vec![Event::Closed {
            request_id: id,
            reason: ApprovalCloseReason::ProcessEnded
        }]
    );
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
}

#[test]
fn a_request_it_cannot_read_is_released() {
    let s = Session::new();
    let mut a = Approvals::new(s.path(), Agent::Claude);
    let hook = s.hook("claude", 30, "not json");
    let deadline = Instant::now() + Duration::from_secs(5);
    while a.waiting() == 0 {
        assert!(a.poll(true).is_empty());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
}

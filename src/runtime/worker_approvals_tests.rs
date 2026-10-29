//! The watcher with the real hook script (`sh`), as the agents run it.

use super::*;
use crate::chat::adapter::ToolResultKind;
use crate::runtime::worker_protocol::{ApplyOutcome, RuleGrant};
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

    fn approvals(&self) -> PathBuf {
        approvals::approvals_dir(self.path())
    }

    /// The hook as `agent` runs it (started by this process), with `stdin`;
    /// `limit` its own wait.
    fn hook(&self, agent: &str, limit: u64, stdin: &str) -> Child {
        let script = self.path().join(approvals::SCRIPT_NAME);
        let cmd = format!(
            "exec /bin/sh {} {agent} {limit}",
            approvals::shell_quote(&script.to_string_lossy())
        );
        self.run(&cmd, stdin)
    }

    /// `sh -c command` with the session's variable, `stdin` piped in.
    fn run(&self, command: &str, stdin: &str) -> Child {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
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

    /// A request as a hook that never answers would leave it: `req-<id>`
    /// and `pid-<id>` naming a live `sleep` started by this process.
    fn fake_request(&self, id: &str, stdin: &str) -> Child {
        let sleeper = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(
            self.approvals().join(format!("pid-{id}")),
            format!("{} {}\n", sleeper.id(), std::process::id()),
        )
        .unwrap();
        std::fs::write(self.approvals().join(format!("req-{id}.json")), stdin).unwrap();
        sleeper
    }

    /// As `fake_request`, with the `sleep` itself as the hook's parent: a
    /// non-shell child of this process (the agent).
    fn fake_request_through_child(&self, id: &str, stdin: &str) -> Child {
        let sleeper = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(
            self.approvals().join(format!("pid-{id}")),
            format!("{} {}\n", sleeper.id(), sleeper.id()),
        )
        .unwrap();
        std::fs::write(self.approvals().join(format!("req-{id}.json")), stdin).unwrap();
        sleeper
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.approvals())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn mtime_ms_ago(path: &Path, ms: u64) {
    let t = std::time::SystemTime::now() - Duration::from_millis(ms);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
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

fn watcher(s: &Session, agent: Agent) -> Approvals {
    Approvals::new(s.path(), agent, Some(std::process::id()))
        .with_confirm(Duration::from_millis(300))
}

/// Polls until at least one event (5 s at most).
fn events(a: &mut Approvals, connected: bool) -> Vec<Event> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = a.poll(connected, Vec::new());
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
        out.extend(a.poll(true, Vec::new()));
        assert!(Instant::now() < deadline, "still waiting");
        std::thread::sleep(Duration::from_millis(20));
    }
    out
}

/// Polls until `n` requests are known (none reported).
fn known(a: &mut Approvals, n: usize, connected: bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while a.waiting() < n {
        assert!(a.poll(connected, Vec::new()).is_empty());
        assert!(Instant::now() < deadline, "not seen");
        std::thread::sleep(Duration::from_millis(20));
    }
}

const SECRET_BASH: &str = r#"{"hook_event_name":"PermissionRequest","session_id":"s1","tool_name":"Bash","tool_input":{"command":"curl -H 'X-Key: sk-proj-abcdef1234567890ABCDEF' https://api.example\necho two","description":"d"},"permission_suggestions":[{"type":"addRules","rules":[{"toolName":"Bash","ruleContent":"curl:*"}],"behavior":"allow","destination":"localSettings"}]}"#;

fn tool_input() -> Value {
    serde_json::from_str::<Value>(SECRET_BASH).unwrap()["tool_input"].clone()
}

fn post_body() -> String {
    serde_json::json!({"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":tool_input()})
        .to_string()
}

fn request_id(event: &Event) -> String {
    match event {
        Event::Request { request_id, .. } => request_id.clone(),
        other => panic!("not a request: {other:?}"),
    }
}

fn applied(id: &str, outcome: ApplyOutcome) -> Event {
    Event::Applied {
        request_id: id.into(),
        outcome,
    }
}

fn closed(id: &str, reason: ApprovalCloseReason) -> Event {
    Event::Closed {
        request_id: id.into(),
        reason,
    }
}

#[test]
fn a_request_is_reported_redacted_and_the_decision_reaches_the_hook() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
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
    assert_eq!(info.always_rules[0].label, "Allow Bash(curl:*)");
    // Claude offers its own suggestions only (no Atem session rule).
    assert_eq!(info.always_rules.len(), 1);
    let rule = info.always_rules[0].rule_id.clone();
    assert_eq!(
        a.decide(
            request_id,
            ApprovalDecision::AllowAlways,
            Some(&rule),
            None,
            None
        ),
        None
    );
    assert_eq!(
        printed(hook),
        r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedPermissions":[{"behavior":"allow","destination":"localSettings","rules":[{"ruleContent":"curl:*","toolName":"Bash"}],"type":"addRules"}]}}}"#
    );
    // Claude: confirmed once nothing contradicted it for a while.
    assert_eq!(drained(&mut a), vec![applied(request_id, ApplyOutcome::Ok)]);
    assert!(s.files().is_empty(), "{:?}", s.files());
}

#[test]
fn a_remote_allow_and_its_post_in_the_same_poll_are_applied() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude).with_confirm(Duration::from_secs(60));
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    a.decide(&id, ApprovalDecision::AllowOnce, None, None, None);
    assert!(printed(hook).contains(r#""behavior":"allow""#));
    // The tool ran (PostToolUse) before the worker looked again.
    s.post(&post_body());
    assert_eq!(
        a.poll(true, Vec::new()),
        vec![applied(&id, ApplyOutcome::Ok)]
    );
    assert_eq!(a.waiting(), 0);
}

#[test]
fn a_remote_deny_followed_by_the_tool_running_is_unknown() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude).with_confirm(Duration::from_secs(60));
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    a.decide(&id, ApprovalDecision::Deny, None, None, Some("no"));
    assert!(printed(hook).contains(r#""behavior":"deny""#));
    assert!(
        a.poll(true, Vec::new()).is_empty(),
        "waits for confirmation"
    );
    // Yet the tool ran: the terminal's Yes won.
    s.post(&post_body());
    assert_eq!(
        a.poll(true, Vec::new()),
        vec![applied(&id, ApplyOutcome::Unknown)]
    );
}

#[test]
fn a_remote_deny_confirmed_by_its_tool_result_is_applied() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude).with_confirm(Duration::from_secs(60));
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    a.decide(&id, ApprovalDecision::Deny, None, None, Some("use staging"));
    printed(hook);
    assert!(a.poll(true, Vec::new()).is_empty());
    let result = Evidence::Tool {
        tool_name: "Bash".into(),
        input: tool_input(),
        kind: ToolResultKind::Failed,
        text: "Error: use staging".into(),
        at_ms: now_ms() + 50,
    };
    assert_eq!(
        a.poll(true, vec![result]),
        vec![applied(&id, ApplyOutcome::Ok)]
    );
}

#[test]
fn terminal_evidence_before_the_claim_is_unknown() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude).with_confirm(Duration::from_secs(60));
    let mut sleeper = s.fake_request("abc", SECRET_BASH);
    mtime_ms_ago(&s.approvals().join("req-abc.json"), 5000);
    let id = request_id(&events(&mut a, true)[0]);
    a.decide(&id, ApprovalDecision::AllowOnce, None, None, None);
    // The hook claims it now; the terminal's answer (a post) is 2 s older.
    let taken = s.approvals().join("taken-abc.json");
    std::fs::rename(s.approvals().join("dec-abc.json"), &taken).unwrap();
    s.post(&post_body());
    for e in std::fs::read_dir(s.approvals()).unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with("post-") {
            mtime_ms_ago(&e.path(), 2000);
        }
    }
    assert_eq!(
        a.poll(true, Vec::new()),
        vec![applied(&id, ApplyOutcome::Unknown)]
    );
    sleeper.kill().unwrap();
    sleeper.wait().unwrap();
}

#[test]
fn a_decision_not_yet_taken_is_withdrawn_when_the_terminal_answers() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    let mut sleeper = s.fake_request("abc", SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    a.decide(&id, ApprovalDecision::AllowOnce, None, None, None);
    s.post(&post_body());
    assert_eq!(
        a.poll(true, Vec::new()),
        vec![closed(&id, ApprovalCloseReason::AnsweredTerminal)]
    );
    // The waiting hook now finds "no decision".
    assert_eq!(
        std::fs::read_to_string(s.approvals().join("dec-abc.json")).unwrap(),
        ""
    );
    sleeper.kill().unwrap();
    sleeper.wait().unwrap();
    assert!(drained(&mut a).is_empty());
}

#[test]
fn deny_and_bad_decisions() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let hook = s.hook("codex", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    let refused = |id: &str| Some(applied(id, ApplyOutcome::NotDelivered));
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowAlways, Some("r0-x"), None, None),
        refused(&id)
    );
    assert_eq!(
        a.decide("nope", ApprovalDecision::AllowOnce, None, None, None),
        refused("nope")
    );
    assert_eq!(
        a.decide(&id, ApprovalDecision::Deny, None, None, Some("not on prod")),
        None
    );
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowOnce, None, None, None),
        refused(&id)
    );
    assert_eq!(
        printed(hook),
        r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"not on prod"}}}"#
    );
    // Codex holds its prompt while the hook waits: taken = applied.
    assert_eq!(drained(&mut a), vec![applied(&id, ApplyOutcome::Ok)]);
}

#[test]
fn without_a_broker_the_hook_is_released_at_once() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let hook = s.hook("codex", 30, SECRET_BASH);
    known(&mut a, 1, false);
    // Codex shows its own dialog for it: still waiting there.
    assert!(!a.take_released().is_empty());
    assert!(a.take_released().is_empty(), "reported once");
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
    assert!(s.files().is_empty());
}

#[test]
fn adoption_releases_what_the_new_broker_does_not_know() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let first = s.hook("codex", 30, SECRET_BASH);
    let one = request_id(&events(&mut a, true)[0]);
    let second = s.hook("codex", 30, SECRET_BASH);
    let two = request_id(&events(&mut a, true)[0]);
    assert!(a.take_released().is_empty());
    a.keep_only(std::slice::from_ref(&two));
    // the released one waits in Codex's own dialog
    assert!(!a.take_released().is_empty());
    assert_eq!(printed(first), "");
    a.decide(&two, ApprovalDecision::AllowOnce, None, None, None);
    assert!(printed(second).contains(r#""behavior":"allow""#));
    // The released one closes `released`, so the broker drops its card.
    assert_eq!(
        drained(&mut a),
        vec![
            closed(&one, ApprovalCloseReason::Released),
            applied(&two, ApplyOutcome::Ok)
        ]
    );
}

#[test]
fn release_approvals_answers_every_waiting_hook_with_no_decision() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let mut ids = Vec::new();
    let hooks: Vec<Child> = (0..2)
        .map(|_| {
            let h = s.hook("codex", 30, SECRET_BASH);
            ids.push(request_id(&events(&mut a, true)[0]));
            h
        })
        .collect();
    a.release_all();
    assert!(!a.take_released().is_empty());
    for h in hooks {
        assert_eq!(printed(h), "");
    }
    ids.sort();
    let closes: Vec<Event> = ids
        .iter()
        .map(|id| closed(id, ApprovalCloseReason::Released))
        .collect();
    assert_eq!(drained(&mut a), closes);
    assert!(s.files().is_empty());
}

#[test]
fn a_killed_hook_is_interrupted_and_a_late_decision_refused() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    let mut hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    unsafe { libc::kill(hook.id() as libc::pid_t, libc::SIGTERM) };
    hook.wait().unwrap();
    assert_eq!(
        events(&mut a, true),
        vec![closed(&id, ApprovalCloseReason::Interrupted)]
    );
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowOnce, None, None, None),
        Some(applied(&id, ApplyOutcome::NotDelivered))
    );
    assert!(s.files().is_empty(), "{:?}", s.files());
}

#[test]
fn a_hook_at_its_timeout_is_timed_out() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex).with_timeout(Duration::from_secs(1));
    let hook = s.hook("codex", 1, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    assert_eq!(printed(hook), "");
    assert_eq!(
        events(&mut a, true),
        vec![closed(&id, ApprovalCloseReason::TimedOut)]
    );
    // no decision: Codex shows its own dialog for it
    assert!(!a.take_released().is_empty());
}

#[test]
fn a_codex_hook_closed_by_a_prompt_or_turn_end_goes_to_codexs_dialog() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    for interrupted in [false, true] {
        let hook = s.hook("codex", 30, SECRET_BASH);
        let id = request_id(&events(&mut a, true)[0]);
        assert!(a.take_released().is_empty());
        let reason = if interrupted {
            ApprovalCloseReason::Interrupted
        } else {
            ApprovalCloseReason::AnsweredTerminal
        };
        assert_eq!(
            a.poll(
                true,
                vec![Evidence::TurnEnded {
                    interrupted,
                    at_ms: Some(now_ms())
                }]
            ),
            vec![closed(&id, reason)]
        );
        assert_eq!(printed(hook), "");
        let calls = a.take_released();
        assert_eq!(calls.len(), 1, "no decision: Codex's dialog");
        assert_eq!(calls[0].tool_name, "Bash");
        assert!(
            calls[0]
                .command
                .as_deref()
                .is_some_and(|c| c.starts_with("curl "))
        );
        drained(&mut a);
    }
}

#[test]
fn claude_answered_in_the_terminal_closes_the_request() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    s.post(
        r#"{"hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":"/x"}}"#,
    );
    assert!(a.poll(true, Vec::new()).is_empty());
    s.post(&post_body());
    assert_eq!(
        events(&mut a, true),
        vec![closed(&id, ApprovalCloseReason::AnsweredTerminal)]
    );
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
    assert!(s.files().is_empty(), "{:?}", s.files());
}

#[test]
fn a_result_matching_two_waiting_requests_closes_neither() {
    // Two identical calls ask (a background agent's and the main one's):
    // a result can't say which ran, so neither card closes on it.
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    let first = s.hook("claude", 30, SECRET_BASH);
    let id1 = request_id(&events(&mut a, true)[0]);
    let second = s.hook("claude", 30, SECRET_BASH);
    let id2 = request_id(&events(&mut a, true)[0]);
    assert_ne!(id1, id2);
    s.post(&post_body());
    for _ in 0..5 {
        assert!(a.poll(true, Vec::new()).is_empty());
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(a.waiting(), 2);
    let ended = a.process_ended();
    assert_eq!(ended.len(), 2, "{ended:?}");
    assert_eq!(printed(first), "");
    assert_eq!(printed(second), "");
}

#[test]
fn a_transcript_rejection_closes_the_matching_request() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    let rejected = |at_ms: i64, input: Value| Evidence::Tool {
        tool_name: "Bash".into(),
        input,
        kind: ToolResultKind::Rejected,
        text: "The user doesn't want to proceed with this tool use.".into(),
        at_ms,
    };
    // Another input, or a rejection long before the request: no match.
    let other = serde_json::json!({"command": "ls"});
    assert!(a.poll(true, vec![rejected(now_ms(), other)]).is_empty());
    assert!(
        a.poll(true, vec![rejected(now_ms() - 60_000, tool_input())])
            .is_empty()
    );
    // The same input in another key order matches.
    let reordered: Value = serde_json::from_str(
        r#"{"description":"d","command":"curl -H 'X-Key: sk-proj-abcdef1234567890ABCDEF' https://api.example\necho two"}"#,
    )
    .unwrap();
    assert_eq!(
        a.poll(true, vec![rejected(now_ms(), reordered)]),
        vec![closed(&id, ApprovalCloseReason::AnsweredTerminal)]
    );
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
}

#[test]
fn turn_ends_and_exits_close_what_waits() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    for (interrupted, reason) in [
        (false, ApprovalCloseReason::AnsweredTerminal),
        (true, ApprovalCloseReason::Interrupted),
    ] {
        let hook = s.hook("claude", 30, SECRET_BASH);
        let id = request_id(&events(&mut a, true)[0]);
        assert_eq!(
            a.poll(
                true,
                vec![Evidence::TurnEnded {
                    interrupted,
                    at_ms: Some(now_ms())
                }]
            ),
            vec![closed(&id, reason)]
        );
        assert_eq!(printed(hook), "");
        assert!(drained(&mut a).is_empty());
    }
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    assert_eq!(
        a.process_ended(),
        vec![closed(&id, ApprovalCloseReason::ProcessEnded)]
    );
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
}

#[test]
fn a_nested_codex_is_released_without_a_report() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let script = approvals::shell_quote(&s.path().join(approvals::SCRIPT_NAME).to_string_lossy());
    // Through one shell that doesn't exec: still this session's agent.
    let direct = s.run(&format!("/bin/sh {script} codex 30; true"), SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    a.release(&id);
    assert_eq!(printed(direct), "");
    drained(&mut a);
    // A codex started inside the session (two levels of shell): released.
    let nested = s.run(
        &format!("/bin/sh -c \"/bin/sh {script} codex 30; true\"; true"),
        SECRET_BASH,
    );
    assert!(!a.take_released().is_empty(), "the session's own");
    known(&mut a, 1, true);
    assert!(
        a.take_released().is_empty(),
        "a nested codex's dialog is not this session's"
    );
    assert_eq!(printed(nested), "");
    assert!(drained(&mut a).is_empty());
}

#[test]
fn a_direct_codex_hook_follows_new_sessions_and_a_wrapped_one_must_match() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    // Started directly by the agent: reported, and its session pinned.
    let first = s.hook("codex", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    a.release(&id);
    assert_eq!(printed(first), "");
    drained(&mut a);
    // `/new` inside Codex: another session, still started directly: reported
    // (R4), and now the pinned one.
    let other = SECRET_BASH.replace(r#""session_id":"s1""#, r#""session_id":"s2""#);
    let second = s.hook("codex", 30, &other);
    let id = request_id(&events(&mut a, true)[0]);
    a.release(&id);
    assert_eq!(printed(second), "");
    drained(&mut a);
    // Through a non-shell child of the agent (a wrapper, or a nested codex
    // started without a shell): only the pinned session is this one's.
    let mut stale = s.fake_request_through_child("wrapped1", SECRET_BASH);
    known(&mut a, 1, true);
    let mut pinned = s.fake_request_through_child("wrapped2", &other);
    let got = events(&mut a, true);
    assert_eq!(request_id(&got[0]), "wrapped2");
    for child in [&mut stale, &mut pinned] {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn oversized_files_are_not_read() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    let big = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {}"}}}}"#,
        "x".repeat(300 * 1024)
    );
    let hook = s.hook("claude", 30, &big);
    known(&mut a, 1, true);
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
    // An oversized post never matches.
    let hook = s.hook("claude", 30, SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    let mut body: Value = serde_json::from_str(&post_body()).unwrap();
    body["padding"] = Value::String("y".repeat(300 * 1024));
    s.post(&body.to_string());
    assert!(a.poll(true, Vec::new()).is_empty());
    a.release(&id);
    assert_eq!(printed(hook), "");
}

#[test]
fn a_request_it_cannot_read_is_released() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude);
    let hook = s.hook("claude", 30, "not json");
    known(&mut a, 1, true);
    assert_eq!(printed(hook), "");
    assert!(drained(&mut a).is_empty());
}

/// The worker polling as fast as it can while the hook claims and reads its
/// decision never takes the decision away from the hook (it once deleted
/// `taken-<id>.json` between the hook's `mv` and its `cat`).
#[test]
fn a_claimed_decision_always_reaches_the_hook_however_fast_the_worker_polls() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    for i in 0..50 {
        let hook = s.hook("codex", 30, SECRET_BASH);
        let id = request_id(&events(&mut a, true)[0]);
        assert_eq!(
            a.decide(&id, ApprovalDecision::AllowOnce, None, None, None),
            None
        );
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = hook.wait_with_output().unwrap();
            let _ = tx.send(String::from_utf8(out.stdout).unwrap());
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let printed = loop {
            a.poll(true, Vec::new());
            if let Ok(out) = rx.try_recv() {
                break out;
            }
            assert!(
                Instant::now() < deadline,
                "iteration {i}: the hook didn't end"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(
            printed.contains(r#""behavior":"allow""#),
            "iteration {i}: the hook printed {printed:?}"
        );
        drained(&mut a);
    }
    assert!(s.files().is_empty(), "{:?}", s.files());
}

/// Within 5 s (here a tenth of the 2 s timeout) of the hook's timeout no
/// decision is handed over: the hook could give up before taking it.
#[test]
fn a_decision_near_the_timeout_is_refused() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Claude).with_timeout(Duration::from_secs(2));
    let mut sleeper = s.fake_request("late", SECRET_BASH);
    let id = request_id(&events(&mut a, true)[0]);
    std::thread::sleep(Duration::from_millis(1850));
    assert_eq!(
        a.decide(&id, ApprovalDecision::AllowOnce, None, None, None),
        Some(applied(&id, ApplyOutcome::NotDelivered))
    );
    assert!(!s.files().iter().any(|f| f.starts_with("dec-")));
    let _ = sleeper.kill();
    let _ = sleeper.wait();
}

/// A hook that ends at its timeout without taking our decision timed out;
/// one killed earlier was interrupted.
#[test]
fn a_hook_ending_with_our_decision_untaken() {
    for (wait_ms, reason) in [
        (1850, ApprovalCloseReason::TimedOut),
        (0, ApprovalCloseReason::Interrupted),
    ] {
        let s = Session::new();
        let mut a = watcher(&s, Agent::Claude).with_timeout(Duration::from_secs(2));
        let mut sleeper = s.fake_request("untaken", SECRET_BASH);
        let id = request_id(&events(&mut a, true)[0]);
        assert_eq!(
            a.decide(&id, ApprovalDecision::AllowOnce, None, None, None),
            None
        );
        std::thread::sleep(Duration::from_millis(wait_ms));
        let _ = sleeper.kill();
        let _ = sleeper.wait();
        assert_eq!(events(&mut a, true), vec![closed(&id, reason)]);
        assert!(s.files().is_empty(), "{:?}", s.files());
    }
}

/// A Codex request without a session id is this session's only when the
/// hook's parent is the agent itself; through a wrapper it is released.
#[test]
fn a_codex_request_without_a_session_id_must_come_from_the_agent_itself() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let unnamed = SECRET_BASH.replace(r#""session_id":"s1","#, "");
    let mut wrapped = s.fake_request_through_child("wrapped", &unnamed);
    known(&mut a, 1, true);
    let _ = wrapped.kill();
    let _ = wrapped.wait();
    assert!(drained(&mut a).is_empty());
    let mut direct = s.fake_request("direct", &unnamed);
    assert_eq!(request_id(&events(&mut a, true)[0]), "direct");
    let _ = direct.kill();
    let _ = direct.wait();
}

/// Evidence read in the same pass as a newer request (the turn's own
/// prompt, a turn end reported before it) never closes it; evidence from
/// after it does. Both agents.
#[test]
fn turn_evidence_older_than_a_request_leaves_it_open() {
    for (agent, name) in [(Agent::Claude, "claude"), (Agent::Codex, "codex")] {
        let s = Session::new();
        let mut a = watcher(&s, agent);
        let mut before = now_ms() - 2000;
        if before % 1000 == 0 {
            before -= 1;
        }
        let hook = s.hook(name, 30, SECRET_BASH);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !s.files().iter().any(|f| f.starts_with("req-")) {
            assert!(Instant::now() < deadline, "no request");
            std::thread::sleep(Duration::from_millis(10));
        }
        // the request and older evidence in one pass: reported, still open
        let out = a.poll(
            true,
            vec![Evidence::TurnEnded {
                interrupted: false,
                at_ms: Some(before),
            }],
        );
        assert_eq!(out.len(), 1, "{name}: {out:?}");
        let id = request_id(&out[0]);
        assert_eq!(a.waiting(), 1, "{name}");
        // evidence from after it closes it
        let out = a.poll(
            true,
            vec![Evidence::TurnEnded {
                interrupted: false,
                at_ms: Some(now_ms() + 1),
            }],
        );
        assert_eq!(
            out,
            vec![closed(&id, ApprovalCloseReason::AnsweredTerminal)],
            "{name}"
        );
        assert_eq!(printed(hook), "", "{name}");
        assert!(drained(&mut a).is_empty());
    }
}

/// A non-shell child of this process (the real binary under a wrapper,
/// this process being the wrapper) with a non-shell child of its own (a
/// codex it started without a shell): their pids.
struct Wrapper {
    real: Child,
    nested: u32,
}

impl Wrapper {
    fn start() -> Self {
        use std::io::BufRead;
        let mut real = Command::new("python3")
            .args([
                "-I",
                "-c",
                "import subprocess, time\np = subprocess.Popen(['sleep', '30'])\nprint(p.pid, flush=True)\ntime.sleep(30)",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(real.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        let nested = line.trim().parse().unwrap();
        Self { real, nested }
    }
}

impl Drop for Wrapper {
    fn drop(&mut self) {
        unsafe { libc::kill(self.nested as libc::pid_t, libc::SIGKILL) };
        let _ = self.real.kill();
        let _ = self.real.wait();
    }
}

/// npm's `codex`: the agent is node, the real binary its child. The first
/// request through it pins its session and makes the real binary the
/// agent: its `/new` re-pins (Direct), and a codex it started without a
/// shell still can't (Wrapped, another session).
#[test]
fn under_a_wrapper_the_real_binary_becomes_the_agent() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let wrapper = Wrapper::start();
    let real = wrapper.real.id();
    let mut hooks = Vec::new();
    let mut request = |id: &str, parent: u32, session: &str| {
        let hook = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(
            s.approvals().join(format!("pid-{id}")),
            format!("{} {parent}\n", hook.id()),
        )
        .unwrap();
        let body = SECRET_BASH.replace(
            r#""session_id":"s1""#,
            &format!(r#""session_id":"{session}""#),
        );
        std::fs::write(s.approvals().join(format!("req-{id}.json")), body).unwrap();
        hooks.push(hook);
    };
    request("first", real, "s1");
    assert_eq!(request_id(&events(&mut a, true)[0]), "first");
    request("afternew", real, "s2");
    assert_eq!(request_id(&events(&mut a, true)[0]), "afternew");
    request("nested", wrapper.nested, "s3");
    known(&mut a, 3, true);
    request("nestedpinned", wrapper.nested, "s2");
    assert_eq!(request_id(&events(&mut a, true)[0]), "nestedpinned");
    for mut hook in hooks {
        let _ = hook.kill();
        let _ = hook.wait();
    }
}

/// A Codex request with a cwd (so it offers an Atem session rule).
fn codex_ask(command: &str, cwd: &str) -> String {
    serde_json::json!({"hook_event_name": "PermissionRequest", "session_id": "s1",
        "cwd": cwd, "tool_name": "Bash",
        "tool_input": {"command": command, "description": "d"}})
    .to_string()
}

/// What the tests' session rules are granted under.
fn grant() -> RuleGrant {
    RuleGrant {
        account_id: "account-a".into(),
        atem_device_id: "device-a".into(),
        host_trust_gen: 3,
    }
}

const ALLOW: &str = r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#;

/// Answers a Codex request `allow_always` with its session rule: the rule
/// id, once the hook took it (the session holds the rule then).
fn always_allow(s: &Session, a: &mut Approvals, stdin: &str) -> String {
    let hook = s.hook("codex", 30, stdin);
    let got = events(a, true);
    let Event::Request { request_id, info } = &got[0] else {
        panic!("{got:?}")
    };
    let [rule] = info.always_rules.as_slice() else {
        panic!("{info:?}")
    };
    assert_eq!(rule.scope, "session");
    let rule_id = rule.rule_id.clone();
    assert_eq!(
        a.decide(
            request_id,
            ApprovalDecision::AllowAlways,
            Some(&rule_id),
            Some(&grant()),
            None
        ),
        None
    );
    assert_eq!(printed(hook), ALLOW, "a plain allow: Codex takes no rule");
    let done = drained(a);
    assert!(
        done.contains(&applied(request_id, ApplyOutcome::Ok)),
        "{done:?}"
    );
    assert!(
        done.iter()
            .any(|e| matches!(e, Event::Rules(r) if r.iter().any(|x| x.rule.rule_id == rule_id))),
        "{done:?}"
    );
    rule_id
}

#[test]
fn a_codex_session_rule_allows_exactly_the_same_command_without_asking() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let ask = codex_ask("npm test", "/p");
    let rule_id = always_allow(&s, &mut a, &ask);
    assert_eq!(a.rules().len(), 1);
    // The same command in the same cwd: allowed by the worker, no approval.
    let hook = s.hook("codex", 30, &ask);
    let got = events(&mut a, true);
    let [
        Event::AutoAllowed {
            rule_id: by,
            tool,
            summary,
            ..
        },
    ] = got.as_slice()
    else {
        panic!("{got:?}")
    };
    assert_eq!(
        (by, tool.as_str(), summary.as_str()),
        (&rule_id, "Bash", "npm test")
    );
    assert_eq!(printed(hook), ALLOW);
    assert!(drained(&mut a).is_empty(), "nothing to report after it");
    // Anything else still asks: more after it, another cwd, one byte more.
    for other in [
        codex_ask("npm test; rm -rf ~", "/p"),
        codex_ask("npm test", "/q"),
        codex_ask("npm test ", "/p"),
        codex_ask("npm  test", "/p"),
    ] {
        let hook = s.hook("codex", 30, &other);
        let id = request_id(&events(&mut a, true)[0]);
        a.release(&id);
        assert_eq!(printed(hook), "");
        drained(&mut a);
    }
    // No broker connected: released as ever (the note couldn't be shown).
    let hook = s.hook("codex", 30, &ask);
    known(&mut a, 1, false);
    assert_eq!(printed(hook), "");
    drained(&mut a);
}

/// After a new broker connected the rules allow nothing until it confirms
/// them: a matching request asks; confirmed, it is allowed again; a rule
/// the broker didn't accept is dropped.
#[test]
fn rules_allow_only_once_the_connected_broker_confirmed_them() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let ask = codex_ask("npm test", "/p");
    let kept = always_allow(&s, &mut a, &ask);
    let dropped = always_allow(&s, &mut a, &codex_ask("make", "/p"));
    a.unconfirm_rules();
    assert!(
        a.rules()
            .iter()
            .all(|r| !r.confirmed && r.granted_under == grant())
    );
    let hook = s.hook("codex", 30, &ask);
    let got = events(&mut a, true);
    assert!(matches!(&got[..], [Event::Request { .. }]), "asks: {got:?}");
    a.release(&request_id(&got[0]));
    assert_eq!(printed(hook), "");
    drained(&mut a);
    a.confirm_rules(std::slice::from_ref(&kept));
    let rules = a.rules();
    assert_eq!(rules.len(), 1, "{rules:?}");
    assert_eq!(rules[0].rule.rule_id, kept);
    assert!(rules[0].confirmed);
    assert!(!rules.iter().any(|r| r.rule.rule_id == dropped));
    let hook = s.hook("codex", 30, &ask);
    let got = events(&mut a, true);
    assert!(
        matches!(&got[..], [Event::AutoAllowed { rule_id, .. }] if *rule_id == kept),
        "{got:?}"
    );
    assert_eq!(printed(hook), ALLOW);
    drained(&mut a);
}

/// An `allow_always` without what the rule is granted under keeps none.
#[test]
fn a_rule_without_a_grant_is_not_kept() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let hook = s.hook("codex", 30, &codex_ask("npm test", "/p"));
    let got = events(&mut a, true);
    let Event::Request { request_id, info } = &got[0] else {
        panic!("{got:?}")
    };
    let rule_id = info.always_rules[0].rule_id.clone();
    assert_eq!(
        a.decide(
            request_id,
            ApprovalDecision::AllowAlways,
            Some(&rule_id),
            None,
            None
        ),
        None
    );
    assert_eq!(printed(hook), ALLOW, "allowed once");
    drained(&mut a);
    assert!(a.rules().is_empty());
}

#[test]
fn a_nested_codex_never_matches_a_session_rule() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let ask = codex_ask("npm test", "/p");
    always_allow(&s, &mut a, &ask);
    let script = approvals::shell_quote(&s.path().join(approvals::SCRIPT_NAME).to_string_lossy());
    // A codex started inside the session (two levels of shell): never
    // allowed by the rule, and not this session's to report either.
    let nested = s.run(
        &format!("/bin/sh -c \"/bin/sh {script} codex 30; true\"; true"),
        &ask,
    );
    known(&mut a, 1, true);
    assert_eq!(printed(nested), "");
    assert!(drained(&mut a).is_empty());
}

#[test]
fn a_revoked_rule_asks_again_and_a_new_process_has_none() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let ask = codex_ask("npm test", "/p");
    let rule_id = always_allow(&s, &mut a, &ask);
    assert!(a.revoke(&rule_id));
    assert!(!a.revoke(&rule_id), "already gone");
    assert!(a.rules().is_empty());
    let hook = s.hook("codex", 30, &ask);
    let id = request_id(&events(&mut a, true)[0]);
    a.release(&id);
    assert_eq!(printed(hook), "");
    drained(&mut a);
    // A respawn is a new agent process (a new worker): no rules.
    always_allow(&s, &mut a, &ask);
    let mut fresh = watcher(&s, Agent::Codex);
    assert!(fresh.rules().is_empty());
    let hook = s.hook("codex", 30, &ask);
    let id = request_id(&events(&mut fresh, true)[0]);
    fresh.release(&id);
    assert_eq!(printed(hook), "");
    drained(&mut fresh);
}

#[test]
fn a_session_holds_at_most_32_rules() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let rule = |n: usize| {
        let v: Value = serde_json::from_str(&codex_ask(&format!("echo {n}"), "/p")).unwrap();
        approvals::request(Agent::Codex, &v)
            .unwrap()
            .session_rule
            .unwrap()
    };
    for n in 0..MAX_SESSION_RULES {
        a.keep_rule(rule(n), grant());
    }
    assert_eq!(a.rules().len(), 32);
    a.keep_rule(rule(99), grant());
    assert_eq!(a.rules().len(), 32, "the 33rd is not kept");
    assert!(!a.rules().iter().any(|r| r.rule.label.contains("echo 99")));
    // Each kept rule was reported (the whole list), the 33rd not.
    let reported = a.poll(true, Vec::new());
    assert_eq!(reported.len(), 32);
    assert!(matches!(reported.last(), Some(Event::Rules(r)) if r.len() == 32));
    // A full session offers no more session rules on its cards.
    let hook = s.hook("codex", 30, &codex_ask("echo 100", "/p"));
    let got = events(&mut a, true);
    let Event::Request { request_id, info } = &got[0] else {
        panic!("{got:?}")
    };
    assert!(info.always_rules.is_empty(), "{info:?}");
    a.release(request_id);
    assert_eq!(printed(hook), "");
    drained(&mut a);
    // Revoking one makes room again.
    let first = a.rules()[0].rule.rule_id.clone();
    assert!(a.revoke(&first));
    a.keep_rule(rule(99), grant());
    assert_eq!(a.rules().len(), 32);
}

#[test]
fn a_codex_nested_through_one_shell_with_another_session_never_matches() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    always_allow(&s, &mut a, &codex_ask("npm test", "/p"));
    // A non-shell process (`find`, standing in for a nested `codex`)
    // started by the agent through one shell runs the hook, for another
    // Codex session with the very same command and cwd. `find -exec` is
    // POSIX: it runs the hook as its child, stdin inherited, and waits
    // (GNU `timeout` did that too, but macOS has none).
    let script = approvals::shell_quote(&s.path().join(approvals::SCRIPT_NAME).to_string_lossy());
    let other = codex_ask("npm test", "/p").replace(r#""session_id":"s1""#, r#""session_id":"s9""#);
    assert!(other.contains(r#""session_id":"s9""#));
    let nested = s.run(
        &format!("find /dev/null -prune -exec /bin/sh {script} codex 30 ';'; true"),
        &other,
    );
    known(&mut a, 1, true);
    assert_eq!(printed(nested), "", "never allowed by the rule");
    assert!(drained(&mut a).is_empty(), "nor reported as this session's");
}

#[test]
fn revoking_withdraws_an_allow_the_hook_has_not_taken() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let ask = codex_ask("npm test", "/p");
    let rule_id = always_allow(&s, &mut a, &ask);
    // A hook that hasn't read its decision yet (it never will).
    let mut sleeper = s.fake_request("slow", &ask);
    let got = events(&mut a, true);
    assert!(matches!(&got[..], [Event::AutoAllowed { .. }]), "{got:?}");
    let dec = s.approvals().join("dec-slow.json");
    assert_eq!(
        std::fs::read_to_string(&dec).unwrap(),
        approvals::allow_output()
    );
    assert!(a.revoke(&rule_id));
    assert_eq!(
        std::fs::read_to_string(&dec).unwrap(),
        "",
        "no decision: Codex's own dialog asks"
    );
    assert!(!a.take_released().is_empty());
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    drained(&mut a);
    // revoke_all does the same for every rule.
    let rule_id = always_allow(&s, &mut a, &codex_ask("make", "/p"));
    let mut sleeper2 = s.fake_request("slow2", &codex_ask("make", "/p"));
    assert!(
        matches!(&events(&mut a, true)[..], [Event::AutoAllowed { rule_id: r, .. }] if *r == rule_id)
    );
    a.revoke_all();
    assert!(a.rules().is_empty());
    assert_eq!(
        std::fs::read_to_string(s.approvals().join("dec-slow2.json")).unwrap(),
        ""
    );
    let _ = sleeper2.kill();
    let _ = sleeper2.wait();
}

#[test]
fn a_rule_the_full_session_cannot_keep_is_reported_before_the_answer_completes() {
    let s = Session::new();
    let mut a = watcher(&s, Agent::Codex);
    let rule = |n: usize| {
        let v: Value = serde_json::from_str(&codex_ask(&format!("echo {n}"), "/p")).unwrap();
        approvals::request(Agent::Codex, &v)
            .unwrap()
            .session_rule
            .unwrap()
    };
    for n in 0..MAX_SESSION_RULES - 1 {
        assert!(a.keep_rule(rule(n), grant()));
    }
    a.poll(true, Vec::new());
    // Offered while there was room…
    let hook = s.hook("codex", 30, &codex_ask("npm test", "/p"));
    let got = events(&mut a, true);
    let Event::Request { request_id, info } = &got[0] else {
        panic!("{got:?}")
    };
    let offered = info.always_rules[0].rule_id.clone();
    // …but full by the time the hook takes the answer.
    assert!(a.keep_rule(rule(99), grant()));
    a.poll(true, Vec::new());
    assert_eq!(
        a.decide(
            request_id,
            ApprovalDecision::AllowAlways,
            Some(&offered),
            Some(&grant()),
            None
        ),
        None
    );
    assert_eq!(printed(hook), ALLOW, "allowed once all the same");
    let done = drained(&mut a);
    assert_eq!(
        done,
        vec![
            Event::RuleNotKept {
                request_id: request_id.clone()
            },
            applied(request_id, ApplyOutcome::Ok)
        ]
    );
    assert!(!a.rules().iter().any(|r| r.rule.rule_id == offered));
}

//! The Codex adapter driven by the spike's fixtures
//! (`designs/fixtures/codex-hooks/`): hook stdin files fired through the
//! real hook script, rollout excerpts written up to an ordinal.

use super::*;
use crate::chat::adapter::{Outcome, Part};
use crate::chat::session::{ChatSession, Origin, Out, State};
use std::fs;
use std::process::{Command, Stdio};

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/designs/fixtures/codex-hooks");
const GEN: &str = "gen-1";

struct Fx {
    root: tempfile::TempDir,
    home: PathBuf,
    a: PathBuf,
    b: PathBuf,
    script: PathBuf,
}

fn fx() -> Fx {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    let day = home.join("sessions/2026/10/17");
    fs::create_dir_all(&day).unwrap();
    let script = root.path().join("approval-hook.sh");
    crate::chat::approvals::install_script(&script).unwrap();
    Fx {
        a: day.join("rollout-2026-10-17T05-32-36-<session-A>.jsonl"),
        b: day.join("rollout-2026-10-17T05-35-51-<session-B>.jsonl"),
        home,
        script,
        root,
    }
}

impl Fx {
    fn adapter(&self) -> CodexAdapter {
        let (a, args) =
            prepare_chat(&self.root.path().join("run"), self.home.clone(), &[]).unwrap();
        assert!(args.is_empty());
        a
    }

    /// The hook fixture `name` with this CODEX_HOME.
    fn hook(&self, name: &str) -> String {
        fs::read_to_string(format!("{FX}/hooks/{name}"))
            .unwrap()
            .replace("/home/user/.codex", &self.home.to_string_lossy())
    }

    /// Runs the real hook script as Codex's event entry does, with the
    /// fixture as its stdin.
    fn fire(&self, a: &CodexAdapter, name: &str) {
        use std::io::Write;
        let body = self.hook(name);
        let v: Value = serde_json::from_str(&body).unwrap();
        let event = v["hook_event_name"].as_str().unwrap();
        let mut child = Command::new("/bin/sh")
            .arg(&self.script)
            .arg("event")
            .arg(event)
            .env(crate::chat::approvals::ENV, a.dir().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success() && out.stdout.is_empty(), "{name}");
    }

    /// Writes an event file directly (seq `n`).
    fn put(&self, a: &CodexAdapter, n: u64, event: &str, body: &str) {
        let p = a
            .dir()
            .unwrap()
            .join("events")
            .join(format!("ev-{n:010}-{event}.json"));
        fs::write(p, body).unwrap();
    }
}

/// `src`'s lines with an ordinal up to `n`, as the rollout `dst`.
fn rollout_upto(dst: &Path, src: &str, n: u64) {
    let text = fs::read_to_string(format!("{FX}/{src}")).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        if v["ordinal"].as_u64().unwrap() <= n {
            out.push_str(line);
            out.push('\n');
        }
    }
    fs::write(dst, out).unwrap();
}

const A: &str = "rollout-session-A.jsonl";
const B: &str = "rollout-session-B-new-and-compact.jsonl";

struct Tick {
    events: Vec<AgentEvent>,
    log: Vec<LogItem>,
    outs: Vec<Out>,
}

/// One worker pass (`runtime/worker.rs` `poll_chat`): events, the log,
/// then turn ends.
fn tick(a: &mut CodexAdapter, chat: &mut ChatSession) -> Tick {
    let events = a.poll_events();
    let log = a.poll_log();
    let mut outs = Vec::new();
    let (ends, others): (Vec<_>, Vec<_>) = events
        .iter()
        .cloned()
        .partition(|e| matches!(e, AgentEvent::TurnEnded));
    for e in others {
        outs.extend(chat.on_event(e, 0, 0));
    }
    for item in &log {
        if !matches!(item, LogItem::Problem { .. }) {
            outs.extend(chat.on_log(item.clone(), 0, 0));
        }
    }
    for e in ends {
        outs.extend(chat.on_event(e, 0, 0));
    }
    Tick { events, log, outs }
}

fn completes(outs: &[Out]) -> Vec<(String, Option<String>, Outcome)> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Complete {
                turn_id,
                request_id,
                outcome,
            } => Some((turn_id.clone(), request_id.clone(), *outcome)),
            _ => None,
        })
        .collect()
}

fn message_ids(outs: &[Out]) -> Vec<String> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Message(m) => Some(m.message_id.clone()),
            _ => None,
        })
        .collect()
}

fn ev_files(a: &CodexAdapter) -> usize {
    fs::read_dir(a.dir().unwrap().join("events"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("ev-"))
        .count()
}

#[test]
fn session_a_then_new_and_compact_through_the_real_hook_script() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);

    // Before the first prompt: no chat, a reason, status unknown.
    let caps = a.capabilities();
    assert!(!caps.chat_v1);
    assert_eq!(caps.reason.as_deref(), Some(FIRST_PROMPT));
    assert_eq!(caps.unavailable, UNAVAILABLE);
    assert!(tick(&mut a, &mut chat).events.is_empty());
    assert_eq!(chat.status().state, State::Unknown);
    assert!(chat.submit("r0", GEN, "hi", 0, false).is_err());

    // Turn 1, typed in the terminal.
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 9);
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.events[..], [
        AgentEvent::SessionStarted { session_id, source, same_log: false, log_path },
        AgentEvent::PromptSubmitted { text },
    ] if session_id == "<session-A>" && source == "startup" && *log_path == f.a
        && text == "Reply with exactly the word: pong"));
    assert!(!t.log.iter().any(|i| matches!(i, LogItem::Backfill(_))));
    assert_eq!(message_ids(&t.outs), ["<id-2>"]);
    assert_eq!(chat.status().state, State::Working);
    assert!(a.capabilities().chat_v1);
    assert_eq!(a.session_id(), Some("<session-A>"));
    assert_eq!(ev_files(&a), 0, "read files are deleted");

    rollout_upto(&f.a, A, 14);
    f.fire(&a, "03-Stop.json");
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty(), "Stop only wakes the reader");
    assert_eq!(message_ids(&t.outs), ["<msg-6>"]);
    assert_eq!(
        completes(&t.outs),
        [("<turn-1>".into(), None, Outcome::Done)]
    );
    assert_eq!(chat.status().state, State::Ready);

    // Turn 2 from chat: accepted on the hook and the rollout's prompt.
    let prompt = "Run the shell command: touch made.txt . Do nothing else.";
    assert_eq!(chat.submit("r1", GEN, prompt, 0, false).unwrap(), prompt);
    f.fire(&a, "04-UserPromptSubmit-approval-turn.json");
    let t = tick(&mut a, &mut chat);
    assert!(!t.outs.iter().any(|o| matches!(o, Out::Accepted { .. })));
    rollout_upto(&f.a, A, 19);
    let t = tick(&mut a, &mut chat);
    assert!(t.outs.contains(&Out::Accepted {
        request_id: "r1".into()
    }));
    assert!(t.outs.iter().any(|o| matches!(o, Out::Message(m)
        if m.origin == Some(Origin::Remote) && m.request_id.as_deref() == Some("r1"))));

    // Its approval: waiting until it closes.
    f.fire(&a, "05-PreToolUse-before-approval.json");
    f.fire(&a, "06-PermissionRequest.json");
    let t = tick(&mut a, &mut chat);
    assert_eq!(
        t.events,
        [AgentEvent::ToolStarted],
        "no PermissionRequest event"
    );
    a.approval_opened();
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    f.fire(&a, "07-PostToolUse-after-approval.json");
    a.approval_closed();
    let t = tick(&mut a, &mut chat);
    assert_eq!(
        t.events,
        [AgentEvent::ToolFinished, AgentEvent::ToolFinished]
    );
    assert_eq!(chat.status().state, State::Working);
    rollout_upto(&f.a, A, 29);
    f.fire(&a, "08-Stop-empty-last-message.json");
    let t = tick(&mut a, &mut chat);
    assert_eq!(
        message_ids(&t.outs),
        ["<exec-1>"],
        "the empty answer is skipped"
    );
    assert_eq!(
        completes(&t.outs),
        [("<turn-2>".into(), Some("r1".into()), Outcome::Done)]
    );
    assert_eq!(chat.status().state, State::Ready);

    // Turn 3 in one pass: commentary, a failed sandboxed try, the approved
    // retry, the poem.
    for h in [
        "09-UserPromptSubmit.json",
        "10-PreToolUse-sandboxed.json",
        "11-PostToolUse-sandbox-failed.json",
        "12-PreToolUse-escalated.json",
        "13-PermissionRequest.json",
        "14-PostToolUse.json",
        "15-Stop.json",
    ] {
        f.fire(&a, h);
    }
    rollout_upto(&f.a, A, 56);
    let t = tick(&mut a, &mut chat);
    assert_eq!(
        message_ids(&t.outs),
        ["<id-6>", "<msg-10>", "<exec-3>", "<msg-11>"]
    );
    assert_eq!(
        completes(&t.outs),
        [("<turn-3>".into(), None, Outcome::Done)]
    );
    assert_eq!(chat.status().state, State::Ready);

    // Turn 4: Esc while streaming → interrupted, no partial text.
    f.fire(&a, "16-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 61);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Working);
    f.fire(&a, "17-Interrupt-esc-while-streaming.json");
    rollout_upto(&f.a, A, 64);
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty());
    assert!(message_ids(&t.outs).is_empty());
    assert_eq!(
        completes(&t.outs),
        [("<turn-4>".into(), None, Outcome::Interrupted)]
    );
    assert_eq!(chat.status().state, State::Ready);

    // Turn 5: Esc at the approval dialog; the approval's close comes late.
    f.fire(&a, "18-UserPromptSubmit-multiline-paste.json");
    f.fire(&a, "19-PreToolUse.json");
    f.fire(&a, "20-PermissionRequest.json");
    rollout_upto(&f.a, A, 69);
    tick(&mut a, &mut chat);
    a.approval_opened();
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    f.fire(&a, "21-Interrupt-esc-at-approval-dialog.json");
    rollout_upto(&f.a, A, 75);
    let t = tick(&mut a, &mut chat);
    assert_eq!(
        completes(&t.outs),
        [("<turn-5>".into(), None, Outcome::Interrupted)]
    );
    assert_eq!(chat.status().state, State::Ready);
    a.approval_closed();
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty(), "the turn's end forgot it");
    assert_eq!(chat.status().state, State::Ready);

    // /new: session B, its rollout live from the first line.
    f.fire(&a, "22-SessionStart-after-new.json");
    f.fire(&a, "23-UserPromptSubmit.json");
    rollout_upto(&f.b, B, 9);
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty(), "held one poll for the old rollout");
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.events[..], [
        AgentEvent::SessionStarted { session_id, source, same_log: false, .. },
        AgentEvent::PromptSubmitted { .. },
    ] if session_id == "<session-B>" && source == "startup"));
    assert!(!t.log.iter().any(|i| matches!(i, LogItem::Backfill(_))));
    assert_eq!(message_ids(&t.outs), ["<id-15>"]);
    assert_eq!(chat.status().state, State::Working);
    assert_eq!(a.session_id(), Some("<session-B>"));
    rollout_upto(&f.b, B, 14);
    f.fire(&a, "24-Stop.json");
    let t = tick(&mut a, &mut chat);
    assert_eq!(
        completes(&t.outs),
        [("<turn-7>".into(), None, Outcome::Done)]
    );

    // /compact: working, no message, then ready; no request completes.
    f.fire(&a, "25-PreCompact-manual.json");
    rollout_upto(&f.b, B, 17);
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty());
    assert!(message_ids(&t.outs).is_empty());
    assert_eq!(chat.status().state, State::Working);
    f.fire(&a, "26-PostCompact-manual.json");
    rollout_upto(&f.b, B, 26);
    let t = tick(&mut a, &mut chat);
    assert!(message_ids(&t.outs).is_empty());
    assert_eq!(
        completes(&t.outs),
        [("<turn-8>".into(), None, Outcome::Done)]
    );
    assert_eq!(chat.status().state, State::Ready);

    // Quit: both sessions' SessionEnd, nothing for chat.
    f.fire(&a, "27-SessionEnd-old-session-at-exit.json");
    f.fire(&a, "28-SessionEnd-current-session-at-exit.json");
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty() && t.log.is_empty() && t.outs.is_empty());
    assert!(a.capabilities().chat_v1);
    assert_eq!(ev_files(&a), 0);
}

#[test]
fn resume_reads_the_conversation_as_history_then_goes_on_live() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    // `codex resume <session-A>`: the rollout so far, then its SessionStart
    // at the next prompt.
    rollout_upto(&f.a, A, 77);
    f.fire(&a, "29-SessionStart-resume.json");
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [AgentEvent::SessionStarted { source, same_log: false, .. }]
        if source == "resume")
    );
    assert!(!t.log.is_empty());
    assert!(
        t.log.iter().all(|i| matches!(i, LogItem::Backfill(_))),
        "{:?}",
        t.log
    );
    assert!(message_ids(&t.outs).is_empty() && completes(&t.outs).is_empty());
    assert_eq!(chat.status().state, State::Ready);
    let history = chat.history(None, 100, 1 << 20);
    assert_eq!(
        history.len(),
        10,
        "5 prompts and 5 non-empty answers or tools"
    );

    f.fire(&a, "30-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 81);
    let t = tick(&mut a, &mut chat);
    assert_eq!(message_ids(&t.outs), ["<id-12>"]);
    rollout_upto(&f.a, A, 86);
    f.fire(&a, "31-Stop.json");
    f.fire(&a, "32-Stop-async-entry.json");
    let t = tick(&mut a, &mut chat);
    assert_eq!(message_ids(&t.outs), ["<msg-17>"]);
    assert_eq!(
        completes(&t.outs),
        [("<turn-6>".into(), None, Outcome::Done)]
    );
    f.fire(&a, "33-SessionEnd.json");
    assert!(tick(&mut a, &mut chat).outs.is_empty());
    assert_eq!(chat.status().state, State::Ready);
}

#[test]
fn a_turn_already_running_at_the_resume_stays_live() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    // The new turn's start is written before the hooks are read.
    rollout_upto(&f.a, A, 81);
    f.fire(&a, "29-SessionStart-resume.json");
    f.fire(&a, "30-UserPromptSubmit.json");
    let t = tick(&mut a, &mut chat);
    let live: Vec<&LogItem> = t
        .log
        .iter()
        .filter(|i| !matches!(i, LogItem::Backfill(_)))
        .collect();
    assert!(
        matches!(&live[..], [
        LogItem::TurnStarted { turn_id },
        LogItem::UserMessage { id, .. },
    ] if turn_id == "<turn-6>" && id == "<id-12>"),
        "{live:?}"
    );
    assert_eq!(chat.status().state, State::Working);
    assert_eq!(message_ids(&t.outs), ["<id-12>"]);
}

#[test]
fn a_missed_session_start_is_made_up_from_the_first_hook() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 9);
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.events[..], [
        AgentEvent::SessionStarted { session_id, source, same_log: false, .. },
        AgentEvent::PromptSubmitted { .. },
    ] if session_id == "<session-A>" && source.is_empty()));
    assert_eq!(message_ids(&t.outs), ["<id-2>"], "the running turn is live");
    assert_eq!(chat.status().state, State::Working);
    assert!(a.capabilities().chat_v1);
}

#[test]
fn switching_reads_the_old_rollout_to_its_end_first() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 9);
    tick(&mut a, &mut chat);
    // turn 1's answer and end land in the same pass as the /new
    rollout_upto(&f.a, A, 14);
    f.fire(&a, "22-SessionStart-after-new.json");
    rollout_upto(&f.b, B, 9);
    // the end is read before the start of B is even considered
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty());
    assert_eq!(message_ids(&t.outs), ["<msg-6>"]);
    assert_eq!(completes(&t.outs).len(), 1);
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [AgentEvent::SessionStarted { session_id, .. }]
        if session_id == "<session-B>")
    );
    assert_eq!(message_ids(&t.outs), ["<id-15>"]);
}

#[test]
fn another_sessions_hooks_never_count() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 9);
    tick(&mut a, &mut chat);
    // a nested codex's events while turn 1 runs: its prompt is ignored, its
    // start too (with a notice)
    f.fire(&a, "23-UserPromptSubmit.json");
    f.fire(&a, "22-SessionStart-after-new.json");
    let t = tick(&mut a, &mut chat);
    assert!(
        t.events.is_empty() && t.log.is_empty(),
        "held: the turn may just have ended"
    );
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty(), "{:?}", t.events);
    assert!(matches!(
        &t.log[..],
        [LogItem::Problem { fatal: false, .. }]
    ));
    assert_eq!(a.session_id(), Some("<session-A>"));
    // once the turn ended, a start of another session re-pins (/new)
    rollout_upto(&f.a, A, 14);
    tick(&mut a, &mut chat);
    f.fire(&a, "22-SessionStart-after-new.json");
    tick(&mut a, &mut chat);
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.events[..], [AgentEvent::SessionStarted { .. }]));
    assert_eq!(a.session_id(), Some("<session-B>"));
    // the old session's hooks no longer count
    f.fire(&a, "02-UserPromptSubmit.json");
    assert!(tick(&mut a, &mut chat).events.is_empty());
}

#[test]
fn same_rollout_start_continues_the_conversation() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "01-SessionStart-startup.json");
    rollout_upto(&f.a, A, 14);
    tick(&mut a, &mut chat);
    f.fire(&a, "29-SessionStart-resume.json");
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [AgentEvent::SessionStarted { same_log: true, source, .. }]
        if source == "resume")
    );
    assert!(t.log.is_empty(), "no replay");
}

#[test]
fn a_rollout_that_is_not_the_sessions_own_is_ignored() {
    let f = fx();
    let home = f.home.to_string_lossy().into_owned();
    let day = format!("{home}/sessions/2026/10/17");
    for (i, path) in [
        "/tmp/elsewhere/rollout-2026-10-17T05-32-36-<session-A>.jsonl".to_string(),
        format!("{day}/rollout-2026-10-17T05-32-36-<session-B>.jsonl"),
        format!("{day}/notes-<session-A>.jsonl"),
        format!("{day}/rollout-2026-10-17T05-32-36-<session-A>.json"),
        format!("{day}/../../../../../escape/rollout-x-<session-A>.jsonl"),
        "sessions/rollout-x-<session-A>.jsonl".to_string(),
        format!("{home}/rollout-x-<session-A>.jsonl"),
    ]
    .iter()
    .enumerate()
    {
        let mut a = f.adapter();
        let body = f.hook("01-SessionStart-startup.json").replace(
            &format!("{day}/rollout-2026-10-17T05-32-36-<session-A>.jsonl"),
            path,
        );
        f.put(&a, 1, "SessionStart", &body);
        assert!(a.poll_events().is_empty(), "{i}: {path}");
        assert!(
            matches!(&a.poll_log()[..], [LogItem::Problem { fatal: false, .. }]),
            "{i}"
        );
        assert_eq!(
            a.capabilities().reason.as_deref(),
            Some(FIRST_PROMPT),
            "{i}"
        );
        assert_eq!(a.session_id(), None);
    }
}

#[test]
fn rollout_paths() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    let ok = |p: &Path, id: &str| rollout_path_ok(&home, id, p);
    let day = home.join("sessions/2026/10/17");
    assert!(ok(
        &day.join("rollout-2026-10-17T05-32-36-abc.jsonl"),
        "abc"
    ));
    assert!(!ok(&day.join("rollout-abc.jsonl"), "abc"), "no time part");
    assert!(!ok(&day.join("rollout--abc.jsonl"), "abc"));
    assert!(!ok(&day.join("rollout-t-abc.jsonl"), ""));
    assert!(!ok(&day.join("rollout-t-.jsonl"), ".jsonl"));
    assert!(!ok(&home.join("sessions"), "abc"));
    // a symlinked CODEX_HOME: the rollout as Codex names it, resolved
    let real = root.path().join("real");
    fs::create_dir_all(real.join("sessions/2026")).unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(rollout_path_ok(
        &link,
        "abc",
        &real.join("sessions/2026/rollout-t-abc.jsonl")
    ));
    assert!(rollout_path_ok(
        &real,
        "abc",
        &link.join("sessions/2026/rollout-t-abc.jsonl")
    ));
    assert!(!rollout_path_ok(
        &link,
        "abc",
        &real.join("other/rollout-t-abc.jsonl")
    ));
}

#[test]
fn a_format_change_withdraws_chat() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "01-SessionStart-startup.json");
    rollout_upto(&f.a, A, 9);
    tick(&mut a, &mut chat);
    assert!(a.capabilities().chat_v1);
    let text = fs::read_to_string(&f.a).unwrap();
    let line = fs::read_to_string(format!("{FX}/{A}"))
        .unwrap()
        .lines()
        .find(|l| l.contains("\"ordinal\": 10,"))
        .unwrap()
        .replace("\"id\": \"<msg-6>\"", "\"msg_id\": \"<msg-6>\"");
    fs::write(&f.a, text + &line + "\n").unwrap();
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.log[..], [LogItem::Problem { fatal: true, .. }]));
    let caps = a.capabilities();
    assert!(!caps.chat_v1);
    assert_eq!(
        caps.reason.as_deref(),
        Some("rollout AgentMessage has no id")
    );
    assert_eq!(caps.unavailable, UNAVAILABLE);
}

#[test]
fn approvals_are_counted() {
    let mut a = CodexAdapter::new(PathBuf::from("/nonexistent"));
    a.approval_closed();
    assert!(a.poll_events().is_empty(), "nothing open");
    a.approval_opened();
    a.approval_opened();
    assert_eq!(
        a.poll_events(),
        [AgentEvent::WaitingForPermission {
            detail: APPROVAL_DETAIL.into()
        }]
    );
    a.approval_closed();
    assert!(a.poll_events().is_empty(), "one still open");
    a.approval_closed();
    assert_eq!(a.poll_events(), [AgentEvent::ToolFinished]);
    a.approval_closed();
    assert!(a.poll_events().is_empty());
}

#[test]
fn events_are_read_by_seq_and_nothing_else_is_touched() {
    let f = fx();
    let mut a = f.adapter();
    let dir = a.dir().unwrap().join("events");
    let ev = |name: &str| format!(r#"{{"hook_event_name":"{name}"}}"#);
    // numeric seq order, then name for a repeated seq
    fs::write(dir.join("ev-0000000010-Stop.json"), ev("Stop")).unwrap();
    fs::write(dir.join("ev-9-PreToolUse.json"), ev("PreToolUse")).unwrap();
    fs::write(
        dir.join("ev-0000000009-PostToolUse.json"),
        ev("PostToolUse"),
    )
    .unwrap();
    fs::write(dir.join("ev-0000000011-Bad.json"), "not json").unwrap();
    fs::write(
        dir.join("ev-0000000012-Big.json"),
        "x".repeat(MAX_EVENT as usize + 1),
    )
    .unwrap();
    // not events: left alone
    for name in [
        "seq",
        "seq.123",
        "seq.lock",
        "tmp.young",
        "ev-x-Stop.json",
        "ev-1-Stop.json.tmp",
        "ev-1-St0p.json",
        "ev.1.json",
    ] {
        fs::write(dir.join(name), ev("Stop")).unwrap();
    }
    let old = dir.join("tmp.old");
    fs::write(&old, "{").unwrap();
    fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(120))
        .unwrap();
    let mut r = EventReader::new(a.dir().unwrap().to_path_buf());
    let names: Vec<String> = r
        .poll()
        .iter()
        .map(|v| v["hook_event_name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["PostToolUse", "PreToolUse", "Stop"]);
    let mut left: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        [
            "ev-1-St0p.json",
            "ev-1-Stop.json.tmp",
            "ev-x-Stop.json",
            "ev.1.json",
            "seq",
            "seq.123",
            "seq.lock",
            "tmp.young"
        ]
    );
    // the adapter ignores hooks without a session (all of these)
    assert!(a.poll_events().is_empty());
}

#[test]
fn unreadable_event_files_stay_until_stale() {
    use std::os::unix::fs::PermissionsExt;
    let f = fx();
    let a = f.adapter();
    let dir = a.dir().unwrap().join("events");
    let young = dir.join("ev-0000000001-Stop.json");
    let old = dir.join("ev-0000000002-Stop.json");
    for (p, age) in [(&young, 1), (&old, 120)] {
        fs::write(p, "{}").unwrap();
        fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(age))
            .unwrap();
        // a mode change keeps the mtime
        fs::set_permissions(p, fs::Permissions::from_mode(0o000)).unwrap();
    }
    if fs::read_to_string(&young).is_ok() {
        return; // running as root: cannot make a file unreadable
    }
    let mut r = EventReader::new(a.dir().unwrap().to_path_buf());
    assert!(r.poll().is_empty());
    assert!(young.exists());
    assert!(!old.exists());
}

#[test]
fn every_fixture_hook_parses() {
    let mut n = 0;
    for e in fs::read_dir(format!("{FX}/hooks")).unwrap() {
        let p = e.unwrap().path();
        let v: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        let hook = Hook::parse(&v).unwrap_or_else(|| panic!("{p:?}"));
        assert!(hook.session_id.starts_with("<session-"), "{p:?}");
        assert_eq!(hook.prompt.is_some(), hook.event == "UserPromptSubmit");
        assert_eq!(!hook.source.is_empty(), hook.event == "SessionStart");
        n += 1;
    }
    assert_eq!(n, 33);
    let v: Value = serde_json::from_str(r#"{"hook_event_name":"Stop","session_id":"s"}"#).unwrap();
    assert_eq!(Hook::parse(&v), None, "no transcript_path");
}

#[test]
fn prepare_refuses_foreign_dirs_and_drop_removes_only_the_session_dir() {
    let root = tempfile::tempdir().unwrap();
    let plain = root.path().join("other");
    fs::create_dir_all(plain.join("events")).unwrap();
    let mut a = CodexAdapter::new(root.path().join("codex"));
    assert!(a.prepare_launch(&[], &plain).is_err());
    let noevents = root.path().join("chat-x");
    fs::create_dir_all(&noevents).unwrap();
    assert!(a.prepare_launch(&[], &noevents).is_err());
    assert!(a.dir().is_none());
    drop(a);
    assert!(plain.exists() && noevents.exists());

    let (a, args) = prepare_chat(
        &root.path().join("run"),
        root.path().join("codex"),
        &["resume".into(), "--last".into()],
    )
    .unwrap();
    assert!(args.is_empty());
    let dir = a.dir().unwrap().to_path_buf();
    assert!(dir.join("events").is_dir() && dir.join("approvals").is_dir());
    assert_eq!(
        a.capabilities(),
        Capabilities {
            chat_v1: false,
            reason: Some(FIRST_PROMPT.into()),
            unavailable: UNAVAILABLE,
        }
    );
    drop(a);
    assert!(!dir.exists());
    assert!(root.path().join("run").exists());
}

#[test]
fn compaction_turn_parts_never_reach_chat() {
    // the summary is a response_item assistant message: never a Part
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "22-SessionStart-after-new.json");
    rollout_upto(&f.b, B, 26);
    let t = tick(&mut a, &mut chat);
    let texts: Vec<&str> = t
        .log
        .iter()
        .filter_map(|i| match i {
            LogItem::AssistantPart {
                part: Part::Text { markdown, .. },
                ..
            } => Some(markdown.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["ok"]);
}

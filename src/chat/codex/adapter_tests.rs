//! The Codex adapter driven by the spike's fixtures
//! (`designs/fixtures/codex-hooks/`): hook stdin files fired through the
//! real hook script, rollout excerpts written up to an ordinal.

use super::*;
use crate::chat::adapter::{Outcome, Part};
use crate::chat::hook_events::MAX_EVENT;
use crate::chat::session::{ChatSession, Origin, Out, State};
use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

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
    fn fresh(&self) -> CodexAdapter {
        let (mut a, args) =
            prepare_chat(&self.root.path().join("run"), self.home.clone(), &[]).unwrap();
        assert!(args.is_empty());
        // The hooks `fire` runs are this process's children (as Codex's are
        // the agent's).
        a.set_agent_pid(Some(std::process::id()));
        a
    }

    /// A fresh adapter whose first `NotReady` was taken.
    fn adapter(&self) -> CodexAdapter {
        let mut a = self.fresh();
        assert_eq!(
            a.poll_events(),
            [AgentEvent::NotReady {
                detail: FIRST_PROMPT.into()
            }]
        );
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
        let body = self.hook(name);
        self.fire_body(a, &body, name);
    }

    /// Runs the real hook script as Codex's event entry does, with `body`
    /// as its stdin (its event from `hook_event_name`).
    fn fire_body(&self, a: &CodexAdapter, body: &str, name: &str) {
        use std::io::Write;
        let v: Value = serde_json::from_str(body).unwrap();
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
        assert!(
            out.status.success() && out.stdout.is_empty(),
            "{name}: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Writes an event file directly (seq `n`), as a hook this process
    /// started.
    fn put(&self, a: &CodexAdapter, n: u64, event: &str, body: &str) {
        let me = std::process::id();
        self.put_from(a, n, event, body, me);
    }

    /// The events counter now (`events/seq`): what Codex's PermissionRequest
    /// hook records as its request's `evseq`.
    fn evseq(&self, a: &CodexAdapter) -> u64 {
        fs::read_to_string(a.dir().unwrap().join("events").join("seq"))
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Writes an event file whose hook's parent was `parent`.
    fn put_from(&self, a: &CodexAdapter, n: u64, event: &str, body: &str, parent: u32) {
        let p = a
            .dir()
            .unwrap()
            .join("events")
            .join(format!("ev-{n:010}-{event}.json"));
        fs::write(p, format!("{parent} {parent}\n{body}")).unwrap();
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

/// A hook stdin as read from an event file.
fn raw(json: Value) -> RawEvent {
    RawEvent {
        pid: 2,
        parent: 1,
        at_ms: 0,
        seq: 1,
        json,
    }
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
        .partition(|e| matches!(e, AgentEvent::TurnEnded { at_ms: None }));
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
    let mut a = f.fresh();
    let mut chat = ChatSession::new(GEN.into(), 0);

    // Before the first prompt: chat opens, status unknown with the hint,
    // a submit is refused with it.
    let caps = a.capabilities();
    assert!(caps.chat_v1);
    assert_eq!(caps.reason, None);
    assert_eq!(caps.unavailable, UNAVAILABLE);
    let t = tick(&mut a, &mut chat);
    assert_eq!(
        t.events,
        [AgentEvent::NotReady {
            detail: FIRST_PROMPT.into()
        }]
    );
    assert_eq!(chat.status().state, State::Unknown);
    assert_eq!(chat.status().detail.as_deref(), Some(FIRST_PROMPT));
    assert_eq!(
        chat.submit("r0", GEN, "hi", 0, false),
        Err(vec![Out::Error {
            text: FIRST_PROMPT.into(),
            request_id: Some("r0".into())
        }])
    );
    assert!(tick(&mut a, &mut chat).events.is_empty(), "said once");

    // Turn 1, typed in the terminal.
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 9);
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.events[..], [
        AgentEvent::SessionStarted { session_id, source, same_log: false, log_path },
        AgentEvent::PromptSubmitted { text, turn_id: Some(turn), at_ms: Some(_) },
    ] if session_id == "<session-A>" && source == "startup" && *log_path == f.a
        && text == "Reply with exactly the word: pong" && turn == "<turn-1>"));
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
    a.set_open_approvals(1);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    f.fire(&a, "07-PostToolUse-after-approval.json");
    a.set_open_approvals(0);
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
    a.set_open_approvals(1);
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
    // the worker's late close: no longer waiting, and the chat stays ready
    a.set_open_approvals(0);
    let t = tick(&mut a, &mut chat);
    assert_eq!(t.events, [AgentEvent::ToolFinished]);
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

    // /compact: working, no message, then ready; no Complete (no prompt).
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
    assert!(completes(&t.outs).is_empty());
    assert!(t.log.iter().any(|i| matches!(i, LogItem::TurnEnded {
        turn_id, outcome: Outcome::Done, ..
    } if turn_id == "<turn-8>")));
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
    // start waits (with a notice)
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
    // once the turn ended, the waiting start re-pins (/new)
    rollout_upto(&f.a, A, 14);
    tick(&mut a, &mut chat);
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty(), "held one poll");
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
        assert_eq!(a.capabilities().reason, None, "{i}");
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
    a.announced = true;
    a.set_open_approvals(0);
    assert!(a.poll_events().is_empty(), "nothing open");
    a.set_open_approvals(2);
    assert_eq!(
        a.poll_events(),
        [AgentEvent::WaitingForPermission {
            detail: APPROVAL_DETAIL.into(),
            outlasts_turn: true,
        }]
    );
    a.set_open_approvals(1);
    assert!(a.poll_events().is_empty(), "one still open");
    a.set_open_approvals(0);
    assert_eq!(a.poll_events(), [AgentEvent::ToolFinished]);
    a.set_open_approvals(0);
    assert!(a.poll_events().is_empty());
}

#[test]
fn events_are_read_by_seq_and_nothing_else_is_touched() {
    let f = fx();
    let mut a = f.adapter();
    let dir = a.dir().unwrap().join("events");
    let ev = |name: &str| format!("1 1\n{{\"hook_event_name\":\"{name}\"}}");
    // numeric seq order, then name for a repeated seq
    fs::write(dir.join("ev-0000000010-Stop.json"), ev("Stop")).unwrap();
    fs::write(dir.join("ev-9-PreToolUse.json"), ev("PreToolUse")).unwrap();
    fs::write(
        dir.join("ev-0000000009-PostToolUse.json"),
        ev("PostToolUse"),
    )
    .unwrap();
    fs::write(dir.join("ev-0000000011-Bad.json"), "1 1\nnot json").unwrap();
    fs::write(
        dir.join("ev-0000000011-NoPids.json"),
        r#"{"hook_event_name":"Stop"}"#,
    )
    .unwrap();
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
    let names: Vec<Option<String>> = r
        .poll()
        .iter()
        .map(|v| {
            v.as_ref()
                .map(|v| v.json["hook_event_name"].as_str().unwrap().to_string())
        })
        .collect();
    let some = |s: &str| Some(s.to_string());
    // the bad one, the one without the hook's pids and the oversized one
    // come as None (deleted all the same)
    assert_eq!(
        names,
        [
            some("PostToolUse"),
            some("PreToolUse"),
            some("Stop"),
            None,
            None,
            None
        ]
    );
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
        let hook = Hook::from_raw(&raw(v)).unwrap_or_else(|| panic!("{p:?}"));
        assert!(hook.session_id.starts_with("<session-"), "{p:?}");
        assert_eq!(hook.prompt.is_some(), hook.event == "UserPromptSubmit");
        assert_eq!(!hook.source.is_empty(), hook.event == "SessionStart");
        n += 1;
    }
    assert_eq!(n, 33);
    let v: Value = serde_json::from_str(r#"{"hook_event_name":"Stop","session_id":"s"}"#).unwrap();
    assert_eq!(Hook::from_raw(&raw(v)), None, "no transcript_path");
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
            chat_v1: true,
            reason: None,
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

#[test]
fn an_unreadable_event_gives_a_notice() {
    let f = fx();
    let mut a = f.adapter();
    f.put(&a, 1, "Stop", "not json");
    assert!(a.poll_events().is_empty());
    assert!(matches!(
        &a.poll_log()[..],
        [LogItem::Problem { fatal: false, .. }]
    ));
    assert_eq!(ev_files(&a), 0);
}

#[test]
fn a_pretooluse_in_the_same_pass_as_an_approval_keeps_it_waiting() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "04-UserPromptSubmit-approval-turn.json");
    rollout_upto(&f.a, A, 19);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Working);
    // the hook's PreToolUse and the worker's approval in one pass
    f.fire(&a, "05-PreToolUse-before-approval.json");
    a.set_open_approvals(1);
    let t = tick(&mut a, &mut chat);
    // (the PreToolUse came before the approval: dropped; and the wait is
    // returned after the pass's hook events anyway)
    assert!(
        matches!(&t.events[..], [AgentEvent::WaitingForPermission { .. }]),
        "{:?}",
        t.events
    );
    assert_eq!(chat.status().state, State::Waiting);
    // a PreToolUse read while it waits is dropped
    f.fire(&a, "05-PreToolUse-before-approval.json");
    assert!(tick(&mut a, &mut chat).events.is_empty());
    assert_eq!(chat.status().state, State::Waiting);
    // the worker's reports follow the pass's hooks: a PostToolUse read with
    // a new approval leaves it waiting (the PostToolUse, read while one
    // waits, finishes nothing of its own)
    a.set_open_approvals(0);
    a.set_open_approvals(1);
    f.fire(&a, "07-PostToolUse-after-approval.json");
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(
            &t.events[..],
            [
                AgentEvent::ToolFinished,
                AgentEvent::WaitingForPermission { .. },
            ]
        ),
        "{:?}",
        t.events
    );
    assert_eq!(chat.status().state, State::Waiting);
}

#[test]
fn only_the_workers_close_ends_the_wait() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "09-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 35);
    tick(&mut a, &mut chat);
    f.fire(&a, "12-PreToolUse-escalated.json");
    a.set_open_approvals(1);
    rollout_upto(&f.a, A, 43);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    // the turn's next item (the command ran) is no close: still waiting
    rollout_upto(&f.a, A, 45);
    let t = tick(&mut a, &mut chat);
    assert_eq!(message_ids(&t.outs), ["<exec-3>"]);
    assert!(tick(&mut a, &mut chat).events.is_empty());
    assert_eq!(chat.status().state, State::Waiting);
    // the worker's close is
    a.set_open_approvals(0);
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert_eq!(chat.status().state, State::Working);
}

#[test]
fn a_new_session_waiting_for_a_turn_end_follows_its_stop_hook() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 9);
    tick(&mut a, &mut chat);
    // /new while the turn still counts as running (its rollout end never
    // came): held, then waiting
    f.fire(&a, "22-SessionStart-after-new.json");
    tick(&mut a, &mut chat);
    let t = tick(&mut a, &mut chat);
    assert!(matches!(
        &t.log[..],
        [LogItem::Problem { fatal: false, .. }]
    ));
    assert_eq!(a.session_id(), Some("<session-A>"));
    // the turn's Stop hook ends it: the start goes ahead (after its hold)
    f.fire(&a, "03-Stop.json");
    f.fire(&a, "23-UserPromptSubmit.json");
    rollout_upto(&f.b, B, 9);
    assert!(tick(&mut a, &mut chat).events.is_empty());
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [
        AgentEvent::SessionStarted { session_id, .. },
        AgentEvent::PromptSubmitted { turn_id: Some(turn), .. },
    ] if session_id == "<session-B>" && turn == "<turn-7>"),
        "{:?}",
        t.events
    );
    assert_eq!(a.session_id(), Some("<session-B>"));
    assert_eq!(message_ids(&t.outs), ["<id-15>"]);
}

#[test]
fn hook_prompts_equal_the_rollouts() {
    // what acceptance compares: each UserPromptSubmit's prompt and turn
    // against the rollout's UserMessage of that turn
    let mut prompts = Vec::new();
    for e in fs::read_dir(format!("{FX}/hooks")).unwrap() {
        let v: Value =
            serde_json::from_str(&fs::read_to_string(e.unwrap().path()).unwrap()).unwrap();
        if let Some(h) = Hook::from_raw(&raw(v)).filter(|h| h.prompt.is_some()) {
            prompts.push((h.turn_id.unwrap(), h.prompt.unwrap()));
        }
    }
    let mut users = Vec::new();
    for src in [A, B] {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.jsonl");
        rollout_upto(&p, src, u64::MAX);
        for item in super::super::rollout::RolloutReader::new(p).poll() {
            if let LogItem::UserMessage { turn_id, text, .. } = item {
                users.push((turn_id, text));
            }
        }
    }
    prompts.sort();
    users.sort();
    assert_eq!(prompts.len(), 7);
    assert_eq!(prompts, users);
}

#[test]
fn a_symlinked_rollout_is_never_read() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    // the day directory is a symlink out of the sessions directory
    let outside = f.root.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let day = f.home.join("sessions/2026/10/17");
    fs::remove_dir_all(&day).unwrap();
    std::os::unix::fs::symlink(&outside, &day).unwrap();
    f.fire(&a, "01-SessionStart-startup.json");
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty());
    assert!(matches!(
        &t.log[..],
        [LogItem::Problem { fatal: false, .. }]
    ));
    // the rollout file itself a symlink: accepted as named, never followed
    fs::remove_file(&day).unwrap();
    fs::create_dir_all(&day).unwrap();
    let real = outside.join("real.jsonl");
    rollout_upto(&real, A, 14);
    std::os::unix::fs::symlink(&real, &f.a).unwrap();
    f.fire(&a, "01-SessionStart-startup.json");
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.events[..], [AgentEvent::SessionStarted { .. }]));
    assert!(t.log.is_empty(), "{:?}", t.log);
}

/// A child of this process that isn't a shell: a hook whose parent it is
/// came through a wrapper (`Ancestry::Wrapped`).
struct Child(std::process::Child);

impl Child {
    fn sleep() -> Child {
        Child(Command::new("sleep").arg("30").spawn().unwrap())
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn only_hooks_the_sessions_agent_started_count() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    // pid 1 isn't this agent or under it: a nested codex (a tool's) can't
    // pin the session
    f.put_from(
        &a,
        1,
        "SessionStart",
        &f.hook("01-SessionStart-startup.json"),
        1,
    );
    f.put_from(
        &a,
        2,
        "UserPromptSubmit",
        &f.hook("02-UserPromptSubmit.json"),
        1,
    );
    rollout_upto(&f.a, A, 9);
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty(), "{:?}", t.events);
    assert_eq!(a.session_id(), None);
    assert_eq!(chat.status().state, State::Unknown);
    // the agent's own hooks pin it
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    let t = tick(&mut a, &mut chat);
    assert!(matches!(
        &t.events[..],
        [
            AgentEvent::SessionStarted { .. },
            AgentEvent::PromptSubmitted { .. }
        ]
    ));
    assert_eq!(a.session_id(), Some("<session-A>"));
    rollout_upto(&f.a, A, 14);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Ready);
    // between turns: a nested /new can't re-pin, and a nested hook naming
    // the pinned session counts neither
    f.put_from(
        &a,
        10,
        "SessionStart",
        &f.hook("22-SessionStart-after-new.json"),
        1,
    );
    f.put_from(
        &a,
        11,
        "UserPromptSubmit",
        &f.hook("04-UserPromptSubmit-approval-turn.json"),
        1,
    );
    for _ in 0..3 {
        assert!(tick(&mut a, &mut chat).events.is_empty());
    }
    assert_eq!(a.session_id(), Some("<session-A>"));
    assert_eq!(chat.status().state, State::Ready);
    // through a non-shell child (a wrapper): the pinned session's hooks
    // count, another session's start doesn't
    let wrapper = Child::sleep();
    f.put_from(
        &a,
        12,
        "SessionStart",
        &f.hook("22-SessionStart-after-new.json"),
        wrapper.pid(),
    );
    for _ in 0..3 {
        assert!(tick(&mut a, &mut chat).events.is_empty());
    }
    assert_eq!(a.session_id(), Some("<session-A>"));
    f.put_from(
        &a,
        13,
        "UserPromptSubmit",
        &f.hook("04-UserPromptSubmit-approval-turn.json"),
        wrapper.pid(),
    );
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [AgentEvent::PromptSubmitted { .. }]),
        "{:?}",
        t.events
    );
}

#[test]
fn a_wrapped_agent_pins_the_first_session() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    let wrapper = Child::sleep();
    f.put_from(
        &a,
        1,
        "SessionStart",
        &f.hook("01-SessionStart-startup.json"),
        wrapper.pid(),
    );
    rollout_upto(&f.a, A, 9);
    let t = tick(&mut a, &mut chat);
    assert!(matches!(&t.events[..], [AgentEvent::SessionStarted { .. }]));
    assert_eq!(a.session_id(), Some("<session-A>"));
    // no agent pid: nothing counts
    let mut b = f.adapter();
    b.set_agent_pid(None);
    f.fire(&b, "01-SessionStart-startup.json");
    assert!(b.poll_events().is_empty());
    assert_eq!(b.session_id(), None);
}

#[test]
fn approvals_open_across_a_re_pin_keep_waiting() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 14);
    tick(&mut a, &mut chat);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Ready);
    // /new: the switch waits one poll; two approvals are reported open in
    // between (the worker's count is the only source)
    f.fire(&a, "22-SessionStart-after-new.json");
    assert!(tick(&mut a, &mut chat).events.is_empty());
    a.set_open_approvals(2);
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [
            AgentEvent::SessionStarted { session_id, .. },
            AgentEvent::WaitingForPermission { .. },
        ] if session_id == "<session-B>"),
        "the wait is sent again after the re-pin: {:?}",
        t.events
    );
    assert_eq!(chat.status().state, State::Waiting);
    // one closes: still waiting
    a.set_open_approvals(1);
    assert!(tick(&mut a, &mut chat).events.is_empty());
    assert_eq!(chat.status().state, State::Waiting);
    // the last one: working again
    a.set_open_approvals(0);
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert_eq!(chat.status().state, State::Working);
}

/// npm's `codex` as Codex's hooks see it: this process is the wrapper
/// (the agent), `real` the real binary (its non-shell child), `nested` a
/// codex the real binary started without a shell.
struct Wrapper {
    real: std::process::Child,
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

#[test]
fn under_a_wrapper_new_re_pins_and_a_nested_codex_still_cannot() {
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    let w = Wrapper::start();
    let real = w.real.id();
    // the real binary's first hooks (through the wrapper) pin session A
    f.put_from(
        &a,
        1,
        "SessionStart",
        &f.hook("01-SessionStart-startup.json"),
        real,
    );
    f.put_from(
        &a,
        2,
        "UserPromptSubmit",
        &f.hook("02-UserPromptSubmit.json"),
        real,
    );
    rollout_upto(&f.a, A, 14);
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(
            &t.events[..],
            [
                AgentEvent::SessionStarted { .. },
                AgentEvent::PromptSubmitted { .. }
            ]
        ),
        "{:?}",
        t.events
    );
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Ready);
    // its /new: the real binary is the agent now, so it re-pins
    f.put_from(
        &a,
        3,
        "SessionStart",
        &f.hook("22-SessionStart-after-new.json"),
        real,
    );
    f.put_from(
        &a,
        4,
        "UserPromptSubmit",
        &f.hook("23-UserPromptSubmit.json"),
        real,
    );
    rollout_upto(&f.b, B, 9);
    assert!(tick(&mut a, &mut chat).events.is_empty(), "held one poll");
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [AgentEvent::SessionStarted { session_id, .. }, AgentEvent::PromptSubmitted { .. }] if session_id == "<session-B>"),
        "{:?}",
        t.events
    );
    assert_eq!(a.session_id(), Some("<session-B>"));
    assert_eq!(chat.status().state, State::Working);
    // a codex the real binary started (no shell): wrapped, another session:
    // it can't re-pin, even once the turn ended
    rollout_upto(&f.b, B, 14);
    tick(&mut a, &mut chat);
    f.put_from(
        &a,
        5,
        "SessionStart",
        &f.hook("29-SessionStart-resume.json"),
        w.nested,
    );
    for _ in 0..3 {
        assert!(tick(&mut a, &mut chat).events.is_empty());
    }
    assert_eq!(a.session_id(), Some("<session-B>"));
}

#[test]
fn resuming_a_rollout_bigger_than_one_read_is_all_history() {
    let f = fx();
    let mut a = f.adapter();
    // 64 bytes a poll: the conversation so far takes many reads
    a.max_read = Some(64);
    let mut chat = ChatSession::new(GEN.into(), 0);
    rollout_upto(&f.a, A, 77);
    f.fire(&a, "29-SessionStart-resume.json");
    let t = tick(&mut a, &mut chat);
    assert!(
        t.log.iter().all(|i| matches!(i, LogItem::Backfill(_))),
        "{:?}",
        t.log
    );
    assert!(message_ids(&t.outs).is_empty() && completes(&t.outs).is_empty());
    assert_eq!(chat.history(None, 100, 1 << 20).len(), 10);
    assert_eq!(chat.status().state, State::Ready);
    // nothing old comes later as live
    for _ in 0..50 {
        let t = tick(&mut a, &mut chat);
        assert!(t.log.is_empty() && t.outs.is_empty(), "{:?}", t.log);
    }
    assert_eq!(chat.status().state, State::Ready);
    // the next turn is live, read 64 bytes at a time
    f.fire(&a, "30-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 86);
    let mut outs = Vec::new();
    for _ in 0..2000 {
        outs.extend(tick(&mut a, &mut chat).outs);
        if !completes(&outs).is_empty() {
            break;
        }
    }
    assert_eq!(message_ids(&outs), ["<id-12>", "<msg-17>"]);
    assert_eq!(completes(&outs), [("<turn-6>".into(), None, Outcome::Done)]);
}

/// Turn 2 of session A waits for an approval the worker reported open.
fn waiting_for_an_approval(f: &Fx) -> (CodexAdapter, ChatSession) {
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "04-UserPromptSubmit-approval-turn.json");
    rollout_upto(&f.a, A, 19);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Working);
    // its call starts (PreToolUse, `<exec-1>`), then asks
    f.fire(&a, "05-PreToolUse-before-approval.json");
    tick(&mut a, &mut chat);
    a.set_approvals(1, 0, 0);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    (a, chat)
}

#[test]
fn a_released_approval_waits_in_codexs_dialog_until_it_is_dismissed() {
    let f = fx();
    let (mut a, mut chat) = waiting_for_an_approval(&f);
    // input to Codex: released ("no decision"), Codex shows its own dialog
    a.set_approvals(0, 1, now_ms());
    for _ in 0..3 {
        assert!(tick(&mut a, &mut chat).events.is_empty());
        assert_eq!(chat.status().state, State::Waiting);
    }
    // a PreToolUse read meanwhile came before it
    f.fire(&a, "05-PreToolUse-before-approval.json");
    assert!(tick(&mut a, &mut chat).events.is_empty());
    // a PostToolUse (even this call's): nothing ties a result to the
    // approval, so it ends nothing
    f.fire(&a, "07-PostToolUse-after-approval.json");
    assert!(tick(&mut a, &mut chat).events.is_empty());
    assert!(a.dialog_open());
    // Esc at Codex's dialog
    f.fire(&a, "21-Interrupt-esc-at-approval-dialog.json");
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert!(!a.dialog_open());
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[test]
fn the_rollouts_next_command_or_reply_leaves_codexs_dialog() {
    let f = fx();
    let (mut a, mut chat) = waiting_for_an_approval(&f);
    a.set_approvals(0, 1, now_ms());
    assert!(tick(&mut a, &mut chat).events.is_empty());
    rollout_upto(&f.a, A, 26);
    let t = tick(&mut a, &mut chat);
    assert!(!message_ids(&t.outs).is_empty());
    assert!(tick(&mut a, &mut chat).events.is_empty());
    assert!(a.dialog_open());
    assert_eq!(chat.status().state, State::Waiting);
}

/// An event as the hook script publishes it, by hand: seq `n` and the
/// counter raised to it.
fn publish(f: &Fx, a: &CodexAdapter, n: u64, body: &Value) {
    let event = body["hook_event_name"].as_str().unwrap();
    f.put(a, n, event, &body.to_string());
    let seq = a.dir().unwrap().join("events").join("seq");
    let now: u64 = fs::read_to_string(&seq)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0);
    fs::write(seq, format!("{}\n", now.max(n))).unwrap();
}

fn call_body(f: &Fx, event: &str, id: &str, command: &str) -> Value {
    let mut body: Value =
        serde_json::from_str(&f.hook("07-PostToolUse-after-approval.json")).unwrap();
    body["hook_event_name"] = event.into();
    body["tool_use_id"] = id.into();
    body["tool_input"]["command"] = command.into();
    body
}

/// Turn 2 of session A, its call's PreToolUse never seen (a hook Codex
/// never started leaves no trace).
fn asking_without_its_pretooluse(f: &Fx) -> (CodexAdapter, ChatSession) {
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "04-UserPromptSubmit-approval-turn.json");
    rollout_upto(&f.a, A, 19);
    tick(&mut a, &mut chat);
    a.set_approvals(1, 0, 0);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    (a, chat)
}

/// Astation's counterexample (#81 6511290452): A's hook absent with nothing
/// to show it (no marker, no gap, a complete history), same-command B the
/// only call seen, B's result first, then a result naming A's call too. No
/// tool result is proven to be the asking call's, so none ends the wait:
/// held throughout (no prompt goes in), until a dismissal.
#[test]
fn no_tool_result_ends_codexs_dialog() {
    let f = fx();
    let (mut a, mut chat) = asking_without_its_pretooluse(&f);
    let base = f.evseq(&a);
    publish(
        &f,
        &a,
        base + 1,
        &call_body(&f, "PreToolUse", "c-b", "touch made.txt"),
    );
    tick(&mut a, &mut chat);
    a.set_approvals(0, 1, now_ms());
    turn_two_ends_awaiting_approval(&f, BEFORE_TURN_TWO + 60_000);
    tick(&mut a, &mut chat);
    assert!(!a.take_answer_hint(), "no tool ended since the dialog");
    publish(
        &f,
        &a,
        base + 2,
        &call_body(&f, "PostToolUse", "c-b", "touch made.txt"),
    );
    publish(
        &f,
        &a,
        base + 3,
        &call_body(&f, "PostToolUse", "<exec-1>", "touch made.txt"),
    );
    for _ in 0..3 {
        let t = tick(&mut a, &mut chat);
        assert!(
            !t.events.contains(&AgentEvent::ToolFinished),
            "{:?}",
            t.events
        );
    }
    assert!(a.dialog_open() && a.waiting());
    // A tool's end only tells the terminal how to end the wait, once.
    assert!(a.take_answer_hint());
    assert!(!a.take_answer_hint());
    assert_eq!(chat.status().state, State::Waiting);
    assert!(chat.submit("r-1", GEN, "go on", 0, false).is_err());
    f.fire(&a, "21-Interrupt-esc-at-approval-dialog.json");
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert_eq!(chat.status().state, State::Ready);
}

/// The person at the terminal says the approval was answered there (the
/// prefix `a`): the wait ends, ready (its turn is over).
#[test]
fn the_person_at_the_terminal_ends_codexs_dialog_wait() {
    let f = fx();
    let (mut a, mut chat) = waiting_for_an_approval(&f);
    a.set_approvals(0, 1, now_ms());
    turn_two_ends_awaiting_approval(&f, BEFORE_TURN_TWO + 60_000);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    a.answered_here();
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert!(!a.dialog_open());
    assert_eq!(chat.status().state, State::Ready);
}

#[test]
fn released_with_no_remote_wait_before_is_waiting_until_an_interrupt() {
    // after an adoption (the new broker knows none) or with no broker: no
    // approval was open for a remote answer, the dialog is Codex's own
    let f = fx();
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "18-UserPromptSubmit-multiline-paste.json");
    rollout_upto(&f.a, A, 67);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Working);
    a.set_approvals(0, 1, now_ms());
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [AgentEvent::WaitingForPermission { .. }]),
        "{:?}",
        t.events
    );
    // no input: it stays
    for _ in 0..3 {
        assert!(tick(&mut a, &mut chat).events.is_empty());
    }
    assert_eq!(chat.status().state, State::Waiting);
    // Esc at Codex's dialog
    f.fire(&a, "21-Interrupt-esc-at-approval-dialog.json");
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert_ne!(chat.status().state, State::Waiting);
}

/// Unix ms before turn 2's prompt in `rollout-session-A.jsonl`: evidence
/// from the fixtures (and every hook fired now) is newer.
const BEFORE_TURN_TWO: i64 = 1_792_215_201_000;

/// Appends rollout records to `dst`: turn 2 of session A, from `at_ms`.
fn append_turn_two(dst: &Path, at_ms: i64, records: &[(&str, Value)]) {
    use std::io::Write;
    let mut file = fs::OpenOptions::new().append(true).open(dst).unwrap();
    for (n, (kind, payload)) in records.iter().enumerate() {
        // the record's time: its `completed_at_ms` wins over `timestamp`
        let mut payload = payload.clone();
        payload["completed_at_ms"] = Value::from(at_ms + n as i64);
        let line = serde_json::json!({
            "timestamp": "2026-10-17T06:00:00.000Z",
            "ordinal": 1000 + n,
            "type": kind,
            "payload": payload,
        });
        writeln!(file, "{line}").unwrap();
    }
}

/// Codex 0.163 ends the turn while its exec cell still waits for the
/// approval (the model's `wait` calls gave up): the reply and the turn's
/// end, as in the incident.
fn turn_two_ends_awaiting_approval(f: &Fx, at_ms: i64) {
    append_turn_two(
        &f.a,
        at_ms,
        &[
            (
                "event_msg",
                serde_json::json!({"type": "item_completed", "thread_id": "<session-A>",
                    "turn_id": "<turn-2>", "item": {"type": "AgentMessage", "id": "<msg-await>",
                    "content": [{"type": "Text", "text": "Awaiting approval to run the command."}],
                    "phase": "final_answer"}}),
            ),
            (
                "event_msg",
                serde_json::json!({"type": "task_complete", "root_turn_id": "<turn-2>",
                    "turn_id": "<turn-2>", "last_agent_message": "Awaiting approval to run the command."}),
            ),
        ],
    );
}

#[test]
fn codex_ending_the_turn_leaves_its_dialog_waiting() {
    // The incident: the turn ended while the approval waited; it got no
    // decision and Codex showed its own dialog. A prompt pasted now would
    // answer that dialog (its Enter picks the default: allow once).
    let f = fx();
    let (mut a, mut chat) = waiting_for_an_approval(&f);
    a.set_approvals(0, 1, now_ms());
    assert!(a.dialog_open());
    turn_two_ends_awaiting_approval(&f, BEFORE_TURN_TWO + 60_000);
    let mut outs = Vec::new();
    for _ in 0..3 {
        outs.extend(tick(&mut a, &mut chat).outs);
    }
    // the turn completes, the session stays waiting, no prompt goes in
    assert_eq!(completes(&outs), [("<turn-2>".into(), None, Outcome::Done)]);
    assert_eq!(chat.status().state, State::Waiting);
    assert!(a.dialog_open());
    assert!(chat.submit("r-1", GEN, "go on", 0, false).is_err());
    // a Stop hook doesn't end it either
    f.fire(&a, "08-Stop-empty-last-message.json");
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    // Esc at Codex's dialog: answered, and with the turn over it is ready
    f.fire(&a, "21-Interrupt-esc-at-approval-dialog.json");
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert!(!a.dialog_open());
    assert_eq!(chat.status().state, State::Ready);
}

#[test]
fn a_remote_wait_outlasts_the_turns_end_too() {
    // The turn ended while the hook still waits for a remote answer: the
    // approval stays open (the worker no longer closes it at a plain turn
    // end), and so does the waiting status.
    let f = fx();
    let (mut a, mut chat) = waiting_for_an_approval(&f);
    turn_two_ends_awaiting_approval(&f, BEFORE_TURN_TWO + 60_000);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Waiting);
    // answered remotely, the tool ran: ready (the turn is over)
    a.set_approvals(0, 0, 0);
    assert_eq!(tick(&mut a, &mut chat).events, [AgentEvent::ToolFinished]);
    assert_eq!(chat.status().state, State::Ready);
}

#[test]
fn a_dismissal_from_before_the_dialog_doesnt_end_it() {
    // An Interrupt published before the dialog opened but read only after
    // it: the dialog records every event published by then (the script's
    // counter), so it is from before and ends nothing.
    let f = fx();
    let (mut a, mut chat) = waiting_for_an_approval(&f);
    f.fire(&a, "21-Interrupt-esc-at-approval-dialog.json");
    a.set_approvals(0, 1, now_ms());
    for _ in 0..3 {
        tick(&mut a, &mut chat);
    }
    assert!(a.dialog_open());
    assert_eq!(chat.status().state, State::Waiting);
}

/// Session A with turn 1 over.
fn after_turn_one(f: &Fx) -> (CodexAdapter, ChatSession) {
    let mut a = f.adapter();
    let mut chat = ChatSession::new(GEN.into(), 0);
    f.fire(&a, "01-SessionStart-startup.json");
    f.fire(&a, "02-UserPromptSubmit.json");
    rollout_upto(&f.a, A, 14);
    tick(&mut a, &mut chat);
    assert_eq!(chat.status().state, State::Ready);
    (a, chat)
}

#[test]
fn after_new_a_prompt_read_before_its_session_start_re_pins() {
    let f = fx();
    let (mut a, mut chat) = after_turn_one(&f);
    // /new: the async hooks published the prompt first
    f.fire(&a, "23-UserPromptSubmit.json");
    rollout_upto(&f.b, B, 9);
    assert!(tick(&mut a, &mut chat).events.is_empty(), "held one poll");
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [
            AgentEvent::SessionStarted { session_id, .. },
            AgentEvent::PromptSubmitted { .. },
        ] if session_id == "<session-B>"),
        "{:?}",
        t.events
    );
    assert_eq!(a.session_id(), Some("<session-B>"));
    assert_eq!(message_ids(&t.outs), ["<id-15>"]);
    assert_eq!(chat.status().state, State::Working);
    // its SessionStart, read later, restarts nothing
    f.fire(&a, "22-SessionStart-after-new.json");
    let t = tick(&mut a, &mut chat);
    assert!(t.events.is_empty() && t.outs.is_empty(), "{:?}", t.events);
    assert_eq!(chat.status().state, State::Working);
}

#[test]
fn a_prompt_and_its_session_start_in_one_pass_start_with_the_start() {
    let f = fx();
    let (mut a, mut chat) = after_turn_one(&f);
    f.fire(&a, "23-UserPromptSubmit.json");
    f.fire(&a, "22-SessionStart-after-new.json");
    rollout_upto(&f.b, B, 9);
    tick(&mut a, &mut chat);
    let t = tick(&mut a, &mut chat);
    assert!(
        matches!(&t.events[..], [
            AgentEvent::SessionStarted { session_id, source, .. },
            AgentEvent::PromptSubmitted { .. },
        ] if session_id == "<session-B>" && source == "startup"),
        "{:?}",
        t.events
    );
    assert_eq!(chat.status().state, State::Working);
}

#[test]
fn a_nested_codexs_prompt_of_another_session_never_re_pins() {
    let f = fx();
    let (mut a, mut chat) = after_turn_one(&f);
    rollout_upto(&f.b, B, 9);
    // a codex a tool ran (not started by the agent): pid 1 is no child of
    // this process
    f.put_from(
        &a,
        900,
        "UserPromptSubmit",
        &f.hook("23-UserPromptSubmit.json"),
        1,
    );
    for _ in 0..3 {
        assert!(tick(&mut a, &mut chat).events.is_empty());
    }
    assert_eq!(a.session_id(), Some("<session-A>"));
    assert_eq!(chat.status().state, State::Ready);
}

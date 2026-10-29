//! Codex adapter: Atem's Codex hooks (`approval_hook.sh event`, one
//! `ev-<seq>-<Event>.json` per hook in the session's `events/`) mark the
//! lifecycle, the rollout JSONL (`rollout.rs`) carries every message, turn
//! start and turn end (`designs/fixtures/codex-hooks/README.md`).
//!
//! - Session: Codex says nothing before its first prompt (SessionStart is
//!   lazy). Chat is available from the launch, but the status stays
//!   unknown (`NotReady` with [`FIRST_PROMPT`]) and a chat submit is
//!   refused with that hint until the first hook: the first prompt is typed
//!   in the terminal (the 2026-10-17 ruling: text typed into Codex's
//!   startup dialogs could answer them). The first hook pins its session (a
//!   missed SessionStart, e.g. a hook not yet trusted, is made up from it)
//!   and names the rollout, which must be `rollout-*-<session_id>.jsonl`
//!   under `$CODEX_HOME/sessions`, also once symlinks are resolved (else
//!   the hook is ignored with a notice). The agent's own UserPromptSubmit
//!   of another session re-pins the same way (its SessionStart may be
//!   published after it after `/new`; that SessionStart, read later, is
//!   then no restart).
//! - Ownership: each event file's first line is the hook's `$$ $PPID`.
//!   Only hooks the session's agent started count (`approvals::HookAgent`,
//!   the rule approvals use): directly (its parent is the agent, or one
//!   shell under it) a hook may pin or re-pin; through a non-shell child (a
//!   wrapper such as npm's `codex`) only the pinned session's, or the first
//!   one — which makes that child (the real binary) the agent, so its
//!   `/new` re-pins; anything deeper (a `codex` a tool ran) never counts,
//!   so a nested Codex can't take over the chat or the status. A wrapped
//!   hook read after its parent exited counts as foreign: harmless, the
//!   rollout's end record is authoritative.
//! - Only the pinned session's hooks count. A SessionStart of another
//!   session re-pins (`/new` → `startup`, a resume of another conversation
//!   → `resume`): the old rollout is read to its end first (the switch
//!   waits one poll), a `startup` rollout is live from its first line,
//!   anything else is history (`Backfill`) up to a turn still running. A
//!   start of another session while the pinned one's turn runs waits (with
//!   a notice) until that turn ends (its rollout end, or its Stop/Interrupt
//!   hook).
//! - Status (`ChatSession`): `UserPromptSubmit` → working (and the hook
//!   half of a prompt's acceptance, with its `turn_id`), PreToolUse /
//!   PostToolUse → tool events, the rollout's `task_started` → working,
//!   `task_complete` / `turn_aborted` → ready. Stop and Interrupt only wake
//!   the reader (the rollout's end record follows them and is
//!   authoritative), as do PreCompact/PostCompact (the compaction's own
//!   task marks it) and SessionEnd (the process exit is the worker's).
//! - Waiting: PermissionRequest never reaches `events/` (it is the
//!   approvals' own protocol, `runtime/worker_approvals.rs`), so the worker
//!   reports how many approvals of this session wait for a remote answer
//!   and when it gave some back to Codex's own dialog ("no decision":
//!   input to Codex, no broker, a broker that doesn't know them, a turn
//!   end or the hook ending while it waited)
//!   ([`CodexAdapter::set_approvals`]; its set is the only source of the
//!   first). Waiting while either holds: not waiting → waiting is
//!   `WaitingForPermission` with `outlasts_turn` (Codex may end the turn
//!   while its exec cell still waits for the approval, or with its dialog
//!   open: the status stays waiting past the turn's end), back
//!   `ToolFinished`, returned after that poll's hook events. Codex's own
//!   dialog counts until evidence from after the approval went there: the
//!   PostToolUse of the one call it can be about (by event sequence:
//!   `call_finished`), its dismissal (Interrupt or UserPromptSubmit hook,
//!   the rollout's next user message or interrupted turn end); never a
//!   Stop, a plain turn end, a reply or another call's result (a re-pin
//!   drops it). Lost events (`EventReader::take_lost`: a synchronous
//!   hook's start marker left by a dead hook, an unreadable event) make a
//!   lost PreToolUse's calls incomplete: then only a dismissal ends one. While it is open a chat prompt is
//!   never pasted ([`CodexAdapter::dialog_open`]: the worker consumes it).
//!   After a re-pin with approvals open, `WaitingForPermission` again. A
//!   PreToolUse read while waiting is dropped (Codex holds the tool while
//!   the hook or its dialog waits).
//! - A format change in the rollout withdraws chat, as for Claude.
//!   Messages arrive whole, never streamed; [`UNAVAILABLE`] says so.

use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::Value;

use super::rollout::RolloutReader;
use crate::chat::adapter::{
    AgentAdapter, AgentEvent, Capabilities, LaunchPlan, LogItem, Outcome,
    UNAVAILABLE_ERROR_DETAILS, UNAVAILABLE_REASONING, UNAVAILABLE_STREAMING,
};
use crate::chat::approvals::{Ancestry, HookAgent};

/// Why a chat prompt is refused before Codex's first hook.
pub const FIRST_PROMPT: &str = "type a first prompt in the terminal: Codex reports nothing before it (and Atem's Codex hooks must be trusted in its /hooks)";
/// What Codex chat can't provide: no partial text (whole messages only),
/// no reasoning (encrypted), no model/API error details (none recorded).
/// "Always allow" is offered as an Atem session rule (Codex itself fails
/// closed on a persistent rule; `chat::approvals`).
pub const UNAVAILABLE: &[&str] = &[
    UNAVAILABLE_STREAMING,
    UNAVAILABLE_REASONING,
    UNAVAILABLE_ERROR_DETAILS,
];
/// The status detail while an approval waits (`ChatSession` shows its own).
const APPROVAL_DETAIL: &str = "approve in the terminal";

/// The call an approval was for, as its PermissionRequest named it (tool
/// and command: no call id), and the hook events published when it asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogCall {
    pub tool_name: String,
    /// `tool_input.command` (a shell command or a patch); `None` for other
    /// tools, whose dialog only a dismissal ends.
    pub command: Option<String>,
    /// The events counter when it asked (`evseq-<id>`): Codex ran the
    /// call's synchronous PreToolUse to its end first, so the call is among
    /// the calls started by then. `None` (unreadable): no call is ever
    /// matched to it.
    pub evseq: Option<u64>,
}

/// A call of the pinned session, from its PreToolUse (`tool_use_id`), by
/// event sequence (the script's counter: publication order).
#[derive(Debug)]
struct Call {
    id: String,
    tool_name: String,
    command: Option<String>,
    started_seq: u64,
    finished_seq: Option<u64>,
}

/// Calls remembered for matching dialogs.
const MAX_CALLS: usize = 256;

/// An approval in Codex's own dialog: since `since` (unix ms) and after
/// event `since_seq` (the newest read then).
#[derive(Debug)]
struct Dialog {
    call: DialogCall,
    since: i64,
    since_seq: u64,
}

/// Codex's permission wait: it outlasts the turn's end (an approval belongs
/// to a tool call that can outlive the turn, and Codex's own dialog stays
/// open after it).
fn waiting_event() -> AgentEvent {
    AgentEvent::WaitingForPermission {
        detail: APPROVAL_DETAIL.into(),
        outlasts_turn: true,
    }
}
/// Event files read per poll; the rest wait for the next.
const EVENTS_PER_POLL: usize = 256;
/// Largest event file read; a bigger one is dropped.
const MAX_EVENT: u64 = 1024 * 1024;
/// A `tmp.*` left by a killed hook, or an unreadable event file, goes
/// after this long.
const LEFTOVER: Duration = Duration::from_secs(60);

pub struct CodexAdapter {
    codex_home: PathBuf,
    /// Who hooks must have been started by (the PTY child, or the real
    /// binary under a wrapper): only those count. Unknown: none does.
    hook_agent: HookAgent,
    dir: Option<PathBuf>,
    events: Option<EventReader>,
    rollout: Option<RolloutReader>,
    /// The Codex session whose hooks count.
    pinned: Option<String>,
    /// Hooks not yet handled: a switch to another rollout waits one poll so
    /// the old one is read to its end first.
    held: VecDeque<Hook>,
    /// The switch at the front of `held` already waited its poll.
    switch_waited: bool,
    /// Log items returned before the reader's own at the next `poll_log`.
    queued: Vec<LogItem>,
    /// Events returned after the hooks' at the next `poll_events`
    /// (approvals: a PreToolUse read in the same pass came first).
    extra: Vec<AgentEvent>,
    /// A start of another session ignored while the pinned turn ran: tried
    /// again once that turn ends (a turn end, or its Stop/Interrupt hook).
    deferred: Option<Hook>,
    /// `NotReady` was sent (before the first hook).
    announced: bool,
    /// The pinned session's turn runs (a prompt or a live `task_started`,
    /// no live turn end yet).
    turn_open: bool,
    /// Approvals open for this session (the worker's count: waiting for a
    /// remote answer).
    approvals: usize,
    /// Approvals that sit in Codex's own dialog: each got "no decision"
    /// (released, closed by a prompt or turn end, its hook ended). Each
    /// holds the status waiting until evidence from after it went there
    /// that it was answered: the PostToolUse of the one call it can be
    /// about (`call_finished`), or the dialog dismissed (Interrupt hook, `turn_aborted`)
    /// or gone (a prompt went in: UserPromptSubmit, the rollout's user
    /// message). Never a Stop, a turn's plain end, a reply or another
    /// call's result: Codex may end the turn with the dialog still open
    /// (its exec cell runs on), and other calls may finish meanwhile.
    dialogs: Vec<Dialog>,
    /// Calls of the pinned session seen at their PreToolUse (at most
    /// `MAX_CALLS`): what a dialog's PostToolUse is matched by.
    calls: Vec<Call>,
    /// Why the calls can't be trusted to be complete (a PreToolUse lost:
    /// its hook died, timed out or failed, Codex ran the tool anyway; or an
    /// unfinished call forgotten): until the next re-pin no PostToolUse
    /// answers a dialog, only a dismissal does.
    calls_incomplete: Option<&'static str>,
    /// The newest event sequence read.
    last_seq: u64,
    /// The pinned session was pinned by a hook other than its SessionStart
    /// (async hooks publish in either order): that SessionStart, read
    /// later on the same rollout, is no restart.
    start_unseen: bool,
    session_started: bool,
    withdrawn: Option<String>,
    /// Rollout bytes read per poll (tests).
    #[cfg(test)]
    max_read: Option<u64>,
}

impl CodexAdapter {
    /// An adapter reading rollouts under `codex_home` (`$CODEX_HOME` of the
    /// launch, else `~/.codex`).
    pub fn new(codex_home: PathBuf) -> Self {
        Self {
            codex_home,
            hook_agent: HookAgent::default(),
            dir: None,
            events: None,
            rollout: None,
            pinned: None,
            held: VecDeque::new(),
            switch_waited: false,
            queued: Vec::new(),
            extra: Vec::new(),
            deferred: None,
            announced: false,
            turn_open: false,
            approvals: 0,
            dialogs: Vec::new(),
            calls: Vec::new(),
            calls_incomplete: None,
            last_seq: 0,
            start_unseen: false,
            session_started: false,
            withdrawn: None,
            #[cfg(test)]
            max_read: None,
        }
    }

    /// The agent was spawned as `pid`: from now on its hooks count.
    pub fn set_agent_pid(&mut self, pid: Option<u32>) {
        self.hook_agent = HookAgent::new(pid);
    }

    /// The session directory (`ATEM_APPROVAL_DIR`: `events/` for the hooks,
    /// `approvals/` for PermissionRequest).
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// The pinned Codex session (from its first hook).
    #[cfg(test)]
    pub fn session_id(&self) -> Option<&str> {
        self.pinned.as_deref()
    }

    /// [`Self::set_approvals`] with nothing released.
    #[cfg(test)]
    pub fn set_open_approvals(&mut self, n: usize) {
        self.set_approvals(n, Vec::new(), 0);
    }

    /// The worker's report: `open` approvals wait for a remote answer, and
    /// `released` were given back to Codex's own dialog at `at_ms` ("no
    /// decision": input to Codex, no broker, a broker that doesn't know
    /// them, a prompt or turn end closing them, their hook ending while it
    /// waited). Waiting while either holds.
    pub fn set_approvals(&mut self, open: usize, released: Vec<DialogCall>, at_ms: i64) {
        let before = self.waiting();
        self.approvals = open;
        // Every event published by now (the script's counter, read or not
        // yet): a later one was published after the dialog opened.
        let since_seq = self.last_seq.max(self.published_seq());
        self.dialogs.extend(released.into_iter().map(|call| Dialog {
            call,
            since: at_ms,
            since_seq,
        }));
        self.status_change(before);
    }

    /// The script's events counter (`events/seq`): the newest event
    /// published, read or not; 0 without one.
    fn published_seq(&self) -> u64 {
        self.dir
            .as_ref()
            .and_then(|d| std::fs::read_to_string(d.join("events").join("seq")).ok())
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0)
    }

    /// An approval sits in Codex's own dialog: input typed now answers it,
    /// so a chat prompt must not be pasted (the worker consumes it).
    pub fn dialog_open(&self) -> bool {
        !self.dialogs.is_empty()
    }

    /// Waiting for an approval: a remote answer or Codex's own dialog. A
    /// chat prompt is never written meanwhile (the worker holds prompts).
    pub fn waiting(&self) -> bool {
        self.approvals > 0 || self.dialog_open()
    }

    /// A call started (its PreToolUse, with its `tool_use_id`).
    fn call_started(&mut self, hook: &Hook) {
        let Some(id) = hook.tool_use_id.clone() else {
            return;
        };
        if self.calls.iter().any(|c| c.id == id) {
            return;
        }
        if self.calls.len() >= MAX_CALLS {
            // Forget a finished call first; forgetting an unfinished one
            // could make a dialog's match look unique.
            match self.calls.iter().position(|c| c.finished_seq.is_some()) {
                Some(i) => {
                    self.calls.remove(i);
                }
                None => {
                    self.calls.remove(0);
                    self.calls_lost("more unfinished calls than Atem keeps");
                }
            }
        }
        self.calls.push(Call {
            id,
            tool_name: hook.tool_name.clone().unwrap_or_default(),
            command: hook.command.clone(),
            started_seq: hook.seq,
            finished_seq: None,
        });
    }

    /// The calls are no longer known to be complete: no tool result answers
    /// a dialog until the next re-pin (only a dismissal does). Said once.
    fn calls_lost(&mut self, why: &'static str) {
        if self.calls_incomplete.is_none() {
            self.calls_incomplete = Some(why);
            self.notice(&format!(
                "a Codex tool call went unrecorded ({why}); an approval left in Codex's own dialog now ends only when it is dismissed (Esc) or a prompt is typed in the terminal"
            ));
        }
    }

    /// A call finished (its PostToolUse). It answers a dialog only when it
    /// is the one call that dialog can be about. Codex's PermissionRequest
    /// names no call; its candidates are the calls with its tool and
    /// command whose PreToolUse was published by its request (`evseq`:
    /// Codex waits for the synchronous PreToolUse, so the asking call is
    /// among them) and that hadn't finished by then. Another candidate (a
    /// same-command call), an unreadable `evseq` or incomplete calls make
    /// it ambiguous: the dialog stays until it is dismissed.
    fn call_finished(&mut self, hook: &Hook) {
        let Some(id) = hook.tool_use_id.as_deref() else {
            return;
        };
        let Some(at) = self.calls.iter().position(|c| c.id == id) else {
            return;
        };
        self.calls[at].finished_seq = Some(hook.seq);
        if self.calls_incomplete.is_some() {
            return;
        }
        let calls = &self.calls;
        let answered = self.dialogs.iter().position(|d| {
            let Some(evseq) = d.call.evseq else {
                return false;
            };
            let candidate = |c: &Call| {
                d.call.command.is_some()
                    && c.tool_name == d.call.tool_name
                    && c.command == d.call.command
                    && c.started_seq <= evseq
                    && c.finished_seq.is_none_or(|f| f > evseq)
            };
            hook.seq > d.since_seq
                && candidate(&calls[at])
                && calls.iter().filter(|c| candidate(c)).count() == 1
        });
        if let Some(i) = answered {
            let before = self.waiting();
            self.dialogs.remove(i);
            self.status_change(before);
        }
        if self.dialogs.is_empty() {
            self.calls.retain(|c| c.finished_seq.is_none());
        }
    }

    /// No dialog of Codex's took the keys (dismissed with Esc, or a prompt
    /// went in): every dialog opened before is gone. A hook event is
    /// ordered by its sequence (published after the dialog opened), never
    /// by its file time (filesystem clocks are coarse); a rollout record
    /// has no sequence and is ordered by its own time, Codex's.
    fn dialogs_gone(&mut self, at_ms: i64, seq: Option<u64>) {
        let before = self.waiting();
        self.dialogs.retain(|d| match seq {
            Some(seq) => seq <= d.since_seq,
            None => d.since >= at_ms,
        });
        self.status_change(before);
    }

    fn status_change(&mut self, before: bool) {
        match (before, self.waiting()) {
            (false, true) => self.extra.push(waiting_event()),
            (true, false) => self.extra.push(AgentEvent::ToolFinished),
            _ => {}
        }
    }
}

/// A new session directory under `root` (as Claude's: `chat-<uuid>/` with
/// `events/` and `approvals/`, 0700) and the arguments Codex needs for it
/// (none: its hooks are in `$CODEX_HOME/hooks.json`, the directory reaches
/// them as `ATEM_APPROVAL_DIR`). On failure nothing is left behind.
pub fn prepare_chat(
    root: &Path,
    codex_home: PathBuf,
    args: &[String],
) -> anyhow::Result<(CodexAdapter, Vec<String>)> {
    let dir = crate::chat::claude::hooks::create_session_dir(root)?;
    let mut adapter = CodexAdapter::new(codex_home);
    match adapter.prepare_launch(args, &dir) {
        Ok(plan) => Ok((adapter, plan.extra_args)),
        Err(error) => {
            drop(adapter);
            let _ = std::fs::remove_dir_all(&dir);
            Err(error)
        }
    }
}

/// `path` is a rollout of `session_id` under `<codex_home>/sessions`:
/// absolute, no `.`/`..`, named `rollout-<…>-<session_id>.jsonl`, inside
/// the sessions directory (as written, or once symlinks are resolved).
pub fn rollout_path_ok(codex_home: &Path, session_id: &str, path: &Path) -> bool {
    if session_id.is_empty() || session_id.contains(['/', '\0']) || session_id.starts_with('.') {
        return false;
    }
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let suffix = format!("-{session_id}.jsonl");
    if !name.starts_with("rollout-")
        || name.len() <= "rollout-".len() + suffix.len()
        || !name.ends_with(&suffix)
    {
        return false;
    }
    let sessions = codex_home.join("sessions");
    let parent = path.parent().and_then(|p| p.canonicalize().ok());
    match (sessions.canonicalize(), parent) {
        // Where it really is decides (no symlink out of the sessions dir).
        (Ok(sessions), Some(parent)) => parent.starts_with(sessions),
        // Not there yet: as written. The reader never follows a symlinked
        // rollout file.
        _ => path.starts_with(&sessions) && path != sessions,
    }
}

impl CodexAdapter {
    /// Read the old rollout to its end (normal items), then open `path`. A
    /// `startup` rollout (a new session, `/new`) is live from its first
    /// line; another's content already there is history, except a turn
    /// still running at its end (its prompt was just typed).
    fn switch_to(&mut self, path: PathBuf, source: &str) {
        if let Some(old) = self.rollout.as_mut() {
            let items = old.read_to_end();
            self.queued.extend(items);
        }
        let mut reader = RolloutReader::new(path);
        #[cfg(test)]
        if let Some(max) = self.max_read {
            reader.set_max_read(max);
        }
        if source != "startup" {
            // All of it (a poll reads at most 8 MiB): what a later poll
            // returned would be live.
            let items = reader.read_to_end();
            let open = items
                .iter()
                .rposition(|i| matches!(i, LogItem::TurnStarted { .. }))
                .filter(|&at| {
                    !items[at..]
                        .iter()
                        .any(|i| matches!(i, LogItem::TurnEnded { .. }))
                });
            for (at, item) in items.into_iter().enumerate() {
                let live = matches!(item, LogItem::Problem { .. }) || open.is_some_and(|o| at >= o);
                self.queued.push(if live {
                    item
                } else {
                    LogItem::Backfill(Box::new(item))
                });
            }
        }
        self.rollout = Some(reader);
    }

    fn notice(&mut self, detail: &str) {
        self.queued.push(LogItem::Problem {
            detail: detail.into(),
            fatal: false,
        });
    }

    /// The pinned session's hook as an event.
    fn map(&mut self, hook: Hook, out: &mut Vec<AgentEvent>) {
        match hook.event.as_str() {
            "UserPromptSubmit" => {
                // A prompt went in: no dialog was taking the keys.
                self.dialogs_gone(hook.at_ms, Some(hook.seq));
                if let Some(text) = hook.prompt {
                    self.turn_open = true;
                    out.push(AgentEvent::PromptSubmitted {
                        text,
                        turn_id: hook.turn_id,
                        at_ms: Some(hook.at_ms),
                    });
                }
            }
            // While an approval waits Codex holds the tool: a PreToolUse
            // read now came before it. Every one is recorded: the call
            // identity a dialog's PostToolUse is matched by.
            "PreToolUse" => {
                self.call_started(&hook);
                if !self.waiting() {
                    out.push(AgentEvent::ToolStarted);
                }
            }
            "PostToolUse" => {
                // The tool ran: the dialog of that call, if any, was
                // answered (the end of the wait is its `ToolFinished`).
                // While an approval still waits, the status stays waiting.
                let before = self.waiting();
                self.call_finished(&hook);
                if !before {
                    out.push(AgentEvent::ToolFinished);
                }
            }
            // Only wake-ups for the reader (the rollout's end record is the
            // turn's end), but the turn is over: a deferred start may go.
            // Stop leaves a dialog Codex showed open (Codex may end the turn
            // before it is answered); Interrupt (Esc) dismissed it.
            "Stop" => self.turn_open = false,
            "Interrupt" => {
                self.turn_open = false;
                self.dialogs_gone(hook.at_ms, Some(hook.seq));
            }
            _ => {}
        }
    }
}

impl AgentAdapter for CodexAdapter {
    fn prepare_launch(&mut self, _args: &[String], dir: &Path) -> anyhow::Result<LaunchPlan> {
        let named = dir
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("chat-"));
        if !named || !dir.join("events").is_dir() {
            anyhow::bail!("not a chat session directory: {}", dir.display());
        }
        self.dir = Some(dir.to_path_buf());
        self.events = Some(EventReader::new(dir.to_path_buf()));
        Ok(LaunchPlan::default())
    }

    fn poll_events(&mut self) -> Vec<AgentEvent> {
        let mut out = Vec::new();
        if !self.announced && !self.session_started {
            self.announced = true;
            out.push(AgentEvent::NotReady {
                detail: FIRST_PROMPT.into(),
            });
        }
        let Some(reader) = self.events.as_mut() else {
            out.append(&mut self.extra);
            return out;
        };
        let read = reader.poll();
        let lost = reader.take_lost();
        let mut incoming = std::mem::take(&mut self.held);
        let mut bad = 0;
        for raw in read {
            if let Some(raw) = &raw {
                self.last_seq = self.last_seq.max(raw.seq);
            }
            match raw.as_ref().and_then(Hook::from_raw) {
                Some(hook) => incoming.push_back(hook),
                None => bad += 1,
            }
        }
        if bad > 0 {
            self.notice("ignored a Codex hook event that could not be read");
        }
        for event in &lost {
            eprintln!("atem worker: a Codex {event} hook event was lost");
        }
        if lost.iter().any(|e| e == "PreToolUse") {
            self.calls_lost("its PreToolUse hook didn't finish or couldn't be read");
        }
        while let Some(hook) = incoming.pop_front() {
            let start = hook.event == "SessionStart";
            let ours = self.pinned.as_deref() == Some(hook.session_id.as_str());
            let ancestry = self.hook_agent.ancestry(hook.parent);
            // Not started by this session's agent (a nested codex), or a
            // wrapped one naming another session than the pinned one.
            let counts = match ancestry {
                Ancestry::Direct => true,
                Ancestry::Wrapped { .. } => ours || self.pinned.is_none(),
                Ancestry::Foreign => false,
            };
            if !counts {
                continue;
            }
            if ours && !start {
                self.map(hook, &mut out);
                if !self.turn_open
                    && let Some(deferred) = self.deferred.take()
                {
                    incoming.push_front(deferred);
                }
                continue;
            }
            // The agent's own prompt in another session: its SessionStart
            // may come later (async hooks publish in either order after
            // `/new`), so it re-pins as a first hook would. Anything else of
            // another session (an old one's SessionEnd) never counts, nor
            // does a nested codex (never `Direct`).
            let prompt_first = hook.event == "UserPromptSubmit" && ancestry == Ancestry::Direct;
            if !ours && !start && self.pinned.is_some() && !prompt_first {
                continue;
            }
            if !ours
                && !start
                && let Some(at) = incoming
                    .iter()
                    .position(|h| h.event == "SessionStart" && h.session_id == hook.session_id)
            {
                // its SessionStart came in the same pass: that goes first
                let session_start = incoming.remove(at).unwrap();
                incoming.push_front(hook);
                incoming.push_front(session_start);
                continue;
            }
            let current = self.rollout.as_ref().map(|r| r.path().to_path_buf());
            if ours && current.as_deref() == Some(hook.transcript_path.as_path()) {
                if std::mem::take(&mut self.start_unseen) && hook.source == "startup" {
                    // the SessionStart of a session its prompt pinned
                    continue;
                }
                // compaction or a resume of the conversation being read
                out.push(AgentEvent::SessionStarted {
                    session_id: hook.session_id,
                    log_path: hook.transcript_path,
                    source: hook.source,
                    same_log: true,
                });
                continue;
            }
            if !rollout_path_ok(&self.codex_home, &hook.session_id, &hook.transcript_path) {
                self.notice(
                    "ignored a Codex hook whose rollout is not its session's under $CODEX_HOME/sessions",
                );
                continue;
            }
            if current.is_some() && !self.switch_waited {
                // Give this tick's poll_log the old rollout's last lines first
                // (its turn may have just ended).
                self.switch_waited = true;
                incoming.push_front(hook);
                self.held = incoming;
                break;
            }
            self.switch_waited = false;
            if !ours && self.turn_open {
                let same = self
                    .deferred
                    .as_ref()
                    .filter(|d| d.session_id == hook.session_id);
                match same {
                    // its SessionStart (or prompt) already waits: a start
                    // replaces a prompt, a prompt adds nothing
                    Some(d) => {
                        if start && d.event != "SessionStart" {
                            self.deferred = Some(hook);
                        }
                    }
                    None => {
                        self.notice(
                            "held a start of another Codex session until the current turn ends",
                        );
                        self.deferred = Some(hook);
                    }
                }
                continue;
            }
            // A hook other than SessionStart first: its SessionStart was
            // missed (not yet trusted, say); where it began is unknown.
            let source = if start {
                hook.source.clone()
            } else {
                String::new()
            };
            self.switch_to(hook.transcript_path.clone(), &source);
            if self.pinned.is_none() {
                // Pinned through a wrapper: its child (the real binary) is
                // the agent from now on.
                let ancestry = self.hook_agent.ancestry(hook.parent);
                self.hook_agent.pinned_by(ancestry);
            }
            self.pinned = Some(hook.session_id.clone());
            self.start_unseen = !start;
            self.turn_open = false;
            // The chat restarts at ready: queued status changes are moot,
            // a dialog of the old session is gone, and approvals still open
            // (the worker's count) wait again.
            self.extra.clear();
            self.dialogs.clear();
            self.calls.clear();
            self.calls_incomplete = None;
            if self.approvals > 0 {
                self.extra.push(waiting_event());
            }
            self.deferred = None;
            self.session_started = true;
            out.push(AgentEvent::SessionStarted {
                session_id: hook.session_id.clone(),
                log_path: hook.transcript_path.clone(),
                source,
                same_log: false,
            });
            if !start {
                self.map(hook, &mut out);
            }
        }
        out.append(&mut self.extra);
        out
    }

    fn poll_log(&mut self) -> Vec<LogItem> {
        let mut items = std::mem::take(&mut self.queued);
        if let Some(reader) = self.rollout.as_mut() {
            items.extend(reader.poll());
        }
        for item in &items {
            match item {
                LogItem::Problem {
                    detail,
                    fatal: true,
                } => {
                    self.withdrawn.get_or_insert_with(|| detail.clone());
                }
                LogItem::TurnStarted { .. } => self.turn_open = true,
                LogItem::TurnEnded { .. } => {
                    self.turn_open = false;
                    if let Some(deferred) = self.deferred.take() {
                        self.held.push_front(deferred);
                    }
                }
                _ => {}
            }
        }
        // Codex's dialogs are gone once a prompt went in or the turn was
        // interrupted. A reply, a command (maybe another call's) or a plain
        // turn end says nothing about them.
        let gone = items
            .iter()
            .filter_map(|i| match i {
                LogItem::UserMessage { created_at_ms, .. } => Some(*created_at_ms),
                LogItem::TurnEnded {
                    outcome: Outcome::Interrupted,
                    at_ms,
                    ..
                } => Some(*at_ms),
                _ => None,
            })
            .max();
        if let Some(at_ms) = gone {
            self.dialogs_gone(at_ms, None);
        }
        items
    }

    fn capabilities(&self) -> Capabilities {
        // Open before the first hook too (status unknown, submit refused
        // with `FIRST_PROMPT`); only a format change withdraws chat.
        Capabilities {
            chat_v1: self.withdrawn.is_none(),
            reason: self.withdrawn.clone(),
            unavailable: UNAVAILABLE,
        }
    }
}

impl Drop for CodexAdapter {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// One Codex hook's stdin, as far as the adapter uses it. Every Codex hook
/// names its session and rollout; one that doesn't is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    /// The hook's parent process (its event file's `$PPID`).
    pub parent: u32,
    /// When the hook wrote its event (the file's time, unix ms).
    pub at_ms: i64,
    pub event: String,
    pub session_id: String,
    pub transcript_path: PathBuf,
    /// SessionStart's `source` (`startup`, `resume`); else empty.
    pub source: String,
    /// UserPromptSubmit's `prompt`.
    pub prompt: Option<String>,
    /// The turn of a turn-scoped hook.
    pub turn_id: Option<String>,
    /// The event's sequence (`RawEvent::seq`).
    pub seq: u64,
    /// A tool hook's `tool_name`, `tool_input.command` and `tool_use_id`.
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub tool_use_id: Option<String>,
}

impl Hook {
    pub fn from_raw(raw: &RawEvent) -> Option<Hook> {
        let json = &raw.json;
        let s = |k: &str| json.get(k).and_then(Value::as_str);
        Some(Hook {
            parent: raw.parent,
            at_ms: raw.at_ms,
            seq: raw.seq,
            event: s("hook_event_name")?.to_string(),
            session_id: s("session_id")?.to_string(),
            transcript_path: PathBuf::from(s("transcript_path")?),
            source: s("source").unwrap_or_default().to_string(),
            prompt: s("prompt").map(str::to_string),
            turn_id: s("turn_id").map(str::to_string),
            tool_name: s("tool_name").map(str::to_string),
            tool_use_id: s("tool_use_id").map(str::to_string),
            command: json
                .pointer("/tool_input/command")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

/// One event file: the hook's `$$ $PPID` line, then its stdin JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct RawEvent {
    /// The hook script's own pid.
    pub pid: u32,
    /// Its parent (Codex, or the shell Codex ran it in).
    pub parent: u32,
    /// The file's time (unix ms): when the hook wrote it.
    pub at_ms: i64,
    /// Its sequence (the name's `<seq>`): the script's counter, taken
    /// under its lock, so publication order.
    pub seq: u64,
    pub json: Value,
}

/// `"<pid> <ppid>\n<json>"` as written by the hook script.
fn parse_event(text: &str, at_ms: i64, seq: u64) -> Option<RawEvent> {
    let (head, body) = text.split_once('\n')?;
    let mut ids = head.split(' ');
    let pid = ids.next()?.parse().ok()?;
    let parent = ids.next()?.parse().ok()?;
    if ids.next().is_some() {
        return None;
    }
    let json = serde_json::from_str::<Value>(body).ok()?;
    Some(RawEvent {
        pid,
        parent,
        at_ms,
        seq,
        json,
    })
}

/// Reads the hook script's `events/ev-<seq>-<Event>.json` files in (seq,
/// name) order (a repeated seq is fine), deleting each once read. Nothing
/// else there is read: `tmp.*` (being written; removed once stale), `seq`,
/// `seq.<pid>`, `seq.lock` (the script's).
pub struct EventReader {
    dir: PathBuf,
    /// Events read but unusable since the last `take_lost` (their names'
    /// `<Event>`): unreadable, too big, or not a hook's.
    unusable: Vec<String>,
    /// Pids of the hooks whose events were read lately: a start marker of
    /// one of them was published, not lost.
    published: VecDeque<u32>,
    /// More events were waiting than one poll reads.
    backlog: bool,
}

/// The seq of an `ev-<digits>-<Letters>.json` name.
fn event_seq(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("ev-")?.strip_suffix(".json")?;
    let (seq, event) = rest.split_once('-')?;
    let valid = !seq.is_empty()
        && seq.bytes().all(|b| b.is_ascii_digit())
        && !event.is_empty()
        && event.bytes().all(|b| b.is_ascii_alphabetic());
    valid.then(|| seq.parse().ok()).flatten()
}

fn stale(meta: &std::fs::Metadata, now: SystemTime) -> bool {
    meta.modified()
        .ok()
        .and_then(|t| now.duration_since(t).ok())
        .is_some_and(|age| age > LEFTOVER)
}

/// A regular file (never through a symlink) and its time (unix ms):
/// `Ok(None)` when larger than `MAX_EVENT`.
fn read_event(path: &Path) -> std::io::Result<Option<(String, i64)>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let at_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as i64);
    let mut text = String::new();
    file.take(MAX_EVENT + 1).read_to_string(&mut text)?;
    Ok((text.len() as u64 <= MAX_EVENT).then_some((text, at_ms)))
}

/// The `<Event>` of an `ev-<seq>-<Event>.json` name.
fn event_name(name: &str) -> Option<&str> {
    name.strip_prefix("ev-")?
        .strip_suffix(".json")?
        .split_once('-')
        .map(|(_, e)| e)
}

/// Pids remembered as published (`EventReader::published`).
const PUBLISHED_PIDS: usize = 4096;
/// A start marker this old is lost whatever its pid says (a reused pid):
/// beyond every synchronous hook's timeout.
const MARKER_LOST_AFTER: Duration = Duration::from_secs(30);

impl EventReader {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            unusable: Vec::new(),
            published: VecDeque::new(),
            backlog: false,
        }
    }

    /// The events lost since the last call (their `<Event>` names): read
    /// but unusable, and synchronous hooks that left their start marker
    /// (`start-<Event>.<pid>`) and died without publishing (killed, timed
    /// out, failed: Codex then went on as if they had run). Markers are
    /// judged only once every event published is read.
    pub fn take_lost(&mut self) -> Vec<String> {
        let mut lost = std::mem::take(&mut self.unusable);
        if self.backlog {
            return lost;
        }
        let Ok(rd) = std::fs::read_dir(self.dir.join("events")) else {
            return lost;
        };
        let now = SystemTime::now();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some((event, pid)) = name
                .strip_prefix("start-")
                .and_then(|r| r.split_once('.'))
                .and_then(|(ev, pid)| Some((ev.to_string(), pid.parse::<u32>().ok()?)))
            else {
                continue;
            };
            let old = std::fs::symlink_metadata(e.path())
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > MARKER_LOST_AFTER);
            // SAFETY: signal 0 only checks that the pid exists.
            let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
            if alive && !old {
                continue;
            }
            let _ = std::fs::remove_file(e.path());
            if !self.published.contains(&pid) {
                lost.push(event);
            }
        }
        lost
    }

    /// The events in order; `None` for one that was too big, had no
    /// `$$ $PPID` line or wasn't JSON (deleted all the same).
    pub fn poll(&mut self) -> Vec<Option<RawEvent>> {
        let Ok(rd) = std::fs::read_dir(self.dir.join("events")) else {
            return Vec::new();
        };
        let now = SystemTime::now();
        let mut files = Vec::new();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(seq) = event_seq(&name) {
                files.push((seq, name, e.path()));
            } else if name.starts_with("tmp.")
                && let Ok(meta) = std::fs::symlink_metadata(e.path())
                && meta.is_file()
                && stale(&meta, now)
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
        files.sort();
        self.backlog = files.len() > EVENTS_PER_POLL;
        files.truncate(EVENTS_PER_POLL);
        let mut out = Vec::new();
        for (seq, name, path) in files {
            let event = event_name(&name).unwrap_or_default().to_string();
            match read_event(&path) {
                Ok(text) => {
                    let _ = std::fs::remove_file(&path);
                    let raw = text.and_then(|(t, at_ms)| parse_event(&t, at_ms, seq));
                    match &raw {
                        Some(raw) => {
                            if self.published.len() >= PUBLISHED_PIDS {
                                self.published.pop_front();
                            }
                            self.published.push_back(raw.pid);
                        }
                        None => self.unusable.push(event),
                    }
                    out.push(raw);
                }
                Err(_) => {
                    // Unreadable: kept for now, dropped once stale; lost
                    // either way (a later event may depend on it).
                    self.unusable.push(event);
                    if std::fs::symlink_metadata(&path).is_ok_and(|m| stale(&m, now)) {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;

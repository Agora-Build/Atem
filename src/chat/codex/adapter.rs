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
//!   and whether it gave some back to Codex's own dialog ("no decision":
//!   input to Codex, no broker, a broker that doesn't know them)
//!   ([`CodexAdapter::set_approvals`]; its set is the only source of the
//!   first). Waiting while either holds: not waiting → waiting is
//!   `WaitingForPermission`, back `ToolFinished` (working), returned after
//!   that poll's hook events. Codex's own dialog counts until its
//!   PostToolUse or Interrupt hook, a Stop, a turn end or the turn's next
//!   rollout item (a re-pin drops it); after a re-pin with approvals
//!   open, `WaitingForPermission` again. A PreToolUse read while waiting is
//!   dropped (Codex holds the tool while the hook or its dialog waits).
//! - A format change in the rollout withdraws chat, as for Claude.
//!   Messages arrive whole, never streamed; [`UNAVAILABLE`] says so.

use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::Value;

use super::rollout::RolloutReader;
use crate::chat::adapter::{
    AgentAdapter, AgentEvent, Capabilities, LaunchPlan, LogItem, UNAVAILABLE_ALWAYS_ALLOW,
    UNAVAILABLE_ERROR_DETAILS, UNAVAILABLE_REASONING, UNAVAILABLE_STREAMING,
};
use crate::chat::approvals::{Ancestry, HookAgent};

/// Why a chat prompt is refused before Codex's first hook.
pub const FIRST_PROMPT: &str = "type a first prompt in the terminal: Codex reports nothing before it (and Atem's Codex hooks must be trusted in its /hooks)";
/// What Codex chat can't provide: no partial text (whole messages only),
/// no reasoning (encrypted), no persistent approval rule (Codex fails
/// closed), no model/API error details (none recorded).
pub const UNAVAILABLE: &[&str] = &[
    UNAVAILABLE_STREAMING,
    UNAVAILABLE_REASONING,
    UNAVAILABLE_ALWAYS_ALLOW,
    UNAVAILABLE_ERROR_DETAILS,
];
/// The status detail while an approval waits (`ChatSession` shows its own).
const APPROVAL_DETAIL: &str = "approve in the terminal";
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
    /// An approval was released ("no decision"): Codex shows its own
    /// dialog, so the status stays waiting until its PostToolUse or
    /// Interrupt hook, a turn end, or the turn's next rollout item.
    terminal_wait: bool,
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
            terminal_wait: false,
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
        self.set_approvals(n, false);
    }

    /// The worker's report after a pass: `open` approvals wait for a remote
    /// answer, and `released` says some of this session's were given back
    /// to Codex's own dialog ("no decision": input to Codex, no broker, a
    /// broker that doesn't know them). Waiting while either holds.
    pub fn set_approvals(&mut self, open: usize, released: bool) {
        let before = self.waiting();
        self.approvals = open;
        self.terminal_wait |= released;
        self.status_change(before);
    }

    /// Waiting for an approval: a remote answer or Codex's own dialog.
    fn waiting(&self) -> bool {
        self.approvals > 0 || self.terminal_wait
    }

    /// Codex's own dialog was answered (or the turn went on, or ended).
    fn end_terminal_wait(&mut self) {
        if self.terminal_wait {
            let before = self.waiting();
            self.terminal_wait = false;
            self.status_change(before);
        }
    }

    fn status_change(&mut self, before: bool) {
        match (before, self.waiting()) {
            (false, true) => self.extra.push(AgentEvent::WaitingForPermission {
                detail: APPROVAL_DETAIL.into(),
            }),
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
            // read now came before it.
            "PreToolUse" if !self.waiting() => out.push(AgentEvent::ToolStarted),
            "PostToolUse" => {
                // The tool ran: a dialog Codex showed was answered (its
                // `ToolFinished` is this one).
                self.terminal_wait = false;
                out.push(AgentEvent::ToolFinished);
            }
            // Only wake-ups for the reader (the rollout's end record is the
            // turn's end), but the turn is over: a deferred start may go,
            // and a dialog Codex showed is gone.
            "Stop" | "Interrupt" => {
                self.turn_open = false;
                self.end_terminal_wait();
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
        let mut incoming = std::mem::take(&mut self.held);
        let mut bad = 0;
        for raw in read {
            match raw.as_ref().and_then(Hook::from_raw) {
                Some(hook) => incoming.push_back(hook),
                None => bad += 1,
            }
        }
        if bad > 0 {
            self.notice("ignored a Codex hook event that could not be read");
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
            self.terminal_wait = false;
            if self.approvals > 0 {
                self.extra.push(AgentEvent::WaitingForPermission {
                    detail: APPROVAL_DETAIL.into(),
                });
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
        // The turn went on (or ended): a dialog Codex showed was answered.
        let went_on = items.iter().any(|i| {
            !matches!(
                i,
                LogItem::Problem { .. } | LogItem::Backfill(_) | LogItem::TurnStarted { .. }
            )
        });
        if went_on {
            self.end_terminal_wait();
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
}

impl Hook {
    pub fn from_raw(raw: &RawEvent) -> Option<Hook> {
        let json = &raw.json;
        let s = |k: &str| json.get(k).and_then(Value::as_str);
        Some(Hook {
            parent: raw.parent,
            at_ms: raw.at_ms,
            event: s("hook_event_name")?.to_string(),
            session_id: s("session_id")?.to_string(),
            transcript_path: PathBuf::from(s("transcript_path")?),
            source: s("source").unwrap_or_default().to_string(),
            prompt: s("prompt").map(str::to_string),
            turn_id: s("turn_id").map(str::to_string),
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
    pub json: Value,
}

/// `"<pid> <ppid>\n<json>"` as written by the hook script.
fn parse_event(text: &str, at_ms: i64) -> Option<RawEvent> {
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
        json,
    })
}

/// Reads the hook script's `events/ev-<seq>-<Event>.json` files in (seq,
/// name) order (a repeated seq is fine), deleting each once read. Nothing
/// else there is read: `tmp.*` (being written; removed once stale), `seq`,
/// `seq.<pid>`, `seq.lock` (the script's).
pub struct EventReader {
    dir: PathBuf,
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

impl EventReader {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
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
        files.truncate(EVENTS_PER_POLL);
        let mut out = Vec::new();
        for (_, _, path) in files {
            match read_event(&path) {
                Ok(text) => {
                    let _ = std::fs::remove_file(&path);
                    out.push(text.and_then(|(t, at_ms)| parse_event(&t, at_ms)));
                }
                Err(_) => {
                    // Unreadable: kept for now, dropped once stale.
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

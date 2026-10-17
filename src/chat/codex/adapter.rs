//! Codex adapter: Atem's Codex hooks (`approval_hook.sh event`, one
//! `ev-<seq>-<Event>.json` per hook in the session's `events/`) mark the
//! lifecycle, the rollout JSONL (`rollout.rs`) carries every message, turn
//! start and turn end (`designs/fixtures/codex-hooks/README.md`).
//!
//! - Session: Codex says nothing before its first prompt (SessionStart is
//!   lazy), so chat stays unavailable until the first hook with the reason
//!   [`FIRST_PROMPT`]: the first prompt is typed in the terminal (the
//!   2026-10-17 ruling: text typed into Codex's startup dialogs could
//!   answer them). The first hook pins its session (a missed SessionStart,
//!   e.g. a hook not yet trusted, is made up from it) and names the
//!   rollout, which must be `rollout-*-<session_id>.jsonl` under
//!   `$CODEX_HOME/sessions` (else the hook is ignored with a notice).
//! - Only the pinned session's hooks count. A SessionStart of another
//!   session re-pins (`/new` → `startup`, a resume of another conversation
//!   → `resume`): the old rollout is read to its end first (the switch
//!   waits one poll), a `startup` rollout is live from its first line,
//!   anything else is history (`Backfill`) up to a turn still running. A
//!   start of another session while the pinned one's turn runs is ignored
//!   with a notice: a `codex` run by a tool inside the turn has this
//!   session's environment too and would otherwise take the chat over (the
//!   event files carry no process ancestry, unlike approval requests).
//! - Status (`ChatSession`): `UserPromptSubmit` → working (and the hook
//!   half of a prompt's acceptance), PreToolUse/PostToolUse → tool events,
//!   the rollout's `task_started` → working, `task_complete` /
//!   `turn_aborted` → ready. Stop and Interrupt only wake the reader (the
//!   rollout's end record follows them and is authoritative), so they map
//!   to nothing, as do PreCompact/PostCompact (the compaction's own task
//!   does) and SessionEnd (the process exit is the worker's).
//! - Waiting: PermissionRequest never reaches `events/` (it is the
//!   approvals' own protocol, `runtime/worker_approvals.rs`), so the worker
//!   reports each approval it opens and closes for this session
//!   ([`CodexAdapter::approval_opened`], [`CodexAdapter::approval_closed`]):
//!   the first open is `WaitingForPermission`, the last close
//!   `ToolFinished` (back to working), both with the next `poll_events`.
//!   A turn's end forgets any still counted.
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

/// Why chat is unavailable before Codex's first hook.
pub const FIRST_PROMPT: &str = "type a first prompt in the terminal: Codex reports nothing before it (and Atem's Codex hooks must be trusted in Codex's /hooks)";
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
/// Largest event file read; a bigger one is dropped.
const MAX_EVENT: u64 = 1024 * 1024;
/// A `tmp.*` left by a killed hook, or an unreadable event file, goes
/// after this long.
const LEFTOVER: Duration = Duration::from_secs(60);

pub struct CodexAdapter {
    codex_home: PathBuf,
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
    /// Events returned first at the next `poll_events` (approvals).
    extra: Vec<AgentEvent>,
    /// The pinned session's turn runs (a prompt or a live `task_started`,
    /// no live turn end yet).
    turn_open: bool,
    /// Approvals open for this session (as the worker reported them).
    approvals: usize,
    session_started: bool,
    withdrawn: Option<String>,
}

impl CodexAdapter {
    /// An adapter reading rollouts under `codex_home` (`$CODEX_HOME` of the
    /// launch, else `~/.codex`).
    pub fn new(codex_home: PathBuf) -> Self {
        Self {
            codex_home,
            dir: None,
            events: None,
            rollout: None,
            pinned: None,
            held: VecDeque::new(),
            switch_waited: false,
            queued: Vec::new(),
            extra: Vec::new(),
            turn_open: false,
            approvals: 0,
            session_started: false,
            withdrawn: None,
        }
    }

    /// The session directory (`ATEM_APPROVAL_DIR`: `events/` for the hooks,
    /// `approvals/` for PermissionRequest).
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// The pinned Codex session (from its first hook).
    pub fn session_id(&self) -> Option<&str> {
        self.pinned.as_deref()
    }

    /// The worker opened an approval for this session (reported it): the
    /// first one makes the status waiting.
    pub fn approval_opened(&mut self) {
        self.approvals += 1;
        if self.approvals == 1 {
            self.extra.push(AgentEvent::WaitingForPermission {
                detail: APPROVAL_DETAIL.into(),
            });
        }
    }

    /// An approval of this session closed (answered, interrupted, timed
    /// out, released): after the last one the turn is working again.
    pub fn approval_closed(&mut self) {
        if self.approvals == 0 {
            return;
        }
        self.approvals -= 1;
        if self.approvals == 0 {
            self.extra.push(AgentEvent::ToolFinished);
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
    if path.starts_with(&sessions) && path != sessions {
        return true;
    }
    match (
        sessions.canonicalize(),
        path.parent().and_then(|p| p.canonicalize().ok()),
    ) {
        (Ok(sessions), Some(parent)) => parent.starts_with(sessions),
        _ => false,
    }
}

impl CodexAdapter {
    /// Read the old rollout to its end (normal items), then open `path`. A
    /// `startup` rollout (a new session, `/new`) is live from its first
    /// line; another's content already there is history, except a turn
    /// still running at its end (its prompt was just typed).
    fn switch_to(&mut self, path: PathBuf, source: &str) {
        if let Some(old) = self.rollout.as_mut() {
            self.queued.extend(old.poll());
        }
        let mut reader = RolloutReader::new(path);
        if source != "startup" {
            let items = reader.poll();
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
                    out.push(AgentEvent::PromptSubmitted { text });
                }
            }
            "PreToolUse" => out.push(AgentEvent::ToolStarted),
            "PostToolUse" => out.push(AgentEvent::ToolFinished),
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
        let mut out = std::mem::take(&mut self.extra);
        let Some(reader) = self.events.as_mut() else {
            return out;
        };
        let mut incoming = std::mem::take(&mut self.held);
        incoming.extend(reader.poll().iter().filter_map(Hook::parse));
        while let Some(hook) = incoming.pop_front() {
            let start = hook.event == "SessionStart";
            let ours = self.pinned.as_deref() == Some(hook.session_id.as_str());
            if ours && !start {
                self.map(hook, &mut out);
                continue;
            }
            if !ours && !start && self.pinned.is_some() {
                continue; // another session's (an old one's SessionEnd, a nested codex)
            }
            let current = self.rollout.as_ref().map(|r| r.path().to_path_buf());
            if ours && current.as_deref() == Some(hook.transcript_path.as_path()) {
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
                self.notice("ignored a start of another Codex session while a turn runs");
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
            self.pinned = Some(hook.session_id.clone());
            self.turn_open = false;
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
                    self.approvals = 0;
                }
                _ => {}
            }
        }
        items
    }

    fn capabilities(&self) -> Capabilities {
        let (chat_v1, reason) = match (&self.withdrawn, self.session_started) {
            (Some(reason), _) => (false, Some(reason.clone())),
            (None, true) => (true, None),
            (None, false) => (false, Some(FIRST_PROMPT.to_string())),
        };
        Capabilities {
            chat_v1,
            reason,
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
    pub event: String,
    pub session_id: String,
    pub transcript_path: PathBuf,
    /// SessionStart's `source` (`startup`, `resume`); else empty.
    pub source: String,
    /// UserPromptSubmit's `prompt`.
    pub prompt: Option<String>,
}

impl Hook {
    pub fn parse(json: &Value) -> Option<Hook> {
        let s = |k: &str| json.get(k).and_then(Value::as_str);
        Some(Hook {
            event: s("hook_event_name")?.to_string(),
            session_id: s("session_id")?.to_string(),
            transcript_path: PathBuf::from(s("transcript_path")?),
            source: s("source").unwrap_or_default().to_string(),
            prompt: s("prompt").map(str::to_string),
        })
    }
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

/// A regular file (never through a symlink): `Ok(None)` when larger than
/// `MAX_EVENT`.
fn read_event(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut text = String::new();
    file.take(MAX_EVENT + 1).read_to_string(&mut text)?;
    Ok((text.len() as u64 <= MAX_EVENT).then_some(text))
}

impl EventReader {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn poll(&mut self) -> Vec<Value> {
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
        let mut out = Vec::new();
        for (_, _, path) in files {
            match read_event(&path) {
                Ok(text) => {
                    let _ = std::fs::remove_file(&path);
                    if let Some(v) = text.and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
                        out.push(v);
                    }
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

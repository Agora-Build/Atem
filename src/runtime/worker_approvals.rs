//! The worker's side of approvals: the agent's `PermissionRequest` hook
//! (`chat::approvals`) writes `req-<id>.json` (its pid and parent pid in
//! `pid-<id>`) into the session's `approvals/` directory and waits for
//! `dec-<id>.json`. The worker reports each request to the broker
//! (`approval_request`, the card redacted), writes the broker's decision,
//! and reports how it ended.
//!
//! Who answered: the hook claims a decision by renaming `dec-<id>.json` to
//! `taken-<id>.json` (stamped with the claim time); the worker withdraws one
//! by renaming it as well, so exactly one side gets it. When the terminal
//! answers (below) while our decision waits, the worker withdraws it: if
//! that wins, the approval closes `answered_terminal` and the hook gets "no
//! decision"; if the hook won, the outcome is judged from what the agent
//! did (`approval_applied`):
//!
//! - `ok`: nothing contradicts the decision (Codex: always — it holds its
//!   prompt while the hook waits, so the terminal can't answer first;
//!   Claude: the tool ran after an allow, its result carries our deny
//!   message, the turn ended, or nothing else happened for a while);
//! - `unknown`: the tool ran after a deny, was refused in the terminal after
//!   an allow, or the terminal's answer predates the claim (more than
//!   100 ms) — the answers crossed;
//! - `not_delivered`: unknown or closed request, a rule that wasn't offered,
//!   the file couldn't be written, or our decision was withdrawn.
//!
//! The terminal answered (Claude, which shows its dialog while the hook
//! waits): the same tool with the same input ran (`post-<id>.json` from its
//! PostToolUse hook) or was refused (`LogItem::ToolResult` from the
//! transcript), a new prompt came or the turn ended → `answered_terminal`;
//! the turn was interrupted (Esc) → `interrupted`. The hook ended without a
//! decision (killed, or at its timeout) → `interrupted` / `timed_out`; the
//! agent exited → `process_ended`.
//!
//! "No decision" (an empty decision: the agent asks as usual) goes to every
//! waiting hook when the broker releases it, says which approvals it knows
//! (adoption), asks for `release_approvals` (any input to Codex), or goes
//! away; a reported one then closes `released`. A request arriving with no
//! broker connected is released at once, as is one that isn't this
//! session's: for Codex (whose hook command is the same for every session)
//! the hook's parent must be the session's agent — directly or through one
//! shell, when its Codex session becomes the pinned one (so `/new` inside
//! Codex keeps working) — or a non-shell child of the agent (a wrapper),
//! when it must be the pinned session; a request without a session id only
//! when the hook's parent is the agent itself; a `codex` started inside the
//! session through a shell never answers through it. A decision is handed
//! over only while the hook has more than 5 s left. Never an allow without
//! the broker's decision.

use crate::chat::adapter::ToolResultKind;
use crate::chat::approvals::{self, Agent, Request};
use crate::runtime::worker_protocol::ApplyOutcome;
use crate::session_protocol::host::ApprovalInfo;
use crate::session_protocol::wire::{ApprovalCloseReason, ApprovalDecision};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Leftovers (`tmp.*`, `withdrawn-*`) older than this are removed.
const LEFTOVER: Duration = Duration::from_secs(60);
/// A hook whose pid can't be checked counts as gone this long after its
/// timeout.
const GRACE: Duration = Duration::from_secs(30);
/// How long Claude's use of a taken decision is watched for a contradiction.
const CONFIRM: Duration = Duration::from_secs(3);
/// Terminal evidence this much older than the claim means the answers crossed.
const CROSSED_MS: i64 = 100;
/// A transcript result matches a request opened at most this much later.
const RESULT_SLACK_MS: i64 = 1000;
/// Largest request or post file read.
pub const MAX_FILE: u64 = 256 * 1024;
const SHELLS: [&str; 8] = ["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox"];

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Request {
        request_id: String,
        info: ApprovalInfo,
    },
    Closed {
        request_id: String,
        reason: ApprovalCloseReason,
    },
    Applied {
        request_id: String,
        outcome: ApplyOutcome,
    },
}

/// What the agent did, as the worker learns it besides the hook files.
#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    /// A tool call ended in an error result (Claude's transcript).
    Tool {
        tool_name: String,
        input: Value,
        kind: ToolResultKind,
        text: String,
        at_ms: i64,
    },
    /// A tool ran (Claude's PostToolUse, via `post-<id>.json`).
    Ran {
        tool_name: String,
        input: Value,
        at_ms: i64,
    },
    /// A new prompt or the turn's end; `interrupted`: the user stopped it.
    TurnEnded { interrupted: bool },
}

#[derive(Debug, Clone, PartialEq)]
enum State {
    /// Waiting for a decision.
    Open,
    /// Our decision is in `dec-<id>.json`, not taken yet.
    Decided { allow: bool, deny: Option<String> },
    /// The hook took it at `claim_ms`; watched until `until` (Claude).
    Claimed {
        allow: bool,
        deny: Option<String>,
        claim_ms: i64,
        until: Instant,
    },
    /// Done for the broker (released, closed or applied); only the files
    /// are left to clean up once the hook is gone.
    Released,
}

struct Waiting {
    request: Option<Request>,
    /// The hook's pid and its OS start time when read.
    pid: Option<(u32, Option<u64>)>,
    opened: Instant,
    /// The request file's time.
    opened_ms: i64,
    /// Sent to the broker.
    reported: bool,
    state: State,
}

pub struct Approvals {
    dir: PathBuf,
    agent: Agent,
    /// The session's agent process (the PTY child).
    agent_pid: Option<u32>,
    timeout: Duration,
    confirm: Duration,
    waiting: BTreeMap<String, Waiting>,
    /// Codex: the first session whose prompt this session reported.
    codex_session: Option<String>,
    /// Events produced outside `poll`, sent with its next result.
    queued: Vec<Event>,
}

fn is_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn mtime_ms(path: &Path) -> Option<i64> {
    let t = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_millis() as i64)
}

/// A regular file of at most `MAX_FILE` bytes, read whole.
fn read_capped(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_FILE + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= MAX_FILE).then_some(text)
}

fn hook_alive(pid: u32, start: Option<u64>) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    let exists = rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
    exists
        && match (start, super::adopt::process_start_time(pid)) {
            (Some(then), Some(now)) => then == now,
            _ => true,
        }
}

fn is_shell(name: &str) -> bool {
    SHELLS.contains(&name)
}

/// How a hook relates to the session's agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ancestry {
    /// Its parent is the agent, or a shell (that didn't exec) whose parent is.
    Direct,
    /// Through a non-shell child of the agent: a wrapper such as npm's
    /// `codex`, which runs the real binary as its child — or a `codex` the
    /// agent itself started without a shell. Ambiguous.
    Wrapped,
    /// Not started by the agent (e.g. a `codex` started inside the session
    /// through a shell is deeper).
    Foreign,
}

fn started_by(parent: u32, agent: u32) -> Ancestry {
    use super::adopt::process_parent_and_name;
    let mut q = parent;
    if q == agent {
        return Ancestry::Direct;
    }
    let Some((up, name)) = process_parent_and_name(q) else {
        return Ancestry::Foreign;
    };
    if is_shell(&name) {
        q = up;
        if q == agent {
            return Ancestry::Direct;
        }
    }
    match process_parent_and_name(q) {
        Some((up, name)) if !is_shell(&name) && up == agent => Ancestry::Wrapped,
        _ => Ancestry::Foreign,
    }
}

/// Equal tool inputs (serde_json's maps compare regardless of key order).
fn same_tool(r: &Request, tool_name: &str, input: &Value) -> bool {
    r.tool_name == tool_name && &r.tool_input == input
}

impl Approvals {
    /// Watches `<session_dir>/approvals` for `agent`'s hook; `agent_pid`
    /// is the session's agent process (Codex requests need it).
    pub fn new(session_dir: &Path, agent: Agent, agent_pid: Option<u32>) -> Self {
        Self {
            dir: approvals::approvals_dir(session_dir),
            agent,
            agent_pid,
            timeout: Duration::from_secs(agent.timeout_secs()),
            confirm: CONFIRM,
            waiting: BTreeMap::new(),
            codex_session: None,
            queued: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[cfg(test)]
    pub fn with_confirm(mut self, confirm: Duration) -> Self {
        self.confirm = confirm;
        self
    }

    /// How close to the hook's timeout counts as "at the timeout": 5 s
    /// (less for a short test timeout). No decision is handed over later,
    /// and a hook that ends then timed out.
    fn slack(&self) -> Duration {
        (self.timeout / 10).min(Duration::from_secs(5))
    }

    fn path(&self, prefix: &str, id: &str, suffix: &str) -> PathBuf {
        self.dir.join(format!("{prefix}-{id}{suffix}"))
    }

    fn write_decision(&self, id: &str, output: &str) -> bool {
        crate::runtime::worker::write_atomic(&self.path("dec", id, ".json"), output.as_bytes())
            .is_ok()
    }

    /// Takes our decision back unless the hook claimed it first.
    fn withdraw(&self, id: &str) -> bool {
        let withdrawn = self.path("withdrawn", id, ".json");
        let ok = std::fs::rename(self.path("dec", id, ".json"), &withdrawn).is_ok();
        let _ = std::fs::remove_file(&withdrawn);
        ok
    }

    /// The claim time of a taken decision, when taken: the mtime of
    /// `taken-<id>.json` (or `claimed-<id>` once the hook read it). Never
    /// removes anything: the hook may be between its `mv` and its `cat`;
    /// the files go once the hook is gone (`ended`).
    fn take_claim(&self, id: &str) -> Option<i64> {
        let taken = self.path("taken", id, ".json");
        let claimed = self.path("claimed", id, "");
        if let Some(at) = mtime_ms(&taken).or_else(|| mtime_ms(&claimed)) {
            return Some(at);
        }
        // Gone without a trace of the claim: it was claimed (now at the latest).
        (!self.path("dec", id, ".json").exists()).then(now_ms)
    }

    fn set(&mut self, id: &str, state: State) {
        if let Some(w) = self.waiting.get_mut(id) {
            w.state = state;
        }
    }

    /// "No decision" for `id`; a decision not taken yet is withdrawn first
    /// (`not_delivered`), a taken one is judged as it is. A reported open
    /// one closes `released`, so the broker drops its card even when the
    /// request crossed the release on the way.
    fn release_one(&mut self, id: &str) {
        let Some(w) = self.waiting.get(id) else {
            return;
        };
        let reported = w.reported;
        match w.state.clone() {
            State::Open => {
                self.write_decision(id, "");
                self.set(id, State::Released);
                if reported {
                    self.queued.push(Event::Closed {
                        request_id: id.into(),
                        reason: ApprovalCloseReason::Released,
                    });
                }
            }
            State::Decided { allow, deny } => {
                if self.withdraw(id) {
                    self.write_decision(id, "");
                    self.set(id, State::Released);
                    self.queued.push(Event::Applied {
                        request_id: id.into(),
                        outcome: ApplyOutcome::NotDelivered,
                    });
                } else {
                    self.claimed(id, allow, deny);
                }
            }
            State::Claimed { .. } | State::Released => {}
        }
    }

    /// The broker's `release_approval` (the host closed it): "no decision".
    pub fn release(&mut self, id: &str) {
        self.release_one(id);
    }

    /// `release_approvals` (input to Codex), or no broker: every waiting
    /// hook gets "no decision". The ones released now (their hooks may still
    /// be running for a moment).
    pub fn release_all(&mut self) -> Vec<String> {
        let ids: Vec<String> = self
            .waiting
            .iter()
            .filter(|(_, w)| matches!(w.state, State::Open | State::Decided { .. }))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            self.release_one(id);
        }
        ids
    }

    /// One of the hooks of `ids` is still running.
    pub fn hooks_running(&self, ids: &[String]) -> bool {
        ids.iter().any(|id| {
            self.waiting.get(id).is_some_and(|w| match w.pid {
                Some((pid, start)) => hook_alive(pid, start),
                None => false,
            })
        })
    }

    /// A broker (after adoption) knows only `known`: the rest are released.
    pub fn keep_only(&mut self, known: &[String]) {
        let ids: Vec<String> = self
            .waiting
            .keys()
            .filter(|id| !known.contains(id))
            .cloned()
            .collect();
        for id in ids {
            self.release_one(&id);
        }
    }

    /// The broker's decision for `id`. `Some(Applied{not_delivered})` when
    /// it can't be handed over; the outcome otherwise follows from `poll`.
    pub fn decide(
        &mut self,
        id: &str,
        decision: ApprovalDecision,
        rule_id: Option<&str>,
        message: Option<&str>,
    ) -> Option<Event> {
        let refused = Some(Event::Applied {
            request_id: id.to_string(),
            outcome: ApplyOutcome::NotDelivered,
        });
        let Some(w) = self.waiting.get(id) else {
            return refused;
        };
        // Too close to the hook's timeout: it may give up before it takes
        // the decision, which would then be reported as applied.
        if w.state != State::Open
            || !w.reported
            || w.opened.elapsed() + self.slack() >= self.timeout
        {
            return refused;
        }
        let Some(output) = w
            .request
            .as_ref()
            .and_then(|r| approvals::decision_output(r, decision, rule_id, message))
        else {
            return refused;
        };
        if !self.write_decision(id, &output) {
            return refused;
        }
        let deny = (decision == ApprovalDecision::Deny).then(|| {
            message
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .unwrap_or(approvals::DEFAULT_DENY)
                .to_string()
        });
        self.set(
            id,
            State::Decided {
                allow: decision != ApprovalDecision::Deny,
                deny,
            },
        );
        None
    }

    /// The agent exited: every hook released, the reported ones closed (a
    /// taken decision not yet confirmed: `unknown`).
    pub fn process_ended(&mut self) -> Vec<Event> {
        let mut out = std::mem::take(&mut self.queued);
        let ids: Vec<String> = self.waiting.keys().cloned().collect();
        for id in ids {
            let w = &self.waiting[&id];
            let reported = w.reported;
            match w.state.clone() {
                State::Open | State::Decided { .. } if reported => out.push(Event::Closed {
                    request_id: id.clone(),
                    reason: ApprovalCloseReason::ProcessEnded,
                }),
                State::Claimed { .. } => out.push(Event::Applied {
                    request_id: id.clone(),
                    outcome: ApplyOutcome::Unknown,
                }),
                _ => {}
            }
            if matches!(w.state, State::Open | State::Decided { .. }) {
                self.withdraw(&id);
                self.write_decision(&id, "");
            }
            self.set(&id, State::Released);
        }
        out
    }

    /// The hook took our decision: Codex applied it; Claude's use is
    /// watched for a contradiction until `confirm` passed.
    fn claimed(&mut self, id: &str, allow: bool, deny: Option<String>) {
        let claim_ms = self.take_claim(id).unwrap_or_else(now_ms);
        if self.agent == Agent::Codex {
            self.queued.push(Event::Applied {
                request_id: id.into(),
                outcome: ApplyOutcome::Ok,
            });
            self.set(id, State::Released);
        } else {
            self.set(
                id,
                State::Claimed {
                    allow,
                    deny,
                    claim_ms,
                    until: Instant::now() + self.confirm,
                },
            );
        }
    }

    /// Reads the directory — new requests (reported when `connected`, else
    /// released at once), decisions the hooks took, Claude's tool-ran notes
    /// — applies `evidence` (from the chat adapter), and finds hooks that
    /// ended.
    pub fn poll(&mut self, connected: bool, evidence: Vec<Evidence>) -> Vec<Event> {
        let mut out = std::mem::take(&mut self.queued);
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        let now = SystemTime::now();
        let mut new = Vec::new();
        let mut posts = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if let Some(id) = name
                .strip_prefix("req-")
                .and_then(|n| n.strip_suffix(".json"))
            {
                if is_id(id) && !self.waiting.contains_key(id) {
                    new.push(id.to_string());
                }
            } else if name.starts_with("post-") && name.ends_with(".json") {
                posts.push(path);
            } else if (name.starts_with("tmp.") || name.starts_with("withdrawn-"))
                && entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| now.duration_since(t).ok())
                    .is_some_and(|age| age > LEFTOVER)
            {
                let _ = std::fs::remove_file(&path);
            }
        }
        new.sort();
        for id in new {
            out.extend(self.open(&id, connected));
        }
        // Decisions the hooks took, before any evidence is weighed.
        let decided: Vec<(String, bool, Option<String>)> = self
            .waiting
            .iter()
            .filter_map(|(id, w)| match &w.state {
                State::Decided { allow, deny } => Some((id.clone(), *allow, deny.clone())),
                _ => None,
            })
            .collect();
        for (id, allow, deny) in decided {
            if !self.path("dec", &id, ".json").exists() {
                self.claimed(&id, allow, deny);
            }
        }
        out.append(&mut self.queued);
        let mut all = Vec::new();
        for path in posts {
            let ran = read_capped(&path).and_then(|t| serde_json::from_str::<Value>(&t).ok());
            let at_ms = mtime_ms(&path).unwrap_or_else(now_ms);
            let _ = std::fs::remove_file(&path);
            if self.agent != Agent::Claude {
                continue;
            }
            if let Some(ran) = ran
                && let Some(tool_name) = ran.get("tool_name").and_then(Value::as_str)
            {
                all.push(Evidence::Ran {
                    tool_name: tool_name.to_string(),
                    input: ran.get("tool_input").cloned().unwrap_or(Value::Null),
                    at_ms,
                });
            }
        }
        all.extend(evidence);
        for ev in all {
            self.weigh(ev, &mut out);
        }
        out.append(&mut self.queued);
        out.extend(self.ended());
        out
    }

    fn open(&mut self, id: &str, connected: bool) -> Option<Event> {
        let req_path = self.path("req", id, ".json");
        let opened_ms = mtime_ms(&req_path).unwrap_or_else(now_ms);
        let value = read_capped(&req_path).and_then(|t| serde_json::from_str::<Value>(&t).ok());
        let request = value
            .as_ref()
            .and_then(|v| approvals::request(self.agent, v));
        let ids: Vec<u32> = read_capped(&self.path("pid", id, ""))
            .map(|t| {
                t.split_whitespace()
                    .filter_map(|p| p.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        let pid = ids
            .first()
            .copied()
            .filter(|p| *p > 0)
            .map(|p| (p, super::adopt::process_start_time(p)));
        let ours = match self.agent {
            Agent::Claude => true,
            Agent::Codex => self.codex_owns(ids.get(1).copied(), value.as_ref()),
        };
        let info = request.as_ref().map(|r| r.info.clone());
        self.waiting.insert(
            id.to_string(),
            Waiting {
                request,
                pid,
                opened: Instant::now(),
                opened_ms,
                reported: false,
                state: State::Open,
            },
        );
        match info {
            Some(info) if connected && ours => {
                self.waiting.get_mut(id).unwrap().reported = true;
                Some(Event::Request {
                    request_id: id.to_string(),
                    info,
                })
            }
            _ => {
                self.release_one(id);
                None
            }
        }
    }

    /// A Codex request is this session's: its hook was started by the
    /// session's agent. Started directly, its Codex session becomes the
    /// pinned one (so `/new` inside Codex keeps working); through a
    /// non-shell child (ambiguous: a wrapper, or a nested `codex`) it must be
    /// the pinned session, or the first one seen. A request without a
    /// session id can't be matched: only a hook whose parent is the agent
    /// itself counts.
    fn codex_owns(&mut self, parent: Option<u32>, request: Option<&Value>) -> bool {
        let (Some(agent), Some(parent)) = (self.agent_pid, parent) else {
            return false;
        };
        let ancestry = started_by(parent, agent);
        if ancestry == Ancestry::Foreign {
            return false;
        }
        let session = request
            .and_then(|v| v.get("session_id"))
            .and_then(Value::as_str);
        match (session, ancestry) {
            // Without a session id only a hook the agent started itself.
            (None, Ancestry::Direct) => parent == agent,
            (None, _) => false,
            (Some(session), Ancestry::Direct) => {
                self.codex_session = Some(session.to_string());
                true
            }
            (Some(session), _) => match &self.codex_session {
                Some(pinned) => pinned == session,
                None => {
                    self.codex_session = Some(session.to_string());
                    true
                }
            },
        }
    }

    /// The request `ev` is about: the oldest open one with the same tool and
    /// input (opened by the evidence's time), else the oldest with our
    /// decision out.
    fn target(&self, tool_name: &str, input: &Value, at_ms: i64) -> Option<String> {
        let mut candidates: Vec<(&String, &Waiting)> = self
            .waiting
            .iter()
            .filter(|(_, w)| {
                w.state != State::Released
                    && w.opened_ms <= at_ms + RESULT_SLACK_MS
                    && w.request
                        .as_ref()
                        .is_some_and(|r| same_tool(r, tool_name, input))
            })
            .collect();
        candidates.sort_by_key(|(_, w)| (w.state != State::Open, w.opened));
        candidates.first().map(|(id, _)| (*id).clone())
    }

    fn weigh(&mut self, ev: Evidence, out: &mut Vec<Event>) {
        match &ev {
            Evidence::TurnEnded { .. } => {
                let ids: Vec<String> = self
                    .waiting
                    .iter()
                    .filter(|(_, w)| w.state != State::Released)
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in ids {
                    self.resolve(&id, &ev, out);
                }
            }
            Evidence::Tool {
                tool_name,
                input,
                at_ms,
                ..
            }
            | Evidence::Ran {
                tool_name,
                input,
                at_ms,
            } => {
                if let Some(id) = self.target(tool_name, input, *at_ms) {
                    self.resolve(&id, &ev, out);
                }
            }
        }
    }

    /// The terminal (or the agent) went on: a waiting request closes, our
    /// decision is withdrawn if the hook hasn't taken it, else judged.
    fn resolve(&mut self, id: &str, ev: &Evidence, out: &mut Vec<Event>) {
        let Some(w) = self.waiting.get(id) else {
            return;
        };
        let reported = w.reported;
        let reason = match ev {
            Evidence::TurnEnded { interrupted: true } => ApprovalCloseReason::Interrupted,
            _ => ApprovalCloseReason::AnsweredTerminal,
        };
        match w.state.clone() {
            State::Released => {}
            State::Open => {
                if reported {
                    out.push(Event::Closed {
                        request_id: id.into(),
                        reason,
                    });
                }
                self.write_decision(id, "");
                self.set(id, State::Released);
            }
            State::Decided { allow, deny } => {
                if self.withdraw(id) {
                    out.push(Event::Closed {
                        request_id: id.into(),
                        reason,
                    });
                    self.write_decision(id, "");
                    self.set(id, State::Released);
                } else {
                    self.claimed(id, allow, deny);
                    out.append(&mut self.queued);
                    self.resolve(id, ev, out);
                }
            }
            State::Claimed {
                allow,
                deny,
                claim_ms,
                ..
            } => {
                out.push(Event::Applied {
                    request_id: id.into(),
                    outcome: judge(allow, deny.as_deref(), claim_ms, ev),
                });
                self.set(id, State::Released);
            }
        }
    }

    /// Hooks that ended, and taken decisions nothing contradicted; their
    /// files go once nothing more is expected.
    fn ended(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        let mut done = Vec::new();
        let ids: Vec<String> = self.waiting.keys().cloned().collect();
        for id in ids {
            let w = &self.waiting[&id];
            let age = w.opened.elapsed();
            let alive = age < self.timeout + GRACE
                && match w.pid {
                    Some((pid, start)) => hook_alive(pid, start),
                    None => true,
                };
            let gone = if age + self.slack() >= self.timeout {
                ApprovalCloseReason::TimedOut
            } else {
                ApprovalCloseReason::Interrupted
            };
            match w.state.clone() {
                State::Open if !alive => {
                    if w.reported {
                        out.push(Event::Closed {
                            request_id: id.clone(),
                            reason: gone,
                        });
                    }
                    done.push(id);
                }
                // Ended without taking our decision (killed, or at its
                // timeout).
                State::Decided { allow, deny } if !alive => {
                    if self.withdraw(&id) {
                        out.push(Event::Closed {
                            request_id: id.clone(),
                            reason: gone,
                        });
                        done.push(id);
                    } else {
                        self.claimed(&id, allow, deny);
                        out.append(&mut self.queued);
                    }
                }
                State::Claimed { until, .. } if Instant::now() >= until => {
                    out.push(Event::Applied {
                        request_id: id.clone(),
                        outcome: ApplyOutcome::Ok,
                    });
                    self.set(&id, State::Released);
                }
                // Only once the hook is gone: it may still be reading.
                State::Released if !alive => {
                    done.push(id);
                }
                _ => {}
            }
        }
        for id in done {
            self.waiting.remove(&id);
            for (prefix, suffix) in [
                ("req", ".json"),
                ("pid", ""),
                ("dec", ".json"),
                ("taken", ".json"),
                ("claimed", ""),
            ] {
                let _ = std::fs::remove_file(self.path(prefix, &id, suffix));
            }
        }
        out
    }

    /// Requests not finished yet (tests and diagnostics).
    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }
}

/// What became of a decision the hook took at `claim_ms`, given what the
/// agent did next.
fn judge(allow: bool, deny: Option<&str>, claim_ms: i64, ev: &Evidence) -> ApplyOutcome {
    let (at_ms, carries_deny) = match ev {
        Evidence::TurnEnded { .. } => return ApplyOutcome::Ok,
        Evidence::Ran { at_ms, .. } => (*at_ms, false),
        Evidence::Tool { at_ms, text, .. } => (*at_ms, deny.is_some_and(|d| text.contains(d))),
    };
    if at_ms + CROSSED_MS < claim_ms {
        return ApplyOutcome::Unknown;
    }
    let consistent = match ev {
        Evidence::Ran { .. } => allow,
        Evidence::Tool { kind, .. } => {
            if allow {
                *kind == ToolResultKind::Failed
            } else {
                carries_deny
            }
        }
        Evidence::TurnEnded { .. } => true,
    };
    if consistent {
        ApplyOutcome::Ok
    } else {
        ApplyOutcome::Unknown
    }
}

#[cfg(test)]
#[path = "worker_approvals_tests.rs"]
mod tests;

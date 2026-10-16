//! The worker's side of approvals: the agent's `PermissionRequest` hook
//! (`chat::approvals`) writes `req-<id>.json` (and its pid in `pid-<id>`)
//! into the session's `approvals/` directory and waits for `dec-<id>.json`.
//! The worker reports each request to the broker (`approval_request`, the
//! card redacted), writes the broker's decision, and reports how it ended:
//!
//! - `approval_applied`: the hook took our decision (`ok`), or the decision
//!   couldn't be handed over (`ok: false`: unknown, already closed, a rule
//!   that wasn't offered).
//! - `approval_closed`: the hook ended without taking a decision — killed
//!   (Claude: Esc; Codex: never, it ends at its timeout) → `interrupted`,
//!   or at its timeout → `timed_out`; or the agent went on without us
//!   (Claude: the tool ran — `post-<id>.json` from its PostToolUse hook with
//!   the same tool and input — or the turn ended or a new prompt came) →
//!   `answered_terminal`; or the agent exited → `process_ended`. Codex holds
//!   its prompt while the hook waits, so the terminal can't answer first.
//!
//! "No decision" (an empty decision file: the agent asks as usual) goes to
//! every waiting hook when the broker releases it, says which approvals it
//! knows (adoption), asks for `release_approvals` (local input), or goes
//! away; a request arriving with no broker connected is released at once.
//! Never an allow without the broker's decision.

use crate::chat::approvals::{self, Agent, Request};
use crate::session_protocol::host::ApprovalInfo;
use crate::session_protocol::wire::{ApprovalCloseReason, ApprovalDecision};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Leftovers (`tmp.*`, unmatched `post-*`) older than this are removed.
const LEFTOVER: Duration = Duration::from_secs(60);
/// A hook whose pid can't be checked counts as gone this long after its
/// timeout.
const GRACE: Duration = Duration::from_secs(30);

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
        ok: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decided {
    /// The broker's decision is in `dec-<id>.json`.
    Remote,
    /// "No decision" was written; nothing more is reported.
    Released,
}

struct Waiting {
    request: Option<Request>,
    /// The hook's pid and its OS start time when read.
    pid: Option<(u32, Option<u64>)>,
    opened: Instant,
    /// Sent to the broker.
    reported: bool,
    decided: Option<Decided>,
    /// Closed for the broker; only the files remain to clean up.
    closed: bool,
}

pub struct Approvals {
    dir: PathBuf,
    agent: Agent,
    timeout: Duration,
    waiting: BTreeMap<String, Waiting>,
}

fn is_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
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

impl Approvals {
    /// Watches `<session_dir>/approvals` for `agent`'s hook.
    pub fn new(session_dir: &Path, agent: Agent) -> Self {
        Self {
            dir: approvals::approvals_dir(session_dir),
            agent,
            timeout: Duration::from_secs(agent.timeout_secs()),
            waiting: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn path(&self, prefix: &str, id: &str, suffix: &str) -> PathBuf {
        self.dir.join(format!("{prefix}-{id}{suffix}"))
    }

    fn write_decision(&self, id: &str, output: &str) -> bool {
        crate::runtime::worker::write_atomic(&self.path("dec", id, ".json"), output.as_bytes())
            .is_ok()
    }

    /// Writes "no decision" (unless a decision is already there).
    fn release_one(&mut self, id: &str) {
        let Some(w) = self.waiting.get(id) else {
            return;
        };
        if w.decided.is_some() {
            return;
        }
        self.write_decision(id, "");
        if let Some(w) = self.waiting.get_mut(id) {
            w.decided = Some(Decided::Released);
            w.closed = true;
        }
    }

    /// The broker's `release_approval` (e.g. the host closed it): "no
    /// decision", nothing reported back.
    pub fn release(&mut self, id: &str) {
        self.release_one(id);
    }

    /// `release_approvals` (local input), or no broker: every waiting hook
    /// gets "no decision".
    pub fn release_all(&mut self) {
        let ids: Vec<String> = self.waiting.keys().cloned().collect();
        for id in ids {
            self.release_one(&id);
        }
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

    /// The broker's decision for `id`. `Some(Applied{ok:false})` when it
    /// can't be handed over; the outcome otherwise follows from `poll`.
    pub fn decide(
        &mut self,
        id: &str,
        decision: ApprovalDecision,
        rule_id: Option<&str>,
        message: Option<&str>,
    ) -> Option<Event> {
        let refused = Some(Event::Applied {
            request_id: id.to_string(),
            ok: false,
        });
        let Some(w) = self.waiting.get(id) else {
            return refused;
        };
        if w.decided.is_some() || w.closed {
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
        self.waiting.get_mut(id).unwrap().decided = Some(Decided::Remote);
        None
    }

    /// Claude went on (a new prompt, or the turn ended): what still waits
    /// was answered in the terminal (or interrupted there).
    pub fn turn_moved_on(&mut self) -> Vec<Event> {
        self.answered_terminal(|_| true)
    }

    /// The agent exited: every hook released, reported ones closed.
    pub fn process_ended(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        let ids: Vec<String> = self.waiting.keys().cloned().collect();
        for id in ids {
            let w = &self.waiting[&id];
            if w.reported && !w.closed {
                out.push(Event::Closed {
                    request_id: id.clone(),
                    reason: ApprovalCloseReason::ProcessEnded,
                });
            }
            self.release_one(&id);
            if let Some(w) = self.waiting.get_mut(&id) {
                w.closed = true;
            }
        }
        out
    }

    fn answered_terminal(&mut self, matches: impl Fn(&Waiting) -> bool) -> Vec<Event> {
        let mut out = Vec::new();
        let ids: Vec<String> = self
            .waiting
            .iter()
            .filter(|(_, w)| !w.closed && matches(w))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if self.waiting[&id].reported {
                out.push(Event::Closed {
                    request_id: id.clone(),
                    reason: ApprovalCloseReason::AnsweredTerminal,
                });
            }
            self.release_one(&id);
            self.waiting.get_mut(&id).unwrap().closed = true;
        }
        out
    }

    /// Reads the directory: new requests (reported when `connected`, else
    /// released at once), Claude's tool-ran notes, and hooks that ended.
    pub fn poll(&mut self, connected: bool) -> Vec<Event> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        let now = std::time::SystemTime::now();
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
            } else if name.starts_with("tmp.")
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
        for path in posts {
            let ran = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok());
            let _ = std::fs::remove_file(&path);
            if self.agent != Agent::Claude {
                continue;
            }
            if let Some(ran) = ran {
                let tool = ran.get("tool_name").cloned().unwrap_or(Value::Null);
                let input = ran.get("tool_input").cloned().unwrap_or(Value::Null);
                out.extend(self.answered_terminal(|w| {
                    w.request.as_ref().is_some_and(|r| {
                        Value::String(r.tool_name.clone()) == tool && r.tool_input == input
                    })
                }));
            }
        }
        out.extend(self.ended());
        out
    }

    fn open(&mut self, id: &str, connected: bool) -> Option<Event> {
        let req = std::fs::read_to_string(self.path("req", id, ".json")).ok();
        let request = req
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| approvals::request(self.agent, &v));
        let pid = std::fs::read_to_string(self.path("pid", id, ""))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
            .filter(|p| *p > 0)
            .map(|p| (p, super::adopt::process_start_time(p)));
        let valid = request.is_some();
        let info = request.as_ref().map(|r| r.info.clone());
        self.waiting.insert(
            id.to_string(),
            Waiting {
                request,
                pid,
                opened: Instant::now(),
                reported: false,
                decided: None,
                closed: false,
            },
        );
        match info {
            Some(info) if connected && valid => {
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

    /// Hooks that took their decision or ended; their files go.
    fn ended(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        let mut done = Vec::new();
        for (id, w) in &mut self.waiting {
            let dec = self.dir.join(format!("dec-{id}.json"));
            let consumed = w.decided.is_some() && !dec.exists();
            let alive = match w.pid {
                Some((pid, start)) => hook_alive(pid, start),
                None => w.opened.elapsed() < self.timeout + GRACE,
            } && w.opened.elapsed() < self.timeout + GRACE;
            if consumed {
                if w.decided == Some(Decided::Remote) && !w.closed {
                    out.push(Event::Applied {
                        request_id: id.clone(),
                        ok: true,
                    });
                }
                done.push(id.clone());
            } else if !alive {
                if w.reported && !w.closed {
                    let age = w.opened.elapsed();
                    let slack = (self.timeout / 10).min(Duration::from_secs(5));
                    out.push(Event::Closed {
                        request_id: id.clone(),
                        reason: if w.decided.is_none() && age + slack >= self.timeout {
                            ApprovalCloseReason::TimedOut
                        } else {
                            ApprovalCloseReason::Interrupted
                        },
                    });
                }
                done.push(id.clone());
            }
        }
        for id in done {
            self.waiting.remove(&id);
            for (prefix, suffix) in [("req", ".json"), ("pid", ""), ("dec", ".json")] {
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

#[cfg(test)]
#[path = "worker_approvals_tests.rs"]
mod tests;

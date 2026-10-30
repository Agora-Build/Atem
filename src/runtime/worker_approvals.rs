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
//!
//! Atem session rules (Codex, r7.2): a Codex card for a shell command offers
//! "Always allow this command" (`approvals::SessionRule`). Once the hook
//! took an `allow_always` naming it, the worker keeps the rule for this
//! agent process (at most `MAX_SESSION_RULES`, else `RuleNotKept`; gone when
//! the process ends, kept across broker restarts since the worker owns it).
//! A later request of this session's pinned Codex (`codex_owns`; a nested or
//! foreign `codex` never) whose tool, full command and cwd are byte-equal to
//! a rule's is answered allow by the worker itself while a broker is
//! connected — no approval is opened — and reported `AutoAllowed`
//! (redacted). Each rule keeps the identity and trust generation it was
//! granted under (`RuleGrant`, from the decision; a decision without one
//! keeps nothing). A rule allows only while confirmed by the broker
//! connected now: one this broker granted is; after every new broker
//! connection all are unconfirmed (`unconfirm_rules`) and matching requests
//! ask as usual until the broker accepts the rules granted under its own
//! identity and trust (`confirm_rules`, which drops the others). The broker
//! can revoke a rule (`revoke`) or all of them (`revoke_all`: the host's
//! identity or trust changed); an allow written for a revoked rule that the
//! hook hasn't taken is withdrawn. Every change is reported as `Rules`.

use crate::chat::adapter::ToolResultKind;
use crate::chat::approvals::{self, Agent, Ancestry, HookAgent, Request, SessionRule};
use crate::runtime::worker_protocol::{ApplyOutcome, HeldRule, RuleGrant};
use crate::session_protocol::host::ApprovalInfo;
use crate::session_protocol::wire::{ApprovalCloseReason, ApprovalDecision, MAX_SESSION_RULES};
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
    /// Allowed by the session rule `rule_id` without asking (r7.2); `tool`
    /// and `summary` are redacted as on a card.
    AutoAllowed {
        request_id: String,
        rule_id: String,
        tool: String,
        summary: String,
    },
    /// The session's rules changed (the whole list).
    Rules(Vec<HeldRule>),
    /// The broker's `revoke_approval_rule`: whether the rule was active
    /// (never produced by `Approvals`; the worker reports it).
    RuleRevoked { rule_id: String, ok: bool },
    /// The hook took an `allow_always` choosing a session rule, but the
    /// session already holds `MAX_SESSION_RULES`: allowed once, not kept
    /// (reported before its `Applied`).
    RuleNotKept { request_id: String },
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
    /// `at_ms`: when the agent reported it (unix ms); it answers only a
    /// request opened by then (unknown: any).
    TurnEnded {
        interrupted: bool,
        at_ms: Option<i64>,
    },
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
    /// This session's agent started its hook (Codex; Claude: always).
    ours: bool,
    /// The session rule an `allow_always` decision chose and what it was
    /// granted under, kept once the hook took it.
    pending_rule: Option<(SessionRule, RuleGrant)>,
    /// The session rule whose allow the worker wrote for it (auto-allowed);
    /// revoking the rule withdraws that allow while the hook hasn't taken it.
    auto_rule: Option<String>,
    state: State,
}

pub struct Approvals {
    dir: PathBuf,
    agent: Agent,
    /// The session's agent process (the PTY child).
    /// Who a Codex hook must have been started by (`HookAgent`).
    hook_agent: HookAgent,
    timeout: Duration,
    confirm: Duration,
    waiting: BTreeMap<String, Waiting>,
    /// Codex: the first session whose prompt this session reported.
    codex_session: Option<String>,
    /// Events produced outside `poll`, sent with its next result.
    queued: Vec<Event>,
    /// Codex: this session's requests that got "no decision" since the
    /// last `take_released` (released, closed by a prompt or an interrupt,
    /// or their hook ended without one): Codex shows its own dialog for
    /// each.
    released: usize,
    /// Codex: the Atem session rules of this agent process, oldest first.
    rules: Vec<Kept>,
}

/// A session rule the worker keeps.
struct Kept {
    rule: SessionRule,
    granted_under: RuleGrant,
    /// Granted or accepted by the broker connected now: only then it allows.
    confirmed: bool,
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
            hook_agent: HookAgent::new(agent_pid),
            timeout: Duration::from_secs(agent.timeout_secs()),
            confirm: CONFIRM,
            waiting: BTreeMap::new(),
            codex_session: None,
            queued: Vec::new(),
            released: 0,
            rules: Vec::new(),
        }
    }

    /// The session rules, oldest first, with what each was granted under
    /// and whether the connected broker confirmed it.
    pub fn rules(&self) -> Vec<HeldRule> {
        self.rules
            .iter()
            .map(|r| HeldRule {
                rule: r.rule.rule.clone(),
                granted_under: r.granted_under.clone(),
                confirmed: r.confirmed,
            })
            .collect()
    }

    /// A new broker connected: no rule allows until it confirms it.
    pub fn unconfirm_rules(&mut self) {
        for r in &mut self.rules {
            r.confirmed = false;
        }
    }

    /// The broker accepted the unconfirmed rules `rule_ids` (granted under
    /// its identity and trust): they allow again. Every other unconfirmed
    /// rule is dropped; confirmed ones (granted by this broker meanwhile)
    /// stay.
    pub fn confirm_rules(&mut self, rule_ids: &[String]) {
        self.rules.retain_mut(|r| {
            if !r.confirmed {
                r.confirmed = rule_ids.contains(&r.rule.rule.rule_id);
            }
            r.confirmed
        });
    }

    /// Revokes the session rule `rule_id`; false when it isn't held.
    /// An allow it wrote that the hook hasn't taken yet is withdrawn ("no
    /// decision": Codex's own dialog asks).
    pub fn revoke(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.rule.rule.rule_id != rule_id);
        self.withdraw_auto(|r| r == rule_id);
        self.rules.len() != before
    }

    /// Drops every session rule (the host's identity or trust generation
    /// changed), withdrawing allows not yet taken, as `revoke`.
    pub fn revoke_all(&mut self) {
        self.rules.clear();
        self.withdraw_auto(|_| true);
    }

    /// Withdraws the not-yet-taken allows written for the rules `which`
    /// names: those hooks get "no decision" instead.
    fn withdraw_auto(&mut self, which: impl Fn(&str) -> bool) {
        let ids: Vec<String> = self
            .waiting
            .iter()
            .filter(|(_, w)| w.auto_rule.as_deref().is_some_and(&which))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Some(w) = self.waiting.get_mut(&id) {
                w.auto_rule = None;
            }
            if self.withdraw(&id) {
                self.write_decision(&id, "");
                let to_dialog = self.waiting.get(&id).is_some_and(|w| self.to_dialog(w));
                self.released += usize::from(to_dialog);
            }
        }
    }

    /// Keeps `rule`, granted under `granted_under`, confirmed (the hook
    /// took the `allow_always` that chose it); false when the session
    /// already holds as many as it may. One with the same matcher counts as
    /// kept: it takes the new grant and is confirmed.
    fn keep_rule(&mut self, rule: SessionRule, granted_under: RuleGrant) -> bool {
        if let Some(held) = self
            .rules
            .iter_mut()
            .find(|r| r.rule.matcher == rule.matcher)
        {
            if !held.confirmed || held.granted_under != granted_under {
                held.confirmed = true;
                held.granted_under = granted_under;
                self.queued.push(Event::Rules(self.rules()));
            }
            return true;
        }
        if self.rules.len() >= MAX_SESSION_RULES {
            eprintln!(
                "atem worker: session rule {} not kept: the session holds {MAX_SESSION_RULES}",
                rule.rule.rule_id
            );
            return false;
        }
        self.rules.push(Kept {
            rule,
            granted_under,
            confirmed: true,
        });
        self.queued.push(Event::Rules(self.rules()));
        true
    }

    /// The confirmed rule this request matches exactly, if any.
    fn matching_rule(&self, request: &Request) -> Option<&SessionRule> {
        let matcher = request.matcher.as_ref()?;
        self.rules
            .iter()
            .find(|r| r.confirmed && &r.rule.matcher == matcher)
            .map(|r| &r.rule)
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
        let to_dialog = self.to_dialog(w);
        match w.state.clone() {
            State::Open => {
                self.released += usize::from(to_dialog);
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
                    self.released += usize::from(to_dialog);
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

    /// Codex: this session's requests that got "no decision" (its own
    /// dialog shows them) since the last call.
    pub fn take_released(&mut self) -> usize {
        std::mem::take(&mut self.released)
    }

    /// Codex shows its own dialog once `w` gets no decision: only for this
    /// session's own Codex hooks.
    fn to_dialog(&self, w: &Waiting) -> bool {
        self.agent == Agent::Codex && w.ours
    }

    /// The person at the terminal says the approvals waiting were answered
    /// there, in the agent's own dialog (the prefix `a`): each hook gets "no
    /// decision" (our decision not taken yet is withdrawn) and a reported
    /// one closes `answered_terminal`. An explicit human assertion: nothing
    /// else ends a wait on the strength of the terminal.
    pub fn answered_here(&mut self) -> Vec<Event> {
        let ids: Vec<String> = self.waiting.keys().cloned().collect();
        let mut out = Vec::new();
        for id in ids {
            let Some(w) = self.waiting.get(&id) else {
                continue;
            };
            let reported = w.reported;
            let answered = match w.state.clone() {
                State::Open => true,
                State::Decided { .. } => self.withdraw(&id),
                State::Claimed { .. } | State::Released => false,
            };
            if answered {
                self.write_decision(&id, "");
                self.set(&id, State::Released);
                if reported {
                    out.push(Event::Closed {
                        request_id: id.clone(),
                        reason: ApprovalCloseReason::AnsweredTerminal,
                    });
                }
            }
        }
        out
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
    /// A session rule `rule_id` chooses is kept only with `granted_under`.
    pub fn decide(
        &mut self,
        id: &str,
        decision: ApprovalDecision,
        rule_id: Option<&str>,
        granted_under: Option<&RuleGrant>,
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
        let rule = w
            .request
            .as_ref()
            .and_then(|r| r.session_rule.clone())
            .filter(|r| {
                decision == ApprovalDecision::AllowAlways
                    && Some(r.rule.rule_id.as_str()) == rule_id
            })
            .zip(granted_under.cloned());
        if let Some(w) = self.waiting.get_mut(id) {
            w.pending_rule = rule;
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
            // A rule the full session couldn't keep is said before the
            // answer completes (its card is still known then).
            if let Some((rule, granted_under)) =
                self.waiting.get_mut(id).and_then(|w| w.pending_rule.take())
                && !self.keep_rule(rule, granted_under)
            {
                self.queued.push(Event::RuleNotKept {
                    request_id: id.into(),
                });
            }
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
        let mut request = value
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
        // A session rule allows it: only this session's pinned agent, only
        // while a broker is connected (it shows the note).
        let auto = request
            .as_ref()
            .filter(|_| connected && ours && self.agent == Agent::Codex)
            .and_then(|r| {
                let rule = self.matching_rule(r)?;
                Some(Event::AutoAllowed {
                    request_id: id.to_string(),
                    rule_id: rule.rule.rule_id.clone(),
                    tool: r.info.tool.clone(),
                    summary: r.info.summary.clone(),
                })
            });
        if let Some(r) = request.as_mut()
            && self.rules.len() >= MAX_SESSION_RULES
        {
            r.withdraw_session_rule();
        }
        let info = request.as_ref().map(|r| r.info.clone());
        self.waiting.insert(
            id.to_string(),
            Waiting {
                request,
                pid,
                opened: Instant::now(),
                opened_ms,
                reported: false,
                ours,
                pending_rule: None,
                auto_rule: None,
                state: State::Open,
            },
        );
        if let Some(event) = auto
            && self.write_decision(id, &approvals::allow_output())
        {
            // Done for the broker: the files go once the hook is gone.
            if let (Some(w), Event::AutoAllowed { rule_id, .. }) =
                (self.waiting.get_mut(id), &event)
            {
                w.auto_rule = Some(rule_id.clone());
            }
            self.set(id, State::Released);
            return Some(event);
        }
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
    /// the pinned session, or the first one seen — which makes that child
    /// (the real binary under npm's wrapper) the agent from then on
    /// (`HookAgent`). A request without a session id can't be matched: only
    /// a hook whose parent is the agent itself counts.
    fn codex_owns(&mut self, parent: Option<u32>, request: Option<&Value>) -> bool {
        let Some(parent) = parent else {
            return false;
        };
        let ancestry = self.hook_agent.ancestry(parent);
        if ancestry == Ancestry::Foreign {
            return false;
        }
        let session = request
            .and_then(|v| v.get("session_id"))
            .and_then(Value::as_str);
        match (session, ancestry) {
            // Without a session id only a hook the agent started itself.
            (None, Ancestry::Direct) => self.hook_agent.is_agent(parent),
            (None, _) => false,
            (Some(session), Ancestry::Direct) => {
                self.codex_session = Some(session.to_string());
                true
            }
            (Some(session), _) => match &self.codex_session {
                Some(pinned) => pinned == session,
                None => {
                    self.codex_session = Some(session.to_string());
                    self.hook_agent.pinned_by(ancestry);
                    true
                }
            },
        }
    }

    /// The request whose decision a tool result can judge: the only one
    /// with the same tool and input whose hook took Atem's decision
    /// (`Claimed`), opened by the result's time. A result never ends a wait
    /// (open, or our decision not taken yet): the agents' PermissionRequest
    /// names no call, so no result can be proven to be the asking call's.
    fn target(&self, tool_name: &str, input: &Value, at_ms: i64) -> Option<String> {
        let candidates: Vec<&String> = self
            .waiting
            .iter()
            .filter(|(_, w)| {
                matches!(w.state, State::Claimed { .. })
                    && w.opened_ms <= at_ms + RESULT_SLACK_MS
                    && w.request
                        .as_ref()
                        .is_some_and(|r| same_tool(r, tool_name, input))
            })
            .map(|(id, _)| id)
            .collect();
        match candidates[..] {
            [id] => Some(id.clone()),
            _ => None,
        }
    }

    fn weigh(&mut self, ev: Evidence, out: &mut Vec<Event>) {
        match &ev {
            Evidence::TurnEnded { at_ms, .. } => {
                // A request opened after it (read in the same pass) is not
                // what the turn's end or the new prompt answered. A
                // whole-second time (a filesystem keeping seconds) counts
                // to the end of its second.
                let at = at_ms.map(|at| if at % 1000 == 0 { at + 999 } else { at });
                let ids: Vec<String> = self
                    .waiting
                    .iter()
                    .filter(|(_, w)| {
                        w.state != State::Released && at.is_none_or(|at| at >= w.opened_ms)
                    })
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
            Evidence::TurnEnded {
                interrupted: true, ..
            } => ApprovalCloseReason::Interrupted,
            _ => ApprovalCloseReason::AnsweredTerminal,
        };
        // "No decision" after a prompt or a turn end (not a tool that ran):
        // Codex may show its own dialog for it.
        let to_dialog = self.to_dialog(w) && matches!(ev, Evidence::TurnEnded { .. });
        match w.state.clone() {
            State::Released => {}
            State::Open => {
                self.released += usize::from(to_dialog);
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
                    self.released += usize::from(to_dialog);
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
            // A Codex hook that ended without a decision: Codex shows its
            // own dialog.
            let to_dialog = self.to_dialog(w);
            match w.state.clone() {
                State::Open if !alive => {
                    self.released += usize::from(to_dialog);
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
                        self.released += usize::from(to_dialog);
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
                ("evseq", ""),
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

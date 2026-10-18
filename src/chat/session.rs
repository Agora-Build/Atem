//! Agent-neutral chat session: status, message history, prompt acceptance and the
//! checks a prompt must pass before it is pasted. It never reads the clock and never
//! touches the PTY; the App feeds it events and the current input count.
//!
//! Event ordering: the App feeds a tick's log items before that tick's hook
//! `TurnEnded`, so the normal case is log-then-hook and "the log's outcome wins"
//! (the log is in hand first). A hook `TurnEnded` that arrives alone is still
//! authoritative: it emits `Complete { Done }` and marks the turn completed; a later
//! log `TurnEnded` for that turn is ignored, so a turn never completes twice.
use crate::chat::adapter::{AgentEvent, ApprovalCard, LogItem, Outcome, Part};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// History kept per session (oldest evicted first; the newest always stays).
pub const MAX_HISTORY_MESSAGES: usize = 500;
pub const MAX_HISTORY_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUESTS: usize = 1000;
const MAX_MESSAGE_BYTES: usize = 131_072;
const MAX_PROMPT_BYTES: usize = 32_768;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const TRUNCATED: &str = "… (truncated)";
/// Reserved part id; adapters never produce ids with this prefix.
const TRUNCATED_ID: &str = "atem:truncated";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ready,
    Working,
    Waiting,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub since_ms: i64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub message_id: String,
    pub role: Role,
    pub origin: Option<Origin>,
    pub turn_id: String,
    pub request_id: Option<String>,
    pub created_at_ms: i64,
    pub parts: Vec<Part>,
}

impl ChatMessage {
    /// Approximate size: the sum of the part text lengths.
    fn bytes(&self) -> usize {
        self.parts.iter().map(part_bytes).sum()
    }
}

fn part_bytes(part: &Part) -> usize {
    match part {
        Part::Text { markdown, .. } => markdown.len(),
        Part::Tool { name, summary, .. } => name.len() + summary.len(),
        Part::Approval(card) => card.tool.len() + card.summary.len(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    Message(ChatMessage),
    Delta {
        message_id: String,
        part: Part,
    },
    Status(Status),
    Accepted {
        request_id: String,
    },
    Complete {
        turn_id: String,
        request_id: Option<String>,
        outcome: Outcome,
    },
    Error {
        text: String,
        request_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestState {
    Pending,
    Accepted,
    Completed { turn_id: String, outcome: Outcome },
    Failed(String),
}

#[derive(Debug)]
struct Pending {
    request_id: String,
    text: String,
    pasted_at: Option<Instant>,
    hook_seen: bool,
    log_seen: bool,
    /// The turn the agent named for the prompt (hook) and the turn of its
    /// log entry: both halves must agree when both are known.
    hook_turn: Option<String>,
    log_turn: Option<String>,
    /// When the paste was sent (unix ms). Only a hook and a log entry from
    /// after it can be this prompt's (a local prompt with the same text
    /// typed just before is not), and only the first of each: once one
    /// from after the paste was another prompt, nothing later pairs.
    pasted_ms: Option<i64>,
    hook_closed: bool,
    log_closed: bool,
}

impl Pending {
    /// A record made at `at_ms` (unix ms) can be this prompt's: not before
    /// the paste. A whole second (a filesystem or a log keeping seconds
    /// only) counts up to its end.
    fn after_paste(&self, at_ms: i64) -> bool {
        let at = if at_ms % 1000 == 0 {
            at_ms + 999
        } else {
            at_ms
        };
        self.pasted_ms.is_none_or(|pasted| at >= pasted)
    }
}

/// A chat session's state, for a broker that connects to a running agent's
/// worker (the worker's session is the authoritative one): status, the
/// input mark, the current and last completed turn, and the newest history.
/// Prompt acceptance in flight is not carried (it belongs to the broker that
/// submitted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatSnapshot {
    pub started: bool,
    pub exited: bool,
    pub state: State,
    pub since_ms: i64,
    pub detail: Option<String>,
    pub input_mark: u64,
    pub current_turn: Option<String>,
    pub last_completed: Option<String>,
    /// How `last_completed` ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_outcome: Option<Outcome>,
    pub history: Vec<ChatMessage>,
}

pub struct ChatSession {
    generation: String,
    status: Status,
    started: bool,
    exited: bool,
    history: VecDeque<ChatMessage>,
    /// Sum of `ChatMessage::bytes` over `history`.
    history_bytes: usize,
    requests: HashMap<String, RequestState>,
    request_order: VecDeque<String>,
    pending: Option<Pending>,
    /// Last request whose delivery timed out: a later matching transcript entry
    /// proves it was delivered, so its turn may still complete with its requestId.
    expired: Option<(String, String)>,
    input_mark: u64,
    current_turn: Option<(String, Option<String>)>,
    last_completed: Option<String>,
    last_outcome: Option<Outcome>,
}

/// Redact credential values (names are kept). See `memory::secrets::redact_secrets`.
pub fn redact(text: &str) -> String {
    crate::memory::secrets::redact_secrets(text)
}

/// Size and character rules for a prompt; the error text is shown to the user.
pub fn clean_prompt(text: &str) -> Result<&str, &'static str> {
    if text.len() > MAX_PROMPT_BYTES {
        return Err("prompt too long (max 32768 bytes)");
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err("prompt contains control characters");
    }
    if text.trim().is_empty() {
        return Err("prompt is empty");
    }
    // "/" runs a command (no hook fires, so no acceptance); "!" is shell mode,
    // which runs the command without a permission prompt.
    if matches!(text.trim_start().chars().next(), Some('/' | '!')) {
        return Err("commands and shell mode are not available from chat");
    }
    Ok(text)
}

/// The prompt as sent and as the agent recorded it: equal once trimmed,
/// or equal but for the length and kind of whitespace runs (an agent may
/// store a pasted prompt as several text blocks, which the adapter joins
/// with newlines).
fn same_prompt(a: &str, b: &str) -> bool {
    let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    a.trim() == b.trim() || squash(a) == squash(b)
}

fn truncate_at(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn redact_part(part: Part) -> Part {
    match part {
        Part::Text { id, markdown } => Part::Text {
            id,
            markdown: redact(&markdown),
        },
        Part::Tool { id, name, summary } => Part::Tool {
            id,
            name: redact(&name),
            summary: redact(&summary),
        },
        // Redacted by the runtime before the approval opened.
        Part::Approval(card) => Part::Approval(card),
    }
}

/// A user message: redacted, capped at 131 072 bytes (then a marker part).
fn user_message(
    id: String,
    turn_id: String,
    text: &str,
    request_id: Option<String>,
    created_at_ms: i64,
) -> ChatMessage {
    let mut text = redact(text);
    let cut = truncate_at(&text, MAX_MESSAGE_BYTES).len();
    let was_cut = cut < text.len();
    text.truncate(cut);
    let mut parts = vec![Part::Text {
        id: "text".into(),
        markdown: text,
    }];
    if was_cut {
        parts.push(truncated_marker());
    }
    ChatMessage {
        message_id: id,
        role: Role::User,
        origin: Some(if request_id.is_some() {
            Origin::Remote
        } else {
            Origin::Local
        }),
        turn_id,
        request_id,
        created_at_ms,
        parts,
    }
}

fn truncated_marker() -> Part {
    Part::Text {
        id: TRUNCATED_ID.into(),
        markdown: TRUNCATED.into(),
    }
}

impl ChatSession {
    pub fn new(generation: String, now_ms: i64) -> Self {
        Self {
            generation,
            status: Status {
                state: State::Unknown,
                since_ms: now_ms,
                detail: None,
            },
            started: false,
            exited: false,
            history: VecDeque::new(),
            history_bytes: 0,
            requests: HashMap::new(),
            request_order: VecDeque::new(),
            pending: None,
            expired: None,
            input_mark: 0,
            current_turn: None,
            last_completed: None,
            last_outcome: None,
        }
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// This session's state with at most `max_messages` / `max_bytes` of
    /// its newest history.
    pub fn snapshot(&self, max_messages: usize, max_bytes: usize) -> ChatSnapshot {
        ChatSnapshot {
            started: self.started,
            exited: self.exited,
            state: self.status.state,
            since_ms: self.status.since_ms,
            detail: self.status.detail.clone(),
            input_mark: self.input_mark,
            current_turn: self.current_turn.as_ref().map(|(t, _)| t.clone()),
            last_completed: self.last_completed.clone(),
            last_outcome: self.last_outcome,
            history: self.history(None, max_messages, max_bytes),
        }
    }

    /// A session continuing from `snapshot` under `generation`.
    pub fn restore(generation: String, snapshot: ChatSnapshot) -> Self {
        let mut session = Self::new(generation, snapshot.since_ms);
        session.started = snapshot.started;
        session.exited = snapshot.exited;
        session.status = Status {
            state: snapshot.state,
            since_ms: snapshot.since_ms,
            detail: snapshot.detail,
        };
        session.input_mark = snapshot.input_mark;
        session.current_turn = snapshot.current_turn.map(|t| (t, None));
        session.last_completed = snapshot.last_completed;
        session.last_outcome = snapshot.last_outcome;
        for message in snapshot.history {
            session.push_message(message);
        }
        session
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    /// The retained history, oldest first.
    pub fn retained(&self) -> impl Iterator<Item = &ChatMessage> {
        self.history.iter()
    }

    /// The retained user message that carried `request_id` (a remote
    /// prompt's), newest first.
    pub fn user_message_of(&self, request_id: &str) -> Option<&str> {
        self.history
            .iter()
            .rev()
            .find(|m| m.role == Role::User && m.request_id.as_deref() == Some(request_id))
            .map(|m| m.message_id.as_str())
    }

    /// `message_id` is still in the retained history of this generation (a
    /// valid `before`); `generation`, when the client names one, must be
    /// this session's.
    pub fn retains(&self, message_id: &str, generation: Option<&str>) -> bool {
        generation.is_none_or(|g| g == self.generation)
            && self.history.iter().any(|m| m.message_id == message_id)
    }

    /// Catches up with the worker's `snapshot` state (its history replaced
    /// this one's after items were dropped on the way): the turn the worker
    /// saw end completes here too (with its outcome), and status, the
    /// current turn and the input mark follow the worker's.
    pub fn catch_up(&mut self, snapshot: &ChatSnapshot) -> Vec<Out> {
        let mut out = Vec::new();
        if self.exited {
            return out;
        }
        self.started |= snapshot.started;
        if let Some(done) = &snapshot.last_completed
            && self.last_completed.as_ref() != Some(done)
        {
            let outcome = snapshot.last_outcome.unwrap_or(Outcome::Done);
            self.complete(done.clone(), outcome, &mut out);
        }
        match &snapshot.current_turn {
            Some(t) if self.current_turn.as_ref().is_none_or(|(c, _)| c != t) => {
                self.current_turn = Some((t.clone(), None));
            }
            _ => {}
        }
        self.input_mark = snapshot.input_mark;
        self.set_status(
            snapshot.state,
            snapshot.detail.as_deref(),
            snapshot.since_ms,
            &mut out,
        );
        out
    }

    /// The whole retained history replaced by `history` (the worker's, after
    /// its backlog dropped items); status, turns and requests stay.
    pub fn replace_history(&mut self, history: Vec<ChatMessage>) {
        self.history.clear();
        self.history_bytes = 0;
        for message in history {
            self.push_message(message);
        }
    }

    /// An approval card message the broker made (`approval_card`), kept in
    /// this (the worker's) history so a later broker gets it with the
    /// snapshot: replaces the message with its id, or is appended. Anything
    /// but one assistant message with exactly one approval part is ignored.
    pub fn put_card(&mut self, message: ChatMessage) -> bool {
        let card = message.role == Role::Assistant
            && message.message_id.starts_with("approval-")
            && matches!(message.parts.as_slice(), [Part::Approval(_)]);
        if !card {
            return false;
        }
        if let Some(m) = self
            .history
            .iter_mut()
            .find(|m| m.message_id == message.message_id)
        {
            let old = m.bytes();
            *m = message;
            let new = m.bytes();
            self.history_bytes = self.history_bytes - old + new;
            return true;
        }
        self.push_message(message);
        true
    }

    /// Every card still `pending` becomes `closed` with `note` (a broker
    /// restart released its approval): the changed messages.
    pub fn close_pending_cards(&mut self, note: &str) -> Vec<ChatMessage> {
        let mut changed = Vec::new();
        for m in self.history.iter_mut() {
            let old = m.bytes();
            let mut touched = false;
            for part in m.parts.iter_mut() {
                if let Part::Approval(card) = part
                    && card.state == crate::chat::adapter::ApprovalCardState::Pending
                {
                    card.state = crate::chat::adapter::ApprovalCardState::Closed;
                    card.note = Some(note.to_string());
                    touched = true;
                }
            }
            if touched {
                let new = m.bytes();
                self.history_bytes = self.history_bytes - old + new;
                changed.push(m.clone());
            }
        }
        changed
    }

    pub fn heartbeat(&self) -> Out {
        Out::Status(self.status.clone())
    }

    fn set_status(&mut self, state: State, detail: Option<&str>, now_ms: i64, out: &mut Vec<Out>) {
        let detail = detail.map(str::to_string);
        if self.status.state == state && self.status.detail == detail {
            return;
        }
        self.status = Status {
            state,
            since_ms: now_ms,
            detail,
        };
        out.push(Out::Status(self.status.clone()));
    }

    fn record(&mut self, request_id: &str, state: RequestState) {
        if self
            .requests
            .insert(request_id.to_string(), state)
            .is_none()
        {
            self.request_order.push_back(request_id.to_string());
            while self.request_order.len() > MAX_REQUESTS {
                if let Some(old) = self.request_order.pop_front() {
                    self.requests.remove(&old);
                }
            }
        }
    }

    fn live(&self) -> bool {
        self.started && !self.exited
    }

    pub fn on_event(&mut self, event: AgentEvent, now_ms: i64, input_count: u64) -> Vec<Out> {
        let mut out = Vec::new();
        if self.exited {
            return out;
        }
        match event {
            AgentEvent::SessionStarted {
                source, same_log, ..
            } => {
                // Compaction or a resume of the session being read (or another
                // start on that log mid-turn): the same conversation goes on, so
                // the turn, the pending prompt and the input mark stay. Startup,
                // /clear or another log start afresh.
                let in_turn = matches!(self.status.state, State::Working | State::Waiting)
                    || self.pending.is_some();
                let continues = match source.as_str() {
                    "startup" | "clear" => false,
                    "compact" | "resume" => true,
                    _ => in_turn,
                };
                if self.started && same_log && continues {
                    return out;
                }
                self.started = true;
                self.input_mark = input_count;
                self.set_status(State::Ready, None, now_ms, &mut out);
            }
            AgentEvent::PromptSubmitted {
                text,
                turn_id,
                at_ms,
            } => {
                // The first hook from after the paste whose turn isn't
                // known to be another decides.
                if let Some(p) = &mut self.pending
                    && !p.hook_seen
                    && !p.hook_closed
                    && at_ms.is_none_or(|at| p.after_paste(at))
                    && match (&p.log_turn, &turn_id) {
                        (Some(log), Some(hook)) => log == hook,
                        _ => true,
                    }
                {
                    p.hook_closed = true;
                    if same_prompt(&p.text, &text) {
                        p.hook_seen = true;
                        p.hook_turn = turn_id;
                    }
                }
                if self.live() {
                    self.set_status(State::Working, None, now_ms, &mut out);
                }
                self.check_accepted(&mut out);
            }
            AgentEvent::ToolStarted => {
                if self.live() {
                    self.set_status(State::Working, None, now_ms, &mut out);
                }
            }
            // A finished tool ends a permission wait (the user approved); otherwise
            // hooks may arrive out of order and it says nothing about the turn.
            AgentEvent::ToolFinished => {
                if self.live() && self.status.state == State::Waiting {
                    self.set_status(State::Working, None, now_ms, &mut out);
                }
            }
            AgentEvent::NotReady { detail } => {
                if !self.started {
                    self.set_status(State::Unknown, Some(&detail), now_ms, &mut out);
                }
            }
            AgentEvent::WaitingForPermission { .. } => {
                if self.live() {
                    self.set_status(
                        State::Waiting,
                        Some("approve in the terminal"),
                        now_ms,
                        &mut out,
                    );
                }
            }
            AgentEvent::TurnEnded { .. } if !self.started => {}
            AgentEvent::TurnEnded { .. } => {
                self.expired = None;
                let turn = self.current_turn.as_ref().map(|(t, _)| t.clone());
                if let Some(turn) = turn
                    && self.last_completed.as_deref() != Some(turn.as_str())
                {
                    self.complete(turn, Outcome::Done, &mut out);
                }
                self.input_mark = input_count;
                self.set_status(State::Ready, None, now_ms, &mut out);
            }
        }
        out
    }

    fn check_accepted(&mut self, out: &mut Vec<Out>) {
        let ready = self
            .pending
            .as_ref()
            .is_some_and(|p| p.hook_seen && p.log_seen);
        if ready {
            let p = self.pending.take().unwrap();
            self.record(&p.request_id, RequestState::Accepted);
            out.push(Out::Accepted {
                request_id: p.request_id,
            });
        }
    }

    /// A turn ended. One with neither a prompt nor a request (Codex's
    /// compaction) completes nothing a client asked for: no `Complete`.
    fn complete(&mut self, turn_id: String, outcome: Outcome, out: &mut Vec<Out>) {
        self.last_completed = Some(turn_id.clone());
        self.last_outcome = Some(outcome);
        let (prompted, request_id) = match &self.current_turn {
            Some((t, r)) if *t == turn_id => (true, r.clone()),
            _ => (false, None),
        };
        if !prompted {
            return;
        }
        if let Some(r) = &request_id {
            self.record(
                r,
                RequestState::Completed {
                    turn_id: turn_id.clone(),
                    outcome,
                },
            );
            if self.pending.as_ref().is_some_and(|p| p.request_id == *r) {
                self.pending = None;
            }
        }
        out.push(Out::Complete {
            turn_id,
            request_id,
            outcome,
        });
    }

    pub fn on_log(&mut self, item: LogItem, now_ms: i64, input_count: u64) -> Vec<Out> {
        let mut out = Vec::new();
        if self.exited {
            return out;
        }
        match item {
            LogItem::UserMessage {
                id,
                turn_id,
                text,
                created_at_ms,
            } => {
                let mut request_id = None;
                // The first log entry from after the paste whose turn isn't
                // known to be another decides.
                if let Some(p) = &mut self.pending
                    && !p.log_seen
                    && !p.log_closed
                    && p.after_paste(created_at_ms)
                    && p.hook_turn.as_ref().is_none_or(|t| *t == turn_id)
                {
                    p.log_closed = true;
                    if same_prompt(&p.text, &text) {
                        p.log_seen = true;
                        p.log_turn = Some(turn_id.clone());
                        request_id = Some(p.request_id.clone());
                    }
                }
                // The timed-out link may only match the NEXT user entry.
                let expired = self.expired.take();
                if request_id.is_none()
                    && let Some((rid, t)) = expired
                    && same_prompt(&t, &text)
                {
                    request_id = Some(rid);
                }
                let message = user_message(
                    id,
                    turn_id.clone(),
                    &text,
                    request_id.clone(),
                    created_at_ms,
                );
                self.current_turn = Some((turn_id, request_id));
                self.push_message(message.clone());
                out.push(Out::Message(message));
                self.check_accepted(&mut out);
            }
            LogItem::AssistantPart {
                message_id,
                part,
                turn_id,
                created_at_ms,
            } => {
                let part = redact_part(part);
                self.assistant_part(message_id, part, turn_id, created_at_ms, &mut out);
            }
            LogItem::TurnStarted { .. } => {
                if self.live() {
                    self.set_status(State::Working, None, now_ms, &mut out);
                }
            }
            LogItem::TurnEnded { .. } if !self.started => {}
            LogItem::TurnEnded {
                turn_id, outcome, ..
            } => {
                self.expired = None;
                if self.last_completed.as_deref() != Some(turn_id.as_str()) {
                    self.complete(turn_id, outcome, &mut out);
                }
                self.input_mark = input_count;
                self.set_status(State::Ready, None, now_ms, &mut out);
            }
            LogItem::Backfill(item) => self.on_backfill(*item),
            // The App handles problems (withdrawing chat when fatal); tool
            // results are the worker's (approvals).
            LogItem::Problem { .. } | LogItem::ToolResult { .. } => {}
        }
        out
    }

    fn push_message(&mut self, message: ChatMessage) {
        self.history_bytes += message.bytes();
        self.history.push_back(message);
        self.trim_history();
    }

    /// Evict the oldest messages beyond 500 messages or 8 MiB (the newest stays).
    fn trim_history(&mut self) {
        while self.history.len() > 1
            && (self.history.len() > MAX_HISTORY_MESSAGES || self.history_bytes > MAX_HISTORY_BYTES)
        {
            if let Some(old) = self.history.pop_front() {
                self.history_bytes -= old.bytes();
            }
        }
    }

    fn assistant_part(
        &mut self,
        message_id: String,
        mut part: Part,
        turn_id: String,
        created_at_ms: i64,
        out: &mut Vec<Out>,
    ) {
        let existing = self
            .history
            .iter()
            .rposition(|m| m.role == Role::Assistant && m.message_id == message_id);
        let size = existing.map_or(0, |i| self.history[i].bytes());
        if let Some(i) = existing {
            let m = &self.history[i];
            if m.parts
                .iter()
                .any(|p| p.id() == part.id() || p.id() == TRUNCATED_ID)
            {
                return; // repeat, or the message already stopped growing
            }
        }
        // Cap the message: keep what fits, then one final marker part.
        let mut marker = false;
        if size + part_bytes(&part) > MAX_MESSAGE_BYTES {
            marker = true;
            let room = MAX_MESSAGE_BYTES - size;
            match &mut part {
                Part::Text { markdown, .. } => {
                    let cut = truncate_at(markdown, room).len();
                    markdown.truncate(cut);
                }
                Part::Tool { .. } | Part::Approval(_) => {}
            }
        }
        let mut new_parts = Vec::new();
        let keep = !(marker && matches!(part, Part::Tool { .. }));
        if keep {
            new_parts.push(part);
        }
        if marker {
            new_parts.push(truncated_marker());
        }
        match existing {
            Some(i) => {
                for p in new_parts {
                    self.history_bytes += part_bytes(&p);
                    self.history[i].parts.push(p.clone());
                    out.push(Out::Delta {
                        message_id: message_id.clone(),
                        part: p,
                    });
                }
                self.trim_history();
            }
            None => {
                let request_id = match &self.current_turn {
                    Some((t, r)) if *t == turn_id => r.clone(),
                    _ => None,
                };
                let message = ChatMessage {
                    message_id,
                    role: Role::Assistant,
                    origin: None,
                    turn_id,
                    request_id,
                    created_at_ms,
                    parts: new_parts,
                };
                self.push_message(message.clone());
                out.push(Out::Message(message));
            }
        }
    }

    /// An approval card (r7 §6a) for this conversation: a new assistant
    /// message `approval-<approval_id>`, or the same message again with the
    /// card's new state (clients replace a message they have by its id).
    pub fn approval_card(&mut self, card: ApprovalCard, created_at_ms: i64) -> Out {
        let message_id = format!("approval-{}", card.approval_id);
        if let Some(m) = self.history.iter_mut().find(|m| m.message_id == message_id) {
            let old = m.bytes();
            m.parts = vec![Part::Approval(card)];
            let new = m.bytes();
            let message = m.clone();
            self.history_bytes = self.history_bytes - old + new;
            return Out::Message(message);
        }
        let turn_id = self
            .current_turn
            .as_ref()
            .map_or_else(|| "approval".to_string(), |(t, _)| t.clone());
        let message = ChatMessage {
            message_id,
            role: Role::Assistant,
            origin: None,
            turn_id,
            request_id: None,
            created_at_ms,
            parts: vec![Part::Approval(card)],
        };
        self.push_message(message.clone());
        Out::Message(message)
    }

    /// Terminal input (`input_count`) arrived since the last prompt was
    /// submitted: a draft that a pasted prompt or legacy input would submit.
    pub fn has_unsent_input(&self, input_count: u64) -> bool {
        input_count != self.input_mark
    }

    /// Validate and, if allowed, return the text to paste (the caller pastes it with
    /// `send_paste`). `Err` carries the `Out`s to send to the asking conversation; a
    /// repeated request that is still in flight has nothing new to report (empty vec).
    pub fn submit(
        &mut self,
        request_id: &str,
        generation: &str,
        text: &str,
        input_count: u64,
        remote_controlled: bool,
    ) -> Result<String, Vec<Out>> {
        let err = |text: &str| {
            Err(vec![Out::Error {
                text: text.to_string(),
                request_id: Some(request_id.to_string()),
            }])
        };
        if self.exited {
            return err("the agent exited; start it again");
        }
        if generation != self.generation {
            return err("the agent was restarted; reopen the chat");
        }
        if let Some(state) = self.requests.get(request_id) {
            return Err(match state {
                RequestState::Pending => Vec::new(),
                RequestState::Accepted => vec![Out::Accepted {
                    request_id: request_id.to_string(),
                }],
                RequestState::Completed { turn_id, outcome } => vec![
                    Out::Accepted {
                        request_id: request_id.to_string(),
                    },
                    Out::Complete {
                        turn_id: turn_id.clone(),
                        request_id: Some(request_id.to_string()),
                        outcome: *outcome,
                    },
                ],
                RequestState::Failed(text) => vec![Out::Error {
                    text: text.clone(),
                    request_id: Some(request_id.to_string()),
                }],
            });
        }
        let text = match clean_prompt(text) {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        if self.status.state == State::Unknown {
            let detail = self.status.detail.clone();
            return err(detail.as_deref().unwrap_or("chat is not ready yet"));
        }
        if self.status.state != State::Ready || self.pending.is_some() {
            return err("the agent is busy; wait for the current turn to finish");
        }
        if self.has_unsent_input(input_count) {
            return err("the terminal has unsent input; finish or clear it there");
        }
        if remote_controlled {
            return err("a terminal viewer has control; release it first");
        }
        self.expired = None;
        self.pending = Some(Pending {
            request_id: request_id.to_string(),
            text: text.to_string(),
            pasted_at: None,
            hook_seen: false,
            log_seen: false,
            hook_turn: None,
            log_turn: None,
            pasted_ms: None,
            hook_closed: false,
            log_closed: false,
        });
        self.record(request_id, RequestState::Pending);
        Ok(text.to_string())
    }

    /// Call right after a successful paste so the 10 s acceptance clock
    /// starts then; `sent_ms` (unix ms, taken right before the paste was
    /// sent) is what the agent's own records of the prompt must not
    /// predate.
    pub fn mark_pasted(&mut self, request_id: &str, now: Instant, sent_ms: i64) {
        if let Some(p) = &mut self.pending
            && p.request_id == request_id
        {
            p.pasted_at = Some(now);
            p.pasted_ms = Some(sent_ms);
        }
    }

    /// The paste itself failed (queue full): report it, never resend.
    pub fn paste_failed(&mut self, request_id: &str, reason: &str) -> Vec<Out> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.request_id == request_id)
        {
            self.pending = None;
        }
        self.record(request_id, RequestState::Failed(reason.to_string()));
        vec![Out::Error {
            text: reason.to_string(),
            request_id: Some(request_id.to_string()),
        }]
    }

    pub fn tick(&mut self, now: Instant) -> Vec<Out> {
        // A paste whose clock was not started (no `mark_pasted`) starts at the first tick.
        if let Some(p) = &mut self.pending {
            p.pasted_at.get_or_insert(now);
        }
        let expired = self.pending.as_ref().is_some_and(|p| {
            p.pasted_at
                .is_some_and(|t| now.saturating_duration_since(t) >= ACCEPT_TIMEOUT)
        });
        if !expired {
            return Vec::new();
        }
        let p = self.pending.take().unwrap();
        self.expired = Some((p.request_id.clone(), p.text.clone()));
        let text = "delivery unknown; check the terminal";
        self.record(&p.request_id, RequestState::Failed(text.into()));
        vec![Out::Error {
            text: text.into(),
            request_id: Some(p.request_id),
        }]
    }

    /// Whole messages, oldest first: the newest ones that fit `max_messages` and
    /// `max_bytes` (sum of part text lengths), strictly older than `before` when given
    /// (an unknown `before` gives nothing). The newest message is always included even
    /// if it alone exceeds `max_bytes` (messages are capped at 131 072 bytes).
    pub fn history(
        &self,
        before: Option<&str>,
        max_messages: usize,
        max_bytes: usize,
    ) -> Vec<ChatMessage> {
        self.page(before, max_messages, max_bytes, |_| true).0
    }

    /// `history` over the messages `keep` accepts only (the limits count
    /// those), and whether the page reaches the oldest retained one of them
    /// (the start: nothing older to ask for).
    pub fn page(
        &self,
        before: Option<&str>,
        max_messages: usize,
        max_bytes: usize,
        keep: impl Fn(&ChatMessage) -> bool,
    ) -> (Vec<ChatMessage>, bool) {
        let end = match before {
            None => self.history.len(),
            Some(id) => match self.history.iter().position(|m| m.message_id == id) {
                Some(i) => i,
                None => return (Vec::new(), true),
            },
        };
        let mut picked = Vec::new();
        let mut bytes = 0usize;
        let mut start = true;
        for m in self.history.iter().take(end).rev().filter(|m| keep(m)) {
            let size = m.bytes();
            if picked.len() >= max_messages || (!picked.is_empty() && bytes + size > max_bytes) {
                start = false;
                break;
            }
            bytes += size;
            picked.push(m.clone());
        }
        picked.reverse();
        (picked, start)
    }

    /// Content that was already in a log the adapter switched to (a resume of
    /// another session): it goes into history only. Nothing is sent, and status,
    /// the current turn, pending prompts and request records are left alone. The
    /// App closes open conversations afterwards so clients reload the history.
    pub fn on_backfill(&mut self, item: LogItem) {
        if self.exited {
            return;
        }
        let mut ignored = Vec::new();
        match item {
            LogItem::UserMessage {
                id,
                turn_id,
                text,
                created_at_ms,
            } => {
                // Resuming a session read earlier must not repeat its prompts.
                if self.history.iter().any(|m| m.message_id == id) {
                    return;
                }
                let message = user_message(id, turn_id, &text, None, created_at_ms);
                self.push_message(message);
            }
            LogItem::AssistantPart {
                message_id,
                part,
                turn_id,
                created_at_ms,
            } => {
                let part = redact_part(part);
                // Old turns carry no request id: pass a turn that is never current.
                let current = self.current_turn.take();
                self.assistant_part(message_id, part, turn_id, created_at_ms, &mut ignored);
                self.current_turn = current;
            }
            LogItem::Backfill(item) => self.on_backfill(*item),
            LogItem::TurnStarted { .. }
            | LogItem::TurnEnded { .. }
            | LogItem::Problem { .. }
            | LogItem::ToolResult { .. } => {}
        }
    }

    pub fn on_process_exit(&mut self, now_ms: i64) -> Vec<Out> {
        let mut out = Vec::new();
        if self.exited {
            return out;
        }
        self.exited = true;
        self.set_status(State::Unknown, None, now_ms, &mut out);
        let request_id = self.pending.take().map(|p| p.request_id);
        if let Some(r) = &request_id {
            self.record(r, RequestState::Failed("the agent exited".into()));
        }
        out.push(Out::Error {
            text: "the agent exited".into(),
            request_id,
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restored_session_continues_with_its_status_and_history() {
        let mut first = ChatSession::new("g1".into(), 0);
        first.on_event(started(), 1, 0);
        first.on_log(
            LogItem::UserMessage {
                id: "u1".into(),
                turn_id: "t1".into(),
                text: "hello".into(),
                created_at_ms: 2,
            },
            2,
            0,
        );
        first.on_log(
            LogItem::TurnEnded {
                turn_id: "t1".into(),
                outcome: Outcome::Done,
                at_ms: 3,
            },
            3,
            1,
        );
        let snapshot = first.snapshot(50, 1024 * 1024);
        let wire: ChatSnapshot =
            serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap();
        let mut restored = ChatSession::restore("g2".into(), wire);
        assert_eq!(restored.generation(), "g2");
        assert_eq!(restored.status().state, State::Ready);
        assert_eq!(restored.history(None, 50, 1024 * 1024).len(), 1);
        // A new prompt is accepted at once (ready, no draft).
        assert!(restored.submit("r1", "g2", "next", 1, false).is_ok());
    }
    use std::path::PathBuf;

    fn started() -> AgentEvent {
        AgentEvent::SessionStarted {
            session_id: "s".into(),
            log_path: PathBuf::from("/x"),
            source: "startup".into(),
            same_log: false,
        }
    }
    fn ready() -> ChatSession {
        let mut s = ChatSession::new("g1".into(), 0);
        s.on_event(started(), 1, 0);
        s
    }
    fn user(id: &str, turn: &str, text: &str) -> LogItem {
        LogItem::UserMessage {
            id: id.into(),
            turn_id: turn.into(),
            text: text.into(),
            created_at_ms: 5,
        }
    }
    fn text_part(id: &str, t: &str) -> Part {
        Part::Text {
            id: id.into(),
            markdown: t.into(),
        }
    }
    fn asst(mid: &str, part: Part, turn: &str) -> LogItem {
        LogItem::AssistantPart {
            message_id: mid.into(),
            part,
            turn_id: turn.into(),
            created_at_ms: 6,
        }
    }
    fn end(turn: &str, outcome: Outcome) -> LogItem {
        LogItem::TurnEnded {
            turn_id: turn.into(),
            outcome,
            at_ms: 6,
        }
    }
    fn completes(outs: &[Out]) -> Vec<&Out> {
        outs.iter()
            .filter(|o| matches!(o, Out::Complete { .. }))
            .collect()
    }
    fn err_text(r: Result<String, Vec<Out>>) -> String {
        match r.unwrap_err().remove(0) {
            Out::Error { text, .. } => text,
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn an_approval_card_is_one_message_replaced_as_its_state_changes() {
        use crate::chat::adapter::{ApprovalCard, ApprovalCardState};
        let mut s = ready();
        let card = |state| ApprovalCard {
            id: "approval".into(),
            approval_id: "a1".into(),
            tool: "Bash".into(),
            summary: "npm test".into(),
            always_rules: vec![],
            state,
            rule_id: None,
            note: None,
            reason: None,
        };
        let Out::Message(first) = s.approval_card(card(ApprovalCardState::Pending), 5) else {
            panic!()
        };
        assert_eq!(first.message_id, "approval-a1");
        assert_eq!(first.role, Role::Assistant);
        let Out::Message(again) = s.approval_card(card(ApprovalCardState::Denied), 9) else {
            panic!()
        };
        assert_eq!(again.message_id, first.message_id);
        assert_eq!(again.created_at_ms, 5, "the same message");
        let history = s.history(None, 50, 1 << 20);
        let cards: Vec<&ChatMessage> = history
            .iter()
            .filter(|m| m.message_id == "approval-a1")
            .collect();
        assert_eq!(cards.len(), 1);
        assert_eq!(
            cards[0].parts,
            vec![Part::Approval(card(ApprovalCardState::Denied))]
        );
    }

    #[test]
    fn a_log_turn_start_means_working() {
        let start = || LogItem::TurnStarted {
            turn_id: "t".into(),
        };
        let mut s = ChatSession::new("g".into(), 0);
        assert!(s.on_log(start(), 1, 0).is_empty(), "not started yet");
        s.on_event(started(), 2, 0);
        s.on_backfill(start());
        assert_eq!(s.status().state, State::Ready, "history only");
        assert_eq!(
            s.on_log(start(), 3, 0),
            vec![Out::Status(Status {
                state: State::Working,
                since_ms: 3,
                detail: None
            })]
        );
        // a turn without a prompt (compaction): no Complete, ready again
        let o = s.on_log(end("t", Outcome::Done), 4, 0);
        assert!(
            !o.iter().any(|o| matches!(o, Out::Complete { .. })),
            "{o:?}"
        );
        assert_eq!(s.status().state, State::Ready);
        assert!(s.history(None, 50, 1 << 20).is_empty());
        // a prompted turn still completes
        s.on_log(user("u1", "t2", "go"), 5, 0);
        let o = s.on_log(end("t2", Outcome::Done), 6, 0);
        assert!(o.contains(&Out::Complete {
            turn_id: "t2".into(),
            request_id: None,
            outcome: Outcome::Done
        }));
    }

    #[test]
    fn a_local_prompt_from_before_the_paste_never_satisfies_a_remote_one() {
        let hook = |turn: &str, text: &str, at: i64| AgentEvent::PromptSubmitted {
            text: text.into(),
            turn_id: Some(turn.into()),
            at_ms: Some(at),
        };
        let user_at = |id: &str, turn: &str, text: &str, at: i64| LogItem::UserMessage {
            id: id.into(),
            turn_id: turn.into(),
            text: text.into(),
            created_at_ms: at,
        };
        let accepted = |o: &[Out]| o.iter().any(|o| matches!(o, Out::Accepted { .. }));
        // Hook first: the same text typed in the terminal just before the
        // paste (its hook and log entry predate it) is a local turn.
        let mut s = ready();
        s.submit("r", "g1", "go", 0, false).unwrap();
        s.mark_pasted("r", Instant::now(), 1000);
        assert!(!accepted(&s.on_event(hook("L", "go", 990), 2, 0)));
        let o = s.on_log(user_at("uL", "L", "go", 995), 3, 0);
        assert!(!accepted(&o));
        assert!(o.iter().any(|o| matches!(o, Out::Message(m)
            if m.origin == Some(Origin::Local) && m.request_id.is_none())));
        // The remote prompt's own records come after it.
        assert!(!accepted(&s.on_event(hook("R", "go", 1010), 4, 0)));
        let o = s.on_log(user_at("uR", "R", "go", 1020), 5, 0);
        assert!(o.contains(&Out::Accepted {
            request_id: "r".into()
        }));
        // Log first (the hook's turn not known yet): the same.
        let mut s = ready();
        s.submit("r", "g1", "go", 0, false).unwrap();
        s.mark_pasted("r", Instant::now(), 1000);
        let o = s.on_log(user_at("uL", "L", "go", 999), 2, 0);
        assert!(!accepted(&o));
        assert!(
            o.iter()
                .any(|o| matches!(o, Out::Message(m) if m.request_id.is_none()))
        );
        assert!(!accepted(&s.on_event(hook("L", "go", 998), 3, 0)));
        s.on_log(user_at("uR", "R", "go", 1001), 4, 0);
        assert!(accepted(&s.on_event(hook("R", "go", 1000), 5, 0)));
        // Only the first turn from after the paste: another prompt there
        // means the pasted one wasn't submitted (yet); a later turn with
        // its text is not paired.
        let mut s = ready();
        s.submit("r", "g1", "go", 0, false).unwrap();
        s.mark_pasted("r", Instant::now(), 1000);
        s.on_event(hook("X", "other", 1005), 2, 0);
        s.on_log(user_at("uX", "X", "other", 1006), 3, 0);
        s.on_event(hook("Y", "go", 1010), 4, 0);
        let o = s.on_log(user_at("uY", "Y", "go", 1011), 5, 0);
        assert!(!accepted(&o));
        assert!(
            o.iter()
                .any(|o| matches!(o, Out::Message(m) if m.request_id.is_none()))
        );
    }

    #[test]
    fn a_whole_second_time_counts_to_the_end_of_its_second() {
        let mut s = ready();
        s.submit("r", "g1", "go", 0, false).unwrap();
        s.mark_pasted("r", Instant::now(), 2500);
        // a filesystem keeping seconds: the hook's file says 2000
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "go".into(),
                turn_id: None,
                at_ms: Some(2000),
            },
            1,
            0,
        );
        let o = s.on_log(
            LogItem::UserMessage {
                id: "u".into(),
                turn_id: "t".into(),
                text: "go".into(),
                created_at_ms: 2501,
            },
            2,
            0,
        );
        assert!(o.contains(&Out::Accepted {
            request_id: "r".into()
        }));
    }

    #[test]
    fn acceptance_needs_the_hooks_turn() {
        let hook = |turn: &str| AgentEvent::PromptSubmitted {
            text: "go".into(),
            turn_id: Some(turn.into()),
            at_ms: None,
        };
        let mut s = ChatSession::new("g".into(), 0);
        s.on_event(started(), 1, 0);
        s.submit("r", "g", "go", 0, false).unwrap();
        // the remote prompt's hook names turn R; a local prompt with the
        // same text logged in turn L is not it
        s.on_event(hook("R"), 2, 0);
        let o = s.on_log(user("uL", "L", "go"), 3, 0);
        assert!(!o.iter().any(|o| matches!(o, Out::Accepted { .. })));
        assert!(o.iter().any(|o| matches!(o, Out::Message(m)
            if m.origin == Some(Origin::Local) && m.request_id.is_none())));
        let o = s.on_log(user("uR", "R", "go"), 4, 0);
        assert!(o.contains(&Out::Accepted {
            request_id: "r".into()
        }));
        // log first: the hook must name the logged turn
        let mut s = ChatSession::new("g".into(), 0);
        s.on_event(started(), 1, 0);
        s.submit("r", "g", "go", 0, false).unwrap();
        s.on_log(user("uR", "R", "go"), 2, 0);
        let o = s.on_event(hook("L"), 3, 0);
        assert!(!o.iter().any(|o| matches!(o, Out::Accepted { .. })));
        let o = s.on_event(hook("R"), 4, 0);
        assert!(o.contains(&Out::Accepted {
            request_id: "r".into()
        }));
    }

    #[test]
    fn prompts_compare_whitespace_blind() {
        assert!(same_prompt("a b\nc ", "a b\nc"));
        assert!(same_prompt("two\nlines", "two\n\nlines"));
        assert!(!same_prompt("ab", "a c"));
        // whitespace runs are one space, never nothing
        assert!(!same_prompt("ab", "a b"));
        assert!(same_prompt("a  b", "a\n\tb"));
    }

    #[test]
    fn status_table() {
        let mut s = ChatSession::new("g".into(), 0);
        assert_eq!(s.status().state, State::Unknown);
        // events before a session started do not change status
        assert!(s.on_event(AgentEvent::ToolStarted, 1, 0).is_empty());
        // a turn end before the session started neither sets Ready nor the input mark
        assert!(
            s.on_event(AgentEvent::TurnEnded { at_ms: None }, 1, 9)
                .is_empty()
        );
        assert!(s.on_log(end("t", Outcome::Done), 1, 9).is_empty());
        assert_eq!(s.status().state, State::Unknown);
        assert!(
            s.on_event(
                AgentEvent::PromptSubmitted {
                    text: "x".into(),
                    turn_id: None,
                    at_ms: None,
                },
                1,
                0
            )
            .is_empty()
        );
        let o = s.on_event(started(), 10, 0);
        assert_eq!(
            o,
            vec![Out::Status(Status {
                state: State::Ready,
                since_ms: 10,
                detail: None
            })]
        );
        // repeated Ready is no change
        assert!(
            s.on_event(AgentEvent::TurnEnded { at_ms: None }, 11, 0)
                .is_empty()
        );
        assert_eq!(s.status().since_ms, 10);
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "x".into(),
                turn_id: None,
                at_ms: None,
            },
            20,
            0,
        );
        assert_eq!(
            (s.status().state, s.status().since_ms),
            (State::Working, 20)
        );
        assert!(s.on_event(AgentEvent::ToolStarted, 21, 0).is_empty());
        // ToolFinished while Working changes nothing
        assert!(s.on_event(AgentEvent::ToolFinished, 22, 0).is_empty());
        let o = s.on_event(
            AgentEvent::WaitingForPermission {
                detail: "raw secret text".into(),
            },
            30,
            0,
        );
        assert_eq!(s.status().state, State::Waiting);
        assert_eq!(
            s.status().detail.as_deref(),
            Some("approve in the terminal")
        );
        assert_eq!(o.len(), 1);
        // approval given: the tool finished, the agent works again
        s.on_event(AgentEvent::ToolFinished, 31, 0);
        assert_eq!(
            (s.status().state, s.status().since_ms),
            (State::Working, 31)
        );
        assert_eq!(s.status().detail, None);
        s.on_event(AgentEvent::TurnEnded { at_ms: None }, 40, 0);
        assert_eq!((s.status().state, s.status().since_ms), (State::Ready, 40));
        assert_eq!(s.status().detail, None);
        assert_eq!(s.heartbeat(), Out::Status(s.status().clone()));
    }

    #[test]
    fn turn_end_from_hook_and_log_completes_once() {
        // log-then-hook (the App's order)
        let mut s = ready();
        s.on_log(user("u1", "t1", "hi"), 2, 0);
        s.on_event(AgentEvent::ToolStarted, 3, 0);
        let o = s.on_log(end("t1", Outcome::Done), 4, 0);
        assert_eq!(completes(&o).len(), 1);
        assert!(completes(&s.on_event(AgentEvent::TurnEnded { at_ms: None }, 4, 0)).is_empty());
        // hook-first
        s.on_log(user("u2", "t2", "again"), 5, 0);
        let o = s.on_event(AgentEvent::TurnEnded { at_ms: None }, 6, 0);
        assert_eq!(
            completes(&o),
            vec![&Out::Complete {
                turn_id: "t2".into(),
                request_id: None,
                outcome: Outcome::Done
            }]
        );
        assert!(completes(&s.on_log(end("t2", Outcome::Interrupted), 6, 0)).is_empty());
    }

    #[test]
    fn problem_items_produce_no_output() {
        let mut s = ready();
        let p = LogItem::Problem {
            detail: "bad".into(),
            fatal: false,
        };
        assert!(s.on_log(p, 2, 0).is_empty());
    }

    #[test]
    fn late_turn_end_completes_a_request_whose_delivery_was_unknown() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "go");
        let t = Instant::now();
        s.tick(t);
        s.tick(t + Duration::from_secs(11));
        // the transcript proves delivery after all
        s.on_log(user("u1", "t1", "go"), 20, 0);
        let o = s.on_log(end("t1", Outcome::Done), 21, 0);
        assert!(matches!(
            completes(&o)[0],
            Out::Complete { request_id: Some(r), .. } if r == "r1"
        ));
        let again = s.submit("r1", "g1", "go", 0, false).unwrap_err();
        assert!(matches!(again[1], Out::Complete { .. }));
    }

    #[test]
    fn timed_out_request_only_matches_the_next_user_entry() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "continue");
        let t = Instant::now();
        s.tick(t);
        s.tick(t + Duration::from_secs(11));
        s.on_log(user("u1", "t1", "something else"), 20, 0);
        s.on_log(end("t1", Outcome::Done), 21, 0);
        s.on_log(user("u2", "t2", "continue"), 22, 0);
        let m = s.history(None, 1, usize::MAX).remove(0);
        assert_eq!(m.origin, Some(Origin::Local));
        assert_eq!(m.request_id, None);
    }

    #[test]
    fn oversized_user_message_gets_a_separate_truncated_part() {
        let mut s = ready();
        s.on_log(user("u1", "t1", &"a".repeat(140_000)), 2, 0);
        let m = &s.history(None, 1, usize::MAX)[0];
        assert_eq!(m.parts.len(), 2);
        assert_eq!(m.parts[1].id(), TRUNCATED_ID);
        assert!(
            matches!(&m.parts[0], Part::Text { markdown, .. } if markdown.len() == MAX_MESSAGE_BYTES)
        );
    }

    #[test]
    fn turn_end_without_open_turn_emits_no_complete() {
        let mut s = ready();
        assert!(completes(&s.on_event(AgentEvent::TurnEnded { at_ms: None }, 2, 0)).is_empty());
    }

    #[test]
    fn interrupt_outcome_wins() {
        let mut s = ready();
        s.on_log(user("u1", "t1", "hi"), 2, 0);
        let o = s.on_log(end("t1", Outcome::Interrupted), 3, 0);
        assert!(matches!(
            completes(&o)[0],
            Out::Complete {
                outcome: Outcome::Interrupted,
                ..
            }
        ));
        assert!(completes(&s.on_event(AgentEvent::TurnEnded { at_ms: None }, 3, 0)).is_empty());
    }

    fn submit_ok(s: &mut ChatSession, rid: &str, text: &str) {
        assert_eq!(s.submit(rid, "g1", text, 0, false).unwrap(), text);
    }

    #[test]
    fn remote_prompt_is_accepted_only_after_hook_and_log() {
        for hook_first in [true, false] {
            let mut s = ready();
            submit_ok(&mut s, "r1", "do it\n");
            let hook = AgentEvent::PromptSubmitted {
                text: "do it".into(), // trailing whitespace is trimmed on both sides
                turn_id: None,
                at_ms: None,
            };
            let log = user("u1", "t1", "do it");
            let (a, b) = if hook_first {
                let a = s.on_event(hook, 2, 0);
                let b = s.on_log(log, 2, 0);
                (a, b)
            } else {
                let a = s.on_log(log, 2, 0);
                let b = s.on_event(hook, 2, 0);
                (a, b)
            };
            let acc = Out::Accepted {
                request_id: "r1".into(),
            };
            assert!(!a.contains(&acc), "accepted too early");
            assert!(b.contains(&acc));
            let m = s.history(None, 10, 1000);
            assert_eq!(m[0].origin, Some(Origin::Remote));
            assert_eq!(m[0].request_id.as_deref(), Some("r1"));
        }
    }

    #[test]
    fn local_prompt_is_origin_local_without_request_id() {
        let mut s = ready();
        let o = s.on_log(user("u1", "t1", "typed"), 2, 0);
        match &o[0] {
            Out::Message(m) => {
                assert_eq!(m.role, Role::User);
                assert_eq!(m.origin, Some(Origin::Local));
                assert_eq!(m.request_id, None);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn assistant_parts_become_message_then_deltas_and_repeats_are_ignored() {
        let mut s = ready();
        let o = s.on_log(asst("m1", text_part("p1", "a"), "t1"), 2, 0);
        assert!(
            matches!(&o[0], Out::Message(m) if m.role == Role::Assistant && m.parts.len() == 1)
        );
        let tool = Part::Tool {
            id: "p2".into(),
            name: "Bash".into(),
            summary: "ls".into(),
        };
        let o = s.on_log(asst("m1", tool.clone(), "t1"), 3, 0);
        assert_eq!(
            o,
            vec![Out::Delta {
                message_id: "m1".into(),
                part: tool
            }]
        );
        assert!(
            s.on_log(asst("m1", text_part("p1", "again"), "t1"), 4, 0)
                .is_empty()
        );
        assert_eq!(s.history(None, 10, 1000)[0].parts.len(), 2);
    }

    #[test]
    fn assistant_reply_to_remote_prompt_carries_request_id() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "go");
        s.on_log(user("u1", "t1", "go"), 2, 0);
        let o = s.on_log(asst("m1", text_part("p", "ok"), "t1"), 3, 0);
        assert!(matches!(&o[0], Out::Message(m) if m.request_id.as_deref() == Some("r1")));
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "go".into(),
                turn_id: None,
                at_ms: None,
            },
            3,
            0,
        );
        let o = s.on_log(end("t1", Outcome::Done), 4, 0);
        assert!(matches!(
            completes(&o)[0],
            Out::Complete { request_id: Some(r), .. } if r == "r1"
        ));
        // after completion a duplicate returns Accepted + Complete
        let again = s.submit("r1", "g1", "go", 0, false).unwrap_err();
        assert!(matches!(again[0], Out::Accepted { .. }));
        assert!(matches!(again[1], Out::Complete { .. }));
    }

    #[test]
    fn submit_checks_in_order_with_exact_errors() {
        let mut s = ChatSession::new("g1".into(), 0);
        assert_eq!(
            err_text(s.submit("r", "other", "hi", 0, false)),
            "the agent was restarted; reopen the chat"
        );
        let long = "a".repeat(32_769);
        assert_eq!(
            err_text(s.submit("r", "g1", &long, 0, false)),
            "prompt too long (max 32768 bytes)"
        );
        assert_eq!(
            err_text(s.submit("r", "g1", "a\x1b[201~b", 0, false)),
            "prompt contains control characters"
        );
        assert_eq!(
            err_text(s.submit("r", "g1", "hi", 0, false)),
            "chat is not ready yet"
        );
        s.on_event(started(), 1, 0);
        s.on_event(AgentEvent::ToolStarted, 2, 0);
        assert_eq!(
            err_text(s.submit("r", "g1", "hi", 0, false)),
            "the agent is busy; wait for the current turn to finish"
        );
        s.on_event(AgentEvent::TurnEnded { at_ms: None }, 3, 0);
        assert_eq!(
            err_text(s.submit("r", "g1", "hi", 2, false)),
            "the terminal has unsent input; finish or clear it there"
        );
        assert_eq!(
            err_text(s.submit("r", "g1", "hi", 0, true)),
            "a terminal viewer has control; release it first"
        );
        // errors do not consume the request id
        assert!(s.submit("r", "g1", "hi", 0, false).is_ok());
        // a second prompt while one waits for acceptance is busy
        assert_eq!(
            err_text(s.submit("r2", "g1", "hi2", 0, false)),
            "the agent is busy; wait for the current turn to finish"
        );
    }

    #[test]
    fn duplicate_request_returns_recorded_state_and_never_pastes() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "go");
        assert!(s.submit("r1", "g1", "go", 0, false).unwrap_err().is_empty());
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "go".into(),
                turn_id: None,
                at_ms: None,
            },
            2,
            0,
        );
        s.on_log(user("u1", "t1", "go"), 2, 0);
        assert_eq!(
            s.submit("r1", "g1", "go", 0, false).unwrap_err(),
            vec![Out::Accepted {
                request_id: "r1".into()
            }]
        );
        // a failed one answers with the earlier error
        let mut s = ready();
        submit_ok(&mut s, "r2", "go");
        let t = Instant::now();
        s.tick(t);
        s.tick(t + Duration::from_secs(11));
        assert_eq!(
            err_text(s.submit("r2", "g1", "go", 0, false)),
            "delivery unknown; check the terminal"
        );
    }

    #[test]
    fn typing_after_turn_end_blocks_submit_and_next_turn_end_clears_it() {
        let mut s = ready();
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "x".into(),
                turn_id: None,
                at_ms: None,
            },
            2,
            0,
        );
        s.on_event(AgentEvent::TurnEnded { at_ms: None }, 3, 5);
        assert!(s.submit("r1", "g1", "hi", 5, false).is_ok());
        let mut s = ready();
        s.on_event(AgentEvent::TurnEnded { at_ms: None }, 3, 5);
        assert!(s.submit("r1", "g1", "hi", 6, false).is_err());
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "typed".into(),
                turn_id: None,
                at_ms: None,
            },
            4,
            6,
        );
        s.on_event(AgentEvent::TurnEnded { at_ms: None }, 5, 6);
        assert!(s.submit("r2", "g1", "hi", 6, false).is_ok());
    }

    #[test]
    fn delivery_unknown_after_10s_and_no_resend() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "go");
        let t = Instant::now();
        assert!(s.tick(t).is_empty());
        assert!(s.tick(t + Duration::from_secs(9)).is_empty());
        let o = s.tick(t + Duration::from_secs(10));
        assert_eq!(
            o,
            vec![Out::Error {
                text: "delivery unknown; check the terminal".into(),
                request_id: Some("r1".into())
            }]
        );
        assert!(s.tick(t + Duration::from_secs(30)).is_empty());
        // the chat can be used again, the request cannot
        assert!(s.submit("r1", "g1", "go", 0, false).is_err());
        assert!(s.submit("r3", "g1", "go", 0, false).is_ok());
    }

    #[test]
    fn paste_failed_reports_once_and_records() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "go");
        let o = s.paste_failed(
            "r1",
            "Terminal input queue full or closed; input was not queued",
        );
        assert_eq!(o.len(), 1);
        assert!(s.submit("r2", "g1", "go", 0, false).is_ok());
    }

    #[test]
    fn history_respects_counts_bytes_and_before() {
        let mut s = ready();
        for i in 0..5 {
            s.on_log(user(&format!("u{i}"), &format!("t{i}"), "0123456789"), 2, 0);
        }
        let ids = |v: Vec<ChatMessage>| v.into_iter().map(|m| m.message_id).collect::<Vec<_>>();
        assert_eq!(ids(s.history(None, 2, 1000)), ["u3", "u4"]);
        assert_eq!(ids(s.history(None, 10, 25)), ["u3", "u4"]);
        assert_eq!(ids(s.history(Some("u3"), 10, 1000)), ["u0", "u1", "u2"]);
        assert_eq!(ids(s.history(Some("u3"), 1, 1000)), ["u2"]);
        assert!(s.history(Some("nope"), 10, 1000).is_empty());
        assert!(s.history(Some("u0"), 10, 1000).is_empty());
        // the newest message is returned even if it alone exceeds max_bytes
        assert_eq!(ids(s.history(None, 10, 3)), ["u4"]);
    }

    #[test]
    fn a_page_leaves_cards_out_before_its_limits_and_says_when_it_starts() {
        use crate::chat::adapter::{ApprovalCard, ApprovalCardState};
        let mut s = ready();
        for i in 0..3 {
            s.on_log(user(&format!("u{i}"), &format!("t{i}"), "hi"), 2, 0);
        }
        for i in 0..60 {
            s.approval_card(
                ApprovalCard {
                    id: "approval".into(),
                    approval_id: format!("a{i}"),
                    tool: "Bash".into(),
                    summary: "ls".into(),
                    always_rules: Vec::new(),
                    state: ApprovalCardState::Pending,
                    rule_id: None,
                    note: None,
                    reason: None,
                },
                3,
            );
        }
        let ids = |v: Vec<ChatMessage>| v.into_iter().map(|m| m.message_id).collect::<Vec<_>>();
        let no_cards = |m: &ChatMessage| !m.message_id.starts_with("approval-");
        // A view-only page: the newest 50 are all cards, yet it holds the
        // older messages, and it is the start.
        let (page, start) = s.page(None, 50, 1 << 20, no_cards);
        assert_eq!(ids(page), ["u0", "u1", "u2"]);
        assert!(start);
        let (page, start) = s.page(Some("approval-a30"), 2, 1 << 20, no_cards);
        assert_eq!(ids(page), ["u1", "u2"]);
        assert!(!start, "u0 is older");
        let (page, start) = s.page(Some("u0"), 50, 1 << 20, no_cards);
        assert!(page.is_empty() && start);
        // With control the cards count.
        let (page, start) = s.page(None, 50, 1 << 20, |_| true);
        assert_eq!(page.len(), 50);
        assert!(!start);
        // A cursor of another generation is not retained.
        assert!(s.retains("u1", None) && s.retains("u1", Some("g1")));
        assert!(!s.retains("u1", Some("g2")) && !s.retains("nope", None));
    }

    #[test]
    fn catching_up_completes_a_turn_whose_end_was_dropped() {
        let hook = |turn: &str, at: i64| AgentEvent::PromptSubmitted {
            text: "go".into(),
            turn_id: Some(turn.into()),
            at_ms: Some(at),
        };
        let mut s = ready();
        s.submit("r", "g1", "go", 0, false).unwrap();
        s.mark_pasted("r", Instant::now(), 1000);
        s.on_event(hook("t1", 1010), 2, 0);
        s.on_log(
            LogItem::UserMessage {
                id: "u1".into(),
                turn_id: "t1".into(),
                text: "go".into(),
                created_at_ms: 1020,
            },
            3,
            0,
        );
        assert_eq!(s.status().state, State::Working);
        // The worker saw the turn end interrupted; that never arrived here.
        let mut worker = s.snapshot(0, 0);
        worker.state = State::Ready;
        worker.since_ms = 50;
        worker.current_turn = Some("t1".into());
        worker.last_completed = Some("t1".into());
        worker.last_outcome = Some(Outcome::Interrupted);
        worker.input_mark = 4;
        let o = s.catch_up(&worker);
        assert!(o.contains(&Out::Complete {
            turn_id: "t1".into(),
            request_id: Some("r".into()),
            outcome: Outcome::Interrupted
        }));
        assert!(
            o.iter()
                .any(|o| matches!(o, Out::Status(st) if st.state == State::Ready))
        );
        assert_eq!(s.status().state, State::Ready);
        // Once is enough.
        assert!(s.catch_up(&worker).is_empty());
    }

    #[test]
    fn history_is_bounded_to_500_messages() {
        let mut s = ready();
        for i in 0..520 {
            s.on_log(user(&format!("u{i}"), "t", "x"), 2, 0);
        }
        let all = s.history(None, 10_000, usize::MAX);
        assert_eq!(all.len(), 500);
        assert_eq!(all[0].message_id, "u20");
    }

    #[test]
    fn oversized_message_stops_growing_with_a_truncated_part() {
        let mut s = ready();
        s.on_log(asst("m", text_part("p1", &"a".repeat(131_000)), "t"), 2, 0);
        let o = s.on_log(asst("m", text_part("p2", &"b".repeat(2000)), "t"), 3, 0);
        assert_eq!(o.len(), 2, "kept part + marker");
        assert!(
            s.on_log(asst("m", text_part("p3", "more"), "t"), 4, 0)
                .is_empty()
        );
        let m = &s.history(None, 1, usize::MAX)[0];
        assert!(m.bytes() <= MAX_MESSAGE_BYTES + TRUNCATED.len());
        assert!(
            matches!(m.parts.last().unwrap(), Part::Text { markdown, .. } if markdown == TRUNCATED)
        );
    }

    #[test]
    fn redaction_masks_secret_values_in_text_and_tool_summaries() {
        let key = "sk-proj-abcdef1234567890ABCDEF";
        let mut s = ready();
        s.on_log(user("u1", "t1", &format!("my key is {key}")), 2, 0);
        s.on_log(
            asst("m1", text_part("p1", &format!("saw {key}")), "t1"),
            3,
            0,
        );
        s.on_log(
            asst(
                "m1",
                Part::Tool {
                    id: "p2".into(),
                    name: "Bash".into(),
                    summary: format!("curl -H 'Authorization: {key}'"),
                },
                "t1",
            ),
            4,
            0,
        );
        let dump = format!("{:?}", s.history(None, 10, usize::MAX));
        assert!(!dump.contains("abcdef1234567890"), "{dump}");
        assert!(dump.contains("[redacted]"));
        assert_eq!(redact("vault get dialf/openai"), "vault get dialf/openai");
    }

    fn restart(source: &str, same_log: bool) -> AgentEvent {
        AgentEvent::SessionStarted {
            session_id: "s".into(),
            log_path: PathBuf::from("/x"),
            source: source.into(),
            same_log,
        }
    }

    #[test]
    fn compact_or_resume_on_the_same_log_keeps_the_turn() {
        for source in ["compact", "resume"] {
            let mut s = ready();
            submit_ok(&mut s, "r1", "go");
            s.on_event(
                AgentEvent::PromptSubmitted {
                    text: "go".into(),
                    turn_id: None,
                    at_ms: None,
                },
                2,
                0,
            );
            let since = s.status().since_ms;
            // typing during the turn moved the input count; compaction must not
            // hide it, nor end the pending prompt or the turn
            assert!(
                s.on_event(restart(source, true), 3, 7).is_empty(),
                "{source}"
            );
            assert_eq!(s.status().state, State::Working);
            assert_eq!(s.status().since_ms, since);
            let o = s.on_log(user("u1", "t1", "go"), 4, 7);
            assert!(o.contains(&Out::Accepted {
                request_id: "r1".into()
            }));
            let o = s.on_log(end("t1", Outcome::Done), 5, 7);
            assert!(matches!(
                completes(&o)[0],
                Out::Complete { request_id: Some(r), .. } if r == "r1"
            ));
        }
        // any SessionStarted on the same log while a turn is in progress keeps it
        let mut s = ready();
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "x".into(),
                turn_id: None,
                at_ms: None,
            },
            2,
            0,
        );
        assert!(s.on_event(restart("", true), 3, 4).is_empty());
        assert_eq!(s.status().state, State::Working);
        // compact while idle keeps the input mark too
        let mut s = ready();
        s.on_event(restart("compact", true), 3, 4);
        assert_eq!(
            err_text(s.submit("r", "g1", "hi", 4, false)),
            "the terminal has unsent input; finish or clear it there"
        );
    }

    #[test]
    fn startup_clear_or_a_new_log_resets_to_ready() {
        for (source, same_log) in [("startup", true), ("clear", true), ("resume", false)] {
            let mut s = ready();
            s.on_event(
                AgentEvent::PromptSubmitted {
                    text: "x".into(),
                    turn_id: None,
                    at_ms: None,
                },
                2,
                0,
            );
            let o = s.on_event(restart(source, same_log), 3, 4);
            assert_eq!(
                o,
                vec![Out::Status(Status {
                    state: State::Ready,
                    since_ms: 3,
                    detail: None
                })],
                "{source} {same_log}"
            );
            assert!(s.submit("r", "g1", "hi", 4, false).is_ok());
        }
    }

    #[test]
    fn backfill_lands_in_history_without_outs_or_status() {
        let mut s = ready();
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "x".into(),
                turn_id: None,
                at_ms: None,
            },
            2,
            0,
        );
        // on_backfill returns nothing: no Outs by construction
        s.on_backfill(user("u1", "t1", "old prompt"));
        s.on_backfill(asst("m1", text_part("p1", "old reply"), "t1"));
        s.on_backfill(asst("m1", text_part("p2", "more"), "t1"));
        s.on_backfill(end("t1", Outcome::Done));
        s.on_backfill(end("t1", Outcome::Interrupted));
        // wrapped items given to on_log are backfill too
        let wrapped = LogItem::Backfill(Box::new(user("u2", "t2", "older")));
        assert!(s.on_log(wrapped, 3, 0).is_empty());
        assert_eq!(s.status().state, State::Working);
        let h = s.history(None, 10, usize::MAX);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].origin, Some(Origin::Local));
        assert_eq!(h[1].parts.len(), 2);
        assert!(h.iter().all(|m| m.request_id.is_none()));
    }

    #[test]
    fn resuming_a_session_read_before_does_not_repeat_its_prompts() {
        let mut s = ready();
        s.on_log(user("u1", "t1", "first"), 2, 0);
        s.on_log(asst("m1", text_part("p1", "reply"), "t1"), 3, 0);
        // /clear, then /resume of the same session: its file is read again
        s.on_backfill(user("u1", "t1", "first"));
        s.on_backfill(asst("m1", text_part("p1", "reply"), "t1"));
        let h = s.history(None, 10, usize::MAX);
        assert_eq!(h.len(), 2);
        assert_eq!(h[1].parts.len(), 1);
    }

    #[test]
    fn commands_and_shell_mode_are_refused() {
        let mut s = ready();
        for text in ["/clear", "  /model opus", "!rm -rf x", "\n\t!ls"] {
            assert_eq!(
                err_text(s.submit("r", "g1", text, 0, false)),
                "commands and shell mode are not available from chat",
                "{text:?}"
            );
        }
        // a duplicate request id is still answered from the record first
        submit_ok(&mut s, "r1", "go");
        assert!(
            s.submit("r1", "g1", "/clear", 0, false)
                .unwrap_err()
                .is_empty()
        );
        let mut s = ready();
        submit_ok(&mut s, "r2", "# remember this");
        let mut s = ready();
        submit_ok(&mut s, "r3", "explain a/b and !x");
    }

    #[test]
    fn prompt_match_ignores_leading_whitespace_too() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "  go");
        s.on_event(
            AgentEvent::PromptSubmitted {
                text: "go".into(),
                turn_id: None,
                at_ms: None,
            },
            2,
            0,
        );
        let o = s.on_log(user("u1", "t1", "go "), 2, 0);
        assert!(o.contains(&Out::Accepted {
            request_id: "r1".into()
        }));
    }

    #[test]
    fn history_is_bounded_to_8_mib() {
        let mut s = ready();
        let big = "a".repeat(120_000);
        for i in 0..80 {
            s.on_log(asst(&format!("m{i}"), text_part("p", &big), "t"), 2, 0);
        }
        let all = s.history(None, 10_000, usize::MAX);
        let total: usize = all.iter().map(ChatMessage::bytes).sum();
        assert!(total <= 8 * 1024 * 1024, "{total}");
        assert_eq!(all.len(), 8 * 1024 * 1024 / 120_000);
        assert_eq!(all.last().unwrap().message_id, "m79");
        // growing a message by deltas counts too
        let mut s = ready();
        for i in 0..69 {
            s.on_log(asst(&format!("m{i}"), text_part("p", &big), "t"), 2, 0);
        }
        s.on_log(asst("m68", text_part("q", "b"), "t"), 2, 0);
        let all = s.history(None, 10_000, usize::MAX);
        let total: usize = all.iter().map(ChatMessage::bytes).sum();
        assert!(total <= 8 * 1024 * 1024, "{total}");
        assert_eq!(all.last().unwrap().parts.len(), 2);
    }

    #[test]
    fn process_exit_goes_unknown_and_refuses_submits() {
        let mut s = ready();
        submit_ok(&mut s, "r1", "go");
        let o = s.on_process_exit(50);
        assert!(o.contains(&Out::Status(Status {
            state: State::Unknown,
            since_ms: 50,
            detail: None
        })));
        assert!(o.contains(&Out::Error {
            text: "the agent exited".into(),
            request_id: Some("r1".into())
        }));
        assert_eq!(
            err_text(s.submit("r9", "g1", "go", 0, false)),
            "the agent exited; start it again"
        );
        assert_eq!(
            err_text(s.submit("r9", "wrong", "go", 0, false)),
            "the agent exited; start it again"
        );
        assert!(s.on_event(started(), 60, 0).is_empty());
        assert_eq!(s.status().state, State::Unknown);
    }
}

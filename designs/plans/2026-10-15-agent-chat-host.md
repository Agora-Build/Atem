# Agent Chat (chat-v1) Host Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Astation's browser (later mobile) chat page talk to the Claude Code session running in Atem's shared terminal, through structured `agentChat` v1 events built from Claude's own hooks and transcript.

**Architecture:** A neutral chat core (`src/chat/session.rs`, `src/chat/wire.rs`) consumes neutral inputs from a per-agent adapter (`src/chat/adapter.rs`). v1 has one adapter, Claude Code (`src/chat/claude/`): per-launch hooks via `--settings` write one JSON file per event into a private directory; Claude's transcript JSONL is the only content source. The App wires the chat core into the existing TUI loop, Astation connection and agent registry.

**Tech Stack:** Rust 2024 (bin crate `atem`), serde/serde_json, uuid, tokio (existing TUI loop), portable-pty (existing PtySession), tokio-tungstenite (tests' fake Astation, existing pattern).

**Spec:** `designs/agent-chat-host.md` (branch `docs/agent-chat-host`). Read it first; this plan argues from it.

## Global Constraints

- Branch: `feat/agent-chat` created from `docs/agent-chat-host` (it already contains the spec). Commit messages end with the line `🤖 Built with SMT <smt@agora.build>`. Never push.
- Content comes only from the transcript; hooks only mark lifecycle. Never scrape the terminal screen; never infer completion or waiting from silence; never start another Claude process; never approve tools; never resend a prompt.
- A chat prompt is refused (nothing typed) unless: matching `generation` and `agentId`; `requestId` new for the agent session; text ≤ 32 768 UTF-8 bytes containing only printable characters, `\n`, `\t`; status `ready` with no prompt awaiting acceptance; no terminal input since the last turn ended; no Astation viewer holding terminal control.
- Acceptance needs both the `UserPromptSubmit` hook event and the matching transcript user entry; none within 10 s → `error` "delivery unknown; check the terminal".
- Hook health: no `SessionStart` within 15 s of launch → chat withdrawn for that agent with a notice; terminal unaffected.
- Status heartbeat every 15 s re-sends the current state with its original `since`.
- History on `open`: latest 50 messages or 256 KB, older pages via `before`. Message cap 131 072 bytes (truncate with a note). Thinking, tool output and file contents are never sent; outgoing text and tool summaries pass `crate::memory::secrets` redaction (`[redacted]`).
- Markdown parts are CommonMark without raw HTML (sent as-is from Claude; clients render without HTML).
- Hook command (per event), exactly: `{ f=$(mktemp "<DIR>/events/ev.XXXXXXXX") && cat > "$f" && mv "$f" "$f.json"; } 2>/dev/null; exit 0` with `<DIR>` the per-session directory (shell-quoted).
- Per-session directory: `$XDG_RUNTIME_DIR/atem/chat-<id>/` else `~/.config/atem/run/chat-<id>/`; mode 0700; `settings.json` 0600; `events/` 0700; removed when the agent ends or Atem exits.
- Never rustfmt `src/cli.rs`, `src/websocket_client.rs`, `src/main.rs`, `src/app.rs`, `src/memory/crypto.rs`, `src/memory/mod.rs`; new files under `src/chat/` may be formatted with `rustfmt --edition 2024`; never project-wide `cargo fmt`.
- Every task: `cargo test` reading EVERY `test result` line (unit + `tests/*` binaries), and `cargo clippy --all-targets` with no new warnings.
- Never run the installed `atem`, never touch `~/.config/atem`, the user's running atem processes or cred agent. Task 1 may run the real `claude` binary in a temporary directory.

## File Structure

| File | Responsibility |
|---|---|
| `src/chat/mod.rs` | module declarations only |
| `src/chat/adapter.rs` | `AgentAdapter` trait, `AgentEvent`, `LogItem`, `Part`, `Outcome`, `Capabilities`, `LaunchPlan` |
| `src/chat/claude/mod.rs` | `ClaudeAdapter` (implements `AgentAdapter`) |
| `src/chat/claude/hooks.rs` | per-session directory, `settings.json`, event-file reader, hook JSON → `AgentEvent` |
| `src/chat/claude/transcript.rs` | transcript follower, entry → `LogItem` |
| `src/chat/session.rs` | agent-neutral chat state: status, history, submit checks, acceptance, request records, outgoing events |
| `src/chat/wire.rs` | `agentChat` v1 types and validation |
| `src/pty_session.rs` | add an input counter to `PtyInput` and `send_paste` |
| `src/agent_client.rs` | `AgentStatus::Unknown`, `AgentInfo.capabilities` |
| `src/websocket_client.rs` | `AstationMessage::AgentChat` |
| `src/app.rs`, `src/app/chat.rs` (new) | wiring: launch, polling, message handling, registry status, closing conversations |
| `tests/fixtures/chat/claude/` | anonymised transcripts and hook events recorded in Task 1 |
| `tests/agent_chat_binary.rs` | end-to-end test with a fake `claude` and a fake Astation |

---

### Task 1: Verify Claude Code's hooks and transcript, record fixtures

**Files:**
- Create: `tests/fixtures/chat/claude/README.md`, `tests/fixtures/chat/claude/session-*.jsonl`, `tests/fixtures/chat/claude/events/*.json`
- Modify: `designs/agent-chat-host.md` (only if a finding contradicts it; add a short "Verified on Claude Code <version>" note either way)

**Interfaces:**
- Produces: fixture files with the exact formats later tasks parse; a README listing, for each hook event, the JSON fields observed (`hook_event_name`, `session_id`, `transcript_path`, `prompt`, `source`, `message`, `notification_type` if present, `tool_name`, `tool_input` keys), and the transcript entry shapes for: a user prompt, a meta entry, a slash-command entry, assistant `text`/`tool_use`/`thinking` blocks (one block per line sharing `message.id`, `message.stop_reason`), a tool result, an interrupt (user entry with `interruptedMessageId` and text `[Request interrupted by user]`), a `system`/`stop_hook_summary` entry.

- [ ] **Step 1: Create the branch**

```bash
git checkout docs/agent-chat-host && git checkout -b feat/agent-chat
```

- [ ] **Step 2: Run real Claude with per-launch hooks in a temp project**

```bash
T=$(mktemp -d); mkdir -p "$T/proj" "$T/chat/events"; chmod 700 "$T/chat" "$T/chat/events"
CMD='{ f=$(mktemp "'"$T"'/chat/events/ev.XXXXXXXX") && cat > "$f" && mv "$f" "$f.json"; } 2>/dev/null; exit 0'
python3 - "$T" "$CMD" <<'EOF'
import json,sys
t,cmd=sys.argv[1],sys.argv[2]
ev=["SessionStart","UserPromptSubmit","PreToolUse","PostToolUse","Notification","Stop"]
h={e:[{"matcher":"","hooks":[{"type":"command","command":cmd}]}] if e in("PreToolUse","PostToolUse") else [{"hooks":[{"type":"command","command":cmd}]}] for e in ev}
json.dump({"hooks":h},open(f"{t}/chat/settings.json","w"),indent=1)
EOF
SID=$(python3 -c 'import uuid;print(uuid.uuid4())'); echo "$T $SID"
```

Then, interactively in a real terminal (or `script -q -c` / a PTY): `cd "$T/proj" && claude --settings "$T/chat/settings.json" --session-id "$SID"`. Before typing anything, check `ls "$T/chat/events"` shows one `SessionStart` file. Then: send a prompt that makes Claude run one harmless Bash command (e.g. "run `echo hi` with Bash then say done"), approve when asked (to see `Notification`), let it finish (`Stop`); send a second prompt and press Esc mid-answer (interrupt); `/clear` once (new `SessionStart`, new transcript); exit.

Expected: every event file parses as JSON; `SessionStart` arrived before the first prompt with `session_id` = `$SID` and a `transcript_path` under `~/.claude/projects/` ending in `$SID.jsonl`.

- [ ] **Step 3: Record anonymised fixtures**

Copy the event files to `tests/fixtures/chat/claude/events/` (named `01-session-start.json`, `02-user-prompt-submit.json`, …, in arrival order) and the transcript(s) to `tests/fixtures/chat/claude/session-basic.jsonl` (and `session-after-clear.jsonl` if created). Anonymise: replace home paths with `/home/user`, cwd with `/home/user/proj`, hostnames/emails/tokens if any, keep all ids and structure. Remove `signature` values from thinking blocks (replace with `"sig"`). Delete the temp project and its `~/.claude/projects/<encoded temp path>` directory afterwards.

- [ ] **Step 4: Write `tests/fixtures/chat/claude/README.md`** with the field lists described under Interfaces, the Claude Code version (`claude --version`), and any deviation from the spec. If a deviation affects the design (e.g. hooks do not fire in interactive mode, `SessionStart` comes after the first prompt, no event JSON on stdin), stop and report BLOCKED with the details instead of continuing.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/chat designs/agent-chat-host.md
git commit -m "test(chat): Claude Code hook and transcript fixtures (verified on Claude Code <version>)

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 2: Neutral adapter types and the Claude transcript reader

**Files:**
- Create: `src/chat/mod.rs`, `src/chat/adapter.rs`, `src/chat/claude/mod.rs` (declarations only in this task), `src/chat/claude/transcript.rs`
- Modify: `src/main.rs` (add `mod chat;`)

**Interfaces:**
- Consumes: fixtures from Task 1.
- Produces:

```rust
// src/chat/adapter.rs
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Text { id: String, markdown: String },
    Tool { id: String, name: String, summary: String },
}
impl Part {
    pub fn id(&self) -> &str { match self { Part::Text { id, .. } | Part::Tool { id, .. } => id } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome { Done, Interrupted }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEvent {
    SessionStarted { session_id: String, log_path: PathBuf },
    PromptSubmitted { text: String },
    ToolStarted,
    ToolFinished,
    WaitingForPermission { detail: String },
    TurnEnded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogItem {
    /// A prompt as recorded in the log. `id` is the entry uuid.
    UserMessage { id: String, turn_id: String, text: String, created_at_ms: i64 },
    /// One part of an assistant message (`message_id` groups parts).
    AssistantPart { message_id: String, part: Part, turn_id: String, created_at_ms: i64 },
    /// The turn ended according to the log (end_turn or interrupt).
    TurnEnded { turn_id: String, outcome: Outcome },
    /// Something could not be read; `fatal` = format changed, withdraw chat.
    Problem { detail: String, fatal: bool },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities { pub chat_v1: bool, pub reason: Option<String> }

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchPlan { pub extra_args: Vec<String>, pub session_id: Option<String> }

pub trait AgentAdapter: Send {
    fn prepare_launch(&mut self, args: &[String], dir: &Path) -> anyhow::Result<LaunchPlan>;
    fn poll_events(&mut self) -> Vec<AgentEvent>;
    fn poll_log(&mut self) -> Vec<LogItem>;
    fn capabilities(&self) -> Capabilities;
}
```

```rust
// src/chat/claude/transcript.rs
pub struct TranscriptReader { /* path, offset: u64, pending: Vec<u8>, seen: HashSet<String> (bounded 10_000), turn_id: String */ }
impl TranscriptReader {
    pub fn new(path: PathBuf) -> Self;
    /// Read new complete lines since the last call and map them to LogItems.
    pub fn poll(&mut self) -> Vec<LogItem>;
    pub fn path(&self) -> &Path;
}
pub fn summarize_tool(name: &str, input: &serde_json::Value) -> String; // ≤120 chars
```

Mapping rules (from the spec and Task 1's README):
- Skip non-`user`/`assistant` types except `TurnEnded` signals below; skip `isSidechain: true` and `isMeta: true`.
- `user` with string content or `text` blocks: if text starts with `<command-` or `<local-command-` → skip; if the entry has `interruptedMessageId` → `TurnEnded { turn_id, Interrupted }` (no message); otherwise → set `turn_id = promptId` (fall back to the entry uuid) and emit `UserMessage { id: uuid, turn_id, text, created_at_ms }`.
- `user` whose content is only `tool_result` blocks → nothing (but keep `turn_id` = its `promptId` if present).
- `assistant`: for each content block: `text` → `AssistantPart{ message_id: message.id, part: Part::Text{ id: uuid, markdown }, … }`; `tool_use` → `Part::Tool{ id: uuid, name, summary: summarize_tool(name, input) }`; `thinking` → nothing. If `message.stop_reason == "end_turn"` → additionally `TurnEnded { turn_id, Done }` after the parts.
- Part ids: the entry `uuid` (one block per line in practice); if a line has several blocks, use `"{uuid}:{index}"`.
- `created_at_ms` from `timestamp` (RFC 3339); unparsable → 0.
- Only complete lines (`\n`-terminated) are consumed; a partial last line stays pending. A missing file returns `vec![]` (retried next poll).
- Dedupe by entry uuid (`seen`): a uuid seen before → skip the whole line.
- A line that isn't JSON → `Problem { fatal: false }` once per poll; a `user`/`assistant` entry missing `uuid` or (assistant) `message.id` → `Problem { fatal: true }`.
- `summarize_tool`: `Bash` → first line of `input.command`; `Read`/`Write`/`Edit`/`MultiEdit`/`NotebookEdit` → `input.file_path` (or `notebook_path`); `Glob`/`Grep` → `input.pattern`; `WebFetch` → `input.url`; `WebSearch` → `input.query`; `Task`/others → `""`. Truncate to 120 chars on a char boundary, adding `…`.

- [ ] **Step 1: Write failing tests** in `src/chat/claude/transcript.rs` (`#[cfg(test)] mod tests`), using `tempfile` for a transcript path and Task 1's fixtures via `include_str!("../../../tests/fixtures/chat/claude/session-basic.jsonl")`:
  - `basic_session_yields_user_messages_parts_and_turn_end` — feed the fixture; assert the sequence starts with `UserMessage` (text of the first prompt), then `AssistantPart`s with `Part::Tool { name: "Bash", summary: "echo hi" }` and a `Part::Text`, ends the first turn with `TurnEnded { outcome: Done }`; no thinking text anywhere; `turn_id`s equal the prompt's `promptId`.
  - `interrupt_entry_ends_the_turn_as_interrupted` (from the fixture's interrupt).
  - `meta_sidechain_and_command_entries_are_skipped` (hand-written lines).
  - `partial_last_line_waits_for_the_rest` — write half a line, poll → nothing; append the rest + `\n`, poll → one item.
  - `lines_are_processed_once_even_if_reread` — reset offset to 0 (via a test-only `reread_from_start()`), poll → no duplicates.
  - `missing_file_is_retried` — poll on a non-existent path → `[]`, create it, poll → items.
  - `garbage_line_is_a_problem_not_a_stop`, `assistant_without_message_id_is_fatal`.
  - `tool_summaries_are_short_and_safe` — `summarize_tool` cases above, 200-char command → 120 chars ending in `…`, multi-line command → first line only.
- [ ] **Step 2:** `cargo test chat::claude::transcript` → fails (types missing).
- [ ] **Step 3: Implement** `adapter.rs` exactly as above and `transcript.rs` per the mapping rules (serde_json::Value-based parsing; `std::fs::File` + `seek` to `offset`).
- [ ] **Step 4:** `cargo test chat::claude::transcript` → pass; full `cargo test` (all binaries) → pass; `cargo clippy --all-targets` no new warnings (allow `dead_code` on items used only by later tasks with `#[allow(dead_code)]` at the item, removed in Task 6 — note this in the commit).
- [ ] **Step 5: Commit** `feat(chat): neutral adapter types and Claude transcript reader`.

---

### Task 3: Claude hooks and the Claude adapter

**Files:**
- Create: `src/chat/claude/hooks.rs`
- Modify: `src/chat/claude/mod.rs` (`ClaudeAdapter`)

**Interfaces:**
- Consumes: `AgentAdapter`, `AgentEvent`, `LogItem`, `LaunchPlan`, `Capabilities`, `TranscriptReader`.
- Produces:

```rust
// hooks.rs
pub const HOOK_EVENTS: [&str; 6] = ["SessionStart","UserPromptSubmit","PreToolUse","PostToolUse","Notification","Stop"];
pub fn session_dir_root() -> PathBuf;               // $XDG_RUNTIME_DIR/atem or ~/.config/atem/run
pub fn create_session_dir(root: &Path) -> anyhow::Result<PathBuf>; // root/chat-<uuid>, 0700, events/ 0700
pub fn hook_command(dir: &Path) -> String;          // the exact Global Constraints command, dir shell-quoted
pub fn write_settings(dir: &Path) -> anyhow::Result<PathBuf>; // dir/settings.json, 0600
pub struct EventReader { /* dir */ }
impl EventReader {
    pub fn new(dir: PathBuf) -> Self;
    /// Read events/*.json ordered by (mtime ns, name), delete each, map to AgentEvent.
    /// Skips names without .json; removes non-.json leftovers older than 60 s.
    pub fn poll(&mut self) -> Vec<AgentEvent>;
}
pub fn map_hook(json: &serde_json::Value) -> Option<AgentEvent>;

// mod.rs
pub struct ClaudeAdapter { /* dir: Option<PathBuf>, events: Option<EventReader>, transcript: Option<TranscriptReader>, started_at: Instant, session_started: bool, withdrawn: Option<String> */ }
impl ClaudeAdapter { pub fn new() -> Self; pub fn dir(&self) -> Option<&Path>; }
impl AgentAdapter for ClaudeAdapter { … }
impl Drop for ClaudeAdapter { fn drop(&mut self) { /* remove dir */ } }
```

Behaviour:
- `map_hook`: by `hook_event_name`: `SessionStart` → `SessionStarted { session_id, log_path: transcript_path }`; `UserPromptSubmit` → `PromptSubmitted { text: prompt }`; `PreToolUse` → `ToolStarted`; `PostToolUse` → `ToolFinished`; `Notification` → `WaitingForPermission { detail: message }` only when the notification is a permission request (use `notification_type` if Task 1 found it, else message text containing "permission"; idle reminders map to nothing); `Stop` → `TurnEnded`; anything else / missing fields → `None`.
- `prepare_launch(args, dir)`: write settings; `extra_args = ["--settings", <path>]`; unless `args` contains `--continue`, `-c`, `--resume`, `-r` or `--session-id`, mint a UUID and add `["--session-id", uuid]` (`session_id: Some(uuid)`).
- `poll_events`: read events; on `SessionStarted`, (re)open the `TranscriptReader` for `log_path` and set `session_started`.
- `poll_log`: transcript items; a `Problem { fatal: true }` sets `withdrawn`.
- `capabilities`: `chat_v1 = session_started && withdrawn.is_none()`; if not started and `started_at.elapsed() >= 15 s` → `reason: Some("Claude hooks are not active: disabled, --bare, or an unsupported version")`; `withdrawn` → that reason.
- Settings JSON shape: `{"hooks": {Event: [{"hooks":[{"type":"command","command": CMD}]}]}}`, with `"matcher": ""` added for `PreToolUse`/`PostToolUse` (as in Task 1's working file).

- [ ] **Step 1: Failing tests** (`hooks.rs`, `mod.rs`):
  - `hook_command_matches_the_spec_and_quotes_the_dir` (dir with a space).
  - `settings_register_every_event_with_the_command` (parse the written file).
  - `session_dir_and_files_are_private` (modes 0700/0600/0700).
  - `hook_command_really_writes_one_event_file` — run `sh -c "<hook_command>"` with JSON on stdin (twice, concurrently via two threads) → two `.json` files, both parse; exit status 0; and with a read-only `events/` dir → still exit 0, no output.
  - `events_are_read_in_order_and_deleted` (create files with increasing mtimes via `filetime`-free approach: write with small sleeps), `tmp_files_are_skipped_then_cleaned`.
  - `map_hook_fixtures` — every fixture event maps as expected; unknown event → `None`; idle notification → `None`.
  - `prepare_launch_pins_session_id_unless_resuming`.
  - `capabilities_wait_for_session_start_then_withdraw_after_15s` (inject `started_at` via a test constructor).
  - `session_start_opens_the_transcript` (end-to-end inside the adapter with fixture files).
- [ ] **Step 2:** run → fail. **Step 3:** implement. **Step 4:** `cargo test` (all binaries), clippy. **Step 5: Commit** `feat(chat): Claude hooks via event files and the Claude adapter`.

---

### Task 4: The agent-neutral chat session

**Files:**
- Create: `src/chat/session.rs`
- Modify: `src/pty_session.rs` (input counter + `send_paste`)

**Interfaces:**
- Consumes: `AgentEvent`, `LogItem`, `Part`, `Outcome`.
- Produces:

```rust
// pty_session.rs additions
impl PtyInput {
    /// Count of send()/send_remote() calls (terminal input), not respond().
    pub fn input_count(&self) -> u64;
    /// Bracketed paste + Enter; does not count as terminal input.
    pub fn send_paste(&self, text: &str) -> anyhow::Result<()>;   // "\x1b[200~" + text + "\x1b[201~" + "\r"
}

// session.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State { Ready, Working, Waiting, Unknown }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status { pub state: State, pub since_ms: i64, pub detail: Option<String> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub message_id: String, pub role: Role, pub origin: Option<Origin>,
    pub turn_id: String, pub request_id: Option<String>, pub created_at_ms: i64,
    pub parts: Vec<Part>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Role { User, Assistant }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Origin { Local, Remote }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {                       // what the App broadcasts to open conversations
    Message(ChatMessage),
    Delta { message_id: String, part: Part },
    Status(Status),
    Accepted { request_id: String },
    Complete { turn_id: String, request_id: Option<String>, outcome: Outcome },
    Error { text: String, request_id: Option<String> },
}

pub enum SubmitCheck<'a> { /* inputs for checks, see submit() */ }

pub struct ChatSession { /* generation: String, status, history: VecDeque<ChatMessage> (bounded 500 msgs), request records: HashMap<String, RequestState> (bounded 1000, oldest evicted), pending: Option<Pending{request_id, text, pasted_at: Instant, hook_seen: bool, log_seen: bool}>, input_mark: u64, current_turn: Option<(String, Option<String>)> */ }

impl ChatSession {
    pub fn new(generation: String, now_ms: i64) -> Self;          // status Unknown until SessionStarted
    pub fn generation(&self) -> &str;
    pub fn status(&self) -> &Status;
    pub fn on_event(&mut self, event: AgentEvent, now_ms: i64, input_count: u64) -> Vec<Out>;
    pub fn on_log(&mut self, item: LogItem, now_ms: i64, input_count: u64) -> Vec<Out>;
    /// Validate and, if allowed, return the text to paste (caller pastes with send_paste).
    pub fn submit(&mut self, request_id: &str, generation: &str, text: &str,
                  input_count: u64, remote_controlled: bool) -> Result<String, Vec<Out>>;
    pub fn tick(&mut self, now: std::time::Instant) -> Vec<Out>;  // 10 s acceptance timeout
    pub fn heartbeat(&self) -> Out;                               // Status(current)
    pub fn history(&self, before: Option<&str>, max_messages: usize, max_bytes: usize) -> Vec<ChatMessage>;
    pub fn on_process_exit(&mut self, now_ms: i64) -> Vec<Out>;   // Unknown + Error, refuse further submits
}
pub fn redact(text: &str) -> String;   // crate::memory::secrets based; replaces each detected value with [redacted]
pub fn clean_prompt(text: &str) -> Result<&str, &'static str>; // size and character rules
```

Behaviour:
- Status: `SessionStarted` → Ready (input_mark = input_count); `PromptSubmitted`/`ToolStarted` → Working; `WaitingForPermission` → Waiting (detail "approve in the terminal"); `TurnEnded` (event or log) → Ready, set input_mark = input_count, emit `Complete` once per turn (dedupe: the hook `TurnEnded` and the log `TurnEnded` for the same turn emit one `Complete`; the log's outcome wins when both arrive); `on_process_exit` → Unknown. Every change emits `Out::Status` with `since_ms = now_ms`.
- Messages: `LogItem::UserMessage` → `ChatMessage { role: User, origin: Remote + request_id if it matches the pending prompt's text (the pending prompt is then `log_seen`), else Local }`, set `current_turn = (turn_id, request_id)`; `AssistantPart` → first part of a `message_id` emits `Message` (role Assistant, `request_id` from `current_turn` if its turn matches), later parts emit `Delta`; a part id already in that message is ignored. All text passes `redact`; a message whose total text exceeds 131 072 bytes stops growing and gets a final text part "… (truncated)".
- Acceptance: when `pending` has both `hook_seen` (a `PromptSubmitted` whose text equals the pending text) and `log_seen` → `Accepted { request_id }`, record `RequestState::Accepted`; `TurnEnded` for that turn → record `Completed(outcome)`.
- `submit` order of checks and error texts (exact):
  1. generation mismatch → "the agent was restarted; reopen the chat"
  2. request seen → return the recorded outcome as `Out`s (`Accepted`, `Complete`, or the earlier `Error`), no paste
  3. `clean_prompt` failure → "prompt too long (max 32768 bytes)" / "prompt contains control characters"
  4. state != Ready or pending exists → "Claude is busy; wait for the current turn to finish"
  5. input_count != input_mark → "the terminal has unsent input; finish or clear it there"
  6. remote_controlled → "a terminal viewer has control; release it first"
  On success: record `pending`, record request as `Pending`, return `Ok(text)`.
- `tick`: pending older than 10 s and not accepted → `Error { request_id, "delivery unknown; check the terminal" }`, record it, clear pending (never resend).
- `history`: newest-last list of whole messages (parts merged), at most `max_messages`/`max_bytes`, older than `before` when given.

- [ ] **Step 1: Failing tests** (`session.rs`, plus `pty_session.rs` for the counter/paste using `PtyInput::test_channel()`):
  - status table: each event/log item → expected state, `since` set, Status out emitted only on change.
  - `turn_end_from_hook_and_log_completes_once`, `interrupt_outcome_wins`.
  - `remote_prompt_is_accepted_only_after_hook_and_log` (either order), `local_prompt_is_origin_local_without_request_id`.
  - `assistant_parts_become_message_then_deltas_and_repeats_are_ignored`, `assistant_reply_to_remote_prompt_carries_request_id`.
  - submit checks 1–6 each with its exact error; `duplicate_request_returns_recorded_state_and_never_pastes`.
  - `typing_after_turn_end_blocks_submit_and_next_turn_end_clears_it`.
  - `delivery_unknown_after_10s_and_no_resend` (inject time via `tick(now)`).
  - `history_respects_counts_bytes_and_before`.
  - `redaction_masks_secret_values_in_text_and_tool_summaries` (use a value `crate::memory::secrets` detects, e.g. an `sk-ant-…`-style key used in that module's own tests).
  - `process_exit_goes_unknown_and_refuses_submits`.
  - `input_count_counts_send_and_send_remote_not_respond_or_paste`, `send_paste_wraps_in_bracketed_paste`.
- [ ] **Step 2:** fail. **Step 3:** implement. **Step 4:** `cargo test` (all), clippy. **Step 5: Commit** `feat(chat): agent-neutral chat session (status, acceptance, submit checks, history)`.

---

### Task 5: The agentChat v1 wire

**Files:**
- Create: `src/chat/wire.rs`
- Modify: `src/websocket_client.rs` (add the variant only; no rustfmt), `src/agent_client.rs` (`AgentStatus::Unknown`, `capabilities`)

**Interfaces:**
- Consumes: `session::{Out, ChatMessage, Status, State, Role, Origin}`, `adapter::{Part, Outcome}`.
- Produces:

```rust
// wire.rs — JSON shapes per the spec's "Wire" and "Message model"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatEnvelope {
    pub v: u32, pub op: String, pub conversation_id: String, pub agent_id: String,
    #[serde(flatten)] pub body: serde_json::Map<String, serde_json::Value>,
}
pub enum Inbound { Open { before: Option<String> }, Submit { generation: String, request_id: String, text: String }, Close }
pub fn parse_inbound(env: &ChatEnvelope) -> Result<Inbound, String>;   // v must be 1; unknown op → Err("unsupported op")
pub fn opened(conv: &str, agent: &str, generation: &str, status: &Status) -> ChatEnvelope;  // sequence 0
pub fn event(conv: &str, agent: &str, generation: &str, sequence: u64, out: &Out) -> ChatEnvelope;
pub fn history_message(conv: &str, agent: &str, generation: &str, sequence: u64, m: &ChatMessage) -> ChatEnvelope; // history: true
pub fn error(conv: &str, agent: &str, text: &str, request_id: Option<&str>) -> ChatEnvelope; // for pre-session errors (no generation)
```

JSON field names (camelCase): `messageId`, `role` ("user"/"assistant"), `origin` ("local"/"remote", user only), `turnId`, `requestId`, `createdAt` (unix ms), `parts` (`{"id","kind":"text","markdown"}` / `{"id","kind":"tool","name","summary"}`), `history`, `part` (delta), `state` ("ready"/"working"/"waiting"/"unknown"), `since` (unix ms), `detail`, `outcome` ("done"/"interrupted"), `text`, `generation`, `sequence`.

```rust
// websocket_client.rs (inside AstationMessage)
#[serde(rename = "agentChat")]
AgentChat(crate::chat::wire::ChatEnvelope),

// agent_client.rs
pub enum AgentStatus { Idle, Thinking, WaitingForInput, Disconnected, Unknown }
pub struct AgentInfo { …, #[serde(default, skip_serializing_if = "Vec::is_empty")] pub capabilities: Vec<String> }
```

- [ ] **Step 1: Failing tests**: round-trip every op; exact JSON for one of each `Out` (field names above); `parse_inbound` rejects `v != 1`, unknown op, missing fields, and over-long `requestId`/`conversationId` (> 128 chars); `AstationMessage::AgentChat` serialises as `{"type":"agentChat","data":{…}}` and parses back; the pinned agent-list JSON test (`test_agent_info_wire_bytes_for_astation`) stays byte-identical when `capabilities` is empty; a second test pins the shape with `capabilities: ["chat-v1"]`; `AgentStatus::Unknown` serialises as `"Unknown"`.
- [ ] **Step 2:** fail. **Step 3:** implement (`#[serde(rename_all…)]` structs for each body; build the `Map` from them). **Step 4:** `cargo test` (all), clippy. **Step 5: Commit** `feat(chat): agentChat v1 wire`.

---

### Task 6: Wire chat into the App; end-to-end test; docs

**Files:**
- Create: `src/app/chat.rs`, `tests/agent_chat_binary.rs`, `tests/fixtures/chat/fake-claude.sh`
- Modify: `src/app.rs` (fields, launch hook, message arm, loop call; no rustfmt), `src/tui/mod.rs` (call `poll_chat` each tick), `src/app/reauth.rs` (close conversations on suspend), AGENTS.md, README.md, npm/README.md (one short "Chat from Astation" paragraph)

**Interfaces:**
- Consumes: everything above.
- Produces (App methods in `src/app/chat.rs`):

```rust
pub struct AgentChat { pub agent_id: String, pub adapter: Box<dyn AgentAdapter>, pub session: ChatSession,
                       pub conversations: HashMap<String, u64 /* next sequence */>, pub last_heartbeat: Instant }
impl App {
    /// Called from ensure_claude_session before spawning: prepares the adapter and returns extra args.
    pub(crate) fn prepare_claude_chat(&mut self, args: &[String]) -> Vec<String>;
    /// Each TUI tick: poll adapter events/log, feed the session, tick timeouts/heartbeat, broadcast Outs,
    /// update the registry status/capabilities, handle process exit.
    pub async fn poll_chat(&mut self);
    /// AstationMessage::AgentChat arm.
    pub async fn handle_agent_chat(&mut self, env: ChatEnvelope);
    /// On Astation disconnect / re-auth suspend: drop all conversations (Claude keeps running).
    pub fn close_chat_conversations(&mut self);
}
```

Behaviour:
- Launch: in `ensure_claude_session`, before `start_session_sized`, create the session dir under `hooks::session_dir_root()`, call `prepare_claude_chat` and append its args to the spawn (do not mutate `claude_client`'s stored args permanently; pass them for this spawn). Generation = a new UUID per spawned process. On adapter preparation failure: log a notice, launch Claude without chat (unchanged behaviour).
- Registry: status mapping Ready→Idle, Working→Thinking, Waiting→WaitingForInput, Unknown→Unknown; `capabilities = ["chat-v1"]` exactly when `adapter.capabilities().chat_v1`; send an updated agent list to Astation when status or capabilities change (existing `send_agent_list`).
- `handle_agent_chat`: ignore while not authenticated or re-auth pending (already gated by the re-auth interceptor); unknown agent or no chat → `error` "chat is not available for this agent" (+ capability reason if any); `Open` → `opened` then history (`history(before, 50, 256*1024)`) as `history: true` messages with increasing sequence; register the conversation; `Submit` → `session.submit(..., claude_sender.input_count(), claude_sender.remote_controlled())`, on `Ok(text)` → `claude_sender.send_paste(&text)` (on write failure → `error` and clear pending); on `Err(outs)` → send them; `Close` → drop the conversation.
- `poll_chat` broadcasts every `Out` to every open conversation of that agent with its own next sequence; heartbeat `Status` every 15 s; process exit (the existing PTY receiver closing) → `on_process_exit`.
- Disconnect/re-auth: `close_chat_conversations` from the existing disconnect path and `suspend_astation`.
- Docs: AGENTS.md (source tree `src/chat/…`, a "Agent chat" paragraph: hooks via `--settings`, event files, transcript, statuses, the wire, capability; message list entry `AgentChat`); README.md and npm/README.md: one paragraph under AI Agents ("Astation can open a chat view of a Claude session launched with `atem agent launch claude`; prompts from chat are refused while you have unsent input in the terminal; approvals stay in the terminal").

`tests/fixtures/chat/fake-claude.sh` (POSIX sh, executable): parses `--settings <f>` and `--session-id <id>`; extracts the hook command from the settings (`python3 -c` is acceptable in tests); emulates: on start write a transcript path `$TMPDIR/…/<id>.jsonl` and run the hook with a `SessionStart` JSON; read lines from stdin (the PTY); on a bracketed-paste prompt: run `UserPromptSubmit` hook, append the user entry, `PreToolUse`/`PostToolUse` hooks, append an assistant `tool_use` line and an assistant `text` line with `stop_reason: end_turn` (same `message.id`), run `Stop`; on `exit` quit.

- [ ] **Step 1: Failing end-to-end test** `tests/agent_chat_binary.rs` (pattern: `tests/terminal_ui_binary.rs` for running the binary in a PTY with `CLAUDE_CLI_BIN=<fake-claude.sh>`, `XDG_RUNTIME_DIR` and `HOME` pointed at temp dirs; and the existing fake Astation WebSocket pattern from `src/websocket_client.rs` tests for a local peer). Cases:
  - `chat_open_submit_reply_complete` — open → `opened` (+ empty history), status ready; submit → `accepted`, user `message` (origin remote, requestId), assistant `message` with a tool part then `delta` text part, `complete {outcome: done, requestId}`, status ready; sequences contiguous.
  - `submit_refused_after_local_typing` — type a character into the PTY, submit → error "the terminal has unsent input…".
  - `duplicate_request_is_not_executed_twice`.
  - `reconnect_restores_status_and_history` — close, reopen → history contains the exchange as `history: true`.
  - `process_exit_reports_unknown`.
  - `agent_list_advertises_chat_v1_after_session_start`.
- [ ] **Step 2:** fail. **Step 3:** implement `src/app/chat.rs` and the wiring; remove Task 2–5 `#[allow(dead_code)]` markers. **Step 4:** `cargo test` (read every `test result` line incl. the new binary), `cargo clippy --all-targets` (no new warnings), `./scripts/run-local-dev-tests.sh` (only the 3 known `atem list` failures). **Step 5: Commit** `feat(chat): chat-v1 host wired into the TUI, Astation and agent registry` and a separate `docs(chat): …` commit.

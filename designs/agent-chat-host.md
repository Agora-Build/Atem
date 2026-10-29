# Agent chat (chat-v1): Atem host side

Status: design approved 2026-10-15; Atem host side built (Claude and Codex
adapters). atem-session r8 (2026-10-18, implemented) replaces the #75 paging
(`open{before}`, `status.page`) with history pages in the sequenced stream,
adds coverage, receipt results, chat Send that acquires the lease and
lease-free approval answers; this document describes the r8 behaviour (the
contract is the appendix "r8" of `protocol/atem-session-v1.md`).
Astation side (browser page, later a mobile app) is the Astation agent's; its
proposed contract is the starting point (atem memory `mem_b3ccce1f`, project
github.com/agora-build/atem) and this document lists the changes Atem needs
(see "Changes to the proposed contract").

## Goal

A chat view of a coding agent that runs in Atem's shared terminal
(`atem agent launch`). Prompts show as outgoing user messages, the agent's
replies as incoming messages, with an honest activity indicator. Web first;
a mobile app later uses the same events, so the host side is client-neutral.

The host side is **adapter-based**: everything agent-specific (how Atem hooks
in, which events mean what, how the session log is parsed) lives in one
adapter per agent; the chat state, message model, wire protocol, security and
reconnect handling are shared. Two adapters: **Claude Code**, and **Codex**
(its rollout JSONL plus Atem's Codex hooks, which need per-installation trust;
`src/chat/codex/adapter.rs`, spec `designs/fixtures/codex-hooks/README.md`,
plan `designs/plans/2026-10-17-codex-chat.md`); other agents (Gemini CLI, OpenCode, Copilot CLI,
Aider, …) get an adapter only once their logs and events are checked. An agent
without an adapter keeps the shared terminal, reports status `unknown` and has
no `chat-v1` capability.

## Rules

- **One source of content:** the agent's own session log (Claude's
  transcript). Agent events (Claude's hooks) only mark the lifecycle. Atem never scrapes the terminal screen and never infers that a
  turn is done or waiting from silence. **Hooks never decide** — with one
  exception: the `PermissionRequest` hook hands Claude a decision that a
  person made on a card in Astation for that exact prompt. It never allows
  anything by itself.
- **The original session stays.** Atem keeps using the interactive Claude CLI
  it launched; chat never starts another Claude process or session.
- **Approvals bound to the exact prompt** (since 2026-10-16, contract
  [§6a](protocol/atem-session-v1.md)). A permission request appears as an
  approval card in the conversations of attachments with `control` (never a
  view-only one); answering it — allow once, always allow with one of the
  rules Claude itself suggested, or deny with an optional message — is an
  `approval` submission bound to that one prompt and process, under the
  current lease or taking it with `acquire: true`. The terminal can always
  answer instead (first answer wins), and anything else — a failure, a
  timeout, nobody answering — is "no decision": Claude asks in its own
  dialog. `[claude] approvals_hook = false` in Atem's config.toml (default
  on, never asked) turns the hook off for later launches; the chat hooks
  stay. Approvals pending before a broker restart or adoption are released
  without `push_resolved`: a phone notification may linger until its
  `expires_at`, and a tap gets `stale_target` ("already answered").
- **Atem session rules for Codex** (since 2026-10-17, contract §6a r7.2).
  Codex's hook can't take a persistent rule, so a Codex card offers one
  Atem rule instead, for a shell command only: "Always allow `<command>` in
  <cwd> for this session" (`scope: "session"`; no rule for file changes or
  for a command whose input carries anything besides `command` and
  `description`; `cwd` is the hook's session cwd). Answering `allow_always` with it allows this request
  and makes the worker keep the rule for the rest of this agent process (at
  most 32; a respawn starts with none). Each rule keeps the account, device
  and trust generation it was granted under; after a broker restart the
  adopted worker's rules allow nothing until the new host accepted them,
  which it does only under the same account, device and trust generation
  (the worker drops the others). A later
  request of the session's own pinned Codex with byte-equal tool, full
  command and cwd is allowed by the worker
  without a card: an `auto_allowed` card naming `rule_id` appears in the
  conversation, runtime.log gets one line without the command, nothing is
  pushed and no lease is taken. A nested `codex`, another cwd or any other
  command still asks. The active rules are listed in `opened.approvalRules`
  and re-sent with `rules` when they change; a `submit` with
  `approval_rule_revoke: {rule_id}` instead of `text` revokes one (r7.3:
  any attachment with `control`, lease or not — `lease_epoch` optional and
  ignored, `acquire` refused, the lease never taken or moved; view-only is
  `forbidden`, an inactive rule `stale_target`; an allow it wrote that Codex
  hasn't taken yet is withdrawn; runtime.log gets one line naming the rule
  and session). A
  rule the session can't keep when Codex takes the answer (32 already) is
  not kept: the card ends `allowed` with a `note`. A new account, device or
  trust generation while the host runs drops every rule. An `apply_patch`
  run as a shell heredoc is a command like any other: its rule is
  byte-exact, patch text included. Claude's rules are unchanged.
- **Never merge with a local draft.** A chat prompt is refused when anyone
  typed into the terminal since Claude's last turn ended.
- **Never resend.** A prompt whose delivery is unknown is reported, not retried.
- **Honest status.** States come from real events; when Atem can't tell, it
  says `unknown`.

## Adapters

An adapter turns one agent's native signals into neutral inputs for the shared
chat state. It is the only agent-specific code.

```rust
trait AgentAdapter {
    /// Extra launch arguments and environment, given the agent's own args
    /// (Claude: --settings, --session-id). Errors leave chat unsupported.
    fn prepare_launch(&self, args: &[String], dir: &Path) -> Result<LaunchPlan>;
    /// Poll the agent's lifecycle source (Claude: hook event files).
    fn poll_events(&mut self) -> Vec<AgentEvent>;
    /// Poll the agent's session log from the saved position (Claude: transcript JSONL).
    fn poll_log(&mut self) -> Vec<LogItem>;
    /// What this agent supports right now (chat-v1 only once healthy).
    fn capabilities(&self) -> Capabilities;
}

enum AgentEvent {            // neutral lifecycle
    SessionStarted { session_id, log_path, source, same_log },  // source: startup|resume|clear|compact|"";
                                                                // same_log: the adapter keeps reading that log
    PromptSubmitted { text },
    ToolStarted, ToolFinished,
    WaitingForPermission { detail },
    TurnEnded,
}
enum LogItem {               // neutral content, already filtered
    UserMessage { id, turn_id, text, created_at },
    AssistantPart { message_id, part, turn_id, created_at, end_of_turn: Option<Outcome> },
    Backfill(LogItem),       // already in a log switched to (resume): history only
    Problem { detail },      // unreadable line, format change
}
```

The shared session (below) owns status, the draft check, prompt submission
and acceptance (`PromptSubmitted` plus the matching `UserMessage`), request-id
records, history and the wire. Adding an agent means writing an adapter and
its tests; the wire and the clients don't change.

### Units

| Unit | Responsibility |
|---|---|
| `src/chat/adapter.rs` | `AgentAdapter`, `AgentEvent`, `LogItem`, `Capabilities`: the neutral interface |
| `src/chat/claude/hooks.rs` | Claude: builds the per-session directory and `settings.json`; reads, orders and deletes the event files; maps hook events to `AgentEvent` |
| `src/chat/claude/transcript.rs` | Claude: follows the transcript and turns entries into `LogItem`s (below) |
| `src/chat/session.rs` | Shared per-agent chat state: status, recent messages, the draft tracker, prompt submission and acceptance, request-id records; agent-neutral |
| `src/chat/wire.rs` | `agentChat` v1 messages to and from Astation: encoding, decoding, validation |
| `src/chat/history.rs` | r8 history (shared by the runtime and the fixtures' fake runtime): conversations as ordered streams (`Conversations`), bounded pages with `history_end`, lookups, `next` tokens, coverage, and a turn's reply ids for `receipt.result` |
| `src/runtime/` (session-v1 descriptor; `agent_registry.rs` was removed) | Status from `session.rs` as the session's `activity`; chat-v1 advertised only when the agent's adapter reports it (v1: Claude with active hooks) |

All of it lives in the Atem process that owns the terminal; there is no new
daemon. Chat state belongs to the agent session, not to a browser connection:
Claude keeps running and Atem keeps reading the transcript whether or not any
chat page is open.

## Claude Code adapter (v1)

### Launch

`atem agent launch claude [args…]`:

1. Creates a private per-session directory, `$XDG_RUNTIME_DIR/atem/chat-<id>/`
   (or `~/.config/atem/run/chat-<id>/` without `XDG_RUNTIME_DIR`), mode 0700,
   holding:
   - `settings.json` (0600): hooks for `SessionStart`, `UserPromptSubmit`,
     `PreToolUse`, `PostToolUse`, `Notification`, `Stop`, each running the
     event-file command below, and the approval hook (`PermissionRequest`,
     plus a `PostToolUse` note) unless `[claude] approvals_hook = false`;
   - `events/` (0700): one file per hook event;
   - `pid` (0600): the Atem process id. The first chat an Atem process prepares
     removes `chat-*` directories under the same root whose `pid` names a
     process that no longer exists, or that have no `pid` file and are older
     than an hour (left by a crash or SIGKILL). Nothing else is touched and no
     symlink is followed.
2. Starts Claude in the shared terminal with `--settings <settings.json>` and,
   unless the user passed `--continue`/`--resume`, `--session-id <new uuid>`.
   With `--continue`/`--resume` the session id is taken from `SessionStart`.
3. Waits for `SessionStart` (fired by Claude at every start and resume, before
   any prompt; it carries `session_id` and `transcript_path`). None within 15 s
   → chat is withdrawn for this agent, with the reason shown in Atem's notices
   ("Claude hooks are not active: disabled, `--bare`, or an unsupported
   version"); the terminal keeps working. A late `SessionStart` (e.g. after
   Claude's workspace-trust question in a new directory) still enables chat.
4. The directory is removed when the agent process ends or Atem exits.

Nothing in the user's `~/.claude` settings changes. Hooks the user already has
keep running; Claude merges `--settings` with them.

### Hook events: one file each

Claude runs a hook as a shell command and passes the event JSON on stdin. Each
hook command writes that JSON to its own file, atomically:

```sh
{ f=$(mktemp "<chat dir>/events/ev.XXXXXXXX") && cat > "$f" && mv "$f" "$f.json"; } 2>/dev/null; exit 0
```

(`mktemp` gives a unique name on both Linux and macOS; `date +%N` would not
work on macOS.)

- One file per event, written then renamed, because hooks can run at the same
  time (parallel tool calls) and an event can be large (a `Write` event holds
  the whole file being written); a shared append-only file could interleave.
- Atem reads `events/*.json` ordered by modification time (nanosecond
  resolution on Linux and APFS), then name; handles each event and deletes
  the file. Files without `.json` are still being written and are skipped;
  leftovers older than a minute are removed.
- The command prints nothing and always exits 0, even when writing fails (for
  Claude, exit code 2 blocks the action and other failures are shown to the
  user), so it can never allow, deny or block
  anything, and it doesn't depend on Atem running or on the Atem binary's
  path: if Atem is gone, the file is simply never read and the directory is
  cleaned up with the session.
- No token, socket or helper process is needed: the private directory (0700)
  already limits who can write events to the user's own account.

### Reading the transcript

- Read from a saved byte offset, only up to the last complete line (a partial
  last line waits). If the file doesn't exist yet, wait for it. When
  `SessionStart` names a new transcript (`/clear`, resume), switch to it:
  - a `SessionStart` whose `transcript_path` file name isn't exactly
    `<session_id>.jsonl` (its own `session_id`) is ignored, with a notice;
  - the same path (compaction, or a resume of the session being read) keeps
    the reader;
  - before switching, the old transcript is read to its end (the switch waits
    one poll so those lines are handled normally first);
  - a resumed session's transcript (source not `startup`/`clear`) usually
    already holds that session's earlier turns: that content is **backfill**,
    added to history only (no `message` or `complete`, no status
    change), and open conversations get `error` "the conversation was
    switched; reopen the chat" and `close`, so clients reload history. Later
    lines are live.
- Order is file order. Each transcript entry is processed once, keyed by its
  entry `uuid` (bounded record of seen uuids per session).
- Entry kinds:
  - `user` entries with text → a `user` message (`role: "user"`), `turnId` =
    the entry's `promptId`; tool results (`tool_result`) are not shown.
  - `assistant` entries → parts of an `assistant` message. Claude writes one
    reply as several lines sharing `message.id` (one per content block); the
    chat `messageId` is that `message.id`, and each line is one **part** whose
    id is the entry `uuid`. Content blocks map to parts:
    - `text` → `{kind: "text", markdown}`;
    - `tool_use` → `{kind: "tool", name, summary}`: `summary` is a file path
      for file tools, the first line of the command for `Bash` (both cut at
      120 characters), or empty;
    - `thinking` → not sent.
  - A `user` entry whose text (a string, or a text block) starts with
    `[Request interrupted by user` ends the current turn as `interrupted` and
    is not shown: Esc during a reply (`[Request interrupted by user]`, with
    `interruptedMessageId`) and deny/Esc at a permission prompt
    (`[Request interrupted by user for tool use]`).
  - `isSidechain` (subagent) and `isMeta` entries, attachments, snapshots and
    other bookkeeping types → skipped.
  - A line that doesn't parse, or an unknown type → skipped, with one notice.
  - Required fields missing in a way that suggests a format change → chat is
    withdrawn for this agent with the reason.

### Status (shared state machine, fed by the adapter)

The session derives status from neutral inputs; the Claude adapter supplies
them as follows:

| Claude source | Status |
|---|---|
| `UserPromptSubmit`, `PreToolUse` | `working` |
| `Notification` asking for permission | `waiting` (approve on the card or in the terminal) |
| `Stop` | `ready` (and `complete`, below) |
| `SessionStart` `startup`/`clear`, or a different transcript | `ready`; the draft mark is reset |
| `SessionStart` `compact`/`resume` on the transcript being read (or any `SessionStart` on it while a turn is in progress) | unchanged: the turn, a prompt waiting for acceptance and the draft mark stay |
| transcript: assistant entry with `stop_reason: "end_turn"`, or the interrupt marker after Esc | `ready` (and `complete`, outcome `interrupted` for an interrupt), even if `Stop` was missed |
| agent process exits | `unknown`; the generation is retired |
| no `SessionStart`, or chat withdrawn | `unknown`, capability removed |

Every status carries `since` (time of the event that set it). Every 15 s Atem
re-sends the current state with its original `since`; it never invents a new
state. A long `working` stays `working` and `since` shows how long.
The session-v1 descriptor's `activity` (and `STATUS` in `atem agent list`)
uses the same state (`ready`, `working`, `waiting`, `unknown`); the former
`AgentRegistry` and its hard-coded `Idle` are removed.

`complete` means **Claude's execution turn has ended** (by `Stop`,
`end_turn` or an interrupt). It does not promise that no more transcript
content will arrive: a late entry for the same `turnId` may still come as
`message` after `complete`, and clients must accept it. On `Stop`,
Atem reads the transcript to its end and sends what it found before
`complete`.

### Sending a prompt from chat

`submit` is refused with an `error` (nothing is typed) unless all hold:

1. `generation` and `agentId` match the running agent process;
2. `requestId` is new **for this agent session** (not only this conversation);
   a repeated `requestId` is never executed again: Atem answers with what it
   already knows (`accepted`, `complete`, or the earlier error);
3. text is at most 32 768 UTF-8 bytes and contains only printable characters,
   `\n` and `\t` (anything else, including ESC, is refused, not stripped: an
   embedded paste-end marker could otherwise inject keystrokes), and its first
   non-whitespace character is not `/` or `!` ("commands and shell mode are not
   available from chat": a `/` command fires no hook, and `!` runs a shell
   command without a permission prompt; `#` is allowed);
4. status is `ready` and no other prompt is waiting for acceptance;
5. **nobody typed into the terminal since the last turn ended** (local or
   Astation terminal input both count). Input typed while the agent is working
   is treated as consumed when the turn ends; an unfinished draft typed during
   a turn is not detected (v1);
6. no Astation viewer holds terminal control.

Then Atem writes the text as one bracketed paste followed by Enter, and
records the request. It is `accepted` when **both** the `UserPromptSubmit`
hook and the matching `user` entry in the transcript have arrived with the
same text (compared without leading and trailing whitespace). No acceptance within 10 s → `error {requestId, "delivery unknown;
check the terminal"}`; it is never resent.

Prompts typed in the terminal arrive the same way and appear as user
messages with `origin: "local"`.

## Message model (client-neutral)

```
message {
  messageId,          // Claude message.id (assistant) or entry uuid (user)
  role: "user" | "assistant",
  origin?: "local" | "remote",   // user messages only
  turnId,             // the prompt this message belongs to (Claude promptId)
  requestId?,         // on user messages with origin "remote", and on the
                      // assistant messages and `complete` of that turn
  createdAt,          // RFC 3339 / unix ms, from the transcript
  parts: [ { id, kind: "text", markdown } | { id, kind: "tool", name, summary }
         | { id: "approval", kind: "approval", approval_id, tool, summary,
             always_rules: [{rule_id, label, scope}],
             state: pending|allowed|always_allowed|denied|answered_terminal|expired|closed
                    |auto_allowed,
             rule_id?,       // auto_allowed: the Atem session rule that allowed it
             reason?,        // final cards (r8 approval.card_reason): the
                             // approval_closed reason (answered_remote, …)
             note? } ],      // e.g. an allow_always whose rule wasn't kept
  history?: true,     // from a history page, or recovered after a gap
  page_id?,           // the history request's page id (absent on the open's page)
  after_message_id?   // recovered after a backlog gap: the retained message
                      // it follows, null when none precedes it (always present)
}
```

- A message that grows (a later part, e.g. a tool call after the text of
  the same assistant message) is sent again whole, with the same
  `messageId` and every part so far, at the conversation's next sequence;
  it replaces the earlier version (r8 §B; before r8 Atem sent the new part
  alone as `delta`, which r8 no longer sends). It is not a token stream:
  each part arrives whole (`unavailable` lists `streaming`). Trade-off: a
  message that grows part by part costs its whole size each time, but a
  message is capped (131 072 bytes of content, 2048 parts) and a version is
  sent only when a transcript entry adds parts, so the cost is bounded,
  and one rule (the highest sequence wins) covers live updates, pages and
  recovered messages alike.
- Markdown is CommonMark without raw HTML, so native apps can render it
  without a web view.
- IDs never change, so clients can cache messages and merge updates.
- Pages send each message whole with all its parts so far. Keep per
  `messageId` the version with the highest sequence; a page never replaces
  a newer version.
- An approval card is an assistant message `approval-<approval_id>`; when its
  state changes the whole message is sent again with the same `messageId`
  (replace it). Final cards carry `reason`, the `approval_closed` reason
  (`answered_remote` with the decision's state, `answered_terminal`,
  `interrupted`/`released`/`process_ended` as `closed`, `timed_out` as
  `expired`); the first reason is kept. A chat `submit` with `approval` (the
  §6a payload) instead of `text` answers it: it needs `control`, never the
  lease (r8 §G: `lease_epoch` optional and ignored, `acquire` refused, the
  first admitted answer wins).
- An `auto_allowed` card (Codex, r7.2) is final when it arrives: the worker
  allowed the request by the session rule `rule_id` without asking; it
  offers nothing to answer (`always_rules: []`).
- `waiting` and `complete` are the events a mobile app can turn into push
  notifications (delivery is Astation's/the app's concern).

## Wire (agentChat v1)

Carried as `{"type":"agentChat","data":{"v":1,"op":…,"conversationId":…,"agentId":…}}`
on the existing authenticated Astation connection.

| op | Direction | Fields |
|---|---|---|
| `open` | Astation → Atem | `conversationId`, `agentId`, `binding` (`before`/`generation` are removed in r8: `unsupported_version`, nothing reset, nothing opened) |
| `opened` | Atem → Astation | `generation`, `sequence: 0`, `status {state, since}`, `unavailable` (array of strings, below), `approvalRules` (the session's active Atem session rules `[{rule_id, label, scope}]`; `[]` without `control`), then the newest page as `message{history:true}` events and a sequenced `history_end` (`selector: "newest"`) |
| `history` | Astation → Atem | `generation`, `page_id` (1–64 bytes `[A-Za-z0-9._:-]`), `binding`, and exactly one of `before` (messageId), `turn_id`, `request_id` (lowercase v4 UUID) or `next` (token from the last `history_end`) |
| `history_end` | Atem → Astation | `page_id` (absent on the open's page), `page {selector, count, content_bytes, wire_bytes, end, next?, coverage, oldest_retained, truncated, holes, holes_more?}` |
| `coverage` | Atem → Astation | `oldest_retained`, `truncated`, `holes` (≤ 16, then `holes_more`): after a backlog reload left a hole |
| `submit` | Astation → Atem | `generation`, `requestId` (UUID), `binding`, and one of `text` (optionally `acquire: true`, with `takeover: true` and `expected_controller`, r8 §F), `approval` (§6a answer; `control` only, no lease, r8 §G) or `approval_rule_revoke` (`{rule_id}`, r7.2; `control` only, no lease: r7.3) |
| `rules` | Atem → Astation | `approvalRules` (the whole list, when it changed; conversations with `control` only) |
| `accepted` | Atem → Astation | `requestId`; `lease {lease_epoch, ms_left}` when the admitted submit carried `acquire` (a grant, a takeover, or the sender's own lease unchanged; r8 §F) |
| `message` | Atem → Astation | see the message model (a later version replaces the earlier one) |
| `status` | Atem → Astation | `state: ready|working|waiting|unknown`, `since`, optional `detail` |
| `complete` | Atem → Astation | `turnId`, optional `requestId`, `outcome: "done"|"interrupted"` (below) |
| `error` | Atem → Astation | `text` (safe, no secrets), optional `requestId`, and `code` on every `error` the session host makes: `rejected` or `outcome_unknown` (a submit's receipt), a session-v1 code from admission (`stale_target`, `stale_lease`, `lease_held` with `controller {controller_session, lease_epoch}`, `forbidden`, …), `invalid_request` (a `history` or Send field rule), `unsupported_version` (a malformed or removed chat message) or `busy` (`open` without chat-v1, too many `history` requests); a history request's error carries its `page_id` when that was valid; the chat's own errors (the agent exited or was restarted, the conversation was switched, chat withdrawn) carry no `code`; an `error` sent before a conversation is open (unknown agent, chat unavailable, bad request) carries no `generation`/`sequence` |
| `close` | either | `conversationId`; from Atem `reason`: `switched`, `withdrawn`, `restarted` or `evicted` (r8 §C); from Astation `binding` is optional (without it, only the sender attachment's own conversation closes) |

- **History (r8 §B, §C).** A conversation is one ordered stream: every
  Atem event in it, pages included, takes the next `sequence`, and a page
  is built in one step from the retained history (no live event of that
  conversation comes between its envelopes; every later event has a higher
  sequence). Keep per `messageId` the version with the highest sequence.
  `history` pages carry `message{history:true, page_id}` then
  `history_end`. Bounds per page: 50 messages, 256 KiB of content (as
  `ChatMessage::bytes` counts it: ids, text, 64 bytes per part, 1 KiB per
  card) and 1 MiB serialized, `history_end` included (`wire_bytes`); a
  page stops before the message that would pass a bound and holds at least
  one when one remains. `newest`/`before` go backwards (each page oldest
  first); `turn_id`/`request_id` go forwards from the turn's oldest retained
  message to its newest at the first page's snapshot (later messages of the
  turn arrive live). `next` is an HMAC-SHA256 token under a key made for
  each runtime run, bound to the attachment, conversation, session,
  `process_gen`, selector, continuation point and the history's reload
  count; out of context, altered, evicted, after a reload or a restart it
  is `stale_target` (start a new selection). A `before` no longer retained
  is `stale_target`; a lookup with nothing retained is an empty page
  (`count: 0, end: true, coverage: "unavailable"`). Field errors are
  `invalid_request` (sequenced in an open conversation, with the valid
  `page_id`); a conversation that isn't open on this attachment, or another
  `generation`, is `stale_target`; more than 8 valid requests a second per
  conversation is `busy` (invalid ones aren't counted). Nothing resets.
- **Coverage.** `coverage` is `complete`, `partial` or `unavailable`; a
  turn is `partial` when its oldest messages were evicted or a hole touches
  it. `truncated` turns true once anything was evicted (retention, or an
  adoption cut) and `oldest_retained` names the oldest retained message.
  Holes are gaps a backlog reload couldn't restore, named by their
  neighbours (`before_message_id: null` at the live edge until the next
  message); a `history_end` lists those whose `before_message_id` is in its
  page plus a live-edge hole on the newest page (≤ 16, then `holes_more`).
  A view-only attachment sees no card ids here: holes are named by visible
  neighbours, one with no visible message before it is left out and
  reported as truncation (`truncated: true`, so the selection is
  `partial`), `oldest_retained` is the oldest visible message, and a
  `before` naming a card is `stale_target`. Truncation, holes and
  `coverage` events never ask for a reopen; only a sequence gap, another
  `generation`, a fenced attachment or `close` with a `reason` do.
- `open` on a running session whose chat-v1 is off (Claude before its
  SessionStart or after chat was withdrawn, Codex without Atem's hooks) is
  answered `error{code:"busy"}` with the text "chat is not available for
  this agent" (`: <reason>` when the adapter gave one) and opens nothing.
  Codex with Atem's hooks offers chat-v1 from launch: `open` before its
  first hook succeeds with status `unknown` and the detail "type a first
  prompt in the terminal: …", and a `submit` is refused with that text
  until the first hook arrives. An exited agent's history stays readable.
- `complete.outcome` is the adapter's turn end: `interrupted` when the turn
  ended interrupted (Esc, a deny at a permission prompt, Codex's
  `turn_aborted`), else `done`. A remote prompt's `complete` follows its
  completed receipt, whose `detail` is the outcome (`"done"` or
  `"interrupted"`, journaled as that word only), so a duplicate `submit`
  after a broker restart gets the real outcome too.
- `opened.unavailable` names what this agent's chat can't provide, so a
  client says so instead of waiting for it: `streaming` (no partial text:
  messages arrive whole), `reasoning`, `error_details` (no model/API error
  behind a failed turn). Claude: `streaming` (transcript blocks arrive
  whole) and `reasoning` (thinking blocks aren't shown); Codex: all three
  (its "always allow" is an Atem session rule, so it is not listed). It comes from the adapter's
  `Capabilities.unavailable`, carried by the worker's `chat` and
  `chat_snapshot` messages (field `unavailable`).
- Every Atem event in a conversation carries `generation` and the next
  `sequence` (1, 2, …; at most 2^53−1). A gap or a different generation means
  the client reopens.
- Unknown fields are ignored; new fields stay optional; `v` changes only for
  incompatible changes. Size limits: prompt 32 768 bytes, message 131 072
  bytes (larger messages are truncated with a note).
- A conversation belongs to the connection that opened it; it closes when that
  connection drops or re-authenticates. Opening again restores status and
  history.
- Each conversation gets the status again 15 s after it last got it (on
  `opened` or a heartbeat). At most 8 conversations are open per agent:
  opening a ninth sends the least recently opened one `close{reason:
  "evicted"}`.
- Atem keeps the newest 500 messages, at most 8 MiB, per agent process.

## Security

- `agentChat` is handled only on an authenticated Astation connection, never
  while re-authentication is pending, and every request is bound to the
  connection, agent and process generation.
- Hook events: the per-session directory is 0700 (event files are written
  inside it), so only the user's own account can add events. The trust
  boundary is that account: a process running as the user could forge an event
  file; that can mislabel status but cannot approve a tool, type input or read
  anything, and acceptance additionally needs the transcript's own user entry.
  Approval decisions go the other way (Atem writes them for the hook in the
  session's `approvals/` directory, 0700) and only for a prompt the hook
  reported. A same-user process that can see `ATEM_APPROVAL_DIR` can forge
  a request file: the result is a fake card, never an agent action
  (same-user attackers are out of scope).
  Event files can hold tool input (file contents); they stay in the private
  directory and are deleted as soon as they are read.
- Outgoing text and tool summaries pass Atem's credential detector
  (`src/memory/secrets.rs`); matches become `[redacted]`. Thinking, tool output
  and file contents are never sent.
- Transport: the existing TLS connection through the relay, so the relay can
  read chat content. End-to-end encryption of chat (e.g. with the account key)
  is a follow-up.

## Failure handling

| Case | Behaviour |
|---|---|
| Atem not running when a hook fires | the event file is written and never read; Claude is unaffected; the directory goes with the session |
| Claude exits or crashes | `unknown`, `error` to open conversations, generation retired, prompts refused |
| Agent restarted | open conversations get `error` "the agent was restarted; reopen the chat" and `close{reason:"restarted"}`; the new process has a new generation |
| Another session resumed in the same process | its earlier turns become history (no events); open conversations get `error` "the conversation was switched; reopen the chat" and `close{reason:"switched"}`; same generation |
| Bad or unknown transcript line | skipped, one notice; reading continues |
| Transcript format changed (required fields missing) | chat withdrawn for this agent, with the reason (open conversations get `error` and `close{reason:"withdrawn"}`); terminal unaffected |
| No acceptance within 10 s of a paste | `error` "delivery unknown"; never resent |
| Astation disconnects / re-authenticates | conversations close; Claude keeps running; a new `open` restores status and history |
| The worker dropped chat items before they reached the broker (its backlog overflowed in one read, `chat.gap > 0`) | r8 §C: the broker asks the worker for its whole retained history (`request_chat_history` → `chat_history_part`s + `chat_history`), replaces its own with it (keeping its newer approval card states, and the worker's truncation and cut turn) and catches up with the worker's chat state carried in `chat_history` (status, current and last completed turn with its outcome, input mark: a turn end it missed completes then, and so does its prompt's receipt). Every recovered (new or changed) message goes to open conversations as a sequenced `message{history:true, after_message_id}` (cards only to conversations with `control`); no `error`, no `close`, no reopen. Without a worker to ask, when the worker goes away before answering, or when the reload is over its bound (1000 messages), the gap stays as a hole (no `count`) and open conversations get a sequenced `coverage` event |
| Broker restart or adoption | the worker's `chat_snapshot` carries its whole retained history (500 messages / 8 MiB), older messages first in `chat_history_part` lines of at most 1 MiB each, approval cards included (the broker copies every card to the worker, `chat_card`); a card still `pending` becomes `closed` with the note "Atem's runtime restarted; answer in the terminal" (the new broker released its approval). Prompt acceptance in flight is not carried |
| Atem exits | the terminal and Claude end with it (as today); a new Atem has a new generation |

## Testing

- Unit: transcript reader on anonymised real samples (block merging, part
  ids, dedupe, partial lines, session switch, interrupt, unknown types);
  status table; `submit` checks (generation, duplicate request, size, control
  characters, draft, terminal control); redaction; wire encode/decode and
  sequence/generation rules.
- Integration (`tests/`, like `terminal_ui_binary`): a fake `claude` script
  that runs the hook commands from `settings.json` and writes a transcript, run by the real binary
  in a pseudo-terminal against a fake Astation WebSocket: open with history;
  submit → accepted → message → complete; refusal after local typing;
  duplicate request; process exit → unknown; reconnect keeps state.
- r8 history: `src/chat/history_tests.rs` (paging, bounds with escaping,
  lookups, token binding, coverage, holes, view-only), broker tests (gap
  reload, holes, cut turns), `host_bridge_tests` over the real runtime with
  the fake Claude, the shared fixtures in both runners (the real runtime
  writes the fixtures' chat content through the fake Claude's transcript),
  and the real-agent Codex test (open page, `before`, lookup by
  `request_id`, `receipt.result`).
- Before building on them, confirm on the installed Claude Code 2.1.x:
  `--settings` hooks fire in interactive mode and receive the event JSON on
  stdin, `SessionStart` arrives before
  the first prompt with `session_id`/`transcript_path`, `--session-id` names
  the transcript, and the interrupt marker's exact form.
- Manual acceptance with real Claude Code and Astation's page.

Verified on Claude Code 2.1.299 (fixtures in tests/fixtures/chat/claude/).

## Changes to the proposed contract (for the Astation agent)

Additive to `mem_b3ccce1f`:

- `message` gains `role`, `origin` (user messages), `turnId`, `createdAt`,
  `parts` (typed: `text` with CommonMark-no-HTML, `tool` with name/summary)
  instead of a single Markdown `text`, and `history`.
- `delta` appended one typed part with an id (removed in r8: a growing message is sent whole again).
- `complete` gains `turnId` and `outcome`; it means the execution turn ended,
  not that no more content can arrive.
- `status` gains `since` and is re-sent every 15 s with the original `since`.
- `open` gained optional `before` for history pages (2026-10-17); r8 removed
  it in favour of `history` and `history_end`.
- `requestId` deduplication is per agent session (stronger than per
  conversation).
- `submit` can be refused because of a local draft, terminal control, status
  not `ready`, or control characters; the `error` text says which.

## Out of scope (v1)

Adapters other than Claude Code and Codex; streaming
token-by-token (the transcript holds whole content blocks); end-to-end
encryption of chat; push delivery of chat messages (approvals ask the relay
to push, §6a); attachments/images.

## Codex

The Codex adapter (`src/chat/codex/adapter.rs`) runs in the worker when
`[codex] hooks = true` (one consent for approvals and chat). Atem's entries
in `$CODEX_HOME/hooks.json` run `approval-hook.sh event <Event>`, which
writes each event to the session's `events/` as `ev-<seq>-<Event>.json`:
first a line with the hook's `$$ $PPID`, then its stdin. The rollout JSONL
named by `transcript_path` carries every message and turn boundary. With
the setting on, each Codex worker runs the idempotent hooks.json merge
itself (backup, read-back, restore) in the launch's `CODEX_HOME` before
spawning, so a session launched from the bare `atem` menu gets every hook
too; it never asks and never writes when the setting is unset or false,
and a failure is a session notice (Codex starts anyway).

- **Ownership.** Only hooks the session's agent started count
  (`approvals::HookAgent` over `started_by`, shared with approvals): with
  the hook's parent the agent (or one shell under it) a hook may pin or
  re-pin (`/new`); through a non-shell child (npm's wrapper: node runs the
  real binary) only the pinned session's, or the first — which makes that
  child the agent, so the real binary's `/new` re-pins and a `codex` it
  starts without a shell still can't; deeper (a `codex` a tool ran) never.
  A wrapped hook read after its parent exited counts as foreign (harmless:
  the rollout's end record is authoritative).
- **Session switches.** A SessionStart of another session re-pins (the
  old rollout is read to its end first). The agent's own UserPromptSubmit
  of another session read before that SessionStart (async hooks publish in
  either order after `/new`) re-pins the same way, and the SessionStart
  read later is then no restart. A resumed rollout is read to its end at
  the switch, however many 8 MiB reads that takes, so all of it is history
  (except a turn still running at its end).
- **Status.** `unknown` until the first hook (SessionStart is lazy: it
  fires at the first prompt), with the detail "type a first prompt in the
  terminal: …"; chat opens, but `submit` is refused with that text (a
  remote prompt needs `ready`: text typed into Codex's startup dialogs could
  answer them). Then `working` from UserPromptSubmit or the rollout's
  `task_started`, `waiting` while the worker has approvals of this session
  open for a remote answer (its set is the only source: Codex has no event
  of its own; after a re-pin with some open it is waiting again) or has
  released one to Codex's own dialog ("no decision": input to Codex — which
  is consumed, never written, so it can't answer the dialog the user hadn't
  seen; a remote prompt or interrupt that released one is `rejected` — no
  broker, an adopting broker that doesn't know it, a prompt or interrupted
  turn end closing it, its hook ending without one) — each such approval
  (its call: tool and `tool_input.command`) until evidence from after it
  went there: the PostToolUse of that same call, or the dialog dismissed or
  gone (Interrupt or UserPromptSubmit hook, the rollout's next user message
  or `turn_aborted`); never a Stop, a plain `task_complete`, a reply or
  another call's result (Codex's rollout names no call for a command, so a
  command item proves nothing) — `ready` at `task_complete` /
  `turn_aborted` otherwise.
  Codex's waits outlast the turn: Codex (0.163, its exec cell) may end the
  turn while the approval still waits, or with its dialog still open, so a
  plain turn end neither closes an open approval nor makes the session
  `ready` (`WaitingForPermission.outlasts_turn`: the turn completes, the
  status stays `waiting`, and the wait's end makes it `ready`); an
  interrupted turn end does both. While an approval sits in Codex's own
  dialog the worker consumes a chat prompt's paste ("Codex's approval
  dialog is open in the terminal; answer it there; not written", the
  prompt `rejected`): its Enter would pick the dialog's default, an allow
  no one gave. The worker latches a "no decision" at once (not at its next
  approvals pass), and while Codex waits (an approval open or a dialog) it
  holds chat prompts at the PTY write boundary too, so a prompt queued
  before is never written (`FencedOutcome::Held`, reported like a consumed
  paste). Terminal input is still written (whoever types sees the
  dialog). A refusal in Codex's dialog leaves no evidence Atem can read:
  the session stays `waiting` until a prompt typed in the terminal or an
  interrupt (fail closed). Found live on 2026-10-29: a remote prompt pasted into the
  dialog approved a command.
- **Prompts.** Pasted bracketed plus Enter through the worker; accepted when
  UserPromptSubmit and the rollout's UserMessage both name it, with the same
  `turn_id`; completed at that turn's end (interrupted at `turn_aborted`).
  `interrupt` writes Esc only while a turn is known to run (`working` or
  `waiting`) and completes at the next turn end; in `ready` or `unknown`
  it completes at once with nothing written (Esc on Codex's startup trust
  dialog quits Codex). A session without turn state, for any agent (Codex
  with its hooks off, Claude before its SessionStart or after its chat was
  withdrawn), gets `interrupt` `rejected` ("no turn state; use the
  terminal") and never an Esc.
- **Approvals and chat evidence.** A new prompt or a turn end (stamped with
  its hook file's or log entry's time) answers only a permission prompt
  opened before it, for both agents: one read in the same pass as a newer
  request leaves it open. For Codex only a prompt or an interrupted turn
  end counts (a plain turn end leaves its approval waiting, see Status).
- **Pairing a remote prompt.** Only a hook (its event file's time) and a log
  entry (its timestamp) from after the paste can be the remote prompt's, and
  only the first of each whose turn isn't known to be another: a local
  prompt with the same text typed just before is a local turn. A
  whole-second time counts up to the end of its second. This applies to
  Claude as well.

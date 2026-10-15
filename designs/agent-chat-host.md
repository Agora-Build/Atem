# Agent chat (chat-v1): Atem host side

Status: design approved 2026-10-15; not implemented. Astation side (browser
page, later a mobile app) is the Astation agent's; its proposed contract is the
starting point (atem memory `mem_b3ccce1f`, project github.com/agora-build/atem)
and this document lists the changes Atem needs (see "Changes to the proposed
contract").

## Goal

A chat view of a coding agent that runs in Atem's shared terminal
(`atem agent launch`). Prompts show as outgoing user messages, the agent's
replies as incoming messages, with an honest activity indicator. Web first;
a mobile app later uses the same events, so the host side is client-neutral.

v1 supports **Claude Code** only. Codex reports status `unknown` and no
`chat-v1` capability until a separate design (its rollout files and hooks
differ).

## Rules

- **One source of content:** Claude's own transcript. Hooks only mark the
  lifecycle. Atem never scrapes the terminal screen and never infers that a
  turn is done or waiting from silence.
- **The original session stays.** Atem keeps using the interactive Claude CLI
  it launched; chat never starts another Claude process or session.
- **No approvals from chat.** Tool permission requests are answered in the
  terminal; chat only shows `waiting`.
- **Never merge with a local draft.** A chat prompt is refused when anyone
  typed into the terminal since Claude's last turn ended.
- **Never resend.** A prompt whose delivery is unknown is reported, not retried.
- **Honest status.** States come from real events; when Atem can't tell, it
  says `unknown`.

## How it works

### Launch

`atem agent launch claude [args…]`:

1. Creates a private per-session directory, `$XDG_RUNTIME_DIR/atem/chat-<id>/`
   (or `~/.config/atem/run/chat-<id>/` without `XDG_RUNTIME_DIR`), mode 0700,
   holding:
   - `settings.json` (0600): hooks for `SessionStart`, `UserPromptSubmit`,
     `PreToolUse`, `PostToolUse`, `Notification`, `Stop`, each running the
     event-file command below;
   - `events/` (0700): one file per hook event.
2. Starts Claude in the shared terminal with `--settings <settings.json>` and,
   unless the user passed `--continue`/`--resume`, `--session-id <new uuid>`.
   With `--continue`/`--resume` the session id is taken from `SessionStart`.
3. Waits for `SessionStart` (fired by Claude at every start and resume, before
   any prompt; it carries `session_id` and `transcript_path`). None within 15 s
   → chat is withdrawn for this agent, with the reason shown in Atem's notices
   ("Claude hooks are not active: disabled, `--bare`, or an unsupported
   version"); the terminal keeps working.
4. The directory is removed when the agent process ends or Atem exits.

Nothing in the user's `~/.claude` settings changes. Hooks the user already has
keep running; Claude merges `--settings` with them.

### Hook events: one file each

Claude runs a hook as a shell command and passes the event JSON on stdin. Each
hook command writes that JSON to its own file, atomically:

```sh
d=<chat dir>/events; f="$d/$(date +%s%N)-$$"; cat > "$f.tmp" && mv "$f.tmp" "$f.json"
```

- One file per event, written then renamed, because hooks can run at the same
  time (parallel tool calls) and an event can be large (a `Write` event holds
  the whole file being written); a shared append-only file could interleave.
- Atem reads `events/*.json` in name order (timestamp, then process id),
  handles each event and deletes the file. `.tmp` files are ignored; leftovers
  older than a minute are removed.
- The command prints nothing and exits 0, so it can never allow, deny or block
  anything, and it doesn't depend on Atem running or on the Atem binary's
  path: if Atem is gone, the file is simply never read and the directory is
  cleaned up with the session.
- No token, socket or helper process is needed: the private directory (0700)
  already limits who can write events to the user's own account.

### Units

| Unit | Responsibility |
|---|---|
| `src/chat/hooks.rs` | Builds the per-session directory and `settings.json`; reads, orders and deletes the event files |
| `src/chat/transcript.rs` | Follows the transcript and turns entries into chat messages (below) |
| `src/chat/session.rs` | Per-agent chat state: status, recent messages, the draft tracker, prompt submission and acceptance, request-id records |
| `src/chat/wire.rs` | `agentChat` v1 messages to and from Astation: encoding, decoding, validation |
| `src/agent_registry.rs` | Status from `session.rs`; `capabilities: ["chat-v1"]` only for Claude agents whose hooks are active |

All of it lives in the Atem process that owns the terminal; there is no new
daemon. Chat state belongs to the agent session, not to a browser connection:
Claude keeps running and Atem keeps reading the transcript whether or not any
chat page is open.

### Reading the transcript

- Read from a saved byte offset, only up to the last complete line (a partial
  last line waits). If the file doesn't exist yet, wait for it. When
  `SessionStart` names a new transcript (`/clear`, compaction, resume), switch
  to it.
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
  - `isSidechain` (subagent) and `isMeta` entries, attachments, snapshots and
    other bookkeeping types → skipped.
  - A line that doesn't parse, or an unknown type → skipped, with one notice.
  - Required fields missing in a way that suggests a format change → chat is
    withdrawn for this agent with the reason.

### Status

| Source | Status |
|---|---|
| `UserPromptSubmit`, `PreToolUse` | `working` |
| `Notification` asking for permission | `waiting` ("approve in the terminal") |
| `Stop` | `ready` (and `complete`, below) |
| transcript: assistant entry with `stop_reason: "end_turn"`, or the interrupt marker after Esc | `ready` (and `complete`, outcome `interrupted` for an interrupt), even if `Stop` was missed |
| agent process exits | `unknown`; the generation is retired |
| no `SessionStart`, or chat withdrawn | `unknown`, capability removed |

Every status carries `since` (time of the event that set it). Every 15 s Atem
re-sends the current state with its original `since`; it never invents a new
state. A long `working` stays `working` and `since` shows how long.
`AgentRegistry` status uses the same state (`ready`→`Idle`,
`working`→`Thinking`, `waiting`→`WaitingForInput`, plus `Unknown`), replacing
today's hard-coded `Idle`.

`complete` means **Claude's execution turn has ended** (by `Stop`,
`end_turn` or an interrupt). It does not promise that no more transcript
content will arrive: a late entry for the same `turnId` may still come as
`message`/`delta` after `complete`, and clients must accept it. On `Stop`,
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
   embedded paste-end marker could otherwise inject keystrokes);
4. status is `ready` and no other prompt is waiting for acceptance;
5. **nobody typed into the terminal since the last turn ended** (local or
   Astation terminal input both count);
6. no Astation viewer holds terminal control.

Then Atem writes the text as one bracketed paste followed by Enter, and
records the request. It is `accepted` when **both** the `UserPromptSubmit`
hook and the matching `user` entry in the transcript have arrived with the
same text. No acceptance within 10 s → `error {requestId, "delivery unknown;
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
  parts: [ { id, kind: "text", markdown } | { id, kind: "tool", name, summary } ],
  history?: true      // backfill on open / page
}
delta { messageId, part: { id, kind, … } }   // append one part; a part id
                                             // already present is ignored
```

- Markdown is CommonMark without raw HTML, so native apps can render it
  without a web view.
- IDs never change, so clients can cache messages and merge updates.
- History never replays deltas: each message is sent whole with all its parts
  so far; clients replace what they had.
- `waiting` and `complete` are the events a mobile app can turn into push
  notifications (delivery is Astation's/the app's concern).

## Wire (agentChat v1)

Carried as `{"type":"agentChat","data":{"v":1,"op":…,"conversationId":…,"agentId":…}}`
on the existing authenticated Astation connection.

| op | Direction | Fields |
|---|---|---|
| `open` | Astation → Atem | `conversationId`, `agentId`, optional `before` (messageId) |
| `opened` | Atem → Astation | `generation`, `sequence: 0`, `status {state, since}`, then history as `message` events (latest 50 or 256 KB, older pages with `before`) |
| `submit` | Astation → Atem | `generation`, `requestId` (UUID), `text` |
| `accepted` | Atem → Astation | `requestId` |
| `message` / `delta` | Atem → Astation | see the message model |
| `status` | Atem → Astation | `state: ready|working|waiting|unknown`, `since`, optional `detail` |
| `complete` | Atem → Astation | `turnId`, optional `requestId`, `outcome: "done"|"interrupted"` |
| `error` | Atem → Astation | `text` (safe, no secrets), optional `requestId` |
| `close` | either | `conversationId` |

- Every Atem event in a conversation carries `generation` and the next
  `sequence` (1, 2, …; at most 2^53−1). A gap or a different generation means
  the client reopens.
- Unknown fields are ignored; new fields stay optional; `v` changes only for
  incompatible changes. Size limits: prompt 32 768 bytes, message 131 072
  bytes (larger messages are truncated with a note).
- A conversation belongs to the connection that opened it; it closes when that
  connection drops or re-authenticates. Opening again restores status and
  history.

## Security

- `agentChat` is handled only on an authenticated Astation connection, never
  while re-authentication is pending, and every request is bound to the
  connection, agent and process generation.
- Hook events: the per-session directory is 0700 (event files are written
  inside it), so only the user's own account can add events. The trust
  boundary is that account: a process running as the user could forge an event
  file; that can mislabel status but cannot approve a tool, type input or read
  anything, and acceptance additionally needs the transcript's own user entry.
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
| Bad or unknown transcript line | skipped, one notice; reading continues |
| Transcript format changed (required fields missing) | chat withdrawn for this agent, with the reason; terminal unaffected |
| No acceptance within 10 s of a paste | `error` "delivery unknown"; never resent |
| Astation disconnects / re-authenticates | conversations close; Claude keeps running; a new `open` restores status and history |
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
  submit → accepted → message/delta → complete; refusal after local typing;
  duplicate request; process exit → unknown; reconnect keeps state.
- Before building on them, confirm on the installed Claude Code 2.1.x:
  `--settings` hooks fire in interactive mode and receive the event JSON on
  stdin, `SessionStart` arrives before
  the first prompt with `session_id`/`transcript_path`, `--session-id` names
  the transcript, and the interrupt marker's exact form.
- Manual acceptance with real Claude Code and Astation's page.

## Changes to the proposed contract (for the Astation agent)

Additive to `mem_b3ccce1f`:

- `message` gains `role`, `origin` (user messages), `turnId`, `createdAt`,
  `parts` (typed: `text` with CommonMark-no-HTML, `tool` with name/summary)
  instead of a single Markdown `text`, and `history`.
- `delta` appends one typed part with an id; repeated part ids are ignored.
- `complete` gains `turnId` and `outcome`; it means the execution turn ended,
  not that no more content can arrive.
- `status` gains `since` and is re-sent every 15 s with the original `since`.
- `open` gains optional `before` for history pages.
- `requestId` deduplication is per agent session (stronger than per
  conversation).
- `submit` can be refused because of a local draft, terminal control, status
  not `ready`, or control characters; the `error` text says which.

## Out of scope (v1)

Codex chat; approvals from chat; streaming token-by-token (the transcript
holds whole content blocks); end-to-end encryption of chat; push delivery;
attachments/images.

# Codex lifecycle hooks and rollout transcript (spike for a Codex chat adapter)

codex-cli 0.162.1, Linux, interactive TUI in tmux (140x45), `codex --profile oss -a on-request -s read-only`,
throwaway HOME, CODEX_HOME and project (only the non-secret `oss` provider fields copied, as in
`tests/approvals_real_agents.rs`). One `hooks.json` entry per event (12 events), all running the same
observe-only `hook.sh` (stdin → file, no output, exit 0), plus one `async: true` Stop entry later.
7 model turns + 1 `/compact`. Real ids, paths and the username are replaced: `<session-A>` (main
session), `<session-B>` (after `/new`), `<turn-N>`, `<id-N>`, `<msg-N>`, `<call-N>`, `<exec-N>`, …;
`/home/user/.codex` = CODEX_HOME, `/home/user/proj` = cwd. Long strings are truncated with a marker,
`encrypted_content` and `rate_limits` removed, `token_count` records dropped (the `ordinal` field is kept,
so gaps show where they were).

Files:
- `hooks/NN-<Event>[-note].json`: every hook stdin, in firing order (the run is described below).
- `rollout-session-A.jsonl`: the whole main session: turns 1–5, then resume and turn 6.
- `rollout-session-B-new-and-compact.jsonl`: the session `/new` made: one turn, then `/compact`.
- `hooks.json` (as installed, before the async entry was reordered), `hook.sh`, `trust-state-excerpt.toml`,
  `screen-approval-dialog.txt`, `screen-hooks-review-detail.txt`.

The run (session A unless noted): turn 1 "Reply with exactly the word: pong" (01–03); turn 2 `touch made.txt`
needing approval, approved with `y` (04–08); turn 3 commentary + `cat notes.txt` (the sandboxed attempt failed
on bwrap, the escalated one needed approval, approved) + a streamed 120-word poem (09–15); turn 4 a long
answer, Esc after 3.5 s while streaming (16–17); turn 5 a two-line bracketed paste asking for `touch two.txt`,
Esc at the approval dialog (18–21); `/new` → session B, one turn (22–24), `/compact` (25–26); quit (27–28);
`codex resume <session-A>`, one turn (29–33).

## 1. Lifecycle hooks

Supported (docs + `/hooks`): SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PermissionRequest,
PostToolUse, PreCompact, PostCompact, Stop, Interrupt, SubagentStart, SubagentStop. There is **no
Notification event**. All 12 load; SubagentStart/Stop never fired (no subagents). Every stdin has
`session_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`; all but SessionEnd/Pre/PostCompact add
`permission_mode`; turn-scoped ones add `turn_id`. No hook gets a message id; the hook env is Codex's own
env (the launch environment, so a worker-set variable like `ATEM_APPROVAL_DIR` reaches every hook); the
hook's parent is the codex binary. No Codex-specific env var names the session.

| Event | Extra fields | When (observed) |
|---|---|---|
| SessionStart | `source` (`startup`, `resume`) | **Lazily, at the first prompt submit** (~25 ms before UserPromptSubmit), not at launch. `/new` → `startup` with the new id. Not fired for `/compact`. |
| UserPromptSubmit | `turn_id`, `prompt` (verbatim, `\n` kept) | ~25 ms after Enter, before the rollout's user record (~20 ms later). |
| PreToolUse | `turn_id`, `tool_name` (`Bash`), `tool_input{command}`, `tool_use_id` (= rollout `CommandExecution` item id `exec-…`) | Before each exec attempt, **before** PermissionRequest. A sandboxed attempt and its escalated retry are two PreToolUses. |
| PermissionRequest | `turn_id`, `tool_name`, `tool_input{command, description}`; no `tool_use_id` | Right before the approval dialog (dialog is held while a hook runs). |
| PostToolUse | `turn_id`, `tool_name`, `tool_input`, `tool_response` (output string), `tool_use_id` | After the command ran, also when it failed (sandbox error in `tool_response`). Not after a cancelled approval. |
| Stop | `turn_id`, `stop_hook_active`, `last_assistant_message` (`""` possible) | At a normal turn end, ~25 ms before the rollout's `task_complete`. **Not** for an interrupted turn, **not** for `/compact`. |
| Interrupt | `turn_id` | On Esc, both while streaming and at the approval dialog, ~25 ms before `turn_aborted`. Timeout clamped to ≤3 s. |
| PreCompact / PostCompact | `turn_id`, `trigger` (`manual`); no `permission_mode` | Around `/compact`. |
| SessionEnd | `reason` (`other`); no `turn_id`, no `permission_mode` | **Only at process exit**, once per session that ran: after `/new` the old session's SessionEnd came at quit, together with the new one's. Timeout clamped to ≤3 s. |

Behaviour: an entry that prints nothing and exits 0 has no effect on any event, Stop included (docs say Stop
needs JSON on exit 0; nothing was reported). What can change behaviour (docs): exit 2 or `decision:"block"` on
UserPromptSubmit (blocks the prompt), PreToolUse (denies), PostToolUse (replaces the result), Stop (makes Codex
continue with `reason` as a new prompt); plain text on SessionStart/UserPromptSubmit becomes model context;
`continue:false` on SessionStart-after-compact/Pre/PostCompact stops. Sync hooks also delay Codex (up to
`timeout`). `async: true` runs a hook in the background and "can't block or rewrite anything" (the async Stop
entry fired alongside the sync one, 32 vs 31); SessionEnd is always sync.

## 2. Rollout transcript

Location `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<local start time>-<session_id>.jsonl` (start time = when the
thread was created at launch), always equal to the hooks' `transcript_path`. **Created at the first prompt**,
not at launch (the thread id already exists at launch: `shell_snapshots/<id>.*.sh`,
`thread-writer-locks/<id>.lock`). Lines: `{timestamp, ordinal, type, payload}`. Each item appears twice: as a
model-level `response_item` and as a UI-level `event_msg` `item_completed{thread_id, turn_id, item}`. Use the
`item_completed` items; they carry `turn_id` and skip internal messages.

| What | Record (ordinals in session A) |
|---|---|
| Turn start | `event_msg task_started{turn_id, turn_attribution.turn_trigger:"user", started_at}` (1, 16, 31, 58, 66, 78); preceded by `thread_settings_applied`, followed by `turn_context`, `world_state`, developer messages (skip all) |
| User prompt | `item_completed` `UserMessage{id, client_id, content[{type:"text", text}]}` (9, 19, 34, 61, 69, 81); `response_item message role:user` also carries `<environment_context>` user messages (5), so don't use those |
| Assistant text | `item_completed` `AgentMessage{id, content[{type:"Text", text}], phase}`, `phase` = `commentary` (35, a mid-turn update) or `final_answer` (10, 25, 52). **Whole message only, no deltas**: the poem streamed on screen for 5 s while the file did not change; its record arrived at the end. `final_answer` text may be `""` (25) |
| Tool calls | `item_completed` `CommandExecution{id:"exec-…", command[], cwd, parsed_cmd, status, aggregated_output, exit_code, duration}` (22, 45), written when the command finishes. The model-level `custom_tool_call name:"exec"` (20, 37, 41, 70) holds JavaScript (`tools.exec_command({cmd:…})`, code mode) and `custom_tool_call_output` / `function_call_output` hold the result text; a sandbox failure (39) and a cancelled approval (72, "aborted by user after 1.3s") appear only there, with no `CommandExecution` |
| Reasoning | `item_completed` `Reasoning{summary_text:[], raw_content:[]}` + `response_item reasoning{encrypted_content}` (50, 51): empty/encrypted at this effort. Skip |
| Turn end | `event_msg task_complete{turn_id, last_agent_message, duration_ms}` (14, 29, 56, 86) |
| Interrupt (Esc) | developer message `<turn_aborted>` (63, 74) then `event_msg turn_aborted{turn_id, reason:"interrupted"}` (64, 75). Partial streamed text is **not** recorded at all |
| Approval wait | **Nothing** is written while the dialog is up (between 20 and 22). The approval itself isn't recorded either; only the outcome (CommandExecution, or the aborted output) |
| Errors | No model/API error occurred, so not observed. A tool failure is only tool output |
| Compaction | session B 15–26: `task_started` (no `turn_attribution`) → a `response_item` **assistant** message holding the summary (17, no `AgentMessage` item) → `compacted{message, replacement_history}` → `item_completed ContextCompaction` → `task_complete{last_agent_message:null}`; no UserPromptSubmit, no Stop |

Turn complete: Stop hook (wake-up) + `task_complete` with the same `turn_id` (authoritative, ordered after all
of the turn's items). Interrupted: Interrupt hook + `turn_aborted`. Waiting for approval: only the
PermissionRequest hook; it ends with PostToolUse/`CommandExecution` (approved), Interrupt/`turn_aborted`
(Esc = cancel at the dialog), or a later item of the turn.

## 3. Session identity

No flag names a new session (`codex --help` has none; `--session-id` doesn't exist). Atem learns the id from
the first hook of the first prompt (SessionStart, then UserPromptSubmit, both carry `session_id` and
`transcript_path`); before the first prompt there is no id from a hook and no rollout file. `codex resume <id>`
(or `--last`) reopens a known id: same id, same rollout file appended (76 on), SessionStart `source:"resume"`
again lazily at the next prompt. `/new`: new id and new rollout file, SessionStart `source:"startup"` (not
`clear`) at its first prompt, no SessionEnd for the old one until exit. `/compact`: same id and file, no
SessionStart (the documented `source:"compact"` didn't fire for manual compaction; auto compaction untested).

## 4. Prompt injection

Literal text + Enter submits. A bracketed paste (`ESC[200~…ESC[201~`, tmux `paste-buffer -p`) with a newline
stays in the composer as two lines; Enter then submits it, and both the UserPromptSubmit `prompt` (18) and the
`UserMessage` (69) carry it verbatim with `\n`. (A raw `\n` outside a paste would act as Enter; not used.)
Acceptance: UserPromptSubmit gives the `turn_id` and exact text; the rollout `UserMessage` with the same
`turn_id` and text follows within ~25 ms; `task_started` precedes both in the file. Input typed before the TUI is
ready is lost (earlier probe).

## 5. Trust

Each handler is trusted separately, as `[hooks.state."<hooks.json path>:<event_snake>:<group>:<handler>"]
trusted_hash` in the writable config layer (`oss.config.toml` with `--profile oss`). The same command under
12 events gives 12 different hashes, and the first start shows "Hooks need review · 12 hooks are new or
changed" (Review / Trust all and continue / Continue without trusting); untrusted hooks don't run (so the first
session's SessionStart was missed). Adding one more entry at the end → "1 hook is new or changed", the others
stay trusted. **Reordering** two existing Stop entries → "2 hooks are new or changed" (the key is positional).
`/hooks` lists events with Installed/Active/Review counts and clamping warnings; a hook's detail shows Source,
Command, Mode (Sync/Async), Timeout and Trust (`screen-hooks-review-detail.txt`).
So one script for all events with one Atem-marked entry per event works, reviewed once if all are installed
together; always append Atem's groups after the user's (inserting before them makes the user re-trust theirs),
and keep the command byte-identical across sessions (any change re-triggers review).

## Recommended adapter design

- **Install:** with the existing approval-hook consent, one Atem-marked entry per event (SessionStart,
  UserPromptSubmit, PreToolUse, PostToolUse, Stop, Interrupt, PreCompact, PostCompact, SessionEnd, plus the
  existing PermissionRequest), appended last, same command for every session, `async: true` for all but
  PermissionRequest (sync, it decides) and SessionEnd (always sync); the script never prints and always exits
  0, and outside Atem (no `ATEM_*` dir) exits at once, as the approval hook does. Events go to the session's
  dir named by the worker env; only hooks whose `session_id` is the pinned session count (same rule as
  approvals; `/new` re-pins on its SessionStart `startup`).
- **Content:** tail the rollout named by `transcript_path`; take `item_completed` `UserMessage`,
  `AgentMessage` (both phases; skip empty text), `CommandExecution` (as tool items); ignore `response_item`s,
  developer messages, Reasoning, `world_state`, `turn_context`, `token_*`, `thread_settings_applied`,
  `compacted`/`ContextCompaction` (the compaction summary is never an `AgentMessage`).
- **Status:** `working` from UserPromptSubmit / `task_started`; `waiting` from PermissionRequest until
  PostToolUse, Interrupt, Stop, or the next item of that turn; `ready` after `task_complete` or `turn_aborted`
  (read the file up to it first; the Stop/Interrupt hook is the prompt to read). A `task_started` with no
  UserPromptSubmit (compaction) is working but completes no request. `unknown` before the first hook
  (SessionStart is lazy) and after a format surprise.
- **Turns and messages:** turn = `turn_id`; message id = the item `id`. A request completes at its turn's
  `task_complete` (Stop's `last_assistant_message` may be `""`) and ends as interrupted at `turn_aborted`.
- **Prompt acceptance:** paste the prompt bracketed, then Enter; accepted when UserPromptSubmit (text equal)
  and the rollout `UserMessage` with the same `turn_id` both arrive; time out as for Claude, never resend.
  Open decision: a freshly launched Codex has no hook until its first prompt, so the "no SessionStart within
  15 s → chat unavailable" rule can't apply; either keep chat available with status `unknown` and allow the
  first submit (acceptance still requires both signals), or require one local prompt first.
- **Unavailable, advertise as such:** streaming/partial text (whole messages only; an interrupted turn's
  partial answer is lost), reasoning, approval cards' "always allow" (already fail-closed), a session id before
  the first prompt, subagent content (not tested), model/API errors (no record observed), Notification-type
  idle signals (no such event).

Setup notes: the sandbox needs bubblewrap; here its loopback setup failed, so even reads asked for escalation.
The TUI ran in-process (`--remote` not used); the user's own app-server daemon under `~/.codex` was untouched.

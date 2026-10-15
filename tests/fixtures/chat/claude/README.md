# Claude Code hook and transcript fixtures

Recorded by driving an interactive `claude --model haiku --settings <settings.json>
--session-id <uuid>` in tmux, with the six hooks from `designs/agent-chat-host.md`
each writing its stdin to `events/ev.XXXXXXXX.json` (mktemp then rename).
Installed version was 2.1.299 at launch; Claude auto-updated and the transcript
entries say `"version":"2.1.300"` (hook behaviour identical).

Anonymised: home -> `/home/user`, cwd -> `/home/user/proj`, chat dir ->
`/run/user/1000/atem/chat-xxxx`, thinking `signature` -> `"sig"`. All ids and
timestamps are real. Large bookkeeping bodies are elided: `api-request-*` lines
keep only their scalar fields plus `"elided":true`; `attachment` lines keep
`attachment.type` plus `"elided":true` (except `plan_mode_exit`);
`serverClassifierContext` is removed. Real files hold much larger versions of
these (up to 100 KB per line), so the reader must not assume small lines.

## Files

- `events/NN-*.json`: all 14 event files in arrival order (mtime). Run: prompt 1
  (auto permission mode, Bash `echo hi`, no approval needed) -> prompt 2 (default
  mode, Bash `touch probe.txt`, approved in the TUI) -> prompt 3 (essay, Esc
  after ~3 s) -> `/clear` -> prompt 4 (`say hi`) -> `/exit`.
- `session-basic.jsonl`: transcript `c142b440-2f9a-4f2e-bf30-d99335ab2e7e` (= the
  `--session-id`), prompts 1-3 including the interrupt.
- `session-after-clear.jsonl`: transcript `0e5a8679-f18d-4d65-ba20-58c30c004ad4`
  created by `/clear` (new session id; `SessionStart` `source:"clear"`).

## Hook events (stdin JSON; all arrive as `<name>.json` files)

Common to all: `session_id`, `transcript_path` (absolute,
`~/.claude/projects/<cwd with / and . replaced by ->/<session_id>.jsonl`), `cwd`,
`hook_event_name`.

| Event | Extra fields observed |
|---|---|
| `SessionStart` | `source` (`startup`, `clear`; resume/compact not exercised), `model` (present on startup, ABSENT on clear) |
| `UserPromptSubmit` | `prompt` (the typed text), `prompt_id` (equals `promptId` of the transcript user entry), `permission_mode` (`auto`, `default`) |
| `PreToolUse` | `prompt_id`, `permission_mode`, `effort:{level}`, `tool_name`, `tool_input` (Bash: `command`, `description`), `tool_use_id` (equals the transcript `tool_use.id`) |
| `PostToolUse` | as PreToolUse plus `tool_response` (Bash: `stdout`, `stderr`, `interrupted`, `isImage`, `noOutputExpected`) and `duration_ms` |
| `Notification` | `prompt_id`, `message` ("Claude needs your permission"), `notification_type` ("permission_prompt"). No `permission_mode`. No idle notification appeared in this run (short run, no 60 s idle). |
| `Stop` | `prompt_id`, `permission_mode`, `effort`, `stop_hook_active`, `last_assistant_message`, `background_tasks`, `session_crons` |

Findings relevant to the design:

- `SessionStart` is written at startup with no prompt typed (first run it
  appeared only once the workspace-trust dialog was answered; Atem's 15 s wait
  must allow for a first-time trust prompt in a new directory). It carries
  `session_id` equal to `--session-id` and a `transcript_path` ending in
  `<session_id>.jsonl`. The transcript file does not exist until the first
  entries are written (first lines are bookkeeping).
- `--settings` hooks fire interactively, receive the JSON on stdin and merge
  with the user's own hooks (the `stop_hook_summary` entry shows `hookCount: 2`:
  a user hook plus ours).
- `Notification` with `notification_type:"permission_prompt"` fired about 6 s
  after the `PreToolUse` of the same tool (permission asked), before
  `PostToolUse`. In `auto` permission mode no `Notification` fired.
- **No `Stop` event after Esc interrupt** (event 11, the essay prompt, is
  followed directly by the `/clear` `SessionStart`). The interrupt is only
  visible in the transcript. The design's table already covers this.
- `/clear` fires `SessionStart source:"clear"` with a new `session_id` and
  `transcript_path`; no `UserPromptSubmit` for `/clear`. Nothing fires on `/exit`.
- `Stop.last_assistant_message` carries the final text (could be used as a
  cross-check, not required).

## Transcript entry shapes (one JSON object per line)

Common on conversation entries: `parentUuid`, `isSidechain`, `uuid`, `timestamp`,
`sessionId`, `cwd`, `version`, `gitBranch`, `userType`, `entrypoint`, optional `slug`.

- User prompt (`session-basic.jsonl` line 8): `type:"user"`, `promptId`,
  `message:{role:"user",content:"<string>"}` (content is a STRING for typed
  prompts), `origin:{kind:"human"}`, `promptSource:"typed"`, `turnOrigin:"human"`,
  `turnPosition:{promptIndex,turnIndex}`, `permissionMode`.
- Meta entry (`session-after-clear.jsonl` line 5): `type:"user"`, `isMeta:true`,
  content string `<local-command-caveat>...`; skip.
- Slash command (`session-after-clear.jsonl` lines 5-7): user entry with content
  string `<command-name>/clear</command-name>\n <command-message>clear</command-message>\n <command-args></command-args>`
  (no `promptId`, not meta), followed by `type:"system"`, `subtype:"local_command"`,
  `commandRun:{command,args}`. The command user entry must not become a chat message.
- Assistant blocks: `type:"assistant"`, `message:{id:"msg_...",role,model,content:[ONE block],stop_reason,usage...}`,
  `apiBlockIndex`, `requestRef`. One content block per line; lines of one reply
  share `message.id`, each with its own `uuid`. Block kinds:
  - `text`: `{type:"text",text}`
  - `tool_use`: `{type:"tool_use",id,name,input:{...},caller:{type:"direct"}}`
  - `thinking`: `{type:"thinking",thinking:"" ,signature}` (thinking text was
    empty in this haiku run; `thinkingDurationMs`, `thinkingDisplay` on the entry)
- `stop_reason`: `end_turn` on the final text line, `tool_use` on a tool_use
  line (observed on the line itself), and **`null` on blocks written while
  streaming** (the aborted partial and its thinking block). Observed replies had
  a single content block, so whether earlier lines of a multi-block reply
  carry `null` vs the final reason was not observed beyond the aborted case.
- Tool result: `type:"user"`, `message.content:[{tool_use_id,type:"tool_result",content:"<string>",is_error}]`,
  `toolUseResult:{stdout,stderr,interrupted,isImage,noOutputExpected}`,
  `sourceToolAssistantUUID`, `promptId`, `permissionDecision` (auto mode).
- Interrupt (`session-basic.jsonl`, last conversation lines): the partial
  assistant text line has `stop_reason:null` and `isAbortedMidStream:true`
  (thinking line before it, same `message.id`); then `type:"user"`,
  `message.content:[{type:"text",text:"[Request interrupted by user]"}]` (an
  ARRAY here), `interruptedMessageId` = that `message.id`, `promptId` = the
  interrupted prompt, no `isMeta`. No `Stop` hook.
- `system` / `stop_hook_summary` (after each turn end): `hookCount`,
  `hookInfos:[{command,durationMs}]`, `hookErrors`, `preventedContinuation`,
  `stopReason`, `hasOutput`, `level`, `toolUseID`; then `system`/`turn_duration`
  (`durationMs`, `messageCount`). `system` entries have no `message`.
- Bookkeeping types to skip: `last-prompt`, `mode`, `permission-mode`,
  `atis-latch`, `ai-title`, `file-history-snapshot`, `cost-state`,
  `attachment` (hook_success, hook_additional_context, environment, model,
  agent_listing_delta, skill_listing, total_tokens_reminder, instructions,
  session_context, date, remote_session_change, prompt_snapshot,
  plan_mode_exit), `api-request-shape`, `api-request-blob`, `api-request`.
  Many have no `uuid`.

## Not recorded

A permission prompt answered with deny/Esc (`[Request interrupted by user for
tool use]`, a user entry without `interruptedMessageId`) could not be recorded
on 2026-10-15: the Claude CLI on the recording machine was not logged in
("Not logged in · Please run /login"). The reader's tests use hand-written
lines for it (`transcript.rs`, `interrupt_marker_without_message_id_ends_the_turn`).

## Deviations from the spec

None that break it. Notes: first-run trust dialog can delay `SessionStart`;
interrupt marker content is an array of one text block; `isAbortedMidStream`
exists as an extra interrupt signal; `Stop` is not sent on interrupt; the
auto-updater can change the Claude version while Atem is running.

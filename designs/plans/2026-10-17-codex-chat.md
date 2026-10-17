# Codex chat adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Codex sessions launched in Atem report honest activity (ready / working / waiting) and serve chat-v1 like Claude: prompts, replies, completion and prompts from chat — the original Codex process and conversation, no scraping.

**Architecture:** Atem's existing Atem-marked entry in `$CODEX_HOME/hooks.json` grows to one entry per Codex hook event, all running the same stable script (`~/.config/atem/hooks/approval-hook.sh`, renamed to a general Codex hook) which, inside an Atem session (`ATEM_APPROVAL_DIR`/session env set by the worker), writes each event's stdin JSON to the session's event dir and exits 0 with no output (PermissionRequest keeps its decision protocol). A Codex `AgentAdapter` in the worker reads those events plus the rollout JSONL named by `transcript_path`, and feeds `ChatSession` exactly as the Claude adapter does.

**Spec:** `designs/fixtures/codex-hooks/README.md` (verified on codex-cli 0.162.1, fixtures in the same dir), `designs/agent-chat-host.md` (adapter model, status rules, never scrape / never infer from silence), AGENTS.md "Agent chat" and "Approval hooks".

## Global Constraints

- Branch `feat/codex-chat` (from `feat/session-runtime`, PR #72). Commits end with a blank line and `🤖 Built with SMT <smt@agora.build>`. Never push without the user asking.
- No backward compatibility (unreleased): rename/replace freely, no shims.
- Never rustfmt `src/app.rs`, `src/main.rs`, `src/cli.rs`, `src/websocket_client.rs`, `src/memory/{mod,crypto,secrets}.rs`; no project-wide `cargo fmt`.
- Tests never touch the real `~/.config/atem`, `~/.codex`, `~/.claude` (test_profile guard; temp `CODEX_HOME`); never the user's running runtime, workers, key agent or tmux session `atem-jt`. Build with `CARGO_TARGET_DIR=/tmp/atem-target-codex` (never `target/release`, the user runs it).
- Status only from agent-native signals (spec "Recommended design"): working ← UserPromptSubmit or `task_started`; waiting ← PermissionRequest until PostToolUse / Interrupt / next item; ready ← `task_complete` or `turn_aborted`; `unknown` before the session's first hook and after exit. Content only from rollout `event_msg item_completed` (UserMessage, AgentMessage, CommandExecution); reasoning and compaction summaries are not chat.
- Prompt acceptance = UserPromptSubmit and the rollout UserMessage with the same `turn_id` (10 s timeout, never resent).
- **Ruling (2026-10-17): a remote chat prompt needs status `ready`.** Before Codex's first hook (SessionStart fires only at the first prompt) the status is `unknown` and chat `submit` is refused with a clear error ("type a first prompt in the terminal"); the terminal (local, or remote with the lease) is the way in. Reason: text typed into Codex's startup dialogs (folder trust, update) could answer them.
- Hooks: one Atem-marked entry per event, appended after the user's entries, identical command for every session (trust is per entry position + hash); `async: true` except PermissionRequest and SessionEnd. Merge/removal keep every other byte, backup first, read back and restore on mismatch (the existing `src/chat/codex` machinery). One consent covers approvals and chat; the setting becomes `[codex] hooks` (replaces `approvals_hook`), `false` removes all Atem entries.
- Only hooks from the session's pinned Codex session count (existing ancestry + pin rules in `runtime/worker_approvals.rs`); `/new` re-pins (SessionStart `source: startup` from the session's own agent); resume keeps the id.
- Unavailable and advertised as such (Capabilities): streaming/partial text, reasoning, always-allow, API error details.
- Every task: full `cargo test` twice reading every result line, `runtime_fixtures_binary` passing, clippy no new warnings, before/after hash snapshot of `~/.config/atem`, `~/.codex/hooks.json`, `~/.claude/settings.json` unchanged.

### Task 1: Hook installation for all Codex events

`src/chat/codex/` (+ the hook script): extend the Atem entry set to one entry per event (SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, Stop, Interrupt), appended after existing groups, idempotent (an install with the full set present changes nothing; a partial old set is completed by appending only what's missing), removal of every marked entry; setting `[codex] hooks` (consent asked once by `atem agent launch codex`, wording covers approvals and chat). The script: event name from an argument or stdin `hook_event_name`; outside Atem exits 0 silently; inside, non-PermissionRequest events are written atomically as `ev-<seq>-<event>.json` (0600) in the session's event dir and exit 0 with no output; PermissionRequest unchanged. Tests on a temp CODEX_HOME with the fixture `hooks.json`: merge after user hooks, idempotence, partial completion, removal, refusal of unexpected structure, backup/restore; script tests with fixture stdin files.

### Task 2: Codex adapter (events + rollout)

`src/chat/codex/adapter.rs`, `src/chat/codex/rollout.rs`: implement `AgentAdapter` from the hook event files and the rollout JSONL (path from the first event's `transcript_path`, must be `rollout-*-<session_id>.jsonl` under `$CODEX_HOME/sessions`; else ignored with a notice). Map records to `LogItem`s/`AgentEvent`s per the spec; status rules above; turn ids; interrupt → turn ends interrupted; `/new` → reset to ready with a new transcript (old one read to its end first); resume → history only; compaction → no message, turn kept; unknown record types skipped; a format change withdraws chat (like Claude). Capabilities as above. Unit tests driven only by the fixtures in `designs/fixtures/codex-hooks/`.

### Task 3: Worker and host wiring

The worker runs the Codex adapter for Codex sessions (when `[codex] hooks` is on), sends `chat`/`chat_snapshot` like Claude; activity reaches the session descriptor and `atem agent list`; the host's prompt receipts and chat-v1 `submit` work for Codex (pasted through the worker, accepted on both signals, completed at turn end), refused while status isn't `ready` (the ruling). `interrupt` writes Esc and completes on the next turn end. Approval cards keep working (PermissionRequest also sets waiting). Tests: in-process broker with a fake Codex agent driving the real hook script and a fake rollout; extend `tests/approvals_real_agents.rs` (renamed `real_agents.rs` if cleaner) with a Codex chat scenario: first prompt local, then a remote chat prompt accepted → reply → complete, and an interrupt.

### Task 4: Docs and handoff

AGENTS.md (Agent chat: Codex adapter; config row `[codex] hooks`), README/npm README, `designs/agent-chat-host.md` (Codex section, the first-prompt ruling, unavailable capabilities), `designs/protocol/atem-host-handoff.md` (Codex now has chat and activity; first remote prompt rule; the dot should follow process state).

### Task 5: Atem session rules ("Always allow this command") for agents without native always-allow (user decision, 2026-10-17)

Only for an agent whose hook can't persist a rule (Codex: `updatedPermissions` fails closed); Claude keeps its own suggested rules unchanged.
- The Codex card offers Allow once / **Always allow this command** / Deny. `always_rules` gets one Atem rule per request: `{rule_id, label: "Always allow `<command first line, redacted>` in <cwd> for this session", scope: "session"}`.
- Answering `allow_always` with that rule allows this request and stores the rule in the worker for this session (process_gen): match = tool kind + the exact full command text (byte-equal, not the redacted summary) + the exact cwd. No prefix, glob or normalisation; anything else still asks. File-change requests: exact path + change kind.
- A later matching request is answered allow by the worker's hook path without opening a remote approval, recorded as a chat note/card in state `auto_allowed` naming the rule, and in `runtime.log` (no command text). Never across sessions, never after the process ends (a respawn clears rules), never through adoption by a new broker unless the worker kept them (the worker owns them, so they survive a broker restart).
- Revoke: chat-v1 `submit` with `approval_rule_revoke{rule_id}` (lease required) or local prefix-key; rules listed in `opened`. Bounded: at most 32 rules per session.
- Docs: contract §6a (rule scope `session`, `auto_allowed`, revoke), AGENTS.md, agent-chat-host.md, handoff. Tests: exact-match only (a command with an extra `; rm` still asks), cwd differs → asks, respawn clears, revoke, bound, nested codex never matches, real-agent: always allow then the same command runs without a card.

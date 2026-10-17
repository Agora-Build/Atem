# Approvals from chat and mobile (step 1b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** The session's lease holder can answer Claude Code's and Codex's permission prompts from Astation's chat view or a phone notification — one tap, bound to the exact prompt — while the terminal can always still answer.

**Architecture:** Each agent's `PermissionRequest` hook writes the request into the session's private directory and waits for a decision file (Claude: per-launch `--settings`; Codex: one Atem entry merged into `~/.codex/hooks.json`, consent asked once by `atem agent launch codex`). The worker reports it; the broker's `SessionHost` turns it into an `approval_request` for viewers; the lease holder answers with an `approval` submission (§6 receipt); the broker writes the decision file. No remote holder → immediate "no decision". Terminal answer / Esc / timeout / lease loss → the request closes and late answers are refused.

**Spec:** `designs/account-trust.md` §6a (branch `docs/account-trust`, PR #70) — verified behaviour of both hooks with fixtures in `designs/fixtures/permission-hook/`; `designs/protocol/atem-session-v1.md` (r6.2) §5–§7.

## Global Constraints

- Branch `feat/approvals` from `feat/runtime`. Commits end with a blank line and `🤖 Built with SMT <smt@agora.build>`. Never push without the user asking.
- No backward compatibility; Chisel unchanged; tests can't reach the real profile (`src/test_profile.rs`), the real `~/.claude`, `~/.codex` or `~/.config/atem` — Codex hook installation tests use a temp CODEX_HOME.
- Decisions (user, 2026-10-16): the card offers **Allow once**, **Always allow** and **Deny**. "Always allow" applies the agent's own suggested rule exactly as the agent proposes it, and the card shows that rule and its scope before you tap. For Claude these are the hook input's `permission_suggestions`, echoed as `updatedPermissions`. For Codex, check whether its hook accepts a persistent decision; if not, Codex cards offer Allow once and Deny only, and say why. The card shows the tool and a short redacted summary (the command's first line or the file path), never full inputs such as file contents.
- Never auto-allow. Any failure, timeout, missing runtime or missing remote holder = "no decision" (the agent's own prompt appears).
- Broker restart: approvals live in the broker's memory only, so after a restart the worker answers "no decision" to any waiting hook whose approval the new broker doesn't know (Task 2: the worker side; Task 3: the broker tells the worker which approvals it knows). A remote takeover keeps a pending approval for the new holder; `lease_lost` closes it only on expiry, release, local input or a trust change. A handed-off decision the agent hasn't confirmed within 630 s is `outcome_unknown`.
- The runtime redacts before opening an approval (`ApprovalInfo`: summary = the command's first line or the file path, rule labels without secrets); Task 2 implements and tests it, the host only checks bounds.
- The terminal can always answer: Claude shows its dialog during the wait (first answer wins); for Codex, any local input releases the hook first (Codex hides its prompt while a hook runs).
- Hook timeouts: Claude 600 s, Codex 120 s. The hook command is identical for every session (session dir from an env var set by the worker) so Codex's trust hash stays valid.
- Codex `hooks.json`: merge, never overwrite; one entry marked as Atem's; backup `hooks.json.atem-bak` before the first change; idempotent; consent asked once and remembered; outside an Atem session the hook exits immediately with no output.
- Never rustfmt `src/app.rs`, `src/main.rs`, `src/cli.rs`, `src/websocket_client.rs`, `src/memory/{mod,crypto,secrets}.rs`. No new deps without need.
- Every task: full `cargo test` twice reading every result line + a before/after snapshot of `~/.config/atem` (unchanged); clippy not above the branch baseline.

### Task 1: Contract r7 — approvals

`designs/protocol/atem-session-v1.md` (+ fixtures): `approval_request{approval_id, session_id, process_gen, tool, summary, created_at, always_rules:[{rule_id, label, scope}]}` (host → viewers with `view`), `approval_closed{approval_id, reason: answered_remote|answered_terminal|interrupted|timed_out|lease_lost|process_ended}`, submission `kind:"approval"` payload `{approval_id, decision: allow_once|allow_always|deny, rule_id?, message?}` (`allow_always` names one of the request's offered rules) (admission: current lease + `control`; the approval must be pending for that exact session/process; else `stale_target`), receipt states for approvals (`completed` when the agent applied the remote decision, `rejected` if the request closed first, `outcome_unknown` if the terminal and remote answers crossed). Remove "approval reserved" text. Fixtures: remote allow; remote deny with message; terminal first → late remote refused; lease lost → closed; duplicate approval submit; viewer without control refused. Core implementation in `src/session_protocol/` (host + wire + client hooks) with the fixtures passing.

### Task 2: Hooks and the worker

`src/chat/claude/hooks.rs`: add the `PermissionRequest` hook (600 s timeout) to the per-launch settings; the hook script writes `permission-<id>.json` to the session dir and polls for `decision-<id>.json` (allow / deny+message / none) — POSIX sh, no deps, exits 0 with no output on none/timeout/missing dir. `src/chat/codex/` (new): the Codex hook entry, consent prompt in `atem agent launch codex` (remembered in config), merge into `$CODEX_HOME/hooks.json` (default `~/.codex`), backup, idempotence, the env var the worker sets. Worker: watch for permission files, report `approval_request` to the broker, write decision files on the broker's command, detect resolution (Claude: PostToolUse / transcript tool result / Esc; Codex: hook exit / turn events) and report `approval_closed`. Tests with fake agents that run the real hook script; Codex install tests on a temp CODEX_HOME (merge with existing hooks, backup, idempotence, declined consent).

### Task 3: Broker wiring and chat card

`src/runtime/host_bridge.rs`: worker approval events → `SessionHost` approvals → `approval_request`/`approval_closed` to attachments; approval submissions → decision to the worker; no remote holder → immediate "no decision"; local input (Codex) → release first; lease loss → close; chat-v1 shows an approval card part (`{kind:"approval", approval_id, tool, summary, state}`) in the conversation. Tests: in-process broker + fake worker; real-runtime binary test with a fake agent running the real hook script.

### Task 4: Docs and handoff

AGENTS.md, README, `designs/agent-chat-host.md` ("no approvals from chat" → lease-holder approvals bound to the exact prompt; "hooks never decide" exception), the Astation handoff (new messages, card, push trigger).

## Push-based approvals (user decision, 2026-10-16) — supersedes "cards only for a lease holder"

- Delivery is independent of the lease: every approval opens a card for all
  attachments with `control`, and Atem asks the relay to push it to every device
  on the account with `control` (APNs/FCM; Astation owns credentials, token
  registry, delivery and the notification UI). Devices need no live connection.
- Push request over Atem's authenticated relay link: `push_approval{approval_id,
  atem_device_id, session_id, tool, summary, expires_at}` (redacted summary only;
  `mutable-content` so iOS can decrypt on device once E2EE lands) and
  `push_resolved{approval_id}` when answered elsewhere / expired / closed
  (collapse-id / FCM tag = approval_id).
- Tap → the app wakes, reconnects, authenticates as a member device, gets the
  pending approval in the catch-up, and answers with `approval{…, acquire:
  true}`: the host takes the lease (takeover allowed) and applies the decision
  atomically. A late tap → "already answered".
- Hook waits: Claude 600 s (its dialog stays visible; first answer wins); Codex
  300 s (its prompt is hidden while waiting; any local key releases it first).
- Until the device list (account trust step 1) exists only the paired Astation
  can answer; phones join when membership lands — the push path is built so they
  work then without further Atem changes.

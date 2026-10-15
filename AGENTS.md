# AGENTS.md

This file provides guidance to AI coding agents working with this repository.

## Project Overview

Atem is a terminal that connects builders, Agora platform, and AI agents. It provides a CLI and TUI for managing Agora projects and tokens, routing tasks between Astation and AI coding agents, voice-driven coding, and more.

Install:

```bash
# Quick install (works in regions where GitHub is not available)
curl -fsSL https://dl.agora.build/atem/install.sh | bash

# Or via npm
npm install -g @agora-build/atem
```

## Development Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo run                                # Run TUI application
cargo run -- [command]                   # Run with CLI arguments
cargo test                               # Run tests (1,250+; use -- --test-threads=1 if a test flakes)
cargo test -p atem-core -p atem-core-ffi # Token library + C ABI tests (workspace members)
./scripts/check-atem-core-ffi.sh         # Build libatem_core_ffi.a, drive it from C (and Swift on macOS)
cargo check                              # Type-check without building
cargo fmt                                # Format code
cargo clippy --all-targets --all-features  # Lint
./scripts/run-local-dev-tests.sh         # End-to-end CLI smoke test (build first)
./scripts/release.sh [VERSION]           # Bump Cargo.toml + commit + tag (no push)
```

## Architecture

### Source Structure

The repo is a Cargo workspace: the `atem` binary at the root plus two library crates.

```
crates/
├── atem-core/           # Agora AccessToken2 (RTC/RTM) build/decode/verify, built for Astation to share (integration is a follow-up); no I/O, no state
│   └── tests/upstream_compat.rs  # must equal Agora's own agora_token crate (pinned git rev)
└── atem-core-ffi/       # versioned C ABI (ABI 1) over atem-core: include/atem_core.h, module.modulemap, tests/c, tests/swift
src/
├── main.rs              # Entry point, CLI parsing (clap)
├── app.rs               # TUI state machine, mark task queue, Claude session management
├── app/terminal.rs      # terminal-v1 message handling for the Claude/Codex sessions
├── app/reauth.rs        # re-authentication when Astation sends auth_required over an open socket
├── app/chat.rs          # chat-v1 host: adapter polling, conversations, submit, registry status/capabilities
├── app/chat_tests.rs    # (test-only) chat-v1 end to end: the App, tests/fixtures/chat/fake-claude.sh in a PTY, a fake Astation
├── chat/                # Agent chat (chat-v1), agent-neutral except the adapters
│   ├── adapter.rs       #   AgentAdapter trait, AgentEvent, LogItem, Capabilities, LaunchPlan
│   ├── session.rs       #   per-agent chat state: status, history, draft check, submit/acceptance, request ids
│   ├── wire.rs          #   agentChat v1 envelopes to and from Astation
│   └── claude/          #   Claude Code adapter: hooks.rs (chat dir, settings.json, event files), transcript.rs (session JSONL)
├── cli.rs               # CLI command definitions
├── repl.rs              # Interactive REPL mode
├── websocket_client.rs  # Astation WebSocket protocol (message types + client)
├── claude_client.rs     # PTY-based Claude Code CLI integration
├── codex_client.rs      # PTY-based Codex terminal integration
├── pty_session.rs       # Shared byte-oriented PTY transport (bounded input/output, write epochs)
├── terminal_share.rs    # terminal-v1: canonical-screen ANSI frames, viewer credit, control leases over the Astation link
├── terminal_keys.rs     # xterm key encoding for the emulated terminal
├── diagnostics.rs       # Background warnings queued while the TUI owns the screen
├── token.rs             # Agora RTC/RTM token generation
├── rtm_client.rs        # Agora RTM FFI wrapper with async Tokio channels
├── ai_client.rs         # Anthropic API client for intent parsing
├── sso_auth.rs          # OAuth 2.0 + PKCE login flow, token refresh primitives
├── credentials.rs       # Encrypted multi-entry credential store (SSO + paired)
├── agora_api.rs         # BFF API client (BffProject, fetch_projects with Bearer auth)
├── auth.rs              # Astation auth session management, deep link flow
├── config.rs            # Config, SSO/BFF URL helpers, active project, project cache
├── time_sync.rs         # HTTP Date-based time synchronization
├── agent_client.rs      # Agent types (AgentInfo, kind, status) sent in Astation's agent list
├── agent_registry.rs    # Registry of the PTY agents Atem launched (Claude Code, Codex)
├── webhook_server.rs    # atem serv webhooks — Agora webhook receiver +
                          # ngrok/cloudflared tunnel integration + SSE console
├── rtc_test_server.rs   # Browser-based RTC test page server
├── files_server.rs      # atem serv files — static file server (Markdown rendered)
├── convo_config.rs      # ConvoAI TOML parsing + Agora REST /join body builder
├── convo_test_server.rs # atem serv convo — ConvoAI test server + --background mode
├── convo_wizard.rs      # atem config convo — interactive config wizard + validation
├── web_server/          # Shared HTTPS scaffolding (cert, request, /api/token, net, html, browser open)
├── command.rs           # Task queue and stream buffer for voice commands
├── dispatch.rs          # Work item dispatcher for mark tasks
├── pair_verify.rs       # atem pair device verification: /dev/tty code confirmation, verifyAbort on failure
├── vault_client.rs      # atem vault CLI client (relay /api/vault: request builders, renderers, executor)
├── memory/              # Atem Memory: shared memory + skills across agents and machines
│   ├── model.rs         #   Memory/Skill types, hashing
│   ├── secrets.rs       #   credential-value detector (fail-closed)
│   ├── project.rs       #   project key = normalized git remote
│   ├── block.rs         #   managed <!-- atem:memory --> block
│   ├── gitguard.rs      #   never write tracked files; .git/info/exclude
│   ├── harvest.rs       #   read Claude Code's auto-memory
│   ├── skills_fs.rs     #   skill dirs, .atem-skill marker, drift
│   ├── store.rs         #   local SQLite (~/.config/atem/knowledge.db) + queue
│   ├── adapters.rs      #   Claude/Codex targets + apply report
│   ├── api.rs           #   relay /api/memory, /api/skills client
│   ├── sync.rs          #   harvest → push → pull → apply
│   ├── encoding.rs      #   length-prefixed fields for signed/bound inputs, base32
│   ├── statements.rs    #   Astation-signed statements (P-256 verify)
│   ├── device_keys.rs   #   device X25519 + Ed25519 signing + unlock-auth keys
│   ├── verification.rs  #   commit-then-reveal safety code; apply signed state/grants
│   ├── trust.rs         #   cred_state.json: pinned Astation keys, epochs
│   ├── grant.rs         #   signed RFC 9180 HPKE key grants
│   ├── account_keys.rs  #   K per account (current + previous) in the agent; e1./h1. field ops (Crypt)
│   ├── project_names.rs #   project_names.json: h1. project hash → project key (+ original-case labels)
│   ├── credential_projects.rs # signed HPKE Git-project reports for Astation's credential picker (atem cred projects)
│   ├── legacy_keys.rs   #   read-only data_keys.enc (steps 0–2a), moved in by the agent
│   ├── crypto.rs        #   EncryptionContext: mode from the signed state, batched Crypt via the agent; private writes
│   ├── storage_key.rs   #   storage key + device_keys.sealed (XChaCha20-Poly1305); unlock-grant/ack checks
│   ├── key_agent.rs     #   key agent state: unlock, rotation, abandon, K installed and used in memory (Crypt)
│   ├── agent_socket.rs  #   `atem key-agent` Unix socket server + client (v2 JSON lines, same UID only)
│   ├── unlock.rs        #   `atem cred projects|status|unlock|lock`; unlock/rotation carried over the Astation link
│   ├── migration.rs     #   migration read-back check + atem-migration-complete-v1 proof input
│   ├── fake_astation.rs #   (test-only) Astation's side of unlock and rotation, mirrors the design doc
│   ├── kat_tests.rs     #   (test-only) known-answer vectors listed in designs/e2e-encryption.md
│   ├── k_agent_tests.rs #   (test-only) K in the agent: install, Crypt, rotation, data_keys.enc migration
│   ├── e2e_tests.rs     #   (test-only) encrypted sync/vault end to end, migration and its signed completion
│   └── cmd.rs           #   CLI handlers
└── tui/
    ├── mod.rs           # Main event loop, rendering dispatch
    ├── draw.rs          # Frame rendering
    ├── terminal_view.rs # Agent terminal view: prefix keys (terminal_prefix in config.toml / ATEM_TERMINAL_PREFIX), local history/selection
    ├── clipboard.rs     # Copy via tmux load-buffer or OSC 52
    └── voice_fx.rs      # Voice activity visual effects
native/
├── include/atem_rtm.h   # C header for RTM client interface
├── src/atem_rtm.cpp     # Stub RTM implementation (default)
├── src/atem_rtm_real.cpp # Real RTM using Agora SDK (feature: real_rtm)
npm/
├── package.json         # @agora-build/atem npm wrapper
├── install.js           # Postinstall binary downloader from GitHub releases
└── bin/atem             # Placeholder (replaced by real binary on install)
scripts/
├── install.sh           # curl | bash installer (dl.agora.build)
├── release.sh           # Bump version + commit + tag (no push)
├── run-local-dev-tests.sh # End-to-end CLI smoke test
├── check-atem-core-ffi.sh # Build atem-core-ffi, run the C (and macOS Swift) consumers
├── package-atem-core-macos.sh # Universal AtemCore.xcframework + header + SHA-256 sums (macOS)
├── update-convoai-toolkit.sh # Refresh vendored assets/convo/ (pinned upstream commit; deps from scripts/convoai-toolkit/package-lock.json, esbuild pinned; UPDATE_LOCK=1 re-resolves)
└── test-create-agent.sh # ConvoAI agent creation (requires env vars)
designs/
├── session-auth.md      # Session-based pairing authentication
├── universal-sessions.md # Universal sessions (astation_id keying)
├── connection-priority.md # Connection cascade: local > relay
├── relay-support.md     # Relay server support
├── voice-coding-stages.md # Voice coding implementation stages
├── remote-agent-control.md   # Astation → atem → agent (text/voice/control keys, terminal-v1 proposal)
├── local-agent-runtime.md    # Launch the original claude/codex CLI in Atem, local and remote access to one session
├── agent-chat-host.md        # Agent chat (chat-v1): adapters, Claude hooks + transcript, status, wire
├── terminal-v1-implementation.md # Shared terminal: what Atem built, wire contract, keys, limits
├── atem-identity.md          # instance_id + unique relay atem_id
├── vault.md                  # Shared cross-agent context store (relay + Postgres)
├── agora-account-grouping.md # Proposed: merge Astations under one Agora login (opt-in)
├── atem-memory.md            # Atem Memory: shared memory + skills across agents and machines
├── atem-core.md              # atem-core token library + C ABI (built for a Swift/Astation integration, which is a follow-up)
├── e2e-encryption.md         # E2E encryption: memory, skills, vault (atem side built) + credentials (atem cred, proposed)
├── plans/                    # Implementation plans, kept after they ship (e.g. e2e step 2b: K in the agent)
└── specs/                    # Completed feature specs (atem pair SSO credentials, serv convo, config convo wizard)
docs/
└── credential-project-reporting.md # Astation credential picker: encrypted Git-project reports (wire format, labels)
```

### Core Components

**TUI State Machine** (`app.rs`): Enum-based mode switching via `AppMode`:
- `MainMenu` - Navigation between features
- `TokenGeneration` - Token creation UI
- `ClaudeChat` - Claude Code CLI integration (PTY)
- `CodexChat` - Codex terminal emulator (PTY)
- `CommandExecution` - Shell command runner

**Mark Task Queue** (`app.rs`, `dispatch.rs`, `command.rs`): Receives task assignments from Astation, reads task JSON from local `.chisel/tasks/` directory, builds prompts from annotations + screenshots, sends to Claude Code, reports results back.

Key pieces:
- `App.dispatcher: TaskDispatcher` - routes each `WorkItem` to the main Claude PTY (serial `TaskQueue`: FIFO, one active, deferred-finalize flag) or, when main is busy and a slot is free (max 2), to a background `claude -p` if a one-turn triage call (`claude -p --model haiku`) picks background (`CLAUDE_CLI_BIN` overrides the binary)
- `App.work_items: HashMap<String, WorkItem>` - built items by task ID

Key methods:
- `load_and_build_work_item()` - reads the task JSON, builds the prompt (`build_mark_task_prompt()`)
- `try_dispatch_main()` - when main is idle, pops the next task, ensures the Claude session and sends the prompt
- `finalize_mark_task()` - reports the main task's result to Astation, dispatches the next
- The TUI loop (`tui/mod.rs`) drains triage verdicts and background results each tick and runs `finalize_mark_task()` when the deferred-finalize flag is set

**Astation Integration** (`websocket_client.rs`): WebSocket protocol with `AstationMessage` enum:
- `MarkTaskAssignment { task_id, received_at_ms }` - received from Astation
- `MarkTaskResult { task_id, success, message }` - sent back to Astation
- `VoiceRequest { session_id, accumulated_text, relay_url }` - voice coding from Astation
- `VisualizeRequest { session_id, topic, relay_url? }` - diagram request from Astation; diagram generation was removed, so atem answers each one at once with `VisualizeResult { success: false, message: "Diagram generation was removed from atem" }`
- `VisualizeResult { session_id, success, message, file_path? }` - sent back to Astation (always unsuccessful, no `file_path`)
- `AgentInput { agent_id?, kind, text?, key? }` - remote agent control: text or a control key from Astation → focused agent PTY (`handle_agent_input`)
- `AgentChat(ChatEnvelope)` - `{"type":"agentChat","data":{"v":1,"op":…}}` both ways: chat with a launched agent (`handle_agent_chat`, see Agent chat)
- Also: project lists, token requests, voice/video toggle, heartbeat, auth flow (`auth_required` → `auth`; the connect path and re-authentication share `auth_proof` to build the proof and `auth_response` to classify replies, so the two can't drift)

**Remote Agent Control** (`app.rs`, `websocket_client.rs`): Receives `AgentInput` from Astation and writes it to the focused agent's PTY — `kind:"text"` types a line and submits it (`\n\r`, matching `send_claude_prompt`); `kind:"key"` writes raw control bytes via `agent_key_to_bytes` (enter/esc/ctrl-c/arrows/y/n). Routes to the codex PTY when it's the active chat, else claude; no-ops if no agent session is live (v1 drives an already-running agent). Voice reuses the existing `VoiceRequest` path. While a terminal-v1 viewer is attached, `AgentInput` is refused (a status message says to use terminal-v1) and so is any `agent_id`. A socket alive is not an authenticated Astation: when Astation sends `auth_required` over an already-authenticated socket (e.g. it alone reconnected to the relay), `app/reauth.rs` shows `Astation ✗`, revokes terminal leases and ignores every other Astation request, then answers only the pinned Astation non-interactively (`AstationClient::answer_auth_required`) with the connect path's proof (`local_proof` on loopback, else the saved session); success restores online and re-sends the agent list (viewers subscribe again, view-only), while denial, expiry, a different `astation_id` or no answer within 15 s leaves a notice and closes the socket for the normal reconnect (never pairing).

**Shared terminal** (`src/terminal_share.rs`, `pty_session.rs`, `app/terminal.rs`, `tui/terminal_view.rs`): `atem agent launch [claude|claude-code|codex] [AGENT_ARGS]...` runs `tui::run_agent_tui`, which starts the installed CLI in a PTY (arguments are forwarded as separate values, with or without `--`; `CLAUDE_CLI_*`/`CODEX_CLI_*` env still apply and come first, after Claude's chat hooks) and shows it full screen with one status row (`Atem | Claude|Codex | Local|Remote | Astation ✓|✗[ | Notice] | <prefix> then ?:help`, from `tui/draw.rs`: `Remote` while a viewer holds the control lease, `✗` whenever `astation_connected` is false — including during re-authentication — and `Notice` once `terminal_ui.messages` has an entry; prefix-pending, help, history and 4 s feedback replace it). It works without Astation. Over the authenticated Astation link, `{"type":"terminal","data":{"v":1,"op":...}}` messages (`list`, `subscribe`, `unsubscribe`, `ack`, `control`, `input`, `resize`, `stop` in; `sessions`, `attached`, `frame`, `controller`, `written`, `exited`, `error` out) let a viewer see the canonical screen as base64 ANSI frames (16 KiB per frame, 128 KiB unacknowledged, bounded queues) and, holding a control lease, send raw input bytes. Terminal ids are `claude` and `codex`; one Claude and one Codex session, one viewer each; sessions end when Atem quits. Local keys use the prefix Ctrl+] (`terminal_prefix` in config.toml or `ATEM_TERMINAL_PREFIX`, which wins, changes it; an invalid value falls back to Ctrl+] with a notice): `h`/`m` hide, `g` take control back, `x` stop, `r` redraw, `[` history, `c` copy, `?` help and recent notices. Background warnings go through `diagnostics` so they never write over the renderer. See `designs/terminal-v1-implementation.md` (the contract), `designs/local-agent-runtime.md` and `designs/remote-agent-control.md`.

**Agent chat** (`src/chat/`, `app/chat.rs`): chat-v1 lets Astation show a launched agent as a chat. Only Claude Code has an adapter. Before each Claude spawn `prepare_claude_chat` creates `chat-<uuid>/` (0700) under `$XDG_RUNTIME_DIR/atem` (else `~/.config/atem/run`; `App.chat_root`) with `settings.json` (hooks for SessionStart, UserPromptSubmit, Pre/PostToolUse, Notification, Stop, each writing its stdin JSON to its own file in `events/`) and puts `--settings <file>` and, unless resuming, `--session-id <uuid>` before the user's arguments for that spawn only; each spawn is a new generation (UUID). If preparing fails, Claude starts without chat. Every TUI tick `poll_chat` reads the event files (lifecycle only) and the transcript JSONL named by SessionStart (all message content), feeds `ChatSession` (log items before a tick's `Stop`, so `complete` follows the content), times out unaccepted prompts (10 s, never resent), re-sends status every 15 s, and sends the results to each open conversation with its own sequence. Status: ready/working/waiting/unknown, mapped in the agent registry to Idle/Thinking/WaitingForInput/Unknown; the registry entry is Unknown with no capabilities until SessionStart, then advertises `capabilities: ["chat-v1"]` while the adapter reports it, and the agent list is re-sent to Astation on a change. No SessionStart within 15 s leaves chat unavailable with a notice (a late one still enables it); a transcript format change withdraws chat (open conversations get `error` and `close`); the terminal is unaffected either way. `submit` is pasted as one bracketed paste plus Enter (`PtyInput::send_paste`, not counted as typing) only for the current generation, a new `requestId`, a clean prompt (≤ 32 768 bytes, no control characters except `\n`/`\t`), status ready with nothing pending, no typing since the last turn ended (`PtyInput::input_count`) and no terminal viewer in control; accepted when both the UserPromptSubmit hook and the transcript's user entry arrive. Approvals stay in the terminal. Outgoing text goes through the credential redactor. Conversations are handled only while `astation_connected` (not during re-authentication) and close on disconnect or re-authentication; a new `open` restores status and history (50 messages / 256 KiB, `before` pages). Claude exiting reports `unknown` and `error`, drops the adapter (removing its directory) and keeps history readable; a respawn sends the old conversations `error` "the agent was restarted; reopen the chat" and `close`. Codex is registered with status Unknown and no capabilities (the agent list is sent when it starts). See `designs/agent-chat-host.md`.

**Vault** (`vault_client.rs`): Client for the relay-hosted shared cross-agent context store. `atem vault new/list/read/write/set-summary` — a versioned, append-only store that multiple atems read/write to hand off context between their agents. Pure request builders + human/plain renderers + a thin reqwest executor (auth: `Authorization: session <id>` + `?id=<instance_id>`). The `/api/vault` endpoints + Postgres live in the relay-server (Astation repo). See `designs/vault.md`.

**Atem Memory** (`src/memory/`): `atem sync`, `atem memory …`, `atem skill …`. Agents learn from each other across agents and machines. Claude's saved memories are harvested (an edited file becomes a replacement, a deleted file an invalidation), Codex saves facts with `atem memory add --agent codex` and replaces outdated ones with `atem memory replace <id> "<new fact>"` (its block shows each fact's short id), and skills are versioned directories (`atem skill history`/`atem skill restore` read old versions from the relay). Facts are never edited in place: `memory replace`/`memory invalidate` keep the history (`valid_at`, `invalid_at`, `superseded_by`; see `memory list --history`), invalidation is final, and only valid facts are injected — a block that leaves facts out says how many and points to `atem memory search`, which is local FTS5 (trigram, BM25) over `knowledge.db`. Everything is synced through the relay (`/api/memory`, `/api/skills`, Astation pairing-session auth) with an offline SQLite store, then applied as a managed block in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and `<repo>/CLAUDE.local.md`, and as skills in `.claude/skills` and `.agents/skills`. Credential values are never stored: names only. Tracked files are never written. See `designs/atem-memory.md`.

**Key agent** (`src/memory/key_agent.rs`, `agent_socket.rs`, `unlock.rs`): this device's keys live sealed in `device_keys.sealed` under a storage key only the home Astation (the first one this device verified with) holds. The hidden `atem key-agent` (same binary, started on demand, detached; Unix socket, same-UID peers only, `"v": 2` JSON lines; `PR_SET_DUMPABLE=0` on Linux, and `mlockall` there when `RLIMIT_MEMLOCK` is unlimited or ≥ 512 MiB; one agent per key directory via a `flock` on `key_agent.lock`; an agent whose socket disappears, e.g. logind removing `$XDG_RUNTIME_DIR`, wipes its keys and exits within ~5 s) holds the unlocked keys; while it is locked, grants are ignored (`encryptionMode`/`keyGrant` arriving while atem waits for another reply are applied, not dropped, and after an unlock atem sends `keyRequest` if the signed state still needs `K`; an already unlocked `atem cred unlock` still connects while the signed state is `enabling`/`disabling`, to finish the migration and send the signed completion, since `atem sync` never talks to Astation). `atem cred unlock` asks it for a single-use key, sends an `unlockRequest` signed by `unlock_auth_key`, and hands Astation's Touch-ID-approved, signed `unlockGrant` straight back to the agent; the agent then rotates the storage key in three crash-safe phases (`.next` → `storageKeyAck` → promote, `.prev` kept until the next unlock → `storageKeyConfirm`), abandoning a stale pending key if needed. `atem pair` escrows the first storage key in the same run; until Astation is known to hold it, a fresh device keeps a plain `device_keys` file (like a step-1 device), which the agent re-seals at each start and deletes at the first confirmed escrow, so an agent that stops first loses nothing; `atem cred lock` wipes the agent and stops it (always allowed: the agent stops listening, removes its socket and `agent.socket`, gives requests in flight up to 1 s, clears its pid from `key_agent.lock` and exits; the CLI waits up to 2 s for it to go, and an agent from an older atem that only wipes is reported as still running until the next `atem cred unlock` replaces it); `atem cred status` shows verified / home Astation / agent / storage key, and the reset steps when a key file is broken. An `unlockDenied` with `revoked: true` (or "revoked" in its reason) is recorded in `cred_state.json` (`atem cred status` shows "revoked by Astation …"); the next `atem pair` with the agent locked renames the old key files to `<name>.revoked-<stamp>`, forgets that Astation's verification, home and escrow state, and verifies with new keys (the signal is unsigned: a forged one costs a re-pair, never keys or trust). Since step 2b `K` lives only in the agent: it installs granted keys into the sealed payload (`InstallGrant`; a payload with keys is `version: 2`, so a step-2a binary refuses it), does every seal/open/keyed hash for `EncryptionContext` in batched `Crypt` requests (no reply carries `K`), takes the mode and kid from the newest signed account state across every verified Astation naming the account (one helper, `verification::effective_state`, for install, `Crypt`, `account_mode` and `key_needed`), serializes key payloads into exactly sized wiped buffers, and moves a leftover `data_keys.enc` in at the first unlock (then deletes it, unless an entry of a verified account can't be parsed: then the valid keys move and the file stays; an unreadable one is renamed aside, never deleted); a locked agent keeps sync changes queued until `atem cred unlock`. A key agent left running from before the upgrade speaks protocol v1 and must be stopped (the error says how); a restart before the first escrow loses a post-2b `K`, which is requested again. After the upgrade a verified device needs `atem cred unlock` once. The status reply carries the agent's `build` (`key_agent::build_id`: version + the executable's mtime and size when the agent started, so every rebuild differs; absent from an older agent, which counts as older). A command that may start the agent compares it with its own once: a locked agent of another build is asked to stop (one too old for that gets SIGTERM, only when its pid is confirmed as this user's `atem key-agent` through `key_agent.lock`, else the error gives the `pgrep`/`pkill` lines) and this build's agent is started; it holds no keys, so nothing is lost. An unlocked one is never restarted: the command warns once ("The key agent was started by another atem build; run `atem cred lock`, then `atem cred unlock` to use this one.") and uses it, a request it rejects as unknown gets that hint instead of the raw error, and `atem cred status` adds `(started by another atem build; run `atem cred lock`, then `atem cred unlock`)` to the agent line (builds are compared for equality only: a dev build and the npm release of the same version differ, and neither counts as newer). The unlocked agent also signs what atem reports to Astation: `CredentialProjects` (the HPKE credential-project report plus optional original-case `labels`, `credential_projects.rs`; sent best effort after each authenticated connection, on `credentialProjectListRequest`, and by `atem cred projects`) and `MigrationComplete` (the `atem-migration-complete-v1` completion with its `K` possession proof, sent only after the read-back pass in `migration.rs` finds every protected field migrated). See `designs/e2e-encryption.md` "Keys on disk (atem)" and "Astation work for step 2a", and `docs/credential-project-reporting.md`.

**Claude Code Integration** (`claude_client.rs`): Manages Claude Code as a PTY subprocess using `portable-pty`. Includes terminal output parsing via `vt100`, session recording, and resize handling.

**RTM Signaling** (`rtm_client.rs`): FFI wrapper for native C RTM client with async Tokio channels. Default build uses a stub; enable `real_rtm` feature for Agora SDK.

**Webhook Server** (`webhook_server.rs`): Receives Agora webhook POSTs (ConvoAI events 101–111, 201–202; RTC NCS events) on a local HTTP port. Optionally spawns `ngrok http <port>` or `cloudflared tunnel --url <port>` to expose the listener publicly. Validates `Agora-Signature-V2` (HMAC-SHA256) against `secret` from `webhooks.toml` when configured, skips validation with a banner warning otherwise. Broadcasts each accepted event to a live web console (SSE) at `GET /` and prints a one-line summary to stdout. `--background` mode: standard daemon shape — registers in `~/.config/atem/servers/webhooks-<port>.json`, redirects stdout/stderr to `webhooks-<port>.log`, manageable via `atem serv list / kill / killall`. ngrok collision detection (refuses to start when a foreign ngrok already owns `:4040` and prints actionable next steps including the paid-plan link). cloudflared failure path captures stderr tail and surfaces it.

### Configuration & Storage (`config.rs`)

**Files in `~/.config/atem/`:**

| File | Contents | Encryption |
|------|----------|------------|
| `config.toml` | Non-sensitive settings (astation_ws, relay URL, bff_url, sso_url, `terminal_prefix` for the shared agent terminal; env `ATEM_TERMINAL_PREFIX` wins) + auto-generated identity (`instance_id`, `atem_id`) + `files_last_port` (last port `atem serv files` bound, reused next run) + `[memory] harvest_claude = false` (turns off harvesting Claude's native memory during `atem sync`) | None |
| `credentials.enc` | SSO + paired tokens (multi-entry `Vec<CredentialEntry>`) | AES-256-GCM (machine-bound) |
| `project_cache.enc` | All projects + `current_app_id` (selected project reference) | AES-256-GCM (machine-bound) |
| `sessions.json` | Per-Astation device session IDs and tokens | None (chmod 0600) |
| `knowledge.db` | Atem Memory local store: memories (with `deleted_at`/`valid_at`/`invalid_at`/`superseded_by`), the `memories_fts` FTS5 trigram search index, skills, harvest map, local `replacements`, and the pending-sync queue (SQLite, mode 0600; holds no secrets — credentials are refused before storing; migrated in place on open) | None |
| `device_keys` | Plain device keys: a build-step-1 device's, or a freshly verified device's until its first escrow; the key agent seals them into `device_keys.sealed` at each start while this file exists, and deletes it once the home Astation is known to hold the storage key | None (chmod 0600, written atomically) |
| `device_keys.sealed` | This device's X25519 device key, Ed25519 signing key and account keys (`K` + previous, step 2b) (`{version, device_id, storage_kid, nonce, ciphertext}`); `device_keys.sealed.next` exists only mid-rotation, `device_keys.sealed.prev` (the replaced file) until an unlock proves Astation holds the current key | XChaCha20-Poly1305 under the storage key (held only by the home Astation, replaced at every unlock) |
| `unlock_auth_key` | Ed25519 key that signs unlock requests | None (chmod 0600; it can only ask Astation) |
| `cred_state.json` | Verified Astation pins (signing, encryption, recovery keys), safety code, epoch floor, latest signed account state, `home_astation` (holds the storage key), `escrowed_storage_kid` (last storage kid Astation is known to hold), `abandoned_kids` (never reused), `escrow_unanswered` (the home Astation never answered the first escrow, e.g. no step-2a support); every read-modify-write holds an `flock` on `cred_state.lock` | None (chmod 0600; no secrets) |
| `project_names.json` | `h1.` project hash → readable project key, per account (memory/skills project names the relay sees only as HMACs), plus optional original-case `labels` per account (used in credential-project reports); replaces the names part of the removed `data_keys.enc` (`data_keys.enc` is moved in and deleted by the key agent at the first unlock; an unreadable one is renamed `data_keys.enc.corrupt-<stamp>`); writes hold an `flock` on `project_names.lock` (taken after the `cred_state.lock`) | None (chmod 0600; no secrets) |
| `key-agent.log` | Output of the detached `atem key-agent` | None |
| `agent.sock`, `agent.lock` | Key-agent socket and its per-socket lock, here only when `$XDG_RUNTIME_DIR` is unset (else `$XDG_RUNTIME_DIR/atem/`); directory 0700, socket 0600, same-UID peers only | — |
| `key_agent.lock`, `agent.socket` | One key agent per key directory: the agent holds an exclusive `flock` on `key_agent.lock` for its life and writes its pid into it (a second agent exits; one that can't reach the holder names its pid and `kill <pid>` only when the lock is held and the pid is confirmed as `atem key-agent`, else gives `pgrep`/`pkill` lines; a clean exit clears the pid), and records its socket path in `agent.socket`, which clients try first (so a session with another `$XDG_RUNTIME_DIR` finds it; the peer-UID check still applies) | None (chmod 0600) |

**Identity** (`config.rs`, `websocket_client.rs`):
- `instance_id` — persistent UUID v4, the canonical atem identity (and the vault `client_id`). Generated once by `ensure_instance_id()`, stored in `config.toml`.
- `atem_id` — the relay-room id `<host>[-<filler>]-<suffix:8>` (host + filler = 12 chars; e.g. `Genie-dc1649f-956631ec`), generated once (`build_atem_id`) and frozen in `config.toml` so it survives restarts and hostname changes. Keeps non-ASCII hostnames (Chinese/Japanese/Korean), restricts ASCII to `[A-Za-z0-9-]`, percent-encoded into the relay URL. See `designs/atem-identity.md`.

**Credentials** (`credentials.rs`):
- `CredentialStore` wraps `Vec<CredentialEntry>`, AES-256-GCM encryption with HMAC-SHA256(machine-id) key derivation — file cannot be decrypted on another machine
- Each entry is either `source: sso` (own login) or `source: astation_paired` (from `atem pair`)
- `CredentialStore::resolve(connected_astation_id, now)` priority:
  1. Paired entry matching the currently connected Astation (active connection wins)
  2. Own SSO entry (from `atem login`)
  3. Paired entry with `save_credentials: true` (offline-capable)
  4. Paired entry within 5 min grace period after disconnect
- `disconnected_at` is stamped when Astation WS drops; cleared on reconnect via `CredentialSync`

**SSO auth** (`sso_auth.rs`):
- `atem login` — OAuth 2.0 + PKCE browser flow against `sso2.agora.io`; writes an `sso` entry to `credentials.enc`
- `atem logout` — removes the `sso` entry from `credentials.enc`
- `atem pair [--save]` — connect to Astation, send `PairSavePreference`, wait for `CredentialSync`, write paired entry, then verify the device: commit-then-reveal (`verifyCommit` → `verifyKeys` → `verifyReveal`), both sides show a 12-character safety code, the user answers `codes match? [y/N]` (read from `/dev/tty`, flushed first, never stdin; no terminal fails the verification) and confirms on Astation with Touch ID, and atem applies the signed `deviceVerified` atomically (pins, device keys, signed state, grants; nothing on failure). If `K` is needed but missing it sends `keyRequest`. Astations that don't answer within 15s leave the device as it was (see `designs/e2e-encryption.md`). Any later failure (code refused, no terminal, 300 s Touch ID timeout, lost connection, apply error) drops the pending pin and sends `verifyAbort` with delivery confirmed (not when Astation itself aborted); the pairing stays saved and `atem pair` exits nonzero. A failed `keyRequest` after success is only a warning (`atem cred unlock` asks again). Logic and tests: `src/pair_verify.rs`. On the home Astation's first verification the fresh keys are sealed and the first storage key is escrowed (`storageKeyRotate` with an empty old kid, then confirmed) in the same run
- `atem cred projects|status|unlock|lock` (tier 2) — send the current Git project and the account's remembered project names to the home Astation's credential picker (keys must be unlocked; connects within 15 s; see `docs/credential-project-reporting.md`); key agent state; Touch ID unlock through the home Astation (waits up to 300 s, then rotates the storage key; when already unlocked it still finishes a pending migration); wipe the unlocked keys and stop the agent. `atem key-agent` is the hidden agent process itself
- `atem unpair [--yes]` — remove all paired entries. It, `atem memory purge` and `atem skill purge` confirm first (`cli::confirm_destructive`): `--yes` skips the question, and without a terminal they refuse unless `--yes` is given. The purge prompts show the id and scope only, never the content, since a purged item may hold a credential
- `valid_token(connected_astation_id, sso_url)` — resolves via priority chain and returns an access token. Within 60s of expiry, an `sso` entry refreshes itself; a paired entry never does (Agora rotates refresh tokens, so it would invalidate Astation's copy): atem connects to Astation, which sends a fresh `credentialSync` on connect.

**BFF API** (`agora_api.rs`):
- `fetch_projects(access_token, bff_url)` — `GET {bff_url}/api/cli/v1/projects`, Bearer auth, returns `Vec<BffProject>`
- Default BFF URL: `https://agora-cli.agora.io` (override via `ATEM_BFF_URL` or `bff_url` in config.toml)
- Default SSO URL: `https://sso2.agora.io` (override via `ATEM_SSO_URL` or `sso_url` in config.toml)

**`atem config show`** displays credentials + active project:
```
SSO:      logged in  (52a4f560...)
Paired:   astation-<uuid>  (SSO: 52a4f560...)  [save: yes]
          Verified: yes  (safety code MN3H-A74N-FJE4)
```
An unverified pairing shows `Verified: no  (run 'atem pair' to verify this device)`.

**WebSocket messages** (`websocket_client.rs`):
- `CredentialSync { access_token, refresh_token, expires_at, login_id, astation_id, save_credentials }` — Astation → Atem, after pair, on connect, or on Astation-side refresh (replaced `SsoTokenSync`)
- `PairSavePreference { save_credentials }` — Atem → Astation during `atem pair`, communicates user's save choice
- `VerifyCommit { device_id, commitment }` — Atem → Astation, starts device verification with a commitment to unrevealed keys
- `VerifyKeys { sign_pub, enc_pub, recovery_sign_pub, nonce }` — Astation → Atem; `sign_pub` is the 65-byte uncompressed P-256 point
- `VerifyReveal { device_pub, device_sign_pub, unlock_auth_pub, nonce }` — Atem → Astation, the keys and nonce behind the commitment
- `DeviceVerified { device_verified, account_state, grants }` — Astation → Atem after Touch ID: signed certificate (bound to the ceremony transcript), signed account state, signed HPKE grants
- `VerifyAbort { reason }` — either side cancels verification
- `EncryptionMode { account_state }` — Astation → Atem, a signed `atem-account-state-v1`; ignored when unsigned or when the device isn't verified
- `KeyRequest { public_key }` — Atem → Astation, a verified device asks for `K`
- `KeyGrant { grant }` — Astation → Atem, `K` sealed to this device with a signed grant; ignored when unsigned or unverified
- `UnlockRequest { request, signature }` — Atem → home Astation, `atem-unlock-request-v1` signed by the unlock-auth key
- `UnlockGrant { grant, encapped_key, ciphertext }` / `UnlockDenied { reason, revoked }` — Astation → Atem, the storage key sealed to the request's single-use key, or a denial
- `StorageKeyRotate { rotate, encapped_key, ciphertext }` — Atem → home Astation, a new storage key sealed to Astation's encryption key, device-signed
- `StorageKeyAck { ack }` / `StorageKeyRejected { reason, pending_kid? }` — Astation → Atem, stored as pending, or refused (`pending_kid`: Astation is committed to that pending key)
- `StorageKeyConfirm { confirm }` / `StorageKeyAbandon { abandon }` — Atem → home Astation, device-signed: switched to the new key / give up a pending key this device has no file for
- `EncryptionMigrationComplete { mode, kid, completion }` — Atem → Astation after a migration's read-back pass (`mode` `on`/`off`): `completion` is a device-signed `atem-migration-complete-v1` with a `K` possession proof, made by the agent (`MigrationComplete`); sent flushed so a short-lived CLI can exit
- `CredentialProjectListRequest` — Astation → Atem, asks an unlocked device for its credential-project report
- `CredentialProjectListResponse { report }` — Atem → Astation, after every authenticated connection, on request, and from `atem cred projects`; `report` is `{signed, encapped_key, ciphertext, labels?}` (HPKE to the pinned Astation key, device-signed by the agent's `CredentialProjects`; `labels` carries original-case spellings). Locked or unverified devices send nothing

**Active project resolution** (`ActiveProject::resolve_app_id/resolve_app_certificate`):
1. CLI flag (`--app-id`)
2. Env var (`AGORA_APP_ID`, `AGORA_APP_CERTIFICATE`)
3. Active project file
4. Error: `"No active project. Run 'atem project list', then 'atem project use <index>'"`

Note: RTC/RTM token generation needs only `app_id` + `app_certificate` (from active project). It does NOT need SSO credentials.

### Capability Tiers

Product rule: `atem login` unlocks a limited set of functions (tier 1); pairing
with Astation unlocks the full set (tier 2) — Astation is the control plane.

| Tier | Needs | Commands |
|---|---|---|
| 0 | — | serv files, config, token with AGORA_APP_ID/CERT env, `project use <index>`, `project show` (local cache) |
| 1 | `atem login` | `project list`, `project use <app-id>`, token (active project), serv rtc/convo/webhooks |
| 2 | paired with Astation | vault, sync, memory, skill, cred, and Astation-driven remote agent control, voice coding, mark tasks |

Gates are centralized in `src/auth.rs`: `require_login(feature)` is the tier-1
gate (passes when `CredentialStore::load().entries` is non-empty);
`require_pairing(feature)` is the tier-2 gate (resolves a `PairedSession` —
relay base, Astation id, session id — from `AtemConfig` + `SessionManager`,
purely local, no network). Both return an actionable `anyhow::Error` built
from `login_gate_message`/`pairing_gate_message` when the check fails.

New cross-machine or cross-agent features are tier 2 and must gate with
`auth::require_pairing`.

### Native FFI Layer

```
native/
├── include/atem_rtm.h       # C header for RTM client interface
├── src/atem_rtm.cpp         # Stub RTM implementation (default)
└── src/atem_rtm_real.cpp    # Real RTM (requires Agora SDK in native/third_party/)
```

Build script (`build.rs`) compiles C++17 code via the `cc` crate. With `real_rtm` feature, links against Agora RTM SDK.

### Feature Flags

| Flag | Description |
|------|-------------|
| `real_rtm` | Link against Agora RTM SDK (default: stub implementation) |
| `openssl-vendored` | Build OpenSSL from source (used in CI for cross-compilation) |

## Key Dependencies

| Category | Crate | Purpose |
|----------|-------|---------|
| CLI | clap (derive) | Command parsing |
| Async | tokio (full) | Runtime, channels, tasks |
| TUI | ratatui, crossterm | Terminal UI rendering |
| Network | reqwest, tokio-tungstenite | HTTP, WebSocket |
| PTY | portable-pty, vt100, vte | Terminal emulation |
| FFI | libc, cc | C interop for RTM |
| Config | toml, dirs | Configuration loading |
| Crypto | hmac, sha2 | Token generation |
| Storage | rusqlite (bundled) | Atem Memory store (`knowledge.db`) |

## Mark Task Flow

```
Chisel (browser) ──POST──→ Express/Chisel middleware
                            ↓ saves .chisel/tasks/{taskId}.json + .png
                            ↓ WS markTaskNotify → Astation
Astation hub ←── markTaskNotify {taskId, status, description}
  ↓ picks best Atem instance
  ↓ markTaskAssignment {taskId, receivedAtMs}
Atem receives assignment (websocket_client.rs)
  ↓ handle_astation_message() in app.rs
  ↓ load_and_build_work_item(): reads .chisel/tasks/{taskId}.json from LOCAL disk
  ↓ build_mark_task_prompt() → annotations + screenshot + source files
  ↓ dispatcher.submit() → main queue (or background `claude -p` via triage)
  ↓ try_dispatch_main(): ensure_claude_session() + send prompt via PTY
  ↓ markTaskResult {taskId, success, message} → Astation
```

## Release Process

**Use `./scripts/release.sh`** — it keeps `Cargo.toml` in sync with the git tag and
guards against common mistakes (dirty tree, duplicate tag, failed build).

```bash
# Patch-bump (reads current Cargo.toml version, adds 1 to the last segment)
./scripts/release.sh

# Or explicit version
./scripts/release.sh 0.5.0
```

What the script does:
1. Resolves target version (auto patch-bump, or from argument)
2. Refuses if tag exists or working tree is dirty (except Cargo.toml/Cargo.lock)
3. Updates `Cargo.toml` → bumps version
4. Runs `cargo build` to refresh `Cargo.lock`
5. Creates a commit for `Cargo.toml` + `Cargo.lock`
6. Creates the tag `vX.Y.Z` locally
7. **Does NOT push** — prints the push command so you can review first

To publish after running the script:
```bash
git show HEAD               # review the release commit
git push && git push origin vX.Y.Z
```

Pushing the tag triggers GitHub Actions (`.github/workflows/release.yml`):
1. Builds binaries for linux-x64, linux-arm64, darwin-x64, darwin-arm64
2. Creates GitHub release with tarballed binaries
3. Publishes `@agora-build/atem` to npm (version synced from tag)

The same workflow builds the atem-core macOS package (`scripts/package-atem-core-macos.sh`) and attaches three assets to the release: `atem-core-<version>-macos-xcframework.zip`, `atem-core-<version>-atem_core.h` and `atem-core-<version>-SHA256SUMS.txt`. See `crates/atem-core-ffi/README.md`.

Requires `NPM_TOKEN` secret in GitHub repo settings.

**Don't manually bump `Cargo.toml` + `git tag` separately** — the two can drift
(any `atem --version` will show the stale Cargo.toml number even if the tag is newer).

## Integration Points

- **Astation**: macOS menubar hub that coordinates Chisel, Atem, and AI agents — talk to your coding agent from anywhere (WebSocket)
- **Chisel**: Dev panel for visual annotation and UI editing by anyone, including AI agents (`.chisel/tasks/`)
- **Claude Code CLI**: Spawned as PTY subprocess for AI-powered code implementation
- **Agora RTM SDK**: Native library for real-time messaging (voice coding)
- **Agora REST API**: Project management, credential fetching
- **Conversational AI (`atem serv convo`)**: Launches a local HTTPS test page that
  drives Agora ConvoAI v2 (`/join`, `/leave`). Config loaded from
  `~/.config/atem/convo.toml` (override via `--config`). Page uses the vendored
  Conversational-AI-Demo toolkit at `assets/convo/` (refreshed by
  `scripts/update-convoai-toolkit.sh`, reproducible from a committed lockfile and pinned esbuild, stale bundles blocked at release time).
  Features: live transcription (RTM), preset checkboxes, avatar video
  (Akool/LiveAvatar/Anam), RTC Stats, API History, camera toggle,
  RTC encryption (key + base64 salt sent to ConvoAI as `properties.rtc.{encryption_key, encryption_salt, encryption_mode}`;
  same params applied to local Web SDK so both peers decrypt). gcm2
  modes (7, 8) require a 32-byte salt; the page auto-generates one and
  exposes it as a copyable, editable field. Project must have Media
  Stream Encryption enabled in the Agora console for the appid.

  `--background` re-execs as a detached daemon (mirrors the rtc daemon
  pattern): parent POSTs `/join`, registers `{id, pid, kind="convo",
  channel}` in `~/.config/atem/servers/<channel>.json`, exits. The
  daemon catches SIGINT + SIGTERM (so `atem serv kill` works) and
  POSTs `/leave` before exiting. A tokio task on the daemon polls
  `GET /agents/{id}` every `[atem].poll_interval_secs` (default 60,
  floored to 5) and writes `last_status` + `last_checked_at` into
  the registry JSON — `atem serv list` reads the cached value with
  no network round-trip. The daemon log (`<channel>.log`) contains
  the `/join` URL (HIPAA path when applicable) and the request body
  with secrets masked (api keys, tokens, encryption_key, certs).

  `--channel` supports `{appid}` (first 12 chars of active app id) and
  `{ts}` (unix epoch seconds) placeholders, expanded by atem at startup.
  Lets fleet for-loops produce channels matching the default auto-gen
  shape without computing prefix/timestamp in the shell:
  `atem serv convo --background --channel 'atem-convo-{appid}-{ts}-001'`.

  `convo.toml` schema:
  - `[atem]` — atem's runtime control surface. atem reads each field
    and decides how to dispatch (URL prefix, build the avatar block,
    pre-fill the web form, etc.). Fields:
    - `channel` (RTC channel name; auto-generated when omitted)
    - `rtc_user_id` (human's RTC uid; "0" = server-assigned)
    - `pipeline` — `"cascaded"` | `"mllm"`. Picks which provider
      block goes into `/join` when both are parked in the file.
      Auto-detected from which block is present when omitted; required
      when both `[agent.asr/llm/tts]` and `[agent.mllm]` exist.
    - `env` — ConvoAI REST environment: `ga` (default, api.agora.io/api) |
      `eap` (partner.ai.agora.io/preview/api + `agora-feature: live-models`
      header; Early Access Preview) | `hipaa` (api.agora.io/hipaa/api, forces
      NORTH_AMERICA + AES_256_GCM2). `[atem].hipaa = true` is a legacy alias
      for `env = "hipaa"`. The web UI shows the environments as single-select
      radios with a live endpoint-URL preview.
    - `[[atem.environments]]` — add/override environments (`name`, `host`,
      `prefix`, `label`, `headers`, `force_geofence`, `force_encryption_mode`).
      Merged over the built-in ga/eap/hipaa by `name`; a new name adds a
      selectable environment — no code change. `ATEM_CONVOAI_API_URL` overrides
      the ga/hipaa host.
    - `envs` — allowlist of environment names to show in the UI, in order
      (e.g. `["ga", "eap"]` hides HIPAA). Empty/omitted → show all. The
      selected `env`/`hipaa` default is clamped to a shown entry.
    - `geofence` — GLOBAL | NORTH_AMERICA | EUROPE | ASIA | JAPAN | INDIA
    - `enable_avatar` — opt in to `[agent.avatar]` this session
    - `[atem.encryption]` — `mode` (0..=8), `key`, `salt` (base64-32-bytes)
  - `[agent]` — about the AI agent itself:
    - `user_id` (the agent's RTC uid; required)
    - `idle_timeout_secs` (server-side reaper)
    - `preset` (comma-separated string; UI splits to checkboxes,
      joins selections back as `properties.preset`)
    - `[agent.llm]` / `[agent.asr]` / `[agent.tts]` / `[agent.avatar]`
      — cascaded provider blocks, forwarded under `properties.<svc>`.
      `[agent.llm]` also accepts `[[agent.llm.mcp_servers]]` entries
      ({`name`, `endpoint`, `transport`, `headers`, `allowed_tools`,
      `timeout_ms`}) → `properties.llm.mcp_servers[]`. When any MCP
      server is present atem auto-sets `advanced_features.enable_tools
      = true` unless that field is pinned in `[advanced_features]`.
    - `[agent.mllm]` — single multimodal model that replaces
      asr+llm+tts. Per Agora's MLLM schema: `vendor`, `url`,
      `api_key`, `greeting_message` at the top of the block; vendor
      knobs (`model`, `voice`, `instructions`, …) under `[…params]`.
      atem auto-injects `enable: true`, `input_modalities: ["audio"]`,
      and `output_modalities: ["text", "audio"]` so the agent emits
      audio. MCP works here too: `[[agent.mllm.mcp_servers]]` (same
      shape as the LLM's) → `properties.mllm.mcp_servers[]`, and
      `enable_tools` is auto-set the same way.
  - Pass-through tables — `[advanced_features]`, `[vad]`, `[sal]`,
    `[parameters]` — atem forwards verbatim as `properties.<key>`.

  Implemented as `ConvoConfig { atem: Option<AtemSection>, agent:
  Option<AgentConfig>, …pass-through… }`. `[atem]` values flow into
  both the web UI (form pre-fills via `DEFAULT_*` JS constants
  emitted by `build_html_page`) and `--background` mode (sent to
  ConvoAI's `/join` body via the resolved values on `JoinArgs`).
  `atem config convo --validate` checks the schema (geofence value,
  encryption mode/key/salt consistency, etc.) — see
  `convo_wizard::run_validate`.

- **`atem serv attach <id>` / `atem serv attach <#>`**: Opens a foreground
  HTTPS UI bound to a running convo daemon's channel. Looks up the entry
  in the servers registry, validates `kind == "convo"`, spawns the
  convo HTTPS server with `attach: true`. The page receives `ATTACH_MODE
  = true` which hides the Start/Stop buttons (the daemon owns the agent;
  trying to /start would create a duplicate agent on the same channel).
  User joins the channel with their RTC uid + matching encryption to
  talk to the live daemon-owned agent.

- **`atem serv list/kill/killall` registry conventions**: All servers
  (rtc, convo, webhooks, files) write JSON entries to `~/.config/atem/servers/`.
  Convo entries use the channel name itself as the id (no kind/port
  suffix) since channels are unique per agent. `list` shows a 1-based
  index (`#`), `ID`, `PID`, `PORT`, `STATUS` (cached from convo's 60s
  poller, `—` until the first poll). `kill` and `attach` accept either
  the literal id or the index from `list`.
- **ConvoAI Config Wizard (`atem config convo`)**: Interactive terminal wizard
  that generates `~/.config/atem/convo.toml`. Flow: Channel & User → Agent →
  Preset (empty = skip) → Add Custom override? → Pipeline (Cascaded | MLLM)
  → Avatar. Preset and Custom stack — preset sets defaults, explicit blocks
  override per-field. Pipeline pick is single-select; the parked one stays in
  the file (`[atem].pipeline` switches between them at runtime). Provider
  selection: ASR (10 vendors), LLM (9), TTS (12), MLLM (4 — OpenAI Realtime
  default `gpt-realtime`, Gemini Live, Vertex AI Gemini Live, xAI Grok),
  Avatar (3). MLLM `api_key`/`url`/`greeting_message` written at the top of
  `[agent.mllm]`; `instructions`/`model`/`voice` go in `[agent.mllm.params]`.
  Pre-fills from existing TOML on re-run; `.bak` rotation keeps last 5
  generations. `--validate` performs read-only schema checks (required
  fields, large-integer precision issues, vendor completeness).

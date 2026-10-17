# AGENTS.md

This file provides guidance to AI coding agents working with this repository.

## Project Overview

Atem is a terminal that connects builders, Agora platform, and AI agents. It provides a CLI and TUI for managing Agora projects and tokens, routing tasks between Astation and AI coding agents, and more.

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
cargo test                               # Run tests (1,450+; use -- --test-threads=1 if a test flakes); tests must inject a temp profile (src/test_profile.rs)
cargo test --test runtime_fixtures_binary # Shared atem-session host fixtures against the real runtime (ATEM_FIXTURE=<name> runs one)
ATEM_REAL_AGENTS=1 cargo test --test approvals_real_agents -- --ignored --nocapture --test-threads=1 # Approvals with the REAL claude/codex CLIs (real API calls; credentials from the environment; Codex runs --profile oss)
cargo test -p atem-core -p atem-core-ffi # Token library + C ABI tests (workspace members)
./scripts/check-atem-core-ffi.sh         # Build libatem_core_ffi.a, drive it from C (and Swift on macOS)
cargo check                              # Type-check without building
rustfmt --edition 2024 <file>            # Format the files you touch; not project-wide: app.rs, main.rs, cli.rs, websocket_client.rs and memory/{mod,crypto,secrets}.rs aren't rustfmt-clean
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
├── app.rs               # Menu TUI state (bare `atem`, no Astation connection); inside `atem runtime`: the Astation link, auth, credentialSync, mark task queue (sessions are the broker's)
├── app/reauth.rs        # re-authentication when Astation sends auth_required over an open socket
├── app/hosted.rs        # the App inside `atem runtime`: session-family inbox for the broker's host, broker sessions for mark tasks (bare `atem` opens no Astation connection)
├── app/op_route.rs      # a running Astation operation's handshake replies go to it only (dropped once it ended)
├── runtime/             # `atem runtime` (the broker) and `atem worker` — see "Runtime" below
│   ├── mod.rs           #   run_runtime: one per config dir (runtime.lock), socket, state dir `<config>/runtime`
│   ├── server.rs        #   local protocol server: frontends, launch/attach/input/paste/resize/reclaim/list/stop/reload, Astation operations, the 16 ms pass
│   ├── protocol.rs      #   local protocol v1 (JSON lines over the same-user socket)
│   ├── client.rs        #   RuntimeClient: find the runtime or start it detached; hello/welcome
│   ├── commands.rs      #   `atem agent launch|attach|list|stop` as runtime clients
│   ├── broker.rs        #   BrokerSession per session: worker connection, screen mirror, chat state, activity, input epoch, exit
│   ├── adopt.rs         #   spawn workers; adopt survivors (session id + process generation + OS start time), else interrupted/recovery_required
│   ├── worker.rs        #   `atem worker` (hidden): agent PTY, canonical screen, chat adapter, fenced writes, record/spec/socket, session log
│   ├── worker_protocol.rs # broker ↔ worker JSON lines (start, hello, write/paste with input epoch, set_input_epoch, resize, stop, output, screen, chat, activity, exited)
│   ├── worker_chat.rs   #   the worker's bounded chat backlog (cut into `chat` messages; `gap` when items were dropped)
│   ├── worker_approvals.rs # the worker's side of approvals: hook files, decisions, who answered (terminal or Astation)
│   ├── push_queue.rs    #   push_approval/push_resolved for the relay: latest state while the link is down, bounded
│   ├── session_log.rs   #   session.ansi + summary.md under `<config>/logs/<session_id>/`
│   ├── host_bridge.rs   #   atem-session host in the broker: SessionHost + FileJournal over the workers (attachments, leases, receipts, approvals, terminal-v1 frames, chat-v1)
│   ├── ops.rs           #   Astation operations on the broker's link: pair, pair verify, cred unlock/projects, paired-token refresh
│   ├── op_client.rs     #   the CLI side of an operation: print/ask/answer/done (answers from /dev/tty)
│   ├── test_hooks.rs    #   debug builds only: the fixture clock and PTY write faults (ATEM_TEST_CLOCK_FILE, ATEM_TEST_PTY_FAULTS)
│   └── *_tests.rs       #   (test-only) server, ops, adoption, broker and host bridge (in-process workers, fake Astation peer)
├── session_protocol/    # atem-session v1 (r7), transport-independent (designs/protocol/atem-session-v1.md)
│   ├── wire.rs          #   strict decode/encode of session-v1 and bound terminal/agentChat messages
│   ├── canonical.rs     #   canonical JSON and payload digests
│   ├── host.rs          #   SessionHost: attachments, registry, leases, input epochs, receipts, family admission → effects
│   ├── journal.rs       #   Journal trait, receipt records, the in-memory journal
│   ├── file_journal.rs  #   FileJournal: per-session receipt logs, fsync per transition, lease-epoch floors, compaction
│   ├── client.rs        #   client machines (LeaseClient, RegistryClient), run by the client fixtures
│   ├── fake_runtime.rs  #   (test-only) the host fixtures' harness around SessionHost
│   └── fixtures.rs      #   (test-only) runner for designs/protocol/fixtures/*.json
├── session.rs           # session ids (`ses-` + 12 base32), providers, launch environment bounds, the frontend output tap
├── daemon.rs            # detached-daemon plumbing (key agent, runtime): private socket dirs, peer checks, pid locks, detached spawn
├── test_profile.rs      # cfg(test) guard: resolving the real profile, runtime dir or key agent panics unless the test injected a temp one
├── chat/                # Agent chat (chat-v1), agent-neutral except the adapters
│   ├── adapter.rs       #   AgentAdapter trait, AgentEvent, LogItem, Capabilities, LaunchPlan
│   ├── session.rs       #   per-agent chat state: status, history, draft check, submit/acceptance, request ids
│   ├── wire.rs          #   agentChat v1 envelopes to and from Astation
│   └── claude/          #   Claude Code adapter: hooks.rs (chat dir, settings.json, event files), transcript.rs (session JSONL)
├── cli.rs               # CLI command definitions
├── repl.rs              # Interactive REPL mode
├── websocket_client.rs  # Astation WebSocket protocol (message types + client)
├── claude_client.rs     # Claude Code binary and arguments (`CLAUDE_CLI_BIN`/`CLAUDE_CLI_ARGS`, from the launch environment)
├── codex_client.rs      # Codex binary and arguments (`CODEX_CLI_BIN`/`CODEX_CLI_ARGS`)
├── pty_session.rs       # Shared byte-oriented PTY transport (bounded input/output; fenced writes checked against the input epoch at the write boundary)
├── terminal_share.rs    # terminal-v1: canonical-screen ANSI frames, viewer credit, `written` acks; bound to session-v1 by the host
├── rtm_client.rs        # Agora RTM FFI wrapper (kept, not wired into the App; see native/)
├── terminal_keys.rs     # xterm key encoding for the emulated terminal
├── diagnostics.rs       # Background warnings queued while the TUI owns the screen
├── token.rs             # Agora RTC/RTM token generation
├── ai_client.rs         # Anthropic API client for intent parsing
├── sso_auth.rs          # OAuth 2.0 + PKCE login flow, token refresh primitives
├── credentials.rs       # Encrypted multi-entry credential store (SSO + paired)
├── agora_api.rs         # BFF API client (BffProject, fetch_projects with Bearer auth)
├── auth.rs              # Astation auth session management, deep link flow
├── config.rs            # Config, SSO/BFF URL helpers, active project, project cache
├── time_sync.rs         # HTTP Date-based time synchronization
├── webhook_server.rs    # atem serv webhooks — Agora webhook receiver +
                          # ngrok/cloudflared tunnel integration + SSE console
├── rtc_test_server.rs   # Browser-based RTC test page server
├── files_server.rs      # atem serv files — static file server (Markdown rendered)
├── convo_config.rs      # ConvoAI TOML parsing + Agora REST /join body builder
├── convo_test_server.rs # atem serv convo — ConvoAI test server + --background mode
├── convo_wizard.rs      # atem config convo — interactive config wizard + validation
├── web_server/          # Shared HTTPS scaffolding (cert, request, /api/token, net, html, browser open)
├── command.rs           # Serial task queue for mark tasks
├── dispatch.rs          # Work item dispatcher for mark tasks
├── pair_verify.rs       # atem pair / atem pair verify device verification: /dev/tty code confirmation, verifyAbort on failure
├── status.rs            # atem status: read-only, offline; also decides pair (no-op when paired), pair verify and the cred unlock gate
├── pairing_binding.rs   # pairing.json: host trust generation + pairing binding; Captured (async Astation work applies replies only under the pairing it started under), BoundAgent
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
│   ├── unlock.rs        #   `atem cred projects|unlock|lock`; unlock/rotation carried over the Astation link
│   ├── migration.rs     #   migration read-back check + atem-migration-complete-v1 proof input
│   ├── fake_astation.rs #   (test-only) Astation's side of unlock and rotation, mirrors the design doc
│   ├── kat_tests.rs     #   (test-only) known-answer vectors listed in designs/e2e-encryption.md
│   ├── k_agent_tests.rs #   (test-only) K in the agent: install, Crypt, rotation, data_keys.enc migration
│   ├── e2e_tests.rs     #   (test-only) encrypted sync/vault end to end, migration and its signed completion
│   └── cmd.rs           #   CLI handlers
└── tui/
    ├── mod.rs           # Menu loop (bare `atem`): agent entries launch/attach through the runtime
    ├── draw.rs          # Frame rendering
    ├── frontend.rs      # Local frontend of one runtime session (restore + output into a local parser, keys/paste/resize back, status row)
    ├── terminal_view.rs # Agent terminal view: prefix keys (terminal_prefix in config.toml / ATEM_TERMINAL_PREFIX), local history/selection
    └── clipboard.rs     # Copy via tmux load-buffer or OSC 52
native/                  # RTM C++ (kept, unused: nothing in the App calls rtm_client)
├── include/atem_rtm.h   # C header for the RTM client interface
├── src/atem_rtm.cpp     # Stub RTM implementation (default)
└── src/atem_rtm_real.cpp # Real RTM using the Agora SDK (feature: real_rtm)
tests/                   # binary tests on temp HOME/XDG_RUNTIME_DIR (never the real profile)
├── runtime_fixtures_binary.rs # the shared atem-session host fixtures against the real runtime, workers and a fake Astation
├── approvals_real_agents.rs # #[ignore], ATEM_REAL_AGENTS=1: approvals answered from a fake Astation with the real Claude Code and Codex in temp HOME/CODEX_HOME
├── runtime_binary.rs, worker_binary.rs, agent_launch_binary.rs, terminal_ui_binary.rs, astation_op_binary.rs, key_agent_binary.rs
└── support/             # Sandbox: temp profile, `atem` in a PTY, cleanup of what it started; astation.rs: fake Astation peer + verified pairing profile
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
├── remote-agent-control.md   # Historical: Astation → atem → agent (agentInput/voice, removed in atem-session r6)
├── local-agent-runtime.md    # Launch the original claude/codex CLI in Atem, local and remote access to one session
├── agent-runtime.md          # `atem runtime` broker + `atem worker`s, local protocol, operations through the runtime (implemented)
├── session-multiplexing.md   # Approved product design: workers, leases, receipts, transports
├── protocol/                 # atem-session-v1.md (r6.2 wire contract), fixtures/ (shared with Astation), atem-host-handoff.md
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

**TUI State Machine** (`app.rs`): bare `atem` is a menu and a client of `atem runtime`; it opens no Astation connection (the runtime owns the machine's one link). Enum-based mode switching via `AppMode`:
- `MainMenu` - Navigation between features
- `TokenGeneration` - Token creation UI
- `CommandExecution` - Shell command runner
- `AgentPanel` - The runtime's sessions (Enter attaches); agent sessions open in `tui/frontend.rs`

**Mark Task Queue** (`app.rs`, `dispatch.rs`, `command.rs`; inside `atem runtime`): Receives task assignments from Astation, reads task JSON from the local `.chisel/tasks/` directory of the live broker Claude session whose working directory holds it (none: `markTaskResult` fails with "no Claude session for this project; run `atem agent launch claude` there"), builds prompts from annotations + screenshots, writes them to that session through its worker as local-origin input (no lease is revoked; a task waits while a remote lease holder exists), reports results back.

Key pieces:
- `App.dispatcher: TaskDispatcher` - routes each `WorkItem` to its project's broker Claude session (serial `TaskQueue`: FIFO, one active, deferred-finalize flag) or, when main is busy and a slot is free (max 2), to a background `claude -p` if a one-turn triage call (`claude -p --model haiku`) picks background (`CLAUDE_CLI_BIN` overrides the binary)
- `App.work_items: HashMap<String, WorkItem>` - built items by task ID

Key methods:
- `load_and_build_work_item()` - reads the task JSON, builds the prompt (`build_mark_task_prompt()`)
- `try_dispatch_main()` - when main is idle and the target session has no remote lease holder, pops the next task and queues its prompt for the broker (`Hosted::writes`)
- `finalize_mark_task()` - reports the main task's result to Astation, dispatches the next
- The runtime's pass drains triage verdicts and background results and runs `finalize_mark_task()` when the deferred-finalize flag is set

**Astation Integration** (`websocket_client.rs`): WebSocket protocol with `AstationMessage` enum:
- `MarkTaskAssignment { task_id, received_at_ms }` - received from Astation
- `MarkTaskResult { task_id, success, message }` - sent back to Astation
- `VisualizeRequest { session_id, topic, relay_url? }` - diagram request from Astation; diagram generation was removed, so atem answers each one at once with `VisualizeResult { success: false, message: "Diagram generation was removed from atem" }`
- `VisualizeResult { session_id, success, message, file_path? }` - sent back to Astation (always unsuccessful, no `file_path`)
- `SessionWire(String)` - every inbound `session`, `terminal` and `agentChat` message, as raw JSON for the session host's strict decoder (`session_family` peeks the `type`); outbound host messages are written as is (`try_send_wire`; terminal-v1 on the bounded terminal queue, in order with the frames). `SessionOversize { id }` - one larger than 32 KiB (terminal) or 1 MiB (session, agentChat), dropped unread and answered with a session `error` `unsupported_version`
- `AgentChat(ChatEnvelope)` / `Terminal(Envelope)` - outbound chat-v1 / terminal-v1 messages the host renders
- Removed (atem-session r6, no compatibility): `agentInput`, `agentPrompt`, `voiceCommand`, `voiceToggle`/`voice_toggle`, `voiceRequest`/`voiceResponse`, `userCommand`/`commandResponse`, `codexTaskRequest`/`codexTaskResponse`, `agentListRequest`/`agentListResponse` (the session-v1 registry replaces the agent list); they no longer parse (`websocket_client::REMOVED_OPS` → `RemovedOp`) and are answered with a session `error` `unsupported_version` (detail `removed in atem-session r6`) and no effect, (r6 §0). Every remote mutation is session-v1 (`designs/protocol/atem-session-v1.md`), wired by the runtime host (`designs/plans/2026-10-16-runtime-host-integration.md`)
- Also: project lists, token requests, volume (voice activity border only)/video toggle, heartbeat, auth flow (`auth_required` → `auth`; the connect path and re-authentication share `auth_proof` to build the proof and `auth_response` to classify replies, so the two can't drift)

**Runtime** (`src/runtime/`, `designs/agent-runtime.md`): `atem runtime` (hidden; one per config dir: an exclusive `flock` on `<config>/runtime.lock` holding its pid, the socket `$XDG_RUNTIME_DIR/atem/runtime.sock` (else in the config dir) recorded in `<config>/runtime.socket`, output in `<config>/runtime.log`) is the broker: it serves local frontends over the same-user socket (local protocol v1, `runtime/protocol.rs`: `hello`, `launch`, `attach`, `detach`, `input`, `paste`, `resize`, `reclaim`, `list`, `stop`, `reload`, `astation_op`/`answer` in; `welcome`, `launched`, `attached`, `output`, `exited`, `sessions`, `detached`, `stopped`, `session`, `astation`, `notice`, `print`/`ask`/`done`, `error` out), holds the App with the machine's one Astation link, and owns the session host. Clients (`atem agent …`, bare `atem`, `atem pair`/`pair verify`/`cred unlock|projects`) start it detached when none answers; a runtime of another protocol without live sessions restarts for them. It exits after 10 minutes with no sessions and no non-passive clients (`ATEM_RUNTIME_IDLE_SECS` overrides), on SIGTERM/SIGINT, or when replaced. Every session runs in its own `atem worker --state <config>/runtime --session <id>` (hidden, spawned detached; socket `$XDG_RUNTIME_DIR/atem/workers/<id>.sock`, else `<config>/runtime/workers/`; spec, record (`session_id`, `process_gen`, pids and OS start times, exit) and log in `<config>/runtime/workers/`), which owns the agent's PTY, the canonical screen, Claude's chat adapter and the session log, and outlives the broker: a new broker adopts each surviving worker only when its `hello` names the record's session id and process generation and the pid's OS start time matches (Linux `/proc/<pid>/stat` field 22, macOS `proc_pidinfo`); otherwise the session is `recovery_required` (or `interrupted`/`exited`) and nothing is restarted or replayed. The broker is the only writer authority: every write and paste carries the input epoch it granted, and the worker drops one whose epoch is older than its current one at the PTY write boundary (`pty_session.rs` fenced writes). Session ids are `ses-` + 12 base32 characters; each process is a new `process_gen` (UUID).

**Session host** (`runtime/host_bridge.rs`, `session_protocol/`, `app/hosted.rs`; contract `designs/protocol/atem-session-v1.md` r7.1, compatibility mode): only `atem runtime` serves sessions remotely. Its broker owns `SessionHost` over a `FileJournal` in `<config>/runtime/journal/` (per-session receipt logs under `receipts/`, 0700/0600, `O_NOFOLLOW`, fsync per transition, admission halted after an fsync error, compaction, a lease-epoch floors file, `journal.lock`, and a `runtime_epoch` counter incremented at each start) and makes the App's authenticated Astation link one attachment — new on every connect or re-authentication (`App::astation_link_gen`), fenced when the link drops or is re-authenticated, so clients `hello` again and an old `attachment_gen` is `stale_target`. A second `hello` on the same authenticated link (Astation reset its client, e.g. after sleep) replaces the attachment (`Effect::Replaced`): the old one is fenced (its leases end, streams and conversations close), the new one gets a new `attachment_gen`/`controller_session` with the link's unchanged authorization deadline; receipts stay; at most one a second (`busy`). runtime.log gets one `HH:MM:SS` UTC line per `hello` (welcome, replaced, refused `<code>`). Only the paired Astation the link captured, verified in `cred_state.json`, gets one (`view`, `control`, `client_kind` `native`); any other link gets none and its session messages are answered `unauthorized`. `welcome` names the verified `data_account` (`account_id`), this device's verified `device_id` (`atem_device_id`) and `pairing.json`'s `host_trust_gen`; `runtime_gen`/`runtime_epoch` change when the broker restarts or the identity changes (a pairing verified after the broker started rebinds the host over the same journal). The attachment is authorized for 24 h (no freshness proof yet), on the monotonic clock and in wall time, whichever ends first: then it is fenced and the link dropped, and the reconnect authenticates again. Every 5 s the broker re-checks the link's pairing capture against `pairing.json` and drops a link whose pairing changed (unpair works even without `reload`). Session-v1 (`hello`, `list` → `sessions`/`session_changed` with a per-attachment `seq`, `acquire`/`renew`/`release` → 15 s leases with explicit `takeover`, `submit` → receipts, `receipt_query`) is the registry and the only way to get control. Receipts per kind: `prompt` is pasted once `ChatSession::submit` accepts it and completes at the chat's turn end (a session without chat — Codex — rejects it with no effect); `interrupt` writes Esc and completes when a turn ends (at once when none runs); `stop` completes at the exit; `approval` completes when the agent applied the decision (see Approval hooks). A refused-before-queueing write is `rejected`, a writer error after queueing `outcome_unknown`; executing work is `outcome_unknown` after a broker restart (never retried); duplicate submits return the recorded receipt, the same `request_id` with other content is `request_id_reused`. Terminal-v1 (`subscribe`/`unsubscribe`/`ack`, and `input`/`resize`/`stop` with the lease; terminal id = session id) and chat-v1 (`open`/`close`/`submit` with a binding, `submit` with the lease; `accepted`/`complete`/`error{code}` from its receipt; at most 8 conversations per session) are bound families. Effects reach the workers: remote bytes are checked with `admit_write` before they are sent and tagged with the worker's input epoch, which the broker raises (`set_input_epoch`, at least the lease epoch) whenever the host's epoch moves after remote bytes or while a lease was held; remote writes and pastes also carry `not_after`, the lease's deadline on CLOCK_MONOTONIC (`pty_session::monotonic_ns`), and the worker drops one at the PTY write boundary once it has passed (reported like an epoch drop; local writes carry none); each remote `input` gets a `written` ack (`control changed; not written` when dropped); a slow terminal transport drops frames and ends streams with `busy`. Local frontend input goes through `local_input` (it revokes any remote lease first). Duplicate session messages (same attachment, `id` and content) within 60 s are handled once (at most 4096 remembered). `advance` runs every 100 ms of the session clock. Adopted workers send a `chat_snapshot` before any `chat`, so chat goes on after a broker restart. Bare `atem` opens no Astation connection, so only the runtime ever sees session-family messages. A runtime whose session host could not start (its journal or a damaged `runtime_epoch`, never reset silently) answers them `unsupported_version`, and `welcome.host_error` (shown by `atem agent list` and in `runtime.log`) says why, e.g. "remote sessions disabled: <path> is damaged; move it aside to reset the runtime epoch". §9 features (resume, browser grants, account-wide access, relay confidentiality) are refused. A socket alive is not an authenticated Astation: when Astation sends `auth_required` over an already-authenticated socket (e.g. it alone reconnected to the relay), `app/reauth.rs` shows `Astation ✗`, fences the attachment and ignores every other Astation request, then answers only the pinned Astation non-interactively (`AstationClient::answer_auth_required`) with the connect path's proof (`local_proof` on loopback, else the saved session); success restores online as a new attachment, while denial, expiry, a different `astation_id` or no answer within 15 s leaves a notice and closes the socket for the normal reconnect (never pairing). The shared fixtures run against the real runtime in `tests/runtime_fixtures_binary.rs` (results: `designs/protocol/atem-host-handoff.md`).

**Astation operations through the runtime** (`runtime/ops.rs`, `runtime/op_client.rs`, `app/op_route.rs`): `atem pair` (first pairing), `atem pair verify`, `atem cred unlock`, `atem cred projects` and the paired-token refresh run inside the broker on its existing Astation link (waiting up to 15 s for it); the CLI is only the user interface (`print`/`ask` out, `answer` in, `done` at the end; answers from `/dev/tty`) and never opens its own connection (a runtime that can't be reached fails the command). One operation at a time (a second is refused); its handshake replies are routed to it only and dropped after it ends; a CLI that goes away ends it as a failure (device verification sends `verifyAbort`); a lost link ends it, never replayed. `atem unpair` and `atem logout` send `reload` to a running runtime (never starting one): it re-reads the config and drops a link whose pairing changed, with its attachments.

**Shared terminal** (`src/terminal_share.rs`, `pty_session.rs`, `runtime/`, `tui/frontend.rs`, `tui/terminal_view.rs`): `atem agent launch [claude|claude-code|codex] [AGENT_ARGS]...` connects to `atem runtime` (starting it detached if none answers), sends `launch` with the current directory, environment and terminal size, and opens the frontend (`tui::frontend::run_frontend`); the agent runs in an `atem worker` (arguments are forwarded as separate values, with or without `--`; `CLAUDE_CLI_*`/`CODEX_CLI_*` from the launch environment still apply and come first, after Claude's chat hooks). `atem agent attach <ses-…>` reopens a session (screen restored), `atem agent list` prints the runtime's pid/protocol/build/Astation line and `ID PROVIDER STATE STATUS ATTACHED CWD`, `atem agent stop <ses-…>` stops one (and removes a session without a worker); each starts the runtime if needed (a new runtime adopts surviving workers). Bare `atem`'s Claude/Codex entries launch the same way and its Agent Sessions panel lists and attaches the runtime's sessions (looked up off the UI loop, within 2 s, as a passive client that never keeps an idle runtime running); the menu opens no Astation connection (the runtime owns it). Runtime notices are scoped: Astation link notices reach every frontend, mark-task notices only the frontend of their session (others go to `runtime.log`). The frontend keeps a local parser fed by `attached` (restore) and `output`, sends keys as `input`, a paste as one `paste` (≤1 MiB, written whole as one local input: a remote lease is revoked once and nothing comes between its bytes) and resize (kept, not applied, while a remote lease holder owns the size; applied at `g`), and shows one status row (`Atem | Claude|Codex | Local|Remote | Astation ✓|✗[ | Notice] | <prefix> then ?:help`: `Remote` while a remote lease holder exists (`session` summary updates), Astation from `welcome`/`astation`, `Notice` once a runtime notice arrived; prefix-pending, help, history and 4 s feedback replace it). Prefix `h`/`m` detaches and prints `Session ses-… is still running. Reattach: atem agent attach ses-… · Stop: atem agent stop ses-…`; `x` stops (the final screen stays with `Exited (…)` until a key), `g` reclaims. When an agent that printed something ends, its worker writes `~/.config/atem/logs/<session_id>/session.ansi` (the last 1 MiB of output) and `summary.md` (`runtime/session_log.rs`; dirs 0700, files 0600, atomic; never the launch environment) and the attached frontend gets "… log saved to … | … Summary saved to …". It works without Astation. Over the authenticated Astation link, `{"type":"terminal","data":{"v":1,"op":...}}` messages (`subscribe`, `unsubscribe`, `ack` in; `attached`, `frame`, `exited`, `error` out) let a viewer see the canonical screen as base64 ANSI frames (16 KiB per frame, 128 KiB unacknowledged, bounded queues). Inside `atem runtime` these are bound to session-v1 (`binding`, and the lease for `input`/`resize`/`stop`, answered with `written`); bare `atem` has no link; `list`/`sessions`, `control`/`controller` and `lease_id` are removed (session-v1 `list` is the registry). Terminal ids are session ids only (no `claude`/`codex` aliases); in `atem runtime` sessions run in `atem worker`s and outlive the broker (a new broker adopts them). Local keys use the prefix Ctrl+] (`terminal_prefix` in config.toml or `ATEM_TERMINAL_PREFIX`, which wins, changes it; an invalid value falls back to Ctrl+] with a notice): `h`/`m` detach, `g` take control back, `x` stop, `r` redraw, `[` history, `c` copy, `?` help and recent notices. Background warnings go through `diagnostics` so they never write over the renderer. See `designs/protocol/atem-session-v1.md` (binding, leases), `designs/terminal-v1-implementation.md` (frames), `designs/agent-runtime.md` and `designs/local-agent-runtime.md`.

**Agent chat** (`src/chat/`, `runtime/worker_chat.rs`): chat-v1 lets Astation show a launched agent as a chat. Only Claude Code has an adapter. Before each Claude spawn the worker (`chat::claude::prepare_chat`) creates `chat-<uuid>/` (0700) under `$XDG_RUNTIME_DIR/atem` (else `~/.config/atem/run`) with `settings.json` (hooks for SessionStart, UserPromptSubmit, Pre/PostToolUse, Notification, Stop, each writing its stdin JSON to its own file in `events/`) and puts `--settings <file>` and, unless resuming, `--session-id <uuid>` before the user's arguments for that spawn only; each spawn is a new generation (UUID). It also writes a `pid` file (the worker's); `atem runtime` sweeps `chat-*` directories whose pid is dead (or, without one, older than an hour) when it starts. If preparing fails, Claude starts without chat. The worker reads the event files (lifecycle only) and the transcript JSONL named by SessionStart (all message content), feeds `ChatSession` (log items before a tick's `Stop`, so `complete` follows the content), times out unaccepted prompts (10 s, never resent), re-sends status to each conversation 15 s after it last got it, and sends the results to each open conversation with its own sequence (at most 8 per agent: a ninth closes the oldest). A SessionStart whose transcript isn't `<session_id>.jsonl` is ignored with a notice; compaction or a resume on the same transcript keeps the turn, while startup, `/clear` or another transcript resets to ready (the old transcript is read to its end first, one tick later). Resuming another session reads its existing content as history only (no `message`/`complete`) and sends open conversations `error` "the conversation was switched; reopen the chat" and `close`. A user entry starting with `[Request interrupted by user` ends the turn as interrupted (Esc, or deny at a permission prompt). Status: ready/working/waiting/unknown (the session-v1 descriptor's `activity`, and `STATUS` in `atem agent list`). No SessionStart within 15 s leaves chat unavailable with a notice (a late one still enables it); a transcript format change withdraws chat (open conversations get `error` and `close`); the terminal is unaffected either way. Remote chat-v1 is served by `atem runtime`'s session host: `open`/`close` and `submit` carry a session-v1 binding, `submit` the lease, and its `accepted`/`complete`/`error{code}` follow its receipt (`ChatSession::submit` applies: current generation, new `requestId`, clean prompt ≤ 32 768 bytes not starting with `/` or `!`, status ready, no draft; accepted when both the UserPromptSubmit hook and the transcript's user entry arrive). Prompts typed in the terminal appear as `origin: local` messages. Approval cards (see Approval hooks) appear as assistant messages `approval-<approval_id>` with one `approval` part, re-sent whole when their state changes, only in conversations of attachments with `control`; a chat `submit` carrying `approval` instead of `text` answers one. Outgoing text goes through the credential redactor. Conversations are handled only while `astation_connected` (not during re-authentication) and close on disconnect or re-authentication; a new `open` restores status and history (50 messages / 256 KiB, `before` pages). Claude exiting reports `unknown` and `error`, drops the adapter (removing its directory) and keeps history readable (500 messages / 8 MiB); a respawn sends the old conversations `error` "the agent was restarted; reopen the chat" and `close`. Codex has no chat adapter (activity `unknown`). See `designs/agent-chat-host.md`.

**Approval hooks** (`src/chat/approval_hook.sh`, `chat/approvals.rs`, `chat/codex/`, `runtime/worker_approvals.rs`, `runtime/host_bridge.rs`, `runtime/push_queue.rs`; contract §6a): agent permission prompts reach the worker through a `PermissionRequest` hook that writes `req-<id>.json` into the session's `approvals/` dir and waits for `dec-<id>.json` (claimed by renaming it to `taken-<id>.json`, then set aside as `claimed-<id>` once read, the claim time kept; the worker withdraws an unclaimed one the same way, so exactly one side gets it, and removes the files only once the hook process is gone). Claude gets it per launch in its `--settings` (600 s; its own dialog stays visible, first answer wins) unless `[claude] approvals_hook = false` in config.toml (default on, never asked; read when the worker starts: off leaves out the `PermissionRequest` hook and its `PostToolUse` note, the chat hooks stay); Codex gets one Atem-marked entry per hook event (`chat::codex::EVENTS`: SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, Stop, Interrupt; commands start with `: atem-approval-hook;`, all run the one script `~/.config/atem/hooks/approval-hook.sh`, the same command for every session, `ATEM_APPROVAL_DIR` set by the worker; outside Atem they exit at once) in `$CODEX_HOME/hooks.json`, appended after the user's entries (Codex trusts each handler by position plus hash, so theirs keep their trust; the PermissionRequest entry is byte for byte the earlier one: sync, 300 s), after `atem agent launch codex` asks once (`[codex] hooks` in config.toml, one answer for approvals and chat; until it is `true` a Codex worker writes no hook script and watches nothing). The other events are `async: true` (SessionEnd is always sync), 3 s, and only record their stdin as `events/ev-<seq>-<Event>.json` in the session directory (`approval_hook.sh event`: 10-digit monotonic seq under `events/seq.lock`, a symlink naming the holder's pid, taken over only when that pid is gone; published with `ln`, never overwriting a file, 0600, no output, exit 0 within ~2.5 s; readers take only `ev-*.json` and ignore `tmp.*`, `seq`, `seq.<pid>`, `seq.lock`). Install is idempotent: an equal entry stays, an older Atem entry is replaced in place, a missing one appended, extra Atem entries of an event dropped. The merge keeps every other byte, writes `hooks.json.atem-bak` first (empty when there was no file) and keeps the file's mode. Setting `[codex] hooks = false` removes every Atem-marked entry on the next `atem agent launch codex` (only groups made of marked hooks; anything unexpected is refused; a copy first as `hooks.json.atem-removed.<secs>`; read back and restored if it doesn't match; no file again when there was none before Atem and nothing else is left); `atem unpair` never touches hooks.json. A Codex hook counts only when the session's agent started it: directly (or through one shell) its Codex session becomes the pinned one, so `/new` keeps working; through a non-shell child it must be the pinned session; a request without a session id counts only when the hook's parent is the agent itself. The worker reports each request redacted (tool, the command's first line or the file path, Claude's own `permission_suggestions` as "always allow" rules); the broker opens it in `SessionHost` whoever holds the lease: `approval_request` goes to subscribed attachments with `control` (view-only ones get nothing), a chat-v1 card appears in their conversations, and `push_approval{approval_id, atem_device_id, session_id, tool, summary, expires_at}` goes to the relay as `{"type":"relay",…}` over the verified link (best effort: the latest state per approval is kept while the link is down, at most 64 entries; `push_resolved{approval_id, reason}` when it stops being pending). An answer is a `kind:"approval"` submission (allow once / always allow with an offered `rule_id` / deny with an optional message), under the current lease, or with `acquire: true` (no `lease_epoch`), which takes the lease (takeover allowed) only once the answer is durably accepted. The decision goes to the worker (`approval_decision`); `approval_applied` `ok`/`unknown`/`not_delivered` finishes the receipt `completed`/`outcome_unknown`/`rejected`, and one the agent never confirms is `outcome_unknown` after 630 s. A decision within 5 s of the hook's timeout is `not_delivered` (the hook might give up before taking it). Closes: `answered_remote`, `answered_terminal` (Claude: the tool ran, or its transcript shows the refusal), `interrupted`, `timed_out` (a hook that ended within 5 s of its timeout, our decision untaken or none), `released`, `process_ended`; lease changes never close one. Every write to a Codex session first sends `release_approvals` (Codex hides its prompt while a hook waits): the waiting hooks get "no decision", close `released`, and the worker holds that input until they exited (at most 500 ms). An adopted worker is told the approvals the new broker knows (none), so it releases the rest, without `push_resolved`: a phone notification may linger until its `expires_at`, and a tap gets `stale_target` (shown as already answered). Same-user processes that can see `ATEM_APPROVAL_DIR` can forge request files: the result is a fake card, never an agent action (same-user attackers are out of scope). Never an allow without a decision from Astation; any failure is "no decision". Codex can't take a persistent rule (`updatedPermissions` fails closed), so its cards offer allow once and deny only.

**Vault** (`vault_client.rs`): Client for the relay-hosted shared cross-agent context store. `atem vault new/list/read/write/set-summary` — a versioned, append-only store that multiple atems read/write to hand off context between their agents. Pure request builders + human/plain renderers + a thin reqwest executor (auth: `Authorization: session <id>` + `?id=<instance_id>`). The `/api/vault` endpoints + Postgres live in the relay-server (Astation repo). See `designs/vault.md`.

**Atem Memory** (`src/memory/`): `atem sync`, `atem memory …`, `atem skill …`. Agents learn from each other across agents and machines. Claude's saved memories are harvested (an edited file becomes a replacement, a deleted file an invalidation), Codex saves facts with `atem memory add --agent codex` and replaces outdated ones with `atem memory replace <id> "<new fact>"` (its block shows each fact's short id), and skills are versioned directories (`atem skill history`/`atem skill restore` read old versions from the relay). Facts are never edited in place: `memory replace`/`memory invalidate` keep the history (`valid_at`, `invalid_at`, `superseded_by`; see `memory list --history`), invalidation is final, and only valid facts are injected — a block that leaves facts out says how many and points to `atem memory search`, which is local FTS5 (trigram, BM25) over `knowledge.db`. Everything is synced through the relay (`/api/memory`, `/api/skills`, Astation pairing-session auth) with an offline SQLite store, then applied as a managed block in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and `<repo>/CLAUDE.local.md`, and as skills in `.claude/skills` and `.agents/skills`. Credential values are never stored: names only. Tracked files are never written. See `designs/atem-memory.md`.

**Key agent** (`src/memory/key_agent.rs`, `agent_socket.rs`, `unlock.rs`): this device's keys live sealed in `device_keys.sealed` under a storage key only the home Astation (the first one this device verified with) holds. The hidden `atem key-agent` (same binary, started on demand, detached; Unix socket, same-UID peers only, `"v": 2` JSON lines; `PR_SET_DUMPABLE=0` on Linux, and `mlockall` there when `RLIMIT_MEMLOCK` is unlimited or ≥ 512 MiB; one agent per key directory via a `flock` on `key_agent.lock`; an agent whose socket disappears, e.g. logind removing `$XDG_RUNTIME_DIR`, wipes its keys and exits within ~5 s) holds the unlocked keys; while it is locked, grants are ignored (`encryptionMode`/`keyGrant` arriving while atem waits for another reply are applied, not dropped, and after an unlock atem sends `keyRequest` if the signed state still needs `K`; an already unlocked `atem cred unlock` still connects while the signed state is `enabling`/`disabling`, to finish the migration and send the signed completion, since `atem sync` never talks to Astation). `atem cred unlock` asks it for a single-use key, sends an `unlockRequest` signed by `unlock_auth_key`, and hands Astation's Touch-ID-approved, signed `unlockGrant` straight back to the agent; the agent then rotates the storage key in three crash-safe phases (`.next` → `storageKeyAck` → promote, `.prev` kept until the next unlock → `storageKeyConfirm`), abandoning a stale pending key if needed. `atem pair` escrows the first storage key in the same run; until Astation is known to hold it, a fresh device keeps a plain `device_keys` file (like a step-1 device), which the agent re-seals at each start and deletes at the first confirmed escrow, so an agent that stops first loses nothing; `atem cred lock` wipes the agent and stops it (always allowed: the agent stops listening, removes its socket and `agent.socket`, gives requests in flight up to 1 s, clears its pid from `key_agent.lock` and exits; the CLI waits up to 2 s for it to go, and an agent from an older atem that only wipes is reported as still running until the next `atem cred unlock` replaces it); The key state is shown by `atem status` (see SSO auth). An `unlockDenied` with `revoked: true` (or "revoked" in its reason) is recorded in `cred_state.json` (`atem status` shows "revoked by <id>"; `atem pair verify` then refuses); `atem unpair` with the agent locked (or not running) renames the old key files to `<name>.revoked-<stamp>` and forgets that Astation's verification, home and escrow state, so the next `atem pair` verifies with new keys (the signal is unsigned: a forged one costs a re-pair, never keys or trust; verification itself never sets keys aside). Since step 2b `K` lives only in the agent: it installs granted keys into the sealed payload (`InstallGrant`; a payload with keys is `version: 2`, so a step-2a binary refuses it), does every seal/open/keyed hash for `EncryptionContext` in batched `Crypt` requests (no reply carries `K`), takes the mode and kid from the newest signed account state across every verified Astation naming the account (one helper, `verification::effective_state`, for install, `Crypt`, `account_mode` and `key_needed`), serializes key payloads into exactly sized wiped buffers, and moves a leftover `data_keys.enc` in at the first unlock (then deletes it, unless an entry of a verified account can't be parsed: then the valid keys move and the file stays; an unreadable one is renamed aside, never deleted); a locked agent keeps sync changes queued until `atem cred unlock`. A key agent left running from before the upgrade speaks protocol v1 and must be stopped (the error says how); a restart before the first escrow loses a post-2b `K`, which is requested again. After the upgrade a verified device needs `atem cred unlock` once. The status reply carries the agent's `build` (`key_agent::build_id`: version + the executable's mtime and size when the agent started, so every rebuild differs; absent from an older agent, which counts as older). A command that may start the agent compares it with its own once: a locked agent of another build is asked to stop (one too old for that gets SIGTERM, only when its pid is confirmed as this user's `atem key-agent` through `key_agent.lock`, else the error gives the `pgrep`/`pkill` lines) and this build's agent is started; it holds no keys, so nothing is lost. An unlocked one is never restarted: the command warns once ("The key agent was started by another atem build; run `atem cred lock`, then `atem cred unlock` to use this one.") and uses it, a request it rejects as unknown gets that hint instead of the raw error, and `atem status` adds `(started by another atem build; run atem cred lock, then atem cred unlock)` to its Credentials line (builds are compared for equality only: a dev build and the npm release of the same version differ, and neither counts as newer). The unlocked agent also signs what atem reports to Astation: `CredentialProjects` (the HPKE credential-project report plus optional original-case `labels`, `credential_projects.rs`; sent best effort after each authenticated connection, on `credentialProjectListRequest`, and by `atem cred projects`) and `MigrationComplete` (the `atem-migration-complete-v1` completion with its `K` possession proof, sent only after the read-back pass in `migration.rs` finds every protected field migrated). See `designs/e2e-encryption.md` "Keys on disk (atem)" and "Astation work for step 2a", and `docs/credential-project-reporting.md`.

**Agent binaries** (`claude_client.rs`, `codex_client.rs`): the binary and extra arguments a worker starts, from `CLAUDE_CLI_BIN`/`CLAUDE_CLI_ARGS` and `CODEX_CLI_BIN`/`CODEX_CLI_ARGS` in the launch environment (else the worker's own). The PTY itself is `pty_session.rs`, in the worker.

**RTM** (`rtm_client.rs`, `native/`, `build.rs`, feature `real_rtm`): the Agora RTM FFI wrapper and its C++ stub/real implementations are kept but unused: nothing in the App calls them (voice coding was removed). `build.rs` still compiles the stub (or links the SDK with `real_rtm`).

**Tests never touch the real profile** (`src/test_profile.rs`): under `cfg(test)` every function that resolves the profile (`~/.config/atem`), the runtime dir or the key agent asks `test_profile`, which panics unless the test injected a temp profile (`test_profile::use_dir`/`temp`) or a key agent (`use_agent`) on its thread (`blocking` carries them to worker threads). New tests must inject one. Binary tests (`tests/*.rs`) run `atem` with a temp `HOME` and `XDG_RUNTIME_DIR` and fake agents, and only signal processes they started. Debug builds read `ATEM_TEST_CLOCK_FILE`/`ATEM_TEST_PTY_FAULTS` (`runtime/test_hooks.rs`) for the fixture harness (a client never passes `ATEM_TEST_*` on to a runtime it starts); release builds don't.

**Webhook Server** (`webhook_server.rs`): Receives Agora webhook POSTs (ConvoAI events 101–111, 201–202; RTC NCS events) on a local HTTP port. Optionally spawns `ngrok http <port>` or `cloudflared tunnel --url <port>` to expose the listener publicly. Validates `Agora-Signature-V2` (HMAC-SHA256) against `secret` from `webhooks.toml` when configured, skips validation with a banner warning otherwise. Broadcasts each accepted event to a live web console (SSE) at `GET /` and prints a one-line summary to stdout. `--background` mode: standard daemon shape — registers in `~/.config/atem/servers/webhooks-<port>.json`, redirects stdout/stderr to `webhooks-<port>.log`, manageable via `atem serv list / kill / killall`. ngrok collision detection (refuses to start when a foreign ngrok already owns `:4040` and prints actionable next steps including the paid-plan link). cloudflared failure path captures stderr tail and surfaces it.

### Configuration & Storage (`config.rs`)

**Files in `~/.config/atem/`:**

| File | Contents | Encryption |
|------|----------|------------|
| `config.toml` | Non-sensitive settings (astation_ws, relay URL, bff_url, sso_url, `terminal_prefix` for the shared agent terminal; env `ATEM_TERMINAL_PREFIX` wins) + auto-generated identity (`instance_id`, `atem_id`) + `files_last_port` (last port `atem serv files` bound, reused next run) + `[memory] harvest_claude = false` (turns off harvesting Claude's native memory during `atem sync`) + `[codex] hooks` (Atem's hooks in `~/.codex/hooks.json`, one per Codex event, for approvals and chat: asked once, `false` removes them) + `[claude] approvals_hook = false` (Claude sessions launched afterwards get no approval hook; default on, never asked). Every write is a read-modify-write under an `flock` on `config.toml.lock` (`config::edit_config_file`), replacing the file atomically (temp + fsync + rename + directory fsync), so a reader — e.g. the runtime reading its identity while its Astation connect stores `instance_id`/`atem_id` — never sees half a file and concurrent writers never lose a key; a symlinked config.toml keeps its link (the target is replaced), the file keeps its mode (a new one is 0600) | None |
| `credentials.enc` | SSO + paired tokens (multi-entry `Vec<CredentialEntry>`) | AES-256-GCM (machine-bound) |
| `project_cache.enc` | All projects + `current_app_id` (selected project reference) | AES-256-GCM (machine-bound) |
| `sessions.json` | Per-Astation device session IDs and tokens | None (chmod 0600) |
| `pairing.json` | `{version, host_trust_gen, binding_id?, astation_id?, created_at?}`: the host trust generation (never decreases or repeats) and the current pairing binding (random id per `atem pair`; `atem unpair` commits the next generation without one before removing anything); a pairing from before the file is generation 1 (`legacy-<astation id>`), computed by readers and recorded by the first capture; writes hold an `flock` on `pairing.lock` | None (chmod 0600, written atomically) |
| `knowledge.db` | Atem Memory local store: memories (with `deleted_at`/`valid_at`/`invalid_at`/`superseded_by`), the `memories_fts` FTS5 trigram search index, skills, harvest map, local `replacements`, and the pending-sync queue (SQLite, mode 0600; holds no secrets — credentials are refused before storing; migrated in place on open) | None |
| `device_keys` | Plain device keys: a build-step-1 device's, or a freshly verified device's until its first escrow; the key agent seals them into `device_keys.sealed` at each start while this file exists, and deletes it once the home Astation is known to hold the storage key | None (chmod 0600, written atomically) |
| `device_keys.sealed` | This device's X25519 device key, Ed25519 signing key and account keys (`K` + previous, step 2b) (`{version, device_id, storage_kid, nonce, ciphertext}`); `device_keys.sealed.next` exists only mid-rotation, `device_keys.sealed.prev` (the replaced file) until an unlock proves Astation holds the current key | XChaCha20-Poly1305 under the storage key (held only by the home Astation, replaced at every unlock) |
| `unlock_auth_key` | Ed25519 key that signs unlock requests | None (chmod 0600; it can only ask Astation) |
| `cred_state.json` | Verified Astation pins (signing, encryption, recovery keys), safety code, epoch floor, latest signed account state, `home_astation` (holds the storage key), `escrowed_storage_kid` (last storage kid Astation is known to hold), `abandoned_kids` (never reused), `escrow_unanswered` (the home Astation never answered the first escrow, e.g. no step-2a support); every read-modify-write holds an `flock` on `cred_state.lock` | None (chmod 0600; no secrets) |
| `project_names.json` | `h1.` project hash → readable project key, per account (memory/skills project names the relay sees only as HMACs), plus optional original-case `labels` per account (used in credential-project reports); replaces the names part of the removed `data_keys.enc` (`data_keys.enc` is moved in and deleted by the key agent at the first unlock; an unreadable one is renamed `data_keys.enc.corrupt-<stamp>`); writes hold an `flock` on `project_names.lock` (taken after the `cred_state.lock`) | None (chmod 0600; no secrets) |
| `key-agent.log` | Output of the detached `atem key-agent` | None |
| `runtime.lock`, `runtime.socket`, `runtime.log` | One `atem runtime` per config dir: exclusive `flock` + pid; the socket path clients try first; its output | None (chmod 0600) |
| `runtime/workers/` | Per session: `<id>.spec.json` (launch spec), `<id>.json` (worker record: session id, process generation, worker/agent pids and OS start times, exit), `<id>.lock`, `<id>.log` (worker output; both removed with the record when the worker is released, or when `atem agent stop` removes a session without a worker), and the worker socket when `$XDG_RUNTIME_DIR` is unusable (else `$XDG_RUNTIME_DIR/atem/workers/<id>.sock`) | None (dir 0700, files 0600) |
| `runtime/journal/` | The session host's `FileJournal`: `receipts/` (per-session receipt logs), the lease-epoch floors file, `journal.lock`, `runtime_epoch` (incremented each runtime start) | None (dir 0700, files 0600; no prompt payloads after a request leaves `accepted`) |
| `logs/<session_id>/` | `session.ansi` (last 1 MiB of an agent's output) and `summary.md`, written by its worker when an agent that printed something ends | None (dirs 0700, files 0600) |
| `agent.sock`, `agent.lock` | Key-agent socket and its per-socket lock, here only when `$XDG_RUNTIME_DIR` is unset (else `$XDG_RUNTIME_DIR/atem/`, next to `runtime.sock`, `workers/` and Claude's `chat-*` dirs); directory 0700, socket 0600, same-UID peers only | — |
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
- `atem logout` — removes the `sso` entry from `credentials.enc`, then tells a running runtime to `reload`
- `atem status` (tier 0, `src/status.rs`; the only status command) — read-only and offline: `Account` (signed in / signed in (expired) / signed out), `Pairing` (`paired (<astation id>)` — the one `require_pairing` resolves, else the first paired one, `(+N more)` for others; `paired (<id>, session expired)` when its saved session expired; `paired (no Astation id)`; or `not paired`), `Verification` (`verified (safety code …)` / `not verified` / `revoked by <id>` only when that is the paired Astation / `—`), `Credentials` (`unlocked` / `locked` / `not set up` / `broken (<problem>)` with `key_agent::RESET` printed after the block; plus `(storage key not yet held by Astation; run atem cred unlock)` for an unlocked, unescrowed agent and `(started by another atem build; run atem cred lock, then atem cred unlock)` for another build's agent; asks only an already running key agent, never starts one; no agent = locked), `Authorization` and `Relay` `unknown (stale)`, `Local agents` `unknown`. Never connects, never writes. "Paired" = any paired credential entry or valid saved Astation session in `sessions.json`. A paired profile whose session expired or was refused gets `The saved Astation session expired or was refused. Run `atem unpair`, then `atem pair`.` instead of "run `atem pair`" (pairing gate, memory sync/history, TUI re-authentication, connect errors, `pair verify`)
- `atem pair [--save]` — on an already paired profile (even unverified or revoked) prints the status plus `Already paired. Verify this device: atem pair verify · Replace the pairing: atem unpair, then atem pair` and exits 0 without connecting or changing anything. Otherwise, inside `atem runtime` on its link: send `PairSavePreference`, wait for `CredentialSync`, write paired entry, then verify the device: commit-then-reveal (`verifyCommit` → `verifyKeys` → `verifyReveal`), both sides show a 12-character safety code, the user answers `codes match? [y/N]` (read from `/dev/tty`, flushed first, never stdin; no terminal fails the verification) and confirms on Astation with Touch ID, and atem applies the signed `deviceVerified` atomically (pins, device keys, signed state, grants; nothing on failure). If `K` is needed but missing it sends `keyRequest`. Astations that don't answer within 15s leave the device as it was (see `designs/e2e-encryption.md`). Any later failure (code refused, no terminal, 300 s Touch ID timeout, lost connection, apply error) drops the pending pin and sends `verifyAbort` with delivery confirmed (not when Astation itself aborted); the pairing stays saved and `atem pair` exits nonzero (`atem pair verify` retries). A failed `keyRequest` after success is only a warning (`atem cred unlock` asks again). Logic and tests: `src/pair_verify.rs`. On the home Astation's first verification the fresh keys are sealed and the first storage key is escrowed (`storageKeyRotate` with an empty old kid, then confirmed) in the same run
- `atem pair verify` — needs a pairing (`Not paired. Run atem pair first.`, exit 1; a paired entry without an Astation id: `The saved pairing has no Astation id. Run `atem unpair`, then `atem pair`.`); already verified with the paired Astation → `Already verified (safety code …).`, no connection; revoked → `This device was revoked by Astation <id>. Run atem unpair, then atem pair, to set it up again.`, exit 1, nothing moved. Otherwise runs the same verification as `atem pair` (`run_device_verification`) inside `atem runtime`, on its link authenticated with the saved session (never pairing; see "Astation operations through the runtime"). A cancelled or failed verification keeps the pairing
- `atem cred projects|unlock|lock` (tier 2; the key state is shown by `atem status`) — send the current Git project and the account's remembered project names to the home Astation's credential picker (keys must be unlocked; runs in `atem runtime`, waiting up to 15 s for its link; see `docs/credential-project-reporting.md`); Touch ID unlock through the home Astation, also in the runtime (waits up to 300 s, then rotates the storage key; when already unlocked it still finishes a pending migration; an unverified device stops offline with `This device isn't verified. Run atem pair verify first.`, and it never starts pairing or verification); wipe the unlocked keys and stop the agent. `atem key-agent` is the hidden agent process itself
- Host trust generation (`pairing_binding.rs`): asynchronous Astation work (connect and re-authentication, `atem pair`/`pair verify`, `atem cred unlock` rotation/escrow, credential-project reports, `credentialSync`, `encryptionMode`/`keyGrant`) captures `pairing.json`'s state and the saved session its proof used when it starts (`AstationClient::capture`), and applies a reply only while both are unchanged, under `pairing.lock` (`Captured::apply`; key-agent requests through `BoundAgent`). A reply that arrives after `atem unpair` or a new `atem pair` is dropped (`pairing_binding::CHANGED`): no session refresh, no relay code, no credentials, pins, grants or storage-key promotion. Encryption messages on a connection without a binding yet are held. `atem status` shows `paired (<id>, trust gen N)`
- `atem unpair [--yes]` — first commits the next host trust generation (no binding), then removes all paired credential entries and saved Astation sessions (the SSO login, memory, vault data, trust pins and keys stay), and set revoked keys aside (see Key agent); a failure to set them aside, or a revocation left recorded (agent unlocked, or not the home Astation), is printed as a notice and the unpair still completes. It, `atem memory purge` and `atem skill purge` confirm first (`cli::confirm_destructive`): `--yes` skips the question, and without a terminal they refuse unless `--yes` is given. The purge prompts show the id and scope only, never the content, since a purged item may hold a credential. Unpair then tells a running runtime to `reload`, which drops the link of the removed pairing and its attachments
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
An unverified pairing shows `Verified: no  (run 'atem pair verify' to verify this device)`.

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
| 0 | — | status, serv files, config, token with AGORA_APP_ID/CERT env, `project use <index>`, `project show` (local cache) |
| 1 | `atem login` | `project list`, `project use <app-id>`, token (active project), serv rtc/convo/webhooks |
| 2 | paired with Astation (verified, for remote sessions) | vault, sync, memory, skill, cred, and Astation-driven terminal viewing and control, chat and mark tasks |

Gates are centralized in `src/auth.rs`: `require_login(feature)` is the tier-1
gate (passes when `CredentialStore::load().entries` is non-empty);
`require_pairing(feature)` is the tier-2 gate (resolves a `PairedSession` —
relay base, Astation id, session id — from `AtemConfig` + `SessionManager`,
purely local, no network). Both return an actionable `anyhow::Error` built
from `login_gate_message`/`pairing_gate_message` when the check fails.

New cross-machine or cross-agent features are tier 2 and must gate with
`auth::require_pairing`.

### Feature Flags

| Flag | Description |
|------|-------------|
| `real_rtm` | Link `native/src/atem_rtm_real.cpp` against the Agora RTM SDK (default: the stub). RTM is kept but unused |
| `openssl-vendored` | Build OpenSSL from source (used in CI for cross-compilation) |

## Key Dependencies

| Category | Crate | Purpose |
|----------|-------|---------|
| CLI | clap (derive) | Command parsing |
| Async | tokio (full) | Runtime, channels, tasks |
| TUI | ratatui, crossterm | Terminal UI rendering |
| Network | reqwest, tokio-tungstenite | HTTP, WebSocket |
| PTY | portable-pty, vt100, vte | Terminal emulation |
| FFI | libc, cc | Unix process and terminal calls; `cc` builds the (unused) RTM C++ in `build.rs` |
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
atem runtime receives assignment on its link (websocket_client.rs)
  ↓ handle_astation_message() in app.rs
  ↓ the live broker Claude session whose cwd holds .chisel/tasks/{taskId}.json (none: fails)
  ↓ load_and_build_work_item(): reads the task JSON from LOCAL disk
  ↓ build_mark_task_prompt() → annotations + screenshot + source files
  ↓ dispatcher.submit() → main queue (or background `claude -p` via triage)
  ↓ try_dispatch_main(): waits while a remote lease holder exists, then the
    broker writes the prompt through the session's worker (local-origin input)
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

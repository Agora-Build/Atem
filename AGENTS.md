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

Supported platforms (README "Supported platforms", from the v0.8.0 release binaries): macOS 11+ on Apple silicon and 10.12+ on Intel (Rust's default deployment targets; the macOS 15 CI runners only change the SDK), Linux x86_64 with glibc 2.38+ (its GLIBC_2.39 need is weak) and arm64 with glibc 2.39+ (cross-linked, a hard need), both built on `ubuntu-latest` (Ubuntu 24.04), no Windows (only `atem-core` builds there). Agent hooks verified with Claude Code 2.1.302 and Codex CLI 0.163.0. Re-check after a toolchain or runner change: the Mach-O `LC_BUILD_VERSION` minos of the darwin binaries and the highest non-weak `GLIBC_` version the Linux binaries need (`readelf -V`: a `Flags: WEAK` entry doesn't count).

## Development Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo run                                # Run TUI application
cargo run -- [command]                   # Run with CLI arguments
cargo test                               # Run tests (1,450+; use -- --test-threads=1 if a test flakes); tests must inject a temp profile (src/test_profile.rs)
cargo test --test runtime_fixtures_binary # Shared atem-session host fixtures against the real runtime (ATEM_FIXTURE=<name> runs one)
cargo test --test host_work_binary -- --test-threads=1 # Opt-in remote launch + directed work over encrypted r9 channels (temp profiles/fake agents)
cargo test --test collab_binary          # Local agent collaboration: real runtime/workers, fake agent children, temp profiles
ATEM_REAL_AGENTS=1 cargo test --test approvals_real_agents -- --ignored --nocapture --test-threads=1 # Approvals with the REAL claude/codex CLIs (real API calls; export only the needed variables, e.g. OSS_API_KEY / ANTHROPIC_AUTH_TOKEN, never a whole credentials file; each agent gets only its own; Codex runs --profile oss)
cargo test -p atem-core -p atem-core-ffi # Token library + C ABI tests (workspace members)
cargo build --release && cargo test --release --bin atem perf_ -- --ignored --nocapture --test-threads=1 # Encrypted-path performance (src/memory/perf_tests.rs; prints numbers to compare with the budgets in designs/e2e-encryption.md "Performance"; perf_2c waits for a quiet host)
./scripts/check-atem-core-ffi.sh         # Build libatem_core_ffi.a, drive it from C (and Swift on macOS)
cargo test -p atem-client -p atem-client-ffi # r9 client core + bindings: vectors, r9 client/relay fixtures, channel and end-to-end tests
./scripts/check-atem-client-bindings.sh [kotlin] [wasm] [swift] [e2e] # binding conformance over the r9 vectors (toolchains from env: KOTLINC, JNA_JAR, WASM_BINDGEN)
./scripts/package-atem-client-bindings.sh <ver> <out> [wasm] [kotlin] [android] # binding packages + SHA256SUMS + SOURCE.json (android: ANDROID_NDK_HOME); check-atem-client-packages.sh checks them; Apple: package-atem-client-apple.sh
cargo test --test runtime_fixtures_binary r9_fixtures -- --nocapture # r9 host scenarios against the real runtime (ATEM_FIXTURE=<name>[,…], ATEM_R9_PARALLEL)
cargo test --test r9_harness -- --nocapture # headless multi-device harness: one real host, phones/bots/browsers through atem-client (ATEM_HARNESS_PHONES/BOTS/BROWSERS, ATEM_HARNESS_OUT)
./scripts/package-atem-r9-harness.sh <ver> <out> # the harness prebuilt for Astation (NON-PRODUCTION: test binary + atem + fake agent + run script, sample transcript, SHA256SUMS, SOURCE.json); CI artifact of `.github/workflows/r9-harness.yml`
cargo check                              # Type-check without building
rustfmt --edition 2024 <file>            # Format the files you touch; not project-wide: app.rs, main.rs, cli.rs, websocket_client.rs and memory/{mod,crypto,secrets}.rs aren't rustfmt-clean
cargo clippy --all-targets --all-features  # Lint
./scripts/run-local-dev-tests.sh         # End-to-end CLI smoke test (build first)
./scripts/release.sh [VERSION]           # Bump Cargo.toml + commit + tag (no push)
```

## Architecture

### Source Structure

The repo is a Cargo workspace: the `atem` binary at the root plus four library crates.

```
crates/
├── atem-core/           # Agora AccessToken2 (RTC/RTM) build/decode/verify, built for Astation to share (integration is a follow-up); no I/O, no state
│   └── tests/upstream_compat.rs  # must equal Agora's own agora_token crate (pinned git rev)
├── atem-core-ffi/       # versioned C ABI (ABI 1) over atem-core: include/atem_core.h, module.modulemap, tests/c, tests/swift
├── atem-client/         # atem-session r9 shared client core, sans-I/O (keys behind KeyProvider): encodings/signing, membership-log verifier, atem-ch1 (both roles), r9 hello/welcome + r8 session-v1 machines (session/, re-exported by atem), principals, service member builders (membership/service.rs) and the `projects` scope hash (project.rs), push hints/seen, Recovery Kit, K backups, restore, the prompt framing (session/framing.rs, delegated host-work design III.2: tags, counted blocks, escaping on Unicode 18.0.0 folding, the worst-case size check); tests run every r9 vector, the framing vectors and client/relay fixtures
└── atem-client-ffi/     # its bindings: UniFFI (Swift, Kotlin/JNA) and wasm-bindgen (feature `wasm`); `host`, `software-keys`, `test-vectors` never in shipped packages; bindings/{swift,kotlin,js} conformance; contract designs/protocol/atem-client-bindings.md
src/
├── main.rs              # Entry point, CLI parsing (clap)
├── app.rs               # Menu TUI state (bare `atem`, no Astation connection); inside `atem runtime`: the Astation link, auth, credentialSync; executable messages use the broker queue
├── app/reauth.rs        # re-authentication when Astation sends auth_required over an open socket
├── app/hosted.rs        # the App inside `atem runtime`: session-family messages for the broker's host (bare `atem` opens no Astation connection)
├── app/op_route.rs      # a running Astation operation's handshake replies go to it only (dropped once it ended)
├── app/relay_only.rs    # relay only (§R9.8a): the connect loop's local check, the local link drop after a committed result
├── app/station_route.rs # the selected Station (designs/protocol/station-route-v1.md): the stationRoute exchange and the transport switch inside `atem runtime`
├── runtime/             # `atem runtime` (the broker) and `atem worker` — see "Runtime" below
│   ├── mod.rs           #   run_runtime: one per config dir (runtime.lock), socket, state dir `<config>/runtime`
│   ├── server.rs        #   local protocol server: frontends, launch/attach/input/paste/resize/reclaim/list/stop/reload, Astation operations, the 16 ms pass
│   ├── protocol.rs      #   local protocol v1 (JSON lines over the same-user socket)
│   ├── client.rs        #   RuntimeClient: find the runtime or start it detached; hello/welcome; replace a runtime of another build (`replace_other_build`); `atem runtime start|restart`; the passive `look` (`status`)
│   ├── commands.rs      #   `atem agent launch|attach|list|stop` as runtime clients
│   ├── broker.rs        #   BrokerSession per session: worker connection, screen mirror, chat state, activity, input epoch, exit
│   ├── adopt.rs         #   spawn workers; adopt survivors (session id + process generation + OS start time), else interrupted/recovery_required
│   ├── worker.rs        #   `atem worker` (hidden): agent PTY, canonical screen, chat adapter, fenced writes, record/spec/socket, session log
│   ├── worker_protocol.rs # broker ↔ worker JSON lines (start, hello, write/paste with input epoch, set_input_epoch, resize, stop, output, screen, chat, activity, exited)
│   ├── worker_chat.rs   #   the worker's bounded chat backlog (cut into `chat` messages; `gap` when items were dropped)
│   ├── worker_approvals.rs # the worker's side of approvals: hook files, decisions, who answered (terminal or Astation)
│   ├── push_queue.rs    #   push_approval/push_resolved for the relay: latest state while the link is down, bounded
│   ├── session_log.rs   #   session.ansi + summary.md under `<config>/logs/<session_id>/`
│   ├── host_bridge.rs   #   atem-session host in the broker: SessionHost + FileJournal over the workers (attachments, leases, receipts, approvals, terminal-v1 frames, chat-v1 and its r8 history, receipt results)
│   ├── host_work.rs     #   opt-in private runtime.toml profiles/routes (no `principals`: the paired Astation's `member:<id>`; errors name the field/line or the profile and rule; `runtime check` lists who may launch), environment sources, durable launch/task/attachment SQLite records (kept for good; only payloads are dropped a day after a settled record's deadline)
│   ├── host_attachments.rs # PNG chunk persistence, sender binding, verified private cache for task prompts
│   ├── host_work_bridge.rs # host launch/query and directed-work scheduling over normal receipts; config/authority rechecks (a changed authority or route approval fails the task), no takeover, explicit results
│   ├── collab.rs        #   local selectors, fixed resolutions, durable outbox/message counters/scoped status; collab_results.rs stores narrow return grants and one reply per task (`reply_query` reads it)
│   ├── collab_context.rs #  publish/read-back exact Memory/Vault snapshots before delivery (background jobs with durable retries)
│   ├── collab_bridge.rs #   internal attachment, sending/replying/completing, workflow inheritance, pauses, correlated results, return grants that end early (the task goes on; the reply is kept, not delivered) and automatic status reports
│   ├── collab_launch_bridge.rs # local launch-on-message: reserve identities atomically, reuse approved worker launches, never retry uncertain spawns
│   ├── refusal_log.rs   #   runtime.log lines for refused session-family requests (no content; rate-limited per link)
│   ├── ops.rs           #   Astation operations on the broker's link: pair, pair verify, cred unlock/projects, paired-token refresh
│   ├── op_client.rs     #   the CLI side of an operation: print/ask/answer/done (answers from /dev/tty)
│   ├── project_scope.rs #   r9 service `projects` scopes: keyed hashes of each session's launch project key from the cred agent, cached; pending = out of scope
│   ├── test_hooks.rs    #   debug builds only: the fixture clock and PTY write faults (ATEM_TEST_CLOCK_FILE, ATEM_TEST_PTY_FAULTS), r9: host clock, membership faults/carriage, state dump, project hashes (ATEM_TEST_HOST_CLOCK, _MEMBERSHIP_FAULTS, _STATE_DUMP, _PROJECT_HASHES, _NO_INIT_LIMIT); `<ATEM_TEST_PTY_FAULTS dir>/hold_dispatch` and `hold_launches` keep accepted work queued and reserved launches unstarted
│   └── *_tests.rs       #   (test-only) server, ops, adoption, broker and host bridge (in-process workers, fake Astation peer)
├── session_protocol/    # atem-session v1 (r8; r9 host side), transport-independent (designs/protocol/atem-session-v1.md)
│   ├── revision.rs      #   re-exports atem_client::session::revision: r8 revision (8), the nine feature names, FEATURES, R8_FIXTURE_NEEDS, R9_NOT_RUN
│   ├── wire.rs          #   re-exports atem_client::session::wire: strict decode/encode of session-v1 and bound terminal/agentChat messages
│   ├── canonical.rs     #   canonical JSON and payload digests
│   ├── host.rs          #   SessionHost: revision admission, attachments, registry, leases, input epochs, receipts and results, chat Send acquire, lease-free approvals, principals and the control fence, journal halt and restart recovery → effects
│   ├── journal.rs       #   Journal trait, receipt records (principal, control_gen, turn ids), control states, refusals, the in-memory journal
│   ├── file_journal.rs  #   FileJournal: per-session receipt logs, fsync per transition, lease-epoch floors, principals, refusal list, clean close, compaction
│   ├── client.rs        #   re-exports atem_client::session::client: client machines (LeaseClient, RegistryClient, admission, ChatClient)
│   ├── membership/      #   r9 device list (§R9.2–§R9.5): MembershipHost (carriage durable before evaluation, commit/freeze/fault/held, pending recoveries on the host clock, replay at start, fences through §H), pairing.rs (the list pinned at pairing), store.rs (membership.* files)
│   ├── r9/              #   r9 admission (§R9.6–§R9.8): R9Host, the atem-ch1 responder per channel, carry before admission, principals/scope/expiry, welcome, fences; envelope.rs (§R9.7a channel envelope, bounds); push.rs (sealed push hints and seen, §R9.9); host_policy.rs (relay only, §R9.8a: the stored policy, set/get, roll-forward)
│   ├── fake_runtime.rs  #   (test-only) the host fixtures' harness around SessionHost (chat through chat::history)
│   ├── fixtures.rs      #   (test-only) runner for designs/protocol/fixtures/*.json
│   └── *_tests.rs       #   (test-only) host_tests, approval_tests, file_journal_tests, persistence_tests (§H/§I: faults, halts, refusal list, clean close, recovery order)
├── session.rs           # session ids (`ses-` + 12 base32), providers, launch environment bounds, the frontend output tap
├── daemon.rs            # detached-daemon plumbing (cred agent, runtime): private socket dirs, peer checks, pid locks, detached spawn
├── test_profile.rs      # cfg(test) guard: resolving the real profile, runtime dir or cred agent panics unless the test injected a temp one
├── chat/                # Agent chat (chat-v1), agent-neutral except the adapters
│   ├── adapter.rs       #   AgentAdapter trait, AgentEvent, LogItem, Capabilities, LaunchPlan
│   ├── session.rs       #   per-agent chat state: status, history, draft check, submit/acceptance, request ids
│   ├── wire.rs          #   agentChat v1 envelopes to and from Astation
│   ├── history.rs       #   r8 history: Conversations (ordered streams, ≤ 8), bounded pages + history_end, lookups, HMAC'd `next` tokens, coverage/holes, a turn's reply ids (history_tests.rs)
│   ├── claude/          #   Claude Code adapter: hooks.rs (chat dir, settings.json, event files), transcript.rs (session JSONL)
│   ├── codex/           #   Codex: mod.rs (hooks.json merge/removal, one entry per event, [codex] hooks), adapter.rs (CodexAdapter, EventReader: ev-<seq>-<Event>.json), rollout.rs (RolloutReader over the rollout JSONL); tests.rs, adapter_tests.rs
│   ├── approvals.rs     #   approval settings, HookAgent/started_by ownership shared by approvals and the Codex adapter
│   └── approval_hook.sh #   the one hook script (Claude, `post`, `codex`, `event <Event>` modes)
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
├── sso_auth.rs          # OAuth 2.0 + PKCE login flow, token refresh; `valid_token` (which login's Agora tokens)
├── credentials.rs       # `Login` behaviour (`agora_tokens`, issuer allowlist, load/save login.enc)
├── records.rs           # the stored types (`Login`, `Tokens`, `PairingRecord`, `SavedSession`, `BindingRecord`); serde only, included by tests/support
├── machine_key.rs       # machine-bound AES-256-GCM, each file's purpose as associated data (login.enc, pairing.enc, project_cache.enc); included by tests/support
├── paths.rs             # `ProfilePaths`/`PairingPaths`/`CredPaths`: the one definition of the profile's layout (std only, included by tests/support)
├── profile.rs           # `Sources` (a profile: config + paths + which running processes to ask) and this user's default paths
├── agora_api.rs         # BFF API client (BffProject, fetch_projects with Bearer auth)
├── auth.rs              # tier gates (`require_login`, `require_pairing`), OTP, hostname
├── config.rs            # Config, SSO/BFF URL helpers, active project, project cache
├── time_sync.rs         # HTTP Date-based time synchronization
├── webhook_server.rs    # atem serv webhooks — Agora webhook receiver +
                          # ngrok/cloudflared tunnel integration + SSE console
├── rtc_test_server.rs   # Browser-based RTC test page server
├── files_server.rs      # atem serv files — static file server (Markdown rendered)
├── convo_config.rs      # ConvoAI TOML parsing + Agora REST /join body builder
├── convo_test_server.rs # atem serv convo — ConvoAI test server + --background mode
├── convo_wizard.rs      # atem config convo — interactive config wizard + validation
├── web_server/          # Shared HTTPS scaffolding (cert, request, /api/token, net, html, browser open, access: the access code every `atem serv` page and API needs)
├── pair_verify.rs       # atem pair / atem pair verify device verification: /dev/tty code confirmation, verifyAbort on failure
├── status.rs            # atem status: read-only (local files + passive looks at the running runtime and cred agent); also decides pair (no-op when paired), pair verify and the cred unlock gate
├── version.rs           # atem --version: this build and protocols, then the running runtime, cred agent and workers (same passive looks)
├── pairing_wire.rs      # the token-free pairing bootstrap's strict reader (4096-byte bound, exact v1 shapes)
├── pairing.rs           # the one pairing (`pairing/pairing.enc`: Astation id, binding, session, shared login, save/grace) + host trust generation (`pairing/trust_gen`); Captured (async Astation work applies replies only under the pairing it started under), BoundAgent
├── station_route.rs     # the stored Station selection (`pairing/station_route.json`; wins over ASTATION_RELAY_URL/astation_relay_url)
├── vault_client.rs      # atem vault CLI client (relay /api/vault: request builders, renderers, executor)
├── memory/              # Atem Memory: shared memory + skills across agents and machines
│   ├── model.rs         #   Memory/Skill types, hashing
│   ├── secrets.rs       #   credential-value detector (fail-closed)
│   ├── project.rs       #   project key = normalized git remote
│   ├── block.rs         #   managed <!-- atem:memory --> block
│   ├── gitguard.rs      #   never write tracked files; .git/info/exclude
│   ├── harvest.rs       #   read Claude Code's auto-memory
│   ├── skills_fs.rs     #   skill dirs, .atem-skill marker, drift
│   ├── store.rs         #   local SQLite (~/.config/atem/knowledge.db) + queue + held skill versions (`held_skills`)
│   ├── adapters.rs      #   Claude/Codex targets + apply report
│   ├── api.rs           #   relay /api/memory, /api/skills client
│   ├── skill_wire.rs    #   skill file transport (F8, #130; Astation PR #76 at 89a2d50): a sealed file as its e1 text (`e1-text`, "" an empty file), plain as `base64`; strict reader/writer
│   ├── sync.rs          #   harvest → push → pull → apply; a skill push's `version_conflict` checked (own write acked, a concurrent edit coalesced into one push and held back for the sync), unpushed skill edits win locally, a skill row that doesn't open held (a key not held stops)
│   ├── sync_pipeline_tests.rs # (test-only) ops sealed ahead in full Crypt groups, page prefetch: requests per phase, rewrites after sealing, failures, crashes, commit order
│   ├── encoding.rs      #   length-prefixed fields for signed/bound inputs, base32
│   ├── statements.rs    #   Astation-signed statements (P-256 verify)
│   ├── device_keys.rs   #   device X25519 + Ed25519 signing + unlock-auth keys
│   ├── verification.rs  #   commit-then-reveal safety code; apply signed state/grants
│   ├── trust.rs         #   cred/state.json: pinned Astation keys, epochs
│   ├── grant.rs         #   signed RFC 9180 HPKE key grants
│   ├── account_keys.rs  #   K per account (current + previous) in the agent; e1./h1. field ops (Crypt)
│   ├── project_names.rs #   project_names.json: h1. project hash → project key (+ original-case labels)
│   ├── credential_projects.rs # signed HPKE Git-project reports for Astation's credential picker (atem cred projects)
│   ├── crypto.rs        #   EncryptionContext: mode from the signed state, batched Crypt via the agent; private writes
│   ├── storage_key.rs   #   storage key + device_keys.sealed (XChaCha20-Poly1305); unlock-grant/ack checks
│   ├── cred_agent.rs     #   cred agent state: unlock, rotation, abandon, K installed and used in memory (Crypt)
│   ├── agent_socket.rs  #   `atem cred-agent` Unix socket server + client (v2 JSON lines, same UID only; one client and connection per process, `shared`)
│   ├── agent_frame.rs   #   binary `Crypt` frames (raw field bytes, bounds before allocation), agreed per connection in the build check's `status`
│   ├── agent_client_tests.rs # (test-only) the client's kept connection: one per process, build check per connection, which requests go again
│   ├── agent_frame_tests.rs # (test-only) frames: agreement and JSON-line fallback both ways, limits, malformed frames, wipes, same refusals
│   ├── unlock.rs        #   `atem cred projects|unlock|lock`; unlock/rotation carried over the Astation link
│   ├── migration.rs     #   migration read-back check + atem-migration-complete-v1 proof input
│   ├── fake_astation.rs #   (test-only) Astation's side of unlock and rotation, mirrors the design doc
│   ├── kat_tests.rs     #   (test-only) known-answer vectors listed in designs/e2e-encryption.md
│   ├── k_agent_tests.rs #   (test-only) K in the cred agent: install, Crypt, rotation
│   ├── e2e_tests.rs     #   (test-only) encrypted sync/vault end to end, migration and its signed completion
│   ├── fake_station_skills.rs # (test-only) the Station's skill file transport, as fake relays serve it (vectors: designs/protocol/fixtures/skills-wire/)
│   ├── perf_tests.rs    #   (test-only, all #[ignore]) the encrypted path's performance (designs/e2e-encryption.md "Performance"): prints numbers, asserts no budget
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
├── runtime_fixtures_binary.rs # the shared atem-session host fixtures (r8 and, through r9_runner/, every r9 host scenario) against the real runtime, workers and a fake Astation
├── r9_harness.rs        # headless multi-device harness (test target only): one real host, simulated phones/bots/browsers through atem-client
├── r9_admission_binary.rs, r9_multi_device_binary.rs, r9_push_binary.rs, r9_services_binary.rs, r9_two_hosts_binary.rs, r9_revoked_binary.rs, r9_host_route_binary.rs, membership_binary.rs # r9 in the real runtime: admission/fences, several devices, sealed push/seen, two enrolled hosts freezing on a forked list, the revoked grants quarantine across restarts and a clock set back between two damages, the host route proof with no Astation online, services (approvals, scope restrictions, live renewal/narrowing, K rotation, held host, revoke_grant), the device list's durability and faults
├── approvals_real_agents.rs # #[ignore], ATEM_REAL_AGENTS=1: approvals answered from a fake Astation with the real Claude Code and Codex in temp HOME/CODEX_HOME
├── collab_binary.rs      # local tags, fan-out, fixed resolution, limits, context, replies and completion, pauses, departed senders, interrupted/expired tasks and launch-on-message through real agent-child commands
├── runtime_binary.rs, worker_binary.rs, agent_launch_binary.rs, terminal_ui_binary.rs, astation_op_binary.rs, cred_agent_binary.rs, runtime_build_binary.rs
└── support/             # Sandbox: temp profile, `atem` in a PTY, cleanup of what it started; astation.rs: fake Astation peer + verified pairing profile; r9.rs/r9log.rs: a pinned, signed test device list and r9 clients
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
├── check-atem-client-bindings.sh, package-atem-client-bindings.sh, package-atem-client-apple.sh, check-atem-client-packages.sh, atem-client-source-pin.sh # atem-client bindings: conformance, packages (WASM, Kotlin/JVM, Android, SwiftPM), their check, the source pin
├── package-atem-r9-harness.sh # NON-PRODUCTION: the r9 harness prebuilt (Linux x86_64) with atem, the fake agent, a run script and a sample transcript
├── update-convoai-toolkit.sh # Refresh vendored assets/convo/ (pinned upstream commit; deps from scripts/convoai-toolkit/package-lock.json, esbuild pinned; UPDATE_LOCK=1 re-resolves)
└── test-create-agent.sh # ConvoAI agent creation (requires env vars)
designs/                      # Design only: current design and planned work (README.md is the index); implementation plans and handoffs are in git history
├── README.md                 # Index: current design, planned work
├── protocol/                 # README.md (the protocols and how atem-session evolved, where the fixtures run), atem-session-v1.md (the wire contract, r9 appendix), atem-client-bindings.md (r9 binding/effect contract), atem-host-work-v1.md (remote launch, directed work, messages, attachments/mark), station-route-v1.md (the selected Station), fixtures/ (shared with Astation)
├── agent-runtime.md          # `atem runtime` broker + `atem worker`s: sessions, leases, receipts, the local protocol, operations through the runtime
├── agent-collaboration.md    # local collaboration (stage 1); stages 2-3 point to delegated-host-work.md
├── delegated-host-work.md    # Planned (only its prompt framing, III.2, is built, with stage 1): delegated host work and host-to-host senders (stages 2-3 of collaboration); delegated-host-work-flows.html is its diagram
├── shared-terminal.md        # Shared terminal (terminal-v1): canonical-screen frames, credit, keys, limits
├── agent-chat-host.md        # Agent chat (chat-v1): adapters, Claude hooks + transcript, Codex, approvals, status
├── agent-chat-api.md         # Developer guide for chat clients
├── agent-hosting.md          # Remote launch (runtime.toml profiles/routes), messages, notices, directed work, Chisel/mark; planned: OS service, durable Station delivery
├── astation-connection.md    # How Atem reaches Astation: local then relay, authentication, token-free pairing, relay only, routed links, Stations
├── account-trust.md          # r9 account trust: the signed device list, recovery, the Recovery Kit
├── e2e-encryption.md         # E2E encryption: memory, skills, vault (atem side built) + credentials (`atem cred get`, planned)
├── atem-memory.md            # Atem Memory: shared memory + skills across agents and machines
├── vault.md                  # Shared cross-agent context store (relay + Postgres)
├── atem-identity.md          # instance_id + unique relay atem_id
├── atem-core.md              # atem-core token library + C ABI (built for a Swift/Astation integration, which is a follow-up)
├── convo.md                  # ConvoAI: `atem serv convo` (test page, daemon) and the `atem config convo` wizard
├── build-by-talk.md          # Planned (Astation + Atem; not implemented): Build by Talk, get the whole project clear by talking (project context + tool calls to the coding agents)
├── agora-account-grouping.md # Proposed: merge Astations under one Agora login (opt-in)
└── fixtures/                 # Agent hook fixtures the tests read (codex-hooks, permission-hook)
docs/
├── credentials.md            # User guide: pairing, device keys, project suggestions
└── credential-project-reporting.md # Astation credential picker: encrypted Git-project reports (wire format, labels)
```

### Core Components

**Host work extension** (v0.8.2; `designs/agent-hosting.md`, wire `designs/protocol/atem-host-work-v1.md`):
`atem runtime start|check` (tier 2) manages an explicitly disabled-by-default
private `runtime.toml`. Start creates missing configuration and starts or
reuses the detached runtime without replacing another build; check validates
without starting processes. Enabled healthy hosting keeps zero-session runtimes
online. Detached startup forwards only runtime variables and enabled profiles'
explicitly approved environment names, excluding test hooks. Encrypted r9
`host_profiles`/`host_launch`/`host_launch_query` use local approved profiles
and durable reserved identities. `work_enqueue`/`work_query`/
`work_cancel`/`work_complete` use a private durable task queue, current scoped
authority and normal session-v1 prompt receipts, blocking on drafts, busy or
unknown readiness, approvals and leases. Turn-end waits for an explicit result;
a task still awaiting it, or of unknown outcome, at its deadline expires. A
task whose sender's authority, authorization or route approval changed fails
at once with its own detail (`sender's authority changed`, `sender's
authorization expired`, `route changed`), a running turn never interrupted, and
its sender then gets `forbidden` reading it; an interrupted turn leaves it
awaiting its result (`turn interrupted`).
`reply_query` (feature `host.reply`, `notify` and `prompt` ops: `work_query`'s
authorization, returning `{kind:"reply", reply}`) reads the reply the task's
agent submitted with `atem message reply` (state
`publishing`/`submitted`/`refused`, `dropped` once the host no longer keeps
its text; it never completes the task). Not
implemented: boot-service installation and Station publication/replay. Strict
membership verifiers must know the launch/message/notify scope ops before a
service is enrolled with them. The default runtime idle policy is unchanged.
`host.messages` adds `message_publish`/`message_query` with inline text and/or
exact context snapshots, multiple resolved recipients and per-recipient
progress (`crates/atem-client/src/session/messages.rs`,
`designs/protocol/atem-host-work-v1.md` §5). The current channel principal must
equal the envelope sender; its key is pinned in the private receipt store.
Native members can store notices without execution consent; scoped services
need non-control `message`. Agent deliveries still need the route's
notify/prompt consent. Envelope, recipient decisions and queued tasks commit
together. Progress stays on the original message/task receipt; there is no
`runtime inbox` command. Not implemented: a Station durable outbox, offline
origin proofs and direct Atem host senders.

**Local agent collaboration** (stage 1, released in v0.8.5; `designs/agent-collaboration.md`):
`atem agent tag add|remove|list` and `atem message send|reply` identify the
calling agent from the local socket peer's verified process ancestry (`message
status|cancel|complete|directory` also run from the owner's terminal, outside
any session: a verified process with no agent in its ancestry; one that can't be
verified, or one under an agent whose start time isn't known, is refused, and
under the same-user model this owner fallback is no security boundary).
`runtime.toml` requires hosting, `[collab] send = true`, approved profiles and
route consent for `local` (a route's own `principals` replaces the
paired-Astation default); defaults keep sending, result prompts and launch off.
Security is at user authentication (design §6): who may reach an agent is the
signed r9 device list's members (routes and `control` authorize them), and
locally same-user socket peers (an agent's commands tied to its session by PID,
start time and ancestry); every request is bound to its sender and checked
against current authority at acceptance and again before dispatch; host work
travels only in end-to-end `atem-ch1` channels. That holds on r9 hosts: a host
without a pinned device list still serves r8 to the paired Astation over a link
neither end to end nor authenticated at Atem's end, so collaboration refuses to
run there (`local_authorized` needs `SessionHost::refuses_r8`; "collaboration
needs a pinned device list: run `atem pair verify`"). Every prompt Atem
renders around sender text (remote tasks, messages and marks, local tasks,
result deliveries) uses the agreed §III.2 framing (`atem_client::session::framing`):
a CSPRNG tag per rendered prompt, drawn after the sender's text is fixed, on
every line of Atem's (the guarantee: no sender line can carry it), the rule
line (narrowed by the owner on 2026-11-09: only this prompt's tagged lines
are Atem's; nothing the agent reads later is, whatever tag it carries), and
counted blocks. The live tag goes to `control` holders only
(`runtime/prompt_tags.rs`, owner decision 2026-11-10): chat-v1 replaces every
tag the runtime drew (kept in `runtime/workers/<sid>.tags`, synced before the
paste) with `****-****-****` for attachments without `control`, and their
terminal-v1 frames pause from a framed prompt's paste until its turn ends
(`Pause::holds`: receipt completed or rejected; with its outcome unknown, as
after a restart, the chat showing the agent took the prompt and the turn
ended; the session not live; else a day from the dispatch on the host's
wall and monotonic clocks, longer only when a broker restart reads as
another boot, as on macOS after a clock step; never the sender's task
deadline), kept in
`runtime/workers/<sid>.pause` so a restarted broker goes on holding it, then
resume with a full frame; only sessions the runtime has, by a parsed id, are
read, and an unreadable tags file hides tag-shaped strings in its own
session's chat only; paraphrases, echoes split across parts or cut short, a
dead tag on screen after the turn and a tag copied into another session's
output stay; as an extra layer, a `|` before any sender line that
folds to `[atem` after leading White_Space (Cf removed, NFKC, then the
lowercased line, its UTS #39 skeleton, or the skeleton taken before
lowercasing, lowercased and skeletonized again; all Unicode 18.0.0, the
lowercase mapping and White_Space from generated tables,
`framing/unicode_data.rs`, `scripts/gen-framing-unicode.py`). Look-alikes
`confusables.txt` doesn't list, or the marker after other text, get no `|`
and rely on the tag. Vectors:
`designs/protocol/fixtures/host-work/prompt-framing-v1.json`. A principal with
`control` still pastes what it likes (design §17, "Prompt framing: what
remains"). A principal
allowed to reach an agent acts through it with the local user's permissions
(shell, files, Atem commands, Memory, skills, vault): Atem doesn't track who
prompted an agent, so its `message send` is `local` and reaches every route that
lists `local`; the agent's tool approvals still apply.
Owner labels and agent-owned `self:` tags feed shared selectors; one message
resolves once to at most 32 other sessions. Limits count messages: `per_hour`
per sending session and `per_workflow` per workflow, for sends and again for
receives (a message counts once however many agents it reaches). They are
checked at send, counting sends whose context is still publishing, counted once
at acceptance and removed when their windows pass (a workflow's counter two days
after its latest message); replies and result deliveries count nothing. A
message whose task could never dispatch is refused before counting (an oversized
vault context shows `refused` in `message status`, not as the send error). The
SQLite outbox, tasks, resolutions, counters and return grants survive runtime
restart. Local work uses the session host's internal attachment and ordinary
prompt receipts, FIFO, readiness, drafts, approvals, leases and control fencing.
A `runtime.toml` that doesn't load, hosting off or a receipt-database fault
pauses local work, never fences it: new sends are refused with the reason,
queued local tasks wait as `paused: <reason>`, replies are stored while their
publication and delivery wait (a receipt-database fault instead refuses a
reply, a completion and a cancel until `atem runtime restart`, and writes no
`paused` detail), and a launch not yet started, local or remote, waits out a
file that doesn't load. Hosting switched off (a deliberate stop), a
receipt-database fault or a session-journal halt fences it (`outcome_unknown`,
never revived), and the spawn guard re-reads the file at the spawn boundary
(one that doesn't load, or hosting off, fences it there too).
A halted session journal fences `local` in memory only and holds its tasks the
same way. `[collab] send = false` is no pause: it only refuses new sends, and
accepted tasks, replies and deliveries go on. `local` is fenced for good only by
a new host identity or a device-list freeze or fault. The agent commands connect
only to the running runtime (none: "no Atem runtime is running; agents run
inside one"; never started or replaced, whatever its build). Context jobs
publish/read back exact decrypted Memory/Vault versions before dispatch.
`--vault` (send and reply) needs the account's signed encryption mode `on`
(checked at capture, before and after publication reads the entry, and by
each read: `VaultClient::encryption_on_only`), since a vault entry's text comes from the
relay; an entry whose text the credential redactor would change is refused
before it is frozen. Every task's stored prompt is the sender's text or the
reply only (a remote message's id and mark ride in `WorkRecord.message`);
Atem's lines around it (`Atem task … from local session …, route …, message
…`, `Answer with`, `Result of task … as data, not the owner's instruction`,
`Complete the task with`) are rendered at dispatch from the records with a
fresh tag (`collab::Frame`, `collab::task_prompt`).
`message reply [--task ID] [--memory ID] [--vault ID:ENTRY@VERSION]` submits one
durable reply for a task of any sender (local, member or service), bound to its
task/session/process/turn, its text redacted of credential values before it is
stored and digested; it never completes the task, and a reply's vault
reference must name its entry. Remote senders read it with `reply_query`. Only
the sender completes a task: `message complete TASK_ID` (its sending session, or
the owner outside any session; it stops a queued delivery) or `work_complete`.
`results = true` on its origin route permits one queued result as data, ending
with `[atem <tag>] Complete the task with: atem message complete TASK_ID`. A task whose return
grant ends early (its sending session gone, or its route no longer taking
results) keeps running and stays awaiting its result (`sender gone; reply kept,
not delivered`, `sender's route changed; reply kept, not delivered`): its reply
is stored, never delivered, and the owner or the sending session completes it. A
departed sender cancels nothing; a changed authority or route approval does end
the task (`failed` at once, for every sender: queued, blocked, awaiting a result
or of unknown outcome). A submitted task whose receipt is gone becomes
`outcome_unknown` (`receipt no longer available`). Every task awaiting a result
or of unknown outcome expires at its deadline, and one awaiting its result holds
no queue slot. The design's "Lifecycle" table lists every event. Automatic
timeout reports remain status only. Empty routes can opt in to `launch =
"on_message"` (Claude Code profiles only; a Codex route is refused when the file
loads): only `message send --launch` starts one, and only on a route an
`atem:<id>/<route>` selector of that send names, using the existing
approved-profile worker launcher; a send without it can share a pending launch
but never starts one. `message status [ID]` (inside a session: its own messages
and the local tasks sent to it), `cancel TASK_ID` (inside a session: its own
messages) and `directory [SELECTOR]` inspect the local runtime. `host.select`,
local `result` snapshots, the `local` sender and the local-only
`from_session`/`reply_to` are never admitted from remote channels.
Cross-instance delivery is not built (planned: `designs/delegated-host-work.md`).

**TUI State Machine** (`app.rs`): bare `atem` is a menu and a client of `atem runtime`; it opens no Astation connection (the runtime owns the machine's one link). Enum-based mode switching via `AppMode`:
- `MainMenu` - Navigation between features
- `TokenGeneration` - Token creation UI
- `CommandExecution` - Shell command runner
- `AgentPanel` - The runtime's sessions (Enter attaches); agent sessions open in `tui/frontend.rs`

**Shared Task Queue / Chisel/mark** (`runtime/host_work.rs`, `runtime/host_work_bridge.rs`):
Executable messages and mark tasks share durable work records and FIFO order
per session. Blocked/submitted/uncertain work holds later work on that session
(uncertain work until it expires, an offline sender's unstarted work until its
deadline); independent sessions can proceed. All use current r9 sender
authority, notify/prompt route consent, readiness/draft/approval/lease checks
and normal session-v1 prompt receipts. Turn-end is `awaiting_result`;
completion is explicit. No separate mark queue, model triage or background
`claude -p` remains. A 100 ms pass where nothing relevant changed reads no task
awaiting its result (or of unknown outcome) and no return grant: deadlines and
authorization expiries come from the `work_waits` table's due index (kept by
triggers on `work`), a grant's next look from `grant_dues`, and the authority,
route and grant checks of all of them re-run only when their inputs changed
(`HostBridge::work_inputs`: control generations, `local`'s standing, the loaded
`runtime.toml`, the host identity, the sessions). A task record this build
can't read (damage, another build's shape) never stops a pass or hosting:
`Store::fail_unreadable` settles it once (`failed`, "record unreadable", its
return grant ended) and closes it, keeping its row and bytes.

`host.attachments` adds encrypted `attachment_put` chunks (96 KiB decoded, PNG
only, ≤8 MiB). Bytes/descriptors persist in the work database, bound to sender
principal/key. Verified private local PNG paths become lines of Atem's at dispatch (`verified screenshot … read this PNG: <path>`);
missing/incomplete bytes block work. Limits: 256 uploads and 128 MiB reserved
bytes. No host-work record is ever deleted: about once a minute
`Store::drop_payloads` clears the payloads (prompt, message and reply text,
context text, a task's mark, upload bytes) of records settled a day past their deadline, so
queries and retries (deduplicated by stored digest; `reply_query` says
`dropped`) keep answering, and the 4,096-record limits count open records only
(`open_records`); downgrading to v0.8.x needs the file moved aside.
`message.mark` carries typed annotation metadata and an immutable screenshot
descriptor. See `designs/protocol/atem-host-work-v1.md` §6. Legacy ID-only
`markTaskAssignment` returns failed `markTaskResult` with upgrade guidance,
never reads local task files or injects input. Not implemented: Station offline
artifact delivery (an offline host).

**Astation Integration** (`websocket_client.rs`): WebSocket protocol with `AstationMessage` enum:
- `MarkTaskAssignment { task_id, received_at_ms }` - received from Astation
- `MarkTaskResult { task_id, success, message }` - sent back to Astation
- `SessionWire(String)` - every inbound `session`, `terminal` and `agentChat` message, as raw JSON for the session host's strict decoder (`session_family` peeks the `type`); outbound host messages are written as is (`try_send_wire`; terminal-v1 on the bounded terminal queue, in order with the frames). `SessionOversize { id }` - one larger than 32 KiB (terminal) or 1 MiB (session, agentChat), dropped unread and answered with a session `error` `unsupported_version`
- `AgentChat(ChatEnvelope)` / `Terminal(Envelope)` - outbound chat-v1 / terminal-v1 messages the host renders
- Removed (atem-session r6, no compatibility): `agentInput`, `agentPrompt`, `voiceCommand`, `voiceToggle`/`voice_toggle`, `voiceRequest`/`voiceResponse`, `userCommand`/`commandResponse`, `codexTaskRequest`/`codexTaskResponse`, `agentListRequest`/`agentListResponse` (the session-v1 registry replaces the agent list); they no longer parse (`websocket_client::REMOVED_OPS` → `RemovedOp`) and are answered with a session `error` `unsupported_version` (detail `removed in atem-session r6`) and no effect, (r6 §0). Every remote mutation is session-v1 (`designs/protocol/atem-session-v1.md`), wired by the runtime host (`designs/agent-runtime.md`)
- Also: project lists, token requests, volume (voice activity border only)/video toggle, heartbeat, auth flow (`auth_required` → `auth`; the connect path and re-authentication share `auth_proof` to build the proof and `auth_response` to classify replies, so the two can't drift)
- Connect (`App::spawn_astation_connect`, inside `atem runtime`): the local `astation_ws` (default `ws://127.0.0.1:8080/ws`) first, then the paired Astation's relay identity room; while the host policy keeps Atem off the local link the local step is skipped. The policy is r9's **relay only** (§R9.8a, `session_protocol/r9/host_policy.rs`, owner decision D12): set and read only inside an admitted `atem-ch1` channel by a native member holding `manage` at the head (checked when each request is handled, retries included; services, browsers and other natives get `forbidden`) with `host_policy_set{request_id, relay_only, expected_revision}` / `host_policy_get`, answered `host_policy_result{re, request_id?, outcome, policy{relay_only, revision, state}, account_id, atem_device_id, host_trust_gen, head, channel_id, attachment_gen}` built for the channel it is sent on (a fresh `id`; outcomes `committed`/`unchanged`/`superseded`/`conflict`/`save_failed`/`uncertain`/`current`; feature `host.policy`). There is no plaintext form: the outer `transportPolicy`/`transportPolicyAck` of earlier builds are removed ops (`websocket_client::REMOVED_POLICY_OPS`, answered `unsupported_version` with `app::hosted::REMOVED_POLICY_OP`, no effect, never a hint). Stored in `pairing/host_policy.json` (`{v, account_id, genesis_hash, revision, relay_only, requests[≤ 64]}`, bound to the pinned device list; a file for another list or one that can't be read fails closed: no local link, set/get `busy` "host policy unreadable"); a change is written first as `pairing/host_policy.pending` (the whole new file), then over the policy file, then the pending file goes: a failure before the pending file's rename is `save_failed` (nothing changed or recorded), any later one `uncertain` (the pending file stays, no local link while it exists, rolled forward at start and every 5 s on the pass). Both files are device-list leftovers: `atem unpair` and a new pin remove them. A commit of `true` while the link is local: no new channel is admitted on it (`close{closed}`) and no Astation operation is handed it, the result's frame is written with a delivery receipt (`Chan::receipt_for`, `AstationClient::try_send_channel_with`), and the link is dropped once that write completed or failed, or 5 s after no operation runs on it (`App::host_policy_changed`, `App::relay_only_receipt`, `App::relay_only_drop`; the policy is checked again at the close, so an intervening `false` cancels it; only for that link generation). A local link that (re)authenticates (a connect, or re-authentication on the same socket) while the policy keeps Atem off local is dropped the same way (`App::drop_local_link_if_relay_only`; it reads the files the one way the connect loop does, `relay_only::local_allowed`, so a broken config.toml never drops a link). With the relay unreachable there is no local fallback (the 30 s retry). First pairing (no record) still tries local first; an unreadable pairing record fails closed: no local attempt and no relay (no Astation id), the error given to a waiting operation and shown as the status (`app::PAIRING_UNREADABLE`), logged once and again only when it changes, the 30 s retry (the record is read from the profile's pairing path, so a broken config.toml is not reported as a damaged record)

**Runtime** (`src/runtime/`, `designs/agent-runtime.md`): `atem runtime` (bare: the runtime process itself, started by the commands that need it; one per config dir: an exclusive `flock` on `<config>/runtime.lock` holding its pid, the socket `$XDG_RUNTIME_DIR/atem/runtime.sock` (else in the config dir) recorded in `<config>/runtime.socket`, output in `<config>/runtime.log`) is the broker: it serves local frontends over the same-user socket (local protocol v1, `runtime/protocol.rs`: `hello`, `launch`, `attach`, `detach`, `input`, `paste`, `resize`, `reclaim`, `approvals_answered`, `list`, `stop`, `reload`, `status`, `restart`, `astation_op`/`answer` in; `welcome` (with `worker_protocol`), `launched`, `attached`, `output`, `exited`, `sessions`, `detached`, `stopped`, `session`, `astation`, `status`, `restarting`, `notice`, `print`/`ask`/`done`, `error` out), holds the App with the machine's one Astation link, and owns the session host. Clients (`atem agent launch|attach|list|stop`, bare `atem`, `atem pair`/`pair verify`/`cred unlock|projects`) start it detached when none answers; a runtime of another protocol without live sessions restarts for them. (`atem agent tag` and `atem message …`, which agents run inside the runtime, only connect to a running one, `RuntimeClient::connect_existing`: never started, never replaced.) A non-passive client of another build replaces it by its own (`client::replace_other_build`, whose doc comment has the rules): `restart` → `restarting`, the runtime exits after that pass (a runtime that doesn't know `restart` gets SIGTERM, only when `runtime.lock` names its pid and that pid is confirmed as this user's `atem runtime`), the client starts its build, which adopts the workers, and prints `Atem's runtime updated to <build> (was <build>); sessions kept.`; it is kept, with a message saying why, when its `welcome.worker_protocol` differs (naming the sessions that block it), while it is busy (an Astation operation runs or a session is starting: `restart` is refused), within 60 s of the last replacement (`runtime.replaced`, against two builds flapping), or while `runtime.toml` fails `host_work::validate` (what `atem runtime check` checks, as this build reads it; `Kept::HostConfig`, so a new runtime never starts without hosting). `atem runtime restart` does the same on request (no 60 s guard; the `runtime.toml` check still applies). Once `restart` is accepted, the exiting runtime refuses new work (`launch`, `attach`, `astation_op`, `restart`: `RESTARTING_NOW`; a new `hello`: `RESTARTING`, so the client waits for the next runtime), and its other frontends get `restarting` and reattach on their own (`RuntimeClient::reconnect`, a brief notice, then a fresh restore of the same session). If another client already replaced it, a second replacer finds the new runtime (another pid in `runtime.lock` or on the socket) and joins it. `status` (passive, read-only) returns the link (`transport`, relay label, retrying), the attachment (welcomed revision, time, authorization left; the last refused `hello` revision), whether the journal halted, and the sessions (with each worker's `build` from its `hello`); `atem status` and `atem --version` read it within 500 ms (`client::look`, a blocking passive client that never starts or keeps a runtime). It exits after 10 minutes with no sessions and no non-passive clients (`ATEM_RUNTIME_IDLE_SECS` overrides), on SIGTERM/SIGINT, or when replaced. Every session runs in its own `atem worker --state <config>/runtime --session <id>` (hidden, spawned detached; socket `$XDG_RUNTIME_DIR/atem/workers/<id>.sock`, else `<config>/runtime/workers/`; spec, record (`session_id`, `process_gen`, pids and OS start times, exit) and log in `<config>/runtime/workers/`), which owns the agent's PTY, the canonical screen, Claude's chat adapter and the session log, and outlives the broker: a new broker adopts each surviving worker only when its `hello` names the record's session id and process generation and the pid's OS start time matches (Linux `/proc/<pid>/stat` field 22, macOS `proc_pidinfo`); otherwise the session is `recovery_required` (or `interrupted`/`exited`) and nothing is restarted or replayed. The broker is the only writer authority: every write and paste carries the input epoch it granted, and the worker drops one whose epoch is older than its current one at the PTY write boundary (`pty_session.rs` fenced writes). Session ids are `ses-` + 12 base32 characters; each process is a new `process_gen` (UUID).

**Session host** (`runtime/host_bridge.rs`, `session_protocol/`, `app/hosted.rs`; contract `designs/protocol/atem-session-v1.md` r8, its appendix authoritative, compatibility mode): only `atem runtime` serves sessions remotely. Its broker owns `SessionHost` over a `FileJournal` in `<config>/runtime/journal/` (per-session receipt logs under `receipts/`, 0700/0600, `O_NOFOLLOW`, fsync per transition, compaction, a lease-epoch floors file, `principals` (each principal's `control` and `control_gen`), `refused` (the refusal list), `clean_close`, `journal.lock`, and a `runtime_epoch` counter incremented at each start) and makes the App's authenticated Astation link one attachment — new on every connect or re-authentication (`App::astation_link_gen`), fenced when the link drops or is re-authenticated, so clients `hello` again and an old `attachment_gen` is `stale_target`. Revision admission (r8 §A, `session_protocol/revision.rs`): a `hello` must carry `revision: 8`; without it (or with another number) it gets session `error{code:"unsupported_version", revision: 8}` and nothing else (no attachment; later requests are refused as before `welcome`); `welcome` echoes `revision: 8` and lists `features`, all nine (`chat.history_end`, `chat.history`, `chat.lookup`, `chat.coverage`, `receipt.result`, `approval.session_rules`, `approval.card_reason`, `chat.send_acquire`, `approval.lease_free`); the forms r8 removed (`open.before`/`open.generation`, `acquire` on an approval answer) are `unsupported_version` with no effect, and a field-rule violation is `invalid_request`. A second `hello` on the same authenticated link (Astation reset its client, e.g. after sleep) replaces the attachment (`Effect::Replaced`): the old one is fenced (its leases end, streams and conversations close), the new one gets a new `attachment_gen`/`controller_session` with the link's unchanged authorization deadline; receipts stay; at most one a second (`busy`). runtime.log gets one `HH:MM:SS` UTC line per `hello` (welcome, replaced, refused `<code>`), and one per other refused request (`runtime/refusal_log.rs`: `refused <family>/<op>[ kind=<kind>] <code>[ session=<sid>][ (<reason>)]`, oversize and full-inbox drops included; decode failures keep only the serde category and field name, never content; at most 20 lines per 10 s per link, then "… N more refusals suppressed"). Only the paired Astation the link captured, verified in `cred/state.json`, gets one (`view`, `control`, `client_kind` `native`); any other link gets none and its session messages are answered `unauthorized`. **Planned (owner decision 2026-11-08), not implemented:** r9 only. Today a host without a pinned device list welcomes this r8 attachment, but the link isn't end to end and Atem never authenticates Astation on it (`websocket_client::auth_response_saving` accepts `authenticated` or `auth{granted}` with no proof, and the challenge's `transport` is the peer's word), so the relay operator, a `ws://` LAN attacker or another listener on 127.0.0.1:8080 could pose as the paired Astation. Planned: every host refuses an r8 `hello` (`unsupported_version`, revision 9), the link gets no attachment and no link principal, a host without a pinned list serves no remote client until `atem pair verify` pins one, `atem status` (`Authorization: not authorized (no device list pinned; …)`) and runtime.log say why, and the clear `push_approval`/`push_resolved` messages go. r8's wire rules stay as the inner protocol of `atem-ch1`; needs Astation's agreement on timing (`designs/protocol/atem-session-v1.md` r9 appendix, "No r8 admission"). `welcome` names the verified `data_account` (`account_id`), this device's verified `device_id` (`atem_device_id`) and the `host_trust_gen` of `pairing/trust_gen`; `runtime_gen`/`runtime_epoch` change when the broker restarts or the identity changes (a pairing verified after the broker started rebinds the host over the same journal). The attachment is authorized for 24 h (no freshness proof yet), on the monotonic clock and in wall time, whichever ends first: then it is fenced and the link dropped, and the reconnect authenticates again (an r9 host, which refuses r8, never welcomes that attachment and keeps its link past the 24 h; each r9 channel has its own lifetime, see r9 below). Every 5 s the broker re-checks the link's pairing capture against the pairing and drops a link whose pairing changed (so an unpair takes effect even if the runtime wasn't told). Session-v1 (`hello`, `list` → `sessions`/`session_changed` with a per-attachment `seq`, `acquire`/`renew`/`release` → 15 s leases with explicit `takeover`, `submit` → receipts, `receipt_query`) is the registry and the only way to get control; `lease_held` names the holder (`controller{controller_session, lease_epoch}`, text "another controller holds this session"). Chat Send (r8 §F): a `prompt` submit (session-v1, or chat-v1 `text`) may carry `acquire: true` (no `lease_epoch`), with `takeover: true` plus `expected_controller` for a confirmed takeover: nobody holding → the prompt's durable acceptance and the grant are one step; the sender holding → its lease, unchanged; another holding → `lease_held` (a stale `expected_controller` too); the admitting reply carries `lease{lease_epoch, ms_left}`; only prompts acquire (`interrupt`/`stop`/rule revoke with `acquire` are `invalid_request`), and the flags are admission parameters outside the digest (a duplicate returns its receipt and never acquires). Principals and the control fence (r8 §H): each attachment speaks for the principal its link authenticated (today `astation:<account>:<astation id>`, `link_principal`); accepted work records the submitter principal and its `control_gen`; a link that re-authenticates without `control` writes the fence (`principals`) first, then fences that principal's attachments, revokes its lease and rejects its queued work (`control revoked`); a dispatch checks the principal still holds `control` at that generation. Persistence (r8 §I): a request is accepted only once its `accepted` record is durable; any failed journal write halts the journal until a restart (every session request but `hello` is `busy` "journal halted; restart Atem", a new link's `hello` gets no `welcome` and no reply while its other requests are `busy`, nothing queued is dispatched and no remote byte passes `admit_write`); a failed admission write goes on the refusal list first and is answered `busy` "acceptance not recorded" (if even that fails, the link is closed without a reply). An orderly stop (SIGTERM/SIGINT, idle exit, replacement) with a healthy journal writes `clean_close` (`{"runtime_epoch": n}`; runtime.log "session journal closed cleanly"). At start, recovered queued work is resolved in order: on the refusal list → `rejected` "acceptance not confirmed"; no clean close, or a queued request whose principal `principals` doesn't name at its `control_gen` (the file lost or older) → "authorization history unknown"; trust changed → "host trust changed"; an older `control_gen` → "control revoked"; else it waits for its principal to be welcomed with `control` and is "control not confirmed" 60 s after the start. Receipts per kind: `prompt` is pasted once `ChatSession::submit` accepts it and completes at the chat's turn end with `detail` `done` or `interrupted`, its completed receipt carrying `result{turn_id, user_message_id, outcome, reply_message_ids, more, replies}` (r8 §D: the two ids are journaled with the transition, never text; the reply ids — the turn's assistant messages in timeline order, approval cards left out, at most 32, `more` when more are retained — and `replies` (`complete`/`partial`/`unavailable`, `partial` when the user message was evicted, a hole touches the turn or an id can't be named and is dropped) are filled from the broker session's retained history each time the receipt is sent; the user message id is recorded per request when the prompt is accepted, so it is known after eviction; only a turn or user message id that isn't an opaque id journals no result) (a session without chat — Codex with `[codex] hooks` off, Claude before its SessionStart or after its chat was withdrawn — rejects it with no effect: "chat is not available for this agent; use the terminal"); `interrupt` writes Esc only while the chat status is `working` or `waiting` and completes when that turn ends, completes at once with nothing written in `ready` or `unknown`, and is `rejected` ("no turn state; use the terminal") whenever the session has no turn state, for any agent (Codex with its hooks off, Claude before its SessionStart or after its chat was withdrawn), never a blind Esc; `stop` completes at the exit; `approval` completes when the agent applied the decision (see Approval hooks). A refused-before-queueing write is `rejected`, a writer error after queueing `outcome_unknown`; executing work is `outcome_unknown` after a broker restart (never retried); duplicate submits return the recorded receipt, the same `request_id` with other content is `request_id_reused`. Terminal-v1 (`subscribe`/`unsubscribe`/`ack`, and `input`/`resize`/`stop` with the lease; terminal id = session id) and chat-v1 (`open`/`history`/`submit` with a binding, `close` with or without one, a `text` `submit` with the lease or `acquire`; `accepted`/`complete`/`error{code}` from its receipt; at most 8 conversations per session) are bound families. Effects reach the workers: remote bytes are checked with `admit_write` before they are sent and tagged with the worker's input epoch, which the broker raises (`set_input_epoch`, at least the lease epoch) whenever the host's epoch moves after remote bytes or while a lease was held; remote writes and pastes also carry `not_after`, the lease's deadline on CLOCK_MONOTONIC (`pty_session::monotonic_ns`), and the worker drops one at the PTY write boundary once it has passed (reported like an epoch drop; local writes carry none); each remote `input` gets a `written` ack (`control changed; not written` when dropped, `the approval was handed to the terminal; not written` when it released a Codex approval hook); a slow terminal transport drops frames and ends streams with `busy`. Local frontend input goes through `local_input` (it revokes any remote lease first). Duplicate session messages (same attachment, `id` and content) within 60 s are handled once (at most 4096 remembered). `advance` runs every 100 ms of the session clock. Adopted workers send a `chat_snapshot` before any `chat` (the whole retained history, 500 messages / 8 MiB, older messages first in `chat_history_part` lines of ≤ 1 MiB; approval cards included, since the broker copies each card to its worker with `chat_card`; a card still pending becomes `closed`), so chat goes on after a broker restart. A `chat` with `gap > 0` makes the broker reload the worker's history (`request_chat_history` → `chat_history`, r8 §C): every new or changed message goes to open conversations as a sequenced `message{history:true, after_message_id}` (`null` without a retained predecessor; cards only where cards are shown), with no `error`, `close` or reopen; the reload also carries the worker's chat state (`ChatSession::catch_up`: a missed turn end completes its receipt) and its truncation and cut turn; a reload lost with its worker, over 1000 messages, or with no worker to ask leaves a hole (no `count`) and a sequenced `coverage` event (the session's holes, ≤ 16). History pages are served by `chat::history` (see Agent chat). Bare `atem` opens no Astation connection, so only the runtime ever sees session-family messages. A runtime whose session host could not start (its journal or a damaged `runtime_epoch`, never reset silently) answers them `unsupported_version`, and `welcome.host_error` (shown by `atem agent list` and in `runtime.log`) says why, e.g. "remote sessions disabled: <path> is damaged; move it aside to reset the runtime epoch". §9 features (resume, browser grants, account-wide access, relay confidentiality) are refused on r8; r9 (below) brings native members, services and browser grants over an end-to-end channel. A socket alive is not an authenticated Astation: when Astation sends `auth_required` over an already-authenticated socket (e.g. it alone reconnected to the relay), `app/reauth.rs` shows `Astation ✗`, fences the attachment and ignores every other Astation request, then answers only the pinned Astation non-interactively (`AstationClient::answer_auth_required`) with the connect path's proof (`local_proof` on loopback, else the saved session); success restores online as a new attachment, while denial, expiry, a different `astation_id` or no answer within 15 s leaves a notice and closes the socket for the normal reconnect (never pairing). The shared fixtures run against the real runtime in `tests/runtime_fixtures_binary.rs` (see `designs/protocol/README.md`).

**r9 remote clients** (`crates/atem-client`, `crates/atem-client-ffi`, `session_protocol/membership/`, `session_protocol/r9/`, `runtime/project_scope.rs`; contract: the r9 appendix of `designs/protocol/atem-session-v1.md`, `designs/protocol/atem-client-bindings.md`, `designs/account-trust.md`; implemented on `feat/r9`, PR #89, merged once Astation ships its side): phones, bots and browsers reach Atem without the Mac. `atem-client` is the shared, sans-I/O client core (keys behind `KeyProvider`) that Astation's apps link through the bindings (SwiftPM/xcframework, Kotlin/JVM, Android `.so` per ABI, WASM; packages built by `.github/workflows/atem-client-bindings.yml` with SHA256SUMS and a `SOURCE.json` pinned to the commit; `host`/`software-keys`/`test-vectors` never shipped) and the host links for verification and the channel responder. **Device list** (§R9.2–§R9.5): `atem pair`'s verification pins the account's signed membership log from its genesis to this host's `add_host` (`verifyCommit.host_trust_gen`; the safety code covers the genesis and the new `host_channel_key`; `pairing/membership.*`, `host_channel_key`, `frozen_genesis`; `atem unpair` removes the list first); a carriage of newer entries is written durably before it is evaluated, then committed (fences of removed or demoted principals through r8 §H) or frozen (conflict: every remote principal fenced); a write fault fences, halts the journal and holds the host (`membership.fault` and its mirror `runtime/journal/membership_fault`: either one holds it, so losing one file never lifts the hold) until a managing device reconciles it, a plain crash replays; recovery waits 24 h on the host clock (wall and monotonic), approve/veto; `atem status` shows `Device list:` (pinned/held/frozen, `N/1024 entries, M/256 members, H/64 hosts`, pending recoveries, unacknowledged push). **Capacity** (D23, no compaction; `membership/capacity.rs`): `Membership::capacity` (the verifier's own counts and limits; nearly full from 90 % of any) and the signer-side `check_change` (nothing on a full log, no `add` or Recovery Kit `recovery_add` with full members, no new host's `add_host` with full hosts, no service `set_roles` granting anything new within 24 h of that service's last grant (a narrowing doesn't restart it); narrowing and removal never paced; `signed_at` clocks, advisory by design), both in the bindings; advisory only, the host accepts every valid entry; **Service builders** (`membership/service.rs`, in every binding): `ServiceScope` (canonical sets, `view` always) → `service_add`/`service_set_roles` actions checked by the verifier's own structural parse (`check_body`), `service_renewal`/`service_narrowing` from the current grant (pair with `check_change`); `service_key_fingerprint` = `r9_svc` (hex SHA-256 of the service `auth_key`'s raw bytes; vectors `crates/atem-client/vectors/r9-svc-fingerprint.json`, equal to Auth's); `atem_client::project` is the one definition of the launch project key (`memory::project` calls it) and of `h1.<kid>.<hex HMAC-SHA256(K, key)>` (from a platform MAC or a software key; equal to the cred agent's); `atem status` warns per limit from nearly full (members: remove expired services so a Recovery Kit keeps a place) and runtime.log gets one line naming the limits when a commit moves one into nearly full or full, and one when a list opens there. A host with a device list refuses r8 (`hello` → `unsupported_version` "this host has a device list: connect with atem-session revision 9"). **Planned (owner decision 2026-11-08), not implemented:** every host refuses it (see the Session host paragraph above). **Admission** (§R9.6–§R9.8, §R9.7a): the router (relay or Astation :8080) wraps each client's `atem-ch1` frames in the `channel` envelope (`open`/`frame`/`close`, exact fields, ≤ 2 MiB as received, over → `close{too_large}`) on Atem's one outbound link (Atem opens no port); `R9Host` runs the SIGMA-I responder per handle, carries the client's suffix before judging its r9 `hello`, admits a native member, a scoped `service` (ops, sessions, `projects` keyed hashes from the cred agent: pending/locked = out of scope, fail closed; cached hashes survive a lock, but a kid the agent no longer retains (`account_keys::NOT_RETAINED`), or an account switched to encryption off (`ENCRYPTION_OFF`), drops its hashes at the next 10 s retention check (a grant gap, `MISSING_KEY`, keeps them), `runtime/project_scope.rs` `REVALIDATE`) or a browser grant (≤ 1 h, revocable), and welcomes it as a `SessionHost` attachment (`welcome.head`, `pending_recovery`, `authorization_ms_left`); r8 session-v1/terminal/chat run unchanged inside the channel; per-channel queues are bounded and a channel that falls behind closes `busy`. Lifetimes: a native channel 24 h on the monotonic clock only (key rotation; removal fences at once), services and browsers at their expiry (wall and monotonic). Several devices at once (§R9.10): one attachment per channel, leases and takeovers as r8. **Host route proof** (§R9.7b, `atem_client::host_route`, `r9/route.rs`): the relay challenges every host connection (`host_challenge{nonce, room}`); the runtime's relay identity link answers in its reader, before Astation authenticates, with `host_route{proof}` signed by `host_channel_key` at the list's head (only a pinned list that can serve, once per challenge), and the relay verifies it with `verify_host_route` against its own log (no fallback). Two carriers: (A) the owner-present room (the Mac in the room authenticates the link as before, no proof needed: pairing, first verification, held-host reconciliation) and (B) the proved route (only to hold the room without the Mac; isolation and binding apply to (B) only); a held or unpinned host only has (A). The verdict counts in either order relative to Astation's `auth_required` (recorded during the auth wait; a later denial leaves the link routed). On the relay's `host_route_ok` a link no Astation authenticated is held **routed** (`App::astation_routed`; no auth timeout or retry): r9 channels and push relay messages only, never r8, Astation operations, credentials or mark tasks; Astation's later `auth_required` upgrades it with the connect path's semantics (a denial keeps it routed, advice logged, no reconnect); one challenge per link, a verdict only for its own proof; `host_route_refused` drops and retries; `atem status` says `r9 routed (no Astation)`. After enrollment or a reconciliation (the route state goes from off to serving, `route::set`), a relay link that proved no route (the link `atem pair` installed included) reconnects once (`App::route_reconnect_due`: after any running Astation operation and any mid-admission request or channel (≤ 30 s), only if the route state is still serving; never a local link) so it proves its route. **Sealed push and seen** (§R9.9, `r9/push.rs`): per approval one host-signed open hint per native member with `control`, tool/summary HPKE-sealed to its `enc_key`, then a resolved hint; a device that rendered the card in a focused foreground window sends `approval_seen` and the host signs a `seen` for recorded recipients only; `push_hint`/`push_seen` to the relay, ≤ 256 KiB per relay message, resent every 10 s and at reconnect until `push_ack`, the resolution is acknowledged or `expires_at + 300 s`; nothing is sent while the list is held/frozen/faulted or the journal halted; at most 64 tracked approvals, never evicting a published live one. Tests: `atem-client`'s tests (every r9 vector, client and relay fixtures), `tests/r9_runner/` (every r9 host scenario against the real runtime; items not expressible are reported NOT RUN with the reason), `r9_*_binary.rs`, `membership_binary.rs`, and `tests/r9_harness.rs` (headless multi-device harness for Astation).

**Astation operations through the runtime** (`runtime/ops.rs`, `runtime/op_client.rs`, `app/op_route.rs`): `atem pair` (first pairing), `atem pair verify`, `atem cred unlock`, `atem cred projects` and the paired-token refresh run inside the broker on its existing Astation link (waiting up to 15 s for it); the CLI is only the user interface (`print`/`ask` out, `answer` in, `done` at the end; answers from `/dev/tty`) and never opens its own connection (a runtime that can't be reached fails the command). One operation at a time (a second is refused); its handshake replies are routed to it only and dropped after it ends; a CLI that goes away ends it as a failure (device verification sends `verifyAbort`); a lost link ends it, never replayed. `atem unpair` and `atem logout` tell a running runtime (never starting one), which drops a link whose pairing changed, with its attachments. To use another Station, change `astation_relay_url` and run `atem runtime restart`.

**Shared terminal** (`src/terminal_share.rs`, `pty_session.rs`, `runtime/`, `tui/frontend.rs`, `tui/terminal_view.rs`): `atem agent launch [claude|claude-code|codex] [AGENT_ARGS]...` connects to `atem runtime` (starting it detached if none answers), sends `launch` with the current directory, environment and terminal size, and opens the frontend (`tui::frontend::run_frontend`); the agent runs in an `atem worker` (arguments are forwarded as separate values, with or without `--`; `CLAUDE_CLI_*`/`CODEX_CLI_*` from the launch environment still apply and come first, after Claude's chat hooks). `atem agent attach <ses-…>` reopens a session (screen restored), `atem agent list` prints the runtime's pid/protocol/build/Astation line and `ID PROVIDER STATE STATUS ATTACHED CWD`, `atem agent stop <ses-…>` stops one (and removes a session without a worker); each starts the runtime if needed (a new runtime adopts surviving workers). Bare `atem`'s Claude/Codex entries launch the same way and its Agent Sessions panel lists and attaches the runtime's sessions (looked up off the UI loop, within 2 s, as a passive client that never keeps an idle runtime running); the menu opens no Astation connection (the runtime owns it). Runtime notices are scoped: Astation link notices reach every frontend, mark-task notices only the frontend of their session (others go to `runtime.log`). The frontend keeps a local parser fed by `attached` (restore) and `output`, sends keys as `input`, a paste as one `paste` (≤1 MiB, written whole as one local input: a remote lease is revoked once and nothing comes between its bytes) and resize (kept, not applied, while a remote lease holder owns the size; applied at `g`), and shows one status row (`Atem | Claude|Codex | Local|Remote | Astation ✓|✗[ | Notice] | <prefix> then ?:help`: `Remote` while a remote lease holder exists (`session` summary updates), Astation from `welcome`/`astation`, `Notice` once a runtime notice arrived; prefix-pending, help, history and 4 s feedback replace it). Prefix `h`/`m` detaches and prints `Session ses-… is still running. Reattach: atem agent attach ses-… · Stop: atem agent stop ses-…`; `x` stops (the final screen stays with `Exited (…)` until a key), `g` reclaims. When an agent that printed something ends, its worker writes `~/.config/atem/logs/<session_id>/session.ansi` (the last 1 MiB of output) and `summary.md` (`runtime/session_log.rs`; dirs 0700, files 0600, atomic; never the launch environment) and the attached frontend gets "… log saved to … | … Summary saved to …". It works without Astation. Over the authenticated Astation link, `{"type":"terminal","data":{"v":1,"op":...}}` messages (`subscribe`, `unsubscribe`, `ack` in; `attached`, `frame`, `exited`, `error` out) let a viewer see the canonical screen as base64 ANSI frames (16 KiB per frame, 128 KiB unacknowledged, bounded queues). Inside `atem runtime` these are bound to session-v1 (`binding`, and the lease for `input`/`resize`/`stop`, answered with `written`); bare `atem` has no link; `list`/`sessions`, `control`/`controller` and `lease_id` are removed (session-v1 `list` is the registry). Terminal ids are session ids only (no `claude`/`codex` aliases); in `atem runtime` sessions run in `atem worker`s and outlive the broker (a new broker adopts them). Local keys use the prefix Ctrl+] (`terminal_prefix` in config.toml or `ATEM_TERMINAL_PREFIX`, which wins, changes it; an invalid value falls back to Ctrl+] with a notice): `h`/`m` detach, `g` take control back, `a` an approval was answered in the agent's own dialog (ends its wait), `x` stop, `r` redraw, `[` history, `c` copy, `?` help and recent notices. Background warnings go through `diagnostics` so they never write over the renderer. See `designs/protocol/atem-session-v1.md` (binding, leases), `designs/shared-terminal.md` (frames) and `designs/agent-runtime.md`.

**Agent chat** (`src/chat/`, `runtime/worker_chat.rs`): chat-v1 lets Astation show a launched agent as a chat. Claude Code and Codex have adapters. Before each Claude spawn the worker (`chat::claude::prepare_chat`) creates `chat-<uuid>/` (0700) under `$XDG_RUNTIME_DIR/atem` (else `~/.config/atem/run`) with `settings.json` (hooks for SessionStart, UserPromptSubmit, Pre/PostToolUse, Notification, Stop, each running the one hook script as `event <Event> sync` (`hooks::event_command`): published under its lock in sequence order and never dropped, read by the shared `chat::hook_events::EventReader`; a hook that died before publishing leaves its start marker, a lost event: the status shows working (no prompt goes in) until the turn ends, with a notice, and requests are no longer bound to calls; a PreToolUse that can't record exits 2, so Claude blocks the tool) and puts `--settings <file>` and, unless resuming, `--session-id <uuid>` before the user's arguments for that spawn only; each spawn is a new generation (UUID). It also writes a `pid` file (the worker's); `atem runtime` sweeps `chat-*` directories whose pid is dead (or, without one, older than an hour) when it starts. If preparing fails, Claude starts without chat. The worker reads the event files (lifecycle only) and the transcript JSONL named by SessionStart (all message content), feeds `ChatSession` (log items before a tick's `Stop`, so `complete` follows the content; a `Stop` recorded before the user entry that began the current, still open turn is an earlier turn's, read after its transcript `end_turn` let the next prompt in, and ends nothing of it, `ChatSession::ends_an_earlier_turn`: on a whole-second filesystem a same-second `Stop` is stale only while the previous turn's own `Stop` is still owed), times out unaccepted prompts (10 s, never resent), re-sends status to each conversation 15 s after it last got it, and sends the results to each open conversation with its own sequence (at most 8 per agent: a ninth closes the oldest with `close{reason:"evicted"}`). A SessionStart whose transcript isn't `<session_id>.jsonl` is ignored with a notice; compaction or a resume on the same transcript keeps the turn, while startup, `/clear` or another transcript resets to ready (the old transcript is read to its end first, one tick later). Resuming another session reads its existing content as history only (no `message`/`complete`) and sends open conversations `error` "the conversation was switched; reopen the chat" and `close{reason:"switched"}`. A user entry starting with `[Request interrupted by user` ends the turn as interrupted (Esc, or deny at a permission prompt). Status: ready/working/waiting/unknown (the session-v1 descriptor's `activity`, and `STATUS` in `atem agent list`). No SessionStart within 15 s leaves chat unavailable with a notice (a late one still enables it); a transcript format change withdraws chat (open conversations get `error` and `close{reason:"withdrawn"}`); the terminal is unaffected either way. Remote chat-v1 is served by `atem runtime`'s session host: `open`, `history` and `submit` carry a session-v1 binding (`close` may omit it and then closes only the sender attachment's own conversation), a `text` `submit` the lease or `acquire: true` (r8 §F; its `accepted` then carries `lease`, and `lease_held` carries `controller`), and its `accepted`/`complete`/`error{code}` follow its receipt (`ChatSession::submit` applies: current generation, new `requestId`, clean prompt ≤ 32 768 bytes not starting with `/` or `!`, status ready, no draft; accepted when both the UserPromptSubmit hook and the transcript's user entry arrive). Prompts typed in the terminal appear as `origin: local` messages. Approval cards (see Approval hooks) appear as assistant messages `approval-<approval_id>` with one `approval` part, re-sent whole when their state changes (final ones carry `reason`, the `approval_closed` reason, r8 `approval.card_reason`), only in conversations of attachments with `control`; a chat `submit` carrying `approval` instead of `text` answers one (no lease, r8 §G). Outgoing text goes through the credential redactor. Conversations are handled only while `astation_connected` (not during re-authentication) and close on disconnect or re-authentication; a new `open` replies `opened` (status), the newest page as `message{history:true}` and a sequenced `history_end` (r8 §B, `chat/history.rs`, shared with the fixtures' fake runtime): every page is built in one step from the retained history with consecutive sequences of its conversation; `history{generation, page_id, before|turn_id|request_id|next}` pages older messages (backwards) or a turn (forwards, frozen at the first page's snapshot); pages hold ≤ 50 messages, ≤ 256 KiB of content (`ChatMessage::bytes`: ids, text, 64 bytes per part, 1 KiB per card; ≤ 2048 parts per message) and ≤ 1 MiB serialized with the `history_end` (`page{selector, count, content_bytes, wire_bytes, end, next?, coverage, oldest_retained, truncated, holes, holes_more?}`); `next` is base64url of a payload plus an HMAC-SHA256 tag under a per-run random key (`HistoryKey`), bound to attachment, conversation, session, process generation, selector, position and the reload count (else `stale_target` with `page_id`); a `before` not retained is `stale_target`; a lookup with nothing retained is an empty `unavailable` page; field errors are `invalid_request` (sequenced, with the valid `page_id`); more than 8 valid requests a second per conversation is `busy`; cards are left out for view-only attachments before the bounds, their holes and `oldest_retained` name only visible messages, a hole before everything they see is reported as `truncated: true`, and a `before` naming a card is `stale_target`; `coverage` is `partial` when the selection was evicted in part or a hole touches it; `open.before` is refused `unsupported_version`; an `open` on a running session without chat-v1 is answered `error{code:"busy"}` "chat is not available for this agent[: reason]". a message that gains a part is sent again whole (same `messageId`, every part so far; r8 sends no `delta`), never a token stream; `complete.outcome` is `interrupted` for a turn that ended interrupted, else `done` (also for a duplicate `submit` after a broker restart). Claude exiting reports `unknown` and `error`, drops the adapter (removing its directory) and keeps history readable (500 messages / 8 MiB); a respawn sends the old conversations `error` "the agent was restarted; reopen the chat" and `close{reason:"restarted"}`. Codex's chat is below. See `designs/agent-chat-host.md`.

**Codex chat** (`chat/codex/adapter.rs`, `rollout.rs`; only with `[codex] hooks = true`, else Codex has no chat and its activity is `unknown`): the worker calls `chat::codex::adapter::prepare_chat` (a `chat-<uuid>/` dir like Claude's, no extra arguments; the adapter's `Drop` removes it) and sends `hello.chat` (required: an older worker is `recovery_required`; the descriptor offers `chat-v1` for Claude or a worker that says so). Atem's hooks write `events/ev-<seq>-<Event>.json` (first line the hook's `$$ $PPID`, then its stdin; `EventReader` takes only that name, in (seq, name) order, at most 256 per poll, `O_NOFOLLOW`, ≤ 1 MiB, deleting each once read) and the rollout JSONL named by the hook's `transcript_path` (must be `<CODEX_HOME>/sessions/…/rollout-*-<session_id>.jsonl`, symlinks resolved, read with `O_NOFOLLOW`, ≤ 8 MiB per poll) carries all content: `RolloutReader` turns `event_msg` records into log items (`task_started` → turn start; `item_completed` user message, agent message, command execution → a `Bash` tool part; `task_complete` → done, `turn_aborted` → interrupted; everything else, e.g. reasoning, is skipped; a known record missing a required field withdraws chat, an automatic compaction's nested `task_started` is suppressed). Hooks pin the session: a hook counts only when the session's agent started it (`approvals::HookAgent`/`started_by`, shared with approvals: direct or through one shell it may pin or re-pin on `/new`, through a non-shell child (npm's wrapper) only the pinned session's or the first, which makes that child the agent so the real binary's `/new` re-pins and a nested `codex` can't; a wrapped hook read after its parent exited counts as foreign, harmless); a SessionStart of another session re-pins after one poll (old rollout read to its end first), or after the current turn ends (deferred). Status: `unknown` until the first hook (Codex fires SessionStart lazily, at the first prompt) with the detail "type a first prompt in the terminal: …", then `working` (UserPromptSubmit or `task_started`), `waiting` while the worker's open-approval set for this session is non-empty (its only source for remote waits) or while an approval that got "no decision" (input to Codex, no broker, an adopting broker that doesn't know it, a prompt or interrupted turn end closing it, its hook ending without one) sits in Codex's own dialog — each such approval until the dialog is dismissed or gone (Interrupt or UserPromptSubmit hook, the rollout's next user message or `turn_aborted`, after it went there) or the person at the terminal says it was answered (the prefix, then `a`: `approvals_answered` → `ApprovalsAnswered`); never a Stop, a plain turn end, a reply or a tool result (`set_approvals`): a tool result never ends a wait, for either agent, since PermissionRequest names no call and no result can be proven to be the exact call's (event collection stays lossless and sequenced: counter first, start markers, gaps and unreadable events reported as lost), `ready` at the turn's end. Codex's waits outlast the turn (Codex 0.163 ends a turn while its exec cell still waits for the approval, or with its dialog open): a plain turn end neither closes an open approval nor makes the session `ready` (`WaitingForPermission.outlasts_turn`; the turn completes, the status stays `waiting` until the wait ends, then `ready`); an interrupted turn end does both. While an approval sits in Codex's own dialog the worker consumes a chat prompt's paste (`APPROVAL_IN_DIALOG`, the prompt `rejected`), since its Enter would answer the dialog; a "no decision" is latched at once, not at the next pass, and while Codex waits (an approval open or a dialog) chat prompts are also held at the PTY write boundary (`PtyInput::hold_prompts`, `FencedOutcome::Held`), so one queued before is never written; terminal input is still written. A resumed rollout is read to its end at the switch (several 8 MiB reads if needed), so all of it is history. The agent's own UserPromptSubmit of another session read before that session's SessionStart (async hooks publish in either order after `/new`) re-pins like a first hook (its late SessionStart is then no restart); a nested `codex` never does. With `[codex] hooks = true` the worker itself runs the idempotent hooks.json merge (backup, read-back, restore) in the launch's `CODEX_HOME` before spawning, so sessions launched from the bare `atem` menu get every hook too; it never asks and never writes when the setting is unset or false; a failure is a session notice and Codex starts anyway. Before the first prompt chat opens but a `submit` is refused with that text (`Refused` receipt detail and chat-v1 `error.text`), since text typed into Codex's startup dialogs could answer them. A remote prompt is accepted only when UserPromptSubmit and the rollout's user message agree on `turn_id` (whitespace-blind text match), and only evidence stamped after the paste counts (`at_ms`: the event file's mtime or the log's timestamp; a whole-second time counts to the end of its second), so a local prompt typed just before is a local turn; this applies to Claude too. A turn end or prompt answers a permission request only when it is newer than the request (`opened_ms <= at_ms`), times compared as they are (a millisecond time ending in `.000` is no whole second; an event file on a filesystem that keeps whole seconds, with no nanoseconds at all, counts to the end of its second at the reader, `hook_events`); tool-result evidence keeps 1 s slack. A turn that is not the prompted one (compaction) emits no `complete`. `interrupt` writes Esc only while `working` or `waiting` and completes at the turn's end; in `ready`/`unknown` it completes at once with nothing written (Esc on a startup dialog quits Codex); with no turn state (hooks off; for Claude too: before its SessionStart or after its chat was withdrawn) it is `rejected` "no turn state; use the terminal", and a prompt "chat is not available for this agent; use the terminal". Capabilities say what Codex's chat can't do: `unavailable` = `streaming` (replies arrive whole), `reasoning`, `error_details` (Claude: `streaming`, `reasoning`; "always allow" is offered as an Atem session rule, see Approval hooks), in the worker's `chat`/`chat_snapshot` messages and chat-v1 `opened.unavailable`. Known limits: whole-second filesystems and logs allow same-second races. See `designs/agent-chat-host.md` (Codex) and `designs/fixtures/codex-hooks/README.md`.

**Approval hooks** (`src/chat/approval_hook.sh`, `chat/approvals.rs`, `chat/codex/`, `runtime/worker_approvals.rs`, `runtime/host_bridge.rs`, `runtime/push_queue.rs`; contract §6a and r8 §G): agent permission prompts reach the worker through a `PermissionRequest` hook that writes `req-<id>.json` into the session's `approvals/` dir and waits for `dec-<id>.json` (claimed by renaming it to `taken-<id>.json`, then set aside as `claimed-<id>` once read, the claim time kept; the worker withdraws an unclaimed one the same way, so exactly one side gets it, and removes the files only once the hook process is gone). Claude gets it per launch in its `--settings` (600 s; its own dialog stays visible, first answer wins; while any of the session's approvals is open, a chat prompt is held at paste and at the PTY write boundary (`APPROVAL_IN_DIALOG`, the prompt `rejected`, nothing written), as it is while Claude's permission dialog is on the canonical screen (`chat::claude::dialog_on_screen`): a background agent can ask after its parent turn's Stop, while the status is still `ready` until Claude's own Notification ~6 s later; the status itself is unchanged (the shared fixtures' contract); each request is bound to the calls it can be (`ClaudeAdapter::call_for`: same tool and input, PreToolUse published by its request's `evseq` and unfinished then, not claimed by an earlier request; Claude asks one call at a time, so normally exactly its own, which it then claims), in the same approvals pass that reads it and before any result is weighed (`Approvals::poll_binding`; not decidable until every event through `evseq` is read with no backlog, and a result it could be about is held back meanwhile, never matched by tool and input), and closes on results only once each of its calls ended (`tool_use_id`, from the PostToolUse note or the transcript's failed or refused result), never on another call's or on a result naming none; bound to none (a lost PreToolUse, no `evseq`), no result closes it; with no PreToolUse sent and none lost (an agent without tool hooks) it stays unbound, and a result closes an unbound request only when it matches exactly one by tool and input) unless `[claude] approvals_hook = false` in config.toml (default on, never asked; read when the worker starts: off leaves out the `PermissionRequest` hook and its `PostToolUse` note, the chat hooks stay); Codex gets one Atem-marked entry per hook event (`chat::codex::EVENTS`: SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, Stop, Interrupt; commands start with `: atem-approval-hook;`, all run the one script `~/.config/atem/hooks/approval-hook.sh`, the same command for every session, `ATEM_APPROVAL_DIR` set by the worker; outside Atem they exit at once) in `$CODEX_HOME/hooks.json`, appended after the user's entries (Codex trusts each handler by position plus hash, so theirs keep their trust; the PermissionRequest entry is byte for byte the earlier one: sync, 300 s), after `atem agent launch codex` asks once (`[codex] hooks` in config.toml, one answer for approvals and chat; until it is `true` a Codex worker writes no hook script and watches nothing). PreToolUse, PostToolUse, UserPromptSubmit (10 s) and Interrupt (3 s, Codex's clamp) are synchronous (`chat::codex::SYNC_EVENTS`: Codex waits for them, so none is late or killed at a timeout; Codex 0.163 blocks a tool only on a PreToolUse exit 2 and lets every other failure, timeout or kill through, so each first leaves `events/start-<Event>.<pid>`, removed once its event is published: a marker whose hook died is a lost event the worker detects (`EventReader::take_lost`, a worker log line); such a PreToolUse waits ~6 s for the event lock and, unable to publish, exits 2 (its tool blocked, no marker)), and while Codex's own approval dialog is on the canonical screen chat prompts are held too (`chat::codex::dialog_on_screen`, a backstop that only adds holds). The other events are `async: true` (SessionEnd is always sync), 3 s, and only record their stdin as `events/ev-<seq>-<Event>.json` in the session directory (`approval_hook.sh event`: 10-digit monotonic seq under `events/seq.lock`, a symlink naming the holder's pid, taken over only when that pid is gone; the counter `events/seq` is advanced first, then the event published with `ln` under that number, never overwriting a file, either failing failing the hook (never a partial success; a number left without its event is a gap the reader reports as a lost event of unknown kind, `chat::hook_events::UNKNOWN`), 0600, no output, exit 0 within ~2.5 s; readers take only `ev-*.json` and ignore `tmp.*`, `seq`, `seq.<pid>`, `seq.lock`). Install is idempotent: an equal entry stays, an older Atem entry is replaced in place, a missing one appended, extra Atem entries of an event dropped. The merge keeps every other byte, writes `hooks.json.atem-bak` first (empty when there was no file) and keeps the file's mode. Setting `[codex] hooks = false` removes every Atem-marked entry on the next `atem agent launch codex` (only groups made of marked hooks; anything unexpected is refused; a copy first as `hooks.json.atem-removed.<secs>`; read back and restored if it doesn't match; no file again when there was none before Atem and nothing else is left); `atem unpair` never touches hooks.json. A Codex hook counts only when the session's agent started it: directly (or through one shell) its Codex session becomes the pinned one, so `/new` keeps working; through a non-shell child it must be the pinned session; a request without a session id counts only when the hook's parent is the agent itself. The worker reports each request redacted (tool, the command's first line or the file path, Claude's own `permission_suggestions` as "always allow" rules); the broker opens it in `SessionHost` whoever holds the lease: `approval_request` goes to subscribed attachments with `control` (view-only ones get nothing), a chat-v1 card appears in their conversations, and (r8 hosts only; an r9 host sends sealed push hints instead, see r9) `push_approval{approval_id, atem_device_id, session_id, tool, summary, expires_at}` goes to the relay as `{"type":"relay",…}` over the verified link (best effort: the latest state per approval is kept while the link is down, at most 64 entries; `push_resolved{approval_id, reason}` when it stops being pending). An answer is a `kind:"approval"` submission (allow once / always allow with an offered `rule_id` / deny with an optional message) from any attachment with `control` (r8 §G, lease-free): no lease check, its `lease_epoch` optional and ignored, it never grants, takes over, renews or releases the lease (no `lease_changed`/`session_changed`, the holder's queued input isn't fenced), `acquire` beside or in it is `unsupported_version`, and the first admitted answer wins (it goes `executing` and closes the approval in the same step; later ones are `stale_target`). **Planned (owner decision 2026-11-08), not implemented:** a `deny` with `message` is accepted only from a principal that also holds `prompt` (a native member with `control`; a service or browser grant with `prompt` in its ops), because the hook hands the text to the agent as the denial reason (`approvals::decision_output`); from any other it is `invalid_request`, nothing recorded and the approval still pending, and a deny without `message` is always admitted (contract §G, R9.6; needs Astation's agreement). The card then shows the decision (`allowed`/`always_allowed`/`denied`) with `reason: answered_remote`; every final card carries the first close reason (r8 `approval.card_reason`). The decision goes to the worker (`approval_decision`); `approval_applied` `ok`/`unknown`/`not_delivered` finishes the receipt `completed`/`outcome_unknown`/`rejected`, and one the agent never confirms is `outcome_unknown` after 630 s. A decision within 5 s of the hook's timeout is `not_delivered` (the hook might give up before taking it). Closes: `answered_remote`, `answered_terminal` (the person at the terminal pressed the prefix, then `a`, after answering the agent's own dialog; an allow written and not yet taken is withdrawn first; a tool result never closes a request, but one with a waiting request's tool and input, or a Codex PostToolUse after a dialog went to the terminal, sends the attached frontend the notice `ANSWER_HINT` once per request or dialog: "A tool ran while an approval waits: if you answered the agent's dialog here, press <prefix> then a", the frontend filling in its prefix for `{prefix}`), `interrupted`, `timed_out` (a hook that ended within 5 s of its timeout, our decision untaken or none), `released`, `process_ended`; lease changes never close one. Every write and paste to a Codex session carries `release_approvals` (Codex hides its prompt while a hook waits, showing "Running hook"): the waiting hooks get "no decision" and close `released` (status stays waiting), and the input that released them is consumed, never written, since the user never saw Codex's dialog it brings back (a `y` must not approve it): the local frontend gets the notice "Codex's approval was handed to the terminal; answer its dialog", a remote `input` is acked `written` with "the approval was handed to the terminal; not written", a remote prompt or interrupt is `rejected`; input after it is consumed too while the released hooks still run (at most 500 ms); input with no hook waiting is written as before. An adopted worker is told the approvals the new broker knows (none), so it releases the rest, without `push_resolved`: a phone notification may linger until its `expires_at`, and a tap gets `stale_target` (shown as already answered). Same-user processes that can see `ATEM_APPROVAL_DIR` can forge request files: the result is a fake card, never an agent action (same-user attackers are out of scope). Never an allow without a decision from Astation; any failure is "no decision". Codex can't take a persistent rule (`updatedPermissions` fails closed), so its cards offer an **Atem session rule** instead (contract §6a r7.2): `always_rules` holds one `{rule_id: "s-<16 hex>", label: "Always allow `<command's first line, redacted>`[ (+N more lines)] in <cwd> for this session", scope: "session"}` only for a shell command (`Bash`/`shell`/`exec_command` whose `tool_input` is a string `command` plus at most `description`; any other key, e.g. a workdir or env, gets no rule) with the hook's session `cwd` (`approvals::RuleMatch`, built from the unredacted request and never leaving the worker); file changes (`apply_patch`) never get one (Allow once / Deny), though an `apply_patch` run as a shell heredoc is a command like any other (byte-exact, patch text included). An `allow_always` naming it is a plain allow for the hook; once the hook took it the worker keeps the rule for this agent process (`worker_approvals`: at most 32, a full session offers none, and one full by the time the hook takes the answer is reported `approval_rule_not_kept`, so the card ends `allowed` with a `note`; gone when the process ends, so a respawn starts with none; each kept with the `account_id`, `atem_device_id` and `host_trust_gen` it was granted under (`granted_under` on the `approval_decision`; a decision without one keeps nothing); kept across broker restarts but unconfirmed after every new broker connection, when matching requests ask as usual: the worker reports its rules as `approval_rules` (each `{rule, granted_under, confirmed}`) on connection and on `request_approval_rules`, which the broker sends when it registers a session, and the broker answers `confirm_approval_rules{rule_ids}` naming those granted under its current identity and trust — the worker confirms them and drops every other unconfirmed one; a new account, device or host trust generation while the broker runs sends every worker `revoke_all_approval_rules`). A later request of the session's pinned Codex (never a nested or foreign `codex`) whose tool, full command (byte-equal) and cwd equal a rule's is answered allow by the worker itself while a broker is connected: no approval, no push, no lease; the worker reports `approval_auto_allowed{rule_id, tool, summary}` (redacted), the broker writes one runtime.log line naming the session, tool and rule (never the command) and shows an `auto_allowed` chat card with `rule_id`. Anything else still asks (an extra `; rm`, another cwd, one byte more). The active rules go to attachments with `control` as session-v1 `approval_rules{session_id, process_gen, rules}` (on change, after each `sessions` snapshot, `[]` when the process ends) and to chat-v1 (`opened.approvalRules`, `rules` on change); any attachment with `control` revokes one, with or without the lease (r7.3), with a `kind:"approval_rule_revoke"` submission `{rule_id}` (chat-v1: `submit` with `approval_rule_revoke` instead of `text`; view-only is `forbidden`, an inactive rule or another process `stale_target`; `lease_epoch` optional and ignored, `acquire` refused; it never takes, renews or moves the lease; journaled with a receipt like any submission), dispatched to the worker (`revoke_approval_rule` → `approval_rule_revoked`, one runtime.log line naming the rule and session, never the command), completed when it dropped the rule; an allow written for that rule that the hook hasn't taken is withdrawn (Codex's own dialog asks). No local prefix-key revoke yet. Claude's rules are unchanged (its own suggestions, echoed as `updatedPermissions`). An interrupt whose Esc only handed a waiting Codex approval to Codex's dialog is `rejected` "the approval was handed to the terminal; interrupt again to stop the turn" (a prompt: "the approval was handed to the terminal; not written").

**Vault** (`vault_client.rs`): Client for the relay-hosted shared cross-agent context store. `atem vault new/list/read/write/set-summary` — a versioned, append-only store that multiple atems read/write to hand off context between their agents. Pure request builders + human/plain renderers + a thin reqwest executor (auth: `Authorization: session <id>` + `?id=<instance_id>`). The `/api/vault` endpoints + Postgres live in the relay-server (Astation repo). See `designs/vault.md`.

**Atem Memory** (`src/memory/`): `atem sync`, `atem memory …`, `atem skill …`. Agents learn from each other across agents and machines. Claude's saved memories are harvested (an edited file becomes a replacement, a deleted file an invalidation), Codex saves facts with `atem memory add --agent codex` and replaces outdated ones with `atem memory replace <id> "<new fact>"` (its block shows each fact's short id), and skills are versioned directories (`atem skill history`/`atem skill restore` read old versions from the relay). Facts are never edited in place: `memory replace`/`memory invalidate` keep the history (`valid_at`, `invalid_at`, `superseded_by`; see `memory list --history`), invalidation is final, and only valid facts are injected — a block that leaves facts out says how many and points to `atem memory search`, which is local FTS5 (trigram, BM25) over `knowledge.db`. Everything is synced through the relay (`/api/memory`, `/api/skills` (a sealed skill file travels as its `e1.` text, encoded once: Astation PR #76), Astation pairing-session auth) with an offline SQLite store, then applied as a managed block in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and `<repo>/CLAUDE.local.md`, and as skills in `.claude/skills` and `.agents/skills`, in every encryption mode today (`sync::apply_all`). **Planned (owner decision 2026-11-08), not implemented:** as a transition measure, apply writes facts and skills only while the account's signed encryption mode is `on` (`verification::account_mode`), because with it off the relay can plant plain text into agents' instructions. With the gate closed everything still syncs and stays searchable and listable, but nothing is written: the managed block keeps its standing instruction lines and gets one fixed line saying why, skill directories Atem wrote (marker present, unedited) are removed, `atem status` gets a `Memory:` line, and this machine's own facts are gated too (the store has no per-row origin: `seq` is relay-supplied and a pulled row overwrites a local one), so an account still off loses all injection until migrated. The gate ends when encryption becomes the only mode for memory, skills and vault (no `off`/`disabling`; new accounts on, forced migration of the rest with relay-sourced content quarantined (each device re-pushes only rows it authored; the rest is held from agents until its author republishes it or the owner approves it in Astation; needs per-row author tracking and signed writes first), relay refuses plain text; issue #130, needs Astation; `designs/e2e-encryption.md` "Encryption becomes the only mode"), alongside signed writes (e2e step 3), an anti-rollback check on pulled rows (today `apply_pulled_memories` overwrites the local row, a local deletion included) and performance budgets that block a release when broken. Credential values are never stored: names only. Tracked files are never written. See `designs/atem-memory.md` and `designs/e2e-encryption.md`.

**Cred agent** (`src/memory/cred_agent.rs`, `agent_socket.rs`, `unlock.rs`): this device's keys live sealed in `device_keys.sealed` under a storage key only the home Astation (the first one this device verified with) holds. The hidden `atem cred-agent` (same binary, started on demand, detached; Unix socket, same-UID peers only, `"v": 2` JSON lines; `PR_SET_DUMPABLE=0` on Linux, and `mlockall` there when `RLIMIT_MEMLOCK` is unlimited or ≥ 512 MiB, each page locked as it is first touched (`MCL_ONFAULT`); one thread: `main` runs it on a current-thread runtime (`agent_socket::cred_agent_main`), its glibc heap kept between requests and given back (`malloc_trim`) once 1 s passed with no request or reply of 128 KiB or more and no connection ending (F5); one agent per key directory via a `flock` on `cred/agent.lock`; an agent whose socket disappears, e.g. logind removing `$XDG_RUNTIME_DIR`, wipes its keys and exits within ~5 s) holds the unlocked keys; while it is locked, grants are ignored (`encryptionMode`/`keyGrant` arriving while atem waits for another reply are applied, not dropped, and after an unlock atem sends `keyRequest` if the signed state still needs `K`; an already unlocked `atem cred unlock` still connects while the signed state is `enabling`/`disabling`, to finish the migration and send the signed completion, since `atem sync` never talks to Astation). `atem cred unlock` asks it for a single-use key, sends an `unlockRequest` signed by `unlock_auth_key`, and hands Astation's Touch-ID-approved, signed `unlockGrant` straight back to the agent; the agent then rotates the storage key in three crash-safe phases (`.next` → `storageKeyAck` → promote, `.prev` kept until the next unlock → `storageKeyConfirm`), abandoning a stale pending key if needed. `atem pair` escrows the first storage key in the same run; until Astation is known to hold it, a fresh device keeps a plain `device_keys` file, which the agent re-seals at each start and deletes at the first confirmed escrow, so an agent that stops first loses nothing; `atem cred lock` wipes the agent and stops it (always allowed: the agent stops listening, removes its socket and `cred/agent.socket`, gives requests in flight up to 1 s, clears its pid from `cred/agent.lock` and exits; the CLI waits up to 2 s for it to go; one that hasn't stopped by then is reported as still running, and the next `atem cred unlock` replaces it). The key state is shown by `atem status` (see SSO auth). An `unlockDenied` with `revoked: true` (or "revoked" in its reason) is recorded in `cred/state.json` (`atem status` shows "revoked by <id>"; `atem pair verify` then refuses); `atem unpair` with the agent locked (or not running) renames the old key files to `<name>.revoked-<stamp>` and forgets that Astation's verification, home and escrow state, so the next `atem pair` verifies with new keys (the signal is unsigned: a forged one costs a re-pair, never keys or trust; verification itself never sets keys aside). `K` lives only in the agent: it installs granted keys into the sealed payload (`InstallGrant`; a payload with keys is `version: 2`), does every seal/open/keyed hash for `EncryptionContext` in batched `Crypt` requests (no reply carries `K`), takes the mode and kid from the newest signed account state across every verified Astation naming the account (one helper, `verification::effective_state`, for install, `Crypt`, `account_mode` and `key_needed`), and serializes key payloads into exactly sized wiped buffers; a locked agent keeps sync changes queued until `atem cred unlock`. A restart before the first escrow loses `K`, which is requested again. The status reply carries the agent's `build` (`cred_agent::build_id`: version + the executable's mtime and size when the agent started, so every rebuild differs). A process shares one client per agent (`agent_socket::shared`, which `default_agent` returns; `running_agent` shares one that never starts an agent), one request at a time over one connection kept between requests (replaced when idle 30 s or closed by the agent before anything is written; no fallback for an agent that closes connections after a reply, none was released: its next request fails cleanly; a request that leaves the agent as it was is sent again, once, on a new connection when its connection, having answered before, drops before any reply byte, never another request; the agent wipes a connection's read buffers once its requests are answered); a `Crypt` goes as a binary frame (`agent_frame.rs`: the fields raw, no base64 or JSON pass, at most 1,024 ops and 2 MiB, 6 MiB for one op, checked before anything is allocated; a malformed frame closes the connection) on a connection whose build check's `status` said `"frames": 1`, else (a released agent, a client that checks no build, a bigger request) as a JSON line, and on the socket path every buffer that held plain text is wiped once over its whole allocation (`encoding::wipe`: `memset` plus an `asm!` barrier; an opened value handed to the caller, a queued op sealed ahead and a relay request body are not wiped, as before); the agent re-reads `cred/state.json` only when its device, inode, size or times changed (a file changed less than 3 s earlier is read every time). A command that may start the agent compares it with its own once per connection: a locked agent of another build is asked to stop (one that doesn't is an error saying to run `atem cred lock`) and this build's agent is started; it holds no keys, so nothing is lost. An unlocked one is never restarted: the command warns once (`cred_agent::OLDER_BUILD`, "The cred agent was started by another atem build; run `atem cred lock`, then `atem cred unlock` to use this one."; `OLDER_RUNTIME` instead, pointing to `atem runtime restart` first, when a passive look finds Atem's runtime — which starts the agent for an unlock — of another build too) and uses it, a request it rejects as unknown gets that hint instead of the raw error, and `atem status` adds the same advice to its Credentials line (builds are compared for equality only: a dev build and the npm release of the same version differ, and neither counts as newer). The unlocked agent also signs what atem reports to Astation: `CredentialProjects` (the HPKE credential-project report plus optional original-case `labels`, `credential_projects.rs`; sent best effort after each authenticated connection, on `credentialProjectListRequest`, and by `atem cred projects`) and `MigrationComplete` (the `atem-migration-complete-v1` completion with its `K` possession proof, sent only after the read-back pass in `migration.rs` finds every protected field migrated). See `designs/e2e-encryption.md` "Keys on disk (atem)", and `docs/credential-project-reporting.md`.

**Agent binaries** (`claude_client.rs`, `codex_client.rs`): the binary and extra arguments a worker starts, from `CLAUDE_CLI_BIN`/`CLAUDE_CLI_ARGS` and `CODEX_CLI_BIN`/`CODEX_CLI_ARGS` in the launch environment (else the worker's own). The PTY itself is `pty_session.rs`, in the worker.

**RTM** (`rtm_client.rs`, `native/`, `build.rs`, feature `real_rtm`): the Agora RTM FFI wrapper and its C++ stub/real implementations are kept but unused: nothing in the App calls them (voice coding was removed). `build.rs` still compiles the stub (or links the SDK with `real_rtm`).

**Tests never touch the real profile** (`src/test_profile.rs`): under `cfg(test)` every function that resolves the profile (`~/.config/atem`), the runtime dir or the cred agent asks `test_profile`, which panics unless the test injected a temp profile (`test_profile::use_dir`/`temp`) or a cred agent (`use_agent`) on its thread (`blocking` carries them to worker threads). New tests must inject one. Binary tests (`tests/*.rs`) run `atem` with a temp `HOME` and `XDG_RUNTIME_DIR` and fake agents, and only signal processes they started. Debug builds read `ATEM_TEST_CLOCK_FILE`/`ATEM_TEST_PTY_FAULTS` (`runtime/test_hooks.rs`) for the fixture harness (a client never passes `ATEM_TEST_*` on to a runtime it starts); release builds don't.

**Webhook Server** (`webhook_server.rs`): Receives Agora webhook POSTs (ConvoAI events 101–111, 201–202; RTC NCS events) on a local HTTP port. Optionally spawns `ngrok http <port>` or `cloudflared tunnel --url <port>` to expose the listener publicly. Validates `Agora-Signature-V2` (HMAC-SHA256) against `secret` from `webhooks.toml` when configured, skips validation with a banner warning otherwise. Broadcasts each accepted event to a live web console (SSE) at `GET /` and prints a one-line summary to stdout. The console and `/events` need the server's access code (`web_server/access.rs`, below); `POST /webhook` doesn't (Agora's registered URL can't carry it; the signature guards it). `--background` mode: standard daemon shape — registers in `~/.config/atem/servers/webhooks-<port>.json`, redirects stdout/stderr to `webhooks-<port>.log`, manageable via `atem serv list / kill / killall`. ngrok collision detection (refuses to start when a foreign ngrok already owns `:4040` and prints actionable next steps including the paid-plan link). cloudflared failure path captures stderr tail and surfaces it.

### Configuration & Storage (`config.rs`)

**Files in `~/.config/atem/`:**

Four user-facing TOML configuration types: general `config.toml`,
`runtime.toml` (approved launch profiles/routes and opt-in hosting), `convo.toml`
and `webhooks.toml`. The remaining files below are generated state. Runtime
configuration stays private (0600) and separate from general settings because
it grants explicit execution approvals.

| File | Contents | Encryption |
|------|----------|------------|
| `config.toml` | Non-sensitive settings (astation_ws, relay URL, bff_url, sso_url, `terminal_prefix` for the shared agent terminal; env `ATEM_TERMINAL_PREFIX` wins) + auto-generated identity (`instance_id`, `atem_id`) + `files_last_port` (last port `atem serv files` bound, reused next run) + `[memory] harvest_claude = false` (turns off harvesting Claude's native memory during `atem sync`) + `[codex] hooks` (Atem's hooks in `~/.codex/hooks.json`, one per Codex event, for approvals and chat: asked once, `false` removes them) + `[claude] approvals_hook = false` (Claude sessions launched afterwards get no approval hook; default on, never asked). Every write is a read-modify-write under an `flock` on `config.toml.lock` (`config::edit_config_file`), replacing the file atomically (temp + fsync + rename + directory fsync), so a reader — e.g. the runtime reading its identity while its Astation connect stores `instance_id`/`atem_id` — never sees half a file and concurrent writers never lose a key; a symlinked config.toml keeps its link (the target is replaced), the file keeps its mode (a new one is 0600) | None |
| `login.enc` | The user's own login (`atem login`/`logout`): one `Login` `{issuer, subject, tokens{access, refresh, expires_at}, connections{}}`; `issuer` is the host of the `sso_url` that issued it (`sso2.agora.io`); Agora API callers use only `Login::agora_tokens` (`connections.agora`, else the identity tokens when the issuer is Agora SSO) | AES-256-GCM (machine-bound, `machine_key.rs`) |
| `pairing/` | The one pairing (0700): `pairing.enc`, one `PairingRecord` `{astation_id, binding{binding_id, host_trust_gen, created_at}?, session{session_id, token, hostname, last_activity}?, shared (the `Login` Astation shared)?, save_credentials, disconnected_at?}`; `trust_gen` (the host trust generation, never decreases or repeats, survives unpair; written atomically; the generation is the highest of it, `cred/trust_gen_floor`, the record's binding and the legacy `pairing.json` (where it lived until v0.7.1; the move restarted it at 1, below generations Astation had accepted; read only, never removed), any unreadable one failing closed (its error says how to recover: with the other copy readable, move the damaged one aside and Atem rebuilds it; otherwise restore it from a backup), and a lower file is raised under the lock) and `trust_gen.lock` (every pairing change and every bound apply hold it); r9: the device list `membership.json`, `membership.{carriage,intent,freeze,fault}`, `revoked_floor` (the copy of the revoked grants' bound, see `runtime/journal/`), `frozen_genesis` with its mirror `runtime/journal/frozen_genesis` (another directory; the same list, written first; the two vouch for each other: one missing is covered by the other, either one unreadable refuses pairing and the unpair of a frozen list, restore it or remove both to forget every frozen list), the host's `host_channel_key`, and the host policy `host_policy.json` with its `host_policy.pending` (§R9.8a) (0600; `atem unpair` removes all but `frozen_genesis` and its mirror, and `revoked_floor`) | `pairing.enc` AES-256-GCM (machine-bound); `trust_gen` none (0600) |
| `project_cache.enc` | All projects + `current_app_id` (selected project reference) | AES-256-GCM (machine-bound) |
| `knowledge.db` | Atem Memory local store: memories (with `deleted_at`/`valid_at`/`invalid_at`/`superseded_by`), the `memories_fts` FTS5 trigram search index, skills, harvest map, local `replacements`, and the pending-sync queue (SQLite, mode 0600; holds no secrets — credentials are refused before storing; migrated in place on open) | None |
| `cred/` | This device's keys, its trust state and the cred agent's files, one directory (0700; files 0600; written atomically). `CredPaths` (`src/paths.rs`) is the only definition of the layout; binary tests include `paths.rs` itself (`tests/support/profile.rs`): `device_keys.sealed` (device X25519 + Ed25519 signing key + account keys `K`; `.next` only mid-rotation, `.prev` until an unlock proves Astation holds the current storage key; XChaCha20-Poly1305 under the storage key only the home Astation holds), `device_keys` (plain, only until the first confirmed escrow), `unlock_auth_key` (signs unlock requests), `state.json` (verified Astation pins, safety code, epoch floor, latest signed account state, `home_astation`, `escrowed_storage_kid`, `abandoned_kids`, `escrow_unanswered`; every read-modify-write holds `state.lock`), `project_names.json` (`h1.` project hash → project key and original-case `labels` per account; `project_names.lock`, taken after `state.lock`), `agent.lock` (the one cred agent's `flock` + pid; a second agent exits; a clean exit clears the pid), `agent.socket` (its socket path, tried first by clients), `agent.log` (its output), `agent.sock` (+ `.lock`) only when `$XDG_RUNTIME_DIR` is unusable (else `$XDG_RUNTIME_DIR/atem/cred-agent.sock`, next to `runtime.sock`, `workers/` and Claude's `chat-*` dirs; socket 0600, same-UID peers only), `trust_gen_floor` (a floor copy of the host trust generation, written before `pairing/trust_gen`, so losing `pairing/` never lowers it), and `<name>.revoked-<stamp>` keys `atem unpair` set aside | No secrets in plain except `device_keys` before escrow |
| `runtime.lock`, `runtime.socket`, `runtime.log`, `runtime.replaced` | One `atem runtime` per config dir: exclusive `flock` + pid; the socket path clients try first; its output; the last replacement by another build (`{at_ms, from, to}`, the 60 s anti-flap guard) | None (chmod 0600) |
| `runtime/workers/` | Per session: `<id>.spec.json` (launch spec), `<id>.json` (worker record: session id, process generation, worker/agent pids and OS start times, exit), `<id>.lock`, `<id>.log` (worker output; both removed with the record when the worker is released, or when `atem agent stop` removes a session without a worker), and the worker socket when `$XDG_RUNTIME_DIR` is unusable (else `$XDG_RUNTIME_DIR/atem/workers/<id>.sock`) | None (dir 0700, files 0600) |
| `runtime/journal/` | The session host's `FileJournal`: `receipts/` (per-session receipt logs; each `accepted` record names its submitter principal and `control_gen`, a completed prompt's transition its turn and user message ids), `floors` (lease-epoch floors), `principals` (each principal's `control` and `control_gen`, which only rises; r8 §H), `refused` (the refusal list: requests answered `busy` for a failed admission write, resolved `rejected` at the next start; r8 §I), `clean_close` (`{"runtime_epoch": n}`, written by an orderly stop with a healthy journal, read and removed at the next start), `journal.lock`, `runtime_epoch` (incremented each runtime start; a missing one next to the session journal's state, or while a surviving file names an earlier epoch (the device list's clean checkpoint, a fault record), was lost, not fresh: the next start vouches for no clean close and takes an epoch above every epoch a surviving file names and at least the wall clock in ms; an epoch no surviving file records can be reused after a second loss with the clock set back, which no authority depends on), r9: `membership_applied` (the device-list head whose fences are durable), `membership_fault` (the mirror of `pairing/membership.fault`), `frozen_genesis` (the mirror of `pairing/frozen_genesis`), `revoked_grants` (`{"v":1,"revoked":{grant_id: until},"quarantine"?:{"started_at","until"}}`: browser grants revoked with `revoke_grant`, each until its grant's expiry, at most 256; an unreadable one is kept aside as `revoked_grants.damaged-<ms>` (hard link, never overwritten) and every browser grant is refused `busy` until the wall clock passed the recorded `until` (65 min after it was found: grant lifetime + `issued_at` skew) and the running process saw 65 min on its monotonic clock; every write carries the `quarantine` record until then, so a revocation or restart meanwhile can't end it, fail closed), `revoked_quarantine` (`{"v":1,"until","high_water"}`, the quarantine's sidecar, written durably before every `revoked_grants` write: the latest quarantine end and the high-water mark, both only rise; each write raises `high_water` to at least the wall time and every retained entry's `until − 65 min`; the host's trusted time is `max(wall, high_water)`: a non-live revocation is kept until trusted time + 65 min and a new quarantine ends no earlier than `max(until, high_water + 65 min, trusted time + 65 min)`; browsers are refused `busy` "host clock went back" while the wall clock is below `max(until, high_water)`, with no override (wait for the clock; removing `runtime/journal/`, `runtime/` or the revoked grants' files is no way out, clock behind or not: `pairing/revoked_floor` keeps the bound). The files vouch for each other: `revoked_grants` missing or unreadable next to the sidecar or a `*.damaged-<ms>` copy, or the sidecar missing or unreadable (kept aside as `revoked_quarantine.damaged-<ms>`) next to `revoked_grants` or a copy, fails closed (`busy` "revoked grants unreadable"; a lost sidecar's bound rebuilt from the entries and record left, the journal directory's newest mtime as an extra floor). The bound also has a copy outside the journal, `pairing/revoked_floor` (same format, only ever raised, written durably before the sidecar at every write that raises it and at the pin; kept by `atem unpair`); it floors the bound, and a sidecar below it (the journal restored or rolled back) or an unreadable copy on a pinned host fails closed the same way. A pin seeds the copy and both journal files (a re-pin over an existing journal raises its sidecar to the copy, so it isn't read as a rollback), so on a host with a pinned device list none of the journal files (`runtime/` removed) is lost too: quarantined from `max(the copy, the list's clean checkpoint `at_wall`, the newest write in `pairing/` and in the journal) + 65 min` and trusted time + 65 min; only a host without a pinned list and none of them is fresh. What remains: removing both `pairing/` and `runtime/` (an unpair; pairing again needs Astation's ceremony), restoring both from an older backup, and same-user tampering (out of scope). A failed sidecar or file write answers `revoke_grant` `busy` "revocation not recorded" (still in effect in memory, the live browser fenced)); browser principals (`browser:<grant_id>`) leave `principals` once no attachment, lease or unfinished request names them | None (dir 0700, files 0600, replaced atomically; ids, codes and outcome words only, no prompt payloads after a request leaves `accepted`) |
| `logs/<session_id>/` | `session.ansi` (last 1 MiB of an agent's output) and `summary.md`, written by its worker when an agent that printed something ends | None (dirs 0700, files 0600) |

**Identity** (`config.rs`, `websocket_client.rs`):
- `instance_id` — persistent UUID v4, the canonical atem identity (and the vault `client_id`). Generated once by `ensure_instance_id()`, stored in `config.toml`.
- `atem_id` — the relay-room id `<host>[-<filler>]-<suffix:8>` (host + filler = 12 chars; e.g. `Genie-dc1649f-956631ec`), generated once (`build_atem_id`) and frozen in `config.toml` so it survives restarts and hostname changes. Keeps non-ASCII hostnames (Chinese/Japanese/Korean), restricts ASCII to `[A-Za-z0-9-]`, percent-encoded into the relay URL. See `designs/atem-identity.md`.

**Logins and the pairing** (`credentials.rs`, `pairing.rs`, `paths.rs`): one pairing at a time. A `Login` keeps identity and Agora connection apart (`issuer` + `subject` + identity `tokens`; `connections.agora` for a future non-Agora issuer); `Login::agora_tokens` is the only way to Agora API tokens (an issuer that isn't Agora SSO without an Agora connection: `credentials::NO_AGORA_CONNECTION`). Agora SSO is an exact allowlist: `sso2.agora.io` (`AGORA_SSO_ISSUER`, also the issuer of every login Astation shares) and the host of the configured `sso_url`. `valid_token` chooses, in order: the pairing's shared login while the link to that Astation is up (`shared_while_connected`); the user's own `login.enc`; the shared login when kept for offline use (`save_credentials`) or within 5 min of `disconnected_at` (`shared_offline`; stamped when the link drops, cleared by the next `credentialSync`). Writes to `pairing.enc` hold `trust_gen.lock`: inside `Captured::apply` through `PairingRecord::update_locked`, elsewhere through `PairingRecord::update`, which also refuses when the binding the caller read changed (so a write never brings back a pairing removed meanwhile).

**SSO auth** (`sso_auth.rs`):
- `atem login` — OAuth 2.0 + PKCE browser flow against `sso2.agora.io`; writes `login.enc` (issuer from `sso_url`)
- `atem logout` — removes `login.enc`, then tells a running runtime
- `atem status` (tier 0, `src/status.rs`; the only status command) — read-only: `Account` (signed in / signed in (expired) from `login.enc`, else signed in through Astation [(expired)] from the pairing's shared login, else signed out), `Pairing` (`paired (<astation id>, trust gen N)`; `, session expired` when its saved session expired; `; relay only (host policy)` after it while the host policy keeps Atem off the local link (relay only, a pending write, or an unreadable policy), plus a note after the block while Astation isn't connected (cleared when a manager turns it off, or by `atem unpair`); `not paired (unfinished pairing with <id>; run `atem pair`)` for a record without a current binding, which `atem pair` and `atem pair verify` treat as not paired (`atem pair` replaces it; only `atem pair` creates a record: background connections and re-authentication only update the bound pairing's session, else keep a granted session in memory); `unknown (<error>)` for an unreadable record; or `not paired`), `Verification` (`verified (safety code …)` / `not verified` / `revoked by <id>` only when that is the paired Astation / `—`), `Credentials` (`unlocked` / `locked` / `not set up` / `broken (<problem>)` with `cred_agent::RESET` printed after the block; plus `(storage key not yet held by Astation; run atem cred unlock)` for an unlocked, unescrowed agent and `(started by another atem build; run atem cred lock, then atem cred unlock)` for another build's agent; asks only an already running cred agent, never starts one; no agent = locked), and from an already running runtime (a passive `status` within 500 ms): `Authorization` (`authorized (r8, since HH:MM, N h left)` / `not authorized (Astation not connected | Astation connected but no session hello yet | the Astation link isn't a verified pairing …)` / `refused (Astation sent revision 7; needs r8)` from the last refused `hello` / `paused (journal halted; run atem runtime restart)` / `unavailable (<host error>)`), `Relay` (`connected via relay (<relay host> as <atem_id>)` / `connected locally` / `not connected (retrying)`), `Local agents` (`2 running (claude ready, codex working); 1 exited`); all three `no runtime running` without one. Never starts anything, never writes, never uses the network. "Paired" = a pairing record exists. A paired profile whose session expired or was refused gets `The saved Astation session expired or was refused. Run `atem unpair`, then `atem pair`.` instead of "run `atem pair`" (pairing gate, memory sync/history, TUI re-authentication, connect errors, `pair verify`)
- `atem pair [--save]` — on an already paired profile (even unverified or revoked) prints the status plus `Already paired. Verify this device: atem pair verify · Replace the pairing: atem unpair, then atem pair` and exits 0 without connecting or changing anything. Otherwise, inside `atem runtime` on its link (no credentials at any point: a local Astation's authenticated loopback challenge names it, over the relay) the token-free pairing bootstrap v1 (Astation's `designs/protocol/pairing-and-service-authorization.md`): send `pairing{v:1, op:"hello", id}` (received `pairing` frames are read strictly by `pairing_wire::parse`: at most 4096 bytes, strict JSON, exact per-op fields, UUID v4 ids, v1; anything else is `PairingInvalid` and fails the attempt) (resent every 3 s with the same `id`) until Astation's `pairing{v:1, op:"introduction", id, astation_id}` (at most 600 s, the relay room's life; `pairing{op:"error", id, code}` (`not_signed_in`, `pairing_cancelled`, `pairing_expired`, `unsupported_version`, `invalid_request`), another version, a malformed introduction or a `credentialSync` from an Astation before the bootstrap fail with a message saying what to do, binding nothing; no credential fallback); `astation_id` is only a routing hint: atem connects the authenticated identity link to it (same `atem_id`; its pairing-code `auth` carries the room's code as `pairing_code` and the hello's id as `pairing_attempt_id`, never a second code, so Astation attaches it to this attempt only), binds the pairing (`pairing::bind_new`; no Login is created, `--save` only records `save_credentials` for a later `credentialSync`), then verifies the device: commit-then-reveal (`verifyCommit` → `verifyKeys` → `verifyReveal`), both sides show a 12-character safety code, the user answers `codes match? [y/N]` (read from `/dev/tty`, flushed first, never stdin; no terminal fails the verification) and confirms on Astation with Touch ID, and atem applies the signed `deviceVerified` atomically (pins, device keys, signed state, grants; nothing on failure). If `K` is needed but missing it sends `keyRequest`. Astations that don't answer within 15s leave the device as it was (see `designs/e2e-encryption.md`). Any later failure (code refused, no terminal, 300 s Touch ID timeout, lost connection, apply error) drops the pending pin and sends `verifyAbort` with delivery confirmed (not when Astation itself aborted); the pairing stays saved and `atem pair` exits nonzero (`atem pair verify` retries). A failed `keyRequest` after success is only a warning (`atem cred unlock` asks again). Logic and tests: `src/pair_verify.rs`. On the home Astation's first verification the fresh keys are sealed and the first storage key is escrowed (`storageKeyRotate` with an empty old kid, then confirmed) in the same run
- `atem pair verify` — needs a pairing (`Not paired. Run atem pair first.`, exit 1); already verified with the paired Astation → `Already verified (safety code …).`, no connection (**Planned (owner decision 2026-11-08), not implemented:** not when the verified pairing has no pinned device list: it runs the ceremony again and pins one, `status::verify_start`); revoked → `This device was revoked by Astation <id>. Run atem unpair, then atem pair, to set it up again.`, exit 1, nothing moved. Otherwise moves the pairing to a new binding in the next host trust generation, durable before `verifyCommit` (`pairing::rebind_for_verification` through `OpCall::Rebind`; every ceremony reveals a fresh `host_channel_key`, so Astation adds it at a higher generation than any `add_host` an earlier, aborted ceremony had signed; the Astation, session and shared login stay, and the link adopts the binding), then runs the same verification as `atem pair` (`run_device_verification`) inside `atem runtime`, on its link authenticated with the saved session (never pairing; see "Astation operations through the runtime"). A cancelled or failed verification keeps the pairing
- `atem cred projects|unlock|lock` (tier 2; the key state is shown by `atem status`) — send the current Git project and the account's remembered project names to the home Astation's credential picker (keys must be unlocked; runs in `atem runtime`, waiting up to 15 s for its link; see `docs/credential-project-reporting.md`); Touch ID unlock through the home Astation, also in the runtime (waits up to 300 s, then rotates the storage key; when already unlocked it still finishes a pending migration; an unverified device stops offline with `This device isn't verified. Run atem pair verify first.`, and it never starts pairing or verification); wipe the unlocked keys and stop the agent. `atem cred-agent` is the hidden agent process itself
- Host trust generation (`pairing.rs`): asynchronous Astation work (connect and re-authentication, `atem pair`/`pair verify`, `atem cred unlock` rotation/escrow, credential-project reports, `credentialSync`, `encryptionMode`/`keyGrant`) captures the trust generation and binding, and the saved session its proof used, when it starts (`AstationClient::capture`), and applies a reply only while both are unchanged, under `trust_gen.lock` (`Captured::apply`; a binding of an older generation than `trust_gen` is no binding; cred-agent requests through `BoundAgent`). A reply that arrives after `atem unpair` or a new `atem pair` is dropped (`pairing::CHANGED`): no session refresh, no credentials, pins, grants or storage-key promotion. Encryption messages on a connection without a binding yet are held. `atem status` shows `paired (<id>, trust gen N)`
- `atem unpair [--yes]` — first commits the next host trust generation (`pairing/trust_gen`), then removes `pairing/pairing.enc` (`pairing::unpair`; the user's own login, memory, vault data, trust pins and keys stay), and set revoked keys aside (see Cred agent); a failure to set them aside, or a revocation left recorded (agent unlocked, or not the home Astation), is printed as a notice and the unpair still completes. It, `atem memory purge` and `atem skill purge` confirm first (`cli::confirm_destructive`): `--yes` skips the question, and without a terminal they refuse unless `--yes` is given. The purge prompts show the id and scope only, never the content, since a purged item may hold a credential. Unpair then tells a running runtime, which drops the link of the removed pairing and its attachments
- `valid_token(connected_astation_id, sso_url)` — the Agora access token of the login chosen as above. Within 60 s of expiry the own login refreshes at `sso_url`; a shared one never does (Agora rotates refresh tokens, so it would invalidate Astation's copy): the runtime's `token` operation waits for Astation's next `credentialSync`.

**BFF API** (`agora_api.rs`):
- `fetch_projects(access_token, bff_url)` — `GET {bff_url}/api/cli/v1/projects`, Bearer auth, returns `Vec<BffProject>`
- Default BFF URL: `https://agora-cli.agora.io` (override via `ATEM_BFF_URL` or `bff_url` in config.toml)
- Default SSO URL: `https://sso2.agora.io` (override via `ATEM_SSO_URL` or `sso_url` in config.toml)

**`atem config show`** displays the login, the pairing and the active project:
```
Login:    52a4f560...  (sso2.agora.io)
Paired:   astation-<uuid>  (login: 52a4f560...)  [save: yes]  [relay only]
          Verified: yes  (safety code MN3H-A74N-FJE4)
```
An unverified pairing shows `Verified: no  (run 'atem pair verify' to verify this device)`.

**WebSocket messages** (`websocket_client.rs`):
- `CredentialSync { access_token, refresh_token, expires_at, login_id, astation_id, save_credentials }` — Astation → Atem, after pair, on connect, or on Astation-side refresh (replaced `SsoTokenSync`)
- `Pairing { v, op, id, astation_id?, code? }` — the token-free pairing bootstrap v1 on the pairing connection: Atem's `hello`, Astation's `introduction` (routing id only) or `error` (see `atem pair`)
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
gate (passes with `login.enc` or a login the pairing shares);
`require_pairing(feature)` is the tier-2 gate (resolves a `PairedSession` —
relay base, Astation id, session id — from `AtemConfig` + the pairing
record, purely local, no network). Both return an actionable `anyhow::Error` built
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
Chisel saves local task JSON + annotated PNG
  -> authorized Chisel/Astation publisher reads the PNG bytes (their repositories)
  -> encrypted attachment_put chunks to the selected Atem host
  -> message_publish with mark metadata + screenshot descriptor + approved agent target
  -> shared durable task queue (FIFO per session), readiness/authority/lease checks
  -> verify screenshot, materialize private PNG, normal session-v1 prompt receipt
  -> message_query/work_query progress, explicit work_complete result
```

Atem's receiver shipped in v0.8.2; the sender (reading the PNG, uploading,
publishing) is Chisel's and Astation's, and Atem's receiver tests don't cover
it. Old `markTaskAssignment` notifications are refused with upgrade guidance.
Not implemented: Station offline artifact storage. No user process/service is
restarted for tests.

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

- **Access code (`web_server/access.rs`)**: every `atem serv` server (rtc, convo, files, the webhooks console) makes a random code at each start (16 bytes, base64url) and prints its URLs with `?t=<code>`. A request carrying it gets an HttpOnly, SameSite=Lax cookie named per port (`atem_access_<port>`; `Secure` on HTTPS) and a 302 to the same URL without the code; every later page and API request needs the cookie; anything else is a plain 404 (`access::admit` before routing; codes compared in constant time). Responses carry `Referrer-Policy: no-referrer`, and `Access-Control-Allow-Origin: *` is gone. A `--background` parent hands the code to its daemon in `ATEM_SERV_ACCESS_CODE` (never on the command line, which `ps` shows to every user); registry files are 0600. Every page has a **Copy link** button (`access::copy_link_button` + `access::COPY_LINK`): it fetches `/__atem/link` (`access::LINK_PATH`, answered by `admit` only with the cookie, `Cache-Control: no-store`, never readable cross-origin) and copies the page's URL with `?t=<code>` added back (the files toolbar before View raw and the index; the header of rtc, convo and the webhooks console). ConvoAI's API History serves bodies masked (`mask_secrets`, now also `authorization`); `?full=1` (the page's **Copy with full credentials** button) keeps them.
- **`atem serv list/kill/killall` registry conventions**: All servers
  (rtc, convo, webhooks, files) write JSON entries to `~/.config/atem/servers/`.
  Convo entries use the channel name itself as the id (no kind/port
  suffix) since channels are unique per agent. `list` shows a 1-based
  index (`#`), `ID`, `PID`, `PORT`, `STATUS` (convo: cached from its 60s
  poller, `—` until the first poll; others: `running`, plus `(no access
  code)` for a page started before 0.8.1; dead entries are pruned) and
  `URL` (a Custom URL first, the user's `extra_hostnames`: from `links`,
  or for an entry from before `links`, the `Custom:` lines its log
  printed; else LAN, else local; `—` for a convo daemon, which has no
  page). `info <id|#>` prints one entry: kind, PID, port, status, start,
  channel, every URL it printed (Local, LAN, then `links`: Cloudflared,
  Ngrok, Custom, each with the access code; the background parent writes
  `links` once the daemon's tunnels reported), the access state and the
  log path. `kill`, `attach` and `info` accept either the literal id or
  the index from `list`.
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

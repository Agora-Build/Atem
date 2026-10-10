# AGENTS.md

This file provides guidance to AI coding agents working with this repository.

## Project Overview

Atem is a terminal that connects builders, Agora platform, and AI agents. It provides a CLI and TUI for managing Agora projects and tokens, routing tasks between Astation and AI coding agents, generating and hosting visual diagrams, voice-driven coding, and more.

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
cargo test                               # Run tests (900+; use -- --test-threads=1 if a test flakes)
cargo check                              # Type-check without building
cargo fmt                                # Format code
cargo clippy --all-targets --all-features  # Lint
./scripts/run-local-dev-tests.sh         # End-to-end CLI smoke test (build first)
./scripts/release.sh [VERSION]           # Bump Cargo.toml + commit + tag (no push)
```

## Architecture

### Source Structure

```
src/
├── main.rs              # Entry point, CLI parsing (clap)
├── app.rs               # TUI state machine, mark task queue, Claude session management
├── cli.rs               # CLI command definitions
├── repl.rs              # Interactive REPL mode
├── websocket_client.rs  # Astation WebSocket protocol (message types + client)
├── claude_client.rs     # PTY-based Claude Code CLI integration
├── codex_client.rs      # PTY-based Codex terminal integration
├── token.rs             # Agora RTC/RTM token generation
├── rtm_client.rs        # Agora RTM FFI wrapper with async Tokio channels
├── ai_client.rs         # Anthropic API client for intent parsing
├── sso_auth.rs          # OAuth 2.0 + PKCE login flow, token refresh primitives
├── credentials.rs       # Encrypted multi-entry credential store (SSO + paired)
├── agora_api.rs         # BFF API client (BffProject, fetch_projects with Bearer auth)
├── auth.rs              # Astation auth session management, deep link flow
├── config.rs            # Config, SSO/BFF URL helpers, active project, project cache
├── time_sync.rs         # HTTP Date-based time synchronization
├── acp_client.rs        # ACP (Agent Communication Protocol) JSON-RPC 2.0 over WebSocket
├── agent_client.rs      # Agent event types (TextDelta, ToolCall, Done, etc.) and PTY client
├── agent_detector.rs    # Lockfile scan + ACP port probe for running agents
├── agent_registry.rs    # Registry of all known agents (PTY + ACP)
├── agent_visualize.rs   # Diagram generation: prompt builder, fs snapshot/diff, upload
├── diagram_server.rs    # Diagram hosting: SQLite blob store + HTTP server
├── webhook_server.rs    # atem serv webhooks — Agora webhook receiver +
                          # ngrok/cloudflared tunnel integration + SSE console
├── rtc_test_server.rs   # Browser-based RTC test page server
├── files_server.rs      # atem serv files — static file server (Markdown rendered)
├── convo_config.rs      # ConvoAI TOML parsing + Agora REST /join body builder
├── convo_test_server.rs # atem serv convo — ConvoAI test server + --background mode
├── convo_wizard.rs      # atem config convo — interactive config wizard + validation
├── web_server/          # Shared HTTPS scaffolding (cert, request, /api/token, net, html)
├── command.rs           # Task queue and stream buffer for voice commands
├── dispatch.rs          # Work item dispatcher for mark tasks
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
│   ├── project_names.rs #   project_names.json: h1. project hash → project key
│   ├── legacy_keys.rs   #   read-only data_keys.enc (steps 0–2a), moved in by the agent
│   ├── crypto.rs        #   EncryptionContext: mode from the signed state, batched Crypt via the agent; private writes
│   ├── storage_key.rs   #   storage key + device_keys.sealed (XChaCha20-Poly1305); unlock-grant/ack checks
│   ├── key_agent.rs     #   key agent state: unlock, rotation, abandon, K installed and used in memory (Crypt)
│   ├── agent_socket.rs  #   `atem key-agent` Unix socket server + client (v2 JSON lines, same UID only)
│   ├── unlock.rs        #   `atem cred status|unlock|lock`; unlock/rotation carried over the Astation link
│   ├── fake_astation.rs #   (test-only) Astation's side of unlock and rotation, mirrors the design doc
│   ├── kat_tests.rs     #   (test-only) known-answer vectors listed in designs/e2e-encryption.md
│   ├── k_agent_tests.rs #   (test-only) K in the agent: install, Crypt, rotation, data_keys.enc migration
│   └── cmd.rs           #   CLI handlers
└── tui/
    ├── mod.rs           # Main event loop, rendering dispatch
    ├── draw.rs          # Frame rendering
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
├── update-convoai-toolkit.sh # Refresh vendored assets/convo/ (pinned upstream commit)
└── test-create-agent.sh # ConvoAI agent creation (requires env vars)
designs/
├── agent-visualize.md   # Agent diagram generation
├── session-auth.md      # Session-based pairing authentication
├── universal-sessions.md # Universal sessions (astation_id keying)
├── connection-priority.md # Connection cascade: local > relay
├── relay-support.md     # Relay server support
├── voice-coding-stages.md # Voice coding implementation stages
├── remote-agent-control.md   # Astation → atem → agent (text/voice/control keys)
├── atem-identity.md          # instance_id + unique relay atem_id
├── vault.md                  # Shared cross-agent context store (relay + Postgres)
├── agora-account-grouping.md # Proposed: merge Astations under one Agora login (opt-in)
├── atem-memory.md            # Atem Memory: shared memory + skills across agents and machines
└── e2e-encryption.md         # E2E encryption: memory, skills, vault (atem side built) + credentials (atem cred, proposed)
```

### Core Components

**TUI State Machine** (`app.rs`): Enum-based mode switching via `AppMode`:
- `MainMenu` - Navigation between features
- `TokenGeneration` - Token creation UI
- `ClaudeChat` - Claude Code CLI integration (PTY)
- `CodexChat` - Codex terminal emulator (PTY)
- `CommandExecution` - Shell command runner

**Mark Task Queue** (`app.rs`): Receives task assignments from Astation, reads task JSON from local `.chisel/tasks/` directory, builds prompts from annotations + screenshots, sends to Claude Code, reports results back.

Key fields:
- `mark_task_queue: VecDeque<String>` - pending task IDs
- `mark_task_active: Option<String>` - currently running task
- `mark_task_needs_finalize: bool` - sync→async bridge flag

Key methods:
- `process_next_mark_task()` - loop-based (no recursion), pops queue, reads JSON, spawns Claude
- `build_mark_task_prompt()` - constructs prompt from task data
- `finalize_mark_task()` - reports result to Astation, processes next
- `check_mark_task_finalize()` - called from main loop for async finalization

**Astation Integration** (`websocket_client.rs`): WebSocket protocol with `AstationMessage` enum:
- `MarkTaskAssignment { task_id }` - received from Astation
- `MarkTaskResult { task_id, success, message }` - sent back to Astation
- `VoiceRequest { session_id, accumulated_text, relay_url }` - voice coding from Astation
- `VisualizeRequest { session_id, topic, relay_url? }` - diagram generation from Astation
- `VisualizeResult { session_id, success, message, file_path? }` - sent back to Astation
- `AgentInput { agent_id?, kind, text?, key? }` - remote agent control: text or a control key from Astation → focused agent PTY (`handle_agent_input`)
- Also: project lists, token requests, voice/video toggle, heartbeat, auth flow

**Remote Agent Control** (`app.rs`, `websocket_client.rs`): Receives `AgentInput` from Astation and writes it to the focused agent's PTY — `kind:"text"` types a line and submits it (`\n\r`, matching `send_claude_prompt`); `kind:"key"` writes raw control bytes via `agent_key_to_bytes` (enter/esc/ctrl-c/arrows/y/n). Routes to the codex PTY when it's the active chat, else claude; no-ops if no agent session is live (v1 drives an already-running agent). Voice reuses the existing `VoiceRequest` path. See `designs/remote-agent-control.md`.

**Vault** (`vault_client.rs`): Client for the relay-hosted shared cross-agent context store. `atem vault new/list/read/write/set-summary` — a versioned, append-only store that multiple atems read/write to hand off context between their agents. Pure request builders + human/plain renderers + a thin reqwest executor (auth: `Authorization: session <id>` + `?id=<instance_id>`). The `/api/vault` endpoints + Postgres live in the relay-server (Astation repo). See `designs/vault.md`.

**Atem Memory** (`src/memory/`): `atem sync`, `atem memory …`, `atem skill …`. Agents learn from each other across agents and machines. Claude's saved memories are harvested (an edited file becomes a replacement, a deleted file an invalidation), Codex saves facts with `atem memory add --agent codex` and replaces outdated ones with `atem memory replace <id> "<new fact>"` (its block shows each fact's short id), and skills are versioned directories (`atem skill history`/`atem skill restore` read old versions from the relay). Facts are never edited in place: `memory replace`/`memory invalidate` keep the history (`valid_at`, `invalid_at`, `superseded_by`; see `memory list --history`), invalidation is final, and only valid facts are injected — a block that leaves facts out says how many and points to `atem memory search`, which is local FTS5 (trigram, BM25) over `knowledge.db`. Everything is synced through the relay (`/api/memory`, `/api/skills`, Astation pairing-session auth) with an offline SQLite store, then applied as a managed block in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and `<repo>/CLAUDE.local.md`, and as skills in `.claude/skills` and `.agents/skills`. Credential values are never stored: names only. Tracked files are never written. See `designs/atem-memory.md`.

**Key agent** (`src/memory/key_agent.rs`, `agent_socket.rs`, `unlock.rs`): this device's keys live sealed in `device_keys.sealed` under a storage key only the home Astation (the first one this device verified with) holds. The hidden `atem key-agent` (same binary, started on demand, detached; Unix socket, same-UID peers only, `"v": 2` JSON lines; `PR_SET_DUMPABLE=0` on Linux, and `mlockall` there when `RLIMIT_MEMLOCK` is unlimited or ≥ 512 MiB; one agent per key directory via a `flock` on `key_agent.lock`; an agent whose socket disappears, e.g. logind removing `$XDG_RUNTIME_DIR`, wipes its keys and exits within ~5 s) holds the unlocked keys; while it is locked, grants are ignored. `atem cred unlock` asks it for a single-use key, sends an `unlockRequest` signed by `unlock_auth_key`, and hands Astation's Touch-ID-approved, signed `unlockGrant` straight back to the agent; the agent then rotates the storage key in three crash-safe phases (`.next` → `storageKeyAck` → promote, `.prev` kept until the next unlock → `storageKeyConfirm`), abandoning a stale pending key if needed. `atem pair` escrows the first storage key in the same run; until Astation is known to hold it, a fresh device keeps a plain `device_keys` file (like a step-1 device), which the agent re-seals at each start and deletes at the first confirmed escrow, so an agent that stops first loses nothing; `atem cred lock` wipes the agent (always allowed); `atem cred status` shows verified / home Astation / agent / storage key, and the reset steps when a key file is broken. Since step 2b `K` lives only in the agent: it installs granted keys into the sealed payload (`InstallGrant`; a payload with keys is `version: 2`, so a step-2a binary refuses it), does every seal/open/keyed hash for `EncryptionContext` in batched `Crypt` requests (no reply carries `K`), takes the mode and kid from the newest signed account state, and moves a leftover `data_keys.enc` in at the first unlock (then deletes it; an unreadable one is renamed aside, never deleted); a locked agent keeps sync changes queued until `atem cred unlock`. A key agent left running from before the upgrade speaks protocol v1 and must be stopped (the error says how); a restart before the first escrow loses a post-2b `K`, which is requested again. After the upgrade a verified device needs `atem cred unlock` once. See `designs/e2e-encryption.md` "Keys on disk (atem)" and "Astation work for step 2a".

**Claude Code Integration** (`claude_client.rs`): Manages Claude Code as a PTY subprocess using `portable-pty`. Includes terminal output parsing via `vt100`, session recording, and resize handling.

**RTM Signaling** (`rtm_client.rs`): FFI wrapper for native C RTM client with async Tokio channels. Default build uses a stub; enable `real_rtm` feature for Agora SDK.

**ACP Client** (`acp_client.rs`): JSON-RPC 2.0 over WebSocket for communicating with ACP agents (Claude Code, Codex). Manages initialize handshake, session creation, prompt sending, and event polling.

**Agent Detection** (`agent_detector.rs`): Discovers running agents by scanning lockfiles (`~/.claude/*.lock`, `~/.codex/*.lock`) and probing common ACP ports (8765-8770).

**Agent Visualize** (`agent_visualize.rs`): Generates visual HTML diagrams via ACP agents. Snapshots `~/.agent/diagrams/` before sending a prompt, detects new HTML files via ToolCall events or filesystem diff, uploads to diagram server, and opens results in the browser.

**Diagram Server** (`diagram_server.rs`): SQLite-backed HTTP server for hosting diagrams. Stores HTML as blobs, serves at `/d/{id}`. Auto-starts as background daemon when needed. Integrates with server registry (`atem serv list/kill`).

**Webhook Server** (`webhook_server.rs`): Receives Agora webhook POSTs (ConvoAI events 101–111, 201–202; RTC NCS events) on a local HTTP port. Optionally spawns `ngrok http <port>` or `cloudflared tunnel --url <port>` to expose the listener publicly. Validates `Agora-Signature-V2` (HMAC-SHA256) against `secret` from `webhooks.toml` when configured, skips validation with a banner warning otherwise. Broadcasts each accepted event to a live web console (SSE) at `GET /` and prints a one-line summary to stdout. `--background` mode: standard daemon shape — registers in `~/.config/atem/servers/webhooks-<port>.json`, redirects stdout/stderr to `webhooks-<port>.log`, manageable via `atem serv list / kill / killall`. ngrok collision detection (refuses to start when a foreign ngrok already owns `:4040` and prints actionable next steps including the paid-plan link). cloudflared failure path captures stderr tail and surfaces it.

### Configuration & Storage (`config.rs`)

**Files in `~/.config/atem/`:**

| File | Contents | Encryption |
|------|----------|------------|
| `config.toml` | Non-sensitive settings (astation_ws, relay URL, bff_url, sso_url) + auto-generated identity (`instance_id`, `atem_id`) + `files_last_port` (last port `atem serv files` bound, reused next run) + `[memory] harvest_claude = false` (turns off harvesting Claude's native memory during `atem sync`) | None |
| `credentials.enc` | SSO + paired tokens (multi-entry `Vec<CredentialEntry>`) | AES-256-GCM (machine-bound) |
| `project_cache.enc` | All projects + `current_app_id` (selected project reference) | AES-256-GCM (machine-bound) |
| `sessions.json` | Per-Astation device session IDs and tokens | None (chmod 0600) |
| `knowledge.db` | Atem Memory local store: memories (with `deleted_at`/`valid_at`/`invalid_at`/`superseded_by`), the `memories_fts` FTS5 trigram search index, skills, harvest map, local `replacements`, and the pending-sync queue (SQLite, mode 0600; holds no secrets — credentials are refused before storing; migrated in place on open) | None |
| `device_keys` | Plain device keys: a build-step-1 device's, or a freshly verified device's until its first escrow; the key agent seals them into `device_keys.sealed` at each start while this file exists, and deletes it once the home Astation is known to hold the storage key | None (chmod 0600, written atomically) |
| `device_keys.sealed` | This device's X25519 device key, Ed25519 signing key and account keys (`K` + previous, step 2b) (`{version, device_id, storage_kid, nonce, ciphertext}`); `device_keys.sealed.next` exists only mid-rotation, `device_keys.sealed.prev` (the replaced file) until an unlock proves Astation holds the current key | XChaCha20-Poly1305 under the storage key (held only by the home Astation, replaced at every unlock) |
| `unlock_auth_key` | Ed25519 key that signs unlock requests | None (chmod 0600; it can only ask Astation) |
| `cred_state.json` | Verified Astation pins (signing, encryption, recovery keys), safety code, epoch floor, latest signed account state, `home_astation` (holds the storage key), `escrowed_storage_kid` (last storage kid Astation is known to hold), `abandoned_kids` (never reused), `escrow_unanswered` (the home Astation never answered the first escrow, e.g. no step-2a support); every read-modify-write holds an `flock` on `cred_state.lock` | None (chmod 0600; no secrets) |
| `project_names.json` | `h1.` project hash → readable project key, per account (memory/skills project names the relay sees only as HMACs); replaces the names part of the removed `data_keys.enc` (`data_keys.enc` is moved in and deleted by the key agent at the first unlock; an unreadable one is renamed `data_keys.enc.corrupt-<stamp>`); writes hold an `flock` on `project_names.lock` (taken after the `cred_state.lock`) | None (chmod 0600; no secrets) |
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
- `disconnected_at` is stamped when Astation WS drops; cleared on reconnect via `SsoTokenSync`

**SSO auth** (`sso_auth.rs`):
- `atem login` — OAuth 2.0 + PKCE browser flow against `sso2.agora.io`; writes an `sso` entry to `credentials.enc`
- `atem logout` — removes the `sso` entry from `credentials.enc`
- `atem pair [--save]` — connect to Astation, send `PairSavePreference`, wait for `SsoTokenSync`, write paired entry, then verify the device: commit-then-reveal (`verifyCommit` → `verifyKeys` → `verifyReveal`), both sides show a 12-character safety code, the user answers `codes match? [y/N]` and confirms on Astation with Touch ID, and atem applies the signed `deviceVerified` atomically (pins, device keys, signed state, grants; nothing on failure). If `K` is needed but missing it sends `keyRequest`. Astations that don't answer within 15s leave the device as it was (see `designs/e2e-encryption.md`). On the home Astation's first verification the fresh keys are sealed and the first storage key is escrowed (`storageKeyRotate` with an empty old kid, then confirmed) in the same run
- `atem cred status|unlock|lock` (tier 2) — key agent state; Touch ID unlock through the home Astation (waits up to 300 s, then rotates the storage key); wipe the unlocked keys. `atem key-agent` is the hidden agent process itself
- `atem unpair` — remove all paired entries
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
- `SsoTokenSync { access_token, refresh_token, expires_at, login_id, astation_id, save_credentials }` — Astation → Atem, after pair or on Astation-side refresh
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
- `UnlockGrant { grant, encapped_key, ciphertext }` / `UnlockDenied { reason }` — Astation → Atem, the storage key sealed to the request's single-use key, or a denial
- `StorageKeyRotate { rotate, encapped_key, ciphertext }` — Atem → home Astation, a new storage key sealed to Astation's encryption key, device-signed
- `StorageKeyAck { ack }` / `StorageKeyRejected { reason, pending_kid? }` — Astation → Atem, stored as pending, or refused (`pending_kid`: Astation is committed to that pending key)
- `StorageKeyConfirm { confirm }` / `StorageKeyAbandon { abandon }` — Atem → home Astation, device-signed: switched to the new key / give up a pending key this device has no file for

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
| 2 | paired with Astation | vault, sync, memory, skill, cred, and Astation-driven remote agent control, voice coding, mark tasks, visualize |

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
| Storage | rusqlite (bundled) | Diagram store, Atem Memory store (`knowledge.db`) |

## Mark Task Flow

```
Chisel (browser) ──POST──→ Express/Chisel middleware
                            ↓ saves .chisel/tasks/{taskId}.json + .png
                            ↓ WS markTaskNotify → Astation
Astation hub ←── markTaskNotify {taskId, status, description}
  ↓ picks best Atem instance
  ↓ markTaskAssignment {taskId}
Atem receives assignment (websocket_client.rs)
  ↓ handle_astation_message() in app.rs
  ↓ process_next_mark_task()
  ↓ reads .chisel/tasks/{taskId}.json from LOCAL disk
  ↓ build_mark_task_prompt() → annotations + screenshot + source files
  ↓ ensure_claude_session() + send prompt via PTY
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
  `scripts/update-convoai-toolkit.sh`, stale bundles blocked at release time).
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
  (rtc, convo, diagrams) write JSON entries to `~/.config/atem/servers/`.
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

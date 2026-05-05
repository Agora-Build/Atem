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
cargo test                               # Run tests (500+ tests)
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
├── convo_config.rs      # ConvoAI TOML parsing + Agora REST /join body builder
├── convo_test_server.rs # atem serv convo — ConvoAI test server + --background mode
├── convo_wizard.rs      # atem config convo — interactive config wizard + validation
├── web_server/          # Shared HTTPS scaffolding (cert, request, /api/token, net, html)
├── command.rs           # Task queue and stream buffer for voice commands
├── dispatch.rs          # Work item dispatcher for mark tasks
└── tui/
    ├── mod.rs           # Main event loop, rendering dispatch
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
└── test-create-agent.sh # ConvoAI agent creation (requires env vars)
designs/
├── HLD.md               # High-level design
├── LLD.md               # Low-level design
├── roadmap.md           # Project roadmap
├── agent-visualize.md   # Agent diagram generation
├── credential-flow.md   # Credential encryption architecture
├── session-auth.md      # Session-based pairing authentication
├── universal-sessions.md # Universal sessions (astation_id keying)
├── connection-priority.md # Connection cascade: local > relay
├── relay-support.md     # Relay server support
├── voice-coding-stages.md # Voice coding implementation stages
├── validation-week0.md  # ConvoAI validation testing
├── test-cases.md        # Manual release test cases
├── data-flow-between-atem-and-astation.md  # Voice coding architecture
└── codex-launcher-design.md  # Codex launcher design
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
- Also: project lists, token requests, voice/video toggle, heartbeat, auth flow

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
| `config.toml` | Non-sensitive settings (astation_ws, relay URL, bff_url, sso_url) | None |
| `credentials.enc` | SSO + paired tokens (multi-entry `Vec<CredentialEntry>`) | AES-256-GCM (machine-bound) |
| `project_cache.enc` | All projects + `active_app_id` (selected project reference) | AES-256-GCM (machine-bound) |
| `session.json` | Astation auth session ID + expiry | None |

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
- `atem pair [--save]` — connect to Astation, send `PairSavePreference`, wait for `SsoTokenSync`, write paired entry
- `atem unpair` — remove all paired entries
- `valid_token(connected_astation_id, sso_url)` — resolves via priority chain, refreshes if expiring within 60s, returns access token

**BFF API** (`agora_api.rs`):
- `fetch_projects(access_token, bff_url)` — `GET {bff_url}/api/cli/v1/projects`, Bearer auth, returns `Vec<BffProject>`
- Default BFF URL: `https://agora-cli.agora.io` (override via `ATEM_BFF_URL` or `bff_url` in config.toml)
- Default SSO URL: `https://sso2.agora.io` (override via `ATEM_SSO_URL` or `sso_url` in config.toml)

**`atem config show`** displays credentials + active project:
```
SSO:      logged in  (52a4f560...)
Paired:   astation-<uuid>  (SSO: 52a4f560...)  [save: yes]
```

**WebSocket messages** (`websocket_client.rs`):
- `SsoTokenSync { access_token, refresh_token, expires_at, login_id, astation_id, save_credentials }` — Astation → Atem, after pair or on Astation-side refresh
- `PairSavePreference { save_credentials }` — Atem → Astation during `atem pair`, communicates user's save choice

**Active project resolution** (`ActiveProject::resolve_app_id/resolve_app_certificate`):
1. CLI flag (`--app-id`)
2. Env var (`AGORA_APP_ID`, `AGORA_APP_CERTIFICATE`)
3. Active project file
4. Error: `"No active project. Run 'atem list project', then 'atem project use <index>'"`

Note: RTC/RTM token generation needs only `app_id` + `app_certificate` (from active project). It does NOT need SSO credentials.

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
| Storage | rusqlite (bundled) | Diagram SQLite store |

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
  POSTs `/leave` before exiting. A 60s tokio task on the daemon polls
  `GET /agents/{id}` and writes `last_status` + `last_checked_at`
  into the registry JSON — `atem serv list` reads the cached value
  with no network round-trip. The daemon log (`<channel>.log`) contains
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
    - `hipaa` — switches ConvoAI URL prefix to `/hipaa/api/...`
    - `geofence` — GLOBAL | NORTH_AMERICA | EUROPE | ASIA | JAPAN | INDIA
    - `enable_avatar` — opt in to `[agent.avatar]` this session
    - `[atem.encryption]` — `mode` (0..=8), `key`, `salt` (base64-32-bytes)
  - `[agent]` — about the AI agent itself:
    - `user_id` (the agent's RTC uid; required)
    - `idle_timeout_secs` (server-side reaper)
    - `preset` (comma-separated string; UI splits to checkboxes,
      joins selections back as `properties.preset`)
    - `[agent.llm]` / `[agent.asr]` / `[agent.tts]` / `[agent.avatar]`
      — provider blocks, forwarded under `properties.<svc>`
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
  that generates `~/.config/atem/convo.toml`. Supports preset-based or custom
  configuration with provider selection for ASR (10 vendors), LLM (9), TTS (12),
  MLLM (3), and Avatar (3). `--validate` performs read-only config validation
  (checks required fields, large-integer precision issues, vendor completeness).
  Always loads existing config as defaults — re-runs change only what's needed.

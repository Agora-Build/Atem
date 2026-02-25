# AGENTS.md

This file provides guidance to AI coding agents working with this repository.

## Project Overview

Atem is a terminal that connects people, Agora platform, and AI agents. It provides a CLI and TUI for managing Agora projects and tokens, routing tasks between Astation and AI coding agents, generating and hosting visual diagrams, voice-driven coding, and more.

Distributed via npm: `npm install -g @agora-build/atem`

## Development Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo run                                # Run TUI application
cargo run -- [command]                   # Run with CLI arguments
cargo test                               # Run tests (460+ tests)
cargo check                              # Type-check without building
cargo fmt                                # Format code
cargo clippy --all-targets --all-features  # Lint
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
├── agora_api.rs         # Agora REST API client (projects, credentials)
├── auth.rs              # Auth session management, deep link flow
├── config.rs            # Config, encrypted credentials, active project, project cache
├── time_sync.rs         # HTTP Date-based time synchronization
├── acp_client.rs        # ACP (Agent Communication Protocol) JSON-RPC 2.0 over WebSocket
├── agent_client.rs      # Agent event types (TextDelta, ToolCall, Done, etc.) and PTY client
├── agent_detector.rs    # Lockfile scan + ACP port probe for running agents
├── agent_registry.rs    # Registry of all known agents (PTY + ACP)
├── agent_visualize.rs   # Diagram generation: prompt builder, fs snapshot/diff, upload
├── diagram_server.rs    # Diagram hosting: SQLite blob store + HTTP server
├── rtc_test_server.rs   # Browser-based RTC test page server
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
- Also: project lists, token requests, voice/video toggle, heartbeat, auth flow, credential sync

**Claude Code Integration** (`claude_client.rs`): Manages Claude Code as a PTY subprocess using `portable-pty`. Includes terminal output parsing via `vt100`, session recording, and resize handling.

**RTM Signaling** (`rtm_client.rs`): FFI wrapper for native C RTM client with async Tokio channels. Default build uses a stub; enable `real_rtm` feature for Agora SDK.

**ACP Client** (`acp_client.rs`): JSON-RPC 2.0 over WebSocket for communicating with ACP agents (Claude Code, Codex). Manages initialize handshake, session creation, prompt sending, and event polling.

**Agent Detection** (`agent_detector.rs`): Discovers running agents by scanning lockfiles (`~/.claude/*.lock`, `~/.codex/*.lock`) and probing common ACP ports (8765-8770).

**Agent Visualize** (`agent_visualize.rs`): Generates visual HTML diagrams via ACP agents. Snapshots `~/.agent/diagrams/` before sending a prompt, detects new HTML files via ToolCall events or filesystem diff, uploads to diagram server, and opens results in the browser.

**Diagram Server** (`diagram_server.rs`): SQLite-backed HTTP server for hosting diagrams. Stores HTML as blobs, serves at `/d/{id}`. Auto-starts as background daemon when needed. Integrates with server registry (`atem serv list/kill`).

### Configuration & Credential Storage (`config.rs`)

All sensitive data is encrypted at rest using machine-bound keys (HMAC-SHA256 from `/etc/machine-id` or macOS `IOPlatformUUID`).

**Files in `~/.config/atem/`:**

| File | Contents | Encryption |
|------|----------|------------|
| `config.toml` | Non-sensitive settings (astation_ws, relay URL, diagram server URL) | None |
| `credentials.enc` | `customer_id` + `customer_secret` (Agora REST API credentials) | AES-256-GCM |
| `active_project.json` | Selected project's `app_id`, `name`, encrypted `app_certificate` | XOR keystream |
| `project_cache.json` | All projects from `atem list project` with encrypted certificates | XOR keystream |
| `session.json` | Astation auth session ID + expiry | None |

**Credential resolution order** (in `AtemConfig::load()`):
1. Encrypted store (`credentials.enc`) — set by `atem login`
2. Env vars (`AGORA_CUSTOMER_ID`, `AGORA_CUSTOMER_SECRET`) — override encrypted store
3. Source tracked via `CredentialSource` enum: `None`, `ConfigFile`, `EnvVar`, `Astation`

**`atem config show`** displays credential source and actionable hints:
- `Credentials: from ENV` / `from encrypted store` / `from Astation`
- `Credentials: (none) — run 'atem login' or set AGORA_CUSTOMER_ID + AGORA_CUSTOMER_SECRET`

**Active project resolution** (`ActiveProject::resolve_app_id/resolve_app_certificate`):
1. CLI flag (`--app-id`)
2. Env var (`AGORA_APP_ID`, `AGORA_APP_CERTIFICATE`)
3. Active project file
4. Error with guidance message

Note: RTC/RTM token generation needs only `app_id` + `app_certificate` (from active project). It does NOT need `customer_id`/`customer_secret`. Customer credentials are only for the Agora REST API (`atem list project`).

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

Releases are triggered by pushing a git tag:

```bash
git tag v0.x.y
git push origin v0.x.y
```

GitHub Actions (`.github/workflows/release.yml`):
1. Builds binaries for linux-x64, linux-arm64, darwin-x64, darwin-arm64
2. Creates GitHub release with tarballed binaries
3. Publishes `@agora-build/atem` to npm (version synced from tag)

Requires `NPM_TOKEN` secret in GitHub repo settings.

## Integration Points

- **Astation**: macOS menubar hub for task routing (WebSocket)
- **Chisel**: Dev panel that creates annotation tasks (`.chisel/tasks/`)
- **Claude Code CLI**: Spawned as PTY subprocess for AI-powered code implementation
- **Agora RTM SDK**: Native library for real-time messaging (voice coding)
- **Agora REST API**: Project management, credential fetching

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Atem is an intelligent CLI tool for developers working with Agora.io real-time communication platforms. It provides a TUI (terminal user interface) with multiple modes: token generation, Claude chat, Codex terminal integration, and RTM signaling for voice-driven coding workflows.

## Development Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo run                                # Run TUI application
cargo run -- [command]                   # Run with CLI arguments
cargo test                               # Run tests
cargo check                              # Type-check without building
cargo fmt                                # Format code
cargo clippy --all-targets --all-features  # Lint
```

## Architecture

### Source Structure

```
src/
├── main.rs              # Entry point, CLI parsing (clap), TUI state machine, event loop
├── token.rs             # RTM token generation
├── rtm_client.rs        # Agora RTM FFI wrapper with async Tokio channels
├── websocket_client.rs  # Astation WebSocket integration, message protocol
└── codex_client.rs      # PTY-based Codex terminal integration
```

### Core Components

**TUI State Machine** (`main.rs`): Enum-based mode switching via `AppMode`:
- `MainMenu` - Navigation between features
- `TokenGeneration` - Token creation UI
- `ClaudeChat` - Claude LLM integration
- `CodexChat` - Codex terminal emulator
- `CommandExecution` - Shell command runner

**RTM Signaling** (`rtm_client.rs`): FFI wrapper for native C RTM client with:
- Connection lifecycle management (connect, login, join_channel)
- Message publishing (channel and peer-to-peer)
- Async event distribution via mpsc channels
- Automatic token refresh tracking

**Astation Integration** (`websocket_client.rs`): WebSocket protocol for real-time communication with Astation (the voice collaboration backend). Handles project lists, token requests, Codex tasks, Claude interactions.

**Codex Integration** (`codex_client.rs`): Manages Codex as a PTY subprocess using `portable-pty`. Includes terminal output parsing via `vt100`, session recording, and resize handling.

### Native FFI Layer

```
native/
├── include/atem_rtm.h       # C header for RTM client interface
├── src/atem_rtm.cpp         # Stub RTM implementation
└── third_party/agora/rtm_linux/rtm/sdk/  # Agora RTM SDK binaries
```

Build script (`build.rs`) compiles C++17 code via the `cc` crate and links against Agora RTM SDK.

## Key Dependencies

| Category | Crate | Purpose |
|----------|-------|---------|
| CLI | clap (derive) | Command parsing |
| Async | tokio (full) | Runtime, channels, tasks |
| TUI | ratatui, crossterm | Terminal UI rendering |
| Network | reqwest, tokio-tungstenite | HTTP, WebSocket |
| PTY | portable-pty, vt100, vte | Terminal emulation |
| FFI | libc | C interop for RTM |

## Voice-Driven Coding Flow

1. **Astation** captures mic audio, runs WebRTC VAD, streams via Agora RTC
2. **ConvoAI** transcribes speech, pushes text over Agora RTM
3. **Atem** receives transcription via RTM, routes to Codex for execution

See `designs/data-flow-between-atem-and-astation.md` for full architecture.

## Integration Points

- **Astation**: External voice/video collaboration backend (WebSocket + RTM)
- **Codex CLI**: Spawned as PTY subprocess for AI-powered code execution
- **Agora RTM SDK**: Native library for real-time messaging

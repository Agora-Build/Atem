# Atem

Agora AI development terminal. A Rust TUI that connects to [Astation](https://github.com/Agora-Build/Astation) for task routing, runs [Claude Code](https://docs.anthropic.com/en/docs/claude-code) sessions, and generates Agora RTC/RTM tokens.

## Install

```bash
npm install -g @agora-build/atem
```

Or download a binary from [Releases](https://github.com/Agora-Build/Atem/releases).

### Build from source

```bash
git clone git@github.com:Agora-Build/Atem.git
cd Atem
cargo build --release
# Binary at target/release/atem
```

## Usage

```bash
atem                              # Launch TUI
atem token rtc create             # Generate RTC token
atem token rtc decode <token>     # Decode existing token
atem list project                 # List Agora projects
atem config show                  # Show current config
```

## How It Works

Atem is a TUI with multiple modes:

| Mode | Description |
|------|-------------|
| **Main Menu** | Navigate between features |
| **Claude Chat** | Claude Code CLI integration via PTY |
| **Token Gen** | Generate Agora RTC/RTM tokens locally |
| **Projects** | Browse Agora projects via API |

### Astation Integration

When connected to an [Astation](https://github.com/Agora-Build/Astation) hub via WebSocket:

- Receives **mark task assignments** from [Chisel](https://github.com/Agora-Build/chisel) annotations
- Reads task data (screenshot + annotations) from local `.chisel/tasks/` directory
- Builds a prompt and sends it to Claude Code for implementation
- Reports task results back to Astation

### Mark Task Flow

```
Chisel (browser) ──POST──> Express middleware (saves .chisel/tasks/)
                            ──WS notify──> Astation hub
                                           ──WS assign──> Atem
                                                          reads task from disk
                                                          spawns Claude Code
                                                          ──WS result──> Astation
```

### Voice-Driven Coding

Astation captures mic audio, runs WebRTC VAD, and streams through Agora RTC. ConvoAI transcribes speech and pushes text over Agora RTM to Atem, which routes it to Claude Code. See `designs/data-flow-between-atem-and-astation.md`.

## Configuration

Create `~/.config/atem/atem.toml`:

```toml
astation_url = "ws://127.0.0.1:8080/ws"

[agora]
app_id = "your_app_id"
app_certificate = "your_app_certificate"
```

Or use environment variables:

```bash
AGORA_CUSTOMER_ID=...
AGORA_CUSTOMER_SECRET=...
ANTHROPIC_API_KEY=...
```

## Architecture

```
src/
  main.rs              # Entry point, CLI parsing
  app.rs               # TUI state machine, mark task queue, Claude session mgmt
  websocket_client.rs  # Astation WebSocket protocol (markTaskAssignment, etc.)
  claude_client.rs     # PTY-based Claude Code integration
  token.rs             # Agora RTC/RTM token generation
  rtm_client.rs        # Agora RTM FFI wrapper
  config.rs            # TOML config + env var loading
  tui/                 # Terminal UI rendering (ratatui)
native/
  include/atem_rtm.h   # C header for RTM interface
  src/atem_rtm.cpp     # Stub RTM (default, no SDK needed)
npm/
  package.json         # npm wrapper for binary distribution
  install.js           # Postinstall binary downloader
designs/
  HLD.md               # High-level design
  LLD.md               # Low-level design
  roadmap.md           # Project roadmap
```

## Development

```bash
cargo build              # Debug build
cargo test               # Run tests (124 tests)
cargo check              # Type-check
cargo fmt                # Format
cargo clippy             # Lint
```

### Feature Flags

| Flag | Description |
|------|-------------|
| `real_rtm` | Link against Agora RTM SDK (default: stub) |
| `openssl-vendored` | Build OpenSSL from source (for cross-compilation) |

## Related Projects

- [Astation](https://github.com/Agora-Build/Astation) -- macOS menubar hub for task routing
- [Chisel](https://github.com/Agora-Build/chisel) -- Dev panel for visual annotation and CSS editing
- [Vox](https://github.com/Agora-Build/Vox) -- AI latency evaluation platform

## License

MIT

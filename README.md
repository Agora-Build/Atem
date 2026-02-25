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

## Commands

```bash
atem                                    # Launch TUI
```

### Authentication

```bash
atem login                              # Pair with Astation, sync credentials (interactive y/n save)
atem login --save-credentials           # Pair and auto-save credentials (skip prompt)
atem logout                             # Clear saved session
```

### Tokens

```bash
atem token rtc create                   # Generate RTC token (interactive)
atem token rtc create --channel test --uid 0 --expire 3600
atem token rtc decode <token>           # Decode existing RTC token
atem token rtm create                   # Generate RTM token
atem token rtm create --user-id bob --expire 3600
```

### Projects

```bash
atem list project                       # List Agora projects
atem list project --show-certificates   # List with app certificates visible
atem project use <APP_ID>               # Set active project by App ID
atem project use <N>                    # Set active project by index (1-based)
atem project show                       # Show current active project
```

### Configuration

```bash
atem config show                        # Show resolved config (secrets masked)
atem config set astation_ws <URL>       # Set Astation WebSocket URL
atem config set astation_relay_url <URL> # Set Astation relay URL
atem config clear                       # Clear active project
```

### AI Agents

```bash
atem agent list                         # Scan and list detected AI agents
atem agent launch                       # Launch Claude Code as PTY agent
atem agent launch codex                 # Launch Codex as PTY agent
atem agent connect <WS_URL>             # Connect to ACP agent and show info
atem agent prompt <WS_URL> "text"       # Send prompt to ACP agent
atem agent probe <WS_URL>               # Probe URL for ACP support
```

### Dev Servers

```bash
atem serv rtc                           # Launch browser-based RTC test page (HTTPS)
atem serv rtc --channel test --port 8443
atem serv rtc --background              # Run as background daemon
atem serv list                          # List running background servers
atem serv kill <ID>                     # Kill a background server
atem serv killall                       # Kill all background servers
```

### Other

```bash
atem repl                               # Interactive REPL with AI command interpretation
atem explain "topic"                    # Generate visual HTML explanation
atem explain "topic" -c file.rs         # Explain with file context
atem explain "topic" -o out.html        # Save to specific file
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

### Voice-Driven Coding

Astation captures mic audio via Agora RTC. A ConvoAI agent transcribes speech (ASR) and pushes text through the relay server to Atem, which routes it to Claude Code. Claude's response flows back through the relay to ConvoAI for TTS playback. See `designs/data-flow-between-atem-and-astation.md`.

### Credential Management

Credentials are encrypted at rest using AES-256-GCM with a machine-bound key. See `designs/credential-flow.md`.

```
Priority: Astation sync (live) > env vars > credentials.enc
Storage:  ~/.config/atem/credentials.enc (Linux)
          ~/Library/Application Support/atem/credentials.enc (macOS)
```

## Configuration

### Via Astation (recommended)

```bash
atem login          # Pair with Astation, credentials sync automatically
```

### Via environment variables

```bash
export AGORA_CUSTOMER_ID="..."
export AGORA_CUSTOMER_SECRET="..."
```

### Config file

Non-sensitive settings in `~/.config/atem/config.toml`:

```toml
astation_ws = "ws://127.0.0.1:8080/ws"
astation_relay_url = "https://station.agora.build"
rtm_channel = "atem_channel"
```

Credentials are stored separately in `~/.config/atem/credentials.enc` (AES-256-GCM encrypted, machine-bound).

## Architecture

```
src/
  main.rs              # Entry point, CLI parsing (clap)
  app.rs               # TUI state machine, mark task queue, Claude session mgmt
  cli.rs               # CLI command definitions and handlers
  websocket_client.rs  # Astation WebSocket protocol
  claude_client.rs     # PTY-based Claude Code integration
  codex_client.rs      # PTY-based Codex terminal integration
  token.rs             # Agora RTC/RTM token generation
  rtm_client.rs        # Agora RTM FFI wrapper
  ai_client.rs         # Anthropic API client for intent parsing
  agora_api.rs         # Agora REST API client (projects, credentials)
  auth.rs              # Auth session management, deep link flow
  config.rs            # Config loading, encrypted credential store
  tui/
    mod.rs             # Main event loop, rendering dispatch
    voice_fx.rs        # Voice activity visual effects
native/
  include/atem_rtm.h   # C header for RTM interface
  src/atem_rtm.cpp     # Stub RTM (default, no SDK needed)
npm/
  package.json         # npm wrapper for binary distribution
  install.js           # Postinstall binary downloader
designs/
  HLD.md               # High-level design
  LLD.md               # Low-level design
  credential-flow.md   # Credential architecture
  roadmap.md           # Project roadmap
```

## Development

```bash
cargo build              # Debug build
cargo build --release    # Release build
cargo test               # Run tests (394 tests)
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

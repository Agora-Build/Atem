# Atem

A terminal that connects people, Agora platform, and AI agents. Manage Agora projects and tokens, route tasks between [Astation](https://github.com/Agora-Build/Astation) and AI coding agents, generate diagrams, drive voice-powered coding workflows, and more -- all from a single CLI/TUI.

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
atem repl                               # Interactive REPL with AI command interpretation
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

### AI Agents

```bash
atem agent list                         # Scan and list detected AI agents
atem agent launch                       # Launch Claude Code as PTY agent
atem agent launch codex                 # Launch Codex as PTY agent
atem agent connect <WS_URL>             # Connect to ACP agent and show info
atem agent prompt <WS_URL> "text"       # Send prompt to ACP agent
atem agent probe <WS_URL>               # Probe URL for ACP support
atem agent visualize "topic"            # Generate visual HTML diagram via agent
atem agent visualize "topic" --url ws://localhost:8765  # Explicit agent URL
atem agent visualize "topic" --no-browser               # Skip opening browser
```

### Dev Servers

```bash
atem serv rtc                           # Launch browser-based RTC test page (HTTPS)
atem serv rtc --channel test --port 8443
atem serv rtc --background              # Run as background daemon
atem serv diagrams                      # Host diagrams from SQLite (HTTP)
atem serv diagrams --port 9000          # Custom port (default: 8787)
atem serv diagrams --background         # Run as background daemon
atem serv list                          # List running background servers
atem serv kill <ID>                     # Kill a background server
atem serv killall                       # Kill all background servers
```

### Configuration

```bash
atem config show                        # Show resolved config (secrets masked)
atem config set astation_ws <URL>       # Set Astation WebSocket URL
atem config set astation_relay_url <URL> # Set Astation relay URL
atem config clear                       # Clear active project
```

## How It Works

### TUI Modes

| Mode | Description |
|------|-------------|
| **Claude Chat** | Claude Code integration via PTY |
| **Codex Chat** | Codex terminal integration via PTY |
| **Token Gen** | Generate Agora RTC/RTM tokens locally |
| **Projects** | Browse and select Agora projects |

### Astation Integration

[Astation](https://github.com/Agora-Build/Astation) is a macOS menubar hub that pairs with Atem over WebSocket. Once paired, Atem can:

- Receive task assignments from [Chisel](https://github.com/Agora-Build/chisel) annotations and route them to AI agents
- Sync Agora credentials automatically
- Relay voice-coding sessions (speech-to-code and code-to-speech)
- Request diagram generation from AI agents

### Diagram Generation

`atem agent visualize "topic"` sends a prompt to a running AI agent, which generates a self-contained HTML diagram and saves it to `~/.agent/diagrams/`. Atem detects the new file and opens it in the browser. See `designs/agent-visualize.md`.

### Voice-Driven Coding

Speak to code: Astation captures audio, a ConvoAI agent transcribes it, and Atem routes the text to Claude Code for implementation. Responses flow back as speech. See `designs/data-flow-between-atem-and-astation.md`.

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

Credentials are stored separately in an encrypted file (AES-256-GCM, machine-bound). See `designs/credential-flow.md`.

## Development

```bash
cargo build              # Debug build
cargo build --release    # Release build
cargo test               # Run tests (400+ tests)
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

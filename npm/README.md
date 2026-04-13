# @agora-build/atem

A terminal that connects people, Agora platform, and AI agents. Manage Agora projects and tokens, route tasks between [Astation](https://github.com/Agora-Build/Astation) and AI coding agents, generate diagrams, drive voice-powered coding workflows, and more -- all from a single CLI/TUI.

## Install

```bash
npm install -g @agora-build/atem
```

This downloads a prebuilt binary for your platform (linux-x64, linux-arm64, darwin-x64, darwin-arm64).

## Commands

```bash
atem                                    # Launch TUI
atem repl                               # Interactive REPL with AI command interpretation
```

### Authentication

```bash
atem login                              # Log in with Agora Console (opens browser)
atem logout                             # Log out from SSO
atem pair                               # Pair with Astation
atem pair --save                        # Pair and save credentials for offline use
atem unpair                             # Unpair from Astation
```

Two ways to authenticate:

- **`atem login`** — your own Agora Console login. Auto-refreshes.
- **`atem pair`** — receive credentials from a connected Astation. Paired tokens take priority when connected; own login is the fallback.

### Tokens

```bash
atem token rtc create                   # Generate RTC token (interactive)
atem token rtc create --channel test --uid 0 --expire 3600
atem token rtc decode <token>           # Decode existing RTC token
atem token rtm create                   # Generate Signaling (RTM) token
atem token rtm create --user-id bob --expire 3600
atem token rtm decode <token>           # Decode existing Signaling (RTM) token
```

### Projects

```bash
atem list project                       # List Agora projects
atem list project --show-certificates   # List with app certificates visible
atem project use <N>                    # Set active project by index (1-based)
atem project use <APP_ID>               # Set active project by App ID
atem project show                       # Show current active project
```

### Configuration

```bash
atem config show                        # Show resolved config
atem config set astation_ws <URL>       # Set Astation WebSocket URL
atem config set astation_relay_url <URL> # Set Astation relay URL
atem config clear                       # Clear active project selection
```

### AI Agents

```bash
atem agent list                         # Scan and list detected AI agents
atem agent launch                       # Launch Claude Code as PTY agent
atem agent launch codex                 # Launch Codex as PTY agent
atem agent connect <WS_URL>             # Connect to ACP agent and show info
atem agent prompt <WS_URL> "text"       # Send prompt to ACP agent
atem agent probe <WS_URL>               # Probe URL for ACP support
atem agent visualize "topic"            # Generate visual HTML diagram via ACP agent
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

## TUI Modes

| Mode | Description |
|------|-------------|
| **Main Menu** | Navigate between features |
| **Claude Chat** | Claude Code CLI integration via PTY |
| **Codex Chat** | Codex terminal integration via PTY |
| **Token Gen** | Generate Agora RTC/RTM tokens locally |
| **Projects** | Browse Agora projects via API |

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Linux | x64, arm64 |
| macOS | x64, arm64 |

## Build from Source

```bash
git clone https://github.com/Agora-Build/Atem.git
cd Atem
cargo build --release
# Binary at target/release/atem
```

## Related Projects

- [Astation](https://github.com/Agora-Build/Astation) -- macOS menubar hub that coordinates Chisel, Atem, and AI agents — talk to your coding agent from anywhere
- [Chisel](https://github.com/Agora-Build/chisel) -- Dev panel for visual annotation and UI editing by anyone, including AI agents
- [Vox](https://github.com/Agora-Build/Vox) -- AI latency evaluation platform

## License

MIT

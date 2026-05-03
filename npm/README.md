# @agora-build/atem

A terminal that connects builders, Agora platform, and AI agents. Manage Agora projects and tokens, route tasks between [Astation](https://github.com/Agora-Build/Astation) and AI coding agents, generate diagrams, drive voice-powered coding workflows, and more -- all from a single CLI/TUI.

## Install

```bash
npm install -g @agora-build/atem
```

Or via shell script:

```bash
curl -fsSL https://dl.agora.build/atem/install.sh | bash
```

Both download a prebuilt binary for your platform (linux-x64, linux-arm64, darwin-x64, darwin-arm64).

## Commands

```bash
atem                                    # Launch TUI
atem repl                               # Interactive REPL with AI command interpretation
```

### Authentication

```bash
atem login                              # Log in with Agora Console (opens browser)
atem logout                             # Log out from SSO
```

### Tokens

```bash
atem token rtc create                   # Generate RTC token (interactive)
atem token rtc create --channel test --rtc-user-id 0 --expire 3600
atem token rtc create --channel test --rtc-user-id alice --with-rtm   # RTC + RTM in one token (reuses rtc-user-id)
atem token rtc create --channel test --rtc-user-id 42 --with-rtm --rtm-user-id bob  # Separate RTM account
atem token rtc decode <token>           # Decode existing RTC token
atem token rtm create                   # Generate Signaling (RTM) token
atem token rtm create --rtm-user-id bob --expire 3600
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
atem config convo                       # Interactive wizard to configure ConvoAI agent
atem config convo --validate            # Validate existing config without modifying
atem config convo --config <PATH>       # Use a specific config file
```

### Dev Servers

```bash
atem serv convo                         # Launch ConvoAI test page (HTTPS)
atem serv convo --config ~/convo.toml   # Use custom config
atem serv convo --background            # Detached daemon — POSTs /join, registers, exits
atem serv attach <ID>                   # Open UI bound to a running convo daemon (talk to live agent)
atem serv attach 3                      # …or by index from `atem serv list`
atem serv rtc                           # Launch RTC test page (HTTPS)
atem serv rtc --channel test --port 8443
atem serv rtc --background              # Run as background daemon
atem serv diagrams                      # Host diagrams from SQLite (HTTP)
atem serv diagrams --port 9000
atem serv diagrams --background
atem serv list                          # List running background servers (#, ID, PID, STATUS)
atem serv kill <ID|#>                   # Kill a server (POSTs /leave for convo)
atem serv killall                       # Kill all background servers

# Fleet test loop — {appid} and {ts} are expanded by atem
for i in $(seq -f '%04g' 1 10); do
  atem serv convo --background --channel 'atem-convo-{appid}-{ts}-'$i
  sleep 0.5
done
```

**`serv convo`** — ConvoAI voice agent: live transcription (RTM), preset selection, avatar (Akool, LiveAvatar, Anam), RTC Stats, API History, camera toggle, RTC encryption (key + salt forwarded to the agent), HIPAA mode (routes via `/hipaa/api/...`), audio dump.

`--background` re-execs as a detached daemon: parent POSTs `/join`, registers in `~/.config/atem/servers/<channel>.json`, exits. The daemon polls Agora's `GET /agents/{id}` every 60s and writes the status (RUNNING/IDLE/STOPPED/…) back into the registry — `atem serv list` reads it without making any network calls. `kill`/`killall` SIGTERM the daemon, which catches the signal and POSTs `/leave` before exiting. Daemon log file (`<channel>.log`) contains the `/join` URL and request body with secrets masked.

**`serv attach <id>`** — opens a foreground HTTPS UI bound to a running convo daemon's channel. The page hides Start/Stop because the daemon owns the agent; you Join to talk to the live agent. Encryption / HIPAA / geofence read from the same `convo.toml` so the local SDK matches what the daemon used.

**`serv rtc`** — RTC test page: join/leave, publish/subscribe audio+video, token generation, RTM messaging, RTC encryption (8 modes; gcm2 modes auto-generate a copyable salt).

**`serv diagrams`** — SQLite-backed HTTP server for hosting AI-generated HTML diagrams.

**Channel placeholders** — `--channel` accepts `{appid}` (first 12 chars of the active app id) and `{ts}` (unix epoch seconds at startup). Useful in for-loops to match the auto-gen channel format.

### AI Agents (WIP)

```bash
atem agent list                         # Scan and list detected AI agents
atem agent launch                       # Launch Claude Code as PTY agent
atem agent launch codex                 # Launch Codex as PTY agent
atem agent connect <WS_URL>             # Connect to ACP agent and show info
atem agent prompt <WS_URL> "text"       # Send prompt to ACP agent
atem agent probe <WS_URL>              # Probe URL for ACP support
atem agent visualize "topic"            # Generate visual HTML diagram via ACP agent
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

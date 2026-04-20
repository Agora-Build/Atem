# Atem

A terminal that connects people, Agora platform, and AI agents. Manage Agora projects and tokens, route tasks between [Astation](https://github.com/Agora-Build/Astation) and AI coding agents, generate diagrams, drive voice-powered coding workflows, and more -- all from a single CLI/TUI.

## Install

```bash
npm install -g @agora-build/atem
```

Or via shell script:

```bash
curl -fsSL https://dl.agora.build/atem/install.sh | bash
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
atem login                              # Log in with Agora Console (opens browser)
atem logout                             # Log out from SSO
```

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
atem serv convo                         # Launch ConvoAI test page (HTTPS)
atem serv convo --config ~/convo.toml   # Use custom config file
atem serv convo --background            # Headless mode (no browser)
atem serv rtc                           # Launch RTC test page (HTTPS)
atem serv rtc --channel test --port 8443
atem serv rtc --background              # Run as background daemon
atem serv diagrams                      # Host diagrams from SQLite (HTTP)
atem serv diagrams --port 9000
atem serv diagrams --background
atem serv list                          # List running background servers
atem serv kill <ID>                     # Kill a background server
atem serv killall                       # Kill all background servers
```

**`serv convo`** — ConvoAI voice agent: live transcription (RTM), preset selection, avatar (Akool, LiveAvatar, Anam), RTC Stats, API History, camera toggle.

**`serv rtc`** — RTC test page: join/leave, publish/subscribe audio+video, token generation, RTM messaging.

**`serv diagrams`** — SQLite-backed HTTP server for hosting AI-generated HTML diagrams.

### Configuration

```bash
atem config show                        # Show resolved config
atem config set astation_ws <URL>       # Set Astation WebSocket URL
atem config set astation_relay_url <URL> # Set Astation relay URL
atem config clear                       # Clear active project selection
atem config convo                       # Interactive wizard to configure ConvoAI agent
atem config convo --validate            # Validate ConvoAI config without modifying
atem config convo --config <PATH>       # Use a specific config file
```

The `atem config convo` wizard supports:
- **Segmented pipeline**: pick ASR + LLM + TTS providers individually (10 ASR, 9 LLM, 12 TTS vendors)
- **Multimodal LLM**: OpenAI Realtime, Google Gemini Live (replaces ASR+LLM+TTS)
- **Presets**: use Agora-managed preset bundles, optionally override providers
- **Avatar**: Akool, LiveAvatar, Anam

## How It Works

### Diagram Generation

`atem agent visualize "topic"` sends a prompt to a running AI agent (via ACP), which generates a self-contained HTML diagram and saves it to `~/.agent/diagrams/`. Atem detects the new file, hosts it via `atem serv diagrams`, and opens it in the browser. Use `--url ws://host:port` to target a specific agent.

### TUI Modes

| Mode | Description |
|------|-------------|
| **Token Gen** | Generate Agora RTC/RTM tokens locally |
| **Projects** | Browse and select Agora projects |
| **Claude Chat** | Claude Code integration via PTY |
| **Codex Chat** | Codex terminal integration via PTY |

### Astation Integration (WIP)

[Astation](https://github.com/Agora-Build/Astation) is a macOS menubar hub that coordinates between [Chisel](https://github.com/Agora-Build/chisel), Atem, and AI agents. It receives annotation tasks from the browser, routes them to the right Atem instance, and tracks task status.

### Voice-Driven Coding (WIP)

Speak to code: Astation captures audio, a ConvoAI agent transcribes it, and Atem routes the text to Claude Code for implementation. Responses flow back as speech.

## Configuration

### Login

```bash
atem login          # Opens browser to log in with Agora Console
```

If the browser redirect doesn't complete within 5 seconds (e.g. remote server), atem will prompt you to paste the callback URL from the browser address bar.

### Storage

Files in `~/.config/atem/`:

| File | Contents | Encryption |
|------|----------|------------|
| `config.toml` | Non-sensitive settings (extra_hostnames, SSO/BFF overrides) | None |
| `convo.toml` | ConvoAI agent config (API keys, provider params) | None (chmod 0600) |
| `credentials.enc` | SSO tokens | AES-256-GCM (machine-bound) |
| `project_cache.enc` | Project list + active project selection | AES-256-GCM (machine-bound) |

Encrypted files are bound to the machine they were created on — copying them to another machine won't decrypt.

### Config file

`~/.config/atem/config.toml`:

```toml
# astation_ws = "ws://127.0.0.1:8080/ws"
# astation_relay_url = "https://station.agora.build"
# bff_url = "https://agora-cli.agora.io"
# sso_url = "https://sso2.agora.io"

# Extra hostnames baked into the self-signed cert + shown as "Custom:" URLs
# extra_hostnames = ["genie.netbird.cloud", "dev.mytailnet.ts.net"]
```

### Environment variable overrides

```bash
ATEM_BFF_URL=...   # Override BFF API base URL
ATEM_SSO_URL=...   # Override SSO base URL
AGORA_APP_ID=...           # Override active project App ID
AGORA_APP_CERTIFICATE=...  # Override active project certificate
```

## Development

```bash
cargo build                       # Debug build
cargo build --release             # Release build
cargo test                        # Run tests (500+ tests)
cargo check                       # Type-check
cargo fmt                         # Format
cargo clippy                      # Lint
./scripts/run-local-dev-tests.sh  # End-to-end CLI smoke test
./scripts/release.sh              # Patch-bump Cargo.toml + commit + tag
./scripts/release.sh 0.5.0        # Explicit version
```

### Release

Releases are tag-driven — pushing `vX.Y.Z` triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds
the binaries and publishes `@agora-build/atem` to npm.

Use `./scripts/release.sh` rather than `git tag` directly — the script keeps
`Cargo.toml` in sync with the tag, so `atem --version` reports the right number.

### Feature Flags

| Flag | Description |
|------|-------------|
| `real_rtm` | Link against Agora RTM SDK (default: stub) |
| `openssl-vendored` | Build OpenSSL from source (for cross-compilation) |

## Related Projects

- [Astation](https://github.com/Agora-Build/Astation) -- macOS menubar hub that coordinates Chisel, Atem, and AI agents — talk to your coding agent from anywhere
- [Chisel](https://github.com/Agora-Build/chisel) -- Dev panel for visual annotation and UI editing by anyone, including AI agents
- [Vox](https://github.com/Agora-Build/Vox) -- AI latency evaluation platform

## License

MIT

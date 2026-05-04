# Atem

A terminal that connects builders, Agora platform, and AI agents. Manage Agora projects and tokens, route tasks between [Astation](https://github.com/Agora-Build/Astation) and AI coding agents, generate diagrams, drive voice-powered coding workflows, and more -- all from a single CLI/TUI.

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
atem project use <APP_ID>               # Set active project by App ID
atem project use <N>                    # Set active project by index (1-based)
atem project show                       # Show current active project
```

### AI Agents (WIP)

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
atem serv convo --background            # Detached daemon — POSTs /join, registers, exits
atem serv attach <ID>                   # Open UI bound to a running convo daemon (talk to live agent)
atem serv attach 3                      # …or by index from `atem serv list`
atem serv rtc                           # Launch RTC test page (HTTPS)
atem serv rtc --channel test --port 8443
atem serv rtc --background              # Run as background daemon
atem serv diagrams                      # Host diagrams from SQLite (HTTP)
atem serv diagrams --port 9000
atem serv diagrams --background
atem serv webhooks                      # Receive Agora webhooks locally (auto-tunneled via ngrok)
atem serv webhooks --no-tunnel          # Local listener only — bring your own tunnel
atem serv webhooks --background         # Run as background daemon
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

`--background` re-execs as a detached daemon: parent POSTs `/join`, registers the agent in `~/.config/atem/servers/<channel>.json`, and exits. The daemon polls Agora's `GET /agents/{id}` every 60s and writes the status (RUNNING/IDLE/STOPPED/…) back into the registry — `atem serv list` reads it without making any network calls. `kill`/`killall` SIGTERM the daemon, which catches the signal and POSTs `/leave` before exiting. The daemon's log file (`<channel>.log`) contains the `/join` URL and request body with secrets masked, useful for debugging encryption mismatches.

**`serv attach <id>`** — opens a foreground HTTPS UI bound to a running convo daemon's channel. The page hides Start/Stop because the daemon owns the agent; you Join to talk to the live agent. Encryption / HIPAA / geofence are read from the same `convo.toml` so the local SDK matches what the daemon used.

**`serv rtc`** — RTC test page: join/leave, publish/subscribe audio+video, token generation, RTM messaging, RTC encryption (8 modes; gcm2 modes auto-generate a copyable salt).

**`serv diagrams`** — SQLite-backed HTTP server for hosting AI-generated HTML diagrams.

**`serv webhooks`** — local receiver for Agora webhook events (ConvoAI: `agent_joined`, `agent_left`, `agent_history`, `agent_error`, `agent_metrics`, …; RTC NCS events). Validates `Agora-Signature-V2` (HMAC-SHA256) when a `secret` is configured in `webhooks.toml`; accepts unsigned events with a banner warning otherwise. Live web console at `http://127.0.0.1:9090/` shows incoming events; each event also prints a one-line summary to stdout. Default tunnel provider is **ngrok** (requires `ngrok config add-authtoken` once); set `tunnel_provider = "cloudflared"` for zero-auth quick tunnels. Use `--no-tunnel` if you're running cloudflared / ngrok separately for stable URLs across atem restarts. See [`configs/webhooks.example.toml`](configs/webhooks.example.toml) for the full config schema.

**Channel placeholders** — `--channel` accepts `{appid}` (first 12 chars of the active app id) and `{ts}` (unix epoch seconds at startup). Useful in for-loops: `--channel 'atem-convo-{appid}-{ts}-001'` produces `atem-convo-2655d20a82fc-1777574763-001`.

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

`convo.toml` also supports routing/security defaults that the web UI pre-fills and `--background` forwards to the agent:

```toml
hipaa    = false            # route via /hipaa/api/... (Agora support must enable for the project)
geofence = "GLOBAL"         # GLOBAL | NORTH_AMERICA | EUROPE | ASIA | JAPAN | INDIA

[encryption]                # mode = 0 → off
mode = 8                    # 1..=8 (Agora's table); 8 = AES_256_GCM2 (recommended)
key  = "your-key-here"
salt = "Q4mTLy5h…="          # base64 32 bytes; required for gcm2 modes (7, 8)
```

The same values flow into both code paths: `serv convo` (web UI form pre-fills, user can override) and `serv convo --background` (forwarded verbatim to ConvoAI's `/join` body). Both peers must use matching encryption/geofence or audio fails silently.

## How It Works

### TUI Modes

| Mode | Description |
|------|-------------|
| **Token Gen** | Generate Agora RTC/RTM tokens locally |
| **Projects** | Browse and select Agora projects |
| **Claude Chat** | Claude Code integration via PTY |
| **Codex Chat** | Codex terminal integration via PTY |

### Diagram Generation

`atem agent visualize "topic"` sends a prompt to a running AI agent (via ACP), which generates a self-contained HTML diagram and saves it to `~/.agent/diagrams/`. Atem detects the new file, hosts it via `atem serv diagrams`, and opens it in the browser. Use `--url ws://host:port` to target a specific agent.

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

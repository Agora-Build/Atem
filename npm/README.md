# @agora-build/atem

Agora AI development terminal. A TUI that connects to [Astation](https://github.com/Agora-Build/Astation) for task routing, runs [Claude Code](https://docs.anthropic.com/en/docs/claude-code) sessions, and generates Agora RTC/RTM tokens.

## Install

```bash
npm install -g @agora-build/atem
```

This downloads a prebuilt binary for your platform (linux-x64, linux-arm64, darwin-x64, darwin-arm64).

## Usage

```bash
atem                              # Launch TUI
atem token rtc create             # Generate RTC token
atem token rtc decode <token>     # Decode existing token
atem list project                 # List Agora projects
atem config show                  # Show current config
```

## Modes

| Mode | Description |
|------|-------------|
| **Main Menu** | Navigate between features |
| **Claude Chat** | Claude Code CLI integration via PTY |
| **Codex Chat** | Codex terminal integration via PTY |
| **Token Gen** | Generate Agora RTC/RTM tokens locally |
| **Projects** | Browse Agora projects via API |

## Astation Pairing

Atem registers with the Station relay service on startup and prints a pairing code:

```
Pairing code: ABCD-EFGH
Open: https://station.agora.build/pair?code=ABCD-EFGH
```

Enter the code in Astation's Dev Console to pair. If a local Astation is running on `ws://127.0.0.1:8080/ws`, Atem connects directly instead.

Override the relay URL:

```bash
AGORA_STATION_RELAY_URL=https://my-relay.example.com atem
```

## Configuration

Create `~/.config/atem/atem.toml`:

```toml
astation_ws = "ws://127.0.0.1:8080/ws"
station_relay_url = "https://station.agora.build"

[agora]
app_id = "your_app_id"
app_certificate = "your_app_certificate"
```

Or use environment variables:

```bash
AGORA_CUSTOMER_ID=...
AGORA_CUSTOMER_SECRET=...
AGORA_STATION_RELAY_URL=...
```

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

- [Astation](https://github.com/Agora-Build/Astation) -- macOS menubar hub for task routing + relay service
- [Chisel](https://github.com/Agora-Build/chisel) -- Dev panel for visual annotation and CSS editing
- [Vox](https://github.com/Agora-Build/Vox) -- AI latency evaluation platform

## License

MIT

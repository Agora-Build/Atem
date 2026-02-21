# Connection Priority Architecture

## Overview

Atem now uses a clear, simple priority cascade for connecting to Astation:

```
1. Local URL (configurable)              ← Same machine / LAN / VPN
2. Relay (wss://station.agora.build/ws)  ← Remote connection
```

The local URL can be configured to support:
- **Same machine**: `ws://127.0.0.1:8080/ws` (default)
- **LAN**: `ws://192.168.1.5:8080/ws` (auto-detected by Astation)
- **VPN**: `ws://100.x.x.x:8080/ws` (Netbird, Tailscale, ZeroTier, etc.)

## Changes Made

### Astation (Server)

**Listen on all interfaces:**
- Changed from `127.0.0.1` to `0.0.0.0` so LAN clients can connect
- Now accessible from:
  - Same machine: `ws://127.0.0.1:8080/ws`
  - LAN: `ws://<local-ip>:8080/ws` (e.g., `ws://192.168.1.5:8080/ws`)
  - Remote: via relay server only

**UI Updates:**
- Settings window now shows detected local network IP addresses
- Astation always listens on all interfaces (`0.0.0.0:8080`)
- Only Station relay URL needs configuration
- Status shows: "Listening on: ws://127.0.0.1:8080/ws, ws://192.168.1.5:8080/ws"
- Info text explains VPN IP configuration for Atem

**Files Modified:**
- `Sources/Menubar/AstationApp.swift` - Listen on `0.0.0.0`, added `getLocalNetworkIP()`
- `Sources/Menubar/SettingsWindowController.swift` - Updated UI, added server status display

### Atem (Client)

**Connection Priority (simplified):**

```rust
// 1. Try configured local URL with session (if available)
config.astation_ws()?session=<id>
// Default: ws://127.0.0.1:8080/ws?session=<id>
// VPN: ws://100.x.x.x:8080/ws?session=<id>

// 2. Try configured local URL direct
config.astation_ws()
// Default: ws://127.0.0.1:8080/ws
// VPN: ws://100.x.x.x:8080/ws

// 3. Try relay with session (if available)
wss://station.agora.build/ws?session=<id>

// 4. Try relay with pairing code
wss://station.agora.build/ws?role=atem&code=<pairing-code>
```

**Configuration:**

For VPN connections (Netbird, Tailscale, ZeroTier), configure the VPN IP in `~/.config/atem/config.toml`:

```toml
astation_ws = "ws://100.64.0.2:8080/ws"  # Netbird IP
# or
astation_ws = "ws://100.100.100.5:8080/ws"  # Tailscale IP
```

For custom relay servers:
```toml
astation_relay_url = "http://100.117.91.44:8080"  # Custom relay
# HTTP/HTTPS base URL - automatically converted to ws:// or wss://
```

Or via environment variables:
```bash
export ASTATION_WS="ws://100.64.0.2:8080/ws"
export ASTATION_RELAY_URL="http://100.117.91.44:8080"
```

**Benefits:**
- Always tries configured local URL first (lowest latency, most stable)
- Supports VPN IPs that Astation can't auto-detect
- Falls back to relay only when needed
- Session-based auth is seamless (no pairing code needed)
- Pairing code is last resort for explicit approval

**Files Modified:**
- `src/app.rs` - Refactored `spawn_astation_connect()` to use `config.astation_ws()`
- `src/config.rs` - Already supports `astation_ws` configuration

## Connection Scenarios

### Same Machine
```
Atem → ws://127.0.0.1:8080/ws → Astation
✅ Direct, fast, no auth needed
✅ Default configuration (no setup required)
```

### Same LAN (Different Machines)
```
Atem → ws://192.168.1.5:8080/ws → Astation
✅ Direct, fast, no relay needed
✅ Configure astation_ws = "ws://192.168.1.5:8080/ws" in Atem config
```

### VPN (Netbird, Tailscale, ZeroTier)
```
Atem → ws://100.64.0.2:8080/ws → Astation (via VPN tunnel)
✅ Direct through VPN, no relay needed
✅ Configure astation_ws = "ws://<vpn-ip>:8080/ws" in Atem config
✅ Astation listens on 0.0.0.0 so VPN interface is accessible
```

### Different Networks (Remote, No VPN)
```
Atem → wss://station.agora.build/ws → Relay → Astation
✅ Via relay server, pairing code or session auth
✅ Fallback when direct connection fails
```

## Security Model

1. **Local connections** - Trusted (localhost or LAN)
2. **Session-based** - After HTTP auth, 30-day TTL
3. **Pairing code** - Explicit approval, short-lived (5 minutes)

## Testing

**Astation:**
- Run on macOS: `swift build && .build/debug/Astation`
- Check logs for network IP: "Network: ws://192.168.1.x:8080"
- Open Settings → Server Info → verify IP displayed

**Atem:**
- Run: `cargo run`
- Watch connection attempts in status bar
- Verify local connection tried first (check Astation logs)
- Disconnect Astation → verify relay fallback works

## Version

- Atem: v0.4.27 (pending release)
- Astation: v0.4.13 (pending release)

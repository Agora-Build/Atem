# Atem + Astation Full Project Roadmap

## Status Overview

| Stage | Project | Name | Size | Status | Blocked By |
|-------|---------|------|------|--------|------------|
| **T0** | Atem | Structural Refactor | M | `done` | — |
| **T1** | Atem | Config + Active Project | M | `done` | T0 |
| **T2** | Atem | Real Token Gen + Time Sync | M | `done` | T1 |
| **T3** | Atem | CLI Command Registry | M | `in_progress` | T2 |
| **T4** | Atem | Real RTM SDK | L | `pending` | T3 |
| **T5** | Atem | Auth & Handshake | M | `pending` | T1, A4, A5 |
| **T6** | Atem | AI REPL | L | `pending` | T3 |
| **T7** | Atem | Voice Kickback | M | `pending` | T4 |
| **T8** | Atem | Voice/Video State Display | S | `pending` | T7 |
| **T9** | Atem | ACP Agent Hub | M | `done` | T3 |
| **T10** | Atem | Agent Visualize | S | `done` | T9 |
| **A0** | Astation | Encrypted Credential Storage | M | `done` | — |
| **A1** | Astation | Settings UI | S | `done` | A0 |
| **A2** | Astation | Real Project Fetching | S | `done` | A1 |
| **A3** | Astation | RTC SDK Integration | L | `in_progress` | A2 |
| **A4** | Astation | Auth Grant Flow | M | `pending` | A3 |
| **A5** | Astation | Cloud Server | L | `pending` | A4 |
| **A6** | Astation | Hotkeys + Multi-Instance | M | `pending` | A5 |

---

## Repositories

| Repo | Path | Stack | Role |
|------|------|-------|------|
| **Atem** | `/home/guohai/Dev/Agora.Build/Atem/` | Rust, TUI/CLI | Execution Hub |
| **Astation** | `/home/guohai/Dev/Agora.Build/Astation/` | Swift 5.9 macOS menu bar + C++17 core | Sensory Hub |
| **Astation Server** | `Astation/server/` (new) | Rust | Cloud backend at `station.agora.build` |

---

## Dependency Graph

```
ASTATION (macOS + Server)              ATEM (Rust)
========================               ===========

A0 (Encrypted Creds)                   T0 (Refactor)
  │                                      │
  v                                      v
A1 (Settings UI)                       T1 (Config + Active Project)
  │                                      │
  v                                      ├──────────────┐
A2 (Real Projects)                     T2 (Tokens)     T5 (Auth) ←── A4 + A5
  │                                      │               │
  v                                      v               v
A3 (RTC SDK) ─── audio/volume ──→     T3 (CLI Cmds)   T6 (AI REPL)
  │               to VAD + Atem          │
  v                                      v
A4 (Auth Grant) ──────────────────→    T4 (Real RTM)
  │                                      │
  v                                      v
A5 (Cloud Server) ────────────────→    T7 (Voice Kickback) ←── A3 (volume data)
  │                                      │
  v                                      v
A6 (Hotkeys + Instances) ────────→    T8 (Voice/Video State Display) ←── A6

                                     T9 (ACP Agent Hub) ←── T3
                                       │
                                       v
                                     T10 (Agent Visualize) ←── T9
```

**Parallelism**:
- Astation A0→A1→A2 and Atem T0→T1→T2→T3 can run fully in parallel
- A3 (RTC SDK) can start after A2 (needs credentials for token generation)
- A4 + A5 must land before T5 (auth needs both sides)
- T6 and T7 can run in parallel
- A6 (hotkeys) owned by Astation → T8 just receives state
- A3 feeds audio to VAD/ASR pipeline and volume data to T7 (voice kickback)

---

## PART 1: ASTATION (macOS App + Server)

### Stage A0: Encrypted Credential Storage

**Status**: `pending`
**Goal**: Add secure storage for `AGORA_CUSTOMER_ID` and `AGORA_CUSTOMER_SECRET` in Astation, encrypted with the machine's hardware UUID. Never store plaintext.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Create | `Sources/Menubar/CredentialManager.swift` | Encrypt/decrypt credentials using machine UUID |
| Create | `Sources/Menubar/MachineIdentity.swift` | Read `IOPlatformUUID` via IOKit |
| Modify | `Sources/Menubar/AstationHubManager.swift` | Load credentials on startup, use for API calls |
| Modify | `Sources/Menubar/StatusBarController.swift` | Add "Settings" menu item |

**Encryption approach**:
- `MachineIdentity.hardwareUUID() -> String` — reads `IOPlatformUUID` via `IOServiceMatching("IOPlatformExpertDevice")` + `IORegistryEntryCreateCFProperty`
- Derive 256-bit key: `HKDF<SHA256>(inputKeyMaterial: hardwareUUID.data, salt: "com.agora.astation", info: "credentials")`
- Encrypt: `AES.GCM.seal(plaintext, using: derivedKey)` via Swift CryptoKit
- Store at: `~/Library/Application Support/Astation/credentials.enc`
- On load: read file → `AES.GCM.open(sealedBox, using: derivedKey)` → parse JSON

**Key types**:
```swift
struct AgoraCredentials: Codable {
    let customerId: String
    let customerSecret: String
}

class CredentialManager {
    func save(_ credentials: AgoraCredentials) throws
    func load() -> AgoraCredentials?
    func delete() throws
    var hasCredentials: Bool { get }
}

struct MachineIdentity {
    static func hardwareUUID() -> String
}
```

---

### Stage A1: Settings UI

**Status**: `pending`
**Goal**: Add a Settings window for entering/updating Agora credentials.

**Complexity**: S

| Action | File | Purpose |
|--------|------|---------|
| Create | `Sources/Menubar/SettingsWindowController.swift` | NSWindow with Customer ID + Secret fields |
| Modify | `Sources/Menubar/StatusBarController.swift` | Add "Settings..." menu item |
| Modify | `Sources/Menubar/AstationHubManager.swift` | Reload credentials after save |

---

### Stage A2: Real Project Fetching

**Status**: `pending`
**Goal**: Replace hardcoded sample projects with real Agora Console API calls.

**Complexity**: S

| Action | File | Purpose |
|--------|------|---------|
| Create | `Sources/Menubar/AgoraAPIClient.swift` | HTTP client for `api.agora.io` |
| Modify | `Sources/Menubar/AstationHubManager.swift` | Fetch real projects |
| Modify | `Sources/Menubar/AstationMessage.swift` | Update `AgoraProject` to match real API fields |

---

### Stage A3: Agora RTC SDK Integration

**Status**: `pending`
**Goal**: Integrate Agora RTC SDK for mic audio, video, and screen sharing.

**Complexity**: L

| Action | File | Purpose |
|--------|------|---------|
| Create | `core/include/astation_rtc.h` | C FFI interface for RTC engine |
| Create | `core/src/astation_rtc.cpp` | RTC engine implementation |
| Create | `Sources/Menubar/RTCManager.swift` | Swift wrapper |
| Modify | `Sources/Menubar/AstationHubManager.swift` | Wire RTC to VAD pipeline |
| Modify | `Sources/Menubar/StatusBarController.swift` | Add mic/camera/screen indicators |
| Modify | `CMakeLists.txt` | Link AgoraRtcKit.framework |
| Modify | `Package.swift` | Add framework search paths |

---

### Stage A4: Auth Grant Flow

**Status**: `pending`
**Goal**: Deep link + Grant/Deny popup for Atem auth requests.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Create | `Sources/Menubar/AuthGrantController.swift` | NSAlert Grant/Deny dialog |
| Modify | `Sources/Menubar/AstationApp.swift` | Register `astation://` URL scheme |
| Modify | `Sources/Menubar/AstationHubManager.swift` | Handle auth requests |
| Modify | `Sources/Menubar/AstationMessage.swift` | Add AuthRequest/AuthResponse |

---

### Stage A5: Astation Cloud Server

**Status**: `pending`
**Goal**: Standalone Rust server at `station.agora.build`.

**Complexity**: L

| Action | File | Purpose |
|--------|------|---------|
| Create | `server/Cargo.toml` | Rust project: axum, tokio, serde, sqlx/sqlite |
| Create | `server/src/main.rs` | HTTP + WebSocket server |
| Create | `server/src/auth.rs` | Session/OTP/token exchange |
| Create | `server/src/routes.rs` | REST endpoints |
| Create | `server/src/session_store.rs` | SQLite persistence |
| Create | `server/src/web/` | Static HTML fallback page |

---

### Stage A6: Global Hotkeys & Multi-Instance

**Status**: `pending`
**Goal**: System-level hotkeys + connected Atem instance management.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Create | `Sources/Menubar/HotkeyManager.swift` | Register global hotkeys |
| Modify | `Sources/Menubar/AstationHubManager.swift` | Hotkey actions, Atem instance list |
| Modify | `Sources/Menubar/StatusBarController.swift` | Show connected Atems |
| Modify | `Sources/Menubar/AstationMessage.swift` | Add VoiceToggle/VideoToggle/AtemInstanceList |
| Modify | `Sources/Menubar/RTCManager.swift` | Wire hotkeys to mute/screen share |

---

## PART 2: ATEM (Rust CLI/TUI)

### Stage T0: Structural Refactor

**Status**: `pending`
**Goal**: Break `main.rs` monolith into modules. No new features.

**Complexity**: M

| Action | File | Contents |
|--------|------|----------|
| Create | `src/app.rs` | `App`, `AppMode`, `TokenInfo`, `AgoraApiProject`, all `impl App` |
| Create | `src/cli.rs` | `Cli`, `Commands`, `TokenCommands`, `RtcCommands`, CLI dispatch |
| Create | `src/tui/mod.rs` | `run_tui()`, event loop, key dispatch |
| Create | `src/tui/draw.rs` | All `draw_*` functions, `style_from_cell`, `centered_rect` |
| Create | `src/agora_api.rs` | `fetch_agora_projects()`, `format_projects()`, `format_unix_timestamp()` |
| Modify | `src/main.rs` | Reduce to `mod` declarations + `#[tokio::main]` entry point |

**Verification**: `cargo test` passes, `cargo run` identical.

---

### Stage T1: Configuration, Credentials & Active Project

**Status**: `pending`
**Goal**: Replace hardcoded constants with `~/.config/atem/config.toml` + env-var overrides. Introduce active project concept.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Create | `src/config.rs` | `AtemConfig` struct, TOML load, env-var overrides, active project |
| Modify | `Cargo.toml` | Add `toml`, `dirs` |
| Modify | `src/app.rs` | Accept `AtemConfig` |
| Modify | `src/cli.rs` | Add `atem config show`, `atem project use <APP_ID>` |

---

### Stage T2: Real Agora Token Generation + Server Time Sync

**Status**: `pending`
**Goal**: Real AccessToken2 with HMAC-SHA256 + server time sync to avoid clock drift.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Rewrite | `src/token.rs` | AccessToken2: HMAC-SHA256, privilege map, binary packing, base64 |
| Create | `src/time_sync.rs` | Server time sync: fetch timestamp, calculate drift, cache offset |
| Modify | `src/cli.rs` | Add `token rtc decode`, `token rtm create` |
| Modify | `Cargo.toml` | Add `hmac`, `sha2`, `rand` |

---

### Stage T3: Expanded CLI Command Registry

**Status**: `pending`
**Goal**: Core Agora operations as non-interactive CLI commands.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Modify | `src/cli.rs` | Add `list project`, `project use`, `project show` |
| Extend | `src/agora_api.rs` | Add `fetch_project_by_id()`, CLI table formatter |

---

### Stage T4: Real RTM SDK Integration

**Status**: `pending`
**Goal**: Replace C++ stub with real Agora RTM SDK.

**Complexity**: L

| Action | File | Purpose |
|--------|------|---------|
| Rewrite | `native/src/atem_rtm.cpp` | Real RTM 2.x SDK |
| Modify | `native/include/atem_rtm.h` | Add new functions |
| Modify | `build.rs` | Link real SDK libs |
| Modify | `src/rtm_client.rs` | FFI bindings for new functions |

---

### Stage T5: Authentication & Astation Handshake

**Status**: `pending`
**Goal**: `atem login` with OTP + deep link pairing.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Create | `src/auth.rs` | Session mgmt, OTP, deep link, token exchange |
| Modify | `src/cli.rs` | `atem login` command |
| Modify | `src/config.rs` | Store session in `session.json` |
| Modify | `src/websocket_client.rs` | AuthRequest/AuthResponse messages |
| Modify | `src/app.rs` | Session check at startup |

---

### Stage T6: AI REPL

**Status**: `pending`
**Goal**: Interactive shell — natural language to Atem commands.

**Complexity**: L

| Action | File | Purpose |
|--------|------|---------|
| Create | `src/repl.rs` | REPL loop: readline, LLM, intent parse, confirm, execute |
| Create | `src/ai_client.rs` | HTTP client for LLM API |
| Modify | `src/cli.rs` | Add `atem repl` command |
| Modify | `Cargo.toml` | Add `rustyline` |

---

### Stage T7: Voice Kickback (Audio-Reactive TUI)

**Status**: `pending`
**Goal**: Border vibration + chromatic oscillation driven by volume.

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Create | `src/tui/voice_fx.rs` | Border vibration + color oscillation |
| Modify | `src/tui/draw.rs` | Integrate voice effects |
| Modify | `src/websocket_client.rs` | Add `VolumeUpdate` message |
| Modify | `src/app.rs` | Add voice state fields |

---

### Stage T8: Voice/Video State & Multi-Instance Display

**Status**: `pending`
**Goal**: Receive state from Astation, show in TUI.

**Complexity**: S

| Action | File | Purpose |
|--------|------|---------|
| Modify | `src/websocket_client.rs` | Add VoiceToggle/VideoToggle/AtemInstanceList |
| Modify | `src/app.rs` | Add voice_active, video_active, peer_atems fields |
| Modify | `src/tui/draw.rs` | Show mic/video indicators, instance sidebar |

---

### Stage T9: ACP Agent Hub

**Status**: `done`
**Goal**: Discover, connect to, and communicate with ACP agents (Claude Code, Codex) via JSON-RPC 2.0 over WebSocket. Adds agent detection (lockfile scan + port probe), ACP client protocol, agent registry, and CLI commands (`agent list`, `agent connect`, `agent prompt`, `agent probe`).

**Complexity**: M

| Action | File | Purpose |
|--------|------|---------|
| Create | `src/acp_client.rs` | JSON-RPC 2.0 client: initialize, session, prompt, events |
| Create | `src/agent_client.rs` | AgentEvent enum, AgentKind, PTY client abstraction |
| Create | `src/agent_detector.rs` | Lockfile scanning, port probing |
| Create | `src/agent_registry.rs` | Registry of all known agents |
| Modify | `src/cli.rs` | Add `agent list/connect/prompt/probe` commands |
| Modify | `src/app.rs` | Add agent panel, ACP client map, active agent routing |

---

### Stage T10: Agent Visualize

**Status**: `done`
**Goal**: Generate visual HTML diagrams by delegating to a running ACP agent. Supports CLI mode (auto-detect agent, stream events, open browser) and TUI mode (Astation-triggered via `visualizeRequest`/`visualizeResult` messages).

**Complexity**: S

| Action | File | Purpose |
|--------|------|---------|
| Create | `src/agent_visualize.rs` | Prompt builder, fs snapshot/diff, agent URL resolver, browser opener |
| Create | `designs/agent-visualize.md` | Design document |
| Modify | `src/cli.rs` | Add `AgentCommands::Visualize` + handler |
| Modify | `src/websocket_client.rs` | Add `VisualizeRequest` / `VisualizeResult` messages |
| Modify | `src/app.rs` | Add `PendingVisualize`, handler, completion checker |

---

## Verification (per stage)

- **Atem stages**: `cargo build` + `cargo test` + `cargo clippy` + manual smoke test
- **Astation macOS stages**: `swift build` + `swift test` + manual menu bar verification
- **Astation Server**: `cargo build` + `cargo test` + `curl` endpoint tests
- **Cross-project (T5 ↔ A4/A5)**: `atem login` → Astation popup → grant → session stored
- **Cross-project (A3 ↔ T4/T7)**: Astation mic → VAD → ASR → RTM → Atem + volume → voice kickback

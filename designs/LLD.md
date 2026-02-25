# Atem Low-Level Design (LLD)

## Module Architecture

```
src/
├── main.rs              # Entry point, CLI/TUI routing
├── cli.rs               # clap command definitions
├── app.rs               # Application state machine
├── config.rs            # Configuration management
├── auth.rs              # OTP authentication flow
├── token.rs             # AccessToken2 generation
├── time_sync.rs         # Clock synchronization
├── agora_api.rs         # Agora REST API client
├── rtm_client.rs        # RTM FFI wrapper
├── websocket_client.rs  # Astation WebSocket protocol
├── codex_client.rs      # Codex PTY subprocess
├── claude_client.rs     # Claude PTY subprocess
├── ai_client.rs         # Claude API for NLU
├── repl.rs              # Interactive shell
├── acp_client.rs        # ACP JSON-RPC 2.0 over WebSocket
├── agent_client.rs      # Agent event types and PTY client
├── agent_detector.rs    # Lockfile scan + ACP port probe
├── agent_registry.rs    # Registry of known agents
├── agent_visualize.rs   # Diagram generation via ACP agents
├── command.rs           # Task queue and stream buffer
├── dispatch.rs          # Work item dispatcher
└── tui/
    ├── mod.rs           # TUI event loop
    ├── draw.rs          # Ratatui rendering
    └── voice_fx.rs      # Voice visualization
```

---

## Core Modules

### 1. Token Generation (`token.rs`)

**Purpose**: Generate Agora AccessToken2 tokens for RTC and RTM services.

**Key Types**:
```rust
pub struct AccessToken2 {
    app_id: String,
    app_certificate: String,
    expire: u32,
    salt: u32,
    ts: u32,
    services: HashMap<u16, Service>,
}

pub struct Service {
    service_type: u16,
    privileges: HashMap<u16, u32>,
}
```

**Protocol**: AccessToken2 v0.07
- Binary packing with little-endian encoding
- HMAC-SHA256 signature
- Base64 encoding with "007" version prefix
- Privilege levels: join channel, publish audio/video, subscribe

**Public API**:
```rust
pub fn build_token_rtc(app_id, app_cert, channel, uid, role, expire) -> String
pub fn build_token_rtm(app_id, app_cert, user_id, expire) -> String
pub fn decode_token(token: &str) -> Result<TokenInfo>
```

---

### 2. RTM Client (`rtm_client.rs`)

**Purpose**: Async wrapper around native Agora RTM SDK via FFI.

**Architecture**:
```
┌─────────────────────────────────────────────────────┐
│                  RtmClient (Rust)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Connection  │  │  Message    │  │   Event     │ │
│  │  Lifecycle  │  │  Publishing │  │  Receiver   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
│         │                │                │        │
│         └────────────────┴────────────────┘        │
│                          │ FFI                     │
└──────────────────────────┼─────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────┐
│              Native C++ RTM Client                  │
│  • atem_rtm_create/destroy                          │
│  • atem_rtm_connect/disconnect                      │
│  • atem_rtm_login/join_channel                      │
│  • atem_rtm_publish_channel/send_peer               │
└─────────────────────────────────────────────────────┘
```

**Key Types**:
```rust
pub struct RtmClient {
    handle: *mut AtemRtmClient,
    config: RtmConfig,
    event_rx: mpsc::UnboundedReceiver<RtmEvent>,
}

pub enum RtmEvent {
    Connected,
    Disconnected,
    MessageReceived { from: String, message: String },
    Error(String),
}
```

**FFI Bindings** (extern "C"):
```rust
fn atem_rtm_create(config: *const AtemRtmConfig) -> *mut AtemRtmClient;
fn atem_rtm_destroy(client: *mut AtemRtmClient);
fn atem_rtm_connect(client: *mut AtemRtmClient) -> i32;
fn atem_rtm_login(client: *mut AtemRtmClient) -> i32;
fn atem_rtm_join_channel(client: *mut AtemRtmClient) -> i32;
fn atem_rtm_publish_channel(client: *mut AtemRtmClient, msg: *const c_char) -> i32;
fn atem_rtm_send_peer(client: *mut AtemRtmClient, peer: *const c_char, msg: *const c_char) -> i32;
```

---

### 3. WebSocket Client (`websocket_client.rs`)

**Purpose**: Bidirectional communication with Astation.

**Message Protocol** (16 message types):
```rust
pub enum AstationMessage {
    // Request/Response pairs
    ProjectListRequest,
    ProjectListResponse { projects: Vec<AgoraProject> },
    TokenRequest { app_id: String, channel: String, uid: u32 },
    TokenResponse { token: String, expires_at: u64 },
    CodexTaskRequest { task: String, context: Option<String> },
    CodexTaskResponse { output: String, success: bool },
    ClaudeRequest { prompt: String },
    ClaudeResponse { response: String },

    // State management
    StatusUpdate { status: String, details: Option<String> },
    Heartbeat { timestamp: u64 },
    VoiceToggle { enabled: bool },
    VideoToggle { enabled: bool },
    AtemInstanceList { instances: Vec<AtemInstance> },

    // Authentication
    AuthRequest { otp: String, hostname: String },
    AuthResponse { success: bool, session_token: Option<String> },

    // Error handling
    Error { code: i32, message: String },
}
```

**Connection Lifecycle**:
```
1. Connect to wss://station.agora.build/ws
2. Send Heartbeat every 30 seconds
3. Handle messages via mpsc channels
4. Auto-reconnect on disconnect
```

---

### 4. Configuration (`config.rs`)

**File Locations**:
```
~/.config/atem/
├── config.toml          # Main configuration
├── active_project.json  # Currently selected project
└── session.json         # Auth session data
```

**Config Schema**:
```toml
[agora]
customer_id = "..."
customer_secret = "..."

[active_project]
app_id = "..."
app_certificate = "..."
name = "My Project"

[astation]
server_url = "wss://station.agora.build"
```

**Environment Variable Overrides**:
| Variable | Purpose |
|----------|---------|
| `AGORA_CUSTOMER_ID` | API authentication |
| `AGORA_CUSTOMER_SECRET` | API authentication |
| `AGORA_APP_ID` | Active project override |
| `AGORA_APP_CERTIFICATE` | Token signing |
| `ASTATION_WS` | Astation WebSocket endpoint override |
| `AGORA_STATION_RELAY_URL` | Station relay URL override |

---

### 5. Authentication (`auth.rs`)

**OTP Flow**:
```
1. Generate 8-digit OTP: rand::random::<u32>() % 100_000_000
2. Display OTP to user
3. User enters OTP in Astation (or uses deep link)
4. Astation sends AuthRequest via WebSocket
5. Atem validates OTP, returns AuthResponse
6. Session token stored in session.json
```

**Deep Link Format**:
```
astation://auth?otp=12345678&hostname=my-machine
```

**Web Fallback**:
```
https://station.agora.build/auth?otp=12345678&hostname=my-machine
```

---

### 6. Time Synchronization (`time_sync.rs`)

**Purpose**: Ensure accurate token timestamps despite clock drift.

**Algorithm**:
```rust
pub async fn get_server_time_offset() -> i64 {
    // 1. Check cached offset (1-hour TTL)
    if let Some(cached) = OFFSET_CACHE.get() {
        if cached.age < 3600 {
            return cached.offset;
        }
    }

    // 2. Fetch server time via HTTP Date header
    let response = reqwest::get("https://api.agora.io/").await?;
    let server_time = parse_http_date(response.headers().get("Date"))?;

    // 3. Calculate and cache offset
    let offset = server_time - SystemTime::now();
    OFFSET_CACHE.set(offset);

    // 4. Warn if drift > 30 seconds
    if offset.abs() > 30 {
        warn!("Clock drift detected: {} seconds", offset);
    }

    offset
}
```

---

### 7. PTY Clients (`codex_client.rs`, `claude_client.rs`)

**Purpose**: Manage Codex/Claude as interactive PTY subprocesses.

**Architecture**:
```
┌─────────────────────────────────────────────────┐
│              CodexClient / ClaudeClient         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │ PTY Master  │  │ vt100/vte   │  │ Resize  │ │
│  │   (r/w)     │  │  Parser     │  │ Handle  │ │
│  └──────┬──────┘  └──────┬──────┘  └────┬────┘ │
│         │                │               │      │
│         ├────────────────┴───────────────┤      │
│         ▼                                ▼      │
│  ┌─────────────────┐          ┌──────────────┐ │
│  │ mpsc::channel   │          │ SIGWINCH     │ │
│  │ (output_rx)     │          │ forwarding   │ │
│  └─────────────────┘          └──────────────┘ │
└─────────────────────────────────────────────────┘
              │
              ▼ PTY Slave
┌─────────────────────────────────────────────────┐
│         Codex CLI / Claude CLI Process          │
└─────────────────────────────────────────────────┘
```

**Configuration**:
```bash
# Codex
CODEX_CLI_BIN=/usr/local/bin/codex
CODEX_CLI_ARGS="--model gpt-4"

# Claude
CLAUDE_CLI_BIN=/usr/local/bin/claude
CLAUDE_CLI_ARGS="--model claude-3-opus"
```

---

### 8. REPL (`repl.rs`)

**Features**:
- Line editing with rustyline (history, completion)
- Known command detection (exact + fuzzy matching)
- Shell-like argument parsing (quoted strings)
- AI-powered command interpretation
- Y/N confirmation before execution

**Flow**:
```
User Input
    │
    ▼
┌─────────────────────┐
│ Known Command?      │───Yes──▶ Parse & Execute
└─────────┬───────────┘
          │ No
          ▼
┌─────────────────────┐
│ AI Interpretation   │
│ (Claude API)        │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Show CommandIntent  │
│ + Explanation       │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ User Confirms?      │───No───▶ Cancel
└─────────┬───────────┘
          │ Yes
          ▼
      Execute Command
```

---

### 9. TUI (`tui/mod.rs`, `tui/draw.rs`)

**App Modes**:
```rust
pub enum AppMode {
    MainMenu,
    TokenGeneration,
    ClaudeChat,
    CodexChat,
    CommandExecution,
}
```

**Event Loop** (100ms poll interval):
```rust
loop {
    // 1. Poll terminal events
    if crossterm::event::poll(Duration::from_millis(100))? {
        handle_key_event(event)?;
    }

    // 2. Process Astation messages
    while let Ok(msg) = astation_rx.try_recv() {
        handle_astation_message(msg)?;
    }

    // 3. Process RTM events
    while let Ok(event) = rtm_rx.try_recv() {
        handle_rtm_event(event)?;
    }

    // 4. Process PTY output
    while let Ok(output) = codex_rx.try_recv() {
        terminal_parser.process(&output);
    }

    // 5. Redraw
    terminal.draw(|f| draw_ui(f, &app))?;
}
```

**Key Bindings**:
| Key | Action |
|-----|--------|
| `Ctrl+V` | Toggle voice mode (via Astation) |
| `Ctrl+Shift+V` | Toggle video collaboration |
| `Ctrl+B` | Exit Codex/Claude PTY mode |
| `Ctrl+C` | Cancel / Exit |
| `Tab` | Cycle through menu items |

---

### 10. ACP Client (`acp_client.rs`)

**Purpose**: JSON-RPC 2.0 over WebSocket for communicating with ACP agents.

**Key Types**:
```rust
pub struct AcpClient {
    url: String,
    next_id: u64,
    session_id: Option<String>,
    sender: Option<mpsc::UnboundedSender<String>>,
    frame_rx: Option<mpsc::UnboundedReceiver<String>>,
    pending_events: VecDeque<String>,
}
```

**Lifecycle**:
```
1. AcpClient::connect(url) — WebSocket handshake
2. client.initialize() — JSON-RPC initialize, returns AcpServerInfo
3. client.new_session() — creates session, stores session_id
4. client.send_prompt(text) — fire-and-forget into session
5. client.try_recv_event() / drain_events() — poll streaming events
```

---

### 11. Agent Detection (`agent_detector.rs`)

**Purpose**: Discover running ACP agents via lockfile scanning and port probing.

**Detection Strategies**:
```
1. Lockfile scan: ~/.claude/*.lock, ~/.codex/*.lock → parse {port, pid} JSON
2. Port scan: ws://127.0.0.1:8765-8770 → ACP initialize probe (500ms timeout)
```

---

### 12. Agent Visualize (`agent_visualize.rs`)

**Purpose**: Generate visual HTML diagrams by delegating to ACP agents.

**Key Functions**:
```rust
pub fn diagrams_dir() -> PathBuf                              // ~/.agent/diagrams/
pub fn build_visualize_prompt(topic: &str) -> String          // Prompt for HTML generation
pub fn snapshot_diagrams_dir() -> HashMap<PathBuf, SystemTime> // Pre-snapshot .html files
pub fn detect_new_html_files(pre: &HashMap<...>) -> Vec<String> // Diff: new/modified, newest-first
pub async fn resolve_agent_url(explicit: Option<String>) -> Result<String> // Auto-detect agent
pub fn open_html_in_browser(path: &str)                       // Platform-conditional browser open
```

**File Detection Strategy**:
```
Primary:   ACP ToolCall { name: "Write", input.file_path: "...html" }
Fallback:  Filesystem snapshot diff (before vs after prompt completion)
```

**TUI Integration** (`app.rs`):
```rust
pub struct PendingVisualize {
    pub session_id: String,
    pub relay_url: Option<String>,
    pub sent_at: Instant,
    pub pre_snapshot: HashMap<PathBuf, SystemTime>,
    pub detected_file: Option<String>,
    pub output_snapshot_len: usize,
    pub last_output_at: Instant,
}
```

Completion detected by 3 seconds of PTY output inactivity.

---

## Native FFI Layer

### Header (`native/include/atem_rtm.h`)

```c
typedef struct AtemRtmClient AtemRtmClient;

typedef struct {
    const char* app_id;
    const char* token;
    const char* channel;
    const char* client_id;
} AtemRtmConfig;

typedef void (*AtemRtmMessageCallback)(
    const char* from,
    const char* message,
    void* user_data
);

// Lifecycle
AtemRtmClient* atem_rtm_create(const AtemRtmConfig* config);
void atem_rtm_destroy(AtemRtmClient* client);

// Connection
int atem_rtm_connect(AtemRtmClient* client);
int atem_rtm_disconnect(AtemRtmClient* client);
int atem_rtm_login(AtemRtmClient* client);
int atem_rtm_join_channel(AtemRtmClient* client);

// Messaging
int atem_rtm_publish_channel(AtemRtmClient* client, const char* message);
int atem_rtm_send_peer(AtemRtmClient* client, const char* peer_id, const char* message);

// Token management
void atem_rtm_set_token(AtemRtmClient* client, const char* token);
int atem_rtm_subscribe_topic(AtemRtmClient* client, const char* topic);
```

### Build Configuration (`build.rs`)

```rust
fn main() {
    // Feature-gated compilation
    let rtm_src = if cfg!(feature = "real_rtm") {
        "native/src/atem_rtm_real.cpp"
    } else {
        "native/src/atem_rtm.cpp"  // Stub for testing
    };

    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .file(rtm_src)
        .include("native/include")
        .compile("atem_rtm");

    // Link Agora SDK (real_rtm feature only)
    if cfg!(feature = "real_rtm") {
        println!("cargo:rustc-link-search=native/third_party/agora/rtm_linux/rtm/sdk/lib");
        println!("cargo:rustc-link-lib=agora_rtm_sdk");
    }
}
```

---

## Data Flow: Voice-Driven Coding

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           ASTATION (macOS)                               │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────────────────┐  │
│  │   Mic   │───▶│WebRTC   │───▶│ Agora   │───▶│    ConvoAI ASR      │  │
│  │ Capture │    │  VAD    │    │  RTC    │    │  (Speech-to-Text)   │  │
│  └─────────┘    └─────────┘    └─────────┘    └──────────┬──────────┘  │
│                                                          │              │
│                                              Transcription│              │
│                                                          ▼              │
│                                               ┌─────────────────────┐   │
│                                               │     Agora RTM       │   │
│                                               │  (publish to Atem)  │   │
│                                               └──────────┬──────────┘   │
└──────────────────────────────────────────────────────────┼──────────────┘
                                                           │
                                                           │ RTM Message
                                                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                              ATEM (Rust)                                 │
│  ┌─────────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │    RTM Client       │───▶│   Transcription │───▶│  Codex Client   │  │
│  │ (receive message)   │    │     Handler     │    │   (PTY exec)    │  │
│  └─────────────────────┘    └─────────────────┘    └────────┬────────┘  │
│                                                              │           │
│                                                    Code/Command          │
│                                                              ▼           │
│                                                   ┌─────────────────┐   │
│                                                   │   TUI Display   │   │
│                                                   │  (ratatui)      │   │
│                                                   └─────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Error Handling

All modules use `anyhow::Result` for error propagation with contextual messages:

```rust
pub fn connect(&mut self) -> Result<()> {
    let result = unsafe { atem_rtm_connect(self.handle) };
    if result != 0 {
        anyhow::bail!("RTM connect failed with code {}", result);
    }
    Ok(())
}
```

---

## Testing Strategy

| Module | Test Type | Coverage |
|--------|-----------|----------|
| `token.rs` | Unit | Roundtrip encoding, privilege levels, expiration |
| `websocket_client.rs` | Unit | Message serialization (60+ tests incl. visualize) |
| `config.rs` | Unit | TOML parsing, env overrides, defaults |
| `auth.rs` | Unit | OTP generation, deep link formatting |
| `time_sync.rs` | Unit | Offset calculation, caching |
| `rtm_client.rs` | Integration | FFI with stub implementation |
| `acp_client.rs` | Unit + Integration | JSON-RPC builders, parsers, mock WS server |
| `agent_detector.rs` | Unit + Integration | Lockfile parsing, port scan, probe result |
| `agent_visualize.rs` | Unit | Prompt format, snapshot diff, file detection, URL resolution |
| `cli.rs` | Unit | CLI parsing (all agent visualize variants) |
| `app.rs` | Unit | PendingVisualize struct construction and clone |

Run all tests:
```bash
cargo test
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `AGORA_CUSTOMER_ID` | — | Agora Console API authentication |
| `AGORA_CUSTOMER_SECRET` | — | Agora Console API authentication |
| `AGORA_APP_ID` | — | Override active project app ID |
| `AGORA_APP_CERTIFICATE` | — | Token signing certificate |
| `ASTATION_WS` | `ws://127.0.0.1:8080/ws` | Astation WebSocket endpoint |
| `AGORA_STATION_RELAY_URL` | `https://station.agora.build` | Station relay URL |
| `ATEM_AI_API_URL` | `https://api.anthropic.com` | AI endpoint override |
| `ATEM_AI_MODEL` | `claude-3-haiku-20240307` | AI model selection |
| `CODEX_CLI_BIN` | `codex` | Codex executable path |
| `CODEX_CLI_ARGS` | — | Additional Codex arguments |
| `CLAUDE_CLI_BIN` | `claude` | Claude executable path |
| `CLAUDE_CLI_ARGS` | — | Additional Claude arguments |

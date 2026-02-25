# Agent Visualize — Design Document

## Overview

`atem agent visualize` generates visual HTML diagrams by delegating to a running ACP (Agent Communication Protocol) agent. The agent writes a self-contained HTML file to `~/.agent/diagrams/`, and Atem detects the new file and opens it in the browser.

## Command

```bash
atem agent visualize "WebRTC data flow"                     # Auto-detect agent
atem agent visualize "auth system" --url ws://localhost:8765 # Explicit ACP URL
atem agent visualize "pipeline" --no-browser                 # Skip browser open
atem agent visualize "architecture" --timeout 60000          # Custom timeout (ms)
```

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `topic` | positional | required | Topic or system to visualize |
| `--url` | optional | auto-detect | WebSocket URL of the ACP agent |
| `--timeout` | optional | `120000` | Timeout in milliseconds |
| `--no-browser` | flag | `false` | Skip opening the result in a browser |

## Architecture

### Two Modes

| Mode | Trigger | Agent Protocol | Detection |
|------|---------|---------------|-----------|
| **CLI** | `atem agent visualize "topic"` | ACP (WebSocket JSON-RPC) | ToolCall event + filesystem diff |
| **TUI** | Astation `visualizeRequest` message | Claude PTY | Filesystem diff after inactivity timeout |

### Module: `agent_visualize.rs`

Six public functions:

| Function | Signature | Purpose |
|----------|-----------|---------|
| `diagrams_dir()` | `-> PathBuf` | Returns `~/.agent/diagrams/` |
| `build_visualize_prompt(topic)` | `-> String` | Prompt instructing agent to generate self-contained HTML |
| `snapshot_diagrams_dir()` | `-> HashMap<PathBuf, SystemTime>` | Lists `.html` files with timestamps; creates dir if needed |
| `detect_new_html_files(pre_snapshot)` | `-> Vec<String>` | Compares current state against snapshot, returns new/modified files newest-first |
| `resolve_agent_url(explicit)` | `async -> Result<String>` | Auto-detect: explicit URL > lockfiles > port scan > error with help |
| `open_html_in_browser(path)` | `()` | Platform-conditional: `xdg-open` (Linux), `open` (macOS), `cmd /C start` (Windows) |

## End-to-End Flow

### CLI Mode

```
atem agent visualize "topic"
  |
  +-- resolve_agent_url() --> lockfile scan --> port scan --> error
  |
  +-- AcpClient::connect() --> initialize --> new_session
  |
  +-- snapshot_diagrams_dir() (before)
  |
  +-- build_visualize_prompt(topic) --> send_prompt()
  |
  +-- Poll ACP events:
  |     |-- TextDelta       --> print to stdout
  |     |-- ToolCall { name: "Write", input.file_path: "...html" }
  |     |                   --> detected_file = Some(path)
  |     |-- ToolResult      --> print [done]
  |     |-- Done            --> detect_new_html_files() fallback
  |     |                   --> open_html_in_browser()
  |     |-- Error           --> bail with message
  |     +-- Disconnected    --> bail
  |
  +-- Print file path
```

### TUI Mode (Astation-triggered)

```
Astation --> VisualizeRequest { session_id, topic, relay_url? }
  |
Atem:
  +-- build_visualize_prompt(topic)
  +-- snapshot_diagrams_dir() (before)
  +-- send prompt to Claude PTY
  +-- Set pending_visualize = PendingVisualize { ... }
  |
  +-- Each tick (process_astation_messages):
        check_visualize_completion()
          |-- Output still growing? --> update snapshot, reset timer
          |-- 3s inactivity?
          |     +-- detect_new_html_files(pre_snapshot)
          |     +-- send VisualizeResult { session_id, success, file_path }
          |     +-- Clear pending_visualize
```

## Astation Protocol Messages

### VisualizeRequest (Astation --> Atem)

```json
{
  "type": "visualizeRequest",
  "data": {
    "session_id": "vis-abc123",
    "topic": "WebRTC data flow",
    "relay_url": "https://relay.example.com"   // optional
  }
}
```

### VisualizeResult (Atem --> Astation)

```json
{
  "type": "visualizeResult",
  "data": {
    "session_id": "vis-abc123",
    "success": true,
    "message": "Diagram generated: /home/user/.agent/diagrams/webrtc-flow.html",
    "file_path": "/home/user/.agent/diagrams/webrtc-flow.html"  // optional
  }
}
```

## Agent URL Resolution

Priority chain used when `--url` is not provided:

```
1. Explicit --url argument         (if provided, use directly)
2. Lockfile scan                   (~/.claude/*.lock, ~/.codex/*.lock)
3. Default port scan               (ws://127.0.0.1:8765-8770, ACP probe)
4. Error with help message         (instructions to start an agent)
```

## File Detection Strategy

Two complementary mechanisms:

1. **ACP ToolCall event** (CLI mode only): When the agent calls the `Write` tool with a `file_path` ending in `.html`, Atem captures the path immediately.

2. **Filesystem snapshot diff** (both modes): Before sending the prompt, Atem snapshots all `.html` files in `~/.agent/diagrams/` with their modification times. After the agent finishes, Atem re-scans and returns any new or modified files, sorted newest-first.

The ToolCall method is preferred (immediate, exact path). The snapshot diff is the fallback (works even when ToolCall events are not available, e.g., PTY mode).

## TUI State: PendingVisualize

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

Mirrors the existing `PendingVoiceRequest` pattern. Completion is detected by 3 seconds of PTY output inactivity (vs. 2 seconds for voice requests, since diagram generation involves larger file writes).

## Files Changed

| File | Action | Description |
|------|--------|-------------|
| `src/agent_visualize.rs` | CREATE | Core module: prompt builder, snapshot/diff, URL resolver, browser opener |
| `src/main.rs` | MODIFY | Add `mod agent_visualize;` |
| `src/cli.rs` | MODIFY | Add `AgentCommands::Visualize` variant + CLI handler |
| `src/websocket_client.rs` | MODIFY | Add `VisualizeRequest` / `VisualizeResult` message types + `send_visualize_result()` |
| `src/app.rs` | MODIFY | Add `PendingVisualize` struct, `handle_visualize_request()`, `check_visualize_completion()` |

## Testing

| Module | Tests | Description |
|--------|-------|-------------|
| `agent_visualize.rs` | 8 | Path check, prompt format, snapshot idempotency, new file detection, sorting, URL resolution |
| `cli.rs` | 4 | Parse: basic, with URL, no-browser flag, custom timeout |
| `websocket_client.rs` | 7 | Serde: request deserialize, request without relay_url, roundtrip, result serialize, result without file_path, result roundtrip |
| `app.rs` | 3 | Default is None, field tracking, clone |

## Future Considerations

- **ACP ToolCall detection in TUI mode**: If ACP is used in TUI (via `acp_clients`), ToolCall events could provide immediate file detection without waiting for the inactivity timeout.
- **Multiple diagram output**: The current implementation picks the newest file. A future version could collect all new files and present them as a gallery.
- **Diagram format support**: Currently HTML-only. SVG, PNG, or Mermaid-to-HTML conversion could be added.

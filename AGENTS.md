## Project Overview

Atem is a development terminal that connects human developers, Agora platform, and AI agents. It provides a CLI and TUI for managing Agora projects and tokens, routing tasks between Astation and AI coding agents (Claude Code, Codex), generating visual diagrams, voice-driven coding, and more.

## Architecture

**Core Components:**
- **CLI Core**: Command parsing and execution engine
- **AI Module**: Integration with LLM APIs for natural language understanding  
- **REPL Shell**: Interactive AI-enhanced environment
- **Command Parser**: Hybrid parser with fuzzy matching for intent detection
- **Execution Engine**: Safe command execution with confirmation workflows

**Integration Points:**
- **Astation**: AI-powered work suite providing voice and video collaboration features
- **Voice Session**: Ctrl+V for voice-to-text command input
- **Video Collaboration**: Ctrl+Shift+V for real-time collaboration

## Core Commands

### Token Management
- `atem token rtc create` - Generate RTC access tokens
- `atem token rtc decode` - Decode existing tokens
- `atem token rtm create` - Generate RTM tokens

### Project Management
- `atem list project` - List all projects
- `atem project use <APP_ID|N>` - Set active project
- `atem project show` - Show current active project

### AI Agents
- `atem agent list` - Scan and list detected AI agents (lockfiles + port scan)
- `atem agent connect <WS_URL>` - Connect to ACP agent and show info
- `atem agent prompt <WS_URL> "text"` - Send prompt to ACP agent
- `atem agent probe <WS_URL>` - Probe URL for ACP support
- `atem agent visualize "topic"` - Generate visual HTML diagram via ACP agent
- `atem agent visualize "topic" --url <WS_URL>` - Explicit agent URL
- `atem agent visualize "topic" --no-browser` - Skip browser open

### Interactive Mode
- `atem` - Launch TUI with multiple modes (Claude, Codex, Token Gen, Agent Panel)
- `atem repl` - Interactive REPL with AI command interpretation

## Development Commands

**Rust Project Setup:**
- **Initialize**: `cargo init --name atem`
- **Build**: `cargo build` 
- **Release build**: `cargo build --release`
- **Run**: `cargo run`
- **Run with args**: `cargo run -- [command]`
- **Test**: `cargo test`
- **Check**: `cargo check`
- **Format**: `cargo fmt`
- **Lint**: `cargo clippy --all-targets --all-features`

## Key Dependencies

**CLI Framework**: Consider `clap` for command parsing and subcommands
**HTTP Client**: `reqwest` for Agora API interactions  
**JSON**: `serde` + `serde_json` for API data handling
**Async Runtime**: `tokio` for async operations
**REPL**: `rustyline` for interactive shell functionality
**AI Integration**: HTTP client for LLM API calls
**Config Management**: `config` or `confy` for settings

## Architecture Notes

- **Dual Mode Operation**: Support both direct CLI commands and interactive AI shell
- **Command Confirmation**: Implement y/n prompts for AI-interpreted commands
- **Token Security**: Secure handling and storage of access tokens
- **Error Handling**: Comprehensive error messages and recovery suggestions
- **Plugin Architecture**: Design for future extensibility
- **Session Memory**: Consider persistent context for long-running sessions

## File Structure

```
src/
├── main.rs              # Entry point, CLI/TUI routing
├── app.rs               # TUI state machine, mark task queue
├── cli.rs               # clap command definitions and handlers
├── websocket_client.rs  # Astation WebSocket protocol
├── claude_client.rs     # Claude Code PTY subprocess
├── codex_client.rs      # Codex PTY subprocess
├── acp_client.rs        # ACP JSON-RPC 2.0 over WebSocket
├── agent_client.rs      # Agent event types and PTY client
├── agent_detector.rs    # Lockfile scan + ACP port probe
├── agent_registry.rs    # Registry of known agents
├── agent_visualize.rs   # Diagram generation via ACP agents
├── token.rs             # Agora RTC/RTM token generation
├── config.rs            # Config loading, encrypted credential store
├── auth.rs              # Auth session management
├── agora_api.rs         # Agora REST API client
├── ai_client.rs         # Anthropic API client
├── repl.rs              # Interactive REPL
├── rtm_client.rs        # RTM FFI wrapper
└── tui/
    ├── mod.rs           # TUI event loop
    └── voice_fx.rs      # Voice visualization
designs/
├── agent-visualize.md   # Agent diagram generation architecture
├── HLD.md, LLD.md       # High/low-level design
└── roadmap.md           # Project roadmap
```

## Integration Notes

- **Astation Integration**: Voice (Ctrl+V) and video collaboration (Ctrl+Shift+V) are managed externally
- **Real-time Features**: Voice transcription and collaborative editing handled by Astation
- **API Security**: Implement secure credential storage and token management
- **ACP Agents**: Atem discovers and communicates with Claude Code, Codex, and other ACP agents via JSON-RPC 2.0 over WebSocket
- **Agent Visualize**: Delegates diagram generation to ACP agents; detects output files via ToolCall events or filesystem snapshot diffing; opens in browser. Astation can trigger via `visualizeRequest` message.


# Repository Guidelines

Check the following files for more details:
designs/
    HLD.md

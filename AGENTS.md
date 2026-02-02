## Project Overview

Atem is an intelligent CLI tool for developers working with Agora.io real-time communication platforms. It combines traditional CLI functionality with AI-powered interactive shell capabilities, supporting both precise command execution and natural language assistance.

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

### Project Management  
- `atem list project` - List all projects
- `atem project id` - Display current project ID

### Streaming Operations
- `atem ingress <rtmp_url> <channel> <uid> <access_token>` - Initiate RTMP stream ingress

### Interactive Mode
- `atem` - Launch AI-enhanced REPL environment

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
├── src/
│   ├── main.rs           # Entry point and command dispatcher
│   ├── cli/              # CLI command implementations
│   │   ├── mod.rs
│   │   ├── token.rs      # Token management commands
│   │   ├── project.rs    # Project operations
│   │   └── streaming.rs  # Ingress and streaming commands
│   ├── repl/             # Interactive AI shell
│   │   ├── mod.rs
│   │   └── ai_shell.rs
│   ├── ai/               # AI integration module
│   │   ├── mod.rs
│   │   └── llm_client.rs
│   ├── agora/            # Agora API client
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   └── api.rs
│   └── config/           # Configuration management
│       ├── mod.rs
│       └── settings.rs
├── tests/                # Integration tests
└── examples/             # Usage examples
```

## Integration Notes

- **Astation Integration**: Voice (Ctrl+V) and video collaboration (Ctrl+Shift+V) are managed externally
- **Real-time Features**: Voice transcription and collaborative editing handled by Astation
- **API Security**: Implement secure credential storage and token management


# Repository Guidelines

Check the following files for more details:
designs/
    HLD.md

Overview
Atem is an intelligent command-line interface (CLI) tool designed specifically for developers working with real-time communication platforms Agora.io. It combines traditional CLI functionality with an AI-powered interactive shell, offering both precise command execution and natural language-driven assistance.

Key Features
1. Comprehensive Multi-Model Commands
Supports core commands related to Agora services, including:

atem token rtc create — Generate RTC access tokens.

atem token rtc decode — Decode tokens.

atem list project — List projects.

atem project id — Display current project ID.

atem ingress <rtmp_url> <channel> <uid> <access_token> — Initiate RTMP stream ingress.

Voice-Enabled Workflow

Voice Session Toggle: Ctrl + V(Managed by Astation) activates and deactivates the voice-to-text input mode.

Real-time Transcription: When active, the tool listens for spoken commands, transcribing them in real time. The transcribed text is displayed in the terminal for user verification.

Command Execution: The transcribed text is sent to the AI-powered shell for interpretation.

Video based collabrating with anyone
Ctrl + Shift + V(Managed by Astation) to launch real-time collabrating
Astation
Powerful AI based work-suite behind the curtain 

2. Interactive AI-powered Shell
When invoked without arguments (atem), launches an AI-enhanced REPL environment.

with Astation better, more powerful AI based work-suite behind the curtain
generate an 8 digits code(this is from https://astation.agora.build), When I type this code in Astation, this Atem will connect to Astation.

Accepts natural language input to interpret user intent.

Automatically detects recognizable commands and prompts for confirmation before execution.

Provides explanations, suggestions, and command corrections via AI assistance.

Handles free-form queries, offering contextual help and insights related to the platform and commands.

3. Seamless AI & CLI Integration
Blends command precision with conversational AI, enabling a fluid developer experience.

Reduces learning curve by explaining commands, workflows, and token mechanisms on demand.

Supports iterative refinement of commands with user feedback (y/n prompts).

Target Users
Developers building on Agora platforms.

DevOps and platform engineers who need quick, secure token management and streaming control.

Developers who prefer a mix of direct CLI commands and intelligent, conversational assistance.

Value Proposition
Efficiency: Streamlines common tasks with simple commands and AI-driven assistance.

Accessibility: Lowers the barrier to complex platform operations through natural language support.

Innovation: Combines AI conversational interfaces with traditional CLI tools for a next-gen developer experience.

Flexibility: Works both as a straightforward CLI and an interactive AI assistant shell.

High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ATEM (Rust CLI/TUI)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │   CLI Mode  │  │  TUI Mode   │  │  REPL Mode  │  │   Voice Pipeline    ││
│  │   (clap)    │  │  (ratatui)  │  │ (rustyline) │  │   (RTM + Codex)     ││
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘│
│         │                │                │                     │          │
│         └────────────────┴────────────────┴─────────────────────┘          │
│                                    │                                        │
│  ┌─────────────────────────────────▼────────────────────────────────────┐  │
│  │                        Command Dispatcher                             │  │
│  │   • Token commands (RTC/RTM create, decode)                          │  │
│  │   • Project management (list, use, show)                             │  │
│  │   • Auth commands (login, logout)                                    │  │
│  │   • Config display                                                   │  │
│  └─────────────────────────────────┬────────────────────────────────────┘  │
│                                    │                                        │
│  ┌────────────┬────────────┬───────┴───────┬────────────┬────────────────┐ │
│  │            │            │               │            │                │ │
│  ▼            ▼            ▼               ▼            ▼                │ │
│ ┌──────┐  ┌──────┐  ┌───────────┐  ┌────────────┐  ┌─────────────┐      │ │
│ │Token │  │Config│  │ Agora API │  │ WebSocket  │  │ RTM Client  │      │ │
│ │ Gen  │  │Mgmt  │  │  Client   │  │  Client    │  │   (FFI)     │      │ │
│ └──────┘  └──────┘  └───────────┘  └────────────┘  └─────────────┘      │ │
│                                          │               │               │ │
│                                          │               │               │ │
│  ┌───────────────────────────────────────┼───────────────┼─────────────┐ │ │
│  │                            Native FFI │Layer          │             │ │ │
│  │                                       ▼               ▼             │ │ │
│  │                               ┌─────────────────────────────┐       │ │ │
│  │                               │   Agora RTM SDK (C++17)     │       │ │ │
│  │                               └─────────────────────────────┘       │ │ │
│  └─────────────────────────────────────────────────────────────────────┘ │ │
│                                                                           │ │
│  ┌───────────────────────────────────────────────────────────────────────┘ │
│  │                                                                         │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │  │   Codex    │  │   Claude    │  │  AI Client  │                      │
│  │  │  (PTY)     │  │   (PTY)     │  │ (HTTP API)  │                      │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                     │
│  │                                                                         │
└──┴─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ WebSocket / RTM
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ASTATION (macOS Menu Bar App)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │ Mic Capture │  │  WebRTC VAD │  │  ConvoAI    │  │  RTM/RTC Engine     ││
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

**Technology Stack (Implemented)**:

| Layer | Technology | Purpose |
|-------|------------|---------|
| CLI/TUI | Rust + clap + ratatui + crossterm | Command parsing, terminal UI |
| Async Runtime | Tokio | Async I/O, channels, task spawning |
| Networking | reqwest + tokio-tungstenite | HTTP API calls, WebSocket |
| Terminal Emulation | portable-pty + vt100 + vte | Codex/Claude subprocess management |
| Cryptography | hmac + sha2 + base64 | AccessToken2 generation |
| Native FFI | libc + C++17 | Agora RTM SDK integration |
| Configuration | toml + dirs | Config file management |
| Line Editing | rustyline | REPL with history |

Future Considerations
Add plugin architecture for community extensions.

Enhance AI contextual memory for long-running sessions.



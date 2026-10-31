# Atem Roadmap

Where atem is headed. This is a direction, not a contract — items shift as we learn.

**Want to help?** Each committed item below has a tracking issue labelled [`help wanted`](https://github.com/Agora-Build/Atem/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22). Comment on the issue to claim it or ask questions. Build-from-source instructions are in the [README](README.md).

## Upcoming

### Windows support (PowerShell)

atem ships for Linux and macOS today. Native Windows support means `atem` runs in PowerShell — adding the `windows-msvc` build target, verifying the ConPTY/`portable-pty` path, a Windows daemon-detach pattern, and an `install.ps1`.

→ **[#3](https://github.com/Agora-Build/Atem/issues/3)** — best owned by someone who develops on Windows day to day.

### `atem studio` — cloud agents + telephony

A new command family for managing **cloud ConvoAI agents** and bridging them to **phone calls** over a SIP trunk — the CLI/TUI counterpart of Agora's Conversational AI Studio. Distinct from `atem agent` (local Claude Code / Codex agents).

Telephony is provider-agnostic: atem takes generic SIP trunk parameters, so numbers provisioned via Twilio / Telnyx / Exotel all work. Agent definitions reuse the existing `convo.toml` schema.

→ **[#4](https://github.com/Agora-Build/Atem/issues/4)** — large epic; will split into per-phase sub-issues after the Phase 0 API research.

## In progress

Built and usable today, but not yet at their best — actively being improved.

### Astation Integration

[Astation](https://github.com/Agora-Build/Astation) is a macOS menubar hub that coordinates [Chisel](https://github.com/Agora-Build/chisel), atem, and AI agents — it receives annotation tasks from the browser, routes them to the right atem instance, and tracks task status. The integration is partially wired and maturing alongside Astation.

## Under discussion

Not committed yet — being shaped before they become roadmap items. Opinions welcome.

### Talk to Your Project

A voice conversation about what you're building, from your phone or Mac: ask what's going on, brainstorm, and decide what's next, with answers grounded in the project's own context (decisions, design docs, commits and session summaries that Atem curates and, per project and opt-in, uploads for retrieval). When the conversation turns into work, the voice agent uses tool calls to reach the coding agent running in Atem: it asks Claude Code or Codex for more information (live status, its latest replies) or, after reading the request back to you, hands it a task, then tells you when the turn completes. Approvals stay taps on your phone, never voice. An Astation feature on top of Atem's agent chat, approvals and r9 remote access (all shipped); it replaces the earlier voice-coding pipeline, which was removed. Design: [designs/voice-context.md](designs/voice-context.md).

### `atem serv agent <github-repo-url>`

An idea to run an agent directly from an official Agora GitHub repository — `atem serv agent <url>` would fetch and serve it. Scope, security model, and exactly what "serve an agent from a repo" means are all open.

→ Discussion: TBD (open a [Discussion](https://github.com/Agora-Build/Atem/discussions) thread to weigh in).

## Shipped

Recent notable additions (see [releases](https://github.com/Agora-Build/Atem/releases) for the full history):

- Atem Memory (`atem sync`, `atem memory`, `atem skill`) — agents share facts and skills across agents and machines, with fact history and offline search
- `atem vault` — a shared, versioned context store for handing work between agents
- AI agents (`atem agent launch|attach|list|stop`, v0.8.0) — the original Claude Code and Codex CLIs in Atem terminals that outlive the runtime; Astation, your phone and approved services view, control and chat with them over atem-session r9, and answer their permission prompts
- MCP server support in `convo.toml` — agents can call tools from MCP servers
- `atem serv files` — serve a directory/file over HTTPS, with Markdown rendering
- ConvoAI MLLM pipeline (OpenAI Realtime, Gemini Live) end-to-end
- `atem config convo` wizard — interactive ConvoAI agent configuration

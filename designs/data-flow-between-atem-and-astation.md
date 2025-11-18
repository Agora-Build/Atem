Making voice-driven coding practical:
  - Astation listens for speech, runs WebRTC VAD to know when you're talking, and streams that audio through Agora RTC.
  - ConvoAI Engine turns the speech into text, and Astation pushes those transcription chunks over Agora RTM straight to the active Atem.
  - Atem receives the text, drops it into the Codex pipeline, and Codex can execute commands or craft code, so you can drive development just by speaking.
  - Keyboard input is still there when you want it, but the voice path covers end-to-end command entry and code generation.

Architecture Snapshot(Automatic Dictation & Transcription)

  - Shared C++17 Core Library (CMake): integrates Agora RTM & RTC SDKs, WebRTC VAD, ConvoAI transcription, and session arbitration; exposes a C API for host apps on macOS (now) and other platforms later.
  - macOS Host App (Swift + ObjC++ bridge): menu-bar UI (Quit, About, Dictation), handles mic capture via AVAudioEngine, feeds audio frames into the core for VAD/transcription control.
  - Atem (Rust): links to a small C FFI shim that wraps Agora RTM operations exposed by the core (or a companion C library), joining channels directly and funneling transcriptions into the Codex workflow.

  VAD Strategy

  - Use the open-source WebRTC VAD library compiled into the C++ core. Mic audio frames are passed from the macOS app to the core; the WebRTC VAD decides "speech vs silence" and drives RTC join/leave and transcription start/stop logic.

  Token Strategy

  - Local generation of Agora RTM/RTC tokens using App ID + App Certificate. The core and Atem share helper code for token creation, abstracted to allow future replacement with a remote token service.

  Implementation Plan

  1. SDK, Token, & VAD Setup
      - Integrate Agora RTM/RTC macOS SDKs (set include paths, link options).
      - Add WebRTC VAD (pull in webrtcvad C library or source) to the core build.
      - Implement shared token generator functions (C++ module + exported C wrapper; provide Rust bindings).
      - Define configuration files/CLI flags to supply App ID, certificate, channel naming.
  2. Message Protocol Design
      - Finalize RTM channel naming and JSON payload schemas: transcription_chunk, activity_ping, active_update, dictation_state, heartbeat, error, token_refresh.
      - Establish metadata requirements (client ID, timestamps, token expirations).
  3. C++ Core Library Modules
      - SignalingClient: wraps Agora RTM (connect/join/send/receive, presence, error handling, local token refresh).
      - RtcAudioClient: manages Agora RTC channel lifecycle, audio streaming hooks, token refresh.
      - VadController: wraps WebRTC VAD; exposes start/stop detection events; configurable sensitivity thresholds.
      - TranscriptionEngine: streams audio (when VAD reports speech) to ConvoAI (REST/streaming) and yields text segments.
      - SessionManager: tracks connected Atem clients, chooses active, enforces 10 s inactivity rule, orchestrates dictation on/off and RTC participation.
      - CoreAPI: expose C functions (init, shutdown, set callbacks, feed audio frames, toggle dictation, query status).
      - Unit tests for token generator, VAD thresholds (with sample audio), session-state transitions, and mocked Agora interactions.
  4. macOS Menu-Bar App
      - Build SwiftUI/AppKit status item with Dictation toggle, active Atem indicator, error notifications.
      - Objective-C++ bridge loads the core library, registers callback handlers, forwards menu actions.
      - AVAudioEngine captures PCM frames (16 kHz/mono); forwards buffers to core for VAD and transcription.
      - Reflect VAD/RTC state in UI (e.g., indicator when speech detected, or dictation idle).
  5. Atem RTM Integration (Rust)
      - Create FFI bindings for minimal RTM client wrapper (connect, join, send, receive, token refresh).
      - Run Tokio task to manage RTM connection with locally generated tokens; send activity_ping on focus/typing; listen for active_update, transcription_chunk.
      - Integrate received transcription into Codex pipeline only when this instance is marked active.
      - Handle token expiry, reconnection, and error surfacing in the TUI.
  6. End-to-End Flow Wiring
      - Dictation ON + active Atem present → Astation joins RTC (local token), starts feeding mic frames through WebRTC VAD.
      - When VAD reports speech, begin streaming audio to ConvoAI; for silence, pause streaming after hangover period.
      - ConvoAI returns transcription text; Astation publishes via RTM targeted at the active Atem ID.
      - Atem validates target, displays text, feeds Codex.
      - No active Atem for 10 s → Astation leaves RTC; Dictation toggle stays on but shows idle; VAD continues monitoring. Dictation off → tear down RTC immediately.
  7. Resilience & Observability
      - Heartbeat messages over RTM to detect disconnects; automatic reconnect with fresh tokens.
      - Logging subsystem in core (configurable level) for VAD events, token refresh, RTM/RTC state, transcription latency/errors.
      - Provide hooks for future telemetry/metrics export.
  8. Testing & Validation
      - C++ unit tests: token generator, VAD detection thresholds (feed sample speech/silence), session manager transitions.
      - Integration tests in C++ with mocked Agora clients and simulated audio streams.
      - Rust integration tests around RTM FFI (using stubs/mocks).
      - Manual macOS QA: multi-Atem scenario, active switching correctness, VAD responsiveness, network drop recovery, token expiry handling, dictation toggle behavior.
  9. Future Token Service Preparation
      - Keep token generation behind interchangeable interfaces in both core and Atem; document API assumptions for external service.
      - Ensure minimal coupling so swapping to remote tokens later means only changing provider implementation.

  Outstanding Decisions

  - Exact parameters for WebRTC VAD (mode, frame size, hangover).
  - How to package/configure Agora SDK binaries alongside the macOS app.
  - Codesigning/notarization plan for macOS distribution.
  - Timeline for packaging the C API for other platforms once macOS MVP stabilizes.
  
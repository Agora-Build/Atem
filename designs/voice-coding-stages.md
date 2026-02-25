# Voice-Driven Coding Implementation Stages

## Overview

Implementation of Agora ConvoAI-based voice coding system with smart buffering.

---

## ✅ Stage 0: Validation Setup (COMPLETED)

**Status:** Ready for testing
**Duration:** 1-2 days
**Blocker:** Must complete before proceeding to other stages

### Completed Items:
- [x] Created test LLM server (`test-llm-server.js`)
- [x] Documented validation procedure (`docs/validation-week0.md`)
- [x] Test server simulates smart buffering (3 empty responses, then real response)

### Next Steps for Stage 0:
1. Start test server: `node test-llm-server.js`
2. Expose via ngrok or public IP
3. Create Agora ConvoAI agent pointing to test endpoint
4. Join RTC channel and speak multi-sentence instructions
5. Verify Agora DOES NOT speak empty responses
6. Document findings and make GO/NO-GO decision

### Success Criteria:
- ✅ Agora skips empty responses (no audio output)
- ✅ Agora continues accepting requests after empty responses
- ✅ Can handle 10+ consecutive empty responses

### Files Created:
```
test-llm-server.js           # Node.js test server for validation
docs/validation-week0.md     # Comprehensive test plan and documentation
```

---

## ✅ Stage 1: Relay Server Foundation (COMPLETED)

**Status:** All tests passing (119 tests)
**Duration:** Completed
**Dependencies:** None (can proceed in parallel with Stage 0 testing)

### Completed Items:
- [x] VoiceSession data model with state machine
- [x] VoiceSessionStore with async waiter mechanism
- [x] LLM proxy endpoint (`/api/llm/chat`) with smart buffering
- [x] Voice session management routes (create, trigger, response, get, delete, list)
- [x] Integrated into main.rs with cleanup tasks
- [x] Comprehensive unit tests (all passing)

### Architecture:
```
VoiceSession States:
  Accumulating → Triggered → ResponseReady
       ↓            ↓            ↓
  (empty resp) (block/wait) (cached resp)
```

### API Endpoints Created:
```
POST   /api/voice-sessions              # Create session (Astation)
GET    /api/voice-sessions              # List all sessions (debug)
GET    /api/voice-sessions/:id          # Get session info (debug)
DELETE /api/voice-sessions/:id          # Delete session
POST   /api/voice-sessions/:id/trigger  # Trigger LLM send (Astation)
POST   /api/voice-sessions/response     # Atem response (Atem)
POST   /api/llm/chat                    # Agora ConvoAI endpoint
```

### Files Created:
```
relay-server/src/voice_session.rs    # State machine, store, tests (395 lines)
relay-server/src/llm_proxy.rs        # Smart buffering endpoint (234 lines)
relay-server/src/voice_routes.rs     # HTTP route handlers (248 lines)
relay-server/src/main.rs             # Integration (updated)
```

### Test Results:
```bash
cd /home/guohai/Dev/Agora.Build/Astation/relay-server
cargo test --bin station-relay-server

test result: ok. 119 passed; 0 failed; 0 ignored; 0 measured
```

---

## ⏳ Stage 2: Astation Integration (PENDING)

**Status:** Ready to start
**Duration:** ~2-3 days
**Dependencies:** Stage 1 complete ✅

### Tasks:
- [ ] VoiceFloatingWindow.swift - Always-on-top UI
  - Status display (joining/recording/processing/completed)
  - Real-time transcription buffer
  - Response display area
  - Auto-close timer (PTT mode)
  - Pause/Leave buttons (Hands-Free mode)

- [ ] VoiceMode.swift - Enum for PTT vs Hands-Free

- [ ] PTTManager.swift - Push-to-Talk mode
  - Ctrl+V hotkey monitoring
  - Auto-join RTC on press
  - Accumulate transcriptions while held
  - Trigger on release
  - Auto-leave after response

- [ ] HandsFreeManager.swift - Persistent session mode
  - Manual join/leave controls
  - Timeout timer (5s default)
  - Keyword detection integration
  - Multiple interaction support

- [ ] TranscriptionAccumulator.swift - Buffer management
  - Receive ASR chunks from Agora
  - Display in floating window
  - Apply timeout triggers
  - Apply keyword triggers

- [ ] TriggerDetector.swift - Keyword matching
  - Regex-based keyword detection
  - User-configurable keyword list
  - Multi-language support
  - Default keywords: "go", "do it", "start", "build it", "execute"

- [ ] VoiceSettings.swift - User preferences
  - Data model + UserDefaults persistence
  - Timeout duration (default 5s)
  - Trigger keywords
  - Keyboard shortcuts
  - Response mode (text-only vs text+voice)

- [ ] VoiceSettingsWindowController.swift - Settings UI
  - SwiftUI settings panel
  - Keyword management list
  - Timeout slider
  - Shortcut customization

- [ ] RTCManager.swift (MODIFY)
  - Add auto-join for PTT mode
  - Add auto-leave after response
  - Track selected Atem ID
  - Expose currentChannel and currentUid

- [ ] StatusBarController.swift (MODIFY)
  - Add "Voice Coding" submenu
  - Add "Push-to-Talk (Ctrl+V)" action
  - Add "Hands-Free Mode..." action
  - Add "Voice Settings..." action

- [ ] AstationHubManager.swift (MODIFY)
  - Create voice session via API
  - Send trigger message to Relay
  - Handle Atem response from Relay
  - Display response in Dev Console + TTS

- [ ] JoinChannelWindowController.swift (MODIFY)
  - Add Atem picker dropdown
  - Show list of connected Atem clients
  - Remember last selected Atem

### Integration Points:
```
User presses Ctrl+V
    ↓
PTTManager.startRecording()
    ↓
RTCManager.autoJoin(channel, selectedAtem)
    ↓
Agora starts sending ASR chunks
    ↓
TranscriptionAccumulator buffers text
    ↓
User releases Ctrl+V
    ↓
PTTManager.stopRecording()
    ↓
POST /api/voice-sessions/:id/trigger → Relay
    ↓
Relay blocks /api/llm/chat, waits for Atem
    ↓
Atem sends response → POST /api/voice-sessions/response
    ↓
Relay wakes waiting request, returns response to Agora
    ↓
Agora TTS speaks response
    ↓
AstationHubManager displays in Dev Console
    ↓
RTCManager.autoLeave()
```

### Files to Create:
```
Sources/Menubar/VoiceFloatingWindow.swift
Sources/Menubar/VoiceMode.swift
Sources/Menubar/PTTManager.swift
Sources/Menubar/HandsFreeManager.swift
Sources/Menubar/TranscriptionAccumulator.swift
Sources/Menubar/TriggerDetector.swift
Sources/Menubar/VoiceSettings.swift
Sources/Menubar/VoiceSettingsWindowController.swift
Sources/Menubar/StatusBarController.swift (modify)
Sources/Menubar/RTCManager.swift (modify)
Sources/Menubar/AstationHubManager.swift (modify)
Sources/Menubar/JoinChannelWindowController.swift (modify)
```

### Testing:
- Unit tests for TriggerDetector (keyword matching)
- Unit tests for VoiceSettings (persistence)
- Integration test: PTT flow (Ctrl+V → trigger → response)
- Integration test: Hands-Free flow (timeout → trigger → response)
- UI test: Floating window display

---

## ⏳ Stage 3: Atem Integration (PENDING)

**Status:** Not started
**Duration:** ~1 day
**Dependencies:** Stage 1 complete ✅

### Tasks:
- [ ] websocket_client.rs (MODIFY)
  - Add VoiceRequest message type
  - Add VoiceResponse message type
  - Handle voice request from Relay
  - Send response directly to Relay

- [ ] app.rs (MODIFY)
  - Handle VoiceRequest in main loop
  - Build prompt from accumulated text
  - Send to Claude Code via PTY
  - Capture Claude response
  - Send VoiceResponse to Relay

### Message Flow:
```
Relay → WebSocket → Atem
{
  "type": "VoiceRequest",
  "session_id": "uuid",
  "accumulated_text": "Create a function that...",
  "channel": "test-channel"
}

Atem → Claude Code PTY
(sends accumulated_text as prompt)

Claude Code → Atem
(response text)

Atem → WebSocket → Relay
{
  "type": "VoiceResponse",
  "session_id": "uuid",
  "response": "Here's the function...",
  "success": true
}
```

### Files to Modify:
```
src/websocket_client.rs      # Add VoiceRequest/Response messages
src/app.rs                    # Handle voice requests, send responses
```

### Testing:
- Unit test: VoiceRequest deserialization
- Unit test: VoiceResponse serialization
- Integration test: Mock Relay → Atem → Claude → Response

---

## ⏳ Stage 4: Agora ConvoAI Configuration (PENDING)

**Status:** Not started (requires Stage 0 validation PASS)
**Duration:** ~1 day
**Dependencies:** Stage 0 validation ✅ GO

### Tasks:
- [ ] Create production Agora ConvoAI agent
- [ ] Configure custom LLM endpoint: `https://relay.agora.build/api/llm/chat`
- [ ] Configure VAD timeout: 800ms
- [ ] Configure Azure TTS voice
- [ ] Test end-to-end flow with real voice
- [ ] Document agent configuration

### Agent Configuration:
```json
{
  "agentId": "atem-voice-coding",
  "properties": {
    "channel": {
      "channelName": "dynamic-per-session"
    },
    "voice": {
      "provider": "azure",
      "voiceName": "en-US-JennyNeural",
      "rate": "0%",
      "pitch": "0%"
    },
    "llm": {
      "provider": "custom",
      "endpoint": "https://relay.agora.build/api/llm/chat",
      "model": "atem-voice-proxy",
      "maxTokens": 2000,
      "temperature": 0.7
    },
    "asr": {
      "language": "en-US",
      "vadTimeout": 800,
      "interimResults": true
    }
  }
}
```

### Testing:
- End-to-end PTT test (Ctrl+V → speak → release → hear response)
- End-to-end Hands-Free test (join → speak → timeout → hear response)
- Keyword trigger test (speak "go" → hear response)
- Latency measurement (target <10s)
- Error handling (timeout, disconnection)

---

## ⏳ Stage 5: Production Readiness (PENDING)

**Status:** Not started
**Duration:** ~2-3 days
**Dependencies:** Stages 1-4 complete

### Tasks:
- [ ] Add Prometheus metrics
  - Voice session count
  - Request latency (ASR → LLM → TTS)
  - Trigger success rate
  - Timeout frequency

- [ ] Add Grafana dashboards
  - Voice coding activity over time
  - Average latency per stage
  - Error rate trends

- [ ] Add alerting rules
  - High latency (>15s)
  - High error rate (>5%)
  - Session leak detection

- [ ] Security hardening
  - Rate limiting on /api/llm/chat
  - Session authentication tokens
  - Log sanitization (remove sensitive voice data)

- [ ] Beta testing
  - 5 internal users for 1 week
  - Collect feedback on UX
  - Monitor costs

- [ ] Documentation
  - User guide (how to use PTT and Hands-Free)
  - Troubleshooting guide
  - Cost estimation guide

### Deployment Checklist:
- [ ] Deploy relay-server to production
- [ ] Configure DNS for relay.agora.build
- [ ] Set up SSL certificates
- [ ] Configure Agora ConvoAI agent
- [ ] Deploy updated Astation to beta users
- [ ] Monitor logs and metrics for 24h
- [ ] Gradual rollout to all users

---

## Summary

### Completed:
- ✅ **Stage 0 Setup:** Test server and validation docs ready
- ✅ **Stage 1:** Relay Server foundation complete (119 tests passing)

### In Progress:
- ⏳ **Stage 0 Testing:** Awaiting Agora empty response validation

### Next Up:
- ⏳ **Stage 2:** Astation Swift UI and integration (can start now)
- ⏳ **Stage 3:** Atem Rust WebSocket integration (can start now)

### Blocked Until Stage 0 Validation:
- ⏳ **Stage 4:** Agora ConvoAI agent creation
- ⏳ **Stage 5:** Production deployment

---

## Timeline Estimate

| Stage | Duration | Status | Can Start |
|-------|----------|--------|-----------|
| Stage 0 Testing | 1-2 days | ⏳ Ready | ✅ Now |
| Stage 1 | Completed | ✅ Done | ✅ Complete |
| Stage 2 | 2-3 days | ⏳ Ready | ✅ Now |
| Stage 3 | 1 day | ⏳ Ready | ✅ Now |
| Stage 4 | 1 day | ⏳ Blocked | ❌ Need Stage 0 GO |
| Stage 5 | 2-3 days | ⏳ Blocked | ❌ Need all prior stages |
| **Total** | **7-10 days** | | |

---

## Critical Path

```
Stage 0 Validation (GO/NO-GO)
    ↓
    ├─ Stage 2 (Astation) ─┐
    ├─ Stage 3 (Atem) ─────┤
    └─ Stage 4 (Agora) ────┴─→ Stage 5 (Production)
```

**Parallelization:** Stages 2 and 3 can be developed in parallel while Stage 0 validation is underway.

---

## Decision Points

### After Stage 0:
- **GO:** Proceed with Option B (Agora ConvoAI + Smart Buffering)
- **NO-GO:** Pivot to Option A (Separate STT/TTS APIs, +1 week timeline)

### After Stage 2+3:
- Local integration testing without Agora (mock voice sessions)
- Verify UI/UX flow before Agora integration

### After Stage 4:
- Beta testing to validate real-world usage
- Cost monitoring before full rollout

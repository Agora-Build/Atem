# Week 0 Validation: Agora Empty Response Testing

**Status:** 🔴 BLOCKER - Must complete before Phase 1 implementation

**Objective:** Validate that Agora ConvoAI properly handles empty `content: ""` responses without triggering TTS or errors.

## Why This Matters

The entire Option B architecture (Relay Server smart buffering) depends on Agora accepting empty responses during the accumulation phase. If Agora speaks empty responses or throws errors, we must pivot to Option A (separate STT/TTS APIs).

## Test Setup

### Prerequisites

1. **Astation credentials:**
   - Agora App ID
   - App Certificate
   - Relay Server secret (for API auth)

2. **Test server:**
   - Node.js installed
   - Port 3100 available
   - Server accessible from Agora (use public IP or ngrok)

### Step 1: Start Test Server

```bash
cd /home/guohai/Dev/Agora.Build/Atem
node test-llm-server.js
```

Expected output:
```
============================================================
Test LLM Server for Agora ConvoAI Validation
============================================================
Server running on port 3100

Configure Agora ConvoAI agent with:
  LLM Endpoint: http://YOUR_IP:3100/api/llm/chat
```

### Step 2: Make Server Publicly Accessible

**Option A: ngrok (recommended for testing)**
```bash
ngrok http 3100
# Use the HTTPS URL provided (e.g., https://abc123.ngrok.io)
```

**Option B: Open firewall port**
```bash
sudo ufw allow 3100/tcp
# Use your public IP (find with: curl ifconfig.me)
```

### Step 3: Create Agora ConvoAI Agent

Use Astation or Agora Console to create a test agent:

**Agent Configuration:**
```json
{
  "agentId": "test-empty-response",
  "properties": {
    "channel": {
      "channelName": "test-voice-coding"
    },
    "voice": {
      "provider": "azure",
      "voiceName": "en-US-JennyNeural"
    },
    "llm": {
      "provider": "custom",
      "endpoint": "https://YOUR_NGROK_URL/api/llm/chat",
      "model": "gpt-4",
      "maxTokens": 1000,
      "temperature": 0.7
    },
    "asr": {
      "language": "en-US",
      "vadTimeout": 800
    }
  }
}
```

**Important:** Replace `YOUR_NGROK_URL` with your actual ngrok or public IP.

### Step 4: Join RTC Channel and Speak

1. **Start Agora agent:**
   ```bash
   # Use Agora REST API or Astation UI
   POST https://api.agora.io/v1/projects/{appId}/agents/{agentId}/start
   ```

2. **Join the same RTC channel** (use Astation or any RTC client)

3. **Speak a multi-sentence instruction slowly:**
   ```
   "Create a new function called calculate total..."
   [pause 1 second - VAD will trigger after 800ms]
   "that takes two parameters..."
   [pause 1 second - VAD will trigger again]
   "and returns their sum..."
   [pause 1 second - VAD will trigger again]
   "multiplied by ten."
   [pause 1 second - final VAD trigger]
   ```

## Expected Behavior (Success Scenario)

### Test Server Logs

```
[Request 1]
User message: Create a new function called calculate total
→ Returning EMPTY response (simulating accumulation)

[Request 2]
User message: that takes two parameters
→ Returning EMPTY response (simulating accumulation)

[Request 3]
User message: and returns their sum
→ Returning EMPTY response (simulating accumulation)

[Request 4]
User message: multiplied by ten
→ Returning REAL response (simulating triggered state)

[Counter reset - ready for next test]
```

### Audio Behavior (What You Hear)

✅ **SUCCESS:** You hear NOTHING after requests 1-3, then hear the full response after request 4:
```
[silence]
[silence]
[silence]
"This is the accumulated response after trigger. The system received your complete instruction."
```

❌ **FAILURE (Pivot to Option A):** You hear anything after requests 1-3:
- Agora speaks "empty" or blank audio
- Agora speaks an error message
- Agora disconnects or stops responding

## Test Variations

### Variation 1: Immediate Empty Response
Modify test server to always return empty:
```javascript
res.json({
  choices: [{
    message: {
      role: 'assistant',
      content: ''
    }
  }]
});
```

**Test:** Speak once, verify Agora doesn't speak anything and keeps listening.

### Variation 2: Whitespace Content
Test with whitespace instead of empty string:
```javascript
content: '   '  // spaces only
content: '\n'   // newline only
```

**Test:** Does Agora treat whitespace differently than empty string?

### Variation 3: Rapid Empty Responses
Speak quickly to trigger VAD every 800ms without pauses.

**Test:** Can Agora handle 10+ empty responses in a row?

## Data Collection

Document the following for each test:

| Test | Empty Response Count | Agora TTS Behavior | Errors/Warnings | Pass/Fail |
|------|---------------------|-------------------|-----------------|-----------|
| Multi-sentence (4 chunks) | 3 | [describe] | [any errors] | ✅/❌ |
| Single sentence (immediate empty) | 1 | [describe] | [any errors] | ✅/❌ |
| Whitespace content | 3 | [describe] | [any errors] | ✅/❌ |
| Rapid fire (10+ chunks) | 10 | [describe] | [any errors] | ✅/❌ |

## GO/NO-GO Decision

### ✅ GO (Proceed with Option B)

**Criteria:**
- Agora DOES NOT speak empty responses
- No errors or disconnections with empty content
- Can handle 10+ consecutive empty responses
- Returns to normal operation after receiving real content

**Next Step:** Begin Phase 1 - Relay Server implementation

### ❌ NO-GO (Pivot to Option A)

**Criteria:**
- Agora speaks empty responses (any audio output)
- Agora throws errors with empty content
- Connection becomes unstable after empty responses

**Next Step:**
1. Abandon Option B architecture
2. Design Option A (separate STT/TTS APIs)
3. Implement without Agora ConvoAI engine

## Timeline

- **Day 1:** Setup test server, create agent, run basic tests
- **Day 2:** Run all variations, document findings, make GO/NO-GO decision

## Questions to Answer

1. ✅ Does Agora accept `content: ""` without speaking?
2. ✅ Does Agora accept whitespace (`"   "`, `"\n"`) differently?
3. ✅ Can Agora handle 10+ consecutive empty responses?
4. ✅ Does Agora provide `session_id` or `conversation_id` in `/api/llm/chat` requests?
5. ✅ What is the actual latency from speech end to TTS start?

## Session Identification Investigation

While testing, inspect the `/api/llm/chat` request headers and body:

```javascript
app.post('/api/llm/chat', (req, res) => {
  console.log('Headers:', req.headers);
  console.log('Body:', JSON.stringify(req.body, null, 2));
  // Look for: session_id, conversation_id, request_id, etc.
});
```

**Goal:** Identify how to link multiple requests from the same user session.

## Cost Estimation

Test costs (minimal):
- Agora ConvoAI: ~$0.01/minute
- Test duration: 30 minutes
- Total: ~$0.30

Production costs will be higher - see architecture review for estimates.

## Rollback Plan

If tests fail:
1. Delete test agent from Agora
2. Remove test server files
3. Design Option A architecture (separate STT/TTS)
4. Estimate new timeline (adds ~1 week for Option A vs Option B)

## Sign-Off

After completing all tests, document findings and get sign-off before proceeding:

**Test Results:** [PASS/FAIL]
**GO/NO-GO Decision:** [GO/NO-GO]
**Tested By:** [Name]
**Date:** [YYYY-MM-DD]
**Approved By:** [Name]

---

**Note:** This validation phase is CRITICAL. Do not skip or rush these tests. The entire Phase 1-4 implementation depends on the outcome.

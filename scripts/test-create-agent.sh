#!/bin/bash
# Create Agora ConvoAI agent for empty response validation
#
# Required env vars:
#   AGORA_APP_ID
#   AGORA_CUSTOMER_ID
#   AGORA_CUSTOMER_SECRET
#   AGENT_TOKEN
#   LLM_ENDPOINT_URL        (e.g. https://your-ngrok.ngrok-free.dev)

set -euo pipefail

: "${AGORA_APP_ID:?Set AGORA_APP_ID}"
: "${AGORA_CUSTOMER_ID:?Set AGORA_CUSTOMER_ID}"
: "${AGORA_CUSTOMER_SECRET:?Set AGORA_CUSTOMER_SECRET}"
: "${AGENT_TOKEN:?Set AGENT_TOKEN}"
: "${LLM_ENDPOINT_URL:?Set LLM_ENDPOINT_URL}"

AUTH=$(echo -n "${AGORA_CUSTOMER_ID}:${AGORA_CUSTOMER_SECRET}" | base64)
AGENT_NAME="test-empty-response-$(date +%s)"

echo "Creating ConvoAI agent: ${AGENT_NAME}"
echo "LLM endpoint: ${LLM_ENDPOINT_URL}/api/llm/chat"
echo ""

curl -v \
  -X POST "https://api.agora.io/api/conversational-ai-agent/v2/projects/${AGORA_APP_ID}/join" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d @- <<BODY
{
  "name": "${AGENT_NAME}",
  "properties": {
    "channel": "test-voice-coding",
    "token": "${AGENT_TOKEN}",
    "agent_rtc_uid": "1001",
    "remote_rtc_uids": ["1002"],
    "enable_string_uid": false,
    "idle_timeout": 120,
    "llm": {
      "url": "${LLM_ENDPOINT_URL}/api/llm/chat",
      "api_key": "test-key",
      "style": "openai",
      "system_messages": [
        {
          "role": "system",
          "content": "You are a helpful voice coding assistant. Respond concisely."
        }
      ],
      "greeting_message": "Hello, voice coding test is ready.",
      "max_history": 10,
      "params": {
        "model": "atem-voice-proxy"
      }
    },
    "asr": {
      "language": "en-US"
    },
    "tts": {
      "vendor": "microsoft",
      "params": {
        "key": "test",
        "region": "eastus",
        "voice_name": "en-US-AndrewMultilingualNeural"
      }
    }
  }
}
BODY

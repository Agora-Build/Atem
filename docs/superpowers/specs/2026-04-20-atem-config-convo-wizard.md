# `atem config convo` — ConvoAI Configuration Wizard

## Goal

Interactive TUI wizard that walks the user through configuring a ConvoAI agent, generates `~/.config/atem/convo.toml`, and validates it. After running the wizard, `atem serv convo` launches with the generated config.

```bash
atem config convo                        # wizard — loads/saves ~/.config/atem/convo.toml
atem config convo --config /path/to.toml # wizard — loads/saves a specific file
atem config convo --validate             # read-only validation of default config
atem config convo --validate --config /path/to.toml  # validate specific file
atem serv convo                          # launch with default config
atem serv convo --config /path/to.toml   # launch with specific config
```

`--config` works the same as `atem serv convo --config` — overrides the default path `~/.config/atem/convo.toml`. Both wizard and validate respect it.

---

## Wizard Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Mode                                                │
│    ○ Preset-based (select from Agora presets)                │
│    ● Custom (pick ASR + LLM + TTS individually)             │
├─────────────────────────────────────────────────────────────┤
│  Step 2: Channel & UIDs                                      │
│    Channel:      [auto-generate]  or  [custom name]          │
│    RTC User ID:  [0]                                         │
│    Agent UID:    [1001]                                      │
│    Idle timeout: [120] seconds                               │
├─────────────────────────────────────────────────────────────┤
│  Step 3: ASR Provider                                        │
│    > Microsoft Azure                                         │
│      Deepgram                                                │
│      OpenAI (Beta)                                           │
│      Speechmatics                                            │
│      ...                                                     │
│    Then: language, api_key, model, vendor-specific params     │
├─────────────────────────────────────────────────────────────┤
│  Step 4: LLM Provider                                        │
│    > OpenAI                                                  │
│      Azure OpenAI                                            │
│      Groq                                                    │
│      Google Gemini                                           │
│      ...                                                     │
│    Then: url, api_key, model, greeting, system prompt        │
├─────────────────────────────────────────────────────────────┤
│  Step 5: TTS Provider                                        │
│    > Microsoft Azure                                         │
│      ElevenLabs                                              │
│      MiniMax                                                 │
│      ...                                                     │
│    Then: api_key, model, voice_id, sample_rate               │
├─────────────────────────────────────────────────────────────┤
│  Step 6: Optional — MLLM                                     │
│    Skip / OpenAI Realtime / Gemini Live / Gemini Vertex      │
├─────────────────────────────────────────────────────────────┤
│  Step 7: Optional — Avatar                                   │
│    Skip / Akool (Beta) / LiveAvatar (Beta) / Anam (Beta)     │
│    Then: avatar_id, api_key                                  │
├─────────────────────────────────────────────────────────────┤
│  Step 8: Advanced Features                                   │
│    [x] Enable RTM (required for transcription)               │
│    [x] Enable SAL                                            │
│    VAD silence: [800] ms                                     │
│    Data channel: [rtm]                                       │
│    Enable word transcription: [yes]                          │
├─────────────────────────────────────────────────────────────┤
│  Step 9: Review & Save                                       │
│    Preview generated TOML                                    │
│    [Save to ~/.config/atem/convo.toml]                       │
│    [Edit again]                                              │
│    [Cancel]                                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Provider Registry

Each provider has a static definition:

```rust
struct ProviderDef {
    name: &'static str,           // "Microsoft Azure"
    vendor_id: &'static str,      // "microsoft" (Agora's vendor string)
    category: Category,           // ASR | LLM | TTS | MLLM | Avatar
    beta: bool,
    required_params: &[ParamDef], // api_key, model, etc.
    optional_params: &[ParamDef],
    docs_url: &'static str,
}

struct ParamDef {
    key: &'static str,      // "api_key"
    label: &'static str,    // "API Key"
    secret: bool,           // mask input
    default: Option<&str>,  // pre-fill
    hint: &'static str,     // "From Azure Portal → Keys"
}
```

### ASR Providers

| Display Name | vendor_id | Required Params |
|---|---|---|
| Microsoft Azure | `microsoft` | api_key, region, language |
| Deepgram | `deepgram` | api_key, model, language |
| OpenAI (Beta) | `openai` | api_key, model, language |
| Speechmatics | `speechmatics` | api_key, language |
| AssemblyAI (Beta) | `assemblyai` | api_key, language |
| Soniox | `soniox` | api_key, model, language |
| Amazon Transcribe (Beta) | `amazon` | access_key, secret_key, region |
| Google (Beta) | `google` | api_key, language |
| Sarvam (Beta) | `sarvam` | api_key, language |

### LLM Providers

| Display Name | vendor_id | Required Params |
|---|---|---|
| OpenAI | `openai` | url, api_key, model |
| Azure OpenAI | `azure` | url, api_key, model |
| Groq | `groq` | url (default: groq endpoint), api_key, model |
| Google Gemini | `gemini` | api_key, model |
| Google Vertex AI | `vertex` | project_id, location, model |
| Claude Anthropic | `anthropic` | api_key, model |
| Amazon Bedrock | `bedrock` | access_key, secret_key, region, model |
| Dify | `dify` | url, api_key |
| Custom LLM | `custom` | url, api_key (optional), model |

### TTS Providers

| Display Name | vendor_id | Required Params | Word Mode |
|---|---|---|---|
| Microsoft Azure | `microsoft` | api_key, region, voice | Yes |
| ElevenLabs | `elevenlabs` | api_key, voice_id, model | Yes |
| MiniMax | `minimax` | key, group_id, model, voice_id | Yes |
| Murf (Beta) | `murf` | api_key, voice_id | No |
| Cartesia (Beta) | `cartesia` | api_key, voice_id | No |
| OpenAI (Beta) | `openai` | api_key, voice, model | No |
| Hume AI (Beta) | `hume` | api_key | No |
| Rime (Beta) | `rime` | api_key, voice | No |
| Fish Audio (Beta) | `fish` | api_key, voice_id | No |
| Google (Beta) | `google` | api_key, voice | No |
| Amazon Polly (Beta) | `polly` | access_key, secret_key, voice_id | No |
| Sarvam (Beta) | `sarvam` | api_key, voice | No |

### Avatar Providers

| Display Name | vendor_id | Required Params |
|---|---|---|
| Akool (Beta) | `akool` | api_key, avatar_id |
| LiveAvatar (Beta) | `liveavatar` | api_key, avatar_id |
| Anam (Beta) | `anam` | api_key, persona_id |

---

## UI Approach

Two options:

### Option A: Terminal prompts (dialoguer-style)

Simple arrow-key selection + text input. No full-screen TUI.

```
? ASR Provider: (use ↑↓, enter to select)
  > Microsoft Azure
    Deepgram
    OpenAI (Beta)
    Soniox
    ...

? API Key: ****************************
? Language: en-US
? Model: (leave empty for default)
```

Pros: lightweight, works over SSH, no screen clearing
Cons: less visual, can't see all config at once

### Option B: ratatui full-screen TUI

Multi-step form with tabs, live TOML preview. Matches atem's existing TUI style.

Pros: polished, can show preview + validation live
Cons: more code, may not work well on minimal terminals

**Recommendation**: Option A (prompts) for v1. Can upgrade to ratatui later.

---

## Implementation

### New files
- `src/convo_wizard.rs` — wizard logic + provider registry
- `src/convo_wizard/providers.rs` — provider definitions (static data)

### Modified files
- `src/cli.rs` — add `ConfigCommands::Convo` subcommand
- `Cargo.toml` — add `dialoguer` dependency (if using Option A)

### TOML Generation

The wizard collects answers into a struct that maps 1:1 to `ConvoConfig`, then serializes via `toml::to_string_pretty`. Secrets are written with `chmod 0600`.

### Validation

Before saving, validate:
1. Required fields present (agent_user_id, at least one of preset/ASR+LLM+TTS)
2. API key format sanity (non-empty, no whitespace)
3. Vendor-param completeness (all required params for chosen vendor filled)
4. Optionally: test-call the LLM endpoint with a simple prompt to verify creds

### Behavior

The wizard ALWAYS loads existing `~/.config/atem/convo.toml` (if it exists) and pre-fills every field with current values. The user tabs through, changing only what they want. Enter on a pre-filled field keeps the existing value.

First run (no config file): all fields start empty/default.
Subsequent runs: all fields show current config. Change one thing, save, done.

### `--validate` mode

Read-only. Parses `~/.config/atem/convo.toml`, checks:
- Required fields present
- Vendor-param completeness
- Known vendor names valid
- API key format sanity

Reports errors/warnings to stdout. Exit 0 if valid, exit 1 if errors.
Never touches the config file.

---

## References

- ASR: https://docs.agora.io/en/conversational-ai/models/asr/overview
- LLM: https://docs.agora.io/en/conversational-ai/models/llm/overview
- TTS: https://docs.agora.io/en/conversational-ai/models/tts/overview
- MLLM: https://docs.agora.io/en/conversational-ai/models/mllm/overview
- Avatar: https://docs.agora.io/en/conversational-ai/models/avatar/overview
- Regional: https://docs.agora.io/en/conversational-ai/best-practices/regional-restrictions
- Filler words: https://docs.agora.io/en/conversational-ai/best-practices/filler-words

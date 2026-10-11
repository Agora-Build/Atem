# atem serv convo — design spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:writing-plans next to produce an implementation plan from this design.

**Goal:** Add `atem serv convo` — a local HTTPS test server for Agora Conversational AI v2. It launches a browser-based UI that starts a ConvoAI agent, joins the same channel as the human, and visualises transcription, agent state, latency, and optional avatar video. A follow-up `atem serv convo wizard` (out of scope here) will build the config file interactively.

**Architecture:** Separate subcommand `atem serv convo` reuses the TLS server scaffolding and token endpoint from `rtc_test_server.rs` via a new shared `web_server/` module. Config comes from a TOML file (default `~/.config/atem/convo.toml`, CLI override via `--config`). The browser drives agent start/stop via local endpoints; atem is the sole bridge to `api.agora.io`, holding all provider secrets. The Agora [Conversational-AI-Demo toolkit](https://github.com/AgoraIO-Community/Conversational-AI-Demo/tree/main/Web/Scenes/VoiceAgent/src/conversational-ai-api) is vendored as a pre-compiled JS bundle; the page uses its public API for transcription and agent events.

**Tech Stack:** Rust, tokio + tokio-rustls (existing), reqwest (existing), toml (existing), AgoraRTC Web SDK 4.23.4+, Agora RTM v2 (2.2.4, already vendored), ConvoAI toolkit (vendored).

---

## 1. CLI surface

```
atem serv convo [OPTIONS]

Options:
      --channel <NAME>       Channel to join. Required unless set in config.
      --rtc-user-id <ID>     Human's RTC uid. Same strict rules as serv rtc:
                             all-digits → int, else string, `s/` prefix forces string.
                             Default "0" (server-assigns) if omitted.
      --agent-user-id <ID>   Agent's RTC uid. Required (CLI > config > hard error).
      --config <PATH>        Override config file. Default ~/.config/atem/convo.toml.
      --port <PORT>          HTTPS port. 0 = auto-assign. Ignored with --background.
      --no-browser           Don't auto-open the browser.
      --background           Daemon mode: no HTTPS server, agent started immediately,
                             lives until the process is killed.
```

Resolution precedence: CLI flag > TOML > default/error. On launch atem prints a one-line summary of what it resolved from where.

---

## 2. Config file (TOML)

Default path: `~/.config/atem/convo.toml`. Written with `chmod 0600` by the wizard (when that exists).

```toml
# Defaults — CLI flags override these.
channel           = "demo"
rtc_user_id       = "42"
agent_user_id     = "1001"
idle_timeout_secs = 120

# Preset shortcut — comma-separated list of Agora preset ids (one per ASR/LLM/TTS).
# When set, [agent.<service>] sections for covered services may be omitted.
preset = "deepgram_nova_3,openai_gpt_5_mini,minimax_speech_2_6_turbo"

[agent.llm]
url              = "https://api.groq.com/openai/v1/chat/completions"
api_key          = "gsk_..."
greeting_message = "Hi, how can I help?"
failure_message  = "Error, please hold on."
max_history      = 32

[[agent.llm.system_messages]]
role    = "system"
content = "You are a helpful agent..."

[agent.llm.params]
model = "openai/gpt-oss-120b"

[agent.asr]
vendor   = "soniox"
language = "en-US"

[agent.asr.params]
api_key        = "..."
model          = "stt-rt-v3"
language_hints = ["en"]

[agent.tts]
vendor = "minimax"

[agent.tts.params]
key                    = "..."
group_id               = "..."
model                  = "speech-02-turbo"
url                    = "wss://api-uw.minimax.io/ws/v1/t2a_v2"
english_normalization  = true

[agent.tts.params.voice_setting]
voice_id = "pvc_voice_pamela_spanish_0919"
emotion  = "angry"

[agent.tts.params.audio_setting]
sample_rate = 44100

# Optional. When absent, the Avatar checkbox on the web page is disabled.
[agent.avatar]
vendor    = "heygen"
avatar_id = "..."

[agent.avatar.params]
# Vendor-specific params, pass-through.
```

**Mapping (TOML → ConvoAI REST `/join` JSON):**

| TOML path | JSON path |
|---|---|
| top-level `channel`, `idle_timeout_secs`, `agent_user_id`, `preset` | `properties.*` |
| `[agent.llm]`, `[agent.asr]`, `[agent.tts]`, `[agent.avatar]` | `properties.{llm,asr,tts,avatar}` |
| `[agent.<svc>.params]` and sub-tables | `properties.<svc>.params` (and nested) |
| `[[agent.llm.system_messages]]` | `properties.llm.system_messages[]` |

Atem additionally inserts:
- `name` — auto-generated `atem-convo-<unix_ts>-<rand4>`
- `properties.token` — generated from active project's app_id + app_certificate (RTC+RTM, for the agent's uid)
- `properties.agent_rtc_uid` — from `agent_user_id`
- `properties.remote_rtc_uids: ["<rtc_user_id>"]` — the human, so the agent knows who to talk to

---

## 3. File layout & refactor

**New code:**

```
src/
├── convo_test_server.rs     # NEW — the subcommand's entrypoint, routes, state
├── convo_config.rs          # NEW — TOML parsing, REST payload builder, validation
└── web_server/              # NEW — shared scaffolding
    ├── mod.rs               # pub struct WebServer, accept loop, TLS glue
    ├── cert.rs              # moved: generate_cert
    ├── request.rs           # moved: read_full_http_request, extract_body, send_response
    └── token_endpoint.rs    # moved: /api/token handler (app_id, cert, optional RTM pin)

assets/
└── convo/
    ├── conversational-ai-api.js   # pre-compiled ESM/IIFE of the upstream TS toolkit
    └── README.md                  # how to rebuild (esbuild command)
```

**Refactor impact on existing code:**
- `rtc_test_server.rs` loses `generate_cert`, `read_full_http_request`, `extract_body`, `send_response`, `handle_token_api` — these move into `web_server/`. Call sites change to `crate::web_server::...`.
- No behaviour change in `serv rtc`. All existing tests for `rtc_test_server` pass unchanged.
- Cargo: no new dependencies. `toml` already present (used for `config.toml`).

---

## 4. HTTP API (interactive mode)

Browser talks only to atem's local HTTPS. Atem is the only caller of `api.agora.io`.

| Method & Path | Purpose | Request | Response |
|---|---|---|---|
| `GET /` | HTML page | — | `text/html` |
| `GET /vendor/agora-rtm-sdk.js` | Vendored RTM SDK (already exists) | — | `application/javascript` |
| `GET /vendor/conversational-ai-api.js` | Vendored ConvoAI toolkit | — | `application/javascript` |
| `POST /api/token` | Shared token endpoint. `serv convo` wires it with `with_rtm: true` always. | `{channel, uid, rtm_user_id?}` | `{token, with_rtm, rtm_user_id, ...}` |
| `POST /api/convo/start` | Start the agent | `{avatar: bool}` | `{agent_id, name, started_at}` or `{error}` |
| `POST /api/convo/stop` | Stop the agent | `{}` | `{stopped: true}` |
| `GET /api/convo/status` | Current state (page refresh / polling) | — | `{running: bool, agent_id?, name?, started_at?, avatar_configured: bool}` |

**Data flow — user clicks Start:**
1. Page has already joined RTC + logged into RTM via `/api/token`.
2. Browser POSTs `/api/convo/start {avatar: true|false}`.
3. Atem:
   - Mints a fresh RTC+RTM token for the agent's uid (from `agent_user_id`), same channel, same expiry as TOML's `idle_timeout_secs * 2` (minimum 3600).
   - Builds the ConvoAI REST body from TOML via the mapping in §2. If `avatar: false` or `[agent.avatar]` is absent, the `avatar` section is omitted from the body.
   - Injects `name`, `properties.token`, `properties.channel`, `properties.agent_rtc_uid`, `properties.remote_rtc_uids`.
   - `POST https://api.agora.io/api/conversational-ai-agent/v2/projects/<app_id>/join` with `Authorization: agora token=<same token>`.
   - Stores `{agent_id, name, started_at}` in process-local state.
4. Browser subscribes to the agent's audio (+ video when avatar enabled) and routes transcription/events through `ConversationalAIAPI`.

**Data flow — Stop / unload:**
1. Browser POSTs `/api/convo/stop`.
2. Atem calls `POST /api/conversational-ai-agent/v2/projects/<app_id>/agents/<agent_id>/leave` with the same Authorization header.
3. State cleared.

**Lifecycle guarantees:**
- At most one active agent per process.
- Shutdown handler (Ctrl+C, SIGTERM) sends `/leave` before exit.
- TOML's `idle_timeout_secs` is the server-side safety net if atem dies unclean.

---

## 5. Background mode

`--background` switches modes:

| | Interactive | Background |
|---|---|---|
| HTTPS server | on | **off** |
| Web page | yes | no |
| Browser RTC join | yes | no |
| ConvoAI agent | started on user click | **started immediately at launch** |
| Registered in `atem serv list` | yes (kind: `convo`, with URL) | yes (kind: `convo`, no URL) |

In background mode: atem reads config, mints token, POSTs `/join`, stashes agent id, runs until signal. `atem serv kill <id>` → SIGTERM → shutdown handler sends `/leave` → exit.

Requires at launch: `--channel` and `--agent-user-id` (CLI or TOML). `--rtc-user-id` is optional — in background mode `remote_rtc_uids` may be empty or populated from TOML (user's external device/client joins on its own).

Flag interactions in background mode:
- `--port`, `--no-browser` are ignored (no server, no browser).
- `--config` still honoured.

Rationale: future use case is an external ConvoAI device that joins the channel independently — atem just keeps the agent alive on the other side of the call.

---

## 6. Web UI (interactive mode)

Three blocks, same visual style as `atem serv rtc`: General / RTC / ConvoAI.

```
┌────────────────────────────────────────────────────────────────┐
│  Welcome to Agora, <random slogan>                             │
├────────────────────────────────────────────────────────────────┤
│  General                                                       │
│    App ID       fb50...9896    [Copy]                          │
│    Channel      demo                                           │
│    Access Token [..................] [Fetch] [Copy]            │
├────────────────────────────────────────────────────────────────┤
│  ● RTC — Disconnected                                          │
│    UID          42    [Join] [Leave] [Mute Mic]                │
│    <local video cell> <agent video cell — visible if avatar>   │
├────────────────────────────────────────────────────────────────┤
│  ● ConvoAI — idle                                              │
│    Agent UID    1001  (read-only)                              │
│    Preset       <preset string or "—">   (read-only)           │
│    [ ] Enable avatar (disabled if [agent.avatar] absent)       │
│    [Start Agent]   [Stop Agent]                                │
│                                                                │
│    ─── Live transcription ───                                  │
│    user:  …                                                    │
│    agent: …                                                    │
│                                                                │
│    ─── Events ───                                              │
│    14:02:03.144  agent.joined (agent_id=a1b2)                  │
│    14:02:04.830  tts.audio   first frame  (latency: 686ms)     │
└────────────────────────────────────────────────────────────────┘
```

**JS integration via the vendored toolkit:**

```js
const convo = await ConversationalAIAPI.init({
  rtcClient,           // the AgoraRTC client used by the RTC block
  rtmClient,           // logged-in RTM client
  renderMode: 'word',  // word-by-word subtitles
});

convo.on('TRANSCRIPT_UPDATED', list => renderTranscript(list));
convo.on('AGENT_STATE_CHANGED', state => setAgentDot(state));
convo.on('AGENT_METRICS',       m    => pushEvent(m));
convo.on('AGENT_INTERRUPTED',   ev   => pushEvent(ev));
convo.on('AGENT_ERROR',         err  => pushEvent(err, 'error'));

await convo.subscribeMessage(agentUid);
```

Transcription panel renders from `TRANSCRIPT_UPDATED`. Events panel concatenates state changes, metrics, interruptions, errors. Latency values come directly from `AGENT_METRICS`.

**UI behaviours:**
- Status dots in block titles: grey=idle, amber=transitioning, green=connected. Same pattern as `serv rtc`.
- Agent UID + Preset are **display-only** on the page. Edits happen via TOML or the future wizard.
- Avatar checkbox: disabled (with tooltip "No avatar configured in TOML") when `/api/convo/status` reports `avatar_configured: false`.
- **Start Agent** is disabled until the browser's RTC is joined (otherwise the agent talks to an empty channel).
- Page refresh mid-session recovers state via `/api/convo/status`.
- Slogan: same mechanism as `serv rtc` — picked randomly once per page load, no rotation.

**Dependencies loaded by the page:**
- `https://download.agora.io/sdk/release/AgoraRTC_N-4.23.4.js` (CDN; bump from 4.23.0)
- `/vendor/agora-rtm-sdk.js` (already vendored)
- `/vendor/conversational-ai-api.js` (new, vendored pre-compiled bundle)

RTC SDK version must be 4.23.4+ so `ENABLE_AUDIO_PTS_METADATA` is available — the toolkit requires it.

---

## 7. Error handling

| Failure | Detection point | Behaviour | User-facing message |
|---|---|---|---|
| TOML missing at default path, no `--config` | Startup | Exit 1 | `No config at ~/.config/atem/convo.toml. Run 'atem serv convo wizard' or pass --config.` |
| TOML malformed / required field missing | Startup | Exit 1, show line | `Config error at convo.toml:L:C — missing field 'agent_user_id'.` |
| CLI flag + TOML conflict | Startup | CLI wins, warn | `Using --channel=demo (overrides 'foo' from config).` |
| No active project | Startup | Same error text as `atem token rtc create` | `No active project. Run 'atem list project', then 'atem project use <N>'.` |
| Agora API 4xx on `/join` | `/api/convo/start` | Return status + truncated body | Toast: `Agent start failed: <status> — <body>` |
| Agora API timeout (30s) | `/api/convo/start` | Return 504 to browser | Toast: `Agent start timed out. Check network / Agora status.` |
| `/leave` fails | Shutdown | Log once, don't block exit | Stderr warning; `idle_timeout_secs` takes over |
| Agent already running + Start clicked | `/api/convo/start` | 409 Conflict | Toast: `Agent already running (id: <short>). Stop it first.` |
| Browser disconnects | Status polling | Agent keeps running | Page refresh restores state |
| Background mode: agent exits unexpectedly | Health-check loop | Log, retry once, then exit | Stderr; daemon stops |
| Toolkit init fails | Page load | Block Start button | "ConvoAI toolkit failed to initialise — check console." |

**Credential safety:**
- TOML may contain provider API keys. Atem never relays them to the browser; the page only talks to local `/api/convo/*`.
- `atem config show` lists `convo.toml` existence but does not dump its contents.
- Atem sets `chmod 0600` on `convo.toml` when writing (via future wizard).

---

## 8. Testing

**Unit tests:**
- TOML → REST JSON mapping (fixture in / JSON out comparison).
- `preset` alone, `preset` + custom overlap, no `preset` (pure custom).
- Avatar section inclusion/omission driven by `{avatar: bool}` input.
- Auto-generated agent `name` uniqueness across rapid successive calls.

**Integration tests (in `run-local-dev-tests.sh`):**
- `atem serv convo --port <X> --no-browser` starts, `GET /` returns HTML with expected blocks and `/vendor/conversational-ai-api.js` script tag, `GET /api/convo/status` returns `{running: false}`.
- `--background` without `--agent-user-id` or `--channel` (and no TOML defaults) exits non-zero with a config error.

**Agent lifecycle test (no real Agora API):**
- Local mock server pretending to be `api.agora.io`; atem is pointed at it via an env var override (new: `ATEM_CONVOAI_API_URL`, default `https://api.agora.io`).
- POST `/api/convo/start` → mock returns `{agent_id: "mock_a1"}` → atem status flips to running.
- POST `/api/convo/stop` → mock returns 200 → atem status clears.
- Failure path: mock returns 400 → atem surfaces error to browser.

**Out of scope for this spec:**
- `atem serv convo wizard` — interactive TOML builder (separate design doc).
- Multiple concurrent agents per process.
- Hot reload of TOML while an agent is running.
- Avatar-vendor-specific integration testing (we pass `[agent.avatar]` through unchanged; upstream owns validation).

---

## 9. Toolkit fetch & freshness pipeline

The Conversational-AI-Demo toolkit upstream is source-only (TypeScript, no npm release). To avoid committing a stale snapshot, automate the fetch + compile as part of the release pipeline.

**New script: `scripts/update-convoai-toolkit.sh`**

```bash
#!/usr/bin/env bash
# Fetch the upstream toolkit, compile to a single browser bundle, and
# write to assets/convo/. Idempotent — running twice produces the same
# output if upstream hasn't changed.
#
# Usage:
#   ./scripts/update-convoai-toolkit.sh          # fetch main @ HEAD
#   ./scripts/update-convoai-toolkit.sh <SHA>    # pin to a specific commit
set -euo pipefail

REPO="https://github.com/AgoraIO-Community/Conversational-AI-Demo.git"
SUBDIR="Web/Scenes/VoiceAgent/src/conversational-ai-api"
REF="${1:-main}"
OUT_DIR="assets/convo"
OUT_FILE="$OUT_DIR/conversational-ai-api.js"
VERSION_FILE="$OUT_DIR/VERSION"

TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT

git clone --depth 50 --branch "$REF" "$REPO" "$TMP" 2>/dev/null \
    || git clone --depth 50 "$REPO" "$TMP"  # if REF is a SHA
cd "$TMP" && git checkout "$REF" 2>/dev/null || true

SHA="$(git -C "$TMP" rev-parse HEAD)"
SRC="$TMP/$SUBDIR"
[[ -d "$SRC" ]] || { echo "Source dir missing at $SRC"; exit 1; }

cd -
npx --yes esbuild "$SRC/index.ts" \
    --bundle --format=iife --global-name=ConversationalAIAPI \
    --target=es2020 --minify \
    --outfile="$OUT_FILE"

{
    echo "upstream: $REPO"
    echo "ref:      $REF"
    echo "sha:      $SHA"
    echo "built:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$VERSION_FILE"

echo "Wrote $OUT_FILE ($(wc -c < "$OUT_FILE") bytes) from $SHA"
```

**Release-time fetch (`.github/workflows/release.yml` addition):**

```yaml
- name: Refresh ConvoAI toolkit
  run: |
    node --version
    ./scripts/update-convoai-toolkit.sh
    # Fail the build if the refresh produced a diff — that means the
    # repo has a stale committed bundle. Releases must ship the latest.
    if ! git diff --quiet -- assets/convo/; then
      echo "ERROR: Committed toolkit is stale. Run the update script locally and commit."
      git --no-pager diff -- assets/convo/
      exit 1
    fi
```

Rationale for the diff-check: the committed bundle is the source of truth for local dev builds. CI refuses to release if the bundle doesn't match upstream, forcing a deliberate update commit before tagging.

**Smoke tests (append to `scripts/run-local-dev-tests.sh`):**

```bash
# assets/convo/conversational-ai-api.js exists and is non-trivial
test -s assets/convo/conversational-ai-api.js
# VERSION marker present with SHA
grep -q '^sha: ' assets/convo/VERSION

# Launch atem serv convo in background, hit /vendor/conversational-ai-api.js
# and verify it serves the committed bundle byte-for-byte.
atem serv convo --port 18190 --no-browser --config tests/fixtures/convo.toml &
# ... curl and compare, then kill
```

**Local dev workflow:**
1. Developer wants to update the toolkit: `./scripts/update-convoai-toolkit.sh`
2. Review `git diff assets/convo/`, commit the new bundle + VERSION.
3. Push. CI's diff-check passes (because the bundle now matches upstream HEAD).

**Pinning (emergency lever):**
If upstream introduces a breaking change, a developer can pin: `./scripts/update-convoai-toolkit.sh <known-good-sha>` and commit. CI's diff-check still passes if the script produces the same bundle for that SHA on every run.

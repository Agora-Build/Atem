# ConvoAI: `atem serv convo` and `atem config convo`

Status: current design (Atem v0.8.0, 2026-11-01).

Code: `src/convo_config.rs` (schema, `/join` body), `src/convo_test_server.rs` (server, page, daemon),
`src/convo_wizard.rs`, `src/web_server/`, `assets/convo/`. Sample: `configs/convo.example.toml`.

## Overview

| Command | What it does |
|---|---|
| `atem config convo` | Wizard that writes `~/.config/atem/convo.toml`. `--validate` checks a file without changing it. |
| `atem serv convo` | Starts an agent from `convo.toml`. Default: a local HTTPS test page. `--background`: a headless daemon. |
| `atem serv attach <id>` | Opens the test page against a running background agent. |
| `atem serv list / kill / killall` | Manage background servers (shared with `serv rtc`, `files`, `webhooks`). |

Atem is the only caller of the ConvoAI REST API; the browser talks to Atem's local server. It needs
an app id and certificate (`AGORA_APP_ID` / `AGORA_APP_CERTIFICATE`, else the current project from
`atem project use`) to mint the agent's RTC+RTM token.

## Configuration

Default path `~/.config/atem/convo.toml`, override with `--config`. A missing file is an error that
points to `atem config convo` and `configs/convo.example.toml`. The file holds API keys: the wizard
writes it `0600`. Precedence: CLI flag, then TOML, then default (or an error).

Unknown keys are a parse error at the top level, in `[atem]`, `[agent]`, `[atem.encryption]`,
`[[atem.environments]]` and each MCP server. Provider blocks (`[agent.llm]`, `asr`, `tts`, `mllm`,
`avatar`) ignore unknown keys. A user id may be a bare TOML integer or a string.

### `[atem]` (read by Atem, not forwarded as is)

| Key | Meaning |
|---|---|
| `channel` | RTC channel. Omitted: `atem-convo-<app_id[..12]>-<unix_ts>-<4 hex>`. `--channel` wins. `{appid}` (first 12 chars of the app id) and `{ts}` expand, so one template works in a shell loop. Sent as `properties.channel`. |
| `rtc_user_id` | The human's RTC uid; `"0"` or omitted means server-assigned. Sent as `properties.remote_rtc_uids[0]`. All digits is an int uid, anything else a string account, `s/` forces a string. |
| `pipeline` | `"cascaded"` or `"mllm"`: which provider blocks go to `/join` (see Pipelines). |
| `env`, `envs`, `[[environments]]`, `hipaa` | REST environment, the page's allowlist, custom environments, and the legacy alias for `env = "hipaa"` (see Environments). |
| `geofence` | `GLOBAL` (default, nothing sent), `NORTH_AMERICA`, `EUROPE`, `ASIA`, `JAPAN`, `INDIA`. Sent as `properties.geofence.area`. |
| `[encryption]` | `mode` 0..=8 (0 off), `key`, `salt` (base64 of 32 bytes, required for modes 7 and 8). |
| `enable_avatar` | Default of the page's Enable Avatar box, and the only switch in `--background`. Default `false` even when `[agent.avatar]` exists, so fleet launches do not use avatar minutes by accident. |
| `poll_interval_secs` | Background status poll. Default 60, floor 5. |

### `[agent]`

| Key | Meaning |
|---|---|
| `user_id` | The agent's RTC uid. Required (or `--agent-user-id`). Sent as `properties.agent_rtc_uid`. |
| `idle_timeout_secs` | Server-side timeout. Sent as `properties.idle_timeout`. Omitted: Agora's default. |
| `preset` | Comma-separated Agora preset names. The page shows one checkbox per name (all checked); the checked names, joined by commas, go in the envelope's `preset`. With none checked, this value is used. |
| `llm`, `asr`, `tts`, `mllm`, `avatar` | Provider blocks. |

### Provider blocks

`[agent.llm]` has `url`, `api_key`, `greeting_message`, `failure_message`, `max_history`,
`[[system_messages]]` (`role`, `content`), `[[mcp_servers]]` and `[params]`.

`asr`, `tts`, `mllm` and `avatar` share one shape: `vendor`, `url`, `api_key`, `greeting_message`,
`language`, `avatar_id`, `[params]` (and `[[mcp_servers]]` on `mllm`). Every `[params]` table, with
its nested tables, goes to `properties.<block>.params` unchanged, so Atem needs no per-vendor code.
A TOML integer above 2^53 can lose precision downstream (JavaScript numbers): quote it
(`group_id = "1967..."`). `--validate` warns about it.

MCP servers (`[[agent.llm.mcp_servers]]` for cascaded, `[[agent.mllm.mcp_servers]]` for mllm) take
`name` (letters and digits, up to 48), `endpoint`, `transport` (`streamable_http`), `headers`,
`allowed_tools` (empty: all; `*` wildcards) and `timeout_ms`. When the active pipeline has any,
Atem sets `advanced_features.enable_tools = true` unless the file sets that key itself.

`[advanced_features]`, `[vad]`, `[sal]` and `[parameters]` (with nested tables such as
`[parameters.transcript]`) are forwarded verbatim as `properties.<name>`. Transcription needs
`advanced_features.enable_rtm = true`, `parameters.data_channel = "rtm"` and
`parameters.transcript.enable_words = true`; without them the agent runs but sends no transcript.

### Pipelines

`cascaded` sends the `llm`, `asr` and `tts` blocks that exist (a preset can stand in for them; the
synonyms `cascade`, `chained` and `segmented` are accepted). `mllm` sends `mllm`, adding
`enable: true`, `input_modalities: ["audio"]` and `output_modalities: ["text","audio"]` unless set.
Both pipelines can sit in one file; the inactive one is not sent. Omitted `pipeline`: detected from
the blocks present; both present without `pipeline` is an error.

### Environments

The REST URL is `{host}/{prefix}/conversational-ai-agent/v2/projects/<app_id>/...`.

| Name | Host | Prefix | Notes |
|---|---|---|---|
| `ga` | `https://api.agora.io` | `api` | Default. |
| `eap` | `https://partner.ai.agora.io` | `preview/api` | Sends `agora-feature: live-models`. Early access; needs allowlisting. |
| `hipaa` | `https://api.agora.io` | `hipaa/api` | Forces geofence `NORTH_AMERICA` and encryption mode 8. |

`[[atem.environments]]` entries (`name`, `host`, `prefix`, `label`, `headers`, `force_geofence`,
`force_encryption_mode`) replace a built-in of the same name or add a new one. No code change is
needed. `envs` limits which environments the page shows; `env` picks the default (clamped to a shown
one). `ATEM_CONVOAI_API_URL` replaces the host of `ga` and `hipaa` (for a proxy or test server).
`/leave` and the status poll use the environment the agent started in.

### Encryption and avatar

With `[atem.encryption].mode > 0`, Atem sends `properties.rtc.{encryption_mode, encryption_key,
encryption_salt}`; the browser SDK must use the same values or audio fails silently. Modes: 1
AES_128_XTS, 2 AES_128_ECB, 3 AES_256_XTS, 4 SM4_128_ECB, 5 AES_128_GCM, 6 AES_256_GCM,
7 AES_128_GCM2, 8 AES_256_GCM2. With no key there is no `rtc` block.

The avatar block is sent only when avatar is enabled (page box, or `enable_avatar` in the
background). It carries `enable`, `vendor`, `params.avatar_id` and the rest of
`[agent.avatar.params]`. Atem adds `agora_uid` (random 5 digits), `agora_channel` (the voice channel)
and `agora_token` unless the file sets them; a pre-minted `agora_token` is used as is, otherwise Atem
mints one from `agora_appid` / `agora_app_cert` in the params or from the current project.
`agora_app_cert` is never sent. Avatar and encryption do not work together (the avatar vendor joins
unencrypted).

### The `/join` body

```
{ "name": "atem-agent-<app_id[..12]>-<ts>-<4 hex>",
  "preset": "<optional>",
  "properties": { "channel", "token", "agent_rtc_uid", "remote_rtc_uids": ["<rtc uid>"],
                  "idle_timeout"?, "llm"/"asr"/"tts" or "mllm", "avatar"?,
                  "advanced_features"?, "vad"?, "sal"?, "parameters"?, "geofence"?, "rtc"? } }
```

`token` is an RTC+RTM token for the agent uid, valid for twice the larger of `idle_timeout_secs` and
3600 s (so at least 7200 s). The request header is `Authorization: agora token=<same token>`, plus
the environment's headers.

## `atem serv convo`

```
atem serv convo [--channel NAME] [--rtc-user-id ID] [--agent-user-id ID] [--config PATH]
                [--port N] [--no-browser] [--background]
```

`--port 0` picks a free port. `--port` and `--no-browser` do nothing with `--background`.

### Interactive mode

The server binds `0.0.0.0` with a self-signed certificate for loopback, the LAN address (as an
`sslip.io` name) and `extra_hostnames` from `config.toml`, so a phone on the LAN can open it. It
prints Local, Network and Custom URLs and opens the browser. It does not register in `serv list`.

| Route | Purpose |
|---|---|
| `GET /`, `/vendor/agora-rtm-sdk.js`, `/vendor/conversational-ai-api.js` | The page, the RTM SDK, the ConvoAI toolkit. |
| `POST /api/token` | RTC+RTM token, 1 h. The page sends its own `rtm_user_id`. |
| `POST /api/convo/start` | Mint token, build body, `POST .../join`. Returns `{agent_id, name, started_at}`. |
| `POST /api/convo/stop` | `POST .../agents/<id>/leave` with a fresh 1 h token. Always clears local state. |
| `GET /api/convo/status`, `/api/convo/history` | `{running, agent_id, name, started_at, avatar_configured}`; the last 200 REST requests and responses (in memory). |

Start body (all optional): `avatar`, `preset`, `env`, `geofence_area`, `encryption_mode`,
`encryption_key`, `encryption_salt`, `enable_dump` (sets `parameters.enable_dump`, a server-side
audio capture retrieved through Agora Support). The page fills them from `convo.toml`. Errors: 409
`agent already running` (one agent per process); an upstream non-2xx status is passed on with its
body in `error`; a transport failure is 502. There is no request timeout.

The page has three blocks: General (app id and project, channel, token, encryption, geofence), RTC
(join, mute, camera, stats) and ConvoAI (environment radios and endpoint, active models, presets,
avatar and audio-dump boxes, Start and Stop, API History, live transcription, events). It loads
AgoraRTC 4.23.4 from Agora's CDN and sets `ENABLE_AUDIO_PTS_METADATA`, which the toolkit needs.

- Start is blocked until RTC is joined. The toolkit is initialised and subscribed before
  `/api/convo/start`, so the greeting's transcript is not missed. It uses the events
  `transcript-updated`, `agent-state-changed`, `agent-interrupted` and `agent-error`.
- A reload asks `/api/convo/status` and shows a running agent again. An environment with `force_*`
  (HIPAA) locks geofence and encryption; the page generates a key and salt if none is configured.
- The Channel and RTC User fields are editable, but `/join` always uses the values resolved at
  start. Change them with flags or `convo.toml`.
- There is no shutdown hook. Press Stop Agent before quitting; if the process dies first,
  `idle_timeout_secs` ends the agent.

### Background mode

`--background` starts no server and no browser. The parent resolves the config, re-executes itself
as a detached daemon, registers it, prints a summary (channel, uids, ID, PID, log path) and exits
without waiting for `/join`. The daemon:

1. Mints the token and posts `/join` (avatar only if `enable_avatar` and `[agent.avatar]`; encryption
   and geofence only from `convo.toml`; preset from `[agent].preset`).
2. Logs the URL and body to `<servers dir>/<channel>.log`, masking values of keys that contain `key`,
   `token`, `secret`, `cert`, `password` or `credential` as `***<N chars>`.
3. Polls `GET .../agents/<id>` every `poll_interval_secs` with the join token and writes
   `last_status` (the response's `status`, `HTTP_<code>` or `ERR`) and `last_checked_at` to its
   registry file.
4. On SIGTERM or SIGINT posts `/leave` with a fresh token (failure ignored), removes its registry
   file and exits. If `/join` fails the daemon exits and the error is in its log.

An environment that forces encryption (HIPAA) is refused in the background unless
`[atem.encryption]` is set, because a headless run cannot generate a key. The use case is an
external client (phone, device) that joins the channel by itself while Atem keeps the agent alive.
`remote_rtc_uids` is `[rtc_user_id]`, which is `["0"]` when unset.

### Registry

Every background server writes `<servers dir>/<id>.json` (`~/.config/atem/servers/`) with `id`,
`pid`, `kind`, `port`, `channel`, URLs, `started_at`, `last_status` and `last_checked_at`. A convo
daemon has `kind = "convo"`, `port = 0`, empty URLs and the channel name as `id`; its log is beside it.

| Command | Behaviour |
|---|---|
| `atem serv list` | Columns `#`, `ID`, `PID`, `PORT`, `STATUS` (`—` before the first poll). Entries whose pid is dead are deleted. |
| `atem serv kill <id\|#>` | SIGTERM, and removes the registry file at once. The daemon then sends `/leave`. |
| `atem serv killall` | The same for every registered server, of any kind. |

### Attach

`atem serv attach <id|#> [--port N] [--no-browser]` works for `kind = "convo"` only. It runs the
interactive server on the daemon's channel, with uids from the default `convo.toml` (attach has no
`--config`, so a daemon started with another file is not matched). The page hides Start and Stop and
locks the settings fixed at `/join` (environment, presets, avatar, encryption, geofence, audio
dump). You join with your own RTC uid and talk to the agent. End it with `atem serv kill`.

### Credentials

- The page does not receive the provider keys, with two exceptions: `GET /api/convo/history` returns
  the `/join` body as sent (keys included), and the page embeds the `[atem.encryption]` key and salt.
- The server has no authentication and listens on all interfaces. Anyone who can reach the port can
  start or stop the agent and read the history. Use it on a trusted network.

### Browser toolkit

`assets/convo/conversational-ai-api.js` is a bundle of the upstream Conversational-AI-Demo toolkit,
embedded in the binary. Do not edit it. `scripts/update-convoai-toolkit.sh` rebuilds it from a pinned
upstream commit (`PINNED_SHA`, in `assets/convo/VERSION`), a committed lockfile and a pinned esbuild,
so two runs give the same bytes (`UPDATE_LOCK=1` re-resolves dependencies). The `toolkit-freshness`
job in `release.yml` fails the release if the committed bundle differs. Upstream has since moved to an
npm package; adopting it is a separate step.

## `atem config convo`

```
atem config convo [--config PATH]              # wizard
atem config convo --validate [--config PATH]   # read-only check
```

### Wizard

The wizard uses plain terminal prompts (`dialoguer`), not a full-screen UI. It loads the existing
file and pre-fills every answer; Enter keeps the current value. Secret prompts show a masked value
and Enter keeps it. A file that `serv convo` would reject (for example an unknown key) only loses the
pre-fill; text that is not valid TOML aborts at save.

| Step | Asks |
|---|---|
| Channel, user, agent | Channel (empty: generate on each run), RTC user, agent user, idle timeout (default 120). |
| Preset and custom | Comma-separated preset names (free text, empty skips). Then "Add Custom override?" (with a preset) or "Configure Custom?"; no leaves provider blocks untouched. |
| Pipeline | Cascaded (ASR, LLM, TTS) or Multimodal LLM, one per run. The other stays parked in the file. |
| Provider prompts | Cascaded: ASR (vendor, params, language), LLM (greeting, failure message, one system prompt), TTS. MLLM: vendor, endpoint, params, greeting. |
| Avatar | Skip or a vendor. |
| Advanced | RTM (default yes), SAL (yes), data channel (`rtm`), word-level transcription (yes), VAD silence (800 ms). |
| Preview and save | Prints the TOML, then confirms. |

| Provider kind | Count | Vendors (Beta ones are marked in the menu) |
|---|---|---|
| ASR | 10 | ARES (built in, no key), Microsoft Azure, Deepgram, Soniox, Speechmatics, OpenAI Whisper, AssemblyAI, Amazon Transcribe, Google, Sarvam |
| LLM | 9 | OpenAI, Azure OpenAI, Groq, Google Gemini, Google Vertex AI, Claude (Anthropic), Amazon Bedrock, Dify, Custom (OpenAI-compatible) |
| TTS | 12 | Microsoft Azure, ElevenLabs, MiniMax, Cartesia, OpenAI, Hume AI, Rime, Fish Audio, Google, Amazon Polly, Murf, Sarvam |
| MLLM | 4 | OpenAI Realtime (default `gpt-realtime`), Gemini Live, Gemini Live (Vertex AI), xAI Grok Realtime |
| Avatar | 3 | Akool, LiveAvatar, Anam |

Each provider is static data in `convo_wizard.rs` (param keys with a default, hint and `secret`
flag); adding a vendor is one entry. Dotted keys (`voice_setting.voice_id`) become nested tables.
`true`, `false` and integers up to 2^53 are written as such, anything else as a string. A vendor not
in the menu (for example `openai_gpt_live`) can be written by hand.

The wizard edits the file through `toml_edit`, so comments, key order and parked blocks survive:

- Always written: `[atem]` `channel` (removed when empty), `rtc_user_id`, `pipeline`; `[agent]`
  `user_id`, `idle_timeout_secs`, `preset` (removed when empty); `[advanced_features]`, `[vad]`,
  `[sal]`, `[parameters]` (with `transcript` and `turn_detector`).
- Written only when collected this run: `[agent.llm]`, `asr`, `tts`, `mllm`, `avatar`. A provider's
  `params` table is replaced in full, and `system_messages` becomes the one prompt.
- Never asked: `env`, `envs`, `geofence`, `[atem.encryption]`, `enable_avatar`, `poll_interval_secs`,
  `[[atem.environments]]`, MCP servers. Edit them by hand; the wizard leaves them alone.

On save the old file is rotated to `convo.toml.bak`, `.bak.1` ... `.bak.4` (five generations) and the
new file is written with mode `0600`. The wizard does not call any provider to test the keys.

Known gap: for Azure OpenAI, Gemini, Vertex, Anthropic, Bedrock and Dify the wizard writes `style`
(also `vendor = "azure"`, and an `anthropic-version` `headers` table for Anthropic) into
`[agent.llm]`. `LlmConfig` has no such fields, so `serv convo` drops them and `/join` lacks them.

### Validation

`--validate` parses the file with the structs `serv convo` uses (a mistyped key under `[atem]` or
`[agent]` is a parse error), prints `ERROR:` and `WARNING:` lines, and exits non-zero on any error.
Warnings do not fail it. It never writes and does not require a channel.

| Errors | Warnings |
|---|---|
| `[agent].user_id` missing | `enable_avatar` with encryption on, or without `[agent.avatar]` |
| `geofence` not in the list above | `[agent.llm]` with neither `api_key` nor `url` |
| encryption `mode` over 8; `mode > 0` without `key` | `advanced_features.enable_rtm` not true |
| mode 7 or 8 without `salt`, or a salt that is not 32 bytes of base64 | `parameters.data_channel` not `rtm` |
| cascaded without a preset or all of `asr`, `llm`, `tts` | `asr` or `tts` block without `vendor` |
| mllm without `[agent.mllm]` | bare integer above 2^53 in a provider's `params` |
| both pipelines without `pipeline`; unknown `pipeline` value | |

It does not check environment names, MCP servers or vendor params. Unit tests live beside the code;
`scripts/run-local-dev-tests.sh` smoke-tests the bundle, the missing-config message, `--validate` on
a mistyped key and the served page.

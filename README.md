# Atem

A terminal that connects builders, Agora platform, and AI agents. Manage Agora projects and tokens, route tasks between [Astation](https://github.com/Agora-Build/Astation) and AI coding agents, and more -- all from a single CLI/TUI.

## Install

```bash
npm install -g @agora-build/atem
```

Or via shell script:

```bash
curl -fsSL https://dl.agora.build/atem/install.sh | bash
```

Or download a binary from [Releases](https://github.com/Agora-Build/Atem/releases).

The npm package downloads the binary for its published version. Documentation
on `main` can describe features newer than the latest release. Check
`atem --version` and `atem cred --help`; use a current release that includes
the commands you need, or build `main` below. Run a source build using its
explicit path, such as `./target/release/atem`, to avoid an older installed CLI.

### Build from source

```bash
git clone git@github.com:Agora-Build/Atem.git
cd Atem
cargo build --release
# Binary at target/release/atem
```

## Commands

```bash
atem                                    # Launch TUI
atem repl                               # Interactive REPL with AI command interpretation
```

### Authentication

```bash
atem login                              # Log in with Agora Console (opens browser)
atem logout                             # Log out from SSO
atem status                             # Account, pairing, verification and credentials (offline, read-only)
atem pair                               # Pair with Astation, then verify this device (shows the status when already paired)
atem pair --save                        # Same, and keep credentials for offline use
atem pair verify                        # Verify this device with the paired Astation (no re-pairing)
atem unpair [--yes]                     # Remove all Astation pairings and saved sessions (asks first)
```

`atem login` unlocks a limited set: project list, tokens for the active
project, and the dev servers (`serv rtc`, `serv convo`, `serv webhooks`).
Pairing with Astation unlocks the full set: vault, sync, memory, skills,
`atem cred`, and Astation-driven terminal viewing, chat and mark
tasks. `serv files`, `config`, and tokens from
`AGORA_APP_ID`/`AGORA_APP_CERTIFICATE` need neither.

`atem pair` receives your Agora login from Astation, then verifies the device:
atem and your Mac each show a 12-character safety code. If they match, type
`y` here; on the Mac click **Codes Match**, then approve with Touch ID.
Either side can finish first. atem reads that `y` from the terminal itself,
never from piped input or keys typed earlier, so run `atem pair` in an
interactive terminal. If verification fails, the pairing stays saved, Astation
is told, and `atem pair` exits nonzero; run `atem pair verify` to retry. A connected or SSO-paired session alone does not
mean the device is verified; check `atem status`. With `--save`
the credentials keep working when Astation disconnects; without it they stop
5 minutes after the disconnect (atem asks when `--save` isn't given).

Once paired, `atem pair` only prints the status (`Already paired. Verify this
device: atem pair verify · Replace the pairing: atem unpair, then atem pair`):
it never pairs again or changes keys, trust or sessions. `atem pair verify`
verifies the existing pairing on the runtime's Astation link, does nothing when the
device is already verified, and refuses after a revocation (run `atem unpair`,
which sets the revoked keys aside, then `atem pair`). `atem status` reads only
local files and an already running key agent; it never connects, so
authorization and relay show as `unknown (stale)`.

### Device keys (`atem cred`)

```bash
atem cred unlock                        # Unlock this device's keys (approve with Touch ID on your Mac)
atem cred lock                          # Wipe unlocked keys and stop the key agent
atem cred projects                      # Send known Git projects to Astation's credential picker (keys must be unlocked)
```

This device's keys are sealed on disk under a storage key that only the paired
Mac (the home Astation) holds. `atem cred unlock` asks the Mac for it (Touch
ID) and starts a background `atem key-agent` that holds the keys in memory;
on a device no Astation verified it stops with `This device isn't verified.
Run atem pair verify first.` and never starts pairing or verification.
`atem cred lock` wipes them and stops the agent. After upgrading atem, run
`atem cred lock` then `atem cred unlock` to pick up the new agent.

`atem cred projects` sends this repo's Git remote, and the project names atem
remembers, to Astation's credential picker, encrypted to your Mac. An
unlocked atem also sends it on its own whenever it connects to Astation (the
TUI, `atem pair`, and right after `atem cred unlock`), so you need
`atem cred projects` only to send it right away from another repo. Retrieving
values from Astation's local Credentials store (`atem cred get/list`) is not
available yet; it is designed in `designs/e2e-encryption.md`.

Updated clients and key agents retain the remote's original capitalization,
such as `github.com/Agora-Build/Atem`; project identity and duplicate checks
ignore case. Older clients/agents may report lowercase names. Reports are
encrypted even when memory encryption is off and can remain in the picker
after the sending command exits. You can also enter another Git remote in
Astation's Credentials editor.

See [pairing, unlocking and project suggestions](docs/credentials.md) for the
steps when Atem runs on another machine and for upgrade troubleshooting.

### Tokens

```bash
atem token rtc create                   # Generate RTC token (interactive)
atem token rtc create --channel test --rtc-user-id 0 --expire 3600
atem token rtc create --channel test --rtc-user-id alice --with-rtm   # RTC + RTM in one token (reuses rtc-user-id)
atem token rtc create --channel test --rtc-user-id 42 --with-rtm --rtm-user-id bob  # Separate RTM account
atem token rtc decode <token>           # Decode existing RTC token
atem token rtm create                   # Generate Signaling (RTM) token
atem token rtm create --rtm-user-id bob --expire 3600
atem token rtm decode <token>           # Decode existing Signaling (RTM) token
```

### Projects

```bash
atem project list                       # List Agora projects
atem project list --show-certificates   # List with app certificates visible
atem project use <APP_ID>               # Set current project by App ID
atem project use <N>                    # Set current project by index (1-based)
atem project show                       # Show current project
```

### AI Agents (WIP)

```bash
atem agent launch                       # Open the original Claude Code CLI in an Atem terminal
atem agent launch codex                 # Open the original Codex CLI in an Atem terminal
atem agent launch claude --continue     # Arguments after the agent type go to that CLI: continue the last Claude session
atem agent launch codex resume --last   # Continue the last Codex session
atem agent launch claude -- --help      # Use -- to read the agent's own help
atem agent list                         # The sessions the background runtime holds
atem agent attach ses-…                 # Reopen a session (screen restored)
atem agent stop ses-…                   # Stop a session
```

`atem agent launch [claude|claude-code|codex] [ARGS]...` runs the installed
`claude` or `codex` CLI, unchanged, in a full-screen Atem terminal. It uses
your working directory and your own login for that CLI. Nothing here replaces
the CLI with an API conversation. It works without Astation.

Sessions belong to a background `atem runtime` (started on demand, one per
profile; it exits after 10 minutes with no sessions and no frontends), and each agent runs in its own `atem
worker` process. Closing the terminal window or hiding it (prefix, then `h`)
leaves the session running; `atem agent attach` reopens it. Several Claude
and Codex sessions can run at once, and they keep running if the runtime
itself restarts. The runtime also holds this machine's one Astation
connection: `atem pair`, `atem pair verify`, `atem cred unlock` and `atem cred
projects` run on it (they start the runtime if needed) and never open their
own, so pairing never disconnects a running session. When an agent that
printed something ends, its last output and a short summary are saved under
`~/.config/atem/logs/<session id>/`.

If you are paired and verified, Astation can view each session, take control
of it (one controller at a time, on a lease Astation keeps renewing; typing
locally takes control back at once), and send prompts to Claude from its chat view.
Every remote request names the exact session; old `agentInput`,
`agentPrompt`, voice and `userCommand` messages were removed.

Atem's own keys start with a prefix, Ctrl+] by default. Press it, then:

| Key | Action |
|-----|--------|
| `h` or `m` | Hide the terminal; the agent keeps running |
| `g` | Take control back locally |
| `x` | Stop the agent |
| `r` | Redraw the screen |
| `[` | Browse local history (arrows, Space to select, Enter to copy, Esc to return) |
| `c` | Copy the visible text (tmux buffer inside tmux, otherwise OSC 52) |
| `?` | Help and recent notices |

The bottom row reads, for example,
`Atem | Claude | Local | Astation ✓ | Notice | Ctrl+] then ?:help`:

- `Claude` or `Codex` is the agent on screen.
- `Local` means your keyboard drives the agent; `Remote` means Astation holds
  control. Typing takes it back (prefix, then `g`, does it without typing).
- `Astation ✓` means the runtime's Astation link is authenticated; `Astation
  ✗` means none (not paired, Astation unreachable, or re-authenticating).
  Every reconnect or re-authentication is a new remote attachment: Astation
  views again and asks for control again.
- `Notice` appears once Atem has recorded a warning or status message. Press
  the prefix, then `?`, to read the recent notices (newest first).

Press the prefix twice to send it to the agent. To change it, set
`terminal_prefix = "Ctrl-a"` in `~/.config/atem/config.toml`, or
`ATEM_TERMINAL_PREFIX` (which wins over the file). Ctrl+], Ctrl+\ or
Ctrl+<letter> other than i or m are accepted. The `CLAUDE_CLI_BIN`/`CLAUDE_CLI_ARGS`
and `CODEX_CLI_BIN`/`CODEX_CLI_ARGS` variables still override the command.
See [`designs/agent-runtime.md`](designs/agent-runtime.md).

**Chat from Astation.** Astation can open a chat view of a Claude session
launched with `atem agent launch claude`: your prompts appear as messages and
Claude's replies come from its own session log, with a status of ready,
working, waiting or unknown. Atem adds its hooks with `--settings` for that run
only; your `~/.claude` settings are not changed. A prompt sent from chat needs
control of the session, is typed into Claude once, and is reported as
accepted, then complete (or failed) when Claude's turn ends. Codex has no
chat yet (its status is unknown). See
[`designs/agent-chat-host.md`](designs/agent-chat-host.md).

**Approve prompts from Astation and your phone.** When Claude Code or Codex
asks for permission to run a tool, Astation shows the request as a card (in
a Claude chat view too) and Atem asks the relay to notify your devices
with control. A card shows the tool and a short summary — the command's first
line or the file path, never file contents — and offers **Allow once**,
**Always allow** (one of the rules the agent itself suggests, with where it
is saved; Claude only) or **Deny** (with an optional note for the agent).
Answering takes control of the session for that device. The terminal can
always answer instead: Claude keeps its own dialog on screen (the first
answer wins), and for Codex any key you type in the terminal hands the
prompt back to Codex's own dialog. If nobody answers, nothing is allowed:
after the hook's wait (Claude 10 min, Codex 5 min) the agent asks in the
terminal as usual. Claude gets the hook with `--settings` for each launch.
The first `atem agent launch codex` asks once whether to add Atem's hook to
`~/.codex/hooks.json` (a backup is kept as `hooks.json.atem-bak`); to turn it
off later, set `approvals_hook = false` under `[codex]` in
`~/.config/atem/config.toml` — the next `atem agent launch codex` removes the
hook. See [§6a of the session protocol](designs/protocol/atem-session-v1.md).

### Vault (shared cross-agent context)

```bash
atem vault new --summary "auth refactor context"   # Create a vault, prints its id
atem vault list                                     # List vaults you can read
atem vault read --vault-id <id>                     # Current contents
atem vault read --vault-id <id> --history           # Every version (shown eN vM)
atem vault read --vault-id <id> --format plain      # Bare text (pipe into a prompt)
atem vault write --vault-id <id> --text "decided: JWT in cookie"   # Append an entry
atem vault write --vault-id <id> --entry-id 3 --text "..."         # Override entry e3
atem vault set-summary --vault-id <id> --text "..."  # Update the summary
```

Requires pairing with Astation. Lets multiple atems (each driving an agent)
share a versioned, append-only context store hosted on the Astation relay; see
`designs/vault.md`.

### Memory & Skills (shared across agents and machines)

Requires pairing with Astation. Agents learn from each other: facts and skills
saved on one machine (by Claude Code, Codex, or you) reach every other paired
atem.

```bash
atem sync                                        # Harvest Claude's memories → push → pull → apply
atem memory add "Relay tests need Valkey on :56379"   # Save a fact (project scope inside a repo)
atem memory add --scope global --confidence high "..."
atem memory list                                 # Global, this machine, and this project
atem memory list --all                           # Every project and machine
atem memory list --full                          # Everything: full id, status, timestamps, whole content
atem memory list --history [<id>]                # Include outdated facts, as replacement chains
atem memory search "valkey"                      # Local full-text search (offline; CJK works)
atem memory replace <id> "the fact as it is now" # New fact replaces the old one (history kept)
atem memory invalidate <id>                      # Mark outdated without a replacement
atem memory rm <id>                              # Remove everywhere
atem memory purge <id> [--yes]                   # Remove a fact that contained a credential, stop re-harvesting it (asks first)
atem memory apply                                # Rewrite the managed blocks and skills from the local store
atem memory status                               # Account, machine, project, pending changes

atem skill add ./my-skill                        # Directory with SKILL.md (global by default)
atem skill list
atem skill rm <name>                             # Remove everywhere
atem skill history <name>                        # Every version, newest first
atem skill restore <name> --version 3            # Re-push an old version as a new one
atem skill purge <name> --version 3 [--yes]      # Erase versions that contained a credential (or --all-versions; asks first)
```

Listings show short ids like `8245ecf6…e6fe` (first 8 + last 4 characters).
Any command that takes an `<id>` accepts that form (`…` or `..`), a full id,
or a unique prefix.

A project is identified by its git `origin` remote, so two repos with the same
folder name never collide. atem shows the remote's own spelling
(`github.com/Agora-Build/Atem`) but matches case-insensitively.

Memories are applied as a managed block in `~/.claude/CLAUDE.md`,
`~/.codex/AGENTS.md` and `<repo>/CLAUDE.local.md`; skills go to
`.claude/skills` and `.agents/skills`. Files tracked by git are never written.
Anything that looks like a credential value is refused; save the
credential's name, never its value. See `designs/atem-memory.md`.

Works with end-to-end encryption on or off. When it is on, changes sync only
while the device is unlocked (`atem cred unlock`); see below.

### End-to-end encryption

Turned on or off in Astation (Settings > Security > End-to-End Encryption).
When it is on, memory content, skill files and vault content are encrypted on
this machine before they reach the relay, and project names become keyed hashes.
Your Mac, verified Atem devices holding the account key, and holders of the
recovery material can decrypt that content. The relay still sees routing identifiers and metadata,
such as timestamps and ciphertext sizes; it is not authoritative for device
trust or encryption state. Migration cannot prove that a server erased old
plaintext backups.

The device must be verified (`atem pair`, or `atem pair verify` to retry) and unlocked (`atem cred unlock`).
While it is locked, `atem sync` keeps changes queued. Switching encryption on
or off migrates existing data; each verified atem finishes its part at its next
`atem cred unlock` (`atem sync` alone doesn't contact Astation). **Turning on**
or **Turning off** is a pending migration, even when the field counts show
no remaining plaintext or obsolete fields. Astation commits the final state
after accepting a verified migration completion; the CLI can then disconnect.
Turning encryption off migrates shared data to plaintext; local Astation
Keychain credentials keep their protection. The local `knowledge.db` stays
plain text (mode 0600). See the [user guide](docs/credentials.md) and
[protocol design](designs/e2e-encryption.md).

### Dev Servers

```bash
atem serv convo                         # Launch ConvoAI test page (HTTPS)
atem serv convo --config ~/convo.toml   # Use custom config file
atem serv convo --background            # Detached daemon — POSTs /join, registers, exits
atem serv attach <ID>                   # Open UI bound to a running convo daemon (talk to live agent)
atem serv attach 3                      # …or by index from `atem serv list`
atem serv rtc                           # Launch RTC test page (HTTPS)
atem serv rtc --channel test --port 8443
atem serv rtc --background              # Run as background daemon
atem serv files ~/docs                  # Serve a directory or file over HTTPS (Markdown rendered)
atem serv files ~/docs --background     # Port auto-picked; reused next run
atem serv webhooks                      # Receive Agora webhooks locally (auto-tunneled via ngrok)
atem serv webhooks --no-tunnel          # Local listener only — bring your own tunnel
atem serv webhooks --background         # Run as background daemon
atem serv list                          # List running background servers (#, ID, PID, STATUS)
atem serv kill <ID|#>                   # Kill a server (POSTs /leave for convo)
atem serv killall                       # Kill all background servers

# Fleet test loop — {appid} and {ts} are expanded by atem
for i in $(seq -f '%04g' 1 10); do
  atem serv convo --background --channel 'atem-convo-{appid}-{ts}-'$i
done
```

**`serv convo`** — ConvoAI voice agent: live transcription (RTM), preset selection, avatar (Akool, LiveAvatar, Anam), RTC Stats, API History, camera toggle, RTC encryption (key + salt forwarded to the agent), HIPAA mode (routes via `/hipaa/api/...`), audio dump.

`--background` re-execs as a detached daemon: parent POSTs `/join`, registers the agent in `~/.config/atem/servers/<channel>.json`, and exits. The daemon polls Agora's `GET /agents/{id}` every 60s and writes the status (RUNNING/IDLE/STOPPED/…) back into the registry — `atem serv list` reads it without making any network calls. `kill`/`killall` SIGTERM the daemon, which catches the signal and POSTs `/leave` before exiting. The daemon's log file (`<channel>.log`) contains the `/join` URL and request body with secrets masked, useful for debugging encryption mismatches.

**`serv attach <id>`** — opens a foreground HTTPS UI bound to a running convo daemon's channel. The page hides Start/Stop because the daemon owns the agent; you Join to talk to the live agent. Encryption / HIPAA / geofence are read from the same `convo.toml` so the local SDK matches what the daemon used.

**`serv rtc`** — RTC test page: join/leave, publish/subscribe audio+video, token generation, RTM messaging, RTC encryption (8 modes; gcm2 modes auto-generate a copyable salt).

**`serv files`** — serves a directory (or a single file) over HTTPS. Markdown is rendered to HTML; append `?raw=1` to any URL for the raw bytes. Useful for browsing AI-generated docs on a remote machine.

**`serv webhooks`** — local receiver for Agora webhook events (ConvoAI: `agent_joined`, `agent_left`, `agent_history`, `agent_error`, `agent_metrics`, …; RTC NCS events). Validates `Agora-Signature-V2` (HMAC-SHA256) when a `secret` is configured in `webhooks.toml`; accepts unsigned events with a banner warning otherwise. Live web console at `http://127.0.0.1:9090/` shows incoming events; each event also prints a one-line summary to stdout. Default tunnel provider is **ngrok** (requires `ngrok config add-authtoken` once); set `tunnel_provider = "cloudflared"` for zero-auth quick tunnels. Use `--no-tunnel` if you're running cloudflared / ngrok separately for stable URLs across atem restarts. See [`configs/webhooks.example.toml`](configs/webhooks.example.toml) for the full config schema.

**Channel placeholders** — `--channel` accepts `{appid}` (first 12 chars of the active app id) and `{ts}` (unix epoch seconds at startup). Useful in for-loops: `--channel 'atem-convo-{appid}-{ts}-001'` produces `atem-convo-2655d20a82fc-1777574763-001`.

### Configuration

```bash
atem config show                        # Show resolved config
atem config set astation_ws <URL>       # Set Astation WebSocket URL
atem config set astation_relay_url <URL> # Set Astation relay URL
atem config clear                       # Clear active project selection
atem config convo                       # Interactive wizard to configure ConvoAI agent
atem config convo --validate            # Validate ConvoAI config without modifying
atem config convo --config <PATH>       # Use a specific config file
```

The `atem config convo` wizard walks you through Channel & User → Agent → Preset (empty = skip) → Add Custom override? → Pipeline → Avatar. Preset and Custom stack: preset sets defaults, explicit blocks override per-field. Pipeline selects one of:
- **Cascaded** (ASR + LLM + TTS): 10 ASR, 9 LLM, 12 TTS vendors
- **Multimodal LLM**: OpenAI Realtime (`gpt-realtime`), Google Gemini Live, xAI Grok Realtime — single model handles voice in/out
- **Avatar**: Akool, LiveAvatar, Anam

`convo.toml` is structured into two atem-managed top-level sections plus the Agora pass-through tables. The web UI pre-fills form fields from `[atem]`; `--background` reads them directly.

```toml
[atem]                       # atem's runtime control surface
channel       = "..."        # auto-generated when omitted
rtc_user_id   = "0"          # human's RTC uid
pipeline      = "cascaded"   # "cascaded" | "mllm" — picks which block goes to /join
hipaa         = false        # route via /hipaa/api/... (Agora support must enable)
geofence      = "GLOBAL"     # GLOBAL | NORTH_AMERICA | EUROPE | ASIA | JAPAN | INDIA
enable_avatar = false        # opt in to use [agent.avatar] this session

[atem.encryption]            # mode = 0 → off
mode = 8                     # 1..=8 (Agora's table); 8 = AES_256_GCM2 (recommended)
key  = "your-key-here"
salt = "Q4mTLy5h…="           # base64 32 bytes; required for gcm2 modes (7, 8)

[agent]                      # the AI agent
user_id           = "1001"
idle_timeout_secs = 120
preset            = "preset_a, preset_b"   # comma-separated; UI splits into checkboxes

[agent.llm]                  # cascaded providers (forwarded under properties.<svc>)
[agent.asr]
[agent.tts]
[agent.mllm]                 # OR a single multimodal model — replaces asr+llm+tts
[agent.avatar]

[advanced_features]          # pass-through (forwarded verbatim to Agora)
[vad]
[sal]
[parameters]
```

Both peers must use matching encryption/geofence or audio fails silently. `enable_avatar` is opt-in even when `[agent.avatar]` is configured — fleet `--background` launches won't burn avatar minutes by accident. `atem config convo --validate` reports any issue (unknown geofence, gcm2 mode without salt, missing `[agent].user_id`, etc.).

## How It Works

### Astation connections

Atem tries a configured direct endpoint first and then the identity relay after
it has learned the target Astation identity. Direct and relay connections use
the same device session, so one Atem can move between networks without pairing
again. Successful authentication stores `astation_relay_code` automatically;
manual configuration is only needed for an override or headless provisioning.

| Atem location | Endpoint | First connection | Internet required |
|---------------|----------|------------------|-------------------|
| Same Mac | `ws://127.0.0.1:8080/ws` | Transparent same-user proof | No |
| Another LAN machine | `ws://<astation-ip>:8080/ws` | Approve pairing in Astation | No |
| Remote network | Public WSS identity relay | Approve pairing in Astation | Yes |

All paths use device authentication v2. Astation sends a fresh challenge; Atem
proves possession of the local bootstrap token or its saved device-session token
with HMAC-SHA256. A session ID by itself is not accepted. Same-Mac operation
continues when Wi-Fi is disabled, and LAN operation needs no relay once the IP is
configured.

Direct LAN currently uses plaintext `ws://`. Authentication prevents a stolen
session ID from being sufficient, but it does not stop traffic inspection or an
active LAN attacker during initial pairing. Treat direct LAN as pre-production
until WSS certificate pinning is implemented. The wire contract and test matrix
are documented in [`designs/session-auth.md`](designs/session-auth.md).

### TUI Modes

| Mode | Description |
|------|-------------|
| **Token Gen** | Generate Agora RTC/RTM tokens locally |
| **Projects** | Browse and select Agora projects |
| **Agent Sessions** | The runtime's Claude/Codex sessions: launch or attach |

Astation integration is in progress — see [ROADMAP.md](ROADMAP.md).

## Configuration

### Login

```bash
atem login          # Opens browser to log in with Agora Console
```

If the browser redirect doesn't complete within 5 seconds (e.g. remote server), atem will prompt you to paste the callback URL from the browser address bar.

### Storage

Files in `~/.config/atem/`:

| File | Contents | Encryption |
|------|----------|------------|
| `config.toml` | Non-sensitive settings (Astation/relay URLs, extra_hostnames, SSO/BFF overrides) and this atem's generated identity (`instance_id`, `atem_id`) | None |
| `convo.toml` | ConvoAI agent config (API keys, provider params) | None (chmod 0600) |
| `credentials.enc` | SSO and Astation-paired tokens | AES-256-GCM (machine-bound) |
| `project_cache.enc` | Project list + active project selection | AES-256-GCM (machine-bound) |
| `sessions.json` | Per-Astation device session IDs and tokens | Plaintext (chmod 0600) |
| `knowledge.db` | Atem Memory: memories, skills, search index, pending-sync queue (no credentials) | None (chmod 0600) |
| `device_keys.sealed` | This device's keys (device, signing and account keys). `.next` exists only during a storage-key rotation, `.prev` until the next unlock | XChaCha20-Poly1305 under a storage key held only by the home Astation |
| `device_keys` | The same keys in plain form, only until the home Astation first holds the storage key; then deleted | None (chmod 0600) |
| `unlock_auth_key` | Key that signs unlock requests (it can only ask Astation) | None (chmod 0600) |
| `cred_state.json` | Verified Astation keys, safety code, signed encryption state, home Astation (no secrets) | None (chmod 0600) |
| `project_names.json` | Account-scoped project hash-to-key mappings and known original-case display labels (no credential values) | None (chmod 0600) |
| `key-agent.log` | Output of the background `atem key-agent` | None |
| `agent.sock`, `agent.socket`, `*.lock` | Key-agent socket and lock files (the socket lives in `$XDG_RUNTIME_DIR/atem/` when that is set) | Socket 0600, same user only |

Machine-bound files can't be decrypted on another machine. `device_keys.sealed` opens only with a storage key from your Mac.

### Config file

`~/.config/atem/config.toml`:

```toml
# astation_ws = "ws://127.0.0.1:8080/ws"
# astation_relay_url = "https://station.agora.build"
# astation_relay_code = "astation-..." # learned automatically after authentication
# bff_url = "https://agora-cli.agora.io"
# sso_url = "https://sso2.agora.io"

# Extra hostnames baked into the self-signed cert + shown as "Custom:" URLs
# extra_hostnames = ["genie.netbird.cloud", "dev.mytailnet.ts.net"]

# Prefix key of the shared agent terminal (default Ctrl+]; env ATEM_TERMINAL_PREFIX wins)
# terminal_prefix = "Ctrl-a"
```

### Environment variable overrides

```bash
ATEM_BFF_URL=...   # Override BFF API base URL
ATEM_SSO_URL=...   # Override SSO base URL
ASTATION_WS=...            # Direct loopback, LAN, or VPN WebSocket endpoint
ASTATION_RELAY_URL=...     # Relay HTTP(S) base URL
ASTATION_RELAY_CODE=...    # Target Astation identity room
AGORA_APP_ID=...           # Override active project App ID
AGORA_APP_CERTIFICATE=...  # Override active project certificate
```

## Development

```bash
cargo build                       # Debug build
cargo build --release             # Release build
cargo test                        # Run tests (900+ tests)
cargo check                       # Type-check
cargo fmt                         # Format
cargo clippy                      # Lint
./scripts/run-local-dev-tests.sh  # End-to-end CLI smoke test
./scripts/release.sh              # Patch-bump Cargo.toml + commit + tag
./scripts/release.sh 0.5.0        # Explicit version
```

### Token library (`atem-core`)

Token generation lives in the `atem-core` crate, with a C ABI in
`atem-core-ffi` for Swift and other native hosts (intended for
Astation; not integrated yet). Run its tests with `cargo test -p atem-core -p atem-core-ffi` and
`./scripts/check-atem-core-ffi.sh`. Release assets, the C ABI and the Swift
steps are in [`crates/atem-core-ffi/README.md`](crates/atem-core-ffi/README.md).

### Release

Releases are tag-driven — pushing `vX.Y.Z` triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds
the binaries and publishes `@agora-build/atem` to npm.

Use `./scripts/release.sh` rather than `git tag` directly — the script keeps
`Cargo.toml` in sync with the tag, so `atem --version` reports the right number.

### Feature Flags

| Flag | Description |
|------|-------------|
| `openssl-vendored` | Build OpenSSL from source (for cross-compilation) |

## Roadmap

See [ROADMAP.md](ROADMAP.md) for upcoming features and where to help. Items labelled [`help wanted`](https://github.com/Agora-Build/Atem/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) are open for contributors.

## Related Projects

- [Astation](https://github.com/Agora-Build/Astation) -- macOS menubar hub that coordinates Chisel, Atem, and AI agents — talk to your coding agent from anywhere
- [Chisel](https://github.com/Agora-Build/chisel) -- Dev panel for visual annotation and UI editing by anyone, including AI agents
- [Vox](https://github.com/Agora-Build/Vox) -- AI latency evaluation platform

## License

MIT

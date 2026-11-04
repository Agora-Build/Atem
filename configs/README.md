# atem config examples

Annotated copies of the TOML files atem reads from `~/.config/atem/`.
Copy the one you need, edit, drop it into the config dir.

| File | Where it goes | What it's for |
|------|---------------|---------------|
| [config.example.toml](config.example.toml) | `~/.config/atem/config.toml` | Astation WebSocket / relay URL, BFF / SSO overrides, extra hostnames for the self-signed cert |
| [runtime.example.toml](runtime.example.toml) | `~/.config/atem/runtime.toml` | Approved profiles, notification routes, local agent collaboration and optional zero-session hosting (disabled by default) |
| [convo.example.toml](convo.example.toml) | `~/.config/atem/convo.toml` | `atem serv convo` — agent provider blocks (LLM/ASR/TTS/avatar), preset list, HIPAA / geofence / encryption / `enable_avatar` defaults |
| [webhooks.example.toml](webhooks.example.toml) | `~/.config/atem/webhooks.toml` | `atem serv webhooks` — local port, HMAC secret, ngrok / cloudflared tunnel provider |

Quick copy:

```bash
cp configs/convo.example.toml    ~/.config/atem/convo.toml
chmod 0600                       ~/.config/atem/convo.toml      # has API keys
cp configs/webhooks.example.toml ~/.config/atem/webhooks.toml
```

Each file is heavily commented — open it before editing. Anything not
documented in the example is documented in the per-command `--help`
output (`atem serv convo --help`, `atem config convo --help`, etc.)
or the project's main [README](../README.md).

For runtime configuration, `atem runtime start` creates `runtime.toml` from
the same sample embedded in the binary when the file is missing. Existing
configuration is preserved. Fill in approved profiles and routes, validate
with `atem runtime check`, and explicitly enable hosting when ready. Both
commands require pairing. Provider environment files are optional private
JSON files referenced by the profile; the samples contain variable names
and placeholders, never credentials.

Local collaboration also requires `[collab] send = true` and `"local"` in
each receiving route's `principals`. Give those routes owner labels such as
`labels = ["tag:backend"]`. Inside an Atem-launched agent:

```bash
atem message directory tag:backend
atem message send --to tag:backend "Review the API contract"
atem message status MESSAGE_ID
atem message reply --task TASK_ID "Contract verified"
atem agent tag add self:reviewer
```

The defaults are 30 sends per session per hour, 8 envelopes/tasks/results per
workflow, a 30-minute status-report timeout, `launch = "off"`,
`results = false`, and `auto_report = "status"`. Set `results = true` on the
originating route to queue replies back into its agent. Set
`launch = "on_message"` on a receiving route to start its approved profile
when no matching session exists. `local` belongs only in route principals;
profile principals continue to control remote launch.

`--memory ID` and `--vault ID[:ENTRY]@VERSION` publish or verify the exact
context before delivery. A bare vault ID/version is accepted only when it
identifies one entry; include `:ENTRY` when ambiguous. These commands currently
reach agents in the same runtime. Cross-instance delivery is planned in the
[collaboration design](../designs/agent-collaboration.md).

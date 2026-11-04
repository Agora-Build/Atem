# atem config examples

Annotated copies of the TOML files atem reads from `~/.config/atem/`.
Copy the one you need, edit, drop it into the config dir.

| File | Where it goes | What it's for |
|------|---------------|---------------|
| [config.example.toml](config.example.toml) | `~/.config/atem/config.toml` | Astation WebSocket / relay URL, BFF / SSO overrides, extra hostnames for the self-signed cert |
| [runtime.example.toml](runtime.example.toml) | `~/.config/atem/runtime.toml` | `atem runtime` remote-launch profiles, notification routes and optional zero-session hosting (disabled by default) |
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

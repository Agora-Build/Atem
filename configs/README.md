# atem config examples

Annotated copies of the TOML files atem reads from `~/.config/atem/`.
Copy the one you need, edit, drop it into the config dir.

| File | Where it goes | What it's for |
|------|---------------|---------------|
| `config.example.toml`   | `~/.config/atem/config.toml`   | Astation WebSocket / relay URL, BFF / SSO overrides, extra hostnames for the self-signed cert |
| `convo.example.toml`    | `~/.config/atem/convo.toml`    | `atem serv convo` — agent provider blocks (LLM/ASR/TTS/avatar), preset list, HIPAA / geofence / encryption / `enable_avatar` defaults |
| `webhooks.example.toml` | `~/.config/atem/webhooks.toml` | `atem serv webhooks` — local port, HMAC secret, ngrok / cloudflared tunnel provider |

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

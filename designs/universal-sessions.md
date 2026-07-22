# Portable Device Sessions

Status: implemented by device authentication v2.

## Goal

Pair an Atem installation with an Astation once, then reuse that device session
over direct LAN, VPN, or the identity relay. Loopback has an additional same-user
bootstrap path so it works offline without an approval prompt.

## Identity model

- `instance_id` is the stable UUID for one Atem installation.
- `atem_id` is the stable, human-readable relay/device ID derived from that UUID.
- `astation_id` identifies one Astation installation on every transport.
- `session_id` selects a paired record but is not a credential.
- `token` is the secret used to prove possession with HMAC-SHA256.

Atem stores sessions keyed by `astation_id`, which allows one Atem installation
to connect to multiple Astations without overwriting credentials. Astation binds
each session to one `atem_id`, which prevents a copied session ID from being
claimed by a different device.

```json
{
  "sessions": {
    "astation-home": {
      "session_id": "...",
      "token": "...",
      "astation_id": "astation-home",
      "hostname": "office-ubuntu",
      "last_activity": 1784678400
    }
  }
}
```

The file is `~/.config/atem/sessions.json`, created as `0600` under a `0700`
directory.

## Transport portability

Astation includes the same `astation_id` in direct and relay challenges. Atem
therefore finds the same record regardless of the endpoint and calculates a new
proof using the challenge for that connection. The token never needs to be sent
again after pairing.

This supports both directions:

- direct LAN becomes unavailable, so Atem reconnects through the relay;
- relay or internet becomes unavailable, so Atem connects to a configured LAN
  address using the existing session.

## Lifecycle

- Sessions expire after seven days of inactivity.
- A successful proof refreshes activity on both peers.
- An invalid or expired session falls back to explicit pairing.
- Existing legacy session records can be read, then bind to the first `atem_id`
  that successfully proves token possession.
- The older `~/.config/atem/session.json` path is legacy and is not the v2
  multi-Astation source of truth.

## Multiple clients

One Astation can keep several local, LAN, and relay Atem connections active at
the same time. Each Atem installation has its own session and stable device ID.
Multiple processes that share one Atem config directory also share an identity;
use separate config homes when process-level identities are required.

## Security constraints

Endpoint portability does not make every transport equally secure. The public
relay uses WSS, while the current direct LAN endpoint is plaintext WebSocket.
See `session-auth.md` for the protocol boundary and required WSS pinning work.

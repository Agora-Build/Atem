# Astation Identity Relay

Status: device authentication v2 is implemented for Atem identity-room clients.
The relay still has production security blockers listed below.

## Roles

- Astation connects to `role=astation` using its stable identity as the room.
- Atem connects to `role=atem` with the target `astation_relay_code` and its
  stable, percent-encoded `atem_id`.
- The relay routes per-Atem envelopes between the room owner and each client.
- Astation remains the device-authentication authority.

## Reconnect flow

```text
Atem -> relay: connect to identity room, then hello
Atem <- relay <- Astation: auth_required {challenge, astation_id, protocol=2}
Atem -> relay -> Astation: auth {session_id, atem_id, proof}
Atem <- relay <- Astation: authenticated
```

The relay must not interpret `hello` or a session ID as authorization. It binds
a pending session claim only after observing Astation's authenticated/granted
response. Until that point Astation rejects application messages and does not
send account credentials.

When Atem has no valid session, the same socket carries an eight-digit pairing
code. Astation shows the device and code for approval, then returns a new token
through the WSS connection.

## Configuration

```toml
astation_relay_url = "https://station.agora.build"
astation_relay_code = "astation-..."
```

The identity code is learned and persisted after successful authentication. It
is an Astation routing identifier, not an authentication secret; a saved v2
session is still required for automatic reconnect.

## Pairing rooms

The legacy `/api/pair` room remains available for discovering/connecting an
Astation. Identity rooms are used for persistent reconnect after Atem knows the
target `astation_id`. Device proof is required after either transport connects.

## Production blockers

1. Authenticate `role=astation` before creating or replacing an identity-room
   owner. A stable room code alone does not establish ownership.
2. Require authenticated device context on Voice, LLM, Vault, and RTC owner
   APIs rather than trusting a bare session ID.
3. Make disconnect/replacement cleanup connection-generation aware so an old
   socket cannot remove its replacement.
4. Apply explicit WebSocket admission, message-size, and message-rate limits.
5. Add device revocation and session rotation controls.

These blockers mean the relay should not yet be described as a complete
production authorization boundary, even though the Atem-to-Astation v2 proof is
implemented.

## Verification

- Confirm `hello` only triggers an Astation challenge.
- Confirm application messages before proof are rejected.
- Confirm a valid LAN-created session authenticates through the identity relay.
- Confirm an invalid proof falls back to pairing on the same socket.
- Confirm two Atem IDs remain independently connected in one Astation room.

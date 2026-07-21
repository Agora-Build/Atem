# Device Authentication v2

Status: implemented for direct and identity-relay connections. This document is
the authoritative Atem-side contract. The matching Astation specification is
`docs/specs/2026-07-21-device-authentication-v2.md` in the Astation repository.

## Connection matrix

| Path | Endpoint | First connection | Internet required |
|------|----------|------------------|-------------------|
| Same Mac | `ws://127.0.0.1:8080/ws` | Same-user bootstrap proof | No |
| LAN or VPN | `ws://<astation-ip>:8080/ws` | User-approved pairing | No |
| Remote | Astation identity room on WSS relay | User-approved pairing | Yes |

The direct endpoint is attempted before relay. All paths can coexist, and the
same saved device session works for direct LAN and relay reconnects.

## Trust boundaries

- Astation determines loopback from the kernel socket peer address. Atem cannot
  claim loopback through a header, hostname, or protocol field.
- Loopback skips interactive pairing only when Atem can read Astation's local
  bootstrap file and that file has no group or other permission bits.
- LAN, VPN, and relay clients pair once and then prove possession of the saved
  session token. A `session_id` alone never authenticates a device.
- The identity relay transports authentication messages. Astation, not the
  relay, verifies the proof and decides whether the Atem can send app messages.

## Challenge and proof

Astation starts a direct connection, or answers an identity-relay `hello`, with:

```json
{
  "type": "statusUpdate",
  "data": {
    "status": "auth_required",
    "data": {
      "astation_id": "astation-...",
      "challenge": "64 lowercase hex characters",
      "transport": "loopback|lan|relay",
      "protocol": "2"
    }
  }
}
```

The proof is lowercase hexadecimal HMAC-SHA256 over this exact UTF-8 string:

```text
astation-auth-v2\n<challenge>\n<astation_id>\n<atem_id>\n<session_id>
```

For loopback, the HMAC key is `local-bootstrap-token` and the proof input uses
the literal session ID `local`. For LAN and relay reconnects, the key is the
saved session token and the real session UUID is used.

The cross-language test vector is:

| Field | Value |
|-------|-------|
| token | `token-abc` |
| challenge | `challenge-123` |
| astation ID | `astation-home` |
| Atem ID | `atem-office` |
| session ID | `session-456` |
| proof | `9fde5ba861c1a159d377b89e6fb3f92d245795998af958f5db3ad343d589d0ba` |

## Pairing and reconnect

1. Atem receives `auth_required` and looks up a session by `astation_id`.
2. When a valid session exists, Atem sends `session_id`, `atem_id`, and `proof`.
3. Astation verifies the proof, expiry, and device binding before registering
   the client or sending credentials.
4. If the session is absent, invalid, or expired, Atem sends an eight-digit
   pairing code and waits up to five minutes for approval.
5. Astation returns a new session ID and token after approval. Atem persists it
   and uses a fresh proof on later connections.

An invalid or expired saved proof falls back to pairing on the same open socket.
Old clients that send only a session ID cannot authenticate against v2.

## Local state

| Path | Mode | Contents |
|------|------|----------|
| `~/.config/atem/sessions.json` | `0600` | Sessions keyed by Astation ID |
| `~/.config/atem/config.toml` | existing user config mode | Stable `instance_id`, `atem_id`, endpoints |
| `~/Library/Application Support/Astation/local-bootstrap-token` | `0600` | Same-user loopback key, read on macOS only |

The `~/.config/atem` directory is set to `0700` when sessions are saved. Never
print session tokens, proofs, or bootstrap contents.

## Practical verification

```bash
cargo test websocket_client::tests::device_auth_proof_matches_protocol_vector
cargo test websocket_client::tests::local_bootstrap_token_requires_private_permissions
cargo test auth::tests::private_file_write_uses_owner_only_permissions
cargo test -- --test-threads=1
```

The coordinated Astation tests start the real NIO WebSocket server and cover an
offline loopback client, a rejected forged proof, five concurrent Atem clients,
and direct auth through a real non-loopback LAN interface.

## Known limitation

Direct LAN currently uses plaintext `ws://`. HMAC verifies possession but does
not encrypt pairing credentials or application traffic and does not prevent an
active man-in-the-middle. Do not call direct LAN production-ready until WSS with
persistent certificate pinning, or an equivalent authenticated encrypted
transport, is implemented.

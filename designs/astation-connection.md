# Atem ↔ Astation connection

Status: current design (Atem v0.8.0, 2026-11-01).

How Atem reaches Astation: the link, its order, authentication, pairing, the relay, r9's relay only and routed links, re-authentication and Station changes. AGENTS.md ("Astation Integration", "Logins and the pairing", "SSO auth", "r9 remote clients") has the full detail.

## Overview

- Only `atem runtime` holds an Astation link: one per config dir, so one per machine and user. Bare `atem` and the CLI commands open none.
- `atem pair`, `atem pair verify`, `atem cred unlock|projects` and the paired-token refresh run as operations inside the runtime, on its link. See [agent-runtime.md](agent-runtime.md).
- Atem always dials out. It opens no port.
- A link is one WebSocket: local (`astation_ws`) or the paired Astation's identity room on the Station (`astation_relay_url`).
- Astation authenticates the link. The relay only routes it, except for the r9 host route proof.
- r8 session-v1, terminal-v1 and chat-v1 run on the authenticated link. On a host with a device list, r9 clients come through `atem-ch1` channels carried on the same link. See the r9 appendix of [atem-session-v1.md](protocol/atem-session-v1.md).

## Identity

- `instance_id`: a UUID v4 in config.toml, this install's identity.
- `atem_id`: the relay id `<host>[-<filler>]-<suffix:8>`, built once and frozen in config.toml, percent-encoded in the relay URL. See [atem-identity.md](atem-identity.md).
- `astation_id`: names one Astation on every transport. It is a routing id, not a secret.
- `pairing/pairing.enc` (machine-bound AES-256-GCM) is the one pairing: the Astation's id, the binding (host trust generation), the saved session (`session_id`, `token`, `last_activity`) and the login Astation shared. There is one pairing at a time.

```toml
astation_ws = "ws://127.0.0.1:8080/ws"             # default: Astation on this Mac
# astation_ws = "ws://192.168.1.20:8080/ws"        # or a LAN/VPN address
astation_relay_url = "https://station.agora.build"  # default (production)
# astation_relay_url = "https://station-dev.agora.build"  # dev profiles
```

`ASTATION_WS` and `ASTATION_RELAY_URL` override them. There is no relay code setting: the room is the pairing's `astation_id`.

## Connection order

The runtime connects when it starts and whenever it has no link (`App::spawn_astation_connect`). Each attempt re-reads config.toml and the pairing record.

1. Read `pairing/pairing.enc`. An unreadable record fails closed: no local attempt, no relay, the error as the status (`app::PAIRING_UNREADABLE`), the 30 s retry.
2. Local: connect `astation_ws` (5 s) and authenticate without pairing. Skipped while the host policy says relay only.
3. Relay: only with a pairing record. Join the paired Astation's identity room and authenticate without pairing, or be routed (r9).
4. Both fail: no link, and another attempt in 30 s.

- A dropped authenticated link reconnects at once.
- Retry timers run on the monotonic clock, so they count awake time only.
- Without a pairing record only the local step runs.
- The order applies at each connect. An established relay link stays when local becomes reachable again.
- `atem status` shows the link: `connected locally`, `connected via relay (<host> as <atem_id>)`, `routed via relay (…; no Astation)` or `not connected (retrying)`. It never shows a room code or a session.

## Authentication (device authentication v2)

Astation challenges a new local socket at once, and a relay link after Atem's `hello` (`statusUpdate{status:"hello", data:{hostname}}`):

```json
{"type":"statusUpdate","data":{"status":"auth_required","data":{
  "astation_id":"astation-…","challenge":"<64 lowercase hex>",
  "transport":"loopback|lan|relay","protocol":"2"}}}
```

- Atem refuses a challenge without `protocol: "2"`, with a malformed challenge or with another transport. There is no bearer-session fallback.
- The proof is lowercase hex HMAC-SHA256 over `astation-auth-v2\n<challenge>\n<astation_id>\n<atem_id>\n<session_id>`, sent as `statusUpdate{status:"auth", data:{session_id, atem_id, proof}}`.
- `loopback`: the key is Astation's `local-bootstrap-token` and the session id is the literal `local` (`method: local_proof`). It works offline and needs no approval.
- Atem reads that token only on macOS, from `~/Library/Application Support/Astation/`, and only from a regular file this user owns with no group or other permission bits (opened with `O_NOFOLLOW`).
- Astation decides `loopback` from the socket's peer address. Atem can't claim it, and a LAN address never gets it.
- `lan` and `relay`: the key is the saved session token and the session id is the real one. The token crosses the wire only in the grant.
- Astation, not the relay, checks the proof. It answers `auth{status:"granted", session_id, token}`, `authenticated`, `auth{status:"denied", message}` or `error{message}` (expired or pairing required).
- Test vector (`device_auth_proof_matches_protocol_vector`): token `token-abc`, challenge `challenge-123`, Astation `astation-home`, Atem `atem-office`, session `session-456` → `9fde5ba861c1a159d377b89e6fb3f92d245795998af958f5db3ad343d589d0ba`.
- Bounds: the challenge within 5 s on local and 10 s on the relay; everything after it within 300 s.

The saved session:

- The one session works on every non-loopback transport. Every challenge names the same `astation_id`, so a session made on the LAN authenticates through the relay, and the other way round.
- It expires after 7 days without activity. A successful proof refreshes it, and so does traffic on the link (at most once a minute).
- Background connects and re-authentication never pair. A refused or expired session fails the attempt with `The saved Astation session expired or was refused. Run `atem unpair`, then `atem pair`.`
- Only `atem pair` creates a pairing record. Other connects only update the bound pairing's session.
- Each authentication captures the trust generation, binding and session it started under. A reply is applied only while they are unchanged (`Captured::apply` under `trust_gen.lock`), so a reply after `atem unpair` or a new pairing is dropped.

## Pairing

`atem pair [--save]` runs only on an unpaired profile. A paired one prints its status and `Already paired. …`, and nothing connects.

1. Local first: connect `astation_ws` with pairing allowed. On loopback the bootstrap proof authenticates and the challenge names the Astation. On a LAN or VPN address Atem sends an eight-digit code; the user approves it in Astation within 5 minutes, and Astation grants a session.
2. Else the relay: `POST <Station>/api/pair` returns a pairing room code. Atem joins that room with its `atem_id` and prints the code, which the user enters in Astation.
3. The token-free pairing bootstrap v1: Atem sends `pairing{v:1, op:"hello", id}` every 3 s until `pairing{v:1, op:"introduction", id, astation_id}` (at most 600 s, the room's life) or `pairing{op:"error", id, code}`. Received `pairing` frames are read strictly (`pairing_wire::parse`: ≤ 4096 bytes, exact fields).
4. The `astation_id` is only a routing hint. Atem opens the identity link to that room with the same `atem_id`. Its `auth` carries the room's code as `pairing_code` and the hello's `id` as `pairing_attempt_id`, so Astation attaches it to this attempt, and Astation grants the session there.
5. Atem binds the pairing in the next host trust generation (`pairing::bind_new`), installs the link as the runtime's link, and verifies the device on it.

- No account credentials cross during pairing. `--save` only records `save_credentials` for a later `credentialSync`.
- Device verification is commit-then-reveal: a 12-character safety code the user compares, Touch ID on the Mac, then the signed `deviceVerified` applied atomically. A failure keeps the pairing, and `atem pair verify` retries. See AGENTS.md ("SSO auth") and [e2e-encryption.md](e2e-encryption.md#devices).
- `atem pair verify` runs on the runtime's link, authenticated with the saved session. It first moves the pairing to a new binding in the next host trust generation (`pairing::rebind_for_verification`, durable before `verifyCommit`), because every ceremony reveals a fresh `host_channel_key`. The Astation, session and shared login stay.
- Verification pins the account's signed device list. Relay only and the host route proof build on it. See [account-trust.md](account-trust.md).
- `atem unpair` commits the next host trust generation, removes the pairing record and sends the runtime `reload`.

## Relay identity room and Stations

- The Station is the relay service at `astation_relay_url`. `https://` becomes `wss://` (`http://` becomes `ws://`).
- Atem joins `<station>/ws?role=atem&code=<astation_id>&atem_id=<atem_id>`.
- Astation keeps a room named by its id. The relay tells the Atems in one room apart by `atem_id`.
- The room code authorizes nothing. A session proof, or the host route proof, is still required.
- The production Station `https://station.agora.build` is the compiled default. Dev profiles set `https://station-dev.agora.build` in config.toml.
- Vault, memory and skills HTTP calls go to the same Station with the pairing's session id (`auth::require_pairing`).

Transport security:

- A relay link is WSS.
- A direct link to a LAN or VPN address is plaintext `ws://`. The proof shows possession of the token. It doesn't encrypt the link or stop an active man-in-the-middle.
- A session grant and `credentialSync` cross such a link in the clear.
- r9 channel traffic (`atem-ch1`) is end-to-end encrypted on any link.

## Relay only (§R9.8a)

- A host with a pinned device list can have a host policy, stored in `pairing/host_policy.json`. Without one, local is allowed.
- Only a native member holding `manage` sets or reads it, inside an admitted `atem-ch1` channel (`host_policy_set` / `host_policy_get`). There is no plaintext form: `transportPolicy` and `transportPolicyAck` are removed ops.
- While the policy says relay only (or can't be read, or a write of it is uncertain), the connect loop skips the local step.
- With the relay unreachable there is no local fallback: the 30 s retry.
- A commit of `true` while the link is local drops that link once the result was written, after any running operation, at most 5 s later. The reconnect goes through the relay.
- A local link that (re)authenticates under relay only is dropped the same way.
- First pairing (no record) still tries local first.
- `atem status` adds `relay only (host policy)` to the Pairing line.
- `atem unpair` and a new pin remove the policy files.

## Routed links (host route proof, §R9.7b)

- The relay challenges every host connection: `{"type":"relay","op":"host_challenge","v":1,"nonce","room"}`.
- A host with a pinned device list that can serve (not held, frozen or faulted; journal not halted) answers once, from the link's reader, before Astation authenticates. The answer is `host_route{proof}`, signed by `host_channel_key` at the list's head for the link's `atem_id` and room. Any other host sends nothing.
- The relay checks the proof against its own copy of the log and answers `host_route_ok` or `host_route_refused{code}`. A refusal drops the link, and Atem retries.
- Carrier (A), owner-present: the Mac is in the room and authenticates the link as above. Pairing, first verification and a held host's reconciliation use it.
- Carrier (B), the proved route: the relay creates or holds the room without the Mac. A held or unpinned host only has (A).
- A link the relay routed and no Astation authenticated is held routed (`App::astation_routed`). It carries r9 channels and push relay messages only: never r8, Astation operations, credentials or mark tasks.
- A routed link has no auth timeout and isn't retried while it lasts. One that drops within 10 s of being routed (or of a failed authentication) retries after 30 s, else at once.
- The verdict counts in either order relative to Astation's `auth_required`.
- Astation's later `auth_required` upgrades a routed link with the connect path's semantics (300 s). A denial keeps it routed.
- After enrollment or a reconciliation, a relay link that proved no route reconnects once, so it proves its route. It waits for a running operation and a pending admission (≤ 30 s). A local link never does.
- `atem status` shows `Authorization: r9 routed (no Astation)`.

## Re-authentication

- Astation sends `auth_required` on an already-authenticated socket when it alone reconnected to the relay (`app/reauth.rs`).
- Atem shows `Astation ✗`, fences the session attachment and ignores every other Astation request.
- It answers only the pinned Astation, non-interactively, with the connect path's proof (`AstationClient::answer_auth_required`, the shared `auth_proof`).
- Success restores the link as a new attachment.
- Denial, expiry, another `astation_id`, or no answer within 15 s leaves a notice and closes the socket for the normal reconnect. It never pairs.
- An r8 attachment is authorized for 24 h. Then it is fenced, the link is dropped and the reconnect authenticates again. An r9 host keeps its link; each channel has its own lifetime.

## Switching Stations and pairings

- The runtime's local `reload` request re-reads config.toml and the pairing. `atem unpair` and `atem logout` send it to a running runtime; they never start one.
- A link whose pairing changed is dropped with its attachments. The runtime also checks this every 5 s, so an unpair works without `reload`.
- A relay link reached at another Station than the configured `astation_relay_url` (a trailing `/` aside) is dropped at `reload` (`App::station_changed`, `LinkVia::Relay.url`). Its attachments, channels and leases go with it, and the reconnect goes to the configured Station at once.
- A local link stays at a Station change.
- v0.8.0 has no `atem runtime reload` subcommand. After editing `astation_relay_url`, run `atem runtime restart` (sessions keep running); any later reconnect also reads the new URL.

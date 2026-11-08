# Atem ↔ Astation connection

Status: current design (Atem v0.8.3).

How Atem reaches Astation: the link, its order, authentication, pairing, the relay, r9's relay only and routed links, re-authentication and Station selection. AGENTS.md ("Astation Integration", "Logins and the pairing", "SSO auth", "r9 remote clients") has the full detail.

## Overview

- Only `atem runtime` holds an Astation link: one per config dir, so one per machine and user. Bare `atem` and the CLI commands open none.
- `atem pair`, `atem pair verify`, `atem cred unlock|projects` and the paired-token refresh run as operations inside the runtime, on its link. See [agent-runtime.md](agent-runtime.md).
- Atem always dials out. It opens no port.
- A link is one WebSocket: local (`astation_ws`) or the paired Astation's identity room on a Station (the one Astation selected, else `astation_relay_url`; see [Station selection](#station-selection)).
- Astation authenticates the link. The relay only routes it, except for the r9 host route proof.
- r8 session-v1, terminal-v1 and chat-v1 run on the authenticated link. On a host with a device list, r9 clients come through `atem-ch1` channels carried on the same link. See the r9 appendix of [atem-session-v1.md](protocol/atem-session-v1.md).
- **Planned (owner decision 2026-11-08), not implemented:** no host serves r8 on the link; remote sessions run only inside `atem-ch1` channels. See [Remote sessions need r9](#remote-sessions-need-r9-planned).

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

`ASTATION_WS` and `ASTATION_RELAY_URL` override them. A Station that Astation selected overrides `astation_relay_url` for the runtime's link (see [Station selection](#station-selection)). There is no relay code setting: the room is the pairing's `astation_id`.

## Connection order

The runtime connects when it starts and whenever it has no link (`App::spawn_astation_connect`). Each attempt re-reads config.toml and the pairing record.

1. Read `pairing/pairing.enc` and the Station to use (`station_route::destination`). An unreadable record fails closed: no local attempt, no relay, the error as the status (`app::PAIRING_UNREADABLE`), the 30 s retry. So does an unreadable `pairing/station_route.json` ("selected Station state unreadable; no routing fallback").
2. Local: connect `astation_ws` (5 s) and authenticate without pairing. Skipped while the host policy says relay only, and while the selected Station blocks direct (`direct_blocked`).
3. Relay: only with a pairing record. Join the paired Astation's identity room on the chosen Station and authenticate without pairing, or be routed (r9). A selected Station that is down never falls back to another one.
4. Both fail: no link, and another attempt in 30 s.

- A dropped authenticated link reconnects at once after it stayed up for ten seconds; shorter-lived links retry after 30 seconds to avoid flicker. Deliberate selected-Station migrations reconnect at once.
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
- The proof runs one way. Atem proves itself to Astation and doesn't authenticate Astation in return: it accepts `authenticated` or `auth{granted}` from whoever answered (`auth_response_saving`, no proof checked), and takes the challenge's `transport` on the peer's word. Anything that ends the socket can answer as Astation: the relay operator, an active attacker on a `ws://` link, another process listening on `127.0.0.1:8080`.

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
- `atem pair verify` on a pairing the Astation already verified prints `Already verified (safety code …)` and connects to nothing, whether or not a device list is pinned. **Planned (owner decision 2026-11-08), not implemented:** it runs the ceremony again when the verified pairing has no pinned list, so a host verified before device lists were pinned can pin one (see [Remote sessions need r9](#remote-sessions-need-r9-planned)).
- `atem unpair` commits the next host trust generation, removes the pairing record and tells a running runtime, which drops that pairing's link with its attachments.

## Relay identity room and Stations

- The Station is the relay service: the one Astation selected, else `astation_relay_url`. `https://` becomes `wss://` (`http://` becomes `ws://`).
- Atem joins `<station>/ws?role=atem&code=<astation_id>&atem_id=<atem_id>`.
- Astation keeps a room named by its id. The relay tells the Atems in one room apart by `atem_id`.
- The room code authorizes nothing. A session proof, or the host route proof, is still required.
- The production Station `https://station.agora.build` is the compiled default. Dev profiles set `https://station-dev.agora.build` in config.toml.
- Vault, memory and skills HTTP calls use the Station from `ASTATION_RELAY_URL`, `astation_relay_url` or the default, with the pairing's session id (`auth::require_pairing`). They do not follow a selected Station.

Transport security:

- A relay link is WSS.
- A direct link to a LAN or VPN address is plaintext `ws://`. The proof shows possession of the token. It doesn't encrypt the link or stop an active man-in-the-middle.
- A session grant and `credentialSync` cross such a link in the clear.
- Atem doesn't authenticate Astation when it connects (see Authentication), so a direct link is open to an active attacker at pairing and afterwards, not only "during initial pairing". WSS certificate pinning is not implemented.
- r9 channel traffic (`atem-ch1`) is end-to-end encrypted on any link, and both ends are authenticated inside the channel.
- An r8 host (no device list) also sends session-v1, terminal-v1 and chat-v1 on this link, readable and forgeable by whatever ends the socket. **Planned (owner decision 2026-11-08), not implemented:** r8 is no longer served (next section).

## Remote sessions need r9 (planned)

**Planned (owner decision 2026-11-08), not implemented.** Atem serves remote sessions only over r9 (`atem-ch1`).

Today:

- A host with a pinned device list admits remote clients only through `atem-ch1` channels and refuses an r8 `hello` on the link.
- A host without one (a pairing verified before device lists were pinned and not verified since) welcomes an r8 `hello` from the paired Astation on the link: `view` and `control` for 24 h, with session-v1, terminal-v1 and chat-v1 readable by the relay. The peer is not authenticated to Atem (Authentication, above), so the relay operator, a `ws://` attacker or a local listener on `127.0.0.1:8080` can take that role.

Planned:

- Every host refuses an r8 `hello`. The link has no session attachment of its own.
- A host without a pinned list serves no remote client until one is pinned. Local agents, the terminal and the Astation operations (`atem pair`, `atem pair verify`, `atem cred …`, `credentialSync`, Station selection) are unaffected.
- `atem pair verify` pins the list (`atem unpair`, then `atem pair`, also works).
- `atem status` shows `Authorization: not authorized (no device list pinned; Atem serves remote sessions only over r9: run atem pair verify)`, and runtime.log gets a line at start and one per refused `hello`.
- The clear relay push messages (`push_approval`, `push_resolved`) go; the sealed hints of r9 stay.
- No Station change. Astation's apps already use r9. The timing needs Astation's agreement: an Astation that still reaches such a host over r8 stops working when this ships.

The wire rules are in the r9 appendix of [protocol/atem-session-v1.md](protocol/atem-session-v1.md) ("No r8 admission").

## Station selection

Astation can pick the Station for this Atem. This is station-route v1, released in Atem v0.8.2. The wire contract is [protocol/station-route-v1.md](protocol/station-route-v1.md).

- On an authenticated Astation link the runtime asks for a selection every 30 s. Astation's offer is a Station origin plus `relay_only`, signed with an HMAC under the saved session token. The token is never sent. Atem checks the offer against its pairing, saves it and acknowledges it with a second HMAC.
- Atem stores `pairing/station_route.json` (0600): the signed offer with its request context and revisions, and a `direct_blocked` bit. It is routing metadata only. It holds no token or other credential. `atem unpair` removes it. A selection saved under another binding, trust generation or session id is ignored.
- For the runtime's WebSocket link the Station is chosen at each connect (`station_route::destination`): the saved selection first; with none, `ASTATION_RELAY_URL`, then `astation_relay_url` in config.toml, then `https://station.agora.build`. While a selection is saved, the env variable and config.toml do not move that link.
- A selected Station that is down is retried every 30 s. There is no fallback to the production or configured Station. A damaged selection file stops the connect.
- `relay_only:true` in an offer sets `direct_blocked`: no local link. Only a native manager's `host_policy_set{relay_only:false}` at a newer policy revision clears it. An offer cannot.
- A changed selection reconnects the runtime to the new Station once any running pairing or unlock operation ends. Workers, sessions and receipts keep going. Clients open fresh channels.
- Vault, memory and skills HTTP calls and the first relay registration of `atem pair` do not follow the selection. They use `ASTATION_RELAY_URL`, `astation_relay_url` or the default.
- **Not implemented:** following the selected Station for those HTTP calls. It needs its own authorization and token-audience contract.
- `atem status` shows the Station in use on the `Relay` line (`connected via relay (<host> as <atem_id>)`).
- Without Astation's selection, switching Stations means changing `astation_relay_url` (or `ASTATION_RELAY_URL`) and running `atem runtime restart`. There is no `atem runtime reload` command.

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
- An r8 attachment is authorized for 24 h. Then it is fenced, the link is dropped and the reconnect authenticates again. An r9 host keeps its link; each channel has its own lifetime. **Planned (owner decision 2026-11-08), not implemented:** with r8 gone only the channel lifetimes remain.

## Switching Stations and pairings

- Astation's selection changes the runtime's Station without a restart (see [Station selection](#station-selection)).
- Otherwise set `astation_relay_url` (`atem config set astation_relay_url <url>`) or `ASTATION_RELAY_URL`, then run `atem runtime restart`. config.toml is re-read at each connect attempt, but an established link keeps its Station until it drops, and the runtime reads the env variable from its own environment. `atem runtime restart` keeps the sessions.
- A saved selection beats that setting. To leave it, Astation selects another Station, or run `atem unpair` and `atem pair`.
- `atem unpair` and `atem logout` tell a running runtime (they never start one) to `reload`: it re-reads the config and drops a link whose pairing changed, with its attachments. The runtime also checks the pairing every 5 s, so an unpair takes effect either way. `reload` is not a CLI command and does not move a healthy link to another Station.

# atem-session v1: sessions, control leases and receipts (DRAFT for joint review)

Status: Atem-side draft, 2026-10-15, for review by the Astation agent. Implements
the Atem-owned parts of [session-multiplexing.md](../session-multiplexing.md)
§2–§5 on the wire. Nothing here is final until both sides accept it and the
fixtures in `fixtures/` pass on both. Sections marked **JOINT — OPEN** need the
joint trust/transport specification and are placeholders only.

## 0. Scope and layering

```
+--------------------------------------------------------------+
| atem-session v1 (this doc): registry, leases, receipts       |
| terminal-v1 (existing) / chat-v1 (existing) streams           |
+--------------------------------------------------------------+
| secure channel (JOINT — OPEN): E2EE, endpoint keys, freshness |
+--------------------------------------------------------------+
| transport: direct ws :8080  |  relay (atem_id + connection_id)|
+--------------------------------------------------------------+
```

- Direct and relay are thin transports. Every message below is identical on
  both; the host deduplicates across them.
- Until the secure channel exists, these messages run inside today's
  authenticated Astation connection (no relay confidentiality is claimed).
- terminal-v1 and chat-v1 keep their own ops. This contract replaces their
  addressing (`terminal_id`/`agentId` = `session_id`) and their control rule
  (one lease per session, defined here) — see §6.

## 1. Envelope

```json
{"type":"session","data":{"v":1,"op":"…","id":"<message id>", …}}
```

- `v` = 1. A receiver ignores unknown fields and refuses unknown `v` with
  `error{code:"unsupported_version"}`.
- `id`: sender-unique message id (UUID); replies carry `re` = the request's
  `id`. Replies are not deduplicated by `id`; submissions are deduplicated by
  `request_id` (§5).
- Host = Atem runtime. Client = one authenticated Astation connection
  (`controller_session` below).

## 2. Identities and generations

| Field | Format | Meaning |
|---|---|---|
| `account_id` | opaque string | account owning the data |
| `atem_device_id` | opaque string | Atem device/profile identity (existing `device_id`) |
| `host_trust_gen` | integer ≥ 1 | increments durably on unpair/rebind; older values rejected |
| `runtime_gen` | UUID | new each time the broker (runtime) starts |
| `session_id` | `ses-` + 12 `[a-z2-7]` | one agent session; stable for its life |
| `process_gen` | UUID | one agent process of a session; a provider resume is a new one |
| `controller_session` | UUID | one authenticated client connection's controller identity (assigned by the host on `hello`; survives a transport switch only through `resume`, §3) |
| `lease_epoch` | integer | increments on every grant/transfer/expiry/revoke of a session's lease |
| `request_id` | UUID | one high-level submission (§5) |

Every mutating request carries the full target:
`{account_id, atem_device_id, host_trust_gen, session_id, process_gen}`. A
mismatch on any field is `error{code:"stale_target"}` with the current values
the client is allowed to see.

## 3. Hello and connection identity

| op | dir | fields |
|---|---|---|
| `hello` | C→H | `client_device_id`, `client_kind` (`native`, `browser`), `resume?{controller_session}` |
| `welcome` | H→C | `account_id`, `atem_device_id`, `host_trust_gen`, `runtime_gen`, `controller_session`, `permissions` (list), `authorization_expires_at` (ms), `server_time` (ms) |

- `resume` keeps the same `controller_session` on a new transport only if the
  host still knows it and its authorization is valid; leases are NOT resumed
  (an expired lease stays expired; a live one continues only if the same
  `controller_session` renews before expiry).
- Authentication of `hello` is the secure channel's job (**JOINT — OPEN**);
  today it is the existing Astation authentication of the socket.

## 4. Session registry

| op | dir | fields |
|---|---|---|
| `list` | C→H | — |
| `sessions` | H→C | `runtime_gen`, `sessions: [session]` |
| `session_changed` | H→C | `session` (pushed on launch, status change, exit, removal) |

`session`:

```json
{"session_id":"ses-abcdefghijkl","process_gen":"…","provider":"claude",
 "cwd_label":"Atem","state":"running|exited|interrupted|recovery_required|closed",
 "activity":"ready|working|waiting|unknown","activity_since":1760500000000,
 "controller":{"controller_session":"…","lease_epoch":7,"expires_at":1760500015000}|null,
 "capabilities":["terminal-v1","chat-v1"],"created_at":1760490000000}
```

- `cwd_label` is the last path component only (no full paths over the wire).
- `interrupted`: the worker/agent ended unexpectedly; `recovery_required`: the
  host can't confirm the worker (e.g. after reboot); a provider resume, if
  offered, creates a new `process_gen`.

## 5. Control leases

| op | dir | fields | result |
|---|---|---|---|
| `acquire` | C→H | target, `takeover: bool` | `lease{session_id, lease_epoch, expires_at}` or `error` |
| `renew` | C→H | target, `lease_epoch` | `lease{…}` (new `expires_at`) or `error` |
| `release` | C→H | target, `lease_epoch` | `lease_released{session_id, lease_epoch}` |
| `lease_changed` | H→C (all viewers) | `session_id`, `controller` (as in `session`), `reason` (`granted`, `takeover`, `local_input`, `expired`, `released`, `revoked`, `process_ended`) |

Rules (host-enforced, serialized per session):

- One lease per session. `expires_at` = grant/renew time + 15 000 ms, or the
  controller's `authorization_expires_at` if sooner. No renewal by then → the
  lease expires (`reason: expired`).
- `acquire` with a lease held by another controller: `takeover:false` →
  `error{code:"lease_held"}`; `takeover:true` → transfer (needs the `control`
  permission), previous holder gets `lease_changed{reason:"takeover"}` and stays
  a viewer.
- Local terminal input on the host takes the lease locally: the remote lease is
  revoked atomically (`reason:"local_input"`) before that input is written.
- Every mutation (terminal input/resize/stop, chat submit, interrupt, future
  APIs) carries `lease_epoch` and is rejected with `error{code:"stale_lease"}`
  unless it equals the session's current epoch held by this
  `controller_session`. Delayed input from an old epoch or `process_gen` is
  never written.
- Disconnect does not release immediately; the lease simply stops being renewed.
  Reconnect never reacquires automatically.

## 6. Submissions and receipts

A submission is a high-level request (chat prompt, interrupt, provider
approval answer, stop). Raw terminal keystrokes are NOT submissions; they are
a live stream (terminal-v1 `input`) checked only against the lease.

| op | dir | fields |
|---|---|---|
| `submit` | C→H | target, `lease_epoch`, `request_id`, `kind` (`prompt`, `interrupt`, `stop`), `payload`, `payload_digest` (SHA-256 hex of the canonical payload JSON) |
| `receipt` | H→C | `request_id`, `session_id`, `process_gen`, `state`, `detail?`, `updated_at` |
| `receipt_query` | C→H | `session_id`, `request_ids: [..]` (≤ 64) |
| `receipts` | H→C | `receipts: [receipt]` |

`state`:

| state | meaning |
|---|---|
| `accepted` | durably recorded by the worker; not yet dispatched |
| `executing` | dispatched to the agent |
| `completed` | the agent's turn for it ended (chat-v1 `complete`) |
| `rejected` | refused; `detail` says why; nothing was dispatched |
| `outcome_unknown` | dispatched before a crash and the outcome can't be recovered |

- Acceptance means the worker wrote the receipt to its journal and synced it;
  the host replies `receipt{state:"accepted"}` only after that.
- Same `request_id` + same digest → the recorded receipt, never re-executed.
  Same `request_id` + other digest → `error{code:"request_id_reused"}`.
- Receipts are kept for the session's life and 7 days after it closes. A
  session that reaches its receipt limit refuses new submissions with
  `error{code:"receipt_limit"}`; receipts of an accepting session are never
  evicted. Closed sessions reject submissions with `error{code:"session_closed"}`.
- chat-v1's `submit`/`accepted`/`complete` map onto this: its `requestId` is
  the `request_id`; its acceptance requires the receipt to be `accepted` first.

## 7. Errors

`error{re, code, message, target?}`; `message` is human-readable, never
contains secrets, paths or raw OS errors.

| code | when |
|---|---|
| `unsupported_version` | unknown `v` |
| `unauthorized` | not authenticated / authorization expired / not fresh |
| `forbidden` | missing permission (`view`, `control`, `approve`, `manage`) |
| `stale_target` | trust generation, session or process generation mismatch |
| `unknown_session` | no such session |
| `lease_held` | another controller holds the lease (no takeover) |
| `stale_lease` | wrong or expired `lease_epoch` |
| `request_id_reused` | same request id, other payload |
| `receipt_limit` | the session's receipt journal is full |
| `session_closed` | the session no longer accepts submissions |
| `busy` | the agent can't take a submission now (e.g. chat-v1 not ready) |
| `paused` | authorization freshness deadline passed; viewing/control paused |

## 8. Freshness, trust and encryption — JOINT — OPEN

Placeholders only; to be specified jointly before implementation:

- Trust anchor, enrollment, membership certificates, management authority,
  host acceptance of account-wide enrollment, unpair/rebind (`host_trust_gen`).
- Authenticated freshness proof for the 24-hour window, clock and restart
  handling, persisted high-water marks; how `authorization_expires_at` is
  derived and refreshed.
- End-to-end encrypted channel binding endpoint keys, account, roles,
  permissions, generations; replay/downgrade protection; how direct :8080 and
  relay share it.
- Browser QR request/grant formats and validation without an online native
  bridge.

## 9. Fixtures

`fixtures/*.json` hold one JSON object per file:
`{"name": "...", "messages": [{"dir":"C→H"|"H→C","json":{…}}...], "expect": "..."}`
covering: hello/welcome; list/sessions; acquire/renew/expiry; takeover;
local-input revocation; stale epoch input; submit accepted → completed;
duplicate submit; reused request id; crash → outcome_unknown; closed session.
Both implementations replay them in tests.

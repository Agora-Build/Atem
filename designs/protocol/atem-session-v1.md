# atem-session v1: sessions, control leases and receipts (DRAFT r2 for joint review)

Status: Atem-side draft r2, 2026-10-15. r1 (`7a0c691`) was reviewed by Astation
([review](https://truck.netbird.cloud:58310/protocol/atem-session-v1-review.md),
summarised in [session-multiplexing.md](../session-multiplexing.md) §12); r2
answers review items 1–7 and 9. Item 8 (trust, freshness, end-to-end channel,
QR grants) stays an implementation gate (§9). Not final until both sides
accept it and the fixtures in `fixtures/` pass in Rust, Swift and the browser.

## 0. Layering and activation

```
+-----------------------------------------------------------------+
| atem-session v1 (this doc): registry, leases, receipts          |
| terminal-v1 / chat-v1 streams, bound to this doc's targets      |
+-----------------------------------------------------------------+
| secure channel (§9 gate): endpoint keys, E2EE, freshness        |
+-----------------------------------------------------------------+
| transport: direct ws :8080  |  relay (atem_id + connection_id)  |
+-----------------------------------------------------------------+
```

- Direct and relay are thin transports; messages are identical on both and the
  host deduplicates across them.
- **Compatibility mode** (until §9 is implemented): the messages run inside
  today's authenticated Astation socket for isolated tests and for the one
  Astation already verified with this host. In this mode: no resume (§3), no
  browser clients, no account-wide native access, and no claim of relay
  confidentiality. Admission fails closed; no placeholder trust decision is
  exposed as production authorization.
- **Upgrade**: a connection is "upgraded" once `welcome` is received. On an
  upgraded connection this contract's lease is the only control lifecycle:
  terminal-v1 `control`, legacy `agentInput`, `agentPrompt`, voice commands,
  `userCommand` and chat-v1 `submit` without a session binding are rejected with
  `error{code:"forbidden"}` (legacy messages stay as today on non-upgraded
  connections).

## 1. Representation

| Item | Rule |
|---|---|
| Envelope | `{"type":"session","data":{"v":1,"op":"…","id":"<uuid>", …}}`; replies carry `re` |
| UUID | lowercase canonical v4 (`8-4-4-4-12`), validated |
| `session_id` | `ses-` + exactly 12 chars `[a-z2-7]` |
| Opaque ids (`account_id`, `atem_device_id`, `client_device_id`) | 1–128 bytes, `[A-Za-z0-9._:-]` |
| Counters (`host_trust_gen`, `lease_epoch`, `revision`) | JSON integers 0 ≤ n ≤ 2^53−1; a value that would exceed it is refused (`error{code:"unsupported_version"}` for peers, fatal for the host's own counters: it stops admitting and asks for re-pairing) — never wraps |
| Times | integer milliseconds since the Unix epoch; **display/estimation only** — authority uses monotonic clocks (§5) |
| Digest | SHA-256, lowercase hex, 64 chars |
| Bounds | message ≤ 1 MiB after decoding; `payload` ≤ 64 KiB canonical; prompt text ≤ 32 768 bytes; `receipt_query.request_ids` ≤ 64; `detail` ≤ 512 bytes; ≤ 64 in-flight requests per attachment (excess → `busy`) |
| Unknown fields | ignored; unknown `v` → `unsupported_version` |
| Parsing | bounds checked before allocation; duplicate object keys, non-integer numbers where integers are required, and out-of-range values are rejected |

## 2. Identities, target and binding

| Field | Meaning |
|---|---|
| `account_id` | account owning the data |
| `atem_device_id` | this Atem device/profile |
| `host_trust_gen` | increments durably on unpair/rebind; older values rejected |
| `runtime_gen` | UUID, new each broker (runtime) start |
| `session_id` | one agent session, stable for its life |
| `process_gen` | UUID, one agent process; replacement/resume = new value |
| `controller_session` | UUID, logical controller identity assigned by the host |
| `attachment_gen` | UUID, one live attachment of a controller to the host; new on every connect/resume; fences the previous one |
| `lease_epoch` | per session, increments on every grant, transfer, expiry, release, revoke |

Every request that targets a session carries one **binding** object:

```json
{"target":{"account_id":"account-a","atem_device_id":"host-a","host_trust_gen":1,
           "session_id":"ses-abcdefghijkl","process_gen":"22222222-2222-4222-8222-222222222222"},
 "attachment_gen":"33333333-3333-4333-8333-333333333333",
 "lease_epoch":7}
```

- Session ops (§4–§6) carry it as `binding`. terminal-v1 and chat-v1 messages on
  an upgraded connection carry it as a top-level `binding` field next to their
  existing fields (`terminal_id`/`agentId` must equal `target.session_id`,
  `generation` must equal `target.process_gen`).
- `lease_epoch` is required for mutations, absent for reads.
- Any mismatch → `error{code:"stale_target"}` with **no** current values; the
  client re-lists (§4). Errors never reveal another target's ids, paths or
  receipts; an unauthorized or unknown session is `unknown_session` either way.

## 3. Hello, attachment and resume

| op | dir | fields |
|---|---|---|
| `hello` | C→H | `resume?: {controller_session}` |
| `challenge` | H→C | `nonce` (32 bytes, base64url) — only when resuming |
| `resume_proof` | C→H | `proof` (§9: signature by the client's authenticated key over the transcript) |
| `welcome` | H→C | `account_id`, `atem_device_id`, `host_trust_gen`, `runtime_gen`, `controller_session`, `attachment_gen`, `client_kind` (`native`/`browser`, as authenticated), `permissions` (`view`, `control`, `approve`), `authorization_ms_left`, `server_time` |

- The client's device and kind come from the authenticated channel, never from
  `hello` fields or relay labels. A `controller_session` UUID is not a credential.
- Resume needs key possession over a fresh `challenge` and yields a **new**
  `attachment_gen`; the host fences the old attachment (closes it and rejects
  anything still arriving on it) before accepting mutations on the new one.
  Resume never re-acquires a lease and never revives an expired one.
- Compatibility mode: no `challenge`/`resume_proof`; every `hello` gets a new
  `controller_session` and `attachment_gen` and holds no lease.
- A broker restart (new `runtime_gen`) invalidates all attachments and leases;
  workers and receipts stay addressable by `session_id`/`process_gen`.

## 4. Session registry

| op | dir | fields |
|---|---|---|
| `list` | C→H | — |
| `sessions` | H→C | `runtime_gen`, `revision`, `sessions: [descriptor]` |
| `session_changed` | H→C | `runtime_gen`, `revision`, `descriptor` |

Descriptor:

```json
{"session_id":"ses-abcdefghijkl","process_gen":"…","provider":"claude",
 "cwd_label":"Atem","state":"running","activity":"ready","activity_since":1760500000000,
 "controller":{"controller_session":"…","lease_epoch":7}|null,
 "capabilities":["terminal-v1","chat-v1"],"created_at":1760490000000}
```

- `state`: `running`, `exited`, `interrupted`, `recovery_required`, `closed`,
  `removed` (tombstone). `activity`: `ready`, `working`, `waiting`, `unknown`.
- `revision` is scoped to `runtime_gen`, starts at 1, and increases by exactly 1
  per `session_changed`. Clients: apply a `session_changed` only if
  `revision == last + 1` (same `runtime_gen`); on a gap, a new `runtime_gen` or
  out-of-order delivery, send `list` and replace state with a snapshot whose
  `revision` ≥ the last applied one; discard older snapshots. A removed session
  is sent as `state:"removed"` and kept as a tombstone for 10 minutes so a late
  update can't resurrect it.
- The registry and every response are filtered by the attachment's view
  permission. `cwd_label` is the last path component only; clients show
  `session_id` when labels repeat. Presence is never liveness evidence.

## 5. Control lease

| op | dir | fields | result |
|---|---|---|---|
| `acquire` | C→H | `binding` (no `lease_epoch`), `takeover` | `lease` or `error` |
| `renew` | C→H | `binding` | `lease` or `error` |
| `release` | C→H | `binding` | `lease_released` |
| `lease` | H→C | `binding` (with the current `lease_epoch`), `ms_left` | — |
| `lease_changed` | H→viewers | `session_id`, `process_gen`, `controller` (or null), `lease_epoch`, `reason` (`granted`, `takeover`, `local_input`, `expired`, `released`, `revoked`, `process_ended`) | — |

Normative rules:

- **Duration**: a lease lasts 15 s from its grant/renewal on the host's
  monotonic clock, capped by the attachment's remaining authorization. Clients
  renew every 5 s and never after their own monotonic estimate of expiry.
  `ms_left` is for estimation only.
- **Fencing**: a lease is held by one (`controller_session`, `attachment_gen`).
  Only a `lease` reply whose binding matches the client's current attachment,
  target and epoch advances its local deadline; any other reply is ignored.
- **Renew** after expiry → `stale_lease` (it never re-acquires).
- **Repeat acquire** by the current holder on the same attachment returns the
  current lease unchanged (same epoch, no extension); on another attachment of
  the same controller → `stale_lease` (resume first).
- **Takeover** (`takeover: true`, needs `control`) moves the lease to the caller
  with a new epoch; the previous holder gets `lease_changed{reason:"takeover"}`
  and stays a viewer. Without takeover a held lease → `lease_held`.
- **Local input wins**: local terminal input on the host revokes any remote lease
  (new epoch, `reason:"local_input"`) before that input is written.
- **Input epoch**: the worker's PTY writer checks the session's input epoch at
  write time for every queued chunk. Transfer, expiry, release, local input and
  revoke bump that epoch first, so already-queued remote bytes are dropped, not
  written. Raw keystrokes are never replayed after reconnect.
- **Restart**: leases are not persisted. A worker restart (new `process_gen`) or
  broker restart (new `runtime_gen`) invalidates them; the epoch counter itself
  is persisted per session so it never repeats.
- **Scope**: the lease governs terminal input/resize/stop, chat submission,
  interrupt, approval answers and future mutations. Disconnect stops renewal;
  the lease then expires.

## 6. Submissions and receipts

| op | dir | fields |
|---|---|---|
| `submit` | C→H | `binding` (with `lease_epoch`), `request_id`, `kind`, `payload` |
| `receipt` | H→C | `request_id`, `target`, `kind`, `state`, `detail?`, `updated_at` |
| `receipt_query` | C→H | `binding` (no `lease_epoch`), `request_ids` (≤ 64) |
| `receipts` | H→C | `receipts: [receipt]` (only those bound to that exact target) |

Kinds and payloads (v1):

| kind | payload | completes when |
|---|---|---|
| `prompt` | `{"text": string}` | the provider confirms the turn ended (chat-v1 `complete`) |
| `interrupt` | `{}` | the provider reports the turn interrupted, or the turn was already over (`detail`) |
| `stop` | `{}` | the agent process exits |
| `approval` | reserved for v1.1 (needs an approval identity); rejected with `forbidden` + `detail:"approval answers are not supported in v1"` |

- **Digest**: the host computes `payload_digest = sha256(JCS(payload))`, JCS =
  RFC 8785 over the supported domain (objects, arrays, strings, booleans, null,
  integers in the safe range; no floats). A client-supplied digest is not used.
  Known-answer vectors: `fixtures/digest-vectors.json`.
- **Immutable request**: (`request_id`, `account_id`, `atem_device_id`,
  `host_trust_gen`, `session_id`, `process_gen`, `kind`, `payload_digest`).
  Same `request_id` with every bound value equal → the recorded receipt (needs
  current view permission for the target; no lease, no re-execution). Same
  `request_id` with any value different → `request_id_reused`.
- **Admission** of a new request needs the current lease (`stale_lease`
  otherwise), `control` permission, and a session that accepts submissions.
- **Crash boundaries**: `accepted` is persisted (fsync) before the reply;
  `executing` is persisted before the first external side effect (e.g. the
  paste). After a crash: `accepted` work may still run under its original target
  and only if the host trust generation is unchanged; otherwise it becomes
  `rejected` with `detail:"host trust changed"`. `executing` work is reconciled
  with the worker/provider; if that can't establish the outcome it becomes
  `outcome_unknown`. Nothing is resubmitted automatically.
- Controller disconnect and lease expiry don't cancel accepted work.
- **Retention**: receipts live for the session's life and 7 days after it closes.
  An accepting session's receipts are never evicted; at its limit new
  submissions get `receipt_limit`. Closed sessions answer `session_closed`.
- chat-v1 on an upgraded connection: its `submit.requestId` is this
  `request_id`, it carries `binding`, and its `accepted`/`complete` follow this
  receipt's `accepted`/`completed`.

## 7. Errors

`error{re, code, detail?}`; `detail` is human-readable, bounded, and never
contains secrets, paths, raw OS errors or other targets' identifiers.

| code | when |
|---|---|
| `unsupported_version` | unknown `v` or out-of-range representation |
| `unauthorized` | not authenticated, attachment fenced, or authorization expired |
| `forbidden` | missing permission, or a legacy op on an upgraded connection |
| `stale_target` | trust generation, session or process generation mismatch |
| `unknown_session` | unknown or not visible to this attachment |
| `lease_held` | another controller holds the lease (no takeover) |
| `stale_lease` | wrong, expired or other-attachment lease epoch |
| `request_id_reused` | same request id, different bound values |
| `receipt_limit` | the session's receipt journal is full |
| `session_closed` | the session no longer accepts submissions |
| `busy` | the agent or attachment can't take it now |
| `paused` | authorization freshness deadline passed; viewing/control paused |

## 8. Fixtures

One JSON file per scenario in `fixtures/`, schema `fixtures/schema.md`:

```json
{"name":"lease-expires-without-renewal",
 "setup":{"sessions":[{"session_id":"ses-aaaaaaaaaaaa","process_gen":"…"}],"clients":["c1"]},
 "steps":[
   {"send":"c1","json":{"type":"session","data":{"v":1,"op":"acquire",…}}},
   {"expect":"c1","match":{"op":"lease","binding.lease_epoch":1}},
   {"advance_ms":15001},
   {"expect_all":{"op":"lease_changed","reason":"expired"}},
   {"send":"c1","json":{…"op":"renew"…}},
   {"expect":"c1","match":{"op":"error","code":"stale_lease"}},
   {"assert":{"pty_writes":0,"dispatches":0}}]}
```

Actions: `send`, `expect` (structured partial match), `expect_none` (for a
duration), `advance_ms` (fake monotonic clock), `disconnect`, `resume`,
`local_input`, `crash_worker`, `restart_runtime`, `assert` (host-side counters:
PTY writes, dispatches, receipts visible). Negative scenarios assert both the
error and the absence of writes, dispatch, disclosure or resurrection. The
first set: hello/welcome, list/snapshot+revision, gap recovery, tombstone,
acquire/renew/expiry, repeat acquire, takeover, local input revocation, queued
bytes dropped on transfer, stale epoch, submit accepted→executing→completed,
duplicate submit, reused id (other target), crash after executing →
outcome_unknown, trust change before dispatch → rejected, closed session,
receipt query scoped to target.

## 9. Gate: trust, freshness, channel and browser grants (joint)

Must be specified jointly, implemented and tested before account-wide native
access, resume, browser clients or relay confidentiality are enabled: trust
anchor installation, signed native membership and bounded management
delegation, host acceptance of account-wide authority, unpair generation
commits, signed revocation ordering, authenticated freshness proofs (the 24 h
window starts at a validated authority proof, never at relay presence,
reconnection, an old signature or a relay timestamp; rollback protection and
conservative restart/clock handling), channel key establishment with
replay/downgrade protection binding endpoint keys, account, roles, permissions
and generations, the `resume_proof` format, and QR grant binding.

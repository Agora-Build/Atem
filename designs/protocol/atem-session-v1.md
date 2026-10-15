# atem-session v1: sessions, control leases and receipts (DRAFT r5 for joint review)

Status: Atem-side draft r5, 2026-10-15. r1 (`7a0c691`), r2 (`9383193`), r3
(`1bf805c`, [r3 review](https://truck.netbird.cloud:58310/protocol/atem-session-v1-r3-review.md))
and r4 (`fd907cc`, [r4 review](https://truck.netbird.cloud:58310/protocol/atem-session-v1-r4-review.md))
were reviewed by Astation ([r1 review](https://truck.netbird.cloud:58310/protocol/atem-session-v1-review.md),
[r2 review](https://truck.netbird.cloud:58310/protocol/atem-session-v1-r2-review.md),
summarised in [session-multiplexing.md](../session-multiplexing.md) §12). r2
answered r1 items 1–7 and 9; r3 answered r2 review items 1–5; r4 answered the three r3 corrections; r5 answers the three r4 findings. Item 8 (trust, freshness, end-to-end channel,
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
- **One session authority, every connection.** Each session has exactly one
  lease authority on the host (§5), whatever socket, transport or message family
  a request uses. A connection is "upgraded" once it received `welcome`; upgrade
  changes how a client addresses things, not who may mutate a session:
  - terminal-v1 `control{take:true}` from a non-upgraded connection is an
    `acquire{takeover:true}` by that connection's attachment on the same
    authority; `control{take:false}` is `release`. Its `lease_id` maps to that
    lease.
  - A session is **managed** from the moment any attachment first acquires its
    lease (session `acquire` or legacy terminal-v1 `control`) until the session
    ends; the flag never clears (not on release, expiry or local reclaim).
    Legacy unscoped mutations (`agentInput`, `agentPrompt`, voice commands,
    `userCommand`, chat-v1 `submit` without `binding`) routed to a managed
    session are always rejected (`forbidden`, nothing written or dispatched),
    whether or not a remote holder exists, and they never acquire. Sessions that
    have never been managed keep today's legacy behaviour (routed per Atem's
    default-session rule); legacy can't create a path into a managed session.
  - Legacy terminal-v1 `control` keeps all its checks (permission, attachment,
    exact `terminal_id`/`generation`, subscribed `stream_id`, deadline) before it
    maps onto `acquire`/`release`.
  - On an upgraded connection every mutation must carry `binding` (§2) and the
    current lease; legacy unscoped mutations there are always `forbidden`.
  - Local terminal input on the host revokes any remote lease first (§5).
  Fixture `legacy-connection-cannot-bypass-lease`.

## 1. Representation

| Item | Rule |
|---|---|
| Envelope | `{"type":"session","data":{"v":1,"op":"…","id":"<uuid>", …}}`; replies carry `re` |
| UUID | lowercase canonical v4 (`8-4-4-4-12`), validated |
| `session_id` | `ses-` + exactly 12 chars `[a-z2-7]` |
| Opaque ids (`account_id`, `atem_device_id`, `client_device_id`) | 1–128 bytes, `[A-Za-z0-9._:-]` |
| Counters (`host_trust_gen`, `lease_epoch`, `runtime_epoch`, `seq`) | JSON integers 0 ≤ n ≤ 2^53−1; a value that would exceed it is refused (`error{code:"unsupported_version"}` for peers, fatal for the host's own counters: it stops admitting and asks for re-pairing) — never wraps |
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

- Session ops (§4–§6) carry it as `data.binding`. terminal-v1 and chat-v1
  carry it as `data.binding` too — inside `data`, next to the family's own
  fields, never inside a nested payload and never beside the outer envelope.
  Their own ids must agree with it: terminal-v1 `terminal_id` = chat-v1
  `agentId` = `binding.target.session_id`; terminal-v1 `generation` = chat-v1
  `generation` (both are the agent process's generation) =
  `binding.target.process_gen`. A disagreement is `stale_target`. Exact
  envelopes:

```json
{"type":"terminal","data":{"v":1,"op":"subscribe","terminal_id":"ses-aaaaaaaaaaaa","generation":"22222222-2222-4222-8222-222222222222",
  "binding":{"target":{…},"attachment_gen":"33333333-…"}}}
{"type":"terminal","data":{"v":1,"op":"input","terminal_id":"ses-aaaaaaaaaaaa","generation":"22222222-…","stream_id":"…","sequence":0,"bytes":"aGkN",
  "binding":{"target":{…},"attachment_gen":"33333333-…","lease_epoch":7}}}
{"type":"terminal","data":{"v":1,"op":"resize","terminal_id":"ses-aaaaaaaaaaaa","generation":"22222222-…","stream_id":"…","rows":40,"cols":120,
  "binding":{"target":{…},"attachment_gen":"33333333-…","lease_epoch":7}}}
{"type":"terminal","data":{"v":1,"op":"stop","terminal_id":"ses-aaaaaaaaaaaa","generation":"22222222-…","stream_id":"…",
  "binding":{"target":{…},"attachment_gen":"33333333-…","lease_epoch":7}}}
{"type":"agentChat","data":{"v":1,"op":"open","conversationId":"…","agentId":"ses-aaaaaaaaaaaa",
  "binding":{"target":{…},"attachment_gen":"33333333-…"}}}
{"type":"agentChat","data":{"v":1,"op":"submit","conversationId":"…","agentId":"ses-aaaaaaaaaaaa","generation":"22222222-…",
  "requestId":"44444444-…","text":"run the tests",
  "binding":{"target":{…},"attachment_gen":"33333333-…","lease_epoch":7}}}
```

  On upgraded connections the terminal-v1 `lease_id` field is not used (the
  binding's epoch replaces it); a chat `submit` is the §6 `submit` with
  `kind:"prompt"`, `request_id = requestId`, `payload = {"text": text}`.
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
| `sessions` | H→C | `runtime_gen`, `runtime_epoch`, `seq`, `sessions: [descriptor]` |
| `session_changed` | H→C | `runtime_gen`, `runtime_epoch`, `seq`, `descriptor` |

Descriptor:

```json
{"session_id":"ses-abcdefghijkl","process_gen":"…","provider":"claude",
 "cwd_label":"Atem","state":"running","activity":"ready","activity_since":1760500000000,
 "controller":{"controller_session":"…","lease_epoch":7}|null,
 "capabilities":["terminal-v1","chat-v1"],"created_at":1760490000000}
```

- Every descriptor field is **required** in both `sessions` and
  `session_changed` (a change carries the complete new descriptor, never a
  patch); `controller` is `null` when no lease is held and `capabilities` may be
  `[]`. Decoders reject a descriptor with a missing field. A removal is a
  complete descriptor with `state:"removed"` (its last values).
- `state`: `running`, `exited`, `interrupted`, `recovery_required`, `closed`,
  `removed`. `activity`: `ready`, `working`, `waiting`, `unknown`.
- **Runtime fencing.** `runtime_epoch` is a host-persisted counter incremented
  at every broker start (with `runtime_gen` its UUID). A client accepts a
  snapshot or change only if its `runtime_epoch` ≥ the highest it has accepted
  from this host; a higher epoch replaces all state (a snapshot at `seq` 1 of
  epoch 8 replaces `seq` 100 of epoch 7); anything from a lower epoch is
  discarded, so a delayed old-runtime snapshot can never switch the client back.
  Each accepted epoch has one fixed `runtime_gen`; the same epoch with a
  different `runtime_gen` is rejected. After accepting a new epoch from a
  change (not a snapshot), the client sends `list` and applies nothing from
  that epoch until its snapshot arrives.
- **Per-attachment sequence.** `list` subscribes the attachment. The host then
  sends, on that attachment's single ordered stream, one `sessions` snapshot
  followed only by `session_changed` events. `seq` counts the messages *this
  attachment* received in this epoch (snapshot = n, next change = n+1, …), so
  changes to sessions it can't see never create gaps. Within an epoch the client
  applies a change only if `seq == last + 1`; `seq ≤ last` is a duplicate and is
  ignored; `seq > last + 1` is a gap: it sends `list` and, until the new
  snapshot arrives, discards every change with `seq` ≤ that snapshot's `seq`.
  A snapshot whose `seq` is lower than the last applied one (same epoch) is
  discarded.
- **Removal.** A removed session is sent as `state:"removed"`; applying it
  deletes the session, and a later change for that `session_id` is only accepted
  with a higher `seq` in the same epoch and a different `process_gen` — never
  as a resurrection of the removed one. (Tombstones are kept 10 minutes host-side
  only to answer late requests with `unknown_session`.)
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
  monotonic clock (expired when `now >= grant + 15 000 ms`), capped by the attachment's remaining authorization. Clients
  renew every 5 s and never after their own monotonic estimate of expiry.
  `ms_left` is for estimation only.
- **Fencing**: a lease is held by one (`controller_session`, `attachment_gen`).
- **Reply correlation and the client deadline** (normative for clients):
  1. A `lease` reply is applied only if its `re` equals one outstanding
     `acquire`/`renew` request id, and each outstanding request consumes at most
     one reply; replies with an unknown, already consumed or duplicate `re` are
     dropped, even when the binding matches.
  2. Before applying it, the client checks its previously acknowledged local
     deadline on the monotonic clock; if that deadline has passed (`now >=
     deadline`, whether or not a UI timer fired), the reply is dropped, the
     client becomes a viewer, and only an explicit new `acquire` can regain
     control.
  3. Otherwise the new deadline = the request's monotonic **send** time +
     `ms_left` from the reply (never the reply's arrival time + 15 s), and never
     later than the authorization deadline.
  4. For a repeat `acquire` while already holding control, the new deadline =
     `min(previous deadline, request send time + ms_left, authorization
     deadline)`: it never extends and honours a shorter remaining lifetime.
  5. Expiry is `now >= deadline`, on both host and client. A client that computes
     a deadline already reached when it applies a reply disables control and input
     immediately (it never holds control with zero remaining lifetime). An explicit `acquire` after expiry is
     a new operation (rule 2 still discards replies to requests sent before it).
  Fixture `late-renew-reply-does-not-resurrect-control` (acquire at t=0, renew
  at t=5000, reply delivered at t=17000 with no timer tick; a duplicate earlier
  reply while a later renew is pending; a repeat-acquire reply near expiry).
- **Renew** after expiry → `stale_lease` (it never re-acquires).
- **Repeat acquire** by the current holder on the same attachment returns the
  current lease unchanged (same epoch, host deadline unchanged, `ms_left` = what
  remains); on another attachment of the same controller → `stale_lease`
  (resume first).
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
- **States and transitions** (all others are invalid and never happen):

| from | to | when |
|---|---|---|
| — | `accepted` | admitted and durably recorded (fsync) — then the reply |
| — | `rejected` | refused at admission (nothing recorded as accepted) |
| `accepted` | `executing` | durably recorded before the first external side effect |
| `accepted` | `rejected` | before any side effect: session closed, trust generation changed, or the durable write of `executing` failed |
| `executing` | `completed` | the kind's completion (table above) observed |
| `executing` | `rejected` | dispatch failed **with proof that no side effect happened** (see below) |
| `executing` | `outcome_unknown` | dispatch failed after a possible partial effect, the agent process ended before the kind's completion, or crash/restart and reconciliation can't establish the outcome |

  `completed`, `rejected` and `outcome_unknown` are final. Every exit from
  `executing` is persisted (fsync) before it is reported; a receipt never stays
  `executing` because of an ordinary failure.
- **Dispatch failures** (normative, per kind):
  - `prompt`: the paste is one PTY write of all chunks reserved together. If the
    reservation/enqueue fails, no byte reached the PTY → `rejected`,
    `detail:"could not write to the terminal"`. If the writer reports an error
    after some bytes may have been written → `outcome_unknown`,
    `detail:"write interrupted"`. If the agent process ends before the turn
    completes → `outcome_unknown`, `detail:"agent exited"`.
  - `interrupt`: the interrupt key could not be enqueued → `rejected`; written
    but no interrupted/ended turn observed within 10 s → `outcome_unknown`,
    `detail:"no interrupt observed"`.
  - `stop`: the signal could not be delivered (e.g. `ESRCH`/`EPERM`) and the
    process is still alive → `rejected`, `detail:"stop failed"`; delivered but
    the process hasn't exited within 10 s → `outcome_unknown`,
    `detail:"process still running"` (a later observed exit doesn't change it).
  - A failure that cannot be classified as "no side effect" is
    `outcome_unknown`. Neither final failure state is ever retried
    automatically; a duplicate `submit` returns the recorded final receipt. A receipt's
  `request_id`, target, kind and digest never change; replies carry the same
  values through recovery.
- **Crash boundaries**: `accepted` is persisted (fsync) before the reply;
  `executing` is persisted before the first external side effect (e.g. the
  paste). After a crash, two cases stay distinct:
  `accepted` work has provably not started any side effect, so it may still be
  dispatched — once, under its original target, and only if the host trust
  generation is unchanged (else `rejected`, `detail:"host trust changed"`).
  `executing` work may have started a side effect: it is never dispatched again;
  it is reconciled with the worker/provider, and if that can't establish the
  outcome it becomes `outcome_unknown`.
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

The setup fixes the host context (`account_id`, `atem_device_id`,
`host_trust_gen`, `runtime_gen`, `runtime_epoch`) and each client's
authenticated identity and permissions; nothing is derived from message fields.
Actions (deterministic clock, see `fixtures/schema.md`): `send`, `expect`,
`expect_none`, `advance_ms`, `hold`/`deliver` (delay and reorder a specific
message), `disconnect`, `resume`, `local_input`, `crash_worker`,
`restart_runtime`, `fail_next_fsync`, `change_trust_gen`, `assert` (host
counters: PTY writes, resizes, stops, dispatches, receipts visible per client;
client state for client-side fixtures: `controls`, `deadline_ms`, registry). Negative scenarios assert both the
error and the absence of writes, dispatch, disclosure or resurrection. The
first set (r3 adds the r2-review cases: two-connection lease bypass, late/duplicate
lease replies, runtime epoch snapshots, snapshot/change reordering, hidden-session
changes, change after removal, receipt-query authorization, changed-target id
reuse, failed durable write, local reclaim at the PTY boundary, old attachment
and old runtime input): hello/welcome, list/snapshot+revision, gap recovery, tombstone,
acquire/renew/expiry, repeat acquire, takeover, local input revocation, queued
bytes dropped on transfer, stale epoch, submit accepted→executing→completed,
dispatch failure before any effect (→ rejected) and after a possible partial
effect (→ outcome_unknown), each followed by a duplicate submit and recovery
after restart returning the same final receipt,
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

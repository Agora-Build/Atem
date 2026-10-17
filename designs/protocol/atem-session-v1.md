# atem-session v1: sessions, control leases, receipts and approvals (r7.2: r7.1 plus Atem session rules — for review)

Status: r7.2 (2026-10-17) adds Atem session rules (§6a): for an agent whose
hook can't keep a persistent rule (Codex), its card offers "Always allow this
command" with `scope: "session"`; Atem's worker keeps the rule for that agent
process and answers a later byte-equal request itself (`auto_allowed`, no
approval, no push, no lease). Attachments with `control` get the active rules
(`approval_rules`) and revoke one with a `kind:"approval_rule_revoke"`
submission. New fixture: `approval-rule-revoke-needs-the-lease-and-an-active-rule`.
r7.1 (2026-10-17) lets a second `hello` on a welcomed attachment
replace it instead of refusing it `unauthorized` (§3, compatibility mode):
after a client reset (e.g. the Mac slept) the client says `hello` again on
the same authenticated transport and gets a new attachment, with no lease
carried over and the old `attachment_gen` `stale_target`; at most one
replacement a second (`busy`). New fixture:
`second-hello-replaces-the-attachment`.
r7 (2026-10-16) adds approvals (§6a): any device with `control`
gets the agent's own permission prompts (pushed through the relay, whoever
holds the lease) and answers them — allow once, always allow (one of the
rules the agent itself suggested) or deny — bound to the exact prompt,
taking the lease with the answer (`acquire`), while the terminal can always
answer instead. Needs Astation's review.
r6 (2026-10-16) removes every legacy path from r5 at the user's
direction (no backward compatibility; Atem and Astation update together) —
needs Astation's review. r5 was accepted by Astation on 2026-10-15 as the
compatibility-mode implementation contract ([r5 review](https://truck.netbird.cloud:58310/protocol/atem-session-v1-r5-review.md)).
Final conformance needs the shared fixtures to pass in the Rust, Swift and
browser implementations; §9 remains the security gate. History: r1 (`7a0c691`), r2 (`9383193`), r3
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
- **One session authority, no legacy paths** (r6). Atem and Astation are
  updated together; there is no backward compatibility. Every remote mutation
  of a session — terminal input/resize/stop, chat submit, interrupt — is a
  session-v1 message carrying `binding` and the current lease, after `welcome`.
  The old ops are removed from the host and answered with
  `error{code:"unsupported_version"}` and no effect: `agentInput`,
  `agentPrompt`, `voiceCommand`/`voiceToggle` prompts, `userCommand`,
  terminal-v1 `control` and its `lease_id` field, terminal-v1 `list`/`sessions`
  (session-v1 `list` is the only registry), chat-v1 `submit` without
  `binding`, and any session op before `welcome`. Terminal ids are session ids
  only (no `claude`/`codex` aliases).
  - Local terminal input on the host revokes any remote lease first (§5).
  Fixture `removed-ops-have-no-effect`.

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
| Bounds | message ≤ 1 MiB after decoding; `payload` ≤ 64 KiB canonical; prompt text ≤ 32 768 bytes; `receipt_query.request_ids` ≤ 64; `detail` ≤ 512 bytes; ≤ 64 in-flight requests per attachment (excess → `busy`); approvals (§6a): `tool` 1–128 bytes, `summary` ≤ 512 bytes, ≤ 8 `always_rules`, rule `label`/`scope` 1–256 bytes each, deny `message` ≤ 512 bytes |
| Display text | approval `tool`, `summary`, rule `label`/`scope` are one line: no control characters (C0, DEL, C1); a deny `message` may contain `\n` and no other control character |
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

  terminal-v1 has no `lease_id` field (the binding's epoch is the lease); a
  chat `submit` is the §6 `submit` with
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
| `welcome` | H→C | `account_id`, `atem_device_id`, `host_trust_gen`, `runtime_gen`, `controller_session`, `attachment_gen`, `client_kind` (`native`/`browser`, as authenticated), `permissions` (`view`, `control`; `control` also answers approvals, §6a), `authorization_ms_left`, `server_time` |

- The client's device and kind come from the authenticated channel, never from
  `hello` fields or relay labels. A `controller_session` UUID is not a credential.
- Resume needs key possession over a fresh `challenge` and yields a **new**
  `attachment_gen`; the host fences the old attachment (closes it and rejects
  anything still arriving on it) before accepting mutations on the new one.
  Resume never re-acquires a lease and never revives an expired one.
- Compatibility mode: no `challenge`/`resume_proof`; every `hello` gets a new
  `controller_session` and `attachment_gen` and holds no lease. A `hello`
  with `resume`, and any `resume_proof`, is refused `unauthorized`. A second
  `hello` (without `resume`) on an attachment that was already welcomed
  replaces it (r7.1): the host fences the old attachment as a transport drop
  or re-authentication would — its leases end (none is carried over), its
  subscriptions, streams and chat conversations close, its pending replies
  are dropped — and answers `welcome` on a new attachment over the same
  authenticated transport: new `attachment_gen` and `controller_session`,
  the same permissions and client kind, and the same authorization deadline
  (not renewed). Anything naming the old `attachment_gen` is then
  `stale_target`. Receipts are untouched (queryable from the new
  attachment); pending approvals stay pending and are sent to the new
  attachment like to any new one. Past the authorization deadline the reply
  is `paused`. At most one replacement per second per transport; more often
  is `busy`. A transport without an attachment still gets `unauthorized`.
  Each attachment is still welcomed once.
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
- **New attachment.** `seq` belongs to one attachment. On every `welcome`
  (reconnect) the client clears its registry state — sessions, last `seq`,
  removals and held changes — keeping only its highest accepted
  (`runtime_epoch`, `runtime_gen`) as the fencing floor; the new attachment's
  first snapshot applies at any `seq`.
- **Removal.** A removed session is sent as `state:"removed"`; applying it
  deletes the session, and a later change for that `session_id` is only accepted
  with a higher `seq` in the same epoch and a different `process_gen` — never
  as a resurrection of the removed one. (Tombstones are kept 10 minutes host-side
  only to answer late requests with `unknown_session`.)
- **Pending approvals** (§6a) follow the snapshot: after every `sessions`
  reply the host sends one `approval_request` per pending approval, so a
  viewer that (re)connects and lists sees them; while subscribed it gets new
  ones and their `approval_closed` live. They are not registry messages and
  carry no `seq`; a client keys them by `approval_id` (a repeat replaces) and
  keeps only those of a session process it holds.
- The registry and every response are filtered by the attachment's view
  permission: `list` without `view` is `forbidden`; an op with a `binding`
  from an attachment without `view` is `unknown_session`. `cwd_label` is the last path component only; clients show
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
- **Epochs**: `lease_epoch` strictly increases per session and may skip values
  (the host reserves epochs durably in blocks, so after a restart the next
  grant can be well above the last one seen); clients compare, never count.
- **Recipients**: `lease_changed` goes to every welcomed attachment with `view`
  except the one whose own request caused the change (it gets the direct
  reply: `lease` or `lease_released`). Expiry, local input, revocation and
  process end have no requester, so the holder gets `lease_changed` too.
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
| `approval` | `{"approval_id", "decision", "rule_id"?, "message"?}` (§6a) | the agent reports it applied the decision |
| `approval_rule_revoke` | `{"rule_id"}` (§6a, r7.2) | the runtime dropped the rule |

- **Digest**: the host computes `payload_digest = sha256(JCS(payload))`, JCS =
  RFC 8785 over the supported domain (objects, arrays, strings, booleans, null,
  integers in the safe range; no floats). A client-supplied digest is not used.
  Known-answer vectors: `fixtures/digest-vectors.json`.
- **Immutable request**: (`request_id`, `account_id`, `atem_device_id`,
  `host_trust_gen`, `session_id`, `process_gen`, `kind`, `payload_digest`).
  Same `request_id` with every bound value equal → the recorded receipt (needs
  current view permission for the target; no lease, no re-execution). Same
  `request_id` with any value different → `request_id_reused`.
- **Admission** of a new request — and every lease-scoped mutation
  (terminal input/resize/stop) — is checked in this order: `control`
  permission (`forbidden`), then a session that accepts work
  (`session_closed`, even when the lease is also stale), then the current
  lease (`stale_lease`). If the durable write of
  `accepted` fails, the reply is `error{code:"busy"}`, nothing is recorded and
  the client may retry with the same `request_id`. After a double I/O failure
  (the write fails and so does undoing it) a request answered `busy` may still
  be dispatched once, under its original target and trust generation; a retry
  with the same `request_id` returns its receipt.
- A duplicate `submit` names the current target: one naming an earlier
  `process_gen` of the session is `stale_target`, while `receipt_query` for
  that earlier target still returns its receipts.
- **Scheduling**: `prompt`s are serialized per session (one paste at a time;
  later ones stay `accepted` until the previous one leaves `executing`);
  `interrupt`, `stop`, `approval` and `approval_rule_revoke` are dispatched
  immediately.
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
  - `approval`: the decision could not be handed to the agent's waiting
    prompt → `rejected`, `detail:"could not hand the decision to the agent"`;
    see §6a for the other outcomes.
  - `approval_rule_revoke`: the runtime could not be asked → `rejected`,
    `detail:"could not revoke the rule"`; the rule was no longer active
    there → `rejected`, `detail:"the rule is no longer active"`.
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
- chat-v1: its `submit.requestId` is this
  `request_id`, it carries `binding`, and its `accepted`/`complete` follow this
  receipt's `accepted`/`completed`.

## 6a. Approvals (r7)

The agent's permission prompt (Claude Code's and Codex's `PermissionRequest`
hook) can be answered remotely, bound to that exact prompt. The terminal
always keeps its own prompt: whichever answers first wins, and the host never
auto-allows. Any failure, timeout or missing runtime means "no decision" — the
agent's own prompt asks. Delivery is independent of control (user decision,
2026-10-16): every approval opens a card for all attachments with `control`
and is pushed to the account's devices, whoever holds the lease; answering
takes the lease with the answer (`acquire`).

| op | dir | fields |
|---|---|---|
| `approval_request` | H→C | `approval_id` (UUID), `session_id`, `process_gen`, `tool`, `summary`, `created_at`, `always_rules: [{rule_id, label, scope}]` |
| `approval_closed` | H→C | `approval_id`, `reason`: `answered_remote`, `answered_terminal`, `interrupted`, `timed_out`, `released`, `process_ended` |
| `submit` | C→H | §6 with `kind:"approval"`, `payload: {approval_id, decision, rule_id?, message?, acquire?}` |
| `push_approval` | H→relay | `approval_id`, `atem_device_id`, `session_id`, `tool`, `summary`, `expires_at` |
| `push_resolved` | H→relay | `approval_id`, `reason` (an `approval_closed` reason) |
| `approval_rules` | H→C | `session_id`, `process_gen`, `rules: [{rule_id, label, scope}]` (r7.2; ≤ 32) |
| `submit` | C→H | §6 with `kind:"approval_rule_revoke"`, `payload: {rule_id}` (r7.2) |

```json
{"type":"session","data":{"v":1,"op":"approval_request","id":"…","approval_id":"88888888-…",
  "session_id":"ses-aaaaaaaaaaaa","process_gen":"22222222-…","tool":"Bash","summary":"npm test",
  "created_at":1760500000000,
  "always_rules":[{"rule_id":"r-npm-test","label":"Bash(npm test:*)","scope":"this project"}]}}
{"type":"session","data":{"v":1,"op":"submit","id":"…","binding":{…,"lease_epoch":7},
  "request_id":"44444444-…","kind":"approval",
  "payload":{"approval_id":"88888888-…","decision":"allow_always","rule_id":"r-npm-test"}}}
{"type":"session","data":{"v":1,"op":"submit","id":"…","binding":{…},
  "request_id":"45454545-…","kind":"approval",
  "payload":{"approval_id":"88888888-…","decision":"allow_once","acquire":true}}}
{"type":"relay","data":{"v":1,"op":"push_approval","approval_id":"88888888-…",
  "atem_device_id":"host-a","session_id":"ses-aaaaaaaaaaaa","tool":"Bash","summary":"npm test",
  "expires_at":1760500600000}}
{"type":"relay","data":{"v":1,"op":"push_resolved","approval_id":"88888888-…","reason":"answered_terminal"}}
```

- **Opening.** The host opens an approval for the session's current process
  whoever holds the lease (or nobody); ≤ 16 pending per session. Lease
  changes — expiry, release, takeover, local input, a trust change — never
  close one.
- **What it shows.** `tool` and a short redacted `summary` (the command's
  first line or the file path) — never full inputs such as file contents.
  `always_rules` are the agent's own suggested rules, exactly as the agent
  proposes them (Claude: the hook's `permission_suggestions`); `label` says
  what the rule allows and `scope` where it is saved, so the card shows both
  before the tap. `[]` when the agent offers none (the card then offers
  Allow once and Deny only). For an agent whose hook can't take a persistent
  decision (Codex) the host offers one Atem session rule instead (below).
  Bounds §1.
- **Recipients.** `approval_request` and `approval_closed` go to every
  attachment subscribed by `list` with `control` (a view-only attachment
  gets neither); after each `sessions` snapshot the pending ones are sent
  again to such an attachment (§4); the chat-v1 card likewise appears only
  in conversations of attachments with `control`, live and in history — the
  same audience the push targets. An approval belongs to one
  (`session_id`, `process_gen`).
- **Push (host → relay).** On opening, the host asks the relay over its own
  authenticated Astation link to push the approval to every device on the
  account with `control`, online or not (APNs/FCM; the relay and Astation
  own credentials, device tokens, delivery and the notification UI):
  `{"type":"relay","data":{"v":1,"op":"push_approval",…}}` with the redacted
  `tool`/`summary` only (never full inputs), this host's `atem_device_id`
  and `expires_at` (wall ms when the agent's hook gives up: Claude 600 s,
  Codex 300 s). When it stops being pending — answered here or in the
  terminal, interrupted, timed out, released, the process ended — the host
  sends `push_resolved{approval_id, reason}`; the relay replaces the
  notification (collapse id / FCM tag = `approval_id`). Best effort: a push
  never blocks or changes an approval. Only a verified pairing's link carries
  them; while it is down the host keeps the latest state per approval
  (bounded) and on reconnect sends `push_approval` only for approvals still
  pending and `push_resolved` only for ones whose `push_approval` went out.
  Beyond 64 kept entries an unsent one is dropped (an expired one first,
  else the oldest); one already pushed is never dropped, so its
  `push_resolved` still goes out. Relay messages are not session messages:
  no `id`, no reply.
- **Payload** (strict; anything else is `unsupported_version`): `approval_id`
  a UUID; `decision` one of `allow_once`, `allow_always`, `deny`; `rule_id`
  present iff `allow_always` (an opaque id); `message` only with `deny` (≤ 512
  bytes; given to the agent with the denial); `acquire` a boolean. No other
  field. With `acquire: true` the binding carries no `lease_epoch` (like
  `acquire`); otherwise it must.
- **Admission**, in order: a duplicate `request_id` returns its receipt first
  (needing only view; it takes no lease). Without `acquire`: the §6 checks
  (`control` → `forbidden`, a session that accepts work → `session_closed`,
  the current lease → `stale_lease`). With `acquire: true`: `control` →
  `forbidden`, a session that accepts work → `session_closed`, no lease
  needed. Then the approval must be pending for exactly the binding's
  `session_id` and `process_gen`, and an `allow_always` `rule_id` must be one
  it offered — otherwise `stale_target` (nothing recorded, nothing handed
  over, no lease taken). A closed, answered or unknown approval is
  `stale_target` (a late tap on a resolved notification: "already
  answered").
- **Acquire is atomic.** Once the answer is durably `accepted`, the host gives
  the answering attachment the lease — a takeover when another attachment
  holds it, nothing new when it already holds it live — and announces it with
  `lease_changed` (`granted`/`takeover`, to every viewer including the
  answering one) and `session_changed`, then reports `accepted` and hands the
  answer over. The lease is taken only when the user acts, and never for an
  answer that was refused. The new holder renews it as usual (§5).
- **Lifecycle of the receipt:**

| state | when |
|---|---|
| `accepted` | admitted and durable (§6) |
| `executing` | durable, then the approval closes for every attachment with `control` (`approval_closed{answered_remote}`, push resolved) and the decision is handed to the agent's waiting prompt |
| `completed` | the agent reported it applied the decision |
| `rejected` | the approval closed before the hand-off (e.g. an `accepted` answer after a restart: approvals don't survive one), or the decision could not be handed over |
| `outcome_unknown` | the terminal's answer and the remote answer crossed (`detail:"the terminal answered too; which answer won is unknown"`), the agent ended (`"agent exited"`), or it never confirmed (`"the agent did not confirm the decision"`) |

- **Closing without the remote answer** (`approval_closed`, the card goes
  away, push resolved): `answered_terminal` (answered in the agent's own
  prompt first), `interrupted` (Esc, or the hook was killed), `timed_out`
  (the hook's limit), `released` (Atem gave the prompt back to the agent:
  input reached a Codex session, which hides its prompt while the hook
  waits, so any input — local, or the lease holder's — first answers the
  hook "no decision"; that input is consumed, never written, since the user
  never saw the dialog it brings back: a remote `input` is answered
  `written` with an error, a prompt or interrupt is `rejected`, and input
  after it is consumed too while the released hooks still run, at most
  500 ms; or the runtime restarted), `process_ended` (the process
  exited, was replaced, or the session closed or was removed).
  `answered_remote` is the host's own reason; the runtime reports the
  others. After a hand-off, a lost lease doesn't cancel the answer (§6:
  lease expiry doesn't cancel accepted work).
- **Takeover keeps the approval.** A remote takeover moves the lease but the
  approval stays pending: the previous holder's epoch is `stale_lease`.
- **Hand-off deadline.** A handed-off answer the agent hasn't confirmed
  within 630 s (above Claude Code's 600 s hook timeout) becomes
  `outcome_unknown` ("the agent did not confirm the decision"), which frees
  its in-flight slot. A decision that could not be handed over (`rejected`)
  also releases the waiting prompt ("no decision").
- **Broker restart.** Approvals live in the broker's memory only. After a
  restart the broker tells each adopted worker which approvals it knows
  (none), so the worker answers "no decision" to every waiting hook, and an
  `accepted` answer is `rejected` (the approval closed before the hand-off).
- A later answer to a closed approval is `stale_target` and is never applied;
  a duplicate of the answer that was handed over returns its receipt.
- Local input to Claude needs no release (its dialog stays visible; first
  answer wins); it still revokes the remote lease (§5) without closing the
  approval.
- **Atem session rules (r7.2).** For an agent whose hook can't keep a rule
  (Codex: `updatedPermissions` fails closed) `always_rules` holds one rule
  the host offers itself: `{rule_id, label: "Always allow `<command's first
  line, redacted>` in <cwd> for this session", scope: "session"}`, for a
  request with an exact form (a shell command with a string `command`, or a
  patch's file changes) and a `cwd`. Answering `allow_always` with it
  allows this request (the agent gets a plain allow) and, once the agent
  took the answer, the runtime keeps the rule for that agent process: at
  most 32 per session (a full session offers none); gone when the process
  ends (a respawn has none); kept across a broker restart (the worker owns
  it). The match uses the full, unredacted request: tool, the exact full
  command (byte-equal; file changes: the exact kinds and paths) and the
  exact cwd — no prefix, glob or normalisation — and only the session's own
  agent (never a nested or foreign process of the same agent). A matching
  request is allowed by the runtime without opening an approval: no
  `approval_request`, no push, no lease; it appears in chat-v1 as a card in
  state `auto_allowed` naming `rule_id`, and in the runtime's log as one
  line without the command. The runtime does this only while a broker is
  connected; otherwise "no decision" as ever.
  The active rules go to every subscribed attachment with `control` as
  `approval_rules{session_id, process_gen, rules}` whenever they change,
  after each `sessions` snapshot (only for sessions that have any), and
  with `rules: []` when the process ends. Revoking one is a §6 `submit`
  with `kind:"approval_rule_revoke"` and `payload: {rule_id}` (strict:
  exactly that field, an opaque id) under the current lease (no `acquire`
  form): admission is the §6 order (`forbidden`, `session_closed`,
  `stale_lease`), then the rule must be active for exactly the binding's
  process, else `stale_target` (nothing recorded or dispatched). It is
  dispatched to the runtime and completes once the runtime dropped the
  rule; the new list follows.

  ```json
  {"type":"session","data":{"v":1,"op":"approval_rules","id":"…","session_id":"ses-aaaaaaaaaaaa",
    "process_gen":"22222222-…","rules":[{"rule_id":"s-0123456789abcdef",
    "label":"Always allow `npm test` in /home/user/proj for this session","scope":"session"}]}}
  {"type":"session","data":{"v":1,"op":"submit","id":"…","binding":{…,"lease_epoch":7},
    "request_id":"46464646-…","kind":"approval_rule_revoke","payload":{"rule_id":"s-0123456789abcdef"}}}
  ```
- **chat-v1 card.** A chat-v1 conversation shows each approval of its session
  as an assistant `message` (`messageId` `approval-<approval_id>`) with one
  part `{id:"approval", kind:"approval", approval_id, tool, summary,
  always_rules, state}`; `state` is `pending`, then `allowed`,
  `always_allowed`, `denied` (answered remotely: set when the answer is
  handed over), `answered_terminal`, `expired` (timed out), or `closed`
  (interrupted, released, the process ended, or a remote answer the agent
  didn't take or whose outcome is unknown, including at the 630 s hand-off
  deadline); `auto_allowed` (r7.2) is a request a session rule allowed
  without asking, final when it arrives, with the part's `rule_id` naming
  the rule and `always_rules: []`. A
  state change re-sends the whole `message` (same `messageId`; the client
  replaces it). Answering from chat is a chat-v1 `submit` with `approval`
  (the payload above) instead of `text`, its `binding` without `lease_epoch`
  when `acquire` is true; its `accepted`/`complete`/`error` follow the
  receipt as for prompts. chat-v1 `opened` carries `approvalRules` (the
  active session rules; `[]` for an attachment without `control`) and a
  `rules{approvalRules}` event follows each change; a chat-v1 `submit` with
  `approval_rule_revoke: {rule_id}` instead of `text` revokes one (its
  binding with `lease_epoch`).

## 7. Errors

`error{re, code, detail?}`; `detail` is human-readable, bounded, and never
contains secrets, paths, raw OS errors or other targets' identifiers.

Errors are answered in the family of the request (ruling i):

- session-v1 requests: session `error{re, code, detail?}`.
- A valid terminal-v1 request that is refused: terminal-v1
  `error{terminal_id, stream_id?, code, message}` (`stream_id` when the
  request carried one; `message` is fixed text per code).
- chat-v1: `error{requestId?, code, text}` (chat-v1's `error` gains `code`).
  A chat `submit` hears about its request only through chat-v1 ops mapped
  from its receipt, never a session `receipt`: `accepted`/`executing` →
  `accepted{requestId}`; `completed` → `complete{requestId, turnId?,
  outcome:"done"}`; `rejected` → `error{requestId, code:"rejected", text:
  detail}`; `outcome_unknown` → `error{requestId, code:"outcome_unknown",
  text: detail}`. Refusals at admission use the §7 code.
- Removed forms (§0) and requests that don't decode — of any family — get a
  session `error{code:"unsupported_version"}` without `re` when the request
  had no readable `id`, and have no effect.

| code | when |
|---|---|
| `unsupported_version` | unknown `v`, out-of-range representation, or a removed op (§0) |
| `unauthorized` | not authenticated, attachment fenced, or authorization expired |
| `forbidden` | missing permission |
| `stale_target` | trust generation, session or process generation mismatch; approval not pending (closed, answered or unknown) or `rule_id` not offered, or a revoked `rule_id` not active (§6a) |
| `unknown_session` | unknown or not visible to this attachment |
| `lease_held` | another controller holds the lease (no takeover) |
| `stale_lease` | wrong, expired or other-attachment lease epoch |
| `request_id_reused` | same request id, different bound values |
| `receipt_limit` | the session's receipt journal is full |
| `session_closed` | the session no longer accepts submissions |
| `busy` | the agent or attachment can't take it now (incl. a second `hello` replacement within a second, §3) |
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
first set (r3 adds the r2-review cases: removed ops have no effect, late/duplicate
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
receipt query scoped to target. r7 adds approvals (§6a): allow once, allow
always with an offered and an unknown rule, deny with a message, the terminal
answering first, an approval staying pending when the lease ends, one opened
with no lease holder and answered with `acquire`, an answer with `acquire`
taking control from the holder, a late answer after `push_resolved`, a
view-only attachment, a duplicate answer, and pending approvals after `list`
on a new attachment. r7.1 adds a second `hello` replacing the attachment (old
lease gone, old `attachment_gen` → `stale_target`, the receipt still
queryable, another replacement within a second `busy`). r7.2 adds revoking
an Atem session rule (`approval_rules` on change and after `list`; an
inactive rule and a stale lease refused with no dispatch; the revoke
completes and the empty list follows; revoking again is `stale_target`).

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

# atem-session v1: sessions, control leases, receipts and approvals (r8: revision admission, chat history pages, receipt results, chat Send acquire, lease-free approvals)

Status: **r8 is implemented in Atem and authoritative** (2026-10-18). The
appendix "r8" at the end is the contract wherever it differs from the r7.3
text above it: required `hello.revision: 8` and `welcome.features` (§A),
history pages in the sequenced stream with bounded selectors and coverage
(§B, §C), `receipt.result` (§D), removal of `open.before`/`status.page`,
chat Send that acquires the lease with the prompt (`chat.send_acquire`, §F),
lease-free approval answers (`approval.lease_free`, §G), the submitter
principal and its durable control fence (§H) and one admission persistence
rule (§I, which removes §6's double-I/O exception). Atem's host speaks only
r8: a `hello` without `revision: 8` is refused, so Astation must send it.
The shared fixtures and where they run are in `atem-host-handoff.md`; the
consolidated Astation note is `r8-astation-handoff.md`.
r8 (2026-10-18) changelog: implemented in Atem (`src/session_protocol/`,
`src/chat/history.rs`, `src/runtime/host_bridge.rs`); welcome advertises all
nine features. The implementation corrected the appendix where it was
wrong or silent; each change is listed in the appendix's "Implementation
notes" and was flagged to Astation. Fixtures: the five r7 approval fixtures
that answered with `acquire` or expected `stale_lease` on an answer are
deleted (superseded by §G; replacements named in `atem-host-handoff.md`),
`r8-approval-card-carries-the-close-reason` is new, and
`r8-hello-without-revision-8-is-refused-before-any-attachment` and
`r8-approval-answer-keeps-the-holders-deadline` were corrected.
r7.3 (2026-10-17) lets any attachment with `control` revoke an Atem
session rule (§6a) with or without the lease: `approval_rule_revoke` needs
only `control`, a running session and an active rule of that exact process
(`stale_target` otherwise); its binding's `lease_epoch` is optional and never
checked (a stale one is not refused), it never takes, renews or moves the
lease, and an `acquire` field is refused (the payload is exactly
`{rule_id}`). Found live: a user tapped Revoke in Astation without holding
control, the revoke was refused `stale_lease` and the rule kept allowing.
Revocation only narrows what runs unattended, so it isn't serialized with
input. Journaling, receipts and duplicate/`request_id_reused` semantics are
unchanged. The fixture
`approval-rule-revoke-needs-the-lease-and-an-active-rule` is replaced by
`approval-rule-revoke-needs-control-not-the-lease`.
r7.2 (2026-10-17) adds Atem session rules (§6a): for an agent whose
hook can't keep a persistent rule (Codex), its card offers "Always allow this
command" with `scope: "session"`; Atem's worker keeps the rule for that agent
process and answers a later byte-equal request itself (`auto_allowed`, no
approval, no push, no lease). Attachments with `control` get the active rules
(`approval_rules`) and revoke one with a `kind:"approval_rule_revoke"`
submission. New fixture: `approval-rule-revoke-needs-the-lease-and-an-active-rule` (replaced in r7.3).
Clarified the same day (no new field): a `completed` `prompt` receipt's
`detail` is its turn's outcome, `"done"` or `"interrupted"` (§6, §7).
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
- `lease_epoch` is required for mutations, absent for reads; an
  `approval_rule_revoke` submission (§6a, r7.3) may carry it or not, and it
  is ignored.
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
  the lease then expires. (r8, authoritative: approval answers leave the lease's scope,
  appendix §G; a chat Send may acquire the lease with its prompt, §F.)

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
| `prompt` | `{"text": string}` | the provider confirms the turn ended (chat-v1 `complete`); `detail` is the turn's outcome, `"done"` or `"interrupted"` |
| `interrupt` | `{}` | the provider reports the turn interrupted, or the turn was already over (`detail`) |
| `stop` | `{}` | the agent process exits |
| `approval` | `{"approval_id", "decision", "rule_id"?, "message"?}` (§6a) | the agent reports it applied the decision |
| `approval_rule_revoke` | `{"rule_id"}` (§6a, r7.2; needs `control`, not the lease: r7.3) | the runtime dropped the rule |

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
  lease (`stale_lease`; skipped for `approval_rule_revoke`, which needs no
  lease, r7.3, and for an approval answer with `acquire`). If the durable write of
  `accepted` fails, the reply is `error{code:"busy"}`, nothing is recorded and
  the client may retry with the same `request_id`. After a double I/O failure
  (the write fails and so does undoing it) a request answered `busy` may still
  be dispatched once, under its original target and trust generation; a retry
  with the same `request_id` returns its receipt. (r8, authoritative: this exception
  and the same-id retry are **removed**; a `busy` for a failed admission
  write is a definitive refusal, the journal halts, and the request is
  resolved `rejected` "acceptance not confirmed" at restart and never
  executed; appendix §I.)
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
  (r8, authoritative: only when the previous run ended with a clean close, and then
  only once its submitter principal's control is confirmed in the new run
  at the recorded `control_gen`; after any other end it is `rejected`
  "authorization history unknown", appendix §H; a request on the refusal
  list is `rejected` first, §I.)
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

**r8 (appendix §G, `approval.lease_free`, user decision 2026-10-18; authoritative):**
an answer needs only a verified attachment with `control` and the exact
pending request. It never takes, needs or moves the lease, its binding's
`lease_epoch` is ignored, `acquire` is refused `unsupported_version`, and
the first admitted answer wins (later ones `stale_target`). It replaces the
r7 text above wherever they differ; the r7 `acquire` on an answer is
refused.

| op | dir | fields |
|---|---|---|
| `approval_request` | H→C | `approval_id` (UUID), `session_id`, `process_gen`, `tool`, `summary`, `created_at`, `always_rules: [{rule_id, label, scope}]` |
| `approval_closed` | H→C | `approval_id`, `reason`: `answered_remote`, `answered_terminal`, `interrupted`, `timed_out`, `released`, `process_ended` |
| `submit` | C→H | §6 with `kind:"approval"`, `payload: {approval_id, decision, rule_id?, message?, acquire?}` |
| `push_approval` | H→relay | `approval_id`, `atem_device_id`, `session_id`, `tool`, `summary`, `expires_at` |
| `push_resolved` | H→relay | `approval_id`, `reason` (an `approval_closed` reason) |
| `approval_rules` | H→C | `session_id`, `process_gen`, `rules: [{rule_id, label, scope}]` (r7.2; ≤ 32) |
| `submit` | C→H | §6 with `kind:"approval_rule_revoke"`, `payload: {rule_id}` (r7.2); `control` only, `lease_epoch` optional and ignored (r7.3) |

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
  line, redacted>` in <cwd> for this session", scope: "session"}`, only
  for a shell command request: a string `command` with no other
  `tool_input` key than `description` (any other key, such as a working
  directory or environment, could change what runs: no rule), and the
  hook's `cwd` — the agent session's working directory as the hook reports
  it, not a per-command directory. File-change requests (patches) never
  get one: their cards offer Allow once and Deny. An `apply_patch` the agent
  runs as a shell heredoc is a shell command like any other: its rule is
  byte-exact on the whole command, patch text included, so it matches only
  that exact patch again. Answering `allow_always` with it
  allows this request (the agent gets a plain allow) and, once the agent
  took the answer, the runtime keeps the rule for that agent process: at
  most 32 per session (a full session offers none); gone when the process
  ends (a respawn has none); kept across a broker restart (the worker owns
  it). The match uses the full, unredacted request: tool, the exact full
  command (byte-equal) and the exact cwd — no prefix, glob or
  normalisation — and only the session's own
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
  exactly that field, an opaque id) from any attachment with `control`,
  with or without the lease (r7.3): admission is `forbidden` (no
  `control`: view-only attachments can't revoke), `session_closed`, then the
  rule must be active for exactly the binding's process, else
  `stale_target` (nothing recorded or dispatched). The lease plays no part:
  the binding's `lease_epoch` is optional and never checked (a stale or
  someone else's epoch is not refused), and a revoke never takes, renews or
  moves the lease, nor changes who holds control. `acquire` is refused, not
  ignored: the payload is exactly `{rule_id}`, so `{rule_id, acquire}` fails
  to decode (`unsupported_version`, nothing recorded) — a client must never
  believe a revoke gave it control. Revoking only narrows what runs
  unattended, so it needs no serialization with the controller's input. The
  receipt is journaled like any other; a duplicate returns it and the same
  `request_id` with other content is `request_id_reused`. It is
  dispatched to the runtime and completes once the runtime dropped the
  rule; the new list follows. An allow the runtime wrote for that rule and
  the agent hasn't taken yet is withdrawn ("no decision": the agent's own
  prompt asks). A rule the session can't keep at the moment the agent takes
  the answer (it already holds 32) is not kept: the request is allowed once
  and its chat-v1 card ends `allowed` with a `note` saying so. Rules are
  bound to the host's identity: each is kept with the account, device and
  host trust generation it was granted under. When any of them changes
  while the host runs, every runtime worker drops all its rules (viewers
  get `rules: []`). After a broker restart the adopted workers' rules are
  inactive (matching requests ask as usual) until the new host has checked
  them: it accepts only rules granted under its current account, device
  and trust generation, which allow and are listed again; the worker drops
  every other one (e.g. after `atem unpair` then `atem pair`, or another
  account or device).

  ```json
  {"type":"session","data":{"v":1,"op":"approval_rules","id":"…","session_id":"ses-aaaaaaaaaaaa",
    "process_gen":"22222222-…","rules":[{"rule_id":"s-0123456789abcdef",
    "label":"Always allow `npm test` in /home/user/proj for this session","scope":"session"}]}}
  {"type":"session","data":{"v":1,"op":"submit","id":"…","binding":{"target":{…},"attachment_gen":"…"},
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
  `approval_rule_revoke: {rule_id}` instead of `text` revokes one (r7.3:
  `control` is enough; its binding's `lease_epoch` is optional and ignored).

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
  outcome}` (`outcome` is the receipt's `detail` for a prompt, `"done"`
  or `"interrupted"`; `"done"` for the other kinds); `rejected` → `error{requestId, code:"rejected", text:
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
r7.3 replaces it with `approval-rule-revoke-needs-control-not-the-lease`: a
control attachment without the lease revokes while another holds it (once
without `lease_epoch`, once naming an epoch it doesn't hold), a view-only one
is `forbidden`, an inactive rule or another process `stale_target`, `acquire`
refused, a duplicate returns the receipt, and the holder still renews at the
same epoch. r8 deletes the r7 approval fixtures that answered with `acquire`
or expected `stale_lease` on an answer
(`approval-answer-with-acquire-takes-control-from-the-holder`,
`approval-opens-without-a-lease-holder`,
`approval-stays-pending-when-the-lease-ends`,
`approval-late-answer-after-push-resolved-is-stale-target`,
`approval-survives-takeover`) and adds the `r8-*` scenarios
(`fixtures/schema.md`, "r8 fixtures").

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

## Appendix: r8 (implemented in Atem 2026-10-18; authoritative)

Status: **implemented in Atem**, 2026-10-18 (drafted 2026-10-17, answering
Astation's review of Atem's agent control API response r1,
`agent-control-api-atem.md` r2). This appendix replaces the affected r7.x
text above. Every `r8-*` fixture (`fixtures/schema.md`, "r8 fixtures")
passes in Atem's core runner, and the ones a single real link can express
pass against the real runtime (`atem-host-handoff.md`); Swift conformance
is Astation's. No backward compatibility: an r8 host and an r8 client
refuse every r7 peer.

**Implementation notes (2026-10-18).** What building r8 showed the text
above had wrong or left open, now written into the sections below (each is
listed for Astation in `r8-astation-handoff.md`). Notes 1, 3, 6 and 13
change or narrow the signed text and need Astation's agreement; the others
only make precise what the signed text leaves open.

1. §H, a failed revocation write: the new link is **not closed**. As
   `r8-control-fence-holds-when-a-rejection-write-fails` step 12 requires,
   it gets no `welcome` (its `hello` has no reply) and every request on it
   is `busy` "journal halted; restart Atem" until the restart.
2. §B: the paragraph on today's code (#75 `open{before}` and `status.page`)
   described what r8 removed; it now names the r8 page builder.
3. §B: the 8-a-second bound counts valid `history` requests only; each
   invalid one gets its sequenced `invalid_request` and is not counted.
   The signed text counts every request, but
   `r8-history-selectors-are-exclusive-and-validated` sends twelve invalid
   requests and a valid one in the same instant and expects no `busy`; Atem
   follows the fixture until the two are aligned.
4. §B: `wire_bytes` (and the 1 MiB bound) includes the page's
   `history_end` itself.
5. §B: "message bytes as counted by `ChatSession`" counts each message's
   ids, every part's text and id plus 64 bytes per part, and 1 KiB per
   approval card; a message holds at most 2048 parts (the last a truncation
   marker), so it serializes far below 1 MiB however it escapes.
6. §B: a chat `close` may come without a binding; it then closes only the
   sender attachment's own conversation of that id. With a binding it is
   checked like a read.
7. (withdrawn: a later version of a live message goes out as the whole
   `message`, as §B says; r8 sends no `delta`.)
8. §C: a recovered message always carries `after_message_id`, `null` when
   no retained message precedes it (the key's presence marks it as
   recovered).
9. §C: for a view-only attachment holes are named by their nearest visible
   neighbours, and `oldest_retained` is the oldest message it can see, in
   pages and in `coverage` events. A hole with no visible message before it
   is left out and reported as truncation (`truncated: true`, so the
   selection's `coverage` is `partial`). A `before` naming a card it can't
   see is `stale_target`.
10. §C: a `coverage` event carries the session's whole hole list (≤ 16,
    then `holes_more`) and follows a reload only when a hole was recorded.
    A reload that fails leaves a hole without `count` (the worker's `gap`
    counts items, not messages).
11. §C: for a lookup, a turn is `partial` when its oldest messages were
    evicted (the newest evicted message belonged to it) or a hole touches
    it (either neighbour is in the turn).
12. §C: Atem sends `close.reason` `switched`, `withdrawn`, `restarted` and
    `evicted`; never `fenced` or `reset` (a fenced attachment's
    conversations end with its transport).
13. §D: every completed `prompt` receipt carries `result`: its turn is
    always known, and the user message id is recorded when the prompt is
    accepted, so `result` names it even after retention evicted the
    message (`replies` is then `partial`, or `unavailable` when nothing of
    the turn is retained). The one narrowing: a turn or user message id
    that isn't an opaque id (1–128 bytes of `[A-Za-z0-9._:-]`, the wire
    rule for ids) can't be journaled or sent, so that receipt completes
    without `result`. `reply_message_ids` leaves approval cards out (they
    aren't the agent's reply, and a view-only `receipt_query` must not
    learn card ids; `history{request_id}` pages them to attachments with
    `control`); a reply id that isn't an opaque id is dropped and makes
    `replies` `partial`.
14. §F: the chat-v1 `lease_held` text is "another controller holds this
    session" (session-v1 `error` uses the same text).

Revised 2026-10-18 for Astation's review of the §F/§G draft (r3 review):
control is a permission of an authenticated **principal**, recorded with
accepted work and revoked through a durable fence that outlives
attachments, reconnects and restarts (§H, finding 1); one persistence rule
for admission (§I, finding 2): a request is accepted only once its
`accepted` record is durable, a `busy` for a failed write is a definitive
refusal resolved `rejected` ("acceptance not confirmed") at restart, and
§6's double-I/O exception (a request answered `busy` "may still be
dispatched once") is **removed**, as is "the client may retry with the
same `request_id`" after such a `busy` (a resend uses a new id, §I.5).
Fixtures: the captures in `r8-failed-persistence-changes-no-lease` moved
to the step level and the scenario now follows §I; new
`r8-double-write-failure-takeover-never-runs`,
`r8-crash-after-durable-acceptance-grants-no-lease`,
`r8-revoked-control-fences-work-across-reconnect-and-restart`,
`r8-control-fence-holds-when-a-rejection-write-fails`,
`r8-recovered-work-needs-its-principal-confirmed`,
`r8-approval-answer-keeps-the-holders-deadline`,
`r8-delayed-send-reply-does-not-regrant-lost-control` and the client
scenario `r8-client-delayed-send-reply-never-restores-control`; the two
r2 history corrections (`chat_opens` 2, `wire_bytes` 675) are applied.

Revised 2026-10-18 for Astation's r4 review (a failed fence write could
lose a revocation if control was restored before the next
authentication): queued work whose authorization history can't be
established never runs. A failure while writing a revocation rejects
that principal's queued work at once in memory and nothing queued is
dispatched after a journal halt (§H, "A failed revocation write"); the
journal gets a **clean close** record, and after any run that didn't end
with one every recovered accepted request not yet executing is `rejected`
"authorization history unknown", for every principal (§H, "Recovery").
The 60 s confirmation stays, after a clean close only. Fixtures: new
`r8-failed-fence-write-rejects-queued-work-at-once`,
`r8-failed-fence-write-then-control-restored-never-runs` (rollback
succeeds, then rollback fails), `r8-crash-rejects-queued-work-whose-history-is-unknown`,
`r8-clean-close-runs-queued-work-once-its-principal-is-confirmed`;
`r8-recovered-work-needs-its-principal-confirmed` now starts from a clean
close, and `r8-crash-after-durable-acceptance-grants-no-lease` and
`r8-control-fence-holds-when-a-rejection-write-fails` now end
`rejected` "authorization history unknown"; the second welcome of
`r8-client-delayed-send-reply-never-restores-control` names a new
`controller_session` (§3). Schema: `crash_runtime`, and `restart_runtime`
is an orderly stop.

### A. Version admission

The envelope stays `v: 1`; the revision named in `hello` is the gate. One
mechanism covers every family (a new `v` would need the same check in
session, terminal and chat parsers and still say nothing about features), and
the refusal is explicit at admission rather than a silent misreading later.

| op | dir | r8 fields |
|---|---|---|
| `hello` | C→H | **`revision`** (required, the JSON integer `8`), `resume?` |
| `welcome` | H→C | r7.2 fields plus **`revision: 8`** and **`features: [string]`** |

- An r8 host answers a `hello` with no `revision`, another number or a
  non-integer with session `error{re, code:"unsupported_version", revision:
  8, detail}` and does nothing else: no attachment, no `welcome`, no lease,
  receipt, subscription or conversation. Every later request on that
  transport is refused as before `welcome` (in its family,
  `unsupported_version`) until a `hello{revision: 8}` is welcomed.
- The client checks `welcome.revision == 8` before anything else; without
  it (an r7 host ignores the unknown `hello.revision` and welcomes without
  one) the client refuses the attachment: it sends nothing further and
  applies nothing it receives, and tells the user the host's Atem must be
  updated.
- `features` lists what this host implements. The client enables only the
  advertised features it knows (unknown names are ignored) and never sends
  an op of a feature it didn't see; an operation that needs a missing
  feature is shown unavailable. A host never advertises a feature before its
  fixtures pass; an op of an unadvertised feature is `unsupported_version`.
  Per-session abilities stay in the descriptor's `capabilities`.

| feature | adds |
|---|---|
| `chat.history_end` | `open` ends with a sequenced `history_end` (§B) |
| `chat.history` | `history{before|next}` pages in the sequenced stream (§B) |
| `chat.lookup` | `history{turn_id|request_id}` (§B) |
| `chat.coverage` | `oldest_retained`, `truncated`, `holes`, `coverage`, the `coverage` event, `close.reason` (§C) |
| `receipt.result` | `result` on completed `prompt` receipts (§D) |
| `approval.session_rules` | r7.2 session rules (already shipped) |
| `approval.card_reason` | final cards carry `reason` (the `approval_closed` reason) |
| `chat.send_acquire` | a `prompt` submit may acquire the lease with the prompt (§F) |
| `approval.lease_free` | approval answers need `control`, never the lease (§G) |

- **Removed in r8**, refused explicitly with `unsupported_version` and no
  effect (never read as another form): chat `open.before`, `open.generation`
  (the r7.2/#75 paging form; an open conversation is not reset and no new
  one opens), the `status.page` marker (replaced by `history_end`), a
  `hello` without `revision`, and `acquire` on an approval answer (r7 §6a;
  in the payload or beside it, §G).

### B. History pages in the ordered conversation stream

**Ordering guarantee.** A conversation is one ordered stream with one
`sequence` counter. The host builds a page in a single step of its
single-threaded broker pass: it snapshots the retained history and enqueues
the page's envelopes with consecutive sequences, and no live event of that
conversation is enqueued between them. Every live event produced after the
snapshot has a higher sequence. (Atem: `src/chat/history.rs` builds every
page, the open's included, in one step from `ChatSession`'s retained
history and numbers its envelopes with the conversation's next sequences;
the runtime and the fixtures' fake runtime share it.)

Each message envelope's `sequence` is its position: a message version
carried at a higher sequence is newer. A client keeps, per `messageId`, the
version with the highest sequence and never lets a page replace a newer
version. A live update of a message is the whole `message` again (it
replaces the previous version; r8 sends no `delta`). No per-message
revision is needed because the stream is the order.
Astation, which returns pages over HTTP and changes over SSE, attaches its
own replay cursor (the conversation sequence) to each page and applies the
same rule. A reopen starts a new stream (`opened` at 0), so positions are
compared within one `opened` only.

`open` (no `before`, no `generation`) replies `opened` (sequence 0), the
newest page as `message{history: true}`, then `history_end`. Older pages
and lookups:

```json
{"type":"agentChat","data":{"v":1,"op":"history","conversationId":"conv-1","agentId":"ses-aaaaaaaaaaaa",
 "generation":"22222222-2222-4222-8222-222222222222","page_id":"p7","turn_id":"turn-9",
 "binding":{"target":{…},"attachment_gen":"33333333-…"}}}
```

- **Selectors**: exactly one of `before` (a retained `messageId`: the page
  ends just before it), `turn_id`, `request_id` (the turn whose user message
  carries it) or `next` (a continuation token, which carries its selector).
  None, two or more → chat `error{code:"invalid_request"}`.
- **Validation**: `before`, `turn_id`: 1–128 bytes of `[A-Za-z0-9._:-]`;
  `request_id`: lowercase v4 UUID; `next`: 1–512 bytes of base64url;
  `page_id`: 1–64 bytes of `[A-Za-z0-9._:-]`, chosen by the client;
  `generation` must equal `binding.target.process_gen` and the conversation
  must be open on this attachment (`stale_target`). At most 8 valid history
  requests a second per conversation (`busy`); invalid ones aren't counted.
- **`close`** may omit `binding`: it then closes only the sender
  attachment's own conversation of that id. With a binding it is checked
  like a read.
- **Reply**: `message{history: true, page_id}` envelopes, then
  `history_end`, all sequenced:

```json
{"type":"agentChat","data":{"v":1,"op":"history_end","conversationId":"conv-1","agentId":"ses-aaaaaaaaaaaa",
 "generation":"22222222-…","sequence":58,"page_id":"p7",
 "page":{"selector":"turn_id","count":28,"content_bytes":168000,"wire_bytes":1017000,
         "end":false,"next":"<opaque>","coverage":"complete",
         "oldest_retained":"m-0001","truncated":true,"holes":[]}}}
```

  `page_id` is absent on the open's `history_end` (`selector: "newest"`).
- **Order**: `newest`/`before` pages go backwards (each page lists its
  messages oldest first; `next` continues with older ones). `turn_id`/
  `request_id` pages go forwards from the turn's oldest retained message to
  its newest message at the first page's snapshot; later messages of the
  turn arrive live.
- **Bounds** (every page, lookups included): ≤ 50 messages, ≤ 256 KiB of
  content (message bytes as counted by `ChatSession`: the message's ids,
  each part's text and id plus 64 bytes per part, 1 KiB per approval card),
  and ≤ 1 MiB serialized (the sum of the page's envelopes, its
  `history_end` included, so Astation can return it as one body;
  `wire_bytes` reports that sum); a page stops before the message that would pass any bound and
  holds at least one message when one remains (a message is ≤ 128 KiB of
  content and ≤ 2048 parts, < 1 MiB however escaped). Cards filtered out
  for a view-only attachment don't count.
- **`end`**: `true` when the selected result is exhausted (no older retained
  message, or the turn's last message at the snapshot was sent); then there
  is no `next`.
- **`next`**: opaque, made by the host (MAC under a key of this runtime),
  binding the attachment, `conversationId`, full target (session and
  `process_gen`), selector and value, the continuation point and the history
  snapshot (the history's reload count). Used in another conversation,
  attachment or target, altered, after its continuation point was evicted,
  after a history reload, or after a runtime restart → chat
  `error{code:"stale_target", page_id}`; the client starts a new selection.
- **`before` not retained** → `stale_target` (as #75). A `turn_id`/
  `request_id` with nothing retained is not an error: `count: 0`, `end:
  true`, `coverage: "unavailable"`.
- Errors for a history request are sequenced in the conversation and carry
  its `page_id` when that was valid; nothing else is sent and nothing resets.

### C. Coverage: truncation and holes

- **`coverage`** of the selected result: `complete` (every message of it is
  retained), `partial` (some were evicted or fall in a hole; for a lookup,
  the turn's oldest messages were evicted or a hole lies inside the turn),
  `unavailable` (none is retained). A turn is `partial` when its oldest
  messages were evicted (the newest evicted message belonged to it) or a
  hole touches it (either neighbour is in the turn).
- **Truncation** is persistent: `oldest_retained` (the oldest retained
  `messageId`, `null` when empty) and `truncated: true` once anything of this
  process's history was evicted (retention 500 messages / 8 MiB, or an
  adoption cut). It is shown, never a reset; clients keep consuming the
  stream and never reopen because of it.
- **Holes** are gaps inside the retained timeline: items the worker's
  backlog dropped (`gap`) that a reload of the worker's history could not
  restore. `holes: [{after_message_id, before_message_id, count?}]` names the
  retained neighbours (`before_message_id: null` at the live edge until the
  next message); `count` when known. A `history_end` lists the holes whose
  `before_message_id` is in its page (≤ 16, then `holes_more: true`); holes
  older than `oldest_retained` become truncation. Holes are persistent and
  no reopen repairs them. A view-only attachment never sees card ids in
  this metadata: its holes are named by their nearest visible neighbours,
  a hole with no visible message before it is left out and reported as
  truncation (`truncated: true`), and its `oldest_retained` is the oldest
  message it can see.
- **Backlog gap handling (r8 implementation change from #75).** Today a
  worker chunk with `gap > 0` makes the broker reload the worker's history
  and then send every open conversation `error` "the chat history was
  incomplete…" and `close`, forcing a reopen. In r8 the broker reloads, sends
  each recovered message to open conversations as a sequenced
  `message{history: true, after_message_id}` (timeline order; `after_message_id`
  is the retained message it follows, `null` when none precedes it; the
  key is always present), and reports what stayed missing in a
  sequenced event, with no `error` or `close`:

```json
{"type":"agentChat","data":{"v":1,"op":"coverage","conversationId":"conv-1","agentId":"ses-aaaaaaaaaaaa",
 "generation":"22222222-…","sequence":9,"oldest_retained":"m-0001","truncated":false,
 "holes":[{"after_message_id":"m-0004","before_message_id":"m-0006","count":1}]}}
```

  A reload that fails (worker gone, over the reload bound) reports the gap as
  a hole with `count` when known (Atem: never, since the worker's `gap`
  counts items, not messages). The `coverage` event carries the session's
  whole hole list (≤ 16, then `holes_more`) and follows a reload only when
  a hole was recorded; a reload that restores everything sends none.
- **Resync** (reopen) only on: a sequence gap in the conversation, a fenced
  conversation (`stale_target` for its attachment, a new attachment), another
  `generation`, or `close` with a `reason`. r8 `close` carries `reason`:
  `switched` (`/clear`, resume, `/new`), `withdrawn` (chat withdrawn),
  `restarted` (new process), `evicted` (a ninth conversation), `fenced`,
  `reset` (any other host reset); Atem sends the first four (a fenced
  attachment's conversations end with its transport). Truncation, holes and
  `coverage` events never ask for one.

### D. `receipt.result`

```json
{"type":"session","data":{"v":1,"op":"receipt","request_id":"44444444-…","target":{…},"kind":"prompt",
 "state":"completed","detail":"done","updated_at":1760600000000,
 "result":{"turn_id":"turn-7","user_message_id":"turn-7-u","outcome":"done",
           "reply_message_ids":["turn-7-a-0001","…","turn-7-a-0032"],"more":true,"replies":"complete"}}}
```

- On `completed` `prompt` receipts only. `turn_id`, `user_message_id` and
  `outcome` (`done`|`interrupted`, equal to `detail`) are journaled with the
  `completed` transition (ids only, never text); the user message id is
  the one recorded when the prompt was accepted, retained or not (only ids
  that aren't opaque ids can't be journaled: that receipt has no
  `result`). `reply_message_ids` (the turn's assistant
  messages, timeline order, approval cards left out, **at most 32**; an id
  that can't be named is dropped and makes `replies` `partial`), `more` (true
  when more replies are retained) and `replies` (`complete`|`partial`|
  `unavailable`, the turn's coverage as in §C) are computed from retained
  history each time the receipt is sent, so they may change with late
  content or eviction. The rest come from `history{request_id}`; nothing is
  ever re-run to recover replies. An `outcome_unknown` prompt has no
  `result`.
- Bounds: a receipt with `result` is ≤ 6 KiB (32 ids ≤ 128 bytes each, plus
  r7.2 bounds); a `receipts` reply holds ≤ 64 receipts (r7.2's
  `request_ids` bound), so ≤ 384 KiB, below the 1 MiB message bound without
  continuation.

### F. Chat Send acquires the lease with the prompt (`chat.send_acquire`)

User-approved behaviour (2026-10-18, Astation handoff "Chat Send and session
control"). Chat and the remote terminal share one lease per session; viewing
either needs none. Remote terminal input still needs an explicit Take
Control (§5 `acquire`). A chat Send needs no separate step:

| ownership at admission | Send |
|---|---|
| nobody | acquires and submits in one host operation |
| this attachment | submits under its current lease |
| another attachment | refused `lease_held` naming the holder; only an explicit, confirmed takeover takes it |

**Wire.** A §6 `submit` of kind `prompt`, or a chat-v1 `submit` with
`text`, may carry `acquire: true`, and with it `takeover: true` plus
`expected_controller`, the lease the user confirmed taking over, in the
descriptor's `controller` shape (§4). Its binding then carries no
`lease_epoch` (as for §5 `acquire`):

```json
{"type":"session","data":{"v":1,"op":"submit","id":"…",
 "binding":{"target":{…},"attachment_gen":"33333333-…"},
 "request_id":"44444444-…","kind":"prompt","payload":{"text":"run the tests"},
 "acquire":true}}
{"type":"session","data":{"v":1,"op":"submit","id":"…",
 "binding":{"target":{…},"attachment_gen":"66666666-…"},
 "request_id":"44444444-…","kind":"prompt","payload":{"text":"run the tests"},
 "acquire":true,"takeover":true,
 "expected_controller":{"controller_session":"…","lease_epoch":7}}}
{"type":"agentChat","data":{"v":1,"op":"submit","conversationId":"…","agentId":"ses-aaaaaaaaaaaa",
 "generation":"22222222-…","requestId":"44444444-…","text":"run the tests","acquire":true,
 "binding":{"target":{…},"attachment_gen":"33333333-…"}}}
```

- **Field rules** (each `invalid_request`, nothing recorded, no lease
  change): `acquire` and `takeover` appear only as `true`; `takeover` needs
  `acquire` and `expected_controller`, and `expected_controller` needs
  `takeover`; `acquire` excludes `binding.lease_epoch`. Only `prompt` (chat:
  `text`) may acquire. `interrupt`, `stop` and `approval_rule_revoke` with
  `acquire` are `invalid_request`; an approval answer with `acquire` is the
  removed r7 form, `unsupported_version` (§G). Without the advertised
  feature, `acquire` is `unsupported_version` (§A).
- **Why `prompt` only.** The user approved Send. `interrupt` acts on the
  turn the current controller started: an acquiring interrupt from someone
  else is exactly the silent ownership change Send must never make, and on
  an unowned session an explicit Take Control first loses nothing (a raced
  interrupt is refused `stale_lease`, never misapplied). `stop` ends the
  process and with it every lease (`process_ended`), so acquiring for it
  means nothing. Either can become its own feature later.
- **Without `acquire`** a `prompt` is the r7 submit: the current lease
  (`lease_epoch`) is checked as in §6 and a wrong one is `stale_lease`. A
  client that holds the lease sends this form; a client that doesn't (or no
  longer knows) sends `acquire: true`.

**Request identity.** `acquire`, `takeover` and `expected_controller` are
admission parameters, like `binding.lease_epoch` and `attachment_gen`: they
are in neither the payload digest nor the immutable request (§6 unchanged:
`payload` is `{"text"}`). A duplicate `request_id` returns the recorded
receipt whatever flags it carries; it never acquires, takes over, renews or
re-executes. Why: a retry must be safe whatever the client believed about
ownership when it resent. The client keeps the `request_id` and text from
the first Send through a `lease_held` refusal, the takeover confirmation
and any uncertain delivery. If the first attempt was in fact accepted (its
reply lost), the confirmed retry gets the original receipt instead of
`request_id_reused`, which would tempt a new id and a second run. Flags in
the digest would buy nothing, since a duplicate never acts on them. A
refused Send records nothing, so the retry is a new admission. Before
offering a new Send or a takeover after an uncertain delivery, the client
checks the receipt (`receipt_query`). Neither a query nor a duplicate
acquires.

**Admission** (one step of the broker's single-threaded pass, so no other
admission, local input or lease change comes between its checks and its
commit). The order follows today's `SessionHost::submit`:

1. Binding (attachment, full target, trust and process generation):
   `unauthorized`/`stale_target`/`unknown_session` as §2.
2. Decode and field rules: `unsupported_version`/`invalid_request`.
3. Duplicate `request_id`: the recorded receipt (view only, no `lease`
   field) or `request_id_reused`.
4. `control` → `forbidden`: the attachment's principal holds `control`
   now (§H). Control authorizes the operation; the lease only coordinates
   writers.
5. A session that accepts work → `session_closed`; one whose descriptor
   lacks `chat-v1` → `busy` ("chat is not available for this agent"), so
   nobody takes control for a prompt that can't run.
6. Ownership, on the host's monotonic clock at this instant (a lease with
   `now >= deadline` has expired: the host applies the expiry first, with
   its `lease_changed{expired}`, as on any clock step). Never as Astation
   last displayed it:
   - held live by this attachment: **own**, no lease change;
   - held by this `controller_session` on another attachment: `stale_lease`
     (as §5 `acquire`);
   - held by another, no `takeover`: `lease_held`;
   - held by another, `takeover` with an `expected_controller` other than
     the current (`controller_session`, `lease_epoch`): `lease_held` (a
     stale confirmation never authorizes a different takeover);
   - held by another, `takeover` matching: a **takeover** is planned;
   - nobody: a **grant** is planned (also with `takeover`: nobody's control
     is taken, so the confirmation isn't needed).
7. The prompt's static checks: text ≤ 32 768 bytes after trimming, not
   starting with `/` or `!` (`ChatSession`'s `clean_prompt`), now at
   admission → `invalid_request`. Dynamic ones (status ready, no unsent
   terminal input, the same generation) stay at dispatch (`rejected` with
   the adapter's text), as in r7.
8. `receipt_limit`; the attachment's in-flight bound → `busy`.
9. A planned grant or takeover reserves its epochs durably (§5 epoch
   blocks). Failure → `busy`.
10. `accepted` is written durably (fsync), with the submitter principal
    and its `control_gen` (§H). A failure here or in step 9 is §I: `busy`,
    no lease change, nothing executes, the journal halts, and after the
    restart the request is `rejected` ("acceptance not confirmed"); a
    resend uses a new `request_id` (§I.5). Epochs reserved in step 9 may
    then be skipped, which §5 allows.
11. **Commit.** Only now the lease moves: a grant or takeover gives this
    attachment a new epoch with the full 15 s (capped by its authorization);
    a takeover also raises the input epoch, so the previous holder's queued
    bytes are dropped at the write boundary. Every other attachment with
    `view` gets `lease_changed{granted|takeover}` and subscribers get
    `session_changed`. Then the reply, then scheduling as any prompt (§6).

This is today's approval `acquire` transaction (`lease_to_acquire` reserves
before the journal append, `grant` runs only after it succeeds), with two
differences. The takeover must be explicit and must match
`expected_controller`. And the sender gets its lease in the reply, not in
`lease_changed`, per §5's recipient rule.

**Reply.** The reply that admits the Send carries the sender's lease:
session `receipt{state:"accepted", …, lease:{lease_epoch, ms_left}}`, or
chat-v1 `accepted{requestId, lease:{lease_epoch, ms_left}}`. That covers a
grant, a takeover and own. For own the epoch is unchanged and `ms_left` is
what remains: a Send never extends a lease (§5 rule 4). The client applies
it as the reply to an `acquire` sent when the Send was sent (§5 rules 2–5:
deadline = send time + `ms_left`). No other receipt carries `lease`: not
`executing`/final ones, duplicates or `receipts`. A client whose admitting
reply was lost doesn't control. If the registry shows it as controller, an
explicit `acquire` (the repeat-acquire rule) returns the current lease
unchanged.

**Refusal.** `lease_held` names the holder in the descriptor's shape so the
UI can offer "Take over and send":

```json
{"type":"session","data":{"v":1,"op":"error","re":"…","code":"lease_held",
 "controller":{"controller_session":"…","lease_epoch":7}}}
{"type":"agentChat","data":{"v":1,"op":"error","conversationId":"…","requestId":"44444444-…",
 "code":"lease_held","text":"another controller holds this session",
 "controller":{"controller_session":"…","lease_epoch":7}}}
```

r8 adds `controller` to every `lease_held`, the §5 `acquire` refusal
included. The host names only the opaque `controller_session`. Mapping it
to a person or device is Astation's job (its link is one attachment, and it
arbitrates its own clients before they reach the host). Nothing in a
refusal is recorded or executed, and no takeover happens.

**Renewal and release.** The lease is the attachment's, as after §5
`acquire`: it lasts 15 s and its holder renews it every 5 s (§5). Astation
owns renewal. The native app renews while that session's chat or terminal
view is in the foreground on the device whose user sent. It stops when the
view closes, the app goes to the background or the device sleeps, and then
sends `release` (best effort; otherwise the lease expires). For the
protected local API, the caller holds the lease explicitly: Astation renews
only while that caller keeps renewing through the API and releases when the
caller's API session ends. An abandoned caller loses control within 15 s.
The host renews nothing implicitly: not chat `open`, `history`, terminal
`subscribe`, `receipt_query`, a duplicate submit, a Send under the own
lease, nor execution of an accepted prompt. Expiry, release, local input or
a takeover don't cancel accepted work (§6).

**Unchanged.** Local terminal input revokes any remote lease before it is
written (`local_input`, §5). A Send queued behind a running turn is then
refused at dispatch by the adapter's unsent-input check. A Send's prompt is
a §6 receipt with every r7 check and transition. Process replacement ends
the lease (`process_ended`) and rejects accepted prompts (`session closed`);
a trust change rejects them (`host trust changed`). New in r8: a
principal that loses `control` is fenced durably (§H): leases held by any
of its attachments are revoked (`lease_changed{revoked}`), and its
`accepted` work not yet `executing`, from any of its attachments, live or
gone, is rejected (`detail:"control revoked"`), now or at dispatch after a
restart; executing work isn't cancelled. In compatibility mode this
happens when the link re-authenticates with fewer permissions, before the
new attachment is welcomed.

Fixtures: `r8-send-acquires-an-unowned-session`,
`r8-send-under-the-own-lease-checks-the-epoch`,
`r8-send-refused-while-another-holds-then-takeover`,
`r8-two-simultaneous-sends-acquire-once`,
`r8-ownership-is-checked-at-admission-not-as-displayed`,
`r8-local-input-wins-over-a-send`,
`r8-stale-takeover-confirmation-is-refused`,
`r8-duplicate-send-never-reacquires-or-replays`,
`r8-disconnect-right-after-acceptance`,
`r8-failed-persistence-changes-no-lease`,
`r8-expired-lease-is-checked-at-admission`,
`r8-revoked-control-refuses-the-send-and-its-queued-prompt`,
`r8-process-replaced-before-dispatch`, `r8-send-acquire-wire-rules`,
`r8-delayed-send-reply-does-not-regrant-lost-control` and, client side,
`r8-client-delayed-send-reply-never-restores-control`.

**Client rule for the reply's `lease`** (normative; §5 rules 1–5 apply as
to an `acquire` reply). The `lease` on an admitting receipt is applied only
if (a) its `re` is a submit still outstanding on the current attachment (a
reply to a submit sent on a replaced or fenced attachment is dropped: the
receipt state may be shown, the lease never), (b) its `lease_epoch` is not
lower than the highest `lease_epoch` the client has seen for that session
since the submit was sent (from `lease_changed`, `session_changed`,
`sessions` or another `lease`): a lower one was superseded by local input,
takeover, expiry, release or revocation while the reply was in flight, and
(c) the deadline it gives (submit send time + `ms_left`) is still ahead
(`now < deadline`). Otherwise the client stays a viewer; only an explicit
`acquire` or a new Send regains control. The host side is unchanged: a
superseded grant is already gone there, so the old epoch is `stale_lease`.

### G. Lease-free approval answers (`approval.lease_free`)

User decision, 2026-10-18. It replaces r7's "answering takes the lease with
the answer (`acquire`)". Answering a permission prompt is a decision about
that prompt, not writer coordination: it doesn't need the lease and never
moves it.

- **Payload** (strict): `{approval_id, decision, rule_id?, message?}`, as
  r7 without `acquire`. `acquire` is refused `unsupported_version` as a
  removed form, with no effect: in the payload (the r7 form) or beside it
  (§F's submit field). The binding's `lease_epoch` is optional and ignored,
  as for `approval_rule_revoke` (r7.3): a stale epoch or someone else's
  isn't refused. chat-v1 answers (`submit` with `approval`) follow the same
  rules.
- **Admission**, in order: a duplicate `request_id` returns its receipt
  (view only); `control` → `forbidden` (a verified attachment with
  `control`; view-only ones get no card and can't answer); a session that
  accepts work → `session_closed`; the approval pending for exactly the
  binding's `session_id` and `process_gen`, and an `allow_always`
  `rule_id` it offered, else `stale_target`. No lease check of any kind.
- **Never moves the lease.** No grant, takeover, renewal or release, no
  `lease_changed`, no `session_changed`. The holder keeps its epoch and
  deadline, and its queued input isn't fenced. A non-holder's answer is
  handed over like the holder's.
- **First answer wins.** The first answer the host admits while the request
  is pending wins. In the same step it goes `executing` and the approval
  closes (`approval_closed{answered_remote}`, push resolved). A later
  answer, from the holder or anyone, is `stale_target` and nothing of it is
  recorded; so is one to a request already closed (`answered_terminal`,
  `timed_out`, `interrupted`, `released`, `process_ended`). Holding the
  lease gives no priority. A duplicate of the winning answer returns its
  receipt. The terminal's own prompt still races as in r7
  (`outcome_unknown` when both crossed).
- **Rules** are granted only with the exact rule and scope the card showed
  (`allow_always` names an offered `rule_id`; r7.2 unchanged). Rule revoke
  stays r7.3: `control`, no lease, `acquire` refused.
- Unchanged from r7: delivery to every attachment with `control` whoever
  holds the lease, push, the receipt lifecycle, the 630 s hand-off deadline,
  release on Codex input, restart behaviour, and lease changes never
  closing an approval.

r8 text for §6a then reads: the intro's "answering takes the lease with the
answer (`acquire`)" becomes "answering needs `control`, never the lease"; the
`submit` row drops `acquire?`; the payload, admission and "Acquire is
atomic" paragraphs are replaced by the rules above; §5 "Scope" drops
approval answers; §6's admission note on approval answers with `acquire`
becomes "approval answers skip the lease check (§G)".

Fixtures: `r8-approval-answer-by-a-non-holder-leaves-the-lease`,
`r8-approval-answer-keeps-the-holders-deadline` (answers by the holder
and a non-holder at t = 6000/9000 leave the holder's deadline at 15 000,
its queued input is written, and an answer with no holder grants
nothing), `r8-approval-answer-with-acquire-is-refused`,
`r8-approval-answers-crossing-first-wins`,
`r8-approval-answer-to-a-closed-request-is-stale-target`.

### H. Submitter principal and the control fence (r8)

Answers the r3 review's finding 1. Control is a permission of an
authenticated principal, not of an attachment, and accepted work keeps the
authority it was accepted under only while that principal keeps `control`.

- **Principal.** The authenticated identity an attachment speaks for, set
  by the host from the link's authentication, never from message fields
  and never from the relay (relay labels are display only). Today
  (compatibility mode) there is exactly one: the paired Astation the link
  captured and `cred_state.json` verified, under the current
  `host_trust_gen`. With account trust (`../account-trust.md` §3.3) each
  device with a signed grant on the account is its own principal (its
  verified device id); Astation's native and API callers stay inside
  Astation's principal, and Astation arbitrates them (§F). `attachment_gen`
  and `controller_session` are not principals: every connect,
  re-authentication or replacement (r7.1) makes new ones for the same
  principal.
- **Control generation.** Per principal the host keeps, durably in the
  journal, whether it holds `control` and a `control_gen`: an integer from
  1 that never decreases and is never reset (kept like the lease-epoch
  floors). Every revocation of `control` raises it by one. Granting
  `control` again keeps the raised value; it never restores an old one.
- **Recorded at acceptance.** The `accepted` record carries the submitter
  `principal` and its `control_gen` at admission. Like `attachment_gen`
  this is admission metadata: it is in neither the payload digest nor the
  immutable request (§6), so duplicates and `request_id_reused` are
  unchanged (a duplicate needs only view).
- **Revocation is a durable fence.** When the host learns that a principal
  lost `control` (today: its link re-authenticates with fewer permissions;
  with account trust also: its grant is removed or lapses,
  `../account-trust.md` §3.4), it does in one step of the pass:
  1. write the fence `control_revoked{principal, control_gen}` (the raised
     value) durably (fsync);
  2. fence the principal's live attachments that had `control`, and revoke
     a lease held by any of its attachments (`lease_changed{revoked}`; the
     input epoch rises, so queued bytes are dropped);
  3. reject each of its `accepted` requests not yet `executing`, whichever
     of its attachments submitted it, live or gone (`rejected`,
     `detail:"control revoked"`, each persisted);
  4. only then welcome the new attachment.

  Executing work isn't cancelled (§6).
- **A failed revocation write** (r4 review). If any write of that step
  fails (the fence in step 1, or a rejection in step 3), whatever the
  rollback did, the host goes on in memory, in the same step: it fences
  the principal's live attachments that had `control` and revokes the
  lease as in step 2 (the input epoch rises, so the worker drops queued
  remote bytes at the write boundary; the epoch of that `lease_changed` is
  not persisted, which is harmless: clients order by `runtime_epoch`
  first, and the restart starts a new one), and marks every one of the
  principal's `accepted` requests not yet `executing` `rejected`,
  `detail:"control revoked"`, in memory, sent to any live attachment
  entitled to the receipt (today none: the principal's attachments were
  just fenced). The journal halts (§I): every later session request but
  `hello` is `busy`, a new link gets no `welcome` (its `hello` has no
  reply and every request on it is `busy` "journal halted; restart Atem";
  the link isn't closed), and
  **nothing queued is dispatched after a journal halt**, of any principal
  (nor any remote terminal input admitted), until the restart. These
  in-memory rejections aren't persisted; the restart rejects the same
  requests anyway, because a halted run never writes a clean close
  (Recovery, below), so they can never run.
- **Clean close.** At an orderly shutdown (SIGTERM/SIGINT, idle exit,
  replacement) whose journal is healthy (not halted, no failed write in
  this run), after admission has stopped and the last other journal write
  is durable, the host writes `<journal>/clean_close`
  (`{"runtime_epoch": n}`, the run's own epoch; temp, fsync, rename,
  directory fsync). A crash, a kill, a halted journal or a failed write
  (including a failed fence) means no clean close. At startup the host
  reads it before incrementing `runtime_epoch`: the previous run ended
  cleanly only when the file exists, parses and names the stored epoch.
  Then it removes the file (and the incremented epoch supersedes it in any
  case, so a removal that fails can't vouch for a later crash). An
  unreadable or stale file counts as no clean close.
- **Dispatch check.** Before an `accepted` request becomes `executing`
  (queued in this run, or recovered after a broker restart or worker
  adoption) the host checks its recorded principal: it must hold `control`
  now, with `control_gen` equal to the recorded one. Otherwise `rejected`,
  `detail:"control revoked"`, never executed. Kinds dispatched in the step
  that admits them (`interrupt`, `stop`, approval answers, rule revokes)
  pass trivially.
- **Same principal, new connection.** A disconnect, a reconnect, a
  re-authentication with the same permissions or an attachment replacement
  leaves `control_gen` unchanged, so accepted work goes on, as it does
  after lease expiry or release (§6). A principal that regains `control`
  after a revocation has no authority over work accepted before it: that
  work carries the older `control_gen` and was rejected at the fence, or is
  at dispatch.
- **Recovery** (broker restart, with worker adoption). Before anything is
  dispatched, every recovered `accepted` request not yet `executing` is
  resolved in this order, each resolution persisted:
  1. on the refusal list (§I.3) → `rejected`, `detail:"acceptance not
     confirmed"`;
  2. the previous run did **not** end with a clean close → `rejected`,
     `detail:"authorization history unknown"`, for every principal,
     whatever the journal holds (a fence on disk or not: a failed write
     may have left it, so what reached the disk never changes the
     outcome);
  3. after a clean close: host trust changed → `host trust changed` (§6);
     `control_gen` below its principal's durable one → `control revoked`;
     the rest is dispatched only once its principal's control is
     confirmed in this run: today when an attachment of that principal is
     welcomed with `control` (welcomed without it, the fence is written
     first and the work is `control revoked`); with account trust, when its
     stored grant verifies. Not confirmed 60 s after the host's start
     (`now >= start + 60 000`) → `rejected`, `detail:"control not
     confirmed"`.

  `executing` work is unaffected: reconciled, else `outcome_unknown`
  (§6). If a resolution can't be persisted, the host starts with remote
  sessions disabled (`welcome.host_error`) and dispatches nothing.
  Requests already `rejected` in the journal keep their detail; the
  in-memory rejections of a failed revocation write (above) were never
  persisted, so the same requests come back `rejected` with step 2's
  detail. Only the state is final; a detail is the best the journal can
  establish.

  Why rule 2: a clean close proves every revocation this host observed is
  durably fenced, so the stored `control_gen` is a complete history of
  them. Without one, a revocation may have been observed and lost (the
  r4 trace: the fence write fails, the host restarts, control is restored
  before the principal next authenticates, and a current `control` flag
  can't show the missed revocation), so no recovered queued work runs.
  The cost: after a crash, queued prompts that never started must be sent
  again by the client, with a new `request_id` (the old one is final,
  §I.5).

  Why the 60 s confirmation stays (after a clean close only): rule 2
  covers revocations the host saw; confirmation covers those that happen
  while it is down, learned only from the principal's next
  authentication (welcomed without `control`, the fence is written before
  anything of it runs), and the bound keeps a prompt from running long
  after its sender went away. A revocation and a re-grant that both happen
  entirely while the host is down are invisible to it; the authority
  (today Astation, which arbitrates its callers, §F) owns that case. The
  restart disconnected every client anyway; they reconnect and query.
- **Today.** One principal, whose control changes only when it
  re-authenticates with fewer permissions; unpair raises
  `host_trust_gen`, which already rejects accepted work (`host trust
  changed`, §6). The rule is per principal so account trust adds
  principals without changing it. The relay supplies none of this.

Fixtures: `r8-revoked-control-refuses-the-send-and-its-queued-prompt`,
`r8-revoked-control-fences-work-across-reconnect-and-restart`,
`r8-control-fence-holds-when-a-rejection-write-fails`,
`r8-failed-fence-write-rejects-queued-work-at-once`,
`r8-failed-fence-write-then-control-restored-never-runs`,
`r8-crash-rejects-queued-work-whose-history-is-unknown`,
`r8-clean-close-runs-queued-work-once-its-principal-is-confirmed`,
`r8-recovered-work-needs-its-principal-confirmed`.

Conformance obligations (r4 review; implementation tests, not wire
fixtures): fault the fence write with both rollback outcomes and the
rejection writes; check that a halted journal also blocks queued raw
terminal writes at the PTY write boundary (they don't pass through the
`accepted` → `executing` transition); fault the refusal-list write and
its atomic replacement, with crashes before and after its rename and
before and after the `rejected` transition is durable: replaying or
clearing the list is idempotent and never lets a refused request run;
and crash before, during and after the clean-close write and its removal.

### I. Admission persistence: one rule (r8)

Answers the r3 review's finding 2. It replaces §6's "If the durable write
of `accepted` fails … the client may retry with the same `request_id`.
After a double I/O failure … a request answered `busy` may still be
dispatched once …": that exception is removed, and a request answered
`busy` never executes. It applies to every kind and to both forms of
submit (session `submit`, chat-v1 `submit`). It matches `FileJournal`
today: an fsync per transition, the log cut back after a failed write,
and every later append refused until the journal is reopened.

1. **Accepted means durable.** A request is accepted only when its
   `accepted` record is written and fsync'd. Only then does anything act
   on it: the lease moves (§F step 11), the reply is sent, the work is
   scheduled.
2. **A failed admission write is a definitive refusal.** If a journal
   write of an admission fails (the epoch reservation, §F step 9, or the
   `accepted` record, step 10): no lease change, no `lease_changed` or
   `session_changed`, no receipt, nothing scheduled. The journal halts:
   until the runtime restarts and reopens it, every session request but
   `hello` is `busy` (`detail:"journal halted; restart Atem"`) and nothing
   becomes `executing`, which needs a durable write too. Before replying,
   the host records the refusal durably apart from the failed log: the
   request's immutable values (§6; no payload) go on the journal's refusal
   list (`<journal>/refused`, replaced atomically: temp, fsync, rename,
   directory fsync). Then the reply: `error{code:"busy", detail:"acceptance
   not recorded"}`.
3. **Resolved at restart, never executed.** When the journal reopens,
   before recovery dispatches anything, each request on the refusal list
   is made durably `rejected`, `detail:"acceptance not confirmed"`: a
   `Transition` when its `accepted` record is on disk after all (the write
   failed after a partial or complete write, or the rollback failed), else
   a receipt recorded directly as `rejected` (— → `rejected`, nothing
   accepted) with its immutable values. Then the list is cleared. If that
   can't be done, the host starts with remote sessions disabled
   (`welcome.host_error`, as for a damaged `runtime_epoch`) and dispatches
   nothing. What reached the disk never changes the outcome, so every
   implementation agrees on it.
4. **No durable refusal, no `busy`.** If the refusal can't be recorded
   either, the host doesn't answer `busy`: it closes the link with no
   reply and stays halted, and the client treats the request's delivery as
   uncertain. After the restart the journal decides: nothing (the request
   was never accepted), or, when the `accepted` record reached the disk, an
   accepted request that §H's recovery rejects (`authorization history
   unknown`: a halted run never ends with a clean close). The same holds
   for a crash after the `accepted` record became durable and before the
   lease moved or the reply was sent. Either way it never runs and no
   lease is granted:
   leases aren't persisted, and a lease is only ever granted in the step
   that sends the admitting reply. The client follows §F: `receipt_query`
   before any new Send or takeover.
5. **Resending.** Before the restart a retry is `busy` (halted). After it,
   a duplicate of the refused request returns its recorded `rejected`
   receipt (view only, no `lease`) whatever flags it carries, and is never
   re-admitted. To send the same text again the client uses a **new**
   `request_id`. Why: the old id is final and can only ever return
   `rejected`, and a new id can't run the prompt twice because the old one
   is durably refused. It is the one case where the client changes ids,
   and only once the old id is known to be final; §F keeps the id through
   `lease_held`, the takeover confirmation and uncertain delivery because
   there the old id may still run. A client that doesn't know why it got
   `busy` queries after reconnecting: `rejected` (whatever the detail:
   "acceptance not confirmed", "authorization history unknown") → a new
   id; nothing recorded → the same id.
6. Unchanged from §6: a failed `executing` write rejects the request
   before any effect, and every exit from `executing` is persisted before
   it is reported; any failed write halts the journal as in 2.
7. **Which detail wins at restart.** "acceptance not confirmed" (the
   refusal list) is resolved first and wins over §H's "authorization
   history unknown": the client was told `busy`, and the detail confirms
   that refusal. Both are `rejected`, final and never executed, so the
   choice changes no outcome (§H, Recovery, gives the full order).

Fixtures: `r8-failed-persistence-changes-no-lease` (single failure, the
retry with the same id while halted, then the restart: `rejected`, the
same id returns that receipt and isn't re-admitted, a new id is),
`r8-double-write-failure-takeover-never-runs` (a confirmed takeover while
another holds the lease: the write and its rollback fail, so the record
may be on disk; no lease change, `rejected` after the restart, never
executed, the same id returns the receipt),
`r8-crash-after-durable-acceptance-grants-no-lease` (durable, then a
crash before the grant: no lease, and after the restart `rejected`
"authorization history unknown", never executed).

### E. Errors (r8 additions)

| code | when |
|---|---|
| `unsupported_version` | also: `hello` without `revision: 8`; anything before such a `welcome`; `open.before`/`open.generation`; an op of an unadvertised feature; `acquire` on an approval answer (§G) |
| `invalid_request` | new: a well-formed message of a known op whose fields break its rules (history selector count, field formats or lengths; §F's `acquire`/`takeover`/`expected_controller` rules and a prompt's static checks) |
| `stale_target` | also: a `next` token used out of its context or stale; a `before` no longer retained |
| `busy` | also: more than 8 history requests a second in a conversation; an acquiring Send to a session without `chat-v1` (§F); a failed admission write (`detail:"acceptance not recorded"`, a definitive refusal) and every request after it, or after any other failed journal write such as a revocation's (§H), until restart (`journal halted; restart Atem`) (§I) |
| `rejected` receipt details | new: `control revoked` (the submitter principal lost `control`, §H), `control not confirmed` (recovered work whose principal wasn't confirmed within 60 s after a clean close, §H), `authorization history unknown` (recovered work not yet executing after a run that didn't end with a clean close, §H), `acceptance not confirmed` (a request refused `busy` for a failed write, resolved at restart, §I) |
| `lease_held` | now carries `controller{controller_session, lease_epoch}` (also for §5 `acquire`); also: an acquiring Send while another holds the lease, or a takeover whose `expected_controller` is no longer the holder (§F) |
| `forbidden` | also: a Send or approval answer from an attachment without `control`, checked before any lease state (§F, §G) |

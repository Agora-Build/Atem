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
**r9 (signed off 2026-10-19; implemented by Atem 2026-10-20, PR #89, not
yet merged):** the appendix "r9" at the end specifies remote clients that
reach Atem without the Mac (native members, scoped services, browser
grants) over the end-to-end channel `atem-ch1`, authorized by a signed
membership log pinned at pairing. Atem implements it in `atem-client`
(with its Swift, Kotlin and WASM bindings) and the runtime host; its
fixtures (`fixtures/r9-*.json`, `requires: "r9"`) run in atem-client's
tests and against the real runtime (`atem-host-handoff.md`). r8 stays
authoritative until r9 ships on both sides.
r9 note (2026-10-20), a clarification of signed-off r8 text, not a
change: §3's replaced-attachment sentence read "its leases end (none is
carried over)", which a reader could take to mean a dropped or
re-authenticated attachment's lease ends at once too, against §5 (left to
expire). It now says a replaced attachment's leases end at once while after
a drop or re-authentication they expire (§5), which is what r8 Atem does;
no wire, fixture or behavior changed. Agreed with Astation (PR #80,
comment 6291951066).
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
  or re-authentication would, except that its leases end at once (after a
  drop or re-authentication a lease is left to expire, §5; either way none
  is carried over; *clarification of the signed-off r8 text, see the r9
  note in the header*) — its
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
  captured and `cred/state.json` verified, under the current
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
| `rejected` receipt details | new: `control revoked` (the submitter principal lost `control`, §H), `control not confirmed` (recovered work whose principal wasn't confirmed within 60 s after a clean close, §H), `authorization history unknown` (recovered work not yet executing after a run that didn't end with a clean close, §H; it also covers a lost or older `principals` file: a recovered request whose principal the host's durable control history doesn't name at the request's `control_gen` or higher), `acceptance not confirmed` (a request refused `busy` for a failed write, resolved at restart, §I) |
| `lease_held` | now carries `controller{controller_session, lease_epoch}` (also for §5 `acquire`); also: an acquiring Send while another holds the lease, or a takeover whose `expected_controller` is no longer the holder (§F) |
| `forbidden` | also: a Send or approval answer from an attachment without `control`, checked before any lease state (§F, §G) |

## Appendix: r9 (signed off 2026-10-19; implemented by Atem 2026-10-20)

Status: **implemented by Atem** (2026-10-20: `crates/atem-client`, its
bindings and the runtime host; PR #89, merged only once Astation ships its
side). Released Atem speaks r8 until r9 ships on both sides; until then r8
(above) is the contract. A build of the PR (its packages and harness)
already refuses r8 on a host once a device list is pinned.
r9 adds remote clients that reach Atem independently of the Mac: native
members (Mac, iPhone, iPad, Android), scoped bots (`service`) and short
browser grants, all over one end-to-end channel (`atem-ch1`) whose
authority is a signed membership log pinned at pairing. It answers the
§9 gate for those features. Design and user decisions:
`remote-agent-api-atem.md` (r3) and `../account-trust.md`. Astation's
reviews of r2, of the first r9 pin `ffe840d` (its r3 review) and of
`016abe7` (its r4 review, both 2026-10-19; "Astation r4 review N" in
this appendix means the latter) are answered point by point in `remote-agent-api-atem.md`
§10. Fixtures: `fixtures/r9-*.json`
(`requires: "r9"`; run by atem-client's tests and, host side, against the
real runtime; the r8 runners report them NOT RUN),
format in `fixtures/schema.md` "r9 fixtures".

**What r9 keeps.** Every r8 operation, error and journal rule (§A–§I)
applies unchanged inside the channel: atomic Send acquire, confirmed
takeover, 5 s renew / 15 s expiry, local input wins, lease for
interrupt/stop/terminal writes, lease-free first-answer-wins approvals,
receipts, `receipt_query`, whole-message history pages, the §H principal
fence and the §I persistence rule. r9 changes only who a principal is,
how it is authenticated, and how revocation reaches the host.

**No compatibility.** An r9 host refuses r8 admission: the "paired
Astation over its authenticated link" principal of §H is removed, and the
Mac is the genesis member using the same channel as every other client
(over Atem's link to the relay or to Astation's :8080, inside the
channel envelope of R9.7a). Its link stays for pairing,
`cred unlock`, `credentialSync`, key grants and relay messages.

### R9.1 Encodings and signed objects

| Item | Rule |
|---|---|
| `enc(fields)` | `src/memory/encoding.rs`: each field is a 4-byte big-endian length then its bytes, the label first. Integers inside `enc` are 8-byte big-endian (`u64(n)`); hashes inside `enc` are their 32 raw bytes, never hex |
| JSON bodies | I-JSON parsed with `parse_strict` (`src/session_protocol/canonical.rs`: no duplicate keys, integers ≤ 2^53−1, no `null`, absent = omitted, no unknown fields in signed bodies); canonical form `jcs(body)` = RFC 8785 |
| Binary in JSON | base64url without padding (`b64u`) for keys, signatures, nonces and ciphertexts; lowercase hex (64 chars) for hashes |
| Signed object | wire `{"body":{…},"sig":"<b64u>"}` (a `set_recovery_key` entry with `kit: "current"` also carries `kit_sig`, R9.5); signing input `enc([label, jcs(body)])` with the label of the body's `type` (table below); the verifier takes the key and `alg` from where the body names its signer, never from the object |
| `p256` | ECDSA P-256/SHA-256 over the signing input, SEC1 uncompressed 65-byte public key, 64-byte `r‖s`, **low S required** (`verify_astation`). Signers normalize S; RFC 6979 or hedged nonces are both valid |
| `ed25519` | RFC 8032 pure Ed25519 over the signing input, 32-byte key, `verify_strict` (`verify_device`) |
| `x25519` | 32-byte public key; encryption only, never signing |
| Size | a signed body's `jcs` ≤ 4096 bytes |

| `type` | label (signing input) | signed by |
|---|---|---|
| `atem-membership-entry` | `atem-membership-entry-v1` | a manager at `seq-1`, or the current recovery key (R9.5) |
| (`kit_sig` beside a `set_recovery_key` entry with `kit: "current"`) | `atem-recovery-cosign-v1` over the same `jcs(body)` | the current recovery key (R9.5) |
| `atem-browser-grant` | `atem-browser-grant-v1` | a native member with `control` (R9.6) |
| `atem-push-hint` | `atem-push-hint-v1` | the host's `host_channel_key` (R9.9) |
| `atem-seen` | `atem-seen-v1` | the host's `host_channel_key` (R9.9) |

Other domain strings (never signing inputs of another kind):
`atem-membership-hash-v1`, `atem-browser-grant-hash-v1`,
`atem-ch1-th2`, `atem-ch1-th3`, `atem-ch1-th4`, `atem-ch1-host-sig-v1`,
`atem-ch1-client-sig-v1`, `atem-ch1 finish c2h`, `atem-ch1 ap c2h`,
`atem-ch1 ap h2c`, `atem-ch1-finish`, `atem-ch1-rec`,
`atem-push-seal-v1`, `atem-enc-kid-v1`, `atem-k-backup-v2`,
`atem-recovery-kit-v2`, `atem-recovery-kit-tag-v1`,
`atem-k-backup-hash-v1`, `atem-recovery-sign-v1`, `atem-safety-code-v2`.
Vectors: `r9-vectors-encoding`, `r9-vectors-keys`.

### R9.2 The membership log

One log per account device list, keyed by its `genesis_hash`. Entry
body (every field required unless marked `?`):

```json
{"type":"atem-membership-entry","v":1,"account_id":"acct-test-1",
 "genesis_hash":"<hex, absent in genesis>","seq":3,"prev_hash":"<hex of entry seq-1>",
 "action":"add","signer":"dev-mac","signed_at":1792400002000,
 "member":{"device_id":"dev-phone","kind":"native",
           "auth_key":{"alg":"p256","pub":"<b64u 65 bytes>"},
           "enc_key":{"alg":"x25519","pub":"<b64u 32 bytes>"},
           "roles":["control","manage","view"]}}
```

`entry_hash = SHA-256(enc(["atem-membership-hash-v1", jcs(body)]))`, hex.
**The signature is not hashed:** a body re-signed (P-256 nonces differ)
is the same entry; two entries at one `seq` conflict only when their
bodies differ (Astation review 2).

| `action` | fields beside the common ones | rules |
|---|---|---|
| `genesis` | `member` (native, roles `["control","manage","view"]`), `recovery_key{alg:"ed25519",pub}` | `seq` 1, `prev_hash` 64 × `0`, no `genesis_hash`, `signer` = `member.device_id`, self-signed. `genesis_hash` = its `entry_hash` |
| `add` | `member` | `device_id` never used before in this log (ids are never reused, even after `remove`) |
| `remove` | `device_id` | a current member; at least one native manager remains |
| `set_roles` | `device_id`, `roles`, `scope?`, `expires_at?` | a current member; same kind rules as `add`; at least one native manager remains. **Always a revocation** (R9.3) |
| `add_host` | `host{host_id, host_trust_gen, host_key{alg:"ed25519",pub}}` | `host_trust_gen` greater than every earlier `add_host` of that `host_id`; the newest one is the host's only valid key |
| `remove_host` | `host_id` | a current host |
| `recovery_add` | `member` | R9.5; `signer` is exactly `"recovery"`, verified with the current recovery key. **Pending** for 24 h on each host's clock (R9.5) |
| `set_recovery_key` | `recovery_key{alg:"ed25519",pub}`, `kit` (`"current"` or `"lost"`) | R9.5; a manager signs; a key never used in this log before. `current`: the wire object also carries `kit_sig` by the current recovery key, in effect at once. `lost`: no `kit_sig`, **pending** like a `recovery_add` |
| `recovery_approve` | `target` (hex `entry_hash`) | R9.5; `target` is a `recovery_add` or a `kit: "lost"` `set_recovery_key` in this log; a manager other than the target's signer. Ends the wait at once |
| `recovery_veto` | `target` | R9.5; same `target` rule; any manager. Cancels the target if it is still pending on this host |
| `k_backup` | `k_backup{blob_version, kids, recovery_key, backup_hash}` | R9.5; a manager; `blob_version` above every earlier one; `recovery_key` current or pending. Records the newest K backup (the restore's version floor) |

`member`: `device_id` (opaque id, 1–128 bytes `[A-Za-z0-9._:-]`, never
`recovery`), `kind`:

- `native`: `auth_key` (`p256` or `ed25519`), `enc_key` (`x25519`,
  required: push hints are sealed to it), `roles` ⊆ {`control`, `manage`,
  `view`}, must contain `view`.
- `service`: `auth_key`, no `enc_key`, `roles` exactly `["service"]`,
  `scope` and `expires_at` required (R9.6), `expires_at` ≤ `signed_at` +
  7 776 000 000 (90 days).

**Arrays** (Astation r4 review 4). Every array in a signed body
(entry, grant, push hint, seen) and in the K-backup envelope and its
plaintext is one of two kinds, fixed per field, so one meaning has one
encoding:

| kind | fields | rule |
|---|---|---|
| **set** | `member.roles`, `set_roles.roles`, `scope.hosts`, `scope.projects`, `scope.sessions`, `scope.ops`, a grant's `ops` | sorted ascending by bytes (UTF-8), no duplicates |
| **sequence** | `k_backup.kids` (entry), the envelope's `kids` and its plaintext `keys` (R9.5) | in meaning order: the current key first, then retained previous generations newest first; no duplicate kid; never sorted. The entry's `kids`, the envelope's `kids` and the plaintext's `keys[].kid` are the same sequence |

A set that isn't sorted, or any array with a duplicate, is invalid
(for an entry `membership_invalid`, detail `array_not_canonical`; for an
envelope `backup_invalid`); a field not in the table can't be an array. A verifier checks a sequence's length and
duplicates and never reorders it (`KB7`, `KB8` and `KB8_stale` keep
their current kid first). `signed_at` is the signer's display time,
never authority (R9.6 says which times are).

**Verifying entry `n` against a chain `C` whose head is `n-1`:** strict
parse; `type`, `v`; `account_id` and `genesis_hash` equal the pin;
`seq = n`; `prev_hash = C[n-1].entry_hash`; the action's rules above;
the signer: `"recovery"` only for `recovery_add`, verified with the
**current** recovery key (genesis, or the newest `set_recovery_key` in
effect on this host; a replaced key is refused, `recovery_key_retired`);
otherwise a `native` member of `C` holding `manage` and in effect on this
host (a member whose `recovery_add` is pending or cancelled here holds
nothing), verified with its `auth_key` under its pinned `alg`. Anything
else is invalid. An entry whose only problem is that it depends on an
entry still pending on this host is **deferred**, not invalid (R9.3,
R9.5). The `alg` of a key is fixed when it enters the log; a new key is
a new member (or a new `add_host`).

Log limits: ≤ 1024 entries, ≤ 256 members, ≤ 64 hosts. A full log is
`membership_invalid` "device list full; re-pair to start a new one".
Vectors: `r9-vectors-membership-log` (E1–E6 and the alternatives used
by the scenarios); `r9-vectors-pairing` (`verifyCommit` and its
`host_trust_gen` cases).

**Pairing (ceremony changes).** `verifyCommit` gains `host_trust_gen`:
the binding's host trust generation, public, a JSON integer with
1 ≤ n ≤ 2^53−1 (R9.1), in the existing message's payload:
`{"type":"verifyCommit","data":{"device_id":"<atem_device_id>",
"commitment":"<base64>","host_trust_gen":3}}`. It is required (no
compatibility): Astation refuses (`verifyAbort`) a `verifyCommit`
without it, or with a value that isn't an integer in that range, and
copies it unchanged into the signed `add_host`. Both sides capture it
with the commitment for that verification attempt and never change it
while the owner's confirmation is pending; the attempt is void after a
reconnect of the link or a new pairing (`atem pair`, `atem unpair`) on
either side. No secrecy or commitment binding is needed: Atem compares
the `add_host` it receives with its own host id, key and generation and
refuses any other. `verifyKeys` gains `genesis_hash`
(lowercase hex); `verifyReveal` gains `host_channel_pub` (the 32-byte
Ed25519 key, R9.6, in base64url without padding as R9.1 says; the
ceremony's older fields stay standard base64), inside the commitment,
whose label is unchanged: `C = SHA-256(enc(["atem-verify-commit-v1",
device_pub, device_sign_pub, unlock_auth_pub, host_channel_pub,
nonce_a]))`; the safety code becomes `base32(SHA-256(enc(["atem-safety-code-v2",
device_pub, device_sign_pub, unlock_auth_pub, host_channel_pub,
astation_sign_pub, astation_enc_pub, recovery_sign_pub, genesis_hash,
nonce_a, nonce_s])))[:12]`. After Touch ID the pairing manager appends
`add_host{host_id = atem_device_id, host_trust_gen, host_key}` (relay
CAS, R9.4) and `deviceVerified` gains `membership{entries}` (genesis to
that entry). Atem verifies the whole chain, that the signer of its
`add_host` is the verified Astation (`member.auth_key` equals the pinned
`astation_sign_pub`) and that the entry names its own key and trust
generation, and pins it (R9.3) before reporting success. Atem refuses a
log whose genesis is in its `frozen_genesis` list (R9.4).

### R9.3 What Atem stores; carrying suffixes

**`pairing/membership.json`** (0600; temp, fsync, rename, directory
fsync; under `pairing/trust_gen.lock`):

```json
{"v":1,"account_id":"…","genesis_hash":"…","recovery_key":{"alg":"ed25519","pub":"…"},
 "host":{"host_id":"host-a","host_trust_gen":1},
 "retired_recovery_keys":["<b64u>"],
 "head":{"seq":6,"hash":"…"},"entries":[{"body":{…},"sig":"…","kit_sig?":"…"}],
 "recovery":[{"entry_hash":"…","seq":7,"state":"pending","first_seen_wall":1793177601000,
              "boot_id":"…","mono_at_first_seen_ns":0,"mono_waited_ms":0,"decided_at_wall?":0,"reason?":"…"}],
 "evidence":{"count":0,"recent":[]},"frozen?":{"at":0,"seq":6,"ours":"<hash>","theirs":{"body":{…},"sig":"…"}}}
```

`recovery_key` is the current one (R9.5); `recovery` holds one record per
`recovery_add` or `kit: "lost"` `set_recovery_key` in the log, written in
the same commit that appends the entry (its wait starts then) and on each
state change (R9.5).

`host_channel_key` (Ed25519 seed) is `pairing/host_channel_key`, 0600,
plain like `unlock_auth_key` (it only proves the host to clients, so it
works while the cred agent is locked). `atem unpair` deletes both files
(and the carriage record, intent and fault record of "Writing the
device list" below), keeps `pairing/frozen_genesis` (≤ 16 hashes), and rotates the key at the
next pairing. The journal gains `<journal>/membership_applied`
(`{seq, hash}`: the head whose fences are durable).

**Carriage.** Atem's head is public and signed in `channel_accept`
(R9.7). The client's `hello` carries `membership{head, entries, more?}`:

| client's log vs Atem's head `(s, h)` | `entries` |
|---|---|
| has `h` at `s` | its suffix `s+1…`, at most 64 entries / 256 KiB; `more: true` when longer |
| has another entry at `s` (diverged) | a window ending at `s`: up to 64 entries ending at `min(s, own head)` |
| shorter than `s` | none; after `welcome` it fetches from the relay and verifies up to `h` (a mismatch makes it the diverged case on its next connect) |

**Applying a carriage** (one step of the broker pass, so concurrent
connections are serialized; the head may have moved since `accept`):

1. Shape: contiguous ascending `seq`, within the bounds, each body
   parses. Otherwise `membership_invalid{index}`, nothing applied.
2. For each entry `e` in order, against a scratch copy of the chain:
   - `e.seq` ≤ scratch head: same `entry_hash` as the stored entry →
     skip (the stored signature stays). Different → the conflict rule
     (R9.4) if `e.prev_hash` is the stored hash at `e.seq-1`; if it is
     not, the divergence is before the window: `membership_invalid`
     `need_before: <window start>` (the client reconnects with an earlier
     window). Processing stops after a conflict.
   - `e.seq` = scratch head + 1: verify (R9.2); valid → append to the
     scratch; invalid → stop, remember its index; **deferred** (it is
     signed by the subject of a `recovery_add` still pending on this
     host, or verifies only with the key of a `set_recovery_key` still
     pending here, R9.5) → stop without an error: the rest is carried
     again once the wait ends.
   - a gap → stop, invalid.
3. **Commit the valid prefix in one write** of `membership.json` (the
   whole bounded batch or the part before the first invalid entry, never
   entry by entry). A valid removal followed by an invalid entry is
   applied (Astation review 5): a signature is trusted whatever else its
   carrier sent. The write follows "Writing the device list" below; a
   failed write **fails closed** there (in-memory fences, journal halt)
   and the carrier gets `busy` "device list not recorded".
4. Then the effects, in seq order, through §H: removal, `set_roles`,
   `remove_host` of this host, expiry shortening and grant fences write
   the `control_revoked` fence (raised `control_gen`) for each affected
   principal, fence **all** its attachments (view ones too, for a
   removal), revoke its lease and reject its accepted-not-executing work
   (`control revoked`). Then `membership_applied` is written. A failed
   fence write follows §H "A failed revocation write" (journal halt,
   in-memory fences).
5. Only then the reply: `account_frozen` if frozen; `membership_invalid
   {head, index}` if an entry was invalid (the connection is refused,
   after the valid prefix took effect); `membership_incomplete{head}` if
   `more` and the sender's principal isn't in the chain yet (the client
   reconnects with the next window); `recovery_pending{entry_hash,
   effective_at}` if the sender's principal is the subject of a pending
   `recovery_add` (or is added only by an entry deferred behind one);
   else admission is judged against the committed head (R9.6, R9.8). A
   deferral is not an error: the carrier is admitted, and its `welcome`
   shows the head below its own and the pending entry.

**Writing the device list** (Astation r3 review 1, r4 review 2). A
carriage that holds anything Atem doesn't store already (an entry beyond
its head, or a different one at a stored `seq`), from any route or the
host's own relay fetch, is processed as:

0. **Carriage record:** `pairing/membership.carriage` = `{v:1,
   runtime_epoch, base{seq,hash}, entries}`: the exact carried objects
   (within the carriage bounds, so ≤ 64 entries / 256 KiB) and the head
   they are judged against (temp, fsync, rename, directory fsync),
   written **before any of them is evaluated**. Atem evaluates only what
   is durably recorded.
1. **Intent:** `pairing/membership.intent` = `{seq, hash}` of the head
   about to be written (same way).
2. **State:** `membership.json` (same way).
3. The effects (step 4 above), then `membership_applied`.
4. Remove the intent, then the carriage record (directory fsync after
   each). A leftover intent or record whose entries are all at or below
   the stored head and equal to it is harmless.

A freeze writes `pairing/membership.freeze` (both entries) the same way
after the carriage record, then `frozen` in `membership.json`, then
removes the record. A carriage with nothing new writes nothing.

**A failed write** — of the carriage record, the intent, the temp file,
its fsync, the rename or the directory fsync, or of the freeze file —
makes the durable state uncertain, and Atem fails closed in the same
step, exactly as §H "A failed revocation write": in memory, every
principal the uncommitted prefix would remove, strip of `control` or
fence (removal, `set_roles`, `remove_host` of this host, expiry
shortening, grant fences) — **every remote principal** when Atem can't
tell which (a freeze, a batch it couldn't evaluate, or a carriage record
that couldn't be written, whose carriage is then refused unread) — has
its attachments fenced, its lease revoked (the input epoch rises, so the
worker drops its queued raw bytes at the write boundary), and its
`accepted` work not yet `executing` rejected (`control revoked`). A
freeze also takes effect in memory at once (R9.4). Membership is then
**faulted** for the run (every later carriage is refused unread), the
fault is **recorded** (below), and the journal halts (§I): every `init` gets a clear `busy`, every later
session request but `hello` is `busy` "journal halted; restart Atem",
nothing queued is dispatched, no remote terminal input is written and no
new push hint is sent, until the restart. Local use goes on. Atem never
retries the write in the same run.

**Fault record** (user decision of 2026-10-19, option 2).
`pairing/membership.fault` = `{v:1, runtime_epoch, file, at}` (temp,
fsync, rename, directory fsync) is written in the fail-closed step of
any observed device-list write fault: a failed write, fsync, rename or
directory fsync of the carriage record, the intent, `membership.json`
or the freeze file. A fault record in any state, even unreadable, counts.
If it can't be written either, the run is halted as above and the
failure is logged; the restart then relies on the carriage record
alone. Only a manager's reconciliation removes it (below).

**Crash recovery.** At start, before any remote admission, Atem fsyncs
`membership.json` and the `pairing/` directory (a rename that is
visible becomes durable; a failure disables remote sessions,
`welcome.host_error`), then, in order:

1. `membership.freeze` exists, in any state, even unreadable → frozen
   (R9.4).
2. `membership.carriage` exists: readable → **replayed**, judged
   against the stored chain exactly as when it arrived (steps 1–5 of
   "Applying a carriage" without a reply, R9.4's conflict rule
   included), written through steps 1–4 above, then removed. Because the
   record was durable before anything in it was evaluated, losing the
   intent, the state or the freeze write loses nothing: a conflict it
   held freezes again, a removal is applied again. Unreadable → held
   (evidence `carriage_unreadable`).
3. Then `membership_applied`: for every entry after the applied head
   Atem replays the fences (idempotent: a raised `control_gen` is never
   raised twice for one entry, the fence names the entry's `seq`) and
   writes `membership_applied`. An unreadable `membership.json` or an
   applied head ahead of the stored head disables remote sessions
   (`welcome.host_error`); nothing is reset silently.
4. **Held** when a fault record exists, or when the replay can't
   reconcile the carriage record (unreadable, or an intent left beyond
   the head after it). Otherwise the host resumes remote admission
   normally: an unclean stop with no recorded fault (a crash, power
   loss or kill) replays the carriage record and goes on.
5. Pre-restart `accepted` work follows §H Recovery (a run that halted
   never wrote a clean close, so it is `rejected`, `authorization
   history unknown`).

**Held: no remote admission until reconciled.** Local use is
unaffected. `init` is answered as usual (its signed head is what clients
compare), carriages are still applied (through the carriage record, so
removals land), and every `hello` except a reconciling one gets `busy`
"device list not reconciled" after its carriage. No push hint is sent.
`atem status`, `atem agent list` and the agent terminal's status row say
that remote access waits for a managing device. Nothing on the host's
side ends it: not time, not a restart (the fault record stays), not
the host's own relay fetch, not a carriage by a service, a view-only
member or an unknown carrier. **Reconciliation** is a `hello` that,
after its carriage is applied:

- comes from a `native` member holding `manage`, in effect at the
  committed head;
- carried no conflicting, invalid or deferred entry, and no `more`;
- reports `membership.head` equal to the committed head: the client
  compared the host-signed head of `accept` (bound in `th2`) with the
  log it verified from its pinned genesis and signed the transcript
  with `sig_c`, so both signatures cover one head;
- leaves no intent unsatisfied (an intent whose `seq` now holds another
  hash keeps the host held, evidence `intent_mismatch`; the way out is
  re-pairing).

The host then removes the fault record (directory fsync; if that
fails, it stays held for the run), leaves held (logged) and admits that
`hello` normally. A manager
whose log is behind the host's head gets `busy` "device list not
reconciled", fetches from the relay and reconnects.

Why this is safe: everything the host evaluated was durable before it
was evaluated and is replayed, so no conflict or removal it saw can be
lost by a failed or lost later write, with or without a crash; a
carriage whose record never became durable was never evaluated, so the
host learnt nothing that its carrier couldn't equally have withheld
(and every honest copy, on devices and at the relay, still exists). A
recorded fault holds the host until a managing device whose own verified
log ends at the host's head confirms it. A manager whose key was stolen
can reconcile too; that key admits it anyway, and it can't erase a
conflict the record holds. If no managing device can ever connect, the
way out is re-pairing (`atem unpair`, `atem pair`).

**Residual risks (accepted, user decision of 2026-10-19, option 2).**
Without a fault the host trusts its disk at start, so two cases are not
covered: storage that drops writes it already reported as done (a
carriage record, intent or freeze that fsync acknowledged and the disk
then lost, with no fault observed), and a `pairing/` directory restored
as a whole from an older backup. Either can bring back an older head
or lose a freeze; the next carriage of the newer entries or the
conflict re-establishes them. Both are accepted.

**On an open channel** a client sends `membership{id, entries}` whenever
it learns newer entries; same algorithm; reply `membership_head{re,
head}` or the error (the channel stays unless its own principal was
fenced). Atem sends every attachment `membership_head{head,
pending_recovery}` (no `re`) when its head moves or a pending entry
starts, takes effect or is cancelled, so clients fetch. Atem may also fetch the suffix
from the relay over its own link; it gets no more trust than any
carrier.

**Bounds against rejected traffic:** ≤ 65 signature checks per carriage;
r7.1's one `hello` per second per transport; `evidence` keeps a count
and the 32 most recent records (`{seq, entry_hash, signer, reason,
at}`), persisted at most once a minute and otherwise only counted in
memory and `runtime.log`. Nothing a refused carrier sends grows storage
beyond that.

Revocation is **eventual, not bounded** (Astation review): a removal
reaches a host when any honest device next connects to it or the host
fetches from the relay. A relay that hides a removal from every device
and the host delays it without limit; the durable head only prevents
rollback after a removal was seen. That is the accepted residual risk.

### R9.4 Conflicts, freeze and concurrent changes

A **conflict** is a valid-shaped entry at `seq` ≤ Atem's head, chaining
from Atem's entry at `seq-1`, whose `entry_hash` differs from Atem's
entry at `seq`. Only that first divergent entry is judged, by the first
row that matches (the first three are the recovery decisions of R9.5):

| the conflicting entry | outcome |
|---|---|
| a valid `recovery_veto` of the same target as Atem's `recovery_veto` at `seq` (two devices vetoed at once) | same effect: if Atem's veto is its head, Atem **replaces** it with the carried one in one write (no effects change), so it can follow the relay's branch; otherwise **ignored**, evidence `duplicate_veto` |
| Atem's entry at `seq` is a `recovery_veto` it applied while the target was pending here, and the carried one is signed by that target's subject or verifies only with its key | **freeze**: the relay ordered the subject's entry ahead of a veto this host applied in time, so the kit or the relay is compromised |
| a `recovery_approve`/`recovery_veto` of a target already in effect here, against Atem's entry signed by that target's subject | **ignored**, evidence `late_decision` (a veto after activation has no effect) |
| invalid against `C[..seq-1]` (bad signature, signer not a manager at `seq-1`, bad action) | **ignored**, evidence `invalid` |
| valid, signer removed or stripped of `manage` anywhere in Atem's `C[seq..head]` | **ignored**, evidence `signer_removed` (a stolen key of a removed manager can't deny service) |
| valid, signer still a manager at Atem's head, or signed by the recovery key | **freeze** |

**Freeze:** `frozen` (with both entries) is made durable first (R9.3
"Writing the device list"; if that write fails, the host is frozen in
memory at once and the journal halts; at the restart a freeze file that
reached the disk in any state keeps it frozen, and otherwise the
carriage record, durable before the conflict was evaluated, is replayed
and freezes it again; the fault record also holds it, R9.3), then
every remote principal is fenced (§H, `control_revoked`; attachments
closed with session `error{code:"account_frozen"}`), every `init` is
answered `account_frozen` before any key work, membership processing
stops and push hints stop. Local use is unaffected. No entry, manager
or recovery signature lifts it. The reset is re-pairing (`atem unpair`,
`atem pair` from a trusted device); the frozen `genesis_hash` goes on
`pairing/frozen_genesis`, so the host can only be re-paired to a **new**
list. UI text (neutral): "Remote access to <host> is paused: it received
conflicting signed device-list history. Re-pair this host from a device
you trust: `atem unpair`, then `atem pair`."

**Honest concurrency is avoided, not resolved** (Astation review 2).
The relay serializes appends per log with a compare-and-swap:

- `POST /api/remote/v1/logs/{genesis_hash}/entries {entry,
  expected:{seq, hash}}` appends iff the relay's head is `expected` (one
  transaction; unique `(genesis_hash, seq)`). An entry whose
  `entry_hash` equals the stored one at that seq answers `200` with the
  stored entry (idempotent retry); otherwise `409 {head, entries,
  more?}`: the relay's entries after `expected.seq`, or, when its hash
  at `expected.seq` differs, a window from before the divergence, at
  most 64 entries / 256 KiB, with `more: true` and the rest from `GET
  …/entries?after=<seq>` (Astation r3 answer). The client fetches and
  verifies all of it before it asks for any fresh owner confirmation and
  never changes a body under an old one. The relay verifies chain and
  signature before storing, as a convenience only.

Client (manager) rules, required of every signer:

1. **Prepare durably.** Build the body on a head the client verified,
   store the exact `jcs` bytes before asking the key to sign, then store
   the signature.
2. **Publish before use.** Never send the entry to a host or a device,
   and never count it in its own log, until the relay answered `200` for
   it. A host can therefore only ever see relay-committed entries from
   honest signers. **One exception, `recovery_veto`** (R9.5): a device
   may send a veto to any host by any route (relay channel, direct
   :8080, the Mac's link) before or without the relay's answer, built on
   that host's head as its `welcome` shows it (which can be behind the
   relay while the host defers entries), and publishes it to the relay
   in parallel. If the relay answers `409`, the device rebuilds the veto
   on the relay's head only if the target is still undecided there; a
   host that applied the direct veto resolves the difference by the
   first three rows above.
3. **Lost the race (`409`).** Discard the prepared body durably (never
   carried), verify and apply the returned entries, re-check the user's
   intent on the new head (the device may already be gone), and if still
   wanted build a new body at the new `seq` with a **fresh** owner
   confirmation (R9.6: a confirmation never covers a changed body).
4. **Uncertain outcome** (timeout, crash): resend the same stored bytes;
   if the signature was lost, re-sign the same body (same `entry_hash`,
   never a conflict). Until `200` or `409` nothing else is signed.
5. One outstanding append per device.

With an honest relay two honest managers never produce siblings: the
second gets `409`. **If the CAS fails** (a faulty or hostile relay
accepts two entries at one `seq`, or shows two devices different heads),
honest siblings exist, and any host that receives both freezes: the
freeze then signals relay misbehaviour, not necessarily a stolen key.
The availability cost is accepted (user decision): a relay that can
cause it can already deny service by dropping traffic, and it gains no
integrity or confidentiality power. A device that sees two entries at
one `seq` from the relay shows "conflicting signed membership history",
stops signing entries, and carries the divergent window to hosts like
any other window (so every host converges on frozen instead of
splitting). Hosts that first saw different successors each freeze when
the other branch arrives. No branch is merged and the relay never picks
a root.

Fixtures: `r9-chain-*` (R9.12).

### R9.5 Recovery, the 24 h wait, kit replacement and the K backup

User decisions of 2026-10-19 (open questions 2 and 3 of r9's first
draft): an enrollment by the Recovery Kit waits 24 h on each host's own
clock, during which any manager can approve or veto it; the kit is
replaceable.

**Recovery entry.** Signed only by the current recovery key with
`signer: "recovery"` (the reserved name; no device id may equal it):

```json
{"type":"atem-membership-entry","v":1,"account_id":"acct-test-1","genesis_hash":"…",
 "seq":7,"prev_hash":"<Atem's head>","action":"recovery_add","signer":"recovery",
 "signed_at":1793177600000,
 "member":{"device_id":"dev-newmac","kind":"native","auth_key":{"alg":"p256","pub":"…"},
           "enc_key":{"alg":"x25519","pub":"…"},"roles":["control","manage","view"]}}
```

It uses the same `member` object as `add` (one key representation,
Astation review 3). Rules: `member.kind` native, roles exactly
`["control","manage","view"]`, a new `device_id` (reserved from then on,
even if the entry is cancelled); it chains from the head like any entry
and is carried like any suffix. The recovery signer can't sign any other
action: it never removes a device, moves a head back, bypasses a fence or
lifts a freeze; a frozen host applies nothing. Old devices stay members
until a manager removes them. A conflicting entry signed by the recovery
key freezes (R9.4).

**Kit replacement.** A manager replaces the kit with `set_recovery_key`:

```json
{"body":{"type":"atem-membership-entry","v":1,"account_id":"acct-test-1","genesis_hash":"…",
         "seq":7,"prev_hash":"…","action":"set_recovery_key","signer":"dev-phone",
         "signed_at":1793177600000,"kit":"current",
         "recovery_key":{"alg":"ed25519","pub":"<the new kit's public key>"}},
 "sig":"<the manager's auth_key>","kit_sig":"<the current recovery key>"}
```

- `kit: "current"`: `kit_sig` = Ed25519 by the **current** recovery key
  over `enc(["atem-recovery-cosign-v1", jcs(body)])`. Like `sig` it is
  outside the body and not hashed; the body names the mode, so stripping
  `kit_sig` makes the entry invalid (`kit_sig_missing`), never a
  different entry. In effect as soon as a host applies it.
- `kit: "lost"`: no `kit_sig`. The client requires a fresh owner
  confirmation (R9.6 rule 4). Pending like a `recovery_add`, with the
  same wait, approve and veto rules.
- With no manager and no kit, there is no entry to sign: re-pair each
  host (`atem unpair`, `atem pair`, a new genesis).

The new key must never have appeared in this log. Once a replacement is
in effect on a host, the replaced key goes on `retired_recovery_keys`
and never signs again there: a `recovery_add` or `kit_sig` by it is
invalid (`recovery_key_retired`), and every entry still pending that it
signed is cancelled (reason `kit_replaced`).

**Decisions.** `recovery_approve{target}` and `recovery_veto{target}`
are ordinary entries signed by a manager (fresh owner confirmation,
R9.6). `target` is the `entry_hash` of a `recovery_add` or a
`kit: "lost"` `set_recovery_key` in the chain before it, otherwise
invalid (`not_a_recovery_entry`). An approval's signer must differ from
the target's signer (`self_approval`); a veto may come from any manager,
the target's signer included. A removed manager signs nothing, so its
approval or veto is invalid (`signer_not_manager`) and changes nothing.
A decision is valid whatever its target's state; it acts only while the
target is pending on the host applying it.

**State machine** (per host, per pending-type entry `P`; every verifier
runs it on its own clock, the host's being the one that grants access):

| state | entered when | effect |
|---|---|---|
| `pending` | the commit that appends `P` to `membership.json` (the host's **first sight**) | the subject gets no access (below); entries that depend on `P` are deferred |
| `active` | the first of: a `recovery_approve` of `P` applied in chain order; the wait ends with `P` still pending | `recovery_add`: the member becomes a manager; `set_recovery_key`: the key replaces the current one |
| `cancelled` | a `recovery_veto` of `P` applied in chain order while `P` is pending; or, for an entry signed by a recovery key, that key's replacement taking effect | final: the subject never becomes a member; an entry signed by it, or by the cancelled key, is invalid |

Precedence: whichever of approve, veto or the end of the wait the host
applies first wins; decisions apply in chain order; anything after that
is a valid entry with no effect (a late veto leaves the device a
manager, and a manager removes it with `remove`). Activation and
cancellation add no entry. Neither raises a fence (nothing was granted);
each is written to `membership.json` before any effect, then announced
in `membership_head` (R9.3).

**Timing (host clock only).** The wait is 86 400 000 ms and ends when
**both** have elapsed since first sight: the monotonic time
(`CLOCK_MONOTONIC`, the same clock as §3's deadlines) and the wall time
(`first_seen_wall + 86 400 000`). No timestamp inside an entry counts:
`signed_at` is display only, so a backdated or relay-delayed entry still
waits 24 h from when this host first saw it. `mono_waited_ms` is
persisted at least once a minute and at shutdown; after a runtime
restart within one boot the monotonic clock continues from
`mono_at_first_seen_ns`; after a reboot (another `boot_id`) it continues
from `mono_waited_ms`, so time while the machine was off or the clock
was unreadable never counts. A forward wall-clock jump can't end the
wait (the monotonic side hasn't elapsed); a backward one delays it.
`effective_at` (shown in `welcome`) = `now_wall + max(86 400 000 −
mono_waited, first_seen_wall + 86 400 000 − now_wall)`; it is an
estimate on the host's clock, recomputed on every report. The 100 ms
`advance` pass checks the wait; while an entry is pending the host also
asks the relay over its link for the suffix after its head every 15
minutes and 5 minutes before `effective_at` (a fetch never delays
activation: a relay that fails it gains nothing).

**During the wait the subject has no access** (not even `view`): a
`hello` by it, or by a device added only by an entry deferred behind it,
gets `recovery_pending{entry_hash, effective_at}`. An entry it signs is
**deferred**: the carriage stops before it without an error, the
carrier is admitted, and the entry is carried again after the wait. The
subject's client signs nothing until the chain it verified holds an
approval of `P`, or 24 h passed on its own clock since it first saw `P`
committed; the relay applies the same rule on its clock as a
convenience. Later entries, removals included, wait behind a deferred
entry, at most until the wait ends on this host; that happens only on a
host that first saw `P` well after the devices did. A `recovery_add` or `kit_sig` that verifies only with the
key of a pending `set_recovery_key` is deferred the same way.

**Relay suppression resistance.**

- Pending entries and their decisions are log entries carried like any
  suffix (R9.3); every carrier, and the host's own fetch, can deliver
  them.
- Every host lists what is pending in its `welcome`
  (`pending_recovery`, R9.8: `entry_hash`, `seq`, `action`, `subject` —
  the member for `recovery_add`, the requesting manager for
  `set_recovery_key` — and `effective_at` on the host's clock),
  authenticated by the channel (`sig_h` covers the transcript the record
  keys derive from). Any device that reaches any host learns of it even
  if every push and every relay fetch was dropped; clients show it
  ("Recovery of <device> pending, takes effect <time>: approve or
  cancel").
- The host shows it locally: `atem status` and the agent terminal's
  status row show that a recovery is pending (exact text is an
  implementation detail), cleared when nothing is pending.
- A veto can arrive by any route, including a direct LAN connection to
  :8080, before the relay has it (R9.4 rule 2's exception; the conflict
  rows of R9.4 settle a veto the relay ordered differently).
- **Residual risk:** a relay that blocks every device from every host
  for the whole 24 h, while nobody looks at a host's screen, lets a kit
  holder's enrollment take effect. That is indistinguishable from the
  genuine all-devices-lost case the wait exists for, and only a holder
  of the current kit can create the entry. A host that never reaches
  the relay and is never connected to also can't be warned; a host
  powered off waits longer, never shorter.

**Recovery Kit v2 and K** (Astation owns the kit, its UI and storage;
the formats are shared so `atem-client` can implement them once). The
kit holds one 256-bit secret `R`, the `account_id`, the account's
**`genesis_hash`**, a `kit_tag` binding the three, and the relay URL;
its text encoding is Astation's. **The printed kit format changes**
(Astation r4 review 1): it now also carries the 32-byte genesis hash
and the 16-byte tag.

```
sign_seed    = HKDF-SHA256(salt = empty, ikm = R, info = "atem-recovery-sign-v1", L = 32)  -> Ed25519 key
recovery_key = public key of sign_seed            (in genesis, or in set_recovery_key)
kit X25519   = secret SHA-512(sign_seed)[0..32] (X25519 clamps it); public = Montgomery form of recovery_key
tag_key      = HKDF-SHA256(salt = empty, ikm = R, info = "atem-recovery-kit-tag-v1", L = 32)
kit_tag      = HMAC-SHA256(tag_key, enc(["atem-recovery-kit-v2", account_id, genesis_hash(32 bytes)]))[0..16]
```

**The genesis anchor.** The log, its hosts and its backups come from the
relay; the kit is the one thing the user kept apart from it. Anyone can
seal to a kit's public key (HPKE base mode), so a relay could copy it
into a genesis of its own, with its own manager and host, and seal a
`K` of its choosing: every signature in that chain verifies and the
envelope opens with the real kit. Only the kit's `genesis_hash` tells
the two apart. What it binds to:

- **At account setup:** Astation generates `R`, derives `recovery_key`,
  builds and signs the genesis naming it, and commits it at the relay;
  the kit is made from that genesis's `entry_hash` and shown to the
  user only then.
- **At replacement** (`set_recovery_key`, either `kit` mode): the new kit
  is bound to the genesis the entry names in its `genesis_hash` (every
  entry names its log's genesis, so it is the same genesis as the
  replaced kit's). It is made when the entry is prepared and shown once
  the entry commits.
- A kit never moves to another genesis: a new list (re-pairing from
  scratch) gets a new kit, and an old kit restores nothing in it.

Hosts pin their genesis at pairing (R9.2) and devices at enrollment, so
only the restore needed this anchor.

The kit's X25519 public key is computed from `recovery_key` alone
(`u = (1 + y) / (1 − y) mod 2^255 − 19`, as libsodium's
`crypto_sign_ed25519_pk_to_curve25519`), so any device holding the
verified log can seal to the current kit and only a holder of `R` can
open (Astation r3 review 3). `atem-recovery-seal-v1` and the symmetric
`atem-k-backup-v1` of the first r9 draft are withdrawn.

**The K backup, `atem-k-backup-v2`.** A signing seed can't restore an
independently generated `K` (Astation review 3), so `K` is backed up,
sealed to the kit, in an envelope the relay stores per log:

```json
{"v":2,"account_id":"acct-test-1","genesis_hash":"…","blob_version":3,
 "kids":["b982533d","1f2e3d4c"],"recovery_key":{"alg":"ed25519","pub":"<b64u>"},
 "enc":"<b64u>","ct":"<b64u>"}
```

RFC 9180 base mode, the suite of R9.9 (DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, ChaCha20-Poly1305), to the kit's X25519 public key, `info
= enc(["atem-k-backup-v2", account_id, genesis_hash(32 bytes),
u64(blob_version), jcs(kids), recovery_key.pub(32 bytes)])`, empty AAD,
plaintext `jcs({"keys":[{"k":"<b64u 32>","kid":"…"},…]})`: the current
key first, then retained previous generations newest first (1–8 keys;
`kids` lists the same kids in the same order: a sequence, R9.2, never
sorted). Opening it authenticates the account,
genesis, version, kids and kit (any change fails the tag). `backup_hash =
hex(SHA-256(enc(["atem-k-backup-hash-v1", jcs(envelope)])))`.

**The version floor is in the log** (Astation r3 review 3). Each backup
is recorded by a `k_backup` entry, signed by the manager that sealed it:

```json
{"…":"common fields","action":"k_backup","signer":"dev-mac",
 "k_backup":{"blob_version":4,"kids":["7a3c9e10","b982533d","1f2e3d4c"],
             "recovery_key":{"alg":"ed25519","pub":"…"},"backup_hash":"<hex>"}}
```

Rules: `blob_version` greater than every earlier `k_backup` in the
chain (`blob_version_not_increasing`); `recovery_key` is the current
recovery key or that of a pending `set_recovery_key`. Hosts verify it
like any entry, keep the newest record, and never fetch or open a
backup. The relay stores envelopes keyed by `(genesis_hash,
blob_version)`, put-if-absent (the same bytes again: `200`; other bytes:
`409 {max_occupied}`, the highest version it holds for that log), and
keeps those named by the two newest `k_backup` entries of
each recovery key; an envelope no entry names is garbage after an hour.

**Committed and occupied versions** (Astation r4 review 3). A version
is **committed** only when a `k_backup` entry in the verified log names
it (with its `backup_hash`). A version the relay holds that no entry
names is **occupied but uncommitted**: the leftover of a writer that
crashed before its CAS, lost a race, or gave up. It is superseded by any
higher version, collected by the relay after an hour, and never fetched,
opened or trusted by a restore (a restore opens only the version the
newest `k_backup` names, checked against its `backup_hash`). Versions
may skip; the log only requires them to increase.

**Writing a backup** (rotation, a changed retained set, a new kit):

1. **Allocate:** `blob_version` = 1 + the highest of: the newest
   committed version in its verified log, every version it uploaded
   itself (kept durably until committed or discarded), and the
   `max_occupied` of the last `409` it got for this log.
2. **Seal** (any manager with the `K` set; no `R` needed) and store
   durably the envelope bytes, its version and the prepared entry body
   (R9.4 rule 1).
3. **Upload** (put-if-absent). `200`: stored (or the same bytes were
   already there). `409 {max_occupied}`: other bytes hold that version.
   Discard the envelope durably; if the newest committed backup already
   covers this `K` set and the current kit, stop; else go back to 1,
   which now allocates above `max_occupied`. Each `409` therefore moves
   the next attempt strictly higher, so repeated collisions make
   progress. A `max_occupied` more than 1024 above the newest committed
   version is relay misbehaviour: stop and report it (availability only;
   a relay can always refuse to store).
4. **Publish** the `k_backup` entry with the log CAS (R9.4). Only after
   the relay commits it may any device use a new `K` (Astation's
   rotation rule, now checkable: "before first use" means "recorded in
   the log").
5. **`409` on the entry** (the log moved): verify and apply the returned
   entries, then:
   - a `k_backup` naming a version ≥ ours was committed: ours can never
     be named. Discard both durably; if the newest committed backup
     covers this `K` set and the current kit, stop; else go back to 1.
   - otherwise (an unrelated entry won the `seq`, e.g. an `add`): keep
     the uploaded envelope, whose bytes bind account, genesis, version,
     kids and kit but not the head, and rebuild only the entry on the
     new head (R9.4 rule 3), provided the kit it names is still current
     or pending; if not, discard both and go back to 1 for the current
     kit.
6. **Interrupted** (crash, timeout): resend the stored bytes in order,
   the upload (idempotent) and then the entry (CAS). A `409` on the
   resent upload means the relay collected the envelope and another
   writer took the version: step 3.

Two managers rotating at once therefore serialize on the log; the
loser's envelope is never named and is collected.

**Restore** (Astation's restore-account flow on a new device; Astation
r4 review 1, user decision of 2026-10-19 "no recovery on a stale
head"):

1. **Read the kit.** Check `kit_tag` (a mismatch: "this Recovery Kit is
   damaged or mistyped", nothing is fetched). The kit's `account_id`
   and `genesis_hash` are the anchor; derive `sign_seed`,
   `recovery_key` and the kit X25519 secret from `R`.
2. **Fetch and anchor the log.** Fetch the log stored under the kit's
   `genesis_hash`. Its entry 1 must be a genesis whose `entry_hash`
   equals the kit's `genesis_hash` and whose `account_id` equals the
   kit's (`genesis_mismatch`; a substitute genesis that reuses this
   kit's public key is refused here, whatever else verifies). Verify
   the chain from that genesis; every host key, manager and backup used
   below comes from it.
3. **Confirm the head.** Send `init` to each host the chain names, over
   any route that answers (relay channel, Astation link, direct :8080 on
   the LAN; `init` needs no membership); each `accept` carries a head
   signed by that host's key **as the anchored chain records it**. At
   least one is needed. A log that doesn't reach the highest such head
   with the same hash is refused (`log_behind_host`: the relay rolled
   it back; retry another route). In r9 a host-signed head is the only
   proof of freshness. **No host answers → the restore waits**
   (`withheld`): nothing is stored as current, nothing is signed or
   published, and the device tells the user why ("Recovery needs to
   reach one of your Atem hosts (<names>) to confirm the device list is
   current. Turn one on or join its network; recovery then continues by
   itself."). It retries; it never falls back to an unconfirmed head.
4. Refuse unless the derived `recovery_key` is the current one in that
   log (`kit_not_current`: "this Recovery Kit was replaced").
5. Take the newest `k_backup` naming this kit; fetch that version's
   envelope; refuse unless its `backup_hash` matches
   (`backup_hash_mismatch`: an older authentic backup, or an
   uncommitted one, is caught here) and it opens with `info` for the
   kit's account and genesis (`backup_invalid`). This authenticates the
   account and genesis through the backup **before** anything is
   appended. Any failure is "this kit doesn't match the account, or the
   backup is damaged" and never creates a new `K` or a new trust root.
6. Store the `K` set durably, then sign and publish the `recovery_add`
   on the confirmed head (prepared durably, R9.4 rules 1–4, so an
   interrupted restore retries the same entry), and show that it takes
   effect after the wait unless another device approves it. On a `409`
   the device verifies the returned entries (they extend the confirmed
   head), repeats steps 4–5 on the new head, and rebuilds the entry
   there.

**No recovery on a stale head** (user decision of 2026-10-19, option
A). The first r9 draft let a restore with no host reachable publish an
unconfirmed `recovery_add`, at the price of freezing every host whose
head was newer. That fallback is removed: a `recovery_add` is only
built on a head that reaches every host-signed head the device
obtained, so recovery never intentionally forces a freeze or a
re-pair. A host the device couldn't reach that holds a newer head than
the relay showed can only exist if the relay hid entries from the
device; that host then freezes on the `recovery_add` like any relay CAS
failure (R9.4), which is the relay's doing, not the recovery's.

**A new kit.** After its `set_recovery_key` commits, the replacing
device seals the retained keys to the new kit at the next version and
records it with `k_backup` (steps above). `kit: "current"`: the old
kit's envelopes then fall out of the newest two and are deleted.
`kit: "lost"`: both kits keep their newest envelope until the
replacement takes effect (Astation decides by the chain: an approval,
or 24 h on its clock with no veto) or is vetoed. After a `kit: "lost"`
replacement Astation also rotates `K` (`../e2e-encryption.md`
rotation), because whoever holds the lost kit could already have opened
every envelope sealed to it; deleting them stops only later downloads.
Atem never sees `K` from a backup, `R`, the kit's secret or an
envelope.

Vectors: `r9-vectors-recovery` (kit 1's derivations and X25519 form;
its `kit` binding (`account_id`, `genesis_hash`, `kit_tag`) and
`kit_2.kit`; `k_backup_bad_ct` (named by `KB8_badct`, fails to open);
`substitute_chain`, the refused substitute genesis with its
backup sealed to kit 1; `k_backup` (version 3) and `k_backup_rotated` (version 4, after a
rotation to `K-gen-3`) sealed to kit 1; `kit_2` and its
`k_backup_resealed`; each with `info`, `ikmE` and `backup_hash`), the
entries in `r9-vectors-membership-log` (`R7`, `R7_backdated`, `A8`,
`V8`, `A8_ipad`, `V8_ipad`, `N8`, `K7_current` with its `kit_sig`,
`K7_current_no_kit_sig`, `R8_oldkit`, `R8_newkit`, `K7_lost`, `V8_k`,
`A8_k_self`, `R8_oldkit_after_lost`, `KB7`, `KB8`, `KB8_stale`, `KB8_badct`, and the
substitute chain `SUB1`–`SUB3`) and the kits in `r9-vectors-keys`
(`recovery`, `recovery-2`, `K-gen-3`, `host-evil`, `K-evil`).

### R9.6 Principals, scope, expiry, keys

| kind | proof | principal | permissions |
|---|---|---|---|
| `native` | member of kind `native` at Atem's head; `sig_c` by its `auth_key` | `member:<device_id>` | `view`; `control` if in its roles (`manage` gives the host nothing) |
| `service` | member of kind `service`, not expired, host in `scope.hosts`; `sig_c` by its `auth_key` | `service:<device_id>` | `view`; `control` if `scope.ops` has any of `prompt`, `interrupt`, `stop`, `terminal`, `approval`, `rule_revoke`; each op checked separately |
| `browser` | grant (below) whose issuer is a native member with `control` at Atem's head; `sig_c` by the grant's `browser_key` | `browser:<grant_id>` (issuer recorded) | `view`; `control` if the grant's `ops` have a control op; never more than the issuer |
| `host` | newest `add_host` of `host_id`; `sig_h` | — (never a client) | — |

Each principal has its own §H `control_gen`; `attachment_gen` and
`controller_session` stay per attachment.

**Ops** (service `scope.ops`, grant `ops`; sets, R9.2): `view` (registry,
chat open/history, terminal subscribe, `receipt_query`; always
required), `prompt` (prompt submits, with or without §F acquire),
`interrupt`, `stop`, `terminal` (terminal input/resize), `approval`
(§G answers), `rule_revoke`. Lease ops (`acquire`/`renew`/`release`)
need one of `prompt`, `interrupt`, `stop`, `terminal`. A request outside
the ops is `forbidden`.

**Service scope:** `{"hosts":[host_id] (1–16), "projects"?:["h1.<kid>.<64
hex>"] (≤ 64; memory sync's keyed project hash), "sessions"?:["ses-…"] (≤ 64), "ops":[…]}`; an absent list
doesn't restrict. A session is in scope when its host is listed, and its
launch project hash is listed (when `projects` is present) and its id is
listed (when `sessions` is present). The project key is taken from the
session's launch working directory at launch and recorded with the
session; Atem compares `h1.<kid>.` hashes of it under the `kid` each
scope entry names (any retained `K` generation, computed by the cred
agent, so a locked agent leaves the comparison pending and the session
out of scope until the first unlock); a later `cd` never moves a session
into scope. Out-of-scope
sessions are `unknown_session` in registry, chat, terminal and receipts
alike. Services never sign entries, never issue grants, never hold
`manage`; approvals only with `approval` in `ops`.

**Browser grant** (signed by the issuer's `auth_key`):

```json
{"type":"atem-browser-grant","v":1,"grant_id":"<uuid>","account_id":"…","genesis_hash":"…",
 "issuer":"dev-phone","browser_key":{"alg":"p256","pub":"…"},
 "target":{"host_id":"host-a","host_trust_gen":1,"session_id?":"ses-…"},
 "ops":["view"],"issued_at":1793264400000,"expires_at":1793268000000}
```

`grant_hash = SHA-256(enc(["atem-browser-grant-hash-v1", jcs(body)]))`.
Rules: `expires_at − issued_at` ≤ 3 600 000; ops default `["view"]`;
non-transitive (a browser never issues); the browser key is a
non-extractable WebCrypto P-256 key. Fenced when the issuer is removed
or loses `control`, at expiry, or by `revoke_grant{grant_id}` (a session
op from the issuer or any member with `control`; Atem journals revoked
ids until their expiry, ≤ 256). Vectors: `r9-vectors-browser-grant`.

**Time rules for authority** (the only ones; native members never
expire, they are removed): service `expires_at` and grant `expires_at`
are checked against Atem's wall clock at admission (`now <
expires_at`), with a grant's `issued_at` ≤ `now + 300 000`; while
attached, a timer fences the principal at expiry (wall and monotonic,
whichever first, as §3's authorization deadline). `welcome.
authorization_ms_left` = min(expiry − now, the channel's remaining
lifetime). A browser principal with no attachment, lease or unfinished
request may be dropped from the journal (only browser principals are
dropped; every other principal keeps §H's `control_gen`); one that attaches again with a
still-valid grant starts at `control_gen` 1, since nothing refers to the
old value and revocation, issuer fencing and expiry are checked at
admission.

**Keys and owner confirmation — requirements on clients** (Atem can't
observe them; the shared core exposes signing as an effect):

1. A native `auth_key` is non-exportable (Secure Enclave, Android
   Keystore/StrongBox, WebCrypto non-extractable); no software copy of a
   manager key exists. Astation's is its ceremony P-256 identity (the
   key it verifies with, `astation_sign_pub`); Astation supplies the
   fresh / 5-minute owner-auth adapter and clears reuse on lock and
   background (Astation r3 answer).
2. A manager's key requires owner authentication (biometrics, with the
   OS passcode/password fallback where the platform offers one).
3. Routine channel signing (`sig_c`) may reuse one owner confirmation for
   at most 5 minutes, cleared when the device locks or the app goes to
   the background.
4. Entry signing (`add`, `remove`, `set_roles`, `add_host`,
   `remove_host`, enrollment approval, `recovery_approve`,
   `recovery_veto`, `set_recovery_key` of either kind) and recovery need
   a **fresh**
   confirmation bound to the exact body shown (account, head and `seq`,
   applicant keys, roles, scope, expiry); a confirmation never covers a
   changed body (R9.4 rule 3) and is never given in the background or a
   notification extension.
5. Services hold a software key in their own secret store; their
   enrollment shows what they may do and that output posted to a third
   party (Discord) is disclosed to it.

### R9.7 Channel `atem-ch1`

One suite, no negotiation, no rekeying, no resumption, no 0-RTT. Every
connection is a full handshake and a new attachment (no lease is
carried, §3). Transport messages are JSON text frames, identical over
the relay and Astation's :8080, each carried in the channel envelope of
R9.7a on Atem's one outbound link:

| # | dir | message |
|---|---|---|
| 1 | C→H | `{"ch":"atem-ch1","op":"init","e":"<b64u e_c>","n":"<b64u n_c>","genesis_hash":"<hex>","host_id":"…","host_trust_gen":1}` |
| 2 | H→C | `{"ch":"atem-ch1","op":"accept","e":"<b64u e_h>","n":"<b64u n_h>","head":{"seq":6,"hash":"<hex>"},"sig":"<b64u sig_h>"}` |
| 3 | C→H | `{"ch":"atem-ch1","op":"finish","ct":"<b64u>"}` (the `hello`) |
| 4… | both | `{"ch":"atem-ch1","op":"rec","ct":"<b64u>"}` |
| — | either, before 4 | `{"ch":"atem-ch1","op":"error","code":"…"}`, then close |

`e_*` are fresh X25519 public keys, `n_*` 32 random bytes, per
connection. **Everything the keys depend on is cleartext** and bound
into the transcript before any key is derived (Astation review 1): the
host's head is public in `accept` and covered by `sig_h`; no key depends
on encrypted data. The head reveals nothing the relay doesn't store.

Step by step (`H` = SHA-256, `‖` never used: every input is `enc`):

1. Client: refuses unless `host_id` has an `add_host` in its verified log
   with exactly `host_trust_gen` and it is the newest for that host.
2. Host, on `init`: `genesis_hash`, `host_id`, `host_trust_gen` must be
   its own (else `stale_target`); frozen → `account_frozen`; then
   ```
   th2 = H(enc(["atem-ch1-th2", e_c, n_c, genesis_hash, host_id,
                u64(host_trust_gen), e_h, n_h, u64(head.seq), head.hash]))
   sig_h = Sign_ed25519(host_channel_key, enc(["atem-ch1-host-sig-v1", th2]))
   ```
3. Client, on `accept`: recomputes `th2` from what it sent and received,
   verifies `sig_h` with the host key from step 1 (`handshake_failed`
   otherwise: a rewritten head, nonce or key fails here). If it holds an
   entry at `head.seq` with another hash it has a divergence and builds
   its window (R9.3); a head beyond its own is not an error.
4. Both: `ss = X25519(e_own, e_peer)`; **an all-zero `ss` is refused**
   (`handshake_failed`) before any HKDF.
   ```
   hs    = HKDF-Extract(salt = th2, ikm = ss)
   k_fin = HKDF-Expand(hs, enc(["atem-ch1 finish c2h", th2]), 32)
   ```
5. Client:
   ```
   th3   = H(enc(["atem-ch1-th3", th2, sig_h, jcs(principal), grant_hash or empty]))
   sig_c = Sign(auth_key or browser_key, enc(["atem-ch1-client-sig-v1", th3]))
   finish.ct = ChaCha20-Poly1305(k_fin, nonce = 12 zero bytes,
                                 aad = enc(["atem-ch1-finish", th2]), hello bytes)
   ```
   `principal` is `{"kind":"native"|"service","device_id":…}` or
   `{"kind":"browser","grant_id":…}`; `grant_hash` (R9.6) only for a
   browser. The `hello` (R9.8) carries `principal`, `sig_c`, the
   carriage and the grant.
6. Host: opens `finish` (failure → `handshake_failed`); applies the
   carriage (R9.3) **before** judging the sender; resolves the principal
   against the committed head (R9.6; `unauthorized` if not a current
   member/valid grant); verifies `sig_c` (`handshake_failed`).
7. Both:
   ```
   th4   = H(enc(["atem-ch1-th4", th3, sig_c, H(hello bytes)]))
   k_c2h = HKDF-Expand(hs, enc(["atem-ch1 ap c2h", th4]), 32)
   k_h2c = HKDF-Expand(hs, enc(["atem-ch1 ap h2c", th4]), 32)
   channel_id = hex(th4[0..16])
   ```
   `e_*` secrets, `ss`, `hs` and `k_fin` are wiped. The host's first
   record is `welcome` or a session `error` (then close): it confirms
   the host derived `th4`.

**Records.** One session-family message (session, terminal, agentChat)
per record, plaintext ≤ 1 MiB. `ct = ChaCha20-Poly1305(k_dir, nonce = 4
zero bytes ‖ u64 counter, aad = enc(["atem-ch1-rec", dir]), plain)` with
`dir` `"c2h"` or `"h2c"`, counters from 0 per direction. The transport
is ordered, so the receiver demands exactly its next counter: a gap, a
replay, a failed tag or a record in the wrong direction closes the
channel without a reply and wipes its keys.

**Limits** (a new channel is required before any is reached; the side
that reaches one first sends nothing more and closes; the client
reconnects, a new attachment): 2^32 records or 2^36 plaintext bytes per
direction; lifetime 24 h for native principals, on the monotonic clock
only (a key-rotation bound: native members never expire, so a suspend
doesn't end it, removal from the device list does at once; it still
counts in `welcome.authorization_ms_left`), the expiry for
service/browser (wall and monotonic, "Time rules for authority");
`accept` within 10 s of `init`, `finish` within 10 s of `accept`, else
closed. The host keeps no state for an `init` beyond its
ephemeral key and answers at most one `init` a second per transport.

**Errors.** Before `finish` opens they are clear, then close:
`handshake_failed` (malformed, bad `sig_h` at the client, zero `ss`, a
failed `finish` tag, timeout), `stale_target` (another account, host or
trust generation), `account_frozen`, `busy` (rate). Once `finish` opens,
the host can derive `th4` whatever `sig_c` is worth, so every refusal is
its first record, a session `error` under `k_h2c`, then close:
`handshake_failed` (bad `sig_c`), `unauthorized`, `membership_invalid`,
`membership_incomplete`, `recovery_pending`, `unsupported_version`,
`account_frozen`, `busy`. Only the sender of `finish` can read it; what
it reveals (the head, whether a device id is a member) is in the relay's
copy of the log anyway. A clear (pre-`finish`) error is unauthenticated:
clients treat it as advisory, a reason to retry or show a diagnostic,
never as authority to repin a host, change a log or persist a freeze
(Astation r3 answer); only a host-signed `accept` head or an encrypted
first record carries host authority.

**Replay.** A replayed `init` gets a fresh `accept`; a replayed `finish`
fails its tag (fresh `e_h`, `n_h` give another `k_fin`); a replayed or
reordered record fails its counter. Relay visibility: routing ids,
`genesis_hash`, the host's head, ephemerals, nonces, sizes and timing;
never the client's identity, messages, approvals or chat.

Vectors: `r9-vectors-channel-handshake` (every intermediate value, the
first records, and the negative cases: tampered head, tampered finish,
replayed finish, replayed record, direction confusion, zero shared
secret).

### R9.7a Channel envelope (routing on Atem's link)

Atem is outbound-only (user decision, 2026-10-20): it opens no listening
port. Every r9 client (the Mac's own Astation included) reaches it over
Atem's one existing outbound link: the relay room (`role=atem`) or
Astation's local :8080. The router (the relay, or Astation on :8080)
wraps each client's `atem-ch1` frames (R9.7) in an envelope that names a
routing handle, so several clients share the link. Agreed with Astation
(#81 6287955132, PR #80 6287954583); fixtures `r9-envelope-*`.

| event | dir | message |
|---|---|---|
| `open` | router → Atem | `{"type":"channel","event":"open","channel":"<h>","transport":"relay"\|"direct"}` |
| `frame` | both | `{"type":"channel","event":"frame","channel":"<h>","frame":{<one atem-ch1 frame, R9.7>}}` |
| `close` | both | `{"type":"channel","event":"close","channel":"<h>","reason"?:"<code>"}` |

**Fields.** Exactly these fields per event (I-JSON, `parse_strict`, no
other field: `open` carries no client address, device identity, roles
or other metadata; routing hints never grant membership, host identity
or authorization). `channel` (the handle): 1–64 characters of
`[A-Za-z0-9_-]`, assigned by the router. `transport` is the router's
label (`relay` for the relay room, `direct` for :8080); Atem logs it and
never trusts it. `reason`: 1–32 characters of `[a-z_]`. `frame` is the
`atem-ch1` frame object itself (not a string). Non-compact JSON is
accepted; every bound below applies to the bytes as received.

**Scope of a handle.** A handle is valid only within one generation of
Atem's link (one authenticated WebSocket connection): Atem keys channels
by (link generation, handle). The router never reuses a handle while
that link lives; a stale handle, or a delayed callback of an earlier
link, never binds to a channel of a new link. The handle is a routing
id only, distinct from the cryptographic `channel_id = hex(th4[0..16])`
(R9.7); neither stands in for the other, and authentication is entirely
`atem-ch1` (R9.7) and the principal checks (R9.6).

**Lifecycle.**

1. `open` comes before the channel's first `frame`; each direction is
   delivered in order per channel (a gap or reorder fails the `atem-ch1`
   counter and closes that channel only).
2. A duplicate `open` of a live handle is ignored: it never replaces the
   live handshake, keys or attachment.
3. A `frame` for a handle Atem doesn't hold (never opened, closed, or of
   an earlier link) is answered with one `close{reason:"unknown_channel"}`
   for that handle per link generation (Atem remembers at most 1024 such
   handles per link and sends at most 16 such closes a second; beyond
   either it drops the frame and counts it in runtime.log). No reply ever
   answers a `close`: a `close` from either side ends the channel at once,
   a repeated or unknown `close` is ignored, so no close loops.
4. Atem's `close` ends a client's channel (after its last record, e.g. a
   refusal or a fence); the router's `close` reports that the client
   went away. Either one fences that channel's attachment (§3: no lease
   is carried) and releases only that channel: every other channel and
   attachment on the link stays.
5. Any failure of one channel (malformed envelope or frame, a failed
   tag, replay or reorder, an exceeded bound, a handshake timeout)
   closes that channel only.
6. **Link loss closes every channel** on it and fences their
   attachments. When Atem ends every channel while its socket stays up
   (its device list was pinned again or removed, or the link is
   re-authenticated, a new generation), it first sends `close{closed}`
   for each live handle. A reconnect is a new link generation: clients open new
   channels, run full handshakes and catch up authoritatively (`sessions`
   snapshot, history pages, `receipt_query`); no lease is restored and
   no prompt is replayed.
7. Dispatch order on Atem: an incoming message whose `type` is
   `channel` is demultiplexed before any other handling of the link's
   messages. Once a device list exists (R9.3), r8 admission is refused
   (`hello` → `unsupported_version`, `revision: 9`): neither the link
   itself nor routing possession bypasses r9 admission.

**Bounds** (each exceeded bound closes the channel, or refuses a new
one, with a `close` naming the reason; records are never silently
dropped and queues never grow without bound):

| bound | value | exceeded |
|---|---|---|
| record plaintext (R9.7) | 1 048 576 bytes | the sender refuses it locally; a peer past it fails the channel |
| inner frame (compact) | a `ct` of at most 1 398 123 base64url characters (1 MiB + the 16-byte tag): the largest legal `rec` is 1 398 159 bytes, the largest `finish` 1 398 162 | `close{reason:"too_large"}` |
| envelope as received | 2 097 152 bytes (2 MiB); the largest legal record with a 64-character handle is 1 398 279 bytes compact | `close{reason:"too_large"}` when its first 4 KiB name its top-level `type` `channel` and `channel` (before `frame`; the message is never parsed), else dropped and logged |
| open channels per link | 64 | the new channel: `close{reason:"busy"}` |
| handshakes in progress per link (opened, not yet welcomed) | 16 | the new channel: `close{reason:"busy"}` |
| bytes queued from Atem per channel (not yet taken by the link) | 4 MiB | that channel: `close{reason:"busy"}` |
| `close`s Atem queues outside any channel (refused `open`s, `unknown_channel`, and envelopes refused unread: `busy` when the broker's inbox is full, `too_large` over the envelope bound) | 1024 queued, 16 a second together, on one clock | dropped and counted in runtime.log |
| `init`s per link (R9.7 "per transport") | 1 a second | clear `busy` error frame, then `close{reason:"busy"}` |

**Overload.** When the link takes nothing (its writer is backed up), Atem
keeps only what the bounds above allow: each channel's queue (4 MiB, then
that channel is closed `busy`) and the closes queued outside a channel
(1024; more are dropped and counted, never queued). When the link takes
again, the queued closes go first, then the channels in turn, one
message per channel per round, each round starting with the channel the
link last refused, so one busy channel can't hold the others back and
none is skipped. Restarting the channels on a live socket (6 above)
keeps the closes already queued and queues a `close{closed}` per live
handle behind them. Each such close holds its channel's slot until the
link takes it: while open channels plus these pending closes number 64, a
new `open` is refused `busy` (a close outside a channel, under its bounds
above), so however many restarts come, at most 64 of them are pending and
at most 1024 + 64 closes are queued in all; none of them is dropped while
the link generation lasts. A new link generation on the same socket hands
the old generation's queued closes to the socket before anything of the
new one; what the socket doesn't take then is dropped and counted (a
handle is scoped to its generation, so a late close could end a new
channel).

**The router enforces the envelope bound.** The router (the relay, or
Astation on :8080) never forwards to Atem an envelope over 2 MiB: a client
frame that would make one is refused at the router and that client's
channel closed there (`too_large`). Atem's link reader takes at most 4 MiB
per WebSocket message (the 2 MiB bound plus a margin); a larger message
ends Atem's **whole link**, every channel on it (each device reconnects),
so a router that forwarded one would cut off every device, not just the
sender. Between 2 and 4 MiB Atem applies the bound itself (the row above).

Atem's `close` reasons: `closed` (Atem ended it: after a refusal or a
fence), `unknown_channel`, `busy`, `too_large`, `malformed`,
`handshake_failed` (a clear handshake error frame was sent first),
`expired` (the channel's lifetime ended, R9.7 "Limits").

**Clients and bindings.** A client implementation holds one
`ClientConnection` (the shared core's per-channel state) per virtual
channel; closing it closes only its channel, never the shared link or
another client's channel (`atem-client-bindings.md`).

### R9.8 r9 hello, welcome and new session ops

| op | dir | fields |
|---|---|---|
| `hello` | C→H (the `finish` plaintext) | `revision: 9` (required), `proof{principal, sig}` (`sig` = `sig_c`, b64u), `membership{head{seq,hash}, entries, more?}`, `grant?` (signed grant, browser only); no `resume` |
| `welcome` | H→C (first record) | r8 fields (`revision: 9`, `features`) plus `principal` (string), `client_kind` (`native`/`service`/`browser`), `permissions`, `scope?` (service/browser: `{ops, sessions?, projects?}`), `head{seq,hash}` (after the carriage), `pending_recovery` (always present, possibly empty: `[{entry_hash, seq, action, subject, effective_at}]`, R9.5), `channel_id`, `authorization_ms_left` |
| `membership` | C→H | `entries` (R9.3) → `membership_head{re, head}` |
| `membership_head` | H→C | `head`, `pending_recovery` (event when Atem's head moves or a pending entry changes state; reply with `re`) |
| `revoke_grant` | C→H | `grant_id` → `grant_revoked{re}` (issuer or a member with `control`) |
| `approval_seen` | C→H | `binding` (read form: target + `attachment_gen`), `approval_id` → `seen{re}` (R9.9) |

- A `hello` without `revision: 9` gets `error{code:"unsupported_version",
  revision: 9}` and nothing else (as §A). Any session message outside a
  channel, or before `welcome`, is refused as before `welcome`.
- `features`: the nine r8 features plus `membership.carry`,
  `push.sealed`, `approval.seen`, `grant.revoke`, `recovery.wait`.
- One principal may have several attachments (a phone and its widget);
  each is fenced separately by `attachment_gen`, together by the
  principal's `control_gen`.

### R9.9 Push hints, seen, and the relay's schedule

Atem never sends tool or summary in clear (the r8 `push_approval` and
`push_resolved` are removed). For each approval Atem sends the relay,
over its link, `{"type":"relay","op":"push_hint","hints":[…]}`: one
**open** envelope per recipient — every native member with `control` at
Atem's head (each has an `enc_key`) — and later one **resolved** hint.

Open envelope (signed by `host_channel_key`):

```json
{"body":{"type":"atem-push-hint","v":1,"state":"open","account_id":"…","genesis_hash":"…",
         "host_id":"host-a","host_trust_gen":1,"approval_id":"<uuid>","session_id":"ses-…",
         "process_gen":"<uuid>","created_at":1793264405000,"expires_at":1793265005000,
         "recipient":{"device_id":"dev-phone","enc_kid":"<16 hex>"},"sealed_hash":"<hex>"},
 "sig":"…","enc":"<b64u>","ct":"<b64u>"}
```

- Sealed part: RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256, ChaCha20-Poly1305 (the suite of `grant.rs`), empty AAD,
  to the recipient's `enc_key`, `info = enc(["atem-push-seal-v1",
  account_id, genesis_hash, host_id, u64(host_trust_gen), approval_id,
  session_id, process_gen, u64(created_at), u64(expires_at), device_id,
  enc_kid])`, plaintext `jcs({"summary":…, "tool":…})` (redacted, §1
  bounds). `sealed_hash = SHA-256(enc([enc, ct]))`; `enc_kid =
  hex(SHA-256(enc(["atem-enc-kid-v1", enc_pub]))[0..8])`. One envelope
  per device (≈ 0.8–1.5 KiB) fits APNs/FCM with the `aps` wrapper.
- Resolved hint: the same identity fields without `recipient`/
  `sealed_hash`, `state: "resolved"`, `reason` (the `approval_closed`
  reason) and `resolved_at`; it must match the open's identity and
  dominates it: once a resolved is accepted, an open for that approval
  is ignored, whatever order they arrive in.
- `created_at` is the approval's creation on Atem's clock and
  `expires_at` = `created_at` + the hook's wait (Claude 600 s, Codex
  300 s); both immutable: retries and reconnects resend the same signed
  bytes.
- **Identity** of a hint or seen: `(account_id, genesis_hash, host_id,
  host_trust_gen, session_id, process_gen, approval_id)`, plus `state`
  and `recipient.device_id` for a hint and `device_id` for a seen. Every
  match, deduplication and suppression below uses the whole identity
  (Astation r3 review 4); an object from another trust generation,
  session or process never matches.

**Verification** (relay and clients; `now` is the verifier's clock):
signature by the newest `add_host` key of `host_id` in its verified log;
account/genesis/host binding; `expires_at > created_at`; `expires_at −
created_at` ≤ 900 000; clients refuse `created_at` > `now + 300 000`
(`skew`); a hint whose `expires_at + 300 000` ≤ `now` is stale (not
shown). Duplicates: identical bytes are idempotent; the same identity
with other bytes is refused and logged (the first stays). A hint never
makes an approval actionable or expired: the client fetches the host's
state over the channel, and shows "may have expired" only from the
host's answer.

**Delivery to the relay is reliable** (Astation r3 review 4). The relay
acknowledges each hint and each seen once it is durably stored
(`{"type":"relay","op":"push_ack","acks":[identity…]}`), in every case:
accepted, idempotent, pending, ignored or refused. Atem keeps every
unacknowledged hint and seen of a live approval in memory and resends
the same bytes every 10 s and at each link reconnect until acknowledged,
the approval closes and its resolved hint is acknowledged, or the
approval's `expires_at + 300 000` passes. A broker restart ends the
approvals (§G) and with them the resends; the relay's own guard (below)
bounds what it still sends.

Every relay message on Atem's link, in either direction, is at most
262 144 bytes (256 KiB) as sent: Atem splits the hints due together over
several `push_hint` messages (one hint, about 0.8–1.5 KiB, always fits),
and the relay splits its acknowledgments over several `push_ack`
messages (about 340 bytes an identity). Atem drops a larger relay
message unread (counted in its log); what it would have acknowledged is
resent and acknowledged again.

What Atem keeps for delivery is bounded, and a bound never cuts a
lifecycle the relay may already hold: once an approval's open hints were
handed to the link, Atem keeps them while the approval is pending, and
its resolved hint until the relay acknowledges it (or `expires_at +
300 000` passes). So, within one runtime and while push isn't
suppressed, every published approval gets its cancellation. The
exceptions, where Atem drops every unacknowledged hint and seen,
published lifecycles included, and sends no resolved hint for them:
push is suppressed (the device list is held, frozen, faulted or failed
to open, §R9.3, or the journal halted, §I); the device list is pinned
again or removed (a re-pin or an unpair: the hints belong to the old
identity); a broker restart (above). In each case the relay's own guard (below) bounds what
it still sends: an open hint whose cancellation never comes can still
escalate to a push until the guard (`expires_at − margin`). To
make room Atem only forgets an approval with nothing left to send, then
one whose opens were never published. When every tracked approval holds
a published lifecycle, a **new** approval gets no push hint at all (Atem
logs it, without content); it is still an approval like any other:
`approval_request` to attached clients with `control`, answerable over
the channel. Atem's bound is at least 64 approvals.

**Clients:** a notification extension that can't use the device's
`enc_key` while the screen is locked shows a generic "Atem on <host>
needs approval" and the app reconnects; there is no separate push key
(Astation r3 answer: the data key keeps its unlocked-device protection);
never plaintext from elsewhere, never a biometric prompt in the
extension.

**Seen.** A client sends `approval_seen` only when the card is rendered
in a focused foreground window and the user was active in the last 60 s
(not for a background delivery, an unopened notification or an
unattended window). Atem checks the attachment has `control`, the
approval is pending for that exact session and process, and it is the
first seen of that device for it (later ones are answered `seen` and
never re-signed; the first one's bytes are what Atem resends until
acknowledged), then signs and sends `{"type":"relay","op":"push_seen","seen":
{body, sig}}`:

```json
{"type":"atem-seen","v":1,"account_id":"…","genesis_hash":"…","host_id":"host-a","host_trust_gen":1,
 "approval_id":"<uuid>","session_id":"ses-…","process_gen":"<uuid>","created_at":1793264405000,
 "device_id":"dev-phone","seen_at":1793264425000}
```

Atem signs a seen only for a device that is a recipient of the
approval's open hints (a native member with `control` at its head). A
service with `approval` (or a browser grant) may send `approval_seen`
under the same checks and is answered `seen`, but nothing is signed or
sent: it is never a hint recipient, so its seen could only wait as
pending at the relay, taking room from real devices' seens (the 256 per
account below). The relay never gets a `push_seen` naming a service or
grant.

Host-signed, so seen needs no manager biometric: the host authenticated
the device over `atem-ch1` at its current head. The relay checks the
signature, then:

- an open with the same identity naming `device_id` as a recipient,
  no resolved yet, and `seen_at` ∈ [`created_at` − 300 000,
  `created_at` + 900 000 + 300 000] → **applied** (suppresses the later
  stages for that approval);
- no matching open yet (seen before open, or the open was lost) →
  **pending**: stored durably (it survives relay restarts and replica
  failover), at most 256 per account (the oldest dropped first), until
  `created_at` + 1 200 000 on the relay's clock; an open that arrives
  later with the same identity applies it at once;
- a resolved already accepted for that identity → **ignored**: a seen
  never reopens, extends or resends anything.

It deduplicates per full identity across replicas (atomic
set-if-absent). Seen never answers, acquires or renews a lease, closes,
or reopens anything.

**Schedule (relay-owned; user decision 2026-10-19; Astation r3 review
2).** Every stage is due at a time derived from the **signed
`created_at`**, never from when a replica received the hint, so delayed
ingress, retries, restarts and failover can't move a deadline. All on
the relay's clock (`now`), with `margin` = 15 000 ms:

- **Skew bound, at first receipt** (separate from delivery): an open
  whose `created_at` differs from `now` by more than 120 000 is refused
  (`skew`), logged, and acknowledged; it is never clamped. The host's
  resolved hint is still accepted (it only cancels; the bound applies to
  opens) and the approval stays answerable over the channel.
- **Immediate stage**, due at `created_at` (in practice at receipt, which
  is later): in-app cards to connected clients; a desktop OS push if no
  desktop Astation is connected; mobile only if the device opted in to
  immediate pushes.
- **Mobile stage**, due at `created_at + 60 000`: a mobile push if no
  resolved and no seen; an optional desktop reminder.
- **Guard:** a provider send happens only at a `now` with `now <
  expires_at − margin`, whatever the clocks. A stage already due when
  the open is accepted (a late receipt) is sent at once if it is still
  before the guard; a stage due at or after the guard is never sent.
- A resolved hint (any answer or closure) cancels every remaining send
  and replaces delivered notifications (collapse id / tag =
  `approval_id`).
- The guard and the margin only stop provider sends: they never label
  the approval expired, shorten the card, or disable a valid answer
  (the card's expiry is the host's).

Vectors: `r9-vectors-push-hint` (two recipients with their HPKE inputs,
resolved, seen, a seen from another `process_gen`, two hints whose
mobile stage lands exactly on the guard (`open_g75`) and 1 ms before it
(`open_g75001`), and the refused cases: skew, `expires_at` ≤
`created_at`, too long, conflicting duplicate).

### R9.10 Several devices at once

Each device is its own principal with its own attachments; r8 decides
everything between them: one lease per session (§5), Send acquire and
confirmed takeover (§F), local input wins, approvals to every attachment
with `control` and first answer wins without the lease (§G), receipts
per request. The Mac is just `member:dev-mac`. With the Mac off, a
phone reaches the host through the relay channel on its own: the host's
key, head and fences don't depend on the Mac or the cred agent. Fixtures:
`r9-multi-device-*`.

### R9.11 Errors (r9 additions)

| code | family | when |
|---|---|---|
| `handshake_failed` | channel (clear, advisory) / session (encrypted first record) | clear before `finish` opens: malformed handshake message, zero shared secret, failed `finish` tag, timeout (a bad `sig_h` is detected by the client, which sends nothing more); encrypted after it opens: a bad `sig_c` (R9.7) |
| `stale_target` | channel (clear) | `init` names another genesis, host id or trust generation |
| `account_frozen` | channel (clear, advisory) and session | the host is frozen (R9.4); also closes every attachment when it freezes. A client never persists a freeze from the clear form |
| `recovery_pending` | session | the principal is the subject of a `recovery_add` pending on this host, or is added only behind one; carries `entry_hash`, `effective_at` (R9.5) |
| `membership_invalid` | session | a carried entry failed (R9.3); carries `head` (after the valid prefix), `index`, `detail` (e.g. `signer_not_manager`, `recovery_key_retired`, `kit_sig_missing`, `self_approval`, `not_a_recovery_entry`, `blob_version_not_increasing`, `array_not_canonical`), and `need_before` when the window starts after a divergence |
| `membership_incomplete` | session | `more` and the principal isn't in the chain yet; carries `head`; reconnect with the next window |
| `unauthorized` | session | not a current member, removed, expired, grant revoked or issuer fenced (detail says which; the principal is authenticated) |
| `forbidden` | session | also: an op outside a service's or grant's `ops` |
| `unknown_session` | all | also: a session outside a service's or grant's scope |
| `busy` | channel/session | also: `init` rate; a device list that exists but can't be opened (clear, at `init`); a failed device-list write ("device list not recorded"), then the journal halt; a held host (a recorded device-list fault, or a carriage record the start can't reconcile): every `hello` but a manager's reconciliation ("device list not reconciled", R9.3) |
| `unsupported_version` | session | also: `hello` without `revision: 9` |
| relay `push_hint` refusals | relay | `skew`, `invalid_times`, `duplicate`, `bad_signature`, `stale` |

### R9.12 Fixtures

`fixtures/r9-*.json`, `requires: "r9"`; format in `fixtures/schema.md`
"r9 fixtures". Vectors (`kind: "vectors"`, every value computed with
the crate's own dependencies and cross-checked independently):
`r9-vectors-keys`, `r9-vectors-encoding`, `r9-vectors-membership-log`,
`r9-vectors-recovery`, `r9-vectors-channel-handshake`,
`r9-vectors-browser-grant`, `r9-vectors-push-hint`, `r9-vectors-pairing`. Scenarios
(`kind: "scenario"`): chain (`valid-suffix`, `rollback`,
`removed-signer-conflict`, `current-manager-conflict`, `unknown-carrier`,
`honest-concurrent-appends`, `relay-cas-failure`, `signature-retry`,
`invalid-tail`, `crash-between-commit-and-fences`,
`removal-on-an-open-channel`, and the write faults:
`membership-write-fault-fences-in-memory-and-halts`,
`uncertain-rename-is-reconciled-at-restart`,
`uncertain-rename-lost-is-replayed-then-held`,
`freeze-write-fault-stays-frozen-in-memory`, and the lost first marker
with no re-carriage: `lost-carriage-record-restart-stays-held`,
`lost-intent-restart-replays-and-stays-held`,
`lost-freeze-restart-replays-the-freeze`, and
`crash-after-a-recorded-fault-stays-held`), recovery (accepted,
refused, `pending-then-in-effect-after-24h`,
`wait-uses-the-host-clock-not-signed-at`, `approve-takes-effect-at-once`,
`veto-cancels`, `late-veto-has-no-effect`,
`decision-by-a-removed-manager-is-refused`,
`kit-replaced-with-the-current-kit`,
`kit-replaced-without-the-kit-then-vetoed`,
`kit-replaced-without-the-kit-then-in-effect`,
`pending-summary-in-every-welcome`, `k-backup-version-only-increases`,
`restore-refuses-a-rolled-back-backup`,
`restore-refuses-a-substitute-chain`,
`stale-head-withholds-the-recovery`, and the backup writer:
`k-backup-crash-before-cas`,
`k-backup-envelope-409-allocates-above-occupied`,
`k-backup-unrelated-cas-loss-keeps-the-envelope`,
`k-backup-repeated-collisions-make-progress`), handshake (success, wrong
head, tampered transcript, replay), hello revision, service scope and
expiry, browser grant, push hints (sign and verify,
`schedule-from-created-at-after-a-late-receipt`,
`delayed-ingress-at-the-skew-bound`,
`created-at-outside-the-skew-bound-is-refused`,
`stage-guard-exact-boundary`, `schedule-survives-relay-failover`), seen
(`approval-seen`, `seen-before-open-is-kept-until-the-open-arrives`,
`seen-from-another-process-generation-suppresses-nothing`,
`seen-after-resolution-reopens-nothing`,
`seen-lost-delivery-is-retried-until-acked`), and the multi-device set
(Mac and phone online, Mac off, takeover, approval while another holds
the lease), and the channel envelope (R9.7a): `r9-envelope-vectors`,
`r9-envelope-several-channels`, `r9-envelope-unknown-and-duplicate`,
`r9-envelope-link-loss`, `r9-envelope-bounds`.

### R9.13 Open questions for Astation

Decided since the first r9 draft (user, 2026-10-19): **recovery waits
24 h with approve and veto** (was question 2) and **the kit is
replaceable** with `set_recovery_key` (was question 3); both in R9.5.
Answered by Astation's r3 review and adopted: the CAS endpoint and its
bounded `409` (R9.4); no separate push key (R9.9); the native `auth_key`
is the ceremony P-256 identity, with Astation's fresh / 5-minute
owner-auth adapter (R9.6); clear errors are advisory (R9.7, R9.11).
Decided after Astation's r4 review of `016abe7` (user, 2026-10-19,
option A): **no recovery on a stale head**; the unconfirmed-restore
fallback is removed and a restore waits for a host-signed head (R9.5).
Answered from that review: the kit carries and binds the genesis hash
(R9.5), a durable carriage record replayed at start plus a fault record,
with a held state that only a manager's reconciliation ends (R9.3), committed
versus occupied backup versions with `409 {max_occupied}` (R9.5), and
sets versus sequences (R9.2). Still open:

1. Product records: push schedule (stages from `created_at`: 0 s / 60 s
   with `seen`), recovery enrolling a manager into the existing list
   after the 24 h wait, kit replacement, and the 5-minute biometric
   reuse are user decisions of 2026-10-19 on Atem's side; Astation's
   recorded policy must be updated to match before r9 is pinned.
2. K-backup blob storage (`(genesis_hash, blob_version)` put-if-absent,
   `409 {max_occupied}`, retention of the two newest per kit, an hour
   for uncommitted envelopes) is Astation's to shape; the semantics in
   R9.5 are the requirement.
3. v0.7.2 device ids: re-verification keeps the device id; r9 never
   infers replacement from hostname, relay room or login. A new id is a
   new member (and the old one is removed explicitly).
4. Service `projects` scopes use `h1.<kid>.` hashes, which change when
   `K` rotates; a rotation must re-issue service scopes (`set_roles`)
   before the old `K` generation is dropped.
5. Cross-language conformance: Swift (CryptoKit P-256 low-S
   normalization, HKDF, ChaCha20-Poly1305, HPKE, and the Ed25519 to
   X25519 conversion of the kit key, which CryptoKit doesn't offer) and
   WebCrypto/WASM must reproduce every `r9-vectors-*` value before the
   pin.
6. **The printed Recovery Kit changes:** it now carries the account's
   `genesis_hash` and a 16-byte `kit_tag` beside `R`, the account id and
   the relay URL (R9.5). Astation owns the text/QR encoding, the setup
   order (genesis committed before the kit is shown) and the restore
   flow's waiting screen; kits printed before r9 have no genesis and
   must be re-issued (`set_recovery_key`, `kit: "current"`).
7. **Held only after a recorded fault** (decided, user, 2026-10-19,
   option 2; R9.3): a plain crash or power loss replays the carriage
   record and resumes; a recorded device-list write fault, or a carriage
   record the start can't reconcile, holds remote access until a
   managing device reconciles. Accepted residual risks: storage that
   drops acknowledged writes, and a `pairing/` directory restored from
   an older backup. Astation's clients should reconnect a manager
   promptly when a host reports held; services and view-only devices
   wait.

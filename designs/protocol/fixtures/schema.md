# Fixture format (atem-session v1, r7.3)

One scenario per `*.json` file; `digest-vectors.json` holds the canonical-digest
known-answer vectors (`vectors`: payload → canonical string → sha256;
`must_reject`: raw JSON (`payload_json`) or bytes (`payload_hex`) a parser must
refuse before canonicalising).

Scenario: `{name, side?, setup, steps, note?}`. `side` is `host` (default: run
against a host implementation with fake clients) or `client` (run a client
implementation; the fixture plays the host with `deliver_to_client`).

`setup`:

- `host`: `{account_id, atem_device_id, host_trust_gen, runtime_gen, runtime_epoch}` — the host's own context.
- `sessions[]`: `{session_id, process_gen, chat?}`.
- `clients[]`: `{name, attachment_gen, permissions, client_kind, holds_lease_epoch?}` — the client's authenticated identity, permissions and connection mode, set by the harness (never derived from message fields).

Host scenarios start with every client already welcomed: the harness connects
each client, sends `hello` itself and consumes (and checks) the `welcome`
before step 0; `reconnect` does the same on the new attachment. With
`holds_lease_epoch: n` the harness then sends a real `acquire` for the
scenario's only session and requires a `lease` at epoch `n`. None of these
setup messages is visible to the steps.

`steps[]`, in order, on a deterministic monotonic clock starting at 0 ms:

| step | meaning |
|---|---|
| `{"send": client, "json": msg}` | client sends `msg` to the host (send time = current clock) |
| `{"expect": client, "type"?: t, "match": {path: value}, "capture"?: {name: path}}` | takes that client's next message of envelope type `t` (when given) and op `match.op` (when given); messages of other types/ops stay queued for later `expect`s. The taken message must match every path (dotted paths into `data`, array indexes as numbers, `#` for an array's length: `receipts.#`; a path that doesn't exist never matches, not even `null`), else the step fails. With neither `type` nor `op` it takes the very next message. `capture` stores values for later steps, referenced in any string as `${name}` |
| `{"expect_all": {…}}` | `expect` with that `match` for every client |
| `{"expect_none": client, "for_ms": n}` | nothing of any type is queued for that client after the clock advances n |
| `{"advance_ms": n, "timers"?: bool}` | advance the clock; timers may fire. With `"timers": false` only the clock moves: the host gets no tick and sees the new time only with the next message, write check or event (expiry must still hold: `now >= deadline`) |
| `{"hold": {"to": client, "op": op}}` / `{"deliver": "held"}` | delay the next matching host→client message, deliver it later (reordering) |
| `{"deliver_to_client": client, "json": msg}` | client-side fixtures: the host's message arrives now |
| `{"disconnect": client}`, `{"resume": client, "attachment_gen": uuid}` | transport events |
| `{"local_input": session_id, "bytes": base64}` | local terminal input on the host |
| `{"crash_worker": session_id}`, `{"restart_runtime": {"runtime_gen": uuid, "runtime_epoch": n}}` | failures |
| `{"fail_next_fsync": true}`, `{"change_trust_gen": n}` | durability and trust events |
| `{"fail_next_pty_enqueue": true}` | the next dispatch fails before any byte reaches the PTY |
| `{"fail_next_pty_write_after_partial": true}` | the next dispatch's writer fails after possibly writing some bytes |
| `{"reconnect": client, "attachment_gen": uuid}` | a new attachment for the same client (no resume) |
| `{"close_session": session_id}` | the runtime closes the session (it no longer accepts work; the process may still run) |
| `{"turn_complete": session_id, "turn_id": t}` | the provider reports that the session's executing prompt's turn `t` ended |
| `{"hold_pty_writes": true}` / `{"flush_pty_writes": true}` | remote terminal writes queue at the PTY writer / the writer writes them now, each re-checked at the write boundary at the current clock (dropped ones count as `pty_writes_dropped`) |
| `{"open_approval": session_id, "tool": t, "summary": s, "always_rules"?: [{rule_id, label, scope}]}` | the agent asks a permission prompt the runtime offers remotely (r7 §6a); the host opens an approval for the session's current process whoever holds the lease, or nobody (r7 §6a; at most 16 pending), and sends `approval_request` to every attachment with `control` subscribed by `list` (view-only ones get nothing). Capture its id from the `approval_request` |
| `{"close_approval": approval_id, "reason": r}` | the runtime saw the prompt end without the remote answer (`answered_terminal`, `interrupted`, `timed_out`, `process_ended`) |
| `{"approval_applied": approval_id, "ok": bool}` | the agent's report on a handed-over decision: applied (`completed`) or not known to be (`outcome_unknown`) |
| `{"approval_rules": session_id, "rules": [{rule_id, label, scope}]}` | the runtime reports the session's active Atem session rules (r7.2); a revoke the host dispatches is answered at once by the harness: the rule is dropped (the receipt completes) and the rules left are reported |
| `{"assert": {…}}` | host counters: `dispatch_attempts` (every dispatch the host started, including ones refused before any effect), `dispatches` (dispatches that reached the PTY/agent: attempts minus those that failed with no effect), `pty_bytes_written` (a number or `"unknown"`), `pty_writes` (terminal input written, split as `pty_writes_local`/`pty_writes_remote`; dispatches are counted separately), `pty_writes_dropped` (remote chunks refused at the write boundary), `resizes`, `stops`, `lease_holder`, `receipts_visible: {client: n}`; approvals: `approval_decisions` (every decision handed to the agent, in order: `[{approval_id, decision, rule_id?, message?}]`; an approval hand-off also counts as a dispatch), `approvals_pending` (on the only session), `approvals_released` (approvals the host closed itself, answered "no decision"), `rule_revokes` (rule ids the runtime was asked to revoke, in order; a revoke also counts as a dispatch) |
| `{"assert_client": {…}}` | client state: `controls`, `deadline_ms`, `registry` (ids), `registry_state`, `runtime_epoch`, `seq`, `sent_list`, `input_enabled`, `approvals` (pending approval ids) |

A host scenario fails if, after its last step, any client still has a queued
(unexpected) message or a held message was never delivered: every message the
host sends must be expected.

Negative scenarios assert the error and the absence of side effects
(writes, resizes, stops, dispatch, disclosure, resurrection).

Wire messages in fixtures are complete: every documented required field is present (e.g. full session descriptors). Decoders must parse them with the real wire types.

Expiry is `now >= deadline` everywhere.

The approval fixtures (`approval-*.json`) run in the core harness; the
real-runtime runner lists them as not run until the runtime opens approvals
from the agents' permission hooks.
`approval-rule-revoke-*` needs session rules, which only a Codex session's
`allow_always` creates: the real-runtime runner (whose agent is Claude)
lists it as not run.

## r8 draft fixtures (not run until r8 ships)

`r8-*.json` scenarios carry `"requires": "r8"` and exercise the **r8
draft** in `../atem-session-v1.md` (appendix "r8 draft"). Both runners
(`src/session_protocol/fixtures.rs`, `tests/runtime_fixtures_binary.rs`)
parse them and report them as NOT RUN (`requires r8`); nothing below is
implemented yet. When r8 ships, `requires` is removed and the runners gain
these actions.

- In an r8 scenario the harness's setup `hello` carries `"revision": 8` and
  the `welcome` must echo `revision: 8` and carry `features`.
- `clients[].welcome: false`: the harness sends no `hello` for that client
  (the steps do).
- Each client `name` is one authenticated principal (§H): `reconnect`,
  `resume`, `set_permissions` and a second `hello` keep it; its
  `attachment_gen`s change. (Today's host has one principal, the paired
  Astation; the harness gives each client its own so the per-principal
  rules can be checked.) After `restart_runtime`, `crash_runtime` or
  `crash_after_accepted` the host's start is the current clock (§H's 60 s
  confirmation window).
- In an r8 scenario `restart_runtime` is an orderly stop and start: the
  host writes its clean-close record (§H) when its journal is healthy,
  and none when the journal is halted. `crash_runtime` and
  `crash_after_accepted` never write one. The clean-close write is not a
  journal append counted by `fail_next_fsync`/`fail_fsync_of`.

| step (r8 draft) | meaning |
|---|---|
| `{"chat_history": session_id, "messages": [message]}` | the session's retained chat history before any step reads it (complete chat-v1 message bodies, oldest first) |
| `{"chat_message": session_id, "message": message}` | the agent produced a message, new or a whole replacement of one with the same `messageId` |
| `{"chat_evict": session_id, "count": n}` | retention evicted the oldest `n` messages (`oldest_retained` moves, `truncated` becomes true) |
| `{"chat_turn": session_id, "turn_id": t, "request_id"?: r, "origin": o, "assistant_messages": n, "text_bytes": b, "escape"?: "control"}` | one turn arrives live: a user message `<t>-u` (origin `o`, `requestId` `r` when given) and `n` assistant messages `<t>-a-0001`…, each one text part of `b` bytes; `escape: "control"` fills the text with U+0001 (6 bytes once JSON-escaped), else `x` |
| `{"worker_gap": session_id, "dropped": [id], "recoverable": [id], "delivered_after": [message]}` | the worker's backlog dropped `dropped`, then delivered `delivered_after` with `gap > 0`; the host's reload of the worker's history finds only `recoverable` (the rest is gone from the worker too) |
| `{"open_approval": …, "turn_id": t}` | as before; `turn_id` is the card's `turnId` |
| `{"expect_live": client, "message_ids": [id], "sequence_from": n}` | takes that many chat `message`s (no `history`), with those ids in order and consecutive sequences from `n` |
| `{"recover": client, "request": msg, "message_ids": [id], "min_pages": n, "max_count": c, "max_content_bytes": b, "max_wire_bytes": w, "end": {path: value}}` | sends `request` (a chat `history` or `open`), takes its page (`opened` first for an `open`; `message{history:true}`s then `history_end`), and while `page.end` is false sends `history{next}` with the same binding and conversation (page id `<page_id>-2`, …) and takes the next page. Every page: consecutive sequences, ≤ `c` messages, ≤ `b` content bytes, ≤ `w` serialized bytes (the sum of its envelopes), and no `end: true` before the last. Newest-first selections are reassembled oldest first. The messages taken equal `message_ids` exactly (no gap, no duplicate); the last `history_end` matches `end`; at least `n` pages |
| `{"client_try": client, "json": msg, "refused": text}` | client side: the client is asked to send `msg` and must refuse locally with that reason (nothing is sent) |
| `{"client_open_chat": client, "conversation": id, "session_id": s}` | client side: the client opens a chat (its `open` is consumed by the fixture) |
| `{"drop": {"to": client, "op": op}}` | the next matching host→client message is lost in transit: never delivered and not expected (repeat the step to lose several) |
| `{"set_permissions": client, "permissions": [p], "attachment_gen": uuid}` | the client's principal re-authenticates with these permissions on a new attachment, whether or not its old one is still live (after `disconnect` too). Losing `control` follows §H: the fence is written, live attachments are fenced, a lease held by any of its attachments is revoked (`lease_changed{revoked}` to the other viewers) and its `accepted` work not yet executing, from any of its attachments, is rejected (`control revoked`); then the harness welcomes the new attachment. The permissions stay with the principal: later `reconnect`s use them |
| `{"fail_next_fsync": true, "undo_fails"?: true}` | r8 (§I; for a revocation's writes §H, "A failed revocation write"): the next journal append fails and the journal halts until `restart_runtime` (every session request but `hello` is `busy`); its rollback succeeds (nothing of it is on disk) unless `undo_fails`, which leaves the record on disk (the worst case). The refusal list write succeeds |
| `{"fail_fsync_of": n}` | as `fail_next_fsync` for the `n`-th next journal append (1 = the next one); the earlier ones succeed |
| `{"crash_after_accepted": {"runtime_gen": uuid, "runtime_epoch": n}}` | the next `accepted` record becomes durable, then the runtime crashes before acting on it (no lease change, no reply, no other message) and restarts with these values, as `crash_runtime` |
| `{"crash_runtime": {"runtime_gen": uuid, "runtime_epoch": n}}` | the runtime is killed (no clean close) and restarts with these values; workers survive and are adopted; every link drops and clients `reconnect` |
| `{"replace_process": session_id, "process_gen": uuid}` | the agent process is replaced (restart/resume) with a new `process_gen` (`SessionHost::replace_process`) |

Send and approval scenarios (`r8-send-*`, `r8-approval-*`, and the other
§F fixtures listed below): the setup `welcome` must advertise
`chat.send_acquire` and `approval.lease_free`. A `local_input` whose bytes
end without CR/LF leaves unsent terminal input, so every prompt dispatched
afterwards is refused by the adapter's draft check (`rejected`, detail `the
terminal has unsent input; finish or clear it there`). A `receipts` reply
lists receipts in the order of `request_ids` (unrecorded ids are omitted).

New `assert` keys (r8 draft): `journal_halted` (the journal refuses
appends until a restart, §I), `attachments` (live attachments on the host),
`chat_opens` / `chat_closes` (`opened` / `close` the host sent, all
conversations), `chat_conversations` (open conversations).

New `assert_client` keys (r8 draft): `admitted` (the welcome passed the
revision check), `revision`, `features_enabled` (advertised features the
client knows and enabled), `lookup_enabled`, `coverage_enabled`,
`chat_enabled`, `chat_loaded` (a `history_end` arrived), `chat_truncated`,
`chat_messages` (ids in timeline order), `chat_reopens` (opens the client
sent after the first), `sent` (messages sent since the last check).

The r8 draft scenarios:

| fixture | side | checks |
|---|---|---|
| `r8-hello-without-revision-8-is-refused-before-any-attachment` | host | r7/missing/other revision refused `unsupported_version` before any attachment or session work |
| `r8-client-refuses-a-host-without-revision-8` | client | r8 client against an older host: no attachment, no feature |
| `r8-client-enables-only-advertised-features` | client | a missing required feature is never used |
| `r8-open-with-before-is-refused` | host | `open.before` refused explicitly, never read as a newest-page open |
| `r8-history-page-and-live-events-share-one-ordered-stream` | host | page snapshot and enqueue are one step in the sequenced stream |
| `r8-long-turn-is-recovered-in-bounded-pages` | host | > 50 messages / > 256 KiB / escaping overhead, bounded pages, `next` |
| `r8-truncated-history-reopens-once-then-stays-live` | host | truncation is persistent information, no reset |
| `r8-client-shows-truncation-and-resyncs-only-on-a-sequence-gap` | client | no reopen loop; resync on a real sequence gap |
| `r8-backlog-hole-is-reported-not-reopened` | host | worker backlog gap: reload, then a persistent hole (changes #75's error + close) |
| `r8-receipt-result-bounds-reply-message-ids` | host | `reply_message_ids` ≤ 32 + `more`, rest by `history{request_id}` |
| `r8-history-selectors-are-exclusive-and-validated` | host | exactly one selector; formats and lengths |
| `r8-stale-or-foreign-next-token-is-stale-target` | host | `next` bound to its context; evicted turn `unavailable`, partly evicted `partial` |
| `r8-send-acquires-an-unowned-session` | host | §F: unowned → acquire + accept in one operation; `lease` on the reply, `granted` to viewers; chat-v1 Send under the own lease |
| `r8-send-under-the-own-lease-checks-the-epoch` | host | ordinary submit checks `lease_epoch`; acquiring Send by the holder: same epoch, deadline not extended |
| `r8-send-refused-while-another-holds-then-takeover` | host | `lease_held{controller}`, nothing runs; confirmed `takeover` with the same `request_id` takes over atomically |
| `r8-two-simultaneous-sends-acquire-once` | host | first admitted acquires; second `lease_held`, nothing recorded |
| `r8-ownership-is-checked-at-admission-not-as-displayed` | host | ownership changed after display: refused; holder gone before the takeover: plain grant |
| `r8-local-input-wins-over-a-send` | host | local input revokes the Send's lease; queued prompt refused by the draft check |
| `r8-stale-takeover-confirmation-is-refused` | host | `expected_controller` no longer the holder → `lease_held`, no takeover |
| `r8-duplicate-send-never-reacquires-or-replays` | host | duplicates (any flags) return the receipt; no acquire, takeover or rerun; delayed receipt |
| `r8-disconnect-right-after-acceptance` | host | replies lost, work runs, lease expires; receipt query then duplicate on a new attachment |
| `r8-failed-persistence-changes-no-lease` | host | §I: failed admission write: `busy`, no grant, nothing runs, journal halted (same-id retry `busy`); after the restart the id is `rejected` "acceptance not confirmed" and not re-admitted; a new id is admitted |
| `r8-double-write-failure-takeover-never-runs` | host | §I: confirmed takeover while c1 holds; write and rollback fail: `busy`, c1 keeps the lease; after the restart `rejected`, never executed, same id returns it |
| `r8-crash-after-durable-acceptance-grants-no-lease` | host | §I.4: durable accepted, crash before the grant: no lease; `rejected` "authorization history unknown" at the restart, never dispatched; duplicate returns the receipt |
| `r8-expired-lease-is-checked-at-admission` | host | expiry at admission without a timer; old epoch stale |
| `r8-revoked-control-refuses-the-send-and-its-queued-prompt` | host | lost `control`: lease revoked, queued prompt rejected, Send `forbidden` |
| `r8-revoked-control-fences-work-across-reconnect-and-restart` | host | §H: same-permission reconnect keeps queued work; view-only re-authentication after disconnect rejects work of the gone attachment; regaining control or a restart doesn't revive it |
| `r8-control-fence-holds-when-a-rejection-write-fails` | host | §H: fence durable, rejection write fails: halted, nothing dispatched; no clean close, so recovery rejects the work (`authorization history unknown`) |
| `r8-failed-fence-write-rejects-queued-work-at-once` | host | §H: the fence write fails: lease revoked and the principal's queued work rejected in memory at once, halted, nothing dispatched after; restart: `authorization history unknown` |
| `r8-failed-fence-write-then-control-restored-never-runs` | host | §H (r4 trace): the fence write fails (rollback succeeds, then in a second cycle rollback fails), restart, control restored before confirmation: the queued request is `rejected` "authorization history unknown" and never dispatched |
| `r8-crash-rejects-queued-work-whose-history-is-unknown` | host | §H rule 2: crash with queued work, principal back with control at once: `rejected` "authorization history unknown"; same id returns it, a new id is admitted |
| `r8-clean-close-runs-queued-work-once-its-principal-is-confirmed` | host | §H rule 3: after a clean close queued work waits for its principal (not another one) and runs once, no lease |
| `r8-recovered-work-needs-its-principal-confirmed` | host | §H rule 3: after a clean close recovered work waits for its principal; not confirmed by 60 s → `control not confirmed` |
| `r8-delayed-send-reply-does-not-regrant-lost-control` | host | §F: the admitting receipt delayed past local input or a takeover grants nothing; its epoch is `stale_lease` |
| `r8-client-delayed-send-reply-never-restores-control` | client | §F reply rule: a late `lease` after local input, takeover, attachment replacement or local expiry is not applied; a timely one is |
| `r8-process-replaced-before-dispatch` | host | queued Send rejected on replacement; old `process_gen` `stale_target`; new one acquires |
| `r8-send-acquire-wire-rules` | host | field rules → `invalid_request`; `interrupt`/`stop`/`approval_rule_revoke` can't acquire |
| `r8-approval-answer-by-a-non-holder-leaves-the-lease` | host | §G: non-holder answers (no epoch, a foreign epoch), lease unchanged; view-only `forbidden` |
| `r8-approval-answer-keeps-the-holders-deadline` | host | §G at t = 6000/9000: holder and non-holder answers keep the deadline (repeat acquire: `ms_left` 6000), queued input written, expiry at 15000; answer with no holder grants nothing |
| `r8-approval-answer-with-acquire-is-refused` | host | `acquire` (payload or submit) → `unsupported_version`, no effect |
| `r8-approval-answers-crossing-first-wins` | host | holder and non-holder cross: first admitted wins, second `stale_target` |
| `r8-approval-answer-to-a-closed-request-is-stale-target` | host | terminal-answered, timed-out and already-answered requests → `stale_target` |
| `r8-approval-opens-without-a-lease-holder` | host | §G (replaces r7 `approval-opens-without-a-lease-holder`): opened and pushed with nobody holding the lease; answered without it, nothing granted, push resolved |
| `r8-approval-stays-pending-when-the-lease-ends` | host | §G (replaces the r7 fixture of that name): expiry closes nothing; an answer with the expired epoch is admitted (the epoch is ignored), nothing granted |
| `r8-approval-late-answer-after-push-resolved-is-stale-target` | host | §G (replaces the r7 fixture of that name): after `push_resolved{answered_terminal}` a late answer without the lease is `stale_target`, nothing recorded |
| `r8-approval-survives-takeover` | host | §G (replaces r7 `approval-survives-takeover`): a takeover keeps the approval pending; the old holder's stale-epoch answer is admitted and wins, the new holder's is `stale_target`, the lease stays the new holder's |

Astation's API-level merge fixture (a delayed HTTP page against newer SSE
versions) is Astation's; the host side of it is
`r8-history-page-and-live-events-share-one-ordered-stream`.

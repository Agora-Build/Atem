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
| `{"open_approval": session_id, "tool": t, "summary": s, "always_rules"?: [{rule_id, label, scope}]}` | the agent asks a permission prompt the runtime offers remotely (r7 §6a); the host opens an approval for the session's current process, or refuses silently (no live remote lease: the agent's own prompt asks). Capture its id from the `approval_request` |
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

New `assert` keys (r8 draft): `attachments` (live attachments on the host),
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

Astation's API-level merge fixture (a delayed HTTP page against newer SSE
versions) is Astation's; the host side of it is
`r8-history-page-and-live-events-share-one-ordered-stream`.

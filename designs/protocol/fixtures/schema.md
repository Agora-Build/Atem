# Fixture format (atem-session v1, r7.2)

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

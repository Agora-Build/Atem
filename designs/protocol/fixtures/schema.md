# Fixture format (atem-session v1, r6)

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

`steps[]`, in order, on a deterministic monotonic clock starting at 0 ms:

| step | meaning |
|---|---|
| `{"send": client, "json": msg}` | client sends `msg` to the host (send time = current clock) |
| `{"expect": client, "match": {path: value}, "capture"?: {name: path}}` | next message to that client matches (dotted paths into `data`); `capture` stores values for later steps, referenced in any string as `${name}` |
| `{"expect_all": {…}}` | every client's next message matches |
| `{"expect_none": client, "for_ms": n}` | nothing reaches that client while the clock advances n |
| `{"advance_ms": n}` | advance the clock; timers may fire |
| `{"hold": {"to": client, "op": op}}` / `{"deliver": "held"}` | delay the next matching host→client message, deliver it later (reordering) |
| `{"deliver_to_client": client, "json": msg}` | client-side fixtures: the host's message arrives now |
| `{"disconnect": client}`, `{"resume": client, "attachment_gen": uuid}` | transport events |
| `{"local_input": session_id, "bytes": base64}` | local terminal input on the host |
| `{"crash_worker": session_id}`, `{"restart_runtime": {"runtime_gen": uuid, "runtime_epoch": n}}` | failures |
| `{"fail_next_fsync": true}`, `{"change_trust_gen": n}` | durability and trust events |
| `{"fail_next_pty_enqueue": true}` | the next dispatch fails before any byte reaches the PTY |
| `{"fail_next_pty_write_after_partial": true}` | the next dispatch's writer fails after possibly writing some bytes |
| `{"reconnect": client, "attachment_gen": uuid}` | a new attachment for the same client (no resume) |
| `{"assert": {…}}` | host counters: `dispatch_attempts`, `pty_bytes_written` (a number or `"unknown"`), `pty_writes` (split as `pty_writes_local`/`pty_writes_remote`), `resizes`, `stops`, `dispatches`, `lease_holder`, `receipts_visible: {client: n}` |
| `{"assert_client": {…}}` | client state: `controls`, `deadline_ms`, `registry` (ids), `registry_state`, `runtime_epoch`, `seq`, `sent_list`, `input_enabled` |

Negative scenarios assert the error and the absence of side effects
(writes, resizes, stops, dispatch, disclosure, resurrection).

Wire messages in fixtures are complete: every documented required field is present (e.g. full session descriptors). Decoders must parse them with the real wire types.

Expiry is `now >= deadline` everywhere.

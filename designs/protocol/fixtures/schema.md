# Fixture format (atem-session v1)

One scenario per `*.json` file; `digest-vectors.json` holds canonical-digest
known-answer vectors (`vectors`: payload → canonical string → sha256;
`must_reject`: raw JSON a parser must refuse).

Scenario: `{name, setup, steps}`.

- `setup.sessions[]`: `{session_id, process_gen, chat?}` live sessions on a fake host.
- `setup.clients[]`: `{name, attachment_gen, permissions, holds_lease_epoch?}` authenticated attachments (compatibility mode).
- `steps[]`, executed in order against a fake monotonic clock:
  - `{"send": client, "json": message}`
  - `{"expect": client, "match": {dotted.path: value}}` — partial match on the next message to that client (`op`, `re`, … refer to `data` fields)
  - `{"expect_all": {...}}` — every client receives a matching message
  - `{"expect_none": client, "for_ms": n}`
  - `{"advance_ms": n}`
  - `{"disconnect": client}`, `{"resume": client, "attachment_gen": uuid}`
  - `{"local_input": session_id, "bytes": base64}`
  - `{"crash_worker": session_id}`, `{"restart_runtime": true}`
  - `{"assert": {"pty_writes": n, "dispatches": n, "lease_holder": client|null, "receipts_visible": {client: n}}}` — host-side counters

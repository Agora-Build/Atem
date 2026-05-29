# Vault — Shared cross-agent context store (atem ↔ relay-server ↔ Postgres)

Status: design — 2026-05-26
Owner: Brent G

## Goal

Let two or more atems — each driving its own coding agent — share a small,
durable, append-only context store called a **vault**, so agents working toward
a common goal can hand off notes, decisions, and summaries without a human
copy-pasting between terminals.

Concretely:

- `atem vault new --summary "..."` creates a vault and prints a short vault id.
- `atem vault write --vault-id <id> --text "..."` appends an entry (or edits an
  existing one with `--entry-id`).
- `atem vault read --vault-id <id>` prints the current contents; `--history`
  shows every version ever written.
- `atem vault watch --vault-id <id>` blocks and re-renders when another atem
  writes.

The store is hosted by the **relay-server (station)** and backed by **Postgres**.
**atem mediates all access** — agents never speak to the vault directly (this is
deliberately **not** MCP).

## Non-goals

- Not a general KV store or file-sync. Vaults hold small text entries meant for
  agent-to-agent context, not artifacts.
- **Not MCP.** The vault is an atem feature; an agent reaches it only through
  `atem vault …` commands that atem (or the human) runs.
- No streaming of large payloads. The relay carries only a tiny `vault-updated`
  nudge; the actual content is fetched over HTTP.
- No per-entry ACLs in v1. Authz is vault-level: work-session membership + a
  writer list.

## Why relay-server + Postgres

- The relay-server (station) is already the shared rendezvous every atem can
  reach (LAN / VPN / relay), already has session auth (see [[session-auth]],
  [[relay-support]]), and is the only always-on component multiple atems share.
- Vault content must survive restarts and be readable by an atem that was
  offline when it was written → a **durable** store. Postgres (chosen over R2)
  gives transactional append, per-vault counters, and a cheap "latest version
  per entry" query.
- The relay's existing JSON-text room is fine for the lightweight
  `vault-updated` notification but is the **wrong** place to store content
  (unbounded in-memory channels, no durability).

## Architecture

```
atem A ─┐                          ┌─ Postgres (vaults, vault_entries)
        │  HTTPS  /api/vault/...    │
atem B ─┼─────────────────────────▶ relay-server (station) ─┘
        │  WS     vault-updated     │
atem C ─┘◀────────────────────────  (relay room broadcast)
```

- **Read / write = HTTPS** to the relay-server: `GET`/`POST /api/vault/<id>`.
- **Notification = the existing relay room**: after a committed write the server
  broadcasts `vault-updated {vault_id, seq}` to the room; subscribed atems
  re-read. No content rides the WS.
- **atem-mediated**: the agent's only interface is the `atem vault` CLI. atem
  holds the session credential and the client id; the agent never sees them.

## Auth model

Two distinct tokens, matching the design intent ("use sessionId to auth, use id
to check if they can see the content"):

| Token | Source | Role |
|-------|--------|------|
| `session_id` | existing pairing / relay session ([[session-auth]]) | **authenticates** — proves the caller is a real, paired atem and resolves its current work session |
| `client_id` (`id=` in the URL) | each atem's stable id | **authorizes** — checked against the vault's writer list |
| `work_session_id` | the work session the caller is currently in | atems sharing it can read **and** write any vault in it |

Request shape:

```
GET  /api/vault/<id>?id=<client_id>     Authorization: session <session_id>
POST /api/vault/<id>?id=<client_id>     Authorization: session <session_id>
```

Authorization predicates (server-side):

```
can_read(vault, caller):
    caller.work_session_id == vault.work_session_id    # in the same work session
    OR caller.client_id = ANY(vault.writer_list)       # past content-writer

can_write(vault, caller):                              # append / override content
    caller.work_session_id == vault.work_session_id    # in-session only
```

- **In-session** atems get full read + write.
- **Out-of-session** atems get **read-only**, and only if their `client_id` is
  in the vault's `writer_list` (i.e. they contributed content earlier, in a
  prior session).
- **`set-summary` follows the read predicate** — any atem that can *see* the
  vault may update its summary (summary is mutable and low-stakes).

## Data model (Postgres)

Two tables. `vaults` holds mutable per-vault metadata plus a denormalized
`writer_list` for fast authz. `vault_entries` is append-only and versioned.

```sql
CREATE TABLE vaults (
    vault_id        TEXT PRIMARY KEY,         -- short, URL-safe, e.g. "v-7Kf3qD"
    summary         TEXT NOT NULL DEFAULT '', -- mutable description
    work_session_id TEXT NOT NULL,            -- the work session this vault belongs to
    created_by      TEXT NOT NULL,            -- client_id of creator
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    writer_list     TEXT[] NOT NULL DEFAULT '{}',  -- denormalized content-writer client_ids
    next_entry_no   INT    NOT NULL DEFAULT 1      -- per-vault entry-number allocator
);

CREATE TABLE vault_entries (
    seq        BIGSERIAL PRIMARY KEY,         -- global write order (also the --since cursor)
    vault_id   TEXT NOT NULL REFERENCES vaults(vault_id),
    entry_no   INT  NOT NULL,                 -- per-vault: 1,2,3 → shown as e1, e2, e3
    version    INT  NOT NULL,                 -- per-entry: 1,2,3 → shown as v1, v2, v3
    kind       TEXT NOT NULL,                 -- 'content' | 'summary'
    writer_id  TEXT NOT NULL,                 -- client_id that wrote this row
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (vault_id, entry_no, version)
);
```

### `vaults` vs `vault_entries`

- **`vaults`** — one row per vault: identity, the mutable summary, who created
  it, the fast-path `writer_list`, and the `entry_no` allocator. Mutable.
- **`vault_entries`** — the append-only log of every write ever made. Rows are
  immutable; an "edit" is a new row with a higher `version`. This is what gives
  history + override with **zero data loss**.

### Append vs. override (no separate "override" kind)

- **Append** (`atem vault write --vault-id <id> --text "..."`): allocate
  `entry_no = vaults.next_entry_no++`, insert with `version = 1`.
- **Override / edit** (`atem vault write --vault-id <id> --entry-id e3 --text "..."`):
  keep `entry_no = 3`, insert with `version = max(version for that entry_no) + 1`.

Whether a write was an append or an override is fully derivable from `version`
(v1 = first write of that entry, v2+ = an edit), so there is **no** `override`
kind — `kind ∈ {content, summary}` only.

### Short stable ids

Entries are addressed by the stable short id `eN` (= `entry_no`), with versions
`vM`. `e3 v2` = the 2nd version of the 3rd entry. The id is stable across edits:
editing e3 never renumbers it and never reorders the view.

## Render rules

**Current view** (`atem vault read --vault-id <id>`):

- For each `entry_no`, take the row with the highest `version` (latest edit
  wins).
- Order by `entry_no` ascending (first-appearance order). Edits do **not** move
  an entry — e3 stays in slot 3 after being edited.
- Show the summary at the top, then `e1 e2 e3 …` with their current text.

**History** (`atem vault read --vault-id <id> --history`):

- Every row, ordered by `seq` (true write order), labeled `eN vM` so overrides
  are visible in the order they happened.

**Incremental** (`atem vault read --vault-id <id> --since <seq>`):

- Only rows with `seq > <since>`. Lets `watch` fetch just what's new; the
  largest `seq` seen becomes the next cursor.

## CLI

| Command | Effect |
|---------|--------|
| `atem vault new --summary "<text>"` | Create a vault in the caller's current work session; print the new `vault_id`. |
| `atem vault list` | List vaults the caller can read (in-session + vaults where caller ∈ writer_list), with id + summary. |
| `atem vault read --vault-id <id> [--since <seq>] [--history] [--format human\|plain]` | Render current view (default), history, or only-new entries. |
| `atem vault write --vault-id <id> [--entry-id <eN>] --text "<text>"` | Append (no `--entry-id`) or override entry `eN` (with `--entry-id`). Adds caller to `writer_list`. |
| `atem vault set-summary --vault-id <id> --text "<text>"` | Update the mutable summary (read-permission only). |
| `atem vault watch --vault-id <id>` | Subscribe to `vault-updated` on the relay room; re-render (via `--since`) on each nudge. |

`--format human` (default) is pretty; `--format plain` is bare text for piping
into a prompt / agent.

## Notification flow

```
atem A: POST /api/vault/v-7Kf3qD   (append e4)
            └─ server commits the row, then broadcasts to the relay room:
relay room ── vault-updated { vault_id: "v-7Kf3qD", seq: 128 } ──▶ atem B, atem C (watching)
atem B/C: atem vault read --vault-id v-7Kf3qD --since <last_seq>   (re-render)
```

- The relay carries only `{vault_id, seq}` — never content. Keeps the
  lossy / unbounded room channel safe.
- `vault-updated` is **best-effort**; the `--since` cursor on read is the source
  of truth, so a dropped nudge just means a later refresh catches up.
- atem does **not** spam the agent's stdin. `watch` re-renders inside atem; the
  agent picks up context by running `atem vault read` (or atem surfaces "vault
  updated" and the agent re-reads).

## Server endpoints (relay-server)

```
POST /api/vault                  create vault    {summary}            → {vault_id}
GET  /api/vault                  list readable                        → [{vault_id, summary}]
GET  /api/vault/<id>             read (current)  [?since= &history=]   → entries
POST /api/vault/<id>             write content   {text, entry_id?}     → {entry_no, version, seq}
POST /api/vault/<id>/summary     set summary     {text}
```

All carry `?id=<client_id>` + session auth; all run the authz predicates above.

## Open questions

1. **`work_session_id` source.** Is the "work session" the relay room
   (= astation_id, per [[relay-support]]), the pairing session, or a new explicit
   id minted by `atem vault new`? Leaning: the work session = the relay room the
   atems share, so two atems paired to the same Astation are automatically in one
   work session.
2. **`client_id` source.** ✅ Resolved — use the persistent `instance_id` (UUID
   v4) introduced in [[atem-identity]]. It's stable across restarts (and hostname
   changes), globally unique, and already the canonical atem identity. Note this
   is the raw `instance_id`, *not* the derived `atem_id` (which is a 12+8 display
   id for relay rooms).
3. **Capability vs. enumeration.** `vault_id` is short (`v-7Kf3qD`) for
   ergonomics; the first sketch had a "12-randomized-id". Authz is enforced
   server-side, so id secrecy is not load-bearing — but make the id long enough
   to not be trivially enumerable.
4. **Summary history.** Summary lives as a mutable column on `vaults` (fast
   read) and *could* also be logged as `kind='summary'` rows in `vault_entries`
   for history. v1 can skip summary-history rows; the schema supports adding
   them later.
5. **`writer_list` growth / GC.** It only ever grows. Fine for small teams;
   revisit if a vault accumulates many one-off writers.
6. **Relay-server session port.** [[session-auth]] notes the relay server still
   needs the Rust `SessionStore` (a TODO there). The vault API depends on it —
   confirm relay-side session validation lands first.

## Phasing

| Phase | Deliverable |
|-------|-------------|
| **v1** | Postgres tables; relay-server `/api/vault` CRUD with session + writer-list authz; `atem vault new/list/read/write/set-summary`. Manual re-read (no watch). |
| v1.5 | `vault-updated` relay broadcast + `atem vault watch` (re-render via `--since`). |
| v2 | Summary history, richer list filters, optional per-entry tags; revisit transport if vaults grow large. |

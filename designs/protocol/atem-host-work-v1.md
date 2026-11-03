# Host launch and directed work

Status: Atem receiver implemented on the feature branch, under integration
review, 2026-11-02. Astation UI, Station publication/replay and optional OS
service installation are separate work. This extension does not enable the
hosted execution API. Types: `atem_client::session::host_work`; real-runtime
tests: `tests/host_work_binary.rs`.

Shared request vectors live in `fixtures/host-work/requests-v1.json`; the
client core runs them independently of the r8 session scenario fixtures.

## Transport and authority

Requests are session messages inside an admitted encrypted atem-ch1 channel.
They require no binding to a session that has not yet been created:

```json
{"type":"session","data":{
  "v":1,"op":"host_profiles","id":"11111111-1111-4111-8111-111111111111",
  "host":{"account_id":"account","atem_device_id":"host","host_trust_gen":1}
}}
```

`id` is a fresh UUID v4 per exchange. The host triple must match exactly.
Requests reject unknown fields, duplicate JSON keys, unsafe integers and
messages over 256 KiB. Healthy opted-in hosts advertise `host.launch` and
`host.work`, `host.messages` and `host.attachments`; clients check the feature before sending. Configuration can
disable operations on an existing channel, which then fail closed.

Services/browsers need explicit `launch` or `notify` ops; work also needs
`prompt`. Native members need control. All principals additionally require
local profile/route consent naming their full `member:<device_id>`,
`service:<device_id>` or `browser:<grant_id>`; a profile or route that
names none consents for the paired Astation only (`member:<its id>`). Memory/vault access grants no
execution authority. Recheck current membership, key, expiry, scopes,
held/faulted/frozen state, browser revocation/quarantine, durable principal
control generation and local consent. Queued work waits for its original
principal's live authorized channel. Regrant does not revive fenced work.

Feature negotiation is additive for accounts without new grants. **New signed
scope op names require upgraded membership verifiers:** older strict clients
reject entries containing `launch`, `message` or `notify`. Upgrade participating SDKs
before enrolling those scopes. Do not modify a live account in tests.

## Local configuration and lifetime

`atem runtime start` starts the runtime detached, or reuses the running one
without replacing its build or changing its environment. If missing, it creates
private `runtime.toml` with `enabled = false`; existing approvals are never
overwritten. `atem runtime check` validates the configuration and environment
sources without starting the runtime or an agent. Both require pairing. Bare
`atem runtime` retains its foreground behavior. The generated file embeds the
[runtime sample](../../configs/runtime.example.toml), which documents
profiles/routes. Each profile approves:

- ID, positive revision, label, provider (`claude`/`codex`).
- Canonical absolute directory and normalized Git project key.
- CLI args, e.g. `["--profile", "oss"]`, and allowed principals (default: the
  paired Astation).
- Environment variable names and optional absolute private JSON env file.

Remote requests cannot provide paths, commands, arguments or environment
values. Launch checks the directory and current Git project again. Project
scopes use the approved project's keyed hash; session-scoped grants cannot
create an unbound new session.

Environment contains basic runtime variables (HOME/PATH/locale), explicitly
named runtime variables and approved JSON-file values. Files must be bounded,
regular, same-user, private, and not symlinks. JSON is never sourced as shell
code; only allowlisted names may appear. Name variables such as `OSS_API_KEY`
and the applicable provider base URL in `env_names`. When starting a new
detached runtime, Atem forwards only the ordinary runtime environment and
variables explicitly named by enabled profiles; unapproved provider variables
and test hooks are excluded. A private JSON file is another source for approved
values and overrides runtime exports. Another terminal's exports, including a
repeated `runtime start`, cannot update an existing runtime. Values never enter
launch results or journals.

Config reloads each second and is checked at the worker Start boundary.
Increase revisions on approval changes. Invalid configuration or failed
durability disables hosting until corrected and the runtime restarted.
Commands do not restart a running runtime. Healthy `enabled = true` hosting
keeps the runtime online with zero sessions. Both remote launch and notifications
use this same runtime. Use `atem runtime start` for detached operation or bare
`atem runtime` in the foreground. With hosting disabled, the ordinary idle
timeout still applies. **OS boot services are not implemented**;
the optional systemd/launchd design remains in `../agent-hosting.md`.

## Launch operations

| op | Additional fields | Result |
|---|---|---|
| `host_profiles` | none | approved profile id/revision/label/provider |
| `host_launch` | UUID v4 `request_id`, `profile_id`, `profile_revision`, `expires_at` | durable launch status |
| `host_launch_query` | `request_id` | same principal's recorded status |

Expiry is absolute host wall milliseconds, after now and at most 24h ahead.
Retries keep the original request ID/profile/revision/expiry with a fresh
message ID. Digest covers host/profile/revision/expiry. Identical retries
return saved state; different input or principal is `request_id_reused`.

Reserve the request/session/process IDs durably before spawn. Use the normal
PTY worker with authorization checks before spawn and Start. `starting` means
reserved; `started` confirms worker launch, not chat readiness. Local
`atem agent attach <session_id>` and remote terminal/chat share that CLI.
Definite preparation failures are `failed`; ambiguous starts are
`outcome_unknown` and never replayed. Restart adopts a verified survivor with
the reserved process identity or keeps the outcome unknown.

## Directed work operations

| op | Additional fields |
|---|---|
| `work_enqueue` | `route_id`, `route_revision`, `task` |
| `work_query` | `task_id` |
| `work_cancel` | `task_id` (queued/blocked only; never interrupts) |
| `work_complete` | `task_id`, immutable `result` snapshot |

Task: UUID v4 `task_id`, UUID v4 `workflow_id`, existing full session `target`,
`expires_at`, nonempty `prompt` and 0–8 context snapshots. Optional `attachments`
carry up to four immutable screenshot descriptors; omit when empty. See the
[attachment/mark contract](atem-task-attachments-v1.md) for transfer and bounds. Target contains the
host triple, `session_id`, `process_gen`. Snapshot: `kind` (`memory`/`vault`),
opaque `id`, positive integer `version`, lowercase hex SHA-256 `digest` of
exact UTF-8 `text`, and `text`. Rendered prompt with attribution/correlation
is at most 32 KiB; no controls except newline/tab. Each snapshot is bounded
to 128 KiB (the rendered-prompt limit further restricts task context).

This increment accepts **resolved immutable snapshots from the authorized
publisher** and verifies their digest. It does not fetch or prove a Station
commit itself. The publisher must verify committed publication and context
access for this route. Station must agree this boundary before production
delivery; a digest alone is not publication evidence. Content stays inside
the encrypted channel and private local task store, never relay routing metadata.

A route selects a profile/principal allowlist. Target must match its directory,
provider, launch-time Git project and profile/route revisions. First scope:
existing sessions. A coordinator may launch, wait for readiness, then enqueue;
automatic launch-on-arrival is not implemented.

Durable task acceptance precedes acknowledgment. The runtime schedules work
without model polling, FIFO per session for all work sources including mark.
Earlier blocked, submitting, submitted or ambiguous work holds later tasks for
the same session; other sessions can proceed. A completed prompt releases its
queue slot while the task awaits its explicit correlated result. Busy, unknown
readiness, draft input, approvals, an
existing lease or absent current authority leave work blocked. Ready/unowned
sessions receive a normal acquiring session-v1 prompt, without takeover or
local-origin injection. Persist `submitting` with a fixed receipt ID before
submission. Reconcile that receipt after restart; ambiguity never retries.
Duplicate enqueue never creates another prompt. Leases follow existing
release/expiry rules; the scheduler does not renew or take them over.

States: `queued`, `blocked`, `submitting`, `submitted`, `awaiting_result`,
`completed`, `failed`, `cancelled`, `expired`, `outcome_unknown`. A completed
prompt receipt means `awaiting_result`, not task completion. The originating
authorized coordinator publishes a correlated result and calls work_complete
with its immutable snapshot. Identical completion is idempotent; conflicts
are refused. The coordinator owns result routing and workflow limits.

## Replies, durability and integration

Success: `host_work_result`, fresh `id`, request `re`, `host`, `attachment_gen`,
`channel_id`, and `result`. Result `kind` is `profiles`, `launch` or `work`,
with a corresponding body. The additive [message API](atem-messages-v1.md)
also returns `kind: message`; uploads return `kind: attachment`. Launch body: request/session/process IDs and state.
Work body: task/receipt IDs, state, detail and nullable explicit result.
Errors use ordinary encrypted session errors: busy, forbidden, unauthorized,
stale_target, invalid_request, request_id_reused.

`Attached::send` tracks at most 64 exchanges and verifies host/channel/
attachment/request correlation before emitting `Event::Family` with family
`session` and host_work_result data. Swift/Kotlin/WASM use their existing
Family JSON event. Query operations recover status after lost replies.
Unsolicited status subscriptions are not implemented in this increment.

`<config>/runtime/host-work.sqlite` uses synchronous commits and binds to one
account/host/trust generation. Limits: 4,096 launch identities, 4,096 work
identities, 256 unfinished tasks. Tombstones outlive the session list; capacity
returns busy. No silent eviction can turn an old retry into new work.
Administrative archival/compaction requires a future contract. Deleting the
database is not a safe retry strategy. Preserve it on host identity changes;
the old binding fails closed.

Station owns atomic publication/outbox, replay/cursors, replica-safe delivery,
lost-ack recovery, result routing and delivery while local Astation is selected.
This document specifies the receiver acknowledgment, not a Station HTTP API.
Astation owns New Agent/route/status UX. Existing hosted execution rollout
policy remains unchanged.

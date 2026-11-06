# Host work v1: launch, directed work, messages and attachments

Status: implemented and released (Atem v0.8.2).

This extension of atem-session r9 lets an admitted client create sessions
through launch profiles the host owner approved, queue directed work, publish
messages and upload task screenshots. Configuration, scheduling behavior and
limits are described in [../agent-hosting.md](../agent-hosting.md). Channels,
principals and scopes are the r9 appendix of
[atem-session-v1.md](atem-session-v1.md); the protocol overview is
[README.md](README.md).

Types: `atem_client::session::{host_work, messages, attachments, mark}`. Host:
`src/runtime/host_work.rs`, `host_work_bridge.rs`, `host_attachments.rs`.
Shared request vectors: `fixtures/host-work/requests-v1.json`, run by the
client core's tests and listed in every SDK's checksum manifest.

Local collaboration (stage 1, unreleased) reuses these receipts inside one
runtime; see [../agent-collaboration.md](../agent-collaboration.md). Its shared
types include `select`, optional message correlation fields, and locally
stored `result` context snapshots. The host advertises `host.reply` (§4,
`reply_query`) but not `host.select`;
remote host admission refuses selector destinations, the `local` sender,
local UUIDv5 task references and `result` context snapshots. Remote admission
still requires the contract below. Cross-instance selector/result support waits for
the stage-2 agreement.

## 1. Features and transport

| Feature | Ops |
|---|---|
| `host.launch` | `host_profiles`, `host_launch`, `host_launch_query` |
| `host.work` | `work_enqueue`, `work_query`, `work_cancel`, `work_complete` |
| `host.reply` | `reply_query` |
| `host.messages` | `message_publish`, `message_query` |
| `host.attachments` | `attachment_put` |

A host lists all five in r9 `welcome.features` when hosting is enabled and
healthy and its work database is open, else none; an r8 host never does.
Clients check the feature before sending. When hosting turns off under an open
channel, or 64 host-work requests already wait for the host's next pass, a
request is `busy` ("agent hosting is disabled or busy").

Requests are `session` messages inside an admitted `atem-ch1` channel. They
name the host, not a session binding (example in §3). Every request:

- has `v: 1` and an `id` that is a fresh UUID v4 per exchange. A retry sends a
  new `id` with the same content.
- has a `host` equal to the channel's `welcome` (`account_id`,
  `atem_device_id`, `host_trust_gen`); otherwise `stale_target`.
- is at most 256 KiB, strict JSON: no duplicate keys, integers only, each at
  most 2^53 − 1.
- has exactly the fields below. Unknown fields are `invalid_request`, and the
  request must serialize back to the same JSON, so optional fields are omitted,
  never `null` or empty (`attachments`, `mark`).

Formats: a UUID v4 is lowercase; an opaque id is 1–128 bytes of
`[A-Za-z0-9._:-]`; a digest is lowercase hex SHA-256 (64 characters); a
session id is `ses-` plus 12 characters of `a`–`z` and `2`–`7`; times are Unix
milliseconds on the host's wall clock.

## 2. Authority

### Ops

R9.6 gains three ops for service `scope.ops` and browser grant `ops`:

| Op | Requests | Control op |
|---|---|---|
| `launch` | `host_profiles`, `host_launch`, `host_launch_query` | yes |
| `notify` | `work_enqueue`, `work_query`, `reply_query`, `work_cancel`, `work_complete` | yes |
| `message` | `message_publish`, `message_query`, `attachment_put` | no |

A native member needs the `control` role for the `launch` and `notify`
requests; the `message` requests are open to every native member. The channel
checks the op before decoding (`forbidden`). Existing grants don't gain these
ops. Membership verifiers older than these ops reject signed entries that
carry them: upgrade every verifier on the account before enrolling one.

### Host checks

Each request resolves the caller's authority again from the current device
list. Held, frozen or faulted membership, a halted journal, an expired
channel, a browser quarantine, or a key that differs from the channel's is
`unauthorized`.

- **Launch.** The profile's `principals` name the caller (none listed: the
  paired Astation's `member:<id>`). The caller's scope has no `sessions`
  restriction, and a `projects` restriction covers the profile's project.
- **Work.** The route's `principals` name the caller (same default). The caller
  holds `notify` and `prompt`, its `control_gen` equals the one recorded at
  enqueue, its scope covers the target session, and the target still matches
  the route's profile (§4). Checked at enqueue, on every query and before
  dispatch.
- **Messages.** Browsers are `forbidden`. The envelope's `sender` equals the
  channel's principal. Destination rules are in §5.
- **Uploads.** Browsers are `forbidden`. A service's `scope.hosts` includes
  this host.

The host records the principal of each launch, task and message, and the
principal's key for tasks, messages and uploads. A query from another
principal or key is `forbidden`. A launch or task id reused with other content
or by another principal is `request_id_reused`; a message id reused by another
sender is `forbidden`.

## 3. Launch

| Op | Fields | Result `kind` |
|---|---|---|
| `host_profiles` | — | `profiles` |
| `host_launch` | `request_id`, `profile_id`, `profile_revision`, `expires_at` | `launch` |
| `host_launch_query` | `request_id` | `launch` |

```json
{"type":"session","data":{"v":1,"op":"host_launch","id":"11111111-1111-4111-8111-111111111111",
  "host":{"account_id":"account","atem_device_id":"host","host_trust_gen":1},
  "request_id":"22222222-2222-4222-8222-222222222222",
  "profile_id":"backend","profile_revision":1,"expires_at":1793620800000}}
```

- `request_id`: UUID v4 chosen by the client and kept across retries.
- `profile_id`: opaque id. `profile_revision`: at least 1, equal to the
  profile's current revision (else `forbidden`).
- `expires_at`: later than now and at most 24 h ahead (else
  `invalid_request`). The host refuses to spawn after it.
- Commands, arguments, paths and environment values are never accepted.

The host checks, in order: the profile and the caller's permission
(`forbidden`); an existing `request_id` (the same principal and the same
digest over host, profile id, revision and expiry return the recorded status,
even after expiry; anything else is `request_id_reused`); the expiry
(`invalid_request`); the live-session limit (`busy`); the durable reservation
(`busy` when full or on a storage failure).

`host_profiles` lists only the profiles the caller may launch; `host_launch`
and `host_launch_query` return the launch's status:

```json
{"kind":"profiles","profiles":[{"id":"backend","revision":1,"label":"Backend Codex","provider":"codex"}]}
{"kind":"launch","launch":{"request_id":"…","session_id":"ses-abcdefghijkl","process_gen":"…","state":"starting"}}
```

States: `starting` (request, session id and process generation reserved
durably before this reply), `started` (the worker launched the agent; not chat
readiness), `failed` (nothing was started) and `outcome_unknown` (it may have
started; never retried). At a runtime restart, `starting` becomes `started`
when a worker with the reserved process generation was adopted, else
`outcome_unknown`.

`host_launch_query` returns the caller's own launch. An unknown id, another
principal's launch, or a profile that was removed, changed revision or no
longer allows the caller is `forbidden`.

A started session appears in the registry (`list`, `session_changed`) under
the returned `session_id` and `process_gen`. Send prompts through the normal
receipts once its activity is `ready`.

## 4. Directed work

| Op | Fields | Result `kind` |
|---|---|---|
| `work_enqueue` | `route_id`, `route_revision`, `task` | `work` |
| `work_query` | `task_id` | `work` |
| `work_cancel` | `task_id` | `work` |
| `work_complete` | `task_id`, `result` | `work` |
| `reply_query` | `task_id` | `reply` (feature `host.reply`) |

### Task

```json
{"task_id":"…","workflow_id":"…","expires_at":1793620800000,
 "target":{"account_id":"account","atem_device_id":"host","host_trust_gen":1,
           "session_id":"ses-abcdefghijkl","process_gen":"…"},
 "prompt":"Add the /v2/orders endpoint",
 "context":[{"kind":"vault","id":"api-contract","version":3,"digest":"<SHA-256 of text>","text":"…"}]}
```

| Field | Rule |
|---|---|
| `task_id`, `workflow_id` | UUID v4; `task_id` is the task's identity |
| `target` | the request's host triple, a session id and a UUID v4 `process_gen` |
| `expires_at` | later than now and at most 24 h ahead at enqueue (else `invalid_request`) |
| `prompt` | not blank, at most 17 KiB, no NUL |
| `context` | 0–8 context snapshots |
| `attachments` | optional: 1–4 distinct screenshot descriptors (§6); omitted when none |

A context snapshot, also the shape of a result, has `kind` (`memory` or
`vault`), `id` (opaque id), `version` (at least 1), `digest` (SHA-256 of the
UTF-8 `text`) and `text` (at most 128 KiB, no NUL). The host checks the
digest, not that the content was published or that the sender may read it:
the publisher vouches for both. The host renders the prompt as:

```text
[Atem task <task_id> / workflow <workflow_id>]
<prompt>

[Context Vault:<id> version <version> sha256 <digest>]
<text>
```

The rendered prompt is at most 32,768 bytes (28,672 with attachments, which
leaves room for the paths the host appends) and has no control characters
other than newline and tab.

### Enqueue

The route names a profile. The target must be a session on this host with the
same `process_gen` and the profile's directory, provider and project key; it
may have been launched locally or remotely.

The host checks, in order: the route (`forbidden` when unknown); an existing
`task_id` (the same principal and the same digest over host, route id,
revision and task return the status while the route still allows the caller,
else `forbidden`; anything else is `request_id_reused`); permission and
target (`forbidden`); the expiry (`invalid_request`); storage (`busy` at a
capacity limit or on a storage failure). The reply follows the durable
`queued` record.

### Status

```json
{"kind":"work","work":{"task_id":"…","receipt_id":"…","state":"blocked","detail":"terminal has unsent input","result":null}}
```

| State | Meaning |
|---|---|
| `queued` | accepted, not yet scheduled |
| `blocked` | waiting; `detail` says why |
| `submitting` | the dispatch intent is durable; the prompt is being submitted |
| `submitted` | the prompt's receipt is accepted or executing |
| `awaiting_result` | the prompt's turn ended; no result yet |
| `completed` | `work_complete` stored the result |
| `failed` | the prompt was rejected, or couldn't be built |
| `cancelled` | cancelled before submission |
| `expired` | not submitted by `expires_at`, or still `awaiting_result` at it (detail `expired awaiting a result`) or `outcome_unknown` (detail `expired with its outcome unknown`) |
| `outcome_unknown` | the submission is uncertain; never resubmitted; `expired` at `expires_at` |

`receipt_id` (UUID v4, fixed at enqueue) is the session-v1 `request_id` of the
prompt. `detail` is display text of at most 1024 bytes; clients don't parse
it. `result` is a context snapshot exactly when the state is `completed`, else
`null`.

### Dispatch

Tasks of one session run in enqueue order. A task that is queued, blocked,
submitting, submitted or `outcome_unknown` holds the later tasks of its
session (an `outcome_unknown` one until it expires at `expires_at`); one
awaiting its result doesn't. A task is dispatched when the
sender has an authorized channel open that passes the work checks, the session
is live with chat and `ready`, the terminal has no unsent input, nobody holds
the lease, no approval is open on the session, and its attachments are
verified. The host then records `submitting` and submits on the sender's
attachment:

```json
{"type":"session","data":{"v":1,"op":"submit","id":"…","binding":{…},"request_id":"<receipt_id>",
  "kind":"prompt","payload":{"text":"<rendered prompt>"},"acquire":true}}
```

The receipt sets the task's state: `accepted` or `executing` →
`submitted`, `completed` → `awaiting_result`, `rejected` → `failed`,
`outcome_unknown` → `outcome_unknown`. No receipt after the submit, or a task
found `submitting` at a restart, is `outcome_unknown`; it is reconciled from
the receipt journal when a receipt exists. A task is never submitted twice.
The host never renews or takes over a lease for it.

### Query, cancel, complete

Each names the caller's own task under a route that still allows the caller;
anything else is `forbidden`. An `outcome_unknown` task is reconciled from its
receipt first.

- `work_query` returns the status.
- `work_cancel` moves `queued` or `blocked` to `cancelled` (again on
  `cancelled`: the same status). Other states are `busy`. It never interrupts
  a turn; use session-v1 `interrupt`.
- `work_complete` carries `result`, a context snapshot. From
  `awaiting_result` it moves to `completed`. The same result again returns the
  status; another result is `request_id_reused`; other states are `busy`.

### Reply

The agent working on a task submits one reply with `atem message reply`, for a
task of any sender (see
[../agent-collaboration.md](../agent-collaboration.md), section 10). The
sender reads it with `reply_query` (feature `host.reply`). A reply is
read-only data: it never completes the task (`work_complete` does, whether or
not the sender read the reply, and with the sender's own result snapshot), and
no existing message or status changes. While a reply exists the task's
`detail` says how it stands ("reply submitted", "reply received; publishing its
context", "reply refused (…)"). A submitted reply proves the prompt's turn ran,
so it moves an `outcome_unknown` task to `awaiting_result`.

```json
{"type":"session","data":{"v":1,"op":"reply_query","id":"11111111-1111-4111-8111-111111111111",
  "host":{"account_id":"account","atem_device_id":"host","host_trust_gen":1},
  "task_id":"22222222-2222-4222-8222-222222222222"}}
```

`task_id` is a UUID v4: a task's id, or the `recipient_id` of an agent
recipient (§5). The result is `{"kind":"reply","reply":null}` while the task
has no reply, else:

```json
{"kind":"reply","reply":{"result_id":"6ba7b810-9dad-51d1-80b4-00c04fd430c8","state":"submitted",
  "digest":"<SHA-256 hex>","text":"Done: /v2/orders is live",
  "context":[{"kind":"vault","id":"api-contract:3","version":1,"digest":"…","text":"…"}],
  "submitted_at":1793620800000}}
```

| Field | Meaning |
|---|---|
| `result_id` | UUID v5 of the task id: the same for every reply to the task, a corrected one included |
| `state` | `publishing`, `submitted` or `refused` (below) |
| `digest` | SHA-256 (hex) identifying the reply's content: the same for an identical retry, another for a corrected reply. Compare it; don't recompute it |
| `text` | the reply text: at most 16 KiB, no control characters other than newline and tab |
| `context` | 0–8 published context snapshots (§4), exact bytes; empty unless `submitted` |
| `submitted_at` | Unix ms on the host's clock when the reply became `submitted`; `null` before |

| State | Meaning |
|---|---|
| `publishing` | the reply is recorded and its context is still being published; `context` is empty, `submitted_at` is `null`. Query again |
| `submitted` | final: the text and the published context. The reply is not changed afterwards, and an identical retry returns it |
| `refused` | the host refused the reply (for example its context can't be delivered within the task bounds); `context` is empty. The task's `detail` (`work_query`) says why, and the agent's corrected reply replaces this one under the same `result_id` |

The host checks exactly what `work_query` checks, in the same order: only the
principal and key that enqueued the task (or sent the message), under a route
that still allows it, may read its reply. Anyone else, an unknown task and a
caller without the `notify` op get the answer `work_query` gives them for that
task, `forbidden`. A task of the host's own `local` sender can't be asked at
all: its id is a UUID v5, which `reply_query` (like `work_query`) refuses at
decode as `invalid_request`. An `outcome_unknown` task is reconciled from its
receipt first. Storage failure is `busy`. A reply may exist while the task is
still `submitted` (the agent replies in its turn), and a task can end with no
reply (a silent turn): poll `reply_query` for the reply and `work_query` for
the task.

## 5. Messages

| Op | Fields | Result `kind` |
|---|---|---|
| `message_publish` | `message` | `message` |
| `message_query` | `message_id` | `message` |

### Envelope

```json
{"message_id":"…","workflow_id":"…","sender":"member:phone",
 "created_at":1793620800000,"expires_at":1793620860000,
 "recipients":[{"recipient_id":"…",
   "host":{"account_id":"account","atem_device_id":"backend","host_trust_gen":1},
   "destination":{"kind":"host"}}],
 "text":"The backend contract is ready to review","context":[]}
```

| Field | Rule |
|---|---|
| `message_id`, `workflow_id` | UUID v4 |
| `sender` | `member:<id>` or `service:<id>`, equal to the channel's principal |
| `created_at`, `expires_at` | `expires_at` after `created_at`, at most 24 h later |
| `recipients` | 1–32, one `account_id`, distinct `recipient_id`s and destinations |
| `text` | at most 16 KiB, no control characters other than newline and tab |
| `context` | 0–8 context snapshots (§4) |
| `mark` | optional (§6); omitted when absent |

The envelope's optional `kind`, `reply_to` and `from_session` belong to local
collaboration ([../agent-collaboration.md](../agent-collaboration.md), section
7): a remote `message_publish` carrying `from_session` or `reply_to`, or a
`kind` other than `request`, is refused: `unsupported_version`, or
`invalid_request` when the envelope doesn't decode (a `kind` other than
`request` needs a `reply_to`).

A message has text that isn't blank, context or a mark, and serializes to at
most 240 KiB. At first acceptance `created_at` is at most 60 s ahead of the
host's clock and `expires_at` is in the future (else `invalid_request`).

A recipient has a UUID v4 `recipient_id`, a `host` triple and a
`destination`:

| `destination` | Fields | Effect |
|---|---|---|
| `{"kind":"host"}` | — | a durable notice; no agent input |
| `{"kind":"project",…}` | `route_id`, `route_revision` | a durable notice for the route's project; no agent input |
| `{"kind":"agent",…}` | `route_id`, `route_revision`, `target` | one task (§4) |

An agent destination's `target` is in its recipient's host. Two agent
recipients can't name the same target, and other destinations can't repeat
on one host. A `message_publish` names a host that has at least one recipient.

An agent recipient becomes a task with `task_id` = `recipient_id`, the
message's `workflow_id`, `target`, `expires_at` and `context`, the prompt
`[Message <message_id> from <sender>]` followed by the text (and the mark), and
the mark's screenshot as its attachment. It must be a valid task (§4).

The message digest is the lowercase hex SHA-256 of the JCS form of the
envelope; recipient order counts.

### Publish

For each of this host's recipients, in envelope order, the delivery is
`{"state":"stored"}` (a notice), `{"state":"work","work":{…}}` (a queued task)
or `{"state":"refused","code":"forbidden"}` when the sender may not reach it:

- Host notice: any native member; a service without `projects` or `sessions`
  restrictions whose `hosts` include the recipient's host.
- Project notice: the route exists at that revision; any native member; a
  service without a `sessions` restriction whose scope covers the host and the
  route's project.
- Agent: the route as above, the target in scope, and every work check of §4.

The envelope, every decision and every task commit in one transaction before
the reply. At a capacity limit or on a storage failure nothing is kept and the
reply is `busy`. A refusal is final for that `message_id`.

The host checks, in order: the `message` op and not a browser (`forbidden`);
`sender` equal to the channel's principal (`forbidden`); an existing
`message_id` (another sender or key is `forbidden`, other content
`request_id_reused`, the same content returns the current receipt, or
`forbidden` if an accepted recipient left the caller's scope); the times
(`invalid_request`); the commit (`busy`).

```json
{"kind":"message","message":{"message_id":"…","digest":"…","sender":"member:phone","recipients":[
  {"recipient_id":"…","delivery":{"state":"stored"}},
  {"recipient_id":"…","delivery":{"state":"work","work":{"task_id":"…","receipt_id":"…",
    "state":"queued","detail":"waiting for a ready agent","result":null}}}]}}
```

The receipt lists this host's recipients only. In a receipt, `work.result` is
a reference `{"kind","id","version","digest"}` without text; `work_query` with
the recipient id returns the whole snapshot. A receipt may carry the codes
`forbidden` and `stale_target`; this host sends only `forbidden`.

`message_query` returns the sender's own message with current task progress;
an unknown id is `forbidden`. A message's tasks are ordinary tasks:
`work_query`, `work_cancel` and `work_complete` take the recipient id.

`Message::publications()` builds one `message_publish` per distinct host, each
carrying the whole envelope. It keeps nothing: the client retains the envelope
and retries each host with a fresh `id` until it accepted.

## 6. Attachments and mark

### `attachment_put`

```json
{"type":"session","data":{"v":1,"op":"attachment_put","id":"…","host":{…},
  "attachment":{"attachment_id":"22222222-2222-4222-8222-222222222222",
    "digest":"<SHA-256 of the PNG>","size":123456,"media_type":"image/png"},
  "offset":0,"data":"<standard padded base64 of this chunk>"}}
```

| Field | Rule |
|---|---|
| `attachment_id` | UUID v4 |
| `digest` | SHA-256 of the whole PNG |
| `size` | 33 to 8,388,608 bytes |
| `media_type` | `image/png` |
| `offset` | byte offset, below `size` |
| `data` | standard padded base64 of 1–98,304 bytes; `offset` plus its length at most `size` |

- A new upload starts at offset 0 (else `invalid_request`).
- The descriptor equals the first chunk's (else `request_id_reused`).
- A chunk at the received length is appended. One before it must lie within
  the stored bytes and equal them (it returns the progress), else
  `request_id_reused`. One past it is a gap: `invalid_request`.
- The chunk that completes the upload is kept only if the digest matches and
  the bytes are a PNG: signature, an `IHDR` first chunk, width and height
  1–16,384, area at most 40,000,000 pixels. Otherwise `invalid_request`.
- A new upload past 256 uploads or 128 MiB of declared sizes is `busy`.

Each chunk is durable before the reply,
`{"kind":"attachment","upload":{"attachment":{…},"received":98304,"ready":false}}`;
`ready` is true exactly when `received` equals `size`. After a lost reply or a
restart, send the chunks again from offset 0 (stored ones return the
progress) or from `received`.

Uploads belong to the uploading principal and key. A task can use only the
uploads of the sender that enqueued it. An upload grants no agent input.

### Mark

`message.mark` makes a message a Chisel/mark task. Every recipient is an
`agent` destination. Text and context may be empty.

```json
{"mark_id":"mark_1793620800000_abcd12","url":"http://localhost:3000/","title":"Settings",
 "screenshot":{"attachment_id":"…","digest":"…","size":123456,"media_type":"image/png"},
 "annotations":[{"tool":"arrow","text":"Make this red","x":320,"y":160}]}
```

| Field | Rule |
|---|---|
| `mark_id` | opaque id: a source correlation id, not a file name |
| `url` | at most 2048 bytes; text only, never fetched |
| `title` | at most 512 bytes |
| `screenshot` | an attachment descriptor |
| `annotations` | at most 128: `tool` ≤ 32 bytes, `text` ≤ 1024 bytes, `x`, `y` integer pixels 0–16,384 |

The rendered mark is at most 16 KiB with no control characters other than
newline and tab. At dispatch the host verifies each attachment, writes it to a
private file and appends to the prompt:

```text
[Verified screenshot <attachment_id> sha256 <digest>]
Read this PNG: <path>
```

A missing or incomplete upload blocks the task ("waiting for verified
screenshot attachments"). If the paths push the prompt over 32,768 bytes the
task fails.

The ID-only `markTaskAssignment` on the Astation link is answered with
`markTaskResult{success: false}` and a message to upgrade the sender. Atem
reads no `.chisel/tasks/` file and writes no input for it.

## 7. Replies and errors

Every success is a `host_work_result`:

```json
{"type":"session","data":{"v":1,"op":"host_work_result","id":"<fresh UUID v4>","re":"<request id>",
  "host":{…},"attachment_gen":"<the channel's>","channel_id":"<the channel's>",
  "result":{"kind":"profiles|launch|work|reply|message|attachment",…}}}
```

A failure is the ordinary encrypted session `error` with `re` set to the
request's `id`:

| Code | When |
|---|---|
| `forbidden` | a missing op or local consent, out of scope, an unknown id or another principal's, a sender mismatch |
| `unauthorized` | the caller's authority is no longer current |
| `stale_target` | the host triple doesn't match |
| `invalid_request` | decoding, a field rule, an expiry, an upload gap, bad PNG bytes |
| `request_id_reused` | the same id with other content |
| `busy` | hosting off, too many queued requests, a capacity limit or storage failure, the live-session limit, cancel or complete in the wrong state |

After a lost reply, query (`host_launch_query`, `work_query`, `reply_query`,
`message_query`) or resend the same content with a fresh `id`. Never mint a
new `request_id`, `task_id` or `message_id` for the same intent.

## 8. Client core

`Attached::send` decodes these requests with the host's rules, checks the host
triple and the feature against `welcome`, refuses a duplicate exchange `id`
and keeps at most 64 exchanges outstanding. A `host_work_result` is accepted
only on the channel's `attachment_gen` and `channel_id`, for an outstanding
exchange it answers (same host and ids; for a `reply_query` a `reply` result,
bounded as above; for a message the digest, sender and
this host's recipient ids in order; for an upload the descriptor and progress
past the chunk; for `work_complete` the same result), and is emitted as
`Event::Family` (family `session`). A session `error` with `re` ends the
exchange. The Swift, Kotlin and WASM bindings use the existing Family JSON
event.

## 9. Host storage

`<config>/runtime/host-work.sqlite` keeps launches, tasks, messages with their
receipts, and upload bytes, each durable before its reply, bound to one host
triple (a new identity moves it aside and starts an empty one; see
[agent hosting](../agent-hosting.md#9-durable-records)). Records are pruned a
day after their `expires_at` once settled: a task completed, failed, cancelled
or expired (with its reply), a message whose tasks all go, a launch no longer
`starting`, an upload no remaining task names. A live task, and its message,
launch and uploads, is never pruned. A retry of a pruned request names an
`expires_at` that passed, so it is `invalid_request` and never becomes work; a
query for a pruned id is `forbidden`, as for an unknown one. Nothing is
evicted: at a limit (4,096 launches, tasks or messages; 256 unfinished tasks,
that is queued, blocked, submitting or submitted; 256 uploads or 128 MiB) new
requests are `busy`.

## 10. Planned (not implemented)

- **Not implemented:** progress events. Launch, task and message status are
  query-only.
- **Not implemented:** launch on arrival. An agent destination names an
  existing live session.
- **Not implemented:** store-and-forward. Channel records can't be replayed on
  a new channel, so a Station can't deliver a stored envelope for its sender,
  and dispatch needs the sender's live channel. There is no origin proof and no
  host-to-host sender.
- **Not implemented:** resolving an `outcome_unknown` task by hand (a reply
  its agent submits moves it to `awaiting_result`; otherwise it expires at
  `expires_at`), and archival or compaction of the host's records.

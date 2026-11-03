# Task screenshots and Chisel/mark

Status: Atem receiver and online Chisel/Station sender implemented locally,
2026-11-02. Sender branches live in sibling `chisel-online-mark` and
`Astation-online-mark` worktrees. ID-only clients require upgrading. Offline
delivery is outside this increment at the user's request. No deployment or
hosted-execution activation is included. Native SDK/grant rollout remains
necessary before live enrollment.

## One task queue

Chisel/mark is an executable [message](atem-messages-v1.md). It uses the same
route, sender authorization, durable work record, scheduler, prompt receipt and
explicit result as other directed work. Both Claude and Codex use this path
when chat readiness is available. There is no separate mark queue, model triage,
background `claude -p`, or local-origin input exception.

The queue is FIFO per target session in durable insertion order. An earlier
blocked task holds later tasks for that session; unrelated sessions can run
independently. A submitted or uncertain task holds its session until its receipt
resolves. Once a turn ends, the task awaits an explicit result while the next
turn may run, subject to the usual readiness, approval, draft, authority and
lease checks. The scheduler never renews or takes over a controller's lease.

An old `markTaskAssignment {taskId, receivedAtMs}` receives a failed
`markTaskResult` explaining the required upgrade. It cannot name an authenticated
sender, target process or immutable screenshot. Atem no longer reads arbitrary
`.chisel/tasks/<id>.json` files in response to that notification. Existing
Chisel/mark execution requires the sender migration before using this build.

## Save, transfer, then publish

1. Chisel saves its task JSON and annotated PNG as it does today. That local
   copy supports editing/retry and is not assumed to exist on the Atem machine.
2. The publishing client obtains the actual PNG bytes through a bounded,
   authorized Chisel/Astation handoff. A task ID or local path alone is not a
   transfer mechanism. Chisel's server middleware now supplies bytes to Station's
   authenticated online marks endpoint; its credential stays in the server env.
3. The client freezes the PNG bytes, UUID v4 attachment ID, lowercase SHA-256
   digest, byte size, and `image/png` media type. It opens an admitted encrypted
   atem-ch1 channel to the selected host and checks `host.attachments`.
4. Upload ordered chunks with `attachment_put`. Wait for a durable reply to
   each chunk. Retain bytes/IDs for retries; do not recapture under the same ID.
5. Publish one `message_publish` with `mark`, the screenshot descriptor, and
   an approved `agent` destination. Check `host.messages` too. Uploading first
   gives the best experience. Publishing early is allowed: work stays blocked
   with `waiting for verified screenshot attachments` until bytes are complete.
6. Atem verifies and materializes the PNG in its private cache and appends the
   local path to the ordinary agent prompt. The agent reads that file using its
   normal image/file tools and permissions. The agent is not sent base64 text.
7. Track the original message's recipient/task receipt. A turn ending is
   `awaiting_result`, not proof the UI change succeeded; report the correlated
   outcome through `work_complete` as for other tasks.

Screenshots are binary task attachments, not memory/vault entries. A small
message references an immutable artifact; memory/vault can hold the resulting
textual context and outcome. No screenshot URL is fetched by the runtime.

## Upload operation

`attachment_put` is a session message inside the existing encrypted channel.
It is enabled with runtime hosting and requires native membership or a service
with `message` permission, within the current host scope. Browser clients are
refused. Uploading bytes grants no agent input or launch permission. Publication
and execution still require the route's `notify`/`prompt` authority and consent.

```json
{"type":"session","data":{
  "v":1,"op":"attachment_put","id":"11111111-1111-4111-8111-111111111111",
  "host":{"account_id":"account","atem_device_id":"host","host_trust_gen":1},
  "attachment":{
    "attachment_id":"22222222-2222-4222-8222-222222222222",
    "digest":"<64 lowercase SHA-256 hex characters>",
    "size":123456,"media_type":"image/png"
  },
  "offset":0,"data":"<standard padded base64 of this chunk>"
}}
```

`offset` is a byte offset, not a chunk number. Each chunk is nonempty and at
most 96 KiB decoded. A PNG is 33 bytes through 8 MiB. The final chunk must end
at exactly the declared size. The request remains below the 256 KiB bound.
Success is `host_work_result` with `result`:

```json
{"kind":"attachment","upload":{
  "attachment":{"attachment_id":"…","digest":"…","size":123456,"media_type":"image/png"},
  "received":98304,"ready":false
}}
```

The attachment descriptor is identical in every chunk and in the task. A fresh
exchange `id` retries the same offset and bytes; already stored matching chunks
return current progress. Lost replies/restarts can be recovered by replaying the
original chunk sequence from offset zero, skipping to `received` after a reply.
An overlapping chunk must be wholly stored and match exactly. Gaps and malformed
chunks return `invalid_request`; changed descriptor or bytes return
`request_id_reused`. Capacity/storage failure returns `busy`. The final chunk
commits only when the complete byte digest, PNG signature and bounded IHDR
dimensions pass. Pixel decoding remains the provider image tool's job.

Uploads are bound to the current principal **and public key**, in the
account/host/trust-bound work database. Another sender/key cannot finish or
resolve an upload. Forwarding must preserve the admitted publisher: a service
may publish as itself with its own authority, not assert a user's sender label.
No extra bearer token is needed inside the already authenticated channel.

## Mark payload

`message_publish.message` gains an optional `mark` field. Omit it for ordinary
messages. For a mark task, all recipients must be `agent` destinations:

```json
{"mark_id":"mark_1793620800000_abcd12",
 "url":"http://localhost:3000/","title":"Settings",
 "screenshot":{"attachment_id":"22222222-2222-4222-8222-222222222222",
   "digest":"<64 lowercase SHA-256 hex characters>","size":123456,"media_type":"image/png"},
 "annotations":[{"tool":"arrow","text":"Make this red","x":320,"y":160}]}
```

The URL is descriptive text, never a fetch target. `mark_id` is an opaque source
correlation ID, not a filename. `recipient_id` remains the queue task ID.
Coordinates are nonnegative integer screenshot pixels (round producer floats),
at most 16384. Title ≤512 bytes, URL ≤2048, ≤128 annotations, each tool ≤32 bytes
and text ≤1024. The rendered mark body is ≤16 KiB; the complete task prompt
retains its normal bounds/control-character checks. A mark can supply the
content when the envelope's `text` and `context` are empty.

Direct `work_enqueue.task` also accepts optional `attachments` (omit when empty),
up to four unique descriptors. Shared client types are `session::attachments`
and `session::mark`; Swift/Kotlin/WASM use the existing Family JSON interface.

## Persistence and limits

Chunk bytes and immutable descriptors commit to `runtime/host-work.sqlite`
before acknowledgment. They survive broker restarts and are independent of
prompt submission, so upload retry never resubmits a task. Materialized PNGs
live under `<config>/runtime/attachments/<sender-key-hash>/<attachment-id>.png`.
Directories/files are private; remote paths, filenames, URLs and symlinks are
not followed. The cache is regenerated from verified database bytes before
dispatch, repairing deletion/edits. Local files and SQLite are owner-private,
not encrypted at rest, like the existing task store. Avoid putting secrets in
screenshots.

Limits: 256 attachment identities and 128 MiB of declared/reserved bytes per
host store, including partial uploads. Materialized copies can use another
128 MiB plus temporary/journal overhead. No automatic eviction exists yet;
capacity refuses uploads. Retention/archival needs a future contract that keeps
queued references and retry identities valid; deleting the database is not a
safe way to retry. Uploads do not start agents. Agent/task expiry and cancellation
do not currently remove attachment bytes.

## Online sender boundary

Chisel resolves the configured session's fresh process target, freezes IDs and
PNG bytes, then POSTs to Station's authenticated
`/api/agent/v1/integrations/:id/hosts/:host/sessions/:session/marks` endpoint.
Station validates the image and service authority, uploads over one R9 channel,
then publishes as that service. Its NDJSON response owns the channel until task
turn-end, disconnect, authorization loss or a ten-minute deadline. No offline
outbox, replay or automatic retry is included. Chisel reports success only after
durable acceptance, preserves files/IDs on failure, and monitors from Node after
the browser save response returns. Lost acceptance is uncertain; turn-end remains
`awaiting_result`.

New service grants opt in with `markTasks: true` during native provisioning,
adding `message`/`notify` to approved `view`/`prompt`. Existing grants stay unchanged.
Upgrade the shared SDK and all account membership verifiers before enrolling
these ops; the Apple package is not yet upgraded. The public hosted API gate
stays intact. Dispatch still requires the sender's live authorized channel.

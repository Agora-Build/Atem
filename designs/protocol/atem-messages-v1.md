# Atem messages

Status: Atem receiver and shared client API implemented locally, 2026-11-02.
This is an additive `host.messages` feature of the admitted atem-ch1 channel.
Station's publication/outbox/replay service, direct Atem host senders and
Astation UI are separate integration work. No production endpoint is enabled.

## Message and destinations

Regular messages and context notifications share one immutable envelope:

```json
{
  "message_id": "11111111-1111-4111-8111-111111111111",
  "workflow_id": "22222222-2222-4222-8222-222222222222",
  "sender": "member:phone",
  "created_at": 1793620800000,
  "expires_at": 1793620860000,
  "text": "The backend contract is ready to review",
  "context": [],
  "recipients": [{
    "recipient_id": "33333333-3333-4333-8333-333333333333",
    "host": {"account_id": "account", "atem_device_id": "backend", "host_trust_gen": 1},
    "destination": {"kind": "host"}
  }]
}
```

Text, context, or a typed `mark` payload supplies message content.
[Chisel/mark and screenshots](atem-task-attachments-v1.md) use the same queue.
Context uses the exact `ContextSnapshot` from [host work](atem-host-work-v1.md):
`kind`, `id`, positive `version`, SHA-256 `digest` and exact `text`. The runtime
checks the digest and never substitutes a newer version. This increment accepts
snapshots resolved by the authenticated publisher; it neither fetches unresolved
references nor attests that content was committed to Station. A context digest
proves byte consistency, not publication or read permission.

Each recipient has a stable UUID v4 and an exact host identity. Destinations:

| kind | Fields | Behavior |
|---|---|---|
| `host` | none | Durable local notice, no agent input |
| `project` | `route_id`, `route_revision` | Notice for the route's project, no agent input |
| `agent` | `route_id`, `route_revision`, full session `target` | Queue one task through the existing scheduler |

Recipients are resolved once before publication, including session/process
identity for executable delivery. A project notice does not select or start an
agent. Automatic role expansion, launch-on-arrival and context application are
not implemented. The existing approved remote-launch operation can create a
session first.

Bounds: 1–32 recipients in the same account, unique recipient IDs and unique
destinations, at most 16 KiB inline text, 0–8 snapshots, 240 KiB envelope and
256 KiB whole request. Agent deliveries must additionally fit the ordinary
32 KiB rendered prompt and reject terminal controls other than newline/tab.
Expiry must follow creation by at most 24 hours; initial acceptance requires a
future expiry and creation no more than 60 seconds ahead of the host clock.

## Publication and recovery

Requests are `session` messages, with `v:1`, fresh UUID v4 `id` and exact `host`:

| op | Additional fields | Result |
|---|---|---|
| `message_publish` | `message` envelope | Message receipt for this host's recipients |
| `message_query` | `message_id` | Same sender's receipt with current task progress |

`atem_client::session::messages::Message::publications()` creates one publication
per distinct host, keeping the entire original recipient list in each request.
Send requests with `Attached::send`; the shared client validates feature,
host/channel/attachment/request correlation, content digest and recipient list
before emitting the ordinary Family JSON event. Existing Swift/Kotlin/WASM
bindings carry these messages through that API. Retries use a fresh exchange
`id` and exactly the same envelope. The message fingerprint is lowercase
`SHA256(JCS(envelope))`; recipient array order is significant.

Success uses `host_work_result` with `result.kind: "message"` and a `message`
receipt containing `message_id`, `digest`, authenticated `sender` and this
host's ordered `recipients`. Each item contains `recipient_id` and `delivery`:

- `{"state":"stored"}`: durable receipt acceptance, not read or completion.
- `{"state":"refused","code":"forbidden"}`: no task was queued.
- `{"state":"work","work":{...}}`: ordinary independent task progress.

Aggregate work progress contains task/receipt IDs, state, detail and a nullable
result reference (`kind`, `id`, `version`, `digest`), without result text.
`work_query` returns the full completion snapshot. This keeps fanout receipts
bounded even when many recipients publish large results.

One disallowed recipient does not discard permitted recipients. The envelope,
all local recipient decisions and every queued task commit in one local SQLite
transaction before the reply. Capacity or storage failure rolls back all of
them and returns `busy`; it does not acknowledge partial durability. A refusal
is frozen for that message. Later consent requires a new explicit publication,
not replay of the old ID. Changing content, expiry or recipients under the same
message ID is `request_id_reused`. Another sender cannot query the message.

Agent task ID equals `recipient_id`; receipt ID is allocated once. Progress,
cancellation and explicit correlated completion use the existing `work_query`,
`work_cancel` and `work_complete` operations. `message_query` joins the same
durable task record, so progress is not maintained as a second copy. A restarted
runtime reconciles submission receipts; ambiguous execution never resubmits.
`outcome_unknown` requires receipt recovery or explicit operator resolution.

Progress stays on the original message/task receipt. There is no separate
runtime inbox command or user mailbox. Internal acceptance/deduplication records
remain durable even when exited sessions leave the session list. The database
retains up to 4,096 messages and work identities, and 256 unfinished tasks;
it refuses new deliveries at capacity instead of evicting deduplication state.

## Sender identity and execution policy

The runtime obtains the sender from the channel's current authenticated
membership authority. The envelope's `sender` must equal it; the receiver pins
that authority's public key in its private record. Unknown fields, duplicate
JSON keys, unsafe integers, stale host identities, expired channels, removed
members, frozen/held membership and narrowed scopes fail closed. A forwarding
service cannot put `member:phone` in its envelope. Relay routing identities and
vault `writer_id` labels grant no authority.

Native account members can store notices without a separate copied token or a
profile principal allowlist. Scoped services need the explicit `message` op;
it is not a control op and does not confer prompt, approval or launch rights.
Browsers are not admitted to this message API. Session/project-scoped services
cannot address the unscoped host notices; project notices must match the current
route project scope. Message receipts remain within the original sender's
current destination scope.

Agent delivery additionally requires `notify` and `prompt`, current route
principal consent, exact project/provider/directory/process matching and the
durable control generation. Receiving a notice never grants execution rights.
The scheduler waits for readiness, drafts, approvals, leases and the original
sender's live authorized channel. Regrant after fencing does not revive work.
No shell hook, model polling, forced takeover or local-input exception is used.
Executable deliveries are FIFO per session, including Chisel/mark. Earlier
blocked/submitted/uncertain tasks hold later work on that session; other sessions
can proceed independently. A completed turn releases the queue slot while the
original task awaits its explicit correlated result.

Old strict SDKs reject signed membership entries containing the new `message`
op. Upgrade participating verifiers before enrolling or changing such scopes.
Do not enroll live account permissions as part of tests.

## Station integration still required

This receiver is usable by current native/service clients through an end-to-end
channel, including opaque forwarding through Station. It is not a store-and-
forward origin-proof format: encrypted channel records cannot be replayed on a
new channel. Station must not impersonate the original publisher to replay a
stored envelope. Direct Atem senders also require a host sender admission and
proof design; an enrolled host key is not a native/service client identity.

Station owns durable sender publication, per-host pending delivery, reconnect
cursors, cross-replica replay, authorization for context reads, and genuine
atomic write-and-notify with memory/vault. Do not simulate that transaction by
performing a content write followed by an independent notification request.
Offline recipients require retained publication state; `publications()` itself
is an in-memory request builder, not a durable outbox. An integrated app must
retain the original envelope and reconcile each host until Station supplies
this service. Offline sender execution requires a separately verified origin
and current authority admission; the current receiver deliberately waits for
the sender's authorized channel.

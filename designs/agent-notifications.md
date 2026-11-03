# Agent notifications and work across machines

Status: design and local implementation, 2026-11-02. The Atem durable message
receipts and shared task queue, text/context envelope, multiple explicit recipients and readiness-aware
existing-session dispatcher are implemented on the feature branch; see the
[message API](protocol/atem-messages-v1.md) and
[host-work extension](protocol/atem-host-work-v1.md). Station publication/replay,
automatic launch-on-arrival and Astation UI remain planned. The user proposed that an
agent publish context in memory/vault and notify another Atem, whose runtime
then delivers work to a coding agent. The coding agent should not poll for
messages on a timer.

This extends the planned [optional hosting and remote launch](agent-hosting.md).
Existing stores remain [Atem Memory](atem-memory.md) and [Vault](vault.md).
Remote mutations still require the shared
[session protocol](protocol/atem-session-v1.md). New coordination operations,
permissions and encrypted envelopes need a specification before implementation.

## 1. Experience

One machine runs the mobile project's agent; another runs the backend agent.
The mobile agent needs an API change. It publishes the request and contract
in a shared vault, addressed to the backend role. The backend Atem receives
an event, queues the task, and submits it when its agent is ready. The backend
agent publishes a correlated result and notifies the mobile role. Neither
coding agent checks an inbox repeatedly.

```text
Mobile coding agent
  -> publish vault context + work request for backend
     -> Station commits content/reference and durable notification
        -> push event over the backend Atem's persistent connection
           -> backend runtime validates, fetches context, queues task
              -> existing ready agent, or an allowed new worker
                 -> publish result + completion notification to mobile
```

Runtimes wait for network and agent-state events without invoking a model.
Heartbeats, bounded transport retries and reconnect backoff remain runtime
responsibilities. No timer asks a coding agent to run memory searches, vault
reads or an equivalent inbox check.

Remote launch and notifications share one runtime. On the feature branch,
`atem runtime start` starts it in the background or reuses it; `atem runtime
check` validates approved profiles/routes without starting processes. Enable
hosting explicitly to stay online with zero sessions. An offline receiver
cannot receive new events; Station must retain and deliver them after reconnect.
Optional boot-service installation remains separate planned work.

## 2. Context, notification and work

Regular messages and context notifications use the same envelope. It contains
an authenticated sender, one or more resolved recipients, inline text, exact
memory/vault snapshots, or both. A short message needs no vault entry. Content
stores remain canonical; per-recipient delivery and execution progress stays on
the original message/task receipt. Receiving a message and permission to submit agent input
are separate decisions. Native account members need no additional copied
token for ordinary notices; services need a scoped credential. The implemented
receiver checks sender identity against the admitted channel. Durable Station
forwarding and Atem host sender proofs remain separate integration work.

| Item | Responsibility |
|---|---|
| Memory fact or vault entry | Durable context the recipient can read and reference |
| Context-change notification | Tell a runtime that subscribed context changed; optionally sync/apply it |
| Explicit work request | Ask an authorized target to perform a task with referenced context |
| Runtime task queue | Keep accepted work pending while busy, awaiting approval or waiting for launch; Station retains offline delivery |
| Correlated result | Report progress/completion to the originating workflow |

Saving a fact does not automatically start coding work on every machine.
Default context subscriptions update knowledge only. Execution requires an
explicit directed request or an owner-configured subscription authorizing
specific changes to create work. Routine sync, imports and historical replay
must not become new tasks.

Subscriptions are the proposed runtime hooks: match a source/topic and route
it to a configured role. They do not execute arbitrary shell hooks supplied
by an event. Start with explicit directed requests; broader rules can follow
with the same authorization and durable queue.

## 3. Role routing and availability

Use stable role IDs, labeled for example `mobile` and `backend`, scoped to
the account/workflow. An owner-configured role binding selects a host, local
project and launch profile, plus an optional preferred live session. A
hostname such as `Genie` is not a routing or authorization identity.

Mobile and backend may be different repositories. Explicitly grant the
cross-project context access and task route. Account membership or access
to global memory alone does not authorize work in every project.

For a role without a live agent, choose one policy:

- Queue until the owner starts/chooses a session.
- Launch through the approved project/profile and remote-launch path, then
  dispatch after the agent becomes ready.

Select one executor per task. Multiple candidate sessions do not all receive
executable work. A role reassignment advances a routing generation and fences
the old assignment. A task already submitted on the old host is not executed
again on its replacement simply because its result is delayed.

The destination runtime must be online to react immediately. Optional service
hosting keeps it available with zero sessions. An on-demand runtime receives
pending work on its next connection; an event cannot start a process on a
powered-off machine.

## 4. Publication and push

Expose an Atem write-and-notify operation and a separate notify operation for
already committed content. Final CLI/API names are not assigned here; these
commands do not exist today.

A work request identifies its task ID, authenticated sender, destination
role and routing generation, workflow/correlation ID, immutable context
references, expiry and completion destination. Bind these fields and the
content digest under the sender's authority. Instructions belong in protected
content, not free-form routing metadata.

Vault references name an entry and exact version/commit position with a
digest. Memory references identify the immutable fact and validity/revision
state. Later edits must not silently change the instructions that triggered
the task. An agent can read newer context separately.

For write-and-notify, commit content and the notification/outbox record in
one server transaction. Rollback emits no work event. Retried publication
with the same task ID returns its recorded result. Separate notify refuses
missing or uncommitted references. Sender-local memory not synchronized to
the Station remains pending publish, without waking a remote agent early.

After commit, push a small event over the destination runtime's authenticated
connection. Fetch context through authorized memory/vault reads. Protect
event content and sensitive references consistently with the account's
encryption mode. Do not add plaintext instructions, repository names or
credential values to room broadcasts or relay logs.

The current Astation connection selects a local link first and a relay link
as fallback; it is not an existing generic Station event subscription. The
coordination transport must deliver while either route is selected and when
the Astation UI is closed. Specify an independent authenticated Station
subscription or equivalent forwarding with the same durable replay. Do not
assume a runtime on its local Astation link also receives relay-room events.

Delivery must work across Station replicas. A process-local callback or lossy
room broadcast is insufficient: commit followed by a relay crash still needs
to deliver the durable event.

## 5. Delivery, acknowledgment and recovery

The Station has a durable outbox; Atem retains accepted work in its durable task queue.
Use at-least-once event delivery with idempotent task acceptance. Do not
claim exactly-once execution of coding-agent side effects.

- Acknowledge event delivery only after durable task/receipt storage. This says
  nothing about agent acceptance or task completion.
- Persist the receive cursor with durable task acceptance. Duplicate events are
  acknowledged without creating another task.
- Reconnect from the durable cursor, catching up into live delivery without
  a snapshot/live gap. Retry missing acknowledgments in the transport.
- Commit dispatch, startup recovery and reconnect drive delivery. Coding
  agents never poll; backend transport retry timers are permitted.
- Define bounded retention, queue limits and backpressure. Never acknowledge
  work that a full task queue cannot retain. Report expiry explicitly.
- If event retention has a gap, recover from durable pending-work state;
  do not advance the cursor past missing work silently.

The task ID, rather than a delivery attempt ID, deduplicates work. Fetching
context or synchronizing memory can retry independently of prompt submission.
Locked credentials or a denied read produce an observable blocked state.

## 6. Agent dispatch

The shared task scheduler in the runtime reacts to new work, readiness/turn-end,
approval resolution, lease release and input/draft changes. It needs no
model call to determine whether work is queued.

If the target agent is working, awaiting approval or has a terminal draft,
keep work queued. Never type a notification into a running tool or approval
dialog, automatically interrupt a turn or overwrite a user's input. Unknown
readiness remains blocked with a reason.

At submission, revalidate sender authority and destination/project/profile.
Use structured prompt acceptance, receipts, leases and worker input epochs.
Peer work remains remote-origin: do not label it local typing or reuse a
local-origin exception to bypass a controller. An active human or
remote controller is not silently displaced. The protocol must specify the
scheduler principal and permitted lease acquisition. Dedicated role sessions
are a useful default for unattended workflows.

If launch-on-arrival is allowed, use the idempotent operation proposed in
[agent-hosting.md](agent-hosting.md). Correlate its launch receipt, wait for
readiness, then submit the task. Replayed events cannot create extra workers.

Record task ID -> assigned host/session/process generation -> submission
receipt before advancing the task. Recover interrupted submission through
that receipt; a missing completion notification is not permission to send
the prompt again. Proven not-submitted work can retry; ambiguous execution
stays `outcome_unknown` until explicitly resolved.

## 7. Results and bounded workflows

Transport acceptance, queueing, agent submission and task completion are
separate states. Proposed states include `pending_publish`, `queued`,
`blocked`, `submitted`, `running`, `waiting`, `completed`, `failed`,
`cancelled`, `expired` and `outcome_unknown`. Their precise transitions need
shared protocol review.

A completion references the task ID, result entry/version and original
workflow/correlation ID. Turn-end alone is not completion: an agent may be
asking a question. Require an explicit correlated result or a defined
completion condition. Existing tool approvals remain explicit approvals.

Deliver results/questions to the initiating role's inbox, waiting if that
agent is busy. Ordinary result storage must not recursively start every
subscriber again. Track parent task/event IDs, suppress sync echoes and
duplicate results, and enforce workflow hop/turn budgets, expiry, per-route
rate limits and session limits.

Owners can pause routes and cancel queued work. Once a prompt is submitted,
cancellation uses authorized interrupt/stop semantics and cannot promise to
undo the agent's actions.

## 8. Trust and authorization

Work notification is a new execution capability. Permission to read/write
memory or vault does not grant it. The vault's self-reported `writer_id`
is a label, not an authenticated sender or permission to launch an agent.

Specify a signed/scoped coordination grant or equivalent authenticated
principal binding source, destination host/role/project, allowed actions and
expiry. Existing host channel keys and approval push hints do not implicitly
grant host-to-host task control. Reuse verified cryptographic primitives,
but define the new envelope and authority explicitly.

Verify current membership/scope on acceptance and before launch/submission.
Revoked senders, expired grants, paused routes or hosted-execution policy,
held membership and inaccessible references block new work. An untrusted
relay hint may request reconciliation; it is not authority to execute.
The receiver's context read access is checked independently.

Peer content stays attributed task/context, not system instructions.
Credentials are referenced by name only. Retain project/profile restrictions
and the coding agent's existing permission flows. A newly connected machine
does not subscribe to executable historical work without owner configuration.

## 9. Existing pieces and ownership

| Existing piece | Reuse / extension |
|---|---|
| Memory sync and vault read/write | Durable context; add atomic write-and-notify and immutable references |
| Vault's proposed `vault-updated` nudge | Context-change concept; `watch` is not built and best-effort hints do not guarantee work delivery |
| Runtime's existing local/relay connection machinery | Reconnect/authentication precedent; specify a coordination subscription reachable on either route |
| r9 sealed approval hints | Encryption/signing principles; approval-specific operations/authority do not become task dispatch |
| Chat readiness, drafts, receipts and worker fencing | Safe delivery to either Codex or Claude |
| Chisel/mark | Uses the shared authorized per-session queue; screenshot upload is separate from the task envelope |
| Optional hosting / remote launch | Receive with zero sessions and create an approved agent when permitted |

Atem owns the notify interface, subscriptions, durable task queue, role routing,
scheduler, result correlation and diagnostics. The Station owns authenticated
publication, transactional outbox, durable replay, cross-replica dispatch and
access checks. Astation/integrated apps configure roles and show pending,
blocked and completed work. A Mac UI need not remain open for independently
authorized Atem runtimes to exchange work through the Station.

[Chisel/mark screenshots](protocol/atem-task-attachments-v1.md) now have an
implemented online Atem receiver and Chisel/Station sender in sibling feature
worktrees. Chisel sends actual PNG bytes to the authenticated Station marks
endpoint; its streamed response owns a live R9 service channel through task
queueing/turn-end. The legacy ID-only assignment is refused with upgrade guidance.
The separate mark dispatcher/background triage and public `runtime inbox`
command are removed. No offline artifacts/outbox/replay are included, per the
user's current scope. Shared/native SDK rollout and explicit grant opt-in remain
production prerequisites; the hosted API release gate is unchanged.

This draft implements no subscription, wakeup command, new grant, service
registration or hosted-execution activation.

## 10. Initial scope and verification

Start with explicit directed tasks between two roles, existing ready agents,
and referenced vault context. Add memory references and approved automatic
launch after host-level launch is available. Keep context-only subscriptions
separate from work-triggering subscriptions.

Verify with two isolated hosts and a test Station:

- A mobile write-and-notify reaches the backend and produces a correlated
  result without any coding-agent inbox polling.
- Rollback creates no event; commit followed by relay crash still delivers.
  Duplicate publication returns the same task.
- Offline receivers, replica changes and lost acknowledgments retain work
  and replay events without duplicate prompt submissions.
- Busy agents, approvals, drafts and controllers block injection; eligible
  state changes resume dispatch without periodic agent checks.
- Crashes around accept/launch/submit/result reconcile receipts or report
  uncertainty rather than silently repeating work.
- Unauthorized/revoked senders, expired grants, changed project bindings and
  inaccessible references cannot cause a launch or turn.
- Versioned context survives later edits; ordinary sync updates do not
  create work or mobile/backend notification loops.
- Role reassignment chooses one executor; cancellation, expiry, bounded
  queues and backpressure remain visible.
- Approved launch-on-arrival creates one worker from zero sessions; without
  that policy, work waits for an explicit agent start.

Checks do not modify real user sessions, services or credentials. Specify
event formats, permission names, retention/expiry bounds and scheduler lease
rules with shared fixtures before implementation. This draft does not amend
the current wire contract.

# Agent collaboration: Atem-to-Atem messaging

Status (2026-11-06): **stage 1 implemented, unreleased**, on
`feat/agent-collaboration`, after a fix round (section 17). Agents in one Atem
runtime can send work and reply through the existing host queue. **Not
implemented:** stages 2 and 3, cross-instance delivery, directory publication,
the Station mailbox and signed projects. This changes no part of the remote
permission contract: every part that would is marked **Needs agreement** and
waits until all three projects agree.

Reviews (2026-11-04): Auth/Portal's answers and changes are folded in; so are
Astation's ([#120](https://github.com/Agora-Build/Atem/issues/120)): a narrow
return grant for results, typed snapshots instead of references in text,
automatic reports that never complete a task, durable selector resolution with
one 32-agent budget across hosts, and separate Station connection capacity.
Astation supports the direction; nothing cross-instance is signed off.

## 1. Goal

Coding agents on the account's Atem instances work together without a person
forwarding messages. Example: the Atem agent ships a feature, records it in
Atem Memory and the vault, and asks the Astation and Auth/Portal agents to
adapt their sides. They do the work, and their results come back to the Atem
agent, correlated to its request.

Requirements:

- authenticated Atem-to-Atem messages with project-level permissions;
- addressing by project, tag and `atem_id`, one or more at once;
- one-to-many delivery with a durable outbox, acknowledgments, retries and
  deduplication;
- context (Memory, vault) published before anyone is asked to act on it;
- task status and results returned automatically, correlated to the request;
- execution only through the existing host-work receiver and approved routes;
- optional launch from an approved profile when no session runs;
- recovery when either side is offline, with delivery and execution status
  kept apart.

## 2. The design in brief

Delivery and execution stay separate layers. The sender's runtime owns a
durable **outbox**; each receiving runtime owns its existing **host-work
queue** ([agent-hosting.md](agent-hosting.md) section 7). Between them travels
an **envelope**: immutable, addressed with selectors, carrying exact context
snapshots, correlated by message, task and workflow ids. Receivers expand the
selectors against their own labels, apply their owner's route consent, and run
the work exactly as host-work v1 does today. Status and results travel back as
envelopes too.

It comes in three stages:

| Stage | Covers | Depends on |
|---|---|---|
| 1. Local (implemented, unreleased) | Agents on the same Atem instance | Atem only; owner opts in through runtime.toml |
| 2. Online | Agents on different instances, while both sides are online | The existing permission contract, plus three agreements with Astation (the return grant, the typed selector and snapshot boundary, Station connection capacity); the Station turns on and extends its host-work adapters |
| 3. Autonomous | Store-and-forward, offline recovery, project-level permissions | **Needs agreement**: origin-signed envelopes, a Station mailbox, signed projects |

## 3. Terms

- **Instance**: one Atem runtime (a host). Its human address is its `atem_id`
  (e.g. `Genie-c6ed4e4-af571944`); its authenticated identity is its `host_id`
  and `host_key` in the account's signed device list (`add_host`).
- **Agent**: a live session on an instance (Claude Code or Codex).
- **Route**: the owner-approved entry in `runtime.toml` through which work
  reaches the agents of one profile. Routes, not senders, decide where work may
  run.
- **Label**: a project or tag attached to an instance, a route or an agent.
  Labels address; they never authorize.
- **Selector**: one address in a message's `to` list.
- **Envelope**: one immutable message (host-work v1's `Message`, extended).
- **Task**: what an envelope becomes for one agent: host-work v1 work, with its
  states.
- **Workflow**: the chain of envelopes one request starts (`workflow_id`),
  replies included.

## 4. Projects and tags

Labels are strings: `project:<name>` and `tag:<name>`, set by the owner, and
`self:<name>`, set by an agent for itself (names: 1–32 characters of
`[a-z0-9-]`).

| Where | Set by | Holds |
|---|---|---|
| `[instance] labels` in `runtime.toml` | the owner | projects and tags for every agent of the instance |
| `[[routes]] labels` | the owner | projects and tags for the agents of that route |
| the agent's own tags | the agent: `atem agent tag add`, `remove`, `list` | `self:` tags only (at most 16), for its session's life |

An agent's labels are the union of its instance's, its route's and its own.
Example, one instance running all four agents:

```toml
[instance]
labels = ["project:astation"]

[[routes]]
id = "auth"
labels = ["tag:auth"]      # also routes "atem", "astation", "portal", each tagged with its name
```

The agent working on token scopes in the Auth repo adds `self:tokens` itself.

- An agent can't add projects or `tag:` labels: those are the owner's. Its own
  tags live in the separate `self:` namespace, so an agent (or one a message
  misled) can't tag itself `tag:auth` and capture mail meant for the owner's
  Auth agents, context included.
- `atem agent tag` finds the calling session from its process ancestry (the
  peer pid on the local socket, walked up to a session's agent pid, the way hook
  ownership is checked today); outside a session it is refused.
- A project label is not a profile's `project` (the Git remote that memory and
  service scopes use).
- Labels only address. Adding `self:tokens` makes an agent reachable by
  messages addressed to `self:tokens`; whether a sender may give it work is
  still decided by permissions (section 6). Until projects are signed (stage
  3), a project grants nothing either. Labels do decide where content goes,
  which is why only the owner sets `project:` and `tag:`.

## 5. Addressing

A message's `to` is a list of 1–16 selectors. The audience is their union, each
agent at most once; the sending agent never receives its own message.

| Selector | Matches |
|---|---|
| `project:astation` | agents with the project, on every instance |
| `tag:auth` | agents with the owner's tag |
| `self:tokens` | agents that gave themselves the tag |
| `project:astation+tag:auth` | agents with all of them (`+` is AND) |
| `atem:<atem_id>` | every agent on that instance |
| `atem:<atem_id>/<route_id>` | the agents of one route on that instance |

**Resolution: planned by the sender, expanded once by each host, then fixed.**

1. The sender plans the hosts. Each instance publishes a directory record
   (`atem_id`, its host identity `{account_id, atem_device_id,
   host_trust_gen}`, labels, routes with their labels and revisions, live
   agents with their tags and activity) to a per-account directory in the vault:
   end-to-end encrypted, refreshed on change and every 10 minutes, stale after
   an hour. A record is a hint, never authority. The plan names each target
   host by its exact identity, never by a label or `atem_id`, and the channel's
   `welcome` must match it.
2. The sender splits one budget of at most **32 agents per message** across
   the planned hosts (`budget` per host, totals at most 32), so the bound holds
   for the whole message, not per host.
3. Each receiving host expands the selectors against its own current labels,
   routes and agents (the authoritative copy), in a fixed order (route id, then
   session start), up to its budget, and applies permissions. It **persists the
   resolution with the envelope, in the same transaction, before it
   acknowledges**: one task per matched agent, each with a stable `task_id`
   derived from the message, the recipient and the session (UUIDv5). A retry
   returns that recorded resolution, whatever changed since (tags, sessions,
   routes). A host that matches nothing records `no_match` for its recipient,
   final for that message.

Stage 1 is the same on one host, with the whole budget. Its directory is read
from the local runtime only; no vault directory record is published yet.

The shared types include a new host-work destination,
`select{selectors, budget}`, beside `host`, `project` and `agent` (feature
`host.select`). Stage 1 uses it internally: `host.select` is not advertised and
remote host admission refuses `select`. Before stage 2, the Station's adapters
must accept it too and the boundary must be agreed.

**When no agent runs.** Only a sender that asks for it (`atem message send
--launch`, with an `atem:<atem_id>/<route_id>` selector) gets a session
launched, and only on a matching route whose owner allows it
(`launch = "on_message"`, off by default) and whose profile is Claude Code: a
route with `launch = "on_message"` on a Codex profile is refused when
`runtime.toml` loads. Stage 1 launches no Codex session, since Codex reports
nothing until a first prompt is typed in its terminal and a launched one would
never become ready (that is fixed and tested separately before Codex launches
are enabled). Codex sessions that are already running take queued tasks as
usual once they are ready. Stage 1 reserves the launch request id, session id
and process generation with the task before starting a worker, and waits until
that session is ready. A send without `--launch` never starts a session, but it
can share a pending launch, including one that just started and whose project
isn't known yet: that session is the route's agent. A failed launch fails the
task; a launch not yet started waits out a pause (section 9). A remote sender
also needs its existing `launch` permission for that; a local sender needs only
the route setting.

## 6. Permissions

**Today's two locks stay.** Every task still needs the caller's account
permission and the receiving owner's route consent
([agent-hosting.md](agent-hosting.md) section 4). Nothing here widens either.

| Stage | Sender identity | Account permission | Route consent |
|---|---|---|---|
| 1. Local | `local`: an internal attachment of the session host, never welcomed over a link | none: the message never leaves the machine (the same-user boundary every local command has) | the route lists `local` in `principals` |
| 2. Online | an existing principal: the instance enrolled as a Station integration, `service:svc-<id>` | its signed service grant: `message`, `notify`, `prompt`, and `launch` for launches; its hosts and projects bound the targets | the route lists that service |
| 3. Autonomous | the instance itself, `host:<host_id>`, signing with its pinned `host_key` (**needs agreement**) | a signed project grant, below (**needs agreement**) | the route lists `project:<name>` or the host (**needs agreement**) |

**Stage 2 in practice.** The instance sends nothing until the owner has
approved its integration in Astation; Auth issues no token before that. One
integration per instance (Auth/Portal's answer), so each can be paused or
revoked on its own, with its own quota, audit trail and R9 service identity.
Costs: each counts toward the built-in Station's plan limit of active
integrations (Basic 4, Premium 10; custom Stations have none); each expires
after at most 90 days and is renewed and approved again; a key rotation keeps
the old key valid for 10 minutes after the new one is registered, so Atem makes
the new key, the owner registers it, and Atem switches once Auth accepts it.
Configuration grows with every pair: each sending instance's service must be
listed in every receiving route's `principals`, which is the practical case for
signed projects.

**Project-level permissions (stage 3, needs agreement).** A project becomes a
signed object: a native device with `manage` signs
`project{name, members: [host ids], ops: [message, notify, prompt, launch]}`
into the device list or a sibling signed log. A route that lists
`project:astation` in `principals` then accepts work from any instance the
signed project names, within the project's ops. Removing an instance from the
project, or removing its host, fences its queued work like any revoked
principal. Until all three projects agree, routes keep naming explicit
principals.

A stage-3 `host:` sender is outside Agora.Build's kill switch: an integration
can be stopped at once by Auth, paused from the Portal or the admin site and is
audited by Auth; a host that signs its own envelopes can be stopped only by
removing it from the device list (consistent with native members using
membership, not scopes).

**Limits against runaway chains.** A misleading message must not fan out:

- sending is off by default (`[collab] send = false`); one message reaches at
  most 32 agents;
- each sending session sends at most `per_hour` messages (default 30), in a
  rolling hour;
- a send from an agent whose current turn came from a task reuses that task's
  `workflow_id`. Each instance sends at most `per_workflow` (default 8)
  **messages** per workflow and accepts at most that many messages per workflow
  (a message counts once, however many agents it reaches), so a loop between
  agents ends without a hop counter on the wire;
- the limits are checked when a message is sent, counting this session's and
  this workflow's sends whose context is still being published, and counted
  once, when the message is accepted. A burst of context sends can still be
  refused at acceptance (`refused` in `atem message status`);
- results don't count against either limit: each task has at most one result
  (section 10), and a result never starts new work;
- a message that can't become a valid task (its prompt with context over the
  task bounds, or control characters other than newline and tab) is refused
  before anything is counted. Inline text and a Memory snapshot are checked
  when the message is sent. A vault reference is checked when its entry is read
  during publication, because its size is known only then: an oversized vault
  context shows as `refused` in `atem message status`, not as the send
  command's error;
- receivers keep every host-work check: readiness, no draft, no open approval,
  no takeover, FIFO per session;
- every counter is durable in `host-work.sqlite` and survives a restart; rows
  of windows that have passed are pruned: an hourly row an hour after its
  message, a workflow's row two days after the workflow's latest message (a
  message lives at most a day, and the turn it started may outlast it).

## 7. Envelopes and the outbox

**Envelope.** Host-work v1's `Message` (ids, sender, creation and expiry at
most 24 h later, recipients, text, up to 8 exact context snapshots with text and
digest), plus:

- `to`: the selectors; each recipient carries `select{selectors, budget}` for
  its host (section 5);
- `reply_to`: the `message_id` and `task_id` it answers, if any;
- `kind`: `request`, `status` or `result`;
- `from_session`: the sending agent's session id, so status and results find
  their way back to it. A local envelope's `sender` is `local`, valid only on
  the internal attachment (today a sender must be `member:` or `service:`,
  equal to the channel's principal; that rule stays for every channel).
  `from_session` and `reply_to` are local-only: a remote `message_publish`
  carrying either, or a `kind` other than `request`, is refused. Stage 1 sends
  only requests; a task's result is its reply (section 10), not an envelope;
- stage 3: `origin`, the sender's signature over the canonical envelope
  (**needs agreement**).

**Outbox.** `atem message send` hands the envelope to the sender's runtime,
which commits it to `host-work.sqlite` before replying; the CLI sends nothing
itself. Per target instance, a delivery row moves through

`publishing` → `ready` → `sent` → `accepted` | `refused(<code>)` | `expired`

- `publishing` holds the envelope until its context is published (section 8).
- Retries reuse the same `message_id` and `recipient_id`, backing off from 1 s
  to 5 minutes, until accepted, refused or expired. The receiver deduplicates by
  those ids: an identical repeat returns the recorded receipt and resolution
  (section 5), the same id with other content is `request_id_reused`, as
  today.
- `accepted` is the receiver's durable acknowledgment: the envelope and its
  tasks are committed there. It means delivered, not executed.
- A new host identity fails the outbox's pending rows, with the rest of the
  database ([agent-hosting.md](agent-hosting.md) section 9).

## 8. Publish before notify

A reference never reaches an agent before its content is published, and an
agent only ever sees exact bytes that the runtime verified.

**The boundary.** The sender's runtime (the authorized publisher) verifies
that the version is committed and readable by the account; the receiving
runtime verifies the exact bytes (the digest) before dispatch. A digest proves
byte consistency, not publication or read authority, so neither side relies on
it alone, and the coding agent never fetches or verifies anything itself.

**Stage 1: guaranteed, not atomic (Atem only).** For each `--memory <id>` and
`--vault <id>[:<entry>]@<version>` the outbox:

1. publishes memory through the sync push (its result names the canonical id
   and `seq`); for a vault reference, reads the already committed entry/version
   without adding a write or incrementing its version;
2. reads it back from the relay: memory by pulling from just below that `seq`
   (the relay has no fetch by id), the vault entry by reading from `seq - 1` and
   matching entry and version; both come back decrypted;
3. compares the plaintext with the local text, and freezes the typed snapshot
   `{kind, id, version, digest: sha256(text), text}` into the envelope (the
   memory's own hash is a normalized dedup key, not this digest).

Only then does the row leave `publishing`. A failure retries and never sends.
The memory's text is frozen when the command is submitted, and exactly that
version must be the one published: if the memory is replaced or invalidated
before its publication finishes, the send is refused ("memory changed before it
was published; send again") rather than delivering another version. Vault references include an entry when needed:
`VAULT_ID:ENTRY@VERSION`. Bare `VAULT_ID@VERSION` is refused if more than one
entry matches. Publication retries use a bounded background job pool; a
byte mismatch is refused rather than delivered.

**Stage 2: typed snapshots only.** The message adapter proposed in Astation's
host-work branch accepts inline text only. Stage 2 does not put references in
the text as a fallback: it waits for typed snapshots in the shared SDK and the
Station adapter, with the boundary above agreed and tested.

**Later: atomic (Station).** The Station stores the encrypted context version
and the pending envelope in one transaction, so neither exists without the
other; Atem supplies the encrypted content and the Station never sees
plaintext. The transaction and the version and access boundary are specified
before anyone calls it atomic.

## 9. Execution on the receiver

Host-work v1, unchanged except for the selector destination:

- the receiver expands the selectors (section 5) and creates one task per
  matched agent, through that agent's route;
- route consent, route and profile revisions, scope checks, FIFO per session,
  readiness, drafts, approvals, leases and expiry apply as today;
- a task is submitted as a session-v1 prompt with `acquire` on its sender's
  attachment, and the prompt's receipt drives the task's states. A remote
  sender's attachment is its live channel (stage 2) or its verified origin
  (stage 3). Local senders share one internal attachment, created through the
  session host's existing `connect` and welcome path (again after a host
  restart or identity change, which clear attachments), with the `local`
  principal, `view` and `control`: their tasks get receipts, the lease and the
  control fence exactly like remote ones, nothing is typed into the terminal,
  and the person at the terminal takes control back with a keystroke, as from
  any remote controller. The runtime reads the internal attachment's receipts
  directly (nothing is sent to it), and a device-list freeze or fault fences
  it like every principal;
- the prompt carries the task, workflow and reply ids and each snapshot, so the
  agent knows what it answers and to whom;
- routes with `launch = "on_message"` start a session when none matches
  (section 5).

**Pauses, not fences.** Three things pause local work: a `runtime.toml` that
doesn't load, hosting disabled, and a receipt-database fault. While one lasts,
new local sends are refused with the reason, queued local tasks wait (their
detail reads `paused: <reason>`), and the publication of replies and the
delivery of results wait. Nothing is fenced, so everything resumes as soon as
the file is valid again (as for remote senders). A reply (and a completion) is
accepted and stored during a pause, so an agent that finishes then loses
nothing; the exception is a receipt-database fault, which refuses both
("agent hosting records are unavailable") until `atem runtime restart`. A local
launch not yet started waits out the pause and then starts; a launch already
handed to the worker spawner completes. (After a database fault the pause lasts
until `atem runtime restart`, which ends the wait of a launch that had not
started: it becomes `outcome_unknown` and is never started.) `[collab] send =
false` is not a pause: it only refuses new local sends. Local tasks already
accepted keep dispatching, and replies and result deliveries are not held back.
Only a real change of authority fences `local`: a new host identity, or a
device-list freeze or fault.

**Agent commands never replace the runtime.** `atem message …` and `atem
agent tag` connect only to the runtime that is already running (the calling
agent runs inside it); they never start one and never replace a runtime of
another build, so an agent whose `atem` differs from the runtime's build can't
restart it in the middle of its own task. With no runtime running they fail
("no Atem runtime is running; agents run inside one"); a runtime of another
protocol is refused with both protocol numbers.

## 10. Status and results

**Two statuses, never mixed.**

| Delivery (per instance) | Execution (per task) |
|---|---|
| `publishing`, `ready`, `sent`, `accepted`, `refused`, `expired` | `queued`, `blocked(<reason>)`, `submitting`, `submitted`, `awaiting_result`, `completed`, `failed`, `cancelled`, `expired`, `outcome_unknown` |

`blocked` names its reason: agent busy, terminal draft, approval open, lease
held, sender offline, screenshot missing, launching. A local task that waits
out a pause keeps its state and shows `paused: <reason>` (section 9).

**Automatic status.** The receiving runtime reports each task transition to
the sender: in-process in stage 1; in stage 2 the sender's outbox polls
`message_query` and `tasks/:id` instead; in stage 3 as `status` envelopes
through the mailbox. The sending agent reads them with `atem message status`;
nothing is typed or prompted into its session for a status (only a result,
under its return grant, below).

Without an id, status shows the latest 32 messages, bounded to 1 MiB; query
an explicit message id for older receipts. Views carry result text and typed
context references rather than copying full context snapshots into status.

**Results.** A finished turn is not a finished task. For every sender, a
result is submitted by the agent that did the work and the task is completed by
its sender: two separate steps.

- **Submitting (one mechanism for every sender).** The agent answers with
  `atem message reply [--task <id>] [--memory <id>]…
  [--vault <id>:<entry>@<version>]… <text>`, for any task in its runtime's
  queue, whoever sent it: a local agent, Astation's apps, an integration, later
  another Atem instance. `--task` may be left out only when exactly one task of
  the calling session is in its turn or awaits a result. A reply's vault
  reference names its entry: a bare `<id>@<version>` is refused before anything
  is stored. The text is at most 16 KiB, with no control characters other than
  newline and tab.
- **Authorization.** The runtime accepts a reply only from the task's target
  session and process (found from the CLI's process ancestry), while the task
  is `submitted`, `awaiting_result` or `outcome_unknown`. It binds the reply,
  when it is submitted, to that task, session, process and turn: the turn id
  is stored when the task's prompt is accepted, so the binding survives a
  runtime restart. A submitted reply proves that the prompt's turn ran, so an
  `outcome_unknown` task it answers becomes `awaiting_result`: its sender can
  complete it, and it no longer holds its session's queue.
- **Durable and idempotent.** The reply is committed (one per task in
  `host-work.sqlite`, `result_id` = UUIDv5 of the task id) before the CLI is
  answered, also during a pause (section 9; not during a receipt-database
  fault, which refuses a reply until `atem runtime restart`). Context
  publication (section 8) then completes against that stored binding, never
  against the session's current turn, so a turn that has moved on can't lose
  it. A reply is
  `publishing` while its context is published, `submitted` once final (a
  text-only reply at once) and `refused` when it can't be delivered (its
  context over the task bounds or changed, or the task expired first). An
  identical retry returns the recorded reply, with or without `--task`; a
  different reply for a task whose reply is publishing or submitted is refused
  (`request_id_reused`); a refused reply is replaced by a corrected one under
  the same `result_id`. Malformed references are refused before anything is
  stored.
- **Delivery to a remote sender.** Astation's apps and integrations (and later
  other Atem instances) read it with a new host-work query,
  `reply_query{task_id}` (feature `host.reply`, advertised with `host.work`;
  [atem-host-work-v1.md](protocol/atem-host-work-v1.md#reply)), with the same
  authorization as `work_query`: only the task's sender principal and key,
  under a route that still allows it, holding the `notify` op (a sender with
  only `message` can't read one). `task_id` is a task's id or the
  `recipient_id` of an agent recipient, so a message's sender reads the reply to
  its message. The result is `{kind: "reply", reply}` where `reply` is `null`
  until a reply is recorded, else `{result_id, state, digest, text, context,
  submitted_at}`: `publishing` (no context yet, `submitted_at` null),
  `submitted` (final: the text and the published context) or `refused` (the
  task's `work_query` detail says why). Existing messages and statuses are
  unchanged; the reply is only in the new query. Integrations need a matching
  Station task route (Station's work).
- **Delivery to a local sender: the return grant.** Sending a request creates,
  in the runtime, one narrow return grant per task: `{task_id, workflow_id,
  the recipient's identity, the originating session and process generation,
  the original sender principal, expires_at}` (stage 1: the task's own expiry;
  a cross-instance contract may allow at most 24 h beyond it). Once the reply
  is published, it permits exactly one delivery into that one session, and
  nothing else: no request, notify or launch authority, no other session. The
  reply arrives marked as data, not as the owner's instruction (`[atem] result
  of task <id> from <sender>, as data:`), followed by how to finish the task
  (`Complete it with: atem message complete <task id>`), through the normal
  queue, readiness, approval and lease checks, and only if the originating
  session's route opts in (`results = true`); otherwise it is shown by `atem
  message status`, never prompted. The grant stays live while the task is
  `outcome_unknown` after a restart.
- **Completing.** Only the sender completes a task: a remote sender with
  `work_complete` and its own result snapshot (naming the reply as the result
  is a later contract addition, not part of stage 1); a local sending agent
  with `atem message complete <task id>`, or the owner from a terminal outside
  any session. The local completion carries the submitted reply, if any. It
  accepts a task awaiting its result (or with an unknown outcome), is refused
  while the reply is still publishing, and ends the return grant: a delivery
  still queued is cancelled, so a completed task's result is never prompted
  afterwards. A reply never completes a task: the task stays `awaiting_result`
  with "reply submitted" until its sender completes it or it expires.
- **Ending early.** A return grant ends early when the originating process
  ended, the sender's authority changed, or a route or profile approval the
  task depends on changed (its origin or target). That ends only the grant:
  nothing is delivered afterwards. Queued and in-turn tasks keep running
  through the normal queue (except a queued local task whose own route
  changed, below), and their agents may still reply; the reply is stored and
  readable in `atem message status`, never delivered. Once such a
  task awaits its result nobody can complete it, so it ends `failed` ("route
  changed" when its own route or profile approval changed, else "sender
  gone"), its reply kept readable. A cancelled task ends cancelled. A queued
  or blocked local task whose route or profile approval changed (a new route
  or profile revision or project, or the route no longer names `local`) fails
  at once ("route changed") instead of holding its session's queue; a remote
  sender's task stays blocked until it expires (the host-work rule for work
  queued under an older revision).
- **Expiry.** Every task awaiting its result, for any sender and whether its
  grant is open, consumed or ended, expires at its deadline ("expired awaiting
  a result"), and so does a task whose outcome is unknown ("expired with its
  outcome unknown"; nothing is resubmitted), so none waits, or holds its
  session's queue, forever. A task awaiting its result holds no place in the
  queue: only queued, blocked, submitting and submitted tasks count toward the
  256 unfinished tasks.
- **Automatic reports.** A turn that ends without a reply leaves the task
  `awaiting_result`. After `result_timeout` (default 30 minutes) the runtime
  records a progress report ("turn ended without a reply"), never a result: it
  doesn't complete the task or consume the return grant. A route can opt in to
  include the turn's final assistant message in that report
  (`auto_report = "final_message"`); it may hold command output or values the
  agent never meant to send, so it stays off by default.
- **Who sees what.** Inside a session, `atem message status` shows the
  messages that session sent, with all their tasks, and the messages with a
  task sent to it, with that task only: the local tasks it received. Tasks
  from remote senders aren't listed there; they reach the agent with their
  task id in the prompt, and it replies with `--task`. `atem message cancel`
  works only on the session's own messages; from outside any session (the
  owner's terminal) both cover everything.
- **Storage.** The runtime writes a grant or result only when its state
  changes.

Stage 1 implements all of this within one runtime. Cross-instance, the return
grant is a contract to agree with Astation before stage 2.

## 11. Recovery

Stage 1 persists local sends, resolutions, tasks, counters, replies and return
grants across broker restarts. It needs no network transport for text-only work;
Memory/Vault publication waits for a reachable relay. A lost or uncertain
launch is not respawned automatically. The cross-instance behavior below is
planned, not implemented.

| Situation | Stage 2 (planned) | Stage 3 (planned) |
|---|---|---|
| Sender restarts | the outbox resumes from its rows | same |
| Receiver offline | the outbox retries until expiry (24 h at most) | the Station mailbox holds the envelope until the receiver reconnects |
| Sender offline after acceptance | its remote tasks stay `blocked(sender offline)`: dispatch needs its live channel | dispatch goes on, on the verified origin; the receiver checks the sender's authority against its own device list |
| Receiver restarts mid-task | host-work recovery: `submitting` becomes `outcome_unknown`, reconciled from its receipt, never sent again | same |
| Results while the sender is offline | queued in the receiver's outbox | held in the mailbox |

On the built-in Station the mailbox means Agora.Build's server stores the
(sealed) envelopes: deleting the account deletes the mailbox's contents, and
the trust notice mentions the mailbox as it does hosted execution.

## 12. Transports

| Transport | Stage | Sender identity | Carried by | Offline |
|---|---|---|---|---|
| In-process | 1 | `local` (the internal attachment; the sending session is recorded with the envelope) | the runtime | not needed |
| Station hosted agent API | 2 | a Station integration, `service:svc-<id>`: the Station holds its R9 key, the instance holds its Auth client key (`private_key_jwt`) in the cred agent | Station adapters: `messages`, `launches`, `tasks`; new: `routes`, a `work_complete` route, the `select` destination, snapshots | no |
| Station mailbox with sealed envelopes | 3 | `host:<host_id>`, origin-signed | the Station stores envelopes per instance and delivers them with acknowledgments | yes |

Stage 2 capacity (Astation): the Station keeps an integration's channel to a
host while its `events` WebSocket is open, which keeps dispatch working, but each
such WebSocket holds one of the Station's eight shared request permits for its
lifetime. Separate, bounded connection and request budgets (per integration and
account) come first, before online collaboration scales. When a token expires,
the instance reconnects with a fresh one; a kept channel never extends a
token's authority.

Why stage 2 doesn't use a key the instance holds: Station provisioning takes no
client-supplied service key, the direct channel endpoint needs a user
`astation.remote` token that Atem must not hold, and the device list gives hosts
no roles. Stage 3 makes the instance's own pinned key the origin, once agreed.

## 13. Commands and configuration

```toml
version = 1
enabled = true              # explicit opt-in; installed sample is disabled

[instance]
labels = ["project:astation", "tag:mac-mini"]

[collab]
send = true                 # off by default
per_hour = 30
per_workflow = 8
result_timeout = "30m"
# Proposed stage-2 keys, NOT accepted by the current runtime.toml parser:
# integration = "i-..."
# station = "https://station-dev.agora.build"

[[profiles]]
id = "auth"
revision = 1
label = "Auth Claude"
provider = "claude"
cwd = "/absolute/canonical/path/to/Auth"
project = "github.com/agora-build/auth"  # normalized Git remote of cwd
args = ["--model", "sonnet"]
env_names = ["ANTHROPIC_AUTH_TOKEN"]    # names only; private env_file is optional
# No profile principals: remote launch defaults to the paired Astation.

[[routes]]
id = "auth"
revision = 1
profile_id = "auth"
labels = ["tag:auth"]
principals = ["local"]      # stage 2 adds services; stage 3 may add project:<name>
launch = "on_message"       # optional; the profile must be Claude Code in stage 1
results = true              # off by default: results of tasks this route's agents sent reach them
auto_report = "status"      # or "final_message" (opt-in)
```

| Command | Effect |
|---|---|
| `atem message send --to <selector>… [--memory <id>]… [--vault <id>[:<entry>]@<version>]… [--launch] [--expires <duration>] <text>` | Queue one request; prints its id. `--launch` (with an `atem:<atem_id>/<route_id>` selector) lets it start a Claude session on a route with `launch = "on_message"` when none matches |
| `atem message reply [--task <id>] [--memory <id>]… [--vault <id>:<entry>@<version>]… <text>` | From inside a task's session, for a task from any sender: its result, bound to that task, session, process and turn. A vault reference names its entry |
| `atem message complete <task id>` | The local sending agent (or the owner, outside any session) completes its task with the submitted reply, if any; also stops a queued delivery |
| `atem message status [<id>]` | Delivery per instance and execution per task; inside a session, only its own messages and the local tasks sent to it |
| `atem message cancel <task id>` | While the task is queued or blocked; inside a session, only its own messages |
| `atem message directory [<selector>]` | Local routes and agents a selector reaches now; no cross-instance directory yet |
| `atem agent tag add\|remove\|list [<name>]` | The calling agent's own `self:` tags |

Every command is a client of the local runtime, which does the work.
Commands require pairing; `send`, `reply` and agent tags also require a child
process of a live Atem-launched agent (`status`, `cancel` and `complete` also
run from the owner's terminal). An ordinary terminal cannot impersonate
one by supplying a session id. Keep the config mode 0600 and validate it with
`atem runtime check`. Repeat `--to` for a union of selectors.

## 14. Ownership and dependencies

The local items below are implemented; directory publication and every
cross-instance item are planned.

| Item | Owner | Depends on |
|---|---|---|
| Labels and `atem agent tag` | Atem | nothing |
| Directory records in the vault (needed from stage 2: local delivery resolves selectors itself) | Atem | nothing |
| Outbox, retries, deduplication, delivery status | Atem | nothing |
| Publish before notify: publish, read back, freeze | Atem | nothing |
| Local delivery between agents of one instance: the internal `local` attachment and route principal | Atem | nothing |
| The `select` destination with budgets and persisted resolution, launch on message, automatic reports, return grants and results (local) | Atem | nothing |
| Cross-instance delivery while online, as a Station integration | Atem | Agreements with Astation: the return grant, the typed `select` and snapshot boundary. Station: turning on the host-work gate (off on every Station; it grants `agent.launch`/`message`/`notify` only when built with `host-work-api`); `routes` and `work_complete` adapters; `select` and typed snapshots in the message adapter; separate connection and request budgets. Auth/Portal: nothing new: the owner registers the instance's public key as a "Custom App / API" integration, and the scope names are final |
| Result submission for every sender: `atem message reply`, the `host.reply` feature and `reply_query` for remote senders | Atem | nothing for Astation's apps over their channel (they adopt the SDK op); integrations need a Station task route for replies |
| Launch on message for Codex | Atem | Codex's first-prompt readiness fixed and tested first |
| Atomic write-and-notify | Station | a transaction over encrypted context versions and pending envelopes, with its boundary specified |
| Mailbox, offline delivery, origin-signed envelopes, `host:` principal, signed projects | all three | **needs agreement** on the permission contract |

Order (Astation's proposal, agreed): (1) Atem builds stage 1 with the
tightened result, correlation, resolution and budget rules, and supplies the
shared contract and fixtures; (2) Atem and Astation agree the return grant and
the typed selector and snapshot boundary; the Station adds its adapters and
connection capacity; (3) a joint online test: lost acknowledgment,
reconnect and restart, duplicate delivery and result, changed selectors, exact
context verification, revocation and refused route or scope, a held lease or
open approval, fan-out and capacity limits. It can be folded into the D28
joint dev check on an upgraded test host. (4) Host-origin signatures, signed
projects and offline dispatch are stage 3, not prerequisites.

## 15. Questions

Astation (answered 2026-11-04, [#120](https://github.com/Agora-Build/Atem/issues/120)):

1. Selectors and snapshots: typed, in the shared SDK and the Station adapter,
   with immutable resolution and publication and access checks; no references
   in free text.
2. The `events` WebSocket keeps the host channel; its request permit is the
   capacity problem (section 12). Message and task queries stay the
   authoritative progress and recovery.
3. Mailbox (stage 3): supported on the selected Station: sealed envelopes per
   instance, at most 24 h retention, quotas, acknowledgments and deduplication,
   the sender's current authority checked before execution; stored channel
   ciphertext is never replayed as an authenticated message on a new channel.
   Atomic write-and-notify lives in the Station (section 8).

Auth/Portal (answered 2026-11-04):

4. A client key the instance generates: acceptable and already supported. The
   "Custom App / API" integration takes a developer-supplied public key (Auth
   stores public keys only: ES256, EdDSA, or RS256 of 2048–4096 bits). Atem
   makes the pair in the cred agent and prints the public JWK; the owner pastes
   it into the Portal, then approves natively in Astation. One integration per
   instance (Astation agrees). Atem creating the integration itself would need
   it to sign in at Auth (`atem login` uses Agora SSO), so that is left out.
5. Final: `agent.launch`, `agent.message`, `agent.notify` with `agent.prompt`
   are on Auth and Portal main and live on dev since 2026-11-03 (Auth #14 and
   Portal #25 closed). Auth refuses `agent.notify` unless the integration also
   has `agent.message` and `agent.prompt`; `agent.view` is always included.
   Design of record: Portal `docs/integrations.md` §3.1.3.

Still open (all three, before stage 2 and stage 3):

6. The return grant (section 10) as the cross-instance contract for results.
7. A `host:<host_id>` principal signing with its pinned `host_key`, or must
   every sender be a service? (Stage 3; Astation's review approves no new
   principal yet.)
8. Signed projects: in the device list or a separate signed log? Signed by a
   native `manage` device only? Which ops may a project grant? (Stage 3.)

## 16. Out of scope

Work on behalf of another account; projects or tags that widen account
permissions; agents editing projects; message content leaving the account.

## 17. Stage 1 implementation

Stage 1 is implemented in local commits on `feat/agent-collaboration`
(unreleased) and was revised in a fix round: limits counted in messages and
checked at send, pauses instead of fences, agent commands that only connect, one
reply for every sender with `reply_query` for remote ones, tasks that end when
their sender is gone or their deadline passes, scoped status, and launch on
request for Claude only. It requires no Station, Astation or Auth/Portal
change and enables no remote API gate. It changes no existing remote wire
shape: the additions are the `reply_query` request, its `reply` result and the
`host.reply` feature. Sending and automatic actions remain opt-in.

| Area | Implementation |
|---|---|
| Configuration | `src/runtime/host_work.rs`: owner labels, `[instance]`, `[collab]`, route launch/results/report options (`launch = "on_message"` needs a Claude profile); bare `local` is a route principal only; the `results` and return-grant tables; expiry of tasks awaiting a result |
| Shared addressing | `crates/atem-client/src/session/select.rs`: labels, AND/union selectors, `atem:` ids, 16 selectors and one 32-agent budget; `messages.rs`: optional correlation and local validation; `host_work.rs`: local task ids, `reply_query` and its result |
| Calling identity | `src/runtime/server.rs`, `adopt.rs`, `broker.rs`: socket peer PID and start time, verified ancestry to the live worker agent, generation-bound persisted `self:` tags (removed with their session) |
| Durable state | `src/runtime/collab.rs`: fixed resolutions, UUIDv5 task IDs, outbox, durable hourly/workflow counters counted in messages and pruned, task validation before counting, scoped status views |
| Queue integration | `src/runtime/collab_bridge.rs`, `host_work_bridge.rs`, `host_bridge.rs`: internal attachment, sender abstraction, normal prompt receipts, leases, fencing and pauses |
| Context | `src/runtime/collab_context.rs`, `src/memory/sync.rs`, `src/vault_client.rs`: immutable capture, publication, exact decrypted read-back, bounded retries before dispatch |
| Results | `src/runtime/collab_results.rs`, `collab_bridge.rs`: one durable reply per task for every sender, bound to its session, process and turn; narrow return grants, explicit completion by the sender, optional origin prompt, status-only automatic reports, tasks that end with their grant |
| Remote replies | `crates/atem-client/src/session/host_work.rs`, `principal.rs`, `connect.rs`, `src/session_protocol/r9/mod.rs`, `host_work_bridge.rs`: `reply_query`, the `host.reply` feature, the shared vectors in `designs/protocol/fixtures/host-work/requests-v1.json` |
| Chat turn attribution | `src/chat/session.rs`: a Claude `Stop` hook recorded before the current turn began ends nothing of it (the collaboration tests found it; it also affected remote chat prompts) |
| Launch on message | `src/runtime/collab_launch_bridge.rs`: only for a send that asks, Claude profiles only; reserve task and launch identities in one transaction, share pending launches, reuse approved profile/environment loading and guarded worker spawn |
| CLI | `src/cli.rs`, `src/runtime/client.rs`, `commands.rs`, `protocol.rs`: agent tags and runtime-backed send/reply/complete/status/cancel/directory commands, which only connect to a running runtime |

### Tests

`tests/collab_binary.rs` exercises the real runtime, workers and fake agent
CLIs. Commands execute as actual children of those agents, so the tests cover
the calling-session boundary. `tests/host_work_binary.rs` drives the same
runtime with encrypted r9 clients. All profiles, sockets, databases and agent
processes belong to temporary test sandboxes.

Coverage includes owner/agent tag separation; fan-out without sender echo;
fixed resolution on retry; disabled defaults; queued-only cancellation;
workflow inheritance and limits counted in messages (one message to nine
agents counts once, replies count nothing, in-flight context sends count at
send, an oversized context is refused before counting); publication retries and
frozen context; one reply per task for every sender (in the task's turn, after
a restart, after the next turn began, after its session ended, during a
pause), idempotent retries and `request_id_reused`, a refused reply and its
correction; completion by the sender, from outside a session, while a reply
publishes and with an unknown outcome; result prompts only under origin
consent; silent turns retaining their return grants; a sender that left, a
route that changed mid-turn and tasks that expire awaiting a result; status and
cancel scoped to a session; pauses that wait and never fence (invalid
`runtime.toml`, hosting off), `send = false` refusing new sends only, agent
commands that never start or replace a runtime; launch on request only, for
Claude only, one launch shared by quick sends, a ready Codex session still
receiving tasks, and a Codex route with `launch = "on_message"` refused. Over
the encrypted channel: `reply_query` in every state (publishing, submitted,
refused), the same answers as `work_query` for other principals, restart
survival and replies read by `recipient_id`; a service's task taking a reply
only from its target session and expiring while it awaits a result.
Shared client tests cover strict remote/local validation, `reply_query` and
its vectors separately; `chat::session` tests reproduce the stale `Stop` batch
with exact and whole-second times. Host-work and R9 fixtures check that the
internal attachment preserves existing remote admission, leases, approvals and
fencing.

These are runtime and protocol tests with fake providers. They do not claim a
live Claude/Codex conversation, native app acceptance or deployed cross-host
delivery. Stages 2 and 3, the directory in the vault, cross-instance return
grants, Station typed adapters/capacity, mailbox and signed projects remain
outside this implementation.

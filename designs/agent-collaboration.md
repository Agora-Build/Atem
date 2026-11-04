# Agent collaboration: Atem-to-Atem messaging

Status: **proposed** (2026-11-04), for review by the Atem, Astation and
Auth/Portal agents. Nothing in this document is built. It changes no part of
the existing permission contract: every part that would is marked **Needs
agreement** and waits until all three projects agree.

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
| 1. Local | Agents on the same Atem instance | Atem only; can be built now |
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

Stage 1 is the same on one host, with the whole budget.

This needs a new host-work destination, `select{selectors, budget}`, beside
`host`, `project` and `agent` (feature `host.select`), as a typed field in the
shared SDK. Between Atem instances that is Atem's change alone; through the
Station's adapters (stage 2) the Station must accept it too.

**When no agent runs.** A matching route whose owner allows it
(`launch = "on_message"`, off by default) gets one session launched from its
profile. The resolution records the launch request id instead of a session;
the task is bound to the new session (its id and process generation) when the
launch starts, and waits until the session is ready. A failed launch fails the
task. A remote sender also needs its existing `launch` permission for that; a
local sender needs only the route setting. `--launch` asks for it explicitly
when addressing `atem:<atem_id>/<route_id>`.

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
- each sender sends at most `per_hour` messages (default 30);
- a send from an agent whose current turn came from a task reuses that task's
  `workflow_id`. Each instance sends at most `per_workflow` (default 8)
  envelopes per workflow and accepts at most that many tasks and results per
  workflow, so neither a loop between agents nor a result can start a fresh
  chain, without a hop counter on the wire;
- receivers keep every host-work check: readiness, no draft, no open approval,
  no takeover, FIFO per session;
- every counter (per hour, per workflow, results per task) is durable in
  `host-work.sqlite` and survives a restart.

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
  equal to the channel's principal; that rule stays for every channel);
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
`--vault <id>@<version>` the outbox:

1. publishes it: memory through the sync push (its result names the
   canonical id and `seq`); a vault write returns its entry, version and `seq`;
2. reads it back from the relay: memory by pulling from just below that `seq`
   (the relay has no fetch by id), the vault entry by reading from `seq - 1` and
   matching entry and version; both come back decrypted;
3. compares the plaintext with the local text, and freezes the typed snapshot
   `{kind, id, version, digest: sha256(text), text}` into the envelope (the
   memory's own hash is a normalized dedup key, not this digest).

Only then does the row leave `publishing`. A failure retries and never sends.

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

## 10. Status and results

**Two statuses, never mixed.**

| Delivery (per instance) | Execution (per task) |
|---|---|
| `publishing`, `ready`, `sent`, `accepted`, `refused`, `expired` | `queued`, `blocked(<reason>)`, `submitting`, `submitted`, `awaiting_result`, `completed`, `failed`, `cancelled`, `expired`, `outcome_unknown` |

`blocked` names its reason: agent busy, terminal draft, approval open, lease
held, sender offline, screenshot missing, launching.

**Automatic status.** The receiving runtime reports each task transition to
the sender: in-process in stage 1; in stage 2 the sender's outbox polls
`message_query` and `tasks/:id` instead; in stage 3 as `status` envelopes
through the mailbox. The sending agent reads them with `atem message status`;
nothing is typed or prompted into its session for a status (only a result,
under its return grant, below).

**Results.** A finished turn is not a finished task, and only an explicit
result completes one.

- **Return grant.** Sending a request creates, in the sender's runtime, one
  narrow return grant per task: `{task_id, workflow_id, the recipient's host
  identity and principal, the originating session and process generation, the
  original sender principal, expires_at}` (the task's expiry plus a result
  window, at most 24 h). It permits exactly one correlated result back into
  that one session, and nothing else: no request, notify or launch authority,
  no other session. It ends at the first matching result, the task's
  cancellation or expiry, the originating process ending, or a change of the
  original sender's authority (`control_gen`) or of the route. Results also
  need the owner's opt-in on the originating session's route (`results =
  true`); without it a result is stored and shown by `atem message status`,
  never prompted.
- **Replying.** The receiving agent answers with `atem message reply --task
  <id> [--vault <id>@<version>] <text>`; `--task` may be left out only when
  exactly one task of the calling session awaits a result. The runtime binds
  the reply to that exact task, session, process and turn (the turn id the
  task's prompt receipt recorded), since a finished turn releases its queue slot
  while the task may still await its result. It publishes the context first
  (section 8) and sends one `result` envelope.
- **Accepting.** The sender's runtime accepts a result only if it matches a
  live return grant exactly; the result then goes through the normal queue,
  readiness, approval and lease checks into the originating session, marked as
  data, not as the owner's instruction (`[atem] result of task <id> from
  <sender>, as data:`), and counted against the workflow's limit. The first
  result is final and durable: an identical repeat returns its receipt, a
  different one for the same task is refused (`request_id_reused`), a mismatch
  (other task, session, process or recipient) is refused.
- **Completing.** On accepting an explicit result, the sender's runtime calls
  `work_complete` with the result's snapshot. Nothing else completes a task.
- **Automatic reports.** A turn that ends without a reply leaves the task
  `awaiting_result`. After `result_timeout` (default 30 minutes) the receiving
  runtime sends a progress report ("turn ended without a reply"), never a
  result: it doesn't complete the task or consume the return grant. A route can
  opt in to include the turn's final assistant message in that report
  (`auto_report = "final_message"`); it may hold command output or values the
  agent never meant to send, so it stays off by default.

Stage 1 implements all of this within one runtime. Cross-instance, the return
grant is a contract to agree with Astation before stage 2.

## 11. Offline recovery

| Situation | Stages 1–2 | Stage 3 |
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
[instance]
labels = ["project:astation", "tag:mac-mini"]

[collab]
send = true                 # off by default
per_hour = 30
per_workflow = 8
result_timeout = "30m"
integration = "i-..."       # stage 2: this instance's Station integration
station = "https://station-dev.agora.build"

[[routes]]
id = "auth"
revision = 1
profile_id = "auth"
labels = ["tag:auth"]
principals = ["local"]      # stage 2 adds services; stage 3 may add project:<name>
launch = "on_message"       # optional
results = true              # off by default: results of tasks this route's agents sent reach them
auto_report = "status"      # or "final_message" (opt-in)
```

| Command | Effect |
|---|---|
| `atem message send --to <selector>… [--memory <id>]… [--vault <id>@<version>]… [--launch] [--expires <duration>] <text>` | Queue one request; prints its id |
| `atem message reply [--task <id>] [--memory <id>]… [--vault <id>@<version>]… <text>` | From inside a task's session: its result, bound to that task, session, process and turn |
| `atem message status [<id>]` | Delivery per instance and execution per task |
| `atem message cancel <task id>` | While the task is queued or blocked |
| `atem message directory [<selector>]` | The instances and agents a selector reaches now |
| `atem agent tag add\|remove\|list [<name>]` | The calling agent's own `self:` tags |

Every command is a client of the local runtime, which does the work.

## 14. What can be built now, and what depends on others

| Item | Owner | Depends on |
|---|---|---|
| Labels and `atem agent tag` | Atem | nothing |
| Directory records in the vault (needed from stage 2: local delivery resolves selectors itself) | Atem | nothing |
| Outbox, retries, deduplication, delivery status | Atem | nothing |
| Publish before notify: publish, read back, freeze | Atem | nothing |
| Local delivery between agents of one instance: the internal `local` attachment and route principal | Atem | nothing |
| The `select` destination with budgets and persisted resolution, launch on message, automatic reports, return grants and results (local) | Atem | nothing |
| Cross-instance delivery while online, as a Station integration | Atem | Agreements with Astation: the return grant, the typed `select` and snapshot boundary. Station: turning on the host-work gate (off on every Station; it grants `agent.launch`/`message`/`notify` only when built with `host-work-api`); `routes` and `work_complete` adapters; `select` and typed snapshots in the message adapter; separate connection and request budgets. Auth/Portal: nothing new: the owner registers the instance's public key as a "Custom App / API" integration, and the scope names are final |
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

## 17. Stage 1 build plan

Status: **for the owner's approval; no code yet.** Stage 1 needs nothing from
the Station, Astation or Auth/Portal and no permission-contract change. Each
task below names its files, interfaces and tests; the implementer writes the
code test-first, task by task, with a review between tasks.

### Constraints

The rules above bind every task; in particular:

- one runtime only: the `host.select` feature is **not** advertised to remote
  clients until stage 2 is agreed (section 5);
- labels, selectors, the 32-agent budget, fixed resolution and stable task ids
  as in sections 4 and 5 (UUIDv5 of message, recipient and session);
- defaults as in section 13: `[collab] send = false`, `per_hour = 30`,
  `per_workflow = 8`, `result_timeout = "30m"`; per route `launch` off,
  `results = false`, `auto_report = "status"`;
- envelope expiry at most 24 h; a return grant at most 24 h past its task's
  expiry; outbox retries from 1 s to 5 minutes (sections 7 and 10);
- only an explicit result completes a task (section 10);
- tests never touch the real profile; `rustfmt --edition 2024` only files that
  were clean; no backward-compatibility shims; commits end with
  `🤖 Built with SMT <smt@agora.build>`, and nothing is pushed or merged
  without the owner's request.

### File map

| File | Responsibility |
|---|---|
| `src/runtime/host_work.rs` | runtime.toml schema (labels, `[instance]`, `[collab]`, route options, the `local` principal); store tables for outbox, resolutions, return grants, counters |
| `crates/atem-client/src/session/select.rs` (new) | labels, selectors, matching, budgets (shared SDK, so stage 2 reuses it) |
| `crates/atem-client/src/session/messages.rs` | `Destination::Select`, envelope fields (`kind`, `reply_to`, `from_session`), local-sender validity |
| `src/runtime/protocol.rs`, `server.rs` | local-protocol ops (`tag`, `message_send`, `message_reply`, `message_status`, `message_cancel`, `message_directory`); the client's peer pid |
| `src/runtime/adopt.rs`, `broker.rs` | process ancestry walk; a session's agent pid and its `self:` tags |
| `src/runtime/collab.rs` (new) | the collaboration service: resolution, limits, outbox state machine, return grants, results, automatic reports |
| `src/runtime/collab_context.rs` (new) | publish-before-notify for Memory and Vault (publish, read back, freeze snapshots) |
| `src/runtime/host_work_bridge.rs`, `host_bridge.rs`, `src/session_protocol/host.rs` | the `Sender` abstraction, the internal `local` attachment, launch on message |
| `src/runtime/commands.rs`, `src/cli.rs` | `atem message …` and `atem agent tag …` |
| `tests/fixtures/approvals/fake-agent.py` | `run-<n>.json`: run a command as the agent's child (real process ancestry in tests) |
| `tests/collab_binary.rs` (new) | stage 1 end to end against the real runtime |


#### Task 1: runtime.toml: labels, `[collab]`, route options, the `local` principal

**Files:**
- Modify: `src/runtime/host_work.rs` (`Config` 22-32, `Route` 56-65, `principal_ok` 67-73, `principals_problem` 77-94, `Config::validate` 175-242, `check` ~728)
- Modify: `configs/runtime.example.toml`
- Test: `src/runtime/host_work.rs` (tests module, after `invalid_files_say_what_and_where`)

**Interfaces:**
- Produces:
  - `pub struct Instance { pub labels: Vec<String> }` (`#[serde(deny_unknown_fields)]`, `Default`), field `#[serde(default)] pub instance: Instance` on `Config`.
  - `pub struct Collab { pub send: bool, pub per_hour: u32, pub per_workflow: u32, pub result_timeout: String }` with `impl Default` (false, 30, 8, `"30m"`) and `pub fn result_timeout_ms(&self) -> u64`; field `#[serde(default)] pub collab: Collab` on `Config`.
  - On `Route`: `#[serde(default)] pub labels: Vec<String>`, `#[serde(default)] pub launch: RouteLaunch` (`enum RouteLaunch { #[default] Off, OnMessage }`, snake_case), `#[serde(default)] pub results: bool`, `#[serde(default)] pub auto_report: AutoReport` (`enum AutoReport { #[default] Status, FinalMessage }`).
  - `pub fn label_problem(label: &str, owner: bool) -> Option<String>` (owner: `project:`/`tag:` only; agent: `self:` only; names as in section 4).
  - `principal_ok` accepts the bare `local` for **routes only** (profiles keep `member:`/`service:`/`browser:`; a remote `launch` still needs profile principals).

- [ ] **Step 1: Write the failing tests** — `labels_and_collab_parse_with_defaults` (a file without the new keys loads with `Collab::default()`, empty labels, `launch = Off`, `results = false`, `auto_report = Status`); `labels_say_what_and_where` (using the `PROFILE.replace(..)` pattern: `tag:Auth` → `route `backend`: label "tag:Auth": names are 1-32 of a-z, 0-9 and -`; `self:x` in a route → owner labels are project: or tag:; 65 labels → at most 64); `local_is_a_route_principal_only` (route `principals = ["local"]` loads; profile `principals = ["local"]` fails with the profile's name); `result_timeout_parses` (`"30m"`, `"90s"`, `"2h"`; `"0s"` and `"25h"` refused).
- [ ] **Step 2: Run** `cargo test --bin atem host_work::tests` — expect compile errors / failures for the new fields.
- [ ] **Step 3: Implement** the structs, defaults and validation (copy the route `if / else if` chain style; errors keep "route `id`: …" / "[collab]: …" / "[instance]: …").
- [ ] **Step 4: Extend `check()`** to print instance labels, each route's labels/launch/results/auto_report and whether sending is on; extend `check_lists_who_may_launch` assertions accordingly.
- [ ] **Step 5: Run** the tests; then `cargo test --test host_work_binary -- --test-threads=1` (no regressions: `deny_unknown_fields` still refuses unknown keys).
- [ ] **Step 6: Document** the keys in `configs/runtime.example.toml` (commented, defaults shown).
- [ ] **Step 7: Commit** `runtime.toml: labels, [collab] and route options for agent collaboration`.

#### Task 2: selectors and the `select` destination in the shared SDK

**Files:**
- Create: `crates/atem-client/src/session/select.rs` (+ `pub mod select;` in `session/mod.rs`)
- Modify: `crates/atem-client/src/session/messages.rs` (`Destination` 24-40, `Message` 61-74, `Message::valid` 77-129, `MessageReceipt::valid` 268-287)
- Test: `crates/atem-client/src/session/select.rs` (unit), `crates/atem-client/tests/` (vector file `vectors/select.json` for stage 2 parity)

**Interfaces:**
- Produces:
  - `pub enum Label { Project(String), Tag(String), SelfTag(String) }`, `impl FromStr for Label`, `Label::as_str`.
  - `pub enum Selector { All(Vec<Label>), Instance { atem_id: String, route_id: Option<String> } }`, `impl FromStr for Selector` (`project:a+tag:b` → `All`), `pub fn matches(&self, agent: &AgentLabels) -> bool`.
  - `pub struct AgentLabels<'a> { pub atem_id: &'a str, pub route_id: &'a str, pub labels: &'a BTreeSet<Label> }`.
  - `pub const MAX_SELECTORS: usize = 16; pub const MAX_AGENTS: u32 = 32;`
  - `Destination::Select { selectors: Vec<String>, budget: u32 }` (validated: 1–16 parseable selectors, `1 ≤ budget ≤ 32`; across a message the budgets total at most 32).
  - `Message` gains `#[serde(default)] pub kind: MessageKind` (`Request` default, `Status`, `Result`), `#[serde(default, skip_serializing_if = "Option::is_none")] pub reply_to: Option<ReplyTo>` (`{message_id, task_id}`), `#[serde(default, skip_serializing_if = "Option::is_none")] pub from_session: Option<String>`.
  - `pub fn valid_local(&self) -> bool`: like `valid()` but the sender is exactly `local` and `from_session` is a valid session id; `valid()` keeps refusing `local`.
- Consumes: nothing from earlier tasks.

- [ ] **Step 1: Failing tests** — `labels_and_selectors_parse` (each form; `tag:`/`self:` names rule; empty and 17 selectors refused); `and_selectors_need_every_label`; `instance_selectors_match_one_atem_id_and_route`; `select_budgets_total_at_most_32` (two recipients 20 + 13 → invalid; 20 + 12 → valid); `a_local_envelope_is_valid_only_through_valid_local` (`valid()` false, `valid_local()` true; a `member:` sender is false for `valid_local`); `serde_round_trip_keeps_new_fields_optional` (a v0.8 envelope without them still decodes).
- [ ] **Step 2: Run** `cargo test -p atem-client select` — expect failures.
- [ ] **Step 3: Implement** select.rs and the messages.rs changes (`deny_unknown_fields` stays; new fields are optional).
- [ ] **Step 4: Run** `cargo test -p atem-client -p atem-client-ffi` (bindings still build; UniFFI records gain the optional fields).
- [ ] **Step 5: Commit** `atem-client: labels, selectors and the select destination`.

#### Task 3: the calling session, `self:` tags, and the fake agent's child commands

**Files:**
- Modify: `src/runtime/server.rs` (acceptor 207-217 keeps `cred.pid()`; `struct Client` 90-108 gains `peer_pid: Option<u32>`; `add_client` 393)
- Modify: `src/runtime/adopt.rs` (new `pub fn ancestors(pid: u32, limit: usize) -> Vec<u32>` over `process_parent_and_name`)
- Modify: `src/runtime/broker.rs` (accessors `pub fn agent_pid(&self) -> Option<(u32, u64)>` from the worker info + start time; `self_tags: BTreeSet<String>` with `add_tag`/`remove_tag`/`tags`)
- Modify: `src/runtime/protocol.rs` (`ClientMsg::Tag { op: TagOp, name: Option<String> }` → `RuntimeMsg::Tags { session_id, tags }`; `ClientMsg::op()` arm)
- Modify: `src/runtime/commands.rs`, `src/cli.rs` (`AgentCommands::Tag { command: TagCommands }`: `Add{name}`, `Remove{name}`, `List`)
- Modify: `tests/fixtures/approvals/fake-agent.py` (`run-<n>.json` = `{"argv": [...]}`: the agent runs it as its own child, writes `run-<n>.out` with exit code, stdout and stderr)
- Test: `src/runtime/adopt.rs` (unit), `src/runtime/server_tests.rs`, `src/cli.rs` (parse), `tests/collab_binary.rs` (new)

**Interfaces:**
- Produces: `Server::calling_session(&self, client: u64) -> Option<SessionId>` — walks `ancestors(peer_pid, 64)` and returns the live session whose agent pid **and** start time match (never a stale pid); `RuntimeMsg::Tags`; `BrokerSession::self_tags()`.
- Consumes: `label_problem(…, owner = false)` from Task 1.

- [ ] **Step 1: Failing tests** — `ancestors_walk_to_init_and_stop_at_the_limit` (unit, with an injected parent lookup); server test `a_tag_from_outside_a_session_is_refused` ("not inside an Atem session"); server test `tags_belong_to_the_calling_session` (two in-process sessions; a client whose peer pid is a child of session A's agent adds `self:x`; `list` shows it on A only; 17th tag refused; `tag:x` refused with the owner-label message); cli parse test `cli_agent_tag_parses`; binary test `collab_binary::an_agent_tags_itself_through_its_own_child` (fake agent `run-1.json` runs `atem agent tag add self:reviewer`; `atem agent list` shows it).
- [ ] **Step 2: Run** the tests — expect failures.
- [ ] **Step 3: Implement** the peer pid capture, ancestry walk, accessors, protocol op (`waits_for_adoption` includes `Tag`), CLI, fake-agent extension.
- [ ] **Step 4: Run** `cargo test --bin atem` and `cargo test --test collab_binary -- --test-threads=1`.
- [ ] **Step 5: Commit** `runtime: identify the calling session; agents' own self: tags`.

#### Task 4: the `local` sender: one internal attachment and a `Sender` abstraction

**Files:**
- Modify: `src/runtime/host_work_bridge.rs` (every `Authority` use listed below)
- Modify: `src/runtime/host_bridge.rs` (create the attachment after the host starts and after `restart`/`rebind`; keep it out of `send`/`send_chat`, `exec` `Close`/`Replaced`, `r9_exec`)
- Modify: `src/session_protocol/host.rs` only if a test shows a needed change (expected: none; `connect` + `welcome_r9` accept `local`)
- Test: `tests/collab_binary.rs`, `src/runtime/host_bridge_tests.rs` or `server_tests.rs` (whichever already builds a host bridge with in-process workers)

**Interfaces:**
- Produces:
  - `pub(crate) enum Sender { Remote(Authority), Local }` with `name()` (`"local"` for Local), `owner()` (replaces `attachment_owner`: `digest(("local", "local"))` for Local), `allows_work()` (Local: true; route consent still decides), `in_scope(..)` (Local: true).
  - `HostBridge::local_attachment(&self) -> &str` (its id; recreated when the host restarts or rebinds).
  - `HostBridge::local_publish(&mut self, message: &Message, resolution: &[ResolvedTask], cx) -> Result<MessageReceipt, &'static str>` (used by Task 5).
- Rewrites (each currently takes `&Authority`): `profile_allowed`, `work_allowed`, `work_route_allowed`, `work_fence_launches`, `message_scope`, `message_request`, `schedule_work`'s dispatcher lookup (Local tasks dispatch on `local_attachment()` when `r.principal == "local"`), `attachment_owner`, `authority_session`.
- Consumes: Task 1 (`local` in route principals), Task 2 (`valid_local`).

- [ ] **Step 1: Failing tests** — `a_local_task_dispatches_as_a_prompt_with_a_receipt` (route `principals = ["local"]`; a task queued by `local_publish` reaches the fake agent's input once; its receipt is `completed` at the turn end; the task becomes `awaiting_result`); `a_local_task_waits_for_a_remote_lease_and_never_takes_it` (a remote `svc-work` holds the lease: blocked "waiting for controller to release the lease"; after release it dispatches); `the_person_at_the_terminal_takes_control_back` (local input while a local task's lease is held revokes it, as for a remote controller); `a_route_without_local_refuses_it` (receipt `forbidden`); `the_local_attachment_survives_a_link_drop_and_returns_after_a_rebind`.
- [ ] **Step 2: Run** — expect failures.
- [ ] **Step 3: Implement** `Sender`, the attachment lifecycle and exclusions; keep r9 behaviour byte-identical (run `cargo test --test host_work_binary` and `--test runtime_fixtures_binary r9_fixtures`).
- [ ] **Step 4: Run** all of the above plus `cargo test --bin atem`.
- [ ] **Step 5: Commit** `runtime: a local sender on an internal session-host attachment`.

#### Task 5: the outbox, fixed resolution, limits, and `atem message send|status|cancel|directory`

**Files:**
- Create: `src/runtime/collab.rs`
- Modify: `src/runtime/host_work.rs` (tables `outbox(message_id, envelope, state, detail, next_try_ms, created_ms)`, `resolutions(message_id, recipient_id, task_id, route_id, session_id, process_gen, launch_request_id)`, `counters(key, window_start_ms, count)`; all in one transaction with `accept_message`)
- Modify: `src/runtime/protocol.rs`, `server.rs` (`message_send`, `message_status`, `message_cancel`, `message_directory` ops; network or slow work off the loop like `start_op`)
- Modify: `src/runtime/commands.rs`, `src/cli.rs` (`Commands::Message { command: MessageCommands }`)
- Modify: `Cargo.toml` (`uuid` features `["v4", "v5"]`)
- Test: `src/runtime/collab.rs` (unit), `tests/collab_binary.rs`

**Interfaces:**
- Produces:
  - `pub struct SendRequest { to: Vec<String>, text: String, memory: Vec<String>, vault: Vec<(String, u32)>, launch: bool, expires_ms: u64 }` (protocol payload).
  - `collab::resolve(config: &Config, sessions: &Sessions, selectors: &[Selector], budget: u32, from: &SessionId) -> Vec<ResolvedTask>` (pure; order and `task_id` as in section 5).
  - `collab::Limits::check_and_count(store, from_session, workflow_id, now) -> Result<(), LimitHit>` (durable counters).
  - `RuntimeMsg::MessageSent { message_id }`, `RuntimeMsg::MessageStatus { messages: Vec<MessageView> }` (delivery per host, execution per task; `blocked` with its reason).
- Consumes: Tasks 1–4.

- [ ] **Step 1: Failing tests** — unit `resolution_is_ordered_budgeted_and_stable` (route id then session start; 40 matches → 32; same inputs → same `task_id`s); unit `limits_survive_a_reopen` (`per_hour` 2: the third send is `limit: 2 messages per hour`; reopen the store, still refused); unit `a_workflow_counts_sends_from_its_tasks` (a send from a session whose current turn came from task T reuses T's `workflow_id`; the 9th is refused); binary `one_message_reaches_two_agents_once_each` (three fake-agent sessions tagged via routes `tag:a`, `tag:b`, `tag:b`; A runs `atem message send --to tag:b "…"` through `run-1.json`; both B sessions get exactly one prompt with the task id; A gets none; `atem message status` shows two tasks `awaiting_result` after their turns end); binary `sending_is_off_by_default` (`[collab] send` absent → refused "collaboration is off: set [collab] send = true"); binary `a_retry_returns_the_recorded_resolution` (restart the runtime between send and dispatch; tags changed meanwhile; the same tasks dispatch, no new ones); binary `cancel_works_while_queued_only`.
- [ ] **Step 2: Run** — expect failures.
- [ ] **Step 3: Implement** collab.rs (send pipeline: limits → resolve → persist envelope + resolution + tasks + return grants (Task 7 adds grants; leave the table hook) in one transaction → `local_publish`), the ops, the CLI (`atem message directory` prints the local routes, their labels and the live agents with their tags, plus what a given selector would reach).
- [ ] **Step 4: Run** `cargo test --bin atem collab` and `cargo test --test collab_binary -- --test-threads=1`.
- [ ] **Step 5: Commit** `runtime: atem message send with a durable outbox and fixed resolution`.

#### Task 6: publish before notify (`--memory`, `--vault`)

**Files:**
- Create: `src/runtime/collab_context.rs`
- Modify: `src/memory/sync.rs` (a public `push_memory_and_read_back(store, client, ctx, id) -> Result<ReadBack>` built on `KnowledgeClient::push` + `pull_memories(since = seq - 1)`, matching the canonical id), `src/vault_client.rs` (`read_back(vault_id, entry_no, version, seq) -> Result<String>` via `read(since = seq - 1)`)
- Modify: `src/runtime/collab.rs` (outbox state `publishing` → `ready`; retry with backoff; never send on failure)
- Test: `src/memory/e2e_tests.rs` (fake relay already there), `src/runtime/collab_context.rs` (unit with injected publisher), `tests/collab_binary.rs`

**Interfaces:**
- Produces: `trait ContextPublisher { async fn memory(&self, id: &str) -> Result<ContextSnapshot>; async fn vault(&self, id: &str, version: u32) -> Result<ContextSnapshot>; }` with the relay implementation; snapshot `digest = sha256(exact plaintext)` (not the memory's normalized `content_hash`); `kind` `Memory`/`Vault`.
- Consumes: Task 5's outbox.

- [ ] **Step 1: Failing tests** — e2e `a_pushed_memory_reads_back_by_its_seq` (encrypted and plain modes; the read-back plaintext equals the local text; a canonical id rewrite is followed); unit `publishing_failure_never_sends_and_retries` (publisher fails twice: state stays `publishing`, no task exists; then succeeds: one task, snapshot attached); unit `a_mismatched_read_back_is_refused` (relay returns other text: state `refused(context changed)`); binary `a_vault_reference_arrives_as_its_exact_text` (binary tests have no relay, so the runtime's publisher is replaced through a debug-only hook, `ATEM_TEST_CONTEXT_DIR` in `runtime/test_hooks.rs`, which serves snapshots from files; release builds ignore it; the B agent's prompt holds the exact text and digest); binary `an_unreachable_relay_keeps_the_send_publishing` (no hook, no relay: state `publishing`, detail "relay unreachable", no task).
- [ ] **Step 2: Run** — expect failures.
- [ ] **Step 3: Implement** the publisher, the read-back helpers and the outbox state.
- [ ] **Step 4: Run** `cargo test --bin atem memory::e2e_tests collab` and the binary tests.
- [ ] **Step 5: Commit** `runtime: publish Memory and Vault context before sending, read back and frozen`.

#### Task 7: return grants, `atem message reply`, results and automatic reports

**Files:**
- Modify: `src/runtime/host_work.rs` (tables `return_grants(task_id, workflow_id, recipient, origin_session, origin_process_gen, sender, expires_ms, state)`, `results(task_id, digest, envelope)`)
- Modify: `src/runtime/collab.rs`, `host_work_bridge.rs` (turn end → `awaiting_result` hook at the `reconcile_work` transition in `schedule_work`; result timeout timer; final assistant message text via `chat.retained()` filtered by the turn id, last assistant non-card message)
- Modify: `src/runtime/protocol.rs`, `server.rs`, `commands.rs`, `src/cli.rs` (`message_reply`)
- Test: `src/runtime/collab.rs` (unit), `tests/collab_binary.rs`

**Interfaces:**
- Produces: `collab::ReturnGrant`; `collab::accept_result(store, envelope, now) -> Result<ResultOutcome, Refusal>` (`Accepted`, `Duplicate(receipt)`; refusals `request_id_reused`, `no_grant`, `mismatch`, `expired`); `RuntimeMsg::MessageReplied { task_id }`.
- Rules (section 10): one grant per task at send time; ends at the first matching result, cancellation, expiry, the originating process ending, a `control_gen` or route change; results prompt the origin session only when its route has `results = true` (else stored, shown by `atem message status`); prompt text starts `[atem] result of task <id> from <sender>, as data:`; on acceptance the runtime calls `work_complete` with the result's snapshot; automatic reports after `result_timeout` are status only (the final message only with `auto_report = "final_message"`) and never complete or consume.
- Consumes: Tasks 4–6.

- [ ] **Step 1: Failing tests** — unit `a_grant_permits_one_result_into_one_session` (second identical → `Duplicate`; different text → `request_id_reused`; other session or process → `mismatch`); unit `a_grant_ends_with_cancel_expiry_process_end_and_control_change`; binary `a_reply_comes_back_as_data_and_completes_the_task` (A sends to B; B's agent runs `atem message reply --vault … "done"` through `run-<n>.json`; A's route has `results = true`; A gets one prompt starting with the data marker; the task is `completed` with the result snapshot); binary `without_results_true_a_result_is_status_only`; binary `reply_needs_task_when_two_are_waiting` (two tasks awaiting in B: plain `reply` is refused, `--task` works); binary `a_silent_turn_gets_a_report_not_a_result` (`result_timeout = "1s"` via config: status "turn ended without a reply", the task stays `awaiting_result`, no prompt to A).
- [ ] **Step 2: Run** — expect failures.
- [ ] **Step 3: Implement** grants, reply binding (task, session, process, turn id from the prompt receipt), acceptance, completion and the timer.
- [ ] **Step 4: Run** the unit and binary tests; then `cargo test --bin atem`.
- [ ] **Step 5: Commit** `runtime: correlated results under a return grant; automatic reports`.

#### Task 8: launch on message

**Files:**
- Modify: `src/runtime/host_work_bridge.rs` (a local launch reuses `RemoteLaunch`/`PendingLaunch`/`LaunchRecord`; the resolution row records `launch_request_id`; the task binds to the session and process generation when the launch starts; a failed launch fails the task)
- Modify: `src/runtime/collab.rs` (resolution: a matching route with `launch = "on_message"` and no live agent contributes one launch within the budget)
- Test: `tests/collab_binary.rs`

**Interfaces:**
- Consumes: Tasks 4–5; produces no new public API.

- [ ] **Step 1: Failing tests** — binary `a_message_to_an_empty_route_launches_one_agent` (route `tag:c` with `launch = "on_message"`, no session: one session starts from the profile, the task dispatches when ready, `atem agent list` shows it); binary `launch_stays_off_by_default` (`no_match`, no session); binary `a_failed_launch_fails_its_task` (profile cwd removed: the task `failed` with the launch's reason).
- [ ] **Step 2–4:** run, implement, run (`--test host_work_binary` too: remote launch unchanged).
- [ ] **Step 5: Commit** `runtime: launch on message from an approved route`.

#### Task 9: documentation

**Files:**
- Modify: `designs/agent-collaboration.md` (status: stage 1 implemented in Atem vX; keep stages 2–3 marked as not implemented), `designs/agent-hosting.md` (pointer), `AGENTS.md` (component paragraph, tree: `collab.rs`, `collab_context.rs`, `tests/collab_binary.rs`), `README.md` (a short "Agents asking agents" section with one example), `configs/README.md`.

- [ ] **Step 1:** update the docs; run the link check.
- [ ] **Step 2:** `cargo test` (whole workspace) and `cargo clippy --all-targets --all-features` (nothing new).
- [ ] **Step 3: Commit** `docs: agent collaboration, stage 1`.


### Coverage and risk

- **Coverage (stage 1):** labels and `self:` tags (T1, T3); selectors, budget, fixed resolution, stable task ids (T2, T5); `local` sender with receipts, leases and fence (T4); outbox, retries, dedup, limits, durable counters (T5); publish before notify with read-back (T6); return grants, exact reply binding, explicit completion, automatic reports, results as data with route opt-in (T7); launch on message (T8); status split delivery/execution (T5, T7); docs (T9). The directory in the vault is stage 2 and not in this plan; `atem message directory` shows local agents only.
- **Deliberate gaps:** stage 2 transport, typed snapshots through the Station, the cross-instance return-grant contract, mailbox and signed projects.
- **Risk:** Task 4 touches the session host's attachment handling; its r9 regression runs (`host_work_binary`, `runtime_fixtures_binary r9_fixtures`) are mandatory before its commit.

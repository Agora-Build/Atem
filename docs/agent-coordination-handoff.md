# Remote agent launch and notifications: cross-repository handoff

Updated: 2026-11-02 UTC.

The user approved starting both features and asked for this context to be
shared with the Astation and Station agents. The current designs are on
`Agora-Build/Atem` main in commit `3946c5b`:

- [Optional hosting and remote launch](../designs/agent-hosting.md)
- [Agent notifications](../designs/agent-notifications.md)

Atem receiver implementation is on `feat/agent-launch-notifications`:
approved local profiles, host-level launch/query, durable task queue,
safe existing-session scheduling and explicit correlated results. The
[host-work extension](../designs/protocol/atem-host-work-v1.md) specifies its
current wire/types/limits and remaining integration boundaries. New tests use
the real runtime, encrypted channels and fake CLIs in isolated profiles.
This branch is not deployed. OS service installation, Station publication/
replay, automatic launch-on-arrival and Astation UI remain to be built.

The unified [message API](../designs/protocol/atem-messages-v1.md) now accepts
inline text, exact context snapshots, or both, with one or many explicit
recipients. A single host transaction stores the envelope, each recipient's
decision and any executable tasks before acknowledgment. Native members can
store ordinary notices without profile principal consent; services need
`message`, which grants no agent control. Agent delivery still needs the
existing notify/prompt permissions and local route consent. Progress stays on
the original message/task receipt; no separate `runtime inbox` command exists.
Shared bindings use `Attached::send` and Family JSON events.

Chisel/mark now uses the same FIFO per-session queue and normal acquiring prompt
receipts. The old App dispatcher, background `claude -p` triage and local-input
exception are removed. Legacy `markTaskAssignment` returns a failed
`markTaskResult` with upgrade guidance. **Clients must upgrade from the ID-only
sender before mark execution works with this build.** See the
[mark/attachment contract](../designs/protocol/atem-task-attachments-v1.md):

1. Chisel retains task JSON and annotated PNG locally, and supplies actual PNG
   bytes to its authorized publishing client (task ID/path alone is insufficient).
2. The client uploads PNG chunks through `attachment_put` in an admitted encrypted
   channel (`host.attachments`), then `message_publish` with typed `mark` metadata
   and the exact screenshot descriptor. Use the same publisher principal/key.
3. Atem stores/verifies bytes durably, materializes a private PNG and appends its
   path to the shared task prompt. Missing bytes block work. Track the original
   message's recipient receipt and explicit correlated completion.
4. Online Chisel/Station delivery is implemented in the sibling
   `chisel-online-mark` and `Astation-online-mark` worktrees. Chisel sends actual
   PNG bytes through the authenticated HTTP marks endpoint; Station's NDJSON
   response owns one R9 service channel through queueing/turn-end. Local files
   and immutable IDs remain on failure. No automatic retry or offline features
   are included, per the user's current scope. The hosted API gate stays intact.

The new sender is verified through Chisel's built middleware, Station's real
HTTP/auth API and a signed encrypted host fixture; receiver/runtime behavior is
verified separately with the real Atem runtime and fake coding CLIs. Rust
Station vendors a source snapshot of this shared SDK with SHA-256 provenance.
Before live service enrollment, publish the SDK, upgrade all strict account
verifiers/Apple bindings, and opt in a new grant with `markTasks: true`. Existing
grants are unchanged. The native UI does not yet expose the opt-in; its typed
prepare/review API supports it. No live deployment or service changes occurred.

PNG bounds: 8 MiB each, 96 KiB decoded chunks, 256 upload identities and 128 MiB
reserved attachment bytes per host store. Uploads never grant agent execution.
There is no automatic attachment pruning yet; full stores refuse uploads.

Integration limits: the receiver derives the sender from the end-to-end channel
and refuses forwarded claims to another principal. Direct Atem host senders,
offline sender proof/admission, Station's durable cross-host outbox/replay and
actual transactional memory/vault write-and-notify are not implemented here.
The SDK fanout helper builds one request per host; it is not a durable outbox.
Keep the original envelope for each retry, reconcile recipients independently,
and do not claim these receiver tests validate deployed Station delivery.

Local setup uses `atem runtime start` and `atem runtime check`. Start creates
missing private `runtime.toml` disabled by default and starts/reuses the
background runtime without replacing a running build. Check validates profiles,
routes and environment sources without starting processes. Both require pairing.
Remote launch and notifications share that runtime; healthy enabled hosting
keeps it available with zero sessions. Bare `atem runtime` remains foreground;
service installation and boot startup are still separate planned work.

Integration attention: upgrade strict device-list verifiers before enrolling
the new launch/message/notify scope ops. Initial work carries immutable resolved
snapshots from an authorized publisher; Station must verify publication and
context access. Existing Family JSON events carry typed host_work_result data
through the client bindings. Review these choices before production wiring.

## User requirements

Remote launch creates a brand-new Codex or Claude process on the selected
machine. The user need not launch a coding CLI there in advance. Atem's runtime
must already be online; the original interactive CLI runs in a worker-owned
PTY. The session supports both ordinary local terminal use and remote text
terminal/chat control. Keep agent arguments such as `codex --profile oss`.
Custom provider base URLs and credentials come from a host-configured launch
profile; remote requests never depend on another terminal's exported variables.
Credentials are referenced by name and never included in this handoff or
in shared memory.

Persistent hosting is optional. Explicit service installation starts the
runtime now and at boot, including with zero agent sessions. Ordinary package
installation or upgrade creates no service. Reboot does not automatically
restart coding agents or replay work. tmux and Herdr remain optional frontends;
the runtime and workers own sessions.

Notifications let an agent on one machine publish context and request work
from another machine's agent, such as mobile asking backend for an API change.
Push an event to the receiving runtime, which durably queues the task and
dispatches it when authorized and ready. Coding agents do not poll an inbox
with timer-driven model calls. Ordinary memory/vault writes and sync do not
automatically start agent turns.

## Ownership

| Owner | Work |
|---|---|
| Atem | Optional hosting, singleton/worker lifetime, approved local project and launch profiles, remote-launch execution and durable results, durable task queue, readiness-aware agent dispatch and diagnostics |
| Astation | New Agent UX and authenticated launch client, host/project/profile selection, terminal/chat attach, launch-result recovery; configure notification roles/routes and show queued, blocked and completed work |
| Station | Authorized transport/API integration, durable notification publication/outbox, replay and acknowledgments, cross-replica delivery, access checks and result routing |
| Shared | Negotiate wire operations/features, permissions, encrypted envelopes, correlation/result recovery, bounds and fixtures before implementing incompatible endpoints |

## Contract work to agree first

Remote creation is a host-level operation inside the authenticated encrypted
channel. It cannot require the binding of a session that does not exist yet.
Select a locally approved project and profile, including its revision; do not
accept arbitrary remote shell commands, environment values or filesystem paths.
Define explicit launch authority and how native, service and browser scopes
authorize creating a new session. Existing `view` or `control` does not silently
grant launch permission.

The launch request needs a durable request ID, payload digest and expiry.
Reserve its session ID and process generation before spawn; persist the result
before acknowledgment. Retrying a request returns its recorded result, and
reusing an ID with different input is a conflict. Recovery reconciles worker
records and process identity rather than spawning again. Results need their
own retention/admission rules beyond the exited-session list's ten minutes.
Report process creation separately from chat readiness. Submit the first prompt
through the existing receipt path after readiness.

A notification needs a stable task ID, authenticated sender, destination
role/project/host and routing generation, workflow/correlation ID, immutable
context references with digests, expiry and a completion destination. Commit
content and its outbox event atomically, or notify only already committed
content. Unsynchronized sender-local memory is not a published reference.

Station delivery is at least once. Atem acknowledges only after durable task/receipt
storage, with the receive cursor committed alongside acceptance. Reconnect and
replica changes replay without a snapshot/live gap. Deduplicate by task ID,
not delivery attempt. Define queue bounds, expiry, gaps, cancellation and result
recovery; an ambiguous launch or prompt must never be retried as new work.

Delivery must reach the runtime whether it currently uses its local Astation
link or its relay link, and when the Astation UI is closed. The current
local-first connection is not a generic Station event subscription. Specify an
independent authenticated subscription or equivalent durable forwarding.

Execution requires its own scoped grant. Memory/vault write access and a
self-reported writer label are not permission to run agents. Revalidate
membership, project/profile scope, route policy and expiry at acceptance and
before launch/submission. Preserve revocation, held-membership and hosted
execution gates. Queue while an agent is busy, has a draft, awaits approval or
has another controller; do not label peer work as local input or bypass leases.
An agent question or turn-end is not automatically task completion. Require a
correlated result and bound workflow recursion.

## Implementation and verification order

1. Agree shared host-launch and notification contracts, feature negotiation,
   authorities and fixtures across the three repositories.
2. Build Atem host launch using the existing worker/session machinery and
   durable reconciliation; add Astation/API clients against those fixtures.
3. Build Station publication/replay and Atem shared task scheduling, then connect
   Astation route/status UX. Start with explicit directed requests and existing
   ready agents; add approved launch-on-arrival using the same launch operation.
4. Verify with isolated hosts and fake agents: duplicate/reconnected/crashed
   launch creates one worker; revoked/out-of-scope requests have no effect;
   local attach and remote terminal/chat share that session; offline delivery
   and lost acknowledgments never submit a prompt twice; busy/draft/lease and
   approval conditions keep work queued; results return to the initiating role.

Use real service managers to verify boot/logout and worker survival when
implementing service integration. Do not register production services, reboot
developer machines, restart credential agents or enable hosted execution as
an automated test side effect.

## Shared-memory publication status

Current implementation fact: `mem_4ef6cdff07a742979a53ff2326a05f85`, updated
2026-11-02 after completing the online sender. It records all three worktrees,
the passing Chisel/Station/R9 and real-runtime checks, online-only scope, grant
opt-in and the remaining native SDK/UI rollout prerequisites. It replaces
`mem_79b2a270bda74032aa804c658ee4cb14` (receiver-only status).

Published to global Atem Memory on 2026-11-02 after the user paired this
profile. Both facts were read back as valid with assigned relay sequence
numbers, and the pending synchronization queue is empty:

- `mem_5042b6dba55a4c9a8cade59e6a15f8c6`, seq 1224: current local receiver
  implementation, contract, tests and remaining ownership. Replaces the
  original approval/status fact at seq 1222; code remains uncommitted/unreleased.
- `mem_889b3425a3404290bbc8524fa4935e1c`, seq 1223: feature requirements,
  durable launch/delivery, optional boot hosting and execution boundaries.

The first attempt before pairing was refused. After pairing, the default
CLI build could store locally but could not synchronize through the running
credential agent of another build. Publication used the installed npm Atem
binary matching the running runtime and credential agent; neither process
was restarted. `atem sync --no-harvest` confirmed no remaining changes.

Agents can find the handoff with:

```sh
atem sync --no-harvest
atem memory search event-driven --scope global --full
atem memory search notifications --scope global --full
```

Keep the facts and this status current as the shared contract and
implementation advance.

Receiver validation on 2026-11-02: workspace compilation, 38 focused unit
tests and 49 binary tests across host-work/runtime/runtime-build/agent-launch/
worker suites pass. The host-work target contains fifteen scenarios (18 tests
including support tests), covering runtime start/check, concurrent startup,
build reuse, approved exports, remote launch and notification dispatch.
Earlier 205 shared-client/binding tests and the scoped-service binary suite
also pass. The 1,931-test
unit run exposed four fixture-discovery failures from putting request vectors
beside scenario fixtures; moving them to their dedicated subdirectory fixes
all four, with the full 16-test fixture group passing on rerun. Current store
tests and workspace compilation also pass. Agents are fake providers in temp
profiles; live provider APIs, OS boot services and Station publication are
not exercised by these checks.

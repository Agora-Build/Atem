# Remote agent launch and notifications: cross-repository handoff

Updated: 2026-11-03 UTC.

The user approved starting both features and asked for this context to be
shared with the Astation and Station agents. The receiver is released in
[Atem v0.8.2](https://github.com/Agora-Build/Atem/releases/tag/v0.8.2), commit
`953afb77d09f874a794e15cf1e0549076fea2ce2`. PR #114 squash-merged as `42866ac`.
The current designs are:

- [Optional hosting and remote launch](../designs/agent-hosting.md)
- [Agent notifications](../designs/agent-notifications.md)

Atem receiver implementation is on main:
approved local profiles, host-level launch/query, durable task queue,
safe existing-session scheduling and explicit correlated results. The
[host-work extension](../designs/protocol/atem-host-work-v1.md) specifies its
current wire/types/limits and remaining integration boundaries. New tests use
the real runtime, encrypted channels and fake CLIs in isolated profiles.
Optional OS service installation, automatic launch-on-arrival and transactional
memory/vault write-and-notify remain separate work. Offline delivery is outside
the current scope. Astation/Station integration is draft
[PR #70](https://github.com/Agora-Build/Astation/pull/70), based on the reviewed
shared SDK pin `2b0c384e7213e5d4637cdba1f0a78ccbc53a2083`.

Existing approved dev hosted execution is enabled. The new launch/message/mark
HTTP adapters remain disabled behind the separate `host-work-api` build gate;
they are off in default and existing `hosted-agent-api` builds. Before activation,
[Auth #14](https://github.com/Agora-Build/Auth/issues/14) and
[Portal #25](https://github.com/Agora-Build/Portal/issues/25) must confirm the
service permission contract, all strict verifiers must be upgraded, and native
consent plus live launch/attach/mark acceptance must pass. The integration PRs
are not merged or deployed.

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
4. Online Chisel/Station delivery is published for review in
   [Chisel PR #1](https://github.com/Agora-Build/chisel/pull/1) at `ddd2f0a` and
   [Station PR #71](https://github.com/Agora-Build/Astation/pull/71), commit
   `5b4ee43094f7e2244582d4f3afa25abd1a48976d`.
   The Station patch is stacked on Astation PR #70 at `3d104f7` and retains
   that PR's reviewed SDK and native consent; it includes no unpublished SDK
   snapshot. Chisel sends actual
   PNG bytes through the authenticated HTTP marks endpoint; Station's NDJSON
   response owns one R9 service channel through queueing/turn-end. Local files
   and immutable IDs remain on failure. No automatic retry or offline features
   are included, per the user's current scope. The separate host-work gate
   stays closed, leaving existing approved dev execution unchanged.

The new sender is verified through Chisel's built middleware, Station's real
HTTP/auth API and a signed encrypted host fixture; receiver/runtime behavior is
verified separately with the real Atem runtime and fake coding CLIs. Both native
and Rust consumers retain PR #70's immutable published SDK pin. Before live
service enrollment, upgrade all participating strict account verifiers and
explicitly approve a new mark grant. Existing marks use `agent.view` and
`agent.prompt` bearer permissions plus signed `message`/`notify`/`prompt` and
local host consent. PR #70 exposes the default-off `markTasks` choice and checks
the exact signed operations; generic proposed service scopes still need the
confirmed Auth/Portal contract and corresponding native consent. No live
deployment, account grant or service changes occurred in this handoff.

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

## Design requirements and future work

The released receiver implements the host-work contracts linked above.
The durable outbox/replay and service-manager requirements in this section
remain design work; they do not imply offline delivery in the online sender.

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

## Verification and shared memory

Release CI passed all four CLI platforms, atem-core packaging, npm publication
and the download mirror. All seven official release asset digests were checked;
an isolated npm installation and mirror download match the Linux release binary.
Local receiver validation before merge passed 2,369 workspace tests and 2,082
release tests; the final release unit run passed 1,921 after its fixture adjustment.

The sender passes four Chisel tests, 562 Station unit tests and all 13 focused
HTTP/R9 tests, including nine isolated Postgres cases. The marks case exercises
actual built Chisel middleware, exact PNG chunks, stale targets, missing grant
opt-in, policy denial, disconnect, heartbeats and lost replies. Ten focused tests
pass in each default and existing hosted build, confirming the separate gate
stays closed. No native/live-provider/deployed-delivery E2E is claimed.

Current release/sender status is saved in global Atem Memory. Agents can find
the handoff with:

```sh
atem sync --no-harvest
atem memory search event-driven --scope global --full
atem memory search notifications --scope global --full
```

Keep the facts and this status current as the shared contract and
implementation advance. Synchronization uses the installed compatible CLI;
user runtimes, workers and credential agents are not restarted for documentation
or memory publication.

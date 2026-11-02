# Remote agent launch and notifications: cross-repository handoff

Updated: 2026-11-02 UTC.

The user approved starting both features and asked for this context to be
shared with the Astation and Station agents. The current designs are on
`Agora-Build/Atem` main in commit `3946c5b`:

- [Optional hosting and remote launch](../designs/agent-hosting.md)
- [Agent notifications](../designs/agent-notifications.md)

Atem implementation work starts on `feat/agent-launch-notifications`.
The existing worker launch and authenticated channel paths have been inspected;
neither new feature nor its wire operations is implemented yet. The names in
the designs are proposals, not an API clients can call today.

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
| Atem | Optional hosting, singleton/worker lifetime, approved local project and launch profiles, remote-launch execution and durable results, durable notification inbox, readiness-aware agent dispatch and diagnostics |
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

Station delivery is at least once. Atem acknowledges only after durable inbox
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
3. Build Station publication/replay and Atem inbox scheduling, then connect
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

On 2026-11-02, both `atem memory add --scope global --agent codex` attempts were
refused by the pairing gate. `atem status` reported `Pairing: not paired`.
Nothing from those attempts was stored or queued in Atem Memory. This file
preserves the handoff in Git; it is not a successful shared-memory publication.
After this profile is paired, the context can be published with:

```sh
atem memory add --scope global --agent codex "$(cat docs/agent-coordination-handoff.md)"
```

Resolve relative paths from the Atem checkout. Keep this status current if the
handoff is later published or implementation advances.

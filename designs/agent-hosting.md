# Agent hosting: remote launch, messages and notifications

Status: implemented and released (Atem v0.8.2; principals default to the paired Astation since v0.8.3).
**Not implemented:** OS service installation and boot startup, automatic
launch when work arrives, and durable delivery through the Station (outbox,
replay, offline senders); section 12 lists the rest.

Agent hosting lets an authorized device or service start a new Claude Code or
Codex session on this machine, send it messages and queue work for it. It is
opt-in and uses the machine's one `atem runtime`. The wire contract is
[protocol/atem-host-work-v1.md](protocol/atem-host-work-v1.md). The runtime,
workers and sessions are described in [agent-runtime.md](agent-runtime.md);
principals, scopes and the device list in [account-trust.md](account-trust.md)
and the r9 appendix of [protocol/atem-session-v1.md](protocol/atem-session-v1.md).

## 1. What it does

- **Remote launch.** A client picks a launch profile the owner approved in
  `runtime.toml`. The runtime starts the original `claude` or `codex` CLI in a
  new worker, as `atem agent launch` does. No agent needs to run beforehand.
- **Messages.** Text, exact memory/vault snapshots, or both, to one or many
  recipients: a host notice, a project notice or a task for one agent.
- **Directed work.** A task is queued per session and delivered as a normal
  prompt when the agent is ready. Completion is an explicit, correlated result.
- **Screenshots.** Chisel/mark tasks carry an uploaded PNG that the agent reads
  from a private local file.

Everything travels inside admitted, end-to-end encrypted r9 `atem-ch1`
channels on the runtime's existing Astation link. Atem opens no port and runs
no shell command a client sends.

Hosting needs:

- A verified pairing with a pinned device list (r9). The host-work features
  exist only in r9's `welcome`; an r8 host has none.
- `atem runtime` running, with `enabled = true` in `runtime.toml` and no
  configuration or database error.
- The selected CLI installed and set up on this machine.

## 2. Configuration: `runtime.toml`

`~/.config/atem/runtime.toml` holds the owner's approvals. `atem runtime start`
creates it from [configs/runtime.example.toml](../configs/runtime.example.toml)
when it is missing, with `enabled = false`. An existing file is never
overwritten.

The file must be a regular file owned by this user, mode 0600 (no group or
other bits), at most 256 KiB, UTF-8, and not a symlink. A missing file means
hosting is off. Unknown keys are errors.

```toml
version = 1
enabled = true

[[profiles]]
id = "backend-codex"
revision = 1
label = "Backend Codex"
provider = "codex"
cwd = "/home/me/src/backend"
project = "github.com/your-org/backend"
args = ["--profile", "oss"]
env_names = ["OSS_API_KEY"]
# principals = ["member:<id>", "service:<id>"]  # default: the paired Astation
# env_file = "/home/me/.config/atem/backend-env.json"

[[routes]]
id = "backend"
revision = 1
profile_id = "backend-codex"
# principals = [...]                            # default: the paired Astation
```

| Profile field | Rule |
|---|---|
| `id` | Opaque id: 1–128 bytes of letters, digits, `.`, `_`, `:`, `-`; unique |
| `revision` | ≥ 1; raise it when the profile's approvals or launch settings change |
| `label` | 1–128 printable characters |
| `provider` | `claude` or `codex` |
| `cwd` | Absolute and canonical (symlinks resolved); must exist at launch |
| `project` | The cwd's project key: its normalized Git remote (no scheme, user or `.git`), else `local:<folder>` |
| `args` | Extra CLI arguments (≤ 256, ≤ 64 KiB, no NUL) |
| `principals` | Who may launch with it (below); ≤ 64 |
| `env_names` | Variable names the agent may receive (≤ 128) |
| `env_file` | Optional absolute path to a private JSON object of names to string values |

A route (`id`, `revision`, `profile_id`, `principals`) names a profile and who
may send work to sessions that match it. At most 64 profiles and 64 routes.

**Principals.** Entries are `member:<device_id>`, `service:<device_id>` or
`browser:<grant_id>`: enrolled identities, not hostnames or logins. A profile
or route with no `principals` is open to the paired Astation only:
`member:<astation id>`, the id `atem status` shows on its Pairing line. A list
of its own replaces that default. Without a pairing and without a list, the
file is invalid. The local list adds consent; it never widens the caller's
account permissions (section 4).

**Environment.** A remote request never carries paths, commands, arguments or
environment values. The agent gets `HOME`, `PATH`, `USER`, `LOGNAME`, `SHELL`,
`LANG`, `LC_ALL`, `TERM`, `TMPDIR`, `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME` and
the profile's `env_names`, as far as the runtime's own environment has them.
Values from `env_file` override those. The file follows the same private-file
rules as `runtime.toml`, is parsed as JSON and never sourced, and may hold only
names listed in `env_names`. Name what the CLI needs: a provider's API key and
base URL, `CODEX_HOME`, and so on. Values never appear in results, journals or
logs.

The runtime's environment depends on how it started:

- Started detached by any `atem` command (`atem runtime start`, `atem agent
  launch`, a restart): only `PATH`, `HOME`, `XDG_RUNTIME_DIR`, `RUST_LOG`,
  `ATEM_*` (never `ATEM_TEST_*`), `ASTATION_*` and, when `enabled = true`, the
  names in the profiles' `env_names`, taken from the starting command.
- A foreground `atem runtime` keeps its shell's environment.

A repeated `atem runtime start` reuses the process; another terminal's exports
never reach it. After changing `env_names`, run `atem runtime restart` from a
shell that has the values, or use `env_file`.

**Reloads.** The runtime rereads `runtime.toml` every second. A changed or
removed profile fences launches that haven't started. Raise `revision` when
approvals change: requests name the revision they were made under, a mismatch
is `forbidden`, and work queued under an older revision stays blocked until it
expires. A file that fails to load, or a host-work
database that can't be opened or bound, turns hosting off until the runtime
restarts (`runtime.log`: "agent hosting unavailable").

## 3. Commands

| Command | Effect |
|---|---|
| `atem runtime start` | Create the disabled `runtime.toml` if missing, then start the runtime detached or reuse the running one (another build is kept; it says so and points to `atem runtime restart`) |
| `atem runtime check` | Validate `runtime.toml` and each profile's directory, project and env file; list who may launch; start nothing |
| `atem runtime restart` | Replace the runtime with this build; workers are adopted |
| `atem runtime` | The runtime in the foreground (e.g. in tmux); exits if another one serves the profile |

`start` and `check` need a pairing (`atem pair`) and refuse before any side
effect. `start` with an invalid existing file fails and leaves the file and the
running runtime alone. Errors name the parser's reason and line, or the
profile or route and the broken rule.

`atem runtime check` prints whether hosting is enabled, each profile (provider,
directory, revision, who may launch), each route (profile, who may send), then
the device list's members and services with their principal ids and whether
each may launch (natives with the `control` role; services with `launch`, no
session restriction and an unexpired grant). The paired Astation is marked.

**Lifetime.** With healthy hosting (`enabled = true`, no error) the runtime
stays up with zero sessions. Otherwise the usual idle exit applies (10 minutes
with no sessions and no clients). Enabling hosting doesn't install a service,
start an agent or grant anyone access. Frontends in tmux, Herdr or any terminal
are clients; the runtime and its workers own the sessions.

## 4. Who may launch and send work

Every request needs two things: the caller's current account permission
(checked from the device list on each request) and, for launch and work, the
owner's local consent in `runtime.toml`.

| Action | Native member | Service | Browser grant |
|---|---|---|---|
| List and use profiles, launch | `control` role | `launch` op, no `sessions` restriction | `launch` op, no session in the grant |
| Enqueue and manage work | `control` role | `notify` and `prompt` ops | `notify` and `prompt` ops |
| Host or project notices, uploads | any member | `message` op | refused |
| Local consent | profile or route `principals` | same | same |

- Notices need no local consent. A native member can store host and project
  notices; a service needs `message` and its scope must cover the destination.
  A task sent as a message's `agent` recipient needs both rows: the message
  permission and the work permission with route consent.
- `launch` and `notify` are control ops: a service holding one has `control`.
  `message` is not and grants no agent input.
- A service restricted to `projects` sees and uses only profiles whose project
  is in its scope; one restricted to `sessions` can't launch at all.
- Before launch and before each dispatch the runtime checks again: membership
  not held, frozen or faulted, journal healthy, channel not expired, the
  caller's key unchanged, its `control_gen` unchanged, scope and local consent
  still in place. Work fenced this way stays blocked until it expires; a new
  grant doesn't revive it.
- Memory or vault access gives no execution right. Vault `writer_id` and relay
  room names are labels, not authority.

## 5. Remote launch

1. The client checks `host.launch` in `welcome`, asks `host_profiles` (only
   profiles it may use are listed) and sends `host_launch` with a new request
   id, the profile id and revision, and an expiry ≤ 24 h ahead.
2. The runtime reserves the request id, a new session id and a process
   generation in its database, then replies `starting`.
3. It prepares the profile: canonical directory unchanged, current Git project
   equal to `project`, environment built. It checks authorization again just
   before spawning the worker and before telling it to start the agent.
4. The worker runs the CLI in a PTY (24×100 until a frontend resizes it) with
   the profile's arguments, Claude's chat and approval hooks, and Codex's hooks
   when `[codex] hooks = true`.
5. The client polls `host_launch_query` until `started`, `failed` or
   `outcome_unknown`, then finds the session in the session-v1 registry.

`started` means the worker launched the agent, not that chat is ready. Readiness
comes from the session's normal status. Send a first prompt through the usual
chat or session-v1 receipt path once the session is ready. A new Codex session
reports nothing before its first prompt typed in its terminal (and only with
Atem's hooks on and trusted); until then work for it stays blocked.

The live-session limit (16) is checked when the request arrives (`busy`) and
again at spawn. A failed preparation (directory or project changed, bad env
file), a runtime that is restarting, or a full session table at spawn gives
`failed`. Any failure after preparation, including a refusal at the spawn
boundary, is `outcome_unknown`. Nothing is retried. Retrying with the same
request id returns the recorded status; the same id with other content or from
another principal is `request_id_reused`. After a runtime restart a `starting`
launch becomes `started` when its worker was adopted with the reserved process
generation, else `outcome_unknown`.

A remote session is an ordinary session: `atem agent list` shows it, `atem
agent attach` opens it locally, and remote terminal and chat work as for any
session.

## 6. Messages and notices

A message is one immutable envelope: a sender (the channel's principal),
1–32 recipients in one account, inline text, up to 8 exact context snapshots,
or both, and an expiry ≤ 24 h after creation. Each recipient has its own id,
host and destination:

| Destination | Effect |
|---|---|
| `host` | A durable notice for this host; no agent input |
| `project` | A durable notice for a route's project; no agent input |
| `agent` | A task for one live session through the route (section 7) |

The envelope, every local recipient decision and every task commit in one
transaction before the reply. One refused recipient doesn't drop the others; a
refusal is final for that message id. The sender queries progress with
`message_query`; agent recipients carry their task's state. There is no inbox
command and no separate mailbox.

The receiver takes the sender from the authenticated channel and pins its key.
A forwarding service can't speak for a member: it publishes as itself.

The client helper `Message::publications()` builds one request per host from
one envelope. It is an in-memory builder, not an outbox: the client keeps the
envelope and retries each host until it accepted.

**Not implemented:** nothing on the host shows or applies a stored notice, and
the runtime fetches no memory or vault reference. It accepts only snapshots the
publisher resolved, and checks their digests, not their publication.

## 7. Directed work

A task comes from `work_enqueue` or from an `agent` message recipient. It names
a route and an exact target: a live session (launched locally or remotely)
whose process generation, directory, provider and project match the route's
profile. The runtime renders the prompt with the task and workflow ids and each
context snapshot (version and digest), and adds verified screenshot paths.

**Scheduling.** The runtime checks the queue every 100 ms; no model call or
agent polling is involved. Tasks run FIFO per session, mark tasks included. An
earlier task that is blocked, being submitted, submitted or uncertain holds
later tasks for its session; other sessions go on. A task is blocked while:

- an earlier task holds the session;
- the sender has no authorized channel open, or its route consent changed;
- the target session is gone, not live, has no chat, or isn't `ready`
  (working, waiting or unknown);
- the terminal has unsent input (a draft);
- another controller holds the lease;
- an approval is open on the session;
- its screenshots aren't fully uploaded and verified.

**Dispatch.** When nothing blocks it, the runtime records `submitting` with a
fixed receipt id, then submits a session-v1 `prompt` with `acquire: true` on
the sender's channel. It is remote input under the sender's principal: no
takeover, no local-input exception, no typing into a running tool or approval
dialog. The scheduler never renews or takes over a lease. The prompt receipt
decides the task's state: `submitted`, then `awaiting_result` when the turn
ends, `failed` when rejected, `outcome_unknown` when uncertain. After a
restart, a task left `submitting` becomes `outcome_unknown` and is reconciled
from its receipt; it is never sent again.

**Results.** A finished turn is not a finished task. The sender calls
`work_complete` with an immutable result snapshot (e.g. the vault entry the
work produced); the task becomes `completed`. A task awaiting its result no
longer holds the session.

**Cancel and expiry.** `work_cancel` works only while a task is `queued` or
`blocked`; it never interrupts a turn (use session-v1 `interrupt`). A task not
submitted by its `expires_at` becomes `expired`.

## 8. Screenshots and Chisel/mark

Chisel/mark is a message with an `agent` recipient and a `mark` payload: page
URL and title, up to 128 annotations, and one PNG screenshot descriptor. It
uses the same route, authority, queue, receipts and explicit result as other
work. There is no separate mark queue, no model triage and no background
`claude -p`.

1. The publisher uploads the PNG with `attachment_put` in chunks of ≤ 96 KiB,
   each acknowledged after it is durable. PNGs are 33 bytes to 8 MiB.
2. It publishes the message with the same descriptor. Publishing first is
   allowed: the task stays blocked until the bytes are complete.
3. At dispatch the runtime checks the digest and PNG header, writes the file to
   `<config>/runtime/attachments/<owner>/<attachment_id>.png` (`<owner>` is a
   hash of the sender's principal and key; the file is rewritten from the
   database each time, so a deleted or edited file is repaired) and adds its
   path to the prompt. The agent reads it with its own tools.

Uploads belong to the uploading principal and key; only that sender's tasks can
use them. The URL is text; the runtime fetches nothing. An upload grants no
agent input.

The old ID-only `markTaskAssignment` is answered with a failed
`markTaskResult` asking to upgrade the Chisel/Astation sender. Atem no longer
reads `.chisel/tasks/` files.

## 9. Durable records

`<config>/runtime/host-work.sqlite` (0600, full-sync commits) holds launch
records, work records, messages with their receipts, and upload bytes. Each
record is committed before it is acknowledged. Values of environment variables
are never stored.

The database is bound to one account, host device id and host trust
generation, at the first pass after the host is verified (an unverified host
binds nothing; hosting waits for verification). When that identity changes (a
new pairing, or `atem pair verify`, which moves to the next trust generation),
the runtime moves the database aside as `host-work.sqlite.retired-<ms>` (kept,
never read again; `runtime.log` names it), fences launches that haven't
started, and starts an empty one. Nothing it held could be honored again:
every request names the host, trust generation included, so a retry for the
old identity is `stale_target`.

Records are never pruned; ids stay as tombstones. At a limit the runtime
refuses new requests with `busy` instead of evicting anything. Files and the
database are owner-private but not encrypted at rest; keep secrets out of
screenshots and context.

## 10. Limits

| Item | Limit |
|---|---|
| Profiles, routes | 64 each; 64 principals each |
| Launch identities | 4,096 |
| Work identities, messages | 4,096 each |
| Unfinished tasks (queued, blocked, submitting, submitted, awaiting a result) | 256 |
| Uploads | 256 identities, 128 MiB declared bytes (partial uploads included) |
| Live sessions | 16 (remote launches included) |
| Request size | 256 KiB; message envelope 240 KiB |
| Request and task lifetime | ≤ 24 h |
| Host-work requests waiting for the runtime's next pass | 64 |

## 11. Other components

- **Astation and integrated apps** use the shared `atem-client` (`Attached::send`
  and the Family JSON event in the Swift, Kotlin and WASM bindings): New Agent
  (host, profile), terminal and chat on the new session, launch and task status
  by query.
- **Station** carries the channels like any r9 traffic (see
  [astation-connection.md](astation-connection.md) and
  [protocol/station-route-v1.md](protocol/station-route-v1.md)). Chisel's
  online sender posts the PNG to a Station endpoint, which uploads and publishes
  as a service over one r9 channel. That sender lives in the Station and Chisel
  repositories.
- **Portal and Auth** handle service enrollment requests and service tokens; a
  managing device signs the service and its scope into the device list. Strict
  membership verifiers that don't know `launch`, `notify` or `message` reject
  entries that carry them: upgrade every client before enrolling such a service.

## 12. Planned (not implemented)

- **Not implemented:** automatic launch when work arrives. A coordinator can
  launch, wait for readiness, then enqueue.
- **Not implemented:** durable delivery through the Station: atomic
  write-and-notify with memory or vault, an outbox, replay with cursors across
  replicas, and delivery to an offline host. Today a sender must reach the host
  while it is online.
- **Not implemented:** work from an offline sender. Dispatch uses the sender's
  live channel, so its tasks wait until it reconnects. There is no origin proof
  that would let the Station replay an envelope, and no Atem-to-Atem sender.
- **Not implemented:** role routing and subscriptions. Senders resolve
  recipients (host, route, session, process) themselves; there are no role ids,
  routing generations or context subscriptions that create work.
- **Not implemented:** result routing and workflow limits. Results go back only
  through `work_query`/`message_query`; there are no hop budgets, per-route rate
  limits or delivery of results to the sender's agent.
- **Not implemented:** progress push. Launch and task status are query-only.
- **Not implemented:** resolving an `outcome_unknown` task by hand. It keeps
  holding its session's queue.
- **Not implemented:** retention, compaction or pruning of `host-work.sqlite`
  and uploads.
- **Not implemented:** `atem cred get` as an environment source for profiles.
- **Not implemented:** launching into a new clone or Git worktree; profiles name
  existing directories.
- **Not implemented:** hosting state in `atem status` and `atem --version`;
  `atem runtime check` is the only report.

### OS service and boot startup (not implemented)

There is no `atem service` command; nothing starts Atem at boot. The approved
design:

- Optional and explicit. Installing or upgrading Atem creates no service.
  `atem service install|status|start|stop|restart|update|uninstall` would
  manage it for the current user and profile, never as root.
- Linux: a `systemd --user` unit with lingering enabled (checked at install),
  the broker in the foreground, `KillMode=process` so workers and the cred agent
  survive broker restarts. macOS: a system LaunchDaemon with `UserName` for boot
  start (a LaunchAgent only starts at login), detached workers preserved.
- Install hands an existing runtime to the service without a duplicate broker:
  the old broker exits, the managed one adopts the workers.
- A manager-owned runtime is replaced only through the manager; clients of
  other builds must not replace or downgrade it. An explicit stop stays stopped.
- Boot starts only the runtime: no agent restarts, no replayed prompts, no
  credential unlock, no new access.
- Tests use isolated profiles and unit names and never register a real service
  or reboot the machine.

## 13. Tests

`tests/host_work_binary.rs` runs the real runtime, encrypted r9 clients and
fake CLIs in temp profiles: `runtime start`/`check` and pairing, concurrent
starts, approved exports, launch deduplication and adoption after restart,
scoped and local consent, drafts, leases, approvals, cancel and expiry, sender
fencing, message fanout, uploads and mark tasks. Shared request vectors are
`protocol/fixtures/host-work/requests-v1.json`. Real provider APIs, OS services
and Station delivery are not exercised.

```bash
cargo test --test host_work_binary -- --test-threads=1
```

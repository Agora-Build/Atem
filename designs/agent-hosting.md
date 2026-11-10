# Agent hosting: remote launch, messages and notifications

Status: implemented and released (Atem v0.8.2; principals default to the paired Astation since v0.8.3).
**Not implemented:** OS service installation and boot startup, automatic
remote launch when work arrives, and durable delivery through the Station (outbox,
replay, offline senders); section 12 lists the rest.

Agent hosting lets an authorized device or service start a new Claude Code or
Codex session on this machine, send it messages and queue work for it. It is
opt-in and uses the machine's one `atem runtime`. The wire contract is
[protocol/atem-host-work-v1.md](protocol/atem-host-work-v1.md). The runtime,
workers and sessions are described in [agent-runtime.md](agent-runtime.md);
principals, scopes and the device list in [account-trust.md](account-trust.md)
and the r9 appendix of [protocol/atem-session-v1.md](protocol/atem-session-v1.md).

[Agent collaboration](agent-collaboration.md) adds opt-in messaging between
agents in this runtime, including selectors, context publication, correlated
replies and local launch on message (stage 1, unreleased). It adds one
read-only remote op, `reply_query` (section 7); the remote contract described
here otherwise retains its existing admission rules.

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
is `forbidden`, and work queued under an older revision, or under a route that
no longer lists its sender, fails at once for every sender (`route changed`;
[agent collaboration](agent-collaboration.md) section 10, "Lifecycle"). A
profile edit that keeps its id, revision and project (a changed `cwd` or
`provider`) is no change of approval: its queued work stays blocked until it
expires. A file that fails to load turns hosting off while it fails: launches
that haven't started wait, requests are `busy`, queued work waits (nothing
dispatches, fails or expires), and `runtime.log` names the problem once (the
parser's reason and line, or the profile and rule); within a second of the
file being fixed hosting follows it again, no restart needed. A host-work
database fault (it can't be opened or recovered, or a write failed) turns
hosting off until `atem runtime restart`, since a failed write leaves that
step's outcome unknown (`runtime.log` names the database), and fences launches
that haven't started.

## 3. Commands

| Command | Effect |
|---|---|
| `atem runtime start` | Create the disabled `runtime.toml` if missing, then start the runtime detached or reuse the running one (another build is kept; it says so and points to `atem runtime restart`) |
| `atem runtime check` | Validate `runtime.toml` and each profile's directory, project and env file; list who may launch; start nothing |
| `atem runtime restart` | Run the check first, then replace the runtime with this build; workers are adopted |
| `atem runtime` | The runtime in the foreground (e.g. in tmux); exits if another one serves the profile |

`start` and `check` need a pairing (`atem pair`) and refuse before any side
effect. `start` with an invalid existing file fails and leaves the file and the
running runtime alone. Errors name the parser's reason and line, or the
profile or route and the broken rule. `atem runtime restart`, and any command
of another build that would replace the running runtime, first run what
`atem runtime check` checks, as the new build reads the file: if it fails,
nothing is stopped, the runtime is kept, and the message names the problem
(fix the file, then run `atem runtime restart`). Without a `runtime.toml`
there is nothing to check; starting a runtime when none runs is never
refused for it.

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
  still in place. A task whose sender's `control_gen` moved on (a fence) or
  whose authorization expired fails at once (`sender's authority changed`,
  `sender's authorization expired`), whether it is queued, blocked, awaiting
  its result or of unknown outcome; a running turn is never interrupted. A new
  grant doesn't revive it, and its sender can no longer read it (`forbidden`).
  A sender that merely has no authorized channel open waits, and its task holds
  its session's queue until the task's deadline.
- Memory or vault access gives no execution right. Vault `writer_id` and relay
  room names are labels, not authority.
- **Security is at user authentication.** Who may reach an agent is decided
  here: the device list authenticates the caller and carries its account
  permission (the table above), and a profile or route that lists it is your
  consent. Every request is bound to its channel's principal, is checked
  against current authority when accepted and again before it dispatches, and
  travels only inside end-to-end `atem-ch1` channels that the Station can't
  read or alter. A principal allowed to reach an agent (here, or with
  `control` over its session) acts through it with your permissions on this
  machine: the agent's shell, files and Atem commands, including `atem
  message send` (its tasks are `local` and may reach every route that lists
  `local`), Memory, skills and the vault. Atem doesn't track who prompted an
  agent, so listing a principal, or granting it `control`, lets it act as you
  through your agents. The agent's own tool approvals still apply to each
  command (agent collaboration, section 6). This holds for r9 hosts. A host
  verified by an earlier build that never pinned a device list still serves
  r8 sessions to the paired Astation over its Astation link, which is neither
  end to end nor authenticated at Atem's end (Atem takes Astation's word for
  being authenticated), so whoever ends that socket can act as the paired
  Astation there; agent collaboration refuses to run on such a host until
  `atem pair verify` pins a list. Atem's own lines in a rendered prompt are
  framed (a tag per prompt, counted blocks, look-alikes of its marker escaped;
  the delegated host-work design, III.2, and host-work v1 §4 "Rendering"), so
  sender text can't imitate them; a principal with `control` can still write
  anything directly (agent collaboration, section 17). The live tag goes to
  principals with `control` only: chat-v1 replaces every tag Atem drew with a
  same-length placeholder for attachments without `control`, and their
  terminal-v1 frames pause from a framed prompt's paste until its turn ends
  (the receipt completed or rejected, or after a restart the chat showing the
  turn ended; the agent or its worker gone; or a day from the dispatch on
  the host's wall and monotonic clocks, longer only when a broker restart
  reads as another boot, as on macOS after a clock step; never the task's
  deadline), across a broker restart (the pause is on disk), then resume
  with a full frame. A paraphrased tag, an echo split across chat parts or
  cut short, a dead tag on the screen after its turn, and a tag an agent
  copies into another session's output stay visible; the rule line tells the
  agent that nothing it reads after the prompt is Atem's, whatever tag it
  carries (section 17 has the details).

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

A launch that hasn't started while `runtime.toml` doesn't load waits and starts
once it loads again, while its sender's channel, `control_gen` and the profile
approval hold and its expiry hasn't passed; requests are `busy` meanwhile.
Switching hosting off (`enabled = false`) is a deliberate stop and fences it,
as a receipt-database fault and a halted session journal do: it is never
started and ends `outcome_unknown`, and switching hosting on again doesn't
revive it. A launch already handed to the spawner re-reads the file at the
spawn boundary: a file that doesn't load or hosting off fences it there too.

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

**Not implemented:** nothing on the host shows or applies a stored remote
notice. The remote receiver accepts only snapshots the publisher resolved,
and checks their digests, not their publication. The local collaboration
sender publishes Memory and reads back pinned Memory/Vault versions before
it queues their exact snapshots.

## 7. Directed work

A task comes from `work_enqueue` or from an `agent` message recipient. It names
a route and an exact target: a live session (launched locally or remotely)
whose process generation, directory, provider and project match the route's
profile. The runtime renders the prompt with the task and workflow ids and each
context snapshot (version and digest), and adds verified screenshot paths.

**Scheduling.** The runtime checks the queue every 100 ms; no model call or
agent polling is involved. Tasks run FIFO per session, mark tasks included. An
earlier task that is blocked, being submitted, submitted or uncertain holds
later tasks for its session (an offline sender's task, until its deadline);
other sessions go on. A task is blocked while:

- an earlier task holds the session;
- the sender has no authorized channel open (its route consent changing fails
  the task instead: `route changed`);
- the target session is gone, not live, has no chat, or isn't `ready`
  (working, waiting or unknown);
- the terminal has unsent input (a draft);
- another controller holds the lease;
- an approval is open on the session;
- its screenshots aren't fully uploaded and verified.

**Dispatch.** When nothing blocks it, the runtime records `submitting` with a
fixed receipt id, then submits a session-v1 `prompt` with `acquire: true` on the
sender's channel. It is remote input under the sender's principal: no takeover,
no local-input exception, no typing into a running tool or approval dialog. The
scheduler never renews or takes over a lease. The prompt receipt decides the
task's state: `submitted`, then `awaiting_result` when the turn ends (detail
`turn interrupted` when it ended interrupted), `failed` when rejected (with the
receipt's own detail, for example `control revoked`, `host trust changed` or
`session closed`), `outcome_unknown` when uncertain. A submitted task whose
receipt the session host no longer has becomes `outcome_unknown` (detail
`receipt no longer available`). After a restart, a task left `submitting`
becomes `outcome_unknown` and is reconciled from its receipt; it is never sent
again.

**Results.** A finished turn is not a finished task. The sender calls
`work_complete` with an immutable result snapshot (e.g. the vault entry the
work produced); the task becomes `completed`. A task awaiting its result no
longer holds the session.

**Replies.** The agent working on a task can answer it with `atem message
reply`, for a task of any sender. The reply is durable, bound to the task, its
session, process and turn, and never completes the task. The sender reads it
with `reply_query{task_id}` (feature `host.reply`, ops `notify` and `prompt`):
the same authorization as `work_query`, answered `{kind:"reply", reply}` with
`reply` `null` until one exists, else `{result_id, state, digest, text,
context, submitted_at, dropped}` and a state of `publishing`, `submitted` or
`refused`
([protocol/atem-host-work-v1.md](protocol/atem-host-work-v1.md#reply)). The
reply isn't pushed: poll it, and complete the task with `work_complete`.

**Cancel and expiry.** `work_cancel` works only while a task is `queued` or
`blocked`; it never interrupts a turn (use session-v1 `interrupt`, which ends
the turn and leaves the task awaiting its result). A task not submitted by its
`expires_at`, or still awaiting its result or of unknown outcome at it,
becomes `expired`; nothing is resubmitted. A task whose sender's authority or
whose route approval changed fails before its deadline (section 4, section 2).

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

Records are never deleted. Every launch, task, message and reply row stays for
the life of the database, so a query or a retry is always answered from its
record. A day after a record settled past its deadline, the runtime (about once
a minute) drops its payloads only: a task's prompt and context text, a
message's inline text and context text, a reply's text, and the bytes of an
upload (with its cached PNG) that no open task names. Ids, principals,
revisions, session ids, states, details, digests, sizes, timestamps and a
task's attachment descriptors stay, and so do a `work_complete` result and a
message's `mark`. The queries keep answering (`reply_query` says `dropped:
true`), and a retry is deduplicated by the digest stored at acceptance: the
identical request returns the recorded receipt, other content is
`request_id_reused`. The 4,096-record limits count records not yet closed this
way, so a closed record frees its slot; at a limit the runtime refuses new
requests with `busy` instead of evicting anything. An upload no task ever named
is not dropped (the upload limits hold it). The file grows by a compact row set
per task and is never trimmed: moving it aside is the only reset. [Agent
collaboration](agent-collaboration.md) section 10 ("Records and retention") has
the details. Files and the database are owner-private but not encrypted at
rest; keep secrets out of screenshots and context.

## 10. Limits

| Item | Limit |
|---|---|
| Profiles, routes | 64 each; 64 principals each |
| Open launch records | 4,096 (a record closes when its payloads are dropped; none is deleted) |
| Open work records, messages, local sends | 4,096 each (same) |
| Unfinished tasks (queued, blocked, submitting, submitted; not those awaiting a result or of unknown outcome) | 256 |
| Local collaboration (`[collab]`) | 32 agents per message; 30 messages per session per hour and 8 per workflow by default (a message counts once, however many agents it reaches) |
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

- **Not implemented:** automatic launch when remote work arrives. A coordinator
  can launch, wait for readiness, then enqueue. Local collaboration supports
  `launch = "on_message"` on an explicitly approved route.
- **Not implemented:** durable delivery through the Station: atomic
  write-and-notify with memory or vault, an outbox, replay with cursors across
  replicas, and delivery to an offline host. Today a sender must reach the host
  while it is online.
- **Not implemented:** work from an offline sender. Dispatch uses the sender's
  live channel, so its tasks wait until it reconnects. There is no origin proof
  that would let the Station replay an envelope. Cross-instance sending is
  planned in [agent-collaboration.md](agent-collaboration.md).
- **Not implemented:** remote selector routing and context subscriptions.
  Remote senders resolve recipients (host, route, session, process) themselves.
  Local collaboration expands selectors once and persists that resolution.
- **Not implemented:** cross-instance result routing and workflow limits.
  A remote sender reads an agent's reply with `reply_query` (feature
  `host.reply`) and completes the task with `work_complete`; progress goes back
  through `work_query`/`message_query`. Local collaboration has durable workflow
  limits counted in messages and one correlated reply per task for every
  sender, delivered into a local sender's agent only with origin-route
  consent.
- **Not implemented:** progress push. Launch and task status are query-only.
- **Not implemented:** resolving an `outcome_unknown` task by hand. It holds
  its session's queue until it expires at its deadline ("expired with its
  outcome unknown"; nothing is resubmitted), unless its agent submits a reply
  first (the task becomes `awaiting_result`) or, for a local task, its sender
  completes it.
- **Not implemented:** deleting, archiving or compacting records in
  `host-work.sqlite` (every receipt is kept and only payloads go, section 9),
  and dropping an upload that no task ever named.
- **Not implemented:** `atem cred get` as an environment source for profiles.
- **Not implemented:** launching into a new clone or Git worktree; profiles name
  existing directories.
- **Not implemented:** hosting state in `atem status` and `atem --version`;
  `atem runtime check` is the only report.

### Sending work from Atem agents

[Agent collaboration](agent-collaboration.md) stage 1 is implemented and
unreleased: agents in this runtime can address work by project, tag or
`atem_id`, with a durable outbox, publish-before-notify, status reports and
explicit correlated results. It uses this receiver and its approved routes.
The agent answers any task, whoever sent it, with `atem message reply`; the
sending agent completes its own task with `atem message complete`, a remote
sender with `work_complete`. `atem message` and `atem agent tag` connect only
to the running runtime (they never start or replace one). An agent's sends are
`local` whoever prompted it, so a route that lists `local` takes work from
every principal that may reach the agents that send (agent collaboration,
section 6). A `runtime.toml` that doesn't load, hosting off or a database
fault pauses local work without fencing it (sends are refused, queued tasks
wait, replies are stored, except that a database fault refuses a reply, a
completion and a cancel until `atem runtime restart`), though hosting off
fences launches not yet started; a halted session journal holds local tasks
the same way until that restart; `[collab] send = false` only refuses new
sends. A session is launched only for `atem message send --launch` on a route
with `launch = "on_message"`, and only for a Claude Code profile.
**Not implemented:** cross-instance transport, the shared Station directory
and mailbox, and the stages 2-3 permission agreements.

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
fencing and the failures it causes, route changes, launches that wait out a
pause, message fanout, uploads, mark tasks, replies read with `reply_query`,
and records kept with their payloads dropped. Shared request vectors are
`protocol/fixtures/host-work/requests-v1.json`. Real provider APIs, OS services
and Station delivery are not exercised.

```bash
cargo test --test host_work_binary -- --test-threads=1
```

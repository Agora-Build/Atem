# Atem runtime: one owner for every agent session and the Astation connection

Status: **current design, implemented and released in Atem v0.8.0
(2026-10-31)**. The host serves atem-session r8, and r9 on a host with a
device list. "Product decisions" are the approved rules; "Implementation
status" says what was built and where it differs from the design text after
it. The wire contract is [protocol/atem-session-v1.md](protocol/atem-session-v1.md)
(overview: [protocol/README.md](protocol/README.md)); see also
[shared-terminal.md](shared-terminal.md), [agent-chat-host.md](agent-chat-host.md)
and [account-trust.md](account-trust.md).

Optional managed hosting with boot startup and remote session creation is
proposed separately in [agent-hosting.md](agent-hosting.md). It is not
implemented and does not change the current on-demand lifetime below.

## Product decisions

Approved by the user and Astation (2026-10-15); where the text below
disagrees, this section and "Implementation status" win. Device trust
(enrollment, freshness, browser grants, recovery, relay confidentiality) was
decided later: [account-trust.md](account-trust.md) and the contract's r9 appendix.

- **One runtime per profile** (OS user and config directory) owns the
  Astation link, the session registry and cred agent access; every other
  `atem` is its client, and concurrent starts elect one owner without
  displacing it. Pairing, verification and unlock never disturb a session.
- **Sessions outlive frontends.** Closing a launch window detaches; the
  session keeps running and stays visible in Astation. The runtime starts on
  demand and exits when idle (no system service). Several sessions run at
  once, several of one provider included (at most 16). Launching is local
  only and needs no pairing.
- **Workers own agents** and survive the broker, which adopts them only on a
  matching session id, process generation and OS start time. A worker or
  agent crash or a reboot shows `interrupted`/`recovery_required`: nothing is
  restarted, and a transcript is never replayed into a new process.
- **One controller at a time.** Many viewers; one controller per session on a
  15 s lease (capped by the authorization), renewed by the client, taken over
  explicitly (the old controller stays a viewer). Local typing takes control
  back: it revokes any remote lease before it is written. Every mutation
  names the session and process generation and is checked against the lease
  epoch; queued bytes of an old lease or process are dropped. A disconnect
  lets the lease expire; a reconnect replays nothing. Approvals need
  `control`, not the lease (r8 §G), and the lease never approves anything.
- **Receipts.** A submission is accepted once its record is durable (in the
  broker's journal); its `request_id` binds target and payload digest. A
  duplicate gets the recorded receipt; work executing at a crash is
  `outcome_unknown`, never retried; accepted work outlives its controller's
  lease. Raw keystrokes are a live stream, never replayed. Receipts last the
  session plus 7 days (at most 4096 per session). The journal keeps no prompt
  text past acceptance (owner-only, not encrypted), and Atem keeps no
  conversation store (the approved 30-day history was not built).
- **Transports.** The direct port-8080 link and the relay are thin adapters
  over one registry, lease and receipt implementation; neither grants trust.
  Remote access is bounded (24 h per r8 attachment or r9 native channel, a
  grant's expiry), then pauses until it authenticates again; agents and the
  local terminal go on.
- **Astation** views sessions, terminals and chats; with `control` and the
  lease it types, prompts (a chat Send may take the lease), interrupts and
  stops; with `control` alone it answers approvals and revokes session rules;
  it assigns mark tasks.
- **CLI.** `atem status` is the one read-only, offline status command (no
  `atem cred status`). `atem pair` on a paired profile only reports;
  replacing a pairing is `atem unpair`, then `atem pair`. `atem pair verify`
  verifies the existing pairing and keeps it on failure. `atem cred
  unlock|lock` never start pairing or verification (lock works offline).
  `atem unpair` commits a new host trust generation and ends remote access,
  keeping account data, keys and running agents.

## Implementation status (built 2026-10-16, released in v0.8.0)

Built as "Product decisions" says, not as the older text below where they
differ:

- **Broker and workers.** `atem runtime` is the broker; every session runs in
  its own `atem worker` (agent PTY, canonical screen, Claude chat adapter,
  session log) that survives the broker. A new broker adopts a surviving
  worker only after its `hello` matches the record's session id and process
  generation and the OS start time of its pid; otherwise the session is
  `interrupted` or `recovery_required`. The "agents end with the runtime" and
  "sessions do not survive a runtime restart" statements below no longer
  hold.
- **One writer authority.** The broker grants input epochs; the worker drops
  a write whose epoch is older than its current one at the PTY write
  boundary. Local input revokes any remote lease first. A remote write also
  carries its lease's deadline (`not_after`, on CLOCK_MONOTONIC), and the
  worker drops it there once that has passed.
- **Session host.** The broker runs atem-session (r6.2 when built; now r8, and r9 on a host with a device list, which refuses r8; compatibility mode,
  `designs/protocol/atem-session-v1.md`) over a `FileJournal` in
  `<config>/runtime/journal/`; the runtime's one Astation link is one
  attachment, new on every connect or re-authentication. Only a paired,
  verified Astation gets one. Terminal-v1 and chat-v1 are bound to session-v1
  (bindings and leases); `agentInput`, `agentPrompt`, voice, `userCommand`,
  terminal-v1 `control`/`list`, provider-name terminal ids and the agent list
  are removed with no compatibility.
- **Operations.** `atem pair`, `atem pair verify`, `atem cred unlock|projects`
  and the paired-token refresh run in the broker on its link, as described
  below; `atem unpair` and `atem logout` tell a running runtime, which drops the link of a changed pairing.
- **Session logs** are written by the worker when an agent that printed
  something ends (`<config>/logs/<session_id>/session.ansi`, `summary.md`).

Deviations from the text below:

- Lifetime: the runtime exits after 10 minutes with no live sessions, no
  launch in progress and no non-passive client; there is no separate
  30-second rule for a runtime started only for an operation (the operation's
  CLI stays connected while it runs).
- `atem pair` on an already paired profile only prints the status (Product
  decisions); re-pairing over a live connection ("`atem pair` cases" 1–3) does
  not exist: `atem unpair`, then `atem pair`.
- Remote viewers and controllers are not limited to "one viewer per session"
  by the runtime: r8 has one attachment (the one Astation link), r9 one per
  channel, several devices at once.
- The shared atem-session host fixtures run against the real runtime
  (`tests/runtime_fixtures_binary.rs`); [protocol/README.md](protocol/README.md)
  says where each set runs.

## Problem

Every `atem` process opens its own Astation connection with the machine's one
identity (`atem_id` in `config.toml`). The relay keeps one socket per
`(room, atem_id)` and closes the older one; a long-lived Atem reconnects at
once. Observed on Genie: an Atem hosting Claude reconnected 0.5 s after
`atem pair` authenticated, the relay closed the pair connection, and Astation
cancelled the pending Touch ID approval, which is bound to that connection
("Astation connection closed during device verification"). Two
`atem agent launch` processes evict each other the same way, so Astation sees
only one of them at a time.

## Requirements

From the user and Astation:

- Several agents run at once on one machine and profile (Codex, Claude, and
  several sessions of the same provider); Astation shows and addresses all of
  them at the same time.
- Each session has its own ID and process generation; the provider kind is
  not a session ID. Commands, replies, status, terminal control and chat stay
  scoped to the addressed session.
- Pairing, device verification and credential operations never interrupt or
  displace a running session, and never lose its process, conversation or
  unfinished input.
- Trust stays per device/profile: one `atem_id`, one pairing, one set of
  device keys. A new identity per launch is not acceptable.
- Coordination through the owner's connection over local IPC, not retry
  delays. Astation keeps its connection-generation checks and owner approval;
  an approval is never redirected to another socket and a verification is
  never replayed.

## Architecture

```
atem agent launch codex  ─┐                 ┌─ ses-…  Codex   (PTY, terminal, status)
atem agent launch claude ─┤                 ├─ ses-…  Claude  (PTY, terminal, chat, status)
atem agent attach <id>   ─┼─ local socket ──┤  ses-…  Claude …
atem pair / cred / list  ─┘  (same user)    └─ one authenticated Astation connection
                                   atem runtime (one per config directory)
```

### The runtime process

- `atem runtime` is a hidden subcommand of the same binary, started detached
  by a client when no runtime answers (the `atem cred-agent` pattern: same
  binary, `setsid`, `chdir($HOME)`, output to `~/.config/atem/runtime.log`).
- One per config directory: an exclusive `flock` on
  `~/.config/atem/runtime.lock` for its life, with its pid in it; a second
  runtime exits. Its socket path is recorded in `runtime.socket`.
- Socket: `$XDG_RUNTIME_DIR/atem/runtime.sock`, else
  `~/.config/atem/runtime.sock`; directory 0700, socket 0600, peers checked to
  be the same UID (`SO_PEERCRED` / `getpeereid`, as `agent_socket.rs` does).
  No network listener.
- Version check: `welcome` carries a protocol version (and the build, shown by
  `atem agent list` so a user can see which build is serving). A client with
  another protocol version may restart a runtime that has no live sessions;
  with live sessions it refuses with "stop your sessions (`atem agent list`)
  or use the atem that started them".
- The runtime owns what `App` owns today for Astation and agents: the Astation
  connection (local or relay, re-authentication, credential sync, encryption
  messages), the session registry (session-v1), every session's PTY (in its worker), canonical
  screen and terminal-v1 sharing, the chat-v1 adapters and sessions, mark
  tasks, voice requests and `AgentInput`/`AgentPrompt` routing (removed in atem-session r6; see designs/protocol/atem-session-v1.md: voice requests, `AgentInput`/`AgentPrompt`). It uses the key
  agent for keys exactly as `App` does now. Its own paired-token refresh uses
  the current in-process path (no IPC to itself).
- Without a pairing the runtime runs local-only (sessions and frontends, no
  Astation), as `atem agent launch` works without Astation today.
- Each session's tasks and each client's handler run isolated: a panic ends
  that session or client (recorded in `runtime.log` with the cause), not the
  runtime. If the runtime itself exits or crashes, its workers and their
  agents keep running and the next runtime adopts them (see "Implementation
  status"); a reboot ends them.

### Sessions

- `session_id` = `ses-` + 12 lowercase base32 characters, random. It is the
  agent registry id, the terminal-v1 `terminal_id` and the chat-v1 `agentId`.
- One process per session; `generation` (a UUID) is kept on the wire as today.
  Restarting an agent is `stop` then `launch` (a new session).
- Attributes: provider (`claude`, `codex`), working directory, created-at,
  status (from chat-v1 where an adapter exists, else `Unknown`), local
  frontend attached (yes/no), remote controller (yes/no), exited (status).
- At most 16 live sessions per runtime; a launch beyond that is refused.
- Launch environment: a launch carries the frontend's working directory and
  environment (at most 512 entries, 256 KiB in total). The agent is spawned
  with it, so it has the same `PATH`, provider credentials and settings as if
  started from that shell; `CLAUDE_CLI_*`/`CODEX_CLI_*` are read from it, not
  from the runtime's own environment. The environment is dropped after the
  spawn and never logged or listed.
- An exited session keeps its final screen for an attached frontend and is
  removed 10 minutes after exit (or at `stop`).

### Local frontends

- `atem agent launch <provider> [args…]` = launch + attach.
  `atem agent attach <id>`, `atem agent list`, `atem agent stop <id>`.
- A frontend sends keys, paste and resize; the runtime sends a restore
  snapshot followed by output (the canonical-screen frames terminal-v1 uses).
  The status row, prefix keys and `terminal_prefix` stay in the frontend;
  `h`/`m` (hide) become detach, which prints one line saying the session is
  still running and how to reattach or stop it; `x` still stops it.
- One local frontend per session: attaching from a second terminal moves the
  session there and the first frontend detaches with a notice.
- Local input counts as terminal input for chat-v1's draft check; the remote
  control lease rules (prefix `g` reclaims) are unchanged.
- Bare `atem` keeps its menu; its Claude/Codex entries launch a session
  through the runtime.

### Lifetime

The runtime is idle when it has no live or exited sessions, no connected
client and no Astation operation in progress. It exits after 10 idle minutes,
or 30 seconds after the last operation when it never had a session (a runtime
started only for `atem pair` or `atem cred …`). While it runs and is paired it
is online for Astation; when it has exited, Astation sees this device offline,
as it does today when no Atem is running.

### Replacing a runtime of another build

A non-passive client (every command that uses the runtime; never `atem
status` or `atem --version`, which only look) whose build differs from the
runtime's replaces it by its own (`client::replace_other_build`): `restart`,
wait until the old process is gone (its socket stops answering and
`runtime.lock` is free), start this build, which adopts the workers, and
print `Atem's runtime updated to <build> (was <build>); sessions kept.` A
runtime from before `restart` gets SIGTERM instead, only when `runtime.lock`
names its pid and that pid is confirmed as this user's `atem runtime`. The
runtime is kept, with a message saying why, when its `worker_protocol`
differs from this build's (the message names the running sessions that block
it), while an Astation operation runs, or within 60 s of the last replacement
(`runtime.replaced`), so two atem builds in use don't keep replacing each
other. `atem runtime restart` does the same on request, without the 60 s
guard.

### Local protocol (v1)

JSON lines, `{"v":1,"op":…,"request_id"?:…}`. Terminal bytes are base64.

| op | from | fields |
|---|---|---|
| `hello` / `welcome` | client / runtime | `protocol`, `build`, `passive` (a client that never keeps an idle runtime running, e.g. the menu's look); runtime adds its pid, `astation` (link up), `host_error?` and `worker_protocol` |
| `paste` | client | `session_id`, `bytes` (base64 UTF-8, ≤ 1 MiB): one local input, written whole (bracketed when the agent asked for it) |
| `stopped` | runtime | `session_id`, `removed`: the answer to `stop` |
| `launch` | client | `provider`, `args`, `cwd`, `env`, `rows`, `cols` → `launched {session}` |
| `attach` / `detach` | client | `session_id`, `rows`, `cols` → `attached {session, restore}` |
| `input` | client | `session_id`, `bytes` |
| `resize` | client | `session_id`, `rows`, `cols` |
| `output` | runtime | `session_id`, `bytes`, `offset` |
| `exited` | runtime | `session_id`, `generation`, `status` |
| `list` / `sessions` | client / runtime | session attributes |
| `stop` | client | `session_id` |
| `notice` | runtime | text for the frontend |
| `session` | runtime | the attached session's changed summary (status, remote control, state) |
| `astation` | runtime | `connected`, on every change of the Astation link |
| `reclaim` | client | `session_id`: take control back from a remote lease holder (prefix `g`) |
| `reload` | client | sent by `atem unpair` and `atem logout`: re-read the login and pairing; a link whose pairing is gone is dropped with its attachments |
| `status` | client / runtime | read-only → `status {status}`: the link (`astation`, `transport` local/relay, `relay` label `<host> as <atem_id>`, `retrying`, `reauthenticating`), the attachment (`attachment`, `welcomed{revision, at_ms, ms_left}`, `refused{revision, needs, at_ms}` of the last refused `hello`), `journal_halted`, `host_error`, `adopting`, `sessions` (each with its worker's `worker_build`); never a secret |
| `restart` / `restarting` | client / runtime | the runtime exits after this pass so the client can start its own build, which adopts the workers; refused (`error`, "An Astation operation is running…") while an operation runs |
| `astation_op` | client | `request_id`, `kind` (`pair`, `pair_verify`, `cred_unlock`, `cred_projects`, `token`), `options` (`save` for `pair`; `astation_id` for `token`; `cwd` for `cred_projects`) |
| `print` | runtime | `request_id`, `level` (info/warn/error), `text` |
| `ask` / `answer` | runtime / client | `request_id`, `question_id`, `kind` (yes_no, text), `text` → `answer` `{request_id, question_id, value}`; `value` is `{"kind":"yes"}`, `{"kind":"no"}`, `{"kind":"text","text":…}`, or why there is none: `{"kind":"no_terminal","text":…}`, `{"kind":"unanswered","text":…}` |
| `done` | runtime | `request_id`, `ok`, `error?`; a second `astation_op` while one runs gets `done` with `ok: false` ("another pairing or unlock is in progress") |

Backpressure: at most 256 KiB of unsent output per frontend; beyond that the
runtime drops the stream and sends a fresh restore snapshot. When a session's
PTY input queue is full the runtime stops reading that client's socket until
it drains (input is never dropped silently).

### Astation operations through the runtime

Only the runtime opens Astation WebSockets. `atem pair`, `atem cred
unlock|projects` and paired-token refresh become runtime clients (starting it
if needed). If the runtime can't be started or reached, or speaks another
protocol version with live sessions, these commands fail with a clear message;
they never fall back to their own socket.

The CLI is only the user interface. The operation code (today in
`cli.rs::run_pair`, `pair_verify.rs`, `memory/unlock.rs`) moves to the runtime
and writes through a UI trait (`print`, `ask`) instead of `println!` and
`/dev/tty`; the CLI renders `print`, reads `ask` answers from `/dev/tty`, and
exits with `done`. `unlock.rs`'s `AstationLink` abstraction is the model.

- **One operation at a time.** `pair`, `cred_unlock` and `cred_projects` are
  serialized; a second request while one runs is refused ("another pairing or
  unlock is in progress").
- **Reply routing.** While an operation is active, the handshake and key
  messages (`verifyKeys`, `deviceVerified`, `verifyAbort`, `unlockGrant`,
  `unlockDenied`, `storageKeyAck`, `storageKeyRejected`, and pairing replies)
  go to it, not to the general handler. When no operation is active, or after
  it ended (success, refusal, Touch ID timeout, client gone), such messages
  are dropped with a log line; a late `deviceVerified` is never applied.
  `encryptionMode`/`keyGrant` keep their current handling (held during
  verification, applied after).
- **Client gone.** If the CLI disconnects or is interrupted mid-operation, the
  runtime ends it as a failure: device verification sends `verifyAbort`
  (as `atem pair` does today); the saved pairing stays.
- **Connection lost mid-operation.** The operation fails (best-effort
  `verifyAbort` if the socket is still writable); the runtime reconnects for
  its sessions only. The ceremony is never resumed or replayed; the user runs
  `atem pair` again.
- **`atem pair` cases.**
  1. Already paired and connected to the same Astation: the runtime runs
     device verification on its current authenticated connection; sessions,
     terminal viewers and chats stay connected.
  2. First pairing, or pairing with a different Astation: the runtime pairs
     (pairing code, credential sync, relay identity) and then replaces its own
     connection with the new one. Terminal viewers and chats on the old
     connection close (they would anyway: it's another Astation); sessions
     keep running and appear in the new Astation's list.
  3. Local Astation (loopback): same as 1/2 over the local connection.
  To confirm with Astation: (a) `verifyCommit` is accepted on a connection
  that authenticated before the re-pair; (b) re-pairing does not send
  `auth_required` over that connection (which would start re-authentication
  and revoke terminal leases mid-ceremony); (c) whether loopback connections
  are also replaced by `atem_id`.

HTTP-only commands (`atem sync`, `memory`, `skill`, `vault`) are unchanged.

### Astation-visible changes

Everything Astation sees of sessions is atem-session: the contract is
[protocol/atem-session-v1.md](protocol/atem-session-v1.md), and
[protocol/README.md](protocol/README.md) gives the overview. Mark tasks go
to a live Claude session whose working directory contains
`.chisel/tasks/<task_id>.json`; with none, the task fails with "no Claude
session for this project; run `atem agent launch claude` there".

## Failure handling

| Case | Behaviour |
|---|---|
| Frontend closed or crashed | Session keeps running; `atem agent attach` reopens it |
| Agent process exits | Session shows exited (final screen kept 10 min); Astation gets `exited`, chat gets `unknown` |
| Session or client handler panics | That session or client ends; cause in `runtime.log`; others continue |
| Runtime crashes | Workers and agents keep running; frontends report it; the next command starts a new runtime, which adopts them (receipts executing at the crash become `outcome_unknown`) |
| Astation disconnects / re-authenticates | Sessions unaffected; the runtime reconnects as `App` does today |
| Connection replaced by another process (an older Atem binary) | Close code 4001, or two closes without a reason within 5 s of authenticating: notice naming the cause and no reconnect for 60 s, then backoff up to 10 min |
| Connection lost during an Astation operation | Operation fails, no replay; sessions reconnect |
| CLI gone during an operation | Operation fails (`verifyAbort` for verification) |
| Second Astation operation while one runs | Refused |
| Two runtimes started at once | The `flock` loser exits; clients connect to the winner |
| Runtime unreachable for pair/cred | The command fails; it never opens its own socket |

Older Atem binaries on the same machine still open their own connections and
can still displace the runtime's (or be displaced); the docs say to upgrade
every atem on a machine together.

## Security

- Local socket is same-UID only, in a 0700 directory; no network listener.
  Any process of the user can already type into that user's terminals, so the
  trust boundary is unchanged.
- The runtime never holds device keys; the cred agent keeps them.
- Launch environments may contain provider credentials: bounded, passed only
  to the spawned agent, dropped after spawn, never logged or listed.
- Remote authorization: the verified Astation pairing (r9: the
  device list, [account-trust.md](account-trust.md)), re-authentication and
  session-v1 control leases.

## Testing

Atem side:

- Unit: session ids, registry, protocol encode/decode and limits, version
  check, backpressure, mark-task routing by working directory, operation
  serialization and reply routing.
- In-process with fake agents and a fake Astation (`runtime/*_tests.rs`):
  session-v1 registry, leases and receipts; terminal-v1 subscribe by session
  id; chat on the Claude one; stop one while the other runs; broker restart
  with adopted workers.
- The shared atem-session host fixtures against the real binaries
  (`tests/runtime_fixtures_binary.rs`; see
  [protocol/README.md](protocol/README.md)).
- Pairing and unlock (fake Astation, a session attached throughout):
  verification completes on the runtime's connection and the session's
  terminal and chat are still attached and unchanged afterwards; Touch ID
  timeout; CLI interrupted (Ctrl-C) → `verifyAbort`; connection dropped
  mid-ceremony → failure, no replay, sessions reconnect; a late
  `deviceVerified` after abort/timeout is dropped; a competing connection for
  the same `atem_id` during pairing (fake old binary) → failure reported, no
  tight reconnect loop; `cred unlock` while sessions are attached; `pair`
  while `cred unlock` runs → refused.
- Binary (temp `HOME`/`XDG_RUNTIME_DIR`): `atem agent launch` starts the
  runtime; a second launch uses the same runtime; closing the frontend leaves
  the session listed; `attach` restores the screen; `stop` ends it; idle exit
  (shortened by a test-only setting); `pair` refuses when the runtime is
  unreachable.

Astation/relay side (for the Astation team):
cross-replica replacement, stale approval rejection on their side, close code
4001, and owner-authenticated device verification in a separately owned test
session.

Manual: Codex and Claude launched separately, `atem pair` again, both visible
and controllable in Astation throughout, verification approved with Touch ID.

## Out of scope

Sessions surviving a reboot; a system service; a GPUI
desktop frontend; attaching to agent processes Atem did not start; several
runtimes per profile; session names.

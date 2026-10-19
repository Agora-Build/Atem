# Atem runtime: one owner for every agent session and the Astation connection

Status: **implemented on `feat/runtime`** (2026-10-16; plans
`designs/plans/2026-10-16-runtime-host-integration.md` and its
predecessors), not yet released. See "Implementation status" below for what
was built and where it deviates from this text. Proposed 2026-10-15
(decisions A–C agreed with the user). **Superseded where it differs by the approved
[session-multiplexing.md](session-multiplexing.md)** (Astation + user,
2026-10-15); see "Alignment with session-multiplexing.md" below, which is
binding for Atem. It is phase 2 of [local-agent-runtime.md](local-agent-runtime.md)
("background PTY owner, private local attach/detach, stable session
identities") and answers Astation's handoff "Atem pair versus running agent
host: connection ownership race" (2026-10-15).

## Alignment with session-multiplexing.md

The approved product design changes this document as follows. Where the text
below disagrees, this section wins.

1. **Workers own agents.** Each session runs in its own `atem worker` process
   that owns the agent process, PTY, output collection and submission journal.
   The runtime is a broker (Astation connections, registry, cred agent access,
   local IPC). A runtime crash or frontend exit does not end workers; a new
   runtime adopts surviving workers through authenticated local IPC, checking
   session id, process generation and process-start metadata (never a pid
   alone). A worker or agent crash, or a reboot, shows the session as
   Interrupted / Recovery Required; a provider resume, when offered, is a new
   process generation. Transcripts are never replayed into a new process.
2. **CLI workflow.** `atem status` (read-only, offline, stale marks; labels
   Account / Pairing / Verification / Credentials / Authorization / Relay /
   Local agents; the user removed the `atem cred status` alias that
   session-multiplexing.md §1 still lists). `atem pair` reports status and
   changes nothing when already paired; `atem pair verify` verifies the existing
   binding (no-op when validly verified; interruption keeps the pairing);
   `atem cred unlock` never starts pairing or verification (unverified → "run
   `atem pair verify`"); `atem cred lock` works offline; `atem unpair` removes the
   binding, commits a new host trust generation and invalidates remote
   authorization while keeping account data and running agents. The
   "`atem pair` cases" below are replaced by this.
3. **Control leases.** One controller per session; a renewable lease that
   expires after 15 s without renewal (earlier when authorization expires);
   many viewers; explicit takeover leaves the old controller a viewer; local
   terminal input wins atomically; every mutation path (terminal, chat, future
   APIs) checks target, controller identity, lease epoch and permissions;
   stale epochs and old process generations are rejected.
4. **Receipts.** A worker durably records a submission (request id bound to the
   exact target and payload digest) before acknowledging acceptance; states
   accepted / executing / completed / rejected / outcome-unknown; duplicates
   return the recorded outcome; same id with other content is rejected. Raw
   keystrokes are a live stream, never replayed. Retention: receipts for the
   session's life + 7 days, Atem-owned conversation history 30 days after
   closure (configurable limits, export/delete), bounded raw scrollback.
   Records owner-only and encrypted under the local key policy, no plaintext
   fallback.
5. **Transports.** Astation's direct port-8080 connection and the relay are thin
   adapters over one identity, registry, lease and receipt implementation.
   Authorization freshness: at most 24 h after the last validated trust update;
   at the deadline remote viewing/control pause while agents and the local
   terminal continue.
6. **Joint contract first.** Trust anchor and enrollment, membership,
   freshness proofs, end-to-end encrypted transport, QR grants and the session
   / lease / receipt wire messages are specified jointly with Astation as a
   versioned contract with fixtures (`designs/protocol/`) before either side
   implements the parts that communicate. Atem builds the local parts (CLI
   workflow, runtime, workers, journal, host lease logic) against that
   contract as it lands.

## Implementation status (feat/runtime, 2026-10-16)

Built as the Alignment section says, not as the older text below where they
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
  boundary. Local input revokes any remote lease first.
- **Session host.** The broker runs atem-session r6.2 (compatibility mode,
  `designs/protocol/atem-session-v1.md`) over a `FileJournal` in
  `<config>/runtime/journal/`; the runtime's one Astation link is one
  attachment, new on every connect or re-authentication. Only a paired,
  verified Astation gets one. Terminal-v1 and chat-v1 are bound to session-v1
  (bindings and leases); `agentInput`, `agentPrompt`, voice, `userCommand`,
  terminal-v1 `control`/`list`, provider-name terminal ids and the agent list
  are removed with no compatibility (the "Astation-visible changes" section
  below is replaced by `designs/protocol/atem-host-handoff.md`).
- **Operations.** `atem pair`, `atem pair verify`, `atem cred unlock|projects`
  and the paired-token refresh run in the broker on its link, as described
  below; `atem unpair` and `atem logout` send `reload`.
- **Session logs** are written by the worker when an agent that printed
  something ends (`<config>/logs/<session_id>/session.ansi`, `summary.md`).

Deviations from the text below:

- Lifetime: the runtime exits after 10 minutes with no live sessions, no
  launch in progress and no non-passive client; there is no separate
  30-second rule for a runtime started only for an operation (the operation's
  CLI stays connected while it runs).
- `atem pair` on an already paired profile only prints the status (Alignment
  item 2); re-pairing over a live connection ("`atem pair` cases" 1–3) does not
  exist: `atem unpair`, then `atem pair`.
- `atem status` is the only status command: the user removed the `atem cred
  status` alias (session-multiplexing.md §1, maintained by Astation, still
  lists it).
- Remote viewers and controllers are not limited to "one viewer per session"
  by the runtime; the limit is the one link (one attachment).
- Shared fixtures (`tests/runtime_fixtures_binary.rs`): nine host fixtures
  pass against the real runtime, and `removed-ops-have-no-effect` passes
  folded onto one attachment; the multi-attachment fixtures run only in the
  core harness (one Astation link today) and closed-session has no runtime
  trigger yet. A remote write carries its lease's deadline (`not_after`, on
  CLOCK_MONOTONIC) and the worker drops it at the PTY write boundary once
  that has passed. See `designs/protocol/atem-host-handoff.md`.

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

From the user and Astation's handoff:

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

## Decisions

- **A. Closing a launch window detaches.** The session keeps running in the
  runtime and stays visible in Astation. `atem agent attach <id>` reopens it;
  `atem agent list` and `atem agent stop <id>` manage it; the prefix key `x`
  still stops it. On detach the terminal prints one line saying the session is
  still running and how to reattach or stop it.
- **B. The runtime starts on demand** and exits when idle (see "Lifetime").
  No system service is installed.
- **C. Delivery in three PRs, released together** (see "Delivery").

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
  `h`/`m` (hide) become detach.
- One local frontend per session: attaching from a second terminal moves the
  session there and the first frontend detaches with a notice.
- Local input counts as terminal input for chat-v1's draft check; the remote
  control lease rules (prefix `g` reclaims) are unchanged.
- Bare `atem` keeps its menu; its Claude/Codex entries launch a session
  through the runtime (step 3).

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
| `reload` | client | re-read credentials, sessions and config (after `unpair`, `logout`, config edits); a link whose pairing is gone is dropped with its attachments |
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

Replaced by atem-session r6.2: the complete list of wire-visible changes, and
how to run the host, are in
[protocol/atem-host-handoff.md](protocol/atem-host-handoff.md). Mark tasks go
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
- Remote authorization is unchanged: Astation pairing, re-authentication and
  terminal-v1 control leases.

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
  (`tests/runtime_fixtures_binary.rs`; results in
  `protocol/atem-host-handoff.md`).
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

Astation/relay side (for the Astation team, listed in the handoff reply):
cross-replica replacement, stale approval rejection on their side, close code
4001, and owner-authenticated device verification in a separately owned test
session.

Manual: Codex and Claude launched separately, `atem pair` again, both visible
and controllable in Astation throughout, verification approved with Touch ID.

## Delivery

Planned as three PRs released together (step 1 alone would leave a
long-lived runtime racing a direct `atem pair`). Built instead on one branch,
`feat/runtime`, by the plans in `designs/plans/2026-10-16-*`; the
aliases, `agent_id` routing and agent list in step 1 were dropped (atem-session
r6, no compatibility):

1. **Runtime and sessions.** `atem runtime`, local protocol, `launch` /
   `attach` / `list` / `stop`, several sessions, agent list and terminal-v1 by
   session id (with aliases), chat-v1 per session, routing by `agent_id`, mark
   tasks by working directory. `App`'s fixed Claude/Codex slots (in
   `app.rs`, `app/terminal.rs`, `app/chat.rs`) become a map keyed by session;
   session and Astation logic move into the runtime; the TUI becomes a
   frontend. This is the large step (`app.rs` ≈ 2.3k lines, `app/*` ≈ 1.8k).
2. **Astation operations through the runtime.** The UI trait; `atem pair`,
   `atem cred unlock|projects` and paired-token refresh as runtime clients;
   operation serialization and reply routing; `reload` from `unpair`/`logout`.
3. **Cleanup.** Bare `atem` menu through the runtime; remove remaining in-TUI
   ownership; update AGENTS.md, README, terminal-v1 and chat-v1 docs; send
   Astation the wire changes and the questions above.

## Out of scope

Sessions surviving a reboot; a system service; a GPUI
desktop frontend; attaching to agent processes Atem did not start; several
runtimes per profile; session names.

# Optional background hosting and remote agent launch

Status: design draft, 2026-11-02. The Atem remote-launch receiver and optional
zero-session lifetime are implemented on the feature branch; see the
[host-work extension](protocol/atem-host-work-v1.md). OS service installation
and Astation UI remain planned. The user requested
remote creation of new Codex/Claude sessions and approved optional service
installation with automatic startup after reboot. The service mechanics and
service commands below are proposed implementation choices; the feature-branch
receiver contract is specified in the host-work extension.

Current behavior remains documented in [agent-runtime.md](agent-runtime.md).
The remote contract remains [atem-session-v1](protocol/atem-session-v1.md);
this draft does not add operations or permissions to the shipped protocol.

The separate [agent notifications design](agent-notifications.md) proposes
event-driven work between machines. Hosting would keep its receiving runtime
online with zero sessions; an explicitly allowed launch-on-arrival policy
would reuse the remote creation operation here. Installing a service alone
does not enable subscriptions or peer-initiated work.

## 1. Experience

A user can keep Atem available on a coding machine and request a new agent
from Astation, a mobile client or an authorized integrated app. No Codex or
Claude process needs to be launched in advance. The machine must be running,
reachable, and have the selected agent installed and configured.

```text
Coding machine                         Astation / integrated app
  managed Atem runtime <------------- authenticated create-session request
    new Atem worker
      PTY -> original Codex / Claude
  session ID + terminal/chat --------> open the new session
```

These are the product requirements:

- Service installation is optional. Installing or upgrading the Atem
  package alone does not install, enable or start an OS service.
- With hosting disabled, the existing on-demand runtime and ten-minute idle
  exit remain the default. Opting into healthy hosting keeps the runtime
  online with zero sessions, including without an OS service.
- Explicit service installation enables startup after reboot and starts
  the runtime now. Managed hosting stays available with zero agent sessions.
- Service startup does not start agents, resume old conversations, replay
  prompts, unlock credentials or grant remote access.
- Local and remote launches use the same worker/session implementation.
  Either kind of session can be opened locally with `atem agent attach`.
- tmux and Herdr are optional places to run Atem frontends. Neither owns
  the agent processes that Atem launches.

## 2. Process ownership and persistence

The OS service manager supervises the broker (`atem runtime`). Each detached
`atem worker` owns one agent's PTY, canonical screen, adapters and logs. A
frontend connects to the broker; its window and network connection do not
own the worker's lifetime.

| Event | Expected behavior |
|---|---|
| Close Astation, hide an Atem frontend or lose the network | Agent continues; a client can reconnect |
| Close a tmux/Herdr pane containing an attached frontend | Frontend detaches; agent continues |
| Restart/crash the broker | Workers continue; replacement broker verifies and adopts them |
| Explicitly stop an agent | Agent ends; its exited row retains the existing ten-minute lifetime |
| Stop the hosting service | Broker goes offline; existing workers continue |
| Reboot or stop a worker | Its live agent process ends |
| Boot after service installation | Runtime starts; old work is not automatically resumed |

An OS service returning after reboot is different from preserving a live
agent process across reboot. Conversation resume must be an explicit future
launch using the agent's saved conversation, with a new process generation.
No process is restarted by replaying a transcript.

## 3. One runtime, including tmux and Herdr

The singleton remains one runtime per OS user and resolved Atem profile,
enforced by the existing profile lock and socket ownership checks. Launching
from another terminal, tmux, Herdr, SSH or a desktop app does not create a new
profile or host identity.

| Invocation | Behavior |
|---|---|
| `atem`, `atem agent launch`, `atem agent attach` with service running | Connect to the managed runtime; open a local frontend where applicable |
| `atem runtime` with a runtime already running | Report the existing owner, PID, build and mode, then exit successfully |
| Concurrent startup for the same profile | The profile lock elects one broker; no second Astation connection |
| Service installed but deliberately stopped | Mutating client commands explain how to start the service; no unmanaged fallback |
| A separate profile | A separate runtime and identity are possible; its service registration must also be separate |

An explicit `atem runtime` in a tmux/Herdr pane without a service keeps its
existing foreground/on-demand behavior. If that broker ends, workers can
survive for a later broker to adopt, subject to OS logout policy. Installing
the service provides the supervised lifetime across terminal logouts.

### Handing an existing runtime to the service

Installation must not start a supervised duplicate that repeatedly loses
the profile lock and restarts. Prepare and validate the service and stable
executable first, then perform a coordinated broker-only handoff. Let an
in-progress Astation operation finish; if a safe handoff is unavailable,
report installation as pending rather than claiming the service is ready.

The old broker closes its link and releases the profile lock. The service
manager starts the managed broker, which verifies/adopts surviving workers
and reconnects under the same profile identity. Clients retry their
connection. Existing worker builds stay until their sessions end.

Adoption alone does not move a worker out of a Linux login-session cgroup.
If an existing worker remains subject to logout cleanup, report that
limitation until it can be migrated through a supported manager mechanism.
Workers newly launched under the managed service must survive terminal
logout; do not restart an old agent to manufacture that guarantee.

If startup fails, preserve workers and profile data, report the failure and
provide a local recovery path. Never create a second profile as a fallback.

## 4. Local commands and proposed service commands

These runtime commands are implemented on the feature branch:

| Command | Effect |
|---|---|
| `atem runtime start` | Start in the background or reuse the existing runtime without replacing its build; create a disabled private configuration only when missing |
| `atem runtime check` | Validate approved launch profiles, environment sources and notification routes; start no processes |
| `atem runtime` | Run in the foreground, including inside tmux/Herdr; the profile lock prevents duplicate runtimes |
| `atem runtime restart` | Replace the broker with this build; verified surviving workers are adopted |

`runtime start` and `runtime check` require pairing. Starting a runtime grants
no remote launch or notification permissions: configure approved profiles
and routes and explicitly set `enabled = true` in `runtime.toml`. A profile or
route without `principals` is open to the paired Astation (`member:<its id>`,
from the pairing record); its own list replaces that default. `atem runtime
check` lists the device list's members and services with whether each may
launch.
Both features use the same runtime. Without enabled hosting, its ordinary idle
timeout still applies. Repeated start preserves configuration and the running
process's environment. Starting a runtime does not install an OS service or
enable startup after reboot.

All service commands below remain proposed, not available today.

| Command | Effect |
|---|---|
| `atem service install` | Install for the current account/profile, enable boot startup, hand over an existing runtime if necessary, and start now |
| `atem service status` | Passive view of registration, boot policy, manager state, runtime identity and readiness |
| `atem service start` | Start the installed service now |
| `atem service stop` | Stop the broker through its manager; keep workers and boot registration |
| `atem service restart` | Replace only the managed broker; verify/adopt workers |
| `atem service update` | Stage the invoking build in the stable service location, validate compatibility, then perform a managed restart |
| `atem service uninstall` | Disable future startup, stop/remove the service and return the profile to on-demand mode |

Stopping the service takes it offline until an explicit start or the next
boot. Ordinary client commands must not undo that stop. Uninstalling service
integration retains agent workers, pairing, credentials, logs and project
settings; it is not an account reset or a bulk agent-stop command. A later
on-demand broker can adopt workers that are still alive.

Installation grants no new account trust. The service runs as the original
user, with that user's profile; `sudo atem ...` must not accidentally create
or operate a root profile. OS authorization, where needed, is limited to
registering service startup for the selected user.

## 5. Platform startup

The default service installation must deliver boot startup, not quietly
substitute startup at the next interactive login.

### Linux

Use a `systemd --user` unit with an absolute executable path and foreground
managed-runtime entrypoint. Enable user lingering so the user manager and
runtime directory exist at boot and survive the last SSH logout. Validate
lingering and service availability during installation. If local policy
requires OS authorization or prevents lingering, explain that boot hosting
is not enabled; do not report success as a boot service.

Record whether lingering was already enabled. Uninstall removes Atem's unit
and boot registration, but does not automatically disable account-wide
lingering, which other services or surviving workers may rely on.

The user home and profile must be available. If they depend on an encrypted
home or a login-mounted filesystem, report that startup prerequisite.
Systems without systemd retain ordinary on-demand operation; another service
backend can be designed separately.

### macOS

Boot startup uses a system-domain LaunchDaemon configured with `UserName`
for the original account. The plist is protected as a system service
registration; the broker and agents run without root privileges. Installing
and changing this registration uses the OS authorization mechanism.

A user LaunchAgent only starts with that user's login session. It may be
offered later as a clearly named login-start alternative, but does not
satisfy the boot-start default. FileVault's preboot unlock and availability
of the user's home still bound when a daemon can actually start. A boot
daemon must not assume an unlocked login Keychain or a GUI session.

### Supervisor behavior and worker survival

The broker runs in the foreground for the manager; it must not self-daemonize.
Use bounded restart backoff for crashes and unavailable dependencies. An
explicit manager stop suppresses restart until start or the next boot.

Detaching with `setsid` does not remove a process from a systemd cgroup.
The broker service must therefore avoid killing all descendants on restart.
For the initial Linux design, use broker-only termination (`KillMode=process`)
with bounded shutdown/escalation targeting the broker. Workers and the
separate credential agent keep their existing lifetimes. Per-session scopes
are a possible later replacement for this termination policy.

On macOS, preserve detached workers when the launchd job ends; configure
`AbandonProcessGroup` as appropriate and verify behavior with real PTYs.
Worker survival is a release requirement tested against the actual service
manager, not inferred from a successful detached-spawn unit test.

The manager must not restart Codex/Claude when an agent exits. An unrelated
failure of a worker must not restart the whole service or other agents.

## 6. Executable selection and upgrades

Service installation records the canonical profile, owning UID, registration,
stable executable location and installed build. The service executable is
independent of a temporary Cargo build, a version-specific Node directory or
an npm directory that an upgrade can remove. Updates stage a complete binary
and switch it atomically; a failed update retains a usable previous build.

All current clients learn whether the broker is manager-owned. When it is,
they must not use the existing automatic replacement-by-the-invoking-build
path. `atem runtime restart` delegates to the manager; service update chooses
the installed build explicitly. Using an older CLI must not downgrade the
service or cause two supervisors to race.

The managed broker rejects generic legacy restart requests that bypass its
manager. Compatibility tests must include the shipped older CLIs; adding a
new welcome field alone cannot make an old CLI understand service ownership.
If replacement cannot adopt existing worker protocols, retain the current
broker and identify the blocking sessions.

Uninstall must be recoverable after partial failure: retain the ownership
record until the manager is disabled and cannot unexpectedly restart the
broker. Do not allow unmanaged fallback while registration state is uncertain.

## 7. Remote creation of an agent

This is a new capability, separate from service installation. Keeping Atem
online does not by itself authorize remote launch or enable a Station's
hosted-execution policy.

Astation presents **New Agent**, then machine, existing project directory,
and a named launch profile. A profile may select Codex with `--profile oss`
or Claude with additional arguments. The runtime starts the original
interactive CLI inside a worker-owned PTY; no local frontend or tmux/Herdr
session is created. Astation opens the resulting session's terminal/chat.

An integrated API uses the same authenticated operation and returns its
request status and session identity. The relay transports the operation;
it does not execute a shell command on the host or bypass host authorization.

### Host-level request and authorization

Creation cannot require the binding of an existing agent session. Add a
host-level operation inside the authenticated encrypted channel, bound to
the host identity, trust generation and current principal. Negotiate a new
feature and update the shared protocol, client bindings and fixtures before
implementing either endpoint. Final wire names/revision are not assigned here.

The proposed request contains a request ID, selected project reference,
launch profile ID and profile revision. It contains no arbitrary shell
command or credential values. A proposed explicit launch permission is
scoped to authorized hosts/projects/profiles; existing `view` or `control`
does not silently acquire it. A grant restricted to existing session IDs
must not implicitly allow creating new sessions.

Recheck authorization and project/profile scope at the spawn boundary.
Account revocation, expired/narrowed grants, held membership, a paused hosted
execution policy or unresolved project scope prevent a spawn. Existing r9
enrollment is required; an old verified record without the membership pin
is not enough. Browser and service launch support require explicit scope
rules, not accidental inheritance from native-client support.

### Local launch settings and environment

Named profiles are configured on the coding machine and identify the agent,
arguments and environment sources. Projects map to local existing directories.
Resolve and validate the directory on the host and compare it to the granted
project before spawning. Initial scope is existing directories, without
automatic cloning or Git worktree creation.

Remote launch cannot inherit exports from an arbitrary terminal. It must
resolve custom provider base URLs, API keys and CLI paths through the selected
host profile. Credentials remain local; return only profile IDs, labels and
readiness. Never store values in the launch journal, memory or service unit.
`atem cred get` is still planned and must not be assumed available for this.

Local `atem agent launch` keeps its existing shell-environment behavior.
Remote launch never sources shell startup files implicitly. Shared startup
code must handle adapters and approval hooks currently prepared by the CLI,
with useful setup errors when unattended launch prerequisites are missing.

### Launch results, retries and session use

Durably reserve the request ID, payload digest, session ID and process
generation before spawning. Repeated requests with that ID return the same
result; the same ID with different input is a conflict. Persist results
before acknowledging them. Recovery reconciles the worker record, process
identity and request; uncertain outcomes must not trigger a second spawn.

Define a host-level result lookup and a retention/admission policy in the
wire contract. Results must outlive the exited session's ten-minute list
retention. Bounded result retention must be paired with request expiry or
another durable admission rule: removing an old result must not turn a retry
into a fresh launch. Expired requests are refused, not accepted again. This
journal is separate from receipts that already require an existing session
binding.

Return creation status and the new session/process identity. Process creation
does not mean the agent is ready to accept a chat prompt: expose starting,
ready or failed state through normal session updates. For the initial
version, send any first prompt separately through the existing chat receipt
flow after readiness; do not append unacknowledged keystrokes to startup.
The existing live-session limit and input-ownership rules still apply.

## 8. Readiness and diagnostics

Report service state and remote-launch readiness separately. A running
service can be offline, unpaired, missing r9 enrollment, waiting for unlock,
blocked by Station policy or missing the selected CLI. Give a concrete
reason. Reboot startup must not silently change key-unlock or approval policy.

`atem status`, `atem --version` and service status remain passive. Include
manager/mode and the actual executable/build in diagnostics; distinguish
local protocol v1 from remote session revision r9. Astation should identify
separate profiles/host identities even when they share a hostname. Multiple
tmux windows of one profile do not constitute multiple hosts.

## 9. Delivery and verification

Implementation can proceed in two increments: optional service hosting and
ownership/handoff first; remote launch and its Astation/API clients after the
shared protocol is specified. Neither increment is implemented by this draft.

Required verification includes:

- Normal package installation creates no service; ordinary idle exit remains.
- Explicit install, reboot and SSH logout retain zero-session hosting on
  Linux; macOS boot and login behavior are tested separately.
- Concurrent service, terminal, tmux and Herdr commands for one profile keep
  one broker and one Astation link; separate profiles remain distinct.
- Install handoff, managed crash/restart, update and uninstall preserve
  verified worker/agent PIDs, PTYs and input fencing under the real manager.
- Explicit service stop stays stopped; partial install/uninstall and stale
  CLIs cannot produce a downgrade, restart loop or unmanaged duplicate.
- Missing enrollment, locked credentials, offline hosts and paused/revoked
  authorization report useful readiness without weakening access policy.
- Remote Codex and Claude creation works from zero sessions, with custom
  provider settings, extra arguments, approval hooks and local attach.
- Duplicate launch requests, reconnects and crashes around each spawn/journal
  transition produce one reconciled session or an explicit uncertain result.
- Project restrictions, profile changes, grant expiry and revocation are
  enforced before spawn; credential values never appear in returned metadata.
- A machine reboot starts only the runtime and never replays agent actions.

All automated checks use isolated profiles, service labels and temporary
units. They must not register a production service, reboot the developer's
machine or disturb existing agents as a test side effect.

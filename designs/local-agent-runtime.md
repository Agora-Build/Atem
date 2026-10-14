# Local Coding Agent Runtime

Status: design with an initial Atem host implementation in the worktree (2026-10-13); Astation UI pending.

See [Shared terminal: first Atem build](terminal-v1-implementation.md) for the
implemented command, exact wire contract, canonical-screen rendering refinement,
validation and remaining acceptance work. The later sections retain the broader
proposal; they do not imply those phases have shipped.
Updated: 2026-10-13
Code baseline: Atem v0.6.13, commit `538887b`.

## Goal

Launch the original interactive `codex` or `claude` CLI inside Atem. The user
operates its normal terminal UI locally and can also view and operate the
**same running session** from a remote Astation app connected to that Atem.
This is the primary requirement, clarified on 2026-10-13.

The agents continue to run with their own installed binaries, authentication,
configuration, skills, and tools. Atem manages their sessions and communication;
the feature does not replace the agents with direct calls to a model API.

Local and remote clients share one process, one PTY, one input buffer, and one
terminal screen. A remote attachment does not launch another agent, start a new
conversation, or replace the original CLI with an SDK conversation UI.

Two integration modes serve different requirements:

| Mode | Experience | Priority |
|------|------------|----------|
| Shared terminal | Original CLI UI, keyboard controls, menus, native approval prompts, and local/remote access to the same process | Required first delivery |
| Structured provider | Messages, tool activity, typed approvals, and completion in Atem/Astation's own conversation UI | Optional later extension |

Remote terminal display is required for both desktop and mobile users who
cannot see the host terminal. Its protocol is specified in
[remote-agent-control.md](remote-agent-control.md). Structured providers are
useful for automation but are not a prerequisite for shared-terminal control.

## What exists today

These observations describe the code baseline, not promises about every
installed version of an external agent.

| Component | Current behavior | Gap for this feature |
|-----------|------------------|----------------------|
| `src/claude_client.rs`, `src/codex_client.rs` | Spawn installed CLIs in a PTY, write input, read ANSI terminal output, support resize | No remote screen subscription; unbounded channels and per-read lossy UTF-8 conversion need review before robust streaming |
| `src/app.rs`, `src/tui/mod.rs` | Display captured terminal output and drive launched sessions from the TUI | Session ownership is tied to the TUI process; Claude/Codex menu entries require an Astation connection |
| `src/tui/mod.rs`, `src/tui/draw.rs` | Forward local keyboard input and render the emulated CLI screen; reserve Ctrl+B for Atem | Validate keyboard, paste, Unicode, cursor, and terminal-mode fidelity against both original CLIs |
| `atem agent launch [claude-code\|codex]` | Prints a placeholder directing the user to the TUI | The CLI command does not launch a session |
| `src/acp_client.rs` | Uses `session/new`, plain-text `session/prompt` parameters, and `message`/`session/done` notifications | Current standard ACP adapters may use different schemas; test and update the contract before claiming interoperability |
| `src/agent_registry.rs` | In-memory agent snapshots and status | No durable session bindings or output replay across process restarts |
| `AgentPrompt` in `src/app.rs` | Routes by agent ID; ignores the supplied session ID | Cannot safely address multiple conversations without a session mapping |
| `AgentInput` in `src/app.rs` | Writes text or keys to the focused PTY; ignores `agent_id` | Explicit session routing, controller ownership, and the full terminal key/paste contract are missing |
| Terminal output in `src/app.rs` | Feeds a local vt100 parser and records output | No shared screen snapshots/diffs, revision recovery, or remote resize policy |
| Existing voice path | Sends transcribed requests to Claude | Selecting the intended Codex/Claude terminal session requires addressed routing |
| `poll_acp_events` | Forwards live ACP events to Astation | No general durable event subscription for independent local CLI clients |

The baseline's `atem agent list/connect/prompt/probe` commands have since been
removed; the ACP client remains for `atem agent visualize` and the TUI.

Calling a server an agent server does not identify its protocol. A Codex
app-server WebSocket endpoint cannot be passed to the existing ACP client and
assumed to work.

## Reference: how Paseo communicates with agents

Paseo runs a local daemon. Its desktop, web, mobile, and CLI clients connect to
that daemon; provider adapters launch agent subprocesses and translate their
input and output into a common event model.

| Provider | Observed Paseo integration | Implication for Atem |
|----------|----------------------------|----------------------|
| Claude Code | Claude Agent SDK with asynchronous input, partial messages, a tool-permission callback, and the resolved Claude executable | Use the SDK through a small bridge, or validate an equivalent structured CLI interface |
| Codex | Launches `codex app-server` with stdin/stdout pipes and exchanges JSON-RPC requests and notifications | Implement a native Codex app-server adapter |
| Other ACP providers | Provider adapters using Agent Client Protocol | Implement the current ACP contract separately from native provider APIs |

This is a reference architecture, not a proposal to make Paseo a runtime
dependency. The source references and revision are recorded below.

Paseo also supports a **workspace terminal**: run `codex` or `claude` there for
the original interactive CLI experience, then access that terminal from its
desktop, web, or mobile app. This terminal path is the relevant precedent for
the user's requirement. It is separate from Paseo's structured provider path.
Its `paseo` CLI can also manage agents and workspace terminals.

### Focused reference: Use Codex in the Paseo terminal

The documented flow is to open a workspace terminal and run `codex` normally.
The source at the pinned revision shows a general terminal implementation;
this path does not require the Codex app-server provider adapter:

| Step | Observed Paseo implementation | Lesson for Atem/Astation |
|------|-------------------------------|-------------------------|
| Host a terminal | `terminal.ts` uses `node-pty` to start a shell or configured command in the workspace | Reuse Atem's `portable-pty` to host the original interactive CLI |
| Track terminal state | A daemon-side `@xterm/headless` receives PTY output and maintains screen/scrollback/modes and revisions | Keep an authoritative parser at Atem for attachment and restoration |
| Deliver live output | The terminal controller coalesces UTF-8 ANSI output into `Output` frames; the protocol header is an opcode plus terminal stream slot | Send terminal text/control bytes; binary framing does not imply video or images |
| Render the UI | The browser renderer uses `@xterm/xterm`; the client routes output by terminal subscription and feeds the renderer | Astation renders the original CLI locally using a compatible terminal component |
| Send input | Terminal input reaches the selected PTY; resize reaches both headless emulator and PTY | Forward keyboard/paste and resize to the same original CLI process |
| Attach/restore | Send terminal-state or ANSI restore payloads, then output newer than the captured snapshot revision | Restore screen/modes and avoid duplicate output across the snapshot boundary |
| Catch up | Output is coalesced; a backed-up stream can switch to snapshot restoration, with limited visible scrollback | Bound buffers and recover from current state without resubmitting input |
| Size ownership | `claim` chooses a size owner; only that owner can `update` dimensions | One PTY needs one size owner rather than competing viewer resizes |

The wire opcodes are `Output`, `Input`, `Resize`, `Snapshot`, and `Restore`.
Snapshots contain terminal text/cell state, or ANSI reconstruction of that
state. The normal live path streams ANSI output rather than cell-grid diffs.
The daemon answers terminal queries; the browser renderer suppresses its own
query replies to avoid duplicates.

Paseo's inspected size-owner rule is not an exclusive keyboard-controller
lease: the inspected input handler checks the subscription/source and forwards
input. Atem's proposed local/remote handoff is an additional policy, not a
claim about Paseo's behavior. See the pinned source links below.

## Proposed architecture

```text
Local Atem terminal                    Remote Astation app
keyboard, paste, screen                 keyboard, paste, screen
          |                                      |
          |                          existing authenticated connection
          +-------------------+------------------+
                              |
                    Atem terminal session owner
                    - addressed session registry
                    - input/controller arbitration
                    - canonical terminal screen
                    - ANSI output, restore snapshots, resize
                              |
                         one PTY master
                              |
                    original codex or claude CLI
                    one live interactive session
```

The first delivery can extend the existing TUI-owned PTY sessions. The owner
continues reading output when an agent panel is unfocused or the remote viewer
disconnects. Astation subscribes to that owner; it does not run a second CLI.

A later background runtime can own the PTY so the local Atem viewer can detach
without ending the process. Use private, owner-only local IPC on Linux/macOS.
Detaching one viewer never implies stopping the agent; explicit stop is a
separate action. Before that phase, keep the owning Atem process running and
document its lifetime honestly.

Astations remain the remote control plane. Reuse the existing authenticated
direct/relay connection and identity routing; see
[connection-priority.md](connection-priority.md) and
[session-auth.md](session-auth.md). Exposing a native provider API directly to
LAN or internet clients is outside the first phase.

### Launch and terminal fidelity

Resolve the installed executable, start its ordinary interactive mode in the
selected workspace, and inherit the user's provider authentication and
configuration. Preserve approval and sandbox behavior. Missing executable,
login-required UI, and process exit remain visible to the user.

Keep PTY output as bytes through the terminal parser. Decoding each read with
replacement characters can corrupt a UTF-8 character split across reads.
Support the terminal modes used by both CLIs, including colors, wide
characters, cursor state, alternate screens, paste, and input sequences.
Validate the ordinary local CLI experience rather than assuming the current
vt100 rendering and key conversion cover every interaction.

Only the session owner answers terminal queries. Local and remote viewers
must not each send a cursor-position response to the same process. Expose a
documented Atem escape/detach shortcut without consuming normal agent keys.

### Input ownership and native approvals

Both clients can observe the same screen. One controller at a time may write
input: local control starts as the default, and Astation explicitly requests
control. Display the current controller. Local reclaim revokes the remote
lease, advances its generation, and rejects stale queued remote input. Do not
silently discard local typing while a remote client holds control.

Route every write through one ordered PTY writer. Identify remote operations
by session, process generation, controller lease, and request ID. Reject stale
or unknown targets rather than writing to whichever agent happens to be
focused. Exclusive control prevents simultaneous typing, but handoff preserves
any unfinished native CLI input. Show that inherited input; the new controller
must explicitly finish or cancel it rather than automatically clearing or
submitting it. Controller handoff does not prove the CLI is at a prompt boundary.

Raw keys and paste preserve the native terminal behavior. A convenience
"send text and submit" action must state its effect on the current terminal
input; it is not a semantic prompt queue. If the CLI is busy or showing an
approval menu, the CLI decides how that input behaves. Voice text uses the
selected terminal through the same input path.

Approve tools using the original CLI's visible approval UI and keyboard
controls. PTY mode cannot reliably infer approval state, turn completion, or
safe prompt submission from screen text or periods of silence.

### Text-based terminal sharing, recovery, and resize

Follow the Paseo terminal pattern first: ordered ANSI terminal output plus
restoration snapshots. The data is text and terminal control sequences; the
remote app renders it. No screen capture or video/image stream is required.
Binary WebSocket frames are an efficient container for these bytes, subject to
support in the direct/relay path. A text-only path needs an explicit byte-safe
encoding. Neither representation changes the terminal's meaning.

The owner maintains one canonical terminal screen. On attach, send a restore
snapshot with dimensions, screen/cursor, bounded scrollback, relevant terminal
modes, session/process generation, and output position. Astation can use
`xterm.js` in a web view or a compatible native terminal component. Only the
owner answers terminal queries; viewers render and send actual user input.

Capture a snapshot at a known output boundary, buffer concurrent output, then
deliver only output newer than that boundary. Proposed Atem envelopes include
stream generation and sequence/offset correlation. Reconnect or an output gap
resets/restores the renderer from current state before continuing the new
stream. Never drop arbitrary ANSI bytes and continue parsing as if complete.
Bound viewer queues and retained scrollback; replace a slow viewer's backlog
with an ordered restore barrier and current snapshot. The initial stream need
not retain a complete transcript. Process exit is explicit and separate from
CLI turn status.

Cell-grid snapshots/diffs remain an alternative for a native Astation renderer,
not a required first implementation or a description of Paseo's live stream.
If selected, diffs need matching base revisions and resnapshot after any gap.

One PTY has one row/column size. Local dimensions govern while locally
controlled; after an explicit handoff, the remote controller can request a
size change. The other viewer pans or letterboxes that canonical screen.
Arbitrary viewer resizes must not repeatedly resize the process. Resize
advances the screen revision and sends a fresh snapshot.

## Build feasibility and first implementation

Assessment on 2026-10-13: the shared-terminal architecture is buildable using
existing PTY and terminal-rendering components. The current Atem feature is
incomplete; a good end-to-end experience must pass the release gates below.
Paseo supplies a working reference for this terminal architecture, not proof
that Atem's current renderer and transport already satisfy those gates.

### Evidence checked

| Check | Result | What it establishes |
|-------|--------|---------------------|
| Atem `538887b`, `cargo test --offline codex_client::tests -- --test-threads=1` | 7 passed; test build succeeded | Existing Codex PTY adapter can spawn, exchange input/output, resize, report exit, and reject missing executables using stand-in programs |
| Atem `538887b`, `cargo test --offline claude_client::tests -- --test-threads=1` | 7 passed | The same PTY primitives work for the Claude adapter |
| Installed provider version checks | Codex CLI `0.160.0`; Claude Code `2.1.296` | Candidate versions for interactive acceptance testing; login and actual agent tasks were not tested |
| Local Astation checkout, HEAD `5460de4c9a35b0be6d3d54892afc78293c140fcc` | Existing typed `agentInput`, authenticated routing, and JSON-text relay forwarding | Reuse the connection, but extend the message enums/dispatch and UI on both sides |
| Cached `vt100` `0.15.2` source | `state_formatted()` and input-mode serialization exist | A restoration starting point, not proof of complete xterm/modern-keyboard compatibility |
| Pinned Paseo terminal source | PTY host, headless state, ANSI transport, xterm rendering, restore, and size ownership | Established component-level approach for the original CLI experience |

The tests above do not exercise an Astation terminal, provider approvals,
real Codex/Claude task execution, remote latency, or mobile keyboards. Those
remain implementation acceptance tests. The build emits existing warnings.

### Concrete engineering choices

1. **Start with one local viewer and one remote Astation for each session.**
   Maintain an explicit terminal registry independent of the focused panel.
   Keep PTY output draining while the panel is hidden and while Astation is
   disconnected. A remote attach selects an existing terminal ID.
2. **Use versioned JSON messages on the existing connection first.** Encode
   terminal byte chunks as base64 so arbitrary read boundaries survive. The
   inspected relay routes text payloads; direct binary terminal forwarding
   would require additional compatibility work. Preserve the relay envelope's
   `atem_id` and current `connection_id`; never broadcast terminal input.
3. **Use a bundled terminal component in Astation.** The initial macOS target
   can host pinned `xterm.js` assets in a `WKWebView`, with a small typed bridge
   to the native connection/session model. Bundle assets locally, batch output
   writes, and use the terminal component's key/paste handling. Its renderer
   must suppress protocol-query replies that the Atem owner already handles.
   Mobile clients must pass their own keyboard/layout tests before shipping.
4. **Make the host parser a deliberate compatibility boundary.** Retain
   `portable-pty`; use bytes rather than per-read lossy UTF-8 strings. Review
   `vt100` restoration of active/alternate buffers, saved cursor, scrolling
   regions, wrap state, and keyboard modes against the selected renderer.
   Add explicit state tracking or select a more capable emulator where needed.
   `state_formatted()` alone is not an accepted complete restoration contract.
5. **Keep session lifetime separate from view lifetime.** The existing Ctrl+B
   path calls `finalize_*_session()` and releases the session handles. Change
   Back to leave the view while retaining the live session. Expose Stop
   separately. The first owner remains the running Atem process; background
   ownership follows once this loop works end to end.
6. **Bound traffic before adding a new transport.** Use application-level
   credits/acknowledgements so a stalled Astation stops further display sends.
   Keep reading the PTY into the canonical parser, discard superseded viewer
   backlog, and restore that viewer when it catches up. Control input remains
   responsive. Measure the relay path before considering RTC or binary routing.

Implementation order: session ownership and byte-safe input/output; direct
Atem-to-Astation viewing and input; restore and control handoff; relay flow
control and reconnect; then the actual-provider usability matrix. Implement
matching protocol changes in Atem and Astation together. A Rust-only change
cannot deliver the remote terminal UI.

## Required user experience

The primary journey is: launch Codex/Claude in a chosen workspace, work locally,
open that session in Astation, take control, continue the same conversation,
and return locally. The interface shows the host, workspace, provider, and
session identity so the user can verify the target before typing.

| Interaction | Required behavior |
|-------------|-------------------|
| Open remotely | Display the current terminal immediately after restoration; start in View only; show Take control |
| Take control | One explicit action, acknowledged by Atem; no approval from an unattended local screen is required for an already authorized Astation; show the inherited prompt exactly as it is |
| Return locally | A visible local reclaim action immediately revokes remote input; both views show the new owner; retain the CLI's unfinished input |
| Type or paste | Preserve native editing, whitespace, multiline paste, shortcuts, and IME composition; send composed text once; never invent local echo for agent output |
| Approve a tool | Show and operate the original CLI approval UI; do not turn generic text submission into an inferred approval |
| Mobile input | Provide Enter, Escape, Tab, arrows, and Ctrl-C; offer a multiline draft with separate Paste and Submit actions; opening the keyboard does not trigger repeated PTY resizes |
| Copy and scroll | Selection copies normally; reading scrollback stays in place when new output arrives, with a visible Jump to live action |
| Disconnect | Mark the last screen stale, disable live input, preserve an unsent local draft, and show Reconnecting; never replay sent keys or automatically submit the draft |
| Reconnect | Restore the same live session in View only; require renewed control before writing; distinguish a running session from an exited or unavailable owner |
| Back, close, stop | Back or closing a remote view leaves the CLI running; Stop is explicit and warns when it will terminate an active process |

The controller owns terminal dimensions. A viewer can zoom/pan without
resizing the process. Handoff may fit the terminal to the new controller;
debounce subsequent size changes. Merely focusing another window must not
claim keyboard control or resize the shared terminal.

### Experience release gates

These are proposed pass/fail targets, not measured results. Record hardware,
OS, provider/renderer versions, relay route, latency, and test fixtures with
the implementation results. Measure terminal echo/rendering with an echo
fixture separately from model response time.

| Gate | Required evidence before calling the experience ready |
|------|-------------------------------------------------------|
| Same live session | Local input, remote input, and return to local all use the same PID/terminal identity; attaching creates no extra provider process |
| Native interaction | Real Codex and Claude runs pass commands, menus, approval/rejection, interruption, multiline paste, IME, selection/copy, and documented shortcuts |
| Local responsiveness | p95 key-to-echo latency <= 50 ms on the reference host, including while a remote viewer is slow |
| Remote responsiveness | p95 key-to-echo <= 150 ms on LAN with RTT <= 20 ms; <= 350 ms on a relay test path with RTT <= 150 ms, excluding model work |
| Attach/reconnect | Current screen visible within 2 seconds after an authenticated connection is ready for the default snapshot budget on the reference network |
| Output fidelity | Colors, wide/combining characters, cursor, wrap, alternate buffers, scrolling regions, and input modes survive split reads, resize, and reconnect without duplicated output |
| Stress and recovery | A sustained output producer plus a stalled viewer does not cause unbounded queues; stopping/reconnecting the viewer keeps local control usable and restores the current screen |
| Lifetime and targeting | Back does not finalize the session; stale connection/session/control generations cannot write; loss of the owner reports unavailable instead of silently launching a replacement |

The first supported platform/version matrix must be explicit. A working macOS
Astations terminal does not establish Windows/Linux/mobile support, and the
current Linux verification host cannot validate the macOS `WKWebView` UI.

### Product and authorization boundaries

- New cross-agent orchestration is tier 2 and gates through
  `auth::require_pairing`. Installation or `atem login` alone does not unlock it.
- Provider discovery checks executable availability separately from whether
  the provider is authenticated and ready. Do not scrape credential values.
- Remote requests must retain the Astation session/device authorization used
  by the existing control channel. Local IPC must verify the calling user.
- Preserve provider approval and sandbox policies. Return approval requests
  to the controlling client; do not disable permissions to make a bridge work.
- Account/SSO login does not approve a device or release E2EE keys. This design
  adds no SSO handoff, device-trust, or account-key migration.

## Optional structured provider interfaces

These adapters support a separate conversation mode. They are not needed to
run or remotely operate the original Claude/Codex terminal UI. Launching one
does not attach it to an existing PTY conversation automatically.

### Codex: native app-server adapter

For a managed session, start `codex app-server` with stdin/stdout pipes and
read newline-delimited JSON. Keep stderr separate from protocol frames.

Connection lifecycle:

1. Send `initialize`, wait for the response, then send `initialized`.
2. Use `thread/start` to create a conversation, or `thread/resume` for an
   explicitly selected stored conversation. Persist the provider thread ID.
3. Send `turn/start` with the thread ID and user input.
4. Translate `item/agentMessage/delta`, item/tool events, and command output
   into the common event stream.
5. Translate approval requests into addressed requests and send the user's
   decision back with the matching provider request ID.
6. Treat `turn/completed` and its status as the completion signal. Support
   explicit interruption; steering an active turn is a separate capability.

Generate or inspect protocol schemas for the supported installed Codex version
when implementing the adapter. App-server and its WebSocket transport are
currently documented as experimental; retain a supported-version matrix and
test the actual installed CLI.

The installed CLI inspected for this design also exposes a shared local
app-server daemon and `codex app-server proxy`. Connecting to that backend is
an optional later integration, with explicit endpoint and thread selection.
It must not silently start a second controller for an unrelated active thread.

### Claude Code: SDK bridge or validated structured CLI

The reference implementation uses Claude Agent SDK. Atem is Rust, so using
the TypeScript SDK requires a small managed bridge process. The bridge accepts
framed input, keeps an asynchronous input stream open, and emits normalized
events, including permission requests. Configure the SDK to use the resolved
Claude Code executable and appropriate user configuration sources.

Persist the SDK's provider session ID and resume only that selected
conversation. Relay the SDK's tool-permission callback to the runtime; keep the
request pending until it is answered, cancelled, or invalidated by the provider.

A direct structured CLI adapter could remove the bridge dependency, but must
first demonstrate bidirectional prompts, streaming messages, permission
responses, cancellation, and session resumption against supported versions.
Do not substitute a one-shot print invocation for a persistent conversation.

### ACP: a separate protocol adapter

ACP means Agent Client Protocol here. Use its current initialization, session,
prompt, update, cancellation, and permission schemas. Support the provider's
advertised transport; stdio does not require a WebSocket bridge.

Existing Atem ACP helpers are starting material. Their current schemas need a
compatibility audit and real-provider tests. A matching port number or an
`initialize` reply alone does not establish prompt/output compatibility.

### PTY: terminal interaction and display

Retain the existing PTY path for agents whose interactive terminal UI is the
desired experience. Atem must own the PTY master or connect to an explicit
terminal service that owns it.

Terminal output is ANSI bytes plus an emulated screen, not semantic messages.
Keep raw output and screen snapshots separate from structured conversation
events. Inactivity is not proof that a turn completed or a permission was
answered. Raw keys are a PTY capability; native provider adapters answer typed
approval requests instead of synthesizing `y`/`n` keystrokes.

The shared-terminal architecture above is the required PTY implementation.

## Managed sessions versus existing sessions

| Situation | Behavior |
|-----------|----------|
| Agent CLI is installed and authenticated | Atem launches its original interactive CLI in terminal mode; structured mode is an explicit alternative |
| CLI was launched in an Atem-owned PTY | Local Atem and remote Astation operate that same live terminal session |
| Managed session exists in the runtime | A new CLI/TUI client can select it, send input, and subscribe to output |
| External agent exposes a supported app-server/ACP endpoint | Connect through the matching adapter after verifying capabilities and authorization |
| Provider has stored conversation history | Explicitly resume it where supported; this does not attach to its original terminal display |
| An arbitrary Claude/Codex process is running in another terminal | A PID or lockfile is not a supported live input/output interface; do not inject into that terminal |

For Codex, a CLI UI and another client may use the same supported app-server
backend. Model this as explicit backend/thread access, with provider-specific
ownership rules, rather than generic process attachment.

The first delivery shares terminal sessions launched by Atem. External
live-session integration and structured provider modes follow independently.

## Commands and event contract

The following commands are **proposed and not available in this form today**:

```bash
atem agent launch codex --mode terminal --cwd /path/to/repo --name backend
atem agent launch claude-code --mode terminal --cwd /path/to/repo --name reviewer
atem agent attach <agent-id>
atem agent stop <agent-id>
```

The launch command opens the original CLI locally and registers its terminal
for remote Astation attachment. `attach` views an existing terminal rather
than starting another process. Detachment independent of the local viewer
requires the later background owner. An explicit `--mode structured` can be
added with the optional provider adapters. The following operations describe
that structured mode, not raw terminal input:

```bash
atem agent send <agent-id> "Review the current diff"
atem agent send <agent-id> --session <session-id> "Also check the tests"
atem agent events <agent-id> --follow --after <sequence>
atem agent interrupt <agent-id> --turn <turn-id>
atem agent approvals <agent-id>
atem agent approve <request-id>
atem agent reject <request-id>
```

`atem agent attach` subscribes to the selected agent's mode. It is different from the
existing `atem serv attach`, which opens a ConvoAI daemon's browser UI. Final
CLI spelling is subject to the command-contract review.

Persist these identifiers and relationships:

- Atem agent ID: stable runtime identity, provider, workspace, mode, and status.
- Atem session ID: selected conversation mapped to its provider session/thread.
- Turn ID and client request ID: input correlation and retry deduplication.
- Runtime/process generation: prevents stale input reaching a replacement
  process or an unrelated process that reused a PID.
- Terminal/controller identity: PTY session, current controller lease, terminal
  dimensions, stream generation/output position, and snapshot revision;
  shared by local and remote viewers.
- Event sequence: durable replay position scoped to a session.
- Approval ID: pending provider request, intended session/turn, and resolution.

Normalized events include status changes, turn start, text deltas, tool start,
tool output/result, approval request/resolution, turn completion/failure,
provider disconnect, and replay gaps. Include agent/session/turn correlation
where applicable. Those semantic events belong to structured mode. Terminal
mode has its required screen stream plus explicit process/control lifecycle.

In structured mode, sending to a busy session queues a follow-up by default.
Steering or interrupting an active turn requires an explicit supported operation. Never create a fresh
conversation silently because a session ID was missing or stale.

Multiple clients may observe a session. Resolve an approval once, atomically;
notify other viewers of that resolution. Only authorized controllers can submit
input or answer requests, and disconnecting one viewer does not cancel a turn.

## Durability, recovery, and backpressure

Terminal reconnection restores the current screen from a snapshot while the
owner remains alive. A background owner later allows local viewer detachment.
A runtime crash loses its PTY and live process control; stored provider history
may permit explicit conversation resume, but cannot restore the original live
terminal process. Report ended or unavailable sessions honestly.

Input request IDs can deduplicate retries within a live owner generation.
Distinguish accepted-for-write from written-to-PTY acknowledgements. Neither
means the agent accepted a semantic prompt or completed a task. If failure
makes a write ambiguous, report that state instead of automatically replaying
keystrokes, approvals, or submitted lines after a reconnect or restart.

The following durable queue and semantic replay requirements apply to the
optional structured runtime, not to automatic replay of terminal input.

Use a dedicated private runtime store, proposed as `agents.db`, rather than
mixing conversation output with Atem Memory's shared `knowledge.db`.

Before acknowledging an accepted prompt, transactionally record its request
ID, target, and queued operation. A bounded acknowledgement timeout distinguishes
accepted work from an operation the runtime refused or could not persist.
Retries with the same request ID return the recorded outcome rather than
enqueueing the prompt twice.

There is no blanket exactly-once guarantee at a provider boundary. If a process
or connection dies after a prompt may have reached the provider, reconcile
provider history and turn status where possible. Mark ambiguous submissions
explicitly; do not blindly resubmit and create duplicate work.

Persist session bindings and replayable normalized output before publishing
events. Reconnecting clients resume from an event sequence. Resume stored
provider conversations after a runtime restart where supported; report an
interrupted turn or unavailable live state honestly.

Bound both provider and client queues. Slow clients recover through replay;
loss of retained history emits a gap with a snapshot/history recovery path.
Coalesce terminal snapshots independently. Approval and control messages must
not be blocked behind terminal screen traffic.

Session output can contain sensitive workspace content. Use owner-only files,
configurable retention, and explicit export. Do not automatically harvest agent
transcripts into shared memory or forward them to unrelated Astations. Required
remote protection must follow the existing device-trust and encryption design;
an SSO login is not a substitute.

## Integration with current Atem and Astation

- Move provider ownership behind the runtime instead of duplicating it in
  each CLI invocation and the TUI's `App` state.
- Extend the agent registry/event abstraction with durable session and turn
  identity, approvals, recovery, and provider capability reporting.
- Map existing `AgentPrompt`/`AgentEvent` messages into the runtime, negotiating
  new fields and event types with Astation. Honor the supplied session ID.
- Keep legacy `AgentInput` for the focused PTY path until explicit addressing
  is implemented. Structured-provider requests must use typed operations.
- Preserve the existing voice transcription path. Its final text can become
  input to the selected terminal, or an addressed structured prompt, without
  adding another ASR pipeline. The current Claude default needs routing changes.
- Add shared terminal display on both Astation desktop and mobile; see
  [remote-agent-control.md](remote-agent-control.md).

This document does not change Astation, the relay, existing wire messages, or
the current CLI. Cross-repository protocol changes require implementation and
compatibility validation on both sides.

## Delivery phases

| Phase | Deliverable |
|-------|-------------|
| 1: shared original CLI | Existing Atem-owned PTY, normal local interaction, addressed remote input, controller handoff, full screen snapshots, bounded output, and explicit size policy on Astation desktop/mobile |
| 2: persistent terminal ownership | Background PTY owner, private local attach/detach, stable session identities, reconnect snapshots, scrollback limits, and explicit stop |
| Optional structured mode | Codex app-server, Claude bridge, and verified ACP adapters; semantic messages, approvals, turn completion, durable queues/replay |
| Optional external backends | Connect to verified existing provider endpoints with explicit backend/thread ownership |

## Acceptance checks

1. Launch the original Claude and Codex CLIs inside Atem with the selected
   workspace and existing provider configuration; validate their normal UI.
2. Use commands, menus, arrows, shortcuts, paste, and native approve/reject
   interactions locally, retaining the provider sandbox/approval settings.
3. Attach Astation remotely and see the same live screen and conversation;
   no second agent process or conversation is created.
4. Hand control to Astation, enter a task remotely, then reclaim local control
   and continue in that same session without mixed input or stale writes.
5. Launch both providers and route input, voice text, and display by explicit
   terminal identity even when another panel has local focus.
6. Disconnect/reconnect Astation and recover the current screen without
   submitting input again or restarting the agent.
7. Exercise resize, cursor queries, alternate screens, split UTF-8 reads, wide
   characters, and controller size changes; viewers remain consistent.
8. Lose stream output and recover with a snapshot; do not duplicate output
   already included in a restore. A slow remote subscriber
   cannot grow queues indefinitely or block local input/control messages.
9. Reject unpaired/unauthorized remote control and stale session, process, or
   controller generations. Surface ambiguous terminal writes honestly.
10. Report process exit explicitly. Closing a remote viewer keeps the agent
    alive; local viewer detachment survives only after the background phase.
11. Optional structured mode separately tests semantic completion, addressed
    approvals, idempotent submission, provider resume, and durable event replay.
12. Validate both CLIs on supported versions and record the terminal fidelity
    matrix. Unsupported arbitrary-process attachment returns a clear error.

## Decisions before implementation

- ANSI stream/restore schema and Astation renderer; input/paste encoding
  and the documented local escape shortcut.
- Controller handoff, local reclaim UX, and terminal size/scrollback limits.
- Minimum Claude/Codex versions and terminal capabilities to validate.
- Background-owner packaging and precise stop/detach lifetime behavior.
- Optional Claude bridge packaging, ACP compatibility, semantic transcript
  retention, and external-backend ownership.
- Final CLI names and backward compatibility for existing ACP commands.

## Sources

Reviewed 2026-10-13. Paseo reference revision:
`1839de5b1d3ea3f668ae6d031f79ebb0590258cc`. Provider behavior is version-dependent.

- [Paseo provider architecture](https://paseo.sh/docs/providers).
- [Paseo Codex integration](https://paseo.sh/docs/codex).
- [Paseo original Codex CLI in its terminal](https://paseo.sh/docs/codex#use-codex-in-the-paseo-terminal).
- [Paseo original Claude Code CLI in its terminal](https://paseo.sh/docs/claude-code#use-claude-code-in-the-paseo-terminal).
- [Paseo PTY host and headless terminal](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/server/src/terminal/terminal.ts).
- [Paseo terminal subscription, input, output, and restoration](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/server/src/terminal/terminal-session-controller.ts).
- [Paseo terminal binary framing](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/protocol/src/binary-frames/terminal.ts).
- [Paseo snapshot/ANSI restoration and catch-up thresholds](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/server/src/terminal/terminal-restore.ts).
- [Paseo terminal size ownership](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/server/src/terminal/terminal-size-ownership.ts).
- [Paseo app terminal subscription](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/app/src/terminal/runtime/terminal-stream-controller.ts).
- [Paseo xterm renderer and protocol-query suppression](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/app/src/terminal/runtime/terminal-emulator-runtime.ts).
- [Paseo CLI: run, send, attach, and permissions](https://paseo.sh/docs/cli).
- [Paseo Claude SDK bridge](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/server/src/server/agent/providers/claude/query.ts).
- [Paseo Claude session adapter](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/server/src/server/agent/providers/claude/agent.ts).
- [Paseo Codex app-server adapter](https://github.com/getpaseo/paseo/blob/1839de5b1d3ea3f668ae6d031f79ebb0590258cc/packages/server/src/server/agent/providers/codex-app-server-agent.ts).
- [Official OpenAI Codex app-server documentation](https://developers.openai.com/codex/app-server/).
- [Agent Client Protocol](https://agentclientprotocol.com/).

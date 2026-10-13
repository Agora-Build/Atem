# Remote Agent Control (Astation → atem → claude/codex)

Status: legacy focused-PTY input plus initial terminal-v1 host implementation; Astation terminal UI pending
Owner: Brent G
Updated: 2026-10-13
Feasibility review: Atem `538887b`; local Astation checkout HEAD `5460de4`.

Implementation update (2026-10-13): [Shared terminal: first Atem build](terminal-v1-implementation.md)
is the authoritative contract for the new worktree implementation. It sends
canonical visible-screen ANSI snapshots/diffs, adds process/stream/lease IDs,
bounded credit, local launch/hide/reclaim/stop and a matching Unicode profile.
The illustrative raw-stream protocol below remains design context. Remote
scrollback and the Astation UI have not shipped.

Related proposal (2026-10-13): [Local Coding Agent Runtime](local-agent-runtime.md)
prioritizes launching the original Claude/Codex CLI inside Atem, operating it
normally locally, and viewing/controlling that same session from Astation.
This document specifies the existing input path and the proposed shared
terminal protocol. The live display uses terminal text/control bytes, following
Paseo's workspace-terminal path. Structured conversations are optional.

## Goal

Let a user drive a coding agent (Claude Code / Codex) running under atem on one
machine from a separate control surface — **Astation** (Mac/PC today, mobile
later) — using **voice, text, or control keys**. The agent's own TUI remains the
source of truth for output.

The clarified requirement is one live process and PTY with two control surfaces:

- **Local Atem** displays the original CLI UI and forwards normal keyboard
  input, paste, shortcuts, and native approval-menu interactions.
- **Remote Astation**, on desktop or mobile, displays that same terminal and
  can take control to send input. A remote desktop user also needs the screen
  when the host terminal is out of reach.

The existing v1 provides input only. Completing this feature requires the
down lane on remote desktop and mobile, explicit session addressing, controller
handoff, and a shared resize policy. Neither a separate SDK conversation nor
an input-only remote control fulfills the complete requirement.

## Existing v1 scope

- No screen/TUI mirroring to the desktop client (you watch atem's terminal).
- No new transport: v1 rides the existing atem↔Astation channel.
- No attaching to an agent atem didn't launch (atem owns the PTY).

These limits describe v1, not the completed shared-terminal feature. The new
scope adds screen sharing over the existing authenticated connection first;
transport upgrades are evaluated against measured load.

## Architecture

```
Layer 3  Control surface + UI      Astation (Mac/PC now, mobile later)
         input affordances (text / voice / keys); shared TUI render
              ▲   (up lane: input)        │ (down lane: screen, desktop/mobile)
              │                           ▼
Layer 2  Transport                 direct (LAN/VPN)  >  relay   [> RTC data channel — see §Transport evolution]
         carries addressed messages across NAT; control = reliable, low-volume
              ▲
Layer 1  atem (agent host)         owns the agent PTY (claude_client / codex_client + vt100)
         arbitrates one input controller; streams ANSI text and restore snapshots;
         addressed PTY sessions, canonical screen/size; relay/direct client
              ▲
Layer 0  Agent process             claude / codex (interactive TUI)
```

Key principle: **atem and Astation speak a transport-agnostic, addressed,
laned message protocol.** The relay is one transport implementation and is
expected to evolve (see §Transport evolution); nothing in atem/Astation is
coupled to today's relay.

### Addressing

Full addressing targets `(atem_id, agent_id)`. The implemented v1 path routes
to the Atem host and its focused PTY; explicit agent selection is still future
work:

- `atem_id` — which atem host. The relay already routes by `atem_id` (it wraps
  Atem-to-Astation frames as `{atem_id, connection_id, payload}` and requires
  both host and current connection ID for targeted Astation-to-Atem messages;
  see Astation `relay-server/src/relay.rs`).
- `agent_id` — which agent on that host. The optional payload field is present,
  but v1 ignores it. Shared-terminal requests must address a registered PTY
  session and its process generation, independent of the locally focused panel.

A terminal session ID identifies the live PTY. It is distinct from an optional
provider conversation/thread ID. Reject stale or unknown IDs rather than
falling back to the focused agent. Remote control also carries the current
controller lease generation so revoked clients cannot continue typing.

### Lanes & QoS

| Lane | Direction | Volume | QoS | Phase |
|------|-----------|--------|-----|-------|
| `control` | Astation to Atem, with acknowledgements back | low | ordered, bounded; reject stale input and report write outcome | Focused text/keys exist; addressed control is proposed |
| `status` | Atem to Astation | low | current process/controller state; explicit lifecycle transitions | Proposed for terminal sessions |
| `terminal` | Atem to Astation | higher | ordered ANSI bytes plus restore snapshots; reset/restore after a gap | Required shared display on desktop/mobile |

The implemented v1 uses only the input path. The proposed shared display
requires bounded queues and recovery. Screen snapshots may replace older
state; ANSI output cannot be dropped and then parsed as if complete.

## v1 — Up lane (Astation desktop → agent)

### What it does

Astation desktop is a **remote control** for the agent atem is running. The
user sends:

1. **Voice — already exists, reuse it.** `VoiceCodingManager` (Astation) does
   PTT (Ctrl+V) and hands-free: mic → a **ConvoAI agent does ASR** → the relay
   accumulates the transcript → Astation sends
   `voiceRequest(sessionId, accumulatedText, relayUrl)` to the target atem
   (with `voiceCommand(text, isFinal)` for streaming interim text). atem
   receives via `pending_voice_request`. v1 **reuses this path**; the result is
   text delivered to the agent.
2. **Text — implemented in Atem.** Type an instruction, send. atem writes it
   to the focused agent's stdin (line + Enter) through `agentInput{kind:text}`.
   (Optional alternative to the ConvoAI mic path: OS/native desktop dictation
   also produces text and rides the same text message — but ConvoAI voice
   already works, so this is just a convenience, not required.)
3. **Control keys — implemented in Atem.** A small set for TUI interaction
   that needs real keystrokes: `Enter`, `Esc`, `Ctrl-C` (interrupt), `↑`/`↓`, `y`/`n`
   (tool approve/reject). Sent as key events, written to the PTY raw.

Output: the user watches atem's terminal directly. No down lane.

### Current implementation and remaining scope (v1)

| Capability | Status |
|---|---|
| Voice → transcript → atem (`voiceRequest`/`voiceCommand`, ConvoAI ASR, PTT + hands-free) | **exists** in `VoiceCodingManager` + atem `pending_voice_request` — reuse |
| Per-atem targeting (`atemId` + channel; relay routes by `atem_id`) | **exists** |
| Text instruction → agent stdin | **implemented** in Atem (`agentInput{kind:text}`), focused PTY only |
| Control keys → agent PTY | **implemented** in Atem (`agentInput{kind:key}`), focused PTY only |
| `agent_id` (multiple agents per atem) | Field exists, but `handle_agent_input` ignores it; explicit multi-agent routing remains future work |

### Message protocol

Today's `AstationMessage` (both sides) carries: `voiceRequest` /
`voiceCommand` / `voiceResponse` (the voice path), `userCommand` /
`commandResponse` (generic command), `markTask*`, `agentListRequest/Response`,
etc. It also includes `agentInput` for text-to-agent-stdin and key events.
The payload carries an optional agent ID, but the v1 handler uses the focused
PTY rather than that selector. Atem's `agentPrompt`/`agentEvent` ACP path is a
separate integration; it does not make v1 PTY input addressable.

v1 uses `agentInput` for text + keys.

**Addressing is two-level and `atem_id` is the *envelope*, not the payload.**
The relay (and Astation's `sendHandler`) already wrap Astation→atem traffic as
`{"atem_id": "<host>", "connection_id": "<current connection>", "payload": <message>}`.
The inspected relay rejects targeted messages lacking `connection_id`; renew
that ID after reconnect rather than reusing an old one. So the
`agentInput` payload must **not** repeat `atem_id`; it carries only the agent
selector + the input:

```
relay envelope (added automatically by Astation/relay):
  { "atem_id": "<host>", "connection_id": "<current connection>", "payload": <agentInput> }

agentInput payload (AstationMessage, tagged type/data):
  { "type": "agentInput",
    "data": {
      "agentId": "<agent on that atem; optional in v1 — omit/null = focused/only agent>",
      "kind": "text" | "key",
      "text": "refactor the auth module",        // kind=text → stdin + Enter
      "key":  "enter|esc|ctrl-c|up|down|y|n"      // kind=key → raw PTY byte(s)
  } }
```

(Authoritative wire contract — kept in sync with the Astation-side spec
`Astation/docs/specs/2026-05-28-remote-agent-control-design.md`.)

Voice stays on the **existing** `voiceRequest` / `voiceCommand` path (ConvoAI
ASR → accumulated text → atem) — it already delivers text to the agent, so v1
does not reroute it through `agentInput`. (If we later want one unified input
path, voice transcripts could fold into `agentInput{kind:text}`, but that's not
required for v1.)

Existing generic/voice feedback uses `commandResponse`, `voiceResponse`, and
`statusUpdate`; it does not establish a terminal write acknowledgement.

`handle_agent_input` currently sets local status after enqueueing input; it
does not provide a correlated remote accepted/written acknowledgement. The
acknowledgement contract below is proposed.

### Injection semantics (atem side)

- atem owns the agent PTY (`claude_client.rs` / `codex_client.rs`). `kind:text`
  → trim, skip-if-empty, then write `text` + the submit sequence `\n\r` to the
  PTY master (matches `send_claude_prompt`, which the Claude/Codex TUIs need to
  reliably accept a line). `kind:key` → write the raw byte(s) (`\r`, `\x1b`,
  `\x03`, arrow CSI, `y`/`n`) to the PTY master. Implemented as
  `handle_agent_input` + `agent_key_to_bytes` in `app.rs`.
- **Busy handling**: input is written to the live TUI's stdin. The CLI decides
  how it handles input while busy or showing a menu; Atem provides no semantic
  follow-up queue or approval-state check. `Ctrl-C` is forwarded to the CLI.
- **Multiple agents**: v1 ignores `agent_id`. It writes to Codex when Codex is
  the active chat and its session is live; otherwise it uses the Claude sender.
  Addressed routing must be implemented before supporting multiple selected
  targets. The [local runtime proposal](local-agent-runtime.md) also specifies
  explicit conversation and turn identity for structured providers.

### v1 transport scope

- Control messages are low-volume and reuse the existing connection. Low
  volume alone does not establish a bounded memory or delivery guarantee.
- No rendering, no resize, no cell-grid streaming.
- Reuses the existing channel, the existing `atem_id` routing, and the existing
  voice scaffolding.

## Proposed shared-terminal control

### Launch and session lifetime

Atem starts the installed CLI in ordinary interactive mode and owns the PTY.
Local and remote access uses that same process and conversation. Attaching
Astations or reconnecting a viewer never starts a second agent automatically.

The first implementation can retain the existing TUI owner, which must keep
reading output even while another panel is focused. Keep that Atem process
running. A later background PTY owner allows local detach/reattach. Closing a
remote viewer does not stop the CLI; explicit stop remains a separate action.
Owner loss ends live PTY control, even if provider history can later be resumed.

The current Ctrl+B handler calls `finalize_*_session()` and releases the
session handles. It must become Back/leave-view behavior for this feature;
finalization belongs to explicit Stop or process exit. Expose a configurable
Atem escape with a send-literal action so the original CLI can still receive
that key. Ctrl-C continues to reach the original CLI.

### Controller handoff and input

Multiple authorized clients may view the screen. Use one input controller at a
time, initially local. Astation requests control and shows whether it is a
viewer or controller. Local reclaim revokes the remote lease and rejects
queued writes from that old lease; the UI must explain a takeover or blocked
input instead of silently discarding keystrokes.

For an authenticated, authorized Astation, Take control needs one explicit
remote action and an acknowledgement from Atem; it must work while the host
is unattended. The local user can reclaim immediately. Viewing, window focus,
or device rotation alone never claims keyboard control. On disconnect revoke
the lease; reconnect restores View only and requires a fresh claim.

Route local keys, remote keys, and paste through one ordered writer. A remote
operation carries session ID, process generation, controller lease generation,
and request ID. Retry deduplication is scoped to the live owner generation.
Exclusive control prevents concurrent typing, but switching controllers keeps
any unfinished CLI input. Show that input and let the new controller explicitly
finish or cancel it; handoff must not automatically clear or submit a line.

Separate raw keys/paste from "type text and submit". Preserve whitespace,
multiline input, and the terminal's paste mode for raw paste. Expand beyond the
v1 key set for ordinary CLI editing/navigation, with capability/version
negotiation. Only the owner answers terminal queries, avoiding duplicate
cursor-position replies from local and remote renderers.

Use the original approval UI for tool permissions. Do not infer that a native
approval is pending by scraping the screen, or treat terminal inactivity as
turn completion. Voice transcript delivery must target the selected terminal;
the existing voice path's Claude default does not yet provide that routing.

An acknowledgement distinguishes accepted-for-write from written-to-PTY. It
does not confirm that a semantic prompt was accepted. After an ambiguous write,
show the outcome as unknown and do not automatically replay input or approvals.

### Text-based display and reconnect

Follow Paseo's terminal path: transmit ANSI terminal output, and render it in
Astations using a compatible terminal component. This carries text, color,
cursor movement, and terminal modes. Binary framing packages terminal bytes;
it does not mean captured video or screenshots.

Maintain a canonical terminal emulator at the owner for restoration:

- On attach: send a snapshot/ANSI restore containing session/process
  generation, output position, dimensions, screen/cursor, bounded scrollback,
  and relevant terminal modes.
- Follow with ordered ANSI output newer than the snapshot boundary. Buffer
  output generated while the snapshot is captured and avoid replaying bytes
  already included in that snapshot.
- Bound each subscriber's queue and retained scrollback. When a subscriber
  falls behind, replace its backlog with an ordered restore barrier and current
  snapshot, then restart streaming. Do not drop arbitrary output mid-stream.
- Keep process exit, control handoff, and write outcomes responsive and
  separate from terminal display traffic.
- Reconnect with a fresh snapshot of the existing process. Do not replay
  terminal input, launch another CLI, or claim restored turn semantics.

Proposed Atem envelopes include session/process/stream generation and output
sequence or offset. A gap requires a reset/restore before later output is
parsed. A cell-grid renderer can instead use snapshots/diffs with base
revisions, but this is an alternative to the Paseo-style ANSI live stream.

Consume PTY output as bytes. Validate Unicode characters split across reads,
wide/combining characters, colors, cursor behavior, alternate screens, paste,
and terminal-query handling on both providers. Fidelity means the native CLI
remains usable locally and remotely, not just that plain text looks similar.

### What the inspected Paseo terminal code does

Reference revision: `1839de5b1d3ea3f668ae6d031f79ebb0590258cc`.

1. `terminal.ts` uses `node-pty` for a workspace shell or configured command.
   Running `codex` inside that shell uses the original Codex terminal UI.
2. The daemon feeds PTY output into `@xterm/headless`, maintains terminal
   state/revisions, and answers terminal queries next to the PTY.
3. A terminal subscription gets a stream slot. Binary frames identify
   `Output`, `Input`, `Resize`, `Snapshot`, or `Restore`; live output payloads
   are UTF-8 ANSI terminal text. Snapshots hold cell state or ANSI restoration.
4. The app routes frames to the selected terminal; its browser `@xterm/xterm`
   renderer draws the UI and suppresses duplicate terminal-query replies.
5. Input frames write to that selected PTY. Size `claim`/`update` limits resize
   updates to the client that currently owns terminal dimensions.
6. Coalesced output and snapshot restoration help catch up a slow viewer;
   revisions prevent output already captured by a snapshot being replayed twice.

Reuse the architecture in Rust with Atem's existing `portable-pty` and terminal
parser. The proposed exclusive keyboard-controller policy is an Atem choice;
Paseo's inspected size ownership is not an exclusive input lease. Source links
and the focused comparison are in
[local-agent-runtime.md](local-agent-runtime.md#focused-reference-use-codex-in-the-paseo-terminal).

### One terminal size

One PTY has one canonical row/column size. The current controller determines
its size: local dimensions initially, remote dimensions after explicit control
handoff. Other viewers pan or letterbox the same screen. Viewer-only window
changes must not repeatedly resize the CLI. A controller resize advances the
screen revision and broadcasts a fresh snapshot; mobile rotation follows the
same policy.

### Proposed wire contract

Define versioned operations for terminal attach/detach, control request/reclaim,
input/paste, resize, ANSI output/restore, write acknowledgements, and process exit.
The addressing and screen fields above are proposed, not current
`AstationMessage` variants. Negotiate capabilities on both ends before using
them. Existing focused-PTY `agentInput` remains a legacy input path until
explicit addressed routing is implemented.

First implement a versioned JSON-text payload on the current transport; base64
encodes PTY bytes without depending on UTF-8 read boundaries. This requires
new typed message handling in both Atem and Astation, but avoids assuming the
relay already forwards Paseo's binary frames. Negotiate `terminal-v1` before
subscribing; old clients keep the existing focused-input behavior.

Proposed operation fields (names subject to a shared Rust/Swift schema review):

| Operation | Required identity and behavior |
|-----------|--------------------------------|
| Subscribe | `terminalId`, process `generation`; return dimensions, lifecycle, and a new `streamId` |
| Restore | New stream generation, snapshot output boundary, dimensions/modes, and bounded payload chunks; commit the restore before live output |
| Output | `terminalId`, process generation, `streamId`, monotonic byte `offset`, `bytesBase64`; apply only to the matching restored stream |
| Control | Claim/release/reclaim; return a new `leaseId`; validate the lease again at the writer before applying queued input |
| Input | Terminal/process identity, lease, `requestId`, byte payload, and raw/paste semantics; one ordered writer |
| Write result | Correlate the request with rejected, accepted-for-write, written-to-PTY, or unknown; never infer a completed agent turn |
| Resize | Controller lease plus rows/columns; apply to host parser and PTY together, then restore viewers at the new dimensions |
| Credit | Acknowledge bounded display consumption for the current stream; stale credit cannot reopen an old stream |
| Exit/unavailable | Explicit process outcome; detach viewers and disable input without launching a replacement |

Start with at most 16 KiB of decoded output per frame, 128 KiB of unacknowledged
live output per viewer, and a separately bounded restore assembly of at most
1 MiB. These are implementation starting budgets to benchmark, not measured
limits or release claims. Restore chunks consume transport credit; advancing
their credit means they entered the bounded restore buffer, while a separate
restore commit enables live rendering/input. Limit snapshot scrollback before
serialization rather than truncating arbitrary ANSI bytes.

When a viewer stops acknowledging, stop sending to it. Continue draining the
PTY into canonical state; discard only its superseded pending display backlog
and require a new restore. Keep pending writes, restore buffers, stream count,
and retained screen/scrollback bounded as well. Credits bound this feature's
traffic; they do not fix unrelated relay queues.

The tier-2 feature gates through `auth::require_pairing` and the existing
authenticated Astation channel. Provider login is separate. Account login
does not approve a device or replace the established device/E2EE boundaries.

## Transport evolution (the relay is expected to change)

The inspected relay (`Astation/relay-server`, local HEAD `5460de4`) routes
JSON text and validates targeted `connection_id` values. Binary terminal
forwarding is not part of the inspected routing path. Older statements about
a single unbounded room queue are not a sufficient description of the current
multi-replica relay; inspect and load-test the deployed version.
Shared-terminal traffic needs bounded end-to-end flow control:

- text/JSON screen snapshots pay serialization and per-frame parsing costs;
  only raw binary output encoded in JSON necessarily adds base64 overhead
- a slow consumer must stop receiving further display frames when credit runs out
- large output must be chunked so display traffic does not monopolize the shared connection

Start by evaluating bounded ANSI output/restore over the existing authenticated
connection. If its queues cannot be bounded, add application-level credit or
acknowledgements to limit in-flight display data. Protocol lanes alone do not
make independent transport queues. Further options are:

- **(a) Upgrade the relay**: support byte-safe frames and bounded display/control
  queues. Obsolete display backlog can be replaced only through ordered
  restoration; live ANSI output remains ordered and complete between restores.
- **(b) Evaluate a separate RTC data channel** if measured display load warrants
  it. Control/signaling can stay on the WS connection, but the terminal channel
  still needs validated ordering, buffering, restore, and trust properties.

Cap update size/rate, but also bound queued and in-flight data. A tick-rate cap
alone cannot bound memory when a subscriber stalls indefinitely. Drop obsolete
screen state only with snapshot recovery; never silently lose arbitrary ANSI
bytes or dependent diffs. Validate transport ordering/reliability if an RTC
option is used, and retain explicit generations and revision recovery.

## Phasing

| Phase | Deliverable |
|-------|-------------|
| **v1 (implemented in Atem)** | Astation **Mac** up-lane: `agentInput` (text + keys) → atem → focused agent stdin. Voice **reuses** the existing `voiceRequest`/ConvoAI path. Watch output in atem's terminal. Explicit `agent_id` routing remains future work. |
| **Next: shared terminal** | Astation desktop/mobile ANSI terminal display and snapshot restoration; addressed input, controller handoff, native CLI key/paste fidelity, one size policy, bounded queues, and explicit process lifecycle |
| Persistent owner | Background PTY ownership and local attach/detach without ending the process |
| Optional structured mode | Provider APIs for semantic prompts, tool events, approvals, and turn status; independent of native terminal control |

## Acceptance checks

1. Start each original CLI inside Atem and use its normal commands, shortcuts,
   menus, paste, and native approvals locally.
2. Attach remotely on desktop and mobile; both show the same process/screen.
3. Hand control to Astation, send input, reclaim locally, and continue the
   same conversation without mixed lines or writes from revoked controllers.
4. Route screen/input/voice by terminal ID while another local panel is focused.
5. Reconnect, interrupt output, and simulate a slow viewer; snapshots restore
   the screen without duplicated output, memory stays bounded, and input is
   not replayed.
6. Test resizing, terminal modes, Unicode, cursor-query responses, exit, stale
   generations, and authorization against the supported CLI/version matrix.

The concrete user journey, build evidence, platform scope, and latency/fidelity
release gates are in
[Required user experience](local-agent-runtime.md#required-user-experience).
Passing current PTY unit tests is necessary foundation evidence, not proof of
the remote terminal experience. Validate real Codex/Claude tasks and the actual
Astations renderer on both direct and relay connections before release.

## Open questions

1. **Terminal schema and renderer** -- define the capabilities, ANSI/restore
   encoding, paste/key handling, and local escape shortcut. Structured
   providers remain a separate optional mode.
2. **Voice vs `agentInput` unification** — keep voice on its existing
   `voiceRequest` path (v1), or fold transcripts into `agentInput{kind:text}`
   for one input path? v1 keeps them separate.
3. **Controller UX** -- define explicit handoff, local reclaim, blocked-input
   feedback, and controller disconnect behavior. The v1 key set needs expansion.
4. **agent_id lifecycle** — the registry already has IDs, but v1 input ignores
   its optional selector. The runtime proposal persists stable agent/session
   IDs, with human-friendly labels as aliases. Define migration and explicit
   routing before enabling multiple targets.
5. **Down-lane transport** -- measure the existing authenticated connection
   with bounded queues/credit before selecting a relay upgrade or RTC path.
6. **Multiple Astations** -- the inspected room directory has one owner
   connection. The first delivery uses one remote Astation plus local Atem.
   Concurrent independent Astation clients require an explicit routing/trust
   design; the legacy `astation_tx` description no longer names current code.

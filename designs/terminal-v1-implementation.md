# Shared terminal: first Atem build

Updated: 2026-10-13. Status: implemented in Atem; not released.
The Astation terminal UI and its acceptance tests remain to be implemented by
the Astation owner. This document is the integration contract for the first
host build. It takes precedence over illustrative protocol names in
[Local Agent Runtime](local-agent-runtime.md) and
[Remote Agent Control](remote-agent-control.md).

## What can be used now

```sh
cargo build --offline
./target/debug/atem agent launch codex
./target/debug/atem agent launch codex --profile oss
./target/debug/atem agent launch claude
./target/debug/atem agent launch claude --model sonnet
```

`claude-code` is also accepted. The existing `CODEX_CLI_BIN`, `CODEX_CLI_ARGS`,
`CLAUDE_CLI_BIN` and `CLAUDE_CLI_ARGS` overrides still work. Arguments in these
environment variables retain the existing whitespace-separated behavior.
Arguments after the agent type are forwarded to that CLI as separate argument
values, preserving shell-quoted spaces and newlines. An explicit `--` separator
is also accepted (`atem agent launch codex -- --profile oss`). Environment
arguments are prepended to the forwarded command-line arguments. For agent
help, use `atem agent launch codex -- --help`; launch-command help remains
available with `atem agent launch --help`.
The original interactive executable inherits the working directory and account
configuration. There is no SDK conversation, app-server replacement, video
stream, or additional network listener.

- Agent views use the entire terminal except one status row. Connection details
  and warnings appear in a details overlay; background diagnostics never write
  directly over Ratatui's screen. The PTY and emulator start at the same viewport
  dimensions, and hardware cursor placement follows the agent's cursor.
- Reverse-video highlights preserve both explicit and terminal-default colors.
  Codex's own startup animation and status spinner remain visible while active;
  the renderer removes cells when the CLI clears them.
- The default Atem prefix is **Ctrl+]**, then `h` (hide), `g` (take local
  control), `x` (stop), `r` (redraw), `[` (local history), `c` (copy), or `?`
  (help and notices). Reopening the same menu entry resumes its PTY. Taking
  local control invalidates queued remote input. Press the prefix twice to
  send it literally to the agent; unknown prefixed keys are forwarded.
- `ATEM_TERMINAL_PREFIX=Ctrl-a` changes the prefix. Choose a prefix that does
  not conflict with your multiplexer. Ctrl+B, Ctrl+G and Ctrl+C normally go to
  the CLI; tmux still consumes its own prefix before input reaches Atem.
- Local history retains up to 2,000 rows, where the CLI's normal screen creates
  scrollback. In history mode, arrows move the cursor, Space marks a selection,
  Enter copies the selection (or viewport), PgUp/PgDn scroll, and Esc returns
  live. A frozen local view never changes canonical output or remote input.
  Resize closes the local history/selection view. Alternate-screen applications
  may provide their own history; Atem does not reconstruct hidden conversations.
- Copy uses `tmux load-buffer -w -` inside tmux and OSC 52 otherwise. This
  requests the system clipboard; terminal support and nested multiplexer policy
  still determine whether it reaches that clipboard. Mouse capture stays off,
  preserving the outer terminal's selection. Multiline paste uses the agent's
  bracketed-paste mode and is submitted as one input operation (16 KiB maximum).
- Local agent launch works without Astation. Remote access uses the existing
  authenticated Astation connection and its pairing rules.
- One Claude and one Codex session can live in the TUI simultaneously. Each
  can have one remote viewer. Quitting Atem ends its owned sessions; detached
  daemon ownership is a later phase.
- Paste uses bracketed mode when requested by the CLI. Arrow/function-key
  modifiers and application cursor mode are encoded as xterm input.

## Frontend and runtime direction

The compact terminal frontend remains the first supported interface for tmux,
other multiplexers and SSH. A GPUI desktop frontend is deferred until a desktop
product is needed; it is not a dependency or part of this implementation.

Both future frontends should attach to one Atem-owned session runtime. That
runtime would own the original PTY process, session/generation identity,
canonical terminal state, control leases and the Astation connection. Frontends
would render state and request launch, attach, input, resize and stop operations.
Opening another frontend must not silently launch another Codex/Claude process
or replace its conversation and unfinished input.

Today `App` still owns sessions and quitting Atem stops them. A future extraction
into `AgentRuntime`, followed by a background service and private local attach
protocol if sessions must outlive frontend windows, is separate work. GPUI would
need a terminal component as well as the graphical framework. Existing Astation
pairing and remote control authorization remain the remote trust boundary.

Regression coverage now includes actual Crossterm ANSI repainting (stale cells,
wide characters, duplicate helper rows, native cursor and long notices), local
history isolation, prefix aliases, and a full-binary PTY test for initial size,
ordinary control keys, multiline paste, resize and explicit clipboard requests.
These checks complement the provider conversation tests; finding reply text
alone does not establish rendering or clipboard correctness.
An anonymized Codex 0.162.1 capture also replays 300 actual incremental repaint
frames through Crossterm and checks every visible cell against the canonical
terminal grid, including removal of its large Braille startup animation while
preserving the CLI's live status spinner.

Validation on Genie (Linux), 2026-10-13:

- `cargo test --offline`: 1,311 unit tests and six integration tests passed.
  The two opt-in provider tests are excluded from that default run.
- Both opt-in WebSocket conversation tests passed separately with installed
  Codex 0.162.1 and Claude 2.1.296. Each received `ATEM_READY`, then `LANTERN`
  in the same process, acknowledged input writes and stopped the test session.
- Fresh full-binary sessions for both providers passed in private tmux servers:
  bracketed paste plus Enter, two replies, resize, one Atem status row and
  copying agent-only text into the tmux buffer. Codex's large startup animation
  cleared; its native status spinner remained valid output.
- A remote release, unsubscribe or disconnect returns size ownership to the
  local frontend on its next resize sync, even when its cached dimensions have
  not changed. The release regression covers both Codex and Claude.
- Build, formatting checks and `git diff --check` passed. Clippy completed with
  warnings. System clipboard delivery, other multiplexers and cross-platform
  desktop/mobile interaction still need acceptance testing.

The WebSocket tests use a loopback Astation stand-in and inherited provider
configuration; they do not validate the pending Astation application UI.

## Rendering decision

The first build sends **canonical visible-screen ANSI snapshots and diffs**.
`vt100` in Atem is the canonical emulator. Only Atem receives the original
PTY byte stream and answers terminal queries. A remote xterm instance applies
the generated screen updates. Original application escape sequences, hidden
buffers, queries, OSC clipboard operations and inline images are not forwarded.

This refines the earlier raw-ANSI proposal: `vt100::state_formatted()` alone
cannot restore all of an application's hidden main/alternate buffers, saved
cursors and scroll regions into a second independent emulator. Sending
canonical screen diffs lets the host preserve those states and publish the
correct visible result when the CLI switches buffers. It also bounds memory
for a slow viewer without pausing the local screen or storing an unlimited
output backlog. Intermediate redraws may be coalesced.

This first contract does **not provide remote scrollback history**. The
renderer should use `scrollback: 0` so its incidental redraw scrolls do not
appear to be a reliable transcript. Restored current screens, colors, cursor,
application cursor/keypad, bracketed paste and supported mouse input modes
are included. A history pane, full mouse parity, advanced keyboard protocols,
IME/device testing and end-to-end latency measurements remain acceptance work.
The existing vt100 emulator's terminal feature limits still apply.

Use `@xterm/xterm` **6.0.0** with `allowProposedApi: true` and bundle the
`assets/terminal/atem-unicode.cjs` provider and its JSON table locally. Register
it and select `atem-unicode-width-0.1.14` before rendering. Default xterm widths
and the Unicode11 add-on differ from Atem for some emoji. The supplied provider
matches the host's Unicode 15.1 scalar-width behavior; it intentionally does
not enable independent grapheme clustering. Its generated table has an
exhaustive Rust check. Retest the proposed xterm Unicode API before upgrading.

## Wire envelope and routing

All messages use the existing authenticated WebSocket as JSON text:

```json
{"type":"terminal","data":{"v":1,"op":"list"}}
```

`src/terminal_share.rs` contains the authoritative serde types. On the relay,
Astation must wrap this payload with both the selected `atem_id` and its
current `connection_id`, using the existing generation-checked routing:

```json
{"atem_id":"selected-host","connection_id":"current-connection","payload":{"type":"terminal","data":{"v":1,"op":"list"}}}
```

Never broadcast a terminal request or reuse a previous connection's routing
generation. No relay binary-frame upgrade is needed. Old Astations have no
terminal view; the new Astation client can probe with `list` and show an
unsupported-host state if no terminal response arrives. A response with
`v != 1` must not be interpreted using this contract.

The list response is `op: "sessions"`, with `sessions` containing objects like:

```json
{"terminal_id":"codex","generation":"process-uuid","provider":"codex","rows":40,"cols":120,"exit_status":null,"rendering":"vt100-screen-diff","width_profile":"atem-unicode-width-0.1.14"}
```

`terminal_id` is `codex` or `claude`, scoped to the selected Atem instance.
`generation` changes on every new process. Terminal focus does not affect
routing. Exited processes remain available as a final read-only screen until
a new process of that provider replaces them.

| Client operation | Fields after `v`, `op` | Result |
| --- | --- | --- |
| `list` | none | `sessions` |
| `subscribe` | `terminal_id`, `generation` | `attached {session, stream_id}`; always view only |
| `unsubscribe` | terminal/process IDs, `stream_id` | revoke control and stop updates |
| `ack` | terminal/process IDs, `stream_id`, `offset` | cumulative decoded-byte acknowledgement |
| `control` | terminal/process IDs, `stream_id`, `take` | `controller` with nullable `lease_id` |
| `input` | terminal/process IDs, `stream_id`, `lease_id`, `sequence`, `bytes` | `written` after the PTY writer completes, or error |
| `resize` | terminal/process IDs, `stream_id`, `lease_id`, `rows`, `cols` | canonical PTY resize, followed by a reset frame |
| `stop` | terminal/process IDs, `stream_id`, `lease_id` | signal the PTY process; final screen, then `exited` |

For example, after attaching and taking control:

```json
{"type":"terminal","data":{"v":1,"op":"input","terminal_id":"codex","generation":"process-uuid","stream_id":"stream-uuid","lease_id":"lease-uuid","sequence":0,"bytes":"aGVsbG8N"}}
```

Here `bytes` is standard padded base64 for `hello` followed by CR. Input is
raw bytes: the host does not trim text, append Enter, infer approvals or
interpret a conversation. A paste should be one input operation, with the
CLI's active bracketed-paste framing. Reject oversized paste before sending;
do not silently split a paste across ownership changes.

## Applying screen updates

A frame has these fields in `data`, in addition to `v: 1` and `op: "frame"`:

```json
{"terminal_id":"codex","generation":"process-uuid","stream_id":"stream-uuid","offset":0,"bytes":"...base64 ANSI...","reset":true,"complete":true,"rows":40,"cols":120}
```

1. Reject messages from any other host connection, process generation or
   stream. A new `attached` replaces the previous stream and resets its
   expected byte offset to zero.
2. Require `offset` to equal the next expected offset. A gap requires a fresh
   subscription; never apply a suffix to a missing snapshot.
3. On `reset: true`, reset the renderer and apply the host's rows/columns.
   Only the first chunk of a reset transaction has `reset: true`.
4. Decode base64 to bytes and write a `Uint8Array` directly to xterm. Frame
   boundaries can split UTF-8 and escape sequences; do not decode each frame
   to an independent JavaScript string.
5. In xterm's write-completion callback, acknowledge the end offset:
   `offset + decoded byte count`. Acknowledgements must refer to an emitted
   frame boundary. Credit is based on consumed decoded bytes, not JSON size.
6. `complete: true` finishes that screen transaction. Its chunks can be
   rendered progressively. Disable controls during the initial restore until
   this marker has been consumed. Acknowledge intermediate chunks promptly.

The host sends at most 16 KiB decoded data per frame and 128 KiB of
unacknowledged bytes per viewer. A pending snapshot/diff is bounded at 1 MiB.
It generates the next diff only after the current transaction is acknowledged,
against the latest host screen. If a highly styled screen exceeds the restore
limit, the host reports an error and revokes that subscription; use a smaller
canonical terminal size before reattaching.

The WebSocket terminal queue is separately bounded at 32 messages; the TUI's
pending response/frame queue is bounded at 128. Overflow revokes subscriptions
and asks the peer to resubscribe. It never replays input. PTY input and output
queues have 64 slots each, and local diagnostic ANSI logs retain at most 1 MiB
per provider. Sustained host overload applies bounded PTY backpressure.

## Control and lifetime

`control {take:true}` grants a fresh lease without an unattended local prompt.
The local status row then says remote; local typing is refused until
the Atem prefix followed by `g` reclaims it. Repeating Take Control while
holding a lease is idempotent.
`take:false`, local reclaim, unsubscribe, process exit and disconnect revoke
it. Reconnecting always requires a new subscribe and deliberate Take Control.
Taking control preserves the CLI's unfinished input.

Input sequence numbers start at zero for each new stream and increase by one.
Duplicates and gaps are rejected. A sequence at the expected position is
consumed even if decoding or queue admission fails. The viewer must display
that failure; after a protocol error, resubscribe rather than guessing which
typing to resend. The writer checks the ownership epoch again immediately
before writing. A write that has already started cannot be rolled back.

`written` includes the terminal/process/stream IDs, `sequence`, and nullable
`error`. A successful result means the bytes were written to the PTY; it does
not mean an agent accepted a prompt or finished a turn. Missing acknowledgements
after disconnect are unknown outcomes and must never cause automatic input
retries. `error {terminal_id?, message}` reports request/stream failures.

Resize and Stop require the same lease as typing. Accepted sizes are 2..200
rows and 2..400 columns. A remote controller owns the canonical size; local
redraws cannot fight it. The Atem prefix followed by `g` restores local size
ownership. A local viewer
smaller than the remote viewport currently clips the larger screen.

Old `agentInput`, agent prompts, voice/control and user-command routes are
rejected while a terminal viewer is attached, so they cannot bypass the new
lease. Automatic mark-task dispatch pauses while the Claude terminal is under
remote control. After process exit, the host sends its final screen before
`exited {terminal_id, generation, status}`, waiting for that screen's credit.
No terminal update claims semantic agent turn completion.

## Verification and remaining work

The Rust tests exercise real PTYs plus a WebSocket Astation stand-in, byte-split
Unicode and queries, stale process/stream/lease rejection, duplicate input,
writer-side revocation, hidden-view continuity, resize ownership, slow-viewer
credit, final-screen ordering and connected Claude rendering. Synthetic
screen fixtures were also compared cell-by-cell against `@xterm/headless`
6.0.0 with the supplied width provider, including wide characters, combining
marks, recent emoji, colors, cursor, alternate-buffer return and resizing.

Live checks used Codex 0.160.0 and Claude Code 2.1.296: interactive startup,
an unsubmitted draft, hide/reopen, and explicit Stop. No coding task or native
approval was submitted in these checks.

### Live provider conversation tests

Opt-in tests (removed with terminal-v1 `control`, atem-session r6) launched the installed original
CLI using the same session-start methods as `atem agent launch`. A loopback
WebSocket peer subscribes to the hidden terminal, takes control, sends a paste
and Enter as separate inputs, renders and acknowledges ANSI frames, and stops
the same process remotely. It verifies a first reply of `ATEM_READY` and a
second reply of `LANTERN`, proving conversation continuity. Neither expected
reply occurs literally in the submitted prompts, so input echo cannot pass.

```sh
cargo test --offline live_claude_websocket_conversation -- --ignored --nocapture

# Use the profile and CLI arguments that work on the serving machine.
CODEX_CLI_ARGS='--no-daemon --profile oss' \
  cargo test --offline live_codex_websocket_conversation -- --ignored --nocapture
```

Both tests passed on October 13, 2026 with Codex 0.162.1 and Claude Code
2.1.296. Claude inherited the exported custom endpoint and authentication
environment; Codex used this machine's existing `oss` profile. Its default
provider returned HTTP 401, and its shared background server required
`--no-daemon` for the current configuration. These settings are specific to
this machine, not Atem requirements.

The live tests are ignored during ordinary `cargo test`: they use existing
credentials and make two real provider requests each. They require the CLI
to reach its actual input field and reject a startup update dialog. They do
not approve provider tools or edit project files. The peer injects the
authenticated connection state; authentication is verified separately by
the WebSocket tests. This validates the Atem host and terminal protocol,
not the Astation UI or cross-machine LAN/relay operation.

An already running session is controlled over its connected Astation link.
There is no local CLI attach command or socket for another coding agent to
attach by PID; these opt-in tests launch and own their test processes.

The Astation owner still needs to implement the typed envelope, targeted
routing, terminal chooser, bundled WKWebView/xterm view, View/Take Control/
Release/Stop states, renderer credit and input-result handling. Then validate
real provider approvals, macOS IME/selection/copy/paste, LAN and relay reconnect,
latency under load, and scrollback/history before calling the complete remote
experience ready. Linux-host tests do not validate the macOS UI or mobile UX.

# Remote Agent Control (Astation → atem → claude/codex)

Status: design — 2026-05-26
Owner: Brent G

## Goal

Let a user drive a coding agent (Claude Code / Codex) running under atem on one
machine from a separate control surface — **Astation** (Mac/PC today, mobile
later) — using **voice, text, or control keys**. The agent's own TUI remains the
source of truth for output.

Two device classes, two different needs:

- **Mac/PC (Astation desktop)** — you can already see the agent's TUI in the
  terminal where atem runs. So the desktop only needs to **send input** (the
  "up lane"). No screen mirroring.
- **Mobile (Astation mobile, later)** — no terminal in reach, so it also needs
  to **see** the agent (the "down lane" — a TUI mirror).

This doc specifies the **up lane** as v1 (desktop) and the **down lane** as a
later phase (mobile), so the protocol is designed once for both.

## Non-goals (v1)

- No screen/TUI mirroring to the desktop client (you watch atem's terminal).
- No new transport: v1 rides the existing atem↔Astation channel.
- No attaching to an agent atem didn't launch (atem owns the PTY).

## Architecture

```
Layer 3  Control surface + UI      Astation (Mac/PC now, mobile later)
         input affordances (text / voice / keys); later: TUI render
              ▲   (up lane: input)        │ (down lane: screen — mobile only, later)
              │                           ▼
Layer 2  Transport                 direct (LAN/VPN)  >  relay   [> RTC data channel — see §Transport evolution]
         carries addressed messages across NAT; control = reliable, low-volume
              ▲
Layer 1  atem (agent host)         owns the agent PTY (claude_client / codex_client + vt100)
         injects input into stdin; (later) emits cell-grid diffs for the down lane;
         registry of local agents; relay/direct client
              ▲
Layer 0  Agent process             claude / codex (interactive TUI)
```

Key principle: **atem and Astation speak a transport-agnostic, addressed,
laned message protocol.** The relay is one transport implementation and is
expected to evolve (see §Transport evolution); nothing in atem/Astation is
coupled to today's relay.

### Addressing

Every message is addressed `(atem_id, agent_id)`:

- `atem_id` — which atem host. The relay already routes by `atem_id` (it wraps
  Atem→Astation frames as `{atem_id, payload}` and routes Astation→Atem by
  `atem_id`; see Astation `relay-server/src/relay.rs`).
- `agent_id` — which agent on that host (atem can run multiple). Carried inside
  the payload; atem routes locally.

### Lanes & QoS

| Lane | Direction | Volume | QoS | Phase |
|------|-----------|--------|-----|-------|
| `control` | Astation → atem | low | reliable, never drop | **v1** |
| `status` | atem → Astation | low, periodic | latest-wins | v1.5 |
| `terminal` (mirror) | atem → Astation | high (cell-grid diffs) | lossy, latest-wins | v2 (mobile) |

v1 uses only the `control` lane (+ optional `status`). The heavy `terminal`
lane is mobile-only and deferred — which is why v1 has none of the
flow-control / backpressure / streaming-transport concerns.

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
2. **Text — new.** Type an instruction, send. atem writes it to the agent's
   stdin (line + Enter). No message for this exists yet (see protocol below).
   (Optional alternative to the ConvoAI mic path: OS/native desktop dictation
   also produces text and rides the same text message — but ConvoAI voice
   already works, so this is just a convenience, not required.)
3. **Control keys — new.** A small set for TUI interaction that needs real
   keystrokes: `Enter`, `Esc`, `Ctrl-C` (interrupt), `↑`/`↓`, `y`/`n`
   (tool approve/reject). Sent as key events, written to the PTY raw.

Output: the user watches atem's terminal directly. No down lane.

### What exists vs. what's new (v1)

| Capability | Status |
|---|---|
| Voice → transcript → atem (`voiceRequest`/`voiceCommand`, ConvoAI ASR, PTT + hands-free) | **exists** in `VoiceCodingManager` + atem `pending_voice_request` — reuse |
| Per-atem targeting (`atemId` + channel; relay routes by `atem_id`) | **exists** |
| Text instruction → agent stdin | **new** (`agentInput{kind:text}`) |
| Control keys → agent PTY | **new** (`agentInput{kind:key}`) |
| `agent_id` (multiple agents per atem) | **new** — today targeting is per-atem only |

### Message protocol

Today's `AstationMessage` (both sides) carries: `voiceRequest` /
`voiceCommand` / `voiceResponse` (the voice path), `userCommand` /
`commandResponse` (generic command), `markTask*`, `agentListRequest/Response`,
etc. There is **no** text-to-agent-stdin or key-event message, and **no
`agent_id`** addressing. (Note: atem has `agentPrompt`/`agentEvent` for ACP
agents, but Astation does not emit them — don't conflate.)

v1 adds one new message, `agentInput`, for text + keys.

**Addressing is two-level and `atem_id` is the *envelope*, not the payload.**
The relay (and Astation's `sendHandler`) already wrap Astation→atem traffic as
`{"atem_id": "<host>", "payload": <message>}` and route by `atem_id`. So the
`agentInput` payload must **not** repeat `atem_id`; it carries only the agent
selector + the input:

```
relay envelope (added automatically by Astation/relay):
  { "atem_id": "<host>", "payload": <agentInput> }

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

atem → Astation acks/feedback ride the existing `commandResponse` /
`voiceResponse` / `statusUpdate` shapes; full structured feedback is v1.5
(`status` lane).

### Injection semantics (atem side)

- atem owns the agent PTY (`claude_client.rs` / `codex_client.rs`). `kind:text`
  → write `text` + `\n` to the PTY master. `kind:key` → write the raw byte(s)
  (`\r`, `\x1b`, `\x03`, arrow CSI, `y`/`n`) to the PTY master.
- **Busy handling**: input is written to the live TUI's stdin. If the agent is
  mid-task, a typed line queues at its prompt (same as a human typing early);
  `Ctrl-C` is how you interrupt. atem does not try to gate on agent state in v1.
- **Multiple agents**: `agent_id` selects the target PTY from atem's registry.

### Why v1 is safe + light

- Control messages are **low-volume and reliable** — exactly what the current
  relay is built for. No firehose, no backpressure risk, no binary needed.
- No rendering, no resize, no cell-grid streaming.
- Reuses the existing channel, the existing `atem_id` routing, and the existing
  voice scaffolding.

## v2 — Down lane (mobile mirror), later

Mobile has no terminal, so Astation mobile must **see** the agent. The down
lane carries the TUI as **structured terminal cell-grid diffs** (text/semantic,
NOT video):

- On attach: full screen snapshot (atem serializes the vt100 grid).
- Then: coalesced **cell diffs** (changed cells) at a capped tick rate
  (latest-wins). Rendered full-screen on mobile, portrait/landscape = relayout.
- Input on mobile = the same up-lane `agentInput` (text box + mic + key bar).

The down lane is the **heavy, lossy** lane and introduces real transport
requirements (see below). It is intentionally out of v1 because the desktop
doesn't need it.

## Transport evolution (the relay is expected to change)

The current relay (`Astation/relay-server`) is a JSON-text room forwarder with
**unbounded channels** and a single queue per peer. That is **fine for the v1
up lane** (low-volume, reliable control) but **wrong for the v2 down lane**:

- text/JSON only → terminal data pays base64 tax + per-frame parse
- unbounded channels → a slow mobile consumer grows relay memory without bound
- single queue → a big screen diff head-of-line-blocks a keystroke

When the down lane is built, choose one (both leave atem/Astation's laned
protocol unchanged):

- **(a) Upgrade the relay**: binary frames; bounded, per-lane buffers with a
  drop-oldest policy on the lossy `terminal` lane; logical stream multiplexing
  so `control` never blocks behind `terminal`.
- **(b) RTC data channel for the `terminal` lane** (recommended to evaluate):
  control + signaling stay on the WS relay; the screen stream rides an Agora
  RTC data channel (binary, built-in flow control, NAT-traversing, P2P-or-TURN).
  This plays to Agora's strength and the relay already has RTC plumbing
  (`relay-server/src/rtc_session.rs`, `voice_session.rs`). The relay's
  streaming weaknesses become irrelevant rather than fixes-to-make.

Interim rule for whoever builds the down lane: atem **hard-caps + coalesces**
the terminal lane (latest-wins, ≤N ticks/sec) so the current relay's unbounded
channels can never blow up; relax when the transport gains real per-lane flow
control.

## Phasing

| Phase | Deliverable |
|-------|-------------|
| **v1** | Astation **Mac** up-lane: new `agentInput` (text + keys) → atem → agent stdin; `agent_id` addressing for multiple agents. Voice **reuses** the existing `voiceRequest`/ConvoAI path. Watch output in atem's terminal. |
| v1.5 | `status` lane: agent state (idle/thinking/waiting) → Astation, so the desktop shows a status badge without the full mirror. |
| **v2** | Astation **mobile**: down-lane TUI mirror (cell-grid snapshot + diffs) + the up-lane input bar (text/voice/keys); transport decision (a) or (b). |

## Open questions

1. **Does `agentInput` reach the *interactive TUI* or a headless agent?** v1
   assumes atem owns the agent's PTY and writes to its stdin (so input lands in
   the live TUI you also watch in atem's terminal). Confirm the target agent in
   v1 is a PTY agent atem launched (`claude_client`/`codex_client`), not an ACP
   agent.
2. **Voice vs `agentInput` unification** — keep voice on its existing
   `voiceRequest` path (v1), or fold transcripts into `agentInput{kind:text}`
   for one input path? v1 keeps them separate.
3. **Key set** — is `Enter / Esc / Ctrl-C / ↑↓ / y-n` enough for claude/codex
   TUI interactions, or do we need a fuller key map?
4. **agent_id source** — atem's registry id (per `serv`-style), or a
   human-friendly label (repo / cwd)? Today targeting is per-atem (`atemId` +
   channel) with no sub-agent id; this is net-new.
5. **Down-lane transport** — (a) upgrade relay vs (b) RTC data channel. Decide
   before v2; lean (b).
6. **Multiple Astations** — the relay room allows one Astation per room today
   (`astation_tx` is a single slot in `relay.rs`); mobile + desktop
   simultaneously would need >1 Astation per room — a relay change.

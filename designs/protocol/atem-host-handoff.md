# Atem host handoff: atem-session r6 on `feat/runtime`

For the Astation team, 2026-10-16. The Atem side of
[atem-session-v1.md](atem-session-v1.md) (r6, compatibility mode) now runs in
Atem's real runtime on the `feat/runtime` branch (not merged, not released).
This note says what is live, how to run it, every change Astation can see on
the wire, how the shared fixtures fare against the real processes, and what
stays gated by §9.

## What is live on feat/runtime

- **One runtime per profile.** `atem runtime` (hidden; started on demand by
  any `atem agent …`, bare `atem`, `atem pair`, `atem pair verify`, `atem cred
  unlock|projects`) is the broker. It holds the machine's one Astation link
  (local `:8080` or the relay, as before) and the session host. Nothing else
  in Atem opens an Astation socket, so pairing and unlock no longer displace a
  running session's connection.
- **Workers.** Each session runs in its own `atem worker` process that owns
  the agent's PTY, canonical screen and (Claude) chat adapter. Workers outlive
  the broker; a restarted broker adopts them after checking session id,
  process generation and the OS start time of the worker's pid.
- **Session host.** `SessionHost` with a durable `FileJournal`
  (`~/.config/atem/runtime/journal/`): attachments, registry, 15 s control
  leases with takeover, input epochs, receipts per request, terminal-v1 and
  chat-v1 bound to session-v1. The broker is the only writer authority; the
  worker drops writes of an older input epoch at the PTY write boundary.
- **Local frontends** (`atem agent launch|attach|list|stop`, bare `atem`)
  talk to the broker over a same-user Unix socket. Local input revokes any
  remote lease before it is written.
- **Astation operations** (`atem pair`, `atem pair verify`, `atem cred
  unlock|projects`, paired-token refresh) run inside the broker on its
  existing link; the CLI is only the UI.

## How to run the host

1. Build the branch: `git checkout feat/runtime && cargo build` (the binary is
   `target/debug/atem`; use the same binary for every command below).
2. Stop every other atem on the machine first (older binaries open their own
   Astation connection with the same `atem_id` and evict the runtime's; an
   older runtime is replaced only when it has no live sessions).
3. Pair and verify: `atem pair` (first pairing; it starts the runtime and
   pairs and verifies on its link), or on an already paired profile `atem
   pair verify`. `atem status` shows Pairing/Verification offline. Only a
   paired **and verified** profile gets a session attachment.
4. Launch agents: `atem agent launch claude` / `atem agent launch codex` (in
   the project directory). `atem agent list` prints `Runtime pid … · protocol
   1 · build … · Astation ✓|✗` and the sessions.
5. In Astation: after the link authenticates, send session-v1 `hello`, then
   `list` (the registry replaces the agent list), `acquire` for control,
   terminal-v1 `subscribe` / chat-v1 `open` with a binding.
6. Logs: `~/.config/atem/runtime.log` (broker),
   `~/.config/atem/runtime/workers/<session>.log` (worker). The runtime exits
   after 10 minutes with no live sessions and no frontends, or on SIGTERM to
   the pid in `~/.config/atem/runtime.lock`.

`ASTATION_WS` (or `astation_ws` in `config.toml`) points the runtime at a
specific local Astation, as before.

## Wire-visible changes

Removed, no compatibility (atem-session r6):

- `agentListRequest`/`agentListResponse` are gone: the registry is session-v1
  `list` → `sessions`, then `session_changed` (per-attachment `seq`).
- `agentInput`, `agentPrompt`, `voiceCommand`, `voiceToggle`/`voice_toggle`,
  `voiceRequest`, `userCommand`, `codexTaskRequest` and `agentListRequest`
  no longer parse. Each is answered with a session
  `error{code:"unsupported_version", detail:"removed in atem-session r6"}`
  (no `re`: they have no session id) and has no effect (r6 §0).
- terminal-v1 `list`/`sessions`, `control`/`controller`, `lease_id`, the
  `terminal_ids` marker and provider-name ids (`claude`, `codex`) are gone;
  chat-v1 `submit` without `binding` is refused. These family messages are
  answered with a session `error{code:"unsupported_version"}` and no effect.

Attachments and identity:

- Bare `atem` (the menu TUI) opens no Astation connection at all; only
  `atem runtime` does, and it serves the sessions. If the runtime's session
  host can't start (e.g. a damaged `runtime/journal/runtime_epoch`, which is
  never reset silently), session-family messages are answered
  `error{code:"unsupported_version"}` and `atem agent list` shows "remote
  sessions disabled: <path> is damaged; move it aside to reset the runtime
  epoch".
- Only the paired Astation the link authenticated with, verified in this
  profile's `cred_state.json`, gets an attachment (`view`, `control`,
  `approve`; `client_kind: native`). Any other link (unpaired, unverified,
  another Astation) gets none: its session-family messages are answered
  `error{code:"unauthorized"}`.
- Every connect and every re-authentication (`auth_required` over an open
  socket) is a **new attachment**: send `hello` again; a message bound to an
  old `attachment_gen` is `stale_target`. Leases are not inherited.
- `welcome`: `account_id` = the verified `data_account` from
  `cred_state.json`; `atem_device_id` = this device's verified `device_id`;
  `host_trust_gen` = `pairing.json`'s generation (moves on every
  `atem pair`/`atem unpair`); `runtime_gen` and `runtime_epoch` change when
  the broker restarts (the epoch is a durable counter) and when the host
  rebinds to a new identity (a pairing verified after the broker started).
- Authorization: an attachment is authorized for 24 h (no freshness proof in
  compatibility mode), counted on the monotonic clock and in wall time,
  whichever ends first (the monotonic clock stands still while the machine
  is suspended). At the end the broker fences it and drops the link; the
  reconnect authenticates again and gets a new attachment.
- Duplicates: a session message with the same `id` and identical content on
  the same attachment within 60 s is handled once (e.g. arriving over both
  transports); other content under that id, or a retry on a new attachment,
  is handled.
- `atem unpair` / `atem logout` make a running runtime reload: a link whose
  pairing is gone is dropped with its attachments. The broker also re-checks
  the link's pairing every 5 s, so an unpair takes effect even if the
  reload never reached it.
- Duplicate detection remembers at most 4096 messages (oldest forgotten
  first).

terminal-v1:

- `terminal_id` = `session_id`; `generation` = `process_gen`. Every message
  carries a session-v1 `binding`; `input`, `resize` and `stop` also need the
  current lease.
- Each `input` is answered with `written` (no `error`, or an error text;
  `"control changed; not written"` when the bytes were dropped at the write
  boundary because control moved or the lease's deadline passed).
- Lease deadline at the write boundary: every remote write and paste the
  broker hands a worker carries `not_after`, the lease's deadline on
  `CLOCK_MONOTONIC`; the worker's PTY writer drops a chunk whose deadline has
  passed when its turn comes, so nothing remote is written at or after the
  deadline even if the host's 100 ms `advance` hasn't run yet. (A chunk queued
  before a `renew` keeps the deadline it was sent with.)
- A slow transport: frames are dropped and every stream ends with
  `error{code:"busy"}` ("Terminal transport congested; subscribe again");
  `written` acks and errors keep their order.
- Inbound `terminal` messages larger than 32 KiB (`session`/`agentChat`:
  1 MiB) are dropped unread and answered with a session
  `error{code:"unsupported_version"}`. A full host inbox (1024 messages per
  pass) answers `busy`.

chat-v1:

- `open`, `close` and `submit` carry a session-v1 binding; `submit` also the
  lease. A submit's `accepted` / `complete{outcome, turnId}` /
  `error{code, text}` follow its receipt (accepted and executing → `accepted`;
  completed → `complete`; rejected / outcome_unknown → `error`), never a
  session receipt.
- At most 8 open conversations per session: a ninth `open` closes the oldest
  (`close`).
- Codex has no chat (`capabilities: ["terminal-v1"]`; Claude:
  `["terminal-v1","chat-v1"]`).

Receipts (session-v1 `submit`), per kind:

- `prompt`: pasted into Claude once its chat accepts it, completed when the
  chat reports the turn's end (`turn_id`). On a session without chat (Codex)
  it is `rejected` with no effect.
- `interrupt`: writes Esc; completes when a turn ends, or at once when none
  runs.
- `stop`: stops the agent; completes at its exit.
- `approval`: `rejected` (approvals stay in the terminal).
- A dispatch refused before anything was queued is `rejected` ("could not
  write to the terminal"); a writer failure after queueing is
  `outcome_unknown` ("write interrupted"). Work executing when the broker
  restarts becomes `outcome_unknown`; nothing is retried. Duplicate submits
  return the recorded receipt; the same `request_id` with other content is
  `request_id_reused`. Receipts survive broker restarts (`receipt_query`).

Pairing, verification and unlock:

- `atem pair`, `atem pair verify`, `atem cred unlock`, `atem cred projects`
  and the paired-token refresh run on the runtime's existing link: the
  handshake messages (`pairSavePreference`, `credentialSync`, `verifyCommit` →
  `verifyKeys` → `verifyReveal` → `deviceVerified`/`verifyAbort`,
  `unlockRequest` → `unlockGrant`/`unlockDenied`, storage-key rotation,
  `credentialProjectListResponse`) arrive on the same socket that carries the
  sessions, not on a new one. One operation at a time; replies are routed to
  the running operation only and dropped after it ends; a CLI that goes away
  ends it (`verifyAbort` for verification); a lost link ends it, never
  replayed.

## Shared fixtures against the real runtime

`tests/runtime_fixtures_binary.rs` runs every host scenario in `fixtures/`
against the `atem runtime` binary on a temp profile (paired and verified as
the fixture's account, device and trust generation), real `atem worker`
processes with a fake agent in their PTYs (a fake Claude that fires Atem's
chat hooks and writes a transcript; turn ids `turn-<n>`), a local frontend
for local input, and a fake Astation that authenticates the runtime's link
and plays the fixture's client. Runtime-chosen ids (session ids, process,
runtime and attachment generations) are translated; the clock and PTY write
faults use debug-only hooks (`src/runtime/test_hooks.rs`). Terminal `frame`s
and `written` acks are not queued for `expect` (the acks count toward
`pty_writes_dropped`).

| Fixture | Result |
|---|---|
| dispatch-failure-after-partial-write-is-outcome-unknown | pass (incl. `restart_runtime` + `reconnect`) |
| lease-expiry-at-the-deadline-needs-no-timer | pass (the remote chunk held at the PTY writer past the deadline is dropped by its `not_after`) |
| dispatch-failure-before-any-effect-is-rejected | pass (incl. `restart_runtime` + `reconnect`) |
| duplicate-submit-returns-receipt-and-reuse-is-rejected | pass |
| exited-session-refuses-work-before-the-lease-check | pass (`crash_worker` = SIGKILL to the worker) |
| family-errors-and-chat-results | pass |
| lease-expires-without-renewal | pass |
| local-input-revokes-the-lease-and-drops-queued-bytes | pass |
| reconnect-restarts-the-registry-sequence | pass |
| removed-ops-have-no-effect | pass folded onto one attachment (the lease holder itself sends every removed op, with and without the lease; `lease_changed` for the second client left out); the two-attachment original runs in the core harness |
| receipt-query-is-scoped-to-the-exact-target | core harness only (3 attachments) |
| takeover-moves-control-and-the-old-holder-becomes-a-viewer | core harness only (3 attachments) |
| closed-session-refuses-work-before-the-lease-check | core harness only: the runtime has no trigger that closes a running session yet |

The multi-attachment fixtures (receipt-query, removed-ops, takeover) run
only in the core harness (`SessionHost` in `src/session_protocol/fixtures.rs`)
because the runtime holds one Astation link, so one attachment, at a time
today; closed-session runs only there because nothing in the runtime closes
a running session yet.

The same fixtures all pass against the in-process `SessionHost`
(`src/session_protocol/fixtures.rs`, with the memory and the file journal).

Not honoured against real processes: `timers: false` (the broker's loop runs
`advance` whenever the clock moved 100 ms), `close_session`,
`disconnect`/`resume` (no resume in compatibility mode), `fail_next_fsync`,
`change_trust_gen`, and more than one client per scenario.

## Differences from session-multiplexing.md

- §1 lists `atem cred status` as a compatibility alias of `atem status`; the
  user removed it. `atem status` is the only status command. (Astation
  maintains session-multiplexing.md.)

## Still gated by §9

Refused until §9 is specified jointly, implemented and tested: resume (and
`resume_proof`), browser clients and QR grants, account-wide native access
(only the one verified Astation attaches), relay confidentiality (no
end-to-end channel; the relay sees the messages), authenticated freshness
proofs (the 24 h window starts at authentication, not at a validated
authority proof), signed membership and revocation ordering. Several
simultaneous Astation clients per host also wait for it (today: one link, one
attachment).

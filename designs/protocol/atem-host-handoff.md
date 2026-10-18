# Atem host handoff: atem-session r8 on `feat/r8` (r6 runtime, r7 approvals)

## atem-session r8 on `feat/r8` (2026-10-18)

Atem's host now speaks **r8 only** ([atem-session-v1.md](atem-session-v1.md),
appendix "r8", authoritative). The consolidated note for the Astation agent,
with every fixture change, every reading to confirm and the work Astation
must do, is [r8-astation-handoff.md](r8-astation-handoff.md).

- **Astation must send `revision: 8`** in every session-v1 `hello`. A `hello`
  without it (or with another number) is answered
  `error{code:"unsupported_version", revision: 8, detail}` and nothing else:
  no attachment, no `welcome`, and every later request on that link is
  refused as before `welcome`.
- `welcome` carries `revision: 8` and `features`, all nine:
  `chat.history_end`, `chat.history`, `chat.lookup`, `chat.coverage`,
  `receipt.result`, `approval.session_rules`, `approval.card_reason`,
  `chat.send_acquire`, `approval.lease_free`.
- Live: history pages in the conversation's sequenced stream (`open` ends
  with `history_end`; `history{before|turn_id|request_id|next}`; coverage,
  truncation, holes and the `coverage` event; a backlog gap is reloaded and
  reported, never a forced reopen; `close.reason`), `receipt.result` on
  completed prompts, chat Send that acquires the lease with the prompt
  (session `submit` or chat-v1 `submit` with `acquire`, `takeover`,
  `expected_controller`; the admitting reply carries `lease`; `lease_held`
  names `controller`), lease-free approval answers (`control` only; the
  first admitted answer wins; `acquire` refused), final cards with
  `reason`, the submitter principal with its durable control fence and
  clean close (§H), and one admission persistence rule (§I).
- Removed and refused (`unsupported_version`): chat `open.before`/
  `open.generation`, the `status.page` marker, `acquire` on an approval
  answer, `hello` without `revision`.
- Deleted r7 fixtures and their r8 replacements:

  | deleted (r7) | replaced by |
  |---|---|
  | `approval-answer-with-acquire-takes-control-from-the-holder` | `r8-approval-answer-with-acquire-is-refused` |
  | `approval-late-answer-after-push-resolved-is-stale-target` | `r8-approval-late-answer-after-push-resolved-is-stale-target` |
  | `approval-opens-without-a-lease-holder` | `r8-approval-opens-without-a-lease-holder` |
  | `approval-stays-pending-when-the-lease-ends` | `r8-approval-stays-pending-when-the-lease-ends` |
  | `approval-survives-takeover` | `r8-approval-survives-takeover` |

- Results: all 72 fixtures pass in the core runner; 24 pass against the real
  runtime and 41 can't be expressed there (see "Shared fixtures (r8)").
- **Pin**: the merge commit of the r8 PR into `main`. Until it merges, pin
  `feat/r8` at the commit named in `r8-astation-handoff.md` ("Pin").

The sections below describe the runtime (r6) and approvals (r7) as they
were handed over; where they say an answer carries `acquire` or needs the
lease, r8 §G replaces it.

## Earlier handoff: atem-session r6 on `feat/runtime`, r7 approvals on `feat/approvals`

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
  profile's `cred_state.json`, gets an attachment (`view`, `control`;
  `client_kind: native`). Any other link (unpaired, unverified,
  another Astation) gets none: its session-family messages are answered
  `error{code:"unauthorized"}`.
- Every connect and every re-authentication (`auth_required` over an open
  socket) is a **new attachment**: send `hello` again; a message bound to an
  old `attachment_gen` is `stale_target`. Leases are not inherited.
- r7.1: a `hello` again on the same, still authenticated link (Astation reset
  its session client, e.g. after the Mac slept) is **accepted** and replaces
  the attachment: new `attachment_gen` and `controller_session`, the old one's
  leases end (none carried over), its streams and conversations close, the
  old `attachment_gen` is `stale_target`; receipts stay queryable and pending
  approvals are sent again. The link's 24 h authorization is not renewed. At
  most one replacement a second (`busy`). When the socket is down, retry by
  reconnecting rather than re-sending `hello`. This is not a verification
  problem: the "Complete verification" UI text is wrong for it (a refused
  `hello` meant the client already had an attachment, never that the device
  needs verifying). runtime.log has one `HH:MM:SS` UTC line per `hello`:
  `welcome`, `replaced attachment … with …; welcome`, or `refused <code>`.
  Every other refused request (an `error` reply, a `rejected` receipt, an
  oversize drop) also gets one line with its family, op, code and session,
  never its content: `refused agentChat/submit kind=approval_rule_revoke
  unsupported_version session=ses-… (decode: agentChat: approval_rule_revoke:
  unknown field `rule`)`; at most 20 per 10 s per link.
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
  boundary because control moved or the lease's deadline passed;
  `"the approval was handed to the terminal; not written"` when they
  released a waiting Codex approval hook and were consumed).
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
- History pages (fix/chat-history, 2026-10-17): `open{before}` on a
  conversation the attachment already has open sends no `opened` and
  resets nothing; the older page arrives as `message{history:true}` at the
  conversation's next sequence numbers (the live sequence continues). Merge
  paged messages by `messageId`/history order, not by `sequence`. Every
  page ends with a sequenced `status` carrying `page: {before, count,
  start}` (`start: true`: the oldest retained message was reached; an empty
  page is the marker alone, `count: 0, start: true`). Cards are left out of
  a view-only attachment's pages before the limits. `open` may carry the
  `generation` of its `before`. A `before` that isn't retained, or named
  with another `generation`, is `error{code:"stale_target"}` ("that message is no
  longer in the history; reopen without before to get the newest page"):
  sequenced on an open conversation (it stays open), without
  `generation`/`sequence` on a new one (nothing opened). `open` without
  `before` on an open conversation still resynchronizes it (`opened` at 0).
- When the worker dropped chat items before the broker got them, the broker
  reloads the worker's whole history and chat state (a turn end it missed
  completes then, with its receipt), then open conversations get `error`
  "the chat history was incomplete (some items were dropped) and was
  reloaded; reopen the chat" and `close`. Reopen: the history is complete.
- After a broker restart or adoption the chat history is whole (500
  messages / 8 MiB) and keeps its approval cards; a card still pending
  becomes `closed` with the note "Atem's runtime restarted; answer in the
  terminal".
- Claude: `capabilities: ["terminal-v1","chat-v1"]`. Codex has chat-v1
  only with Atem's Codex hooks on (`[codex] hooks = true`; else
  `["terminal-v1"]`, and a `prompt` there is `rejected` with "chat is not
  available for this agent; use the terminal"). Before Codex's first prompt
  its status is `unknown`
  with the detail "type a first prompt in the terminal: …", and a chat
  `submit` (or a `prompt` receipt) is `rejected` with that text as its
  `detail`/`text`; a submit refused for the status (busy, a local draft) is
  `rejected` with the reason too.
- `opened` carries `unavailable`: an array of strings naming what the
  agent's chat can't provide — `streaming`, `reasoning`, `error_details`
  (all three for Codex, none for Claude) — and `approvalRules`, the
  session's active Atem session rules (r7.2, below).

Receipts (session-v1 `submit`), per kind:

- `prompt`: pasted into the agent once its chat accepts it (status
  `ready`, no local draft), completed when the chat reports the turn's end
  (`turn_id`), with `detail` `"done"` or `"interrupted"` (the turn's
  outcome, as chat `complete.outcome`; journaled, so it survives a broker
  restart). On a session without chat (Codex with its hooks off) it is
  `rejected` with no effect.
- `interrupt`: writes Esc only while the chat status says a turn runs
  (`working`/`waiting`) and completes when it ends; in `ready` or `unknown`
  it completes at once ("no turn was running") with nothing written. A
  session without turn state — any agent: Codex with its hooks off, Claude
  before its SessionStart or after its chat was withdrawn — gets it
  `rejected` ("no turn state; use the terminal"), never Esc.
- `stop`: stops the agent; completes at its exit.
- `approval`: handed to the agent's waiting permission hook; completes when
  the agent applied it (see [Approvals](#approvals-r7-6a-on-featapprovals)).
- `approval_rule_revoke` (r7.2; r7.3): `{rule_id}` from any attachment
  with `control`, lease or not (`lease_epoch` optional and ignored);
  dispatched to the session's worker, completed when it dropped the rule
  (an inactive rule is `stale_target` at admission).
- An `interrupt` (or `prompt`) whose write only handed a waiting Codex
  approval to Codex's own dialog is `rejected` with "the approval was handed
  to the terminal; interrupt again to stop the turn" ("…; not written" for a
  prompt): show it as is; a second interrupt stops the turn.
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

## Codex chat (for Astation)

Codex now has a chat-v1 adapter (branch `feat/codex-chat`; design:
`designs/agent-chat-host.md`, "Codex"). What changes for the relay and the
web page:

- **Availability.** `["terminal-v1","chat-v1"]` only when the user allowed
  Atem's Codex hooks (`[codex] hooks = true`, asked once at the first
  `atem agent launch codex`; with it on, every Codex worker keeps the hooks
  merged, so menu launches get chat too; Codex also needs them trusted in
  its `/hooks`).
  Otherwise `["terminal-v1"]` and no turn state. Show chat per descriptor,
  not per provider.
- **`opened.unavailable`.** An array of strings naming what the agent's chat
  cannot provide: `streaming`, `reasoning`, `error_details`. Codex sends all
  three, Claude `[]`. Hide or disable the matching UI (no typing indicator
  for partial text, no reasoning fold, no error detail). Unknown names must
  be ignored. ("Always allow" is offered on Codex cards as an Atem session
  rule, see below.)
- **Typed chat-v1 decoder: accept unknown fields.** Astation's typed
  chat-v1 decoder must accept (ignore) fields it doesn't know before Codex
  `opened` messages arrive: `opened.unavailable` is new, and a decoder that
  rejects unknown fields would drop every Codex `opened`.
- **No streaming.** A Codex reply arrives whole, as the rollout records it
  (commentary and final answers are separate messages; a command run is a
  `Bash` tool part). Do not animate it as a stream.
- **Activity is real.** Codex's `activity` (descriptor, `atem agent list`,
  chat `status`) is `unknown` before its first prompt, then `working`,
  `waiting` (a permission prompt is open) and `ready`. It no longer stays
  `unknown`. The activity dot should follow process state: `exited` or an
  unavailable session is not "ready", and `unknown` is grey, never green.
- **First-prompt refusal.** Codex reports nothing until it gets a prompt, so
  chat opens in status `unknown` with the detail "type a first prompt in the
  terminal: Codex reports nothing before it (and Atem's Codex hooks must be
  trusted in its /hooks)". A chat `submit` (or a session-v1 `prompt`
  receipt) before then is refused: chat-v1 `error{text}` and the receipt's
  `rejected` `detail` carry that same text. Show it and let the user type in
  the terminal; chat prompts work once the status is `ready` (after that first turn ends).
  Other refusals (busy, a local draft) now carry their reason the same way.
  With hooks off, a prompt is `rejected` with "chat is not available for
  this agent; use the terminal".
- **Interrupt.** Esc is written only while the status is `working` or
  `waiting`, and the receipt completes at that turn's end (chat `complete`
  with outcome `interrupted`). In `ready` or `unknown` it completes at once
  with nothing written. With no turn state (hooks off; Claude too, before its
  SessionStart or after its chat was withdrawn) it is `rejected` ("no turn
  state; use the terminal"). `outcome_unknown` after 10 s means no interrupt
  was observed.
- **Prompt origin.** Only a prompt after the paste can be the remote one; a
  local prompt typed just before shows as `origin: local`. Compaction turns
  produce no `complete`.
- **Approvals** are unchanged: cards in the chat, allow once / deny only.
- **Worker `hello.chat` is required** (an older worker is
  `recovery_required` after a runtime upgrade; no compatibility).

Known limits: filesystems and logs with whole-second times allow same-second
races when pairing a prompt or a turn end; tool-result evidence keeps 1 s
slack; a hook read after its npm-wrapper parent exited is dropped (harmless).

## Shared fixtures (r8)

Two runners execute `fixtures/` (format in `fixtures/schema.md`):

- **Core runner** (`src/session_protocol/fixtures.rs`, `cargo test --bin
  atem session_protocol::fixtures`): `SessionHost` through the fixtures' fake
  runtime, once with the memory journal and once with the `FileJournal`.
  **All 72 fixtures pass** (65 host, 7 client), with both journals; every
  `r8-*` one is gated on the host work it needs (`R8_FIXTURE_NEEDS` in
  `src/session_protocol/revision.rs`) and all of it is implemented.
- **Real runtime** (`tests/runtime_fixtures_binary.rs`, `cargo test --test
  runtime_fixtures_binary`; `ATEM_FIXTURE=<name>` runs one): every host
  scenario against the `atem runtime` binary on a temp profile (paired and
  verified as the fixture's account, device and trust generation), real
  `atem worker` processes with a fake agent in their PTYs (a fake Claude
  that fires Atem's chat hooks and writes a transcript, turn ids
  `turn-<n>`; chat content a fixture names is appended to that transcript
  as Claude Code writes it, and after `chat_history` the harness waits on a
  probe conversation that never reaches the client), a local frontend for
  local input, and a fake Astation that authenticates the runtime's link
  and plays the fixture's client. Runtime-chosen ids (session ids, process,
  runtime and attachment generations, rule ids) are translated; the clock
  and PTY write faults use debug-only hooks (`src/runtime/test_hooks.rs`).
  Terminal `frame`s and `written` acks are not queued for `expect` (the
  acks count toward `pty_writes_dropped`). **24 pass, 41 are not run, 0
  fail**: 35 need two or three attachments (the runtime holds one
  Astation link, so one attachment), one needs `close_session` (nothing in
  the runtime closes a running session), and five history scenarios need
  what a real agent can't be made to produce (below). A not-run reason is
  printed for each; a scenario that starts passing fails the test until it
  is taken off the list. `removed-ops-have-no-effect` also runs folded onto
  one attachment (`removed_ops_have_no_effect_on_one_attachment`).

| Fixture | Side | Core runner | Real runtime |
|---|---|---|---|
| `approval-allow-always-must-name-an-offered-rule` | host | pass | pass |
| `approval-allow-once-is-handed-to-the-agent-and-completes` | host | pass | pass |
| `approval-answered-in-the-terminal-first-refuses-the-late-remote-answer` | host | pass | pass |
| `approval-deny-carries-the-message-to-the-agent` | host | pass | pass |
| `approval-duplicate-submit-returns-the-receipt` | host | pass | pass |
| `approval-needs-control-and-the-lease` | host | pass | not run: 2 attachments (one link) |
| `approval-pending-is-sent-again-after-list` | host | pass | pass |
| `approval-rule-revoke-needs-control-not-the-lease` | host | pass | not run: 3 attachments (one link) |
| `closed-session-refuses-work-before-the-lease-check` | host | pass | not run: the runtime never closes a running session |
| `dispatch-failure-after-partial-write-is-outcome-unknown` | host | pass | pass |
| `dispatch-failure-before-any-effect-is-rejected` | host | pass | pass |
| `duplicate-submit-returns-receipt-and-reuse-is-rejected` | host | pass | pass |
| `exited-session-refuses-work-before-the-lease-check` | host | pass | pass |
| `family-errors-and-chat-results` | host | pass | pass |
| `late-renew-reply-does-not-resurrect-control` | client | pass | — (client machines run in the core runner only) |
| `lease-expires-without-renewal` | host | pass | pass |
| `lease-expiry-at-the-deadline-needs-no-timer` | host | pass | pass |
| `local-input-revokes-the-lease-and-drops-queued-bytes` | host | pass | pass |
| `r8-approval-answer-by-a-non-holder-leaves-the-lease` | host | pass | not run: 3 attachments (one link) |
| `r8-approval-answer-keeps-the-holders-deadline` | host | pass | not run: 2 attachments (one link) |
| `r8-approval-answer-to-a-closed-request-is-stale-target` | host | pass | not run: 2 attachments (one link) |
| `r8-approval-answer-with-acquire-is-refused` | host | pass | not run: 2 attachments (one link) |
| `r8-approval-answers-crossing-first-wins` | host | pass | not run: 2 attachments (one link) |
| `r8-approval-card-carries-the-close-reason` | host | pass | pass |
| `r8-approval-late-answer-after-push-resolved-is-stale-target` | host | pass | pass |
| `r8-approval-opens-without-a-lease-holder` | host | pass | pass |
| `r8-approval-stays-pending-when-the-lease-ends` | host | pass | pass |
| `r8-approval-survives-takeover` | host | pass | not run: 2 attachments (one link) |
| `r8-backlog-hole-is-reported-not-reopened` | host | pass | not run: no backlog fault in the real worker |
| `r8-clean-close-runs-queued-work-once-its-principal-is-confirmed` | host | pass | not run: 2 attachments (one link) |
| `r8-client-delayed-send-reply-never-restores-control` | client | pass | — (client machines run in the core runner only) |
| `r8-client-enables-only-advertised-features` | client | pass | — (client machines run in the core runner only) |
| `r8-client-refuses-a-host-without-revision-8` | client | pass | — (client machines run in the core runner only) |
| `r8-client-shows-truncation-and-resyncs-only-on-a-sequence-gap` | client | pass | — (client machines run in the core runner only) |
| `r8-control-fence-holds-when-a-rejection-write-fails` | host | pass | not run: 2 attachments (one link) |
| `r8-crash-after-durable-acceptance-grants-no-lease` | host | pass | not run: 2 attachments (one link) |
| `r8-crash-rejects-queued-work-whose-history-is-unknown` | host | pass | not run: 2 attachments (one link) |
| `r8-delayed-send-reply-does-not-regrant-lost-control` | host | pass | not run: 2 attachments (one link) |
| `r8-disconnect-right-after-acceptance` | host | pass | not run: 2 attachments (one link) |
| `r8-double-write-failure-takeover-never-runs` | host | pass | not run: 2 attachments (one link) |
| `r8-duplicate-send-never-reacquires-or-replays` | host | pass | not run: 2 attachments (one link) |
| `r8-expired-lease-is-checked-at-admission` | host | pass | not run: 2 attachments (one link) |
| `r8-failed-fence-write-rejects-queued-work-at-once` | host | pass | not run: 2 attachments (one link) |
| `r8-failed-fence-write-then-control-restored-never-runs` | host | pass | not run: 2 attachments (one link) |
| `r8-failed-persistence-changes-no-lease` | host | pass | not run: 2 attachments (one link) |
| `r8-hello-without-revision-8-is-refused-before-any-attachment` | host | pass | pass |
| `r8-history-page-and-live-events-share-one-ordered-stream` | host | pass | not run: the runtime sends a later message version as `delta`, the fixture the whole message |
| `r8-history-selectors-are-exclusive-and-validated` | host | pass | pass |
| `r8-local-input-wins-over-a-send` | host | pass | not run: 2 attachments (one link) |
| `r8-long-turn-is-recovered-in-bounded-pages` | host | pass | pass |
| `r8-open-with-before-is-refused` | host | pass | pass |
| `r8-ownership-is-checked-at-admission-not-as-displayed` | host | pass | not run: 2 attachments (one link) |
| `r8-process-replaced-before-dispatch` | host | pass | not run: 2 attachments (one link) |
| `r8-receipt-result-bounds-reply-message-ids` | host | pass | not run: the real adapter also sends sequenced `status` around a remote turn |
| `r8-recovered-work-needs-its-principal-confirmed` | host | pass | not run: 2 attachments (one link) |
| `r8-revoked-control-fences-work-across-reconnect-and-restart` | host | pass | not run: 2 attachments (one link) |
| `r8-revoked-control-refuses-the-send-and-its-queued-prompt` | host | pass | not run: 2 attachments (one link) |
| `r8-send-acquire-wire-rules` | host | pass | not run: 2 attachments (one link) |
| `r8-send-acquires-an-unowned-session` | host | pass | not run: 2 attachments (one link) |
| `r8-send-refused-while-another-holds-then-takeover` | host | pass | not run: 2 attachments (one link) |
| `r8-send-under-the-own-lease-checks-the-epoch` | host | pass | not run: 2 attachments (one link) |
| `r8-stale-or-foreign-next-token-is-stale-target` | host | pass | not run: real retention evicts only past 500 messages / 8 MiB |
| `r8-stale-takeover-confirmation-is-refused` | host | pass | not run: 3 attachments (one link) |
| `r8-truncated-history-reopens-once-then-stays-live` | host | pass | not run: real retention evicts only past 500 messages / 8 MiB |
| `r8-two-simultaneous-sends-acquire-once` | host | pass | not run: 2 attachments (one link) |
| `receipt-query-is-scoped-to-the-exact-target` | host | pass | not run: 3 attachments (one link) |
| `reconnect-restarts-the-registry-sequence` | host | pass | pass |
| `registry-restarts-on-a-new-attachment` | client | pass | — (client machines run in the core runner only) |
| `removed-ops-have-no-effect` | host | pass | not run: 2 attachments (one link) |
| `runtime-epoch-and-sequence-ordering` | client | pass | — (client machines run in the core runner only) |
| `second-hello-replaces-the-attachment` | host | pass | pass |
| `takeover-moves-control-and-the-old-holder-becomes-a-viewer` | host | pass | not run: 3 attachments (one link) |

Why the five history scenarios stay off the real runtime (each runs in the
core runner, and the same `chat::history` code serves both):
`r8-backlog-hole-is-reported-not-reopened` needs a worker backlog fault (the
real worker drops only past 4096 items / 8 MiB, and its reload then finds
everything); `r8-stale-or-foreign-next-token-is-stale-target` and
`r8-truncated-history-reopens-once-then-stays-live` need `chat_evict` (real
retention evicts only past 500 messages / 8 MiB, which would put hundreds of
messages the fixture doesn't name into its pages);
`r8-receipt-result-bounds-reply-message-ids` runs a remote prompt's turn, and
the real Claude adapter also sends `status` `working`/`ready` in the
conversation around it (sequenced events the fixture's sequence numbers don't
model; `receipt.result` is checked live by the real-agent Codex test);
`r8-history-page-and-live-events-share-one-ordered-stream` appends a part to
a live message, which the runtime sends as chat-v1 `delta{part}` where the
fixture expects the whole message again (both are newer versions by the
sequence rule; see `r8-astation-handoff.md`).

Not honoured against real processes: `timers: false` (the broker's loop runs
`advance` whenever the clock moved 100 ms), `close_session`,
`disconnect`/`resume` (no resume in compatibility mode), journal faults
(`fail_next_fsync`, `fail_fsync_of`, `crash_after_accepted`),
`set_permissions`, `drop`, `replace_process`, `change_trust_gen`,
`approval_rules`, `chat_evict`, `worker_gap`, and more than one client per
scenario.

## Approvals (r7 §6a, on `feat/approvals`)

Branch `feat/approvals` (from `feat/runtime`; not merged). The agent's own
permission prompt — Claude Code's and Codex's `PermissionRequest` hook — can be
answered from Astation, bound to that exact prompt; the terminal can always
answer instead, and Atem never allows anything by itself (any failure,
timeout or missing answer is "no decision": the agent asks in its own
dialog). The contract is [§6a](atem-session-v1.md); this lists everything
Astation sees that changed since r6.2.

### Wire changes since r6.2

- **`approval_request`** (H→C): `approval_id` (UUID), `session_id`,
  `process_gen`, `tool`, `summary`, `created_at`, `always_rules: [{rule_id,
  label, scope}]`. Sent when the hook asks, **whoever holds the lease (or
  nobody)**, to every attachment subscribed by `list` that has `control`, and
  again after every `sessions` snapshot for each pending one. Key it by
  `approval_id`; a repeat replaces. `summary` is redacted (the command's
  first line or the file path; credentials masked), never full inputs.
- **`approval_closed`** (H→C): `approval_id`, `reason`: `answered_remote`,
  `answered_terminal`, `interrupted`, `timed_out`, `released`,
  `process_ended`. **`lease_lost` is gone**, renamed in effect to
  `released`: Atem gave the prompt back to the agent (input reached a Codex
  session, or the runtime restarted). Lease changes — expiry, release,
  takeover, local input, trust change — never close an approval.
- **`submit` `kind:"approval"`**, payload exactly `{approval_id, decision:
  allow_once|allow_always|deny, rule_id?, message?, acquire?}`: `rule_id`
  iff `allow_always` (one of the request's `always_rules`), `message` only
  with `deny` (≤ 512 bytes, given to the agent; without one the agent reads
  "Denied from Astation"). (**r8 §G replaces the rest of this item**: an
  answer needs only `control`, its `lease_epoch` is optional and ignored,
  it never takes or moves the lease, `acquire` is refused
  `unsupported_version`, and the first admitted answer wins.) r7: without
  `acquire` the binding carries the current
  `lease_epoch` (else `stale_lease`). **With `acquire: true`** the binding
  has no `lease_epoch`: Atem needs `control` and a running session, and once
  the answer is durably `accepted` it gives this attachment the lease (a
  takeover if another holds it), sends `lease_changed` (`granted`/`takeover`,
  to every viewer including you) and `session_changed`, then the receipts —
  the lease is taken only together with an answer that was admitted. A
  closed, answered or unknown approval, another process, or a rule it didn't
  offer is `stale_target` (nothing recorded, no lease taken): show "already
  answered". Receipt: `accepted` → `executing` (the card closes
  `answered_remote`) → `completed` when the agent applied it; `rejected` if
  it closed first or couldn't be handed over; `outcome_unknown` when the
  terminal answered too, the agent exited, or it never confirmed within
  630 s.
- **View-only rule.** `approval_request`, `approval_closed` and chat cards go
  only to attachments with `control` (today the runtime's one link always
  has `view` and `control`). `welcome.permissions` has no `approve`.
- **Relay messages (H→relay)**, over Atem's authenticated link, only when it
  is the verified pairing's; not session messages (no `id`, no reply):

  ```json
  {"type":"relay","data":{"v":1,"op":"push_approval","approval_id":"…","atem_device_id":"…",
    "session_id":"ses-…","tool":"Bash","summary":"npm test","expires_at":1760500600000}}
  {"type":"relay","data":{"v":1,"op":"push_resolved","approval_id":"…","reason":"answered_terminal"}}
  ```

  `expires_at` is wall ms when the agent's hook gives up (Claude 600 s,
  Codex 300 s after `created_at`). `push_resolved.reason` is an
  `approval_closed` reason. Best effort: while the link is down Atem keeps
  the latest state per approval (≤ 64; unsent ones are dropped first, a
  pushed one never) and on reconnect sends `push_approval` only for
  approvals still pending and not expired, `push_resolved` only for ones it
  pushed.
- **chat-v1 card.** In a chat conversation (Claude, or Codex with its hooks
  on; only for attachments with
  `control`, live and in history) each approval is an assistant `message`
  `approval-<approval_id>` with one part `{id:"approval", kind:"approval",
  approval_id, tool, summary, always_rules, state}`; `state` is `pending`,
  `allowed` / `always_allowed` / `denied` (answered from Astation, set at the
  hand-off), `answered_terminal`, `expired`, or `closed` (interrupted,
  released, process ended, or a remote answer not taken / outcome unknown,
  including the 630 s deadline). A state change re-sends the whole message
  with the same `messageId`: replace it. Answer from chat with `submit`
  carrying `approval` (the payload above) instead of `text`; `accepted` /
  `complete` / `error{code}` follow the receipt as for prompts.
- **Codex: "Always allow this command" is an Atem session rule (r7.2).**
  Codex's hook can't take a persistent rule (`updatedPermissions` fails
  closed), so a Codex request's `always_rules` holds one Atem rule:
  `{rule_id: "s-…", label: "Always allow `npm test` in /home/me/proj for
  this session", scope: "session"}` for a shell command only (none for
  file changes, for a command whose input carries anything besides
  `command`/`description`, or when the session already holds 32). File-change
  cards offer Allow once and Deny. Show it like Claude's rules: the
  label on the button, the scope as "this Codex session only". Answering
  `allow_always` with that `rule_id` allows this request; Atem keeps the
  rule for the rest of that agent process.

### Atem session rules: how to show them (r7.2)

- **Auto-allowed requests.** A later request of the same Codex session with
  the exact same command and folder is allowed by Atem without asking: no
  `approval_request`, no push, no lease change. Each one appears in chat as
  a card message `approval-<id>` whose part has `state: "auto_allowed"` and
  `rule_id` (the rule that allowed it), `tool` and the redacted `summary`;
  it is final (nothing to answer). Show it as a quiet note ("Allowed by your
  session rule: `npm test`") with a link to the rule. runtime.log gets one
  line naming the session, tool and rule, never the command.
- **The rule list.** Attachments with `control` get
  `{"op":"approval_rules","session_id","process_gen","rules":[{rule_id,
  label, scope}]}` (session-v1) whenever it changes, after each `sessions`
  snapshot when it isn't empty, and `rules: []` when the process ends; chat
  conversations get `opened.approvalRules` and a `rules` op
  (`approvalRules`) on change. Show the active rules on the session (e.g.
  under the chat header or in the session's details), each with a
  **Revoke** button.
- **Revoke (r7.3: needs only `control`, no lease, no `acquire`).**
  session-v1 `submit` with `kind:"approval_rule_revoke"`,
  `payload: {"rule_id": "s-…"}`, or chat-v1 `submit` with
  `approval_rule_revoke: {"rule_id": "s-…"}` instead of `text`. Send it from
  any attachment with `control`, whether or not it holds the lease: don't
  acquire or take over first, and omit `lease_epoch` (one sent is ignored,
  even a stale one). Don't put `acquire` in the payload: it is exactly
  `{rule_id}`, so `acquire` fails to decode (`unsupported_version`). A
  revoke never moves the lease, so whoever holds control keeps it. A
  view-only attachment is `forbidden`. (r7.2 required the lease; a Revoke
  tapped without control was refused `stale_lease` and the rule kept
  allowing.) The receipt
  completes once the worker dropped the rule (chat: `complete`), then the
  new list arrives. An unknown or already revoked rule is `stale_target`
  (refresh the list). A revoke also withdraws an allow written for that
  rule that Codex hasn't taken yet (Codex's own dialog asks). A rule never
  outlives the agent process: a respawn starts with none, and a new
  account, device or trust generation drops every rule (`rules: []`).
- **Rule not kept.** If the session filled up (32) between the card and the
  answer, the request is allowed once and the card ends `allowed` with a
  `note` ("allowed once; the rule wasn't kept: …"): show the note.
- Shared fixture: `approval-rule-revoke-needs-control-not-the-lease` (r7.3,
  replaces `approval-rule-revoke-needs-the-lease-and-an-active-rule`; core
  harness; the real-runtime runner lists it as not run, since its
  agent is Claude, and the real-agent Codex test covers it end to end).

### Expected relay behaviour (Astation's side)

- On `push_approval`: notify every device on the account with `control`,
  online or not — APNs on iOS (`mutable-content`, so the app can decrypt on
  device once end-to-end encryption lands) and FCM on Android — with the tool
  and summary only ("Claude on Genie wants to run `npm test`"). Use
  `approval_id` as the collapse id (APNs `apns-collapse-id`, FCM tag), and
  don't deliver after `expires_at`.
- On `push_resolved`: replace or remove that notification everywhere (same
  collapse id / tag).
- A tap wakes the app, which reconnects, authenticates, `list`s (the pending
  approval follows the snapshot) and answers (r8: without the lease and
  without `acquire`). A late tap
  gets `stale_target`: "already answered". Until the device list (account
  trust step 1) exists, only the paired Astation has an attachment, so only
  it can answer.

### Behaviour on the Atem side

- Claude: the hook runs per launch from `--settings` (600 s) while Claude
  shows its own dialog; the first answer wins. A terminal answer is seen
  from the tool running (PostToolUse) or the transcript's refusal and closes
  the card `answered_terminal`. `[claude] approvals_hook = false` in Atem's
  config.toml (default on, never asked) leaves the hook out of later
  launches: their prompts stay in the terminal.
- Codex: Atem's entries in `~/.codex/hooks.json` (one per Codex event;
  PermissionRequest is the approval hook), added after the first
  `atem agent launch codex` asks once (`[codex] hooks` in Atem's
  config.toml; `false` removes them, and until it is `true` a Codex session
  watches nothing). Codex hides its prompt while the hook
  waits (showing "Running hook"), so any input to the session — local keys
  or the lease holder's, typed or pasted — first releases the waiting hooks
  (`approval_closed{released}`), and the input that released them is
  consumed, never written: the user never saw the dialog it brings back, so
  a `y` approves nothing. The local frontend shows "Codex's approval was
  handed to the terminal; answer its dialog"; a remote `input` gets
  `written` with `"the approval was handed to the terminal; not written"`
  (a remote prompt or interrupt is `rejected`). Input after it is consumed
  too while the released hooks still run (≤ 500 ms); the next key answers
  Codex's own dialog. Codex's hook only counts when the session's agent itself started
  it.
- Approvals live in the broker's memory: after a runtime restart every
  waiting hook gets "no decision" and an `accepted` answer is `rejected`.
  Approvals pending before a broker restart or adoption are released without
  `push_resolved`: a phone notification may linger until its `expires_at`,
  and a tap on it gets `stale_target`, which the app shows as "already
  answered".
- A decision within 5 s of the hook's timeout is `not_delivered` (the hook
  might give up before taking it); a hook that ends that close to its
  timeout closes `timed_out`.
- Same-user processes that can see `ATEM_APPROVAL_DIR` can forge request
  files: the result is a fake card, never an agent action. Same-user
  attackers are out of scope.

### How to test

- `tests/fixtures/approvals/fake-agent.py` stands in for Claude (with
  `--settings`) or Codex (`FAKE_CODEX_HOOK` = the command Atem puts in
  hooks.json). It runs the real hook script for each `$FAKE_DIR/ask-<n>.json`
  (`{tool_name, tool_input, permission_suggestions?}`) and acts on the answer
  as the agent does; `terminal-yes-<n>` / `terminal-no-<n>` answer in its own
  dialog, `kill-<n>` interrupts, `stop-<n>` freezes the hook. It logs to
  `$FAKE_DIR/events` (`answer <n> allow|deny|none <message>`, `input <bytes>`).
- `cargo test --bin atem host_bridge::tests` runs the in-process broker
  tests (card + push + acquire, deny with message, terminal answer, Codex
  release before input, view-only link, the 630 s deadline, and Codex chat:
  `tests/fixtures/chat/fake-codex.py` runs the hooks.json Atem installed and
  writes a rollout — first prompt local, then a remote prompt, an interrupt
  and an approval);
  `ATEM_REAL_AGENTS=1 cargo test --test approvals_real_agents -- --ignored`
  runs the same against the real Claude Code and Codex (`codex_chat_end_to_end`);
  `cargo test --test runtime_fixtures_binary` runs the approval fixtures
  against the real runtime binary (table above).
- The rejection text Claude writes for a terminal "No" (also with a typed
  instruction) and for a hook deny (the message as it is) were checked
  against a live Claude Code 2.1.301 on 2026-10-16
  (`tests/fixtures/chat/claude/session-rejected-tool.jsonl`).

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

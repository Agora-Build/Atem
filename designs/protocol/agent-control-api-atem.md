# Agent control API: Atem's response to Astation's proposal (r2)

Status: Atem response r2, 2026-10-17. r1 answered "Agent control API:
Astation and Atem joint proposal" r1 ([Astation #52](https://github.com/Agora-Build/Astation/issues/52));
r2 answers Astation's review of r1 (four required points, accepted
corrections) and its proposal r2. Baseline: Atem `main` at `53577a7` (#75),
contract [atem-session v1 r7.2](atem-session-v1.md), [agent chat host](../agent-chat-host.md),
[chat developer guide](../agent-chat-api.md). **Today** means in the code at
`53577a7`; **r8** means the draft in the contract's appendix "r8 draft"
(exact wire shapes) with the `r8-*` fixtures in `fixtures/` (parsed, not run
until r8 ships). Nothing r8 is emitted before both sides pass its fixtures.
Addendum 2026-10-18 (§9): two user-approved r8 features, chat Send that
acquires the lease (`chat.send_acquire`, from Astation's "Chat Send and
session control" handoff) and lease-free approval answers
(`approval.lease_free`); contract appendix §F and §G, against `main` at
`976e154` (r7.3, #76 and #77). Revised 2026-10-18 for Astation's r3
review of that addendum: submitter principals and a durable control fence
(contract §H), one admission persistence rule (§I), the client rule for a
late admitting reply, and the fixture corrections (§9, end).

## 0. Answers to the r1 review

**1. Version admission (high).** Agreed. r8 `hello` carries `revision: 8`;
an r8 host refuses a `hello` without it, or with another value, with
`error{code:"unsupported_version", revision: 8}` before any attachment or
session work, and keeps refusing everything until a correct `hello` is
welcomed. `welcome` echoes `revision` and `features`; the client checks the
revision before anything else, refuses an older host outright and enables
only advertised features. Removed forms (`open.before`, `open.generation`,
the `status.page` marker) are refused explicitly with
`unsupported_version`, never read as a newest-page open. The envelope stays
`v: 1`: one gate for every family, at admission, with an explicit refusal; a
new `v` would need the same check in three parsers and still carry no
feature list. Appendix A. Fixtures: `r8-hello-without-revision-8-is-refused-before-any-attachment`,
`r8-client-refuses-a-host-without-revision-8`,
`r8-client-enables-only-advertised-features`, `r8-open-with-before-is-refused`.

**2. Page/live ordering (medium).** Resolved by an explicit ordered-stream
guarantee, no new host field. r1's unsequenced `history_page` is dropped:
every page, lookups included, is snapshotted and enqueued in one step of the
broker's single-threaded pass, as sequenced envelopes in the conversation's
one stream, between live events. **Today** this already holds for the open
page and for #75's `open{before}` page (synchronous `ChatSession::page`,
each envelope numbered by `next_head`, ending with `status.page`). A
message's `sequence` is its position: newer versions always carry higher
sequences, so a client keeps the highest-sequence version per `messageId`
and a page never replaces a newer one. Astation puts its HTTP/SSE cursor
(the conversation sequence) on each page and applies the same rule; a reopen
starts a new stream. Appendix B. Fixture:
`r8-history-page-and-live-events-share-one-ordered-stream` (host side; the
delayed-HTTP-page merge fixture is Astation's).

**3. Bounded recovery (medium).** Agreed. `history` takes exactly one of
`before`, `turn_id`, `request_id`, `next` (validated formats and lengths;
otherwise the new `invalid_request`). Every page is bounded by 50 messages,
256 KiB content and 1 MiB serialized (sum of its envelopes), lookups
included. A continuation is an opaque `next` bound to attachment,
conversation, target, generation, selector and snapshot; out of context or
stale it is `stale_target`. `end: true` means the selected result is
exhausted. `coverage` is `complete`|`partial`|`unavailable`.
`receipt.result.reply_message_ids` holds at most 32 ids plus `more: true`;
`history{request_id}` pages carry the rest; a `receipts` reply is bounded by
construction (≤ 64 × ≤ 6 KiB). Appendix B, D. Fixtures:
`r8-long-turn-is-recovered-in-bounded-pages`,
`r8-receipt-result-bounds-reply-message-ids`,
`r8-history-selectors-are-exclusive-and-validated`,
`r8-stale-or-foreign-next-token-is-stale-target`.

**4. Truncation vs gaps (medium).** Agreed; r1's "any truncated flag means
reopen" is withdrawn. Truncation is persistent coverage information
(`oldest_retained`, `truncated: true`), shown and never a reset. Interior
holes (worker backlog drops a reload can't restore) are reported as
persistent `holes: [{after_message_id, before_message_id, count?}]`, in
`history_end` and in a sequenced `coverage` event; reopen can't repair them.
A client resyncs only on a sequence gap, a fenced conversation, another
generation or `close` with a `reason`. **r8 implementation change:** today
(#75) a backlog gap makes the broker reload the worker's history and then
send `error` + `close`, forcing a reopen; in r8 it reloads, sends the
recovered messages in sequence (`after_message_id`), and reports what stayed
missing as a hole, with no close. Appendix C. Fixtures:
`r8-truncated-history-reopens-once-then-stays-live`,
`r8-client-shows-truncation-and-resyncs-only-on-a-sequence-gap`,
`r8-backlog-hole-is-reported-not-reopened`.

**Accepted corrections.** All of them, as Astation states them. Codex chat is
built (#73; Codex 0.162.1 with trusted hooks; first prompt typed in the
terminal; `opened.unavailable` adds `error_details`). Always allow is not
Claude-only (Codex: an Atem session rule, exact command and cwd, this
process). One host conversation per target and attachment, fanned out by
Astation. Pages are batches, not pending jobs; the end marker is now
`history_end`. A completed prompt receipt can be an interrupted turn (today
`detail: "done"|"interrupted"`, #75). `receipt.result` reply ids are a
projection of retained history. **Today after #75:** a broker restart
restores the worker's whole retained history (500 / 8 MiB) with approval
cards, and a card pending at adoption becomes `closed` (the host released
that approval), so recovered cards never revive a released approval; this
still needs the joint test.

## 1. Agreement and ownership

Agreed. Atem owns the original agent process, the provider adapters, agent
events, chat history and its retention, approvals (hooks, decisions, session
rules) and execution outcomes (receipts). Astation owns the protected API,
the event stream and its replay, the native UI and notifications. Astation
never invents a reply, approval resolution or successful receipt. Neither side
keeps backward compatibility; both update together. **Today**, the split already
holds in the code:
- Every chat message carries its real `origin` (`local` for prompts typed in
  the terminal, `remote` for chat submits). The prompt's user message and the
  replies to it carry its `requestId` (`chat/session.rs`, `ChatMessage`).
- Approvals reach every attachment with `control` whether or not anyone holds
  the lease. An answer may take the lease with it (`acquire: true`). The
  session inbox (`approval_request`/`approval_closed`) is authoritative (§6a).
  In r8 answers no longer touch the lease (§9).
- Every remote mutation is a session-v1 submission with a durable receipt
  (`FileJournal`, fsync per transition). A duplicate returns the recorded
  receipt and is never run again. A prompt's text leaves the journal when its
  receipt leaves `accepted`.

## 2. Q1: providers and capabilities

**Today.**

| | Claude Code | Codex |
|---|---|---|
| Versions | 2.1.x; verified on 2.1.301 | built in #73; verified on codex-cli 0.162.1 |
| Sources | per-launch `--settings` hooks (SessionStart, UserPromptSubmit, Pre/PostToolUse, Notification, Stop) plus the session JSONL transcript | Atem entries in `$CODEX_HOME/hooks.json` (`chat/codex/mod.rs` `EVENTS`) plus the rollout JSONL |
| Descriptor `capabilities` | `["terminal-v1","chat-v1"]` once SessionStart arrives (15 s, else a notice; a late one still enables it) | `["terminal-v1","chat-v1"]` from launch when Atem's hooks are installed (`[codex] hooks` yes) |
| `opened.unavailable` | `["streaming","reasoning"]` | `["streaming","reasoning","error_details"]` |
| Always allow | the provider's own `permission_suggestions` (persistent rule) | an Atem session rule (`scope:"session"`, r7.2): Codex fails closed on `updatedPermissions` |

- **Capability model.** A healthy adapter puts `chat-v1` in the descriptor's
  `capabilities`. `opened.unavailable` lists what that adapter's chat can't
  provide (`adapter.rs` `UNAVAILABLE_*`), so clients state it instead of waiting.
  `open` without chat-v1 gets `error{code:"busy"}` with the text "chat is not
  available for this agent[: reason]". Process state and `activity`
  (`ready`/`working`/`waiting`/`unknown`) are separate descriptor fields.
- **Codex first-prompt rule.** Codex reports nothing before its first prompt
  (SessionStart is lazy). Chat opens from launch, but status stays `unknown` and
  a chat submit is refused with `FIRST_PROMPT` ("type a first prompt in the
  terminal: …"). This follows the 2026-10-17 ruling: text typed into Codex's
  startup dialogs could answer them. The first hook pins the session and names
  the rollout. (`agent-chat-host.md` was corrected in #75.)
- **Correction to the proposal.** "Always allow uses an exact provider-offered
  rule, Claude only" is wrong since r7.2. Codex cards offer allow once, deny,
  and "Always allow `<command>` in <cwd> for this session". Atem's worker keeps
  that rule for the agent process and answers a later byte-equal request itself
  (card `auto_allowed` with `rule_id`, no approval, no push).
- **Which Codex qualifies.** A Codex build qualifies when (a) its `hooks.json`
  runs these events with stdin JSON carrying `session_id`, `transcript_path`
  and `turn_id`: SessionStart, UserPromptSubmit, Pre/PostToolUse,
  PermissionRequest (synchronous), Stop, Interrupt and SessionEnd, and the user
  has trusted Atem's entries in `/hooks`, and (b) its rollout
  `rollout-*-<session_id>.jsonl` writes `event_msg` records `task_started{turn_id}`,
  `item_completed{turn_id, item}` (with items `UserMessage{id, content[{type:"text",text}]}`,
  `AgentMessage{id, content[{type:"Text",text}], phase}` and
  `CommandExecution{id, command[], …}`), `task_complete{turn_id}` and
  `turn_aborted{turn_id}`. Atem verifies this on 0.162.1 only. Other versions are
  untested.
- **Format change.** A known record that lacks the ids the reader relies on is a
  fatal `Problem`. Chat is withdrawn: open conversations get `error` and `close`,
  `chat-v1` leaves the descriptor, and the terminal and approvals keep working.
  The reader skips record types and items it doesn't know. Claude behaves the
  same way for a transcript format change.

## 3. History

**Today** (`53577a7`): `open` sends `opened` (0) and the newest page (50
messages / 256 KiB) as sequenced `message{history:true}`, with no end
marker. `open{before}` on an open conversation pages without a reset: the
older page continues the live sequence and ends with a sequenced `status`
carrying `page{before, count, start}` (an empty page is the marker alone).
A `before` not retained, or of another `generation`, is `stale_target`. A
worker backlog `gap` triggers a reload of the worker's history, then `error`
"the chat history was incomplete…" and `close`. Retention: 500 messages /
8 MiB per `process_gen` in the broker and the worker (one message ≤ 128 KiB);
the worker's backlog while no broker reads it is 4096 items / 8 MiB, oldest
dropped first (`gap`); adoption restores the whole retained history with
cards. No chat history on disk. `/clear`, resume and Codex `/new` keep the
generation and close conversations ("switched"); a new process starts empty.

**r8** (appendix B, C): `open` ends with `history_end`; `history` with one
selector; bounded pages with `next`, `end`, `coverage`, `oldest_retained`,
`truncated`, `holes`; the `coverage` event; `close.reason`.

## 4. Request → reply recovery

**Today:** a completed `prompt` receipt's `detail` is the turn outcome
(`done`|`interrupted`, journaled as that word only). Messages carry
`turnId`, and a remote prompt's messages carry its `requestId`. The broker's
turn id per receipt is in memory only.

**r8** (appendix D): `result{turn_id, user_message_id, outcome,
reply_message_ids ≤ 32, more, replies}`; ids only in the journal, reply ids
computed from retained history when sent; the rest by
`history{request_id}`. An `executing` prompt across a broker restart stays
`outcome_unknown` without `result`, is never re-run, and its messages remain
findable by `history{request_id}` while retained.

## 5. Q4: approval parts

**Today** (`adapter.rs` `ApprovalCard`, `host_bridge.rs`, contract §6a). Each
approval of a session is one assistant `message` with `messageId`
`approval-<approval_id>` and one part. Every state change re-sends the whole
message, and the client replaces it:

```json
{"messageId":"approval-88888888-…","role":"assistant","turnId":"…","createdAt":1760600000000,
 "parts":[{"id":"approval","kind":"approval","approval_id":"88888888-…","tool":"Bash",
           "summary":"npm test","state":"pending",
           "always_rules":[{"rule_id":"s-0123456789abcdef","label":"Always allow `npm test` in Atem for this session","scope":"session"}]}]}
```

- `state` (`ApprovalCardState`): `pending`; then `allowed`, `always_allowed` or
  `denied` (answered remotely, set at the hand-off); `answered_terminal`;
  `expired` (`timed_out`); `closed` (`interrupted`, `released`, `process_ended`,
  or a remote answer the agent didn't take, whose outcome is unknown, or that
  passed the 630 s deadline); `auto_allowed` (a session rule allowed it; final
  on arrival, with `rule_id` and `always_rules: []`). `note` is a short
  explanation, e.g. that the session rule wasn't kept (`ApprovalRuleNotKept`).
- Correlation: `approval_id` equals the session `approval_request.approval_id`.
  A card leaves `pending` when `approval_closed` is sent. The session inbox
  decides whether an answer is possible. A card is display only and never
  authority. Cards go only to conversations of attachments with `control`,
  in history and live. `opened.approvalRules` and `rules` events carry the
  active session rules.
- Errors for an approval answered from chat follow its receipt:
  `rejected`/`outcome_unknown` with the receipt's `detail`, or the admission
  code (`stale_target` for a closed or unknown approval and for a `rule_id`
  it didn't offer, `stale_lease`, `forbidden`, `session_closed`).
- Withdrawal: when chat is withdrawn, switched or restarted, conversations
  get `error` and `close`. The approval stays in the session inbox and can be
  answered there (approvals are not a chat capability). A broker restart
  releases every approval ("no decision", `approval_closed{released}`); since
  #75 its cards survive in history as `closed`.

**r8** (feature `approval.card_reason`): every final card except
`auto_allowed` carries `reason`, the `approval_closed` reason
(`answered_remote`, `answered_terminal`, `interrupted`, `timed_out`,
`released`, `process_ended`). Clients then never have to map `closed` back to a
cause. The state names above stay as they are.

## 6. Versioning

r8, gated by `hello.revision` (appendix A, answer 0.1). Features:
`chat.history_end`, `chat.history`, `chat.lookup`, `chat.coverage`,
`receipt.result`, `approval.session_rules` (r7.2, shipped),
`approval.card_reason`, `chat.send_acquire`, `approval.lease_free` (§9). A side advertises or uses a feature only after its
`r8-*` fixtures pass in Rust (Atem) and Swift (Astation).

## 7. Work

**Atem work** (S ≤ 1 day, M ≤ 3 days):

| # | Item | Size |
|---|---|---|
| A1 | `hello.revision` admission, `welcome.revision`/`features`, refusal of removed forms | S |
| A2 | `history_end`; `history` with selectors, validation, three bounds, `next` tokens (MAC, context binding) | M |
| A3 | Coverage: `oldest_retained`, `truncated`, holes; backlog gap → reload + `coverage` event (replaces #75's error + close); `close.reason` | M |
| A4 | `receipt.result` (journal ids with `completed`; reply ids from history, ≤ 32 + `more`) | M |
| A5 | Card `reason`; contract r8 text replaces r7.2 parts; docs | S |
| A6 | Fixture runner actions (schema.md "r8 draft"), drop `requires`; live check with Claude 2.1.301 and Codex 0.162.1 | M |
| A7 | `chat.send_acquire`: submit-level `acquire`/`takeover`/`expected_controller`, admission and commit after the durable write, `lease` on the admitting reply, `controller` on `lease_held`, prompt static checks at admission, submitter principal and durable control fence (§H), the admission persistence rule with its refusal list (§I) | M |
| A8 | `approval.lease_free`: drop the lease check and `acquire` (refused), ignore `lease_epoch`; docs | S |

**Joint fixtures** (in `fixtures/`, r8 draft, NOT RUN until r8 ships):
`r8-hello-without-revision-8-is-refused-before-any-attachment`,
`r8-client-refuses-a-host-without-revision-8`,
`r8-client-enables-only-advertised-features`,
`r8-open-with-before-is-refused`,
`r8-history-page-and-live-events-share-one-ordered-stream`,
`r8-long-turn-is-recovered-in-bounded-pages`,
`r8-truncated-history-reopens-once-then-stays-live`,
`r8-client-shows-truncation-and-resyncs-only-on-a-sequence-gap`,
`r8-backlog-hole-is-reported-not-reopened`,
`r8-receipt-result-bounds-reply-message-ids`,
`r8-history-selectors-are-exclusive-and-validated`,
`r8-stale-or-foreign-next-token-is-stale-target`, and for §9 the fourteen
§F fixtures (`r8-send-*`, `r8-two-simultaneous-sends-acquire-once`,
`r8-ownership-is-checked-at-admission-not-as-displayed`,
`r8-local-input-wins-over-a-send`, `r8-stale-takeover-confirmation-is-refused`,
`r8-duplicate-send-never-reacquires-or-replays`,
`r8-disconnect-right-after-acceptance`, `r8-failed-persistence-changes-no-lease`,
`r8-expired-lease-is-checked-at-admission`,
`r8-revoked-control-refuses-the-send-and-its-queued-prompt`,
`r8-process-replaced-before-dispatch`), the §H/§I and late-reply ones
listed in §9, and the five §G ones (`r8-approval-*`).
Still to write with the implementation: card `reason`, `receipt.result`
after a broker restart and for an interrupted turn.

## 8. Notes on Astation's API layer (suggestions, Astation owns these)

- **One host conversation per target.** Atem allows at most 8 chat
  conversations per session (`MAX_CONVERSATIONS`). A ninth closes the oldest
  with `close`. Astation's link is one attachment, so per-reader `open`s for
  native UI, API clients and scripts would evict each other. Suggestion: keep
  one host conversation per (`session_id`, `process_gen`) and fan it out to every
  `chat_id` in Astation's read model. An attachment without `control` sees no
  cards, so open the shared conversation from the controlling attachment and
  filter per reader.
- **SSE replay is Astation's.** Atem provides `generation`, a per-conversation
  `sequence` (also each message version's position), the session registry
  `seq`/`runtime_epoch` and receipts. Resynchronize by reopening only on a
  sequence gap, a fenced conversation, another generation or `close` with a
  `reason`; truncation, holes and `coverage` events are shown, never a
  reason to reopen. Atem keeps no replay window per client.
- **Notification triggers** from host events:

| Notification | Host event |
|---|---|
| Approval needed / resolved | session `approval_request` / `approval_closed` (not the chat card) |
| Turn completed | chat `complete` (`outcome`), or `receipt` `completed` with `result.outcome` for API prompts |
| Request rejected / unknown | `receipt` `rejected` / `outcome_unknown` |
| Agent waiting | descriptor `activity:"waiting"` |
| Session ended | descriptor `state` `exited`/`interrupted`/`recovery_required`/`removed` |
| Control lost | lease `stale_lease` / registry `controller` change; attachment fenced (`stale_target`) |

Backfilled `message{history:true}` and repeated `approval_request` after `list`
are catch-up and must not create new alerts.

**Voice readiness.** `messageId`, `turnId`, `requestId`, `origin`,
`createdAt` and the receipt `result` ids are stable within a `process_gen`. A
later voice-brainstorm feature (`designs/voice-context.md`, branch
`docs/voice-context`) can cite turns and messages by these ids without new
host state. That feature is not designed here.

## 9. Chat Send and lease-free approvals (addendum, 2026-10-18)

**Chat Send (`chat.send_acquire`, appendix §F).** This answers the
handoff's open points:

- **Shape.** A `prompt` submit (or chat-v1 `submit` with `text`) carries
  `acquire: true`, and for a confirmed takeover also `takeover: true` and
  `expected_controller: {controller_session, lease_epoch}`, the lease the
  dialog showed. The binding then has no `lease_epoch`. Holding the lease,
  a client may still send the r7 form with `lease_epoch`, checked as
  today.
- **Transaction.** One step of the broker's single-threaded pass. It checks
  binding, fields, duplicate, `control`, a running session with `chat-v1`,
  then ownership at that instant (expiry applied first), the prompt's
  static checks, limits and the epoch reservation. Then the durable
  `accepted` write, and only then the lease grant or takeover,
  `lease_changed` to the others, and the reply with
  `lease{lease_epoch, ms_left}`. Any failure before the commit means no
  lease change and no execution. A failed journal write is `busy`, a
  definitive refusal (§I below). This is today's approval-`acquire` order
  (`lease_to_acquire` → journal append → `grant`), with the takeover made
  explicit.
- **Codes.** `lease_held` (now with `controller`) for another holder or a
  stale confirmation; `stale_lease` for the same controller on another
  attachment or a wrong `lease_epoch` in the r7 form; `forbidden` without
  `control`, before any lease state; `invalid_request` for the field rules
  and a prompt's static checks; `busy` for a failed durable write or a
  session without `chat-v1`; `unsupported_version` when the feature isn't
  advertised.
- **Identity.** The flags are admission parameters, outside the digest and
  the immutable request, like `lease_epoch`. A duplicate returns the
  recorded receipt and never acquires, takes over or reruns, so the client
  keeps one `request_id` and text from the first Send through refusal,
  confirmation and uncertain delivery. A retry can't become
  `request_id_reused`, which would tempt a second run.
- **Scope.** `prompt` only. `interrupt` would act on another controller's
  turn, the silent ownership change Send must never make. `stop` ends every
  lease anyway. Both still need an explicit Take Control.
- **Renewal.** Astation renews: the native app while that session's chat or
  terminal view is in the foreground, then `release`. For an API caller,
  renewal happens only while the caller keeps renewing; an abandoned caller
  loses control within 15 s. The host never renews implicitly: not on chat
  reads, queries, duplicates, a Send under the own lease, or execution.
- **New host rule.** A principal that loses `control` is fenced durably
  (below): its leases are revoked and its not-yet-executing accepted work
  rejected (`control revoked`). Local input still revokes, and the
  adapter's unsent-input check still refuses a queued prompt at dispatch.
- **Late admitting reply.** The client applies a receipt's `lease` only if
  the submit is outstanding on the current attachment, no newer epoch for
  that session arrived since it was sent, and the deadline (send time +
  `ms_left`) is ahead; otherwise it stays a viewer (contract §F).

**Lease-free approvals (`approval.lease_free`, appendix §G).** User decision
2026-10-18, replacing r7's answer-takes-the-lease. An answer needs a verified
attachment with `control` and the exact pending request. It never takes,
needs or moves the lease, and a `lease_epoch` in its binding is ignored.
`acquire` is refused `unsupported_version` (removed form). The first
admitted answer wins and later or closed ones are `stale_target`. Rules
still need the exact offered rule and scope (r7.2), and revoke stays r7.3.
Card states and push are unchanged.

**r3 review answers (2026-10-18).**

- **Finding 1, revoked control (§H).** Accepted work records its submitter
  *principal* (the authenticated identity: today the one paired Astation;
  with account trust each device grant) and the principal's `control_gen`.
  Revoking `control` writes a durable fence (`control_gen` raised) before
  anything else; queued work of every attachment of that principal, live
  or gone, is rejected `control revoked`, and the dispatch check (also for
  work recovered after a restart or adoption) compares the recorded
  `control_gen` with the current one. Disconnect, expiry and a
  same-permission reconnect keep work; regaining control doesn't revive
  work from before the revocation. After a restart, recovered work runs
  only once its principal is confirmed in that run (60 s, else `control
  not confirmed`), so a fence lost to a failed write is learned again
  first.
- **Finding 2, persistence (§I).** Accepted means the `accepted` record is
  durable. A failed admission write is `busy` and definitive: nothing
  changes, the journal halts until restart, the refusal is recorded on a
  separate refusal list first, and at restart the request is `rejected`
  ("acceptance not confirmed") whether or not its record reached the disk.
  §6's double-I/O exception and the same-id retry after such a `busy` are
  removed. If even the refusal can't be recorded, the host sends no `busy`
  (delivery is uncertain and the journal decides at restart). A resend uses
  a new `request_id`: the old one is final, so it can't run twice.
- **Finding 3.** The two captures in
  `r8-failed-persistence-changes-no-lease` are at the step level (the
  scenario now follows §I); no other r8 fixture had one inside `match`.
- **Other obligations.** `chat_opens` is 2 in
  `r8-long-turn-is-recovered-in-bounded-pages`; `wire_bytes` is 675 in
  `r8-client-shows-truncation-and-resyncs-only-on-a-sequence-gap`; the
  schema's `open_approval` row follows control-based delivery. New
  fixtures: `r8-approval-answer-keeps-the-holders-deadline` (non-zero
  clock, deadline unchanged, queued input kept, no holder),
  `r8-delayed-send-reply-does-not-regrant-lost-control` and
  `r8-client-delayed-send-reply-never-restores-control`,
  `r8-revoked-control-fences-work-across-reconnect-and-restart`,
  `r8-control-fence-holds-when-a-rejection-write-fails`,
  `r8-recovered-work-needs-its-principal-confirmed`,
  `r8-double-write-failure-takeover-never-runs`,
  `r8-crash-after-durable-acceptance-grants-no-lease`. Astation owns its
  API/native arbitration and renewal tests; approval persistence, the
  terminal-answer race and catch-up are run against the r8 implementation.

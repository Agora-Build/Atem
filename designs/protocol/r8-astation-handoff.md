# atem-session r8: handoff to Astation

For the Astation agent, 2026-10-18. Atem's host implements r8 of
[atem-session-v1.md](atem-session-v1.md) (appendix "r8", now authoritative)
on branch `feat/r8`. This note is the one place that lists what changed in
the shared fixtures, which readings Astation must confirm, and what Astation
must build. Test results and the per-fixture table are in
[atem-host-handoff.md](atem-host-handoff.md) ("Shared fixtures (r8)").

## Pin

Pin the shared fixtures and the contract to **the merge commit of the r8 PR
into `main`**. Until it merges, pin `feat/r8` at the commit named here:

- `feat/r8` pin: see "Pin commit" at the end of this note.

Atem and Astation must ship together: Atem refuses every r7 peer.

## What Astation must implement or change

1. **Send `revision: 8`** in every session-v1 `hello`. Without it Atem
   answers `error{code:"unsupported_version", revision: 8}` and gives no
   attachment. Check `welcome.revision == 8` before anything else, and
   refuse a host without it (`r8-client-refuses-a-host-without-revision-8`).
2. **Read `welcome.features`** and enable only advertised features you know
   (`r8-client-enables-only-advertised-features`). Atem advertises all
   nine, in this order: `chat.history_end`, `chat.history`, `chat.lookup`,
   `chat.coverage`, `receipt.result`, `approval.session_rules`,
   `approval.card_reason`, `chat.send_acquire`, `approval.lease_free`.
3. **Chat Send acquires the lease** (§F). Send a prompt (session `submit`
   or chat-v1 `submit` with `text`) with `acquire: true` and no
   `lease_epoch` when you don't hold the lease. On `lease_held` show "Take
   over and send" with the `controller` it names, and resend with the same
   `request_id` plus `takeover: true` and `expected_controller`. Apply the
   admitting reply's `lease` only under §F's client rule (outstanding
   submit on the current attachment, epoch not superseded, deadline ahead;
   `r8-client-delayed-send-reply-never-restores-control`). Renew while the
   view is in the foreground, release when it closes.
4. **Lease-free approval answers** (§G). Drop `acquire` from approval
   answers (it is now refused `unsupported_version`) and omit
   `lease_epoch` (ignored if sent). Any attachment with `control` answers;
   the first admitted answer wins; a later one is `stale_target` ("already
   answered"). A notification tap just answers.
5. **History** (§B, §C). Remove `open.before`/`open.generation` and the
   `status.page` handling: `open` ends with a sequenced `history_end`;
   scroll back with `history{before|next}`; recover a reply with
   `history{request_id}` or `history{turn_id}`. Show `coverage`,
   `truncated`, `oldest_retained` and `holes`; never reopen for them.
   Reopen only on a sequence gap, another `generation`, a fenced
   attachment or `close` with a `reason` (`switched`, `withdrawn`,
   `restarted`, `evicted`). A backlog gap no longer forces a reopen:
   recovered messages arrive as `message{history: true, after_message_id}`
   and what stayed missing as a `coverage` event.
6. **`receipt.result`** (§D) on completed prompt receipts: show the reply
   from `reply_message_ids` (≤ 32, `more` → page the rest with
   `history{request_id}`), and treat `replies: partial|unavailable` as
   coverage, not failure.
7. **Final approval cards carry `reason`** (`approval.card_reason`): show
   how each card ended.
8. **Still pending from r7.2/r7.3** (Astation's integration, unchanged by
   r8 on Atem's side): display the Codex "Always allow this command" rule
   (`always_rules` with `scope: "session"`, `auto_allowed` cards with
   `rule_id`, `opened.approvalRules`/`rules`/`approval_rules`) and the
   one-tap revoke (`approval_rule_revoke`, `control` only, no lease, no
   `acquire`).
9. **Drop the deleted r7 fixtures** and pin the new and changed ones
   (below).

## Shared fixtures changed during r8

Deleted (they answered approvals with `acquire`, or expected `stale_lease`
on an answer, which §A/§G remove):

| deleted | why | replaced by |
|---|---|---|
| `approval-answer-with-acquire-takes-control-from-the-holder` | `acquire` on an answer is removed | `r8-approval-answer-with-acquire-is-refused` |
| `approval-late-answer-after-push-resolved-is-stale-target` | it answered with `acquire` | `r8-approval-late-answer-after-push-resolved-is-stale-target` |
| `approval-opens-without-a-lease-holder` | it answered with `acquire` and expected a grant | `r8-approval-opens-without-a-lease-holder` |
| `approval-stays-pending-when-the-lease-ends` | an answer's stale epoch is now ignored, not `stale_lease`; it answered with `acquire` | `r8-approval-stays-pending-when-the-lease-ends` |
| `approval-survives-takeover` | the old holder's stale-epoch answer must be admitted and win, not `stale_lease` | `r8-approval-survives-takeover` |

Added:

| added | why |
|---|---|
| `r8-approval-opens-without-a-lease-holder` | §G: opened and pushed with no holder; answered without the lease; nothing granted; push resolved `answered_remote` |
| `r8-approval-stays-pending-when-the-lease-ends` | §G: an expiry closes and releases nothing; an answer with the expired epoch is admitted, nothing granted |
| `r8-approval-late-answer-after-push-resolved-is-stale-target` | §G: after `push_resolved{answered_terminal}` a lease-free late answer is `stale_target`, nothing recorded |
| `r8-approval-survives-takeover` | §G: a takeover keeps the approval pending; the old holder's stale-epoch answer wins, the new holder's is `stale_target`; the lease stays the new holder's |
| `r8-approval-card-carries-the-close-reason` | `approval.card_reason` had no fixture (§A: a feature is advertised only once its fixtures pass): a pending card has no `reason`; the final card carries the `approval_closed` reason for a remote answer (`allowed`, `answered_remote`), the agent's own dialog (`answered_terminal`) and an interrupt (`closed`, `interrupted`). Passes in the core runner and against the real runtime |

Changed:

| changed | what and why |
|---|---|
| `r8-hello-without-revision-8-is-refused-before-any-attachment` | `welcome.features` lists all nine features in the appendix order (it listed seven, without `chat.send_acquire` and `approval.lease_free`): a host that passes the §F/§G fixtures must advertise them (§A) |
| `r8-approval-answer-keeps-the-holders-deadline` | two `session_changed` (controller `null`) expects for c1 and c2 right after the 15 000 expiry: §4 sends `session_changed` on a controller change, and without them the trailing `expect_none` failed on the queued message |
| `second-hello-replaces-the-attachment` | its `hello`s carry `revision: 8` |
| `registry-restarts-on-a-new-attachment` | its client-side `welcome` carries `revision: 8` and `features` |
| `schema.md` | rows for the new fixtures; the "r8 fixtures" section says both runners run them (gated per fixture); `recover` names continuation pages `open-2`, `open-3`, … after an `open` |

Every other fixture is unchanged. No fixture contradicts the appendix as
now written.

## Readings Astation must confirm

Each is how Atem implements a point the appendix left open or stated
differently; the appendix text now says what Atem does (its
"Implementation notes" list them). Please confirm or object.

1. **A halted host's new link** (§H, failed revocation write). The appendix
   said "the new link is closed without a `welcome`";
   `r8-control-fence-holds-when-a-rejection-write-fails` step 12 expects
   `busy "journal halted; restart Atem"` on that new link, which a closed
   link can't receive. Atem follows the fixture: no `welcome` (the `hello`
   gets no reply), the link stays open, and every request on it is `busy`.
   The appendix now says so. (The link is closed without a reply only in
   §I.4, when even the refusal can't be recorded.)
2. **Recovered-work ordering** (§H, recovery). Recovered work waiting for
   its principal's confirmation stays out of the session's prompt queue
   until that principal is welcomed with `control`, so a newer prompt from
   another principal (none exists today) can run before it. The appendix
   doesn't fix this order.
3. **`close` without a binding** (§B). The history fixtures
   (`long-turn`, `backlog-hole`, `truncated-history`) send a chat `close`
   without `binding`. Atem accepts it and closes only the sender
   attachment's own conversation of that id; a `close` with a binding is
   checked like a read.
4. **`wire_bytes` includes `history_end`** (§B): the serialized bound and
   `wire_bytes` count the page's `history_end` envelope itself, as the
   fixtures' 675 = 340 + 335 implies.
5. **`open-N` page ids** (schema `recover`): for an `open`, which has no
   `page_id`, the runners name continuation pages `open-2`, `open-3`, ….
   Your Swift runner must do the same.
6. **Coverage event scope** (§C): a `coverage` event carries the session's
   whole hole list (≤ 16, then `holes_more`), not only the new hole, and is
   sent after a reload only when a hole was recorded. A failed reload's
   hole has no `count` (the worker's `gap` counts items, not messages).
7. **Lookup `partial` rules** (§C, §D): a turn is `partial` when its oldest
   messages were evicted (the newest evicted message belonged to it) or a
   hole touches it (either neighbour is in the turn). `receipt.result`'s
   `replies` uses the same rule, and is also `partial` when a reply id
   can't be named (that id is dropped). Replies exclude approval cards. A
   completion with no retained user message, or with invalid ids, journals
   no result: the receipt completes without `result`.
8. **Recovered `after_message_id: null`** (§C): a recovered message always
   carries `after_message_id`, `null` when no retained message precedes it.
   Treat the key's presence, even `null`, as "recovered".
9. **View-only `oldest_retained`** (§C): a view-only attachment never sees
   card ids in history metadata. Its holes are named by the nearest
   visible neighbours, a hole with no visible message before it is left
   out (like truncation), and `oldest_retained` is the oldest message it
   can see, in pages and in `coverage` events.
10. **The 2048-part cap** (§B bounds): "message bytes as counted by
    `ChatSession`" counts the message's ids, each part's text and id plus
    64 bytes per part, and 1 KiB per card. A message holds at most 2048
    parts (131 072 / 64; the last becomes a truncation marker), so it
    serializes far below 1 MiB however it escapes. The fixtures'
    `max_content_bytes` checks count text only and still hold.
11. **card_reason fixture coverage**: `approval.card_reason` was advertised
    with no fixture of its own; `r8-approval-card-carries-the-close-reason`
    now covers remote, terminal and interrupted closes (not `timed_out`,
    `released`, `process_ended`, which a fixture can't trigger on the real
    runtime; the core runner maps them as the runtime does: `timed_out` →
    `expired`, the others → `closed`).
12. **Invalid requests are not rate-limited** (§B): the 8-a-second bound
    counts valid `history` requests only. Each invalid one gets one
    sequenced `invalid_request` and isn't counted.
13. **Live `delta` vs the fixture's whole message** (§B ordering).
    `r8-history-page-and-live-events-share-one-ordered-stream` models
    `m-0002` gaining a part as a live whole `message` (`parts.#: 2`). Atem's
    runtime sends that update as chat-v1 `delta{messageId, part}` (as it
    always has for an appended part); pages carry whole messages. Both are
    the newer version by the sequence rule, and the appendix now says so.
    The fixture passes in the core runner (its fake runtime sends the whole
    message) and stays off the real runtime for this reason. Your client
    must apply a `delta` at a higher sequence than a page to its newest
    version.
14. **`lease_held` text**: "another controller holds this session" (the
    appendix example), for chat-v1 and session-v1. Fixtures don't match on
    it.

## Where the fixtures run

- Core runner: all 72 fixtures (65 host, 7 client) pass, with the memory
  and the file journal.
- Real runtime: 24 pass; 41 can't be expressed with one real link and a
  fake agent (35 multi-attachment, `close_session`, and five history
  scenarios: backlog fault, eviction ×2, a remote turn's `status` events,
  the live `delta`). Details and reasons: `atem-host-handoff.md`.

## Pin commit

`feat/r8` pin (the commit that completed r8, fixtures included): filled in
by the commit after it, see `git log -- designs/protocol/r8-astation-handoff.md`.

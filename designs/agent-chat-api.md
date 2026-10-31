# Building on Agent chat

A developer guide for clients of Atem's agent chat: Astation's native chat, a
mobile app, a Discord-style bot, a headless tool. It tells you what to send,
what you get back and what to do when something goes wrong.

This is a guide, not the contract. Contracts: `designs/protocol/atem-session-v1.md`
(r8, its appendix authoritative: revision admission, history pages and
coverage, receipt results, chat Send that acquires the lease, lease-free
approval answers; plus sessions, leases, receipts, approvals and Atem session
rules from r7.x; on a host with a device list, r9: the same messages
inside an end-to-end `atem-ch1` channel, appendix "r9"), `designs/agent-chat-host.md`
(chat-v1 host side) and `designs/protocol/atem-host-handoff.md` (what Astation
and the relay do). Field names below were checked against `src/chat/wire.rs`,
`src/chat/session.rs`, `src/chat/history.rs`, `src/chat/adapter.rs`,
`src/session_protocol/` and `src/runtime/host_bridge.rs`.

## 1. Model

```
agent process (claude / codex, in an atem worker)
   └─ session  ses-xxxxxxxxxxxx      the original agent process and its conversation
        ├─ terminal-v1               canonical screen (not covered here)
        └─ chat-v1 conversations     up to 8 views of the same session
Atem runtime (host) ── authenticated Astation link ── relay ── your client
```

- **Session** = one original agent process the user launched with
  `atem agent launch`. Chat never starts another agent or session. The session
  id is `ses-` + 12 base32 characters and is also the chat `agentId`.
- **Conversation** = a client's view of a session, named by your own
  `conversationId` (1-128 bytes). It holds no state of its own: closing it
  loses nothing, and the session keeps running with no conversation open.
- **Generation** = the agent process (`process_gen`, a UUID). Every chat event
  carries `generation` and a per-conversation `sequence` (1, 2, ...). A restart
  is a new generation.
- **Messages** have `messageId`, `role` (`user`/`assistant`), `turnId`,
  `createdAt` (unix ms), `parts`. User messages carry `origin`: `local` (typed
  in the terminal) or `remote` (a chat/session-v1 prompt, then also with
  `requestId`).
- Content comes from the agent's own session log (Claude transcript, Codex
  rollout), never from the screen. Atem never infers "done" from silence.
- Chat rides the session-v1 attachment. The link is authenticated by the
  paired Astation; your client hears about it only through the relay/Astation.

Envelopes:

```json
{"type":"session","data":{"v":1,"op":"…","id":"<uuid>", …}}
{"type":"agentChat","data":{"v":1,"op":"…","conversationId":"c1","agentId":"ses-aaaaaaaaaaaa", …}}
```

Unknown fields are ignorable everywhere; new fields are always optional.

## 2. Lifecycle

### 2.1 Attach and discover

1. `hello` (with `"revision": 8`, required) -> `welcome`. A `hello` without
   it (or with another number) gets `error{code:"unsupported_version",
   revision: 8}` and no attachment. In compatibility mode (today) every
   `hello` gets a new `controller_session` and `attachment_gen` and holds no
   lease. `welcome` has `revision: 8`, `features` (Atem advertises all nine
   r8 features: `chat.history_end`, `chat.history`, `chat.lookup`,
   `chat.coverage`, `receipt.result`, `approval.session_rules`,
   `approval.card_reason`, `chat.send_acquire`, `approval.lease_free`; use
   only what is listed), `account_id`, `atem_device_id`, `host_trust_gen`,
   `runtime_gen`, `controller_session`, `attachment_gen`, `client_kind`,
   `permissions` (`view`, `control`), `authorization_ms_left`,
   `server_time`. Refuse a `welcome` without `revision: 8`.
   Only an attachment with `control` can submit, answer approvals or see
   approval cards.
2. `list` -> `sessions`, then `session_changed` events (`seq` per attachment;
   a gap or lower `runtime_epoch` rules are in session-v1 section 4).

```json
{"session_id":"ses-abcdefghijkl","process_gen":"22222222-2222-4222-8222-222222222222",
 "provider":"claude","cwd_label":"Atem","state":"running","activity":"ready",
 "activity_since":1760500000000,"controller":null,
 "capabilities":["terminal-v1","chat-v1"],"created_at":1760490000000}
```

Show chat for a session only when `capabilities` contains `chat-v1` (per
descriptor, not per provider). Codex has it only when the user allowed Atem's
Codex hooks; without it, a prompt is `rejected` with "chat is not available
for this agent; use the terminal".

Every message that targets a session carries a `binding`:

```json
{"target":{"account_id":"account-a","atem_device_id":"host-a","host_trust_gen":1,
           "session_id":"ses-abcdefghijkl","process_gen":"22222222-…"},
 "attachment_gen":"33333333-…","lease_epoch":7}
```

`lease_epoch` is present on mutations under your lease (a submit without
`acquire`, `renew`, `release`, terminal input) and absent on reads (`open`,
`history`, `close`, `receipt_query`), on `acquire`, on an acquiring Send and
on approval answers and rule revokes (ignored if sent). A mismatch of
anything else is `stale_target`: re-list.

### 2.2 Open a conversation

```json
{"type":"agentChat","data":{"v":1,"op":"open","conversationId":"c1","agentId":"ses-abcdefghijkl",
 "binding":{"target":{…},"attachment_gen":"33333333-…"}}}
```

Reply, in order: `opened` (sequence 0), the newest page as
`message{history:true}` events, then a sequenced `history_end`.

```json
{"v":1,"op":"opened","conversationId":"c1","agentId":"ses-abcdefghijkl",
 "generation":"22222222-…","sequence":0,
 "status":{"state":"ready","since":1760500000000},
 "unavailable":["streaming","reasoning"],"approvalRules":[]}
{"v":1,"op":"message","conversationId":"c1","agentId":"ses-abcdefghijkl",
 "generation":"22222222-…","sequence":1,"messageId":"m1","role":"user","origin":"remote",
 "turnId":"t1","requestId":"4444…","createdAt":1700000000000,
 "parts":[{"kind":"text","id":"p1","markdown":"run the tests"}],"history":true}
{"v":1,"op":"history_end","conversationId":"c1","agentId":"ses-abcdefghijkl",
 "generation":"22222222-…","sequence":2,
 "page":{"selector":"newest","count":1,"content_bytes":120,"wire_bytes":640,"end":true,
         "coverage":"complete","oldest_retained":"m1","truncated":false,"holes":[]}}
```

- A conversation is **one ordered stream**: pages and live events share its
  `sequence`, and a page is built in one host step, so nothing of that
  conversation comes between its envelopes. Keep per `messageId` the version
  with the highest sequence (a message that grows is sent whole again and
  replaces the earlier version); a page never replaces a newer version. Pages carry whole messages.
- Older pages and lookups:

```json
{"type":"agentChat","data":{"v":1,"op":"history","conversationId":"c1","agentId":"ses-abcdefghijkl",
 "generation":"22222222-…","page_id":"p7","before":"m40",
 "binding":{"target":{…},"attachment_gen":"33333333-…"}}}
```

  Exactly one selector: `before` (a retained `messageId`; the page ends just
  before it), `turn_id`, `request_id` (the turn whose user message carries
  it) or `next` (the token from the last `history_end`). `page_id` is yours
  (1-64 bytes `[A-Za-z0-9._:-]`) and comes back on every page message and
  the `history_end`. The reply is `message{history:true, page_id}` then
  `history_end{page_id, page}`, all sequenced.
- Bounds per page: 50 messages, 256 KiB of content, 1 MiB serialized
  (`history_end` included). `newest`/`before` go backwards (each page lists
  its messages oldest first; `next` continues with older ones); `turn_id`/
  `request_id` go forwards from the turn's oldest retained message to its
  newest one when the first page was taken (later messages of the turn come
  live). `end: true` means the selection is exhausted (no `next`).
- `next` is opaque and bound to this attachment, conversation, session,
  process, selector and history snapshot. Used elsewhere, altered, after
  the history was reloaded or evicted past it, or after a runtime restart:
  `error{code:"stale_target", page_id}`; start a new selection. A `before`
  Atem no longer retains is `stale_target` too. A lookup with nothing
  retained is an empty page (`count: 0`, `end: true`, `coverage:
  "unavailable"`).
- Field errors (no selector, two, a malformed value) are
  `error{code:"invalid_request", page_id}` (the `page_id` only when it was
  valid), sequenced; nothing resets. More than 8 valid `history` requests a
  second per conversation is `busy`.
- **Coverage.** `page.coverage` is `complete`, `partial` (some of the
  selection was evicted or lies in a hole) or `unavailable`.
  `truncated: true` once anything of this process's history was evicted
  (500 messages / 8 MiB); `oldest_retained` names the oldest retained
  message. `holes: [{after_message_id, before_message_id, count?}]` are gaps
  inside the retained timeline (≤ 16, then `holes_more: true`). Show them;
  never reopen because of them. Without `control` you never see card ids
  here: holes are named by the messages you can see, a hole before
  everything you can see is reported as `truncated: true` instead, and
  `oldest_retained` is the oldest one you can see; a `before` naming a card
  is `stale_target`.
- `open.before` and `open.generation` (the 2026-10-17 paging form) are
  removed: `error{code:"unsupported_version"}`, nothing opened or reset.
  There is no `status.page` marker any more.
- `open` on an open conversation resynchronizes it: a new `opened` at
  `sequence` 0 and the newest page; replace your cache.
- `opened.unavailable` lists what this agent's chat can't provide:
  `streaming` (no partial text), `reasoning`, `error_details` (no model/API
  error behind a failed turn). Hide the matching UI. Unknown names are
  ignorable.
- `opened.approvalRules` lists the session's active Atem session rules
  (`[{rule_id, label, scope}]`, section 5.5); `[]` without `control`.
- Approval cards (messages with an `approval` part) appear in history and live
  only for attachments with `control`.
- If chat is not available for a running session the answer is
  `error{code:"busy", text:"chat is not available for this agent: <reason>"}`
  and no conversation. An exited agent's history stays readable.
- A ninth open conversation closes the least recently opened one with
  `close{reason:"evicted"}`.

### 2.3 Live events

All carry `generation` and `sequence` (apply only `last + 1`):

| op | fields |
|---|---|
| `message` | the message above (a new user or assistant message, or a later version of one, always whole: replace what you had for that `messageId`) |
| `status` | `state` (`ready`/`working`/`waiting`/`unknown`), `since`, optional `detail`; re-sent every 15 s with the original `since` |
| `accepted` | `requestId`: your prompt reached the agent; `lease{lease_epoch, ms_left}` when your submit carried `acquire` (section 3.2) |
| `history_end` | `page_id` (absent on the open's page), `page` (section 2.2) |
| `coverage` | `oldest_retained`, `truncated`, `holes` (≤ 16, `holes_more`): sent after a burst of agent output was reloaded and something stayed missing |
| `complete` | `turnId`, optional `requestId`, `outcome`: `interrupted` when the turn ended interrupted (Esc, a deny at the agent's prompt, Codex's `turn_aborted`), else `done`; for your own submit it comes from the receipt, whose `detail` keeps the outcome, so a duplicate after a broker restart says the same |
| `error` | `text`, optional `requestId`, optional `page_id` (a history request's), and `code` on host-made errors: `rejected`/`outcome_unknown` (your submit's receipt), a session-v1 admission code (`stale_target`, `stale_lease`, `lease_held` with `controller{controller_session, lease_epoch}` and the text "another controller holds this session", `forbidden`, `session_closed`, `busy`, `paused`, ...), `invalid_request` (a field rule), `unsupported_version` (malformed or removed message), `busy` (open without chat, too many history requests). The chat's own notices (agent restarted, conversation switched, chat withdrawn) have no `code` |
| `rules` | `approvalRules`: the whole list of active Atem session rules, when it changed (conversations with `control` only) |
| `close` | the conversation ended; `reason`: `switched`, `withdrawn`, `restarted` or `evicted` (not sequenced) |
| `message{history:true, after_message_id}` | a message recovered after a burst of agent output was reloaded: place it after `after_message_id` (`null`: no retained message precedes it); the key's presence marks it as recovered |

`complete` means the execution turn ended, not that nothing more can arrive: a
late `message` for the same `turnId` is possible. Accept it.
Message parts (`kind`):

```json
{"kind":"text","id":"p1","markdown":"CommonMark, no raw HTML"}
{"kind":"tool","id":"p2","name":"Bash","summary":"npm test"}
{"kind":"approval","id":"approval","approval_id":"8888…","tool":"Bash","summary":"npm test",
 "always_rules":[{"rule_id":"r-npm-test","label":"Bash(npm test:*)","scope":"this project"}],
 "state":"pending"}
{"kind":"approval","id":"approval","approval_id":"9999…","tool":"Bash","summary":"npm test",
 "always_rules":[],"state":"auto_allowed","rule_id":"s-0123456789abcdef"}
```

An approval part may also carry `reason` (every final card, r8
`approval.card_reason`: the `approval_closed` reason, e.g. `answered_remote`
on an `allowed` card), `rule_id` (an `auto_allowed` card: the Atem
session rule that allowed it) and `note` (for example on an `allowed` card
whose session rule wasn't kept: "allowed once; the rule wasn't kept: this
session already holds 32 rules").

(`approval_id` and `always_rules` keep snake_case inside `parts`; envelope
fields are camelCase.) Messages are capped at 131 072 bytes (a truncation part
marks the cut). Text and summaries pass the credential redactor.

### 2.4 Close, reopen, and what ends a conversation

| Event | What you get | What to do |
|---|---|---|
| You send `close` (with or without `binding`; without it, your attachment's own conversation of that id closes) | nothing | -- |
| Your attachment drops or re-authenticates, or a second `hello` replaces it (r7.1) | all your conversations close, leases end, pending replies are dropped | `hello`, `list`, `open` again |
| Second `hello` on a welcomed attachment | `welcome` with new `attachment_gen` and `controller_session`; same permissions; authorization deadline not renewed; more than once a second is `busy`; the old `attachment_gen` is `stale_target` | rebuild every binding |
| Link/broker restart (new `runtime_gen`) | all attachments and leases invalid | same; receipts stay queryable |
| Agent restarted | `error` "the agent was restarted; reopen the chat", then `close{reason:"restarted"}`; new `generation` | open again, expect new history |
| Another session resumed inside the agent (`/resume`, Codex `/new`) | `error` "the conversation was switched; reopen the chat", `close{reason:"switched"}`; same `generation` | open again; the earlier turns are history only |
| Agent exits | status `unknown`, errors to open conversations, generation retired | history stays readable |
| Chat withdrawn (log format changed) | `error`, `close{reason:"withdrawn"}`; descriptor loses `chat-v1` | fall back to the terminal view |
| Atem dropped chat items before they reached the runtime (a huge burst of agent output) | the runtime reloads the worker's history and sends what was missing as `message{history:true, after_message_id}`; if something stays missing, a `coverage` event with the hole; no `error`, no `close` | keep consuming; show the hole |
| Ninth conversation opened | `close{reason:"evicted"}` for the oldest | -- |

A new `open` always restores status and the newest page. Reopen only on a
sequence gap, another `generation`, a fenced attachment or a `close` with a
`reason`; truncation, holes and `coverage` events never need one. Atem keeps
the newest 500 messages / 8 MiB per agent process.

## 3. Sending prompts

### 3.1 Lease

Control is one lease per session, 15 s long, held by one attachment.

```json
{"type":"session","data":{"v":1,"op":"acquire","id":"<uuid>","binding":{…no lease_epoch…},"takeover":false}}
```

Reply `lease{binding (with lease_epoch), ms_left}`. A chat Send can take the
lease with its prompt instead (section 3.2). Renew every 5 s (`renew`),
never after your own monotonic estimate of expiry (compute the deadline from
the request's send time + `ms_left`). `lease_held` means someone else has it (it names `controller`);
`takeover:true` (needs `control`) takes it and moves the other holder to
viewer. Local typing on the host revokes any remote lease
(`lease_changed{reason:"local_input"}`). A renew after expiry is `stale_lease`:
acquire again. Release with `release` when done.

### 3.2 Submit

Two equivalent forms; the chat form answers in chat ops.

```json
{"type":"agentChat","data":{"v":1,"op":"submit","conversationId":"c1","agentId":"ses-abcdefghijkl",
 "generation":"22222222-…","requestId":"44444444-…","text":"run the tests",
 "binding":{"target":{…},"attachment_gen":"33333333-…","lease_epoch":7}}}
```

```json
{"type":"session","data":{"v":1,"op":"submit","id":"<uuid>","binding":{…,"lease_epoch":7},
 "request_id":"44444444-…","kind":"prompt","payload":{"text":"run the tests"}}}
```

- `requestId` is a fresh UUID per prompt and is unique per agent session, not
  per conversation. The host computes the payload digest itself
  (sha256 of the canonical JSON payload); you never send one.
- Same `requestId` and same content: returns the recorded receipt, executes
  nothing. Same `requestId` with different content: `request_id_reused`.
- A chat submit hears back only in chat ops, never as a session `receipt`.
- **Send that acquires** (r8 `chat.send_acquire`): either form may carry
  `"acquire": true` instead of `lease_epoch`. Nobody holds the lease: the
  prompt is accepted and the lease granted to you in one step. You hold it:
  it submits under your lease (same epoch, deadline not extended). Someone
  else holds it: `lease_held` with `controller`, nothing recorded; after
  the user confirms "Take over and send", resend with the **same**
  `requestId` plus `"takeover": true` and `"expected_controller"` (the
  `controller` you were shown); a holder that changed meanwhile is
  `lease_held` again. The admitting reply (`receipt{state:"accepted"}` or
  chat `accepted`) carries `lease{lease_epoch, ms_left}`: apply it as an
  `acquire` reply sent when the submit was sent, only if that submit is
  still outstanding on your current attachment, the epoch isn't lower than
  one you saw since, and the deadline is still ahead. Only prompts acquire;
  `interrupt`, `stop` and rule revokes with `acquire` are
  `invalid_request`. A duplicate `requestId` returns its receipt and never
  acquires.

### 3.3 Receipt states and their chat form

| Receipt state | chat-v1 | Meaning |
|---|---|---|
| `accepted`, `executing` | `accepted{requestId}` | admitted and durable (and then pasted); not yet seen by the agent |
| `completed` | `complete{requestId, turnId, outcome}` | the agent's turn ended |
| `rejected` | `error{requestId, code:"rejected", text}` | refused with proof nothing was typed |
| `outcome_unknown` | `error{requestId, code:"outcome_unknown", text}` | may or may not have been typed (write interrupted, agent exited, restart, no acceptance in 10 s: "delivery unknown; check the terminal") |

The prompt is pasted once, as a bracketed paste plus Enter. It counts as
accepted for the agent only when its own prompt hook and its own log entry both
show the same text. Never resend after an error or timeout: query the receipt
(section 3.5).

### 3.4 Refusals (nothing is typed)

Reported as `rejected`/`error` with these texts:

| Text | Why |
|---|---|
| `the agent was restarted; reopen the chat` | `generation` is old |
| `the agent exited; start it again` | session ended |
| `prompt too long (max 32768 bytes)` | 32 768 UTF-8 bytes |
| `prompt contains control characters` | only printable, `\n`, `\t` (ESC is refused, not stripped) |
| `prompt is empty` | |
| `commands and shell mode are not available from chat` | first non-space char is `/` or `!` (`#` is fine) |
| `the agent is busy; wait for the current turn to finish` | status not `ready`, or another prompt waits for acceptance |
| `the terminal has unsent input; finish or clear it there` | someone typed locally since the last turn ended |
| `type a first prompt in the terminal: Codex reports nothing before it (and Atem's Codex hooks must be trusted in its /hooks)` | Codex before its first hook (status `unknown`) |
| `chat is not available for this agent[: <reason>]` | no `chat-v1` capability (Codex hooks off, Claude hooks inactive) |

Admission errors (not receipts) use session-v1 codes: `forbidden` (no
`control`), `stale_lease`, `stale_target`, `session_closed`, `busy` (also
"too many requests in flight", 64 per attachment), `paused` (authorization
expired), `unauthorized`. In chat form they arrive as `error{requestId, code, text}`.
A draft typed during a running turn is not detected (v1 limit).

### 3.5 Unsure? Query, do not resend

```json
{"type":"session","data":{"v":1,"op":"receipt_query","id":"<uuid>","binding":{…no lease_epoch…},
 "request_ids":["44444444-…"]}}
```

Reply `receipts` (<= 64 ids, only those bound to that exact target). Receipts
survive broker restarts. A session-v1 `receipt` has `request_id`, `target`,
`kind`, `state`, `detail?`, `updated_at`. A `completed` `prompt` receipt's
`detail` is the turn's outcome: `"done"` or `"interrupted"` (the same as the
chat `complete.outcome`; the journal keeps only that word, never prompt or
reply text). It also carries `result` (r8 `receipt.result`):

```json
"result":{"turn_id":"turn-7","user_message_id":"turn-7-u","outcome":"done",
          "reply_message_ids":["turn-7-a-0001","…"],"more":true,"replies":"complete"}
```

`reply_message_ids` are the turn's assistant messages in timeline order, at
most 32 (`more: true`: fetch the rest with `history{request_id}`), without
approval cards. `replies` is the turn's coverage (`partial` when part of the
turn was evicted, lies in a hole, or an id couldn't be named). The ids are
journaled, the replies computed from the retained history each time, so
they can change. Every completed prompt carries it; the user message id stays
known after the message itself was evicted (`replies` is then `partial`, or
`unavailable` when nothing of the turn is retained). No `result` on other
receipts, nor in the one case where the agent's own turn or message id isn't a
valid id (1-128 bytes of `[A-Za-z0-9._:-]`). Work executing across a broker restart
becomes `outcome_unknown` and is never retried. Replay after a reconnect of the
same chat submit is safe because the same `requestId` returns the recorded
outcome, but the right first move is `receipt_query`.

### 3.6 Interrupt and stop

Session-v1 `submit` with `kind:"interrupt"` or `kind:"stop"` and `payload: {}`
(under the lease; these never acquire):

- `interrupt` writes Esc only while the status is `working` or `waiting`;
  completes when the turn ends (chat `complete` with outcome `interrupted`).
  In `ready`/`unknown` it completes at once with detail "no turn was running" and
  nothing written. With no turn state (no chat) it is `rejected`: "no turn
  state; use the terminal". `outcome_unknown` ("no interrupt observed") after 10 s.
- `stop` stops the agent; completes at its exit. `rejected` "stop failed", or
  `outcome_unknown` "process still running" after 10 s.

## 4. Status semantics

| State | Meaning |
|---|---|
| `ready` | the agent finished its last turn and takes a prompt |
| `working` | a turn runs (prompt, tool, or Codex's own turn start) |
| `waiting` | a permission prompt is open (card, or the agent's own dialog) |
| `unknown` | Atem can't tell: before the first hook, chat withdrawn, agent exited |

- `since` is the time of the event that set it; the repeat every 15 s keeps it.
  A long `working` stays `working`.
- Process state and activity are different. The session descriptor has both:
  `state` (`running`, `exited`, `interrupted`, `recovery_required`, `closed`,
  `removed`) and `activity`. The status dot follows the process: an `exited`,
  `recovery_required` or unavailable session is not "ready", and `unknown` is
  grey, never green. Presence is not liveness.
- Delivery, activity and outcome are separate. `accepted` is delivery,
  `status` is activity, `complete.outcome` is outcome of a turn.
- Compaction turns produce no `complete`.

## 5. Approvals

When the agent asks for permission, Atem opens an approval for every
attachment with `control` (whoever holds the lease), and asks the relay to push it.
Answering needs `control`, never the lease (r8 `approval.lease_free`).

### 5.1 Cards in chat and session-v1

A chat card is an assistant message `approval-<approval_id>` with one `approval`
part (section 2.3). When its state changes the whole message is sent again with
the same `messageId`: replace it. `state`: `pending`, `allowed`,
`always_allowed`, `denied`, `answered_terminal`, `expired`, `closed`, and
`auto_allowed` (final on arrival: an Atem session rule allowed the request
without asking; nothing to answer, section 5.5).

Session-v1 form (after each `sessions` snapshot, and live):

```json
{"type":"session","data":{"v":1,"op":"approval_request","id":"…","approval_id":"88888888-…",
 "session_id":"ses-aaaaaaaaaaaa","process_gen":"22222222-…","tool":"Bash","summary":"npm test",
 "created_at":1760500000000,
 "always_rules":[{"rule_id":"r-npm-test","label":"Bash(npm test:*)","scope":"this project"}]}}
{"type":"session","data":{"v":1,"op":"approval_closed","id":"…","approval_id":"88888888-…","reason":"answered_terminal"}}
```

`summary` is redacted and shows the first line of the command or a file path,
never file contents. Key by `approval_id`; a repeat replaces.

### 5.2 Answering

A `kind:"approval"` submission, from chat with `approval` in place of `text`:

```json
{"type":"agentChat","data":{"v":1,"op":"submit","conversationId":"c1","agentId":"ses-aaaaaaaaaaaa",
 "generation":"22222222-…","requestId":"45454545-…",
 "approval":{"approval_id":"88888888-…","decision":"allow_once"},
 "binding":{"target":{…},"attachment_gen":"33333333-…"}}}
```

- `decision`: `allow_once`, `allow_always` (needs `rule_id` from the card's
  `always_rules`), `deny` (optional `message`, <= 512 bytes, handed to the agent
  with the denial). `rule_id` only with `allow_always`; `message` only with
  `deny`; anything else is refused. A submit carries `text` or `approval`, never both.
- No lease: the binding's `lease_epoch` is optional and ignored (a stale one
  is fine), an answer never takes, renews or moves the lease, and `acquire`
  (in the payload or beside it) is refused `unsupported_version`. A phone
  tap that arrives with no lease just answers. The first answer Atem admits
  wins, whoever holds the lease; a later one is `stale_target`.
- A closed, answered or unknown approval, or a `rule_id` it did not offer, is
  `stale_target` ("already answered"); nothing is applied.
- Receipt: `accepted`, `executing` (approval closed everywhere,
  `answered_remote`, decision handed over), `completed` (agent applied it),
  `rejected` (could not hand over), `outcome_unknown` (terminal answered too,
  agent ended, or no confirmation within 630 s).
- The terminal can always answer first; first answer wins. Anything else
  (failure, timeout, nobody) is "no decision": the agent asks in its own dialog.
  Atem never allows by itself.

### 5.3 Close reasons

`answered_remote`, `answered_terminal`, `interrupted`, `timed_out`,
`released` (Atem gave the prompt back: for Codex any input first releases the
hook, and that input is consumed; or the runtime restarted), `process_ended`.
Lease changes never close an approval; a takeover keeps it pending, and an
answer from the previous holder is still admitted (the epoch is ignored).
The final card carries the reason as `reason`.

### 5.4 Notifications

Over the verified link the host sends the relay (not you):

```json
{"type":"relay","data":{"v":1,"op":"push_approval","approval_id":"88888888-…","atem_device_id":"host-a",
 "session_id":"ses-aaaaaaaaaaaa","tool":"Bash","summary":"npm test","expires_at":1760500600000}}
{"type":"relay","data":{"v":1,"op":"push_resolved","approval_id":"88888888-…","reason":"answered_terminal"}}
```

Relays and apps use them for push notifications; collapse by `approval_id`.
`expires_at` is when the agent gives up (Claude 600 s, Codex 300 s). Best effort:
approvals pending across a broker restart are released without
`push_resolved`, so a notification may linger and a tap returns `stale_target`.

### 5.5 Differences and work in progress

- Claude offers its own suggested "always allow" rules (`scope` such as "this
  project"); Claude applies them itself.
- **Atem session rules** (Codex, which can't take a persistent rule). A Codex
  card for a shell command offers one rule, `{rule_id: "s-<16 hex>", label:
  "Always allow `<command>` in <cwd> for this session", scope: "session"}`.
  Commands only: file changes get none (Allow once / Deny), nor does a
  command whose input carries anything besides `command` and `description`.
  Answer it like any rule: `allow_always` with that `rule_id`.
- The worker then keeps the rule for the rest of that agent process (at most
  32; a respawn has none). A later request of the same session's own Codex
  with the byte-equal full command and cwd is allowed without asking: no
  `approval_request`, no push, no lease; you get an `auto_allowed` card with
  `rule_id`. Anything else still asks (one byte more, another cwd, a nested
  `codex`). An `apply_patch` run as a shell heredoc is a command like any
  other: its rule matches only that exact patch again.
- Active rules: `opened.approvalRules`, chat `rules` on change, session-v1
  `approval_rules{session_id, process_gen, rules}` (after each `sessions`
  snapshot and on change; `[]` when the process ends). All only with `control`.
- Revoke (r7.3: needs only `control`, not the lease; `lease_epoch` optional
  and ignored, `acquire` refused, the lease never taken or moved; view-only
  is `forbidden`): chat `submit` with
  `"approval_rule_revoke":{"rule_id":"s-…"}` in place of `text`, or session-v1
  `submit` with `kind:"approval_rule_revoke"`, `payload:{"rule_id":"s-…"}`.
  It completes once the worker dropped the rule (chat `complete`); a rule not
  active for that exact process is `stale_target`. An allow the worker wrote
  for it that Codex hasn't taken yet is withdrawn (Codex's dialog asks).
- A full session (32 rules) offers none; one that fills up before Codex takes
  the answer allows once and the card ends `allowed` with a `note`.
- Rules are bound to the account, device and host trust generation they were
  granted under. A change of any of them drops every rule. Rules survive a
  broker restart, but are inactive until the new host confirms them under the
  same identity and trust: meanwhile a matching request asks as usual (a
  normal card), and rules of another identity (`atem unpair` then
  `atem pair`, another account or device) are dropped, not listed again.

## 6. Per-agent differences

| | Claude Code | Codex |
|---|---|---|
| Chat availability | `chat-v1` once its hooks produced SessionStart (15 s wait; late one still enables) | only with `[codex] hooks = true` and hooks trusted in Codex's `/hooks` |
| Content source | transcript JSONL | rollout JSONL |
| `unavailable` | `["streaming","reasoning"]` | `["streaming","reasoning","error_details"]` |
| Reply shape | whole messages; a later content block of the same reply sends the message again, whole | whole messages (commentary and final answer are separate messages; a command is a `Bash` tool part); later parts also arrive as `delta` |
| Status before first prompt | `ready` after SessionStart | `unknown` until the first prompt typed in the terminal |
| First remote prompt | allowed when `ready` | refused until a first prompt was typed locally (the "type a first prompt" text) |
| Always allow | agent's `permission_suggestions` as `always_rules` | an Atem session rule, shell commands only (section 5.5) |
| Approval `waiting` | from Notification and open approvals | only from approvals this session has open (no native event) |
| `expires_at` | 600 s | 300 s |

A message that gains a part (for example a tool part after text) is sent again
whole by the shared chat state (`ChatSession`) for both agents, replacing the
earlier version (r8; there is no `delta` any more). It is not a token stream. No agent streams partial text today, and both
declare it in `unavailable` (`streaming`): Claude's transcript holds whole
content blocks, Codex's rollout whole messages. Treat both as "parts arrive
whole", and never animate text as a stream.

## 7. Recipes

Common rules for every client:

1. Never resend on a timeout, close or error: `receipt_query` first, then decide.
2. Track `generation` and `sequence`: apply `last + 1`, ignore a repeat, and on
   a gap or a different `generation` reopen (`open`) and replace your cache.
3. Ignore unknown fields, ops, part kinds, `unavailable` names and card states.
4. Cache by `messageId`/part `id`; later messages with the same id replace.
5. After any reconnect: `hello`, `list`, `open`. A conversation does not survive
   its attachment.

### (a) A mobile chat screen

Ops: `hello` (`revision: 8`), `list` (session picker, activity dot), `open`,
`history` (`before`/`next` for scroll-back, `request_id` to recover a reply),
`submit` (chat form, `acquire:true` to send without a separate Take
Control), `renew`/`release`, `close`, `receipt_query` on resume, approval
answers (no lease).

- Open only for sessions with `chat-v1`; render markdown as CommonMark without
  HTML, `tool` parts as chips, approval parts as cards. Render `origin: local`
  user messages as the user's own, labelled as typed on the computer.
- Take the lease only by sending (`acquire:true`); renew every 5 s while the
  composer is focused, release when it closes. Do not hold control while idle.
  On `lease_held` offer "Take over and send" (same `requestId`, `takeover`,
  `expected_controller`).
- A send button state: enabled only when `status.state == ready`, no draft
  refusal and you hold or can take the lease. Show `detail` for `unknown`.
- Pitfalls: backgrounding kills the socket; on foreground do the full
  reconnect sequence and `receipt_query` your in-flight `requestId`s instead of
  resending. A notification tap on a resolved approval gets `stale_target`:
  show "already answered". Do not show a typing indicator for partial text (no
  streaming); use `working`.

### (b) A Discord bridge

Ops: `hello`, `list`, `open`, chat `submit`, `acquire`/`renew`/`release`,
approval answers, `receipt_query`, `close`. One bot attachment, one `conversationId`
per Discord channel or thread, a mapping channel/thread <-> `ses-...` kept by
the bot.

- User message -> check `status == ready` then `submit` with a UUID
  `requestId` (store it with the Discord message id). `accepted` -> a reaction;
  `error` -> reply with `text`.
- Assistant `message` (not `history`) and `complete` -> bot reply. Send text
  parts as replies (split to Discord's length limits; the host caps a message
  at 128 KiB), tool parts as one short line. Post once per turn on `complete`
  when you would otherwise flood the channel, but accept late messages after it.
  Do not echo your own prompt back: its user `message` has `origin:"remote"`
  and your `requestId`.
- Approval card -> a message with buttons (Allow once, Deny, and one button per
  `always_rules` entry when present). A click is an approval submit (no
  lease); edit the message when the card state changes (`allowed`,
  `denied`, `answered_terminal`, ...). Authorize who may click: the bot's
  attachment has `control`, so any click acts with it.
- `status` -> presence or typing indicator: typing while `working`, a
  "waiting for approval" presence for `waiting`, idle for `ready`, grey for
  `unknown`/`exited`.
- Shared channel and leases: the bot's attachment is one controller. Send with
  `acquire:true` (without `takeover`), serialize prompts in the bot (one in flight per
  session; queue the rest in Discord order), and renew only while a prompt is
  pending. On `lease_held` tell the user a person or another client is in
  control, and do not `takeover` automatically. Local typing revokes the lease
  (`lease_changed`, `local_input`): the next send acquires again.
- Mapping several users to one session is the bot's problem: Atem sees one
  controller. Never interleave two prompts; a second user message while
  `working` is refused ("the agent is busy").
- Pitfalls: Discord retries and gateway reconnects produce duplicate events: key
  by Discord message id to `requestId`. On a restart of the bot, `receipt_query`
  every stored in-flight `requestId`. Do not post history on `open` as new
  replies (`history:true`). Terminal output is not exposed through chat: no
  replies from screen diffs.

### (c) A headless API/CLI client

Ops: `hello`, `list`, chat `open`/`submit` or session-v1 `submit`
(`kind:"prompt"`, `acquire:true`), `receipt_query`, `history{request_id}`,
`release`.

- Session-v1 `submit` with `kind:"prompt"` returns receipts you can poll with
  `receipt_query` (and no conversation needed). Chat gives you the content;
  use it when you need the reply text.
- A script flow: submit with `acquire:true`; wait for `complete` or the receipt
  `completed`; its `result` names the turn and its reply ids; fetch them with
  `history{request_id}` (or collect live `message`s by `turnId`); release.
- Exit codes should tell `rejected` (nothing happened, safe to retry later with
  a new `requestId`) from `outcome_unknown` (do not retry: check the terminal).
- Pitfalls: a CI script must not retry `outcome_unknown` with a new
  `requestId`, which would run the prompt twice. Handle `complete` before
  `accepted` ordering on reconnect (a duplicate returns both). Treat a 15 s lease
  as hostile to long waits: renew every 5 s while you wait for a turn, or let
  it lapse (accepted work continues without you).

## 8. Limits and what's not there yet

- Text-only prompts. No attachments or images, no slash commands or `!` shell
  mode from chat (`/` and `!` are refused).
- One native Astation link today. Several devices or browsers at once wait
  on account trust (`designs/account-trust.md`, PR #70); compatibility mode has no
  resume (`hello` with `resume` is `unauthorized`) and an attachment is
  authorized for 24 h, then fenced and reconnected. Chat content is readable by the
  relay (end-to-end encryption of chat is a follow-up).
- No remote session launch: sessions start locally with `atem agent launch` (or the
  bare `atem` menu). Clients only attach to what is already running.
- Sizes: prompt 32 768 bytes; message 131 072 bytes (≤ 2048 parts); a history
  page 50 messages / 256 KiB of content / 1 MiB serialized (older pages and
  lookups with `history`, 8 a second); `receipt.result` 32 reply ids; 8
  conversations per session (the oldest is
  closed); 500 messages / 8 MiB kept per agent process; 64 in-flight requests per
  attachment; inbound chat/session messages 1 MiB (larger are dropped with an
  `unsupported_version` error); `receipt_query` 64 ids; 16 pending approvals per
  session; deny `message` 512 bytes.
- No semantic turn-completion signal beyond the agent's own turn end; no
  reasoning; no Discord adapter in Atem (the bridge above is yours).
- Approvals do not survive a broker restart. Their cards stay in history; one
  still pending becomes `closed` with the note "Atem's runtime restarted;
  answer in the terminal". Atem session rules survive, inactive until the new
  host confirms them (section 5.5). Chat history (500 messages / 8 MiB)
  survives a broker restart whole.

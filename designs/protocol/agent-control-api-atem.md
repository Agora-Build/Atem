# Agent control API: Atem's response to Astation's proposal r1

Status: Atem response r1, 2026-10-17, to "Agent control API: Astation and
Atem joint proposal" r1 ([Astation #52](https://github.com/Agora-Build/Astation/issues/52)).
Baseline: Atem `main` at `af56d39` (#73), contract
[atem-session v1 r7.2](atem-session-v1.md), [agent chat host](../agent-chat-host.md),
[chat developer guide](../agent-chat-api.md). Every paragraph is marked
**Today** (in the code at `af56d39`) or **Proposed** (not built and not agreed
yet). Nothing **Proposed** is emitted before §6's feature markers and fixtures
exist.

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
  the rollout. Fix: `agent-chat-host.md` still says that Codex `open` before
  its first hook is `busy`.
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

## 3. Q2: history page end

**Today** (`host_bridge.rs` `open_conversation`). `open` sends `opened`
(`sequence` 0), then the newest page (50 messages / 256 KiB) as
`message{history:true}` at sequences 1…n. The conversation's live sequence then
continues at n+1. All of this happens in one broker pass, so no live event
falls between those messages. There are three defects:
1. Nothing marks the end of the page. A quiet socket and a finished page look
   the same.
2. `open{before}` on an open conversation reopens it: a new `opened` at 0, and
   the live counter is reset to the page length. Paging therefore restarts
   the live sequence, and a live event can collide with or precede history.
3. An unknown or evicted `before` returns an empty page, which can't be told
   apart from "no older messages". The worker's backlog `gap` (messages dropped
   while no broker was attached) is ignored by the broker (`broker.rs`,
   `gap: _`), so incomplete history is never reported.

**Proposed** (feature `chat.history_end`, `chat.history_page`):
- `open` takes no `before`. Its reply is `opened`, the newest page as sequenced
  `message{history:true}`, then a sequenced `history_end`. Live events follow
  from `history_end.sequence + 1`. The host builds all of it in one pass, so
  every event produced after the snapshot comes after `history_end`.
- Older pages use a new unsequenced request, `history`. Its reply,
  `history_page`, carries no `sequence` and never touches the live counter.
  Paging and live delivery are independent, and a page is never merged with
  live events by sequence. A client merges by `messageId`, and a whole
  message always replaces an earlier copy.
- A `before` that is no longer retained gets `end:"unknown_cursor"`, never an
  empty page that claims to be the start.

```json
{"type":"agentChat","data":{"v":1,"op":"history_end","conversationId":"c1","agentId":"ses-aaaaaaaaaaaa",
 "generation":"<process_gen>","sequence":51,"page":{"count":50,"next_before":"m-0451",
 "end":"more","oldest_retained":"m-0001","truncated":true,"retained":{"messages":500,"bytes":7340032}}}}
{"type":"agentChat","data":{"v":1,"op":"history","conversationId":"c1","agentId":"ses-aaaaaaaaaaaa",
 "binding":{…},"page_id":"p7","before":"m-0451"}}
{"type":"agentChat","data":{"v":1,"op":"history_page","conversationId":"c1","agentId":"ses-aaaaaaaaaaaa",
 "generation":"<process_gen>","page_id":"p7","messages":[{"messageId":"m-0401",…}],
 "page":{"count":50,"next_before":"m-0401","end":"more","oldest_retained":"m-0001","truncated":true}}}
```

- `end` is one of: `more` (`next_before` names the oldest message in this page),
  `start` (the oldest retained message was sent), or `unknown_cursor`.
  `truncated: true` means messages older than `oldest_retained` existed and were
  lost: evicted, cut by an adoption snapshot, or dropped as a worker backlog gap.
  The broker then stops ignoring `gap`. Approval cards filtered out for a
  view-only attachment are not truncation.
- `generation` is the agent's `process_gen` (the chat generation equals it
  **today**). Another `generation` means another process: discard the cache.
- Retention (**today**, unchanged by this proposal):

| Where | Bound | Survives |
|---|---|---|
| Broker `ChatSession` (serves pages) | newest 500 messages / 8 MiB per `process_gen`; one message ≤ 128 KiB (cut with "… (truncated)") | agent exit (readable until the session is removed) |
| Worker `ChatSession` | the same 500 / 8 MiB; backlog while no broker is attached: 4096 items / 8 MiB, oldest first dropped (`gap`) | broker restart |
| Broker restart or adoption | rebuilt from the worker's `chat_snapshot`: newest **200 messages / 1 MiB**; approval cards are lost (only the broker makes them); in-flight prompt acceptance and the in-memory turn outcomes are lost | — |
| `/clear`, `/resume`, Codex `/new` | same generation; history kept (resumed content backfilled); conversations get "the conversation was switched; reopen the chat" | — |
| New process (relaunch) or session removed | none; a new `process_gen` starts empty | — |

Atem stores no chat history on disk. The providers' own transcript files are
theirs. **Proposed:** the adoption snapshot grows to the full 500 / 8 MiB, in
chunks under the line bound, so a broker restart loses nothing except approval
cards.

## 4. Q3: request → reply recovery

**Today.** A completed `prompt` receipt carries only `request_id`, `target`,
`kind`, `state`, `detail?` and `updated_at`. The broker knows the turn and
outcome in memory only (`host.rs` entry `turn_id`, `host_bridge.rs`
`outcomes`, capped at 4096). Both are lost on broker restart, and neither is
journaled. A prompt receipt is `completed` for an **interrupted** turn too:
only the chat `complete.outcome` tells the two apart. The user message
and the assistant messages of a remote prompt's turn carry its `requestId`,
and every message carries `turnId`.

**Proposed** (feature `receipt.result`):
- A `prompt` receipt in `completed` carries `result`. Only ids are journaled
  (`turn_id`, `user_message_id`, `outcome`), written with the `completed`
  transition. `reply_message_ids` is computed when the receipt is sent,
  from retained history. The journal never holds prompt or reply text, and the
  payload is already dropped when the receipt leaves `accepted`.

```json
{"type":"session","data":{"v":1,"op":"receipt","request_id":"46464646-…","target":{…},"kind":"prompt",
 "state":"completed","updated_at":1760600000000,
 "result":{"turn_id":"t-9","user_message_id":"m-0412","outcome":"done",
           "reply_message_ids":["m-0413","m-0414"],"replies":"retained"}}}
```

- `outcome` is `done` or `interrupted`. `replies` is `retained` (every message
  of the turn is still in history), `partial` (the oldest were evicted) or
  `unavailable` (the turn was evicted or the process is gone; then
  `reply_message_ids` is `[]`). A turn may complete before late content arrives,
  so `reply_message_ids` is as of the moment the receipt is sent. A later
  `receipt_query` may list more.
- `receipt_query` after a reconnect or broker restart returns `result` from the
  journal, plus reply ids recomputed from retained history.
- Recovering the messages uses chat `history` with `turn_id` or `request_id`
  in place of `before`. The reply is one `history_page` holding that turn's
  retained messages (`end:"start"`), or `end:"unknown_cursor"` once they were
  evicted.
- An `executing` prompt whose broker restarted stays `outcome_unknown`. It
  gets no `result` and is never re-run. Its messages can still be found by
  `history{request_id}`, because the worker's snapshot keeps `requestId` on
  each message. After eviction or a new process the answer is `unavailable`.
  Nothing is recreated by running the request again.
- `interrupt` receipts may carry `result{turn_id, outcome}` when a turn ended.
  `stop` and `approval` receipts carry none.

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
  releases every approval ("no decision", `approval_closed{released}`), and its
  cards vanish from history (see §3).

**Proposed** (feature `approval.card_reason`): every final card except
`auto_allowed` carries `reason`, the `approval_closed` reason
(`answered_remote`, `answered_terminal`, `interrupted`, `timed_out`,
`released`, `process_ended`). Clients then never have to map `closed` back to a
cause. The state names above stay as they are.

## 6. Q5: versioning

Recommend **r8**, not r7.3. r7.x revisions only added things. r8 changes
semantics: `open` loses `before`, and a page no longer resets the live sequence.
Clients built for r7 would page incorrectly. **Proposed:** `welcome` gains a
required `revision: "r8"` and `features: [string]`. Unknown fields are ignored
today (§1), so the field is safe to add. Per-session abilities stay in the
descriptor's `capabilities`.

```json
{"type":"session","data":{"v":1,"op":"welcome",…,"revision":"r8",
 "features":["chat.history_end","chat.history_page","receipt.result","approval.session_rules","approval.card_reason"]}}
```

A side emits a feature only after the shared fixture for it is in
`designs/protocol/fixtures/` and passes in Rust (Atem) and Swift (Astation). An
r8 host never advertises a feature it hasn't implemented. `approval.session_rules`
names what r7.2 already ships.

## 7. Work

**Atem work** (S ≤ 1 day, M ≤ 3 days, L > 3 days):

| # | Item | Size |
|---|---|---|
| A1 | `history_end` after `opened`; `history`/`history_page` unsequenced; drop `open.before`; `unknown_cursor` | M |
| A2 | Track truncation in `ChatSession` (eviction, snapshot cut, worker `gap` stops being ignored); `oldest_retained`, `retained` | S |
| A3 | Full adoption snapshot (500 / 8 MiB, chunked) | S |
| A4 | Journal `turn_id`/`user_message_id`/`outcome` with `completed`; `result` in `receipt`/`receipts`; `replies` computed from history | M |
| A5 | `history{turn_id|request_id}` lookup | S |
| A6 | Card `reason`; `welcome.revision`/`features`; contract r8 text; docs (`agent-chat-host.md` Codex `busy` fix, `agent-chat-api.md`) | S |
| A7 | Live check: Claude 2.1.301 and Codex 0.162.1 through the r8 fixtures with a real runtime (`tests/runtime_fixtures_binary.rs`) | M |

**Joint fixtures** (new `designs/protocol/fixtures/*.json`, written before
either side emits the feature):
- `chat-open-ends-with-history-end`
- `chat-live-after-history-end-continues-the-sequence`
- `chat-history-page-does-not-touch-the-live-sequence`
- `chat-history-unknown-cursor`
- `chat-history-truncated-after-eviction`
- `chat-history-truncated-after-adoption-gap`
- `chat-history-by-turn-and-request`
- `receipt-result-on-completed-prompt`
- `receipt-result-interrupted-turn`
- `receipt-result-after-broker-restart`
- `receipt-replies-unavailable-after-eviction`
- `executing-prompt-after-restart-is-unknown-without-result`
- `approval-card-reason-matches-approval-closed`
- `approval-card-withdrawn-with-chat-inbox-still-answers`
- `welcome-features-gate-emission`

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
  `sequence`, the session registry `seq`/`runtime_epoch`, receipts and gap
  signals: a sequence gap, another generation, a `close`, or `truncated`. Any
  of these means resynchronize by reopening. Atem keeps no replay window per
  client.
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

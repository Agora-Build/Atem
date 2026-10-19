# §9 proposal: one pairing, many devices on the same account

Status: Atem-side proposal for joint review, 2026-10-16; freshness and forks
replaced by the user's final decision of 2026-10-19 (§3.5, re-pairing as the reset; exact rules in
[protocol/remote-agent-api-atem.md](protocol/remote-agent-api-atem.md) §3; exact formats in the
r9 appendix of [protocol/atem-session-v1.md](protocol/atem-session-v1.md), §R9.1–§R9.13). Answers
`session-multiplexing.md` §9 / atem-session §9 ("trust anchor, membership,
freshness") for the user's decision: **Atem pairs once; the user's other
devices on the same account (Mac, iPhone, iPad) reach it without pairing
again — not by trusting the account login, and not by forwarding through the
Mac.** Diagrams: [account-trust-diagrams.html](account-trust-diagrams.html) (open it in a browser, e.g. via `atem serv files designs/account-trust-diagrams.html`).

## 1. Idea in one paragraph

The account has a small **signed device list** (the *membership log*). Every
trusted device keeps its own private key; the log records which device keys
belong to the account and what each may do. When Atem pairs with the first
Astation it **pins the start of that log** (its genesis hash) and from then on
accepts any device the log lists — and nothing else. A new device joins once,
approved with Touch ID or the password on a device that is already trusted;
that adds one signed entry. Removing a device appends a signed removal. Atem
never trusts the relay, the account login or a device's own claims: it trusts
signatures that chain back to what it pinned.

## 2. Pieces

| Piece | Where it lives | What it is |
|---|---|---|
| Device key | each native Astation (Secure Enclave / platform keystore) | P-256 signing key + X25519 key; never leaves the device; on a manager the signing key requires Face ID / Touch ID (key policy, not protocol) |
| Membership log | relay stores it (untrusted storage), every trusted device and Atem keep copies | append-only list of signed entries |
| Log entry | in the log | `{account_id, seq, prev_hash, action: add\|remove\|set_roles, device_id, device_sign_pub, device_enc_pub, roles, signer_device_id, signed_at}` + signature by a device whose roles include `manage` at `seq-1` |
| Genesis | entry `seq = 1` | `add` of the first Astation by itself, roles `manage, view, control`, plus the Recovery Kit's public key (`recovery_sign_pub`) |
| Recovery Kit | offline, saved by the user (password manager, printed QR + phrase, or another device) | Astation account-recovery feature: a mandatory Ed25519 key created at account setup; never a member; used only in Astation's restore-account flow when every Astation device is lost |
| Atem pin | Atem's `pairing/membership.json`, beside `pairing/pairing.enc` and `pairing/trust_gen` | `{account_id, genesis_hash, host_trust_gen, recovery_sign_pub, head:{seq, hash}, entries, evidence, frozen?}`; the head only moves forward and is made durable before anything depends on it |

Roles: `view` (see sessions/output), `control` (take the lease, type, submit;
answer the agent's permission prompts without the lease, r8 §G), `manage` (add/remove devices).
Viewing ≠ control ≠ enrolment, as the product design requires.

## 3. Flows

### 3.1 Pairing (once per Atem)

Today's `atem pair` + safety-code verification, with one addition: Astation
sends the current membership log; Atem verifies the chain from genesis, checks
that the pairing Astation's verified key is a listed `manage` device, and pins
`genesis_hash` and the head (`seq`, hash) as its durable head. The safety code also covers
the genesis hash (so a relay can't swap in another account's log).

### 3.2 Adding a device (once per device, not per Atem)

1. New iPhone signs in to the same account → creates its device key → shows
   "waiting for approval" with a short code (and its key fingerprint).
2. A trusted manager device (the Mac) shows "Allow iPhone of Alice? code
   ABCD-1234". The user compares the code and approves with Touch ID/password.
3. The Mac appends `add{iPhone keys, roles}` signed with its own device key; the
   relay stores it. Account login alone can't produce this signature.
4. Every Atem that pinned this account will accept the iPhone as soon as it
   sees the new entry — no Atem-side action.

### 3.3 A device connects to Atem

1. Device ↔ Atem over relay or direct :8080 (same messages).
2. Atem sends its challenge: a nonce and its head `(seq, hash)`.
3. Device answers with: its device id, the log entries from Atem's head to its
   own head (none if equal or behind; its whole log if it doesn't contain
   Atem's head), and a signature by its device key over the transcript (nonce,
   head, `atem_device_id`, `host_trust_gen`, both ephemeral X25519 keys).
4. Atem verifies: each new entry chains from its head and is signed by a
   manager at `seq-1`; it makes the new head durable and applies the entries
   (removals fence at once) **before** admitting anyone; then the device must
   be listed (not removed) with the roles it asks for, and the transcript
   signature must be the device's.
5. Both sides derive session keys from the ephemeral exchange (step 2 of this
   proposal: end-to-end encryption of the session channel). `welcome` grants
   exactly the device's roles and carries Atem's head, so the device can show
   "up to date"; leases and receipts work as today.

### 3.4 Removing a device

Settings → Devices → Remove "Old iPad" on any manager device → `remove` entry
signed and appended. Atem applies it the next time any trusted device connects
(every connection must bring entries up to its own head), or when Atem fetches
the log itself. Applying it is immediate: the removed device's live
attachments are fenced and its queued work is rejected (r8 §H, `control_gen`).
Atem keeps its head durably, so it never goes back to an older list. There are
no revocation acknowledgements.

### 3.5 Freshness and forks (user decision, 2026-10-19)

**Trust the signature, not the sender.** Any device can carry entries,
including revocations, even a revoked Astation or device. Only authorized
managers sign additions and removals. Atem verifies signatures, device
identities and the hash chain before applying anything, so a forged device id
can't remove anyone or gain access: every effect needs a valid signature
chaining from Atem's head. No periodic renewals.

- **No attestations, heartbeats or window.** Freshness comes from normal
  connections: every connection carries the suffix from Atem's head. There
  are no clock rules, no manager authority expiry and no acknowledgements.
- **Atem's chain is authoritative up to its head.** A lower seq, or an entry
  that doesn't chain from the head, is never applied. Beyond the head, the
  first valid suffix applied wins.
- **Conflicts:** an entry at or below Atem's head that differs from Atem's,
  signed by a key Atem's chain has removed or that wasn't a manager at that
  seq, is ignored and logged as evidence, without freezing. One signed by a
  manager still valid in Atem's chain (not removed later) is real evidence
  of a compromised manager key: remote access for the account freezes. Local
  use is unaffected. Managers can never resolve a freeze.
- **Stolen device:** remove it from another manager device. The removal is
  a signed log entry carried by every connection and applied by Atem on its
  own; nothing more is needed.
- **Reset: re-pairing.** If a manager key was compromised, or a host shows
  the security freeze, run `atem unpair`, then `atem pair` on each affected
  host, from a trusted device. That pins a new genesis (a new device list
  starting from the trusted device, with only the good devices); other
  devices rejoin it. There is no Atem command for the Recovery Kit. Freeze message: "Remote access to <host> is paused
  for safety. Re-pair this host from a device you trust: `atem unpair`, then
  `atem pair`." Managers can never resolve a freeze.
- **Residual risks, in the user's words:** a compromised manager signing key,
  or a relay hiding revocations. A revocation reaches a host when any honest
  device next connects; a stolen *unlocked* manager can act until then.
  Re-pairing is the remedy for both.

### 3.6 Lost devices / account recovery

The Recovery Kit is an Astation account-recovery feature, used only when
every Astation device is lost. It is mandatory, created at account setup and
kept offline (password manager, printed QR + phrase, or another device). It
is used only in Astation's "restore account" flow on a new device, and does
two things there: (a) restores the account key `K`, so encrypted memory,
vault and credentials can be read again; (b) signs a log entry that makes
the new device a manager of the existing device list, so hosts and phones
keep working without re-pairing. Atem only verifies and applies that entry
like any other: it chains from Atem's head and is signed by the recovery key
pinned in genesis (`recovery_sign_pub`, as in the e2e verification design).
Atem has no command for it, and it is not a trust reset.

Without the kit, a lost-everything account re-pairs each Atem host (`atem
unpair`, `atem pair`), a new genesis and trust generation; account data and
encryption keys are kept as today.

## 4. Why this shape

| Alternative | Problem |
|---|---|
| Trust the account login | Anyone with the password/session (or a compromised relay) controls the agents |
| Forward through the paired Mac | Phone stops working when the Mac sleeps; Mac becomes a single point of failure |
| Pair every device with every Atem | Exactly what the user doesn't want; N×M ceremonies |
| One shared account private key copied to all devices | Can't stay in Secure Enclave; a leak can't be revoked per device |
| **Signed device list pinned at pairing (proposed)** | Pair once; add a device once; per-device revocation; relay is only storage |

## 5. What changes on each side

**Astation (native):** device keys (exists for verification), membership log
create/append/verify, the add-device approval UI (code + Touch ID), Settings →
Devices (remove), the Recovery Kit at account setup and its restore-account flow, carrying the log suffix from Atem's head on every
connection. **Relay:** store and serve the log per account (append-only,
reject non-chaining appends as a convenience — not trusted). **Atem:** verify
the chain, pin at pairing, a durable head, apply suffixes before admission,
the conflict rule and freeze message, applying the recovery-key entry like any entry, challenge/response in `hello`, roles → permissions, accept many attachments at
once (the runtime already multiplexes viewers; today it only admits the paired
Astation).

## 6. Steps

1. **Membership** (this proposal): log format, signatures, pairing pin,
   add/remove, the suffix carried on every connection, the conflict rule and
   freeze, re-pairing as the reset, the Recovery Kit as account recovery — plus shared fixtures (valid chain, conflict
   by a removed key, conflict by a current manager, removed device, rollback,
   recovery-key entry, wrong account).
1b. **Approvals from chat/mobile:** prompt-bound `approval_request` /
   `approval` submissions by any attachment with `control` (see question 3).
2. **End-to-end channel:** ephemeral X25519 + device keys → session keys for
   the atem-session channel over relay and direct; relay can no longer read
   terminal or chat traffic.
3. **Browser QR grants:** a native device signs `{browser key, target, scope,
   expiry ≤ 1 h}`; the browser proves its key on connect; same checks.

## 6a. Approvals in chat and on mobile (step 1b)

Since r8 (atem-session appendix §G) any attachment with `control` may answer the
agent's permission prompts from the chat view or a phone, for the exact pending
request; the lease is neither needed nor moved. Both agents can take an external allow/deny without simulating keys:

| | Claude Code ([hooks](https://code.claude.com/docs/en/hooks)) | Codex ([hooks](https://developers.openai.com/codex/hooks)) |
|---|---|---|
| Hook | `PermissionRequest` — runs only when a permission dialog would appear | `PermissionRequest` — runs only when an approval would be asked |
| Input | `session_id`, `tool_name`, `tool_input`, `permission_suggestions` | `turn_id`, `tool_name`, `tool_input` |
| Answer | `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}` or `deny` + `message` | same shape |
| No answer | normal terminal dialog appears | normal prompt appears |
| Setup | per launch via `--settings` (as chat does) | `~/.codex/hooks.json`, trusted once in Codex (`/hooks`) |

Verified on Claude Code 2.1.301 (interactive, hook from `--settings`;
fixtures: `designs/fixtures/permission-hook/`):

- The hook fires with `session_id`, `transcript_path`, `cwd`, `prompt_id`,
  `permission_mode`, `tool_name`, `tool_input`, `permission_suggestions`.
- **The terminal dialog is shown at once while the hook runs.** The local user
  can answer it immediately; the hook is not killed and its late output is
  ignored. The hook decides only if it answers before the user does.
- `allow` → no dialog, the command runs ("Allowed by PermissionRequest hook");
  `deny` + message → not run, the model sees the message and doesn't retry;
  no output → normal dialog.
- A `timeout` field is honoured (SIGTERM at the limit; the dialog stays).
- Esc on the dialog interrupts the turn and SIGTERMs the waiting hook.
- The Notification `permission_prompt` hook fires ~6 s later, only if the dialog
  is still unanswered.

So the terminal dialog and the remote approval race, and **whichever answers
first wins** — Claude arbitrates; the local user never loses the ability to
answer. Flow:

1. The hook writes the request (tool, summary, `prompt_id`) as one event file in
   the session's private directory, like the other chat hooks.
2. Whoever holds the lease, the runtime announces `approval_request{approval_id,
   session_id, process_gen, tool, summary, created_at}` to every attachment with
   `control` (and asks the relay to push it); chat shows an approval card with
   Allow / Deny; the hook keeps waiting (hook `timeout` 600 s).
3. A controller answers with a §6 submission `kind:"approval"`, payload
   `{approval_id, decision, rule_id?, message?}`, without `acquire` and with
   no lease check (a `lease_epoch` is ignored); the runtime checks `control`
   and that the prompt is still pending for that exact session/process, writes
   the decision file, and the hook returns it. The first admitted answer wins;
   the lease never moves.
4. **Answered in the terminal first**, interrupted (Esc), timed out or
   released → the request is closed; lease changes never close it (the runtime sees the tool run or fail via the
   PostToolUse/transcript events, or the hook's exit); a later remote answer gets
   `error{code:"stale_target"}` and is never applied. The card disappears.
5. Receipts record the outcome as observed: `completed` when the tool ran/was
   refused as decided by the remote answer, `outcome_unknown` if the terminal
   answer and the remote answer crossed and Atem can't tell which won.

Codex (verified on codex-cli 0.162.1, interactive, `-a on-request`; fixtures:
`designs/fixtures/permission-hook/codex/`) behaves differently in two ways:

- **Codex holds its approval prompt until the hook exits** (the TUI shows
  "Running hook"); the local user can't answer while the hook waits.
- Esc interrupts the turn but doesn't stop the hook; a timeout shows "Hook
  failed: hook timed out" and then the normal prompt.
- Same answers otherwise: no output → prompt; allow → runs; deny + message →
  "Blocked by hook", the model sees the message. Input: `session_id`,
  `turn_id`, `transcript_path`, `cwd`, `model`, `permission_mode`, `tool_name`,
  `tool_input` (no `prompt_id`).
- Hooks are on by default; a non-managed hook must be **trusted once** in Codex
  (startup review or `/hooks`), stored as a hash of the hook entry — any change
  to the entry needs a new review.

What that means for Atem with Codex:

1. **Local input releases the hook.** All local keystrokes already pass through
   the runtime, which revokes the remote lease before writing them; for Codex it
   also answers "no decision" to a waiting hook first, so Codex shows its prompt
   and the user answers it in the terminal (the keystroke that released it is
   consumed, never written: the user saw only "Running hook", so it must not
   answer the prompt it brings back; the frontend says "Codex's approval was
   handed to the terminal; answer its dialog").
2. **Hook timeout 300 s for Codex** (long enough to answer from a locked phone);
   any local key releases it earlier; on timeout Codex shows its own prompt.
3. On Esc the runtime closes the request itself (the hook may keep running; its
   late output is ignored).
4. **Set up by `atem agent launch codex`, once, without breaking anything**
   (user decision, 2026-10-16 — no separate command):
   - On the first Codex launch Atem asks once ("Allow approvals from Astation
     for Codex? This adds one hook to ~/.codex/hooks.json") and remembers the
     answer; declining just means Codex approvals stay terminal-only.
   - It **merges**: the user's existing hooks are kept, one entry marked as
     Atem's is added (idempotent; a backup `hooks.json.atem-bak` is written
     before the first change; never overwritten wholesale).
   - The hook command is identical for every session (it finds the session
     through an environment variable set by the worker), so Codex's one-time
     trust stays valid.
   - **Outside Atem it does nothing:** in a Codex run not started by Atem the
     variable is absent and the hook exits at once with no output, so Codex shows
     its normal prompt — plain `codex` behaves as before (one short shell start
     per approval prompt).
   - Inside Atem with no remote controller it also exits at once; it never
     auto-allows, and any failure means "no decision".
   - Codex shows its "hooks need review" screen once after the entry is added
     (also in plain `codex`); the user trusts it there.
   - To verify while building: how Codex combines our hook with other
     `PermissionRequest` hooks the user already has (ours must never override
     their deny).
   - Claude Code needs none of this: its hook comes per launch through
     `--settings`, nothing global changes.


Changes to earlier rules: chat's "no approvals from chat" becomes "approvals by
any attachment with `control`, bound to the exact prompt, no lease (r8 §G)"; "hooks never decide" gains one
exception — the `PermissionRequest` hook may return a decision it received from
the runtime; the local terminal dialog always stays available.

### Push-based approvals (user decision, 2026-10-16)

The core experience: leave the computer, lock the phone, still get and answer
approval requests. Notification delivery and lease ownership are independent:

1. Every approval opens a card for all devices with `control` — no lease needed
   to receive it.
2. Atem asks the relay (over its authenticated link) to push it:
   `push_approval{approval_id, atem_device_id, session_id, tool, summary,
   expires_at}`; the relay delivers via **APNs (iOS) / FCM (Android)** to every
   device on the account with `control`, online or not. Astation owns the push
   credentials, device token registration and the notification UI.
3. The notification shows "Claude on Genie wants to run `npm test`" (tool +
   short redacted summary only); marked `mutable-content` so iOS can decrypt it on
   device once end-to-end encryption lands.
4. Tapping wakes the app, which reconnects, authenticates as a member device and
   receives the pending approval; Allow once / Always allow (Claude) / Deny.
5. The answer needs `control` and the exact pending request, never the lease
   (r8 §G): it doesn't take, renew or move the lease, and `acquire` is refused.
6. Answered elsewhere, expired or closed → `push_resolved{approval_id}` replaces
   the notification everywhere (collapse-id / FCM tag = approval_id); a late tap
   says "already answered".
7. Hook waits: Claude 600 s (dialog stays visible; first answer wins), Codex
   300 s (prompt hidden while waiting; any local key releases it).

Phones can answer once they are members (step 1); until then only the paired
Astation can.

## 6b. Comparison with Codex Remote (ChatGPT mobile)

OpenAI's Remote lets a phone continue Codex chats, answer questions and approve
commands on a Mac/Windows host through OpenAI's relay
([announcement](https://openai.com/index/work-with-codex-from-anywhere/),
[architecture overview](https://codex.danielvaughan.com/2026/05/15/codex-mobile-chatgpt-app-relay-architecture-remote-agent-control/),
[pairing RPCs](https://codex.danielvaughan.com/2026/06/06/codex-cli-remote-control-mobile-pairing-app-server-v2-remodex/),
[app-server](https://developers.openai.com/codex/app-server/)).

| | Codex Remote | Atem + Astation |
|---|---|---|
| Agent session | `codex app-server`; an already running terminal session isn't shared live | the original terminal session stays live; chat comes from the agent's hooks and transcript |
| Phone view | structured thread items (messages, tool steps, diffs, approvals) | chat-v1 messages + terminal view |
| Approvals | `item/…/requestApproval` → accept / acceptForSession / decline / cancel | `PermissionRequest` hook → `approval_request` → `approval` by `control`, lease-free |
| Trust | QR pairing per phone per host + account MFA; list/revoke controllers per host | pair Atem once; add each device to the account once; Settings → Devices |
| Control | multi-device / local-terminal arbitration not documented | many viewers, one lease holder, local input wins |
| Relay | OpenAI relay; E2EE documented only by a third-party bridge | our relay; E2EE in step 2 (ephemeral X25519 + signed transcript) |

Borrowed: approval cards with push; recording the approval's source (our
receipts); a revocable controller list (Settings → Devices); the handshake shape
for step 2. Not borrowed: per-host pairing of every phone, and replacing the
terminal session with an app-server conversation.

## 7. Decisions (user, 2026-10-16)

1. **Who can add devices:** only devices marked "can manage devices" (role
   `manage`). The approval screen asks for it; off by default for phones. The
   first Astation (genesis, e.g. the Mac) starts as the **only** manager;
   further devices become managers only when the user marks them (confirmed by
   the user, 2026-10-16).
2. **Freshness (replaced 2026-10-19):** the 6 h heartbeat, head attestations
   and the 24 h window are dropped. The log suffix travels with every
   connection; a conflict signed by a current manager freezes remote access
   until the host is re-paired; manager keys
   require biometrics (§3.5).
3. **Decided (user, 2026-10-16): approvals from chat and mobile are allowed for
   whoever holds control.** No separate `approve` role: a device with `control`
   may answer (since r8 §G without the lease) the agent's permission
   prompts from the chat view or a phone, not only in the terminal. To keep a late
   or replayed tap from approving the wrong action, approvals are **bound to the
   exact prompt**: Atem announces `approval_request{approval_id, session,
   process_gen, tool, summary}` when the agent asks; the controller answers with a
   §6 submission `kind:"approval"`, payload `{approval_id, decision:
   allow|deny}` (r8: no lease, no `acquire`); Atem applies it only if that
   prompt is still the one pending, then records the receipt. Delivery to the
   agent (to be verified per agent): preferably the agent's own structured
   permission hook (Claude Code's permission hook answering allow/deny), else the
   exact keypress for that prompt. Built as its own step after membership (§6
   step 1b).

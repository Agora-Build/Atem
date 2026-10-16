# §9 proposal: one pairing, many devices on the same account

Status: Atem-side proposal for joint review, 2026-10-16. Answers
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
| Device key | each native Astation (Secure Enclave / platform keystore) | P-256 signing key + X25519 key; never leaves the device |
| Membership log | relay stores it (untrusted storage), every trusted device and Atem keep copies | append-only list of signed entries |
| Log entry | in the log | `{account_id, seq, prev_hash, action: add\|remove\|set_roles, device_id, device_sign_pub, device_enc_pub, roles, signer_device_id, signed_at}` + signature by a device whose roles include `manage` at `seq-1` |
| Genesis | entry `seq = 1` | `add` of the first Astation by itself, roles `manage, view, control` |
| Head attestation | produced on request by any online `manage` device | `{account_id, seq, head_hash, issued_at, atem_nonce?}` signed by a manager — "this is the latest log as of now" |
| Atem pin | Atem's `cred_state.json`, next to the existing verification pins | `{account_id, genesis_hash, high_water_seq, high_water_hash, last_fresh_at}` |

Roles: `view` (see sessions/output), `control` (take the lease, type, submit,
answer the agent's permission prompts while holding the lease), `manage` (add/remove devices).
Viewing ≠ control ≠ enrolment, as the product design requires.

## 3. Flows

### 3.1 Pairing (once per Atem)

Today's `atem pair` + safety-code verification, with one addition: Astation
sends the current membership log; Atem verifies the chain from genesis, checks
that the pairing Astation's verified key is a listed `manage` device, and pins
`genesis_hash` and the head as its high-water mark. The safety code also covers
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
2. Atem sends `challenge{nonce}`.
3. Device answers with: its device id, the log entries Atem doesn't have yet
   (from Atem's high-water seq to head), a **head attestation** that includes
   Atem's nonce (fresh) or one issued < 24 h ago, and a signature by its device
   key over the transcript (nonce, `atem_device_id`, `host_trust_gen`, both
   ephemeral X25519 keys).
4. Atem verifies: the new entries chain from its pinned high-water hash; the
   attestation is signed by a manager listed at that seq and isn't older than
   the head Atem already knows; the device is listed (not removed) with the
   roles it asks for; the transcript signature is the device's.
5. Both sides derive session keys from the ephemeral exchange (step 2 of this
   proposal: end-to-end encryption of the session channel). `welcome` grants
   exactly the device's roles; leases and receipts work as today.

### 3.4 Removing a device

Settings → Devices → Remove "Old iPad" on any manager device → `remove` entry
signed and appended. Atem applies it the next time any device connects (they
must bring entries up to the head) or when Atem polls the relay for the head.
Atem keeps the highest seq it has seen, so it never goes back to an older list.

### 3.5 Freshness and offline

- **Fresh proof:** a head attestation that echoes Atem's nonce, signed by an
  online manager, shows the list is current *now*.
- **Offline window (approved: 24 h):** with no online manager, Atem accepts an
  attestation issued < 24 h ago (Atem's own clock; also bounded by the time it
  last saw a fresh one). After 24 h without fresh proof, remote viewing/control
  pause; agents and the local terminal keep running.
- **A withheld removal** (relay or attacker hides the newest entries) can delay
  revocation by at most 24 h — the approved bound — and never past any newer
  head Atem has already seen.
- **Clock changes:** Atem measures the 24 h with both the monotonic and the wall
  clock and uses whichever expires first; a clock set backwards can't extend it.

### 3.6 Lost devices / recovery

If every manager device is lost, the account's log can't grow. Recovery is the
approved one: on each Atem host, local `atem unpair` + `atem pair` with a new
Astation, which starts a **new genesis** (new trust generation). Account data
and encryption keys are kept as today.

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
Devices (remove), head attestations on request, connecting to Atem with the
proof bundle. **Relay:** store and serve the log per account (append-only,
reject non-chaining appends as a convenience — not trusted). **Atem:** verify
the chain and attestations, pin at pairing, high-water + freshness state,
challenge/response in `hello`, roles → permissions, accept many attachments at
once (the runtime already multiplexes viewers; today it only admits the paired
Astation).

## 6. Steps

1. **Membership + freshness** (this proposal): log format, signatures, pairing
   pin, add/remove, connect proof, 24 h rule — plus shared fixtures (valid
   chain, forked chain, removed device, stale attestation, wrong account).
1b. **Approvals from chat/mobile:** prompt-bound `approval_request` /
   `approval` submissions for the lease holder (see question 3).
2. **End-to-end channel:** ephemeral X25519 + device keys → session keys for
   the atem-session channel over relay and direct; relay can no longer read
   terminal or chat traffic.
3. **Browser QR grants:** a native device signs `{browser key, target, scope,
   expiry ≤ 1 h}`; the browser proves its key on connect; same checks.

## 6a. Approvals in chat and on mobile (step 1b)

The lease holder may answer the agent's permission prompts from the chat view or
a phone. Both agents can take an external allow/deny without simulating keys:

| | Claude Code ([hooks](https://code.claude.com/docs/en/hooks)) | Codex ([hooks](https://developers.openai.com/codex/hooks)) |
|---|---|---|
| Hook | `PermissionRequest` — runs only when a permission dialog would appear | `PermissionRequest` — runs only when an approval would be asked |
| Input | `session_id`, `tool_name`, `tool_input`, `permission_suggestions` | `turn_id`, `tool_name`, `tool_input` |
| Answer | `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}` or `deny` + `message` | same shape |
| No answer | normal terminal dialog appears | normal prompt appears |
| Setup | per launch via `--settings` (as chat does) | `~/.codex/hooks.json`, trusted once in Codex (`/hooks`) |

Flow:

1. The hook writes the request (tool, summary) as one event file in the
   session's private directory, like the other chat hooks, then waits for a
   decision file.
2. The worker reports it; the runtime announces
   `approval_request{approval_id, session_id, process_gen, tool, summary,
   created_at}` to attached viewers; chat shows an **approval card** (tool,
   command or file, reason) with Allow / Deny, and a mobile app can raise it as
   a lock-screen notification.
3. **No remote controller** → the runtime answers "no decision" at once and the
   normal dialog appears in the terminal.
4. **Remote controller** → it answers with a §6 submission `kind:"approval"`,
   payload `{approval_id, decision: allow|deny}`, under its current lease epoch;
   the runtime checks that this prompt is still pending for that exact
   session/process, writes the decision file, records the receipt (which device,
   which lease, which prompt), and the hook returns the decision.
5. **Local keyboard input while waiting** → local input wins: the remote lease is
   revoked, the hook gets "no decision", the dialog appears.
6. **No answer within the hook's window** → no decision, dialog appears. Never
   auto-allow.

Changes to earlier rules: chat's "no approvals from chat" becomes "approvals by
the lease holder, bound to the exact prompt"; "hooks never decide" gains one
exception — the `PermissionRequest` hook may return a decision it received from
the runtime. To verify on the installed Claude Code before building: the hook's
default timeout and that `--settings` hooks fire for this event.

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
| Approvals | `item/…/requestApproval` → accept / acceptForSession / decline / cancel | `PermissionRequest` hook → `approval_request` → lease-bound `approval` |
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
   first Astation (genesis) is a manager.
2. **Freshness heartbeat:** besides on-demand attestations for Atem's nonce,
   every online manager re-signs the current head every 6 h, so a device can
   connect with a fresh-enough list even when no manager is reachable at that
   moment (still bounded by the 24 h window).
3. **Decided (user, 2026-10-16): approvals from chat and mobile are allowed for
   whoever holds control.** No separate `approve` role: a device with `control`
   that currently holds the session's lease may answer the agent's permission
   prompts from the chat view or a phone, not only in the terminal. To keep a late
   or replayed tap from approving the wrong action, approvals are **bound to the
   exact prompt**: Atem announces `approval_request{approval_id, session,
   process_gen, tool, summary}` when the agent asks; the controller answers with a
   §6 submission `kind:"approval"`, payload `{approval_id, decision:
   allow|deny}`, under its current lease epoch; Atem applies it only if that
   prompt is still the one pending, then records the receipt. Delivery to the
   agent (to be verified per agent): preferably the agent's own structured
   permission hook (Claude Code's permission hook answering allow/deny), else the
   exact keypress for that prompt. Built as its own step after membership (§6
   step 1b).

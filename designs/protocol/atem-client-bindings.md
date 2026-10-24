# atem-client bindings: the binding and effect contract

Status: built (Task 5 of `designs/plans/2026-10-20-r9.md`), for Astation's
integration. Crate: `crates/atem-client-ffi`. Protocol: the r9 appendix of
`atem-session-v1.md` (§R9.5–§R9.9). Integration view:
`remote-agent-api-atem.md` §6.

`atem-client` is the shared r9 client core: canonical encoding and
signatures, the membership verifier, `atem-ch1`, the r9 hello/welcome, r8's
session-v1 client machines, push hints and seen, the Recovery Kit, K
backups and the restore. `atem-client-ffi` puts a small, safe surface over
it for:

| consumer | binding | artifact |
|---|---|---|
| Astation macOS / iOS | UniFFI 0.32.2 → Swift | SwiftPM package `AtemClient` + `atem_client_ffiFFI.xcframework` (static libs: macOS arm64+x86_64, iOS arm64, iOS simulator arm64+x86_64) |
| Astation Android | UniFFI 0.32.2 → Kotlin (JNA) | `atem_client_ffi.kt` + `libatem_client_ffi.so` per ABI |
| browser, Node bots, the relay | wasm-bindgen 0.2.101 (feature `wasm`) | `atem_client_ffi.js` + `atem_client_ffi_bg.wasm` (+ `.d.ts`) |
| Rust bots | the `atem-client` crate itself | — |

Everything is sans-I/O: the app owns sockets, storage, timers, UI,
notifications and key storage. The binding takes bytes, times and key
results in and gives bytes, decisions and effects out.

## 1. What stays in Rust, what the app does

In Rust (one implementation, the same as the Atem host): canonical JSON,
`enc`, every signature check (P-256 low S, Ed25519 strict, alg pins), the
membership chain, signer authority, carriage, the conflict rule and freeze,
recovery waits, the channel handshake and records, the welcome checks,
lease/registry/chat ordering, push-hint verification, dedup and the
schedule, K-backup format and version allocation, the restore's anchor and
freshness rules.

In the app:

- **Keys** behind `AppKeyProvider` (§3). Native members' private keys never
  enter Rust. The exceptions are values the user or the account already
  hands to the app in the clear: the Recovery Kit's `R` (typed or scanned)
  and the account keys `K` (sealed into or opened from K backups).
- **Transport**: send the frames the binding returns, pass every frame
  received. Frames are JSON text (`{"ch":"atem-ch1",…}`), the same over
  the relay and Astation's :8080. Each `ClientConnection` is one virtual
  channel: the app's transport adapter carries its frames on that channel
  only, and the router wraps them in the channel envelope on Atem's link
  (atem-session-v1.md §R9.7a). The binding never sees the envelope or the
  routing handle.
- **Clock**: a monotonic time in ms for every channel call; the verifier
  clock (`HostClock{wall_ms, mono_ms, boot_id}`) for the log; wall ms for
  push hints.
- **Storage** (trusted local storage: the app's own container, not shared
  or synced storage):
  - the log's durable snapshot (`MembershipLog.stored_json()`), after every
    change and before acting on it (§2 "Durable state"). **Exclude it from
    device and cloud backups** (iOS `isExcludedFromBackup`, Android
    `allowBackup="false"` / `dataExtractionRules`; the same for the
    writers' `prepared_json()`): restoring a backup rolls the wait clocks
    and decisions back to an older state the verifier can't tell apart
    from the current one;
  - **every write in flight, before acting on it**: an `EntryPublisher`'s,
    a `KBackupWriter`'s and a `RestoreSession`'s `prepared_json()` (§R9.4
    rule 1, §R9.5 "Writing a backup" step 2). After a restart the app
    resumes from them (`EntryPublisher::resume`, `KBackupWriter::resume`,
    `RestoreSession::resume`), never starting a new write for the same
    device while one is saved (rule 4: nothing else is signed until the
    relay answered). `resume` reads the saved state strictly and checks the
    prepared body again with the verifier's schema, but the state is not
    integrity-protected: keep it where only the app can write;
  - `K` and the kit's `R` only in the platform key store.

  The host's head is authoritative for everything else.
- **Secrets returned to the app**: `RecoveryKitHandle::secret_r()`,
  `open_k_backup`'s keys and `RestoredInfo.keys` are copies the binding
  can't wipe once returned (UniFFI buffers, JS arrays). Store them in the
  key store at once and wipe the app-side buffers.
- **UI**: what the effects below say to show.

## 2. Objects and the order of calls

Names below are Rust's; Swift and Kotlin use lowerCamelCase methods and
UpperCamelCase types (`MembershipLog.verify(accountId:genesisHash:entries:now:)`,
`membershipLog.extend(entries, now)`), JS uses camelCase (§6).

### MembershipLog (§R9.2–§R9.5)

| call | effect for the app |
|---|---|
| `MembershipLog::from_stored(account_id, genesis_hash, stored_json, now)` | at start, from the committed snapshot; `account_id` and `genesis_hash` are the anchors the app holds (pairing, or the kit's), never the snapshot's own |
| `stored_json()` | the durable snapshot (canonical JSON): commit it after every change, before acting on it (below) |
| `MembershipLog::verify(account_id, genesis_hash, entries, now)` | a new log from signed entries alone (first enrollment, a fetch from the genesis): every pending wait starts at `now` |
| `entries()` | the entries (canonical JSON, in order): to carry or show |
| `extend(entries, now)` | after fetching `…/entries?after=` from the relay: keeps the valid prefix; check `stop` (`invalid` → report, `need_before` → fetch an earlier window, `deferred` → wait, `conflict:freeze` / `frozen` → show the frozen state, stop signing entries) |
| `evaluate(entries, now)` | the same without keeping it |
| `head()`, `relation(head)` | how a head another party signed relates (`same`, `host_behind`, `host_ahead` → fetch and extend, `diverged`) |
| `members()`, `member(id)`, `host(id)`, `recovery_key()`, `k_backup()`, `frozen()` | display, and the keys the app needs (a member's `enc_key`, the current kit) |
| `pending_recovery(now)` | show "Recovery of <subject> pending, takes effect <effective_at>: approve or cancel" |
| `advance(now)` | ends waits that are over on this clock |
| `draft_entry(signer, signed_at, action_json)` | the next entry's body, checked with the verifier's own schema; show it, then publish (below) |
| `check_member(member_json)` | a member object for `add` / `recovery_add`, checked |
| `capacity()` | `CapacityInfo{entries, max_entries, members, max_members, hosts, max_hosts, level, entries_level, members_level, hosts_level}`: the verifier's own counts against its limits (1024 entries; 256 members, counting members in effect and pending `recovery_add`s; 64 current hosts); `level` `ok` / `nearly_full` (≥ 90 % of any) / `full`. From `nearly_full` show a warning per limit (D23): entries, "renewals use one entry each; a full list needs re-pairing"; members, "remove expired or unused services so a place stays free for a Recovery Kit" (a full member list refuses the kit's `recovery_add` too); hosts, "remove hosts no longer used" |
| `check_change(action_json, now_ms)` | before `draft_entry` (same `action_json`; `now_ms` the `signed_at` it would carry): `None` to go ahead, else `ChangeRefusalInfo` `LogFull` (no entry fits, a removal included), `MembersFull` (no `add`, and no `recovery_add`: a Recovery Kit can't bring the account back until a member is removed), `HostsFull` (no `add_host` of a host that isn't current), `ServiceChangeTooSoon{last_signed_at, retry_at}` (JS `service_change_too_soon`: a service `set_roles` that grants anything new, e.g. a renewal, within 24 h of that service's last grant; a narrowing doesn't restart the clock; narrowing and `remove` are never paced). Advisory for signers: hosts still accept any valid entry |
| `admit_carrier(device_id, entries, more, now)` | host role, feature `host` only (never in an app build) |

The log object is shared by reference: `extend`, `advance`, a publisher's
or writer's reply change it in place. `snapshot()` copies.

**Durable state** (Atem #93). `stored_json()` is the log's durable form,
versioned (`"v": 1`), the same the host keeps in `membership.json` (§R9.3)
without the host's own fields: the entries, one recovery record per
pending-type entry with its wait clock (`first_seen_wall`, `boot_id`,
`mono_anchor_ms`, `mono_waited_ms`) and decision (`decided_at_wall`,
`decided_at_seq`, `order`, `reason`), the evidence, a freeze and the
derived head and recovery keys. Rebuilding from `entries()` with `verify`
loses what the entries can't say: every pending wait would start again at
`now`, and a wait-ended decision's chain position (which later entries are
judged against) would be lost.

- **The cadence: change, export, commit, act.** Every call that takes a
  clock reading or changes the log is followed by `stored_json()` and a
  durable commit (atomic replace and sync in the app's container, the §1
  storage rules) **before** the app acts on the returned effects, shows
  them, or exposes what they permit (a recovered device's access, a removed
  member's loss of it). The calls: `advance(now)`, `extend`, the publisher's
  and writer's replies (`reply_stored`, `reply_conflict`, `put_reply`,
  `append_stored`, `append_conflict`, `fetched`), and a `RestoreSession`'s
  `log()` after `attempt`. While `pending_recovery` is non-empty, run
  `advance(now)` → `stored_json()` → commit → act on its effects at least
  once a minute and when the app goes to the background or stops: only
  `advance` and `extend` record the time waited (`stored_json()` and
  `pending_recovery(now)` take no reading), so this is what keeps the time
  waited across a reboot. The effects are recomputable from the committed
  state; an action taken on state that was never committed is not.
- **A failed commit halts the adapter.** Don't act on the effects, don't
  sign or publish, don't show the new state as current; keep the last
  committed snapshot as the truth and retry the commit (or reload from it)
  before going on.
- **After a crash, reload, export, resume.** `MembershipLog::from_stored(account_id,
  genesis_hash, stored_json, now)` with the last committed snapshot, then
  at once `stored_json()` and commit (the load's clock reading re-anchors
  waits on a new boot only in memory), then continue (`advance(now)`,
  `pending_recovery(now)`, fetch and `extend`). On the same boot the result
  is what the log would have been without the restart. Across a reboot it
  is conservative: time from the last committed reading to the shutdown,
  and from the boot to the load, isn't counted, so a wait can only end
  later, never earlier. Effects of a change whose commit was lost are
  produced again by repeating the fetch or `advance`.
- **Timing.** `now` at load is the run's first reading of the verifier clock
  (`HostClock`), exactly as the host takes one at start: on the same
  `boot_id` every wait continues from its first sight (its monotonic
  anchor); on another boot from the persisted `mono_waited_ms`. Both clocks
  must pass: a wall clock set back neither ends a wait early nor restarts
  it (`first_seen_wall` is kept), a wall clock jumped forward alone ends
  nothing. No `signed_at`, relay time or host challenge in the snapshot
  counts as time waited or as freshness. `HostClock` times are
  milliseconds, at most 2^53 − 1: a larger value (e.g. nanoseconds) is
  refused by every call that takes one (`Invalid{malformed}`), so
  `verify`, `extend`, `evaluate`, `advance`, `pending_recovery` and the
  writers' replies all throw on it.
- **Versions.** `from_stored` reads snapshot version 1 only and refuses a
  missing `v` (`malformed`) or any other (`unsupported_version`, e.g. a
  snapshot written by a newer binding after a downgrade). A later binding
  that changes the format bumps `v` and must keep reading every earlier
  version (migrating it), so an app update never strands a committed
  snapshot; within a version the snapshot must be exactly what that
  version's `stored_json()` writes.
- **Checked, bounded, fails closed.** `from_stored` reads at most 16 MiB
  (the host's own bound on `membership.json`: a full log of 1024 entries
  with bodies ≤ 4 KiB, plus records and evidence), strict JSON, then the
  shared verifier rebuilds the state against the caller's anchors: the
  genesis is the pinned one, every entry verifies against the chain before
  it with the recorded decisions at their positions, one record per
  pending-type entry, decisions at positions the chain reached, the stored
  head, recovery key, retired keys and freeze equal the derived ones. A
  client's snapshot may hold the restore-only `host_confirmed` decision (a
  kit restore read through a past recovery on a host-signed head); the
  host's reader refuses that reason. Any failure is `AtemError::Stored`
  (§4) and nothing is restored: keep the adapter halted and recover the
  state with the user (re-verify from the relay's entries with `verify`,
  which restarts pending waits: conservative), never guess. The snapshot
  is not integrity-protected (the entries are signed, the clocks and
  decisions aren't): keep it where only the app can write, like
  `prepared_json()`, and out of backups (§1).
- **Restoring grants nothing.** The result is a verified log, like
  `verify`'s: no controller session, lease, host authority or channel; the
  app connects and is admitted as before.
- **Writers keep their own state.** `EntryPublisher`, `KBackupWriter` and
  `RestoreSession` persist their `prepared_json()` as before (§1) and are
  resumed from it. `EntryPublisher` and `KBackupWriter` take the log in
  their calls: pass the restored one (`EntryPublisher::resume`, then
  `reply_stored(log, …)`; `KBackupWriter::resume`, then `put_reply(log, …)`,
  `append_stored(log, …)`, …). `RestoreSession::resume` takes no log: it
  holds none until `attempt` succeeds again on a new fetch and host
  accept; then commit its `log().stored_json()` and use that log from then
  on. Commit order: a writer's `prepared_json()` before signing or
  sending, the log's snapshot after the reply that changed it.

### ClientConnection (§R9.7, §R9.8; r8 session-v1 inside)

```text
ClientConnection::new(host_id, identity, need_before)
start(log, now)                         → init frame            send
on_accept(frame, log, provider, now)    → finish frame          send   (sig_c: purpose Channel)
  or on_accept_deferred(frame, log, now) → SignRequest           sign it (async)
     finish_with_signature(sig, now)    → finish frame          send
on_welcome(frame, log, now)             → WelcomeInfo, or AtemError::Refused{next}
list / acquire / renew / release / submit_prompt / submit_interrupt /
submit_stop / submit_approval / submit_rule_revoke / receipt_query /
approval_seen / revoke_grant / send_membership / terminal_subscribe /
chat_open                               → Outgoing{id, frame}   send; replies carry re = id
send_json(message_json, now)            → frame                 send (other terminal-v1/chat-v1 messages)
on_frame(frame, now)                    → [ClientEvent]
```

Effects and timers:

- **Any `Channel` error** (and `Malformed`): close the transport (that
  connection's virtual channel only); the object is `Closed`. Make a new connection to retry.
- **`accept_deadline_ms()`**: give up waiting for `accept` then. The
  `finish` must follow `accept` within 10 s (a deferred signer must answer
  in time).
- **`AtemError::Refused{code, detail, error_json, next}`**: `Reconnect
  {need_before}` → a new `ClientConnection` with that `need_before`;
  `WaitForRecovery{entry_hash, effective_at}` → show it, retry after;
  `RetryLater` (busy); `Stop` → show the error, don't loop.
- **`AtemError::BadWelcome{check}`**: the host contradicted what the
  client verified; the channel is dropped. Report, don't retry blindly.
- **`WelcomeInfo`**: `authorization_ms_left` bounds the channel (the
  binding enforces it); show `pending_recovery`; `fetch_to(log)` → fetch
  up to that head and `extend` the log (never adopt it unverified).
- **`ClientEvent::Outgoing{frame}`**: send it now (a chat resync `open`).
- **`ClientEvent::MembershipHead{head, pending_recovery}`**: as `fetch_to`.
- **`ClientEvent::Fenced{code, detail}`**: the attachment is over
  (`unauthorized` with `removed`, `expired`, `grant revoked`, …, or
  `account_frozen`); the channel is closed. Reconnect to learn more.
- **`ClientEvent::Lease{session_id, outcome}`**, `lease(session, now)`:
  while `controls`, call `renew` every 5 s; stop at `deadline_ms`.
- **`ClientEvent::Session{op, id, re, json}`**: receipts (`receipt`, its
  `state` `accepted`/`completed`/`rejected`/`outcome_unknown`),
  `receipts` (a query's answer), `sessions`/`session_changed` (the registry,
  also through `sessions()`), approvals, `lease_changed`, errors with `re`.
- **`ClientEvent::Error{code, re}`**: a refused request (`forbidden`,
  `unknown_session`, `lease_held`, `stale_lease`, …). Its `json` is the
  whole error: a `lease_held` names the holder in `controller`
  (`{controller_session, lease_epoch}`), which a confirmed takeover sends
  back as `expected_controller` (r8 §F).
- **`approval_seen`**: only when the card was rendered in a focused
  foreground window and the user was active in the last 60 s; never from a
  background delivery or a notification.
- **`submit_prompt`** acquires the lease with the prompt (r8 §F) when none
  is held; keep `request_id` (a UUID v4) to `receipt_query` it after a
  reconnect.
- **`binding_json(session, mutation, now)`**: the binding for messages the
  app builds: `mutation` false for reads (subscribe, open, history, ack),
  true for terminal input/resize (none without the lease).

### EntryPublisher (§R9.4 client rules 1–5)

1. `prepare(log, body_json)`; **persist `prepared_json()`** (the body is
   stored before the key signs it).
2. `sign(provider, key_id, cosign_kit)`: one fresh owner confirmation of
   that body (`cosign_kit`: the current kit for `set_recovery_key` with
   `kit: "current"`); persist `prepared_json()` again.
3. Send `POST …/entries {"entry": <entry_json>, "expected": <expected>}`.
   On an uncertain outcome resend exactly `outstanding()`.
4. `reply_stored(log, now)` (200) or `reply_conflict(log, head, entries,
   more, now)` (409); persist `prepared_json()` (now none).

| outcome | the app |
|---|---|
| `Committed{head}` | done; the log holds it |
| `StoredPending{head, on}` | stored at the relay; joins the log when `on` takes effect here |
| `LostRace{head}` | our body is discarded; re-check the intent on the new head; a new body needs a new confirmation |
| `FetchMore{after}` | fetch after `after`, `extend`, decide again |
| `Diverged` | stop signing entries; carry the window to hosts |
| `Waiting{on}` | wait for `on` |
| `RelayInconsistent{head}` / `RelayInvalid{index, code}` | refetch later; never rebuild on the unchanged head |

After a restart: `EntryPublisher::resume(saved)`, then resend
`outstanding()`, or `sign` again (a lost signature is re-made over the same
body, the same `entry_hash`).

The publisher gives up the device's claim (§5) as soon as the relay's
answer is applied (`reply_stored` / `reply_conflict`), whatever the
outcome: the body is then committed or discarded, and the next write may
start.

### KBackupWriter (§R9.5 "Writing a backup")

`KBackupWriter::start(log, kids, kit_recovery_key, signer)`, then perform
each `BackupStep` and feed the answer back:

| step | the app |
|---|---|
| `Seal{blob_version}` | `seal_k_backup(account, genesis, blob_version, kit_recovery_key, keys)` (the app holds `K`), then `sealed(log, envelope_json, signed_at)` |
| `Sign{body_json}` | `sign(provider, manager_key)` (purpose `KeyBackup`, fresh confirmation of `body_json`) |
| `Put{blob_version, bytes}` | upload put-if-absent, then `put_reply(log, None)` (200) or `put_reply(log, Some(max_occupied))` (409) |
| `Append{request}` | append with the CAS, then `append_stored` / `append_conflict` |
| `Fetch{after}` | fetch, then `fetched(log, entries, more, now, signed_at)` |
| `Done{committed}` | the newest committed backup covers the job |
| `Failed{code}` | stop (`relay_misbehaviour`, `diverged`, `waiting`, …) |

`restart()` after an uncertain outcome resends the upload, then the entry.

Durability (§R9.5 step 2, §R9.4 rules 1 and 4): **persist
`prepared_json()` after every call, before performing the returned step**.
It holds the job, the phase, the envelope bytes and their version, the
versions uploaded and not committed, the last `max_occupied`, the prepared
`k_backup` body (and its signature once signed) and what was discarded;
`None` once nothing is in flight (`Done`, `Failed`). After a restart,
`KBackupWriter::resume(saved)` stands at the same step: it signs the same
body again (same `entry_hash`, never a sibling); a writer saved with its
append in flight resends the same envelope first (`Put`, §R9.5 step 6),
then the same signed entry (`Append`). Don't `start` a new backup while a
saved one exists. `resume` refuses state whose parts don't belong together
(the phase and what it needs, the prepared body naming the stored
envelope's `blob_version` and `backup_hash`, the job's signer, the
account).

`sealed`, `sign`, `put_reply`, `append_*`, `fetched` and `restart` can
also fail with `Publish{code: outstanding}`: applying the step would give
the device a second prepared body while another publisher or writer of the
same device holds one (§5).

### RecoveryKitHandle, K backups

- `RecoveryKitHandle::generate(account_id, genesis_hash)` at account setup:
  print `secret_r()` and `kit_tag()` for the user, put `recovery_key()` in
  the genesis or a `set_recovery_key`; store nothing.
- `RecoveryKitHandle::read(r, account, genesis, tag)`: `kit_tag_mismatch`
  ("this Recovery Kit is damaged or mistyped") before anything is fetched.
- `parse_k_backup`, `open_k_backup(envelope, kit)`, `seal_k_backup(…)`.

### RestoreSession (§R9.5 "Restore"; no recovery on a stale head)

1. `RestoreSession::read(r, account, genesis, tag)`.
2. Fetch the relay's log and newest envelope; reach at least one host and
   keep its `init`/`accept` pair; `attempt(entries, envelope, [HostAcceptPair],
   now)`.
   - `no_host_reachable`: show `waiting_for_hosts()` ("Recovery needs to
     reach one of your Atem hosts (<names>) …") and retry; never fall back.
   - `log_behind_host` (`refetch()`): fetch again or by another route.
   - other codes: show, stop. Nothing is stored on any refusal.
3. Success (`RestoredInfo{head, keys}`): store `keys` in the key store,
   then `enroll(member_json, signed_at)` (the kit signs the `recovery_add`),
   **persist `prepared_json()`**, send the `AppendRequest`, then
   `append_stored(now)` → `Published{head}` (takes effect after 24 h unless
   approved or vetoed) or `append_conflict(…)` → `Rebuild` (run `attempt`
   again) / `Stopped`.
   After a restart in between: `RestoreSession::resume(r, account, genesis,
   tag, saved)`, `attempt(…)` with a new fetch, resend `outstanding()`, then
   `append_stored` / `append_conflict`; `enroll` is refused (`outstanding`)
   while that `recovery_add` is in flight. `resume` refuses a saved body
   that isn't this kit's `recovery_add` (signer `recovery`, the kit's
   account and genesis).
4. `may_rotate_k(device)` / `may_seal_backup(device)` stay false until the
   recovery took effect.

`verify_host_accept(init, accept, log)` checks one host-signed head on its
own; `host_accept_th2` gives its `th2`.

### Push hints and seen (§R9.9)

A phone receiving a hint (APNs/FCM payload):

1. `verify_push_hint(hint_json, log, wall_now, Client)` (exact fields, the
   host's newest key, binding, times, skew, staleness);
2. `book.offer(hint)` on its `PushHintBook` (`accepted` → show,
   `idempotent` → already shown, `ignored_after_resolved`, or refused
   `duplicate`/`bad_sealed`); a resolved hint replaces the notification;
3. `hint.open(provider, enc_key_id, device_id)` → `HintContent{tool,
   summary}` (HPKE open by the provider; refused for another device or
   `enc_key` before anything is opened). A locked device shows a generic
   hint instead.

The relay: `verify_push_hint(…, Relay)`, its book, `push_stages(created_at,
recipient)`, `push_send_now(…)`, `push_next_due(…)`, `push_guard(expires_at)`
(all from the signed `created_at`; never the relay's receipt time),
`verify_seen`, `seen_in_window`, acks (`hint.ack_json()`, `seen_ack_json`,
`push_ack_message`, `parse_push_ack`). `sign_seen` is the host's (feature
`host`, never in an app build; an app provider should refuse a
`HostSigning` request anyway).

### Browser grants (§R9.6)

The phone issues one for a browser's public key (a QR):
`issue_browser_grant(log, provider, issuer_key_id, issuer, browser_key,
host_id, host_trust_gen, session_id, ops, issued_at, expires_at)` (purpose
`BrowserGrant`, fresh confirmation; ≤ 1 h; `ops` contain `view`; a
control op gives the browser control within them). The browser connects
with `ClientIdentity{kind: Browser, key_id, grant_json}`; any member with
control revokes it with `revoke_grant`. `parse_browser_grant` reads one.

### Encoding helpers

`canonical_json`, `encode_fields`, `hash_fields` (SHA-256 of `enc`),
`signing_input(label, payload)`, `verify_signature(key, label, payload,
sig)`, `signed_object_info`, `verify_signed_object`, `enc_kid`,
`ed25519_public_to_x25519` (the kit's HPKE key; CryptoKit lacks it),
`check_public_key`.

### Pairing ceremony

`verify_commit_host_trust_gen(message_json)` (JS `verifyCommitHostTrustGen`)
reads `verifyCommit.host_trust_gen` as §R9.2 requires: strict JSON, a JSON
integer 1 ≤ n ≤ 2^53−1, present. It fails `Invalid{code}` with `malformed`,
`not_verify_commit`, `absent` or `out_of_range`; answer `verifyAbort`.
Astation must read the field with this function, never by decoding it
itself: Swift's `JSONDecoder` accepts `3.0` and `3e0` as an `Int`, which
the contract refuses (vectors `r9-vectors-pairing`).

## 3. The KeyProvider contract and signing purposes

```text
trait AppKeyProvider (Swift protocol / Kotlin interface):
  public_key(key_id) -> PublicKeyData{alg, raw}
  sign(SignRequest{key_id, purpose, fresh_confirmation, label, input, body_json}) -> bytes
  x25519(key_id, peer) -> 32 bytes
  hpke_open(key_id, enc, ct, info, aad) -> plaintext
errors: ProviderError.Cancelled{reason} | UnknownKey | Failed{reason}
```

- **Formats.** P-256: public key SEC1 uncompressed (65 bytes); signature
  ECDSA over SHA-256 of `input`, 64-byte `r‖s`, either S (the core
  normalizes to low S and verifies it before use). Ed25519: 32-byte public
  key, signature over `input`. X25519: 32-byte keys; `x25519` returns the
  raw shared secret (the core refuses all-zero). HPKE: RFC 9180 base mode,
  DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (CryptoKit
  `HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly`, macOS 14 / iOS 17; Tink
  on Android).
- **Purposes** (`SignRequest.purpose`, derived by the binding from the
  signing label and, for entries, the body's `action`):

  | purpose | what is signed | confirmation (R9.6) |
  |---|---|---|
  | `Channel` | `sig_c` over the transcript (`body_json` none) | may reuse one owner confirmation ≤ 5 min; cleared on lock and background |
  | `Genesis` | the account's first entry | fresh, bound to `body_json` |
  | `Enroll` | `add` | fresh |
  | `Remove` | `remove` | fresh |
  | `Roles` | `set_roles` | fresh |
  | `Host` | `add_host`, `remove_host` | fresh |
  | `Recovery` | `recovery_add`, `recovery_approve`, `recovery_veto` | fresh |
  | `Kit` | `set_recovery_key`, the current kit's co-signature | fresh |
  | `KeyBackup` | `k_backup` | fresh (decision: a manager entry like the others) |
  | `BrowserGrant` | a browser grant | fresh |
  | `HostSigning` | `sig_h`, push hints, seens | never asked of a client |

  `fresh_confirmation` is true for every purpose but `Channel` and
  `HostSigning`. A fresh confirmation covers exactly `body_json` (show the
  account, head and seq, applicant keys, roles, scope, expiry); a changed
  body needs a new one; never in the background or a notification
  extension. Managers' keys always need owner authentication (biometrics
  with the passcode fallback).
- **Cancel.** Return `ProviderError.Cancelled`: nothing is sent; the call
  fails with `Channel{code: signing_failed}` (handshake) or `Publish{code:
  sign}` / `Invalid{code: provider_error}`.
- **Asynchronous signers** (WebCrypto, or an app whose owner-auth prompt
  must not block a thread): `on_accept_deferred` returns the
  `SignRequest`; sign `input` and call `finish_with_signature(signature,
  now)` within the 10 s step. The signature is normalized and verified
  with the identity's own key before anything is sent: the member's
  `auth_key` in the client's verified log, or the grant's `browser_key`
  (a device missing from its own log is refused `Request{this device is
  not in the verified log}` at `on_accept`). Browsers do this with a
  non-extractable WebCrypto P-256 key:

  ```js
  const keyPair = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const req = conn.onAcceptDeferred(acceptFrame, log, now());
  const sig = new Uint8Array(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, keyPair.privateKey, req.input));
  socket.send(conn.finishWithSignature(sig, now()));
  ```
- **Bots** (`service` principals; R9.6 rule 5) hold a software key from
  their own secret store: feature `software-keys` exports
  `SoftwareKeyStore` (`insert_p256`, `insert_ed25519`, `insert_x25519`,
  `generate`; `provider()` in Swift/Kotlin, passed directly in JS). Never
  for a native member's keys; not in the shipped app artifacts.

## 4. Errors

`AtemError` (Swift `AtemError`, Kotlin `AtemException`, JS a thrown
`Error` with `kind`, `code`, `detail` and the variant's fields):

| variant | `code` (stable) |
|---|---|
| `Invalid{code, detail}` | the crate's: `not_strict_json`, `not_canonical`, `too_large`, `null_value`, `malformed`, `unknown_type`, `array_not_canonical`, `kit_sig_missing`, `kit_sig_unexpected`, `bad_key`, `weak_key`, `wrong_alg`, `high_s`, `bad_signature`, `zero_shared_secret`, `open_failed`, `backup_invalid`, `kit_tag_mismatch`, `genesis_mismatch`, `unknown_key`, `provider_error`; `not_canonical` also for a caller's integer above 2^53 − 1 (a time, a version) that would enter a signed body; `malformed` for a `HostClock` time above 2^53 − 1 |
| `Membership{code, detail, index}` | `membership_invalid`; `detail` the verifier's (`bad_signature`, `gap`, `signer_not_manager`, `blob_version_not_increasing`, `kit_sig_missing`, …); `index` into what was passed |
| `Channel{code, detail}` | `handshake_failed`, `stale_target`, `account_frozen`, `busy` (also as the host's clear, advisory error before the channel opens), `unknown_host`, `record_rejected`, `limit`, `too_large`, `closed`, `signing_failed`, `invalid_hello`, `cannot_carry` (a divergence deeper than any carriage) |
| `Refused{code, detail, error_json, next}` | the host's session error code (`unauthorized`, `membership_invalid`, `membership_incomplete`, `recovery_pending`, `account_frozen`, `unsupported_version`, `busy`, …) |
| `BadWelcome{check}` | `bad_welcome` (`check`: `revision`, `re`, `channel_id`, `principal`, `account_id`, `host`, `head`) |
| `Request{detail}` | `request` (`unknown session`, `no lease`, `too many requests in flight`, `not attached`, …) |
| `Restore{code, detail}` | `kit_tag_mismatch`, `genesis_mismatch`, `membership_invalid`, `no_host_reachable`, `log_behind_host`, `kit_not_current`, `no_backup`, `backup_hash_mismatch`, `backup_invalid` |
| `Publish{code, detail}` | `outstanding` (also: another publisher or writer of this device holds a prepared body), `not_on_head`, `nothing_prepared`, `sign` |
| `Push{code, detail}` | `malformed`, `binding`, `bad_signature`, `invalid_times`, `skew`, `stale`, `bad_sealed`, `duplicate` |
| `Stored{code, detail}` | `MembershipLog::from_stored` refused the snapshot: `too_large` (over 16 MiB), `malformed` (not strict JSON, not an object, no `v`, no `account_id`/`genesis_hash`), `unsupported_version` (a `v` other than 1), `account_mismatch`, `genesis_mismatch` (the snapshot's are not the caller's anchors), `stored_invalid` (the shared verifier refused it, or it isn't exactly `stored_json()`'s form); a malformed anchor argument is `Invalid` |
| `State{detail}` | `state` (a call out of order: `already started`, `not waiting for accept`, `no signature pending`, …; or the object changed while the provider was signing) |

`detail` is for logs and may change; branch on the variant and `code`.

## 5. Threading

- Every object is thread-safe (an internal lock held only for the call)
  and can be used from several threads at once: `MembershipLog`,
  `ClientConnection`, `EntryPublisher`, `KBackupWriter`, `RestoreSession`,
  `PushHint`, `PushHintBook`, `RecoveryKitHandle`. Records are values.
- **No binding lock is held while the app's provider runs.** The calls
  that sign (`ClientConnection::on_accept`, `EntryPublisher::sign`,
  `KBackupWriter::sign`, `issue_browser_grant`, `PushHint::open`) do their
  work under the lock, release it, call the provider, then take the lock
  again to apply the result. So a provider waiting on an owner-auth prompt
  doesn't block a UI thread reading the log, the registry or a writer's
  step, and a provider may call any binding object. If the object moved
  meanwhile (another thread answered the same step), the call fails with
  `AtemError::State` ("… changed while the provider was signing") and
  nothing is applied.
- Provider callbacks run synchronously on the thread that called the
  binding. Call the binding off the main thread (a provider may block on a
  biometric prompt), or use the deferred handshake.
- One outstanding append per device (§R9.4 rule 5): within the process, a
  second `EntryPublisher` or `KBackupWriter` for the same account and
  signer is refused `Publish{code: outstanding}` while one holds a prepared
  body (the claim ends when the relay answered, at `Done`/`Failed`, or when
  the object is freed). Across restarts, use the saved state.
- One `ClientConnection` per virtual channel (§R9.7a); feed its frames
  in order. Several connections may share one network connection to the
  router; each has its own channel, keys and attachment.
- WASM is single-threaded; nothing blocks inside the binding.

## 6. Data conventions

- Hashes and genesis hashes: lowercase hex. Keys: raw bytes with their
  `alg`. Signed objects, entries, grants, hints, envelopes: JSON text
  (strict on input; canonical on output). Times: ms.
- Swift: `Data`, `UInt64`. Kotlin: `ByteArray`, `ULong`
  (`1793264001000uL`). JS: `Uint8Array`, numbers (all r9 times are below
  2^53), records as plain objects with camelCase fields, enums with data as
  `{type: "<snake_case>", …}`, unit enums as strings; an absent value is
  `null` inside an object and `undefined` as a plain return. JS takes
  records such as the clock as objects (`{wallMs, monoMs, bootId}`) and
  enum values as strings (`"p256"`, `"client"`, `"mobile"`).
- `ClientConnection.disconnect()` closes the channel: its keys are wiped
  and the app closes that virtual channel only (the router sends Atem the
  envelope's `close` for its handle); the shared link and other clients'
  channels stay, and Atem fences only that channel's attachment (Swift/Kotlin
  objects also have the generated `close()`/`destroy()` that free the
  Rust object).

## 7. Building and consuming

Feature flags of `atem-client-ffi`:

| feature | |
|---|---|
| `uniffi` (default) | the Swift/Kotlin scaffolding |
| `bindgen` | the `uniffi-bindgen` binary (library mode) |
| `wasm` | the wasm-bindgen surface (`--no-default-features --features wasm`) |
| `software-keys` | `SoftwareKeyStore` (bots, tests) |
| `test-vectors` | raw primitive verification for the vectors (implies `software-keys`) |
| `host` | host-role functions and types (`sign_seen`, `admit_carrier`, `AdmissionInfo`), for the conformance and host-side tests |

Shipped artifacts use the defaults only (`wasm` alone for JS); the
conformance builds add `software-keys,test-vectors,host`.

- **Apple:** `scripts/package-atem-client-apple.sh <version> <out>` →
  `<out>/AtemClient` (SwiftPM: `Package.swift`, `Sources/AtemClient/atem_client_ffi.swift`,
  `atem_client_ffiFFI.xcframework`), `atem-client-<version>-apple-swiftpm.zip`,
  the C header and `SHA256SUMS`. Add the package (local path, or the
  unzipped release asset) and `import AtemClient`. Platforms: macOS 14,
  iOS 17 (CryptoKit HPKE).
- **Android:** `ANDROID_NDK_HOME=<ndk> scripts/package-atem-client-bindings.sh
  <version> <out> android` (Linux x86_64; `rustup target add
  aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`)
  links the release cdylib for arm64-v8a, armeabi-v7a and x86_64 with the
  NDK's clang (`ANDROID_API`, default 24) and `-z max-page-size=16384`,
  checks each library's ELF class, machine and 16 KB LOAD alignment, and
  zips them with the generated Kotlin. In the app: the `.so` files under
  `src/main/jniLibs/<abi>/`, the Kotlin in its sources, and
  `net.java.dev.jna:jna:5.19.1@aar`.
- **JVM:** generate Kotlin with `cargo run -p atem-client-ffi --features
  bindgen --bin uniffi-bindgen -- generate --library <host lib> --language
  kotlin --out-dir <dir>` and use it with the JNA jar.
- **WASM:** `rustup target add wasm32-unknown-unknown`; `cargo build -p
  atem-client-ffi --target wasm32-unknown-unknown --release
  --no-default-features --features wasm`; `wasm-bindgen --target web` (or
  `nodejs`, `bundler`) with wasm-bindgen-cli 0.2.101 exactly.

### Getting the packages (CI artifacts)

Every run of `.github/workflows/atem-client-bindings.yml` (pushes to main,
pull requests touching the crates, fixtures or these scripts, and manual
runs) uploads the production packages as workflow artifacts. They are
built with the default features only (`wasm` alone for JS): no
`software-keys`, `test-vectors` or `host` code is in them. Nothing is
published to a registry. Every package is built from the commit under
review: a pull request's **head** commit (the workflow checks it out
explicitly, never GitHub's synthetic merge of the PR into main), or the
pushed commit on main. `<version>` is the crate version and that commit's
first 12 hex digits (`0.1.0-5e14c29c8f6a`). CI fails unless every package's
pin names exactly that commit with `tree_dirty: false`.

| artifact | built on | files |
|---|---|---|
| `atem-client-apple-swiftpm-<version>` | macos-latest (`scripts/package-atem-client-apple.sh`) | `atem-client-<version>-apple-swiftpm.zip` (the SwiftPM package `AtemClient` with `atem_client_ffiFFI.xcframework`), `atem-client-<version>-atem_client_ffiFFI.h`, `-SOURCE.json`, `-SHA256SUMS.txt` |
| `atem-client-wasm-<version>` | ubuntu-latest (`scripts/package-atem-client-bindings.sh … wasm`) | `atem-client-<version>-wasm.tar.gz` (`atem-client-wasm/{web,nodejs,bundler}/`: `atem_client_ffi.js`, `atem_client_ffi_bg.wasm`, `.d.ts`), `-SOURCE.json`, `-SHA256SUMS.txt` |
| `atem-client-kotlin-jvm-linux-x86-64-<version>` | ubuntu-latest (`… kotlin`) | `atem-client-<version>-kotlin-jvm-linux-x86-64.tar.gz` (`src/uniffi/atem_client_ffi/atem_client_ffi.kt`, `linux-x86-64/libatem_client_ffi.so`, `atem-client-ffi-<version>.jar`: the compiled bindings with the library inside, for JNA on a Linux JVM), `-SOURCE.json`, `-SHA256SUMS.txt` |
| `atem-client-android-<version>` | ubuntu-latest, NDK r28c `28.2.13676358` (`… android`) | `atem-client-<version>-android.zip` (`atem-client-android/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libatem_client_ffi.so`: minSdk 24, LOAD segments 16 KB aligned; `kotlin/uniffi/atem_client_ffi/atem_client_ffi.kt`, the same source as the JVM package; `README.txt`), `-SOURCE.json`, `-SHA256SUMS.txt` |

CI checks the Android libraries the way `scripts/check-atem-client-packages.sh`
does after a download: each ABI's ELF class and machine, every LOAD
segment aligned to 16 KB, the UniFFI exports present and no test-only or
host-role symbol. They are not run on a device or emulator in CI.

`atem-client-<version>-SOURCE.json` is the source pin: `commit` (full SHA)
and `tree_dirty`, `crates` (`atem-client`, `atem-client-ffi`, and
`uniffi`, `wasm-bindgen` from `Cargo.lock`), `features`, and `toolchain`
(`rustc`, `cargo`, and per package `wasm-bindgen-cli`, `kotlinc`, `jna`,
`android-ndk`, `xcodebuild`, `swift`).

To take one (`gh` with read access to the repository; artifacts expire
after GitHub's retention, 90 days). `<sha>` is the full commit you were
asked to integrate (the PR head named on #80/#81, e.g. `gh pr view 89 -R
Agora-Build/Atem --json headRefOid -q .headRefOid`):

```sh
gh run list -R Agora-Build/Atem -w atem-client-bindings -c <sha> -L 5   # runs of exactly that commit
gh run download <run-id> -R Agora-Build/Atem -n atem-client-wasm-<version> -D atem-client-wasm
cd atem-client-wasm
shasum -a 256 -c atem-client-<version>-SHA256SUMS.txt        # every file: OK
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); assert p["commit"] == sys.argv[2] and p["tree_dirty"] is False, p; print("pin ok")' \
  atem-client-<version>-SOURCE.json <sha>
```

Only then unpack (`unzip` / `tar xzf`) and use it. A mismatching sum, a
pin naming another commit (for instance a merge commit) or `tree_dirty:
true` means the download is not the build you asked for: don't use it.
`EXPECT_COMMIT=<sha> scripts/check-atem-client-packages.sh <version> <dir>`
is what CI runs on the Linux packages (sums, the pin's commit and clean
tree, no test-only or host-role export, and one call through the Node
build and the JVM jar); it can be run on a download the same way.

## 8. Tests

`scripts/check-atem-client-bindings.sh [kotlin] [wasm] [swift] [e2e]`
(toolchains passed in: `KOTLINC`, `JNA_JAR`, `JAVA`, `NODE`,
`WASM_BINDGEN`); CI: `.github/workflows/atem-client-bindings.yml` (Linux:
Rust, Kotlin, WASM, end to end; macOS: Swift, the package dry run).

- **Conformance** (the same 38 checks in each language, over
  `designs/protocol/fixtures/r9-vectors-*.json`): `bindings/kotlin/Conformance.kt`
  (with a Kotlin `AppKeyProvider` on the JDK's crypto: P-256 signing, HPKE
  open), `bindings/js/conformance.mjs`, `bindings/swift/Tests/AtemClientTests/ConformanceTests.swift`
  (with a CryptoKit `AppKeyProvider`).
- **Durable log** (`tests/stored_log.rs`, Rust; one conformance check per
  language): a partly elapsed wait across a same-boot restart and a reboot,
  the wall clock set back after restore, a wait-ended decision at its chain
  position (with the entry that relies on it), pending, approved and vetoed
  recovery and key-replacement records, a frozen log, corrupted, oversize,
  extended, unversioned or newer and mismatched snapshots refused, clock
  readings above 2^53 − 1 refused, and a restored log driving a resumed
  `EntryPublisher`, a `KBackupWriter` and a `RestoreSession`'s log
  (including a read-through restore's `host_confirmed` decision; the host's
  reader still refuses it: `src/session_protocol/membership/tests.rs`).
- **Flows** (`bindings/js/flows.mjs`): the K-backup writer and its 409s,
  the restore's enrollment, the publisher's 409, host-role admission, the
  recovery wait, kits, push books, acks and seens, object state errors.
- **End to end** (`tests/e2e_bindings.rs`): a Kotlin phone and a
  Node/WASM browser (WebCrypto key, deferred handshake) use a test host
  over loopback TCP: hello and welcome, list, lease, prompt and receipts,
  the other session requests, a browser grant, push hints (verified,
  opened, seen), a membership entry carried on the channel, the grant's
  revocation and the browser's fence. The host is built from atem-client's
  responder role (`atem-client/tests/support/host.rs`). The real runtime
  host runs the shared r9 host fixtures in
  `src/session_protocol/membership/fixtures_tests.rs` (real engine, store
  and session host) and `tests/r9_*_binary.rs` (the `atem runtime`
  process).

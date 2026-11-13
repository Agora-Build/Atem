# atem-client bindings: the binding and effect contract

Selected-Station addition (the binding helpers shipped in Atem v0.8.2; the
native sender that calls them is Astation's):
`stationRouteOffer(requestJson:relayUrl:relayOnly:sessionToken:)` uses the
shared strict decoder, origin normalization and domain-separated HMAC for
[Selected Station Handoff v1](station-route-v1.md). Native must validate and
recheck the exact authenticated session, account, selected Station and
connection before signing/sending. After saving the selection, the host sends
an authenticated `accepted` acknowledgment; native verifies it against its
exact pending offer with
`stationRouteVerifyAccepted(offerJson:acceptedJson:sessionToken:)` and
rechecks the captured app context. The helpers perform no I/O and grant no
R9 authority. Stage the selected endpoint and verify acceptance before
committing R9 relay-only policy on a direct socket. Conformance uses
`fixtures/station-route/v1.json`.

Remote launch and messages use the existing production binding surface. Check
the admitted welcome's features, then send session-family JSON through
`ClientConnection::send_json` (Swift/Kotlin/WASM: `sendJson`; Rust core:
`Attached::send`). Results arrive as
`ClientEvent::Family { family: "session", op: "host_work_result", json }`.
The core checks the exact host, channel, attachment and request correlation
before emitting that event; apps still inspect errors and each result state.

| Feature | Operations | Contract |
|---|---|---|
| `host.launch` | `host_profiles`, `host_launch`, `host_launch_query` | [Host work](atem-host-work-v1.md) |
| `host.work` | `work_enqueue`, `work_query`, `work_cancel`, `work_complete` | [Host work](atem-host-work-v1.md) |
| `host.reply` | `reply_query` | [Host work](atem-host-work-v1.md#reply) |
| `host.messages` | `message_publish`, `message_query` | [Host work](atem-host-work-v1.md#5-messages) |
| `host.attachments` | `attachment_put` | [Host work](atem-host-work-v1.md#6-attachments-and-mark) |
| `host.delegated` (planned; no host advertises it yet) | `work_interrupt`, `work_resolve` | [Host work §11.2](atem-host-work-v1.md#112-work_interrupt-and-work_resolve) |
| `host.alerts` (planned; no host advertises it yet) | `alert_list` | [Host work §11.3](atem-host-work-v1.md#113-alert_list-hostalerts) |

The two planned features' results are host-work results too:
- `alert_list` answers with an `alerts` result kind, and `work_resolve` with
  a `work` result that carries `resolved`.
- Released readers reject both, so Atem and Astation enable these features
  together (host-work-v1 §11.2, "Compatibility").

Planned, advertised by no host yet: `host.senders`'s two session ops,
`control_records` and `host_enc_key_get`, go through `send_json` the same way
(session-v1 R9.8, R9.14). The core refuses them without the feature, reads them
as the host does and tracks each request, and their answers arrive as
`ClientEvent::Family` with `op` `control_records_result` or `host_enc_key`. A
`host_enc_key` answer is taken only from the channel's host at its trust
generation; its `host_id`, `host_trust_gen`, `enc_key.pub` and `enc_sig` are the
arguments of `host_enc_key_action` (below), which a manager signs.

Persist launch request IDs and immutable message/task identities before sending.
Recover uncertain results with their query operations; a retry uses a fresh
exchange `id` and preserves the original request or envelope. A `started` launch
does not mean chat is ready, and `awaiting_result` work does not mean the task
is complete. The client tracks at most 64 outstanding host-work exchanges;
reconnect and query after a lost response rather than filling that bound.

Upgrade every participating strict membership verifier before signing grants
with the new `launch`, `message` or `notify` ops. Existing grants do not acquire
these permissions automatically. Native launch/work needs account control and
local host consent; services additionally need the explicit scoped ops. The
current Station marks path reuses the token's `agent.view`/`agent.prompt`
scopes plus separately approved signed `message`/`notify` permissions. Service
launch token scopes and HTTP adapters remain Station/Auth/Portal integration
work; `agent.prompt` alone does not authorize creating a process.

Every production SDK artifact includes
`atem-client-<version>-host-work-requests-v1.json`,
`atem-client-<version>-host-work-prompt-framing-v1.json`,
`atem-client-<version>-host-work-framing-size-v1.json`,
`atem-client-<version>-r9-vectors-host-work-control.json`,
`atem-client-<version>-r9-vectors-push-hint.json`,
`atem-client-<version>-r9-vectors-delegated-wire.json`,
`atem-client-<version>-r9-vectors-host-envelope.json`,
`atem-client-<version>-r9-vectors-station-calls.json` (amended for step 4,
**agreed with Astation (2026-11-13, #120 comment 6848326392)**: a new file in the manifest) and the six
`atem-client-<version>-r9-control-ack-*.json` (amended for step 4: the
sixth, `r9-control-ack-reasons`, is O5's, **for Astation's sign-off**) in its SHA-256
manifest. These are the shared positive/negative request vectors from
`fixtures/host-work/requests-v1.json`, the prompt framing's vectors from
`fixtures/host-work/prompt-framing-v1.json` (tags, escaping, rendered prompts
and the size check; delegated host-work design III.2), the preflight size
cases from `fixtures/host-work/framing-size-v1.json` (each with its complete
inputs and the expected checked length), the control records' vectors from
`fixtures/r9-vectors-host-work-control.json` (§9), the push hints' vectors
from `fixtures/r9-vectors-push-hint.json` (approvals and `outcome_unknown`
alerts, R9.9), the delegated wire shapes from
`fixtures/r9-vectors-delegated-wire.json` (session-v1 R9.14), the
envelopes' and results' vectors from `fixtures/r9-vectors-host-envelope.json`
(host-work-v1 §11.5; planned, host role), the Station calls' byte goldens
from `fixtures/r9-vectors-station-calls.json` (host-work-v1 §11.4, §9) and
the Station's acknowledgment fixtures `fixtures/r9-control-ack-*.json` (§9,
delegated host-work test 48).
The Rust core's tests run all of them; the Swift, Kotlin and WASM
conformance suites run the framing vectors through the exports of
[Prompt framing](#prompt-framing-delegated-host-work-design-iii2) (VII.C test
40), the control records', the push hints', the envelopes' and results' and
the Station calls' vectors and the acknowledgment fixtures, and
`scripts/check-atem-client-packages.sh` runs the framing vectors through the
packaged WASM build. They are fixture data, not a live integration test: the
host renders every prompt (`session::framing`); a client never does.

Status: built and released in Atem v0.8.0 (2026-10-31);
Astation integrates the bindings, and the joint live tests passed. Crate: `crates/atem-client-ffi`. Protocol: the r9 appendix of
`atem-session-v1.md` (§R9.5–§R9.9). Overview of the protocols: [README.md](README.md).

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
| `check_change(action_json, now_ms)` | before `draft_entry` (same `action_json`; `now_ms` the `signed_at` it would carry): `None` to go ahead, else `ChangeRefusalInfo` `LogFull` (no entry fits, a removal included), `MembersFull` (no `add`, and no `recovery_add`: a Recovery Kit can't bring the account back until a member is removed), `HostsFull` (no `add_host` of a host that isn't current), `ServiceChangeTooSoon{last_signed_at, retry_at}` (JS `service_change_too_soon`: a service `set_roles` that grants anything new, e.g. a renewal, within 24 h of that service's last grant; a narrowing doesn't restart the clock; narrowing and `remove` are never paced), `AlreadyRevoked` (JS `already_revoked`: a `host_sender_revoke` of a host already revoked; the verifier would refuse it, `already_revoked`), `NotRevoked` (JS `not_revoked`: a `host_sender_readmit` of a host that isn't revoked, a host never added included; `not_revoked`), `EncKeyReused` (JS `enc_key_reused`: a `host_enc_key` of a key already set for that host since its newest `add_host`, the current, previous, a retired or a dropped one; the verifier would refuse it, `enc_key_reused`: ask the host for a new key). The project actions and a revoke of a host never added (the verifier refuses it, `unknown_host`) are never refused here; none of the five actions is paced. Advisory for signers: hosts still accept any valid entry |
| `admit_carrier(device_id, entries, more, now)` | host role, feature `host` only (never in an app build) |
| `service_grant(device_id)` | `ServiceGrantInfo{scope, expires_at}` of an active service member (its scope in canonical order), else `None`: what a renewal or narrowing starts from. Status only: an expired service is still returned; compare `expires_at` with the time yourself |
| `service_renewal_action(device_id, expires_at, signed_at)` | the action JSON of a renewal (the current scope, a later `expires_at` ≤ 90 days after `signed_at`); `Invalid` `not_a_service` / `not_a_renewal`. Run `check_change` on it first: a renewal is paced |
| `service_narrowing_action(device_id, scope, expires_at?, signed_at)` | the action JSON of a narrowing (`expires_at` `None`: unchanged): nothing new granted and something changed, else `Invalid` `not_a_narrowing`; never paced |
| `host_sender_state(host_id)` | `HostSenderStateInfo` `Authorized{generation}` or `Revoked{seq}` (JS `{type: "authorized", generation}` / `{type: "revoked", seq}`) of a host an `add_host` ever named (a removed host keeps it), else `None`: its sending authorization (delegated host work II.3.1). Only a revoke or readmit changes it; a re-verification, a removal and a re-add never do |
| `host_membership_epoch(host_id)` | the `seq` of the host's first `add_host` after its last `remove_host` (its first if never removed); `None` for a host never added, or removed and not added again |
| `projects()` | the projects in effect, by name: `ProjectInfo{name, hosts, members, ops}` (`hosts` as the latest `project_set` signed them, `members` the ones whose membership is still in effect, `ops` from `launch`, `message`, `notify`, `prompt`; all sorted). A project whose hosts were all removed stays, with no `members`, until a `project_remove` |
| `host_projects(host_id)` | the names of the projects the host is an in-effect member of, in order |
| `project_ops_between(a, b)` | what two hosts may send each other: the sorted union of the `ops` of every project both are in-effect members of; empty when `a` is `b` |
| `host_enc_key(host_id)` | `HostEncKeysInfo{current, previous?}` of a current host for its newest `add_host` (II.4.1), else `None`: each key `HostEncKeyInfo{enc_kid, key (X25519), seq, host_trust_gen}`, the previous `PreviousHostEncKeyInfo{key, retired, replaced_at_seq}`. A re-verification (a newer `add_host`) or a removal voids both |

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
3. `hint.open(provider, enc_key_id, device_id)` → `HintContent`: an
   approval hint's `Approval{tool, summary}`, or an `outcome_unknown` hint's
   `OutcomeUnknown{task_id, session_id, sender, reason}` (HPKE open by the
   provider; refused for another device or `enc_key` before anything is
   opened). Facts that aren't a delegated sender's UUID v4 task are refused
   `malformed` at open (`r9-vectors-push-hint`'s
   `outcome_unknown_invalid_facts`). A `reason` that is blank (nothing but
   White_Space) or carries a control or Cf character is refused `malformed`
   at open too, and one over 256 bytes is refused (amended for step 4,
   **agreed with Astation (2026-11-13, #120 comment 6848326392)**: a blank one is new; `outcome_unknown_invalid_facts`
   carries one, a delegated task's reason of a space, a no-break space
   and an ideographic space, with no control or format character, so
   only the blank rule refuses it: the deferred vector Astation asked
   for). A
   locked device shows a generic hint instead.

`verify_push_hint` takes both kinds of hint (the body's `kind`, which only
the planned `outcome_unknown` hint of `host.alerts` has, tells them apart;
session-v1 R9.9, host-work-v1 §11.3). `hint.state()` is `Open`, `Resolved`
or `OutcomeUnknown{device_id, enc_kid, sealed_hash}`; `hint.approval()` and
`hint.alert()` (an `AlertRef`: the account, genesis, host, trust generation
and `alert_id`) each fail `malformed` for the other kind; `book.offer`,
`ack_json`, `json`, `check_sealed`, `created_at` and `expires_at` serve both.
An `outcome_unknown` hint has no resolved hint and no seen.

**Binding API change** (reviewed by Astation with #149's contract sign-off,
2026-11-11, #120 comment 6810116314). No host sends the new kind
until `host.alerts` is advertised. What changes:
- `HintContent` was a record `{tool, summary}`; it is now an enum.
- `approval()` can now fail.
- `HintStateInfo` gains the case `OutcomeUnknown`. That breaks every
  exhaustive Swift `switch` and Kotlin `when` over it, which must handle the
  new case.
- In JS, `open()` now returns an object with a `type` tag (`"approval"` or
  `"outcome_unknown"`), and `state()` has the `outcome_unknown` type.

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

### Service members (§R9.2, §R9.6)

What a manager drafts to enroll, renew or narrow a bot (a Station agent
module, a Discord bridge, a custom app). The builders make
`atem-client`'s own action and run the verifier's structural parse over
the drafted body, so they return only action JSON the verifier accepts
for its shape, or its own refusal (`Membership` `bad_scope`,
`service_expiry`, `wrong_alg`, …); there is no second wire form.

| call | effect for the app |
|---|---|
| `service_add_action(device_id, auth_key, scope, expires_at, signed_at)` | the `add` of a service (`auth_key` P-256 or Ed25519, the bot's own key; `expires_at` ≤ 90 days after `signed_at`): `{"action":"add","member":{…}}`, for `check_change` then `draft_entry` (purpose `Enroll`) |
| `service_set_roles_action(device_id, scope, expires_at, signed_at)` | a service `set_roles` (purpose `Roles`). Any `set_roles` fences the service's live channels at once (`unauthorized` "roles changed"); it reconnects under the new grant |
| `ServiceScopeInfo{hosts, projects?, sessions?, ops}` | lists in any order: sorted by bytes, duplicates dropped, `view` added to `ops`; `projects`/`sessions` absent don't restrict (`hosts` 1–16, `projects` and `sessions` ≤ 64, ops from §R9.6) |
| `project_key_of_remote(url)`, `local_project_key(folder_name)` | a session's launch project key, as Atem records it: the normalized `origin` remote (`github.com/agora-build/atem`, lowercase, credentials/port/`.git` dropped), else `local:<folder>` (case kept) |
| `project_hash_from_mac(kid, mac)` | **the recommended path**: `h1.<kid>.<hex>` of the HMAC-SHA256 the platform computed with `K` itself (no derived subkey) for the generation `kid` over `project_hash_input(project_key)`; the key stays in the key store (WebCrypto: `crypto.subtle.sign("HMAC", key, input)`) |
| `project_hash(account_key, project_key)` | the software form, only for an app that already holds `K` bytes in memory (the restore and K-backup flows, as `seal_k_backup` takes them); WASM: `software-keys` builds only |
| `is_project_hash(text)` | the verifier's syntax check of a scope's project entry |
| `service_key_fingerprint(auth_key)`, `MembershipLog::service_key_fingerprint(device_id)` | `r9_svc` (Atem #81): lowercase hex SHA-256 of the service `auth_key`'s raw public bytes as its `add` entry carries them (P-256: 65-byte SEC1 uncompressed; Ed25519: 32 bytes), nothing else hashed (no alg, no JSON); the key is checked first (`bad_key`, `weak_key`, X25519 `wrong_alg`). The log form: an active service member's, else `None` (status only). Vectors: `crates/atem-client/vectors/r9-svc-fingerprint.json` (Auth's station-token `r9Key`/`r9Svc` pairs and E5's svc-discord) |

`projects` entries are hashes under one `K` generation each: a `K`
rotation must re-issue the service's scope (`service_set_roles_action`
with the new kid's hashes) before the old generation is dropped (§R9.13
item 4). The host compares a session's hash under the kid each entry
names, so both generations' hashes can be listed during the change.

### Host senders, projects and host keys (delegated host work; signing planned)

What a native manager drafts to authorize hosts to send each other work
(delegated host work design II.2.2, II.3.1, II.4.1; the entries, rules and
vectors are in `atem-session-v1.md` R9.2, "Host senders and projects").
Like the service builders, each returns action JSON for `check_change`,
then `draft_entry`, already checked by the verifier's own structural
parse (a shape it refuses by itself is its refusal here, `Membership`
`bad_project` or `malformed`; there is no second wire form). Whether the
entry is valid on the chain (hosts current, a project in effect, a host's
sending state, the key binding) is the verifier's, after signing.
**Atem never signs these entries, and Astation's signing gate stays
closed until every strict verifier of the account knows them** (an older
verifier refuses the whole chain at the first one, II.2.2): the bindings
carry the builders and queries so Astation can be ready.

| call | effect for the app |
|---|---|
| `project_set_action(name, hosts, ops, signed_at)` | a `project_set`: the project's whole new state, replacing any earlier one of that name. `name` 1–32 of `[a-z0-9-]`, `hosts` 2–64 host ids, `ops` from `launch`, `message`, `notify`, `prompt` (`notify` needs `message` and `prompt`); lists in any order, duplicates dropped. `bad_project` otherwise. Purpose `Project` |
| `project_remove_action(name, signed_at)` | a `project_remove` (the project must be in effect: the verifier says `not_a_project`). Purpose `Project` |
| `host_sender_revoke_action(host_id, interrupt_running, signed_at)` | a `host_sender_revoke`: the host's later envelopes are refused, and with `interrupt_running` each receiving host also interrupts what it already started from it. The verifier: `unknown_host`, `already_revoked` (`check_change` says it first). Purpose `HostSender` |
| `host_sender_readmit_action(host_id, signed_at)` | a `host_sender_readmit` of a revoked host (`not_revoked` otherwise; `check_change` says it first). Purpose `HostSender` |
| `host_enc_key_action(host_id, host_trust_gen, enc_key, enc_sig_b64u, retire_previous, signed_at)` | a `host_enc_key`: install the X25519 `enc_key` the host vouched for with `enc_sig` (64 bytes of base64url, from the host over its channel), for its newest trust generation. `retire_previous` (false is omitted: its only form) retires the key this one replaces at once, after a suspected compromise. `wrong_alg` for a key that isn't X25519. The verifier: `not_a_host`, `host_trust_gen_not_current`, `bad_enc_sig`, `enc_key_reused` (a key set for the host since its newest `add_host` never comes back, a retired one included; `check_change` says it first). Purpose `HostEncKey` |
| `verify_host_enc_sig(host_key, account_id, genesis_hash, host_id, host_trust_gen, enc_key, enc_sig_b64u)` | `true` when `enc_sig` is the host's (`host_key`, Ed25519 strict) signature over exactly this account, genesis, host, generation and `enc_key`; `false` for anything else, malformed inputs included, never an error (JS `verifyHostEncSig` too: an unknown `hostAlg` or `encAlg`, or a `hostTrustGen` that isn't a non-negative safe integer, is `false`). Check what the host handed over before building the entry. The host signs `enc_sig` itself, in Rust (label `atem-host-enc-key-v1`); no binding signs it, and an app provider never sees that label except as `HostSigning` |

The queries are on `MembershipLog` (`host_sender_state`,
`host_membership_epoch`, `projects`, `host_projects`, `project_ops_between`,
`host_enc_key`, above). Their effects through `extend`/`evaluate`:
`ProjectSet{name}`, `ProjectRemoved{name}`, `HostSenderRevoked{host_id, seq,
interrupt_running}`, `HostSenderReadmitted{host_id, seq}` and
`HostEncKeySet{host_id, retire_previous}`. The vectors (`others`: `P*`,
`EK*`, `HS*`, each with its `chain` on log L and either `expect`, the state
the queries above read, or `valid: false` and its `reason`) run through
all three conformance suites: the queries against `expect`, the refusals
against `reason` (a set out of order, `array_not_canonical`, is refused by
the signed-object parse itself: `evaluate` throws it rather than stopping),
every builder against the vector's `jcs` byte for byte where a builder can
write the body (not another signer's entry, `retire_previous: false`, a
missing or extra field, or a set out of order; a shape the verifier refuses
by itself is the builder's `bad_project`, `malformed` or `wrong_alg` too),
`check_change` on the redundant revoke and readmit and on a reused host
key, `verify_host_enc_sig` on every `enc_sig` whose binding fields parse,
and (Kotlin and Swift, whose providers see the request) the signing
purposes.

### Control records (delegated host work; planned)

`build_control_record`, `control_record_signing_input`,
`control_record_with_signature`, `parse_control_record`,
`verify_control_record` and `ControlStateHandle` (whose `apply` returns a
`ControlTransition`): the signed stops a
Station issues for the integrations it hosts and a native manager signs
for a service or a host sender. Production exports for Station builders:
§9. An app (Astation) signs a native manager's `revoke` or
`interrupt_running` with `build_control_record` under purpose
`ControlRecord` (§3).

### Station calls and the acknowledgment ledger (delegated host work; planned)

`relay_decode_to_station`, `relay_decode_to_host`, the relay builders
(`relay_control_sync`, `relay_control_sync_result`, `relay_heads`,
`relay_control_ack`, `relay_membership_fetch`,
`relay_membership_fetch_result`), `relay_control_sync_answers` (whether a
`control_sync_result` answers a `control_sync`), `AckLedgerHandle` (whose
calls return an `AckTransition`) and `report_answer`: a Station's side of
its hosts' feed calls and acknowledgments, and its reports to the Portal.
Production exports for Station builders: §9. An app (Astation) uses none of
them, but for its `:8080` proxy, which matches a feed result to the call it
forwarded with `relay_control_sync_answers` (correlation, §9 "Station
calls").

### Mail between hosts (delegated host work; planned, host role)

The `atem-envelope` a host sender seals to another host of the account (a
request, a cancel or a complete) and the `atem-result` the host that ran the
work sends back (a status, a refusal or a result): host-work-v1 §11.5, the
objects, seals, plaintexts, the receiver's checks and their verdicts. **Host
role only** (feature `host`, never in an app build, like `sign_seen`):
nothing sends them in this version, and an app never holds a host's keys.
The bindings carry them so the Swift, Kotlin and WASM suites run
`r9-vectors-host-envelope` through the host's own code.

| call | effect |
|---|---|
| `seal_envelope(provider, host_key_id, fields, plain_json, recipient_enc)`, `seal_result(…)` | the object's wire JSON (canonical): `plain_json` (one plaintext shape, read by the receiver's own strict parse: no `null`, exactly its fields; its canonical form is what is sealed; within its bound) sealed to the recipient host's X25519 encryption key, whose `enc_kid` must be `fields.enc_kid` (`malformed` otherwise), and the body signed with the Ed25519 `host_key_id` (purpose `HostSigning`). `fields` is `MailFieldsData{account_id, genesis_hash, sender, recipient, enc_kid, id, created_at, expires_at, signed_at_head}`, its `sender` and `recipient` each a `MailHostData{host_id, host_trust_gen}` |
| `seal_envelope_with_ikm(…, ikm_e)`, `seal_result_with_ikm(…, ikm_e)` | the same with the ephemeral `DeriveKeyPair(ikm_e)`: the vectors' objects byte for byte (feature `test-vectors`) |
| `open_envelope(object_json, log, me, provider, now_ms)` | the receiver's checks 1 to 6 against its device list (amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: `RefusedAuthenticated` gains `sender_host`, `MailRecipientData` gains `generated`, and `Pending` is for a key this host made but hasn't applied): `EnvelopeVerdictInfo` `Open{plain_json, sender}`, `Pending{host_id, host_trust_gen}`, `Refused{reason, evidence}`, `RefusedAuthenticated{object_id, reason, sender_host}` or `Unavailable{code, detail}`. `Pending` may also mean the object is sealed to a key this host made but hasn't applied yet (signed at a head beyond its own): judge it again after each device-list advance and each change of `me.keys`. `Refused` (any refusal before the copy is shown to be the sender's, signed and intact: steps 1 to 4, for example a bad signature or a sealed part its `sealed_hash` doesn't name) claims no id and is never reported; the ids `Open` and `RefusedAuthenticated` claim are the authenticated sender's, `(sender_host.host_id, id)`, and `RefusedAuthenticated.sender_host` is that sender, a `MailHostData{host_id, host_trust_gen}` (its `host_trust_gen` says which `add_host` key verified the copy; it is no part of the claim; named apart from `Open`'s `sender`, the principal string, so one field name has one type; the `sender` of host-work-v1 §11.5 and of the host-envelope vectors' `expect` is this field). `me` is `MailRecipientData{host_id, host_trust_gen, keys, generated}`: the host's own trust generation from its pairing (never one read from its device list), the keys it accepts now (`MailKeyData{key_id, enc_kid}`) and the `enc_kid` (16 hex) of every key it made in that generation, from its own record, each written durably before the key was handed out (design II.4.1); a key in `keys` counts as made, listed here or not (a key id in neither is refused `enc_key_not_accepted` even beyond its head, for good; one only in `generated` waits there) |
| `accept_result(object_json, log, me, outbox, provider, now_ms)` | the sending host's check of a result against its row `MailOutboxData{recipient, message_id, cancel_complete_ids, task_ids}`: `ResultVerdictInfo` `Accepted`, `NotDelivered{plain_json, sender, reason}` (a revoked or removed sender's result, kept as data), and the same `Pending`, `Refused`, `RefusedAuthenticated`, `Unavailable` |

The verdict functions throw only for bytes that don't parse as a signed
object: for example not strict JSON (a duplicate key, a float, a `null`),
over 512 KiB, not an object, no `body` or `sig`, a `sig`, `enc` or `ct`
that isn't base64url, an unknown top-level field, a `kit_sig`, `enc`
without `ct`, a body without a known `type` or with `v` other than 1, an
array in a mail body, or a body over 4,096 bytes; or anything else the
signed-object parse refuses. The host refuses
those bytes too, under the SHA-256 of the bytes as fetched (host-work-v1
§11.5). Anything about a signed object's content is a verdict. JS: `sealEnvelope`, `sealResult`,
`sealEnvelopeWithIkm`, `sealResultWithIkm`, `openEnvelope`, `acceptResult`
with a `SoftwareKeyStore` (builds with `software-keys` and `host`), the
fields and records as camelCase objects (the receiver `{hostId,
hostTrustGen, keys: [{keyId, encKid}], generated: [encKid]}`), the verdicts
as `{type, …}` (an authenticated refusal's `senderHost` as `{hostId,
hostTrustGen}`; amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: `generated`
and `senderHost`).

### Encoding helpers

`canonical_json`, `encode_fields`, `hash_fields` (SHA-256 of `enc`),
`signing_input(label, payload)`, `verify_signature(key, label, payload,
sig)`, `signed_object_info`, `verify_signed_object`, `enc_kid`,
`ed25519_public_to_x25519` (the kit's HPKE key; CryptoKit lacks it),
`check_public_key`.

### Prompt framing (delegated host-work design III.2)

The host renders every prompt around a task's sender text: a tag drawn after
the text is fixed, counted blocks and an escaping of the sender's lines that
could pass for Atem's own (`atem_client::session::framing`). A client never
renders a prompt. What it can use is how its text will be escaped and what a
task will cost in bytes. These four calls are in every package (JS:
camelCase, `framingEscape`, …; `FramingEscaped` is `{escaped, barsAdded}`):

| call | effect for the app |
|---|---|
| `framing_unicode_version()` | the Unicode version (`18.0.0`) of all the folding data (normalization, general categories, confusables, the lowercase mapping, White_Space). A build with other data would escape other lines, so the vectors pin it |
| `framing_escape(text)` | `FramingEscaped{escaped, bars_added}`: the text as it goes into a counted block, a `\|` in front of every line (a line ends at LF, CR, VT, FF, NEL, U+2028 or U+2029) that, after the `\|`s it already starts with, folds to Atem's marker `[atem`; nothing else changes (`escaped` is `bars_added` bytes longer). For a preview or a check of what the agent will be shown |
| `framing_folds_to_marker(line)` | whether one line folds to the marker (Cf removed, NFKC, lowercase, the UTS #39 skeleton, three forms; after leading white space). The line is taken as it is: the escaping tests it after the `\|`s it starts with, so strip those first to mirror it |
| `framing_checked_len(text, mark_json, context_json)` | a task's size for a **preflight**, before it is enqueued or published. It calls the shared `framing::checked_len`: the exact size of the framed text, mark and context blocks with the longest first and last lines any sender, route or message gets, and no screenshot lines (their room is the 4,096-byte attachment reserve). `mark_json` is a host-work `MarkTask` (`None`: no mark), `context_json` a JSON array of host-work `ContextSnapshot`s (`[]`: none): strict JSON of exactly those shapes, else `Invalid`: `not_strict_json` (not JSON, not strict, or over the 1 MiB the bindings parse) or `malformed` (strict JSON of another shape) |

`framing_checked_len` is a **size-only preflight**; the host stays
authoritative. It does not check a snapshot's digest against its text, an
id, a kind's use (a `result` snapshot is sized like any other) or any limit
but the size, and it takes the complete task, not a byte count: each snapshot
adds its own block (its kind, id, version, digest and provenance lines) and
its own escaping, so equal text bytes in different snapshots render to
different sizes (`framing-size-v1.json`).

The bound the result is compared with is 32,768 bytes, or 28,672 (32,768
minus the 4,096-byte attachment reserve, their screenshot lines being added
at dispatch) when the task has attachments. **A message with a mark always
has one, its screenshot, so a mark's bound is 28,672, never 32,768**; a
sender that preflights a Chisel mark against 32,768 is told "fits" for
28,673 to 32,768 bytes and the host refuses it. Above 32,768 the value is
only a lower bound, since once the raw bytes alone are over it nothing is
escaped. The host makes the same calculation (`framing::checked_len`, through
`WorkTask::checked_len`) in two places: `work_enqueue` checks
`WorkTask::valid` (the task's own attachments, up to four; a task has no mark,
so pass `None`), and `message_publish` checks `Message::valid`, where each
agent recipient's task is the message's text and context with the mark
measured too and its screenshot as the task's one attachment (a message with
no mark has no attachment: 32,768). JS returns a number.

**Rendering is vectors-only.** `framing_render_for_vectors(input_json,
tag_bits)` exists only with the `test-vectors` feature (the conformance builds)
and is never in a shipped package: it renders the vectors' prompts with a
chosen tag so the Swift, Kotlin and JS suites compare them byte for byte
(`tag_bits`: `UInt64`, Kotlin `ULong`, JS a `BigInt`; the tag is its low 60
bits, 12 Crockford base32 characters). A client that rendered a prompt
itself would draw its tag before the text was fixed, which the framing exists
to prevent. The package checks look for it in the WASM package's files (and
`framingRenderForVectors` must be `undefined` on its packaged Node build), in
the generated Kotlin and Swift sources, and in the Android libraries' dynamic
symbols (`scripts/check-atem-client-packages.sh`, the Apple check and the
workflow's macOS grep); the JVM `.so` and the Apple static libraries are not
symbol-scanned (the scripts build them without the `test-vectors` feature).
What the core refuses to render (a line of Atem's that isn't one line, a
snapshot that doesn't match its digest) is `Invalid` `malformed`.

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
errors: ProviderError.Cancelled{reason} | UnknownKey | OpenFailed | Failed{reason}
```

- **`ProviderError.OpenFailed`** (planned, for host mail; **agreed with Astation (2026-11-11, #120 comment
  6810116314)**: a new error case its providers can construct, a source
  change for an app that switches over `ProviderError` exhaustively). From
  `hpke_open` only, when the seal doesn't open under the key: the AEAD
  refuses the ciphertext (CryptoKit's authentication failure, the JDK's
  `AEADBadTagException`), or `enc` isn't a valid X25519 public key. The
  core reads it as the seal's own failure (`open_failed`), as it reads
  `UnknownKey` as `unknown_key`, and the host refuses the object as the
  sender's doing. Any other failure (a missing or locked key, a cancelled
  prompt, the provider's own fault) is `Failed` or `Cancelled`: the host
  decides nothing and tries again later (`Unavailable`). A provider that
  reports a failed open another way only delays that refusal to the
  object's expiry. `SoftwareKeyStore` returns it for exactly those cases.
  WASM has no foreign provider (JS passes a `SoftwareKeyStore`), so there
  a failed open is the core's `open_failed` code already, as `unknown_key`
  is.

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
  | `Project` | `project_set`, `project_remove`: a project grant, which hosts may send each other which ops (show the name, hosts and ops, or the removal) | fresh |
  | `HostSender` | `host_sender_revoke`, `host_sender_readmit`: stop (with `interrupt_running`, also interrupt what it started) or resume accepting one host as a sender of host work | fresh |
  | `HostEncKey` | `host_enc_key`: install the encryption key a host vouched for, which other hosts seal mail to (show the host, its trust generation, the key's `enc_kid` and `retire_previous`) | fresh |
  | `ControlRecord` | a native manager's control record (`signer` `member:<device_id>`): `revoke` or `interrupt_running` of a service or a host sender (show the principal, the action and `interrupt_running`; for a host principal, the host and the `revoke_seq` of the device-list revoke it follows) | fresh |
  | `ServiceControl` | a control record signed with the principal's own service key (`signer` equal to a `service:` principal): the Station that hosts the integration signs it on its own, from the Portal's feed (§9) | none; never asked of a native member's key (refuse it: such a signature would never verify) |
  | `Recovery` | `recovery_add`, `recovery_approve`, `recovery_veto` | fresh |
  | `Kit` | `set_recovery_key`, the current kit's co-signature | fresh |
  | `KeyBackup` | `k_backup` | fresh (decision: a manager entry like the others) |
  | `BrowserGrant` | a browser grant | fresh |
  | `HostSigning` | `sig_h`, push hints, seens, a host's `enc_sig` | never asked of a client |

  `fresh_confirmation` is true for every purpose but `Channel`,
  `HostSigning` and `ServiceControl`. A control record's purpose comes from
  the signer its body names, never from the key asked. A fresh confirmation covers exactly `body_json` (show the
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
| `Invalid{code, detail}` | the crate's: `not_strict_json`, `not_canonical`, `too_large`, `null_value`, `malformed`, `unknown_type`, `array_not_canonical`, `kit_sig_missing`, `kit_sig_unexpected`, `bad_key`, `weak_key`, `wrong_alg`, `high_s`, `bad_signature`, `zero_shared_secret`, `open_failed`, `backup_invalid`, `kit_tag_mismatch`, `genesis_mismatch`, `unknown_key`, `provider_error`; `not_canonical` also for a caller's integer above 2^53 − 1 (a time, a version) that would enter a signed body; `malformed` for a `HostClock` time above 2^53 − 1; for a control record its parse refuses (§9), also `wrong_type`, `unknown_field`, `field_not_allowed`, `not_for_host_principal` (`detail` names the field) |
| `Membership{code, detail, index}` | `membership_invalid`; `detail` the verifier's (`bad_signature`, `gap`, `signer_not_manager`, `blob_version_not_increasing`, `kit_sig_missing`, …); `index` into what was passed |
| `Channel{code, detail}` | `handshake_failed`, `stale_target`, `account_frozen`, `busy` (also as the host's clear, advisory error before the channel opens), `unknown_host`, `record_rejected`, `limit`, `too_large`, `closed`, `signing_failed`, `invalid_hello`, `cannot_carry` (a divergence deeper than any carriage) |
| `Refused{code, detail, error_json, next}` | the host's session error code (`unauthorized`, `membership_invalid`, `membership_incomplete`, `recovery_pending`, `account_frozen`, `unsupported_version`, `busy`, …) |
| `BadWelcome{check}` | `bad_welcome` (`check`: `revision`, `re`, `channel_id`, `principal`, `account_id`, `host`, `head`) |
| `Request{detail}` | `request` (`unknown session`, `no lease`, `too many requests in flight`, `not attached`, …) |
| `Restore{code, detail}` | `kit_tag_mismatch`, `genesis_mismatch`, `membership_invalid`, `no_host_reachable`, `log_behind_host`, `kit_not_current`, `no_backup`, `backup_hash_mismatch`, `backup_invalid` |
| `Publish{code, detail}` | `outstanding` (also: another publisher or writer of this device holds a prepared body), `not_on_head`, `nothing_prepared`, `sign` |
| `Push{code, detail}` | `malformed`, `binding`, `bad_signature`, `invalid_times`, `skew`, `stale`, `bad_sealed`, `duplicate` |
| `Stored{code, detail}` | a stored snapshot didn't load. `MembershipLog::from_stored`: `too_large` (over 16 MiB), `malformed` (not strict JSON, not an object, no `v`, no `account_id`/`genesis_hash`), `unsupported_version` (a `v` other than 1), `account_mismatch`, `genesis_mismatch` (the snapshot's are not the caller's anchors), `stored_invalid` (the shared verifier refused it, or it isn't exactly `stored_json()`'s form); a malformed anchor argument is `Invalid`. `ControlStateHandle::from_json` (§9): `too_large` (over 64 MiB), `malformed` (not strict JSON, not an object, no `v`, an `account_id` or `genesis_hash` missing or not readable: such a header names no list; amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**), `unsupported_version` (a `v` other than 2: amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**), `account_mismatch`, `genesis_mismatch` (a well-formed header naming another device list: delete the state and start with `new`), `stored_invalid` (the state's own rules refuse it, or it isn't exactly `to_json()`'s form). `control_state_from_parts` (§9; amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: new): `too_large` (over 64 MiB in all), `malformed` (a part that isn't strict JSON), `stored_invalid` (a principal given twice; a part of this list its rules refuse, that isn't exactly `part()`'s form, or whose principal is no principal; a part whose device list can't be read); never `account_mismatch` or `genesis_mismatch` (another list's parts are reported in `foreign`) |
| `State{detail}` | `state` (a call out of order: `already started`, `not waiting for accept`, `no signature pending`, …; or the object changed while the provider was signing) |

`detail` is for logs and may change; branch on the variant and `code`.

## 5. Threading

- Every object is thread-safe (an internal lock held only for the call)
  and can be used from several threads at once: `MembershipLog`,
  `ClientConnection`, `EntryPublisher`, `KBackupWriter`, `RestoreSession`,
  `PushHint`, `PushHintBook`, `RecoveryKitHandle`, `ControlStateHandle`
  (which never changes: `apply` returns the next state as a new handle).
  Records are values.
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
| `test-vectors` | raw primitive verification and `framing_render_for_vectors`, for the vectors (implies `software-keys`) |
| `host` | host-role functions and types (`sign_seen`, `admit_carrier`, `AdmissionInfo`, and host mail: `seal_envelope`, `seal_result`, `open_envelope`, `accept_result` and their records), for the conformance and host-side tests |

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
tree, every shipped vectors file and acknowledgment fixture listed in the
sums and the same bytes as the repository's, no test-only or
host-role export (the framing's vectors-only rendering included), the
packaged framing vectors through the Node build, and one call through the JVM
jar); it can be run on a download the same way.

## 8. Tests

`scripts/check-atem-client-bindings.sh [kotlin] [wasm] [swift] [e2e]`
(toolchains passed in: `KOTLINC`, `JNA_JAR`, `JAVA`, `NODE`,
`WASM_BINDGEN`); CI: `.github/workflows/atem-client-bindings.yml` (Linux:
Rust, Kotlin, WASM, end to end; macOS: Swift, the package dry run).

- **Conformance** (70 checks in JS, 72 in Kotlin and in Swift: the same 70
  in each language, plus two in Kotlin and Swift, whose provider sees the
  signing request and so the purposes of the five device-list actions and
  of control records; over `designs/protocol/fixtures/r9-vectors-*.json`,
  the acknowledgment fixtures `r9-control-ack-*.json`, atem-client's own
  `crates/atem-client/vectors/r9-svc-fingerprint.json` and the framing vectors
  `designs/protocol/fixtures/host-work/{prompt-framing-v1,framing-size-v1}.json`,
  four checks: the Unicode version, escape cases and marker check; the rendered
  prompts byte for byte and every tag of the vectors; the size section; every
  size case with its complete inputs, and the shapes the preflight refuses):
  `bindings/kotlin/Conformance.kt`
  (with a Kotlin `AppKeyProvider` on the JDK's crypto: P-256 signing, HPKE
  open), `bindings/js/conformance.mjs`, `bindings/swift/Tests/AtemClientTests/ConformanceTests.swift`
  (with a CryptoKit `AppKeyProvider`).
- **Host mail** (planned, host role; four conformance checks per language,
  of the 70 and 72 above): every entry of `r9-vectors-host-envelope`
  extends log L to its hash, the builders reproduce every `built` object
  byte for byte (a fresh seal opens, a builder refuses a plaintext with
  `null`, a dropped reply and a key that isn't the `enc_kid`'s, and seals a
  plaintext's canonical form only), and every check's verdict and reason
  through `open_envelope` and `accept_result` (with each receiver's
  `generated` key ids and each authenticated refusal's `sender`), with the
  plaintext an open gives (the largest by its length and SHA-256). Kotlin
  and Swift also open the request and the re-signed copy through their own
  platform providers (`JdkKeys`, `CryptoKitKeys`), whose failed open is
  `ProviderError.OpenFailed` (§3): the same verdicts.
- **Device-list actions** (`tests/host_actions.rs`, Rust; four conformance
  checks in JS, five in Kotlin and Swift, of the 70 and 72 above): every
  `P*`/`EK*`/`HS*` vector of
  `r9-vectors-membership-log` through the queries (`expect`) and the
  refusals (`reason`), the builders against the vectors' `jcs` and
  `check_change`'s advice, `verify_host_enc_sig` on every `enc_sig` whose
  binding fields parse (and `false`, never a throw, for inputs that can't
  be a key, a generation or an algorithm), and a manager signing each
  action through a recording provider under its own purpose and publishing
  it (the verifier takes the entry).
- **Control records** (`tests/control.rs`, Rust; five conformance checks
  in JS, six in Kotlin and Swift, of the 70 and 72 above): every record of
  `r9-vectors-host-work-control` parsed (or refused by the parse with its
  code) and verified on each of its chains as `checks` says, the builders
  reproducing it byte for byte (a software store, and the signing input
  plus the vector's signature; a body the parse refuses is refused, nothing
  signed), every sequence through a `ControlStateHandle` (from its
  `initial` state when it has one) with each step's per-effect results,
  the `standing` of its record's principal and the parts it `touched`
  (exactly the parts that changed), and the state it leaves (each step
  applied to the next state the step before returned), the state loading
  only for its own device list and exactly as written, whole and from its
  parts per principal (in any order; a principal given twice, a part that
  isn't strict JSON or not of its principal's kind refused), a failed
  commit losing no effect
  (the handle `apply` was called on unchanged, the record applied again
  giving the same results and actions, and a duplicate once the next
  state is adopted), and (Kotlin and Swift) the
  provider asked under `ServiceControl` (no confirmation) for the
  integration's own key and `ControlRecord` (a fresh confirmation of the
  body) for a native manager.
- **The Station's side** (`tests/station.rs`, Rust; ten conformance
  checks per language, of the 70 and 72 above): every acknowledgment
  fixture (`r9-control-ack-*`, one check each) through `AckLedgerHandle` as
  a Station persists it (each call's next state committed before the
  reports go and adopted after, restarts from the committed state, two
  replicas from one state giving the same next state and reports and the
  one that lost the compare-and-swap making nothing), with the Portal's
  answers through `report_answer`; a call never changing the handle it was
  called on, and the state loading only as written; every fixture ack read
  and written back, feed pages, heads and device-list fetches round-tripping,
  the builders refusing what the readers refuse (a record the control
  parser refuses, a position above the head, a `mailbox` head before stage
  3, another direction's message); the three refusals exactly and read
  strictly (unknown codes, fields, nulls, duplicate keys), and an ack
  refused for its stale association with nothing counted or disclosed;
  the Portal's statuses in their classes; and the byte goldens of
  `r9-vectors-station-calls` (`goldens_round_trip_through_the_bindings`):
  every message of the six calls and the three refusals built byte for byte
  from its fields (an ack written again from what it decoded to; a page with
  a record the control parser refuses is refused by the builder with that
  parse code), read back to its fields with each page record judged by
  `parse_control_record` as the file says, refused by the other side's
  reader as `wrong_message`, and every invalid text refused with its code.
- **Durable log** (`tests/stored_log.rs`, Rust; two conformance checks per
  language, of the 70 and 72 above): a partly elapsed wait across a same-boot restart and a reboot,
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
  revocation and the browser's fence; and a Node/WASM service bot
  (`bindings/js/bot.mjs`, `svc-discord`'s software key): admitted as a
  service within its scope (only the in-scope session listed; lease,
  prompt and interrupt complete), `forbidden` outside its ops (approval,
  stop, terminal input), `unknown_session` for an out-of-scope session,
  fenced at expiry and refused after it. The host is built from atem-client's
  responder role (`atem-client/tests/support/host.rs`). The real runtime
  host runs the shared r9 host fixtures in
  `src/session_protocol/membership/fixtures_tests.rs` (real engine, store
  and session host) and `tests/r9_*_binary.rs` (the `atem runtime`
  process).

## 9. For Station builders

A Station that hosts integrations signs control records with their service
keys, serves them in its control feed and accounts for the hosts'
acknowledgments (delegated host-work design I.5; `atem-host-work-v1.md`
§11; **planned**: no host advertises `host.senders` yet). The built-in
Station uses the `atem-client` crate directly (`atem_client::control`); a
Station written in another language uses these exports, which are the
same code and pass the same vectors and fixtures
(`r9-vectors-host-work-control`, `r9-control-ack-*`, run by the Rust core
and all three conformance suites). They are production exports, in the
default UniFFI build and in the `wasm`-only package (plan decision 6). The
wire they read and write is host-work-v1 §11.4 ("Station calls and
acknowledgments").

### Control records

| call | what it does |
|---|---|
| `build_control_record(provider, key_id, body)` (Swift, Kotlin) | signs `body` (a `ControlRecordBody`) with `key_id` through the provider and returns the record's wire JSON (canonical). The body is checked first exactly as a host's parse checks it: one it refuses is `Invalid{code}` and nothing is signed. The provider sees purpose `ServiceControl` when `signer` is the principal itself (the integration's service key: no owner confirmation) and `ControlRecord` for `member:<device_id>` (a fresh confirmation, §3) |
| `control_record_signing_input(body)`, then `control_record_with_signature(body, signer_key, signature)` (all three; JS `controlRecordSigningInput(body)`, `controlRecordWithSignature(body, signerAlg, signerRaw, signature)`) | the same in two steps, for a key that signs elsewhere (a KMS, an HSM, WebCrypto): the bytes to sign, `enc(["atem-host-work-control-v1", jcs(body)])`, then the record. The signature (P-256 64-byte `r‖s`, either S, normalized to low S; Ed25519) is verified under `signer_key` before the record is returned (`bad_signature`; an X25519 key is `wrong_alg`) |
| `parse_control_record(record_json)` | the body, field by field (strict JSON, at most 16 KiB, exactly the body's fields); no signature check. For a record text over 16 KiB this call and the page reader (`FeedEntry::parse_record`, a `control_sync_result`'s records) give different codes (`not_strict_json` here, `malformed` there), though both refuse the same records: compare whether it parses, not the code |
| `control_why_codes()` | the shared vocabulary of reasons, every code once in a fixed order (JS `controlWhyCodes()`; **for Astation's sign-off**, amended for step 4, O5): the codes `ControlApplied.why` and `ControlEffectResult.why` take in this version. A well-formed reason outside it, read from a `control_ack`, is a later version's: treat it as unrecognized, information only. `r9-vectors-station-calls`'s `why_codes` pins it |
| `verify_control_record(log, record_json)` | against a verified `MembershipLog`: `Valid{signer, key_seq, head}` (`signer` `service:<id>` for the principal's own key, from the entry at `key_seq`; `member:<id>` for a current native manager), `Pending{reason}` (`principal_unknown`, `signer_unknown`, `revoke_not_in_list`: verify again after the list advances) or `Refused{reason}` (`wrong_account`, `bad_signature`, `key_mismatch`, `signer_not_allowed`, `removed_manager`, `host_key_signed`, `not_a_service`, `not_a_revoke`: keep it as evidence). A record the parse refuses is `Invalid{code}` |
| `ControlStateHandle::new(log)`, `from_json(log, state_json)`, `to_json()`, `apply(record_json, log, pos, host_applied_seq)` | the reference control state of one device list, as a host keeps it. A handle never changes: `apply` verifies the record against `log` (the device list at the head of this transaction) and returns `ControlTransition{applied, next, touched}`, `applied` being `ControlApplied{result, effects, actions, evidence, why}` (`why`, amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: `Applied::why`'s code, host-work-v1 §11.1, set exactly when the record is pending or refused or kept as evidence, else `None`; JS `null`; and each effect's `ControlEffectResult.why`, O5, **for Astation's sign-off**, the record's `why` exactly on an effect `pending` or `refused`, what a host writes in its `control_ack`), `next` the state after the record, a new handle, and `touched` the principals whose part it changed (the record's, or none). `pos` is `ControlFeedPos{origin, feed_id, feed_seq}`, where the record was read: its `origin` is always the Station origin you sync the feed from (a host's own configured Station), never one taken from a page or the record, which is what bounds a part's `order`; a record whose body names another `origin` or `feed_id` counts as read at no position (its hold still applies, its cover and release don't). Amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: `touched`, and the rule that `pos`'s `origin` is the host's own configured Station origin, are new |
| `principals()`, `part(principal)`, `control_state_from_parts(log, parts)` | the state one part per principal (amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: new), for a store that keeps a row per principal: `part` is a principal's canonical JSON (`None` when the state has none); `control_state_from_parts` (JS `controlStateFromParts`) loads `ControlStatePart{principal, part_json}`s in any order, read as strictly as `from_json`, and returns `ControlLoadedParts{state, foreign}`. Every part names its device list (`account_id`, `genesis_hash`): one of another list (an earlier pairing's leftover) is skipped, never loaded, and its principal listed in `foreign`: delete those rows. The list loaded is always `log`, never inferred from the parts. Write the parts a transition `touched` (a touched principal always has a part in `next`); no other part changed |
| `standing(principal)` | what is in force for `service:<id>` or `host:<host_id>` (amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: new): `ControlStanding{revoked, interrupted, held, coverage}`: the revoking record's `record_id` (never for a host principal, whose revocation is a device-list entry), the revocations whose interrupt a record put in force (a service's revoking `record_id`, a host principal's `revoke_seq` in decimal; sorted as text, so `"10"` before `"9"`), the hold, and `ControlCoverage{origin, feed_id}`, the covering feed. A principal the state holds nothing for has nothing in force |

JS takes a body as a plain object with `ControlRecordBody`'s fields in
camelCase (`accountId`, `genesisHash`, `origin`, `feedId`, `principal`,
`principalKey`, `signer`, `action`, `interruptRunning`, `revokeSeq`,
`recordId`, `issuedAt`, `integrationId`, `by`), absent ones omitted, `null`
or `undefined`; any other key is refused (`malformed`), never dropped.
`apply`'s `pos` is `{origin, feedId, feedSeq}` or `null`, and it returns a
`ControlTransition` with the getters `applied` (a plain object), `next`
(a `ControlStateHandle`) and `touched` (an array of principals). JS's
`controlStateFromParts(log, parts)` takes `[{principal, partJson}]` (any
other key is refused) and returns a `ControlLoadedParts` with the getters
`state` and `foreign`; `part` returns `undefined` for a principal with none, and
`standing` a plain object whose `revoked` and `coverage` (`{origin,
feedId}`) are `null` when there are none (amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**:
`touched`, `controlStateFromParts`, `part` and `standing`). Only
bots and tests get
`buildControlRecord(store, keyId, body)` (feature `software-keys`).

**The body** (`atem-host-work-control`, host-work-v1 §11.1). A service's
record names `origin` (the Station's exact origin), `feed_id` (the feed's
UUID v4: minted with the feed, never reused, not after a restore or a
migration either), `principal_key` (the integration's `r9Svc`, the
lowercase hex SHA-256 of its `auth_key`'s raw bytes,
`service_key_fingerprint`: cross-check it against the Portal feed's value)
and `integration_id` (Auth's client id). `by` is the Portal feed's
least-disclosure reason (`owner`, `station`, `agora_build`,
`member_removed`, `station_removed`, `reconciled`, later
`account_deleted`); any 1 to 32 characters of `[a-z_]` are accepted for
display, and nothing is decided by it. `record_id` is a fresh UUID v4 per
record, a re-signed record included. `issued_at` comes from the Station's
synchronized clock: it orders covers (below).

**Persistence and the order of calls** (each step durable before the next):

1. Build the record and store it in the feed at its position (`feed_seq`)
   in one transaction, before you announce the head or report the change
   to the Portal as propagating (I.5.8, "durable before announced").
2. If you keep a control state (to predict what hosts report, or to know
   what a reset's snapshot must re-issue), `apply` the record at its
   position (`{origin, feed_id, feed_seq}` in your own feed) and store the
   transition's `next.to_json()` (or `next.part(p)` for each principal it
   `touched`, one row per principal; amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**)
   in the same transaction as the feed row.
   Use `next` from then on only once that transaction committed. If it
   fails, keep the handle you applied on: `apply` didn't change it, and
   applying the record again gives the same results and actions, so no
   effect is lost. Never rebuild a state by re-applying stored records: a
   record that verified then may not verify against today's list, and
   idempotency is by the records the state keeps.
3. At start, load it with `from_json(log, state_json)` (or
   `control_state_from_parts(log, parts)`), the log being your pinned
   device list. A whole state that doesn't load is `Stored{code}`
   (`too_large`, `malformed`, `unsupported_version`, `account_mismatch`,
   `genesis_mismatch`, `stored_invalid`). `account_mismatch` or
   `genesis_mismatch` (a well-formed header naming another device list)
   means the stored state is another device list's, after a re-pair to
   this account or another: delete it and start with `new`, as for
   foreign parts. Start with `new` only when your own pairing changed;
   otherwise treat a mismatch as damage and keep the work stopped (a
   well-formed but damaged header reads like another list's). A header
   that can't be read is `malformed`: it names no list, so nothing may
   start empty. Parts name their device list, so a store of parts
   loads the current list's parts and skips the others, reporting them
   in `foreign` (delete those rows only when your own pairing changed;
   under the same pairing they are damage: stop the work, as Astation
   answered on #120, 2026-11-13): an old list's leftovers never load,
   so a service id that recurs in the new list inherits no revoke, hold or
   coverage, and the current list's stops beside them stay in force. At a
   live re-pair, delete the old list's rows in the transaction that adopts
   `new`. Parts never give `account_mismatch` or `genesis_mismatch`: a
   part of the current list that fails, or one whose device list can't be
   read, is `stored_invalid`, a part that isn't strict JSON `malformed`,
   and parts over 64 MiB in all `too_large`. Store each `part_json` byte
   for byte: anything but `part()`'s exact form is `stored_invalid`. On
   any code but a whole state's `account_mismatch` or `genesis_mismatch`,
   stop the work it guards and never start again from an empty state. A
   `v` 1 state, the format before parts per principal, is
   `unsupported_version`: this version reads `v` 2 only. (Amended for
   step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**: everything in this step about parts, `foreign` and
   `v` 2. Only a pairing change you established yourself permits a fresh
   state or deleting another list's rows; an unexpected mismatch under the
   same pairing is damage: stop the work.)

**Its size.** Each principal keeps at most 256 counted record ids (about
125 bytes each, `MAX_RECORD_IDS`), the next evicting its oldest but never
its revocation's record or the coverage's cover, and the order a release
follows keeps one feed per Station origin: a part is about 32 KB at most,
plus one order entry per origin (**Atem's proposal, agreed with Astation (2026-11-13, #120 comment 6848326392)**: stops are
never blocked by the bound, and the floor complements O1, never replaces
it; host-work-v1 §11.1 rule 1 and "The state, per principal").
**An evicted record that comes back grants nothing:** `feed_seq` isn't
signed, so whoever serves a host the covering feed (you, or a carrier
that rewrites your pages, such as Astation's `:8080` proxy) could
otherwise re-serve an evicted release at a fresh position and lift a
hold. So the floor guards only what can grant or lift: a `cover` or
`release` of a principal that isn't revoked, under an id the state no
longer counts and issued no later than the newest record evicted (the
part's `evicted_floor`), is `refused` as a possible replay and kept as
evidence. A cover or release applies when it was issued after every
evicted record of that principal, which you meet for every record you
signed yourself when each record you sign for a principal, holds
included, is issued after every record you signed for it before (your
signing duty below). A stop
never meets the floor: a hold applies as any hold (an evicted one
replayed holds again, which grants nothing), and revokes and interrupts
replayed are duplicates. The residual: a Station whose clock lags the
floor (after a host switches to it, or after another Station's record
issued ahead of its clock was evicted) has its covers and releases
refused as possible replays until its `issued_at` passes the floor; it
fails safe (holds stay, nothing new starts).

**A release lifts only holds issued before it** (O1, requested by
Astation, 2026-11-13; **for Astation's sign-off**, amended for step 4; host-work-v1
§11.1 rule 6). Each service part keeps `hold_issued_at`, the newest
`issued_at` of every hold the state verified for it (one that found it
held, read out of order, from another feed or none, or under a counted id
included), and a release taken in feed order while held lifts the hold
only when issued strictly after it; one issued no later, the same
millisecond included, is `refused` with `why` `not_after_hold`, no
evidence, and takes no position in the feed's order. No eviction, reset,
coverage change or restart erases it. A stored `v` 2 part without
`hold_issued_at` loads only while it holds nothing; a held one without it
is `stored_invalid`.
Only principals of the device list count records, so a state stays far
under the 64 MiB that `from_json` and `control_state_from_parts` read (a larger one is
`too_large`). The acknowledgment ledger doesn't prune in this version.

**Reading results.** `apply` gives the record's `result` and one result per
effect it carries (`revocation`, `interrupt`, `hold`, `release`, `cover`).
Read `effects`, not only `result`: a revoke that adds `interrupt_running:
true` to one already applied is `applied` for its interrupt and
`duplicate` for its revocation. For the revocation, `duplicate` means
"already in force on this host" and counts as done (decision 8).
`pending` waits (apply the record again once the device list,
host-work's applied `seq` or (amended for step 4, **agreed with Astation (2026-11-13, #120 comment 6848326392)**) the
principal's revocation advanced);
`refused` never applies from this record; `evidence` means keep the record and alert: it failed
verification, or it reuses a `record_id` of the same principal with
another body (a stop, `hold`, `revoke` or `interrupt_running`, still
applies its effects then; a `cover` or `release` is refused). Record ids
are per principal: one principal's record never blocks another's with the
same id. `actions` is what the host does in the same transaction
(`Revoke`, `Interrupt`, `Hold`, `Release`, `Cover`).

**The Station's duties** (**Atem's proposal, agreed with Astation (2026-11-11,
#120 comment 6810116314) and Auth/Portal (2026-11-12, #147 comment 6813332550)**; host-work-v1 §11.1, "Resets" and "Stations: the
trust model"):

- Covers are ordered by `(issued_at, record_id)`: another Station's cover
  takes coverage only when strictly newer, and a cover never releases a
  hold.
- **Your signing duty** (**agreed with Astation, 2026-11-13, #120 comment
  6848326392**; amended for step 4; host-work-v1 §11.1, "Stations: the
  trust model"): every record you sign for a principal, **holds
  included**, is issued strictly after every record you signed for it
  before. Serialize signing per account, genesis and principal; keep the
  greatest `issued_at` you signed durably **before** publishing any signed
  output; carry it at handover and keep it across a restart and a
  snapshot's generation (a snapshot's records signed anew are issued
  now); and when your clock can't safely give a later time, wait: never
  sign at or below the mark, never bypass it. Why: a `cover` or `release`
  issued no later than a record a host evicted is refused there as a
  possible replay (rule 1), and a release lifts only holds issued before
  it (O1, rule 6), so a hold you sign with an older time than a release
  you already signed could be lifted by that release served late. What
  it can't close: a hold another signer (another Station, a native
  manager's device) issued with a clock behind your release can still be
  lifted by it, within that clock skew (no regression: before O1 any
  release in feed order could); and your release is refused
  `not_after_hold` while your clock is behind another signer's hold,
  until it passes it (fails safe; the ack's reason says so).
- Your covers' `issued_at` only
  rises: each cover you sign for a
  principal is newer than any cover issued for it before, a handed-over
  integration's included (the handover carries the last cover's
  `issued_at`). A cover that isn't newer than the coverage's takes
  nothing: yours is a `duplicate` that leaves the coverage on its feed,
  another Station's is `refused`; your holds still apply, but your
  releases from a feed the coverage isn't on are refused until a newer
  cover.
- A stop always wins: a hold applies from any feed, yours or not, covering
  or not. Only a release needs the coverage's current feed, after its
  cover and after that feed's last hold or release.
- A reset (a new `feed_id` for your origin) starts with a snapshot taken
  from your current effective state (the Portal's Station feed), never
  from a restored backup's view: for each principal you **currently**
  cover, its `cover` first, signed anew (so newer), then its current hold
  or release, signed anew; revoke and interrupt records as they are, or
  signed anew. Never re-issue a cover for a principal you no longer cover.
- Never sign another body under a `record_id` you used for the same
  principal (a re-signed record gets a fresh id).
- The principal's own key may sign every action, so whoever holds it
  controls coverage. An integration handed to another Station: stop
  signing for it, and the key leaves with it (or the integration is created
  again as a new principal). A revoke is final whoever holds the key.
- A Station learns of its own removal only through the Portal's two-phase
  removal (its integrations go `revoking` with reason `station_removed`, it
  issues and serves their records, then the removal completes), never
  another way.

### Station calls

A host calls its Station over its one link (`{"type":"relay","op":…}`,
host-work-v1 §11.4). Every message is read and written by the shared code.
Keep one control feed per (Station, account), with its own `feed_id`, and
answer `control_sync`, `heads` and `membership_fetch` only for the account
of the calling link's verified association: `heads` names only that
account's feeds, `control_sync` serves only them, `membership_fetch` only
its device list, and a request naming another account's feed is refused
with `relay_control_sync_refused` or `relay_membership_fetch_refused`
(**Atem's proposal, for Auth/Portal's agreement**; it and the refusal wire are
**agreed with Astation on 2026-11-11**, #120 comment 6810116314, and the
refusal wire was confirmed on 2026-11-12, #148 comment 6812769009).

**Refusals.** A Station refuses a host's call on the link with exactly
`{"type":"relay","op":"control_sync_refused","code":"forbidden"}`,
`{"type":"relay","op":"membership_fetch_refused","code":"forbidden"}` or
`{"type":"relay","op":"control_ack_refused","code":"forbidden"}`: `code` is
exactly `forbidden` in this version, and nothing else is carried (no
account, feed, host, cursor, principal, integration or record), so a
refusal never discloses another account. `control_ack_refused` is also the
reply to an ack `ack` refuses for its association on the link
(`not_the_link`, `other_account`, `other_station`); no other refusal of an
ack gets a reply. A refusal is an authorization failure on that link,
never an empty successful page or an application acknowledgment: it
advances no cursor, membership head, clock floor or ledger evidence, opens
no gate, carries no request id or cursor (correlation leaves the three
unchanged: a refusal names a call kind, never a request) and must not
complete or correlate a request. The host keeps that link's synchronization
gates closed while it repairs the association and resynchronizes; the
transport may still fence or close an invalid or superseded link.

**Correlation** (**amended in place on Astation's request, #164 comment
6858189009**; unshipped, so no new version and no fallback). A
`control_sync` carries `request_id`, a lowercase UUID v4 that the host makes
fresh for every call (a retry after a timeout and a call on a new link
generation included, even at the same cursor); answer it with the same
`request_id` and its `after` echoed, on the feed it named (a call that names
no feed asks from 0 for the account's current feed), with records strictly
after that `after`. A named feed that is stale (pre-reset) is refused
`control_sync_refused`, never answered on the new feed. The host and
Astation's `:8080` proxy decide whether a result answers a call with the one
shared helper, `relay_control_sync_answers` (below): the same `request_id`,
origin, feed (when the call named one) and `after`. The link generation, the
account and the genesis captured with the call are the caller's to compare,
and an id is a correlation value, never authorization: a result for a
retired, timed-out or old-generation call, or for no call, advances nothing
and opens no gate.

| call | what it does |
|---|---|
| `relay_decode_to_station(message)` | reads a host's call strictly (at most 256 KiB as received, one strict I-JSON parse, exact fields, never `null`): `ControlSync{request_id, origin, feed_id?, after}` (answer with its `request_id` and `after`), `ControlAck{ack}` or `MembershipFetch{after}`. Another relay message on the link (`push_hint`, `push_seen`, …) is `Invalid{wrong_message}`: dispatch it elsewhere. The calling host is never a field: take it from the link's verified association (below). An ack's `ControlEffectResult.why` (O5, **for Astation's sign-off**, amended for step 4; host-work-v1 §11.4 wire rule 10; the vocabulary is `control_why_codes()`, JS `controlWhyCodes()`) is why an effect `pending` or `refused` isn't in force, as the host wrote it, or `None` (JS `null`): read it as information only, never as a count or a request to re-sign, and treat a code you don't know as unrecognized (a later version's; the result stands). A reason that is `null`, not a text, empty, over 64 bytes, outside `[a-z0-9_]` or beside `applied` or `duplicate` refuses the whole ack, `Invalid{malformed}` |
| `relay_control_sync_result(request_id, origin, feed_id, after, head, station_time, records)` | the answer to the call `request_id` names, its `after` echoed, on the feed it named (or, for a call that named none, the account's current feed): at most 64 `RelayFeedRecord{feed_seq, record_json}`, ascending, each `feed_seq` strictly after `after` and at most `head` (gaps are legal; a `head` below `after`, a feed that went back under the same id, takes no record: the host rescans), 256 KiB in all. Never leave out earlier stored records to fill a page with later ones. Each record goes through the control parser first: one it refuses is `Invalid{code}` with its parse code, and the page isn't written. Serve only records you validated at intake and stored |
| `relay_control_sync_answers(call, result)` | whether the `control_sync_result` text `result` answers the `control_sync` text `call` (each read strictly; `Invalid{code}` if either isn't one): `RelaySyncVerdict::Answers`, else the first field that differs, `RequestId`, `Origin`, `FeedId` or `After`. The shared matching decision of the host and the `:8080` proxy; the caller compares the link generation, account and genesis it captured with the call |
| `relay_heads(feeds, membership)` | each covering feed's `RelayFeedHead{origin, feed_id, head, station_time}` (at most 64, a feed once) and the device list's `LogHead`. Send it on every (re)connection, every 30 seconds and at once when a record is stored. `membership` is the stored log's `LogHead` exactly: the host compares `seq` and hash (**Atem's reading, for Astation**, step 4, 2026-11-13; host-work-v1 §11.4, "The gate") |
| `relay_membership_fetch_result(head, entries)` | the device list's head and the entries after the host's `after` (signed objects' JSON), at most 64: an R9.3 carriage |
| `relay_control_sync_refused(code)`, `relay_membership_fetch_refused(code)`, `relay_control_ack_refused(code)` | a refusal of that call on this link (`code`: `RelayRefusalCode::Forbidden`, the only one); never send an empty page or an ack instead. `relay_decode_to_host` reads them as `ControlSyncRefused{code}`, `MembershipFetchRefused{code}`, `ControlAckRefused{code}` |
| `relay_control_sync(request_id, origin, feed_id, after)`, `relay_control_ack(ack)`, `relay_membership_fetch(after)`, `relay_decode_to_host(message)` | the host's side, for tests and other hosts (`request_id`: the caller's, a fresh lowercase UUID v4 for every call; `relay_decode_to_host` reads a page as `ControlSyncResult{request_id, origin, feed_id, after, head, station_time, records}`) |

**Known answers.** `fixtures/r9-vectors-station-calls.json` holds every
message of the six calls and the three refusals as the exact text these
builders write (compact, keys in RFC 8785 order), with its decoded fields,
the control parser's verdict on each page record, and the invalid texts each
reader refuses with its code (an unknown field, a `null`, a duplicate key,
an unknown refusal code, a count of 65, and each refused form of a
typed reason: `null`, not a text, empty, over 64 bytes, outside
`[a-z0-9_]`, beside `applied` or `duplicate`, a duplicate `why` key; and
each refused form of correlation: a call's or a result's `request_id`
missing, `null`, upper case or not a v4 UUID, a result without its `after`,
a record at or below `after`, and a `head` below `after` with records),
the `matching` cases (a result read against one or more calls by
`relay_control_sync_answers`: a match, a discovery answered on the current
feed, a feed gone back, mismatches on the id, the origin, the feed and the
`after`, two calls at the same cursor that differ only by their ids, and a
retired call's late reply, each with its verdict),
and the byte bound for each call
that can carry a large page (a text of exactly 262,144 bytes read, one of
262,145 and one of 300,000 refused, for `control_sync_result` and
`membership_fetch_result` alike): a Station that writes or reads the same
bytes and gives the same codes agrees with Atem's host, and `scripts/check-r9-vectors.py` confirms them with a
reader written from host-work-v1 §11.4. A page whose records the control
parser refuses is a builder's page with those values put in their slots
(`hand_assembled: true` in its case): a Station serves only what it
validated at intake, so its builder refuses them, and a `null` or a string
record kept as evidence with the page standing is Atem's reading of "any
JSON type", agreed with Astation (2026-11-13, #120 comment 6848326392): keep such records' evidence, apply none of them, and
never take their delivery for application evidence; a page that isn't
strict JSON keeps the gate closed.

Each builder checks what the reader checks, so what it writes the reader
accepts; a value out of its grammar is `Invalid{code}` (`too_large`,
`malformed`). `relay_decode_to_host` gives each record's JSON as the
Station sent it, of any JSON type: a record the control parser refuses
costs only itself, never the page. JS: `relayDecodeToStation(message)`,
`relayDecodeToHost(message)` (plain objects, `{type: "control_sync" | "control_ack" | …, …}`, camelCase),
`relayControlSync(requestId, origin, feedId?, after)`,
`relayControlSyncResult(requestId, origin, feedId, after, head, stationTime, [{feedSeq, recordJson}])`,
`relayControlSyncAnswers(call, result)` (`"answers"`, `"request_id"`, `"origin"`, `"feed_id"` or `"after"`),
`relayHeads([{origin, feedId, head, stationTime}], {seq, hash})`,
`relayControlAck({accountId, genesisHash, hostId, hostTrustGen, origin, feedId, cursor, results})`
(each result `{type: "record", recordId, effects}` or `{type: "entry", seq,
entryHash, appliedSeq, effects}`, each effect `{effect, result}`),
`relayMembershipFetch(after)`, `relayMembershipFetchResult({seq, hash}, entries)`,
`relayControlSyncRefused("forbidden")`, `relayMembershipFetchRefused("forbidden")`,
`relayControlAckRefused("forbidden")` (read back as `{type: "control_sync_refused", code: "forbidden"}` and so on);
an object with a key outside these is refused (`malformed`).

### The acknowledgment ledger

`AckLedgerHandle` is the reference Station side of the hosts'
acknowledgments for one device list (an account and its root) at one
Station (its exact origin): which covered hosts have each revocation in
force, the reports owed to the Portal, and the native-signed records still
to re-sign. Keep one per device list your Station serves.

| call | what it does |
|---|---|
| `AckLedgerHandle::new(origin, account_id, genesis_hash)`, `from_json(state_json)`, `to_json()` | an empty ledger (`origin` exact, as hosts compare it: `https://` and a lowercase host, a port only when not the default, no path; `http://` on a loopback address for development; else `Invalid{malformed}`); the stored one (`Stored{code}`: `too_large` over 64 MiB, `malformed`, `unsupported_version`, `stored_invalid`, also for a `pending` list not in the order the reports were made: it would stall a principal); its durable state, canonical JSON (`"v": 1`) |
| `origin()`, `account_id()`, `genesis_hash()` | the Station and the device list the ledger is for (`genesis_hash` in lowercase hex): check them against the device list a stored state is loaded for |
| `record(record_json, revoked_at_ms, covered_hosts, now_ms)` | a record you stored in your feed, before you serve it. Your own `revoke` (signed with the integration's service key) starts the revocation: `revoked_at_ms` is when the Portal revoked the integration (the deadline's start, but the ledger keeps `min(revoked_at_ms, the record's issued_at + 1 hour)`, so the deadline is at most `issued_at` plus 25 hours, where a host stops resending the revoke's result: **Atem's proposal, agreed with Astation (2026-11-11, #120 comment 6810116314)**, host-work-v1 §11.4), `covered_hosts` the hosts its grant covered. For any other record `covered_hosts` are the hosts its re-sign alert waits for. Refused (`Invalid{code}`): `other_account`, `other_station`, `record_id_reused` (another body under a `record_id` the ledger tracks), `malformed`, or the record's parse code |
| `ack(link, ack_json, now_ms)` | a host's `control_ack` as received, on the link whose verified association is `link` (`LinkAssociationInfo{account_id, genesis_hash, host_id, host_trust_gen, connection_id}`). Refused whole, nothing counted: `incomplete_link`, `not_the_link` (the ack's account, root, host or trust generation isn't the link's), `other_account`, `other_station`, `not_the_record` (a result whose effects aren't the record's), or the reader's code. Answer `not_the_link`, `other_account` and `other_station` with `relay_control_ack_refused` on the link; the others get no reply |
| `tick(now_ms)` | your timer: a revocation 24 hours past its start (`record`'s `min(revoked_at_ms, issued_at + 1 hour)`) gets its `revoked{deadline_passed}` report |
| `pending_reports()` | what to send now, in order: `ReportIntentInfo{report_id, report, not_before}`, `report` being `RevocationApplied{integration_id, host, record_id}` or `Revoked{integration_id, outcome, pending_hosts}` |
| `report_answer(status)` | the class of the Portal's HTTP status: `Confirm`, `Retry`, `Refuse`, `StopReporting` (below) |
| `confirm(report_id)`, `refuse(report_id)` | the Portal accepted the report; refused it for good (settled, never sent again, a `ReportRefused` alert) |
| `stop_reporting(client_id)`, `resume_reporting(client_id)` | the Portal answered `403` to your report client `client_id` (your `station.report` client at Auth): the ledger records the ID and holds every report, none sent, until a resume (one `ReportingStopped` alert; refused `Invalid{malformed}` for an ID that isn't 1 to 128 characters of `[A-Za-z0-9._:-]`); you report again as `client_id`: the stop's own ID clears the stop and keeps every report, another ID drops the reports pending then (below); a ledger not stopped changes nothing, whatever the ID |
| `resign_alerts()`, `refused_reports()`, `dropped_reports()`, `dropped_client_ids()`, `reporting_stopped()`, `stopped_client_id()` | the native-signed records not yet in force on every host they cover, for every effect they carry (`record_id`s: Astation alerts the owner to re-sign those whose signer was removed); the reports refused for good; the reports a resume under another ID dropped, and the report client ID each was dropped under (the stopped one; the same order); whether reporting is stopped, and under which report client ID |

Every call that moves the ledger returns `AckTransition{next, made,
alerts}` and never changes the handle it was called on. `made` lists what
the call made; never send it: send the committed state's
`pending_reports()`. JS: `new
AckLedgerHandle(origin, accountId, genesisHash)`,
`AckLedgerHandle.fromJson(text)`, `toJson()`, `origin()`, `accountId()`,
`genesisHash()`, `record(recordJson,
revokedAtMs, coveredHosts, nowMs)`, `ack({accountId, genesisHash, hostId,
hostTrustGen, connectionId}, ackJson, nowMs)`, `tick(nowMs)`,
`confirm(id)`, `refuse(id)`, `stopReporting(clientId)`,
`resumeReporting(clientId)`, `pendingReports()` (plain objects:
`{reportId, report: {type: "revocation_applied" | "revoked", …},
notBefore}`), `resignAlerts()`, `refusedReports()`, `droppedReports()`,
`droppedClientIds()`,
`reportingStopped()`, `stoppedClientId()` (a string, or `undefined`); `AckTransition` has the
getters `next`, `made` and `alerts` (`{type: "report_refused",
reportId}`, `{type: "reporting_stopped", clientId}`, `{type:
"reports_dropped", clientId, dropped}`);
`reportAnswer(status)` gives `"confirm"`, `"retry"`, `"refuse"` or
`"stop_reporting"`.

**Which host is calling.** `link` is the complete association of the link
the ack arrived on, as your transport authenticated it: the account and its
root, the host and its trust generation, and the connection. Take it from
the link: a routed link's verified root, host and connection binding; for
a link the paired Astation authenticated (carrier A) or a call through
Astation's `:8080`, the authenticated transport's host association, or a
fresh host-key challenge proof where that can't be verified (session-v1
R9.7b's `host_challenge`/`host_route`, carried through the proxy;
host-work-v1 §11.4). Never from a field of the ack: the ledger refuses an ack whose
claim differs from `link`. **Fence connections at your transport**: an ack
from a connection of the host that isn't its current authenticated
connection (a superseded one) never reaches `ack`. The ledger compares the
account, root, host and trust generation and requires a connection id, but
it can't tell a superseded connection from the current one.

**Persistence and the order of calls** (each step durable before the next):

1. **A record.** Store it in your feed and call `record` at that time; in
   one transaction, store the feed row and `next.to_json()`. Then announce
   the head (`relay_heads`). Mint every `record_id` as a fresh UUID v4,
   unique in your Station (a re-signed record gets a new one).
2. **An ack.** Read it with `relay_decode_to_station`, take `link` from
   the connection, call `ack`, and store `next.to_json()` in one
   transaction **before any HTTP**: `next` holds every report not yet
   settled, so the reports are persisted with the state. Adopt `next` only
   once that committed. If the commit failed, keep the handle you called
   on: the host sends its ack again, and the same call on the same state
   gives the same next state and the same `report_id`s.
3. **Serialize the transitions of one ledger**, by compare-and-swap on the
   stored state. Two replicas that load the same state and process the
   same ack at the same `now_ms` give the same next state and the same
   reports, byte for byte, so the Portal would deduplicate them; but only
   serialized transitions keep it so (an ack processed at another time can
   pass a deadline). The replica whose compare-and-swap failed loads the
   new state and calls again: it makes nothing new.
4. **Your timer** calls `tick(now_ms)` at least once a minute, so a
   revocation's deadline is reported when no ack arrives (`ack` and
   `record` apply passed deadlines too).
5. **Delivery.** After each commit, POST `pending_reports()` in order to
   the Portal (`POST /api/v1/stations/reports`, the `report_id` as
   `reportId`; the HTTP body is Auth/Portal's, `platform.md`), and act on
   each answer by `report_answer(status)`. `confirm`, `refuse` and
   `stop_reporting` are transitions: commit each, and raise its `alerts`
   once it committed. A `403` is for your report client, not one ledger:
   call `stop_reporting` on every ledger you keep, in one transaction
   (raise one operator alert for the Station). If your store can't, then
   at start, before any resume, first stop every ledger not yet stopped
   under the report client ID a stopped ledger names.
6. **At start**, load the state with `from_json`, call
   `resume_reporting` with your current report client ID (commit it like
   any transition), raise again the alerts the state still holds (a
   crash between a commit and its alert loses the alert, never its cause:
   `refused_reports()`, `dropped_reports()` with `dropped_client_ids()`,
   `stopped_client_id()`), and
   send
   `pending_reports()` again. On any `Stored` error, keep reporting
   stopped for that device list and never start again from an empty
   ledger: it would lose the deadlines and the per-host counts.

**The 403 stop and its resume** (agreed with Auth/Portal; **agreed with Astation (2026-11-11, #120 comment
6810116314)**, whose built-in Station takes its report client
ID from its configuration and always resumes). A `403` stops reporting
under the report client ID that got it: the ledger records the ID, holds
every report (none is sent, none is dropped) and goes on counting and
making reports. `pending_reports()` is empty while stopped; `made` still
lists what each call made, and those reports are held.
When the Station reports again (after a restart, say once an operator fixed
a misconfigured token) it resumes with its report client ID. The ID is
compared only there, at a resume after a `403` stop: a ledger that isn't
stopped changes nothing, whatever the ID, so a report client that changes
without a stop changes nothing in the ledger.

- **The stop's own ID** clears the stop: every held report goes, in order.
- **Another ID than the stop's** is another Station at Auth (a removed
  Station registered again, with new integrations); Auth/Portal's rule is
  "start fresh, drop the old pending reports", read as follows (**agreed with Auth/Portal (2026-11-11, #148 comment 6803727308)**):
  the reports pending at that moment are dropped
  (settled unsent, kept in `dropped_reports()`, a `ReportsDropped` alert
  naming each), and nothing else changes: every revocation reports on as
  usual under the new ID (a host that applies it later, its final
  `revoked`), and the Portal's answers decide what becomes of them (a
  refusal is final, with an alert). No revocation is ever silenced. A
  final made after such a drop goes without the dropped per-host reports
  (they are settled unsent), and may be `all_applied`.

**`report_id` and the Portal's idempotency.** A report's id comes from its
identity only, never from time, order or a counter: `<kind>:` + lowercase
hex SHA-256 of `enc(["atem-station-report-id-v1", kind, account_id,
genesis_hash (32 raw bytes), principal, integration_id, host])`, without
the host for `revoked`; `enc` puts a 4-byte big-endian length before every
field (R9.1). The derivation is host-work-v1 §11.4, "Reports", with known
answers in `r9-control-ack-*` (recomputed independently by
`scripts/check-r9-vectors.py`). An id is 72 or 83 characters of
`[a-z0-9_:]`, within the Portal's 1 to 128 characters of
`[A-Za-z0-9._:-]`. A retry, a restart or a replica sends the same id with
the same body; the Portal answers a repeated id with the same body with its
recorded answer and counts nothing again, and a repeated id with another
body with `409 report_id_reused` (the first stands). A revocation has one
`revoked` and one `revocation_applied` per host, so neither the record a
`revocation_applied` names nor a `revoked`'s outcome is part of the id.

**The Portal's report rules** (Auth/Portal's Phase B, the revised set;
the Portal's `platform.md` "Station Builders" contract is authoritative and
points here for the `reportId` derivation): the per-host body is
`{integrationId, state: "revocation_applied", reportId, host, recordId}`
and the final body `{integrationId, state: "revoked", reportId, outcome,
pendingHosts}`; `reportId` is 1 to 128 characters of `[A-Za-z0-9._:-]`,
opaque to the Portal; `host` and every `pendingHosts` entry follow the
device-list id grammar, and `recordId` is a lowercase UUID v4;
`pendingHosts` holds at most 100 distinct entries (the ledger's bound is
64, `MAX_HOSTS`); a body is at most 16 KiB; `revocation_applied` needs the
integration in `revoking` or `revoked`, else `409 invalid_state`; the same
host under another `reportId` gets `200` and is not counted again, and a
second final under another `reportId` gets `409`. Report order, a final
at once for an own revoke past its deadline or with no covered host, the
24-hour clock and the 403 stop and resume are agreed with Auth/Portal (2026-11-11, #148 comment 6803727308).

**The Portal's answers** (Auth/Portal's classes; `report_answer`):

| answer | class | what the Station does |
|---|---|---|
| `200`, the recorded `200` of a repeated `reportId` included | `Confirm` | `confirm` |
| a network error, a timeout, any 5xx (`503` and unknown ones too) | `Retry` | send the same report (same `reportId`, same body) again later, with backoff |
| `408` | `Retry` | the same, like a timeout |
| `429` | `Retry` | the same, after its `Retry-After` |
| `401` | `Retry` | refresh the `station.report` token, then the same |
| `409 report_id_reused`, `400`, `404`, `409 invalid_state`, `413`, `415`, any other 4xx | `Refuse` | `refuse`: final, with an operator alert |
| `403` | `StopReporting` | `stop_reporting(client_id)` on every ledger: every report held, none sent, one alert, until a resume (above) |
| any other status (1xx, 3xx, a 2xx other than `200`) | `Refuse` | final, with an operator alert (agreed with Auth/Portal: the Portal answers none of these). **Never follow a 3xx**: it would carry the `station.report` bearer wherever it points |

A network error or a timeout has no status: it is `Retry`, so never pass a
"no response" sentinel such as `0` to `report_answer`, which takes it for
a status the Portal never answers with (`Refuse`).

Reports of one principal go in the order they were made, one at a time:
`pending_reports()` offers a report only once every report of the same
principal made before it is settled (confirmed, refused or dropped), so a
per-host report made after its revocation's `revoked` is delivered after
it, and a final after the per-host reports made before it (`not_before`). Keep sending `revocation_applied` after a
revocation's `revoked{deadline_passed}`: a host that applies it late is
still reported, and the Portal records it (it lowers "n hosts didn't
confirm"); `revoked` is never sent again.

**What counts** (host-work-v1 §11.4, "Acknowledgments"): only an effect
result of `applied` or `duplicate`, per host and per effect (a principal's
revocation, and the interrupt for it); the cursor, `pending` and `refused`
never count. `revocation_applied` goes once per host and revoked
integration, at the host's first `applied` or `duplicate` for the
revocation, naming that record (**changed agreed meaning, agreed by
Auth/Portal, and by Astation (2026-11-11, #120 comment 6810116314)**: the agreed design sent it only
at `applied`; a host that applied the revocation through another record
first reports this Station's record `duplicate` and is still counted);
`revoked{all_applied}` goes after every covered host's
`revocation_applied` (but one dropped by a resume under another report
client ID), `revoked{deadline_passed, pending_hosts}` 24 hours after the
revocation's start (`min(revoked_at_ms, the own revoke's issued_at + 1
hour)`).

**Its size.** The ledger keeps the `revoke` and `interrupt_running` records
it tracks (at most 64 covered hosts each), what each host has in force, the
reports not yet settled and the ids of those settled unsent. Nothing is
pruned in this version: keep it as long as the principal exists (design
I.5.2's retention); `from_json` reads at most 64 MiB.

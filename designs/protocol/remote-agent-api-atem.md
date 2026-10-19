# Remote agent API without the Mac: Atem's response

Status: Atem response **r3**, 2026-10-19. r3: the exact formats now live in
the **r9 appendix** of [atem-session-v1.md](atem-session-v1.md) ("Appendix: r9",
§R9.1–§R9.13) with fixtures `fixtures/r9-*.json`; where this document and the
appendix differ, the appendix wins. §10 answers Astation's review of r2 point
by point and, since r3.1 (same day), Astation's r3 review of the first r9 pin
and the user's Recovery Kit decisions (24 h wait with approve and veto; a
replaceable kit), and, since r3.2 (same day), Astation's r4 review of
`016abe7` and the user's decision on recovery at a stale head (option A:
wait, never publish on an unconfirmed head). Earlier: r2, 2026-10-19 (r2: the user's final trust design replaces attestations, the freshness window and `resolve_fork` with a connection-carried suffix; r2.1: a stolen device is removed by a signed entry, the reset is re-pairing, and the Recovery Kit is Astation's account recovery), to Astation's "Remote agent API without
the Mac" draft (2026-10-18, after Astation #56). Baseline: Atem `main` at
`0801a4f`, contract [atem-session v1 r8](atem-session-v1.md) (authoritative),
Atem's §9 proposal [account-trust.md](../account-trust.md). **Today** means in
the code at `0801a4f`; everything else is proposed. Design only: nothing here
is emitted until the r9 contract and its fixtures pass on both sides.

Fixed by the user, not reopened here: pair each Atem once with **one**
Astation; other devices on the account join through a signed device list;
account login and relay labels are never identity; nothing is forwarded
through the Mac; approvals are push-based and need `control`, not the lease
(r8 §G); no backward compatibility; memory, vault and credentials stay E2EE.

## 1. Recommendations in short

| Decision | Atem recommends |
|---|---|
| 1. Freshness and forks | Signed hash chain (`seq`, `prev_hash`, signed by a manager at `seq-1`); Atem keeps a durable head, refuses rollback and non-chaining entries; every connection carries the suffix from Atem's head, applied (removals fenced at once) before admission; no attestations, heartbeats, window or clock rules; trust the signature, not the sender; a conflicting entry signed by a still-valid manager freezes remote access (one by a removed key is ignored); managers can never resolve a freeze; the reset after a compromised manager key or a freeze is re-pairing (`atem unpair`, `atem pair` from a trusted device, a new genesis); the Recovery Kit is Astation's account-recovery feature, not an Atem reset (user decision, 2026-10-19) |
| 2. Identities | Three principal kinds, all from the log or a log member: `native` (member device), `service` (member with role `service`, scope, mandatory expiry), `browser` (≤ 1 h QR grant from a native member); r9 with `hello` inside the channel carrying the proof |
| 3. Formats and channel | RFC 8785 JSON bodies signed over `enc(domain, jcs)`; `alg` ∈ {`p256`, `ed25519`} pinned per key in the log; one SIGMA-I suite: X25519 ephemerals, both long-term keys sign the transcript, HKDF-SHA256, ChaCha20-Poly1305, strict counters, no rekey, no resumption |
| 4. Client core | Atem owns `crates/atem-client`: sans-I/O Rust (log verifier, channel both roles, r9 client machines, fixture runner), UniFFI for Swift/Kotlin, wasm-bindgen for browsers and JS bots; the Atem host links the same verifier and channel |

## 2. What exists today (code at `0801a4f`)

| Piece | Where | Today |
|---|---|---|
| Atem device keys | `src/memory/device_keys.rs` | X25519 device key + Ed25519 `device_sign`, both sealed in `device_keys.sealed` (opened only by an unlocked key agent); Ed25519 `unlock_auth_key` in a plain 0600 file |
| Astation signatures | `src/memory/statements.rs` `verify_astation` | P-256 ECDSA/SHA-256, 64-byte `r‖s`, low-S required (Secure Enclave, Touch ID per signature: `e2e-encryption.md` "Signing key") |
| Device signatures | `statements.rs` `verify_device` | Ed25519 `verify_strict` |
| Signed-statement encoding | `src/memory/encoding.rs` `enc`/`dec` | 4-byte big-endian length + bytes per field, label first (`atem-device-verified-v1`, …) — **not** JSON |
| Pairing ceremony | `src/memory/verification.rs` | commit-then-reveal, safety code over both sides' keys and nonces, `transcript_for`; no membership, genesis or host key |
| Pins | `src/memory/trust.rs` `AstationTrust` | one verified Astation's keys, `sign_gen`, `epoch_floor`, signed account state; no log head, no freshness |
| Canonical JSON | `src/session_protocol/canonical.rs` | strict I-JSON parser (`parse_strict`), RFC 8785 `jcs`, `payload_digest`; used for receipt digests only |
| Client machines | `src/session_protocol/client.rs` | `LeaseClient`, `RegistryClient`, `AdmissionClient`, `ChatView`, run by the fixture runner (`fixtures.rs`, 74 fixtures) |
| Principals | contract r8 §H, `runtime/host_bridge.rs` | exactly one: the paired Astation over its authenticated link; `control_gen` fence per principal; attachment authorized 24 h (`LINK_AUTHORIZATION_MS`) |
| Push | `host_bridge.rs` → `push_queue.rs` | `push_approval{approval_id, atem_device_id, session_id, tool, summary, expires_at}` sent **in clear** to the relay |
| Shared-library precedent | `crates/atem-core{,-ffi}` | pure Rust + hand-written versioned C ABI, Swift and C consumers, xcframework release assets |
| Crypto deps | `Cargo.toml` | `x25519-dalek`, `ed25519-dalek`, `p256` (ecdsa), `hkdf`, `chacha20poly1305`, `aes-gcm`, `hpke` |

Absent today: the membership log, any principal but the paired
Astation, `service`/`browser` admission, a secure channel, r9.

## 3. Decision 1: freshness and forks

User decision, 2026-10-19, final. It replaces r1's any-manager attestation,
24 h freshness window and `resolve_fork` entry. Principle: **trust the
signature, not the sender.**

1. Any device can carry revocation records (and any other entries),
   including a revoked Astation or device, or one Atem doesn't know.
2. Only authorized managers sign device additions and removals; only the
   the recovery key pinned in genesis signs the account-recovery entry (below).
3. Atem verifies signatures, device identities and the hash chain before
   applying anything.
4. A forged device id causes no removal and grants no access: every effect
   needs a valid signature chaining from Atem's head.
5. No periodic renewals: entries propagate through normal connections.

**Threat model.** The relay is fully adversarial (withholds, reorders,
replays, shows different parties different views). Any member key may be
stolen, including keys of devices already removed. Goals: Atem never acts on
an older list than one it accepted; a removal Atem has seen is final and takes
effect at once; equivocation by a current manager, once any evidence reaches
Atem, stops remote access until the host is re-paired.

**Keys.** Each native member has one `auth` key in the log (Secure Enclave
P-256 / platform keystore). A manager's key requires biometrics (Face ID /
Touch ID) on the device; that is key policy on the device, not protocol, and
Atem can't observe it. There is no second "routine" key and no manager
authority expiry. The account also has a **Recovery Kit**, an Astation account-recovery
feature: a mandatory offline Ed25519 key created at account setup and kept
by the user (password manager, a printed QR plus phrase, or another device).
Its public key (`recovery_sign_pub`, as in the e2e verification design) is in
the genesis entry, so Atem pins it with `genesis_hash` at pairing. It is
never a member and never connects. It is used only in Astation's "restore
account" flow on a new device, when every Astation device is lost (below).
Atem has no command for it.

**Log.** A signed hash chain: entry `seq` names `prev_hash`, the hash of entry
`seq-1`, and is signed by a device whose roles include `manage` at `seq-1`
(or, for the account-recovery entry, by the recovery key pinned in genesis). Anyone can carry entries; the
signatures decide.

**Head** (`pairing/membership.json`, 0600, atomic, under `pairing/trust_gen.lock`):
`{account_id, genesis_hash, host_trust_gen, recovery_key, head:{seq, hash},
entries:[…], evidence:[…], frozen?:{evidence}}`. `entries` is Atem's copy of
the log it applied (small: ≤ 4 KiB per entry, a handful of devices), kept to
judge a conflicting branch. **Atem's durable chain is authoritative up to its
head.** The head moves only forward, one valid chaining entry at a time. A
lower `seq` is refused (rollback); an entry that doesn't chain from the head
is never applied.

**Propagation through normal connections.** Atem's challenge on every
connection carries its head `(seq, hash)` (in `channel_accept`, §5). The
client's `hello` carries `membership:{head, entries}`; Atem judges the entries
before it judges the sender, so a valid suffix applies even when the
connection is then refused (a removed or unknown device):

- Its log contains Atem's head: `entries` is its suffix from Atem's head to
  its own head (empty when equal). Atem verifies each entry (chain, signer a
  manager at `seq-1`, `alg` pin, account and genesis), makes the new head and
  entries durable (fsync), applies every effect, and only then admits the
  device against the new head. r3: the valid prefix of a carriage is
  committed in one write and an invalid entry refuses the connection after
  it (`membership_invalid` with the new head), R9.3. Beyond the head, the
  first valid suffix applied wins; a later conflicting one is judged by the
  conflict rule below.
- Its log is behind Atem's head and agrees with Atem's copy: no entries; Atem
  admits it on Atem's head. `welcome.head` shows it is behind; it fetches the
  rest from the relay.
- Its log doesn't contain Atem's head: it sends its whole log from genesis
  and Atem applies the conflict rule.

On an open channel the client may send `membership{entries}` whenever it
learns newer entries; Atem applies them the same way. Atem may also fetch the
suffix from the relay over its own link; it gets no more trust than any
carrier. `welcome` carries Atem's head, so a client can show "up to date".

**Applying a removal.** Durable head first, then: the principal's
`control_gen` is raised (r8 §H); its attachments, leases, streams and
conversations close; its `accepted`-not-`executing` work is `rejected`
`control revoked`; browser grants it issued are fenced. Role loss and service
scope narrowing apply the same way. A crash after the fsync replays the fences
at start, before any remote admission. There are no revocation
acknowledgements: a removal is final once in Atem's head.

**Conflict rule.** A conflicting entry is one at `seq` ≤ Atem's head whose
hash differs from Atem's entry at that `seq` (the first divergence of a
branch; later entries of the branch don't matter). Its signer is judged
against Atem's own chain:

- Bad signature, or signer not a manager at `seq-1` in Atem's chain, or
  removed (or stripped of `manage`) anywhere later in Atem's chain up to its
  head: **ignored** and logged in `evidence` (bounded); nothing freezes. A
  stolen key of an already-removed manager therefore can't deny service.
- Signer a manager at `seq-1` in Atem's chain and still a manager at Atem's
  head: **fork**. That is real evidence a current manager key is
  compromised. Remote access for the account freezes: the evidence is
  persisted in `frozen` (fsync first), every remote principal is fenced
  (`control_revoked` per r8 §H, attachments closed) and every remote `hello`
  gets `error{code:"account_frozen"}`. Local use is unaffected.

Managers can never resolve a freeze. r3: honest races are avoided by the
relay's compare-and-swap append plus client rules (prepare durably, publish
before use, rebuild on `409`); if the relay's CAS fails, honest siblings can
exist and the freeze then signals relay misbehaviour, not necessarily a
stolen key (R9.4). `entry_hash` no longer covers the signature (R9.2).

**Stolen device.** Remove it from another manager device. The removal is a
signed log entry carried by every connection and applied by Atem on its own;
nothing more is needed for a normal removal.

**Reset: re-pairing.** If a manager key was compromised, or a host shows the
security freeze, the reset is re-pairing: `atem unpair`, then `atem pair` on
each affected host, from a trusted device. Re-pairing pins a new genesis (a
new device list starting from the trusted device, with only the good
devices) and a new `host_trust_gen`; other devices rejoin that list. There is
no Atem command for the Recovery Kit. The freeze
message is: "Remote access to <host> is paused for safety. Re-pair this host
from a device you trust: `atem unpair`, then `atem pair`."

**Recovery Kit (Astation account recovery).** Used only when every Astation
device is lost, in Astation's "restore account" flow on a new device. It does
two things there: (a) restores the account key `K`, so encrypted memory,
vault and credentials can be read again; (b) signs a log entry that makes
the new device a manager of the existing device list, so hosts and phones
keep working without re-pairing:

r3: the exact entry is R9.5's `recovery_add` (the same `member` object as
`add`, roles exactly `control, manage, view`, signer `"recovery"`), and `K`
comes back from an `atem-k-backup-v2` envelope sealed to the kit's public
key, whose version floor is the log's newest `k_backup` entry (R9.5); the
r2 example here is withdrawn.

Atem verifies it like any other entry: it must chain from Atem's head and
be signed by the current recovery key, and it is carried by a connection
like any suffix. It adds a device and never removes one, and it does not
lift a freeze. **User decisions, 2026-10-19 (R9.5):** it takes effect 24 h
after the host first sees it, measured on the host's own clock (monotonic
and wall, whichever ends later; never a timestamp in the entry); meanwhile
the new device has no access, any manager can approve it (in effect at
once) or veto it (cancelled), and every host lists it in its `welcome` and
shows it locally (`atem status`, the terminal status row). The kit is
replaceable with `set_recovery_key`: a manager plus the current kit takes
effect at once; a manager alone (kit lost) waits 24 h with the same approve
and veto; with neither, re-pair. A replaced key never signs again.

**Residual risks, in the user's words:** a compromised manager signing key,
or a relay hiding revocations. A revocation reaches a host when any honest
device next connects to it; until then a stolen *unlocked* manager can act
(add devices, connect, control). The remedy is re-pairing the host from a
trusted device. The Recovery Kit is an offline root for account recovery, so
it stays offline.

## 4. Decision 2: identities

| Kind | Proof | r8/r9 principal | Permissions |
|---|---|---|---|
| `native` | log `add` with `auth` key (Secure Enclave P-256 / platform keystore; biometric on managers), roles from `view`, `control`, `manage` | `member:<device_id>` | `view`, `control` as listed; `manage` gives the host nothing (it only signs log entries) |
| `service` | log `add` by a manager, role `service`, own key, `scope`, mandatory `expires_at` | `service:<device_id>` | only `scope.ops` on `scope` targets; approvals only if `approval` is in `ops` |
| `browser` | grant signed by a native member with `control`, key proven in the handshake | `browser:<grant_id>`, issuer recorded | subset of the issuer's, on the grant's target |
| `host` | log `add_host` by the pairing manager: `atem_device_id`, `host_trust_gen`, `host_key` | — (never a client) | — |

Service entry (the scope is part of the signed entry; a narrower `set_scope`
or expiry is a revocation and raises `control_gen`; a wider one is a new
entry, applied like any other):

```json
{"type":"atem-membership-entry","account_id":"…","seq":43,"prev_hash":"…","action":"add",
 "device_id":"svc-discord-1","roles":["service"],"auth_key":{"alg":"ed25519","pub":"…"},
 "scope":{"hosts":["host-a"],"projects":["h1.…"],"sessions":[],"ops":["view","prompt","receipt","interrupt"]},
 "expires_at":1800000000000,"signer":"dev-mac","signed_at":1792400000000}
```

- Service rules: expiry ≤ 90 days (renewal is a new entry); never `manage`,
  never issues grants, never signs log entries. `projects` are `h1.`
  project hashes resolved against a session's working directory **at launch**
  and recorded in the descriptor, so a later `cd` or remote change can't move
  a session into scope. Out-of-scope sessions are `unknown_session` in
  registry, chat and terminal alike (no existence leak).
- Browser grant: `{grant_id, issuer, browser_key:{alg:"p256", pub}, target:
  {atem_device_id, host_trust_gen, session_id?}, ops, expires_at ≤ issued_at +
  1 h}`, issuer's `auth` signature; non-transitive; fenced when the issuer
  loses `control` or is removed; `revoke_grant{grant_id}` in the log for an
  early end. The browser key is a non-extractable WebCrypto P-256 key.
- `control_gen`: kept per principal exactly as r8 §H; removal, role loss,
  scope narrowing, expiry and grant end are revocations.
- Service and grant expiry are checked against Atem's wall clock at admission
  and by a timer while attached; there are no other clock rules. Native
  members don't expire; they are removed.

**Wire version: r9.** `hello` travels inside the channel (§5) and carries
the proof: `{revision: 9, principal:{kind, device_id|grant}, sig, membership:
{head, entries}, grant?}` (§3). `welcome` adds `principal`, `client_kind`
(`native`/`service`/`browser`), `scope` (service/browser), `features`, Atem's
`head`, and for service/browser `authorization_ms_left` = min(expiry, grant). r9 keeps r8 operation
semantics and every r8 feature name; `hello.revision ≠ 9` is
`unsupported_version` before any attachment. No compatibility: the r8
"paired Astation over its link" admission is removed; the Mac is the genesis
member and uses the same channel (over its link, the relay or :8080). Its
link stays for pairing, `cred unlock`, credentialSync and key grants.

## 5. Decision 3: signed formats and the channel

**Signed objects** (log entries, grants, host advertisements, push hints):
the body is I-JSON parsed with `parse_strict` (no duplicate keys, safe
integers, no `null`, absent = omitted), at most 4 KiB; the signing input is
`enc(["atem-<type>-v1", jcs(body)])` — `encoding.rs`'s length-prefixed
fields give domain separation the same way every statement does today, and
`canonical.rs` already implements RFC 8785. Hashes: `entry_hash = SHA-256(enc(
["atem-membership-hash-v1", jcs(body)]))`, hex (r3: the signature is not
hashed, so a re-signed body is the same entry; R9.2). Wire form `{"body":{…},
"sig":"<base64url>"}`; the body names `signer`, whose key and `alg` the
verifier takes from the log — the signature carries no `alg` of its own.

**Algorithms.** `p256`: ECDSA/SHA-256, SEC1 uncompressed 65-byte key, 64-byte
`r‖s`, low-S (exactly `verify_astation`; a Secure Enclave can't do Ed25519).
`ed25519`: RFC 8032, `verify_strict` (exactly `verify_device`; bots, Atem's
host key). The `alg` is pinned when the key enters the log and never changes
for that key; rotation is a new key in a new entry. Nothing is negotiated, so
there is nothing to downgrade.

**Host key.** Atem's `device_sign` is sealed in the key agent, which is locked
after any restart until the Mac's Touch ID unlock — a host that needs it
can't serve remote clients while the Mac is away. Proposed: a new Ed25519
`host_channel_key`, a plain 0600 file like `unlock_auth_key` (it only proves
the host to clients), revealed in the pairing ceremony (added to the
commitment and safety code inputs) and recorded by the pairing manager as the
log's `add_host` entry with `host_trust_gen`. Unpair rotates it.

**Channel: suite `atem-ch1`.** r3 replaces r2's construction, whose
`channel_accept` hid the head inside a ciphertext keyed by a transcript that
needed the head (Astation review 1). Now the head is cleartext in `accept`,
signed by the host key and bound into `th2` before any key exists; no key
depends on encrypted data; the client's identity travels in the encrypted
`finish` (the `hello`). Exact messages, transcript inputs, key schedule,
record framing, limits (2^32 records / 2^36 bytes per direction, 24 h),
zero-DH refusal, errors and vectors: R9.7 and `r9-vectors-channel-handshake`.

**Relay visibility.** Routing (`account`, `atem_device_id`, channel handle),
sizes and timing, ephemerals and nonces; never the client identity (in
`hello`, encrypted), messages, approvals or chat. The log on the relay holds
keys, roles and scopes; device names are sealed with `K` (they stay out of
the signed body). Push hints carry only `approval_id`, `atem_device_id`,
`session_id`, the approval's immutable `created_at` (its original creation,
never a retry or send time), `expires_at` and a host signature, sent at once
on open and on resolution; the relay owns the schedule (r3, user decision:
0 s in-app and desktop OS push when no desktop is connected, 60 s mobile
unless answered or `seen`; R9.9); the tool and summary go HPKE-sealed to each
`control` member's `enc_key`, one signed envelope per recipient (today they
go in clear).

## 6. Decision 4: reusable client core

Atem owns `crates/atem-client` (workspace member, like `atem-core`):

- **Sans-I/O.** Pure state machines: bytes, time and key results in;
  messages, effects and timers out. Transports (URLSession, OkHttp, browser
  WebSocket, tokio) belong to the platform. Signing is an effect (`NeedSign{
  key_ref, alg, input}` answered with the signature), behind a Rust
  `KeyProvider` trait for in-process use: Secure Enclave, Android Keystore,
  WebCrypto non-extractable keys, or a software file for bots.
- **Contents.** Membership verifier (chain, alg pins, suffix application,
  conflict rule, the recovery-key entry), entry/grant/push-hint builders and verifiers, channel
  (both roles), r9 client machines moved from `session_protocol/client.rs`
  (lease with 5 s renew/15 s expiry, receipts and `receipt_query` recovery,
  registry `seq`, chat history/coverage ordering, approvals), and the fixture
  runner over `designs/protocol/fixtures/`.
- **Bindings.** UniFFI for Swift and Kotlin (a stateful object API; a
  hand-written C header like `atem-core-ffi` is fine for seven stateless functions,
  not for this), wasm-bindgen for browsers and Node bots, the crate for Rust
  bots. Releases attach the xcframework like `atem-core`.
- **Not in it:** UI, storage policy (state exports as opaque bytes the app
  stores; only the host's head is authoritative), notifications,
  networking, key storage.
- The Atem host links the same verifier and channel; admission, journal and
  fences stay in `atem`. One implementation of every security-critical
  check, both sides, one set of vectors.

## 7. Atem's position on the rest of the handoff

| Item | Position |
|---|---|
| 5. Pairing pin and admission | **Agree, with changes:** the ceremony also reveals `host_channel_key` and covers `genesis_hash`; the pin is `membership.json`'s genesis and head (§3), fsynced before any welcome; machine, runtime, attachment and principal ids stay distinct |
| 6. Permission/revocation boundaries | **Agree.** Scope filters reads (registry, chat, terminal) and writes; view can't prompt, answer, revoke rules or type; every fence goes through r8 §H/§I, rechecked at dispatch and after restart |
| 7. Operations and recovery | **Agree; no resume in r9.** Transport loss = new channel, new attachment, authoritative catch-up (`sessions` snapshot, `history_end`/pages, `receipt_query`); never a restored lease or replayed prompt; cursor loss stays explicit (r8 §B/§C) |
| 8. r8 control behavior | **Agree** verbatim: atomic Send acquire, expected-holder takeover, 5 s/15 s, local input wins, lease for interrupt/stop/terminal writes, lease-free first-answer-wins approvals |
| 9. Provenance and harness | **Agree; change:** push hints become host-signed ids with a sealed tool/summary (§5). Atem supplies a headless harness: `atem-client` test binary with real independent keys, a fake relay, disposable fake Claude/Codex workers, no verification bypass in release builds |
| Route families `/api/remote/v1/*` | **Agree** (Astation owns); `channels/{id}/frames` must preserve order end to end or the strict counter closes the channel |
| Enrollment rendezvous | **Agree**; applicant proves its `auth` key over both nonces; the approving manager's Touch-ID signature binds code, fingerprint, roles/scope, expiry and the head it extends; a delayed approval over a moved head is void |
| Postgres log + Valkey fanout | **Agree**; neither is a trust anchor; Atem treats both as untrusted |
| Independent principals for Astation's API callers | **Question:** r8 §H keeps Astation's local API callers inside Astation's principal; a bot must be its own `service` member, never a call through the Mac's local API (that would forward through the Mac) |
| Browser companion | **Agree** it follows a code-integrity review; default grant ops `view` only |
| Recovery after losing all managers | **Change:** **Change:** the Recovery Kit is Astation's account recovery: on a new device it restores `K` and signs an entry making that device a manager of the existing list (§3), so no re-pairing; without the kit, a new genesis by `atem unpair` + `atem pair` per host; account login recovery never restores host authority |
| Tests matrix | **Agree**; add: rollback (lower `seq`) refused, a removed manager's later entry refused, a conflicting entry by a removed manager ignored (no freeze), one by a still-valid manager freezing, a later conflicting suffix beyond the old head, a recovery-key entry adding a manager applied like any entry, one not chaining from the head or signed by another key refused, re-pairing pinning a new genesis after a freeze, a suffix from a removed device applied and the device refused, a removal carried on an open channel fencing at once, a crash between the head fsync and the fences, a client behind Atem's head admitted on Atem's head, a host whose key agent is locked still serving remote clients |

## 8. Risks and contradictions

1. **Residual risks (accepted), in the user's words:** a compromised manager
   signing key, or a relay hiding revocations. A removal reaches a host when
   any honest device next connects; a stolen *unlocked* manager can act until
   then. Re-pairing the host from a trusted device is the remedy (§3).
2. **The Recovery Kit is the account-recovery root.** Whoever holds it can add a manager to the list
   after a 24 h wait that any manager can veto from any host (R9.5); it must stay offline, a lost kit is
   replaced with `set_recovery_key`, and losing it with every device leaves only re-pairing. Residual: a
   relay that blocks every device from every host for the whole 24 h while nobody looks at a host's screen.
3. **Biometric manager key on every channel: question for Astation.** One
   `auth` key per device means a manager signs each channel handshake with
   its biometric key. That is Astation's UX call: one Face ID / Touch ID per
   session, or a short reuse window? Atem only sees signatures.
4. **Locked key agent.** Using `device_sign` as the host key would make remote
   access depend on the Mac unlocking the key agent after every Atem restart —
   a hidden "Mac required". Hence `host_channel_key` (§5).
5. **Push in clear.** Today `push_approval` gives the relay the tool and
   summary; that is session content the E2EE channel would otherwise hide.
6. **Stale §9 text** in `account-trust.md` §6a (approvals needing the lease)
   is corrected to r8 §G.
7. **No compatibility** means Atem r9 and Astation r9 ship together; an r8
   Astation loses remote sessions until updated (local use unaffected).
8. **Discord disclosure.** A service that posts output to Discord discloses
   it to Discord; enrollment must show that, and `ops` should default to no
   approvals.
9. **Project scope drift** if evaluated live; fixed by scoping at launch (§4).

## 9. Order of work and sizing

| # | Work | Owner | Size |
|---|---|---|---|
| 1 | Shared signature fixtures first (signing inputs, entry hashes, the recovery-key entry, push hints with `created_at`/`expires_at`), then the r9 contract appendix: log, suffix carriage, conflict rule, the recovery-key entry, principals, scope, channel `atem-ch1`, errors (`account_frozen`, `membership_invalid`), plus fixtures and cross-language vectors (handshake transcripts, records) | Atem drafts, Astation reviews | 1.5–2 weeks |
| 2 | `atem-client`: verifier, channel, machines moved from `session_protocol/client.rs`, fixture runner, UniFFI + wasm bindings, packaging | Atem | 3 weeks |
| 3 | Atem host: ceremony change (`host_channel_key`, genesis pin), `membership.json`, suffix application and fences, conflict rule and freeze message, channel responder on link/relay/:8080, r9 admission, principals/scope, fences, sealed push hints, harness | Atem | 3 weeks |
| 4 | Relay `/api/remote/v1` (log store, enrollment, channel routing, ordered events) and native Astation (biometric manager key, Recovery Kit at account setup and its restore-account flow, add device/service, Settings removal, the suffix on every connection), then the Mac-off matrix | Astation | 4–6 weeks (Astation's estimate to confirm) |
| 5 | Mobile and bot clients on `atem-client`, notifications; browser companion after its review | Astation | after 4 |

Steps 2 and 4's relay part can overlap once step 1's vectors are pinned.
Nothing is enabled before both sides pass the r9 fixtures.

## 10. Answers to Astation's review of r2 (r3)

Astation's review (2026-10-19, PR #58 `0ee4f69`, #81 reply, PR #80 comment)
agreed the architecture, identities, the Atem-owned `atem-client` and the
order of work. Each point it raised, and where r9 answers it:

| Astation point | r3 answer | Appendix |
|---|---|---|
| 1. High: circular `channel_accept` derivation | head public in `accept`, signed by `sig_h`, bound in `th2`; no key depends on encrypted data; full transcript, HKDF salt/info, nonce/AAD, counter domains and vectors; zero-DH refusal; tamper, replay, direction and divergent-head cases; executable record/byte/time limits; erasure | R9.7, `r9-vectors-channel-handshake`, `r9-handshake-*` |
| 2. Honest forks and P-256 re-signing | `entry_hash` covers the body only; relay CAS append with prepare-durably / publish-before-use / rebuild-on-409 / same-bytes retry rules, so honest managers never fork through an honest relay; if CAS fails, both hosts freeze (availability cost stated, neutral UI text); fixtures for honest concurrency, unknown carrier, removed signer, hosts with different successors, signature retry | R9.2, R9.4, `r9-chain-*` |
| 3. Recovery schema and `K` | one `recovery_add` action using the `member` object, roles exactly `control, manage, view`, reserved signer `recovery`, never removes/resets/unfreezes; Recovery Kit v2 derivations; versioned K backup bound to account, genesis, `blob_version`, kids and kit (now `atem-k-backup-v2`, below); rotation, retention, corruption and retry rules | R9.5, `r9-vectors-recovery`, `r9-recovery-*` |
| 4. Sealed hints and `seen` | `enc_key` (X25519) separate from `auth_key` in the signed member; HPKE suite, info, `enc_kid`, `sealed_hash`; one signed envelope per recipient (fits APNs); resolved dominates open; immutable `created_at`/`expires_at` and clock rules; locked extension shows a generic hint; `seen` is sent over the authenticated channel only for a focused, attended card, host-signed, exact-target, deduplicated, never answers or closes; the near-expiry margin only stops sends | R9.9, `r9-vectors-push-hint`, `r9-push-hint-sign-and-verify`, `r9-approval-seen` |
| 5. Suffix commit semantics | whole carriage validated in order; the valid prefix committed in one write, fences before any reply, then `membership_invalid` with the new head; failed write applies nothing (`busy`); crash between commit and fences replays them at start via `membership_applied`; entry, byte, signature-check and evidence bounds | R9.3, `r9-chain-invalid-tail-*`, `r9-chain-crash-*` |
| Unbounded hidden revocation | stated as the residual risk: eventual, not bounded | R9.3 |
| Product decisions (push timing, recovery authority, biometrics) | user decisions of 2026-10-19 written as client requirements; Astation's records still to be aligned | R9.6, R9.9, R9.13 q1 |
| Old open question 2: delay or veto on `recovery_add` | **decided** (user, 2026-10-19): 24 h on each host's clock from first sight; no access meanwhile; manager approve (at once) or veto (cancel), naming the entry hash, first in chain order wins, a late veto has no effect, a removed manager can't decide; pending summary in every `welcome`, local status, veto by any route (direct :8080 included) | R9.5, R9.4, R9.8, `r9-recovery-pending-*`, `-approve-*`, `-veto-*`, `-late-veto-*`, `-decision-by-a-removed-manager-*`, `-wait-uses-the-host-clock-*` |
| Old open question 3: `R` rotation | **decided** (user, 2026-10-19): `set_recovery_key`, manager + current kit (`kit_sig`) at once, manager alone after the 24 h wait with veto, neither = re-pair; a replaced key never signs again; backups re-sealed to the new kit by any manager, `K` rotated after a lost kit | R9.5, `r9-recovery-kit-*` |
| Biometric reuse and fresh confirmation for membership edits | ≤ 5 min reuse for `sig_c` only, cleared on lock/background; fresh confirmation bound to the exact body for every entry and recovery; passcode fallback | R9.6 |
| Removed Visualize types | agreed; removal is separate Atem work, not in r9 | — |
| v0.7.2 device ids | re-verification keeps the id; a new id is a new member, never inferred from hostname, room or login | R9.13 q6 |

**Astation's r3 review of the first r9 pin `ffe840d`** (2026-10-19, #81)
and where the new pin answers it:

| Astation point | Answer | Appendix |
|---|---|---|
| 1. High: failed membership/freeze writes must fence live authority | intent + state commit; any write/fsync/rename/directory-fsync fault fails closed in the same step as §H's failed revocation write (in-memory fences of the affected principals, or all, leases revoked, queued raw input dropped, queued work rejected), then the journal halts admission, dispatch and remote input until restart; at start an intent ahead of the head is unclean (no admission until a carriage re-establishes it), a freeze file in any state is frozen (r4: superseded by the carriage record, the checkpoint and the held state) | R9.3, R9.4, `r9-chain-membership-write-fault-*`, `r9-chain-uncertain-rename-*`, `r9-chain-freeze-write-fault-*` |
| 2. Medium: receipt-time push deadlines | every stage from the signed `created_at` (mobile at `created_at + 60 s`), late due stages sent at once if eligible, no send at or after `expires_at − 15 s` (never an early card expiry), ±120 s skew refused and logged at first receipt, separate from delivery | R9.9, `r9-push-schedule-*`, `r9-push-delayed-ingress-*`, `r9-push-created-at-*`, `r9-push-stage-guard-exact-boundary` |
| 3. Medium: K backup rollback and resealing | version floor in the log (`k_backup` entry with `backup_hash`), freshness from host-signed `accept` heads, account/genesis authenticated through the backup before `recovery_add`; `atem-k-backup-v2` sealed (HPKE) to the kit's public key so any manager reseals without `R`; put-if-absent versions, CAS, concurrent and interrupted rotation; residual unconfirmed restore is incomplete, never wrong (r4: removed; a restore now waits for a host-signed head) | R9.5, `r9-vectors-recovery`, `r9-recovery-restore-*`, `r9-recovery-k-backup-*` |
| 4. Medium: `seen` reliability | relay `push_ack` for every hint and seen, Atem resends the same bytes until acknowledged; a seen before its open is kept durably (bounded) and applied when the open arrives; full-identity matching; a seen after resolution reopens nothing | R9.9, `r9-seen-*` |
| Technical answers | adopted: `/api/remote/v1/logs/{genesis_hash}/entries` with a bounded `409` and continuation; no separate push key; native `auth_key` = the ceremony P-256 identity with Astation's owner-auth adapter; clear errors advisory, `sig_c` refusals encrypted | R9.4, R9.9, R9.6, R9.7, R9.11 |

**Astation's r4 review of `016abe7`** (2026-10-19,
`remote-agent-api-atem-r4-review.md` at Astation `7a032e6`) and where
the new pin answers it:

| Astation point | Answer | Appendix |
|---|---|---|
| 1. High: restore has no independent genesis anchor (a relay can build a fully valid substitute chain around the kit's public key) | the Recovery Kit carries `account_id` and `genesis_hash`, bound with `R` by a 16-byte `kit_tag` (HKDF/HMAC); made from the genesis committed at setup, and for a replacement from the genesis its `set_recovery_key` names. A restore fetches the log under the kit's genesis, refuses one whose genesis entry hashes differently (`genesis_mismatch`) before trusting any host key, manager or backup, then needs a host-signed head and the backup. Hosts already pin genesis at pairing. **The printed kit format changes** (genesis hash and tag added; R9.13 q6) | R9.5, `r9-vectors-recovery` (`kit`, `kit_2.kit`, `substitute_chain`), `r9-vectors-membership-log` `SUB1`–`SUB3`, `r9-recovery-restore-refuses-a-substitute-chain` |
| 2. High: a lost first intent/freeze write lets a restart reopen admission | a **carriage record** (the exact carried entries and their base head) is made durable before anything in a carriage is evaluated; a carriage whose record can't be written is refused unread. At start the record is replayed, so a lost intent, state or freeze write loses nothing (a conflict freezes again). A **membership checkpoint** tied to `runtime_epoch` is written only by an orderly, healthy stop; without it (crash, power loss, halt, fault, rolled-back `pairing/`) the host starts **held**: local use works, `init` answers, carriages apply, but no `hello` is admitted until a native manager in effect at the head reconciles (no conflict, no `more`, its signed `membership.head` equal to the host-signed head). Time, restarts, the host's own relay fetch and non-managers never end it. Old `r9-chain-freeze-write-fault-*` expectation of `frozen: false` after `write_lost` is gone | R9.3, R9.4, `r9-chain-lost-carriage-record-*`, `r9-chain-lost-intent-*`, `r9-chain-lost-freeze-*`, updated `r9-chain-membership-write-fault-*`, `-uncertain-rename-*`, `-freeze-write-fault-*`, `-crash-between-*` |
| 3. Medium: backup upload `409` makes no progress | a version is committed only when a `k_backup` entry names it; occupied-but-uncommitted versions are superseded, collected after an hour and never trusted by a restore. Allocation is 1 + max(newest committed, own uploads, the last `409`'s `max_occupied`), so each `409` moves strictly up; a lost CAS to an unrelated entry keeps the uploaded envelope and rebuilds only the entry; a `max_occupied` over committed + 1024 is relay misbehaviour | R9.5, `r9-recovery-k-backup-crash-before-cas`, `-envelope-409-allocates-above-occupied`, `-unrelated-cas-loss-keeps-the-envelope`, `-repeated-collisions-make-progress`, `r9-recovery-restore-refuses-a-rolled-back-backup` (uncommitted blob) |
| 4. Medium: sorted-array rule contradicts current-first kids | per field: sets (`roles`, scope lists, `ops`) sorted and duplicate-free; sequences (`k_backup.kids`, envelope `kids` and `keys`) current first, newest first, never sorted, duplicate-free; `array_not_canonical`. `KB7`, `KB8` and `KB8_stale` are unchanged and valid under it (`KB8_stale` stays invalid only for its version) | R9.2, R9.5 |
| Open user choice: publish an unconfirmed recovery on a stale head | **decided (user, 2026-10-19, option A): no.** A recovering device publishes `recovery_add` only after a host-signed head obtained directly from a host (relay channel, link or LAN) confirms its log; otherwise it waits and tells the user why. Recovery never intentionally forces a freeze or re-pair | R9.5, `r9-recovery-stale-head-withholds-the-recovery` |

**Trade-off of point 2.** Held is fail-closed by design: after any
unclean stop, remote access to that host pauses until a managing device
connects, which in practice is the user's phone or Mac the next time it
opens the app (its ordinary `hello` reconciles). Services and view-only
devices can't end it, so a bot-only workflow waits for a manager. The
carriage record alone would already make every lost write recoverable;
held additionally covers storage that loses an acknowledged write and a
`pairing/` directory restored from a backup. If no managing device can
ever connect, the way out is re-pairing (`atem unpair`, `atem pair`);
otherwise a manager's next connection ends it. Relaxing held to "only
after a write fault" would trade that coverage for availability; that
would be a user decision (R9.13 q7).

Open questions for Astation are R9.13.

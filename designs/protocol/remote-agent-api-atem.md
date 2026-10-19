# Remote agent API without the Mac: Atem's response

Status: Atem response r2, 2026-10-19 (r2: the user's final trust design replaces attestations, the freshness window and `resolve_fork`), to Astation's "Remote agent API without
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
| 1. Freshness and forks | Signed hash chain (`seq`, `prev_hash`, signed by a manager at `seq-1`); Atem keeps a durable head, refuses rollback and non-chaining entries; every connection carries the suffix from Atem's head, applied (removals fenced at once) before admission; no attestations, heartbeats, window or clock rules; a valid conflicting branch freezes remote access until the host is re-paired (user decision, 2026-10-19) |
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
24 h freshness window and `resolve_fork` entry.

**Threat model.** The relay is fully adversarial (withholds, reorders,
replays, shows different parties different views). Any member key may be
stolen, including keys of devices already removed. Goals: Atem never acts on
an older list than one it accepted; a removal Atem has seen is final and takes
effect at once; a fork, once any evidence reaches Atem, stops remote access.

**Keys.** Each native member has one `auth` key in the log (Secure Enclave
P-256 / platform keystore). A manager's key requires biometrics (Face ID /
Touch ID) on the device; that is key policy on the device, not protocol, and
Atem can't observe it. There is no second "routine" key, no recovery key and
no manager authority expiry.

**Log.** A signed hash chain: entry `seq` names `prev_hash`, the hash of entry
`seq-1`, and is signed by a device whose roles include `manage` at `seq-1`.
Only managers sign entries; any member (or the relay, or Atem's own link) can
carry them, since the signatures decide.

**Head** (`membership.json`, 0600, atomic, `flock`, beside `pairing.json`):
`{account_id, genesis_hash, host_trust_gen, head:{seq, hash}, entries:[…],
fork?:{evidence}}`. `entries` is Atem's copy of the log it applied (small:
≤ 4 KiB per entry, a handful of devices), kept to judge a conflicting branch.
The head moves only forward, one valid chaining entry at a time. A lower `seq`
is refused (rollback); an entry that doesn't chain from the head is never
applied.

**Propagation through normal connections.** Atem's challenge on every
connection carries its head `(seq, hash)` (in `channel_accept`, §5). The
client's `hello` carries `membership:{head, entries}`:

- Its log contains Atem's head: `entries` is its suffix from Atem's head to
  its own head (empty when equal). Atem verifies each entry (chain, signer a
  manager at `seq-1`, `alg` pin, account and genesis), makes the new head and
  entries durable (fsync), applies every effect, and only then admits the
  device against the new head.
- Its log is behind Atem's head and agrees with Atem's copy: no entries; Atem
  admits it on Atem's head. `welcome.head` shows it is behind; it fetches the
  rest from the relay.
- Its log doesn't contain Atem's head: it sends its whole log from genesis.
  An invalid branch (bad signature, signer not a manager at `seq-1` in that
  branch, broken chain) is refused (`membership_invalid`) and changes nothing.
  A valid one is a fork (below).

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

**Fork.** Two valid entries at one `seq`, or a valid suffix that doesn't
chain from Atem's head while signed by managers valid in its own branch,
freezes remote access for the account: the evidence is persisted in `fork`
(fsync first), every remote principal is fenced (`control_revoked` per r8
§H, attachments closed) and every remote `hello` gets
`error{code:"account_frozen"}`. Local use is unaffected. No entry lifts it;
resolution is re-pairing the host (`atem unpair` + `atem pair`: a new genesis
and `host_trust_gen`, `account-trust.md` §3.6). The relay's transactional
append makes honest races practically impossible; forks are expected only
from an attacking relay or a stolen manager key.

**Residual risk.** A revocation reaches a host when any honest device next
connects to it (or Atem fetches it). Until then a stolen *unlocked* manager
can act: add devices, connect, control. If the relay keeps honest devices
away from the host, re-pairing the host is the fallback. A stolen manager
key, even one already removed, can sign a branch from before its removal and
so freeze remote access (denial of service, never admission); re-pairing
resolves that too.

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
["atem-membership-hash-v1", jcs(body), sig]))`, hex. Wire form `{"body":{…},
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

**Channel: suite `atem-ch1` (SIGMA-I shape; one suite, no negotiation).**

1. C→H `channel_init`: `{suite:"atem-ch1", e_c, n_c, host:{atem_device_id,
   host_trust_gen}}` in clear (the relay routes on it).
2. H→C `channel_accept`: `{e_h, n_h, ct}`. `th2 = SHA-256(enc(["atem-ch1-th2",
   jcs(init), e_h, n_h, atem_device_id, host_trust_gen, genesis_hash, head_seq,
   head_hash]))`; `ss = X25519(e, e')`; `hs = HKDF-Extract(th2, ss)`;
   `k_h2c_hs`, `k_c2h_hs` = HKDF-Expand(hs, "atem-ch1 h2c hs"/"… c2h hs", 32).
   `ct` = AEAD under `k_h2c_hs` of `{head:{genesis_hash, head_seq, head_hash},
   sig_h = Sign(host_channel_key, th2)}`. The client checks `sig_h` against
   the log's `add_host` for that `atem_device_id`/`host_trust_gen` before
   sending anything that names itself.
3. C→H, AEAD under `k_c2h_hs`: `hello{…, sig_c = Sign(auth, th3)}` with
   `th3 = SHA-256(enc(["atem-ch1-th3", th2, sig_h, jcs(principal)]))`.
   `head` in step 2 is Atem's challenge head (§3) and is bound by `th2`;
   `hello.membership` carries the suffix from it. Entries carry their own
   signatures, so `sig_c` needn't cover them.
4. `th4 = SHA-256(enc(["atem-ch1-th4", th3, sig_c]))`; `ak = HKDF-Extract(th4,
   ss)`; `k_c2h`, `k_h2c` = HKDF-Expand(ak, "atem-ch1 c2h"/"… h2c", 32); the
   host answers `welcome` (or an error) under `k_h2c`; ephemerals are wiped.

Records: ChaCha20-Poly1305 (`chacha20poly1305`, already the HPKE AEAD here;
CryptoKit and WASM have it, WebCrypto doesn't need to). Nonce = 4 zero bytes ‖
64-bit big-endian counter from 0 per key; AAD = `enc(["atem-ch1-rec",
direction])`; one session-family message per record, ≤ 1 MiB + 16. The
transport is ordered (WSS; SSE keeps the same ordered stream), so the
receiver demands exactly the next counter: any gap, replay or failed tag
closes the channel. No rekey: keys are fresh per channel and the counter can't
wrap in practice; a service or browser channel ends at its expiry, a native
one when either side closes it or the member loses its roles (`membership`
on the open channel carries newer entries, §3). No resumption, no 0-RTT: every
connect is a full handshake, a new attachment, no lease (r8 §3 unchanged;
`resume` stays refused). Cross-channel or cross-replica replay fails on
`n_h` and fresh ephemerals.

**Relay visibility.** Routing (`account`, `atem_device_id`, channel handle),
sizes and timing, ephemerals and nonces; never the client identity (in
`hello`, encrypted), messages, approvals or chat. The log on the relay holds
keys, roles and scopes; device names are sealed with `K` (they stay out of
the signed body). Push hints carry only `approval_id`, `atem_device_id`,
`session_id`, the approval's immutable `created_at` (its original creation,
never a retry or send time), `expires_at` and a host signature, sent at once
on open and on resolution; the relay owns the 60/180 s schedule; the tool and summary go
HPKE-sealed to each `control` member's device key (today they go in clear).

## 6. Decision 4: reusable client core

Atem owns `crates/atem-client` (workspace member, like `atem-core`):

- **Sans-I/O.** Pure state machines: bytes, time and key results in;
  messages, effects and timers out. Transports (URLSession, OkHttp, browser
  WebSocket, tokio) belong to the platform. Signing is an effect (`NeedSign{
  key_ref, alg, input}` answered with the signature), behind a Rust
  `KeyProvider` trait for in-process use: Secure Enclave, Android Keystore,
  WebCrypto non-extractable keys, or a software file for bots.
- **Contents.** Membership verifier (chain, alg pins, suffix application,
  fork evidence), entry/grant/push-hint builders and verifiers, channel
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
| Recovery after losing all managers | **Agree**: new genesis by local unpair/pair per host; account recovery never restores old host authority |
| Tests matrix | **Agree**; add: rollback (lower `seq`) refused, a removed manager's later entry refused, an invalid non-chaining branch refused without freezing, a valid one freezing, a removal carried on an open channel fencing at once, a crash between the head fsync and the fences, a client behind Atem's head admitted on Atem's head, a host whose key agent is locked still serving remote clients |

## 8. Risks and contradictions

1. **Residual revocation delay (accepted).** A removal reaches a host when any
   honest device next connects to it. A stolen *unlocked* manager can act
   until then; if the relay keeps honest devices away, re-pairing the host is
   the fallback (§3).
2. **Freeze by an old key.** A stolen manager key, even after its removal, can
   sign a branch from before the removal and freeze remote access. It never
   gains admission; re-pairing resolves it.
3. **Biometric manager key on every channel.** One `auth` key per device means
   a manager signs each channel handshake with its biometric key. Whether one
   Face ID / Touch ID covers a short reuse window is Astation's key policy;
   Atem only sees signatures.
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
| 1 | Shared signature fixtures first (signing inputs, entry hashes, push hints with `created_at`/`expires_at`), then the r9 contract appendix: log, suffix carriage, fork, principals, scope, channel `atem-ch1`, errors (`account_frozen`, `membership_invalid`), plus fixtures and cross-language vectors (handshake transcripts, records) | Atem drafts, Astation reviews | 1.5–2 weeks |
| 2 | `atem-client`: verifier, channel, machines moved from `session_protocol/client.rs`, fixture runner, UniFFI + wasm bindings, packaging | Atem | 3 weeks |
| 3 | Atem host: ceremony change (`host_channel_key`, genesis pin), `membership.json`, suffix application and fences, channel responder on link/relay/:8080, r9 admission, principals/scope, fences, sealed push hints, harness | Atem | 3 weeks |
| 4 | Relay `/api/remote/v1` (log store, enrollment, channel routing, ordered events) and native Astation (biometric manager key, add device/service, Settings removal, the suffix on every connection), then the Mac-off matrix | Astation | 4–6 weeks (Astation's estimate to confirm) |
| 5 | Mobile and bot clients on `atem-client`, notifications; browser companion after its review | Astation | after 4 |

Steps 2 and 4's relay part can overlap once step 1's vectors are pinned.
Nothing is enabled before both sides pass the r9 fixtures.

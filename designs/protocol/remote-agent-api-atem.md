# Remote agent API without the Mac: Atem's response

Status: Atem response r1, 2026-10-19, to Astation's "Remote agent API without
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
| 1. Freshness and forks | Majority-of-managers checkpoints over Atem's checkpointed high-water head; 24 h window from the oldest counted attestation, on wall and monotonic clocks, whichever ends first; any fork freezes remote access until a quorum-signed `resolve_fork` entry that extends Atem's high-water mark |
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

Absent today: the membership log, attestations, any principal but the paired
Astation, `service`/`browser` admission, a secure channel, r9.

## 3. Decision 1: freshness and forks

**Threat model.** The relay is fully adversarial (withholds, reorders,
replays, shows different parties different views). Any member key may be
stolen, including keys of devices already removed. Clocks jump. Goals: Atem
never acts on an older list than one it accepted; a removal made by honest
managers stops access within 24 h of being made even if the relay hides it;
a fork, once any evidence reaches Atem, stops remote access. Out of scope: a
majority of the managers at Atem's high-water head being compromised (they
are the account's authority). Astation's removed-manager attack is in scope.

**Keys.** Each native member has an `auth` key (no user presence: channel
signatures and heartbeats) and, if a manager, a `manage` key (Touch
ID/password per signature: log entries). Today's Touch-ID-per-signature
Secure Enclave key cannot do 6-hourly heartbeats, so the split is required.

**Attestation** (signed by a manager's `auth` key):

```json
{"type":"atem-head-attestation","account_id":"…","genesis_hash":"…","seq":42,
 "head_hash":"…","issued_at":1792400000000,"signer":"dev-…"}
```

`atem_nonce` is absent (heartbeat, every 6 h by each online manager, stored
on the relay) or Atem's handshake nonce `n_h` (on demand; counts as issued at
Atem's own time of the nonce). Absent fields are omitted, never `null`.

**Checkpoint.** A set of attestations for one head H, each by a distinct
manager listed at Atem's **high-water head** HW, numbering a strict majority
of HW's managers (with one manager — the default, the genesis Mac — that is
one). H must equal or extend HW through the presented suffix. Any two
majorities of HW's managers intersect, so two conflicting heads can each get
a checkpoint only if a manager signs both — attributable equivocation, and a
fork (below). A removed manager alone is never a majority when HW lists two
or more managers: the removed-manager fresh-nonce attack yields no
checkpoint, and access pauses at the deadline. Checkpoints count managers at
HW, never at H, so a fork that rewrites the manager set cannot vouch for
itself. This changes `account-trust.md` §3.5's "any manager" rule only when
there are two or more managers.

**High-water mark** (`membership.json`, 0600, atomic, `flock`, beside
`pairing.json`): `{account_id, genesis_hash, host_trust_gen, hw:{seq, hash},
pending:[entries past hw], abandoned:[hash], fork?:{evidence},
deadline_wall, last_wall_seen}`. HW moves only forward, only by a
checkpoint, and is fsynced before any welcome or effect that depends on it.
A suffix or checkpoint that doesn't extend HW is refused (rollback refusal);
abandoned hashes are refused forever. Valid entries past HW are kept as
`pending`: restrictive ones that touch no manager (`remove`, narrowing
roles/scope of a non-manager, `revoke_grant`) apply at once — failing closed
is safe — while additions, widenings and every manager-set change wait for a
checkpoint.

**Window.** On accepting a checkpoint at Atem wall time W and monotonic M,
let `t_old` be the oldest `issued_at` among the counted attestations (refused
if more than 5 min ahead of W). `deadline_wall = t_old + 24 h`;
`deadline_mono = M + (deadline_wall − W)`; remote authorization ends at
whichever comes first. A newer-head checkpoint replaces the deadline; a
same-head one may only extend it. After a restart (monotonic lost) the
persisted `deadline_wall` is used with a new monotonic deadline from it, and a
wall clock earlier than `last_wall_seen − 5 min` counts as expired. Because
`t_old` is the oldest counted attestation, an honest manager's pre-removal
heartbeat replayed by the relay buys at most 24 h after the removal.

**While the Mac is offline.** A phone or bot fetches the log suffix from
Atem's HW and the latest heartbeats from the relay and presents them in
`hello` (or later in `refresh` on the open channel). Admission lasts until
the deadline; `welcome.authorization_ms_left` says how long. At the deadline
Atem fences every remote attachment (`paused`, §H fence for queued work);
agents and the local terminal keep running. With one manager this is the
approved bound: the Mac must heartbeat within 24 h.

**Fork.** Atem holding two valid entries with the same `seq` or the same
`prev_hash`, or two manager attestations for heads not on one chain, freezes
remote access for the account: the evidence is persisted in `fork`, every
remote principal is fenced (`control_revoked` per r8 §H, attachments closed),
and every remote `hello` gets `error{code:"account_frozen"}`. Local use is
unaffected. It lifts only with a `resolve_fork` entry that chains from
Atem's HW through the chosen branch, names the first entry of each abandoned
branch, and is signed by a majority of HW's managers. A conflict at or below
HW (a checkpointed entry contradicted) means a majority equivocated: no entry
can resolve it; recovery is `atem unpair` + `atem pair` (new genesis, new
`host_trust_gen`). The relay's transactional append makes honest races
practically impossible; forks are expected only from an attacking relay.

**Removal propagation.** A manager appends `remove` (relay CAS is a
convenience, not consensus). Atem learns it from any client's suffix, from
its own poll of `/api/remote/v1/membership` every 5 min over its link, or
from the next checkpoint. Applying it: the principal's `control_gen` is
raised (r8 §H), its attachments, leases, streams and conversations close, its
`accepted`-not-`executing` work is `rejected` `control revoked`, browser
grants it issued are fenced. Bound: immediate once seen; otherwise the next
checkpoint must cover it within 24 h of the removal.

## 4. Decision 2: identities

| Kind | Proof | r8/r9 principal | Permissions |
|---|---|---|---|
| `native` | log `add` with `auth` key (Secure Enclave P-256 / platform keystore), roles from `view`, `control`, `manage` | `member:<device_id>` | `view`, `control` as listed; `manage` gives the host nothing (it only counts toward checkpoints) |
| `service` | log `add` by a manager, role `service`, own key, `scope`, mandatory `expires_at` | `service:<device_id>` | only `scope.ops` on `scope` targets; approvals only if `approval` is in `ops` |
| `browser` | grant signed by a native member with `control`, key proven in the handshake | `browser:<grant_id>`, issuer recorded | subset of the issuer's, on the grant's target |
| `host` | log `add_host` by the pairing manager: `atem_device_id`, `host_trust_gen`, `host_key` | — (never a client) | — |

Service entry (the scope is part of the signed entry; a narrower `set_scope`
or expiry is a revocation and raises `control_gen`; a wider one is a new
grant and waits for a checkpoint):

```json
{"type":"atem-membership-entry","account_id":"…","seq":43,"prev_hash":"…","action":"add",
 "device_id":"svc-discord-1","roles":["service"],"auth_key":{"alg":"ed25519","pub":"…"},
 "scope":{"hosts":["host-a"],"projects":["h1.…"],"sessions":[],"ops":["view","prompt","receipt","interrupt"]},
 "expires_at":1800000000000,"signer":"dev-mac","signed_at":1792400000000}
```

- Service rules: expiry ≤ 90 days (renewal is a new entry); never `manage`,
  never issues grants, never counts toward checkpoints. `projects` are `h1.`
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
- Expiry uses wall and monotonic time, whichever ends first, like the window.

**Wire version: r9.** `hello` travels inside the channel (§5) and carries
the proof: `{revision: 9, principal:{kind, device_id|grant}, sig, membership:
{suffix, checkpoint}, grant?}`. `welcome` adds `principal`, `client_kind`
(`native`/`service`/`browser`), `scope` (service/browser), `features`, and
`authorization_ms_left` = min(window, expiry, grant). r9 keeps r8 operation
semantics and every r8 feature name; `hello.revision ≠ 9` is
`unsupported_version` before any attachment. No compatibility: the r8
"paired Astation over its link" admission is removed; the Mac is the genesis
member and uses the same channel (over its link, the relay or :8080). Its
link stays for pairing, `cred unlock`, credentialSync and key grants.

## 5. Decision 3: signed formats and the channel

**Signed objects** (log entries, attestations, grants, host advertisements):
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
   jcs(init), e_h, n_h, atem_device_id, host_trust_gen, genesis_hash, hw_seq,
   hw_hash]))`; `ss = X25519(e, e')`; `hs = HKDF-Extract(th2, ss)`;
   `k_h2c_hs`, `k_c2h_hs` = HKDF-Expand(hs, "atem-ch1 h2c hs"/"… c2h hs", 32).
   `ct` = AEAD under `k_h2c_hs` of `{head:{genesis_hash, hw_seq, hw_hash},
   sig_h = Sign(host_channel_key, th2)}`. The client checks `sig_h` against
   the log's `add_host` for that `atem_device_id`/`host_trust_gen` before
   sending anything that names itself.
3. C→H, AEAD under `k_c2h_hs`: `hello{…, sig_c = Sign(auth, th3)}` with
   `th3 = SHA-256(enc(["atem-ch1-th3", th2, sig_h, jcs(principal)]))`.
4. `th4 = SHA-256(enc(["atem-ch1-th4", th3, sig_c]))`; `ak = HKDF-Extract(th4,
   ss)`; `k_c2h`, `k_h2c` = HKDF-Expand(ak, "atem-ch1 c2h"/"… h2c", 32); the
   host answers `welcome` (or an error) under `k_h2c`; ephemerals are wiped.

Records: ChaCha20-Poly1305 (`chacha20poly1305`, already the HPKE AEAD here;
CryptoKit and WASM have it, WebCrypto doesn't need to). Nonce = 4 zero bytes ‖
64-bit big-endian counter from 0 per key; AAD = `enc(["atem-ch1-rec",
direction])`; one session-family message per record, ≤ 1 MiB + 16. The
transport is ordered (WSS; SSE keeps the same ordered stream), so the
receiver demands exactly the next counter: any gap, replay or failed tag
closes the channel. No rekey: keys are fresh per channel, the counter can't
wrap in practice, and a channel ends at the authorization deadline (`refresh`
with a new checkpoint extends it in place). No resumption, no 0-RTT: every
connect is a full handshake, a new attachment, no lease (r8 §3 unchanged;
`resume` stays refused). Cross-channel or cross-replica replay fails on
`n_h` and fresh ephemerals.

**Relay visibility.** Routing (`account`, `atem_device_id`, channel handle),
sizes and timing, ephemerals and nonces; never the client identity (in
`hello`, encrypted), messages, approvals or chat. The log on the relay holds
keys, roles and scopes; device names are sealed with `K` (they stay out of
the signed body). Push hints carry only `approval_id`, `atem_device_id`,
`session_id`, `expires_at` and a host signature; the tool and summary go
HPKE-sealed to each `control` member's device key (today they go in clear).

## 6. Decision 4: reusable client core

Atem owns `crates/atem-client` (workspace member, like `atem-core`):

- **Sans-I/O.** Pure state machines: bytes, time and key results in;
  messages, effects and timers out. Transports (URLSession, OkHttp, browser
  WebSocket, tokio) belong to the platform. Signing is an effect (`NeedSign{
  key_ref, alg, input}` answered with the signature), behind a Rust
  `KeyProvider` trait for in-process use: Secure Enclave, Android Keystore,
  WebCrypto non-extractable keys, or a software file for bots.
- **Contents.** Membership verifier (chain, alg pins, checkpoint, fork
  evidence, window arithmetic), entry/attestation/grant builders, channel
  (both roles), r9 client machines moved from `session_protocol/client.rs`
  (lease with 5 s renew/15 s expiry, receipts and `receipt_query` recovery,
  registry `seq`, chat history/coverage ordering, approvals), and the fixture
  runner over `designs/protocol/fixtures/`.
- **Bindings.** UniFFI for Swift and Kotlin (a stateful object API; a
  hand-written C header like `atem-core-ffi` is fine for seven stateless functions,
  not for this), wasm-bindgen for browsers and Node bots, the crate for Rust
  bots. Releases attach the xcframework like `atem-core`.
- **Not in it:** UI, storage policy (state exports as opaque bytes the app
  stores; only the host's high-water mark is authoritative), notifications,
  networking, key storage.
- The Atem host links the same verifier and channel; admission, journal and
  fences stay in `atem`. One implementation of every security-critical
  check, both sides, one set of vectors.

## 7. Atem's position on the rest of the handoff

| Item | Position |
|---|---|
| 5. Pairing pin and admission | **Agree, with changes:** the ceremony also reveals `host_channel_key` and covers `genesis_hash`; the pin is `membership.json` (§3), fsynced before any welcome; machine, runtime, attachment and principal ids stay distinct |
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
| Tests matrix | **Agree**; add: two-manager removal with the removed key attesting, checkpoint counted at HW not H, `pending` restrictive entries applied before a checkpoint, wall clock moved back across a restart, a host whose key agent is locked still serving remote clients |

## 8. Risks and contradictions

1. **Touch ID per signature.** Astation's current signing key needs Touch ID
   for every signature; heartbeats and channel signatures need a second,
   no-user-presence key per device (§3 "Keys"). Otherwise either the phone
   prompts constantly or the 6 h heartbeat can't exist.
2. **Locked key agent.** Using `device_sign` as the host key would make remote
   access depend on the Mac unlocking the key agent after every Atem restart —
   a hidden "Mac required". Hence `host_channel_key` (§5).
3. **Two managers.** Majority checkpoints mean both must heartbeat within
   24 h; one or three managers avoid that. The user should accept this change
   to the "any manager" rule (it fixes the removed-manager attack; with one
   manager nothing changes). The UI should warn when a second manager is added.
4. **Push in clear.** Today `push_approval` gives the relay the tool and
   summary; that is session content the E2EE channel would otherwise hide.
5. **Stale §9 text.** `account-trust.md` §6a and its decision 3 still say
   approvals need the lease and `acquire`; r8 §G supersedes them. Update it
   with r9.
6. **No compatibility** means Atem r9 and Astation r9 ship together; an r8
   Astation loses remote sessions until updated (local use unaffected).
7. **Discord disclosure.** A service that posts output to Discord discloses
   it to Discord; enrollment must show that, and `ops` should default to no
   approvals.
8. **Project scope drift** if evaluated live; fixed by scoping at launch (§4).
9. **Majority compromise** of HW's managers is unrecoverable by signatures;
   documented as out of scope, recovery is re-pairing.

## 9. Order of work and sizing

| # | Work | Owner | Size |
|---|---|---|---|
| 1 | r9 contract appendix: log, checkpoint, fork, principals, scope, channel `atem-ch1`, errors (`account_frozen`), plus fixtures and cross-language vectors (signing inputs, hashes, handshake transcripts, records) | Atem drafts, Astation reviews | 1.5–2 weeks |
| 2 | `atem-client`: verifier, channel, machines moved from `session_protocol/client.rs`, fixture runner, UniFFI + wasm bindings, packaging | Atem | 3 weeks |
| 3 | Atem host: ceremony change (`host_channel_key`, genesis pin), `membership.json`, polling, channel responder on link/relay/:8080, r9 admission, principals/scope, fences, sealed push hints, harness | Atem | 3 weeks |
| 4 | Relay `/api/remote/v1` (log store, enrollment, channel routing, ordered events) and native Astation (two SE keys, add device/service, Settings removal, heartbeats), then the Mac-off matrix | Astation | 4–6 weeks (Astation's estimate to confirm) |
| 5 | Mobile and bot clients on `atem-client`, notifications; browser companion after its review | Astation | after 4 |

Steps 2 and 4's relay part can overlap once step 1's vectors are pinned.
Nothing is enabled before both sides pass the r9 fixtures.

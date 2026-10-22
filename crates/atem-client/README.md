# atem-client

The shared client core of atem-session r9, owned by Atem and linked by both
sides: Astation's apps (through the bindings in
[`../atem-client-ffi`](../atem-client-ffi/README.md)), bots, and the Atem
host itself. The contract is the r9 appendix of
[`designs/protocol/atem-session-v1.md`](../../designs/protocol/atem-session-v1.md);
the shared known-answer vectors are `designs/protocol/fixtures/r9-vectors-*.json`
([`schema.md`](../../designs/protocol/fixtures/schema.md) "r9 fixtures").

## Scope

Sans-I/O: no networking, no filesystem and no clocks (tests read the fixture
files). Secret keys stay behind the `KeyProvider` trait. Crypto comes only
from the workspace's reviewed dependencies (`p256`, `ed25519-dalek`,
`x25519-dalek`, `hkdf`, `hmac`, `sha2`, `hpke`); comparisons of hashes and tags
are constant-time and secrets are wiped on drop.

Status: r9 is implemented (plan `designs/plans/2026-10-20-r9.md`, Tasks
1–9): encodings and signatures (§R9.1–§R9.2), the membership-log verifier
and its writers (§R9.2–§R9.5), the `atem-ch1` channel in both roles
(§R9.7), the r9 client machines with r8's session-v1 inside, principals,
push hints and `seen` (§R9.6–§R9.9), the Recovery Kit, K backups and the
restore (§R9.5). Every `r9-vectors-*` value is reproduced; the client and
relay sides of the r9 scenarios run here, the host side against the real
Atem runtime (`tests/r9_runner/` in the workspace root).

## API

| module | what |
|---|---|
| `encoding` | `enc` (4-byte big-endian length + bytes, label first; the same as atem's `src/memory/encoding.rs`), `u64_field`, strict `b64u` (no padding, no non-zero trailing bits), lowercase hex, `Hash32` (SHA-256 with constant-time `==`) |
| `canonical` | `parse_strict` (no duplicate keys, safe integers, no lone surrogates) and RFC 8785 `jcs`; atem's `session_protocol::canonical` re-exports it |
| `domain` | every domain string of §R9.1; `SignLabel` and `SigningInput` (`enc([label, payload])`, only constructible with a label) |
| `keys` | `Alg` (`p256`, `ed25519`, `x25519`), `PublicKey` (validated, its `alg` pinned), `verify` (P-256 low S only; Ed25519 `verify_strict`; X25519 never), `ed25519_public_to_x25519`, `enc_kid` |
| `signed` | `SignedObject`: parse (`{"body","sig"}` plus `kit_sig` for `set_recovery_key` with `kit: "current"`, `enc`/`ct` for push hints), `sign`, `cosign`, `verify(pinned key)`, `verify_kit_sig`, `entry_hash`, `grant_hash`; set and sequence rules (`array_not_canonical`); body `jcs` ≤ 4096 bytes; no `null` |
| `hpke` | RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305: `seal`, `seal_with_ikm` (ephemeral `DeriveKeyPair(ikmE)`, for vectors), `open_with_secret`, `Sealed::hash` (`sealed_hash`) |
| `kit` | Recovery Kit v2: `sign_seed`, `recovery_key`, the kit's X25519 key, `tag_key`, `kit_tag`; `RecoveryKit::read` (tag check: `kit_damaged`) and `check_genesis` (`genesis_mismatch`) |
| `backup` | `KBackupEnvelope` (`atem-k-backup-v2`): `seal`, `parse`, `info`, `jcs`, `backup_hash`, `open` (through a `KeyProvider`) and `open_with_kit` |
| `provider` | `KeyProvider` (sign, X25519, HPKE open) and `sign`, which normalizes P-256 to low S and checks the result; `SoftwareKeys` with the `software-keys` feature (tests and bots only) |
| `membership` | typed entries and schemas, `Membership` (chain verification, signer authority, carriage evaluation, the conflict rule and freeze, recovery waits on the verifier's clock, the membership side of admission), `draft` (bodies on a verified head), `publish` (`EntryPublisher`, §R9.4 client rules 1–5), `stored` (a host's durable log) |
| `backup_writer` | `KBackupWriter`: version allocation, seal, put-if-absent upload, `k_backup` publication and their `409` paths; resumable |
| `restore` | the Recovery Kit restore over the fetched log, envelope and host-signed heads (`RestoreFlow`; no recovery on a stale head) |
| `channel` | `atem-ch1` (SIGMA-I): initiator and responder, transcript, key schedule, records, counters, limits, carriage inside the handshake |
| `session` | r8's session-v1 wire and client machines (re-exported by atem), `revision`, and r9's `hello`/`welcome`/errors/new ops (`r9`) |
| `connect` | a client's connection: handshake, carriage, the checked welcome, then r8's lease, registry and chat machines inside the channel |
| `principal` | native, service and browser principals: scope, ops, expiry, browser grants |
| `push` | sealed push hints, `seen`, acks, the relay's schedule from the signed `created_at`, a reference `RelayLedger`, the host's per-approval state and `Outbox` |
| `ceremony` | `verifyCommit.host_trust_gen`, read the same way on both sides |

The verifier always supplies the key: `SignedObject::verify` takes the
`PublicKey` pinned for the signer the body names, never a key or `alg` from
the object. Errors are one `Error` enum whose `code()` is the stable name
(`array_not_canonical`, `kit_sig_missing`, `backup_invalid`, …).

```rust,ignore
use atem_client::{KeyId, SignedObject, SoftwareKeys, Alg, PublicKey};

let mut keys = SoftwareKeys::new();
keys.generate(KeyId::new("auth"), Alg::P256)?;
let entry = SignedObject::sign(&keys, &KeyId::new("auth"), body)?;   // a phone
let wire = serde_json::to_vec(&entry.to_json())?;

let received = SignedObject::parse(&wire)?;                           // the host
received.verify(&pinned_signer_key)?;
let hash = received.entry_hash().unwrap().to_hex();
```

## Tests

```bash
cargo test -p atem-client
```

- `tests/vectors.rs` runs every `r9-vectors-*` file: every value is
  reproduced (none pending); a top-level field neither checked nor listed
  fails the run. `-- --nocapture` prints the per-file counts.
- `tests/channel_fixtures.rs`, `tests/scenarios.rs`, `tests/r9_fixtures.rs`:
  the r9 handshake, membership/recovery and push/seen/principal/multi-device
  scenarios (client and relay sides; the host side against `support/host.rs`,
  the full host side in Atem's `tests/r9_runner/`).
- `tests/channel_e2e.rs`, `tests/client_e2e.rs`, `tests/membership_e2e.rs`,
  `tests/deferred_signing.rs`: phones, bots and browsers over real loopback
  sockets through the public API.
- `tests/misuse.rs`: round trips through `KeyProvider`; wrong labels, swapped
  algorithms, high S, unsorted or duplicate sets and reordered sequences are
  refused.
- `tests/canonical_properties.rs`: generated inputs; canonical bytes are a
  fixed point, every spelling of a value has one canonical form, binary
  fields have one encoding, `enc` is injective.
- `tests/end_to_end.rs`: a phone signs, a host verifies; a manager seals K to
  the kit, a restorer opens it; the host signs a `seen`, the phone verifies it.

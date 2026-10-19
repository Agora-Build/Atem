# atem-client

The shared client core of atem-session r9, owned by Atem and linked by both
sides: Astation's apps (through bindings, a later task), bots, and the Atem
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

Built so far (plan Task 1): §R9.1–§R9.2 encodings and signatures, and the
pure Recovery Kit and K-backup formats of §R9.5. Later tasks add the
membership-log verifier (Task 2), the `atem-ch1` channel (Task 3), r9 client
machines with push hints and `seen` (Task 4) and the Swift/Kotlin/WASM
bindings (Task 5).

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

- `tests/vectors.rs` runs every `r9-vectors-*` file. It checks each value this
  task can reproduce and lists the rest as pending with the task that brings
  it; a top-level field neither checked nor listed fails the run. Run with
  `-- --nocapture` for the per-file counts and the pending list.
- `tests/misuse.rs`: round trips through `KeyProvider`; wrong labels, swapped
  algorithms, high S, unsorted or duplicate sets and reordered sequences are
  refused.
- `tests/canonical_properties.rs`: generated inputs; canonical bytes are a
  fixed point, every spelling of a value has one canonical form, binary
  fields have one encoding, `enc` is injective.
- `tests/end_to_end.rs`: a phone signs, a host verifies; a manager seals K to
  the kit, a restorer opens it; the host signs a `seen`, the phone verifies it.

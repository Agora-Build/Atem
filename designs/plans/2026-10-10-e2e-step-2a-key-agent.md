# E2E build step 2a: sealed device keys, the key agent, Touch ID unlock — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The device keys from step 1 stop living in a plain file: they are sealed under a storage key that only the home Astation holds, opened inside a same-user key agent after a Touch ID approval on the Mac, and the storage key is replaced at every unlock; `atem cred unlock|lock|status` drive it.

**Architecture:** New focused modules under `src/memory/`: `storage_key` (the storage key and the `device_keys.sealed` file), `key_agent` (the agent's state machine: status, load, unlock, rotation, grants — pure, no sockets, testable in process), `agent_socket` (the Unix-socket server behind the hidden `atem key-agent` subcommand, and the client every command uses) and `unlock` (the CLI side: carries agent requests to Astation over the existing WebSocket, `atem cred`). `statements.rs` gains the five unlock/rotation statements, `trust.rs` the home Astation, `verification.rs` seals keys at the first verification instead of writing them plain and opens grants through the agent. The agent never talks to the network; the storage key never passes through the CLI in plain form.

**Tech Stack:** Rust 2024 edition crate `atem`; `p256` 0.13 (ECDSA verify), `ed25519-dalek` 2, `hpke` 0.12 (RFC 9180, `alloc` + `x25519`), `x25519-dalek` 2, `chacha20poly1305` 0.10 (XChaCha20-Poly1305), new `zeroize` 1, `rand` 0.8 `OsRng`, `tokio` (UnixListener, `peer_cred`), `libc` (`setsid`, `prctl`, `mlockall`, `getuid`), `serde_json`, `tempfile` (tests).

**Spec:** `designs/e2e-encryption.md` — sections "Keys", "Signed statements", "Devices" (Verification, Sealing a key to a device, Keys on disk (atem), Unlock policy), "What each side stores", "Formats", "Wire messages (build steps 0–1)", "Astation work for steps 0–1", "Test vectors". Step 2a scope and decisions were settled with the user on 2026-10-10 and are copied into Global Constraints.

## Global Constraints

- **Scope (step 2a):** sealed device keys, the key agent, Touch ID unlock through Astation, storage-key rotation at every unlock, `atem cred unlock|lock|status`, grants opened inside the agent, migration of the plain `device_keys` file, docs and the Astation/relay handoff. **Out of scope:** moving `K` / `data_keys.enc` behind the agent (step 2b; until then the agent hands `K` back to the caller), auto-unlock checks and tickets (step 7; the request's `ticket` field is sent empty), `atem cred get/list` (step 5), device-signed memory writes (step 3).
- **Key agent process:** the same binary, hidden subcommand `atem key-agent` (`#[command(hide = true)]`), started on demand by the first command that needs keys: `std::env::current_exe()` with arg `key-agent`, detached with `pre_exec(libc::setsid)`, stdin null, stdout/stderr appended to `~/.config/atem/key-agent.log`.
- **Socket:** `$XDG_RUNTIME_DIR/atem/agent.sock` when `XDG_RUNTIME_DIR` is set and non-empty, else `~/.config/atem/agent.sock`; never `/tmp`. Socket directory 0700, socket 0600. The server refuses any peer whose UID (`tokio::net::UnixStream::peer_cred()`) isn't its own.
- **Hardening:** on Linux the agent sets `PR_SET_DUMPABLE=0` and best-effort `mlockall(MCL_CURRENT | MCL_FUTURE)` (logged when skipped or failing). Secrets live in `zeroize::Zeroizing` buffers or in `x25519-dalek`/`ed25519-dalek` types with their `zeroize` feature.
- **Protocol:** newline-delimited JSON; every request carries `"v": 1`; the agent answers any other version with an error so an old running agent and a newer CLI fail clearly. The agent stays unlocked until it exits or receives `lock`.
- **Unlock statements:** `atem-unlock-request-v1` = `enc(label, account, device_id, boot_id, ticket, e_pub, nonce, time(u64), storage_kid)`, signed by the unlock-auth Ed25519 key; `atem-unlock-grant-v1` = `enc(label, account, sign_gen(u64), device_id, storage_kid, SHA-256(request statement bytes), sealed_hash(encapped, ciphertext))`, signed by Astation (P-256, low-S `r ‖ s`). The storage key is HPKE-sealed (same suite as K grants) to `e_pub` with `info = enc("atem-unlock-info-v1", account, device_id, storage_kid, SHA-256(request statement bytes))`, empty AAD. `boot_id` is `/proc/sys/kernel/random/boot_id` (trimmed), `""` if unavailable; `time` is Unix seconds.
- **Rotation statements:** `atem-storage-rotate-v1` = `enc(label, account, device_id, old_storage_kid ("" at first sealing), new_storage_kid, sealed_hash)` signed by the device signing key (Ed25519), carrying the new storage key HPKE-sealed to the pinned `astation_enc_pub` with `info = enc("atem-storage-key-info-v1", account, device_id, new_storage_kid)`; `atem-storage-ack-v1` = `enc(label, account, sign_gen(u64), device_id, new_storage_kid)` signed by Astation; `atem-storage-confirm-v1` = `enc(label, account, device_id, new_storage_kid)` signed by the device signing key.
- **Sealed file:** `device_keys.sealed` is JSON `{version: 1, device_id, storage_kid, nonce, ciphertext}`; XChaCha20-Poly1305 under the 32-byte storage key; AAD `enc("atem-device-keys-v1", device_id, storage_kid)`; plaintext = the device key and device signing key only. `storage_kid` is 8 lowercase hex characters (`valid_kid`). The unlock-auth key moves to its own plain 0600 file `unlock_auth_key`.
- **Rotation phases:** P1 the agent writes `device_keys.sealed.next` (via `write_private`) and returns `storageKeyRotate`; P2 Astation stores the key as pending and replies `storageKeyAck`; P3 the agent verifies the ack, renames `.next` over `device_keys.sealed`, returns `storageKeyConfirm`, which the CLI sends. Unlock opens whichever of `device_keys.sealed` / `.next` carries the `storage_kid` Astation released.
- **Home Astation:** one storage key per device, escrowed to its first verified Astation, recorded as `home_astation` in `cred_state.json`. Unlock and rotation go through the home Astation; grants from any verified Astation are opened by the unlocked agent.
- **No plain-key fallback once sealed:** grants while locked are ignored with a clear "locked; run `atem cred unlock`" status; `keyRequest` uses the pinned `device_pub` from the trust entry.
- **CLI:** `atem cred status|unlock|lock`, tier 2, gated with `crate::auth::require_pairing`. `unlock` waits up to 300 s and prints `Approve on your Mac with Touch ID…`.
- **Wire messages** (`{"type": …, "data": {…}}`, snake_case fields, binary values base64): `unlockRequest {request, signature}`, `unlockGrant {grant: SignedWire, encapped_key, ciphertext}`, `unlockDenied {reason}`, `storageKeyRotate {rotate: SignedWire, encapped_key, ciphertext}`, `storageKeyAck {ack: SignedWire}`, `storageKeyConfirm {confirm: SignedWire}`.
- **Crates:** `p256 0.13`, `ed25519-dalek 2`, `hpke 0.12` (`alloc`, `x25519`) — **not** 0.13; `rand 0.8` `OsRng`. Add `zeroize = "1"`.
- **Formatting:** run `rustfmt --edition 2024` only on new files and on files whose only `mod` is `mod tests` (each task names them). Never run project-wide `cargo fmt`. Never rustfmt `src/cli.rs`, `src/websocket_client.rs`, `src/memory/crypto.rs`, `src/memory/mod.rs`, or `src/memory/verification.rs` (it has `mod ceremony_tests`); format edits there by hand to match the surrounding code.
- **Tests:** `cargo test -- --test-threads=1` (the `agent_visualize` tests flake in parallel, pre-existing). `./scripts/run-local-dev-tests.sh` has 3 pre-existing `atem list` failures; anything else failing is new.
- **Platforms:** Unix-only code behind `#[cfg(unix)]`, Linux-only calls (`prctl`, `mlockall`) behind `#[cfg(target_os = "linux")]`. The crate must still build on macOS (darwin binaries are released); local cross-checks don't work because `build.rs` compiles C++, so rely on the cfg gates and CI.
- **Secrets:** no key, storage key or `K` is ever printed or logged.
- **Commits** end with the line `🤖 Built with SMT <smt@agora.build>`.

## File Structure

| File | Responsibility |
|---|---|
| `Cargo.toml` (modify) | add `zeroize`; explicit `zeroize` features on the dalek crates |
| `src/memory/storage_key.rs` (new) | `StorageKey`, `new_storage_key`, `new_storage_kid`, `device_keys_aad`, `SealedDeviceKeys` (the sealed file), `promote_next`, wire structs `UnlockGrantWire`, `StorageRotation` |
| `src/memory/device_keys.rs` (modify) | `UnlockAuthKey` (own file), sealed plaintext of the two sealed keys, Ed25519 statement signing, `PublicKeys` trait + `DevicePublics` |
| `src/memory/trust.rs` (modify) | `home_astation` in `cred_state.json`; `set_pending` takes any `PublicKeys` |
| `src/memory/encoding.rs` (modify) | `u64_field` becomes production code (atem now encodes a number field) |
| `src/memory/statements.rs` (modify) | `UnlockRequest`, `UnlockGrant`, `StorageRotate`, `StorageAck`, `StorageConfirm`, info helpers; test-only `verify_device`; `FakeAstation` gains an X25519 encryption key |
| `src/memory/grant.rs` (modify) | `hpke_seal` / `hpke_open` helpers (same suite) |
| `src/memory/fake_astation.rs` (new, test-only) | `FakeKeyServer`: Astation's side of unlock and rotation; `pin`, `sealed_device` fixtures |
| `src/memory/key_agent.rs` (new) | `Request`/`Reply`, `KeyAgent` state machine, `KeyAgentApi` trait (+ in-process impl), `build_unlock_request`, `default_agent`, `running_agent` |
| `src/memory/agent_socket.rs` (new, unix) | socket path, `bind`, `serve` (peer UID), `run_key_agent`, `KeyAgentClient` (autostart), versioned framing |
| `src/memory/verification.rs` (modify) | `KeyPaths` key files; `VerificationKeys`; first verification seals keys and loads the agent; `apply_grant` / `device_keys_for_verification` through the agent |
| `src/memory/unlock.rs` (new) | `AstationLink`, `unlock_via`, `rotate_via`, `escrow_if_needed`, `atem cred` handlers and `status_report` |
| `src/memory/mod.rs` (modify) | register modules |
| `src/websocket_client.rs` (modify) | six message variants; `handle_encryption_message` through the agent; `connected_astation_id()` |
| `src/cli.rs` (modify) | hidden `KeyAgent`, `Cred`/`CredCommands`, verification uses the agent and escrows the storage key |
| `src/memory/kat_tests.rs` (modify) | known-answer vectors for the new encodings, signatures and AAD |
| `designs/e2e-encryption.md`, `AGENTS.md` (modify) | status, statements, formats, wire messages, Astation handoff, vectors, modules, files |

---

### Task 1: The sealed device-keys file and the unlock-auth key file

**Files:**
- Modify: `Cargo.toml`, `src/memory/mod.rs`, `src/memory/device_keys.rs`
- Create: `src/memory/storage_key.rs`

**Interfaces:**
- Consumes: `crate::memory::crypto::{write_private, valid_kid}`, `crate::memory::encoding::enc`, `crate::memory::statements::SignedWire`.
- Produces:
  - `device_keys.rs`: `pub struct UnlockAuthKey` with `pub fn public(&self) -> [u8; 32]`, `pub fn sign_statement(&self, statement: &[u8]) -> SignedWire`, `pub fn load_from(path: &Path) -> Result<Option<Self>>`, `pub fn save_to(&self, path: &Path) -> Result<()>`; on `DeviceKeys`: `pub(crate) fn from_secrets(device: [u8; 32], device_sign: [u8; 32], unlock_auth: [u8; 32]) -> Self` (no longer test-only), `pub fn unlock_auth_key(&self) -> UnlockAuthKey`, `pub fn sign_statement(&self, statement: &[u8]) -> SignedWire` (device signing key), `pub(crate) fn secret_parts(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)`, `pub fn sealed_plaintext(&self) -> Result<Zeroizing<Vec<u8>>>`, `pub fn from_sealed_plaintext(plain: &[u8], unlock_auth: UnlockAuthKey) -> Result<Self>`.
  - `storage_key.rs`: `pub type StorageKey = zeroize::Zeroizing<[u8; 32]>`, `pub fn new_storage_key() -> StorageKey`, `pub fn new_storage_kid() -> String`, `pub fn device_keys_aad(device_id: &str, storage_kid: &str) -> Vec<u8>`, `pub struct SealedDeviceKeys { pub version: u8, pub device_id: String, pub storage_kid: String, pub nonce: String, pub ciphertext: String }` with `seal(keys: &DeviceKeys, device_id: &str, storage_kid: &str, storage_key: &[u8; 32]) -> Result<Self>`, `open(&self, storage_key: &[u8; 32], unlock_auth: UnlockAuthKey) -> Result<DeviceKeys>`, `load_from(path: &Path) -> Result<Option<Self>>`, `save_to(&self, path: &Path) -> Result<()>`; `pub fn promote_next(next: &Path, sealed: &Path) -> Result<()>`; `pub struct UnlockGrantWire { pub grant: SignedWire, pub encapped_key: String, pub ciphertext: String }`; `pub struct StorageRotation { pub rotate: SignedWire, pub encapped_key: String, pub ciphertext: String }`.

- [ ] **Step 1: Add the crate and the explicit features**

```bash
cargo add zeroize@1
cargo add x25519-dalek@2 --features static_secrets,zeroize
cargo add ed25519-dalek@2 --features rand_core,zeroize
cargo build
```
Expected: builds. `Cargo.toml` now has `zeroize = "1"`, `x25519-dalek = { version = "2", features = ["static_secrets", "zeroize"] }`, `ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }`; `hpke` is still `0.12`.

- [ ] **Step 2: Register the module** — in `src/memory/mod.rs`, after `pub mod grant;` add:

```rust
pub mod storage_key;
```

- [ ] **Step 3: Write the failing device-key tests** — append inside `mod tests` of `src/memory/device_keys.rs`:

```rust
    #[test]
    fn sealed_plaintext_holds_only_the_two_sealed_keys() {
        let keys = DeviceKeys::generate();
        let plain = keys.sealed_plaintext().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        let mut fields: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        fields.sort();
        assert_eq!(fields, ["device", "device_sign", "version"]);
        let back = DeviceKeys::from_sealed_plaintext(&plain, keys.unlock_auth_key()).unwrap();
        assert_eq!(back.device_pub(), keys.device_pub());
        assert_eq!(back.device_sign_pub(), keys.device_sign_pub());
        assert_eq!(back.unlock_auth_pub(), keys.unlock_auth_pub());
        assert!(DeviceKeys::from_sealed_plaintext(b"{}", keys.unlock_auth_key()).is_err());
    }

    #[test]
    fn unlock_auth_key_round_trips_as_its_own_0600_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unlock_auth_key");
        assert!(UnlockAuthKey::load_from(&path).unwrap().is_none());
        let keys = DeviceKeys::generate();
        keys.unlock_auth_key().save_to(&path).unwrap();
        let loaded = UnlockAuthKey::load_from(&path).unwrap().unwrap();
        assert_eq!(loaded.public(), keys.unlock_auth_pub());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn statements_are_signed_with_the_right_key() {
        use ed25519_dalek::{Signature, VerifyingKey};
        let keys = DeviceKeys::generate();
        let check = |public: [u8; 32], signed: &SignedWire| {
            let raw: [u8; 64] = STANDARD
                .decode(&signed.signature)
                .unwrap()
                .try_into()
                .unwrap();
            VerifyingKey::from_bytes(&public)
                .unwrap()
                .verify_strict(b"statement", &Signature::from_bytes(&raw))
                .is_ok()
        };
        let by_device = keys.sign_statement(b"statement");
        assert_eq!(STANDARD.decode(&by_device.statement).unwrap(), b"statement");
        assert!(check(keys.device_sign_pub(), &by_device));
        assert!(!check(keys.unlock_auth_pub(), &by_device));
        let by_unlock_auth = keys.unlock_auth_key().sign_statement(b"statement");
        assert!(check(keys.unlock_auth_pub(), &by_unlock_auth));
    }
```

- [ ] **Step 4: Write the failing sealed-file tests** — create `src/memory/storage_key.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::crypto::valid_kid;

    fn sealed(keys: &DeviceKeys, key: &[u8; 32]) -> SealedDeviceKeys {
        SealedDeviceKeys::seal(keys, "dev-1", "0a1b2c3d", key).unwrap()
    }

    #[test]
    fn sealed_keys_open_with_the_storage_key_only() {
        let keys = DeviceKeys::generate();
        let storage_key = new_storage_key();
        let file = sealed(&keys, &storage_key);
        assert_eq!(
            (file.version, file.device_id.as_str(), file.storage_kid.as_str()),
            (1, "dev-1", "0a1b2c3d")
        );
        let opened = file.open(&storage_key, keys.unlock_auth_key()).unwrap();
        assert_eq!(opened.device_pub(), keys.device_pub());
        assert_eq!(opened.device_sign_pub(), keys.device_sign_pub());
        assert_eq!(opened.unlock_auth_pub(), keys.unlock_auth_pub());
        assert!(file.open(&new_storage_key(), keys.unlock_auth_key()).is_err());
    }

    #[test]
    fn header_and_ciphertext_are_bound() {
        let keys = DeviceKeys::generate();
        let storage_key = new_storage_key();
        let file = sealed(&keys, &storage_key);
        let mut other_kid = file.clone();
        other_kid.storage_kid = "4e5f6a7b".into();
        assert!(other_kid.open(&storage_key, keys.unlock_auth_key()).is_err());
        let mut other_device = file.clone();
        other_device.device_id = "dev-2".into();
        assert!(other_device.open(&storage_key, keys.unlock_auth_key()).is_err());
        let mut tampered = file.clone();
        let mut bytes = STANDARD.decode(&tampered.ciphertext).unwrap();
        bytes[0] ^= 1;
        tampered.ciphertext = STANDARD.encode(bytes);
        assert!(tampered.open(&storage_key, keys.unlock_auth_key()).is_err());
    }

    #[test]
    fn file_round_trips_0600_and_promotes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_keys.sealed");
        let next = dir.path().join("device_keys.sealed.next");
        assert!(SealedDeviceKeys::load_from(&path).unwrap().is_none());
        let file = sealed(&DeviceKeys::generate(), &new_storage_key());
        file.save_to(&next).unwrap();
        promote_next(&next, &path).unwrap();
        assert!(!next.exists());
        assert_eq!(SealedDeviceKeys::load_from(&path).unwrap().unwrap(), file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn storage_kids_and_keys_are_fresh() {
        let (first, second) = (new_storage_kid(), new_storage_kid());
        assert!(valid_kid(&first) && valid_kid(&second));
        assert_ne!(first, second);
        assert_ne!(*new_storage_key(), *new_storage_key());
        let bad = SealedDeviceKeys::seal(&DeviceKeys::generate(), "dev-1", "XYZ", &new_storage_key());
        assert!(bad.is_err());
    }

    #[test]
    fn aad_binds_label_device_and_kid() {
        assert_eq!(
            device_keys_aad("dev-1", "0a1b2c3d"),
            crate::memory::encoding::enc(&[b"atem-device-keys-v1", b"dev-1", b"0a1b2c3d"])
        );
    }
}
```

- [ ] **Step 5: Run them to see them fail**

Run: `cargo test memory::storage_key memory::device_keys -- --test-threads=1`
Expected: compile errors (`SealedDeviceKeys`, `UnlockAuthKey`, `sealed_plaintext`, … not found).

- [ ] **Step 6: Implement the device-key additions** — in `src/memory/device_keys.rs`:

Replace the module doc comment (first four lines) with:

```rust
//! The device's own keys, created fresh at verification: X25519 to open keys
//! sealed to this device, Ed25519 to sign its writes, Ed25519 to sign unlock
//! requests. The first two are sealed in `device_keys.sealed` (see
//! storage_key.rs); the unlock-auth key sits in its own 0600 file because it
//! must work while the others are locked.
```

Add to the `use` lines:

```rust
use zeroize::Zeroizing;

use crate::memory::statements::SignedWire;
```

Change `from_secrets` from test-only to crate-visible (remove its `#[cfg(test)]` and replace its doc comment):

```rust
    /// Keys from raw secrets: known-answer tests, and the key agent taking
    /// keys handed over at verification.
    pub(crate) fn from_secrets(
```

Add these methods inside `impl DeviceKeys` (after `device_secret_bytes`):

```rust
    pub fn unlock_auth_key(&self) -> UnlockAuthKey {
        UnlockAuthKey {
            key: self.unlock_auth.clone(),
        }
    }

    /// Signs `statement` with the device signing key.
    pub fn sign_statement(&self, statement: &[u8]) -> SignedWire {
        signed_wire(&self.device_sign, statement)
    }

    /// The three secrets, for handing unlocked keys to the key agent.
    pub(crate) fn secret_parts(
        &self,
    ) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        (
            Zeroizing::new(self.device.to_bytes()),
            Zeroizing::new(self.device_sign.to_bytes()),
            Zeroizing::new(self.unlock_auth.to_bytes()),
        )
    }

    /// The device key and device signing key, serialized for
    /// `device_keys.sealed`. The unlock-auth key is not included.
    pub fn sealed_plaintext(&self) -> Result<Zeroizing<Vec<u8>>> {
        let device = Zeroizing::new(STANDARD.encode(self.device.to_bytes()));
        let device_sign = Zeroizing::new(STANDARD.encode(self.device_sign.to_bytes()));
        Ok(Zeroizing::new(serde_json::to_vec(&SealedPlainRef {
            version: 1,
            device: &device,
            device_sign: &device_sign,
        })?))
    }

    pub fn from_sealed_plaintext(plain: &[u8], unlock_auth: UnlockAuthKey) -> Result<Self> {
        let SealedPlain {
            version,
            device,
            device_sign,
        } = serde_json::from_slice(plain).context("sealed device keys are unreadable")?;
        let (device, device_sign) = (Zeroizing::new(device), Zeroizing::new(device_sign));
        if version != 1 {
            bail!("unsupported sealed device keys version {version}");
        }
        Ok(Self {
            device: StaticSecret::from(decode32(&device, "device key")?),
            device_sign: SigningKey::from_bytes(&decode32(&device_sign, "device signing key")?),
            unlock_auth: unlock_auth.key,
        })
    }
```

Add these items after `impl DeviceKeys` (before `#[cfg(test)] mod tests`):

```rust
#[derive(Serialize)]
struct SealedPlainRef<'a> {
    version: u8,
    device: &'a str,
    device_sign: &'a str,
}

#[derive(Deserialize)]
struct SealedPlain {
    version: u8,
    device: String,
    device_sign: String,
}

/// Signs `statement` with an Ed25519 key; carried like Astation's statements.
fn signed_wire(key: &SigningKey, statement: &[u8]) -> SignedWire {
    use ed25519_dalek::Signer;
    SignedWire {
        statement: STANDARD.encode(statement),
        signature: STANDARD.encode(key.sign(statement).to_bytes()),
    }
}

/// Signs unlock requests while the other two keys are sealed. Unsealed on
/// disk (0600): it can only ask Astation for an unlock; Astation decides.
pub struct UnlockAuthKey {
    key: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct StoredUnlockAuth {
    version: u8,
    unlock_auth: String,
}

impl UnlockAuthKey {
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign_statement(&self, statement: &[u8]) -> SignedWire {
        signed_wire(&self.key, statement)
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => Zeroizing::new(raw),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stored: StoredUnlockAuth =
            serde_json::from_slice(&raw).context("unlock_auth_key is unreadable")?;
        let encoded = Zeroizing::new(stored.unlock_auth);
        if stored.version != 1 {
            bail!("unsupported unlock_auth_key version {}", stored.version);
        }
        let secret = Zeroizing::new(decode32(&encoded, "unlock-auth key")?);
        Ok(Some(Self {
            key: SigningKey::from_bytes(&secret),
        }))
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let stored = StoredUnlockAuth {
            version: 1,
            unlock_auth: STANDARD.encode(self.key.to_bytes()),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&stored)?);
        let _wipe = Zeroizing::new(stored.unlock_auth);
        crate::memory::crypto::write_private(path, &bytes)
    }
}
```

(`DeviceKeys::save_to`/`load_from` for the plain step-1 format stay as they are; Task 8 makes `save_to` test-only.)

- [ ] **Step 7: Implement the sealed file** — put this above the test module in `src/memory/storage_key.rs`:

```rust
//! The storage key and the sealed device-keys file. The storage key's only
//! job is to protect `device_keys.sealed`; Astation holds it, the key agent
//! holds it while unlocked, and it is replaced at every unlock.
//! See designs/e2e-encryption.md "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

use crate::memory::device_keys::{DeviceKeys, UnlockAuthKey};
use crate::memory::encoding::enc;
use crate::memory::statements::SignedWire;

pub type StorageKey = Zeroizing<[u8; 32]>;

pub fn new_storage_key() -> StorageKey {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// 8 lowercase hex characters, like a `kid`.
pub fn new_storage_kid() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Associated data of the sealed file: which device and which storage key.
pub fn device_keys_aad(device_id: &str, storage_kid: &str) -> Vec<u8> {
    enc(&[
        b"atem-device-keys-v1",
        device_id.as_bytes(),
        storage_kid.as_bytes(),
    ])
}

/// `device_keys.sealed` (and `.next` during a rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDeviceKeys {
    pub version: u8,
    pub device_id: String,
    pub storage_kid: String,
    /// Base64 24-byte XChaCha20 nonce.
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedDeviceKeys {
    pub fn seal(
        keys: &DeviceKeys,
        device_id: &str,
        storage_kid: &str,
        storage_key: &[u8; 32],
    ) -> Result<Self> {
        if !crate::memory::crypto::valid_kid(storage_kid) {
            bail!("storage key id must be 8 lowercase hex characters");
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(storage_key));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let plain = keys.sealed_plaintext()?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: &device_keys_aad(device_id, storage_kid),
                },
            )
            .map_err(|_| anyhow!("could not seal the device keys"))?;
        Ok(Self {
            version: 1,
            device_id: device_id.into(),
            storage_kid: storage_kid.into(),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    pub fn open(&self, storage_key: &[u8; 32], unlock_auth: UnlockAuthKey) -> Result<DeviceKeys> {
        if self.version != 1 {
            bail!("unsupported device_keys.sealed version {}", self.version);
        }
        let nonce = STANDARD
            .decode(&self.nonce)
            .context("device_keys.sealed nonce is not base64")?;
        if nonce.len() != 24 {
            bail!("device_keys.sealed nonce has the wrong length");
        }
        let ciphertext = STANDARD
            .decode(&self.ciphertext)
            .context("device_keys.sealed ciphertext is not base64")?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(storage_key));
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &device_keys_aad(&self.device_id, &self.storage_kid),
                    },
                )
                .map_err(|_| {
                    anyhow!(
                        "the storage key doesn't open device_keys.sealed (wrong key, or the file was changed)"
                    )
                })?,
        );
        DeviceKeys::from_sealed_plaintext(&plain, unlock_auth)
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(
            serde_json::from_slice(&raw)
                .with_context(|| format!("{} is unreadable", path.display()))?,
        ))
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        crate::memory::crypto::write_private(path, &serde_json::to_vec_pretty(self)?)
    }
}

/// Moves `device_keys.sealed.next` over `device_keys.sealed` and syncs the
/// directory, so the rename survives a crash.
pub fn promote_next(next: &Path, sealed: &Path) -> Result<()> {
    std::fs::rename(next, sealed)?;
    #[cfg(unix)]
    if let Some(parent) = sealed.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Astation's reply to an unlock request: the storage key sealed to the
/// request's `e_pub`, and the signed `atem-unlock-grant-v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockGrantWire {
    pub grant: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}

/// A storage key for Astation: sealed to its encryption key, with the
/// device-signed `atem-storage-rotate-v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRotation {
    pub rotate: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}
```

- [ ] **Step 8: Run the tests**

Run: `cargo test memory::storage_key memory::device_keys -- --test-threads=1`
Expected: PASS (dead-code warnings for items later tasks use are expected until Task 4).

- [ ] **Step 9: Format and commit**

```bash
rustfmt --edition 2024 src/memory/storage_key.rs src/memory/device_keys.rs
cargo test memory:: -- --test-threads=1
git add Cargo.toml Cargo.lock src/memory/mod.rs src/memory/storage_key.rs src/memory/device_keys.rs
git commit -m "feat(memory): sealed device-keys file and a separate unlock-auth key

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 2: The home Astation and the key files' paths

**Files:**
- Modify: `src/memory/trust.rs`, `src/memory/verification.rs:152-174` (`KeyPaths`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `TrustStore::home(&self) -> Option<&str>` (only when that Astation is verified), `TrustStore::set_home(&mut self, astation_id: &str)`, `TrustStore::home_or_first_verified(&self) -> Option<String>`; `KeyPaths` derives `Debug, Clone` and gains `pub device_keys_sealed: PathBuf` (`device_keys.sealed`), `pub device_keys_next: PathBuf` (`device_keys.sealed.next`), `pub unlock_auth_key: PathBuf` (`unlock_auth_key`); `device_keys` keeps naming the plain step-1 file.

- [ ] **Step 1: Write the failing trust tests** — append inside `mod tests` of `src/memory/trust.rs`:

```rust
    #[test]
    fn home_is_the_verified_astation_it_was_set_to() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        assert_eq!(store.home(), None);
        store.set_home(ASTATION);
        assert_eq!(store.home(), None, "a pending Astation is not a home");
        store
            .confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode()))
            .unwrap();
        assert_eq!(store.home(), Some(ASTATION));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred_state.json");
        store.save_to(&path).unwrap();
        assert_eq!(TrustStore::load_from(&path).unwrap().home(), Some(ASTATION));
    }

    #[test]
    fn a_step_one_store_falls_back_to_its_first_verified_astation() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        assert_eq!(store.home_or_first_verified(), None);
        store
            .confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode()))
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred_state.json");
        store.save_to(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("home_astation"), "no home is not written");
        let loaded = TrustStore::load_from(&path).unwrap();
        assert_eq!(loaded.home(), None);
        assert_eq!(loaded.home_or_first_verified().as_deref(), Some(ASTATION));
    }
```

- [ ] **Step 2: Write the failing paths test** — append inside `mod tests` of `src/memory/verification.rs` (after `astation()`):

```rust
    #[test]
    fn key_paths_name_every_key_file() {
        let paths = KeyPaths::in_dir(std::path::Path::new("/x"));
        assert_eq!(paths.device_keys, std::path::Path::new("/x/device_keys"));
        assert_eq!(paths.device_keys_sealed, std::path::Path::new("/x/device_keys.sealed"));
        assert_eq!(paths.device_keys_next, std::path::Path::new("/x/device_keys.sealed.next"));
        assert_eq!(paths.unlock_auth_key, std::path::Path::new("/x/unlock_auth_key"));
    }
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test memory::trust memory::verification::tests::key_paths -- --test-threads=1`
Expected: compile errors (`home`, `set_home`, `device_keys_sealed`, … not found).

- [ ] **Step 4: Implement the home Astation** — in `src/memory/trust.rs`, add a field to `TrustStore` right after `version`:

```rust
    /// The Astation that holds this device's storage key: its first verified
    /// one. Unlock and storage-key rotation go only through it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    home_astation: Option<String>,
```

and add to `impl TrustStore` (after `verified`):

```rust
    /// The home Astation, once it is verified.
    pub fn home(&self) -> Option<&str> {
        self.home_astation
            .as_deref()
            .filter(|id| self.astations.contains_key(*id))
    }

    pub fn set_home(&mut self, astation_id: &str) {
        self.home_astation = Some(astation_id.into());
    }

    /// The home Astation, or, for a step-1 store that has none, the first
    /// verified Astation by id (used once, to migrate a plain `device_keys`).
    pub fn home_or_first_verified(&self) -> Option<String> {
        self.home()
            .map(str::to_string)
            .or_else(|| self.astations.keys().min().cloned())
    }
```

- [ ] **Step 5: Implement the paths** — in `src/memory/verification.rs`, replace the `KeyPaths` struct and its `in_dir`:

```rust
/// Every file verification and the key agent read or write. Tests point
/// these at a temp dir.
#[derive(Debug, Clone)]
pub struct KeyPaths {
    pub data_keys: PathBuf,
    pub trust: PathBuf,
    /// The plain step-1 file; the key agent seals it into
    /// `device_keys_sealed` and deletes it.
    pub device_keys: PathBuf,
    pub device_keys_sealed: PathBuf,
    /// Written in rotation phase 1, renamed over `device_keys_sealed` in phase 3.
    pub device_keys_next: PathBuf,
    pub unlock_auth_key: PathBuf,
    /// The plain X25519 key from #36; deleted once a device is verified.
    pub legacy_device_key: PathBuf,
}
```

```rust
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            data_keys: dir.join("data_keys.enc"),
            trust: dir.join("cred_state.json"),
            device_keys: dir.join("device_keys"),
            device_keys_sealed: dir.join("device_keys.sealed"),
            device_keys_next: dir.join("device_keys.sealed.next"),
            unlock_auth_key: dir.join("unlock_auth_key"),
            legacy_device_key: dir.join("device_key"),
        }
    }
```

- [ ] **Step 6: Run the tests**

Run: `cargo test memory::trust memory::verification -- --test-threads=1`
Expected: PASS.

- [ ] **Step 7: Format and commit** (`trust.rs` only; `verification.rs` is formatted by hand)

```bash
rustfmt --edition 2024 src/memory/trust.rs
git add src/memory/trust.rs src/memory/verification.rs
git commit -m "feat(memory): record the home Astation and name the sealed key files

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 3: Unlock and storage-key statements, HPKE helpers, and a fake key server

**Files:**
- Modify: `src/memory/encoding.rs`, `src/memory/statements.rs`, `src/memory/grant.rs`, `src/memory/mod.rs`
- Create: `src/memory/fake_astation.rs` (test-only)

**Interfaces:**
- Consumes: Task 1 `SealedDeviceKeys`, `new_storage_key`, `UnlockGrantWire`, `StorageRotation`, `DeviceKeys::sign_statement`, `unlock_auth_key`; Task 2 `TrustStore::set_home`, `KeyPaths` fields.
- Produces:
  - `encoding.rs`: `pub fn u64_field(value: u64) -> [u8; 8]` (production).
  - `statements.rs`: `pub struct UnlockRequest { account, device_id, boot_id, ticket: String, e_pub: [u8; 32], nonce: [u8; 32], time: u64, storage_kid: String }` with `LABEL`, `encode()`, `parse()`; `pub fn unlock_request_hash(statement: &[u8]) -> [u8; 32]`; `pub fn unlock_info(account: &str, device_id: &str, storage_kid: &str, request_hash: &[u8; 32]) -> Vec<u8>`; `pub struct UnlockGrant { account, sign_gen: u64, device_id, storage_kid, request_hash: [u8; 32], sealed_hash: [u8; 32] }` with `parse()` (+ test `encode()`); `pub fn storage_key_info(account: &str, device_id: &str, storage_kid: &str) -> Vec<u8>`; `pub struct StorageRotate { account, device_id, old_storage_kid, new_storage_kid, sealed_hash: [u8; 32] }` with `encode()` (+ test `parse()`); `pub struct StorageAck { account, sign_gen: u64, device_id, storage_kid }` with `parse()` (+ test `encode()`); `pub struct StorageConfirm { account, device_id, storage_kid }` with `encode()` (+ test `parse()`); test-only `pub(crate) fn verify_device(sign_pub: &[u8; 32], signed: &SignedWire) -> Result<Vec<Vec<u8>>>`; `FakeAstation::enc_pub(&self) -> [u8; 32]`, `FakeAstation::enc_secret_bytes(&self) -> [u8; 32]`.
  - `grant.rs`: `pub(crate) fn hpke_seal(recipient: &[u8; 32], info: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>`, `pub(crate) fn hpke_open(secret: &[u8; 32], encapped: &[u8], ciphertext: &[u8], info: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>>`.
  - `fake_astation.rs` (test-only): consts `ASTATION_ID = "astation-1"`, `ACCOUNT = "acct"`, `DEVICE_ID = "dev-1"`; `pin(paths: &KeyPaths, astation: &FakeAstation, keys: &DeviceKeys, home: bool)`; `sealed_device(dir: &Path, kid: &str) -> (KeyPaths, FakeKeyServer, DeviceKeys)`; `FakeKeyServer { astation, device_sign_pub, unlock_auth_pub, storage_keys: HashMap<String, [u8; 32]>, pending: Option<(String, [u8; 32])> }` with `grant_unlock(&self, request: &SignedWire) -> Result<UnlockGrantWire>`, `unlock_grant(&self, signer: &FakeAstation, request: &SignedWire, kid: &str) -> Result<UnlockGrantWire>`, `accept_rotation(&mut self, rotation: &StorageRotation) -> Result<SignedWire>`, `confirm(&mut self, confirm: &SignedWire) -> Result<()>`.

- [ ] **Step 1: Write the failing statement tests** — append inside `mod tests` of `src/memory/statements.rs`:

```rust
    #[test]
    fn unlock_statements_round_trip() {
        let request = UnlockRequest {
            account: "acct".into(),
            device_id: "dev".into(),
            boot_id: "boot".into(),
            ticket: String::new(),
            e_pub: [1; 32],
            nonce: [2; 32],
            time: 1_760_000_000,
            storage_kid: "0a1b2c3d".into(),
        };
        let bytes = request.encode();
        assert_eq!(UnlockRequest::parse(&dec(&bytes).unwrap()).unwrap(), request);
        assert_eq!(
            unlock_request_hash(&bytes),
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        let grant = UnlockGrant {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev".into(),
            storage_kid: "0a1b2c3d".into(),
            request_hash: unlock_request_hash(&bytes),
            sealed_hash: [3; 32],
        };
        assert_eq!(UnlockGrant::parse(&dec(&grant.encode()).unwrap()).unwrap(), grant);
        assert!(
            UnlockGrant::parse(&dec(&bytes).unwrap()).is_err(),
            "a request is not a grant"
        );
        assert_ne!(
            unlock_info("acct", "dev", "0a1b2c3d", &[4; 32]),
            unlock_info("acct", "dev", "0a1b2c3d", &[5; 32])
        );
    }

    #[test]
    fn storage_statements_round_trip() {
        let rotate = StorageRotate {
            account: "acct".into(),
            device_id: "dev".into(),
            old_storage_kid: String::new(),
            new_storage_kid: "0a1b2c3d".into(),
            sealed_hash: [6; 32],
        };
        assert_eq!(StorageRotate::parse(&dec(&rotate.encode()).unwrap()).unwrap(), rotate);
        let ack = StorageAck {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev".into(),
            storage_kid: "0a1b2c3d".into(),
        };
        assert_eq!(StorageAck::parse(&dec(&ack.encode()).unwrap()).unwrap(), ack);
        let confirm = StorageConfirm {
            account: "acct".into(),
            device_id: "dev".into(),
            storage_kid: "0a1b2c3d".into(),
        };
        assert_eq!(
            StorageConfirm::parse(&dec(&confirm.encode()).unwrap()).unwrap(),
            confirm
        );
        assert!(StorageAck::parse(&dec(&confirm.encode()).unwrap()).is_err());
        assert_ne!(
            storage_key_info("acct", "dev", "0a1b2c3d"),
            storage_key_info("acct", "dev", "4e5f6a7b")
        );
    }

    #[test]
    fn device_signatures_verify_only_with_the_signing_key() {
        let keys = crate::memory::device_keys::DeviceKeys::generate();
        let signed = keys.sign_statement(&enc(&[b"label", b"x"]));
        assert_eq!(
            verify_device(&keys.device_sign_pub(), &signed).unwrap(),
            vec![b"label".to_vec(), b"x".to_vec()]
        );
        assert!(verify_device(&keys.unlock_auth_pub(), &signed).is_err());
    }

    #[test]
    fn fake_astation_has_an_encryption_key() {
        let fake = FakeAstation::new();
        let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            fake.enc_secret_bytes(),
        ));
        assert_eq!(derived.to_bytes(), fake.enc_pub());
        assert_ne!(fake.enc_pub(), FakeAstation::new().enc_pub());
    }
```

and inside `mod tests` of `src/memory/grant.rs`:

```rust
    #[test]
    fn hpke_helpers_round_trip_and_bind_info() {
        let recipient = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&recipient).to_bytes();
        let (encapped, ciphertext) = hpke_seal(&public, b"info", b"secret").unwrap();
        let plain = hpke_open(&recipient.to_bytes(), &encapped, &ciphertext, b"info").unwrap();
        assert_eq!(plain.as_slice(), b"secret");
        assert!(hpke_open(&recipient.to_bytes(), &encapped, &ciphertext, b"other").is_err());
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test memory::statements memory::grant -- --test-threads=1`
Expected: compile errors (`UnlockRequest`, `hpke_seal`, `enc_pub`, … not found).

- [ ] **Step 3: Make `u64_field` production code** — in `src/memory/encoding.rs`, replace

```rust
/// Encodes a number field; atem only reads statements, so tests alone write.
#[cfg(test)]
pub fn u64_field(value: u64) -> [u8; 8] {
```

with

```rust
/// Encodes a number field (8 bytes, big-endian).
pub fn u64_field(value: u64) -> [u8; 8] {
```

and in `src/memory/statements.rs` replace the two import lines

```rust
#[cfg(test)]
use crate::memory::encoding::u64_field;
use crate::memory::encoding::{dec, enc, read_u64};
```

with

```rust
use crate::memory::encoding::{dec, enc, read_u64, u64_field};
```

- [ ] **Step 4: Add the statements** — in `src/memory/statements.rs`, change the module doc's first line to `//! Signed statements: the ones Astation signs with its Secure Enclave P-256` and its second line to `//! key, and the unlock/rotation statements this device signs (Ed25519).`; then add after `pub fn sealed_hash` (before `FakeAstation`):

```rust
/// Asks the home Astation to release this device's storage key. Signed by
/// the unlock-auth key; `e_pub` is a single-use X25519 key the release is
/// sealed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockRequest {
    pub account: String,
    pub device_id: String,
    /// `/proc/sys/kernel/random/boot_id`, empty where there is none.
    pub boot_id: String,
    /// Empty until auto-unlock tickets (build step 7).
    pub ticket: String,
    pub e_pub: [u8; 32],
    pub nonce: [u8; 32],
    /// Unix seconds.
    pub time: u64,
    /// The storage key the device asks for: `device_keys.sealed`'s header.
    pub storage_kid: String,
}

impl UnlockRequest {
    pub const LABEL: &'static str = "atem-unlock-request-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            self.device_id.as_bytes(),
            self.boot_id.as_bytes(),
            self.ticket.as_bytes(),
            &self.e_pub,
            &self.nonce,
            &u64_field(self.time),
            self.storage_kid.as_bytes(),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 9)?;
        Ok(Self {
            account: text(&fields[1])?,
            device_id: text(&fields[2])?,
            boot_id: text(&fields[3])?,
            ticket: text(&fields[4])?,
            e_pub: key32(&fields[5])?,
            nonce: key32(&fields[6])?,
            time: read_u64(&fields[7])?,
            storage_kid: text(&fields[8])?,
        })
    }
}

/// SHA-256 of the exact request bytes: what the grant and the HPKE info bind to.
pub fn unlock_request_hash(statement: &[u8]) -> [u8; 32] {
    Sha256::digest(statement).into()
}

/// HPKE `info` for a storage key released to an unlock request's `e_pub`.
pub fn unlock_info(
    account: &str,
    device_id: &str,
    storage_kid: &str,
    request_hash: &[u8; 32],
) -> Vec<u8> {
    enc(&[
        b"atem-unlock-info-v1",
        account.as_bytes(),
        device_id.as_bytes(),
        storage_kid.as_bytes(),
        request_hash,
    ])
}

/// Astation's answer to one unlock request: which storage key it released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockGrant {
    pub account: String,
    pub sign_gen: u64,
    pub device_id: String,
    pub storage_kid: String,
    pub request_hash: [u8; 32],
    /// `sealed_hash(encapped_key, ciphertext)` of the HPKE output.
    pub sealed_hash: [u8; 32],
}

impl UnlockGrant {
    pub const LABEL: &'static str = "atem-unlock-grant-v1";

    /// Astation's side of the encoding: atem only parses, so tests alone encode.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.device_id.as_bytes(),
            self.storage_kid.as_bytes(),
            &self.request_hash,
            &self.sealed_hash,
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 7)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            device_id: text(&fields[3])?,
            storage_kid: text(&fields[4])?,
            request_hash: key32(&fields[5])?,
            sealed_hash: key32(&fields[6])?,
        })
    }
}

/// HPKE `info` for a storage key sealed to Astation's encryption key.
pub fn storage_key_info(account: &str, device_id: &str, storage_kid: &str) -> Vec<u8> {
    enc(&[
        b"atem-storage-key-info-v1",
        account.as_bytes(),
        device_id.as_bytes(),
        storage_kid.as_bytes(),
    ])
}

/// A new storage key for Astation to hold. Signed by the device signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRotate {
    pub account: String,
    pub device_id: String,
    /// Empty at the first sealing, when Astation holds no storage key yet.
    pub old_storage_kid: String,
    pub new_storage_kid: String,
    pub sealed_hash: [u8; 32],
}

impl StorageRotate {
    pub const LABEL: &'static str = "atem-storage-rotate-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            self.device_id.as_bytes(),
            self.old_storage_kid.as_bytes(),
            self.new_storage_kid.as_bytes(),
            &self.sealed_hash,
        ])
    }

    /// Astation's side: atem only encodes, so tests alone parse.
    #[cfg(test)]
    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 6)?;
        Ok(Self {
            account: text(&fields[1])?,
            device_id: text(&fields[2])?,
            old_storage_kid: text(&fields[3])?,
            new_storage_kid: text(&fields[4])?,
            sealed_hash: key32(&fields[5])?,
        })
    }
}

/// Astation stored the new storage key as pending (and kept the old one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageAck {
    pub account: String,
    pub sign_gen: u64,
    pub device_id: String,
    pub storage_kid: String,
}

impl StorageAck {
    pub const LABEL: &'static str = "atem-storage-ack-v1";

    /// Astation's side of the encoding: atem only parses, so tests alone encode.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.device_id.as_bytes(),
            self.storage_kid.as_bytes(),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 5)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            device_id: text(&fields[3])?,
            storage_kid: text(&fields[4])?,
        })
    }
}

/// The device switched to the new storage key; Astation may drop the old one.
/// Signed by the device signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfirm {
    pub account: String,
    pub device_id: String,
    pub storage_kid: String,
}

impl StorageConfirm {
    pub const LABEL: &'static str = "atem-storage-confirm-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            self.device_id.as_bytes(),
            self.storage_kid.as_bytes(),
        ])
    }

    /// Astation's side: atem only encodes, so tests alone parse.
    #[cfg(test)]
    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 4)?;
        Ok(Self {
            account: text(&fields[1])?,
            device_id: text(&fields[2])?,
            storage_kid: text(&fields[3])?,
        })
    }
}

/// Astation's check of a device (or unlock-auth) Ed25519 signature.
#[cfg(test)]
pub(crate) fn verify_device(sign_pub: &[u8; 32], signed: &SignedWire) -> Result<Vec<Vec<u8>>> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(sign_pub)
        .map_err(|_| anyhow!("device signing key is malformed"))?;
    let statement = STANDARD
        .decode(&signed.statement)
        .context("statement is not base64")?;
    let raw: [u8; 64] = STANDARD
        .decode(&signed.signature)
        .context("signature is not base64")?
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    key.verify_strict(&statement, &ed25519_dalek::Signature::from_bytes(&raw))
        .map_err(|_| anyhow!("device signature check failed"))?;
    dec(&statement)
}
```

Give `FakeAstation` an encryption key — replace its struct and `new`:

```rust
#[cfg(test)]
pub(crate) struct FakeAstation {
    key: p256::ecdsa::SigningKey,
    enc: x25519_dalek::StaticSecret,
}

#[cfg(test)]
impl FakeAstation {
    pub fn new() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
            enc: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
        }
    }

    /// Astation's X25519 encryption public key (receives storage keys).
    pub fn enc_pub(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.enc).to_bytes()
    }

    pub fn enc_secret_bytes(&self) -> [u8; 32] {
        self.enc.to_bytes()
    }
```

(keep `sign_pub`, `sign`, `sign_randomized` unchanged below it).

- [ ] **Step 5: Add the HPKE helpers** — in `src/memory/grant.rs`, add after `open_grant`:

```rust
/// RFC 9180 base-mode seal with this module's suite and empty AAD.
pub(crate) fn hpke_seal(
    recipient: &[u8; 32],
    info: &[u8],
    plain: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    use hpke::{OpModeS, Serializable};
    let public = <Kem as KemTrait>::PublicKey::from_bytes(recipient)
        .map_err(|error| anyhow!("recipient key is unusable for HPKE: {error:?}"))?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &public,
        info,
        plain,
        b"",
        &mut rand::rngs::OsRng,
    )
    .map_err(|error| anyhow!("HPKE seal failed: {error:?}"))?;
    Ok((encapped.to_bytes().to_vec(), ciphertext))
}

/// The matching open; the plain text is wiped when dropped.
pub(crate) fn hpke_open(
    secret: &[u8; 32],
    encapped: &[u8],
    ciphertext: &[u8],
    info: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let secret = <Kem as KemTrait>::PrivateKey::from_bytes(secret)
        .map_err(|error| anyhow!("key is unusable for HPKE: {error:?}"))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(encapped)
        .map_err(|error| anyhow!("key encapsulation is malformed: {error:?}"))?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &secret,
        &encapped,
        info,
        ciphertext,
        b"",
    )
    .map(zeroize::Zeroizing::new)
    .map_err(|_| anyhow!("sealed key could not be opened"))
}
```

- [ ] **Step 6: Add the fake key server** — in `src/memory/mod.rs`, after `mod kat_tests;` add:

```rust
#[cfg(test)]
mod fake_astation;
```

and create `src/memory/fake_astation.rs`:

```rust
//! Test stand-in for Astation's side of unlock and storage-key rotation:
//! the pins it keeps, the storage keys it holds, the grants and acks it
//! signs. Mirrors "Astation work for step 2a" in designs/e2e-encryption.md.
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::HashMap;
use std::path::Path;

use crate::memory::device_keys::DeviceKeys;
use crate::memory::encoding::dec;
use crate::memory::grant::{hpke_open, hpke_seal};
use crate::memory::statements::{
    DeviceVerified, FakeAstation, SignedWire, StorageAck, StorageConfirm, StorageRotate,
    UnlockGrant, UnlockRequest, sealed_hash, storage_key_info, unlock_info, unlock_request_hash,
    verify_device,
};
use crate::memory::storage_key::{
    SealedDeviceKeys, StorageRotation, UnlockGrantWire, new_storage_key,
};
use crate::memory::trust::TrustStore;
use crate::memory::verification::{AstationKeys, KeyPaths};

pub(crate) const ASTATION_ID: &str = "astation-1";
pub(crate) const ACCOUNT: &str = "acct";
pub(crate) const DEVICE_ID: &str = "dev-1";

/// Pins `astation` for `keys` in `paths.trust`, as a finished verification
/// does; `home` also makes it the home Astation.
pub(crate) fn pin(paths: &KeyPaths, astation: &FakeAstation, keys: &DeviceKeys, home: bool) {
    let pinned = AstationKeys {
        sign_pub: astation.sign_pub(),
        enc_pub: astation.enc_pub(),
        recovery_sign_pub: [6; 32],
        nonce_s: [7; 32],
    };
    let mut trust = TrustStore::load_from(&paths.trust).unwrap();
    trust.set_pending(ASTATION_ID, DEVICE_ID, keys, &pinned, "AAAA-BBBB-CCCC", &[8; 32]);
    let certificate = DeviceVerified {
        account: ACCOUNT.into(),
        sign_gen: 1,
        device_id: DEVICE_ID.into(),
        device_pub: keys.device_pub(),
        device_sign_pub: keys.device_sign_pub(),
        unlock_auth_pub: keys.unlock_auth_pub(),
        transcript: [8; 32],
        epoch: 1,
    };
    trust
        .confirm(ASTATION_ID, &astation.sign(&certificate.encode()))
        .unwrap();
    if home {
        trust.set_home(ASTATION_ID);
    }
    trust.save_to(&paths.trust).unwrap();
}

/// A verified device in `dir`: home Astation pinned, keys sealed under a
/// storage key with id `kid` that Astation holds, unlock-auth key on disk.
pub(crate) fn sealed_device(dir: &Path, kid: &str) -> (KeyPaths, FakeKeyServer, DeviceKeys) {
    let paths = KeyPaths::in_dir(dir);
    let keys = DeviceKeys::generate();
    let astation = FakeAstation::new();
    pin(&paths, &astation, &keys, true);
    let storage_key = new_storage_key();
    SealedDeviceKeys::seal(&keys, DEVICE_ID, kid, &storage_key)
        .unwrap()
        .save_to(&paths.device_keys_sealed)
        .unwrap();
    keys.unlock_auth_key().save_to(&paths.unlock_auth_key).unwrap();
    let server = FakeKeyServer {
        astation,
        device_sign_pub: keys.device_sign_pub(),
        unlock_auth_pub: keys.unlock_auth_pub(),
        storage_keys: HashMap::from([(kid.to_string(), *storage_key)]),
        pending: None,
    };
    (paths, server, keys)
}

pub(crate) struct FakeKeyServer {
    pub astation: FakeAstation,
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
    /// Storage keys Astation holds for this device, by storage_kid.
    pub storage_keys: HashMap<String, [u8; 32]>,
    /// A rotated key stored as pending until the device confirms it.
    pub pending: Option<(String, [u8; 32])>,
}

impl FakeKeyServer {
    /// "Touch ID approved": releases the storage key the request names.
    pub fn grant_unlock(&self, request: &SignedWire) -> Result<UnlockGrantWire> {
        let bytes = STANDARD.decode(&request.statement)?;
        let kid = UnlockRequest::parse(&dec(&bytes)?)?.storage_kid;
        self.unlock_grant(&self.astation, request, &kid)
    }

    /// Releases storage key `kid` (current or pending) for `request`, with
    /// the grant signed by `signer`.
    pub fn unlock_grant(
        &self,
        signer: &FakeAstation,
        request: &SignedWire,
        kid: &str,
    ) -> Result<UnlockGrantWire> {
        let fields = verify_device(&self.unlock_auth_pub, request).context("unlock-auth signature")?;
        let parsed = UnlockRequest::parse(&fields)?;
        if parsed.account != ACCOUNT || parsed.device_id != DEVICE_ID {
            bail!("unlock request for another account or device");
        }
        let key = self
            .storage_keys
            .get(kid)
            .copied()
            .or_else(|| {
                self.pending
                    .as_ref()
                    .filter(|(pending, _)| pending == kid)
                    .map(|(_, key)| *key)
            })
            .ok_or_else(|| anyhow!("Astation holds no storage key {kid}"))?;
        let request_hash = unlock_request_hash(&STANDARD.decode(&request.statement)?);
        let (encapped, ciphertext) = hpke_seal(
            &parsed.e_pub,
            &unlock_info(ACCOUNT, DEVICE_ID, kid, &request_hash),
            &key,
        )?;
        let statement = UnlockGrant {
            account: ACCOUNT.into(),
            sign_gen: 1,
            device_id: DEVICE_ID.into(),
            storage_kid: kid.into(),
            request_hash,
            sealed_hash: sealed_hash(&encapped, &ciphertext),
        };
        Ok(UnlockGrantWire {
            grant: signer.sign(&statement.encode()),
            encapped_key: STANDARD.encode(encapped),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    /// Phase 2: checks the device signature and the seal, stores the key as
    /// pending (keeping the current one) and acks.
    pub fn accept_rotation(&mut self, rotation: &StorageRotation) -> Result<SignedWire> {
        let rotate = StorageRotate::parse(&verify_device(&self.device_sign_pub, &rotation.rotate)?)?;
        if rotate.account != ACCOUNT || rotate.device_id != DEVICE_ID {
            bail!("rotation for another account or device");
        }
        if !rotate.old_storage_kid.is_empty()
            && !self.storage_keys.contains_key(&rotate.old_storage_kid)
        {
            bail!("rotation from a storage key Astation doesn't hold");
        }
        let encapped = STANDARD.decode(&rotation.encapped_key)?;
        let ciphertext = STANDARD.decode(&rotation.ciphertext)?;
        if sealed_hash(&encapped, &ciphertext) != rotate.sealed_hash {
            bail!("rotation seal doesn't match its signature");
        }
        let plain = hpke_open(
            &self.astation.enc_secret_bytes(),
            &encapped,
            &ciphertext,
            &storage_key_info(ACCOUNT, DEVICE_ID, &rotate.new_storage_kid),
        )?;
        let key: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("storage key has the wrong length"))?;
        self.pending = Some((rotate.new_storage_kid.clone(), key));
        Ok(self.astation.sign(
            &StorageAck {
                account: ACCOUNT.into(),
                sign_gen: 1,
                device_id: DEVICE_ID.into(),
                storage_kid: rotate.new_storage_kid,
            }
            .encode(),
        ))
    }

    /// Phase 3: the device switched; only the new key is kept.
    pub fn confirm(&mut self, confirm: &SignedWire) -> Result<()> {
        let confirmed = StorageConfirm::parse(&verify_device(&self.device_sign_pub, confirm)?)?;
        let (kid, key) = self
            .pending
            .take()
            .ok_or_else(|| anyhow!("no storage key is pending"))?;
        if confirmed.account != ACCOUNT
            || confirmed.device_id != DEVICE_ID
            || confirmed.storage_kid != kid
        {
            bail!("confirmation for another storage key");
        }
        self.storage_keys.clear();
        self.storage_keys.insert(kid, key);
        Ok(())
    }
}
```

- [ ] **Step 7: Run the tests**

Run: `cargo test memory:: -- --test-threads=1`
Expected: PASS (`fake_astation` items are unused until Task 4; test-build warnings about them are expected).

- [ ] **Step 8: Format and commit**

```bash
rustfmt --edition 2024 src/memory/encoding.rs src/memory/statements.rs src/memory/grant.rs src/memory/fake_astation.rs
git add src/memory/encoding.rs src/memory/statements.rs src/memory/grant.rs src/memory/fake_astation.rs src/memory/mod.rs
git commit -m "feat(memory): unlock and storage-key statements, HPKE helpers, fake key server

🤖 Built with SMT <smt@agora.build>"
```

---
### Task 4: The key agent's core — locked by default, loaded keys, grants, lock, migration

**Files:**
- Create: `src/memory/key_agent.rs`
- Modify: `src/memory/mod.rs`

**Interfaces:**
- Consumes: Task 1 `DeviceKeys::{from_secrets, secret_parts, unlock_auth_key, load_from}`, `UnlockAuthKey`, `SealedDeviceKeys`, `StorageKey`, `new_storage_key`, `new_storage_kid`; Task 2 `TrustStore::{home_or_first_verified, set_home}`, `KeyPaths`; `grant::{GrantWire, OpenedGrant, open_grant}`; Task 3 `fake_astation` fixtures (tests).
- Produces:
  - `pub const PROTOCOL_VERSION: u64 = 1`, `pub const LOCKED: &str`.
  - `pub enum Request` (serde `tag = "op"`, snake_case): `Status`, `PublicKeys`, `LoadUnlocked { device_id, device, device_sign, unlock_auth, storage_kid, storage_key: String }`, `OpenGrant { astation_id: String, grant: GrantWire, trust: Option<AstationTrust> }`, `Lock` (Tasks 5–6 add variants).
  - `pub enum Reply` (serde `tag = "kind"`, snake_case): `Status { unlocked: bool, storage_kid: Option<String>, escrowed: bool }`, `PublicKeys { device_pub, device_sign_pub: String }`, `Grant { kid, key: String }`, `Done` (Tasks 5–6 add variants).
  - `pub struct AgentStatus { pub unlocked: bool, pub storage_kid: Option<String>, pub escrowed: bool }`.
  - `pub struct KeyAgent` with `pub fn new(paths: KeyPaths) -> Result<Self>` (migrates a plain `device_keys`) and `pub fn handle(&mut self, request: Request) -> Result<Reply>`.
  - `pub trait KeyAgentApi: Send + Sync` with required `fn call(&self, request: Request) -> Result<Reply>` and provided `status() -> Result<AgentStatus>`, `public_keys() -> Result<([u8; 32], [u8; 32])>`, `load_unlocked(device_id: &str, keys: &DeviceKeys, storage_kid: &str, storage_key: &[u8; 32]) -> Result<()>`, `open_grant(astation_id: &str, grant: &GrantWire, trust: Option<&AstationTrust>) -> Result<OpenedGrant>`, `lock_keys() -> Result<()>`; implemented for `std::sync::Mutex<KeyAgent>` (in-process, used by tests and by the socket server).
  - test-only `pub(crate) fn error_of<T>(result: Result<T>) -> String`.

- [ ] **Step 1: Register the module** — in `src/memory/mod.rs`, after `pub mod storage_key;` add:

```rust
pub mod key_agent;
```

- [ ] **Step 2: Write the failing tests** — create `src/memory/key_agent.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::fake_astation::{ACCOUNT, ASTATION_ID, DEVICE_ID, pin, sealed_device};
    use crate::memory::grant::seal_k_grant;
    use crate::memory::statements::FakeAstation;
    use std::sync::Mutex;

    fn agent(paths: &KeyPaths) -> Mutex<KeyAgent> {
        Mutex::new(KeyAgent::new(paths.clone()).unwrap())
    }

    #[test]
    fn a_new_agent_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let status = agent.status().unwrap();
        assert!(!status.unlocked);
        assert_eq!(status.storage_kid.as_deref(), Some("0a1b2c3d"));
        assert!(error_of(agent.public_keys()).contains("locked"));
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert!(error_of(agent.open_grant(ASTATION_ID, &grant, None)).contains("atem cred unlock"));
    }

    #[test]
    fn loaded_keys_open_grants_until_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &[9; 32])
            .unwrap();
        let status = agent.status().unwrap();
        assert!(status.unlocked && !status.escrowed);
        assert_eq!(status.storage_kid.as_deref(), Some("0a1b2c3d"));
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        let opened = agent.open_grant(ASTATION_ID, &grant, None).unwrap();
        assert_eq!((opened.kid.as_str(), opened.key), ("0123abcd", [42; 32]));
        agent.lock_keys().unwrap();
        assert!(!agent.status().unwrap().unlocked);
        assert!(error_of(agent.open_grant(ASTATION_ID, &grant, None)).contains("locked"));
    }

    #[test]
    fn a_grant_from_an_unverified_astation_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &[9; 32])
            .unwrap();
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert!(error_of(agent.open_grant("astation-2", &grant, None)).contains("isn't verified"));
    }

    #[test]
    fn a_plain_step_one_file_is_sealed_when_the_agent_starts() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let keys = DeviceKeys::generate();
        keys.save_to(&paths.device_keys).unwrap();
        pin(&paths, &FakeAstation::new(), &keys, false);
        let agent = agent(&paths);
        let status = agent.status().unwrap();
        assert!(
            status.unlocked && !status.escrowed,
            "migrated keys wait for their first escrow"
        );
        assert!(!paths.device_keys.exists(), "the plain file is deleted");
        let sealed = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap();
        assert_eq!(sealed.device_id, DEVICE_ID);
        assert_eq!(Some(sealed.storage_kid), status.storage_kid);
        assert_eq!(
            UnlockAuthKey::load_from(&paths.unlock_auth_key)
                .unwrap()
                .unwrap()
                .public(),
            keys.unlock_auth_pub()
        );
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().home(),
            Some(ASTATION_ID)
        );
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
    }

    #[test]
    fn migration_refuses_keys_that_are_not_the_pinned_ones() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        DeviceKeys::generate().save_to(&paths.device_keys).unwrap();
        pin(&paths, &FakeAstation::new(), &DeviceKeys::generate(), true);
        assert!(error_of(KeyAgent::new(paths.clone())).contains("pinned"));
        assert!(paths.device_keys.exists() && !paths.device_keys_sealed.exists());
    }

    #[test]
    fn an_unverified_plain_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        DeviceKeys::generate().save_to(&paths.device_keys).unwrap();
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        assert!(paths.device_keys.exists());
    }
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test memory::key_agent -- --test-threads=1`
Expected: compile errors (`KeyAgent`, `KeyAgentApi`, `error_of`, … not found).

- [ ] **Step 4: Implement** — put this above the test module in `src/memory/key_agent.rs`:

```rust
//! The key agent: this device's unlocked keys, in memory only, like
//! ssh-agent. It never talks to the network: the CLI carries its requests
//! to Astation and Astation's answers back. Keys are wiped on `Lock` and
//! when the process exits. See designs/e2e-encryption.md "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::memory::device_keys::{DeviceKeys, UnlockAuthKey};
use crate::memory::grant::{GrantWire, OpenedGrant, open_grant as open_sealed_grant};
use crate::memory::storage_key::{SealedDeviceKeys, StorageKey, new_storage_key, new_storage_kid};
use crate::memory::trust::{AstationTrust, TrustStore};
use crate::memory::verification::KeyPaths;

/// Every request carries `"v": PROTOCOL_VERSION`; the agent answers any
/// other version with an error, so an old agent and a newer CLI fail clearly.
pub const PROTOCOL_VERSION: u64 = 1;

pub const LOCKED: &str = "this device's keys are locked; run `atem cred unlock`";

/// What the agent serves. Only the same user can reach it (agent_socket.rs).
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    PublicKeys,
    /// Keys handed over at the first verification (same-user socket): the
    /// agent holds them unlocked until Astation has their storage key.
    LoadUnlocked {
        device_id: String,
        device: String,
        device_sign: String,
        unlock_auth: String,
        storage_kid: String,
        storage_key: String,
    },
    /// Opens a key grant with the device key. `trust` is set only during
    /// verification, before the pins are saved; otherwise the agent uses the
    /// verified entry in cred_state.json.
    OpenGrant {
        astation_id: String,
        grant: GrantWire,
        #[serde(default)]
        trust: Option<AstationTrust>,
    },
    Lock,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    Status {
        unlocked: bool,
        storage_kid: Option<String>,
        escrowed: bool,
    },
    PublicKeys {
        device_pub: String,
        device_sign_pub: String,
    },
    /// `K` goes back to the caller until build step 2b moves data_keys.enc
    /// behind the agent.
    Grant { kid: String, key: String },
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    pub unlocked: bool,
    /// The storage key the keys are sealed under (the file's, while locked).
    pub storage_kid: Option<String>,
    /// Whether the home Astation holds that storage key.
    pub escrowed: bool,
}

struct Unlocked {
    keys: DeviceKeys,
    device_id: String,
    storage_kid: String,
    storage_key: StorageKey,
    escrowed: bool,
}

pub struct KeyAgent {
    paths: KeyPaths,
    unlocked: Option<Unlocked>,
}

fn decode32(value: &str, what: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(
        STANDARD
            .decode(value)
            .with_context(|| format!("{what} is not base64"))?,
    );
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{what} has the wrong length"))?;
    Ok(Zeroizing::new(bytes))
}

impl KeyAgent {
    /// An agent for the key files in `paths`: locked, unless a plain step-1
    /// `device_keys` file is migrated (then unlocked, not yet escrowed).
    pub fn new(paths: KeyPaths) -> Result<Self> {
        let mut agent = Self {
            paths,
            unlocked: None,
        };
        agent.migrate_plain_keys()?;
        Ok(agent)
    }

    pub fn handle(&mut self, request: Request) -> Result<Reply> {
        match request {
            Request::Status => Ok(self.status()),
            Request::PublicKeys => {
                let unlocked = self.unlocked()?;
                Ok(Reply::PublicKeys {
                    device_pub: STANDARD.encode(unlocked.keys.device_pub()),
                    device_sign_pub: STANDARD.encode(unlocked.keys.device_sign_pub()),
                })
            }
            Request::LoadUnlocked {
                device_id,
                device,
                device_sign,
                unlock_auth,
                storage_kid,
                storage_key,
            } => self.load_unlocked(
                device_id,
                &Zeroizing::new(device),
                &Zeroizing::new(device_sign),
                &Zeroizing::new(unlock_auth),
                storage_kid,
                &Zeroizing::new(storage_key),
            ),
            Request::OpenGrant {
                astation_id,
                grant,
                trust,
            } => self.open_grant(&astation_id, &grant, trust),
            Request::Lock => {
                self.wipe();
                Ok(Reply::Done)
            }
        }
    }

    /// Drops every secret; their types zeroize on drop.
    fn wipe(&mut self) {
        self.unlocked = None;
    }

    fn unlocked(&self) -> Result<&Unlocked> {
        self.unlocked.as_ref().ok_or_else(|| anyhow!(LOCKED))
    }

    fn status(&self) -> Reply {
        match &self.unlocked {
            Some(unlocked) => Reply::Status {
                unlocked: true,
                storage_kid: Some(unlocked.storage_kid.clone()),
                escrowed: unlocked.escrowed,
            },
            None => Reply::Status {
                unlocked: false,
                storage_kid: SealedDeviceKeys::load_from(&self.paths.device_keys_sealed)
                    .ok()
                    .flatten()
                    .map(|sealed| sealed.storage_kid),
                escrowed: false,
            },
        }
    }

    fn load_unlocked(
        &mut self,
        device_id: String,
        device: &str,
        device_sign: &str,
        unlock_auth: &str,
        storage_kid: String,
        storage_key: &str,
    ) -> Result<Reply> {
        if !crate::memory::crypto::valid_kid(&storage_kid) {
            bail!("storage key id must be 8 lowercase hex characters");
        }
        let keys = DeviceKeys::from_secrets(
            *decode32(device, "device key")?,
            *decode32(device_sign, "device signing key")?,
            *decode32(unlock_auth, "unlock-auth key")?,
        );
        let storage_key = decode32(storage_key, "storage key")?;
        self.unlocked = Some(Unlocked {
            keys,
            device_id,
            storage_kid,
            storage_key,
            escrowed: false,
        });
        Ok(Reply::Done)
    }

    fn open_grant(
        &self,
        astation_id: &str,
        grant: &GrantWire,
        trust: Option<AstationTrust>,
    ) -> Result<Reply> {
        let unlocked = self.unlocked()?;
        let entry = match trust {
            Some(entry) => entry,
            None => TrustStore::load_from(&self.paths.trust)?
                .verified(astation_id)
                .cloned()
                .ok_or_else(|| anyhow!("this device isn't verified with Astation {astation_id}"))?,
        };
        let opened = open_sealed_grant(&entry, &unlocked.keys, grant)?;
        Ok(Reply::Grant {
            kid: opened.kid,
            key: STANDARD.encode(opened.key),
        })
    }

    /// A plain step-1 `device_keys` (and no sealed file): seal it under a new
    /// storage key, split out the unlock-auth key, record the home Astation,
    /// delete the plain file. The keys stay unlocked here until the CLI sends
    /// the storage key to the home Astation (`atem cred unlock`).
    fn migrate_plain_keys(&mut self) -> Result<()> {
        if self.paths.device_keys_sealed.exists() {
            return Ok(());
        }
        let Some(keys) = DeviceKeys::load_from(&self.paths.device_keys)? else {
            return Ok(());
        };
        let mut trust = TrustStore::load_from(&self.paths.trust)?;
        let Some(home) = trust.home_or_first_verified() else {
            eprintln!("key agent: device_keys belongs to no verified Astation; left as it is");
            return Ok(());
        };
        let entry = trust
            .verified(&home)
            .cloned()
            .expect("home_or_first_verified names a verified Astation");
        if entry.device_pub != STANDARD.encode(keys.device_pub())
            || entry.device_sign_pub != STANDARD.encode(keys.device_sign_pub())
            || entry.unlock_auth_pub != STANDARD.encode(keys.unlock_auth_pub())
        {
            bail!(
                "device_keys doesn't hold the keys pinned for Astation {home}; run `atem pair` to verify this device again"
            );
        }
        let storage_key = new_storage_key();
        let storage_kid = new_storage_kid();
        SealedDeviceKeys::seal(&keys, &entry.device_id, &storage_kid, &storage_key)?
            .save_to(&self.paths.device_keys_sealed)?;
        keys.unlock_auth_key().save_to(&self.paths.unlock_auth_key)?;
        trust.set_home(&home);
        trust.save_to(&self.paths.trust)?;
        std::fs::remove_file(&self.paths.device_keys)?;
        eprintln!(
            "key agent: sealed device_keys under storage key {storage_kid}; run `atem cred unlock` to hand it to Astation {home}"
        );
        self.unlocked = Some(Unlocked {
            keys,
            device_id: entry.device_id,
            storage_kid,
            storage_key,
            escrowed: false,
        });
        Ok(())
    }
}

/// How callers talk to the agent: over its socket (`KeyAgentClient`), or
/// in process (`Mutex<KeyAgent>`, used by tests and by the socket server).
pub trait KeyAgentApi: Send + Sync {
    fn call(&self, request: Request) -> Result<Reply>;

    fn status(&self) -> Result<AgentStatus> {
        match self.call(Request::Status)? {
            Reply::Status {
                unlocked,
                storage_kid,
                escrowed,
            } => Ok(AgentStatus {
                unlocked,
                storage_kid,
                escrowed,
            }),
            _ => unexpected(),
        }
    }

    /// The device key and device signing key (public halves).
    fn public_keys(&self) -> Result<([u8; 32], [u8; 32])> {
        match self.call(Request::PublicKeys)? {
            Reply::PublicKeys {
                device_pub,
                device_sign_pub,
            } => Ok((
                *decode32(&device_pub, "device key")?,
                *decode32(&device_sign_pub, "device signing key")?,
            )),
            _ => unexpected(),
        }
    }

    fn load_unlocked(
        &self,
        device_id: &str,
        keys: &DeviceKeys,
        storage_kid: &str,
        storage_key: &[u8; 32],
    ) -> Result<()> {
        let (device, device_sign, unlock_auth) = keys.secret_parts();
        let request = Request::LoadUnlocked {
            device_id: device_id.into(),
            device: STANDARD.encode(&device[..]),
            device_sign: STANDARD.encode(&device_sign[..]),
            unlock_auth: STANDARD.encode(&unlock_auth[..]),
            storage_kid: storage_kid.into(),
            storage_key: STANDARD.encode(storage_key),
        };
        match self.call(request)? {
            Reply::Done => Ok(()),
            _ => unexpected(),
        }
    }

    fn open_grant(
        &self,
        astation_id: &str,
        grant: &GrantWire,
        trust: Option<&AstationTrust>,
    ) -> Result<OpenedGrant> {
        let request = Request::OpenGrant {
            astation_id: astation_id.into(),
            grant: grant.clone(),
            trust: trust.cloned(),
        };
        match self.call(request)? {
            Reply::Grant { kid, key } => Ok(OpenedGrant {
                kid,
                key: *decode32(&key, "granted key")?,
            }),
            _ => unexpected(),
        }
    }

    /// Wipes the unlocked keys. (Not `lock`: `Mutex::lock` would shadow it.)
    fn lock_keys(&self) -> Result<()> {
        match self.call(Request::Lock)? {
            Reply::Done => Ok(()),
            _ => unexpected(),
        }
    }
}

fn unexpected<T>() -> Result<T> {
    bail!("the key agent sent an unexpected reply")
}

impl KeyAgentApi for std::sync::Mutex<KeyAgent> {
    fn call(&self, request: Request) -> Result<Reply> {
        self.lock()
            .map_err(|_| anyhow!("the key agent's state is poisoned"))?
            .handle(request)
    }
}

/// The error text of a result that must fail (works for any `T`, Debug or not).
#[cfg(test)]
pub(crate) fn error_of<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => format!("{error:#}"),
    }
}
```

`UnlockAuthKey` is imported for Task 5; if the compiler flags it unused now, leave it — Task 5 uses it.

- [ ] **Step 5: Run the tests**

Run: `cargo test memory::key_agent -- --test-threads=1`
Expected: PASS.

- [ ] **Step 6: Format and commit**

```bash
rustfmt --edition 2024 src/memory/key_agent.rs
cargo test memory:: -- --test-threads=1
git add src/memory/key_agent.rs src/memory/mod.rs
git commit -m "feat(memory): key agent core — locked by default, grants, lock, plain-file migration

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 5: Unlock — a single-use key, a signed request, Astation's signed release

**Files:**
- Modify: `src/memory/key_agent.rs`

**Interfaces:**
- Consumes: Task 3 `UnlockRequest`, `UnlockGrant`, `unlock_request_hash`, `unlock_info`, `sealed_hash`, `verify_astation`, `hpke_open`, `FakeKeyServer::{grant_unlock, unlock_grant}`; Task 1 `UnlockGrantWire`, `promote_next`; Task 2 `TrustStore::home`.
- Produces:
  - `Request::BeginUnlock { astation_id: String }`, `Request::FinishUnlock { astation_id: String, request: String, grant: UnlockGrantWire }` (`request` = base64 request statement).
  - `Reply::UnlockChallenge { e_pub, nonce, storage_kid, device_id, account: String }`, `Reply::Unlocked { storage_kid: String }`.
  - `pub struct UnlockChallenge { pub e_pub: [u8; 32], pub nonce: [u8; 32], pub storage_kid: String, pub device_id: String, pub account: String }`.
  - `KeyAgentApi::begin_unlock(&self, astation_id: &str) -> Result<UnlockChallenge>`, `KeyAgentApi::finish_unlock(&self, astation_id: &str, request: &str, grant: &UnlockGrantWire) -> Result<String>` (the released `storage_kid`).
  - `pub fn build_unlock_request(challenge: &UnlockChallenge, boot_id: &str, time: u64, unlock_auth: &UnlockAuthKey) -> SignedWire` (CLI side; `statement` is the base64 request, `signature` the unlock-auth signature).

- [ ] **Step 1: Write the failing tests** — append inside `mod tests` of `src/memory/key_agent.rs`:

```rust
    use crate::memory::encoding::dec;
    use crate::memory::fake_astation::FakeKeyServer;
    use crate::memory::statements::{SignedWire, UnlockRequest};

    /// What the CLI does: take a challenge, sign the request.
    fn request(agent: &Mutex<KeyAgent>, paths: &KeyPaths, time: u64) -> (UnlockChallenge, SignedWire) {
        let challenge = agent.begin_unlock(ASTATION_ID).unwrap();
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        let request = build_unlock_request(&challenge, "boot-1", time, &unlock_auth);
        (challenge, request)
    }

    /// A whole unlock against `server`.
    fn unlock(agent: &Mutex<KeyAgent>, server: &FakeKeyServer, paths: &KeyPaths) -> Result<String> {
        let (_, request) = request(agent, paths, 1_760_000_000);
        let grant = server.grant_unlock(&request)?;
        agent.finish_unlock(ASTATION_ID, &request.statement, &grant)
    }

    #[test]
    fn unlock_opens_the_sealed_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), "0a1b2c3d");
        let status = agent.status().unwrap();
        assert!(status.unlocked && status.escrowed);
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        assert!(error_of(agent.begin_unlock(ASTATION_ID)).contains("already unlocked"));
    }

    #[test]
    fn the_challenge_names_this_device_and_a_fresh_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let first = agent.begin_unlock(ASTATION_ID).unwrap();
        assert_eq!(
            (first.account.as_str(), first.device_id.as_str(), first.storage_kid.as_str()),
            (ACCOUNT, DEVICE_ID, "0a1b2c3d")
        );
        let second = agent.begin_unlock(ASTATION_ID).unwrap();
        assert_ne!(first.e_pub, second.e_pub);
        assert_ne!(first.nonce, second.nonce);
        let (_, signed) = request(&agent, &paths, 7);
        let parsed = UnlockRequest::parse(
            &dec(&STANDARD.decode(&signed.statement).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!((parsed.boot_id.as_str(), parsed.ticket.as_str(), parsed.time), ("boot-1", "", 7));
    }

    #[test]
    fn a_relay_swapped_e_pub_is_refused_on_both_sides() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (challenge, honest) = request(&agent, &paths, 1);
        let relay_key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random_from_rng(
            rand::rngs::OsRng,
        ))
        .to_bytes();
        // The relay swaps in its own e_pub: Astation's unlock-auth check fails.
        let mut swapped = UnlockRequest::parse(
            &dec(&STANDARD.decode(&honest.statement).unwrap()).unwrap(),
        )
        .unwrap();
        swapped.e_pub = relay_key;
        let forged = SignedWire {
            statement: STANDARD.encode(swapped.encode()),
            signature: honest.signature.clone(),
        };
        assert!(server.grant_unlock(&forged).is_err());
        // Even a validly signed request for another e_pub doesn't unlock this agent.
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        let other = UnlockChallenge {
            e_pub: relay_key,
            ..challenge
        };
        let relay_request = build_unlock_request(&other, "boot-1", 1, &unlock_auth);
        let grant = server.grant_unlock(&relay_request).unwrap();
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &relay_request.statement, &grant))
                .contains("different request")
        );
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_replayed_grant_for_an_old_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, old_request) = request(&agent, &paths, 1);
        let old_grant = server.grant_unlock(&old_request).unwrap();
        agent
            .finish_unlock(ASTATION_ID, &old_request.statement, &old_grant)
            .unwrap();
        agent.lock_keys().unwrap();

        // After a lock (or reboot) the relay replays the recorded exchange.
        let (_, new_request) = request(&agent, &paths, 2);
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &old_request.statement, &old_grant))
                .contains("different request")
        );
        // E is single use: the failed attempt consumed it.
        let new_grant = server.grant_unlock(&new_request).unwrap();
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &new_request.statement, &new_grant))
                .contains("no unlock is in progress")
        );
        // A fresh request paired with the old grant: the request hash differs.
        let (_, fresh) = request(&agent, &paths, 3);
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &fresh.statement, &old_grant))
                .contains("different request")
        );
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_grant_signed_by_anyone_else_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, request) = request(&agent, &paths, 1);
        let forged = server
            .unlock_grant(&FakeAstation::new(), &request, "0a1b2c3d")
            .unwrap();
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &forged))
                .contains("signature")
        );
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_tampered_seal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, request) = request(&agent, &paths, 1);
        let mut grant = server.grant_unlock(&request).unwrap();
        let mut ciphertext = STANDARD.decode(&grant.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        grant.ciphertext = STANDARD.encode(ciphertext);
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &grant))
                .contains("does not match what Astation signed")
        );
    }

    #[test]
    fn only_the_home_astation_unlocks() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert!(error_of(agent.begin_unlock("astation-2")).contains("home Astation"));
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test memory::key_agent -- --test-threads=1`
Expected: compile errors (`begin_unlock`, `UnlockChallenge`, `build_unlock_request` not found).

- [ ] **Step 3: Implement** — in `src/memory/key_agent.rs`:

Add to the `use` lines:

```rust
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::memory::encoding::dec;
use crate::memory::grant::hpke_open;
use crate::memory::statements::{
    SignedWire, UnlockGrant, UnlockRequest, sealed_hash, unlock_info, unlock_request_hash,
    verify_astation,
};
use crate::memory::storage_key::{UnlockGrantWire, promote_next};
```

Add to `enum Request` (before `Lock`):

```rust
    /// Starts an unlock through the home Astation: a single-use X25519 key.
    BeginUnlock { astation_id: String },
    /// Astation's answer to the request built from the challenge.
    FinishUnlock {
        astation_id: String,
        request: String,
        grant: UnlockGrantWire,
    },
```

Add to `enum Reply` (before `Done`):

```rust
    UnlockChallenge {
        e_pub: String,
        nonce: String,
        storage_kid: String,
        device_id: String,
        account: String,
    },
    Unlocked { storage_kid: String },
```

Add after `struct Unlocked`:

```rust
/// The single-use key of an unlock in progress.
struct PendingUnlock {
    astation_id: String,
    e_secret: StaticSecret,
    e_pub: [u8; 32],
    nonce: [u8; 32],
}

/// What the CLI needs to build and sign an unlock request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockChallenge {
    pub e_pub: [u8; 32],
    pub nonce: [u8; 32],
    pub storage_kid: String,
    pub device_id: String,
    pub account: String,
}

/// The CLI's half: the `atem-unlock-request-v1` statement for `challenge`,
/// signed by the unlock-auth key. Auto-unlock tickets come in build step 7.
pub fn build_unlock_request(
    challenge: &UnlockChallenge,
    boot_id: &str,
    time: u64,
    unlock_auth: &UnlockAuthKey,
) -> SignedWire {
    let statement = UnlockRequest {
        account: challenge.account.clone(),
        device_id: challenge.device_id.clone(),
        boot_id: boot_id.into(),
        ticket: String::new(),
        e_pub: challenge.e_pub,
        nonce: challenge.nonce,
        time,
        storage_kid: challenge.storage_kid.clone(),
    }
    .encode();
    unlock_auth.sign_statement(&statement)
}
```

Add a field to `KeyAgent`:

```rust
    pending_unlock: Option<PendingUnlock>,
```

In `KeyAgent::new` change the constructor to:

```rust
        let mut agent = Self {
            paths,
            unlocked: None,
            pending_unlock: None,
        };
```

Replace `wipe` with:

```rust
    /// Drops every secret; their types zeroize on drop.
    fn wipe(&mut self) {
        self.unlocked = None;
        self.pending_unlock = None;
    }
```

Add these arms to `handle` (before `Request::Lock`):

```rust
            Request::BeginUnlock { astation_id } => self.begin_unlock(&astation_id),
            Request::FinishUnlock {
                astation_id,
                request,
                grant,
            } => self.finish_unlock(&astation_id, &request, &grant),
```

Add these methods to `impl KeyAgent` (after `open_grant`):

```rust
    /// The pins of the home Astation, which must be `astation_id`.
    fn home(&self, astation_id: &str) -> Result<AstationTrust> {
        let store = TrustStore::load_from(&self.paths.trust)?;
        let home = store
            .home()
            .ok_or_else(|| anyhow!("this device has no home Astation yet; run `atem pair` to verify it"))?;
        if home != astation_id {
            bail!(
                "this device's keys unlock through its home Astation ({home}), not {astation_id}"
            );
        }
        store
            .verified(home)
            .cloned()
            .ok_or_else(|| anyhow!("the home Astation's pins are missing; run `atem pair`"))
    }

    fn begin_unlock(&mut self, astation_id: &str) -> Result<Reply> {
        if self.unlocked.is_some() {
            bail!("this device's keys are already unlocked");
        }
        let trust = self.home(astation_id)?;
        let sealed = SealedDeviceKeys::load_from(&self.paths.device_keys_sealed)?
            .ok_or_else(|| anyhow!("this device has no sealed keys; run `atem pair` to verify it"))?;
        if sealed.device_id != trust.device_id {
            bail!("device_keys.sealed belongs to another device id");
        }
        let e_secret = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e_secret).to_bytes();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        self.pending_unlock = Some(PendingUnlock {
            astation_id: astation_id.into(),
            e_secret,
            e_pub,
            nonce,
        });
        Ok(Reply::UnlockChallenge {
            e_pub: STANDARD.encode(e_pub),
            nonce: STANDARD.encode(nonce),
            storage_kid: sealed.storage_kid,
            device_id: trust.device_id,
            account: trust.data_account,
        })
    }

    fn finish_unlock(
        &mut self,
        astation_id: &str,
        request: &str,
        grant: &UnlockGrantWire,
    ) -> Result<Reply> {
        // Single use: E is gone after this call, whatever the outcome.
        let pending = self
            .pending_unlock
            .take()
            .ok_or_else(|| anyhow!("no unlock is in progress; run `atem cred unlock` again"))?;
        if pending.astation_id != astation_id {
            bail!("the unlock reply came from a different Astation");
        }
        let trust = self.home(astation_id)?;
        let request_bytes = STANDARD
            .decode(request)
            .context("unlock request is not base64")?;
        let sent = UnlockRequest::parse(&dec(&request_bytes)?)?;
        if sent.e_pub != pending.e_pub || sent.nonce != pending.nonce {
            bail!("the unlock reply answers a different request");
        }
        if sent.account != trust.data_account || sent.device_id != trust.device_id {
            bail!("the unlock request names another account or device");
        }
        let request_hash = unlock_request_hash(&request_bytes);
        let sign_pub = STANDARD.decode(&trust.astation_sign_pub)?;
        let granted = UnlockGrant::parse(&verify_astation(&sign_pub, &grant.grant)?)?;
        if granted.account != trust.data_account {
            bail!("unlock grant is for a different account");
        }
        if granted.sign_gen != trust.sign_gen {
            bail!("unlock grant is signed by a different signing-key generation");
        }
        if granted.device_id != trust.device_id {
            bail!("unlock grant is for a different device");
        }
        if granted.request_hash != request_hash {
            bail!("unlock grant answers a different request");
        }
        if !crate::memory::crypto::valid_kid(&granted.storage_kid) {
            bail!("unlock grant has an invalid storage key id");
        }
        let encapped = STANDARD
            .decode(&grant.encapped_key)
            .context("unlock grant key encapsulation is not base64")?;
        let ciphertext = STANDARD
            .decode(&grant.ciphertext)
            .context("unlock grant ciphertext is not base64")?;
        if sealed_hash(&encapped, &ciphertext) != granted.sealed_hash {
            bail!("unlock grant does not match what Astation signed");
        }
        let info = unlock_info(
            &granted.account,
            &granted.device_id,
            &granted.storage_kid,
            &request_hash,
        );
        let e_secret = Zeroizing::new(pending.e_secret.to_bytes());
        drop(pending);
        let plain = hpke_open(&e_secret, &encapped, &ciphertext, &info)
            .context("the storage key could not be opened")?;
        let storage_key: StorageKey = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("storage key has the wrong length"))?,
        );
        let (sealed, from_next) = self.sealed_with_kid(&granted.storage_kid)?;
        let unlock_auth = UnlockAuthKey::load_from(&self.paths.unlock_auth_key)?.ok_or_else(|| {
            anyhow!("unlock_auth_key is missing; run `atem pair` to verify this device again")
        })?;
        let keys = sealed.open(&storage_key, unlock_auth)?;
        if STANDARD.encode(keys.device_pub()) != trust.device_pub
            || STANDARD.encode(keys.device_sign_pub()) != trust.device_sign_pub
        {
            bail!("the sealed keys aren't this device's pinned keys");
        }
        if from_next {
            // Astation released the key a crashed rotation left pending.
            promote_next(&self.paths.device_keys_next, &self.paths.device_keys_sealed)?;
        }
        self.unlocked = Some(Unlocked {
            keys,
            device_id: trust.device_id,
            storage_kid: granted.storage_kid.clone(),
            storage_key,
            escrowed: true,
        });
        Ok(Reply::Unlocked {
            storage_kid: granted.storage_kid,
        })
    }

    /// The sealed file the released key belongs to: the current one, or the
    /// `.next` a rotation left when it crashed after Astation stored the key.
    fn sealed_with_kid(&self, storage_kid: &str) -> Result<(SealedDeviceKeys, bool)> {
        if let Some(sealed) = SealedDeviceKeys::load_from(&self.paths.device_keys_sealed)?
            && sealed.storage_kid == storage_kid
        {
            return Ok((sealed, false));
        }
        if let Some(next) = SealedDeviceKeys::load_from(&self.paths.device_keys_next)?
            && next.storage_kid == storage_kid
        {
            return Ok((next, true));
        }
        bail!("no sealed keys on disk match the storage key Astation released ({storage_kid})")
    }
```

Add to `trait KeyAgentApi` (after `public_keys`):

```rust
    fn begin_unlock(&self, astation_id: &str) -> Result<UnlockChallenge> {
        match self.call(Request::BeginUnlock {
            astation_id: astation_id.into(),
        })? {
            Reply::UnlockChallenge {
                e_pub,
                nonce,
                storage_kid,
                device_id,
                account,
            } => Ok(UnlockChallenge {
                e_pub: *decode32(&e_pub, "unlock key")?,
                nonce: *decode32(&nonce, "unlock nonce")?,
                storage_kid,
                device_id,
                account,
            }),
            _ => unexpected(),
        }
    }

    /// Returns the storage key id Astation released.
    fn finish_unlock(&self, astation_id: &str, request: &str, grant: &UnlockGrantWire) -> Result<String> {
        match self.call(Request::FinishUnlock {
            astation_id: astation_id.into(),
            request: request.into(),
            grant: grant.clone(),
        })? {
            Reply::Unlocked { storage_kid } => Ok(storage_kid),
            _ => unexpected(),
        }
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test memory::key_agent -- --test-threads=1`
Expected: PASS.

- [ ] **Step 5: Format and commit**

```bash
rustfmt --edition 2024 src/memory/key_agent.rs
git add src/memory/key_agent.rs
git commit -m "feat(memory): unlock through the home Astation with a single-use key

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 6: Storage-key rotation in three crash-safe phases

**Files:**
- Modify: `src/memory/key_agent.rs`

**Interfaces:**
- Consumes: Task 3 `StorageRotate`, `StorageAck`, `StorageConfirm`, `storage_key_info`, `hpke_seal`, `FakeKeyServer::{accept_rotation, confirm}`; Task 1 `StorageRotation`, `promote_next`.
- Produces:
  - `Request::BeginRotation { astation_id: String }`, `Request::ConfirmRotation { astation_id: String, ack: SignedWire }`.
  - `Reply::Rotation { rotation: StorageRotation }`, `Reply::Confirmed { storage_kid: String, confirm: SignedWire }`.
  - `KeyAgentApi::begin_rotation(&self, astation_id: &str) -> Result<StorageRotation>`, `KeyAgentApi::confirm_rotation(&self, astation_id: &str, ack: &SignedWire) -> Result<(String, SignedWire)>` (new `storage_kid`, the signed `atem-storage-confirm-v1`).
  - Semantics: when the current storage key isn't escrowed yet (first sealing or migration), `begin_rotation` sends the current key with `old_storage_kid = ""` and writes no `.next`; otherwise it writes `.next` under a new key and kid.

- [ ] **Step 1: Write the failing tests** — append inside `mod tests` of `src/memory/key_agent.rs`:

```rust
    use crate::memory::statements::{StorageAck, StorageRotate, verify_device};

    #[test]
    fn the_first_escrow_sends_the_current_storage_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        // As after a first verification: the agent has the key, Astation doesn't.
        let storage_key = [9u8; 32];
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "0a1b2c3d", &storage_key)
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        server.storage_keys.clear();
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &storage_key)
            .unwrap();

        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let statement =
            StorageRotate::parse(&verify_device(&keys.device_sign_pub(), &rotation.rotate).unwrap())
                .unwrap();
        assert_eq!(
            (statement.old_storage_kid.as_str(), statement.new_storage_kid.as_str()),
            ("", "0a1b2c3d")
        );
        assert!(!paths.device_keys_next.exists(), "the first escrow re-seals nothing");
        let ack = server.accept_rotation(&rotation).unwrap();
        assert_eq!(server.pending, Some(("0a1b2c3d".to_string(), storage_key)));
        let (kid, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(kid, "0a1b2c3d");
        server.confirm(&confirm).unwrap();
        assert!(agent.status().unwrap().escrowed);

        agent.lock_keys().unwrap();
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), "0a1b2c3d");
    }

    #[test]
    fn rotation_after_unlock_replaces_the_storage_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let old_key = server.storage_keys["0a1b2c3d"];
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();

        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let next = SealedDeviceKeys::load_from(&paths.device_keys_next)
            .unwrap()
            .expect("phase 1 writes .next");
        assert_ne!(next.storage_kid, "0a1b2c3d");
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            "0a1b2c3d",
            "the current file stays until Astation acks"
        );
        let ack = server.accept_rotation(&rotation).unwrap();
        let (kid, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(kid, next.storage_kid);
        assert!(!paths.device_keys_next.exists());
        let current = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap();
        assert_eq!(current.storage_kid, kid);
        server.confirm(&confirm).unwrap();
        assert_eq!(server.storage_keys.keys().collect::<Vec<_>>(), vec![&kid]);

        // A stolen copy of the old storage key no longer opens the file.
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        assert!(current.open(&old_key, unlock_auth).is_err());
        agent.lock_keys().unwrap();
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), kid);
    }

    #[test]
    fn a_crash_between_ack_and_confirm_unlocks_with_the_next_file() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        {
            let agent = agent(&paths);
            unlock(&agent, &server, &paths).unwrap();
            let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
            server.accept_rotation(&rotation).unwrap();
            // The process dies here: no phase 3.
        }
        let new_kid = server.pending.as_ref().unwrap().0.clone();
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        // Astation still holds both keys and releases the pending one.
        let (_, request) = request(&agent, &paths, 5);
        let grant = server
            .unlock_grant(&server.astation, &request, &new_kid)
            .unwrap();
        assert_eq!(
            agent
                .finish_unlock(ASTATION_ID, &request.statement, &grant)
                .unwrap(),
            new_kid
        );
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            new_kid
        );
        assert!(!paths.device_keys_next.exists());
    }

    #[test]
    fn a_forged_or_mismatched_ack_promotes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        agent.begin_rotation(ASTATION_ID).unwrap();
        let new_kid = SealedDeviceKeys::load_from(&paths.device_keys_next)
            .unwrap()
            .unwrap()
            .storage_kid;
        let ack = |kid: &str| StorageAck {
            account: ACCOUNT.into(),
            sign_gen: 1,
            device_id: DEVICE_ID.into(),
            storage_kid: kid.into(),
        };
        let forged = FakeAstation::new().sign(&ack(&new_kid).encode());
        assert!(error_of(agent.confirm_rotation(ASTATION_ID, &forged)).contains("signature"));

        agent.begin_rotation(ASTATION_ID).unwrap();
        let wrong = server.astation.sign(&ack("ffffffff").encode());
        assert!(
            error_of(agent.confirm_rotation(ASTATION_ID, &wrong)).contains("different storage key")
        );
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            "0a1b2c3d"
        );
        assert!(paths.device_keys_next.exists());
        assert_eq!(agent.status().unwrap().storage_kid.as_deref(), Some("0a1b2c3d"));
    }

    #[test]
    fn rotation_needs_unlocked_keys_and_the_home_astation() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert!(error_of(agent.begin_rotation(ASTATION_ID)).contains("locked"));
        unlock(&agent, &server, &paths).unwrap();
        assert!(error_of(agent.begin_rotation("astation-2")).contains("home Astation"));
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test memory::key_agent -- --test-threads=1`
Expected: compile errors (`begin_rotation`, `confirm_rotation` not found).

- [ ] **Step 3: Implement** — in `src/memory/key_agent.rs`:

Extend the imports: add `StorageAck, StorageConfirm, StorageRotate, storage_key_info` to the `crate::memory::statements` import, `hpke_seal` to the `crate::memory::grant` import (`use crate::memory::grant::{hpke_open, hpke_seal};`), and `StorageRotation` to the `crate::memory::storage_key` import.

Add to `enum Request` (before `Lock`):

```rust
    /// Rotation phase 1: a new storage key for the home Astation.
    BeginRotation { astation_id: String },
    /// Rotation phase 3, after Astation's signed acknowledgement.
    ConfirmRotation { astation_id: String, ack: SignedWire },
```

Add to `enum Reply` (before `Done`):

```rust
    Rotation { rotation: StorageRotation },
    Confirmed { storage_kid: String, confirm: SignedWire },
```

Add after `struct PendingUnlock`:

```rust
/// A storage key sent to Astation and not yet acknowledged.
struct PendingRotation {
    storage_kid: String,
    storage_key: StorageKey,
    /// The first escrow of the current key: nothing to rename.
    initial: bool,
}
```

Add a field to `KeyAgent`:

```rust
    pending_rotation: Option<PendingRotation>,
```

In `KeyAgent::new` add `pending_rotation: None,` to the constructor, and replace `wipe` with:

```rust
    /// Drops every secret; their types zeroize on drop.
    fn wipe(&mut self) {
        self.unlocked = None;
        self.pending_unlock = None;
        self.pending_rotation = None;
    }
```

In `load_unlocked`, add `self.pending_rotation = None;` right before `self.unlocked = Some(Unlocked {`.

Add these arms to `handle` (before `Request::Lock`):

```rust
            Request::BeginRotation { astation_id } => self.begin_rotation(&astation_id),
            Request::ConfirmRotation { astation_id, ack } => {
                self.confirm_rotation(&astation_id, &ack)
            }
```

Add these methods to `impl KeyAgent` (after `sealed_with_kid`):

```rust
    fn begin_rotation(&mut self, astation_id: &str) -> Result<Reply> {
        let unlocked = self.unlocked.as_ref().ok_or_else(|| anyhow!(LOCKED))?;
        let trust = self.home(astation_id)?;
        if unlocked.device_id != trust.device_id {
            bail!("the unlocked keys belong to another device id");
        }
        let initial = !unlocked.escrowed;
        let (old_kid, new_kid, new_key) = if initial {
            (
                String::new(),
                unlocked.storage_kid.clone(),
                unlocked.storage_key.clone(),
            )
        } else {
            let (kid, key) = (new_storage_kid(), new_storage_key());
            // Phase 1: the re-sealed file waits beside the current one.
            SealedDeviceKeys::seal(&unlocked.keys, &unlocked.device_id, &kid, &key)?
                .save_to(&self.paths.device_keys_next)?;
            (unlocked.storage_kid.clone(), kid, key)
        };
        let enc_pub: [u8; 32] = STANDARD
            .decode(&trust.astation_enc_pub)?
            .try_into()
            .map_err(|_| anyhow!("the pinned Astation encryption key has the wrong length"))?;
        let (encapped, ciphertext) = hpke_seal(
            &enc_pub,
            &storage_key_info(&trust.data_account, &unlocked.device_id, &new_kid),
            new_key.as_slice(),
        )?;
        let statement = StorageRotate {
            account: trust.data_account.clone(),
            device_id: unlocked.device_id.clone(),
            old_storage_kid: old_kid,
            new_storage_kid: new_kid.clone(),
            sealed_hash: sealed_hash(&encapped, &ciphertext),
        }
        .encode();
        let rotate = unlocked.keys.sign_statement(&statement);
        self.pending_rotation = Some(PendingRotation {
            storage_kid: new_kid,
            storage_key: new_key,
            initial,
        });
        Ok(Reply::Rotation {
            rotation: StorageRotation {
                rotate,
                encapped_key: STANDARD.encode(encapped),
                ciphertext: STANDARD.encode(ciphertext),
            },
        })
    }

    fn confirm_rotation(&mut self, astation_id: &str, ack: &SignedWire) -> Result<Reply> {
        let trust = self.home(astation_id)?;
        let pending = self
            .pending_rotation
            .take()
            .ok_or_else(|| anyhow!("no storage-key rotation is in progress"))?;
        let sign_pub = STANDARD.decode(&trust.astation_sign_pub)?;
        let acked = StorageAck::parse(&verify_astation(&sign_pub, ack)?)?;
        if acked.account != trust.data_account
            || acked.sign_gen != trust.sign_gen
            || acked.device_id != trust.device_id
            || acked.storage_kid != pending.storage_kid
        {
            bail!("Astation's acknowledgement is for a different storage key");
        }
        let unlocked = self.unlocked.as_mut().ok_or_else(|| anyhow!(LOCKED))?;
        if !pending.initial {
            // Phase 3: Astation holds the new key, so the new file becomes current.
            promote_next(&self.paths.device_keys_next, &self.paths.device_keys_sealed)?;
        }
        let confirm = unlocked.keys.sign_statement(
            &StorageConfirm {
                account: trust.data_account,
                device_id: trust.device_id,
                storage_kid: pending.storage_kid.clone(),
            }
            .encode(),
        );
        unlocked.storage_kid = pending.storage_kid.clone();
        unlocked.storage_key = pending.storage_key;
        unlocked.escrowed = true;
        Ok(Reply::Confirmed {
            storage_kid: pending.storage_kid,
            confirm,
        })
    }
```

Add to `trait KeyAgentApi` (after `finish_unlock`):

```rust
    fn begin_rotation(&self, astation_id: &str) -> Result<StorageRotation> {
        match self.call(Request::BeginRotation {
            astation_id: astation_id.into(),
        })? {
            Reply::Rotation { rotation } => Ok(rotation),
            _ => unexpected(),
        }
    }

    /// Returns the new storage key id and the signed confirmation to send.
    fn confirm_rotation(&self, astation_id: &str, ack: &SignedWire) -> Result<(String, SignedWire)> {
        match self.call(Request::ConfirmRotation {
            astation_id: astation_id.into(),
            ack: ack.clone(),
        })? {
            Reply::Confirmed {
                storage_kid,
                confirm,
            } => Ok((storage_kid, confirm)),
            _ => unexpected(),
        }
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test memory::key_agent -- --test-threads=1`
Expected: PASS.

- [ ] **Step 5: Format and commit**

```bash
rustfmt --edition 2024 src/memory/key_agent.rs
git add src/memory/key_agent.rs
git commit -m "feat(memory): rotate the storage key in three crash-safe phases

🤖 Built with SMT <smt@agora.build>"
```

---
### Task 7: The agent's socket, its client, and the hidden `atem key-agent`

**Files:**
- Create: `src/memory/agent_socket.rs`
- Modify: `src/memory/mod.rs`, `src/memory/key_agent.rs`, `src/cli.rs` (`Commands`, `handle_cli_command`, tests)

**Interfaces:**
- Consumes: Task 4–6 `KeyAgent`, `KeyAgentApi`, `Request`, `Reply`, `PROTOCOL_VERSION`; Task 2 `KeyPaths::default_paths`; `crate::config::AtemConfig::config_dir`.
- Produces (all `#[cfg(unix)]`, module `crate::memory::agent_socket`):
  - `pub fn agent_socket_path() -> PathBuf`, `pub fn agent_log_path() -> PathBuf` (`~/.config/atem/key-agent.log`).
  - `pub fn bind(socket: &Path) -> Result<tokio::net::UnixListener>` (dir 0700, socket 0600, refuses a live agent, replaces a stale socket).
  - `pub async fn serve(listener: tokio::net::UnixListener, agent: Arc<Mutex<KeyAgent>>, allowed_uid: u32) -> Result<()>`.
  - `pub async fn run_key_agent() -> Result<()>` (the `atem key-agent` entry point).
  - `pub struct KeyAgentClient` with `pub fn at(socket: PathBuf) -> Self` (never starts an agent), `pub fn autostart() -> Self` (this user's socket; starts the agent when none answers), `pub fn is_running(&self) -> bool`; `impl KeyAgentApi for KeyAgentClient`.
  - `pub(crate) fn encode_request(request: &Request) -> Result<String>`, `pub(crate) fn decode_request(line: &str) -> Result<Request>`, `pub(crate) fn decode_response(line: &str) -> Result<Reply>`.
  - In `key_agent.rs` (all platforms): `pub fn default_agent() -> Box<dyn KeyAgentApi>` (autostart client; on non-Unix an agent that always errors) and `pub fn running_agent() -> Option<Box<dyn KeyAgentApi>>` (the running agent, never starting one).
  - `cli.rs`: `Commands::KeyAgent` (hidden, `atem key-agent`).

- [ ] **Step 1: Register the module** — in `src/memory/mod.rs`, after `pub mod key_agent;` add:

```rust
#[cfg(unix)]
pub mod agent_socket;
```

- [ ] **Step 2: Write the failing tests** — create `src/memory/agent_socket.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};

    /// Unix socket paths are limited to ~100 bytes; keep them short.
    fn short_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("atem-ka")
            .tempdir_in("/tmp")
            .unwrap()
    }

    fn own_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    /// Serves an agent for the key files in `dir` on its own thread.
    fn start_agent(dir: &Path, allowed_uid: u32) -> PathBuf {
        let socket = dir.join("run").join("agent.sock");
        let paths = KeyPaths::in_dir(dir);
        let (ready, started) = std::sync::mpsc::channel();
        let path = socket.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = bind(&path).unwrap();
                let agent = Arc::new(Mutex::new(KeyAgent::new(paths).unwrap()));
                ready.send(()).unwrap();
                let _ = serve(listener, agent, allowed_uid).await;
            });
        });
        started.recv().unwrap();
        socket
    }

    #[test]
    fn the_socket_prefers_the_runtime_dir() {
        let config = Path::new("/home/u/.config/atem");
        assert_eq!(
            socket_path_from(Some("/run/user/1000".into()), config),
            Path::new("/run/user/1000/atem/agent.sock")
        );
        assert_eq!(
            socket_path_from(None, config),
            Path::new("/home/u/.config/atem/agent.sock")
        );
        assert_eq!(
            socket_path_from(Some("".into()), config),
            Path::new("/home/u/.config/atem/agent.sock")
        );
    }

    #[test]
    fn every_request_carries_the_protocol_version() {
        let line = encode_request(&Request::Status).unwrap();
        assert!(line.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value, serde_json::json!({"op": "status", "v": 1}));
        assert!(matches!(decode_request(line.trim()).unwrap(), Request::Status));
        let newer = decode_request(r#"{"op":"status","v":2}"#).err().unwrap();
        assert!(format!("{newer:#}").contains("protocol version 2"));
        assert!(decode_request(r#"{"op":"status"}"#).is_err());
    }

    #[test]
    fn a_newer_cli_gets_a_clear_error_from_an_older_agent() {
        let newer_agent = decode_response(r#"{"v":2,"ok":true,"reply":{"kind":"done"}}"#);
        assert!(format!("{:#}", newer_agent.err().unwrap()).contains("pkill"));
        let refused = decode_response(
            r#"{"v":1,"ok":false,"error":"unsupported key agent protocol version 2"}"#,
        );
        assert!(format!("{:#}", refused.err().unwrap()).contains("protocol version 2"));
        assert!(matches!(
            decode_response(r#"{"v":1,"ok":true,"reply":{"kind":"done"}}"#).unwrap(),
            Reply::Done
        ));
    }

    #[test]
    fn the_same_user_talks_to_the_agent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = KeyAgentClient::at(socket.clone());
        assert!(client.is_running());
        assert!(!client.status().unwrap().unlocked);
        client.lock_keys().unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(socket.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        // A request in an unknown version is answered with an error, not dropped.
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream.write_all(b"{\"op\":\"status\",\"v\":2}\n").unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["v"], 1);
        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("protocol version 2"));
    }

    #[test]
    fn another_user_is_refused() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid().wrapping_add(1));
        let error = format!(
            "{:#}",
            KeyAgentClient::at(socket).status().err().unwrap()
        );
        assert!(error.contains("closed the connection"), "{error}");
    }

    #[test]
    fn bind_replaces_a_stale_socket_but_not_a_live_agent() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let live = bind(&socket).err().unwrap();
            assert!(format!("{live:#}").contains("already running"));
            let stale = dir.path().join("stale").join("agent.sock");
            std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
            drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
            assert!(stale.exists());
            bind(&stale).unwrap();
        });
    }

    #[test]
    fn a_client_that_may_not_start_an_agent_says_so() {
        let dir = short_dir();
        let client = KeyAgentClient::at(dir.path().join("none.sock"));
        assert!(!client.is_running());
        assert!(format!("{:#}", client.status().err().unwrap()).contains("isn't running"));
    }
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test memory::agent_socket -- --test-threads=1`
Expected: compile errors (`bind`, `serve`, `KeyAgentClient`, … not found).

- [ ] **Step 4: Implement the socket** — put this above the test module in `src/memory/agent_socket.rs`:

```rust
//! The key agent's Unix socket: newline-delimited JSON, `"v": 1` on every
//! request, same-user peers only. `atem key-agent` serves it; commands that
//! need keys connect, starting the agent when none is running.
//! See designs/e2e-encryption.md "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::memory::key_agent::{KeyAgent, KeyAgentApi, PROTOCOL_VERSION, Reply, Request};
use crate::memory::verification::KeyPaths;

/// `$XDG_RUNTIME_DIR/atem/agent.sock`, else `~/.config/atem/agent.sock`.
pub fn agent_socket_path() -> PathBuf {
    socket_path_from(
        std::env::var_os("XDG_RUNTIME_DIR"),
        &crate::config::AtemConfig::config_dir(),
    )
}

fn socket_path_from(runtime_dir: Option<OsString>, config_dir: &Path) -> PathBuf {
    match runtime_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("atem").join("agent.sock"),
        _ => config_dir.join("agent.sock"),
    }
}

pub fn agent_log_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("key-agent.log")
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Response {
    v: u64,
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply: Option<Reply>,
}

pub(crate) fn encode_request(request: &Request) -> Result<String> {
    let mut value = serde_json::to_value(request)?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("key agent request must be a JSON object"))?
        .insert("v".into(), PROTOCOL_VERSION.into());
    Ok(format!("{value}\n"))
}

pub(crate) fn decode_request(line: &str) -> Result<Request> {
    let value: serde_json::Value =
        serde_json::from_str(line).context("key agent request is not JSON")?;
    match value.get("v").and_then(serde_json::Value::as_u64) {
        Some(PROTOCOL_VERSION) => {}
        other => bail!(
            "unsupported key agent protocol version {}; this agent speaks v{PROTOCOL_VERSION}",
            other.map_or_else(|| "(none)".to_string(), |v| v.to_string())
        ),
    }
    serde_json::from_value(value).context("key agent request is malformed")
}

pub(crate) fn decode_response(line: &str) -> Result<Reply> {
    let response: Response =
        serde_json::from_str(line.trim()).context("the key agent sent an unreadable reply")?;
    if response.v != PROTOCOL_VERSION {
        bail!(
            "the running key agent speaks protocol v{}, this atem speaks v{PROTOCOL_VERSION}; stop it with `pkill -u \"$USER\" -f 'atem key-agent'` (its keys stay sealed on disk) and retry",
            response.v
        );
    }
    if !response.ok {
        bail!(
            "{}",
            response
                .error
                .unwrap_or_else(|| "the key agent refused the request".into())
        );
    }
    response
        .reply
        .ok_or_else(|| anyhow!("the key agent sent an empty reply"))
}

fn respond(agent: &Mutex<KeyAgent>, line: &str) -> Response {
    match decode_request(line).and_then(|request| agent.call(request)) {
        Ok(reply) => Response {
            v: PROTOCOL_VERSION,
            ok: true,
            error: None,
            reply: Some(reply),
        },
        Err(error) => Response {
            v: PROTOCOL_VERSION,
            ok: false,
            error: Some(format!("{error:#}")),
            reply: None,
        },
    }
}

/// Listens on `socket`: directory 0700, socket 0600. A socket file nobody
/// answers on is left by an agent that died, and is replaced.
pub fn bind(socket: &Path) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let dir = socket
        .parent()
        .ok_or_else(|| anyhow!("the agent socket path has no directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            bail!("a key agent is already running at {}", socket.display());
        }
        std::fs::remove_file(socket)?;
    }
    let listener = tokio::net::UnixListener::bind(socket)
        .with_context(|| format!("could not listen on {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves `agent` to peers running as `allowed_uid`; others are dropped.
pub async fn serve(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<KeyAgent>>,
    allowed_uid: u32,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, &agent, allowed_uid).await {
                eprintln!("key agent: {error:#}");
            }
        });
    }
}

async fn serve_connection(
    stream: tokio::net::UnixStream,
    agent: &Mutex<KeyAgent>,
    allowed_uid: u32,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let peer = stream.peer_cred()?.uid();
    if peer != allowed_uid {
        bail!("refused a connection from uid {peer}");
    }
    let (read, mut write) = stream.into_split();
    let mut lines = tokio::io::BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        let mut reply = serde_json::to_string(&respond(agent, &line))?;
        reply.push('\n');
        write.write_all(reply.as_bytes()).await?;
    }
    Ok(())
}

/// No core dumps, no ptrace by the same user, and (when the limit allows)
/// no swapping. Linux only; elsewhere a no-op.
fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) } != 0 {
            eprintln!(
                "key agent: PR_SET_DUMPABLE failed ({})",
                std::io::Error::last_os_error()
            );
        }
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let known = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0;
        // With MCL_FUTURE, every allocation past the limit fails, so lock only
        // when the limit leaves room for the whole process.
        if !known || (limit.rlim_cur != libc::RLIM_INFINITY && limit.rlim_cur < 512 << 20) {
            eprintln!("key agent: not locking memory (RLIMIT_MEMLOCK is too low); keys could reach swap");
        } else if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
            eprintln!(
                "key agent: mlockall failed ({}); keys could reach swap",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// `atem key-agent`: serve this user's agent until the process exits.
pub async fn run_key_agent() -> Result<()> {
    harden_process();
    let socket = agent_socket_path();
    let listener = bind(&socket)?;
    let agent = KeyAgent::new(KeyPaths::default_paths())?;
    eprintln!(
        "atem key agent (protocol v{PROTOCOL_VERSION}) listening on {}",
        socket.display()
    );
    serve(listener, Arc::new(Mutex::new(agent)), unsafe { libc::getuid() }).await
}

/// Starts `atem key-agent` detached from this command and its terminal.
fn spawn_agent(log: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)?;
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .arg("key-agent")
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file);
    let detach = || -> std::io::Result<()> {
        if unsafe { libc::setsid() } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: setsid is async-signal-safe, as pre_exec requires.
    unsafe {
        command.pre_exec(detach);
    }
    command.spawn().context("could not start the key agent")?;
    Ok(())
}

pub struct KeyAgentClient {
    socket: PathBuf,
    autostart: bool,
}

impl KeyAgentClient {
    /// A client for the agent at `socket` that never starts one.
    pub fn at(socket: PathBuf) -> Self {
        Self {
            socket,
            autostart: false,
        }
    }

    /// A client for this user's agent that starts it when none answers.
    pub fn autostart() -> Self {
        Self {
            socket: agent_socket_path(),
            autostart: true,
        }
    }

    pub fn is_running(&self) -> bool {
        UnixStream::connect(&self.socket).is_ok()
    }

    fn connect(&self) -> Result<UnixStream> {
        match UnixStream::connect(&self.socket) {
            Ok(stream) => Ok(stream),
            Err(error)
                if self.autostart
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
            {
                spawn_agent(&agent_log_path())?;
                for _ in 0..50 {
                    std::thread::sleep(Duration::from_millis(100));
                    if let Ok(stream) = UnixStream::connect(&self.socket) {
                        return Ok(stream);
                    }
                }
                bail!(
                    "the key agent didn't start; see {}",
                    agent_log_path().display()
                )
            }
            Err(error) => Err(anyhow!(error).context(format!(
                "the key agent isn't running at {}",
                self.socket.display()
            ))),
        }
    }
}

impl KeyAgentApi for KeyAgentClient {
    fn call(&self, request: Request) -> Result<Reply> {
        let line = encode_request(&request)?;
        let stream = self.connect()?;
        let closed = |error: std::io::Error| {
            anyhow!("the key agent closed the connection ({error}); is it running as another user?")
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(closed)?;
        (&stream).write_all(line.as_bytes()).map_err(closed)?;
        let mut reply = String::new();
        BufReader::new(&stream)
            .read_line(&mut reply)
            .map_err(closed)?;
        if reply.is_empty() {
            bail!("the key agent closed the connection; is it running as another user?");
        }
        decode_response(&reply)
    }
}
```

- [ ] **Step 5: Add `default_agent` and `running_agent`** — append to `src/memory/key_agent.rs` (above `#[cfg(test)] pub(crate) fn error_of`):

```rust
/// This user's agent, started on first use (lazily: nothing connects until
/// a request is made).
pub fn default_agent() -> Box<dyn KeyAgentApi> {
    #[cfg(unix)]
    {
        Box::new(crate::memory::agent_socket::KeyAgentClient::autostart())
    }
    #[cfg(not(unix))]
    {
        Box::new(NoAgent)
    }
}

/// The running agent, without starting one.
pub fn running_agent() -> Option<Box<dyn KeyAgentApi>> {
    #[cfg(unix)]
    {
        use crate::memory::agent_socket::{KeyAgentClient, agent_socket_path};
        let client = KeyAgentClient::at(agent_socket_path());
        if client.is_running() {
            return Some(Box::new(client));
        }
    }
    None
}

#[cfg(not(unix))]
struct NoAgent;

#[cfg(not(unix))]
impl KeyAgentApi for NoAgent {
    fn call(&self, _request: Request) -> Result<Reply> {
        bail!("the key agent needs a Unix system")
    }
}
```

- [ ] **Step 6: Add the hidden subcommand** — in `src/cli.rs`, add to `enum Commands` after the `Skill { … }` variant:

```rust
    /// Runs the key agent (started automatically when keys are needed)
    #[command(hide = true)]
    KeyAgent,
```

add to `handle_cli_command`, after the `Commands::Skill { command } => …` arm:

```rust
        Commands::KeyAgent => {
            #[cfg(unix)]
            {
                crate::memory::agent_socket::run_key_agent().await
            }
            #[cfg(not(unix))]
            {
                anyhow::bail!("the key agent needs a Unix system")
            }
        }
```

and add to `mod tests` in `src/cli.rs` (after `cli_unpair`):

```rust
    #[test]
    fn key_agent_is_a_hidden_subcommand() {
        use clap::CommandFactory;
        let cli = Cli::try_parse_from(["atem", "key-agent"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::KeyAgent)));
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("key-agent"), "{help}");
    }
```

- [ ] **Step 7: Run the tests**

Run: `cargo test memory::agent_socket cli::tests::key_agent -- --test-threads=1`
Expected: PASS.

- [ ] **Step 8: Try the real agent by hand**

```bash
cargo build
XDG_RUNTIME_DIR=$(mktemp -d) sh -c './target/debug/atem key-agent & sleep 1; ls -l "$XDG_RUNTIME_DIR/atem"; kill %1'
```
Expected: `agent.sock` listed as `srw-------`; the log line `atem key agent (protocol v1) listening on …`.

- [ ] **Step 9: Format and commit** (`agent_socket.rs` and `key_agent.rs` only; `cli.rs` by hand)

```bash
rustfmt --edition 2024 src/memory/agent_socket.rs src/memory/key_agent.rs
cargo test -- --test-threads=1
git add src/memory/agent_socket.rs src/memory/key_agent.rs src/memory/mod.rs src/cli.rs
git commit -m "feat(memory): key agent socket, client and hidden atem key-agent

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 8: Verification seals the keys and opens grants through the agent

**Files:**
- Modify: `src/memory/device_keys.rs`, `src/memory/trust.rs`, `src/memory/verification.rs`, `src/websocket_client.rs` (`handle_encryption_message`), `src/cli.rs` (`run_device_verification`)

**Interfaces:**
- Consumes: Task 4–7 `KeyAgentApi`, `KeyAgent`, `default_agent`, `LOCKED`; Task 1 `SealedDeviceKeys`, `new_storage_key`, `new_storage_kid`, `UnlockAuthKey`; Task 2 `TrustStore::{set_home, home}`.
- Produces:
  - `device_keys.rs`: `pub trait PublicKeys { fn device_pub(&self) -> [u8; 32]; fn device_sign_pub(&self) -> [u8; 32]; fn unlock_auth_pub(&self) -> [u8; 32]; }` implemented for `DeviceKeys` and `DevicePublics`; `pub struct DevicePublics { pub device_pub, pub device_sign_pub, pub unlock_auth_pub: [u8; 32] }`; `DeviceKeys::save_to` becomes `#[cfg(test)]`.
  - `trust.rs`: `TrustStore::set_pending(&mut self, astation_id: &str, device_id: &str, keys: &impl PublicKeys, astation: &AstationKeys, code: &str, transcript: &[u8; 32])`.
  - `verification.rs`: `pub enum VerificationKeys { Fresh(DeviceKeys), Sealed(DevicePublics) }` (+ `impl PublicKeys`, `impl From<DeviceKeys>`); `Handshake::start(keys: impl Into<VerificationKeys>)`, `Handshake::keys(&self) -> &VerificationKeys`, `Handshake::into_keys(self) -> VerificationKeys`; `Applied::Locked`; `pub fn apply_grant(paths: &KeyPaths, agent: &dyn KeyAgentApi, astation_id: &str, grant: Option<&GrantWire>) -> Result<Applied>`; `pub fn complete_verification(paths: &KeyPaths, agent: &dyn KeyAgentApi, astation_id: &str, keys: VerificationKeys, device_verified: &SignedWire, account_state: &SignedWire, grants: &[GrantWire]) -> Result<VerificationOutcome>`; `pub fn device_keys_for_verification(paths: &KeyPaths, agent: &dyn KeyAgentApi) -> Result<VerificationKeys>`; test-only `pub(crate) fn test_agent(paths: &KeyPaths) -> std::sync::Mutex<KeyAgent>`.

- [ ] **Step 1: Write the failing tests** — in `src/memory/verification.rs`:

In `mod tests`, replace the whole `verification_reuses_saved_device_keys` test with:

```rust
    #[test]
    fn verification_reuses_the_sealed_device_keys() {
        let empty = tempfile::tempdir().unwrap();
        let empty_paths = KeyPaths::in_dir(empty.path());
        let fresh_agent = test_agent(&empty_paths);
        assert!(matches!(
            device_keys_for_verification(&empty_paths, &fresh_agent).unwrap(),
            VerificationKeys::Fresh(_)
        ));

        let dir = tempfile::tempdir().unwrap();
        let (paths, agent, _, device_pub) = verify(dir.path(), EncryptionMode::Off);
        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        assert!(matches!(keys, VerificationKeys::Sealed(_)));
        assert_eq!(keys.device_pub(), device_pub);
    }
```

Replace the whole `verification_installs_signed_state_and_key` test with:

```rust
    #[test]
    fn verification_installs_signed_state_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, agent, _, _) = verify(dir.path(), EncryptionMode::On);
        let context = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap();
        assert_eq!(context.mode, EncryptionMode::On);
        assert!(context.seal("mem-1", "content", b"x").is_ok());
        assert!(
            !paths.legacy_device_key.exists(),
            "old plain device_key must be deleted"
        );
        assert!(!paths.device_keys.exists(), "device keys are never written in plain");
        assert!(paths.device_keys_sealed.exists() && paths.unlock_auth_key.exists());
        assert!(agent.status().unwrap().unlocked);
    }
```

In `unverified_devices_ignore_everything`, replace

```rust
        let grant = seal_k_grant(&fake, "acct", "dev-1", [9; 32], "0123abcd", [42; 32]);
        assert!(matches!(
            apply_grant(&paths, ASTATION_ID, Some(&grant)).unwrap(),
```

with

```rust
        let grant = seal_k_grant(&fake, "acct", "dev-1", [9; 32], "0123abcd", [42; 32]);
        let agent = test_agent(&paths);
        assert!(matches!(
            apply_grant(&paths, &agent, ASTATION_ID, Some(&grant)).unwrap(),
```

In `mod ceremony_tests`, add these tests at the end of the module:

```rust
    #[test]
    fn first_verification_seals_the_keys_and_hands_them_to_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::Off, None, 2),
            &[],
        )
        .unwrap();
        assert!(!paths.device_keys.exists(), "no plain device_keys any more");
        let sealed = crate::memory::storage_key::SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap();
        assert_eq!(sealed.device_id, "dev-1");
        assert_eq!(
            UnlockAuthKey::load_from(&paths.unlock_auth_key).unwrap().unwrap().public(),
            certificate.unlock_auth_pub
        );
        let status = agent.status().unwrap();
        assert!(status.unlocked && !status.escrowed, "Astation doesn't hold the storage key yet");
        assert_eq!(status.storage_kid, Some(sealed.storage_kid));
        assert_eq!(
            agent.public_keys().unwrap(),
            (certificate.device_pub, certificate.device_sign_pub)
        );
        assert_eq!(TrustStore::load_from(&paths.trust).unwrap().home(), Some(ASTATION_ID));
    }

    #[test]
    fn re_verification_with_sealed_keys_opens_grants_in_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::Off, None, 2),
            &[],
        )
        .unwrap();

        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        assert!(matches!(keys, VerificationKeys::Sealed(_)));
        let (handshake, certificate) = start(&paths, &fake, keys, 8, 3);
        let grant = seal_k_grant(&fake, "acct", "dev-1", certificate.device_pub, "0123abcd", [42; 32]);
        let outcome = complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::On, Some("0123abcd"), 4),
            &[grant],
        )
        .unwrap();
        assert!(!outcome.key_needed);
        let context = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap();
        assert!(context.seal("mem", "content", b"x").is_ok());
    }

    #[test]
    fn a_locked_agent_cannot_verify_existing_keys() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::Off, None, 2),
            &[],
        )
        .unwrap();
        // After a reboot the agent starts locked.
        let rebooted = test_agent(&paths);
        let error = crate::memory::key_agent::error_of(device_keys_for_verification(&paths, &rebooted));
        assert!(error.contains("atem cred unlock"), "{error}");
    }

    #[test]
    fn a_second_astation_does_not_move_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::Off, None, 2),
            &[],
        )
        .unwrap();

        let other = FakeAstation::new();
        let handshake = Handshake::start(device_keys_for_verification(&paths, &agent).unwrap());
        let astation = AstationKeys {
            sign_pub: other.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [9; 32],
        };
        let transcript = handshake.transcript(&astation);
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        trust.set_pending(
            "astation-2",
            "dev-1",
            handshake.keys(),
            &astation,
            &handshake.safety_code(&astation),
            &transcript,
        );
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let second = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: reveal.device_pub,
            device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub,
            transcript,
            epoch: 1,
        };
        complete_verification(
            &paths,
            &agent,
            "astation-2",
            handshake.into_keys(),
            &other.sign(&second.encode()),
            &state(&other, EncryptionMode::Off, None, 2),
            &[],
        )
        .unwrap();
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.home(), Some(ASTATION_ID));
        assert!(trust.verified("astation-2").is_some());
        assert_eq!(second.device_pub, certificate.device_pub, "one device key for both");
    }

    #[test]
    fn grants_wait_while_the_agent_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::On, Some("0123abcd"), 2),
            &[],
        )
        .unwrap();
        let grant = seal_k_grant(&fake, "acct", "dev-1", certificate.device_pub, "0123abcd", [42; 32]);
        let locked = test_agent(&paths);
        assert!(matches!(
            apply_grant(&paths, &locked, ASTATION_ID, Some(&grant)).unwrap(),
            Applied::Locked
        ));
        assert!(key_needed(&paths, ASTATION_ID).unwrap());
        assert!(matches!(
            apply_grant(&paths, &agent, ASTATION_ID, Some(&grant)).unwrap(),
            Applied::KeyInstalled(_)
        ));
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test memory::verification -- --test-threads=1`
Expected: compile errors (`test_agent`, `VerificationKeys`, `Applied::Locked`, new `complete_verification` arity, … not found).

- [ ] **Step 3: Public keys without secrets** — in `src/memory/device_keys.rs`, add after `pub struct DeviceKeys { … }`:

```rust
/// The three public keys a device reveals at verification.
pub trait PublicKeys {
    fn device_pub(&self) -> [u8; 32];
    fn device_sign_pub(&self) -> [u8; 32];
    fn unlock_auth_pub(&self) -> [u8; 32];
}

/// Public keys of a device whose secrets stay sealed (or in the key agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePublics {
    pub device_pub: [u8; 32],
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
}

impl PublicKeys for DevicePublics {
    fn device_pub(&self) -> [u8; 32] {
        self.device_pub
    }
    fn device_sign_pub(&self) -> [u8; 32] {
        self.device_sign_pub
    }
    fn unlock_auth_pub(&self) -> [u8; 32] {
        self.unlock_auth_pub
    }
}

impl PublicKeys for DeviceKeys {
    fn device_pub(&self) -> [u8; 32] {
        DeviceKeys::device_pub(self)
    }
    fn device_sign_pub(&self) -> [u8; 32] {
        DeviceKeys::device_sign_pub(self)
    }
    fn unlock_auth_pub(&self) -> [u8; 32] {
        DeviceKeys::unlock_auth_pub(self)
    }
}
```

and make the plain writer test-only — put `#[cfg(test)]` on `DeviceKeys::save_to` and replace its doc (add one) with:

```rust
    /// The plain step-1 format. Only tests write it now; the key agent seals
    /// such a file when it starts (key_agent.rs).
    #[cfg(test)]
    pub fn save_to(&self, path: &Path) -> Result<()> {
```

- [ ] **Step 4: `set_pending` takes public keys** — in `src/memory/trust.rs`, replace the import `use crate::memory::device_keys::DeviceKeys;` with `use crate::memory::device_keys::PublicKeys;`, change the `set_pending` signature's `keys: &DeviceKeys,` to `keys: &impl PublicKeys,` (the body is unchanged), and add `use crate::memory::device_keys::DeviceKeys;` as the first line inside `mod tests` (after `use super::*;`).

- [ ] **Step 5: Verification through the agent** — in `src/memory/verification.rs`:

Replace the `use crate::memory::device_keys::DeviceKeys;` line with:

```rust
use crate::memory::device_keys::{DeviceKeys, DevicePublics, PublicKeys, UnlockAuthKey};
use crate::memory::key_agent::KeyAgentApi;
use crate::memory::storage_key::{SealedDeviceKeys, new_storage_key, new_storage_kid};
```

Replace the `Handshake` struct and its `impl` with:

```rust
/// The keys a verification reveals: fresh ones (first verification, secrets
/// in hand), or this device's sealed keys, which only the key agent opens.
pub enum VerificationKeys {
    Fresh(DeviceKeys),
    Sealed(DevicePublics),
}

impl From<DeviceKeys> for VerificationKeys {
    fn from(keys: DeviceKeys) -> Self {
        Self::Fresh(keys)
    }
}

impl PublicKeys for VerificationKeys {
    fn device_pub(&self) -> [u8; 32] {
        match self {
            Self::Fresh(keys) => keys.device_pub(),
            Self::Sealed(publics) => publics.device_pub,
        }
    }
    fn device_sign_pub(&self) -> [u8; 32] {
        match self {
            Self::Fresh(keys) => keys.device_sign_pub(),
            Self::Sealed(publics) => publics.device_sign_pub,
        }
    }
    fn unlock_auth_pub(&self) -> [u8; 32] {
        match self {
            Self::Fresh(keys) => keys.unlock_auth_pub(),
            Self::Sealed(publics) => publics.unlock_auth_pub,
        }
    }
}

pub struct Handshake {
    keys: VerificationKeys,
    nonce_a: [u8; 32],
}

impl Handshake {
    pub fn start(keys: impl Into<VerificationKeys>) -> Self {
        let mut nonce_a = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_a);
        Self {
            keys: keys.into(),
            nonce_a,
        }
    }

    pub fn reveal(&self) -> Reveal {
        Reveal {
            device_pub: self.keys.device_pub(),
            device_sign_pub: self.keys.device_sign_pub(),
            unlock_auth_pub: self.keys.unlock_auth_pub(),
            nonce_a: self.nonce_a,
        }
    }

    pub fn commitment(&self) -> [u8; 32] {
        commitment_for(&self.reveal())
    }

    pub fn safety_code(&self, astation: &AstationKeys) -> String {
        safety_code(&self.reveal(), astation)
    }

    pub fn transcript(&self, astation: &AstationKeys) -> [u8; 32] {
        transcript_for(&self.commitment(), &self.nonce_a, &astation.nonce_s)
    }

    pub fn keys(&self) -> &VerificationKeys {
        &self.keys
    }

    pub fn into_keys(self) -> VerificationKeys {
        self.keys
    }
}
```

Add a variant to `enum Applied` (after `Ignored`):

```rust
    /// A key grant arrived while the key agent is locked. After
    /// `atem cred unlock`, atem asks for the key again.
    Locked,
```

Replace `apply_grant` with:

```rust
/// Installs a signed `K` grant for this verified device. The grant is opened
/// only inside the unlocked key agent; there is no plain-key fallback.
pub fn apply_grant(
    paths: &KeyPaths,
    agent: &dyn KeyAgentApi,
    astation_id: &str,
    grant: Option<&GrantWire>,
) -> Result<Applied> {
    let Some(grant) = grant else {
        return Ok(Applied::Ignored("an unsigned key grant from the relay"));
    };
    let trust = TrustStore::load_from(&paths.trust)?;
    let Some(entry) = trust.verified(astation_id) else {
        return Ok(Applied::Ignored(
            "a key grant for a device that isn't verified",
        ));
    };
    if !agent.status()?.unlocked {
        return Ok(Applied::Locked);
    }
    let opened = agent.open_grant(astation_id, grant, None)?;
    EncryptionContext::install_grant_at(
        &paths.data_keys,
        astation_id,
        &entry.data_account,
        &opened.kid,
        opened.key,
    )?;
    Ok(Applied::KeyInstalled(opened.kid))
}
```

Replace `complete_verification` (doc comment included) with:

```rust
/// Finishes verification once the user confirmed the code on this device and
/// Astation sent its signed certificate.
///
/// Everything is checked in memory first: the certificate, the signed state
/// and every grant. Fresh keys (a device's first verification) make this
/// Astation the home: they are sealed under a new storage key and handed to
/// the key agent before anything is written, so if the agent can't take
/// them nothing is saved. Then the sealed keys, the state and grants, the
/// pins and the home are written and the old plain files deleted. On any
/// failure before that point nothing is written.
pub fn complete_verification(
    paths: &KeyPaths,
    agent: &dyn KeyAgentApi,
    astation_id: &str,
    keys: VerificationKeys,
    device_verified: &SignedWire,
    account_state: &SignedWire,
    grants: &[GrantWire],
) -> Result<VerificationOutcome> {
    let mut staged = TrustStore::load_from(&paths.trust)?;
    let first = staged.verified(astation_id).is_none();
    staged.confirm(astation_id, device_verified)?;
    let changed = staged.accept_account_state(astation_id, account_state)?;
    let entry = staged
        .verified(astation_id)
        .expect("confirmed above")
        .clone();
    let state = match changed {
        Some(state) => state,
        None => stored_state(&entry)?.ok_or_else(|| anyhow!("no signed account state"))?,
    };
    check_state(&state)?;
    let opened = grants
        .iter()
        .map(|grant| match &keys {
            VerificationKeys::Fresh(fresh) => open_grant(&entry, fresh, grant),
            // The staged pins: they aren't saved until everything holds.
            VerificationKeys::Sealed(_) => agent.open_grant(astation_id, grant, Some(&entry)),
        })
        .collect::<Result<Vec<_>>>()?;
    if opened
        .iter()
        .any(|grant| Some(grant.kid.as_str()) != state.kid.as_deref())
    {
        bail!("a key grant names a different key id than the signed account state");
    }

    let sealed = match &keys {
        VerificationKeys::Fresh(fresh) => {
            let storage_key = new_storage_key();
            let storage_kid = new_storage_kid();
            let sealed = SealedDeviceKeys::seal(fresh, &entry.device_id, &storage_kid, &storage_key)?;
            agent.load_unlocked(&entry.device_id, fresh, &storage_kid, &storage_key)?;
            staged.set_home(astation_id);
            Some((sealed, fresh.unlock_auth_key()))
        }
        VerificationKeys::Sealed(_) => None,
    };

    if let Some((sealed, unlock_auth)) = &sealed {
        sealed.save_to(&paths.device_keys_sealed)?;
        unlock_auth.save_to(&paths.unlock_auth_key)?;
        remove_if_exists(&paths.device_keys_next)?;
        remove_if_exists(&paths.device_keys)?;
    }
    if first {
        // Whatever the unauthenticated path stored for this Astation (mode,
        // K, rotation history, project names) is dropped, not trusted.
        EncryptionContext::purge_unverified_at(&paths.data_keys, astation_id, &state.account)?;
    }
    EncryptionContext::update_mode_at(
        &paths.data_keys,
        astation_id,
        &state.account,
        state.mode,
        state.kid.as_deref(),
    )?;
    for grant in opened {
        EncryptionContext::install_grant_at(
            &paths.data_keys,
            astation_id,
            &entry.data_account,
            &grant.kid,
            grant.key,
        )?;
    }
    staged.save_to(&paths.trust)?;
    remove_if_exists(&paths.legacy_device_key)?;
    Ok(VerificationOutcome {
        key_needed: key_needed(paths, astation_id)?,
    })
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
```

Replace `device_keys_for_verification` (doc comment included) with:

```rust
/// The keys to verify with: this device's sealed keys when it has them (so
/// every Astation pins the same device key), fresh ones otherwise. Sealed
/// keys are revealed only while the key agent holds them unlocked; starting
/// the agent also seals a plain step-1 `device_keys` file.
pub fn device_keys_for_verification(
    paths: &KeyPaths,
    agent: &dyn KeyAgentApi,
) -> Result<VerificationKeys> {
    if !paths.device_keys_sealed.exists() && !paths.device_keys.exists() {
        return Ok(VerificationKeys::Fresh(DeviceKeys::generate()));
    }
    if !agent.status()?.unlocked {
        bail!("this device's keys are locked; run `atem cred unlock`, then `atem pair` again");
    }
    let (device_pub, device_sign_pub) = agent.public_keys()?;
    let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)?.ok_or_else(|| {
        anyhow!("unlock_auth_key is missing; remove device_keys.sealed and run `atem pair` to start over")
    })?;
    Ok(VerificationKeys::Sealed(DevicePublics {
        device_pub,
        device_sign_pub,
        unlock_auth_pub: unlock_auth.public(),
    }))
}

/// An in-process key agent over the same files, for tests.
#[cfg(test)]
pub(crate) fn test_agent(paths: &KeyPaths) -> std::sync::Mutex<crate::memory::key_agent::KeyAgent> {
    std::sync::Mutex::new(crate::memory::key_agent::KeyAgent::new(paths.clone()).unwrap())
}
```

- [ ] **Step 6: Update the existing tests to the new signatures** — in `src/memory/verification.rs`:

In `mod tests`, replace the `verify` helper with:

```rust
    /// Runs the atem side of verification against a fake Astation and returns
    /// the paths, the (unlocked) key agent, the fake, and the device public key.
    fn verify(
        dir: &std::path::Path,
        mode: EncryptionMode,
    ) -> (KeyPaths, std::sync::Mutex<crate::memory::key_agent::KeyAgent>, FakeAstation, [u8; 32]) {
        let paths = KeyPaths::in_dir(dir);
        let agent = test_agent(&paths);
        std::fs::write(&paths.legacy_device_key, [1u8; 32]).unwrap();
        let fake = FakeAstation::new();
        let handshake = Handshake::start(DeviceKeys::generate());
        let astation = AstationKeys {
            sign_pub: fake.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [7; 32],
        };
        let code = handshake.safety_code(&astation);
        let transcript = handshake.transcript(&astation);
        let mut trust = TrustStore::default();
        trust.set_pending(
            ASTATION_ID,
            "dev-1",
            handshake.keys(),
            &astation,
            &code,
            &transcript,
        );
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let certificate = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: reveal.device_pub,
            device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub,
            transcript,
            epoch: 1,
        };
        let grants = if mode.requires_key() {
            vec![seal_k_grant(
                &fake,
                "acct",
                "dev-1",
                reveal.device_pub,
                "0123abcd",
                [42; 32],
            )]
        } else {
            vec![]
        };
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &signed_state(&fake, mode, 1),
            &grants,
        )
        .unwrap();
        (paths, agent, fake, reveal.device_pub)
    }
```

Then, in the rest of `mod tests`, replace every `let (paths, _, _) = verify(` with `let (paths, _, _, _) = verify(` and every `let (paths, fake, _) = verify(` with `let (paths, _, fake, _) = verify(`.

In `mod ceremony_tests`:

Change the `start` helper's parameter `keys: DeviceKeys,` to `keys: impl Into<VerificationKeys>,` (body unchanged).

In `replayed_old_certificate_cannot_roll_a_verified_device_back` and `legitimate_re_verification_keeps_mode_and_key`, add `let agent = test_agent(&paths);` right after `let paths = KeyPaths::in_dir(dir.path());`; in both, change every `complete_verification(\n            &paths,\n            ASTATION_ID,` to `complete_verification(\n            &paths,\n            &agent,\n            ASTATION_ID,`; change `device_keys_for_verification(&paths).unwrap()` to `device_keys_for_verification(&paths, &agent).unwrap()`; and in the first test change `apply_grant(&paths, ASTATION_ID, Some(&grant)).unwrap();` to `apply_grant(&paths, &agent, ASTATION_ID, Some(&grant)).unwrap();`.

Replace `assert_nothing_written` with:

```rust
    /// What a first verification attempt may have left on disk.
    fn assert_nothing_written(paths: &KeyPaths) {
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(
            trust.verified(ASTATION_ID).is_none(),
            "no verified entry may be saved"
        );
        assert!(
            !paths.device_keys.exists() && !paths.device_keys_sealed.exists(),
            "device keys must not be written"
        );
        assert!(!paths.unlock_auth_key.exists(), "unlock_auth_key must not be written");
        assert!(!paths.data_keys.exists(), "data_keys must not be written");
        assert!(
            paths.legacy_device_key.exists(),
            "the old device_key must not be deleted"
        );
    }
```

In `first_verification`, add `let agent = test_agent(&paths);` after `let paths = KeyPaths::in_dir(dir);` and change its `complete_verification(\n            &paths,\n            ASTATION_ID,` to `complete_verification(\n            &paths,\n            &agent,\n            ASTATION_ID,`.

- [ ] **Step 7: Route the WebSocket handler through the agent** — in `src/websocket_client.rs`, replace `handle_encryption_message` (from `pub async fn handle_encryption_message(` to the end of its body, before `async fn finish_encryption_migration`) with:

```rust
    pub async fn handle_encryption_message(
        &self,
        message: &AstationMessage,
    ) -> Result<Option<String>> {
        use crate::memory::verification::{apply_account_state, apply_grant, key_needed, Applied, KeyPaths};

        if !matches!(message, AstationMessage::EncryptionMode { .. } | AstationMessage::KeyGrant { .. }) {
            return Ok(None);
        }
        let Some(astation_id) = self.connected_astation_id.clone() else {
            return Ok(Some("Ignored an encryption message that arrived before Astation's identity".into()));
        };
        let paths = KeyPaths::default_paths();
        let agent = crate::memory::key_agent::default_agent();
        let applied = match message {
            AstationMessage::EncryptionMode { account_state } => apply_account_state(&paths, &astation_id, account_state.as_ref())?,
            AstationMessage::KeyGrant { grant } => apply_grant(&paths, agent.as_ref(), &astation_id, grant.as_ref())?,
            _ => unreachable!("filtered above"),
        };
        let request_key = || async {
            // Astation answers only for the device key it pinned, so ask with exactly that one.
            let trust = crate::memory::trust::TrustStore::load_from(&paths.trust)?;
            let public_key = trust
                .verified(&astation_id)
                .ok_or_else(|| anyhow!("this device isn't verified with this Astation"))?
                .device_pub
                .clone();
            self.send_message(AstationMessage::KeyRequest { public_key }).await?;
            Ok::<_, anyhow::Error>(Some("Encryption key requested from Astation".to_string()))
        };
        match applied {
            Applied::Ignored(reason) => Ok(Some(format!("Ignored {reason}"))),
            Applied::Locked => Ok(Some(format!("Ignored a key grant: {}", crate::memory::key_agent::LOCKED))),
            Applied::Unchanged => {
                // A repeat of the stored state still asks for K if it is missing
                // (e.g. a keyRequest or grant was lost earlier).
                if key_needed(&paths, &astation_id)? {
                    return request_key().await;
                }
                Ok(Some("Account encryption state unchanged".into()))
            }
            Applied::ModeChanged(state) => {
                if key_needed(&paths, &astation_id)? {
                    return request_key().await;
                }
                self.finish_encryption_migration(&astation_id, state.kid).await
            }
            Applied::KeyInstalled(kid) => self.finish_encryption_migration(&astation_id, Some(kid)).await,
        }
    }
```

- [ ] **Step 8: `atem pair` verifies through the agent** — in `src/cli.rs`, `run_device_verification`:

Replace

```rust
    let paths = KeyPaths::default_paths();
    let device_id = crate::config::AtemConfig::ensure_instance_id();
    let handshake = Handshake::start(device_keys_for_verification(&paths)?);
```

with

```rust
    let paths = KeyPaths::default_paths();
    let device_id = crate::config::AtemConfig::ensure_instance_id();
    let agent = crate::memory::key_agent::default_agent();
    let handshake = Handshake::start(device_keys_for_verification(&paths, agent.as_ref())?);
```

and replace

```rust
                    let outcome = complete_verification(
                        &paths,
                        astation_id,
```

with

```rust
                    let outcome = complete_verification(
                        &paths,
                        agent.as_ref(),
                        astation_id,
```

- [ ] **Step 9: Run the tests**

Run: `cargo test -- --test-threads=1`
Expected: PASS (all of `memory::verification`, `memory::trust`, `memory::grant`, `memory::kat_tests`, `memory::e2e_tests`, `memory::crypto` included).

- [ ] **Step 10: Format and commit** (`device_keys.rs`, `trust.rs` only; the others by hand)

```bash
rustfmt --edition 2024 src/memory/device_keys.rs src/memory/trust.rs
cargo clippy --all-targets --all-features
git add src/memory/device_keys.rs src/memory/trust.rs src/memory/verification.rs src/websocket_client.rs src/cli.rs
git commit -m "feat(memory): seal device keys at verification and open grants in the key agent

🤖 Built with SMT <smt@agora.build>"
```

---
### Task 9: Wire messages, and carrying unlock and rotation over the Astation link

**Files:**
- Modify: `src/websocket_client.rs` (`AstationMessage`, tests), `src/memory/mod.rs`
- Create: `src/memory/unlock.rs`

**Interfaces:**
- Consumes: Task 4–6 `KeyAgentApi::{begin_unlock, finish_unlock, begin_rotation, confirm_rotation, status}`, `build_unlock_request`; Task 1 `UnlockAuthKey`, `UnlockGrantWire`; Task 2 `TrustStore::home`; Task 3 `fake_astation` (tests).
- Produces:
  - `AstationMessage::UnlockRequest { request: String, signature: String }`, `UnlockGrant { grant: SignedWire, encapped_key: String, ciphertext: String }`, `UnlockDenied { reason: String }`, `StorageKeyRotate { rotate: SignedWire, encapped_key: String, ciphertext: String }`, `StorageKeyAck { ack: SignedWire }`, `StorageKeyConfirm { confirm: SignedWire }`.
  - `unlock.rs`: `pub const UNLOCK_TIMEOUT: Duration` (300 s), `pub const ROTATION_TIMEOUT: Duration` (60 s); `pub(crate) trait AstationLink { async fn send(&mut self, message: AstationMessage) -> Result<()>; async fn recv(&mut self) -> Option<AstationMessage>; }` implemented for `AstationClient`; `pub fn boot_id() -> String`; `pub(crate) async fn unlock_via<L: AstationLink>(link: &mut L, agent: &dyn KeyAgentApi, paths: &KeyPaths, astation_id: &str, wait: Duration) -> Result<String>`; `pub(crate) async fn rotate_via<L: AstationLink>(link: &mut L, agent: &dyn KeyAgentApi, astation_id: &str, wait: Duration) -> Result<String>`; `pub(crate) async fn escrow_if_needed<L: AstationLink>(link: &mut L, agent: &dyn KeyAgentApi, paths: &KeyPaths, astation_id: &str) -> Result<Option<String>>`.

- [ ] **Step 1: Write the failing message test** — append inside `mod tests` of `src/websocket_client.rs` (after `verify_messages_round_trip`):

```rust
    #[test]
    fn unlock_and_storage_messages_round_trip() {
        use crate::memory::statements::SignedWire;
        let signed = SignedWire { statement: "s".into(), signature: "g".into() };
        let messages = vec![
            (
                AstationMessage::UnlockRequest { request: "r".into(), signature: "g".into() },
                r#"{"type":"unlockRequest","data":{"request":"r","signature":"g"}}"#,
            ),
            (
                AstationMessage::UnlockGrant { grant: signed.clone(), encapped_key: "e".into(), ciphertext: "c".into() },
                r#"{"type":"unlockGrant","data":{"grant":{"statement":"s","signature":"g"},"encapped_key":"e","ciphertext":"c"}}"#,
            ),
            (
                AstationMessage::UnlockDenied { reason: "no".into() },
                r#"{"type":"unlockDenied","data":{"reason":"no"}}"#,
            ),
            (
                AstationMessage::StorageKeyRotate { rotate: signed.clone(), encapped_key: "e".into(), ciphertext: "c".into() },
                r#"{"type":"storageKeyRotate","data":{"rotate":{"statement":"s","signature":"g"},"encapped_key":"e","ciphertext":"c"}}"#,
            ),
            (
                AstationMessage::StorageKeyAck { ack: signed.clone() },
                r#"{"type":"storageKeyAck","data":{"ack":{"statement":"s","signature":"g"}}}"#,
            ),
            (
                AstationMessage::StorageKeyConfirm { confirm: signed },
                r#"{"type":"storageKeyConfirm","data":{"confirm":{"statement":"s","signature":"g"}}}"#,
            ),
        ];
        for (message, json) in messages {
            assert_eq!(serde_json::to_string(&message).unwrap(), json);
            let parsed: AstationMessage = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        }
    }
```

- [ ] **Step 2: Write the failing link tests** — in `src/memory/mod.rs`, after `pub mod key_agent;` add `pub mod unlock;`, and create `src/memory/unlock.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::fake_astation::{ASTATION_ID, DEVICE_ID, FakeKeyServer, sealed_device};
    use crate::memory::key_agent::{KeyAgent, error_of};
    use crate::memory::statements::SignedWire;
    use crate::memory::storage_key::{SealedDeviceKeys, StorageRotation};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const WAIT: Duration = Duration::from_secs(5);

    /// An Astation connection whose far end is a `FakeKeyServer`; unrelated
    /// traffic arrives before every answer, as it does on the real socket.
    struct ScriptedLink {
        server: FakeKeyServer,
        inbox: VecDeque<AstationMessage>,
        deny: Option<String>,
        silent: bool,
    }

    impl ScriptedLink {
        fn new(server: FakeKeyServer) -> Self {
            Self {
                server,
                inbox: VecDeque::new(),
                deny: None,
                silent: false,
            }
        }
    }

    impl AstationLink for ScriptedLink {
        async fn send(&mut self, message: AstationMessage) -> Result<()> {
            if self.silent {
                return Ok(());
            }
            self.inbox
                .push_back(AstationMessage::EncryptionMode { account_state: None });
            match message {
                AstationMessage::UnlockRequest { request, signature } => {
                    let reply = match &self.deny {
                        Some(reason) => AstationMessage::UnlockDenied {
                            reason: reason.clone(),
                        },
                        None => {
                            let grant = self.server.grant_unlock(&SignedWire {
                                statement: request,
                                signature,
                            })?;
                            AstationMessage::UnlockGrant {
                                grant: grant.grant,
                                encapped_key: grant.encapped_key,
                                ciphertext: grant.ciphertext,
                            }
                        }
                    };
                    self.inbox.push_back(reply);
                }
                AstationMessage::StorageKeyRotate {
                    rotate,
                    encapped_key,
                    ciphertext,
                } => {
                    let ack = self.server.accept_rotation(&StorageRotation {
                        rotate,
                        encapped_key,
                        ciphertext,
                    })?;
                    self.inbox.push_back(AstationMessage::StorageKeyAck { ack });
                }
                AstationMessage::StorageKeyConfirm { confirm } => self.server.confirm(&confirm)?,
                _ => {}
            }
            Ok(())
        }

        async fn recv(&mut self) -> Option<AstationMessage> {
            self.inbox.pop_front()
        }
    }

    fn agent(paths: &KeyPaths) -> Mutex<KeyAgent> {
        Mutex::new(KeyAgent::new(paths.clone()).unwrap())
    }

    #[tokio::test]
    async fn unlock_then_rotate_over_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        let kid = unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(kid, "0a1b2c3d");
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        let new_kid = rotate_via(&mut link, &agent, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_ne!(new_kid, "0a1b2c3d");
        assert_eq!(
            link.server.storage_keys.keys().cloned().collect::<Vec<_>>(),
            vec![new_kid.clone()]
        );
        assert!(link.server.pending.is_none());
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            new_kid
        );
        agent.lock_keys().unwrap();
        assert_eq!(
            unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
                .await
                .unwrap(),
            new_kid
        );
    }

    #[tokio::test]
    async fn a_denied_unlock_leaves_the_keys_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.deny = Some("Denied on the Mac".into());
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(error.contains("Denied on the Mac"), "{error}");
        assert!(!agent.status().unwrap().unlocked);
    }

    #[tokio::test]
    async fn a_silent_astation_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.silent = true;
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(error.contains("closed"), "{error}");
    }

    #[tokio::test]
    async fn keys_astation_does_not_hold_yet_are_escrowed_once() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let storage_key = [9u8; 32];
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "0a1b2c3d", &storage_key)
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        server.storage_keys.clear();
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &storage_key)
            .unwrap();
        let mut link = ScriptedLink::new(server);
        assert_eq!(
            escrow_if_needed(&mut link, &agent, &paths, "astation-2")
                .await
                .unwrap(),
            None,
            "only the home Astation holds the storage key"
        );
        assert_eq!(
            escrow_if_needed(&mut link, &agent, &paths, ASTATION_ID)
                .await
                .unwrap()
                .as_deref(),
            Some("0a1b2c3d")
        );
        assert_eq!(link.server.storage_keys.get("0a1b2c3d"), Some(&storage_key));
        assert_eq!(
            escrow_if_needed(&mut link, &agent, &paths, ASTATION_ID)
                .await
                .unwrap(),
            None
        );
    }

    #[test]
    fn boot_id_is_trimmed_or_empty() {
        let id = boot_id();
        assert_eq!(id, id.trim());
    }
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test memory::unlock websocket_client::tests::unlock_and_storage -- --test-threads=1`
Expected: compile errors (`UnlockRequest` variant, `AstationLink`, `unlock_via`, … not found).

- [ ] **Step 4: Add the message variants** — in `src/websocket_client.rs`, inside `enum AstationMessage`, insert before `#[serde(rename = "encryptionMigrationComplete")]`:

```rust
    /// Atem → Astation: an `atem-unlock-request-v1` statement (base64) and
    /// its Ed25519 signature by this device's unlock-auth key.
    #[serde(rename = "unlockRequest")]
    UnlockRequest { request: String, signature: String },

    /// Astation → Atem: after Touch ID, the storage key sealed to the
    /// request's `e_pub`, with a signed `atem-unlock-grant-v1`.
    #[serde(rename = "unlockGrant")]
    UnlockGrant { grant: crate::memory::statements::SignedWire, encapped_key: String, ciphertext: String },

    /// Astation → Atem: the unlock was denied.
    #[serde(rename = "unlockDenied")]
    UnlockDenied { reason: String },

    /// Atem → Astation: a storage key sealed to Astation's encryption key,
    /// with a device-signed `atem-storage-rotate-v1`.
    #[serde(rename = "storageKeyRotate")]
    StorageKeyRotate { rotate: crate::memory::statements::SignedWire, encapped_key: String, ciphertext: String },

    /// Astation → Atem: the storage key is stored as pending (`atem-storage-ack-v1`).
    #[serde(rename = "storageKeyAck")]
    StorageKeyAck { ack: crate::memory::statements::SignedWire },

    /// Atem → Astation: this device switched to the new storage key
    /// (device-signed `atem-storage-confirm-v1`); Astation drops the old one.
    #[serde(rename = "storageKeyConfirm")]
    StorageKeyConfirm { confirm: crate::memory::statements::SignedWire },

```

- [ ] **Step 5: Implement the link side** — put this above the test module in `src/memory/unlock.rs`:

```rust
//! The CLI side of unlock and storage-key rotation: carries the key agent's
//! requests to the home Astation and Astation's answers back. The storage
//! key never passes through here in plain form.
//! See designs/e2e-encryption.md "Unlock policy" and "Keys on disk (atem)".
use anyhow::{Result, anyhow, bail};
use std::time::Duration;

use crate::memory::device_keys::UnlockAuthKey;
use crate::memory::key_agent::{KeyAgentApi, build_unlock_request};
use crate::memory::storage_key::UnlockGrantWire;
use crate::memory::trust::TrustStore;
use crate::memory::verification::KeyPaths;
use crate::websocket_client::{AstationClient, AstationMessage};

/// Touch ID may take a while: the user may have to walk to the Mac.
pub const UNLOCK_TIMEOUT: Duration = Duration::from_secs(300);
/// Rotation needs no prompt, only a device signature.
pub const ROTATION_TIMEOUT: Duration = Duration::from_secs(60);

/// What unlock and rotation need from an Astation connection.
pub(crate) trait AstationLink {
    async fn send(&mut self, message: AstationMessage) -> Result<()>;
    async fn recv(&mut self) -> Option<AstationMessage>;
}

impl AstationLink for AstationClient {
    async fn send(&mut self, message: AstationMessage) -> Result<()> {
        self.send_message(message).await
    }

    async fn recv(&mut self) -> Option<AstationMessage> {
        self.recv_message_async().await
    }
}

/// `/proc/sys/kernel/random/boot_id`; empty where the OS has none.
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|id| id.trim().to_string())
        .unwrap_or_default()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The next message `wanted` accepts, skipping unrelated traffic.
async fn next_reply<L: AstationLink>(
    link: &mut L,
    wanted: fn(&AstationMessage) -> bool,
) -> Result<AstationMessage> {
    loop {
        match link.recv().await {
            Some(message) if wanted(&message) => return Ok(message),
            Some(_) => continue,
            None => bail!("Astation's connection closed before it answered"),
        }
    }
}

/// Unlocks the agent through `astation_id` (the home Astation): the agent's
/// single-use key goes out in a request signed by the unlock-auth key, and
/// Astation's sealed, signed answer goes straight back to the agent.
/// Returns the storage key id Astation released.
pub(crate) async fn unlock_via<L: AstationLink>(
    link: &mut L,
    agent: &dyn KeyAgentApi,
    paths: &KeyPaths,
    astation_id: &str,
    wait: Duration,
) -> Result<String> {
    let challenge = agent.begin_unlock(astation_id)?;
    let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)?.ok_or_else(|| {
        anyhow!("unlock_auth_key is missing; run `atem pair` to verify this device again")
    })?;
    let request = build_unlock_request(&challenge, &boot_id(), now_secs(), &unlock_auth);
    link.send(AstationMessage::UnlockRequest {
        request: request.statement.clone(),
        signature: request.signature,
    })
    .await?;
    let reply = tokio::time::timeout(
        wait,
        next_reply(link, |message| {
            matches!(
                message,
                AstationMessage::UnlockGrant { .. } | AstationMessage::UnlockDenied { .. }
            )
        }),
    )
    .await
    .map_err(|_| anyhow!("timed out waiting for Astation to approve the unlock"))??;
    match reply {
        AstationMessage::UnlockGrant {
            grant,
            encapped_key,
            ciphertext,
        } => agent.finish_unlock(
            astation_id,
            &request.statement,
            &UnlockGrantWire {
                grant,
                encapped_key,
                ciphertext,
            },
        ),
        AstationMessage::UnlockDenied { reason } => bail!("Astation denied the unlock: {reason}"),
        _ => unreachable!("filtered by next_reply"),
    }
}

/// Runs the three rotation phases with `astation_id`. Returns the new
/// storage key id.
pub(crate) async fn rotate_via<L: AstationLink>(
    link: &mut L,
    agent: &dyn KeyAgentApi,
    astation_id: &str,
    wait: Duration,
) -> Result<String> {
    let rotation = agent.begin_rotation(astation_id)?;
    link.send(AstationMessage::StorageKeyRotate {
        rotate: rotation.rotate,
        encapped_key: rotation.encapped_key,
        ciphertext: rotation.ciphertext,
    })
    .await?;
    let ack = match tokio::time::timeout(
        wait,
        next_reply(link, |message| {
            matches!(message, AstationMessage::StorageKeyAck { .. })
        }),
    )
    .await
    .map_err(|_| anyhow!("timed out waiting for Astation to store the new storage key"))??
    {
        AstationMessage::StorageKeyAck { ack } => ack,
        _ => unreachable!("filtered by next_reply"),
    };
    let (storage_kid, confirm) = agent.confirm_rotation(astation_id, &ack)?;
    link.send(AstationMessage::StorageKeyConfirm { confirm })
        .await?;
    Ok(storage_kid)
}

/// Hands the storage key to the home Astation when the agent holds one
/// Astation doesn't have yet (after a first verification, or after the
/// agent sealed a plain step-1 file). `None` when there is nothing to send.
pub(crate) async fn escrow_if_needed<L: AstationLink>(
    link: &mut L,
    agent: &dyn KeyAgentApi,
    paths: &KeyPaths,
    astation_id: &str,
) -> Result<Option<String>> {
    if TrustStore::load_from(&paths.trust)?.home() != Some(astation_id) {
        return Ok(None);
    }
    let status = agent.status()?;
    if !status.unlocked || status.escrowed {
        return Ok(None);
    }
    rotate_via(link, agent, astation_id, ROTATION_TIMEOUT)
        .await
        .map(Some)
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test memory::unlock websocket_client::tests::unlock_and_storage -- --test-threads=1`
Expected: PASS.

- [ ] **Step 7: Format and commit** (`unlock.rs` only)

```bash
rustfmt --edition 2024 src/memory/unlock.rs
git add src/memory/unlock.rs src/memory/mod.rs src/websocket_client.rs
git commit -m "feat(memory): unlock and storage-key messages over the Astation link

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 10: `atem cred status|unlock|lock`, and `atem pair` escrows the storage key

**Files:**
- Modify: `src/memory/unlock.rs`, `src/websocket_client.rs` (`connected_astation_id`), `src/cli.rs` (`Commands`, `CredCommands`, dispatch, `run_device_verification`, tests)

**Interfaces:**
- Consumes: Task 9 `unlock_via`, `rotate_via`, `escrow_if_needed`, `UNLOCK_TIMEOUT`, `ROTATION_TIMEOUT`; Task 7 `default_agent`, `running_agent`; Task 4 `AgentStatus`; Task 8 `key_needed`; `crate::auth::require_pairing`; `AstationClient::{new, connect_without_pairing, connect_relay_identity_without_pairing, send_message, recv_message_async, handle_encryption_message}`.
- Produces:
  - `cli.rs`: `Commands::Cred { command: CredCommands }`, `pub enum CredCommands { Status, Unlock, Lock }`.
  - `websocket_client.rs`: `pub fn connected_astation_id(&self) -> Option<&str>`.
  - `unlock.rs`: `pub enum AgentState { NotRunning, Running(AgentStatus), Unreachable(String) }`, `pub fn status_report(trust: &TrustStore, astation_id: &str, agent: &AgentState, sealed_kid: Option<&str>) -> String`, `pub async fn handle_cred(command: crate::cli::CredCommands) -> Result<()>`.

- [ ] **Step 1: Write the failing tests** — append inside `mod tests` of `src/memory/unlock.rs`:

```rust
    use crate::memory::key_agent::AgentStatus;
    use crate::memory::trust::TrustStore;

    #[test]
    fn status_report_shows_each_agent_state() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(
            status_report(&trust, ASTATION_ID, &AgentState::NotRunning, Some("0a1b2c3d")),
            "Verified: yes  (safety code AAAA-BBBB-CCCC)\n\
             Home Astation: astation-1\n\
             Key agent: not running (starts with 'atem cred unlock')\n\
             Storage key: 0a1b2c3d\n"
        );
        let waiting = AgentState::Running(AgentStatus {
            unlocked: true,
            storage_kid: Some("4e5f6a7b".into()),
            escrowed: false,
        });
        let report = status_report(&trust, ASTATION_ID, &waiting, None);
        assert!(report.contains("Key agent: unlocked\n"), "{report}");
        assert!(
            report.contains("Storage key: 4e5f6a7b  (not yet held by Astation; run 'atem cred unlock')"),
            "{report}"
        );
        let locked = AgentState::Running(AgentStatus {
            unlocked: false,
            storage_kid: Some("0a1b2c3d".into()),
            escrowed: false,
        });
        assert!(
            status_report(&trust, ASTATION_ID, &locked, None)
                .contains("Key agent: locked (run 'atem cred unlock')")
        );
        let broken = AgentState::Unreachable("protocol v2".into());
        assert!(
            status_report(&trust, ASTATION_ID, &broken, Some("0a1b2c3d"))
                .contains("Key agent: not answering (protocol v2)")
        );
        let report = status_report(&TrustStore::default(), ASTATION_ID, &AgentState::NotRunning, None);
        assert!(report.starts_with("Verified: no"), "{report}");
        assert!(report.contains("Home Astation: none (verify with 'atem pair')"));
        assert!(report.contains("Storage key: none"));
    }
```

and inside `mod tests` of `src/cli.rs` (after `key_agent_is_a_hidden_subcommand`):

```rust
    #[test]
    fn cred_commands_parse() {
        for (arg, expected) in [("status", "Status"), ("unlock", "Unlock"), ("lock", "Lock")] {
            let cli = Cli::try_parse_from(["atem", "cred", arg]).unwrap();
            match cli.command {
                Some(Commands::Cred { command }) => assert_eq!(format!("{command:?}"), expected),
                _ => panic!("expected atem cred {arg}"),
            }
        }
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test memory::unlock cli::tests::cred_commands -- --test-threads=1`
Expected: compile errors (`status_report`, `AgentState`, `Commands::Cred` not found).

- [ ] **Step 3: Add the CLI commands** — in `src/cli.rs`:

Add to `enum Commands`, right before the hidden `KeyAgent` variant:

```rust
    /// This device's keys: unlock with Touch ID on your Mac, lock, status (see designs/e2e-encryption.md)
    Cred {
        #[command(subcommand)]
        command: CredCommands,
    },
```

Add after the `VaultCommands` enum:

```rust
#[derive(clap::Subcommand, Debug)]
pub enum CredCommands {
    /// Show whether this device is verified, its home Astation and its key agent
    Status,
    /// Unlock this device's keys (approve with Touch ID on your Mac)
    Unlock,
    /// Wipe the unlocked keys from the key agent's memory
    Lock,
}
```

Add to `handle_cli_command`, before the `Commands::KeyAgent` arm:

```rust
        Commands::Cred { command } => crate::memory::unlock::handle_cred(command).await,
```

- [ ] **Step 4: Expose the connected Astation** — in `src/websocket_client.rs`, add to `impl AstationClient` (right after `pub fn new()`'s closing brace):

```rust
    /// The Astation this client authenticated with, once it said who it is.
    pub fn connected_astation_id(&self) -> Option<&str> {
        self.connected_astation_id.as_deref()
    }
```

- [ ] **Step 5: Implement `atem cred`** — in `src/memory/unlock.rs`, extend the imports:

```rust
use anyhow::Context;

use crate::memory::key_agent::{AgentStatus, default_agent, running_agent};
use crate::memory::storage_key::SealedDeviceKeys;
```

and add above the test module:

```rust
/// What `atem cred status` learned about the key agent.
pub enum AgentState {
    NotRunning,
    Running(AgentStatus),
    Unreachable(String),
}

/// `atem cred status`, for the configured Astation `astation_id`.
pub fn status_report(
    trust: &TrustStore,
    astation_id: &str,
    agent: &AgentState,
    sealed_kid: Option<&str>,
) -> String {
    let (agent_line, storage_kid, waiting) = match agent {
        AgentState::NotRunning => (
            "not running (starts with 'atem cred unlock')".to_string(),
            sealed_kid.map(str::to_string),
            false,
        ),
        AgentState::Unreachable(error) => (
            format!("not answering ({error})"),
            sealed_kid.map(str::to_string),
            false,
        ),
        AgentState::Running(status) if status.unlocked => (
            "unlocked".to_string(),
            status.storage_kid.clone(),
            !status.escrowed,
        ),
        AgentState::Running(status) => (
            "locked (run 'atem cred unlock')".to_string(),
            status.storage_kid.clone(),
            false,
        ),
    };
    let storage_line = match (storage_kid, waiting) {
        (Some(kid), true) => format!(
            "Storage key: {kid}  (not yet held by Astation; run 'atem cred unlock')"
        ),
        (Some(kid), false) => format!("Storage key: {kid}"),
        (None, _) => "Storage key: none".to_string(),
    };
    format!(
        "{}\nHome Astation: {}\nKey agent: {agent_line}\n{storage_line}\n",
        trust.verification_line(astation_id),
        trust.home().unwrap_or("none (verify with 'atem pair')"),
    )
}

/// `atem cred …` (tier 2: needs a pairing with Astation).
pub async fn handle_cred(command: crate::cli::CredCommands) -> Result<()> {
    use crate::cli::CredCommands;
    let paired = crate::auth::require_pairing("atem cred")?;
    let paths = KeyPaths::default_paths();
    match command {
        CredCommands::Status => {
            let trust = TrustStore::load_from(&paths.trust)?;
            let sealed_kid = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .ok()
                .flatten()
                .map(|sealed| sealed.storage_kid);
            let agent = match running_agent() {
                None => AgentState::NotRunning,
                Some(agent) => match agent.status() {
                    Ok(status) => AgentState::Running(status),
                    Err(error) => AgentState::Unreachable(format!("{error:#}")),
                },
            };
            print!(
                "{}",
                status_report(&trust, &paired.astation_id, &agent, sealed_kid.as_deref())
            );
            Ok(())
        }
        CredCommands::Unlock => unlock_command(&paths).await,
        CredCommands::Lock => {
            match running_agent() {
                None => println!("The key agent isn't running; this device's keys are locked."),
                Some(agent) => {
                    agent.lock_keys()?;
                    println!("Locked: the key agent wiped this device's keys from memory.");
                }
            }
            Ok(())
        }
    }
}

/// Connects to the home Astation without pairing: locally when the local
/// Astation is the home one, else through its relay identity room.
async fn connect_home(home: &str) -> Result<AstationClient> {
    let config = crate::config::AtemConfig::load()?;
    let mut local = AstationClient::new();
    if local
        .connect_without_pairing(config.astation_ws())
        .await
        .is_ok()
        && local.connected_astation_id() == Some(home)
    {
        return Ok(local);
    }
    let mut client = AstationClient::new();
    client
        .connect_relay_identity_without_pairing(config.astation_relay_url(), home)
        .await
        .with_context(|| format!("couldn't reach this device's home Astation ({home})"))?;
    if client.connected_astation_id() != Some(home) {
        bail!("connected to a different Astation than this device's home ({home})");
    }
    Ok(client)
}

async fn unlock_command(paths: &KeyPaths) -> Result<()> {
    let trust = TrustStore::load_from(&paths.trust)?;
    let home = trust
        .home()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("This device isn't verified yet. Run `atem pair` first."))?;
    let agent = default_agent();
    let status = agent.status()?;
    if status.unlocked && status.escrowed {
        println!(
            "Already unlocked (storage key {}).",
            status.storage_kid.unwrap_or_default()
        );
        return Ok(());
    }
    let mut client = connect_home(&home).await?;
    if status.unlocked {
        // Unlocked, but Astation doesn't hold the storage key yet.
        if let Some(kid) = escrow_if_needed(&mut client, agent.as_ref(), paths, &home).await? {
            println!("Astation now holds this device's storage key ({kid}).");
        }
    } else {
        println!("Approve on your Mac with Touch ID…");
        unlock_via(&mut client, agent.as_ref(), paths, &home, UNLOCK_TIMEOUT).await?;
        println!("✅ Unlocked.");
        match rotate_via(&mut client, agent.as_ref(), &home, ROTATION_TIMEOUT).await {
            Ok(kid) => println!("Storage key rotated ({kid})."),
            Err(error) => eprintln!(
                "⚠️  The storage key wasn't rotated ({error:#}); it rotates at the next unlock."
            ),
        }
    }
    if crate::memory::verification::key_needed(paths, &home)? {
        request_missing_key(&mut client, &trust, &home).await?;
    }
    Ok(())
}

/// A grant that arrived while the keys were locked was ignored: ask again.
async fn request_missing_key(
    client: &mut AstationClient,
    trust: &TrustStore,
    home: &str,
) -> Result<()> {
    let public_key = trust
        .verified(home)
        .ok_or_else(|| anyhow!("this device isn't verified with its home Astation"))?
        .device_pub
        .clone();
    client
        .send_message(AstationMessage::KeyRequest { public_key })
        .await?;
    println!("Encryption key requested from Astation…");
    let waited = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match client.recv_message_async().await {
                Some(message @ AstationMessage::KeyGrant { .. }) => {
                    return client.handle_encryption_message(&message).await;
                }
                Some(_) => continue,
                None => bail!("Astation closed the connection"),
            }
        }
    })
    .await;
    match waited {
        Ok(Ok(Some(status))) => println!("{status}"),
        Ok(Ok(None)) => {}
        Ok(Err(error)) => eprintln!("⚠️  {error:#}"),
        Err(_) => eprintln!(
            "⚠️  Astation didn't send the key yet; it arrives on a later connection."
        ),
    }
    Ok(())
}
```

- [ ] **Step 6: `atem pair` hands Astation the storage key** — in `src/cli.rs`, `run_device_verification`, replace

```rust
                    println!("✅ Device verified with Astation (safety code {code}).");
```

with

```rust
                    println!("✅ Device verified with Astation (safety code {code}).");
                    match crate::memory::unlock::escrow_if_needed(&mut *client, agent.as_ref(), &paths, astation_id).await {
                        Ok(Some(storage_kid)) => println!("Astation holds this device's storage key ({storage_kid})."),
                        Ok(None) => {}
                        Err(error) => eprintln!(
                            "⚠️  Astation didn't take this device's storage key yet ({error:#}). Run 'atem cred unlock' before this machine restarts, or its keys can't be unlocked."
                        ),
                    }
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -- --test-threads=1`
Expected: PASS.

- [ ] **Step 8: Smoke-test the commands**

```bash
cargo build
./target/debug/atem cred --help
./target/debug/atem cred status
./scripts/run-local-dev-tests.sh
```
Expected: `--help` lists `status`, `unlock`, `lock` and not `key-agent`; on an unpaired machine `cred status` fails with "atem cred works only on machines paired with your Astation…"; on a paired one it prints the four status lines. The smoke script shows only the 3 pre-existing `atem list` failures.

- [ ] **Step 9: Format and commit** (`unlock.rs` only)

```bash
rustfmt --edition 2024 src/memory/unlock.rs
cargo clippy --all-targets --all-features
git add src/memory/unlock.rs src/websocket_client.rs src/cli.rs
git commit -m "feat(cred): atem cred status/unlock/lock; atem pair escrows the storage key

🤖 Built with SMT <smt@agora.build>"
```

---
### Task 11: Known-answer vectors, the design doc, and AGENTS.md

**Files:**
- Modify: `src/memory/kat_tests.rs`, `designs/e2e-encryption.md`, `AGENTS.md`

**Interfaces:**
- Consumes: Task 1 `device_keys_aad`, `DeviceKeys::{sign_statement, unlock_auth_key}`; Task 3 `UnlockRequest`, `UnlockGrant`, `StorageRotate`, `StorageAck`, `StorageConfirm`, `unlock_request_hash`, `unlock_info`, `storage_key_info`.
- Produces: fixed vectors Astation's Swift must reproduce; docs.

The vectors below were computed independently of atem's code (Python `cryptography` 41 for X25519 and Ed25519, a hand-written `enc`); `device_sign_pub` and `unlock_auth_pub` from that computation equal the step 0–1 vectors, which cross-checks the inputs. Extra inputs: X25519 secret `E` = 32 × `aa`, unlock nonce = 32 × `bb`, `boot_id` `"boot-1"`, `ticket` `""`, `time` 1760000000, old `storage_kid` `"0a1b2c3d"`, new `storage_kid` `"4e5f6a7b"`, unlock-grant `sealed_hash` = 32 × `cc`, rotation `sealed_hash` = 32 × `dd`.

- [ ] **Step 1: Write the vector tests** — in `src/memory/kat_tests.rs`, extend the imports:

```rust
use crate::memory::statements::{
    StorageAck, StorageConfirm, StorageRotate, UnlockGrant, UnlockRequest, storage_key_info,
    unlock_info, unlock_request_hash,
};
use crate::memory::storage_key::device_keys_aad;
```

and append at the end of the file:

```rust
const OLD_STORAGE_KID: &str = "0a1b2c3d";
const NEW_STORAGE_KID: &str = "4e5f6a7b";
const E_PUB: &str = "14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070";
const UNLOCK_REQUEST: &str = "000000166174656d2d756e6c6f636b2d726571756573742d763100000006616363742d31000000056465762d3100000006626f6f742d31000000000000002014ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e2407000000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000080000000068e77800000000083061316232633364";
const UNLOCK_REQUEST_HASH: &str = "1301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d";
const UNLOCK_REQUEST_SIGNATURE: &str = "e82afd604b8697c54433e33fc7f2f1cf168ad248e0c620edb2c2e470d7908a2cf71362934c8c33f2c9449f27f52d4de6076ad7e2fa16fa87c274192ca3b58008";
const UNLOCK_INFO: &str = "000000136174656d2d756e6c6f636b2d696e666f2d763100000006616363742d31000000056465762d31000000083061316232633364000000201301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d";
const UNLOCK_GRANT: &str = "000000146174656d2d756e6c6f636b2d6772616e742d763100000006616363742d31000000080000000000000001000000056465762d31000000083061316232633364000000201301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d00000020cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DEVICE_KEYS_AAD: &str = "000000136174656d2d6465766963652d6b6579732d7631000000056465762d31000000083061316232633364";
const STORAGE_KEY_INFO: &str = "000000186174656d2d73746f726167652d6b65792d696e666f2d763100000006616363742d31000000056465762d31000000083465356636613762";
const STORAGE_ROTATE: &str = "000000166174656d2d73746f726167652d726f746174652d763100000006616363742d31000000056465762d3100000008306131623263336400000008346535663661376200000020dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const STORAGE_ROTATE_SIGNATURE: &str = "2041a1670126328aa40f7bb9cf4d35146cd45cc447ecef1c904c5b970876242a7c37f59dc117a5486e8e37d0b39b958f00806c0cf00d9c52e4d3fd90818e4408";
const FIRST_STORAGE_ROTATE: &str = "000000166174656d2d73746f726167652d726f746174652d763100000006616363742d31000000056465762d310000000000000008306131623263336400000020dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const STORAGE_ACK: &str = "000000136174656d2d73746f726167652d61636b2d763100000006616363742d31000000080000000000000001000000056465762d31000000083465356636613762";
const STORAGE_CONFIRM: &str = "000000176174656d2d73746f726167652d636f6e6669726d2d763100000006616363742d31000000056465762d31000000083465356636613762";
const STORAGE_CONFIRM_SIGNATURE: &str = "6a7c7961862d5ef7d3028b3d6c511434f5a5e8e4fd1f0541de1ca3a6db9aca2b32d5f3aec90aa750948a46faa61078dee3339490cd873e58e5639ec36167db0d";

fn signature_hex(signed: &SignedWire) -> String {
    hex(&STANDARD.decode(&signed.signature).unwrap())
}

fn rotate(old: &str, new: &str) -> StorageRotate {
    StorageRotate {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        old_storage_kid: old.into(),
        new_storage_kid: new.into(),
        sealed_hash: [0xdd; 32],
    }
}

#[test]
fn unlock_vectors() {
    let e_pub =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0xaa; 32])).to_bytes();
    assert_eq!(hex(&e_pub), E_PUB);
    let request = UnlockRequest {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        boot_id: "boot-1".into(),
        ticket: String::new(),
        e_pub,
        nonce: [0xbb; 32],
        time: 1_760_000_000,
        storage_kid: OLD_STORAGE_KID.into(),
    }
    .encode();
    assert_eq!(hex(&request), UNLOCK_REQUEST);
    let request_hash = unlock_request_hash(&request);
    assert_eq!(hex(&request_hash), UNLOCK_REQUEST_HASH);
    // Ed25519 is deterministic, so the unlock-auth signature is fixed too.
    assert_eq!(
        signature_hex(&device_keys().unlock_auth_key().sign_statement(&request)),
        UNLOCK_REQUEST_SIGNATURE
    );
    assert_eq!(
        hex(&unlock_info(ACCOUNT, DEVICE_ID, OLD_STORAGE_KID, &request_hash)),
        UNLOCK_INFO
    );
    let grant = UnlockGrant {
        account: ACCOUNT.into(),
        sign_gen: 1,
        device_id: DEVICE_ID.into(),
        storage_kid: OLD_STORAGE_KID.into(),
        request_hash,
        sealed_hash: [0xcc; 32],
    };
    assert_eq!(hex(&grant.encode()), UNLOCK_GRANT);
}

#[test]
fn storage_key_vectors() {
    assert_eq!(hex(&device_keys_aad(DEVICE_ID, OLD_STORAGE_KID)), DEVICE_KEYS_AAD);
    assert_eq!(
        hex(&storage_key_info(ACCOUNT, DEVICE_ID, NEW_STORAGE_KID)),
        STORAGE_KEY_INFO
    );
    let rotation = rotate(OLD_STORAGE_KID, NEW_STORAGE_KID).encode();
    assert_eq!(hex(&rotation), STORAGE_ROTATE);
    assert_eq!(
        signature_hex(&device_keys().sign_statement(&rotation)),
        STORAGE_ROTATE_SIGNATURE
    );
    assert_eq!(hex(&rotate("", OLD_STORAGE_KID).encode()), FIRST_STORAGE_ROTATE);
    let ack = StorageAck {
        account: ACCOUNT.into(),
        sign_gen: 1,
        device_id: DEVICE_ID.into(),
        storage_kid: NEW_STORAGE_KID.into(),
    };
    assert_eq!(hex(&ack.encode()), STORAGE_ACK);
    let confirm = StorageConfirm {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        storage_kid: NEW_STORAGE_KID.into(),
    }
    .encode();
    assert_eq!(hex(&confirm), STORAGE_CONFIRM);
    assert_eq!(
        signature_hex(&device_keys().sign_statement(&confirm)),
        STORAGE_CONFIRM_SIGNATURE
    );
}
```

- [ ] **Step 2: Run them**

Run: `cargo test memory::kat_tests -- --test-threads=1`
Expected: PASS. A mismatch means an encoding or label differs from the spec: fix the code, never the constants.

- [ ] **Step 3: Format and commit the vectors**

```bash
rustfmt --edition 2024 src/memory/kat_tests.rs
git add src/memory/kat_tests.rs
git commit -m "test(memory): known-answer vectors for unlock and storage-key statements

🤖 Built with SMT <smt@agora.build>"
```

- [ ] **Step 4: Update the design doc** — in `designs/e2e-encryption.md`:

(a) Use one name for the sealed file everywhere:

```bash
sed -i 's/device_key\.sealed/device_keys.sealed/g' designs/e2e-encryption.md
```

(b) Replace the Status paragraph (from `Status: build steps 0–1 are built` through `Not built.`) with:

```markdown
Status: build steps 0–1 are built on the atem side (2026-10-09): signed
account state and plain-text rejection (fixes to #36), and device
verification (commit-then-reveal safety code, signed device certificate,
signed account state, signed RFC 9180 HPKE grants for `K`). Build step 2a
is built on the atem side (2026-10-10): `device_keys.sealed` under a
storage key held by the home Astation, the key agent (`atem key-agent`),
Touch ID unlock, storage-key rotation at every unlock, and
`atem cred unlock|lock|status`. The Astation side of steps 0–2a is pending
(see "Astation work for steps 0–1" and "Astation work for step 2a"); until
it lands, atems stay unverified and keep plain-text sync. Moving `K` behind
the agent (2b), device-signed writes (3), the recovery secret (4),
credentials (5–6, 8) and auto-unlock (7): design approved for planning
(2026-10-09), hardened after an independent security review the same day
(see "Review findings"). Not built.
```

(c) In the "Signed statements" table, insert after the `atem-grant-v1` row:

```markdown
| `atem-unlock-request-v1` | unlock-auth key (Ed25519) | account, device_id, boot_id, ticket, E_pub, nonce, time, storage_kid | Asks the home Astation to release the storage key; `ticket` stays empty until build step 7. |
| `atem-unlock-grant-v1` | signing key | account, sign_gen, device_id, storage_kid, SHA-256(request), SHA-256(sealed key) | Proves Astation released this storage key for this one request. |
| `atem-storage-rotate-v1` | device signing key | account, device_id, old storage_kid (empty at first sealing), new storage_kid, SHA-256(sealed key) | Hands Astation a new storage key, sealed to its encryption key. |
| `atem-storage-ack-v1` | signing key | account, sign_gen, device_id, storage_kid | Astation stored the new key as pending and kept the old one. |
| `atem-storage-confirm-v1` | device signing key | account, device_id, storage_kid | The device switched to the new key; Astation deletes the old one. |
```

(d) In "Keys on disk (atem)", insert after the paragraph that starts `The OS keychain isn't used` (before `### Unlock policy`):

```markdown
**How build step 2a builds it.**

- `device_keys.sealed` is JSON `{version: 1, device_id, storage_kid, nonce, ciphertext}`:
  XChaCha20-Poly1305 under the storage key, associated data
  `enc("atem-device-keys-v1", device_id, storage_kid)`. `storage_kid` is 8
  lowercase hex characters, new at every rotation.
- The agent is the same binary, `atem key-agent` (hidden), started on demand
  by the first command that needs keys and detached with `setsid`; it logs
  to `~/.config/atem/key-agent.log`. It speaks newline-delimited JSON; every
  request carries `"v": 1` and any other version gets an error. It refuses
  peers whose UID isn't its own, sets `PR_SET_DUMPABLE=0`, and locks its
  memory with `mlockall` when `RLIMIT_MEMLOCK` leaves room (Linux). It never
  talks to the network: the CLI carries its messages to Astation, and the
  storage key never passes through the CLI in plain form.
- **Home Astation.** One storage key per device, held by the device's first
  verified Astation and recorded as `home_astation` in `cred_state.json`.
  Unlock and rotation go only through the home Astation; grants from any
  verified Astation are opened by the unlocked agent.
- **First sealing.** On the home Astation's first verification, atem seals
  the fresh keys under a new storage key, hands the unlocked keys to the
  agent, and sends the storage key to Astation (`storageKeyRotate` with an
  empty old `storage_kid`). A plain `device_keys` file from build step 1 is
  sealed the same way when the agent next starts; its key goes to Astation
  at the next `atem pair` or `atem cred unlock`.
- **Rotation, crash-safe in three phases.** (1) The agent writes
  `device_keys.sealed.next` under a new storage key and atem sends
  `storageKeyRotate`. (2) Astation stores the new key as pending, keeps the
  old one, and replies `storageKeyAck`. (3) The agent renames `.next` over
  `device_keys.sealed` and atem sends `storageKeyConfirm`; Astation deletes
  the old key. Until then Astation releases whichever key a request names,
  and the agent opens whichever file carries the released `storage_kid`.
- Until build step 2b, the agent opens `K` grants and hands `K` back to the
  caller for `data_keys.enc`; grants that arrive while it is locked are
  ignored and requested again after `atem cred unlock`.
```

(e) In "Unlock policy", replace the numbered list (from `1. The agent sends \`unlockRequest` through `request.`) with:

```markdown
1. The agent creates a single-use X25519 key `E` and a nonce. atem sends
   `unlockRequest` with the statement `atem-unlock-request-v1`
   (account, device_id, boot_id, ticket, E_pub, nonce, time, storage_kid),
   signed by the unlock-auth key. `storage_kid` names the key that opens the
   `device_keys.sealed` on disk.
2. Astation checks the signature against the pinned unlock-auth key, then
   applies the policy below.
3. If it releases, it seals the storage key named by `storage_kid` with HPKE
   to `E_pub`, `info = enc("atem-unlock-info-v1", account, device_id,
   storage_kid, SHA-256(request))`, and signs `atem-unlock-grant-v1`
   (account, sign_gen, device_id, storage_kid, SHA-256(request),
   SHA-256(enc(encapped_key, ciphertext))). The agent opens it only if the
   request carries its own `E_pub` and nonce, the hash matches and the
   signature is the pinned one; `E` is used once. A relay that swaps `E_pub`
   breaks the unlock-auth signature; a replayed reply doesn't match a new
   request.
```

(f) In "What each side stores" → atem, insert after the `unlock_auth_key` bullet:

```markdown
- `device_keys.sealed.next`: exists only between rotation phases 1 and 3.
```

and append to the `cred_state` bullet's text, before its final period: `, and the home Astation that holds the storage key`.

(g) In "Formats", replace the row starting `| Unlock reply |` with:

```markdown
| Unlock reply | same HPKE to the request's `E_pub` | `info = enc("atem-unlock-info-v1", account, device_id, storage_kid, SHA-256(request))`; signed `atem-unlock-grant-v1` |
| Storage key to Astation | same HPKE to Astation's encryption key | `info = enc("atem-storage-key-info-v1", account, device_id, storage_kid)`; device-signed `atem-storage-rotate-v1` |
| Sealed device keys | `device_keys.sealed`: JSON `{version, device_id, storage_kid, nonce, ciphertext}`, XChaCha20-Poly1305 under the storage key | `enc("atem-device-keys-v1", device_id, storage_kid)` |
| Unlock request signature | Ed25519, unlock-auth key | `atem-unlock-request-v1` |
```

(h) Insert before `## Where the work lands`:

```markdown
## Wire messages (build step 2a)

Same envelope as steps 0–1 (`{"type": …, "data": {…}}`, base64 binary).

| Type | Direction | Data |
|---|---|---|
| `unlockRequest` | atem → Astation | `request` (the `atem-unlock-request-v1` statement), `signature` (Ed25519 by the unlock-auth key, 64 bytes) |
| `unlockGrant` | Astation → atem | `grant: SignedWire` (`atem-unlock-grant-v1`), `encapped_key`, `ciphertext` |
| `unlockDenied` | Astation → atem | `reason` |
| `storageKeyRotate` | atem → Astation | `rotate: SignedWire` (`atem-storage-rotate-v1`, Ed25519 by the device signing key), `encapped_key`, `ciphertext` |
| `storageKeyAck` | Astation → atem | `ack: SignedWire` (`atem-storage-ack-v1`) |
| `storageKeyConfirm` | atem → Astation | `confirm: SignedWire` (`atem-storage-confirm-v1`, Ed25519 by the device signing key) |
```

then, directly under that table, the section "Work for Astation and the relay (step 2a)" from the end of this plan, verbatim, with its heading changed to `### Astation work for step 2a`; then:

```markdown
### Test vectors (step 2a)

`src/memory/kat_tests.rs` checks these too. Inputs are the step 0–1 inputs
plus: X25519 secret `E` = 32 × `aa`, unlock nonce = 32 × `bb`, boot_id
`"boot-1"`, ticket `""`, time 1760000000, old storage_kid `"0a1b2c3d"`, new
storage_kid `"4e5f6a7b"`, unlock-grant sealed_hash = 32 × `cc`, rotation
sealed_hash = 32 × `dd`. Ed25519 signatures are deterministic, so atem's
must match; CryptoKit's own Ed25519 signatures are randomized, which is
fine because Astation only verifies device signatures.

| Value | Result |
|---|---|
| `E_pub` | `14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070` |
| `atem-unlock-request-v1` | `000000166174656d2d756e6c6f636b2d726571756573742d763100000006616363742d31000000056465762d3100000006626f6f742d31000000000000002014ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e2407000000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000080000000068e77800000000083061316232633364` |
| SHA-256(request) | `1301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d` |
| request signature (unlock-auth key) | `e82afd604b8697c54433e33fc7f2f1cf168ad248e0c620edb2c2e470d7908a2cf71362934c8c33f2c9449f27f52d4de6076ad7e2fa16fa87c274192ca3b58008` |
| unlock `info` | `000000136174656d2d756e6c6f636b2d696e666f2d763100000006616363742d31000000056465762d31000000083061316232633364000000201301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d` |
| `atem-unlock-grant-v1` | `000000146174656d2d756e6c6f636b2d6772616e742d763100000006616363742d31000000080000000000000001000000056465762d31000000083061316232633364000000201301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d00000020cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc` |
| sealed-file AAD | `000000136174656d2d6465766963652d6b6579732d7631000000056465762d31000000083061316232633364` |
| storage-key `info` (new kid) | `000000186174656d2d73746f726167652d6b65792d696e666f2d763100000006616363742d31000000056465762d31000000083465356636613762` |
| `atem-storage-rotate-v1` | `000000166174656d2d73746f726167652d726f746174652d763100000006616363742d31000000056465762d3100000008306131623263336400000008346535663661376200000020dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd` |
| rotate signature (device signing key) | `2041a1670126328aa40f7bb9cf4d35146cd45cc447ecef1c904c5b970876242a7c37f59dc117a5486e8e37d0b39b958f00806c0cf00d9c52e4d3fd90818e4408` |
| first `atem-storage-rotate-v1` (old `""`, new `0a1b2c3d`) | `000000166174656d2d73746f726167652d726f746174652d763100000006616363742d31000000056465762d310000000000000008306131623263336400000020dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd` |
| `atem-storage-ack-v1` | `000000136174656d2d73746f726167652d61636b2d763100000006616363742d31000000080000000000000001000000056465762d31000000083465356636613762` |
| `atem-storage-confirm-v1` | `000000176174656d2d73746f726167652d636f6e6669726d2d763100000006616363742d31000000056465762d31000000083465356636613762` |
| confirm signature (device signing key) | `6a7c7961862d5ef7d3028b3d6c511434f5a5e8e4fd1f0541de1ca3a6db9aca2b32d5f3aec90aa750948a46faa61078dee3339490cd873e58e5639ec36167db0d` |
```

- [ ] **Step 5: Update `AGENTS.md`**

In the `memory/` source tree, after the `│   ├── grant.rs …` line add:

```
│   ├── storage_key.rs   #   storage key + device_keys.sealed (XChaCha20-Poly1305)
│   ├── key_agent.rs     #   key agent state: unlock, rotation, grants opened in memory
│   ├── agent_socket.rs  #   `atem key-agent` Unix socket server + client (v1 JSON lines)
│   ├── unlock.rs        #   `atem cred`; unlock/rotation carried over the Astation link
```

In the `~/.config/atem/` table, replace the `device_keys` row with:

```markdown
| `device_keys` | Build-step-1 plain keys; the key agent seals them into `device_keys.sealed` on its next start and deletes this file | None (chmod 0600) |
| `device_keys.sealed` | This device's X25519 device key and Ed25519 signing key (`{version, device_id, storage_kid, nonce, ciphertext}`); `device_keys.sealed.next` exists only mid-rotation | XChaCha20-Poly1305 under the storage key (held by the home Astation, replaced at every unlock) |
| `unlock_auth_key` | Ed25519 key that signs unlock requests | None (chmod 0600; it can only ask Astation) |
| `key-agent.log` | Output of the detached `atem key-agent` | None |
| `agent.sock` | Key-agent socket when `$XDG_RUNTIME_DIR` is unset (else `$XDG_RUNTIME_DIR/atem/agent.sock`); directory 0700, socket 0600, same-UID peers only | — |
```

and change the `cred_state.json` row's contents cell to `Verified Astation pins (signing, encryption, recovery keys), safety code, epoch floor, latest signed account state, home Astation (holds the storage key)`.

After the **Atem Memory** paragraph add:

```markdown
**Key agent** (`src/memory/key_agent.rs`, `agent_socket.rs`, `unlock.rs`): this device's keys live sealed in `device_keys.sealed` under a storage key only the home Astation holds. `atem cred unlock` asks the hidden, on-demand `atem key-agent` (same binary, Unix socket, same-UID only, `"v": 1` JSON lines) for a single-use key, sends a request signed by `unlock_auth_key`, and hands Astation's Touch-ID-approved, signed reply straight back to the agent; the agent then rotates the storage key (three crash-safe phases). Grants are opened inside the agent; while it is locked they are ignored. `atem cred lock` wipes it; `atem cred status` shows verified / home Astation / agent / storage key. See `designs/e2e-encryption.md` "Keys on disk (atem)".
```

In the Capability Tiers table, change the tier-2 commands cell to `vault, sync, memory, skill, cred, and Astation-driven remote agent control, voice coding, mark tasks, visualize`.

- [ ] **Step 6: Full check**

Run: `cargo test -- --test-threads=1 && cargo clippy --all-targets --all-features && cargo build && ./scripts/run-local-dev-tests.sh`
Expected: tests and clippy pass; the smoke script shows only the 3 pre-existing `atem list` failures.

- [ ] **Step 7: Commit**

```bash
git add designs/e2e-encryption.md AGENTS.md
git commit -m "docs: step 2a key agent, unlock, rotation, wire messages and vectors

🤖 Built with SMT <smt@agora.build>"
```

---

## Work for Astation and the relay (step 2a)

atem can't unlock against a real Astation until these land. They go to the
Astation agent as one handoff (Task 11 also copies this section into the
design doc as "Astation work for step 2a").

**Astation (macOS):**
1. **Storage keys.** Keep, per verified device, its storage keys in the
   Keychain (`WhenUnlockedThisDeviceOnly`), keyed by `storage_kid`: one
   current key and at most one pending key.
2. **`unlockRequest`.** Decode `request`; verify `signature` with Ed25519
   (`Curve25519.Signing.PublicKey(rawRepresentation:)`, the device's pinned
   unlock-auth key); parse `atem-unlock-request-v1`; check account and
   device_id; refuse revoked devices with `unlockDenied`. Show the Touch ID
   prompt (device name, boot ID, request time, last unlock) with Approve,
   Deny, and Deny and revoke. On deny send `unlockDenied { reason }`.
3. **On approve,** take the storage key whose kid equals the request's
   `storage_kid`, current or pending (no such key → `unlockDenied`). Seal it
   with `HPKE.Sender(recipientKey: E_pub, ciphersuite: .Curve25519_SHA256_ChachaPoly,
   info: enc("atem-unlock-info-v1", account, device_id, storage_kid, SHA-256(request bytes)))`,
   empty AAD. Sign `atem-unlock-grant-v1` = `enc(label, account, sign_gen,
   device_id, storage_kid, SHA-256(request bytes), SHA-256(enc(encapped_key, ciphertext)))`
   with the Secure Enclave key (64-byte `r ‖ s`, low-S). Send
   `unlockGrant { grant, encapped_key, ciphertext }`.
4. **`storageKeyRotate`.** Verify `rotate.signature` with the device's pinned
   device signing key (Ed25519); parse `atem-storage-rotate-v1`; check
   account and device_id. The old `storage_kid` must be the current key's
   kid, or empty when you hold no storage key for this device (first
   sealing). Check `SHA-256(enc(encapped_key, ciphertext))` against the
   statement. Open with `HPKE.Recipient(privateKey: <Astation encryption key>,
   ciphersuite: .Curve25519_SHA256_ChachaPoly, info: enc("atem-storage-key-info-v1",
   account, device_id, new_storage_kid), encapsulatedKey: encapped_key)`,
   empty AAD; the plaintext is 32 bytes. Store it as **pending**, keep the
   current key, and reply `storageKeyAck` with a signed
   `atem-storage-ack-v1` = `enc(label, account, sign_gen, device_id, new_storage_kid)`.
   No Touch ID: the device signature is the authorization.
5. **`storageKeyConfirm`.** Verify with the pinned device signing key; parse
   `atem-storage-confirm-v1` = `enc(label, account, device_id, storage_kid)`.
   If its kid is the pending one, make it current and delete the old key.
6. **Home rule.** atem sends `unlockRequest` and `storageKeyRotate` only to
   its home Astation (the first one it verified with). Another Astation that
   holds no storage key for the device answers `unlockDenied`.
7. Check the Swift code against "Test vectors (step 2a)": encodings, infos
   and AAD must match byte for byte; atem's Ed25519 signatures must verify.

**Relay:** forward `unlockRequest`, `unlockGrant`, `unlockDenied`,
`storageKeyRotate`, `storageKeyAck` and `storageKeyConfirm` between an atem
and its Astation exactly like the step 0–1 types (add them to any type
allowlist). Nothing new is stored.

---

## Self-review

**Spec coverage** (decisions 1–11 and the spec sections):
- Agent process, socket path and modes, peer UID, hardening, zeroize, versioned protocol, survives upgrades — Tasks 4, 7.
- Unlock flow (BeginUnlock → signed request → unlockGrant → FinishUnlock; agent checks pins, fields, request hash, sealed hash, single-use E) — Tasks 3, 5, 9.
- Rotation P1–P3, `.next`, crash between P2 and P3 — Tasks 6, 9; first escrow with old `""` — Tasks 6, 8, 9, 10.
- Home Astation — Tasks 2, 5, 6, 8, 9; documented in Task 11.
- Verification integration (no plain `device_keys`, seal at first home verification, `LoadUnlocked`, validate-before-write) — Task 8.
- Callers of `DeviceKeys::load_from(device_keys)`: `apply_grant` → `OpenGrant` (Task 8), `keyRequest` from the pinned `device_pub` (Task 8), `device_keys_for_verification` via the agent (Task 8); locked → `Applied::Locked` with the `atem cred unlock` hint (Task 8); missing `K` re-requested after unlock (Task 10).
- Migration of the plain file at agent start — Task 4; its escrow at the next `atem pair` / `atem cred unlock` — Tasks 9, 10.
- `atem cred status|unlock|lock`, tier 2, 300 s, Touch ID prompt, local-then-relay connect — Task 10.
- Six wire messages with round-trip tests — Task 9.
- Tests listed in decision 10 — locked by default (T4), happy path (T5), relay-swapped `e_pub` (T5), replayed grant (T5), wrong signer (T5), three phases and crash (T6), same-UID accept and other-UID refuse (T7), Lock wipes (T4), OpenGrant while locked (T4), migration (T4), sealed-file tamper (T1), protocol versioning (T7); KATs (T11).
- Docs: status, statements, formats, wire table, Astation handoff, vectors, AGENTS.md modules/files/tiers — Task 11.

**Placeholder scan:** every code step has complete code; every command has its expected result.

**Type consistency:** `KeyAgentApi::{status, public_keys, load_unlocked, open_grant, lock_keys, begin_unlock, finish_unlock, begin_rotation, confirm_rotation}`, `UnlockChallenge`, `UnlockGrantWire`, `StorageRotation`, `AgentStatus`, `VerificationKeys`, `KeyPaths::{device_keys_sealed, device_keys_next, unlock_auth_key}`, `TrustStore::{home, set_home, home_or_first_verified}` are spelled the same in every task that defines or uses them. The trait method is `lock_keys` (not `lock`, which `Mutex` would shadow).

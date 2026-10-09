# E2E build steps 0–1: stop trusting the relay, verify devices — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** atem stops obeying unsigned encryption messages from the relay and stops accepting plain text while encryption is on (step 0), and gains device verification — fresh device keys, a commit-then-reveal safety code confirmed on both sides, a signed device certificate, a signed account state, and signed HPKE grants for `K` (step 1).

**Architecture:** New focused modules under `src/memory/`: `encoding` (length-prefixed fields, base32), `statements` (Astation-signed statements, P-256 verify), `device_keys` (the device's three keys), `verification` (handshake + applying verified messages), `trust` (`cred_state.json`: pins, epochs, latest account state) and `grant` (HPKE open of signed grants). `crypto.rs` keeps encrypting fields; it gains plain-text rejection and a gate that requires a signed account state on verified devices. `websocket_client.rs` routes messages; `cli.rs` runs the ceremony at the end of `atem pair`.

**Tech Stack:** Rust 2024 edition crate `atem`; `p256` 0.13 (ECDSA verify), `ed25519-dalek` 2, `hpke` 0.13 (RFC 9180), existing `x25519-dalek` 2, `sha2`, `base64` 0.21, `serde_json`, `tokio`, `tempfile` (tests).

**Spec:** `designs/e2e-encryption.md` (sections "Signed statements", "Devices → Verification", "Sealing a key to a device", "The Astation setting", "What gets encrypted", "Formats", "Review findings").

## Global Constraints

- **Option A (decided 2026-10-09):** an atem that has completed verification for an Astation follows the strict rule — no upload without a signed account state, nothing unsigned obeyed. An atem that has never been verified keeps today's plain-text sync and ignores every `encryptionMode` and `keyGrant` message.
- Every signed, hashed or bound input uses `enc(...)`: each field is a 4-byte big-endian length followed by its bytes, label first.
- Astation signatures: P-256 ECDSA over SHA-256, carried as 64-byte `r ‖ s`, base64. atem rejects high-S.
- Safety code: `base32(SHA-256(enc("atem-safety-code-v1", device_pub, device_sign_pub, unlock_auth_pub, astation_sign_pub, astation_enc_pub, recovery_sign_pub, nonce_a, nonce_s)))[:12]`, shown `XXXX-XXXX-XXXX`, RFC 4648 alphabet.
- Commitment: `SHA-256(enc("atem-verify-commit-v1", device_pub, device_sign_pub, unlock_auth_pub, nonce_a))`.
- Grants: HPKE RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305; `info = enc("atem-grant-info-v1", account, type, device_id, device_pub, kid, scope_hmac)`; the signed `atem-grant-v1` statement carries `SHA-256(enc(encapped_key, ciphertext))`. (This splits the design's "info = grant statement" into info + signed hash, which avoids the statement containing a hash of a ciphertext produced with it; Task 10 updates the design doc.)
- `kid` is 8 lowercase hex characters (existing `valid_kid`).
- Files atem writes under `~/.config/atem/` are mode 0600, written to a temp file, fsynced, renamed.
- Messages go to stderr/stdout as today; no secret value or key is ever printed.
- Commits end with the line `🤖 Built with SMT <smt@agora.build>`.
- Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and the named tests before each commit. Use `-- --test-threads=1` if a test flakes.

## File Structure

| File | Responsibility |
|---|---|
| `src/memory/encoding.rs` (new) | `enc`/`dec`, u64 fields, base32 prefix |
| `src/memory/statements.rs` (new) | `SignedWire`, `verify_astation`, `AccountState`, `DeviceVerified`, `GrantStatement`; test-only `FakeAstation` |
| `src/memory/device_keys.rs` (new) | `DeviceKeys` (X25519 device, Ed25519 device signing, Ed25519 unlock-auth), load/save |
| `src/memory/trust.rs` (new) | `TrustStore` in `cred_state.json`: pending and verified pins, epoch floor, latest account state |
| `src/memory/grant.rs` (new) | `GrantWire`, `open_grant` (signature + hash + HPKE) |
| `src/memory/verification.rs` (new) | `KeyPaths`, `Handshake`, `AstationKeys`, safety code, `apply_account_state`, `apply_grant`, `complete_verification` |
| `src/memory/crypto.rs` (modify) | `EncryptionMode::as_str`, `write_private`, `pub(crate) valid_kid`, plain-text rejection, verified-needs-state gate; remove the old `DeviceKey`/`wrap_aad` |
| `src/memory/mod.rs` (modify) | register the new modules |
| `src/vault_client.rs` (modify) | plain-text rejection on read/list |
| `src/websocket_client.rs` (modify) | new/changed message variants; `handle_encryption_message` rewrite; drop fingerprint print |
| `src/cli.rs` (modify) | `prompt_yes_no`, `run_device_verification`, `run_pair` changes |
| `src/config.rs` (modify) | `atem config show` verification line |
| `src/memory/e2e_tests.rs` (modify) | relay plain-text injection test |
| `designs/e2e-encryption.md`, `AGENTS.md` (modify) | grant info/hash detail, wire messages, module list |

---

### Task 1: Dependencies and the length-prefixed encoding

**Files:**
- Modify: `Cargo.toml`, `src/memory/mod.rs`
- Create: `src/memory/encoding.rs`

**Interfaces:**
- Produces: `pub fn enc(fields: &[&[u8]]) -> Vec<u8>`, `pub fn dec(bytes: &[u8]) -> anyhow::Result<Vec<Vec<u8>>>`, `pub fn u64_field(value: u64) -> [u8; 8]`, `pub fn read_u64(field: &[u8]) -> anyhow::Result<u64>`, `pub fn base32_prefix(bytes: &[u8], chars: usize) -> String`.

- [ ] **Step 1: Add the crates**

```bash
cargo add p256@0.13 --features ecdsa
cargo add ed25519-dalek@2 --features rand_core
cargo add hpke@0.13 --no-default-features --features alloc,x25519
cargo build
```
Expected: builds. If `hpke` or `p256` pulls a second `rand_core` major version and a later task fails to pass `rand::rngs::OsRng`, pin to the release whose `rand_core` is 0.6 (`hpke 0.13.x`, `p256 0.13.x`, `ed25519-dalek 2.x` all use 0.6).

- [ ] **Step 2: Register the module**

In `src/memory/mod.rs`, after `pub mod crypto;` add:

```rust
pub mod encoding;
```

- [ ] **Step 3: Write the failing tests** — create `src/memory/encoding.rs` containing only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_every_field() {
        let fields: Vec<&[u8]> = vec![b"label", b"", b"\x00\x01", b"abc"];
        let bytes = enc(&fields);
        let back = dec(&bytes).unwrap();
        assert_eq!(back, fields.iter().map(|f| f.to_vec()).collect::<Vec<_>>());
    }

    #[test]
    fn field_boundaries_cannot_shift() {
        assert_ne!(enc(&[b"a/b", b"cd"]), enc(&[b"a/bc", b"d"]));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut bytes = enc(&[b"label", b"value"]);
        bytes.pop();
        assert!(dec(&bytes).is_err());
        assert!(dec(&[0, 0]).is_err());
    }

    #[test]
    fn u64_fields_round_trip() {
        assert_eq!(read_u64(&u64_field(0x0102_0304_0506_0708)).unwrap(), 0x0102_0304_0506_0708);
        assert!(read_u64(b"short").is_err());
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32_prefix(b"foobar", 10), "MZXW6YTBOI");
        assert_eq!(base32_prefix(b"foobar", 4), "MZXW");
        assert_eq!(base32_prefix(&[0xff; 32], 12), "777777777777");
    }
}
```

- [ ] **Step 4: Run them to see them fail**

Run: `cargo test memory::encoding`
Expected: compile errors (`enc`, `dec`, … not found).

- [ ] **Step 5: Implement** — put this above the test module in `src/memory/encoding.rs`:

```rust
//! Length-prefixed encoding for every signed, hashed or bound input: each
//! field is a 4-byte big-endian length followed by its bytes, label first.
//! See designs/e2e-encryption.md "Formats".
use anyhow::{anyhow, bail, Result};

pub fn enc(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|field| field.len() + 4).sum());
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

pub fn dec(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 { bail!("encoded statement is truncated"); }
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        bytes = &bytes[4..];
        if bytes.len() < len { bail!("encoded statement is truncated"); }
        fields.push(bytes[..len].to_vec());
        bytes = &bytes[len..];
    }
    Ok(fields)
}

pub fn u64_field(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn read_u64(field: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = field.try_into().map_err(|_| anyhow!("expected an 8-byte number"))?;
    Ok(u64::from_be_bytes(bytes))
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The first `chars` base32 characters of `bytes` (RFC 4648 alphabet, no padding).
pub fn base32_prefix(bytes: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            if out.len() == chars { return out; }
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    out
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test memory::encoding`
Expected: 5 passed.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/memory/mod.rs src/memory/encoding.rs
git commit -m "feat(memory): length-prefixed encoding for signed statements

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 2: Astation-signed statements

**Files:**
- Create: `src/memory/statements.rs`
- Modify: `src/memory/mod.rs`, `src/memory/crypto.rs` (add `EncryptionMode::as_str`)

**Interfaces:**
- Consumes: `enc`, `dec`, `u64_field`, `read_u64` (Task 1); `EncryptionMode` (`crypto.rs`).
- Produces:
  - `#[derive(Serialize, Deserialize)] pub struct SignedWire { pub statement: String, pub signature: String }` (both base64)
  - `pub fn verify_astation(sign_pub: &[u8], signed: &SignedWire) -> Result<Vec<Vec<u8>>>`
  - `pub struct AccountState { pub account: String, pub sign_gen: u64, pub mode: EncryptionMode, pub kid: Option<String>, pub epoch: u64 }` with `LABEL`, `encode()`, `parse(&[Vec<u8>])`
  - `pub struct DeviceVerified { pub account: String, pub sign_gen: u64, pub device_id: String, pub device_pub: [u8; 32], pub device_sign_pub: [u8; 32], pub unlock_auth_pub: [u8; 32], pub epoch: u64 }` with `LABEL`, `encode()`, `parse()`
  - `pub struct GrantStatement { pub account: String, pub sign_gen: u64, pub kind: String, pub device_id: String, pub device_pub: [u8; 32], pub kid: String, pub scope_hmac: String, pub sealed_hash: [u8; 32] }` with `LABEL`, `encode()`, `parse()`, `info()`, and `pub fn sealed_hash(encapped: &[u8], ciphertext: &[u8]) -> [u8; 32]`
  - `#[cfg(test)] pub(crate) struct FakeAstation` with `new()`, `sign_pub() -> Vec<u8>`, `sign(&[u8]) -> SignedWire`
  - `EncryptionMode::as_str(self) -> &'static str`

- [ ] **Step 1: Add `as_str`** — in `src/memory/crypto.rs`, inside `impl EncryptionMode`, after `parse`:

```rust
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Enabling => "enabling",
            Self::On => "on",
            Self::Disabling => "disabling",
        }
    }
```

- [ ] **Step 2: Register the module** — `src/memory/mod.rs`, after `pub mod encoding;`:

```rust
pub mod statements;
```

- [ ] **Step 3: Write the failing tests** — create `src/memory/statements.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn state(epoch: u64) -> AccountState {
        AccountState { account: "acct".into(), sign_gen: 1, mode: EncryptionMode::On, kid: Some("0123abcd".into()), epoch }
    }

    #[test]
    fn signed_account_state_verifies_and_parses() {
        let astation = FakeAstation::new();
        let signed = astation.sign(&state(3).encode());
        let fields = verify_astation(&astation.sign_pub(), &signed).unwrap();
        assert_eq!(AccountState::parse(&fields).unwrap(), state(3));
    }

    #[test]
    fn other_signer_and_tampering_are_rejected() {
        let astation = FakeAstation::new();
        let relay = FakeAstation::new();
        let forged = relay.sign(&state(3).encode());
        assert!(verify_astation(&astation.sign_pub(), &forged).is_err());

        let mut signed = astation.sign(&state(3).encode());
        signed.statement = STANDARD.encode(state(4).encode());
        assert!(verify_astation(&astation.sign_pub(), &signed).is_err());
    }

    #[test]
    fn high_s_signature_is_rejected() {
        let astation = FakeAstation::new();
        let signed = astation.sign(&state(3).encode());
        let raw = STANDARD.decode(&signed.signature).unwrap();
        let low = Signature::from_slice(&raw).unwrap();
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -s).unwrap();
        let tampered = SignedWire { statement: signed.statement.clone(), signature: STANDARD.encode(high.to_bytes()) };
        assert!(verify_astation(&astation.sign_pub(), &tampered).unwrap_err().to_string().contains("low-S"));
    }

    #[test]
    fn wrong_label_or_field_count_is_rejected() {
        let verified = DeviceVerified {
            account: "acct".into(), sign_gen: 1, device_id: "dev".into(),
            device_pub: [1; 32], device_sign_pub: [2; 32], unlock_auth_pub: [3; 32], epoch: 9,
        };
        let fields = dec(&verified.encode()).unwrap();
        assert!(AccountState::parse(&fields).is_err());
        assert_eq!(DeviceVerified::parse(&fields).unwrap(), verified);
        assert!(DeviceVerified::parse(&fields[..7]).is_err());
    }

    #[test]
    fn grant_statement_round_trips_and_info_excludes_the_hash() {
        let grant = GrantStatement {
            account: "acct".into(), sign_gen: 1, kind: "K".into(), device_id: "dev".into(),
            device_pub: [4; 32], kid: "0123abcd".into(), scope_hmac: String::new(),
            sealed_hash: sealed_hash(b"enc", b"ct"),
        };
        assert_eq!(GrantStatement::parse(&dec(&grant.encode()).unwrap()).unwrap(), grant);
        let mut other = grant.clone();
        other.sealed_hash = [0; 32];
        assert_eq!(grant.info(), other.info());
        assert_ne!(sealed_hash(b"enc", b"ct"), sealed_hash(b"en", b"cct"));
    }
}
```

- [ ] **Step 4: Run them to see them fail**

Run: `cargo test memory::statements`
Expected: compile errors (types not defined).

- [ ] **Step 5: Implement** — above the test module:

```rust
//! Statements Astation signs with its Secure Enclave P-256 key. atem trusts a
//! mode, key or device only when it arrives inside one of these.
//! See designs/e2e-encryption.md "Signed statements".
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::memory::crypto::EncryptionMode;
use crate::memory::encoding::{dec, enc, read_u64, u64_field};

/// A statement as it travels: its exact encoded bytes and a 64-byte `r ‖ s`
/// signature, both base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWire {
    pub statement: String,
    pub signature: String,
}

/// Checks `signed` against Astation's SEC1 public key and returns its fields.
pub fn verify_astation(sign_pub: &[u8], signed: &SignedWire) -> Result<Vec<Vec<u8>>> {
    let key = VerifyingKey::from_sec1_bytes(sign_pub)
        .map_err(|_| anyhow!("Astation signing key is malformed"))?;
    let statement = STANDARD.decode(&signed.statement).context("statement is not base64")?;
    let raw = STANDARD.decode(&signed.signature).context("signature is not base64")?;
    let signature = Signature::from_slice(&raw).map_err(|_| anyhow!("signature must be 64 bytes r‖s"))?;
    if signature.normalize_s().is_some() {
        bail!("signature is not in low-S form");
    }
    key.verify(&statement, &signature)
        .map_err(|_| anyhow!("Astation signature check failed"))?;
    dec(&statement)
}

fn text(field: &[u8]) -> Result<String> {
    String::from_utf8(field.to_vec()).context("statement field is not UTF-8")
}

fn key32(field: &[u8]) -> Result<[u8; 32]> {
    field.try_into().map_err(|_| anyhow!("expected a 32-byte key"))
}

fn expect(fields: &[Vec<u8>], label: &str, count: usize) -> Result<()> {
    if fields.first().map(Vec::as_slice) != Some(label.as_bytes()) {
        bail!("expected a {label} statement");
    }
    if fields.len() != count {
        bail!("{label} statement has {} fields, expected {count}", fields.len());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    pub account: String,
    pub sign_gen: u64,
    pub mode: EncryptionMode,
    pub kid: Option<String>,
    pub epoch: u64,
}

impl AccountState {
    pub const LABEL: &'static str = "atem-account-state-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.mode.as_str().as_bytes(),
            self.kid.as_deref().unwrap_or("").as_bytes(),
            &u64_field(self.epoch),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 6)?;
        let kid = text(&fields[4])?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            mode: EncryptionMode::parse(&text(&fields[3])?)?,
            kid: (!kid.is_empty()).then_some(kid),
            epoch: read_u64(&fields[5])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceVerified {
    pub account: String,
    pub sign_gen: u64,
    pub device_id: String,
    pub device_pub: [u8; 32],
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
    pub epoch: u64,
}

impl DeviceVerified {
    pub const LABEL: &'static str = "atem-device-verified-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.device_id.as_bytes(),
            &self.device_pub,
            &self.device_sign_pub,
            &self.unlock_auth_pub,
            &u64_field(self.epoch),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 8)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            device_id: text(&fields[3])?,
            device_pub: key32(&fields[4])?,
            device_sign_pub: key32(&fields[5])?,
            unlock_auth_pub: key32(&fields[6])?,
            epoch: read_u64(&fields[7])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantStatement {
    pub account: String,
    pub sign_gen: u64,
    /// `K` in this step; `index` and `scope` arrive with credentials.
    pub kind: String,
    pub device_id: String,
    pub device_pub: [u8; 32],
    pub kid: String,
    /// Empty except for scope grants.
    pub scope_hmac: String,
    /// `sealed_hash(encapped_key, ciphertext)` of the HPKE output.
    pub sealed_hash: [u8; 32],
}

impl GrantStatement {
    pub const LABEL: &'static str = "atem-grant-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.kind.as_bytes(),
            self.device_id.as_bytes(),
            &self.device_pub,
            self.kid.as_bytes(),
            self.scope_hmac.as_bytes(),
            &self.sealed_hash,
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 9)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            kind: text(&fields[3])?,
            device_id: text(&fields[4])?,
            device_pub: key32(&fields[5])?,
            kid: text(&fields[6])?,
            scope_hmac: text(&fields[7])?,
            sealed_hash: key32(&fields[8])?,
        })
    }

    /// HPKE `info`: everything the seal is for, without the hash of its own output.
    pub fn info(&self) -> Vec<u8> {
        enc(&[
            b"atem-grant-info-v1",
            self.account.as_bytes(),
            self.kind.as_bytes(),
            self.device_id.as_bytes(),
            &self.device_pub,
            self.kid.as_bytes(),
            self.scope_hmac.as_bytes(),
        ])
    }
}

pub fn sealed_hash(encapped: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    Sha256::digest(enc(&[encapped, ciphertext])).into()
}

/// Test stand-in for Astation: a P-256 key that signs statements the way
/// Astation's Secure Enclave key does (64-byte r‖s, low-S).
#[cfg(test)]
pub(crate) struct FakeAstation {
    key: p256::ecdsa::SigningKey,
}

#[cfg(test)]
impl FakeAstation {
    pub fn new() -> Self {
        Self { key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng) }
    }

    pub fn sign_pub(&self) -> Vec<u8> {
        self.key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    pub fn sign(&self, statement: &[u8]) -> SignedWire {
        use p256::ecdsa::signature::Signer;
        let signature: Signature = self.key.sign(statement);
        let signature = signature.normalize_s().unwrap_or(signature);
        SignedWire {
            statement: STANDARD.encode(statement),
            signature: STANDARD.encode(signature.to_bytes()),
        }
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test memory::statements`
Expected: 5 passed. If `Signature::from_scalars(r, -s)` doesn't compile in the high-S test, build the high-S value by negating `s` with `p256::Scalar` (`let s = p256::Scalar::from(*s); Signature::from_scalars(*r, -s)`); the assertion stays the same.

- [ ] **Step 7: Commit**

```bash
git add src/memory/mod.rs src/memory/statements.rs src/memory/crypto.rs
git commit -m "feat(memory): verify Astation-signed statements

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 3: The device's own keys

**Files:**
- Create: `src/memory/device_keys.rs`
- Modify: `src/memory/mod.rs`, `src/memory/crypto.rs` (add `write_private`)

**Interfaces:**
- Produces:
  - `pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()>` in `crypto.rs`
  - `pub struct DeviceKeys` with `generate()`, `device_pub() -> [u8; 32]`, `device_sign_pub() -> [u8; 32]`, `unlock_auth_pub() -> [u8; 32]`, `device_secret_bytes() -> [u8; 32]`, `load_from(&Path) -> Result<Option<Self>>`, `save_to(&self, &Path) -> Result<()>`

- [ ] **Step 1: Add `write_private`** — in `src/memory/crypto.rs`, after the two `set_mode_600` functions:

```rust
/// Writes `bytes` to `path` as a 0600 file: temp file, fsync, rename.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let temp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    set_mode_600(path)
}
```

- [ ] **Step 2: Register the module** — `src/memory/mod.rs`, after `pub mod statements;`:

```rust
pub mod device_keys;
```

- [ ] **Step 3: Write the failing tests** — create `src/memory/device_keys.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_distinct_and_survive_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_keys");
        assert!(DeviceKeys::load_from(&path).unwrap().is_none());
        let keys = DeviceKeys::generate();
        assert_ne!(keys.device_sign_pub(), keys.unlock_auth_pub());
        keys.save_to(&path).unwrap();
        let loaded = DeviceKeys::load_from(&path).unwrap().unwrap();
        assert_eq!(loaded.device_pub(), keys.device_pub());
        assert_eq!(loaded.device_sign_pub(), keys.device_sign_pub());
        assert_eq!(loaded.unlock_auth_pub(), keys.unlock_auth_pub());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn two_generations_differ() {
        assert_ne!(DeviceKeys::generate().device_pub(), DeviceKeys::generate().device_pub());
    }
}
```

- [ ] **Step 4: Run them to see them fail**

Run: `cargo test memory::device_keys`
Expected: compile errors.

- [ ] **Step 5: Implement** — above the test module:

```rust
//! The device's own keys, created fresh at verification: X25519 to open keys
//! sealed to this device, Ed25519 to sign its writes, Ed25519 to sign unlock
//! requests. Build step 2 seals the first two behind the storage key; until
//! then the file is plain and 0600.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct DeviceKeys {
    device: StaticSecret,
    device_sign: SigningKey,
    unlock_auth: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct StoredDeviceKeys {
    version: u8,
    device: String,
    device_sign: String,
    unlock_auth: String,
}

pub fn device_keys_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("device_keys")
}

fn decode32(value: &str, what: &str) -> Result<[u8; 32]> {
    STANDARD.decode(value)
        .with_context(|| format!("{what} is not base64"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} has the wrong length"))
}

impl DeviceKeys {
    pub fn generate() -> Self {
        Self {
            device: StaticSecret::random_from_rng(OsRng),
            device_sign: SigningKey::generate(&mut OsRng),
            unlock_auth: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn device_pub(&self) -> [u8; 32] {
        PublicKey::from(&self.device).to_bytes()
    }

    pub fn device_sign_pub(&self) -> [u8; 32] {
        self.device_sign.verifying_key().to_bytes()
    }

    pub fn unlock_auth_pub(&self) -> [u8; 32] {
        self.unlock_auth.verifying_key().to_bytes()
    }

    pub fn device_secret_bytes(&self) -> [u8; 32] {
        self.device.to_bytes()
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stored: StoredDeviceKeys = serde_json::from_slice(&raw).context("device_keys is unreadable")?;
        if stored.version != 1 { bail!("unsupported device_keys version {}", stored.version); }
        Ok(Some(Self {
            device: StaticSecret::from(decode32(&stored.device, "device key")?),
            device_sign: SigningKey::from_bytes(&decode32(&stored.device_sign, "device signing key")?),
            unlock_auth: SigningKey::from_bytes(&decode32(&stored.unlock_auth, "unlock-auth key")?),
        }))
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let stored = StoredDeviceKeys {
            version: 1,
            device: STANDARD.encode(self.device.to_bytes()),
            device_sign: STANDARD.encode(self.device_sign.to_bytes()),
            unlock_auth: STANDARD.encode(self.unlock_auth.to_bytes()),
        };
        crate::memory::crypto::write_private(path, &serde_json::to_vec(&stored)?)
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test memory::device_keys`
Expected: 2 passed.

- [ ] **Step 7: Commit**

```bash
git add src/memory/mod.rs src/memory/device_keys.rs src/memory/crypto.rs
git commit -m "feat(memory): fresh device, device-signing and unlock-auth keys

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 4: Commit-then-reveal handshake and safety code

**Files:**
- Create: `src/memory/verification.rs`
- Modify: `src/memory/mod.rs`

**Interfaces:**
- Consumes: `DeviceKeys` (Task 3), `enc`, `base32_prefix` (Task 1).
- Produces:
  - `pub struct AstationKeys { pub sign_pub: Vec<u8>, pub enc_pub: [u8; 32], pub recovery_sign_pub: [u8; 32], pub nonce_s: [u8; 32] }` with `pub fn from_wire(sign_pub: &str, enc_pub: &str, recovery_sign_pub: &str, nonce: &str) -> Result<Self>` (all base64; `sign_pub` is SEC1, 65 bytes uncompressed)
  - `pub struct Reveal { pub device_pub: [u8; 32], pub device_sign_pub: [u8; 32], pub unlock_auth_pub: [u8; 32], pub nonce_a: [u8; 32] }`
  - `pub fn commitment_for(reveal: &Reveal) -> [u8; 32]`
  - `pub fn safety_code(reveal: &Reveal, astation: &AstationKeys) -> String` (format `XXXX-XXXX-XXXX`)
  - `pub struct Handshake` with `start(DeviceKeys) -> Self`, `commitment() -> [u8; 32]`, `reveal() -> Reveal`, `safety_code(&AstationKeys) -> String`, `keys() -> &DeviceKeys`, `into_keys() -> DeviceKeys`

- [ ] **Step 1: Register the module** — `src/memory/mod.rs`, after `pub mod device_keys;`:

```rust
pub mod verification;
```

- [ ] **Step 2: Write the failing tests** — create `src/memory/verification.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn astation() -> AstationKeys {
        AstationKeys { sign_pub: vec![4; 65], enc_pub: [5; 32], recovery_sign_pub: [6; 32], nonce_s: [7; 32] }
    }

    #[test]
    fn commitment_matches_the_reveal_and_hides_the_nonce() {
        let first = Handshake::start(DeviceKeys::generate());
        assert_eq!(commitment_for(&first.reveal()), first.commitment());
        let mut changed = first.reveal();
        changed.nonce_a[0] ^= 1;
        assert_ne!(commitment_for(&changed), first.commitment());
    }

    #[test]
    fn safety_code_is_stable_formatted_and_covers_every_key() {
        let handshake = Handshake::start(DeviceKeys::generate());
        let code = handshake.safety_code(&astation());
        assert_eq!(code, handshake.safety_code(&astation()));
        assert_eq!(code.len(), 14);
        assert!(code.chars().enumerate().all(|(i, c)| if i == 4 || i == 9 { c == '-' } else { "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c) }));

        let mut swapped = astation();
        swapped.recovery_sign_pub = [9; 32];
        assert_ne!(code, handshake.safety_code(&swapped));
        let mut nonce = astation();
        nonce.nonce_s = [8; 32];
        assert_ne!(code, handshake.safety_code(&nonce));
    }

    #[test]
    fn astation_keys_parse_from_base64() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let keys = AstationKeys::from_wire(
            &STANDARD.encode([4u8; 65]), &STANDARD.encode([5u8; 32]),
            &STANDARD.encode([6u8; 32]), &STANDARD.encode([7u8; 32]),
        ).unwrap();
        assert_eq!(keys.enc_pub, [5; 32]);
        assert!(AstationKeys::from_wire("", &STANDARD.encode([5u8; 31]), "", "").is_err());
    }
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test memory::verification`
Expected: compile errors.

- [ ] **Step 4: Implement** — above the test module:

```rust
//! Device verification: commit-then-reveal, a 12-character safety code both
//! sides show, then applying what a verified Astation sends.
//! See designs/e2e-encryption.md "Devices → Verification".
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::memory::device_keys::DeviceKeys;
use crate::memory::encoding::{base32_prefix, enc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AstationKeys {
    /// SEC1-encoded P-256 public key of Astation's Secure Enclave signing key.
    pub sign_pub: Vec<u8>,
    pub enc_pub: [u8; 32],
    pub recovery_sign_pub: [u8; 32],
    pub nonce_s: [u8; 32],
}

fn decode_exact<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    STANDARD.decode(value)
        .with_context(|| format!("{what} is not base64"))?
        .try_into()
        .map_err(|_| anyhow!("{what} has the wrong length"))
}

impl AstationKeys {
    pub fn from_wire(sign_pub: &str, enc_pub: &str, recovery_sign_pub: &str, nonce: &str) -> Result<Self> {
        let sign_pub = STANDARD.decode(sign_pub).context("Astation signing key is not base64")?;
        if sign_pub.len() != 65 {
            return Err(anyhow!("Astation signing key must be a 65-byte SEC1 point"));
        }
        Ok(Self {
            sign_pub,
            enc_pub: decode_exact(enc_pub, "Astation encryption key")?,
            recovery_sign_pub: decode_exact(recovery_sign_pub, "recovery signing key")?,
            nonce_s: decode_exact(nonce, "Astation nonce")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    pub device_pub: [u8; 32],
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
    pub nonce_a: [u8; 32],
}

pub fn commitment_for(reveal: &Reveal) -> [u8; 32] {
    Sha256::digest(enc(&[
        b"atem-verify-commit-v1",
        &reveal.device_pub,
        &reveal.device_sign_pub,
        &reveal.unlock_auth_pub,
        &reveal.nonce_a,
    ])).into()
}

pub fn safety_code(reveal: &Reveal, astation: &AstationKeys) -> String {
    let digest = Sha256::digest(enc(&[
        b"atem-safety-code-v1",
        &reveal.device_pub,
        &reveal.device_sign_pub,
        &reveal.unlock_auth_pub,
        &astation.sign_pub,
        &astation.enc_pub,
        &astation.recovery_sign_pub,
        &reveal.nonce_a,
        &astation.nonce_s,
    ]));
    let raw = base32_prefix(&digest, 12);
    format!("{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..])
}

pub struct Handshake {
    keys: DeviceKeys,
    nonce_a: [u8; 32],
}

impl Handshake {
    pub fn start(keys: DeviceKeys) -> Self {
        let mut nonce_a = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_a);
        Self { keys, nonce_a }
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

    pub fn keys(&self) -> &DeviceKeys {
        &self.keys
    }

    pub fn into_keys(self) -> DeviceKeys {
        self.keys
    }
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test memory::verification`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add src/memory/mod.rs src/memory/verification.rs
git commit -m "feat(memory): commit-then-reveal handshake and safety code

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 5: Trust store (`cred_state.json`)

**Files:**
- Create: `src/memory/trust.rs`
- Modify: `src/memory/mod.rs`

**Interfaces:**
- Consumes: `SignedWire`, `verify_astation`, `DeviceVerified`, `AccountState` (Task 2); `DeviceKeys` (Task 3); `AstationKeys` (Task 4); `write_private` (Task 3).
- Produces:
  - `pub struct AstationTrust { pub device_id, pub data_account, pub sign_gen: u64, pub astation_sign_pub, pub astation_enc_pub, pub recovery_sign_pub, pub device_pub, pub device_sign_pub, pub unlock_auth_pub (all String, base64), pub safety_code: String, pub epoch_floor: u64, pub account_state: Option<SignedWire>, pub account_epoch: u64 }`
  - `pub struct TrustStore` with `load_from(&Path) -> Result<Self>`, `save_to(&mut self, &Path) -> Result<()>`, `verified(&self, astation_id) -> Option<&AstationTrust>`, `set_pending(&mut self, astation_id, device_id, &DeviceKeys, &AstationKeys, code)`, `remove_pending(&mut self, astation_id)`, `confirm(&mut self, astation_id, &SignedWire) -> Result<DeviceVerified>`, `accept_account_state(&mut self, astation_id, &SignedWire) -> Result<Option<AccountState>>`, `verification_line(&self, astation_id) -> String`
  - `pub fn trust_path() -> PathBuf`, `pub fn trust_path_for(data_keys_path: &Path) -> PathBuf`

- [ ] **Step 1: Register the module** — `src/memory/mod.rs`, after `pub mod verification;`:

```rust
pub mod trust;
```

- [ ] **Step 2: Write the failing tests** — create `src/memory/trust.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::crypto::EncryptionMode;
    use crate::memory::statements::FakeAstation;

    const ASTATION: &str = "astation-1";

    fn pending(fake: &FakeAstation) -> (TrustStore, DeviceKeys) {
        let keys = DeviceKeys::generate();
        let astation = AstationKeys { sign_pub: fake.sign_pub(), enc_pub: [5; 32], recovery_sign_pub: [6; 32], nonce_s: [7; 32] };
        let mut store = TrustStore::default();
        store.set_pending(ASTATION, "dev-1", &keys, &astation, "AAAA-BBBB-CCCC");
        (store, keys)
    }

    fn certificate(keys: &DeviceKeys, epoch: u64) -> DeviceVerified {
        DeviceVerified {
            account: "acct".into(), sign_gen: 1, device_id: "dev-1".into(),
            device_pub: keys.device_pub(), device_sign_pub: keys.device_sign_pub(),
            unlock_auth_pub: keys.unlock_auth_pub(), epoch,
        }
    }

    fn state(mode: EncryptionMode, epoch: u64) -> AccountState {
        AccountState { account: "acct".into(), sign_gen: 1, mode, kid: Some("0123abcd".into()), epoch }
    }

    #[test]
    fn pending_is_not_trusted_until_a_matching_certificate_arrives() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        assert!(store.verified(ASTATION).is_none());
        store.confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode())).unwrap();
        let trust = store.verified(ASTATION).unwrap();
        assert_eq!((trust.data_account.as_str(), trust.epoch_floor), ("acct", 5));
    }

    #[test]
    fn certificate_for_other_keys_or_signer_is_rejected() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        let mut other = certificate(&keys, 5);
        other.device_pub = [9; 32];
        assert!(store.confirm(ASTATION, &fake.sign(&other.encode())).is_err());
        assert!(store.confirm(ASTATION, &FakeAstation::new().sign(&certificate(&keys, 5).encode())).is_err());
        assert!(store.verified(ASTATION).is_none());
    }

    #[test]
    fn account_state_needs_verification_floor_and_order() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        assert!(store.accept_account_state(ASTATION, &fake.sign(&state(EncryptionMode::On, 6).encode())).is_err());
        store.confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode())).unwrap();

        assert!(store.accept_account_state(ASTATION, &fake.sign(&state(EncryptionMode::On, 4).encode())).is_err());
        let on = fake.sign(&state(EncryptionMode::On, 6).encode());
        assert_eq!(store.accept_account_state(ASTATION, &on).unwrap().unwrap().mode, EncryptionMode::On);
        assert!(store.accept_account_state(ASTATION, &on).unwrap().is_none());
        assert!(store.accept_account_state(ASTATION, &fake.sign(&state(EncryptionMode::Off, 6).encode())).is_err());
        assert!(store.accept_account_state(ASTATION, &fake.sign(&state(EncryptionMode::Off, 5).encode())).is_err());

        let mut wrong_account = state(EncryptionMode::Off, 7);
        wrong_account.account = "other".into();
        assert!(store.accept_account_state(ASTATION, &fake.sign(&wrong_account.encode())).is_err());
        let mut wrong_gen = state(EncryptionMode::Off, 7);
        wrong_gen.sign_gen = 2;
        assert!(store.accept_account_state(ASTATION, &fake.sign(&wrong_gen.encode())).is_err());
    }

    #[test]
    fn store_round_trips_and_shows_a_line() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        store.confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred_state.json");
        store.save_to(&path).unwrap();
        let loaded = TrustStore::load_from(&path).unwrap();
        assert!(loaded.verified(ASTATION).is_some());
        assert_eq!(loaded.verification_line(ASTATION), "Verified: yes  (safety code AAAA-BBBB-CCCC)");
        assert_eq!(loaded.verification_line("other"), "Verified: no  (run 'atem pair' to verify this device)");
        assert_eq!(trust_path_for(&dir.path().join("data_keys.enc")), path);
    }
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test memory::trust`
Expected: compile errors.

- [ ] **Step 4: Implement** — above the test module:

```rust
//! What this device trusts about each Astation: the keys it pinned during
//! verification, the epoch floor, and the latest signed account state.
//! Pending entries are never trusted. Stored in `cred_state.json` (0600).
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::memory::device_keys::DeviceKeys;
use crate::memory::statements::{verify_astation, AccountState, DeviceVerified, SignedWire};
use crate::memory::verification::AstationKeys;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstationTrust {
    pub device_id: String,
    /// Empty while pending; set from the device certificate.
    pub data_account: String,
    pub sign_gen: u64,
    pub astation_sign_pub: String,
    pub astation_enc_pub: String,
    pub recovery_sign_pub: String,
    pub device_pub: String,
    pub device_sign_pub: String,
    pub unlock_auth_pub: String,
    pub safety_code: String,
    pub epoch_floor: u64,
    pub account_state: Option<SignedWire>,
    pub account_epoch: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    #[serde(default = "store_version")]
    version: u8,
    #[serde(default)]
    astations: HashMap<String, AstationTrust>,
    #[serde(default)]
    pending: HashMap<String, AstationTrust>,
}

fn store_version() -> u8 { 1 }

pub fn trust_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("cred_state.json")
}

/// The trust store that sits next to a given `data_keys.enc`.
pub fn trust_path_for(data_keys_path: &Path) -> PathBuf {
    data_keys_path.with_file_name("cred_state.json")
}

impl TrustStore {
    pub fn load_from(path: &Path) -> Result<Self> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let store: Self = serde_json::from_slice(&raw).context("cred_state.json is unreadable")?;
        if store.version != 1 { bail!("unsupported cred_state.json version {}", store.version); }
        Ok(store)
    }

    pub fn save_to(&mut self, path: &Path) -> Result<()> {
        self.version = 1;
        crate::memory::crypto::write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn verified(&self, astation_id: &str) -> Option<&AstationTrust> {
        self.astations.get(astation_id)
    }

    pub fn set_pending(&mut self, astation_id: &str, device_id: &str, keys: &DeviceKeys, astation: &AstationKeys, code: &str) {
        self.pending.insert(astation_id.into(), AstationTrust {
            device_id: device_id.into(),
            data_account: String::new(),
            sign_gen: 0,
            astation_sign_pub: STANDARD.encode(&astation.sign_pub),
            astation_enc_pub: STANDARD.encode(astation.enc_pub),
            recovery_sign_pub: STANDARD.encode(astation.recovery_sign_pub),
            device_pub: STANDARD.encode(keys.device_pub()),
            device_sign_pub: STANDARD.encode(keys.device_sign_pub()),
            unlock_auth_pub: STANDARD.encode(keys.unlock_auth_pub()),
            safety_code: code.into(),
            epoch_floor: 0,
            account_state: None,
            account_epoch: 0,
        });
    }

    pub fn remove_pending(&mut self, astation_id: &str) {
        self.pending.remove(astation_id);
    }

    /// Promotes the pending entry once Astation's signed certificate names
    /// exactly the keys this device revealed.
    pub fn confirm(&mut self, astation_id: &str, signed: &SignedWire) -> Result<DeviceVerified> {
        let entry = self.pending.get(astation_id)
            .ok_or_else(|| anyhow!("no device verification is in progress for this Astation"))?;
        let sign_pub = STANDARD.decode(&entry.astation_sign_pub)?;
        let certificate = DeviceVerified::parse(&verify_astation(&sign_pub, signed)?)?;
        if certificate.device_id != entry.device_id
            || STANDARD.encode(certificate.device_pub) != entry.device_pub
            || STANDARD.encode(certificate.device_sign_pub) != entry.device_sign_pub
            || STANDARD.encode(certificate.unlock_auth_pub) != entry.unlock_auth_pub
        {
            bail!("Astation's device certificate names different keys than this device revealed");
        }
        let mut entry = self.pending.remove(astation_id).expect("checked above");
        entry.data_account = certificate.account.clone();
        entry.sign_gen = certificate.sign_gen;
        entry.epoch_floor = certificate.epoch;
        self.astations.insert(astation_id.into(), entry);
        Ok(certificate)
    }

    /// Accepts a newer signed account state. Returns `None` for a repeat of the
    /// current one, and an error for anything unsigned, stale or mismatched.
    pub fn accept_account_state(&mut self, astation_id: &str, signed: &SignedWire) -> Result<Option<AccountState>> {
        let entry = self.astations.get_mut(astation_id)
            .ok_or_else(|| anyhow!("this device isn't verified with this Astation"))?;
        let sign_pub = STANDARD.decode(&entry.astation_sign_pub)?;
        let state = AccountState::parse(&verify_astation(&sign_pub, signed)?)?;
        if state.account != entry.data_account { bail!("account state is for a different account"); }
        if state.sign_gen != entry.sign_gen { bail!("account state is signed by a different signing-key generation"); }
        if state.epoch < entry.epoch_floor { bail!("account state is older than this device's verification"); }
        if entry.account_state.is_some() {
            if state.epoch < entry.account_epoch { bail!("account state is older than the one already applied"); }
            if state.epoch == entry.account_epoch {
                if entry.account_state.as_ref() == Some(signed) { return Ok(None); }
                bail!("two different account states share epoch {}", state.epoch);
            }
        }
        entry.account_state = Some(signed.clone());
        entry.account_epoch = state.epoch;
        Ok(Some(state))
    }

    pub fn verification_line(&self, astation_id: &str) -> String {
        match self.verified(astation_id) {
            Some(trust) => format!("Verified: yes  (safety code {})", trust.safety_code),
            None => "Verified: no  (run 'atem pair' to verify this device)".to_string(),
        }
    }
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test memory::trust`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add src/memory/mod.rs src/memory/trust.rs
git commit -m "feat(memory): trust store for verified Astation pins and signed state

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 6: Open signed HPKE grants

**Files:**
- Create: `src/memory/grant.rs`
- Modify: `src/memory/mod.rs`, `src/memory/crypto.rs` (make `valid_kid` `pub(crate)`)

**Interfaces:**
- Consumes: `AstationTrust` (Task 5), `DeviceKeys` (Task 3), `GrantStatement`, `sealed_hash`, `verify_astation`, `SignedWire` (Task 2).
- Produces:
  - `#[derive(Serialize, Deserialize)] pub struct GrantWire { pub signed: SignedWire, pub encapped_key: String, pub ciphertext: String }`
  - `pub struct OpenedGrant { pub kid: String, pub key: [u8; 32] }`
  - `pub fn open_grant(trust: &AstationTrust, keys: &DeviceKeys, grant: &GrantWire) -> Result<OpenedGrant>`
  - `#[cfg(test)] pub(crate) fn seal_k_grant(astation: &FakeAstation, account: &str, device_id: &str, device_pub: [u8; 32], kid: &str, key: [u8; 32]) -> GrantWire`

- [ ] **Step 1: Expose `valid_kid`** — in `src/memory/crypto.rs` change `fn valid_kid(kid: &str) -> bool {` to `pub(crate) fn valid_kid(kid: &str) -> bool {`.

- [ ] **Step 2: Register the module** — `src/memory/mod.rs`, after `pub mod trust;`:

```rust
pub mod grant;
```

- [ ] **Step 3: Write the failing tests** — create `src/memory/grant.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::statements::{DeviceVerified, FakeAstation};
    use crate::memory::trust::TrustStore;
    use crate::memory::verification::AstationKeys;

    fn verified(fake: &FakeAstation, keys: &DeviceKeys) -> AstationTrust {
        let astation = AstationKeys { sign_pub: fake.sign_pub(), enc_pub: [5; 32], recovery_sign_pub: [6; 32], nonce_s: [7; 32] };
        let mut store = TrustStore::default();
        store.set_pending("astation-1", "dev-1", keys, &astation, "AAAA-BBBB-CCCC");
        let certificate = DeviceVerified {
            account: "acct".into(), sign_gen: 1, device_id: "dev-1".into(),
            device_pub: keys.device_pub(), device_sign_pub: keys.device_sign_pub(),
            unlock_auth_pub: keys.unlock_auth_pub(), epoch: 1,
        };
        store.confirm("astation-1", &fake.sign(&certificate.encode())).unwrap();
        store.verified("astation-1").unwrap().clone()
    }

    #[test]
    fn signed_grant_opens() {
        let (fake, keys) = (FakeAstation::new(), DeviceKeys::generate());
        let trust = verified(&fake, &keys);
        let grant = seal_k_grant(&fake, "acct", "dev-1", keys.device_pub(), "0123abcd", [42; 32]);
        let opened = open_grant(&trust, &keys, &grant).unwrap();
        assert_eq!((opened.kid.as_str(), opened.key), ("0123abcd", [42; 32]));
    }

    #[test]
    fn relay_sealed_key_is_rejected_even_with_a_real_signature() {
        let (fake, keys) = (FakeAstation::new(), DeviceKeys::generate());
        let trust = verified(&fake, &keys);
        let real = seal_k_grant(&fake, "acct", "dev-1", keys.device_pub(), "0123abcd", [42; 32]);
        // The relay seals its own key to the public device key and reuses Astation's signature.
        let relay = seal_k_grant(&FakeAstation::new(), "acct", "dev-1", keys.device_pub(), "0123abcd", [66; 32]);
        let spliced = GrantWire { signed: real.signed.clone(), ..relay.clone() };
        assert!(open_grant(&trust, &keys, &spliced).is_err());
        assert!(open_grant(&trust, &keys, &relay).is_err());
    }

    #[test]
    fn grant_for_another_device_or_account_is_rejected() {
        let (fake, keys) = (FakeAstation::new(), DeviceKeys::generate());
        let trust = verified(&fake, &keys);
        let other_device = DeviceKeys::generate();
        let wrong_device = seal_k_grant(&fake, "acct", "dev-1", other_device.device_pub(), "0123abcd", [42; 32]);
        assert!(open_grant(&trust, &keys, &wrong_device).is_err());
        let wrong_account = seal_k_grant(&fake, "other", "dev-1", keys.device_pub(), "0123abcd", [42; 32]);
        assert!(open_grant(&trust, &keys, &wrong_account).is_err());
        let bad_kid = seal_k_grant(&fake, "acct", "dev-1", keys.device_pub(), "XYZ", [42; 32]);
        assert!(open_grant(&trust, &keys, &bad_kid).is_err());
    }
}
```

- [ ] **Step 4: Run them to see them fail**

Run: `cargo test memory::grant`
Expected: compile errors.

- [ ] **Step 5: Implement** — above the test module:

```rust
//! Keys sealed to this device: RFC 9180 HPKE, plus Astation's signature over
//! what the seal is for and a hash of its output. The relay can carry a grant
//! but can't make one. See designs/e2e-encryption.md "Sealing a key to a device".
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait, OpModeR};
use serde::{Deserialize, Serialize};

use crate::memory::device_keys::DeviceKeys;
use crate::memory::statements::{sealed_hash, verify_astation, GrantStatement, SignedWire};
use crate::memory::trust::AstationTrust;

type Kem = X25519HkdfSha256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantWire {
    pub signed: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}

pub struct OpenedGrant {
    pub kid: String,
    pub key: [u8; 32],
}

pub fn open_grant(trust: &AstationTrust, keys: &DeviceKeys, grant: &GrantWire) -> Result<OpenedGrant> {
    let sign_pub = STANDARD.decode(&trust.astation_sign_pub)?;
    let statement = GrantStatement::parse(&verify_astation(&sign_pub, &grant.signed)?)?;
    if statement.account != trust.data_account { bail!("key grant is for a different account"); }
    if statement.sign_gen != trust.sign_gen { bail!("key grant is signed by a different signing-key generation"); }
    if statement.kind != "K" { bail!("unsupported key grant type {:?}", statement.kind); }
    if statement.device_id != trust.device_id || statement.device_pub != keys.device_pub() {
        bail!("key grant is for a different device");
    }
    if !crate::memory::crypto::valid_kid(&statement.kid) { bail!("key grant has an invalid key id"); }

    let encapped = STANDARD.decode(&grant.encapped_key).context("grant key encapsulation is not base64")?;
    let ciphertext = STANDARD.decode(&grant.ciphertext).context("grant ciphertext is not base64")?;
    if sealed_hash(&encapped, &ciphertext) != statement.sealed_hash {
        bail!("key grant does not match what Astation signed");
    }
    let secret = <Kem as KemTrait>::PrivateKey::from_bytes(&keys.device_secret_bytes())
        .map_err(|error| anyhow!("device key is unusable for HPKE: {error:?}"))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&encapped)
        .map_err(|error| anyhow!("grant key encapsulation is malformed: {error:?}"))?;
    let plain = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base, &secret, &encapped, &statement.info(), &ciphertext, b"",
    ).map_err(|_| anyhow!("key grant could not be opened"))?;
    let key: [u8; 32] = plain.try_into().map_err(|_| anyhow!("granted key has the wrong length"))?;
    Ok(OpenedGrant { kid: statement.kid, key })
}

/// Test stand-in for Astation sealing `K` to a device.
#[cfg(test)]
pub(crate) fn seal_k_grant(
    astation: &crate::memory::statements::FakeAstation,
    account: &str,
    device_id: &str,
    device_pub: [u8; 32],
    kid: &str,
    key: [u8; 32],
) -> GrantWire {
    use hpke::{OpModeS, Serializable};
    let mut statement = GrantStatement {
        account: account.into(), sign_gen: 1, kind: "K".into(), device_id: device_id.into(),
        device_pub, kid: kid.into(), scope_hmac: String::new(), sealed_hash: [0; 32],
    };
    let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&device_pub).unwrap();
    let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base, &recipient, &statement.info(), &key, b"", &mut rand::rngs::OsRng,
    ).unwrap();
    let encapped = encapped.to_bytes().to_vec();
    statement.sealed_hash = sealed_hash(&encapped, &ciphertext);
    GrantWire {
        signed: astation.sign(&statement.encode()),
        encapped_key: STANDARD.encode(encapped),
        ciphertext: STANDARD.encode(ciphertext),
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test memory::grant`
Expected: 3 passed. If `hpke` 0.13's names differ (`single_shot_open`, `OpModeR::Base`, `Deserializable::from_bytes`), check `cargo doc -p hpke --open` and adapt the calls only; keep the checks and their order.

- [ ] **Step 7: Commit**

```bash
git add src/memory/mod.rs src/memory/grant.rs src/memory/crypto.rs
git commit -m "feat(memory): open signed RFC 9180 HPKE key grants

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 7: Step 0 — reject plain text while encryption is on

**Files:**
- Modify: `src/memory/crypto.rs` (`decrypt_memory`, `decrypt_skill`, new `require_sealed`), `src/vault_client.rs` (`list`, `read`)

**Interfaces:**
- Produces: `impl EncryptionContext { pub fn require_sealed(&self, value: &str, prefix: &str, what: &str) -> Result<()> }` — errors when `mode == On`, `value` is non-empty and doesn't start with `prefix`.

Only `On` rejects: during `Enabling` and `Disabling` the relay legitimately holds both forms while migration runs.

- [ ] **Step 1: Write the failing tests** — add to the `tests` module in `src/memory/crypto.rs` (its `context()` helper is in mode `On`):

```rust
    #[test]
    fn plain_text_from_the_relay_is_rejected_while_on() {
        let context = context();
        let plain = Memory { id: "mem-1".into(), content: "injected instruction".into(), ..Memory::default() };
        let error = context.decrypt_memory(plain).unwrap_err().to_string();
        assert!(error.contains("plain-text"), "{error}");

        let plain_project = Memory { id: "mem-2".into(), project: "github.com/x/y".into(), ..Memory::default() };
        assert!(context.decrypt_memory(plain_project).is_err());

        let tombstone = Memory { id: "mem-3".into(), ..Memory::default() };
        assert!(context.decrypt_memory(tombstone).is_ok());

        let skill = Skill {
            files: BTreeMap::from([("SKILL.md".to_string(), b"injected".to_vec())]),
            ..Skill::default()
        };
        assert!(context.decrypt_skill(skill).is_err());
    }

    #[test]
    fn plain_text_is_still_read_during_migration() {
        let mut context = context();
        context.mode = EncryptionMode::Enabling;
        let plain = Memory { id: "mem-1".into(), content: "legacy".into(), ..Memory::default() };
        assert_eq!(context.decrypt_memory(plain).unwrap().content, "legacy");
    }
```

If `Skill` has no `Default`, build it the way `src/memory/e2e_tests.rs::RelayState::seeded` does, with an empty `project`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test memory::crypto::tests::plain_text`
Expected: `plain_text_from_the_relay_is_rejected_while_on` FAILS (plain content passes through); the migration test passes.

- [ ] **Step 3: Implement** — in `impl EncryptionContext` in `crypto.rs`, add:

```rust
    /// While encryption is on, every non-empty field from the relay must be
    /// sealed (`e1.`) or keyed (`h1.`). Plain text would let the relay inject
    /// instructions into the managed blocks agents read.
    pub fn require_sealed(&self, value: &str, prefix: &str, what: &str) -> Result<()> {
        if self.mode == EncryptionMode::On && !value.is_empty() && !value.starts_with(prefix) {
            bail!("relay sent plain-text {what} while encryption is on; refusing it");
        }
        Ok(())
    }
```

In `decrypt_memory`, right after the `if self.mode == EncryptionMode::Off { … }` block:

```rust
        self.require_sealed(&memory.content, "e1.", "memory content")?;
        self.require_sealed(&memory.project, "h1.", "memory project")?;
```

In `decrypt_skill`, right after its `Off` early return:

```rust
        self.require_sealed(&skill.project, "h1.", "skill project")?;
        for path in skill.files.keys() {
            self.require_sealed(path, "e1.", "skill file path")?;
        }
```

In `src/vault_client.rs`, in `list`, inside the `for item in &mut items` loop before the `if item.summary.starts_with("e1.")` line:

```rust
            encryption.require_sealed(&item.summary, "e1.", "vault summary")?;
```

and in `read`, inside `for entry in &mut entries` before `if entry.content.starts_with("e1.")`:

```rust
            encryption.require_sealed(&entry.content, "e1.", "vault entry")?;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test memory::crypto && cargo test memory::e2e_tests && cargo test vault_client`
Expected: all pass (the existing e2e migration test reads plain text only in `Enabling`).

- [ ] **Step 5: Commit**

```bash
git add src/memory/crypto.rs src/vault_client.rs
git commit -m "fix(memory): reject plain text from the relay while encryption is on

Review finding 5: the relay could inject plain-text memory into the
managed blocks agents read.

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 8: Step 0 + verified path — signed messages only

**Files:**
- Modify: `src/memory/verification.rs` (add `KeyPaths`, `Applied`, `apply_account_state`, `apply_grant`, `complete_verification`)
- Modify: `src/memory/crypto.rs` (verified-needs-state gate in `for_astation_at`; remove `DeviceKey`, `device_key_path`, `WRAP_DOMAIN`, `wrap_aad` and their tests)
- Modify: `src/websocket_client.rs` (message variants, `handle_encryption_message`)
- Modify: `src/cli.rs` (the `run_pair` receive loop)

**Interfaces:**
- Consumes: everything from Tasks 2–6.
- Produces:
  - `pub struct KeyPaths { pub data_keys: PathBuf, pub trust: PathBuf, pub device_keys: PathBuf, pub legacy_device_key: PathBuf }` with `default_paths()` and `in_dir(&Path)`
  - `pub enum Applied { Ignored(&'static str), Unchanged, ModeChanged(AccountState), KeyInstalled(String) }`
  - `pub fn apply_account_state(paths: &KeyPaths, astation_id: &str, signed: Option<&SignedWire>) -> Result<Applied>`
  - `pub fn apply_grant(paths: &KeyPaths, astation_id: &str, grant: Option<&GrantWire>) -> Result<Applied>`
  - `pub fn complete_verification(paths: &KeyPaths, astation_id: &str, keys: DeviceKeys, device_verified: &SignedWire, account_state: &SignedWire, grants: &[GrantWire]) -> Result<()>`
  - `AstationMessage` variants: `EncryptionMode { account_state: Option<SignedWire> }`, `KeyRequest { public_key: String }` (unchanged), `KeyGrant { grant: Option<GrantWire> }`, `VerifyCommit { device_id: String, commitment: String }`, `VerifyKeys { sign_pub: String, enc_pub: String, recovery_sign_pub: String, nonce: String }`, `VerifyReveal { device_pub: String, device_sign_pub: String, unlock_auth_pub: String, nonce: String }`, `DeviceVerified { device_verified: SignedWire, account_state: SignedWire, grants: Vec<GrantWire> }`, `VerifyAbort { reason: String }`

- [ ] **Step 1: Write the failing tests** — add to the `tests` module in `src/memory/verification.rs`:

```rust
    use crate::memory::crypto::{EncryptionContext, EncryptionMode};
    use crate::memory::grant::seal_k_grant;
    use crate::memory::statements::{AccountState, DeviceVerified, FakeAstation};
    use crate::memory::trust::TrustStore;

    const ASTATION_ID: &str = "astation-1";

    fn signed_state(fake: &FakeAstation, mode: EncryptionMode, epoch: u64) -> crate::memory::statements::SignedWire {
        fake.sign(&AccountState { account: "acct".into(), sign_gen: 1, mode, kid: Some("0123abcd".into()), epoch }.encode())
    }

    /// Runs the atem side of verification against a fake Astation and returns
    /// the paths, the fake, and the device public key.
    fn verify(dir: &std::path::Path, mode: EncryptionMode) -> (KeyPaths, FakeAstation, [u8; 32]) {
        let paths = KeyPaths::in_dir(dir);
        std::fs::write(&paths.legacy_device_key, [1u8; 32]).unwrap();
        let fake = FakeAstation::new();
        let handshake = Handshake::start(DeviceKeys::generate());
        let astation = AstationKeys { sign_pub: fake.sign_pub(), enc_pub: [5; 32], recovery_sign_pub: [6; 32], nonce_s: [7; 32] };
        let code = handshake.safety_code(&astation);
        let mut trust = TrustStore::default();
        trust.set_pending(ASTATION_ID, "dev-1", handshake.keys(), &astation, &code);
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let certificate = DeviceVerified {
            account: "acct".into(), sign_gen: 1, device_id: "dev-1".into(),
            device_pub: reveal.device_pub, device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub, epoch: 1,
        };
        let grants = if mode.requires_key() {
            vec![seal_k_grant(&fake, "acct", "dev-1", reveal.device_pub, "0123abcd", [42; 32])]
        } else {
            vec![]
        };
        complete_verification(&paths, ASTATION_ID, handshake.into_keys(), &fake.sign(&certificate.encode()), &signed_state(&fake, mode, 1), &grants).unwrap();
        (paths, fake, reveal.device_pub)
    }

    #[test]
    fn verification_installs_signed_state_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _) = verify(dir.path(), EncryptionMode::On);
        let context = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap();
        assert_eq!(context.mode, EncryptionMode::On);
        assert!(context.seal("mem-1", "content", b"x").is_ok());
        assert!(!paths.legacy_device_key.exists(), "old plain device_key must be deleted");
        assert!(DeviceKeys::load_from(&paths.device_keys).unwrap().is_some());
    }

    #[test]
    fn unsigned_or_forged_mode_changes_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _) = verify(dir.path(), EncryptionMode::On);
        assert!(matches!(apply_account_state(&paths, ASTATION_ID, None).unwrap(), Applied::Ignored(_)));
        let forged = signed_state(&FakeAstation::new(), EncryptionMode::Off, 9);
        assert!(apply_account_state(&paths, ASTATION_ID, Some(&forged)).is_err());
        let context = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap();
        assert_eq!(context.mode, EncryptionMode::On, "K and mode must survive");
    }

    #[test]
    fn signed_newer_state_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, fake, _) = verify(dir.path(), EncryptionMode::On);
        let disabling = signed_state(&fake, EncryptionMode::Disabling, 2);
        assert!(matches!(apply_account_state(&paths, ASTATION_ID, Some(&disabling)).unwrap(), Applied::ModeChanged(_)));
        assert_eq!(EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap().mode, EncryptionMode::Disabling);
    }

    #[test]
    fn unverified_devices_ignore_everything() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let fake = FakeAstation::new();
        assert!(matches!(apply_account_state(&paths, ASTATION_ID, Some(&signed_state(&fake, EncryptionMode::Off, 1))).unwrap(), Applied::Ignored(_)));
        let grant = seal_k_grant(&fake, "acct", "dev-1", [9; 32], "0123abcd", [42; 32]);
        assert!(matches!(apply_grant(&paths, ASTATION_ID, Some(&grant)).unwrap(), Applied::Ignored(_)));
        assert_eq!(EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap().mode, EncryptionMode::Off);
    }

    #[test]
    fn verified_device_without_a_state_refuses_to_build_a_context() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _) = verify(dir.path(), EncryptionMode::Off);
        // Simulate a verified entry that never received a state: an Option
        // field missing from the JSON deserializes as None.
        let raw = std::fs::read_to_string(&paths.trust).unwrap().replace("\"account_state\": {", "\"account_state_was\": {");
        std::fs::write(&paths.trust, raw).unwrap();
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(trust.verified(ASTATION_ID).unwrap().account_state.is_none());
        let error = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap_err().to_string();
        assert!(error.contains("signed encryption state"), "{error}");
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test memory::verification`
Expected: compile errors (`KeyPaths`, `complete_verification`, … not found).

- [ ] **Step 3: Implement the verification functions** — append to `src/memory/verification.rs`, above the test module, and add these imports at the top of the file:

```rust
use std::path::{Path, PathBuf};

use crate::memory::crypto::EncryptionContext;
use crate::memory::grant::{open_grant, GrantWire};
use crate::memory::statements::{AccountState, SignedWire};
use crate::memory::trust::TrustStore;
```

```rust
/// Every file verification reads or writes. Tests point these at a temp dir.
pub struct KeyPaths {
    pub data_keys: PathBuf,
    pub trust: PathBuf,
    pub device_keys: PathBuf,
    /// The plain X25519 key from #36; deleted once a device is verified.
    pub legacy_device_key: PathBuf,
}

impl KeyPaths {
    pub fn default_paths() -> Self {
        Self::in_dir(&crate::config::AtemConfig::config_dir())
    }

    pub fn in_dir(dir: &Path) -> Self {
        Self {
            data_keys: dir.join("data_keys.enc"),
            trust: dir.join("cred_state.json"),
            device_keys: dir.join("device_keys"),
            legacy_device_key: dir.join("device_key"),
        }
    }
}

#[derive(Debug)]
pub enum Applied {
    Ignored(&'static str),
    Unchanged,
    ModeChanged(AccountState),
    KeyInstalled(String),
}

/// Applies a signed account state from a verified Astation. Unsigned states,
/// and any state for a device that isn't verified, are ignored.
pub fn apply_account_state(paths: &KeyPaths, astation_id: &str, signed: Option<&SignedWire>) -> Result<Applied> {
    let Some(signed) = signed else { return Ok(Applied::Ignored("an unsigned encryption mode from the relay")) };
    let mut trust = TrustStore::load_from(&paths.trust)?;
    if trust.verified(astation_id).is_none() {
        return Ok(Applied::Ignored("an encryption mode for a device that isn't verified"));
    }
    let Some(state) = trust.accept_account_state(astation_id, signed)? else { return Ok(Applied::Unchanged) };
    EncryptionContext::update_mode_at(&paths.data_keys, astation_id, &state.account, state.mode, state.kid.as_deref())?;
    trust.save_to(&paths.trust)?;
    Ok(Applied::ModeChanged(state))
}

/// Installs a signed `K` grant for this verified device.
pub fn apply_grant(paths: &KeyPaths, astation_id: &str, grant: Option<&GrantWire>) -> Result<Applied> {
    let Some(grant) = grant else { return Ok(Applied::Ignored("an unsigned key grant from the relay")) };
    let trust = TrustStore::load_from(&paths.trust)?;
    let Some(entry) = trust.verified(astation_id) else {
        return Ok(Applied::Ignored("a key grant for a device that isn't verified"));
    };
    let keys = DeviceKeys::load_from(&paths.device_keys)?
        .ok_or_else(|| anyhow!("this device's keys are missing; run 'atem pair' to verify it again"))?;
    let opened = open_grant(entry, &keys, grant)?;
    EncryptionContext::install_grant_at(&paths.data_keys, astation_id, &entry.data_account, &opened.kid, opened.key)?;
    Ok(Applied::KeyInstalled(opened.kid))
}

/// Finishes verification once the user confirmed the code on this device and
/// Astation sent its signed certificate: pins become final, the fresh device
/// keys are saved, the old plain key is deleted, and the signed state and
/// grants are applied.
pub fn complete_verification(
    paths: &KeyPaths,
    astation_id: &str,
    keys: DeviceKeys,
    device_verified: &SignedWire,
    account_state: &SignedWire,
    grants: &[GrantWire],
) -> Result<()> {
    let mut trust = TrustStore::load_from(&paths.trust)?;
    trust.confirm(astation_id, device_verified)?;
    keys.save_to(&paths.device_keys)?;
    trust.save_to(&paths.trust)?;
    match std::fs::remove_file(&paths.legacy_device_key) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    apply_account_state(paths, astation_id, Some(account_state))?;
    for grant in grants {
        apply_grant(paths, astation_id, Some(grant))?;
    }
    Ok(())
}
```

- [ ] **Step 4: Gate `EncryptionContext` on a signed state for verified devices** — in `src/memory/crypto.rs`, at the start of `for_astation_at`, before `let store = StoredKeys::load_from(path)?;`:

```rust
        let trust = crate::memory::trust::TrustStore::load_from(&crate::memory::trust::trust_path_for(path))?;
        if trust.verified(astation_id).is_some_and(|entry| entry.account_state.is_none()) {
            bail!("waiting for Astation's signed encryption state; reconnect to Astation");
        }
```

- [ ] **Step 5: Remove the old unauthenticated device key** — in `src/memory/crypto.rs` delete `const WRAP_DOMAIN`, `fn device_key_path`, `pub struct DeviceKey` and its `impl`, `fn wrap_aad`, and the tests that use them (`device_key_is_stable_and_private` and every test calling `DeviceKey` or `wrap_aad`/`open_grant`; find them with `grep -n "DeviceKey\|wrap_aad\|open_grant" src/memory/crypto.rs`). Remove imports that become unused (`x25519_dalek`, `Hkdf`, `ChaCha20Poly1305` if unused — `cargo clippy` lists them).

- [ ] **Step 6: Replace the wire messages** — in `src/websocket_client.rs`, replace the `EncryptionMode`, `KeyRequest` and `KeyGrant` variants with:

```rust
    /// Astation → Atem: the account's encryption mode, as a signed
    /// `atem-account-state-v1` statement. Messages without one are ignored.
    #[serde(rename = "encryptionMode")]
    EncryptionMode {
        #[serde(default)]
        account_state: Option<crate::memory::statements::SignedWire>,
    },

    /// Atem → Astation: a verified device asks for `K`; `public_key` is its
    /// base64 X25519 device key, which Astation checks against its pin.
    #[serde(rename = "keyRequest")]
    KeyRequest { public_key: String },

    /// Astation → Atem: `K` sealed to this device with a signed grant.
    #[serde(rename = "keyGrant")]
    KeyGrant {
        #[serde(default)]
        grant: Option<crate::memory::grant::GrantWire>,
    },

    /// Atem → Astation: start device verification with a commitment to keys
    /// atem hasn't revealed yet. All values base64.
    #[serde(rename = "verifyCommit")]
    VerifyCommit { device_id: String, commitment: String },

    /// Astation → Atem: Astation's public keys and nonce, sent only after it
    /// stored the commitment. `sign_pub` is a 65-byte SEC1 P-256 point.
    #[serde(rename = "verifyKeys")]
    VerifyKeys { sign_pub: String, enc_pub: String, recovery_sign_pub: String, nonce: String },

    /// Atem → Astation: the keys and nonce behind the commitment.
    #[serde(rename = "verifyReveal")]
    VerifyReveal { device_pub: String, device_sign_pub: String, unlock_auth_pub: String, nonce: String },

    /// Astation → Atem: after Touch ID, the signed device certificate, the
    /// signed account state, and signed grants (`K` when it exists).
    #[serde(rename = "deviceVerified")]
    DeviceVerified {
        device_verified: crate::memory::statements::SignedWire,
        account_state: crate::memory::statements::SignedWire,
        #[serde(default)]
        grants: Vec<crate::memory::grant::GrantWire>,
    },

    /// Either side: verification was cancelled; discard everything from it.
    #[serde(rename = "verifyAbort")]
    VerifyAbort { reason: String },
```

`EncryptionMigrationComplete` stays as is.

- [ ] **Step 7: Rewrite `handle_encryption_message`** — replace the whole method body (the `match message { … }` from `use crate::memory::crypto::{DeviceKey, …}` down to `_ => Ok(None),`) with:

```rust
        use crate::memory::crypto::EncryptionContext;
        use crate::memory::verification::{apply_account_state, apply_grant, Applied, KeyPaths};
        use base64::{engine::general_purpose::STANDARD, Engine};

        if !matches!(message, AstationMessage::EncryptionMode { .. } | AstationMessage::KeyGrant { .. }) {
            return Ok(None);
        }
        let Some(astation_id) = self.connected_astation_id.clone() else {
            return Ok(Some("Ignored an encryption message that arrived before Astation's identity".into()));
        };
        let paths = KeyPaths::default_paths();
        let applied = match message {
            AstationMessage::EncryptionMode { account_state } => apply_account_state(&paths, &astation_id, account_state.as_ref())?,
            AstationMessage::KeyGrant { grant } => apply_grant(&paths, &astation_id, grant.as_ref())?,
            _ => unreachable!("filtered above"),
        };
        match applied {
            Applied::Ignored(reason) => Ok(Some(format!("Ignored {reason}"))),
            Applied::Unchanged => Ok(Some("Account encryption state unchanged".into())),
            Applied::ModeChanged(state) => {
                if state.mode.requires_key() && EncryptionContext::for_astation(&astation_id).is_err() {
                    let keys = crate::memory::device_keys::DeviceKeys::load_from(&paths.device_keys)?
                        .ok_or_else(|| anyhow!("this device's keys are missing; run 'atem pair' to verify it again"))?;
                    self.send_message(AstationMessage::KeyRequest { public_key: STANDARD.encode(keys.device_pub()) }).await?;
                    return Ok(Some("Encryption key requested from Astation".into()));
                }
                self.finish_encryption_migration(&astation_id, state.kid).await
            }
            Applied::KeyInstalled(kid) => self.finish_encryption_migration(&astation_id, Some(kid)).await,
        }
```

and add this method right after it:

```rust
    async fn finish_encryption_migration(&mut self, astation_id: &str, kid: Option<String>) -> Result<Option<String>> {
        if let Some(target) = crate::memory::crypto::migrate_account(astation_id).await? {
            let kid = kid.ok_or_else(|| anyhow!("encryption migration has no key id"))?;
            self.send_message(AstationMessage::EncryptionMigrationComplete { mode: target.to_string(), kid }).await?;
            return Ok(Some(format!("Encryption migration complete; requesting {target}")));
        }
        Ok(Some("Account encryption state updated".into()))
    }
```

In `authenticate_with_pairing`, delete the four lines that print `Encryption fingerprint` (the `match crate::memory::crypto::DeviceKey::load_or_create() { … }` block).

- [ ] **Step 8: Simplify the `run_pair` receive loop** — in `src/cli.rs` `run_pair`, the loop waits for an encryption mode and key before returning credentials. Those messages are now ignored until the device is verified, so return as soon as `CredentialSync` arrives. Replace the body of the `timeout(Duration::from_secs(60), async { … })` block with:

```rust
        loop {
            match client.recv_message_async().await {
                Some(message) => {
                    if let Some(status) = client.handle_encryption_message(&message).await? {
                        println!("{status}");
                        continue;
                    }
                    if let crate::websocket_client::AstationMessage::CredentialSync {
                        access_token,
                        refresh_token,
                        expires_at,
                        login_id,
                        astation_id,
                        save_credentials: server_save_credentials,
                    } = message
                    {
                        return Ok::<_, anyhow::Error>((
                            access_token,
                            refresh_token,
                            expires_at,
                            login_id,
                            astation_id,
                            server_save_credentials,
                        ));
                    }
                }
                None => anyhow::bail!("Astation connection closed before sending credentials."),
            }
        }
```

- [ ] **Step 9: Fix other references** — `grep -n "EncryptionMode {\|KeyGrant {\|DeviceKey" src/*.rs src/memory/*.rs src/tui/*.rs`. Update any test that builds the old variants to the new shapes (e.g. `AstationMessage::EncryptionMode { account_state: None }`), and add a serde test next to the existing `PairSavePreference` tests in `websocket_client.rs`:

```rust
    #[test]
    fn unsigned_encryption_mode_from_old_astation_still_parses() {
        let json = r#"{"type":"encryptionMode","data":{"mode":"off","data_account":"a","astation_id":"b"}}"#;
        let parsed: AstationMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(parsed, AstationMessage::EncryptionMode { account_state: None }));
    }

    #[test]
    fn verify_messages_round_trip() {
        let message = AstationMessage::VerifyCommit { device_id: "d".into(), commitment: "c".into() };
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(json, r#"{"type":"verifyCommit","data":{"device_id":"d","commitment":"c"}}"#);
    }
```

- [ ] **Step 10: Run the tests**

Run: `cargo test memory:: && cargo test websocket_client && cargo clippy --all-targets --all-features`
Expected: all pass, no clippy warnings in touched files.

- [ ] **Step 11: Commit**

```bash
git add src/memory/verification.rs src/memory/crypto.rs src/websocket_client.rs src/cli.rs
git commit -m "fix(memory): obey only signed encryption messages from verified Astations

Review findings 1 and 4: an unsigned encryptionMode could switch an
account to plain text, and any party could seal a K to the public device
key. Unverified devices now ignore both; verified devices need a signed
account state and signed HPKE grants.

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 9: The verification ceremony in `atem pair`, and `atem config show`

**Files:**
- Modify: `src/cli.rs` (`prompt_yes_no`, `run_device_verification`, `next_verify_message`, end of `run_pair`)
- Modify: `src/config.rs` (paired lines in config show)

**Interfaces:**
- Consumes: `Handshake`, `AstationKeys`, `KeyPaths`, `complete_verification` (Tasks 4, 8); `TrustStore` (Task 5); message variants (Task 8).
- Produces: `async fn run_device_verification(client: &mut AstationClient, astation_id: &str) -> Result<()>` in `cli.rs`.

The ceremony needs a live Astation, so its logic is covered by Task 8's tests through `complete_verification`; this task wires it up and is checked by building and by the smoke test.

- [ ] **Step 1: Generalize the prompt** — in `src/cli.rs` replace `prompt_save_credentials` with:

```rust
fn prompt_yes_no(question: &str) -> bool {
    use std::io::{self, BufRead, Write};

    print!("{question}");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn prompt_save_credentials() -> bool {
    prompt_yes_no("Save credentials so they keep working when Astation disconnects? [y/N]: ")
}
```

- [ ] **Step 2: Add the ceremony** — in `src/cli.rs`, after `run_pair`:

```rust
/// Waits for the next device-verification message, skipping unrelated traffic.
async fn next_verify_message(
    client: &mut crate::websocket_client::AstationClient,
) -> Result<crate::websocket_client::AstationMessage> {
    use crate::websocket_client::AstationMessage;
    loop {
        match client.recv_message_async().await {
            Some(message @ (AstationMessage::VerifyKeys { .. }
            | AstationMessage::DeviceVerified { .. }
            | AstationMessage::VerifyAbort { .. })) => return Ok(message),
            Some(_) => continue,
            None => anyhow::bail!("Astation connection closed during device verification"),
        }
    }
}

/// Verifies this device with Astation: commit, receive Astation's keys,
/// reveal, compare the safety code on both sides, then wait for Astation's
/// signed certificate. Nothing is trusted unless both sides confirm.
async fn run_device_verification(
    client: &mut crate::websocket_client::AstationClient,
    astation_id: &str,
) -> Result<()> {
    use crate::memory::device_keys::DeviceKeys;
    use crate::memory::trust::TrustStore;
    use crate::memory::verification::{complete_verification, AstationKeys, Handshake, KeyPaths};
    use crate::websocket_client::AstationMessage;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use tokio::time::{timeout, Duration};

    let paths = KeyPaths::default_paths();
    let device_id = crate::config::AtemConfig::ensure_instance_id();
    let handshake = Handshake::start(DeviceKeys::generate());
    client
        .send_message(AstationMessage::VerifyCommit {
            device_id: device_id.clone(),
            commitment: STANDARD.encode(handshake.commitment()),
        })
        .await?;

    let astation = match timeout(Duration::from_secs(15), next_verify_message(client)).await {
        Err(_) => {
            println!("This Astation doesn't support device verification yet. Pairing is saved; encrypted sync stays off on this device.");
            return Ok(());
        }
        Ok(result) => match result? {
            AstationMessage::VerifyKeys { sign_pub, enc_pub, recovery_sign_pub, nonce } => {
                AstationKeys::from_wire(&sign_pub, &enc_pub, &recovery_sign_pub, &nonce)?
            }
            AstationMessage::VerifyAbort { reason } => anyhow::bail!("Astation stopped device verification: {reason}"),
            _ => anyhow::bail!("unexpected message during device verification"),
        },
    };

    let reveal = handshake.reveal();
    client
        .send_message(AstationMessage::VerifyReveal {
            device_pub: STANDARD.encode(reveal.device_pub),
            device_sign_pub: STANDARD.encode(reveal.device_sign_pub),
            unlock_auth_pub: STANDARD.encode(reveal.unlock_auth_pub),
            nonce: STANDARD.encode(reveal.nonce_a),
        })
        .await?;
    let code = handshake.safety_code(&astation);

    let mut trust = TrustStore::load_from(&paths.trust)?;
    trust.set_pending(astation_id, &device_id, handshake.keys(), &astation, &code);
    trust.save_to(&paths.trust)?;
    let abandon = |trust: &mut TrustStore| -> Result<()> {
        trust.remove_pending(astation_id);
        trust.save_to(&paths.trust)
    };

    println!();
    println!("Safety code:  {code}");
    println!("Astation shows a code too. They must match exactly.");
    if !prompt_yes_no("Do the codes match? [y/N]: ") {
        client
            .send_message(AstationMessage::VerifyAbort { reason: "the codes didn't match on atem".into() })
            .await?;
        abandon(&mut trust)?;
        anyhow::bail!("Device verification cancelled: the codes didn't match, so nothing was trusted.");
    }

    println!("Confirm on your Mac with Touch ID…");
    match timeout(Duration::from_secs(300), next_verify_message(client)).await {
        Err(_) => {
            abandon(&mut trust)?;
            anyhow::bail!("Timed out waiting for Astation to confirm this device.")
        }
        Ok(result) => match result? {
            AstationMessage::DeviceVerified { device_verified, account_state, grants } => {
                complete_verification(&paths, astation_id, handshake.into_keys(), &device_verified, &account_state, &grants)?;
                println!("✅ Device verified with Astation (safety code {code}).");
                Ok(())
            }
            AstationMessage::VerifyAbort { reason } => {
                abandon(&mut trust)?;
                anyhow::bail!("Astation declined device verification: {reason}")
            }
            _ => {
                abandon(&mut trust)?;
                anyhow::bail!("unexpected message during device verification")
            }
        },
    }
}
```

- [ ] **Step 3: Call it at the end of `run_pair`** — in the `Ok(Ok((…)))` arm, the relay branch currently creates `identity_client` inside `if result != "local" { … }` and drops it. Restructure so the authenticated client survives:

```rust
            let mut active_client = if result != "local" {
                println!("Establishing an authenticated relay session...");
                drop(client);
                let mut identity_client = crate::websocket_client::AstationClient::new();
                identity_client
                    .connect_relay_identity(config.astation_relay_url(), &astation_id)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "Relay room paired, but device authentication failed: {}",
                            error
                        )
                    })?;
                identity_client
            } else {
                client
            };
            let verify_astation_id = astation_id.clone();
```

Keep the rest of the arm (relay code, credential store, the `Paired with Astation` messages) unchanged, then add at the end of the arm, before it returns `Ok(())`:

```rust
            if let Err(error) = run_device_verification(&mut active_client, &verify_astation_id).await {
                eprintln!("⚠️  {error}");
                eprintln!("Pairing is saved. Run 'atem pair' again to verify this device.");
            }
```

If the arm ends in an expression instead of `Ok(())`, put the call before that expression.

- [ ] **Step 4: Show it in `atem config show`** — in `src/config.rs`, in the `for p in paired` loop, after the `Paired:   …` line is pushed:

```rust
                let trust = crate::memory::trust::TrustStore::load_from(&crate::memory::trust::trust_path())
                    .unwrap_or_default();
                lines.push(format!("          {}", trust.verification_line(aid)));
```

- [ ] **Step 5: Build, test, smoke-test**

Run: `cargo build && cargo test && cargo clippy --all-targets --all-features && ./scripts/run-local-dev-tests.sh`
Expected: all pass. `cargo run -- config show` prints `Verified: no  (run 'atem pair' to verify this device)` under each paired Astation.

- [ ] **Step 6: Commit**

```bash
git add src/cli.rs src/config.rs
git commit -m "feat(pair): verify the device with a safety code confirmed on both sides

Review findings 2, 3 and 8: commit-then-reveal so the relay can't search
for a matching code, pins stay pending until both sides confirm, and
verification creates fresh device keys.

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 10: Relay injection test, design doc, agent docs

**Files:**
- Modify: `src/memory/e2e_tests.rs`, `designs/e2e-encryption.md`, `AGENTS.md`

- [ ] **Step 1: Write the injection test** — add to `src/memory/e2e_tests.rs` (it uses the file's existing `RelayState::seeded`, `stub_relay`, `clients`, `set_key` and constants):

```rust
#[tokio::test]
async fn relay_injected_plain_text_is_rejected_while_on() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("data_keys.enc");
    set_key(&store_path, EncryptionMode::On, OLD_KID, [7; 32]);
    let state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(state.clone()).await;
    let (knowledge, vault) = clients(&base, &store_path);

    let error = knowledge.pull_memories(0).await.unwrap_err().to_string();
    assert!(error.contains("plain-text"), "{error}");

    let vault_error = vault.list().await.unwrap_err().to_string();
    assert!(vault_error.contains("plain-text"), "{vault_error}");
}
```

If `RelayState::seeded()`'s vault starts with an empty summary, set `state.lock().unwrap().vault_summary = "injected".into();` before calling `vault.list()`.

- [ ] **Step 2: Run it**

Run: `cargo test memory::e2e_tests::relay_injected_plain_text_is_rejected_while_on`
Expected: PASS (Task 7 already made it pass; this guards the full HTTP path).

- [ ] **Step 3: Update the design doc** — in `designs/e2e-encryption.md`:

In "Sealing a key to a device", replace the sentence beginning "The HPKE `info` is the encoded `atem-grant-v1` statement" with:

```markdown
The HPKE `info` is `enc("atem-grant-info-v1", account, type, device_id,
device_pub, kid, scope_hmac)`, and Astation signs the `atem-grant-v1`
statement, which adds `SHA-256(enc(encapped_key, ciphertext))`. (The info
can't contain a hash of the seal's own output.)
```

In the "Formats" table, change the key-grant row's "Bound to" cell to ``info = enc("atem-grant-info-v1", account, type, device_id, device_pub, kid, scope_hmac); the signed `atem-grant-v1` carries SHA-256(enc(encapped_key, ciphertext))``.

Add a section before "Where the work lands":

````markdown
## Wire messages (build steps 0–1)

All are `{"type": …, "data": {…}}` on the existing Astation WebSocket;
binary values are base64. `SignedWire` is `{statement, signature}`;
`GrantWire` is `{signed, encapped_key, ciphertext}`.

| Type | Direction | Data |
|---|---|---|
| `verifyCommit` | atem → Astation | `device_id`, `commitment` |
| `verifyKeys` | Astation → atem | `sign_pub` (65-byte SEC1), `enc_pub`, `recovery_sign_pub`, `nonce` |
| `verifyReveal` | atem → Astation | `device_pub`, `device_sign_pub`, `unlock_auth_pub`, `nonce` |
| `deviceVerified` | Astation → atem | `device_verified: SignedWire`, `account_state: SignedWire`, `grants: [GrantWire]` |
| `verifyAbort` | either | `reason` |
| `encryptionMode` | Astation → atem | `account_state: SignedWire` (messages without it are ignored) |
| `keyRequest` | atem → Astation | `public_key` (the verified device key) |
| `keyGrant` | Astation → atem | `grant: GrantWire` |
| `encryptionMigrationComplete` | atem → Astation | unchanged |

Until Astation supports verification, atems stay unverified: they keep
plain-text sync and ignore `encryptionMode` and `keyGrant` (decided
2026-10-09, option A).
````

- [ ] **Step 4: Update `AGENTS.md`** — in the `memory/` part of the source tree, after the `sync.rs` line add:

```
│   ├── encoding.rs      #   length-prefixed fields for signed/bound inputs, base32
│   ├── statements.rs    #   Astation-signed statements (P-256 verify)
│   ├── device_keys.rs   #   device X25519 + Ed25519 signing + unlock-auth keys
│   ├── verification.rs  #   commit-then-reveal safety code; apply signed state/grants
│   ├── trust.rs         #   cred_state.json: pinned Astation keys, epochs
│   ├── grant.rs         #   signed RFC 9180 HPKE key grants
```

and in the `~/.config/atem/` table add rows:

```markdown
| `device_keys` | This device's X25519, Ed25519 signing and unlock-auth keys (created by `atem pair` verification; sealed in build step 2) | None (chmod 0600) |
| `cred_state.json` | Verified Astation pins (signing, encryption, recovery keys), safety code, epoch floor, latest signed account state | None (chmod 0600; no secrets) |
```

- [ ] **Step 5: Full check**

Run: `cargo fmt && cargo test && cargo clippy --all-targets --all-features && ./scripts/run-local-dev-tests.sh`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/memory/e2e_tests.rs designs/e2e-encryption.md AGENTS.md
git commit -m "docs: wire messages and modules for device verification

🤖 Built with SMT <smt@agora.build>"
```

---

## Work for Astation and the relay (not in this plan)

atem can't complete verification against a real Astation until these land.
They go to the Astation agent as one handoff.

**Astation (macOS):**
1. Keys, created on first need and kept in the Keychain (`WhenUnlockedThisDeviceOnly`):
   - signing key: Secure Enclave P-256 (`SecureEnclave.P256.Signing.PrivateKey`), `sign_gen = 1`;
   - encryption key: X25519 (`Curve25519.KeyAgreement.PrivateKey`), sealed by a Secure Enclave key;
   - recovery secret `R` (32 random bytes) and the recovery signing key, Ed25519 from `HKDF-SHA256(R, info: "atem-recovery-sign-v1")`; the kit gains the `Recovery key:` line and must be saved before the first device is verified;
   - an account `epoch` counter (u64) that increases on every signed account-state, certificate or grant.
2. Encoding: `enc` exactly as in "Formats" (4-byte big-endian length per field, label first). Statements as in "Signed statements".
3. Signatures: `signature.rawRepresentation` (64-byte `r ‖ s`). CryptoKit may return high-S; normalize to low-S (`s = n − s` when `s > n/2`) before sending. atem rejects high-S.
4. Verification:
   - on `verifyCommit`, store `{device_id, commitment}` and reply `verifyKeys` with a fresh 32-byte nonce;
   - on `verifyReveal`, check `SHA-256(enc("atem-verify-commit-v1", device_pub, device_sign_pub, unlock_auth_pub, nonce_a)) == commitment`, else send `verifyAbort`;
   - compute the safety code (Global Constraints) and show it with the device name; Approve needs Touch ID; Deny sends `verifyAbort`;
   - on approve, pin the three device keys, then send `deviceVerified` with a signed `atem-device-verified-v1`, the current signed `atem-account-state-v1` (mode `off` if encryption was never turned on), and a signed `K` grant if `K` exists;
   - on an incoming `verifyAbort`, discard the attempt.
5. Grants: CryptoKit `HPKE.Sender(recipientKey:ciphersuite: .Curve25519_SHA256_ChachaPoly, info:)` (macOS 14+), with `info = enc("atem-grant-info-v1", account, "K", device_id, device_pub, kid, "")`, empty AAD; send `encapped_key` and `ciphertext`; sign `atem-grant-v1` including `SHA-256(enc(encapped_key, ciphertext))`.
6. `encryptionMode` always carries a signed account state; `keyRequest` is answered only when `public_key` equals the pinned device key.

**Relay:** forward the five new message types (`verifyCommit`, `verifyKeys`, `verifyReveal`, `deviceVerified`, `verifyAbort`) between an atem and its Astation exactly like existing message types. If the relay filters by type, add them to the list. Nothing new is stored in steps 0–1.

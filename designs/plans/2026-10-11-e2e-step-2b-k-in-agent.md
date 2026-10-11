# E2E Build Step 2b: `K` Behind the Key Agent — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the account key `K` (and its previous keys) into the key agent's sealed payload, make the agent the only code that ever uses `K` (batched `Crypt` requests), derive the encryption mode from the signed account state alone, move project names to `project_names.json`, and migrate away `data_keys.enc`.

**Architecture:** `device_keys.sealed` gains an `account_keys` field inside its encrypted payload; the agent installs granted `K`s itself (`InstallGrant`) by re-sealing the file it holds the storage key for, and serves `Crypt { astation_id, ops }` (seal / open / keyed hash in the unchanged `e1.`/`h1.` formats). `EncryptionContext` becomes a thin client: it reads mode and kid from the latest signed account state in `cred_state.json`, never touches the agent when encryption is off, and batches one call site's fields into as few `Crypt` requests as a size budget allows. At the first unlock the agent moves `data_keys.enc` into the sealed payload and `project_names.json`, then deletes it.

**Tech Stack:** Rust 2024 (bin crate `atem`), serde/serde_json, chacha20poly1305 0.10 (XChaCha20-Poly1305), hmac 0.12 + sha2 0.10, zeroize 1 (serde feature), tokio (`spawn_blocking`), existing in-process test agent (`Mutex<KeyAgent>`) and `FakeKeyServer`.

**Spec:** `designs/e2e-encryption.md` ("Keys on disk (atem)", "What each side stores", "Memory, skills and vault notes", "Migration", step 2a sections). This plan's scope was decided with the user; the decisions are listed in "Scope" below and implemented exactly.

## Global Constraints

- Commit messages end with: `🤖 Built with SMT <smt@agora.build>`
- rustfmt only files with no `mod` declarations other than `mod tests`; never project-wide `cargo fmt`; never rustfmt `cli.rs`, `websocket_client.rs`, `crypto.rs`, `mod.rs`, `vault_client.rs`. Files that are not rustfmt-clean today (`verification.rs`, `api.rs`, `sync.rs`, `e2e_tests.rs`) are edited by hand and not formatted either. Each task lists the files it may format, with `rustfmt --edition 2024 <file>`.
- Crates: p256 0.13, ed25519-dalek 2, hpke 0.12 (not 0.13), rand 0.8 `OsRng`, zeroize 1 (serde feature on). No new crates.
- `cargo test` accepts one filter per command; full run `cargo test -- --test-threads=1`; `./scripts/run-local-dev-tests.sh` has 3 known `atem list` failures.
- macOS must still build: Linux-only calls behind `cfg`.
- Wire/ciphertext formats on the relay must not change in this step (`e1.<kid>.<base64(nonce ‖ ct)>`, AAD `"{record}\n{field}"`, `h1.<kid>.<hex HMAC-SHA256(K, value)>`).

## Scope (decided with the user)

1. `K` storage: the sealed payload gains `account_keys` (account → current kid + key, previous keys by kid). Storage-key rotation re-seals it. Installing/replacing `K` = the agent atomically re-seals the current sealed file under the current storage key; a new `K` arrives via a signed grant, so a crashed re-seal is recovered by requesting `K` again.
2. Mode and kid come from the latest signed account state in `cred_state.json`. `StoredMode` and the "local state doesn't match" check are removed. Unverified devices: mode Off.
3. Project names live in `~/.config/atem/project_names.json` (0600, `write_private`, no secrets). The HMAC is computed by the agent.
4. `data_keys.enc` is migrated at the first unlock (or at agent start when it starts unlocked) and deleted; unverified devices just delete it. Crash-safe ordering + tests.
5. The agent never hands out `K`: batched `Crypt`; secrets `Zeroizing` on the wire; `OpenGrant` no longer returns `K`.
6. `EncryptionContext` keeps its public methods; pull/push/migrate send one `Crypt` per batch. Every sync agent call from async code goes through `key_agent::blocking` (R7).
7. A locked agent with encryption on errors like a missing key ("run `atem cred unlock`"), queued ops stay queued. Off / unverified never touch the agent.
8. Out of scope: `K` subkeys / format changes (step 3), auto-unlock (step 7), credentials get/list (step 5).

## Rulings made while planning (beyond the scope list)

- `Crypt` names the Astation (`astation_id`), not the account: the agent derives the account and the signed state from that one `cred_state.json` entry, so a caller can't pair one Astation's state with another account's key.
- Requests are `InstallGrant` (installs, returns the kid) and `CheckGrant` (verification staging, returns the kid, stores nothing); `OpenGrant` and `Reply::Grant` are removed, so no request returns `K`.
- Agent protocol bumped to v2: a step-2a agent left running gets the existing "stop it and retry" message instead of a confusing "malformed request".
- `MAX_LINE` 1 MiB → 8 MiB; `EncryptionContext` splits batches at 2 MiB / 1024 ops (one skill, max 1 MiB, always fits).
- Retired keys are pruned lazily: at install, `Crypt`, `HeldKid`, every unlock, and when the Astation link sees a non-key state with a running agent.
- `data_keys.enc` is deleted only when the agent is escrowed and not unlocked via `.prev`; an unreadable one is deleted; an unverified device's is deleted at agent start.
- Fresh-key verification still checks grants in-process (this process holds the fresh device key anyway) and drops `K` at once; the agent installs after the write. An install failure after a saved verification is a warning, not an error.
- Single-item `EncryptionContext` methods production no longer calls (`open`, `keyed_hash`, `encrypt_memory`, `decrypt_memory`, `encrypt_skill`) become `#[cfg(test)]`.
- `project_names.json` writes take an `flock` on `project_names.lock` (the same helper `cred_state.json` uses).
- `key_needed` treats a locked agent as "K missing".
- `persist` refuses to re-seal a file whose storage kid isn't the one the agent holds.

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `src/memory/account_keys.rs` | Create | `AccountKeys` (per-account key rings, `Zeroizing`), the `e1.`/`h1.` field crypto moved out of `crypto.rs`, `CryptOp`/`CryptOut`, `crypt()`, `install()`, `reconcile()`, `merge()`, sealed-payload wire form |
| `src/memory/project_names.rs` | Create | `project_names.json`: `h1.` hash → readable project key, per account; flocked read-modify-write |
| `src/memory/legacy_keys.rs` | Create | Read-only access to `data_keys.enc` (machine-bound): `read`, `purge_unverified_at`, `keys_for`/`names_for` for migration, test writer |
| `src/memory/k_agent_tests.rs` | Create | (test-only) the agent holding `K`: install, crypt, rotation, reconcile, migration crash windows |
| `src/memory/device_keys.rs` | Modify | Sealed plaintext carries optional `account_keys` |
| `src/memory/storage_key.rs` | Modify | `seal_with` / `open_with_accounts` |
| `src/memory/key_agent.rs` | Modify | `Unlocked.accounts`, `persist`, `reconcile`, `InstallGrant`, `CheckGrant`, `Crypt`, `HeldKid`; `OpenGrant`/`Reply::Grant` removed; protocol v2; `data_keys.enc` migration |
| `src/memory/agent_socket.rs` | Modify | `crypt`/`crypted` parsed straight into `Zeroizing`; `grant` special case removed; `MAX_LINE` 8 MiB |
| `src/memory/verification.rs` | Modify | `KeyPaths.project_names`, `AccountMode`/`account_mode`, `stored_state` pub(crate), `apply_grant`/`complete_verification`/`key_needed` use the agent; `VerifiedForTest` removed |
| `src/memory/trust.rs` | Modify | `verified_entries()`; `trust_path_for` removed |
| `src/memory/crypto.rs` | Modify | `StoredKeys` & co. removed; `EncryptionContext` thin client with batching and `blocking` |
| `src/memory/api.rs` | Modify | Batched encrypt/decrypt inside `EncryptionContext::blocking`; test hook `with_encryption` |
| `src/vault_client.rs` | Modify | Same for vault list/read/write/migrate |
| `src/memory/fake_astation.rs` | Modify | `unlock_with`, `set_state`, `UnlockedDevice` |
| `src/memory/e2e_tests.rs` | Modify | Relay tests against the agent-backed context; batching and copied-config-dir tests |
| `src/memory/unlock.rs`, `src/websocket_client.rs` | Modify | `key_needed` takes the agent and runs on a blocking thread |
| `src/memory/mod.rs` | Modify | Register new modules |
| `tests/key_agent_binary.rs` | Modify | Protocol v2 literal |
| `designs/e2e-encryption.md`, `AGENTS.md` | Modify | Status, step-2b description, files |

---

### Task 1: Account keys and the field operations the agent performs

**Files:**
- Create: `src/memory/account_keys.rs`
- Modify: `src/memory/mod.rs` (add one line)
- Test: `src/memory/account_keys.rs` (`mod tests`)

**Interfaces:**
- Consumes: `crate::memory::crypto::{EncryptionMode, valid_kid}`, `crate::memory::device_keys::decode32` (all existing).
- Produces (used by Tasks 2, 4, 6, 7, 8):
  - `pub const MISSING_KEY: &str`
  - `pub struct AccountKey { pub kid: String, pub key: Zeroizing<[u8; 32]> }` (Clone)
  - `pub struct AccountKeys` (Clone, Default) with `is_empty(&self) -> bool`, `current_kid(&self, account: &str) -> Option<&str>`, `previous_kids(&self, account: &str) -> Vec<String>`, `install(&mut self, account: &str, kid: &str, key: Zeroizing<[u8; 32]>) -> bool`, `reconcile(&mut self, modes: &SignedModes) -> bool`, `crypt(&self, account: &str, mode: EncryptionMode, kid: Option<&str>, ops: Vec<CryptOp>) -> Result<Vec<CryptOut>>`, `to_wire(&self) -> AccountKeysWire`, `from_wire(wire: AccountKeysWire) -> Result<Self>`
  - `pub type SignedModes = BTreeMap<String, Option<(EncryptionMode, Option<String>)>>`
  - `pub type AccountKeysWire = BTreeMap<String, RingWire>` (`RingWire`: Serialize + Deserialize)
  - `pub enum CryptOp { Seal { record, field, plain: Zeroizing<String> }, Open { record, field, value }, KeyedHash { value: Zeroizing<String> } }` with `CryptOp::seal(&str, &str, &[u8])`, `CryptOp::open(&str, &str, &str)`, `CryptOp::keyed_hash(&[u8])`, `wire_len(&self) -> usize`
  - `pub enum CryptOut { Sealed(String), Opened(Zeroizing<String>), Hashed(String) }` with `into_text(self) -> Result<String>`, `into_plain(self) -> Result<Zeroizing<Vec<u8>>>`
  - `pub(crate) fn seal_field(key: &AccountKey, record: &str, field: &str, plain: &[u8]) -> Result<String>`

- [ ] **Step 1: Register the module**

In `src/memory/mod.rs` (edit by hand, never rustfmt), add after `pub mod key_agent;`:

```rust
pub mod account_keys;
```

- [ ] **Step 2: Write the module with its failing tests first**

Create `src/memory/account_keys.rs` with the tests module only (so the test step fails to compile on missing items), then add the implementation in Step 4. Full test module (placed at the end of the file):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "0123abcd";
    /// `e1.` of "use port 27183" for record `mem-1`, field `content`, under
    /// K = [7; 32] with nonce 00 01 … 17: the format of build steps 0–2a.
    const E1_VECTOR: &str = "e1.0123abcd.AAECAwQFBgcICQoLDA0ODxAREhMUFRYX3WTOpYpzKdEF9bZ23tEau96ycT/fld12nKOh2bIB";
    /// `h1.` of "github.com/agora/atem" under K = [7; 32].
    const H1_VECTOR: &str =
        "h1.0123abcd.777eda018c9c9736a84728e10308571167773f209924bf052477a1283cfd7cb6";

    fn key(kid: &str, byte: u8) -> AccountKey {
        AccountKey {
            kid: kid.into(),
            key: Zeroizing::new([byte; 32]),
        }
    }

    fn keys_with(kid: &str, byte: u8) -> AccountKeys {
        let mut keys = AccountKeys::default();
        keys.install("acct", kid, Zeroizing::new([byte; 32]));
        keys
    }

    fn texts(results: Vec<CryptOut>) -> Vec<String> {
        results
            .into_iter()
            .map(|out| out.into_text().unwrap())
            .collect()
    }

    #[test]
    fn fields_keep_the_format_of_steps_0_to_2a() {
        let nonce: Vec<u8> = (0u8..24).collect();
        let sealed = seal_field_with_nonce(
            &key(KID, 7),
            "mem-1",
            "content",
            b"use port 27183",
            XNonce::from_slice(&nonce),
        )
        .unwrap();
        assert_eq!(sealed, E1_VECTOR);
        let keys = keys_with(KID, 7);
        let mut out = keys
            .crypt(
                "acct",
                EncryptionMode::On,
                Some(KID),
                vec![
                    CryptOp::open("mem-1", "content", E1_VECTOR),
                    CryptOp::keyed_hash(b"github.com/agora/atem"),
                ],
            )
            .unwrap()
            .into_iter();
        assert_eq!(&*out.next().unwrap().into_plain().unwrap(), b"use port 27183");
        assert_eq!(out.next().unwrap().into_text().unwrap(), H1_VECTOR);
    }

    #[test]
    fn seals_round_trip_and_are_bound_to_record_and_field() {
        let keys = keys_with(KID, 7);
        let sealed = texts(
            keys.crypt(
                "acct",
                EncryptionMode::On,
                Some(KID),
                vec![CryptOp::seal("mem-1", "content", b"hello")],
            )
            .unwrap(),
        )
        .remove(0);
        assert!(sealed.starts_with("e1.0123abcd."));
        let open = |record: &str, field: &str, value: &str| {
            keys.crypt(
                "acct",
                EncryptionMode::On,
                Some(KID),
                vec![CryptOp::open(record, field, value)],
            )
        };
        assert_eq!(
            &*open("mem-1", "content", &sealed).unwrap().remove(0).into_plain().unwrap(),
            b"hello"
        );
        assert!(open("mem-2", "content", &sealed).is_err());
        assert!(open("mem-1", "summary", &sealed).is_err());
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(open("mem-1", "content", std::str::from_utf8(&tampered).unwrap()).is_err());
    }

    #[test]
    fn empty_values_stay_empty() {
        let keys = keys_with(KID, 7);
        let mut out = keys
            .crypt(
                "acct",
                EncryptionMode::On,
                Some(KID),
                vec![CryptOp::seal("r", "f", b""), CryptOp::open("r", "f", "")],
            )
            .unwrap()
            .into_iter();
        assert_eq!(out.next().unwrap().into_text().unwrap(), "");
        assert!(out.next().unwrap().into_plain().unwrap().is_empty());
    }

    #[test]
    fn crypt_needs_the_signed_kid_and_a_mode_that_is_not_off() {
        let keys = keys_with(KID, 7);
        let hash = || vec![CryptOp::keyed_hash(b"x")];
        let error = |result: Result<Vec<CryptOut>>| format!("{:#}", result.err().unwrap());
        assert!(error(keys.crypt("acct", EncryptionMode::On, Some("89abcdef"), hash())).contains("requires encryption"));
        assert!(error(keys.crypt("other", EncryptionMode::On, Some(KID), hash())).contains("requires encryption"));
        assert!(error(keys.crypt("acct", EncryptionMode::Off, None, hash())).contains("off"));
        assert!(keys.crypt("acct", EncryptionMode::Enabling, Some(KID), hash()).is_ok());
    }

    #[test]
    fn previous_keys_open_until_the_state_is_on() {
        let mut keys = keys_with("0123abcd", 1);
        let old = seal_field(&key("0123abcd", 1), "mem", "content", b"old").unwrap();
        assert!(keys.install("acct", "89abcdef", Zeroizing::new([2; 32])));
        assert_eq!(keys.current_kid("acct"), Some("89abcdef"));
        assert_eq!(keys.previous_kids("acct"), vec!["0123abcd".to_string()]);
        let open = |keys: &AccountKeys, mode| {
            keys.crypt("acct", mode, Some("89abcdef"), vec![CryptOp::open("mem", "content", &old)])
        };
        assert!(open(&keys, EncryptionMode::Enabling).is_ok());
        assert!(open(&keys, EncryptionMode::Disabling).is_ok());
        let error = format!("{:#}", open(&keys, EncryptionMode::On).err().unwrap());
        assert!(error.contains("unavailable key id"), "{error}");
    }

    #[test]
    fn install_reports_changes_and_never_duplicates_kids() {
        let mut keys = keys_with("0123abcd", 1);
        assert!(!keys.install("acct", "0123abcd", Zeroizing::new([1; 32])), "a repeat changes nothing");
        assert!(keys.install("acct", "89abcdef", Zeroizing::new([2; 32])));
        assert!(keys.install("acct", "0123abcd", Zeroizing::new([1; 32])));
        assert_eq!(keys.current_kid("acct"), Some("0123abcd"));
        assert_eq!(keys.previous_kids("acct"), vec!["89abcdef".to_string()]);
    }

    #[test]
    fn reconcile_drops_what_the_signed_states_retired() {
        let mut keys = keys_with("0123abcd", 1);
        keys.install("acct", "89abcdef", Zeroizing::new([2; 32]));
        keys.install("gone", "11112222", Zeroizing::new([3; 32]));
        keys.install("waiting", "33334444", Zeroizing::new([4; 32]));
        let mut modes = SignedModes::new();
        modes.insert("acct".into(), Some((EncryptionMode::Enabling, Some("89abcdef".into()))));
        modes.insert("waiting".into(), None);
        assert!(keys.reconcile(&modes), "an account no verified Astation names goes");
        assert_eq!(keys.current_kid("gone"), None);
        assert_eq!(keys.current_kid("waiting"), Some("33334444"), "no state yet: kept");
        assert_eq!(keys.previous_kids("acct"), vec!["0123abcd".to_string()]);
        assert!(!keys.reconcile(&modes));
        modes.insert("acct".into(), Some((EncryptionMode::On, Some("89abcdef".into()))));
        assert!(keys.reconcile(&modes));
        assert!(keys.previous_kids("acct").is_empty(), "on with the current kid: history goes");
        modes.insert("acct".into(), Some((EncryptionMode::Off, None)));
        assert!(keys.reconcile(&modes));
        assert_eq!(keys.current_kid("acct"), None, "off: K goes");
    }

    #[test]
    fn the_wire_form_round_trips_and_is_checked() {
        let mut keys = keys_with("0123abcd", 1);
        keys.install("acct", "89abcdef", Zeroizing::new([2; 32]));
        let json = serde_json::to_string(&keys.to_wire()).unwrap();
        let back = AccountKeys::from_wire(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(back.current_kid("acct"), Some("89abcdef"));
        assert_eq!(back.previous_kids("acct"), vec!["0123abcd".to_string()]);
        let bad_kid = r#"{"acct":{"kid":"XYZ","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}"#;
        assert!(AccountKeys::from_wire(serde_json::from_str(bad_kid).unwrap()).is_err());
        let short_key = r#"{"acct":{"kid":"0123abcd","key":"AAAA"}}"#;
        assert!(AccountKeys::from_wire(serde_json::from_str(short_key).unwrap()).is_err());
    }

    #[test]
    fn ops_and_results_are_externally_tagged() {
        assert_eq!(
            serde_json::to_string(&CryptOp::seal("r", "f", b"hi")).unwrap(),
            r#"{"seal":{"record":"r","field":"f","plain":"aGk="}}"#
        );
        assert_eq!(
            serde_json::to_string(&CryptOp::keyed_hash(b"hi")).unwrap(),
            r#"{"keyed_hash":{"value":"aGk="}}"#
        );
        let back: CryptOut = serde_json::from_str(r#"{"opened":"aGk="}"#).unwrap();
        assert_eq!(&*back.into_plain().unwrap(), b"hi");
        assert!(CryptOut::Sealed("e1.x".into()).into_plain().is_err());
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test memory::account_keys`
Expected: FAIL to compile (`AccountKeys`, `CryptOp`, `seal_field_with_nonce` … not found).

- [ ] **Step 4: Write the implementation above the tests**

Put this at the top of `src/memory/account_keys.rs`:

```rust
//! The account keys `K` (current and previous, per account) as the key agent
//! holds them, and the field operations it performs for callers that never
//! see `K`: `e1.` seals and opens, `h1.` keyed hashes. Formats and associated
//! data are exactly those of build steps 0–2a, so ciphertext on the relay
//! doesn't change. See designs/e2e-encryption.md "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::memory::crypto::{EncryptionMode, valid_kid};
use crate::memory::device_keys::decode32;

/// The error every caller treats as "no `K` yet": sync keeps its changes
/// queued, and atem asks Astation for the key.
pub const MISSING_KEY: &str =
    "this account requires encryption; connect to Astation to receive the encryption key";

#[derive(Clone)]
pub struct AccountKey {
    pub kid: String,
    pub key: Zeroizing<[u8; 32]>,
}

/// One account's current `K` and the keys it replaced, kept while a
/// rotation's migration may still meet fields sealed under them.
#[derive(Clone)]
struct KeyRing {
    current: AccountKey,
    previous: Vec<AccountKey>,
}

#[derive(Clone, Default)]
pub struct AccountKeys {
    rings: BTreeMap<String, KeyRing>,
}

/// The latest signed state of each account a verified Astation names:
/// `(mode, kid)`, or `None` while that Astation has sent no state yet.
pub type SignedModes = BTreeMap<String, Option<(EncryptionMode, Option<String>)>>;

impl AccountKeys {
    pub fn is_empty(&self) -> bool {
        self.rings.is_empty()
    }

    pub fn current_kid(&self, account: &str) -> Option<&str> {
        self.rings.get(account).map(|ring| ring.current.kid.as_str())
    }

    /// The kids of the keys `account`'s current key replaced, oldest first.
    pub fn previous_kids(&self, account: &str) -> Vec<String> {
        self.rings
            .get(account)
            .map(|ring| ring.previous.iter().map(|key| key.kid.clone()).collect())
            .unwrap_or_default()
    }

    /// Makes `key` the current key of `account`; a different current key
    /// becomes a previous one. Returns whether anything changed.
    pub fn install(&mut self, account: &str, kid: &str, key: Zeroizing<[u8; 32]>) -> bool {
        let fresh = AccountKey {
            kid: kid.into(),
            key,
        };
        let Some(ring) = self.rings.get_mut(account) else {
            self.rings.insert(
                account.into(),
                KeyRing {
                    current: fresh,
                    previous: Vec::new(),
                },
            );
            return true;
        };
        if ring.current.kid == kid && *ring.current.key == *fresh.key {
            return false;
        }
        let replaced = std::mem::replace(&mut ring.current, fresh);
        ring.previous
            .retain(|previous| previous.kid != kid && previous.kid != replaced.kid);
        if replaced.kid != kid {
            ring.previous.push(replaced);
        }
        true
    }

    /// Drops what the signed states retired: every key of an account no
    /// verified Astation names or whose state is `off`, and the previous keys
    /// once the state is `on` with the current kid (every field has moved to
    /// it). Returns whether anything changed.
    pub fn reconcile(&mut self, modes: &SignedModes) -> bool {
        let before = self.shape();
        self.rings.retain(|account, _| match modes.get(account) {
            None | Some(Some((EncryptionMode::Off, _))) => false,
            Some(_) => true,
        });
        for (account, ring) in &mut self.rings {
            if let Some(Some((EncryptionMode::On, kid))) = modes.get(account)
                && kid.as_deref() == Some(ring.current.kid.as_str())
            {
                ring.previous.clear();
            }
        }
        before != self.shape()
    }

    fn shape(&self) -> (usize, usize) {
        (
            self.rings.len(),
            self.rings.values().map(|ring| ring.previous.len()).sum(),
        )
    }

    /// Runs `ops` for `account` under the signed `mode` and `kid`, results in
    /// order. Seals and hashes use the current key, which must be `kid`;
    /// opens use the key the field names (a previous one only while the mode
    /// isn't `on`). Any failure fails the whole batch.
    pub fn crypt(
        &self,
        account: &str,
        mode: EncryptionMode,
        kid: Option<&str>,
        ops: Vec<CryptOp>,
    ) -> Result<Vec<CryptOut>> {
        if mode == EncryptionMode::Off {
            bail!("encryption is off for this account");
        }
        let ring = self
            .rings
            .get(account)
            .filter(|ring| Some(ring.current.kid.as_str()) == kid)
            .ok_or_else(|| anyhow!(MISSING_KEY))?;
        ops.into_iter()
            .map(|op| match op {
                CryptOp::Seal {
                    record,
                    field,
                    plain,
                } => {
                    let plain = decode_bytes(&plain, "plain text")?;
                    Ok(CryptOut::Sealed(seal_field(
                        &ring.current,
                        &record,
                        &field,
                        &plain,
                    )?))
                }
                CryptOp::Open {
                    record,
                    field,
                    value,
                } => {
                    let plain = open_field(ring, mode, &record, &field, &value)?;
                    Ok(CryptOut::Opened(Zeroizing::new(STANDARD.encode(&plain[..]))))
                }
                CryptOp::KeyedHash { value } => {
                    let value = decode_bytes(&value, "hash input")?;
                    Ok(CryptOut::Hashed(keyed_hash(&ring.current, &value)))
                }
            })
            .collect()
    }

    /// The form stored inside the sealed payload of `device_keys.sealed`.
    pub fn to_wire(&self) -> AccountKeysWire {
        self.rings
            .iter()
            .map(|(account, ring)| {
                (
                    account.clone(),
                    RingWire {
                        kid: ring.current.kid.clone(),
                        key: Zeroizing::new(STANDARD.encode(&ring.current.key[..])),
                        previous: ring
                            .previous
                            .iter()
                            .map(|key| KeyWire {
                                kid: key.kid.clone(),
                                key: Zeroizing::new(STANDARD.encode(&key.key[..])),
                            })
                            .collect(),
                    },
                )
            })
            .collect()
    }

    pub fn from_wire(wire: AccountKeysWire) -> Result<Self> {
        let mut rings = BTreeMap::new();
        for (account, ring) in wire {
            let current = key_from_wire(ring.kid, &ring.key)?;
            let previous = ring
                .previous
                .into_iter()
                .map(|key| key_from_wire(key.kid, &key.key))
                .collect::<Result<Vec<_>>>()?;
            rings.insert(account, KeyRing { current, previous });
        }
        Ok(Self { rings })
    }
}

/// One stored key: base64, wiped when dropped.
#[derive(Serialize, Deserialize)]
pub struct KeyWire {
    kid: String,
    key: Zeroizing<String>,
}

/// One account's keys inside the sealed payload.
#[derive(Serialize, Deserialize)]
pub struct RingWire {
    kid: String,
    key: Zeroizing<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    previous: Vec<KeyWire>,
}

pub type AccountKeysWire = BTreeMap<String, RingWire>;

fn key_from_wire(kid: String, key: &str) -> Result<AccountKey> {
    if !valid_kid(&kid) {
        bail!("a sealed account key id is invalid");
    }
    Ok(AccountKey {
        kid,
        key: decode32(key, "sealed account key")?,
    })
}

fn decode_bytes(value: &str, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        STANDARD
            .decode(value)
            .with_context(|| format!("{what} is not base64"))?,
    ))
}

/// One operation of a `Crypt` request. Externally tagged
/// (`{"seal": {...}}`): serde reads it straight into its fields, never
/// through an unwiped buffer, so plain text stays in `Zeroizing` memory.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptOp {
    /// `plain` is base64 of the bytes to seal.
    Seal {
        record: String,
        field: String,
        plain: Zeroizing<String>,
    },
    /// `value` is an `e1.` field (empty stays empty).
    Open {
        record: String,
        field: String,
        value: String,
    },
    /// `value` is base64 of the bytes to HMAC.
    KeyedHash { value: Zeroizing<String> },
}

impl CryptOp {
    pub fn seal(record: &str, field: &str, plain: &[u8]) -> Self {
        Self::Seal {
            record: record.into(),
            field: field.into(),
            plain: Zeroizing::new(STANDARD.encode(plain)),
        }
    }

    pub fn open(record: &str, field: &str, value: &str) -> Self {
        Self::Open {
            record: record.into(),
            field: field.into(),
            value: value.into(),
        }
    }

    pub fn keyed_hash(value: &[u8]) -> Self {
        Self::KeyedHash {
            value: Zeroizing::new(STANDARD.encode(value)),
        }
    }

    /// Roughly what this op adds to a request line and its reply, for batching.
    pub fn wire_len(&self) -> usize {
        match self {
            Self::Seal {
                record,
                field,
                plain,
            } => record.len() + field.len() + plain.len() * 2 + 96,
            Self::Open {
                record,
                field,
                value,
            } => record.len() + field.len() + value.len() * 2 + 96,
            Self::KeyedHash { value } => value.len() + 160,
        }
    }
}

/// One result of a `Crypt` request, in the order of the ops.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptOut {
    /// An `e1.` field (empty for empty plain text).
    Sealed(String),
    /// Base64 of the opened bytes.
    Opened(Zeroizing<String>),
    /// An `h1.` keyed hash.
    Hashed(String),
}

impl CryptOut {
    pub fn into_text(self) -> Result<String> {
        match self {
            Self::Sealed(value) | Self::Hashed(value) => Ok(value),
            Self::Opened(_) => bail!("the key agent answered an open where a seal or hash was asked"),
        }
    }

    pub fn into_plain(self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Opened(encoded) => decode_bytes(&encoded, "an opened field"),
            _ => bail!("the key agent answered a seal or hash where an open was asked"),
        }
    }
}

fn field_aad(record: &str, field: &str) -> Vec<u8> {
    format!("{record}\n{field}").into_bytes()
}

/// `e1.<kid>.<base64(nonce ‖ ciphertext)>`, XChaCha20-Poly1305, AAD
/// `"{record}\n{field}"`; empty plain text stays empty.
pub(crate) fn seal_field(key: &AccountKey, record: &str, field: &str, plain: &[u8]) -> Result<String> {
    seal_field_with_nonce(
        key,
        record,
        field,
        plain,
        &XChaCha20Poly1305::generate_nonce(&mut OsRng),
    )
}

fn seal_field_with_nonce(
    key: &AccountKey,
    record: &str,
    field: &str,
    plain: &[u8],
    nonce: &XNonce,
) -> Result<String> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    let cipher = XChaCha20Poly1305::new((&*key.key).into());
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plain,
                aad: &field_aad(record, field),
            },
        )
        .map_err(|_| anyhow!("field encryption failed"))?;
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&ciphertext);
    Ok(format!("e1.{}.{}", key.kid, STANDARD.encode(payload)))
}

fn open_field(
    ring: &KeyRing,
    mode: EncryptionMode,
    record: &str,
    field: &str,
    value: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    if value.is_empty() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    let rest = value
        .strip_prefix("e1.")
        .ok_or_else(|| anyhow!("encrypted field is malformed"))?;
    let (kid, encoded) = rest
        .split_once('.')
        .ok_or_else(|| anyhow!("encrypted field is malformed"))?;
    let key = if ring.current.kid == kid {
        &ring.current
    } else if mode != EncryptionMode::On {
        ring.previous
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| anyhow!("encrypted field uses an unavailable key id"))?
    } else {
        bail!("encrypted field uses an unavailable key id");
    };
    let payload = STANDARD.decode(encoded).context("invalid encrypted field")?;
    if payload.len() < 40 {
        bail!("encrypted field is too short");
    }
    let cipher = XChaCha20Poly1305::new((&*key.key).into());
    cipher
        .decrypt(
            XNonce::from_slice(&payload[..24]),
            Payload {
                msg: &payload[24..],
                aad: &field_aad(record, field),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("encrypted field authentication failed"))
}

/// `h1.<kid>.<hex HMAC-SHA256(K, value)>`.
fn keyed_hash(key: &AccountKey, value: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.key[..]).expect("HMAC accepts 32 bytes");
    mac.update(value);
    let digest: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("h1.{}.{digest}", key.kid)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test memory::account_keys`
Expected: PASS (9 tests). `fields_keep_the_format_of_steps_0_to_2a` proves the relay format is unchanged.

- [ ] **Step 6: Format and build**

Run: `rustfmt --edition 2024 src/memory/account_keys.rs && cargo build`
Expected: builds. `dead_code` warnings for the new items are expected until Task 4 uses them; do not add `allow`s.

- [ ] **Step 7: Commit**

```bash
git add src/memory/account_keys.rs src/memory/mod.rs
git commit -m "feat(memory): account keys and the e1/h1 field operations for the key agent

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 2: The sealed payload carries the account keys

**Files:**
- Modify: `src/memory/device_keys.rs` (`sealed_plaintext`, `from_sealed_plaintext`, `SealedPlainRef`, `SealedPlain`)
- Modify: `src/memory/storage_key.rs` (`SealedDeviceKeys::seal`, `open`)
- Test: both files' `mod tests`

**Interfaces:**
- Consumes: `AccountKeys`, `AccountKeysWire`, `AccountKeys::{to_wire, from_wire, is_empty}` (Task 1).
- Produces:
  - `DeviceKeys::sealed_plaintext_with(&self, accounts: &AccountKeys) -> Result<Zeroizing<Vec<u8>>>`
  - `DeviceKeys::from_sealed_plaintext_with(plain: &[u8], unlock_auth: UnlockAuthKey) -> Result<(DeviceKeys, AccountKeys)>`
  - `SealedDeviceKeys::seal_with(keys: &DeviceKeys, accounts: &AccountKeys, device_id: &str, storage_kid: &str, storage_key: &[u8; 32]) -> Result<SealedDeviceKeys>`
  - `SealedDeviceKeys::open_with_accounts(&self, storage_key: &[u8; 32], unlock_auth: UnlockAuthKey) -> Result<(DeviceKeys, AccountKeys)>`
  - `seal` / `open` / `sealed_plaintext` / `from_sealed_plaintext` keep their signatures (no account keys).

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `src/memory/device_keys.rs`:

```rust
    #[test]
    fn account_keys_add_one_field_to_the_sealed_plaintext() {
        use crate::memory::account_keys::AccountKeys;
        let keys = DeviceKeys::generate();
        let mut accounts = AccountKeys::default();
        accounts.install("acct", "0123abcd", Zeroizing::new([1; 32]));
        let plain = keys.sealed_plaintext_with(&accounts).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        let mut fields: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort();
        assert_eq!(fields, ["account_keys", "device", "device_sign", "version"]);
        assert_eq!(json["account_keys"]["acct"]["kid"], "0123abcd");
        let (back, held) =
            DeviceKeys::from_sealed_plaintext_with(&plain, keys.unlock_auth_key()).unwrap();
        assert_eq!(back.device_pub(), keys.device_pub());
        assert_eq!(held.current_kid("acct"), Some("0123abcd"));
        // No account keys: exactly the bytes of step 2a.
        assert_eq!(
            *keys.sealed_plaintext_with(&AccountKeys::default()).unwrap(),
            *keys.sealed_plaintext().unwrap()
        );
    }
```

Append to `mod tests` in `src/memory/storage_key.rs`:

```rust
    #[test]
    fn account_keys_ride_in_the_sealed_file() {
        use crate::memory::account_keys::AccountKeys;
        let keys = DeviceKeys::generate();
        let storage_key = new_storage_key();
        let mut accounts = AccountKeys::default();
        accounts.install("acct", "0123abcd", Zeroizing::new([1; 32]));
        accounts.install("acct", "89abcdef", Zeroizing::new([2; 32]));
        let file =
            SealedDeviceKeys::seal_with(&keys, &accounts, "dev-1", "0a1b2c3d", &storage_key)
                .unwrap();
        let (opened, held) = file
            .open_with_accounts(&storage_key, keys.unlock_auth_key())
            .unwrap();
        assert_eq!(opened.device_pub(), keys.device_pub());
        assert_eq!(held.current_kid("acct"), Some("89abcdef"));
        assert_eq!(held.previous_kids("acct"), vec!["0123abcd".to_string()]);
        // The plain open still reads the device keys of a step-2b file.
        assert_eq!(
            file.open(&storage_key, keys.unlock_auth_key())
                .unwrap()
                .device_sign_pub(),
            keys.device_sign_pub()
        );
    }

    #[test]
    fn a_step_2a_file_holds_no_account_keys() {
        let keys = DeviceKeys::generate();
        let storage_key = new_storage_key();
        let file = sealed(&keys, &storage_key);
        let (_, held) = file
            .open_with_accounts(&storage_key, keys.unlock_auth_key())
            .unwrap();
        assert!(held.is_empty());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test sealed`
Expected: FAIL to compile (`sealed_plaintext_with`, `seal_with`, `open_with_accounts` not found).

- [ ] **Step 3: Implement in `device_keys.rs`**

Add the import `use crate::memory::account_keys::{AccountKeys, AccountKeysWire};` next to the existing `use crate::memory::statements::SignedWire;`.

Replace `sealed_plaintext` and `from_sealed_plaintext` with:

```rust
    /// The device key and device signing key, serialized for
    /// `device_keys.sealed`. The unlock-auth key is not included.
    pub fn sealed_plaintext(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.sealed_plaintext_with(&AccountKeys::default())
    }

    /// Like `sealed_plaintext`, plus the account keys (`K` and the keys it
    /// replaced, build step 2b). With none the bytes are exactly step 2a's.
    pub fn sealed_plaintext_with(&self, accounts: &AccountKeys) -> Result<Zeroizing<Vec<u8>>> {
        let device = Zeroizing::new(STANDARD.encode(self.device.to_bytes()));
        let device_sign = Zeroizing::new(STANDARD.encode(self.device_sign.to_bytes()));
        let account_keys = (!accounts.is_empty()).then(|| accounts.to_wire());
        Ok(Zeroizing::new(serde_json::to_vec(&SealedPlainRef {
            version: 1,
            device: &device,
            device_sign: &device_sign,
            account_keys: account_keys.as_ref(),
        })?))
    }

    pub fn from_sealed_plaintext(plain: &[u8], unlock_auth: UnlockAuthKey) -> Result<Self> {
        Self::from_sealed_plaintext_with(plain, unlock_auth).map(|(keys, _)| keys)
    }

    /// The device keys and the account keys of a sealed payload (none in a
    /// step-2a file).
    pub fn from_sealed_plaintext_with(
        plain: &[u8],
        unlock_auth: UnlockAuthKey,
    ) -> Result<(Self, AccountKeys)> {
        let SealedPlain {
            version,
            device,
            device_sign,
            account_keys,
        } = serde_json::from_slice(plain).context("sealed device keys are unreadable")?;
        let (device, device_sign) = (Zeroizing::new(device), Zeroizing::new(device_sign));
        if version != 1 {
            bail!("unsupported sealed device keys version {version}");
        }
        let accounts = AccountKeys::from_wire(account_keys)?;
        Ok((
            Self {
                device: StaticSecret::from(*decode32(&device, "device key")?),
                device_sign: SigningKey::from_bytes(&*decode32(&device_sign, "device signing key")?),
                unlock_auth: unlock_auth.key,
            },
            accounts,
        ))
    }
```

Replace the two payload structs with:

```rust
#[derive(Serialize)]
struct SealedPlainRef<'a> {
    version: u8,
    device: &'a str,
    device_sign: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_keys: Option<&'a AccountKeysWire>,
}

#[derive(Deserialize)]
struct SealedPlain {
    version: u8,
    device: String,
    device_sign: String,
    #[serde(default)]
    account_keys: AccountKeysWire,
}
```

- [ ] **Step 4: Implement in `storage_key.rs`**

Add `use crate::memory::account_keys::AccountKeys;` to the imports. Replace `SealedDeviceKeys::seal` and `SealedDeviceKeys::open` with:

```rust
    pub fn seal(
        keys: &DeviceKeys,
        device_id: &str,
        storage_kid: &str,
        storage_key: &[u8; 32],
    ) -> Result<Self> {
        Self::seal_with(keys, &AccountKeys::default(), device_id, storage_kid, storage_key)
    }

    /// Seals the device keys and the account keys (build step 2b) under
    /// `storage_key`.
    pub fn seal_with(
        keys: &DeviceKeys,
        accounts: &AccountKeys,
        device_id: &str,
        storage_kid: &str,
        storage_key: &[u8; 32],
    ) -> Result<Self> {
        if !crate::memory::crypto::valid_kid(storage_kid) {
            bail!("storage key id must be 8 lowercase hex characters");
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(storage_key));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let plain = keys.sealed_plaintext_with(accounts)?;
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
        self.open_with_accounts(storage_key, unlock_auth)
            .map(|(keys, _)| keys)
    }

    /// The device keys and the account keys the file carries.
    pub fn open_with_accounts(
        &self,
        storage_key: &[u8; 32],
        unlock_auth: UnlockAuthKey,
    ) -> Result<(DeviceKeys, AccountKeys)> {
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
        DeviceKeys::from_sealed_plaintext_with(&plain, unlock_auth)
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test sealed`
Expected: PASS, including the existing `sealed_plaintext_holds_only_the_two_sealed_keys` and `sealed_keys_open_with_the_storage_key_only`.

Run: `cargo test memory::kat_tests`
Expected: PASS (vectors unchanged).

- [ ] **Step 6: Format and commit**

```bash
rustfmt --edition 2024 src/memory/device_keys.rs src/memory/storage_key.rs
git add src/memory/device_keys.rs src/memory/storage_key.rs
git commit -m "feat(memory): device_keys.sealed carries the account keys

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 3: `project_names.json`, the signed mode, and key paths

**Files:**
- Create: `src/memory/project_names.rs`
- Modify: `src/memory/mod.rs` (one line), `src/memory/verification.rs` (`KeyPaths`, `stored_state`, new `AccountMode`/`account_mode`, test), `src/memory/trust.rs` (`verified_entries`)
- Test: `src/memory/project_names.rs`, `src/memory/verification.rs`

**Interfaces:**
- Consumes: `crate::memory::crypto::write_private`, `TrustStore::lock` (existing).
- Produces:
  - `pub struct ProjectNames` with `load_from(&Path) -> Result<Self>`, `name(&self, account: &str, hash: &str) -> Option<&str>`, `len(&self, account: &str) -> usize`
  - `pub fn remember(path: &Path, account: &str, pairs: impl IntoIterator<Item = (String, String)>) -> Result<()>`
  - `pub fn forget_account_at(path: &Path, account: &str) -> Result<()>`
  - `KeyPaths.project_names: PathBuf` (`<dir>/project_names.json`)
  - `pub(crate) fn stored_state(entry: &AstationTrust) -> Result<Option<AccountState>>` (verification.rs, was private)
  - `pub struct AccountMode { pub mode: EncryptionMode, pub data_account: String, pub kid: Option<String> }` and `pub fn account_mode(trust_path: &Path, astation_id: &str) -> Result<AccountMode>` (verification.rs)
  - `TrustStore::verified_entries(&self) -> impl Iterator<Item = &AstationTrust>`

- [ ] **Step 1: Register the module**

In `src/memory/mod.rs` add after `pub mod account_keys;`:

```rust
pub mod project_names;
```

- [ ] **Step 2: Write `project_names.rs` tests first**

Create `src/memory/project_names.rs` with this `mod tests` at the end:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn pair(hash: &str, name: &str) -> (String, String) {
        (hash.to_string(), name.to_string())
    }

    #[test]
    fn names_round_trip_per_account_in_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        assert_eq!(ProjectNames::load_from(&path).unwrap().len("acct"), 0);
        remember(&path, "acct", [pair("h1.0123abcd.aa", "github.com/agora/atem")]).unwrap();
        remember(&path, "other", [pair("h1.0123abcd.bb", "github.com/agora/dialf")]).unwrap();
        let names = ProjectNames::load_from(&path).unwrap();
        assert_eq!(names.name("acct", "h1.0123abcd.aa"), Some("github.com/agora/atem"));
        assert_eq!(names.name("acct", "h1.0123abcd.bb"), None, "names are per account");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        forget_account_at(&path, "acct").unwrap();
        let names = ProjectNames::load_from(&path).unwrap();
        assert_eq!(names.len("acct"), 0);
        assert_eq!(names.len("other"), 1);
    }

    #[test]
    fn nothing_new_writes_nothing_and_nothing_is_created_by_a_forget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        remember(&path, "acct", Vec::new()).unwrap();
        forget_account_at(&path, "acct").unwrap();
        assert!(!path.exists());
        remember(&path, "acct", [pair("h1.x.aa", "a")]).unwrap();
        let before = std::fs::read(&path).unwrap();
        remember(&path, "acct", [pair("h1.x.aa", "a")]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn an_unreadable_file_is_an_error_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        std::fs::write(&path, b"not json").unwrap();
        let error = format!("{:#}", ProjectNames::load_from(&path).err().unwrap());
        assert!(error.contains("project_names.json"), "{error}");
    }

    #[test]
    fn concurrent_writers_keep_each_others_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        let writers: Vec<_> = (0..4)
            .map(|writer| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for n in 0..25 {
                        remember(&path, "acct", [pair(&format!("h1.x.{writer}-{n}"), "p")]).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(ProjectNames::load_from(&path).unwrap().len("acct"), 100);
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test memory::project_names`
Expected: FAIL to compile (`ProjectNames`, `remember`, `forget_account_at` not found).

- [ ] **Step 4: Implement `project_names.rs`** (above the tests)

```rust
//! `~/.config/atem/project_names.json`: the readable project key each `h1.`
//! project hash on the relay stands for, per account. The relay sees only
//! the hash (keyed by `K`, which never leaves the key agent); atem keeps the
//! names locally to show and filter by them. No secrets, still 0600 and
//! written atomically. See designs/e2e-encryption.md "What each side stores".
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectNames {
    #[serde(default = "version_one")]
    version: u8,
    #[serde(default)]
    accounts: BTreeMap<String, BTreeMap<String, String>>,
}

fn version_one() -> u8 {
    1
}

impl ProjectNames {
    pub fn load_from(path: &Path) -> Result<Self> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    version: 1,
                    ..Self::default()
                });
            }
            Err(error) => return Err(error.into()),
        };
        let names: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("{} is unreadable", path.display()))?;
        if names.version != 1 {
            bail!("unsupported project_names.json version {}", names.version);
        }
        Ok(names)
    }

    fn save_to(&mut self, path: &Path) -> Result<()> {
        self.version = 1;
        crate::memory::crypto::write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn name(&self, account: &str, hash: &str) -> Option<&str> {
        self.accounts
            .get(account)
            .and_then(|names| names.get(hash))
            .map(String::as_str)
    }

    pub fn len(&self, account: &str) -> usize {
        self.accounts.get(account).map_or(0, BTreeMap::len)
    }
}

/// Records `hash → name` pairs for `account`: a read-modify-write under an
/// `flock` on `project_names.lock` (the helper cred_state.json uses), so the
/// key agent and other atem commands keep each other's names. Writes only
/// when something is new.
pub fn remember(
    path: &Path,
    account: &str,
    pairs: impl IntoIterator<Item = (String, String)>,
) -> Result<()> {
    let pairs: Vec<(String, String)> = pairs.into_iter().collect();
    if pairs.is_empty() {
        return Ok(());
    }
    let _lock = crate::memory::trust::TrustStore::lock(path)?;
    let mut names = ProjectNames::load_from(path)?;
    let entry = names.accounts.entry(account.into()).or_default();
    let mut changed = false;
    for (hash, name) in pairs {
        if entry.get(&hash) != Some(&name) {
            entry.insert(hash, name);
            changed = true;
        }
    }
    if changed {
        names.save_to(path)?;
    }
    Ok(())
}

/// Forgets every name of `account` (a first verification drops what the
/// unauthenticated path may have stored). A missing file stays missing.
pub fn forget_account_at(path: &Path, account: &str) -> Result<()> {
    if path.symlink_metadata().is_err() {
        return Ok(());
    }
    let _lock = crate::memory::trust::TrustStore::lock(path)?;
    let mut names = ProjectNames::load_from(path)?;
    if names.accounts.remove(account).is_some() {
        names.save_to(path)?;
    }
    Ok(())
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test memory::project_names`
Expected: PASS (4 tests).

- [ ] **Step 6: `KeyPaths.project_names`, `verified_entries`, `stored_state`, `account_mode` — write the failing tests**

In `src/memory/verification.rs`, test `key_paths_name_every_key_file` (in `mod tests`), add:

```rust
        assert_eq!(paths.project_names, std::path::Path::new("/x/project_names.json"));
```

Add to `mod tests` (the first test module of `verification.rs`):

```rust
    #[test]
    fn the_mode_comes_from_the_signed_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, fake, _) = verify(dir.path(), EncryptionMode::On);
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap(),
            AccountMode {
                mode: EncryptionMode::On,
                data_account: "acct".into(),
                kid: Some("0123abcd".into()),
            }
        );
        apply_account_state(
            &paths,
            ASTATION_ID,
            Some(&signed_state(&fake, EncryptionMode::Disabling, 2)),
        )
        .unwrap();
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::Disabling
        );
        // Unverified: off, whatever any file says.
        assert_eq!(
            account_mode(&paths.trust, "astation-2").unwrap(),
            AccountMode {
                mode: EncryptionMode::Off,
                data_account: "astation-2".into(),
                kid: None,
            }
        );
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.verified_entries().count(), 1);
    }
```

Run: `cargo test memory::verification`
Expected: FAIL to compile (`project_names` field, `account_mode`, `AccountMode`, `verified_entries` not found).

- [ ] **Step 7: Implement**

`src/memory/trust.rs`, after `pub fn verified(...)`:

```rust
    /// Every verified Astation's entry.
    pub fn verified_entries(&self) -> impl Iterator<Item = &AstationTrust> {
        self.astations.values()
    }
```

`src/memory/verification.rs` (edit by hand):

1. In `struct KeyPaths`, replace `pub data_keys: PathBuf,` with:

```rust
    /// `data_keys.enc` from build steps 0–2a (`K`, project names, under the
    /// machine-bound key). The key agent moves it into `device_keys_sealed`
    /// and `project_names` at the first unlock and deletes it.
    pub data_keys: PathBuf,
    /// `project_names.json`: `h1.` project hash → readable project key.
    pub project_names: PathBuf,
```

2. In `KeyPaths::in_dir`, after `data_keys: dir.join("data_keys.enc"),` add `project_names: dir.join("project_names.json"),`.

3. Change `fn stored_state(entry: &AstationTrust)` to `pub(crate) fn stored_state(entry: &AstationTrust)`.

4. Change the import `use crate::memory::crypto::EncryptionContext;` to `use crate::memory::crypto::{EncryptionContext, EncryptionMode};`.

5. After `stored_state`, add:

```rust
/// What the latest signed account state says for this device and
/// `astation_id`: the one source of the encryption mode and kid (build
/// step 2b). `data_account` is the Astation id when it isn't verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMode {
    pub mode: EncryptionMode,
    pub data_account: String,
    pub kid: Option<String>,
}

/// Unverified devices are `off`: they never obey stored state, which may
/// come from the old unauthenticated path. A verified device without a
/// signed state yet must not guess: that is an error.
pub fn account_mode(trust_path: &Path, astation_id: &str) -> Result<AccountMode> {
    let trust = TrustStore::load_from(trust_path)?;
    let Some(entry) = trust.verified(astation_id) else {
        return Ok(AccountMode {
            mode: EncryptionMode::Off,
            data_account: astation_id.into(),
            kid: None,
        });
    };
    let state = stored_state(entry)?.ok_or_else(|| {
        anyhow!("waiting for Astation's signed encryption state; reconnect to Astation")
    })?;
    Ok(AccountMode {
        mode: state.mode,
        data_account: state.account,
        kid: state.kid,
    })
}
```

- [ ] **Step 8: Run the tests**

Run: `cargo test memory::verification`
Expected: PASS (all existing tests plus `the_mode_comes_from_the_signed_state_only`).

- [ ] **Step 9: Format and commit**

```bash
rustfmt --edition 2024 src/memory/project_names.rs src/memory/trust.rs
git add src/memory/project_names.rs src/memory/mod.rs src/memory/verification.rs src/memory/trust.rs
git commit -m "feat(memory): project_names.json and the mode from the signed state

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 4: The key agent holds `K` and serves `Crypt`

**Files:**
- Modify: `src/memory/key_agent.rs`
- Modify: `src/memory/fake_astation.rs` (test helpers)
- Create: `src/memory/k_agent_tests.rs`
- Modify: `src/memory/mod.rs` (one line)
- Test: `src/memory/k_agent_tests.rs`

**Interfaces:**
- Consumes: Task 1 (`AccountKeys`, `CryptOp`, `CryptOut`, `SignedModes`), Task 2 (`seal_with`, `open_with_accounts`), Task 3 (`stored_state`, `verified_entries`).
- Produces:
  - `Request::InstallGrant { astation_id: String, grant: GrantWire }` → `Reply::GrantInstalled { kid: String }`
  - `Request::CheckGrant { grant: GrantWire, trust: AstationTrust }` → `Reply::GrantChecked { kid: String }`
  - `Request::Crypt { astation_id: String, ops: Vec<CryptOp> }` → `Reply::Crypted { results: Vec<CryptOut> }`
  - `Request::HeldKid { astation_id: String }` → `Reply::HeldKid { kid: Option<String> }`
  - `KeyAgentApi::install_grant(&self, astation_id: &str, grant: &GrantWire) -> Result<String>`
  - `KeyAgentApi::check_grant(&self, grant: &GrantWire, trust: &AstationTrust) -> Result<String>`
  - `KeyAgentApi::crypt(&self, astation_id: &str, ops: Vec<CryptOp>) -> Result<Vec<CryptOut>>`
  - `KeyAgentApi::held_kid(&self, astation_id: &str) -> Result<Option<String>>`
  - `impl<T: KeyAgentApi + ?Sized> KeyAgentApi for std::sync::Arc<T>`
  - `pub(crate) fn open_sealed_checked(...) -> Result<(DeviceKeys, AccountKeys)>`
  - `#[cfg(test)] pub(crate) fn holds_k(agent: &dyn KeyAgentApi, astation_id: &str) -> bool`
  - fake_astation: `pub(crate) fn unlock_with(agent: &dyn KeyAgentApi, server: &FakeKeyServer, paths: &KeyPaths) -> Result<String>`, `pub(crate) fn set_state(paths: &KeyPaths, astation: &FakeAstation, mode: EncryptionMode, kid: Option<&str>, epoch: u64)`, `pub(crate) struct UnlockedDevice { pub paths, pub server, pub keys, pub agent: Arc<Mutex<KeyAgent>>, .. }` with `new(dir: &Path) -> Self`, `state(&mut self, mode, kid: Option<&str>)`, `grant(&self, kid: &str, key: [u8; 32]) -> GrantWire`, `set_key(&mut self, mode, kid: &str, key: [u8; 32])`
  - `OpenGrant` / `Reply::Grant` still exist after this task (removed in Task 5).

- [ ] **Step 1: Register the test module**

In `src/memory/mod.rs`, after `#[cfg(test)] mod fake_astation;` add:

```rust
#[cfg(test)]
mod k_agent_tests;
```

- [ ] **Step 2: Add the test helpers to `fake_astation.rs`**

Add to the imports of `src/memory/fake_astation.rs`:

```rust
use crate::memory::crypto::EncryptionMode;
use crate::memory::device_keys::UnlockAuthKey;
use crate::memory::grant::{GrantWire, seal_k_grant};
use crate::memory::key_agent::{KeyAgent, KeyAgentApi, build_unlock_request, test_agent};
use crate::memory::statements::AccountState;
use std::sync::{Arc, Mutex};
```

Append (before the file's `mod tests`):

```rust
/// What `atem cred unlock` does with `agent`, against `server`.
pub(crate) fn unlock_with(
    agent: &dyn KeyAgentApi,
    server: &FakeKeyServer,
    paths: &KeyPaths,
) -> Result<String> {
    let challenge = agent.begin_unlock(ASTATION_ID)?;
    let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)?
        .ok_or_else(|| anyhow!("unlock_auth_key is missing"))?;
    let request = build_unlock_request(&challenge, "boot-1", 1_760_000_000, &unlock_auth);
    let grant = server.grant_unlock(&request)?;
    agent.finish_unlock(ASTATION_ID, &request.statement, &grant)
}

/// Signs `mode`/`kid` at `epoch` as `astation` and accepts it into
/// `paths.trust`, as `apply_account_state` does.
pub(crate) fn set_state(
    paths: &KeyPaths,
    astation: &FakeAstation,
    mode: EncryptionMode,
    kid: Option<&str>,
    epoch: u64,
) {
    let signed = astation.sign(
        &AccountState {
            account: ACCOUNT.into(),
            sign_gen: 1,
            mode,
            kid: kid.map(str::to_string),
            epoch,
        }
        .encode(),
    );
    TrustStore::update(&paths.trust, |trust| {
        trust.accept_account_state(ASTATION_ID, &signed)?;
        Ok(())
    })
    .unwrap();
}

/// A verified device with its home Astation, unlocked through the
/// in-process agent (shared, so contexts and clients can hold it).
pub(crate) struct UnlockedDevice {
    pub paths: KeyPaths,
    pub server: FakeKeyServer,
    pub keys: DeviceKeys,
    pub agent: Arc<Mutex<KeyAgent>>,
    epoch: u64,
}

impl UnlockedDevice {
    pub(crate) fn new(dir: &Path) -> Self {
        let (paths, server, keys) = sealed_device(dir, "0a1b2c3d");
        let agent = Arc::new(test_agent(&paths));
        unlock_with(agent.as_ref(), &server, &paths).unwrap();
        Self {
            paths,
            server,
            keys,
            agent,
            epoch: 1,
        }
    }

    /// Signs and applies the next account state.
    pub(crate) fn state(&mut self, mode: EncryptionMode, kid: Option<&str>) {
        self.epoch += 1;
        set_state(&self.paths, &self.server.astation, mode, kid, self.epoch);
    }

    /// A signed `K` grant for this device.
    pub(crate) fn grant(&self, kid: &str, key: [u8; 32]) -> GrantWire {
        seal_k_grant(
            &self.server.astation,
            ACCOUNT,
            DEVICE_ID,
            self.keys.device_pub(),
            kid,
            key,
        )
    }

    /// A new state with `kid`, and its grant installed by the agent.
    pub(crate) fn set_key(&mut self, mode: EncryptionMode, kid: &str, key: [u8; 32]) {
        self.state(mode, Some(kid));
        self.agent
            .install_grant(ASTATION_ID, &self.grant(kid, key))
            .unwrap();
    }
}
```

- [ ] **Step 3: Write the failing agent tests**

Create `src/memory/k_agent_tests.rs`:

```rust
//! The key agent holding `K` (build step 2b): installed from signed grants,
//! kept sealed, used only through `Crypt`, retired by signed states.
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::memory::account_keys::CryptOp;
use crate::memory::crypto::{EncryptionMode, fail_writes_to};
use crate::memory::fake_astation::{
    ASTATION_ID, UnlockedDevice, sealed_device, set_state, unlock_with,
};
use crate::memory::key_agent::{KeyAgentApi, error_of, holds_k, test_agent};
use crate::memory::trust::TrustStore;

const A: &str = "0123abcd";
const B: &str = "89abcdef";

/// Locks the agent and unlocks it again through the fake Astation: what the
/// agent then holds came from the sealed file.
fn relock(device: &UnlockedDevice) {
    device.agent.lock_keys().unwrap();
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
}

fn seal(device: &UnlockedDevice, plain: &[u8]) -> String {
    device
        .agent
        .crypt(ASTATION_ID, vec![CryptOp::seal("mem", "content", plain)])
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap()
}

fn open(device: &UnlockedDevice, value: &str) -> anyhow::Result<Vec<u8>> {
    let out = device
        .agent
        .crypt(ASTATION_ID, vec![CryptOp::open("mem", "content", value)])?
        .remove(0);
    Ok(out.into_plain()?.to_vec())
}

#[test]
fn a_granted_k_is_kept_sealed_and_never_handed_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    // The reply names the kid only.
    let kid: String = device
        .agent
        .install_grant(ASTATION_ID, &device.grant(A, [42; 32]))
        .unwrap();
    assert_eq!(kid, A);
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some(A));
    let sealed = seal(&device, b"fact");
    assert_eq!(open(&device, &sealed).unwrap(), b"fact");
    let raw = std::fs::read(&device.paths.device_keys_sealed).unwrap();
    assert!(!raw.windows(32).any(|window| window == [42u8; 32]));
    assert!(!String::from_utf8_lossy(&raw).contains(&STANDARD.encode([42u8; 32])));
    // Locked, K is gone from memory; unlocked again, it comes from the file.
    device.agent.lock_keys().unwrap();
    assert!(error_of(device.agent.crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")])).contains("atem cred unlock"));
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    assert_eq!(open(&device, &sealed).unwrap(), b"fact");
}

#[test]
fn a_grant_must_name_the_kid_of_the_latest_signed_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    let error = error_of(device.agent.install_grant(ASTATION_ID, &device.grant(A, [1; 32])));
    assert!(error.contains("before the account mode"), "{error}");
    device.state(EncryptionMode::On, Some(A));
    let error = error_of(device.agent.install_grant(ASTATION_ID, &device.grant(B, [2; 32])));
    assert!(error.contains("does not match"), "{error}");
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
}

#[test]
fn crypt_needs_an_unlocked_agent_a_signed_state_and_k() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
    let agent = test_agent(&paths);
    let hash = || vec![CryptOp::keyed_hash(b"x")];
    assert!(error_of(agent.crypt(ASTATION_ID, hash())).contains("atem cred unlock"));
    unlock_with(&agent, &server, &paths).unwrap();
    assert!(error_of(agent.crypt(ASTATION_ID, hash())).contains("signed encryption state"));
    set_state(&paths, &server.astation, EncryptionMode::On, Some(A), 2);
    assert!(error_of(agent.crypt(ASTATION_ID, hash())).contains("requires encryption"));
    assert!(error_of(agent.crypt("astation-2", hash())).contains("isn't verified"));
}

#[test]
fn a_failed_re_seal_installs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::Enabling, A, [1; 32]);
    device.state(EncryptionMode::Enabling, Some(B));
    let before = std::fs::read(&device.paths.device_keys_sealed).unwrap();
    {
        let _failing = fail_writes_to(&device.paths.device_keys_sealed);
        assert!(device.agent.install_grant(ASTATION_ID, &device.grant(B, [2; 32])).is_err());
    }
    assert_eq!(std::fs::read(&device.paths.device_keys_sealed).unwrap(), before);
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some(A));
    // The grant comes again (keyRequest) and installs.
    device.agent.install_grant(ASTATION_ID, &device.grant(B, [2; 32])).unwrap();
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some(B));
}

#[test]
fn k_survives_a_storage_key_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, A, [42; 32]);
    let rotation = device.agent.begin_rotation(ASTATION_ID).unwrap();
    let ack = device.server.accept_rotation(&rotation).unwrap();
    let (_, confirm) = device.agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    device.server.confirm(&confirm).unwrap();
    relock(&device);
    assert!(holds_k(device.agent.as_ref(), ASTATION_ID));
}

#[test]
fn k_installed_mid_rotation_also_reaches_the_next_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    // Phase 1 wrote .next before K arrived.
    let rotation = device.agent.begin_rotation(ASTATION_ID).unwrap();
    device.agent.install_grant(ASTATION_ID, &device.grant(A, [42; 32])).unwrap();
    let ack = device.server.accept_rotation(&rotation).unwrap();
    let (_, confirm) = device.agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    device.server.confirm(&confirm).unwrap();
    relock(&device);
    assert!(holds_k(device.agent.as_ref(), ASTATION_ID), "the promoted file carries K");
}

#[test]
fn off_drops_k_and_on_drops_previous_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::Enabling, A, [1; 32]);
    let old = seal(&device, b"old");
    device.set_key(EncryptionMode::Enabling, B, [2; 32]);
    assert_eq!(open(&device, &old).unwrap(), b"old", "migration still reads A");
    device.state(EncryptionMode::On, Some(B));
    assert!(format!("{:#}", open(&device, &old).err().unwrap()).contains("unavailable key id"));
    relock(&device);
    assert!(open(&device, &old).is_err(), "A is gone from the sealed file too");
    assert!(holds_k(device.agent.as_ref(), ASTATION_ID));
    device.state(EncryptionMode::Off, None);
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
    relock(&device);
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
}

#[test]
fn an_off_state_that_arrived_while_locked_is_applied_at_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, A, [1; 32]);
    device.agent.lock_keys().unwrap();
    device.state(EncryptionMode::Off, None);
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    device.agent.lock_keys().unwrap();
    // Re-sealed at that unlock: a second unlock finds no K either.
    device.state(EncryptionMode::On, Some(A));
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
}

#[test]
fn check_grant_opens_against_given_pins_and_stores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    let entry = TrustStore::load_from(&device.paths.trust)
        .unwrap()
        .verified(ASTATION_ID)
        .unwrap()
        .clone();
    assert_eq!(device.agent.check_grant(&device.grant(A, [1; 32]), &entry).unwrap(), A);
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
}
```

- [ ] **Step 4: Run to verify failure**

Run: `cargo test memory::k_agent_tests`
Expected: FAIL to compile (`install_grant`, `crypt`, `held_kid`, `check_grant`, `holds_k` not found).

- [ ] **Step 5: Implement in `key_agent.rs`**

1. Imports: add

```rust
use std::collections::BTreeMap;

use crate::memory::account_keys::{AccountKeys, CryptOp, CryptOut, SignedModes};
use crate::memory::crypto::EncryptionMode;
```

and change `use crate::memory::verification::KeyPaths;` to `use crate::memory::verification::{KeyPaths, stored_state};`.

2. In `enum Request`, add after the `OpenGrant { .. }` variant:

```rust
    /// Opens a `K` grant from a verified Astation and stores `K` in the
    /// sealed file (it is never handed back). The grant must name the kid
    /// of the latest signed account state in cred_state.json.
    InstallGrant {
        astation_id: String,
        grant: GrantWire,
    },
    /// Verification only: opens a grant against pins not saved yet, to
    /// check it, and drops `K`.
    CheckGrant {
        grant: GrantWire,
        trust: AstationTrust,
    },
    /// Field operations with the account's `K` (account_keys.rs), in order.
    Crypt {
        astation_id: String,
        ops: Vec<CryptOp>,
    },
    /// The current kid held for `astation_id`'s account, once the keys a
    /// newer signed state retired are dropped.
    HeldKid {
        astation_id: String,
    },
```

3. In `enum Reply`, add after `Grant { .. }`:

```rust
    GrantInstalled {
        kid: String,
    },
    GrantChecked {
        kid: String,
    },
    Crypted {
        results: Vec<CryptOut>,
    },
    HeldKid {
        kid: Option<String>,
    },
```

4. In `struct Unlocked`, add after `keys: DeviceKeys,`:

```rust
    /// `K` and the keys it replaced, per account (build step 2b), as sealed
    /// in the file this agent holds the storage key for.
    accounts: AccountKeys,
```

5. `open_sealed_checked` returns the account keys too:

```rust
pub(crate) fn open_sealed_checked(
    sealed: &SealedDeviceKeys,
    device_id: &str,
    storage_kid: &str,
    storage_key: &[u8; 32],
    unlock_auth: UnlockAuthKey,
) -> Result<(DeviceKeys, AccountKeys)> {
    if sealed.device_id != device_id {
        bail!("device_keys.sealed belongs to another device");
    }
    if sealed.storage_kid != storage_kid {
        bail!(
            "device_keys.sealed is under storage key {}, not {storage_kid}",
            sealed.storage_kid
        );
    }
    sealed.open_with_accounts(storage_key, unlock_auth)
}
```

6. In `handle`, add arms before `Request::Lock`:

```rust
            Request::InstallGrant { astation_id, grant } => {
                self.install_grant(&astation_id, &grant)
            }
            Request::CheckGrant { grant, trust } => {
                let opened = open_sealed_grant(&trust, &self.unlocked()?.keys, &grant)?;
                Ok(Reply::GrantChecked { kid: opened.kid })
            }
            Request::Crypt { astation_id, ops } => self.crypt(&astation_id, ops),
            Request::HeldKid { astation_id } => self.held_kid(&astation_id),
```

7. `load_unlocked`: in the `Unlocked { .. }` literal add `accounts: AccountKeys::default(),`.

8. `finish_unlock`: replace `let keys = open_sealed_checked(` with `let (keys, accounts) = open_sealed_checked(`; in the final `self.unlocked = Some(Unlocked { .. })` literal add `accounts,`; right after that assignment (before `Ok(Reply::Unlocked { .. })`) add:

```rust
        self.after_unlock();
```

9. `begin_rotation` phase 1: replace

```rust
            SealedDeviceKeys::seal(&unlocked.keys, &unlocked.device_id, &kid, &key)?
                .save_to(&self.paths.device_keys_next)?;
```

with

```rust
            SealedDeviceKeys::seal_with(
                &unlocked.keys,
                &unlocked.accounts,
                &unlocked.device_id,
                &kid,
                &key,
            )?
            .save_to(&self.paths.device_keys_next)?;
```

10. `migrate_inner`: in its `Unlocked { .. }` literal add

```rust
            // The sealed file this overwrote can't be opened (its storage key
            // went with the agent that wrote it): any `K` in it is asked for
            // again. data_keys.enc, while it exists, brings it back (step 2b).
            accounts: AccountKeys::default(),
```

11. Add these methods to `impl KeyAgent` (after `open_grant`):

```rust
    fn install_grant(&mut self, astation_id: &str, grant: &GrantWire) -> Result<Reply> {
        let unlocked = self.unlocked()?;
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let entry = trust
            .verified(astation_id)
            .ok_or_else(|| anyhow!("this device isn't verified with Astation {astation_id}"))?;
        let opened = open_sealed_grant(entry, &unlocked.keys, grant)?;
        let state = stored_state(entry)?
            .ok_or_else(|| anyhow!("received an encryption key before the account mode"))?;
        if state.kid.as_deref() != Some(opened.kid.as_str()) {
            bail!("encryption key grant does not match the announced account mode");
        }
        let kid = opened.kid.clone();
        let mut accounts = unlocked.accounts.clone();
        accounts.install(&entry.data_account, &kid, opened.key);
        accounts.reconcile(&self.signed_modes()?);
        // Saved before it is used: K is in memory only once it is on disk.
        self.persist(&accounts)?;
        self.unlocked.as_mut().expect("unlocked above").accounts = accounts;
        Ok(Reply::GrantInstalled { kid })
    }

    fn crypt(&mut self, astation_id: &str, ops: Vec<CryptOp>) -> Result<Reply> {
        self.unlocked()?;
        self.reconcile()?;
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let entry = trust
            .verified(astation_id)
            .ok_or_else(|| anyhow!("this device isn't verified with Astation {astation_id}"))?;
        let state = stored_state(entry)?.ok_or_else(|| {
            anyhow!("waiting for Astation's signed encryption state; reconnect to Astation")
        })?;
        let results = self.unlocked()?.accounts.crypt(
            &entry.data_account,
            state.mode,
            state.kid.as_deref(),
            ops,
        )?;
        Ok(Reply::Crypted { results })
    }

    fn held_kid(&mut self, astation_id: &str) -> Result<Reply> {
        self.unlocked()?;
        self.reconcile()?;
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let kid = trust.verified(astation_id).and_then(|entry| {
            self.unlocked
                .as_ref()?
                .accounts
                .current_kid(&entry.data_account)
                .map(str::to_string)
        });
        Ok(Reply::HeldKid { kid })
    }

    /// The latest signed state of every account a verified Astation names
    /// (the highest epoch when two name one account).
    fn signed_modes(&self) -> Result<SignedModes> {
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let mut latest: BTreeMap<String, Option<(u64, EncryptionMode, Option<String>)>> =
            BTreeMap::new();
        for entry in trust.verified_entries() {
            let state = stored_state(entry)?;
            let slot = latest.entry(entry.data_account.clone()).or_insert(None);
            if let Some(state) = state
                && slot.as_ref().is_none_or(|(epoch, _, _)| state.epoch > *epoch)
            {
                *slot = Some((state.epoch, state.mode, state.kid));
            }
        }
        Ok(latest
            .into_iter()
            .map(|(account, state)| (account, state.map(|(_, mode, kid)| (mode, kid))))
            .collect())
    }

    /// Drops the account keys the signed states retired (`off`, or previous
    /// keys once `on` names the current kid) and re-seals when anything did.
    fn reconcile(&mut self) -> Result<()> {
        let modes = self.signed_modes()?;
        let mut accounts = self.unlocked()?.accounts.clone();
        if accounts.reconcile(&modes) {
            self.persist(&accounts)?;
            self.unlocked.as_mut().expect("unlocked above").accounts = accounts;
        }
        Ok(())
    }

    /// Writes the sealed file this agent holds the storage key for (and a
    /// pending rotation's `.next`) again, with `accounts`, under the storage
    /// keys they already use (temp file, fsync, rename). Only if that file
    /// is still the one the agent opened: another kid there means another
    /// run changed it. A crash leaves the old or the new file, both opened
    /// by the same storage key; at worst a newly installed `K` is missing,
    /// and atem asks Astation for it again (a `K` always comes as a signed
    /// grant).
    fn persist(&self, accounts: &AccountKeys) -> Result<()> {
        let unlocked = self.unlocked()?;
        let held = if unlocked.via_prev {
            &self.paths.device_keys_prev
        } else {
            &self.paths.device_keys_sealed
        };
        let on_disk = SealedDeviceKeys::load_from(held)?.ok_or_else(|| {
            anyhow!("{} is missing; the account keys can't be stored", held.display())
        })?;
        if on_disk.device_id != unlocked.device_id || on_disk.storage_kid != unlocked.storage_kid {
            bail!(
                "{} is under storage key {}, not the one this agent holds ({}); run `atem cred lock`, then `atem cred unlock`",
                held.display(),
                on_disk.storage_kid,
                unlocked.storage_kid
            );
        }
        SealedDeviceKeys::seal_with(
            &unlocked.keys,
            accounts,
            &unlocked.device_id,
            &unlocked.storage_kid,
            &unlocked.storage_key,
        )?
        .save_to(held)?;
        // A rotation in progress promotes .next: it must carry the same keys.
        if let Some(pending) = &self.pending_rotation
            && !pending.initial
        {
            SealedDeviceKeys::seal_with(
                &unlocked.keys,
                accounts,
                &unlocked.device_id,
                &pending.storage_kid,
                &pending.storage_key,
            )?
            .save_to(&self.paths.device_keys_next)?;
        }
        Ok(())
    }

    /// Once unlocked: drops account keys a signed state retired while the
    /// agent was locked. Never fatal: logged.
    fn after_unlock(&mut self) {
        if let Err(error) = self.reconcile() {
            eprintln!("key agent: {error:#}");
        }
    }
```

12. Add to `trait KeyAgentApi` (after `open_grant`):

```rust
    /// Installs a granted `K` in the agent; returns its kid.
    fn install_grant(&self, astation_id: &str, grant: &GrantWire) -> Result<String> {
        match self.call(Request::InstallGrant {
            astation_id: astation_id.into(),
            grant: grant.clone(),
        })? {
            Reply::GrantInstalled { kid } => Ok(kid),
            _ => unexpected(),
        }
    }

    /// Checks a grant against pins not saved yet (verification); its kid.
    fn check_grant(&self, grant: &GrantWire, trust: &AstationTrust) -> Result<String> {
        match self.call(Request::CheckGrant {
            grant: grant.clone(),
            trust: trust.clone(),
        })? {
            Reply::GrantChecked { kid } => Ok(kid),
            _ => unexpected(),
        }
    }

    /// Runs field operations with `astation_id`'s `K`, results in order.
    fn crypt(&self, astation_id: &str, ops: Vec<CryptOp>) -> Result<Vec<CryptOut>> {
        let count = ops.len();
        match self.call(Request::Crypt {
            astation_id: astation_id.into(),
            ops,
        })? {
            Reply::Crypted { results } if results.len() == count => Ok(results),
            Reply::Crypted { .. } => bail!("the key agent answered a different number of operations"),
            _ => unexpected(),
        }
    }

    /// The current kid held for `astation_id`'s account.
    fn held_kid(&self, astation_id: &str) -> Result<Option<String>> {
        match self.call(Request::HeldKid {
            astation_id: astation_id.into(),
        })? {
            Reply::HeldKid { kid } => Ok(kid),
            _ => unexpected(),
        }
    }
```

13. After `impl KeyAgentApi for std::sync::Mutex<KeyAgent>`, add:

```rust
/// A shared agent (`EncryptionContext` holds an `Arc<dyn KeyAgentApi>`).
impl<T: KeyAgentApi + ?Sized> KeyAgentApi for std::sync::Arc<T> {
    fn call(&self, request: Request) -> Result<Reply> {
        (**self).call(request)
    }
}
```

14. After `fn error_of`, add:

```rust
/// Whether `agent` holds `K` for `astation_id`'s account: it can seal.
#[cfg(test)]
pub(crate) fn holds_k(agent: &dyn KeyAgentApi, astation_id: &str) -> bool {
    agent
        .crypt(astation_id, vec![CryptOp::seal("mem", "content", b"x")])
        .is_ok()
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test memory::k_agent_tests`
Expected: PASS (9 tests).

Run: `cargo test memory::key_agent`
Expected: PASS (existing tests unchanged; `open_sealed_checked` callers use `.is_ok()` / `error_of`).

Run: `cargo test memory::verification`
Expected: PASS.

- [ ] **Step 7: Format and commit**

```bash
rustfmt --edition 2024 src/memory/key_agent.rs src/memory/fake_astation.rs src/memory/k_agent_tests.rs
git add src/memory/key_agent.rs src/memory/fake_astation.rs src/memory/k_agent_tests.rs src/memory/mod.rs
git commit -m "feat(memory): the key agent installs K, keeps it sealed and serves Crypt

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 5: Verification and the Astation link use the agent; no request returns `K`

**Files:**
- Modify: `src/memory/verification.rs` (`apply_account_state`, `apply_grant`, `complete_verification`, `key_needed`, tests)
- Modify: `src/memory/key_agent.rs` (remove `OpenGrant`, `Reply::Grant`, `open_grant`; tests)
- Modify: `src/memory/agent_socket.rs` (remove the `grant` reply special case; tests)
- Modify: `src/memory/unlock.rs`, `src/websocket_client.rs` (`key_needed` call sites)
- Test: `src/memory/verification.rs`, `src/memory/key_agent.rs`, `src/memory/agent_socket.rs`

**Interfaces:**
- Consumes: Task 4 (`install_grant`, `check_grant`, `held_kid`, `holds_k`), Task 3 (`account_mode`, `project_names::forget_account_at`).
- Produces:
  - `pub fn key_needed(paths: &KeyPaths, agent: &dyn KeyAgentApi, astation_id: &str) -> Result<bool>` (blocking: agent call; a locked agent counts as not holding `K`)
  - `apply_grant` unchanged signature; installs through the agent.
  - `complete_verification` unchanged signature; installs grants through the agent after the write; an install failure becomes `outcome.warning`.
  - After this task `data_keys.enc` is never written by atem (only purged at a first verification).

- [ ] **Step 1: Update the tests first (they fail until Step 3)**

In `src/memory/verification.rs`:

(a) `mod tests` imports: replace `use crate::memory::crypto::{EncryptionContext, EncryptionMode};` with `use crate::memory::crypto::EncryptionMode;` and `use crate::memory::key_agent::{KeyAgent, test_agent};` with `use crate::memory::key_agent::{KeyAgent, holds_k, test_agent};`.

(b) `verification_installs_signed_state_and_key`: replace the two lines starting `let context = EncryptionContext::for_astation_at` / `assert!(context.seal(...` with:

```rust
        assert_eq!(account_mode(&paths.trust, ASTATION_ID).unwrap().mode, EncryptionMode::On);
        assert!(holds_k(&agent, ASTATION_ID));
```

(c) `unsigned_or_forged_mode_changes_are_ignored`: change `let (paths, _, _, _) = verify(` to `let (paths, agent, _, _) = verify(`, and replace the last two lines with:

```rust
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::On,
            "the mode must survive"
        );
        assert!(holds_k(&agent, ASTATION_ID), "K must survive");
```

(d) In `signed_newer_state_is_applied`, `signed_state_with_invalid_kid_is_rejected`, `signed_state_needing_a_key_without_kid_is_rejected` and `unverified_devices_ignore_everything`, replace each

```rust
            EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys)
                .unwrap()
                .mode,
```

with

```rust
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
```

(e) `verified_device_without_a_state_refuses_to_build_a_context`: replace `let error = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys)` with `let error = account_mode(&paths.trust, ASTATION_ID)`.

(f) `ceremony_tests` imports: replace `use crate::memory::key_agent::{error_of, test_agent};` with `use crate::memory::key_agent::{error_of, holds_k, test_agent};`.

(g) `replayed_old_certificate_cannot_roll_a_verified_device_back` and `legitimate_re_verification_keeps_mode_and_key`: replace

```rust
        let context = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap();
        assert_eq!(context.mode, EncryptionMode::On);
        assert!(
            context.seal("mem", "content", b"x").is_ok(),
            "K must survive"
        );
```

with

```rust
        assert_eq!(account_mode(&paths.trust, ASTATION_ID).unwrap().mode, EncryptionMode::On);
        assert!(holds_k(&agent, ASTATION_ID), "K must survive");
```

(h) `assert_nothing_written`: after the `data_keys` assertion add

```rust
        assert!(!paths.project_names.exists(), "project_names.json must not be written");
```

(i) `first_verification_purges_legacy_keys`: the mode entry is no longer written; change the final expected tuple to `(None, None, vec![], 0)`.

(j) Replace `outcome_says_when_k_is_still_needed` with:

```rust
    #[test]
    fn outcome_says_when_k_is_still_needed() {
        let dir = tempfile::tempdir().unwrap();
        let (_, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::On, Some("0123abcd"), 2), vec![])
        });
        assert!(result.unwrap().key_needed);

        let dir = tempfile::tempdir().unwrap();
        let (_, result) = first_verification(dir.path(), 1, |fake, device_pub| {
            (
                state(fake, EncryptionMode::On, Some("0123abcd"), 2),
                vec![seal_k_grant(
                    fake, "acct", "dev-1", device_pub, "0123abcd", [42; 32],
                )],
            )
        });
        assert!(!result.unwrap().key_needed);

        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::Off, None, 2), vec![])
        });
        assert!(!result.unwrap().key_needed);
        let empty = tempfile::tempdir().unwrap();
        let locked = test_agent(&KeyPaths::in_dir(empty.path()));
        assert!(!key_needed(&paths, &locked, ASTATION_ID).unwrap(), "off needs no K");
        assert!(!key_needed(&paths, &locked, "never-verified").unwrap());
    }
```

(k) `re_verification_with_sealed_keys_opens_grants_in_the_agent`: replace the last two lines with `assert!(holds_k(&agent, ASTATION_ID));`.

(l) `grants_wait_while_the_agent_is_locked`: replace `assert!(key_needed(&paths, ASTATION_ID).unwrap());` with `assert!(key_needed(&paths, &locked, ASTATION_ID).unwrap());` and append at the end of the test:

```rust
        assert!(!key_needed(&paths, &agent, ASTATION_ID).unwrap());
        assert!(holds_k(&agent, ASTATION_ID));
```

(m) `NewerStateMeanwhile::call`: replace `let open = matches!(request, crate::memory::key_agent::Request::OpenGrant { .. });` with `let open = matches!(request, crate::memory::key_agent::Request::CheckGrant { .. });`. In `a_newer_state_applied_during_re_verification_is_kept`, replace the comment `// data_keys still announces the newer kid: its grant installs.` with `// The signed state names the newer kid: its grant installs.` and replace the final block from `let context = EncryptionContext::for_astation_at(` to the end of the test with:

```rust
        let mode = account_mode(&paths.trust, ASTATION_ID).unwrap();
        assert_eq!(mode.mode, EncryptionMode::On);
        assert_eq!(mode.kid.as_deref(), Some("89abcdef"), "the older state isn't re-applied");
        assert_eq!(agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some("89abcdef"));
    }
```

In `src/memory/key_agent.rs` `mod tests`:

(n) `a_new_agent_is_locked`: replace `agent.open_grant(ASTATION_ID, &grant, None)` with `agent.install_grant(ASTATION_ID, &grant)`.

(o) Replace `loaded_keys_open_grants_until_locked` with:

```rust
    #[test]
    fn loaded_keys_install_grants_until_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &server.storage_keys["0a1b2c3d"])
            .unwrap();
        let status = agent.status().unwrap();
        assert!(status.unlocked && !status.escrowed);
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        crate::memory::fake_astation::set_state(
            &paths,
            &server.astation,
            crate::memory::crypto::EncryptionMode::On,
            Some("0123abcd"),
            2,
        );
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert_eq!(agent.install_grant(ASTATION_ID, &grant).unwrap(), "0123abcd");
        assert!(holds_k(&agent, ASTATION_ID));
        agent.lock_keys().unwrap();
        assert!(!agent.status().unwrap().unlocked);
        assert!(error_of(agent.install_grant(ASTATION_ID, &grant)).contains("locked"));
    }
```

(p) `a_grant_from_an_unverified_astation_is_refused`: replace `agent.open_grant("astation-2", &grant, None)` with `agent.install_grant("astation-2", &grant)`.

In `src/memory/agent_socket.rs` `mod tests`:

(q) In `rich_requests`, replace the two `Request::OpenGrant { .. }` entries with:

```rust
            Request::InstallGrant {
                astation_id: "a".into(),
                grant: grant(),
            },
            Request::CheckGrant {
                grant: grant(),
                trust,
            },
```

(r) Replace `a_grant_reply_with_k_decodes_without_the_tagged_enum` with:

```rust
    #[test]
    fn replies_decode_through_their_kind() {
        assert!(matches!(
            decode_response(r#"{"v":1,"ok":true,"reply":{"kind":"grant_installed","kid":"ab12cd34"}}"#).unwrap(),
            Reply::GrantInstalled { kid } if kid == "ab12cd34"
        ));
        assert!(matches!(
            decode_response(r#"{"v":1,"ok":true,"reply":{"kind":"status","unlocked":false,"storage_kid":null,"escrowed":false}}"#).unwrap(),
            Reply::Status { unlocked: false, .. }
        ));
        // No reply carries K any more.
        assert!(decode_response(r#"{"v":1,"ok":true,"reply":{"kind":"grant","kid":"ab12cd34","key":"AAAA"}}"#).is_err());
    }
```

Run: `cargo test memory::verification`
Expected: FAIL to compile (`key_needed` arity, `Request::OpenGrant` still matched elsewhere, etc.).

- [ ] **Step 2: Remove `OpenGrant` and the `K`-carrying reply**

`src/memory/key_agent.rs`:
- Delete the `Request::OpenGrant { .. }` variant (with its doc comment), the `Reply::Grant { .. }` variant (with its doc comment), the `Request::OpenGrant { .. } => self.open_grant(..)` arm in `handle`, the private `fn open_grant(&self, ...)` method of `KeyAgent`, and the `fn open_grant(...) -> Result<OpenedGrant>` method of `KeyAgentApi`.
- Change `use crate::memory::grant::{GrantWire, OpenedGrant, hpke_open, hpke_seal, open_grant as open_sealed_grant};` to `use crate::memory::grant::{GrantWire, hpke_open, hpke_seal, open_grant as open_sealed_grant};`.

`src/memory/agent_socket.rs`:
- Delete `struct GrantResponse`, `struct GrantReply` and, in `decode_response`, the `if kind == "grant" { ... }` block.

- [ ] **Step 3: Rewire `verification.rs`**

Replace `apply_account_state`'s body after `let Some(state) = trust.accept_account_state(...)? else { ... };` with:

```rust
    // Checked before anything is saved: a bad kid leaves the trust store
    // untouched. The signed state is the only record of mode and kid.
    check_state(&state)?;
    trust.save_to(&paths.trust)?;
    Ok(Applied::ModeChanged(state))
}
```

Replace `apply_grant` with:

```rust
/// Installs a signed `K` grant for this verified device. The key agent opens
/// it and keeps `K` sealed; nothing returns `K` to this process.
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
    if trust.verified(astation_id).is_none() {
        return Ok(Applied::Ignored(
            "a key grant for a device that isn't verified",
        ));
    }
    if !agent.status()?.unlocked {
        return Ok(Applied::Locked);
    }
    match agent.install_grant(astation_id, grant) {
        Ok(kid) => Ok(Applied::KeyInstalled(kid)),
        // Locked between the two calls.
        Err(error) if format!("{error:#}").contains(LOCKED) => Ok(Applied::Locked),
        Err(error) => Err(error),
    }
}
```

Replace `complete_verification` (whole function, doc comment kept) with:

```rust
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
    // The account state epoch the certificate is checked against here.
    let checked_epoch = staged
        .verified(astation_id)
        .map_or(0, |previous| previous.account_epoch);
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
    match &keys {
        // New keys become the home Astation's to hold: never under another
        // home (R12: the home never moves), which could never unlock them.
        VerificationKeys::Fresh(_) => {
            if has_device_keys(paths) {
                bail!(
                    "this device already has keys; verify with them (run `atem cred unlock`, then `atem pair` again)"
                );
            }
            if staged.home_is_set() && staged.home() != Some(astation_id) {
                bail!(
                    "this device's home Astation is {}; verify with it, or start over (delete ~/.config/atem/cred_state.json too)",
                    staged.recorded_home().unwrap_or_default()
                );
            }
        }
        // Sealed keys never leave the agent: it must hold exactly these.
        VerificationKeys::Sealed(publics) => {
            if !agent.status()?.unlocked {
                bail!("{LOCKED}, then `atem pair` again");
            }
            if agent.public_keys()? != (publics.device_pub, publics.device_sign_pub) {
                bail!("the key agent holds other device keys than this verification revealed");
            }
        }
    }
    // Every grant is checked before anything is written. Fresh keys are in
    // this process anyway, so their grants are opened here and `K` dropped at
    // once; sealed keys' grants are checked in the agent, which drops `K`.
    // The agent installs `K` below, once the pins it checks against are saved.
    let granted_kids = grants
        .iter()
        .map(|grant| match &keys {
            VerificationKeys::Fresh(fresh) => open_grant(&entry, fresh, grant).map(|opened| opened.kid),
            // The staged pins: they aren't saved until everything holds.
            VerificationKeys::Sealed(_) => agent.check_grant(grant, &entry),
        })
        .collect::<Result<Vec<_>>>()?;
    if granted_kids
        .iter()
        .any(|kid| Some(kid.as_str()) != state.kid.as_deref())
    {
        bail!("a key grant names a different key id than the signed account state");
    }

    let sealed = match &keys {
        VerificationKeys::Fresh(fresh) => {
            let storage_key = new_storage_key();
            let storage_kid = staged.pick_storage_kid("", new_storage_kid);
            let sealed =
                SealedDeviceKeys::seal(fresh, &entry.device_id, &storage_kid, &storage_key)?;
            agent.load_unlocked(&entry.device_id, fresh, &storage_kid, &storage_key)?;
            Some((sealed, fresh.unlock_auth_key()))
        }
        VerificationKeys::Sealed(_) => None,
    };
    // Returns the kid whose grants the agent installs afterwards.
    let write = || -> Result<Option<String>> {
        // Fresh keys: no key file exists (checked above). The plain file
        // stays until Astation confirms it holds the storage key (the agent
        // deletes it then), so an agent that stops before that re-seals the
        // keys from it instead of losing them.
        if let (Some((sealed, unlock_auth)), VerificationKeys::Fresh(fresh)) = (&sealed, &keys) {
            sealed.save_to(&paths.device_keys_sealed)?;
            unlock_auth.save_to(&paths.unlock_auth_key)?;
            fresh.save_to(&paths.device_keys)?;
        }
        // The staged changes again, on the store as it is now, under its
        // lock (never held across an agent call): another process's changes
        // since `staged` was loaded aren't lost, and a newer signed state it
        // applied meanwhile is kept, never rolled back.
        let _trust_lock = TrustStore::lock(&paths.trust)?;
        let mut current = TrustStore::load_from(&paths.trust)?;
        let first = current.verified(astation_id).is_none();
        current.confirm_since(astation_id, device_verified, checked_epoch)?;
        let newer = current
            .verified(astation_id)
            .filter(|entry| entry.account_state.is_some() && entry.account_epoch > state.epoch)
            .map(stored_state)
            .transpose()?
            .flatten();
        if newer.is_none() {
            current.accept_account_state(astation_id, account_state)?;
        }
        if sealed.is_some() {
            if current.home_is_set() && current.recorded_home() != Some(astation_id) {
                bail!("another run made a different Astation this device's home");
            }
            current.set_home(astation_id);
        }
        if first {
            // Whatever the unauthenticated path stored for this Astation (K,
            // rotation history, project names) is dropped, not trusted.
            EncryptionContext::purge_unverified_at(&paths.data_keys, astation_id, &state.account)?;
            crate::memory::project_names::forget_account_at(&paths.project_names, &state.account)?;
        }
        current.save_to(&paths.trust)?;
        // Grants are for this verification's state's kid: installed unless
        // the newer state moved to another key (its own grant brings that).
        Ok(newer.map_or(state.kid.clone(), |newer| newer.kid))
    };
    let install_kid = match write() {
        Ok(kid) => kid,
        Err(error) => {
            if let (Some((written, unlock_auth)), VerificationKeys::Fresh(fresh)) = (&sealed, &keys) {
                // Undo the fresh keys entirely: no sealed file without its
                // verification, and no agent holding keys that aren't on disk.
                // Only files this call wrote go: a concurrent pairing run's stay.
                // With the files gone the agent accepts the lock.
                if SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                    .is_ok_and(|file| file.is_some_and(|file| file.storage_kid == written.storage_kid))
                {
                    let _ = remove_if_exists(&paths.device_keys_sealed);
                }
                if UnlockAuthKey::load_from(&paths.unlock_auth_key)
                    .is_ok_and(|file| file.is_some_and(|file| file.public() == unlock_auth.public()))
                {
                    let _ = remove_if_exists(&paths.unlock_auth_key);
                }
                if DeviceKeys::load_from(&paths.device_keys).is_ok_and(|file| {
                    file.is_some_and(|file| file.device_sign_pub() == fresh.device_sign_pub())
                }) {
                    let _ = remove_if_exists(&paths.device_keys);
                }
                if agent
                    .public_keys()
                    .is_ok_and(|held| held == (fresh.device_pub(), fresh.device_sign_pub()))
                {
                    let _ = agent.lock_keys();
                }
            }
            return Err(error);
        }
    };
    remove_if_exists(&paths.legacy_device_key)?;
    let mut warnings = Vec::new();
    // The verification is saved: a K that can't be stored now is asked for
    // again (key_needed below), never a reason to fail.
    for (grant, kid) in grants.iter().zip(&granted_kids) {
        if Some(kid) != install_kid.as_ref() {
            continue;
        }
        if let Err(error) = agent.install_grant(astation_id, grant) {
            warnings.push(format!(
                "the encryption key couldn't be stored in the key agent ({error:#}); atem asks Astation for it again"
            ));
        }
    }
    let escrow = match sealed {
        Some(_) => match agent.begin_rotation(astation_id) {
            Ok(rotation) => Some(rotation),
            Err(error) => {
                warnings.push(format!(
                    "this device's storage key couldn't be prepared for Astation ({error:#}); run `atem cred unlock` before this machine restarts"
                ));
                None
            }
        },
        None => None,
    };
    Ok(VerificationOutcome {
        key_needed: key_needed(paths, agent, astation_id)?,
        escrow,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    })
}
```

Replace `key_needed` with:

```rust
/// Whether this device is verified with `astation_id`, its signed state
/// needs `K`, and the key agent doesn't hold that `K` (a locked agent counts
/// as not holding it): then it should send `keyRequest`. Blocking: from
/// async code call it inside `key_agent::blocking`.
pub fn key_needed(paths: &KeyPaths, agent: &dyn KeyAgentApi, astation_id: &str) -> Result<bool> {
    let trust = TrustStore::load_from(&paths.trust)?;
    let Some(entry) = trust.verified(astation_id) else {
        return Ok(false);
    };
    let Some(state) = stored_state(entry)? else {
        return Ok(false);
    };
    if !state.mode.requires_key() {
        return Ok(false);
    }
    match agent.held_kid(astation_id) {
        Ok(held) => Ok(held != state.kid),
        Err(error) if format!("{error:#}").contains(LOCKED) => Ok(true),
        Err(error) => Err(error),
    }
}
```

- [ ] **Step 4: Call sites**

`src/memory/unlock.rs`, `unlock_command`: replace

```rust
    if key_needed(paths, &home)? {
        request_missing_key(&mut client, &trust, &home).await?;
    }
```

with

```rust
    let missing = {
        let (agent, paths, home) = (agent.clone(), paths.clone(), home.clone());
        blocking(move || key_needed(&paths, agent.as_ref(), &home)).await?
    };
    if missing {
        request_missing_key(&mut client, &trust, &home).await?;
    }
```

and in `already_unlocked` replace `|| key_needed(paths, home)?` with `|| key_needed(paths, agent, home)?`.

`src/websocket_client.rs` (edit by hand, never rustfmt), in `handle_encryption_message`:

1. Replace `use crate::memory::key_agent::{blocking, default_agent, LOCKED};` with `use crate::memory::key_agent::{blocking, default_agent, running_agent, LOCKED};`.
2. After the `let request_key = || async { ... };` closure, add:

```rust
        // Asks the agent whether K for the signed kid is held (blocking socket I/O).
        let needs_key = || {
            let (paths, astation_id) = (paths.clone(), astation_id.clone());
            blocking(move || key_needed(&paths, default_agent().as_ref(), &astation_id))
        };
```

3. In `Applied::Unchanged`, replace `if key_needed(&paths, &astation_id)? {` with `if needs_key().await? {`.
4. Replace the `Applied::ModeChanged(state) => { ... }` arm with:

```rust
            Applied::ModeChanged(state) => {
                if !state.mode.requires_key() {
                    // A running, unlocked agent drops the account's keys now; a
                    // locked one does at its next unlock.
                    let astation = astation_id.clone();
                    blocking(move || {
                        if let Some(agent) = running_agent() {
                            let _ = agent.held_kid(&astation);
                        }
                        Ok(())
                    })
                    .await?;
                }
                if needs_key().await? {
                    return request_key().await;
                }
                self.finish_encryption_migration(&astation_id, state.kid).await
            }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test memory::verification`
Expected: PASS.

Run: `cargo test memory::key_agent`
Expected: PASS.

Run: `cargo test memory::agent_socket`
Expected: PASS.

Run: `cargo test memory::k_agent_tests`
Expected: PASS.

Run: `cargo build`
Expected: builds (websocket_client.rs, unlock.rs, cli.rs compile). `dead_code` warnings for `EncryptionContext::update_mode_at` / `install_grant_at` (now used only by the old tests) are expected until Task 7 deletes them.

- [ ] **Step 6: Format and commit**

```bash
rustfmt --edition 2024 src/memory/key_agent.rs src/memory/agent_socket.rs src/memory/unlock.rs
git add src/memory/verification.rs src/memory/key_agent.rs src/memory/agent_socket.rs src/memory/unlock.rs src/websocket_client.rs
git commit -m "feat(memory): verification and grants install K in the agent; no reply carries K

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 6: `Crypt` on the wire: wiped buffers, protocol v2, bigger lines

**Files:**
- Modify: `src/memory/agent_socket.rs`, `src/memory/key_agent.rs` (`PROTOCOL_VERSION`), `tests/key_agent_binary.rs`
- Test: `src/memory/agent_socket.rs`, `tests/key_agent_binary.rs`

**Interfaces:**
- Consumes: Task 4 (`Request::Crypt`, `Reply::Crypted`, `CryptOp`, `CryptOut`, `KeyAgentApi::crypt`).
- Produces: `PROTOCOL_VERSION = 2`; `MAX_LINE = 8 MiB`; `decode_request` parses `crypt` via a plain struct; `decode_response` parses `crypted` via a plain struct (no serde `Content` buffering of plain text).

- [ ] **Step 1: Write the failing tests**

In `src/memory/agent_socket.rs` `mod tests`:

(a) `every_request_carries_the_protocol_version`: replace with

```rust
    #[test]
    fn every_request_carries_the_protocol_version() {
        let line = encode_request(&Request::Status).unwrap();
        assert!(line.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value, serde_json::json!({"op": "status", "v": 2}));
        assert!(matches!(
            decode_request(line.trim()).unwrap(),
            Request::Status
        ));
        let newer = decode_request(r#"{"op":"status","v":3}"#).err().unwrap();
        assert!(format!("{newer:#}").contains("protocol version 3"));
        let older = decode_request(r#"{"op":"status","v":1}"#).err().unwrap();
        assert!(format!("{older:#}").contains("protocol version 1"));
        assert!(decode_request(r#"{"op":"status"}"#).is_err());
    }
```

(b) `a_newer_cli_gets_a_clear_error_from_an_older_agent`: replace with

```rust
    #[test]
    fn a_newer_cli_gets_a_clear_error_from_an_older_agent() {
        // A step-2a agent (v1) left running after an upgrade.
        let older_agent = decode_response(r#"{"v":1,"ok":true,"reply":{"kind":"done"}}"#);
        let hint = format!("{:#}", older_agent.err().unwrap());
        // Check first that Astation holds the storage key, then stop it.
        let (status, pkill) = (
            hint.find("atem cred status").expect(&hint),
            hint.find("pkill").expect(&hint),
        );
        assert!(status < pkill, "{hint}");
        let refused = decode_response(
            r#"{"v":2,"ok":false,"error":"unsupported key agent protocol version 3"}"#,
        );
        assert!(format!("{:#}", refused.err().unwrap()).contains("protocol version 3"));
        assert!(matches!(
            decode_response(r#"{"v":2,"ok":true,"reply":{"kind":"done"}}"#).unwrap(),
            Reply::Done
        ));
    }
```

(c) In `replies_decode_through_their_kind` (Task 5), change every `"v":1` to `"v":2`.

(d) In `rich_requests`, append to the returned `vec![...]`:

```rust
            Request::Crypt {
                astation_id: "a".into(),
                ops: vec![
                    crate::memory::account_keys::CryptOp::seal("r", "f", b"hi"),
                    crate::memory::account_keys::CryptOp::open("r", "f", "e1.x.AA=="),
                    crate::memory::account_keys::CryptOp::keyed_hash(b"p"),
                ],
            },
            Request::HeldKid {
                astation_id: "a".into(),
            },
```

(e) Add:

```rust
    #[test]
    fn crypt_requests_and_replies_parse_without_the_tagged_enum() {
        use crate::memory::account_keys::CryptOp;
        let request = Request::Crypt {
            astation_id: "a".into(),
            ops: vec![
                CryptOp::seal("r", "f", b"hi"),
                CryptOp::open("r", "f", "e1.x"),
                CryptOp::keyed_hash(b"p"),
            ],
        };
        let line = encode_request(&request).unwrap();
        assert!(line.contains(r#""op":"crypt""#), "{}", *line);
        assert!(
            line.contains(r#"{"seal":{"record":"r","field":"f","plain":"aGk="}}"#),
            "{}",
            *line
        );
        match decode_request(line.trim()).unwrap() {
            Request::Crypt { astation_id, ops } => {
                assert_eq!(astation_id, "a");
                assert_eq!(ops.len(), 3);
            }
            _ => panic!("expected a crypt request"),
        }
        let reply = decode_response(
            r#"{"v":2,"ok":true,"reply":{"kind":"crypted","results":[{"sealed":"e1.x"},{"opened":"aGk="},{"hashed":"h1.y"}]}}"#,
        )
        .unwrap();
        let Reply::Crypted { results } = reply else {
            panic!("expected crypted");
        };
        let mut results = results.into_iter();
        assert_eq!(results.next().unwrap().into_text().unwrap(), "e1.x");
        assert_eq!(&*results.next().unwrap().into_plain().unwrap(), b"hi");
        assert_eq!(results.next().unwrap().into_text().unwrap(), "h1.y");
    }

    #[test]
    fn a_crypt_batch_bigger_than_a_mebibyte_reaches_the_agent() {
        use crate::memory::account_keys::CryptOp;
        use crate::memory::key_agent::error_of;
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = KeyAgentClient::at(socket);
        let big = vec![b'x'; 3 << 20];
        let error = error_of(client.crypt("a", vec![CryptOp::seal("r", "f", &big)]));
        // The locked agent's answer, not a refused line.
        assert!(error.contains("locked"), "{error}");
    }
```

In `tests/key_agent_binary.rs`, change both `b"{\"op\":\"status\",\"v\":1}\n"` to `b"{\"op\":\"status\",\"v\":2}\n"`.

Run: `cargo test memory::agent_socket`
Expected: FAIL (`"v": 1` still emitted; the 3 MiB line is refused as too long).

- [ ] **Step 2: Implement**

`src/memory/key_agent.rs`: `pub const PROTOCOL_VERSION: u64 = 2;` and update its doc comment:

```rust
/// Every request carries `"v": PROTOCOL_VERSION`; the agent answers any
/// other version with an error, so an old agent and a newer CLI fail clearly.
/// v2 (build step 2b): `K` stays in the agent (`InstallGrant`, `Crypt`).
```

`src/memory/agent_socket.rs`:

1. First doc line: `//! The key agent's Unix socket: newline-delimited JSON, `"v": 2` on every`.
2. `use crate::memory::key_agent::{...}` stays; add `use crate::memory::account_keys::{CryptOp, CryptOut};`.
3. `MAX_LINE`:

```rust
/// Bounds a misbehaving peer. A `Crypt` batch is kept under 2 MiB of input by
/// `EncryptionContext`, and one skill (at most 1 MiB, base64 on the wire)
/// always fits.
const MAX_LINE: usize = 8 << 20;
```

4. After `struct LoadUnlockedWire`, add:

```rust
/// `crypt` carries plain text to seal or hash: parsed straight from the
/// line into `Zeroizing` fields (`CryptOp` is externally tagged).
#[derive(Deserialize)]
struct CryptWire {
    astation_id: String,
    ops: Vec<CryptOp>,
}
```

and in `decode_request`, after the `load_unlocked` block:

```rust
    if head.op.as_deref() == Some("crypt") {
        let wire: CryptWire =
            serde_json::from_str(line).context("key agent request is malformed")?;
        return Ok(Request::Crypt {
            astation_id: wire.astation_id,
            ops: wire.ops,
        });
    }
```

5. Before `decode_response`, add:

```rust
/// The `crypt` reply carries opened plain text: parsed straight from the line.
#[derive(Deserialize)]
struct CryptedResponse {
    reply: CryptedReply,
}

#[derive(Deserialize)]
struct CryptedReply {
    results: Vec<CryptOut>,
}
```

and in `decode_response`, where the `grant` block was (after `let kind = ...;`):

```rust
    if kind == "crypted" {
        let crypted: CryptedResponse =
            serde_json::from_str(line).context("the key agent sent an unreadable reply")?;
        return Ok(Reply::Crypted {
            results: crypted.reply.results,
        });
    }
```

6. In `respond`, the fallback literal becomes `b"{\"v\":2,\"ok\":false,\"error\":\"the key agent could not encode its reply\"}\n"`.

7. In `serve_connection`, look for the newline only in bytes not scanned yet (a multi-MiB `Crypt` line arrives in 4 KiB reads; rescanning the whole buffer each time is quadratic). Replace the loop

```rust
    loop {
        while let Some(end) = pending.0.iter().position(|byte| *byte == b'\n') {
            let line = Zeroizing::new(pending.0.drain(..=end).collect::<Vec<u8>>());
```

with

```rust
    // Bytes of `pending` already known to hold no newline.
    let mut scanned = 0;
    loop {
        while let Some(offset) = pending.0[scanned..].iter().position(|byte| *byte == b'\n') {
            let end = scanned + offset;
            scanned = 0;
            let line = Zeroizing::new(pending.0.drain(..=end).collect::<Vec<u8>>());
```

and, right after that `while` loop's closing brace (before `if pending.0.len() > MAX_LINE {`), add:

```rust
        scanned = pending.0.len();
```

- [ ] **Step 3: Run the tests**

Run: `cargo test memory::agent_socket`
Expected: PASS (including `secret_and_grant_requests_reach_the_agent_over_the_wire` with the `Crypt`/`HeldKid` additions and `an_endless_line_closes_the_connection` with the larger `MAX_LINE`).

Run: `cargo test --test key_agent_binary`
Expected: PASS.

- [ ] **Step 4: Format and commit**

```bash
rustfmt --edition 2024 src/memory/agent_socket.rs src/memory/key_agent.rs tests/key_agent_binary.rs
git add src/memory/agent_socket.rs src/memory/key_agent.rs tests/key_agent_binary.rs
git commit -m "feat(agent): Crypt parsed into wiped buffers, protocol v2, 8 MiB lines

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 7: `EncryptionContext` becomes a thin, batching client; `data_keys.enc` is read-only legacy

**Files:**
- Create: `src/memory/legacy_keys.rs`
- Modify: `src/memory/mod.rs` (one line), `src/memory/crypto.rs`, `src/memory/api.rs`, `src/vault_client.rs`, `src/memory/verification.rs` (purge call, `VerifiedForTest` removed, test), `src/memory/trust.rs` (`trust_path_for` removed), `src/memory/e2e_tests.rs`
- Test: `src/memory/crypto.rs`, `src/memory/legacy_keys.rs`, `src/memory/e2e_tests.rs`

**Interfaces:**
- Consumes: Tasks 1, 3, 4, 6.
- Produces:
  - `EncryptionContext::for_astation(astation_id: &str) -> Result<Self>` (default paths, lazy default agent)
  - `EncryptionContext::for_astation_with(astation_id: &str, paths: &KeyPaths, agent: Arc<dyn KeyAgentApi>) -> Result<Self>` (pub(crate))
  - `EncryptionContext::blocking<T: Send + 'static>(&self, work: impl FnOnce(&Self) -> Result<T> + Send + 'static) -> impl Future<Output = Result<T>>` (`pub async fn`)
  - Batch methods: `seal_many(&self, &[(&str, &str, &[u8])]) -> Result<Vec<String>>`, `open_many(&self, &[(&str, &str, &str)]) -> Result<Vec<Vec<u8>>>`, `wire_projects(&self, &[String]) -> Result<Vec<String>>`, `encrypt_memories(Vec<Memory>)`, `decrypt_memories(Vec<Memory>)`, `encrypt_skills(Vec<Skill>)`, `decrypt_skills(Vec<Skill>)` (all `-> Result<Vec<_>>`)
  - Single methods kept: `seal`, `wire_project`, `decrypt_skill`, `require_sealed`, `should_encrypt` (production) and `open`, `keyed_hash`, `encrypt_memory`, `decrypt_memory`, `encrypt_skill` (`#[cfg(test)]`: production batches)
  - `legacy_keys`: `pub enum Legacy { Missing, Unreadable(anyhow::Error), Keys(LegacyKeys) }`, `pub fn read(path: &Path) -> Result<Legacy>`, `pub fn purge_unverified_at(path: &Path, astation_id: &str, data_account: &str) -> Result<()>`, `#[cfg(test)] write_for_test`, `#[cfg(test)] summary_at`
  - `KnowledgeClient::with_encryption(paths: KeyPaths, agent: Arc<dyn KeyAgentApi>)`, `VaultClient::with_encryption(...)` (test-only; replace `with_encryption_store`)

- [ ] **Step 1: `legacy_keys.rs` — failing tests first**

In `src/memory/mod.rs` add after `pub mod project_names;`:

```rust
pub mod legacy_keys;
```

Create `src/memory/legacy_keys.rs` ending with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_store_reads_back_and_a_missing_one_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        assert!(matches!(read(&path).unwrap(), Legacy::Missing));
        write_for_test(&path, "astation", "acct", &[("0123abcd", [1; 32]), ("11112222", [2; 32])], &[("h1.x.aa", "github.com/agora/atem")]);
        assert_eq!(summary_at(&path, "acct"), (Some("11112222".into()), vec!["0123abcd".into()], 1));
        std::fs::write(&path, b"not machine-bound").unwrap();
        assert!(matches!(read(&path).unwrap(), Legacy::Unreadable(_)));
    }

    #[test]
    fn purge_removes_only_this_astations_legacy_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        write_for_test(&path, "astation", "legacy", &[("0123abcd", [1; 32]), ("11112222", [2; 32])], &[("h1.x.aa", "p")]);
        purge_unverified_at(&path, "astation", "certified").unwrap();
        assert_eq!(summary_at(&path, "legacy"), (None, vec![], 0), "the account the mode entry named goes too");
        // A missing store stays missing.
        let absent = dir.path().join("absent.enc");
        purge_unverified_at(&absent, "astation", "certified").unwrap();
        assert!(!absent.exists());
    }
}
```

Run: `cargo test memory::legacy_keys`
Expected: FAIL to compile.

- [ ] **Step 2: Implement `legacy_keys.rs`** (above the tests)

```rust
//! `data_keys.enc`, where build steps 0–2a kept `K`, its previous keys and
//! the project names, encrypted with the machine-bound key (which a copied
//! disk includes). Build step 2b only reads it: the key agent moves it into
//! `device_keys.sealed` and `project_names.json` and deletes it
//! (key_agent.rs), and a first verification still purges what the
//! unauthenticated #36 path stored in it.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroizing;

use crate::memory::crypto::EncryptionMode;

#[derive(Serialize, Deserialize)]
struct StoredMode {
    data_account: String,
    mode: EncryptionMode,
    kid: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    key: Zeroizing<String>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct LegacyKeys {
    #[serde(default = "version_one")]
    version: u8,
    #[serde(default)]
    astations: HashMap<String, StoredMode>,
    #[serde(default)]
    accounts: HashMap<String, StoredKey>,
    #[serde(default)]
    previous_keys: HashMap<String, Vec<StoredKey>>,
    #[serde(default)]
    project_names: HashMap<String, HashMap<String, String>>,
}

fn version_one() -> u8 {
    1
}

pub enum Legacy {
    Missing,
    /// It can never be read on this machine (another machine id, damage).
    Unreadable(anyhow::Error),
    Keys(LegacyKeys),
}

/// Reads `data_keys.enc`. Only an I/O error other than "not found" is an
/// error: a file that can't be decrypted or parsed is `Unreadable`.
pub fn read(path: &Path) -> Result<Legacy> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Legacy::Missing),
        Err(error) => return Err(error.into()),
    };
    let parsed = crate::credentials::decrypt_machine_bound(&raw)
        .context("data_keys.enc cannot be decrypted on this machine")
        .and_then(|plain| {
            let plain = Zeroizing::new(plain);
            serde_json::from_slice::<LegacyKeys>(&plain).context("data_keys.enc is unreadable")
        })
        .and_then(|keys| {
            if keys.version != 1 {
                anyhow::bail!("unsupported data_keys.enc version {}", keys.version);
            }
            Ok(keys)
        });
    Ok(match parsed {
        Ok(keys) => Legacy::Keys(keys),
        Err(error) => Legacy::Unreadable(error),
    })
}

impl LegacyKeys {
    fn save_to(&self, path: &Path) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(self)?);
        let encrypted = crate::credentials::encrypt_machine_bound(&plain)?;
        crate::memory::crypto::write_private(path, &encrypted)
    }
}

/// Removes what the unauthenticated #36 path may have stored for this
/// Astation: its mode entry, and the keys, rotation history and project
/// names of `data_account` and of the account that entry named. Called on a
/// device's first verification with this Astation. A missing or unreadable
/// file is left as it is (the key agent deletes an unreadable one).
pub fn purge_unverified_at(path: &Path, astation_id: &str, data_account: &str) -> Result<()> {
    let Legacy::Keys(mut store) = read(path)? else {
        return Ok(());
    };
    let mut accounts = vec![data_account.to_string()];
    if let Some(legacy) = store.astations.remove(astation_id)
        && legacy.data_account != data_account
    {
        accounts.push(legacy.data_account);
    }
    for account in &accounts {
        store.accounts.remove(account);
        store.previous_keys.remove(account);
        store.project_names.remove(account);
    }
    store.save_to(path)
}

/// Test stand-in for a step-2a store: `keys` oldest first (the last is
/// current), with a mode entry for `astation_id`.
#[cfg(test)]
pub(crate) fn write_for_test(
    path: &Path,
    astation_id: &str,
    account: &str,
    keys: &[(&str, [u8; 32])],
    names: &[(&str, &str)],
) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let stored = |(kid, key): &(&str, [u8; 32])| StoredKey {
        kid: kid.to_string(),
        key: Zeroizing::new(STANDARD.encode(key)),
    };
    let (last, earlier) = keys.split_last().expect("at least one key");
    let mut store = LegacyKeys {
        version: 1,
        ..LegacyKeys::default()
    };
    store.astations.insert(
        astation_id.into(),
        StoredMode {
            data_account: account.into(),
            mode: EncryptionMode::Enabling,
            kid: Some(last.0.into()),
        },
    );
    store.accounts.insert(account.into(), stored(last));
    store
        .previous_keys
        .insert(account.into(), earlier.iter().map(stored).collect());
    store.project_names.insert(
        account.into(),
        names.iter().map(|(hash, name)| (hash.to_string(), name.to_string())).collect(),
    );
    store.save_to(path).unwrap();
}

/// Test view: (current kid, previous kids, number of project names).
#[cfg(test)]
pub(crate) fn summary_at(path: &Path, account: &str) -> (Option<String>, Vec<String>, usize) {
    let Legacy::Keys(store) = read(path).unwrap() else {
        return (None, Vec::new(), 0);
    };
    (
        store.accounts.get(account).map(|key| key.kid.clone()),
        store
            .previous_keys
            .get(account)
            .map(|keys| keys.iter().map(|key| key.kid.clone()).collect())
            .unwrap_or_default(),
        store.project_names.get(account).map_or(0, HashMap::len),
    )
}
```

Run: `cargo test memory::legacy_keys`
Expected: PASS (2 tests).

- [ ] **Step 3: Rewrite `crypto.rs` (by hand, never rustfmt)**

1. Header doc and imports — replace lines 1–18 (doc through `use crate::memory::model::...;`) with:

```rust
//! End-to-end encryption for relay-backed memory, skills, and vaults.
//! Local knowledge.db remains plaintext; transforms happen only at HTTP edges.
//! `K` lives only in the key agent (build step 2b): `EncryptionContext` reads
//! the mode from the signed account state and asks the agent to seal, open
//! and hash. Also: private atomic file writes for every key file.

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::memory::account_keys::{CryptOp, CryptOut};
use crate::memory::key_agent::KeyAgentApi;
use crate::memory::model::{content_hash, skill_hash, Memory, Skill};
use crate::memory::verification::KeyPaths;
```

2. Delete the items `struct StoredMode`, `struct StoredKey`, `struct StoredKeys` (with `impl StoredKeys`), `fn store_version`, `fn key_store_path` (old lines 57–139). Keep `set_mode_600`, `unique_temp`, `is_stale_temp`, `sweep_stale_temps`, the `FAILING_WRITES` test hook, `write_private`, `valid_kid`.

3. Replace everything from `#[derive(Debug, Clone)] pub struct EncryptionContext` through the end of `fn resolve_project` (old lines 288–594) with:

```rust
/// Most bytes and operations one `Crypt` request carries; bigger batches are
/// split. One skill (at most `MAX_SKILL_BYTES`, 1 MiB) always fits.
const CRYPT_BATCH_BYTES: usize = 2 << 20;
const CRYPT_BATCH_OPS: usize = 1024;

const UNKNOWN_PROJECT: &str = "encrypted project name is unknown on this Atem; sync from a device that used it first";

/// One Astation's encryption mode, and a handle on the key agent, which
/// holds `K` and does every seal, open and keyed hash: this process never
/// sees `K`. Mode and kid come from the latest signed account state; off
/// (and unverified) contexts never touch the agent. Methods that reach the
/// agent block on its socket: from async code run them inside `blocking`.
#[derive(Clone)]
pub struct EncryptionContext {
    pub mode: EncryptionMode,
    pub data_account: String,
    pub kid: Option<String>,
    astation_id: String,
    /// `None` while encryption is off.
    agent: Option<Arc<dyn KeyAgentApi>>,
    names_path: PathBuf,
}

impl std::fmt::Debug for EncryptionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionContext")
            .field("mode", &self.mode)
            .field("data_account", &self.data_account)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

fn next_text(results: &mut impl Iterator<Item = CryptOut>) -> Result<String> {
    results.next().ok_or_else(|| anyhow!("the key agent answered too few operations"))?.into_text()
}

fn next_plain(results: &mut impl Iterator<Item = CryptOut>) -> Result<Vec<u8>> {
    Ok(results.next().ok_or_else(|| anyhow!("the key agent answered too few operations"))?.into_plain()?.to_vec())
}

#[cfg(test)]
fn one<T>(items: Vec<T>) -> Result<T> {
    items.into_iter().next().ok_or_else(|| anyhow!("encryption returned nothing"))
}

impl EncryptionContext {
    pub fn for_astation(astation_id: &str) -> Result<Self> {
        Self::for_astation_with(
            astation_id,
            &KeyPaths::default_paths(),
            Arc::from(crate::memory::key_agent::default_agent()),
        )
    }

    pub(crate) fn for_astation_with(astation_id: &str, paths: &KeyPaths, agent: Arc<dyn KeyAgentApi>) -> Result<Self> {
        let state = crate::memory::verification::account_mode(&paths.trust, astation_id)?;
        Ok(Self {
            mode: state.mode,
            data_account: state.data_account,
            kid: state.kid,
            astation_id: astation_id.into(),
            agent: state.mode.requires_key().then_some(agent),
            names_path: paths.project_names.clone(),
        })
    }

    /// Runs `work` on a blocking thread when it may reach the key agent
    /// (R7: socket I/O and autostart must not stall the runtime); inline
    /// when encryption is off.
    pub async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        if self.agent.is_none() {
            return work(self);
        }
        let context = self.clone();
        crate::memory::key_agent::blocking(move || work(&context)).await
    }

    /// `ops` in as few `Crypt` requests as the budget allows, results in order.
    fn run(&self, ops: Vec<CryptOp>) -> Result<Vec<CryptOut>> {
        if ops.is_empty() {
            return Ok(Vec::new());
        }
        let agent = self.agent.as_deref().ok_or_else(|| anyhow!("encryption is off for this account"))?;
        let mut results = Vec::with_capacity(ops.len());
        let mut batch = Vec::new();
        let mut bytes = 0;
        for op in ops {
            let size = op.wire_len();
            if !batch.is_empty() && (bytes + size > CRYPT_BATCH_BYTES || batch.len() >= CRYPT_BATCH_OPS) {
                results.extend(agent.crypt(&self.astation_id, std::mem::take(&mut batch))?);
                bytes = 0;
            }
            bytes += size;
            batch.push(op);
        }
        results.extend(agent.crypt(&self.astation_id, batch)?);
        Ok(results)
    }

    pub fn should_encrypt(&self) -> bool {
        matches!(self.mode, EncryptionMode::Enabling | EncryptionMode::On)
    }

    pub fn wire_project(&self, project: &str) -> Result<String> {
        if project.is_empty() || !self.should_encrypt() { return Ok(project.to_string()); }
        Ok(self.wire_projects(&[project.to_string()])?.remove(0))
    }

    /// Project keys as the relay sees them (`h1.` hashes while encrypting),
    /// remembered in project_names.json. Empty stays empty.
    pub fn wire_projects(&self, projects: &[String]) -> Result<Vec<String>> {
        if !self.should_encrypt() { return Ok(projects.to_vec()); }
        let ops = projects.iter()
            .filter(|project| !project.is_empty())
            .map(|project| CryptOp::keyed_hash(project.as_bytes()))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        let mut names = Vec::new();
        let wire = projects.iter()
            .map(|project| {
                if project.is_empty() { return Ok(String::new()); }
                let hash = next_text(&mut results)?;
                names.push((hash.clone(), project.clone()));
                Ok(hash)
            })
            .collect::<Result<Vec<_>>>()?;
        self.remember(names)?;
        Ok(wire)
    }

    pub fn seal(&self, record: &str, field: &str, plain: &[u8]) -> Result<String> {
        Ok(self.seal_many(&[(record, field, plain)])?.remove(0))
    }

    /// `e1.` fields for `(record, field, plain)`; empty plain text stays empty.
    pub fn seal_many(&self, items: &[(&str, &str, &[u8])]) -> Result<Vec<String>> {
        let ops = items.iter()
            .filter(|(_, _, plain)| !plain.is_empty())
            .map(|(record, field, plain)| CryptOp::seal(record, field, plain))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        items.iter()
            .map(|(_, _, plain)| if plain.is_empty() { Ok(String::new()) } else { next_text(&mut results) })
            .collect()
    }

    #[cfg(test)]
    pub fn open(&self, record: &str, field: &str, value: &str) -> Result<Vec<u8>> {
        Ok(self.open_many(&[(record, field, value)])?.remove(0))
    }

    /// The bytes of `(record, field, e1. value)`; an empty value stays empty.
    pub fn open_many(&self, items: &[(&str, &str, &str)]) -> Result<Vec<Vec<u8>>> {
        let ops = items.iter()
            .filter(|(_, _, value)| !value.is_empty())
            .map(|(record, field, value)| CryptOp::open(record, field, value))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        items.iter()
            .map(|(_, _, value)| if value.is_empty() { Ok(Vec::new()) } else { next_plain(&mut results) })
            .collect()
    }

    #[cfg(test)]
    pub fn keyed_hash(&self, value: &[u8]) -> Result<String> {
        let mut results = self.run(vec![CryptOp::keyed_hash(value)])?.into_iter();
        next_text(&mut results)
    }

    #[cfg(test)]
    pub fn encrypt_memory(&self, memory: Memory) -> Result<Memory> {
        one(self.encrypt_memories(vec![memory])?)
    }

    /// Every memory's project and content hash and sealed content, in one
    /// batch of agent requests.
    pub fn encrypt_memories(&self, memories: Vec<Memory>) -> Result<Vec<Memory>> {
        if !self.should_encrypt() { return Ok(memories); }
        let mut ops = Vec::new();
        for memory in &memories {
            if !memory.project.is_empty() { ops.push(CryptOp::keyed_hash(memory.project.as_bytes())); }
            if !memory.content.is_empty() {
                ops.push(CryptOp::keyed_hash(memory.content.as_bytes()));
                ops.push(CryptOp::seal(&memory.id, "content", memory.content.as_bytes()));
            }
        }
        let mut results = self.run(ops)?.into_iter();
        let mut names = Vec::new();
        let mut encrypted = Vec::with_capacity(memories.len());
        for mut memory in memories {
            if !memory.project.is_empty() {
                let hash = next_text(&mut results)?;
                names.push((hash.clone(), std::mem::replace(&mut memory.project, hash)));
            }
            if memory.content.is_empty() {
                memory.content_hash = String::new();
            } else {
                memory.content_hash = next_text(&mut results)?;
                memory.content = next_text(&mut results)?;
            }
            encrypted.push(memory);
        }
        self.remember(names)?;
        Ok(encrypted)
    }

    /// While encryption is on, every non-empty field from the relay must be
    /// sealed (`e1.`) or keyed (`h1.`). Plain text would let the relay inject
    /// instructions into the managed blocks agents read. Checked before any
    /// agent call.
    pub fn require_sealed(&self, value: &str, prefix: &str, what: &str) -> Result<()> {
        if self.mode == EncryptionMode::On && !value.is_empty() && !value.starts_with(prefix) {
            bail!("relay sent plain-text {what} while encryption is on; refusing it");
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn decrypt_memory(&self, memory: Memory) -> Result<Memory> {
        one(self.decrypt_memories(vec![memory])?)
    }

    pub fn decrypt_memories(&self, memories: Vec<Memory>) -> Result<Vec<Memory>> {
        if self.mode == EncryptionMode::Off { return Ok(memories); }
        for memory in &memories {
            self.require_sealed(&memory.content, "e1.", "memory content")?;
            self.require_sealed(&memory.project, "h1.", "memory project")?;
        }
        let names = if memories.iter().any(|memory| memory.project.starts_with("h1.")) { Some(self.names()?) } else { None };
        let ops = memories.iter()
            .filter(|memory| memory.content.starts_with("e1."))
            .map(|memory| CryptOp::open(&memory.id, "content", &memory.content))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        memories.into_iter()
            .map(|mut memory| {
                if memory.project.starts_with("h1.") {
                    memory.project = names.as_ref()
                        .and_then(|names| names.name(&self.data_account, &memory.project))
                        .map(str::to_string)
                        .ok_or_else(|| anyhow!(UNKNOWN_PROJECT))?;
                }
                if memory.content.starts_with("e1.") {
                    memory.content = String::from_utf8(next_plain(&mut results)?)
                        .context("memory content is not UTF-8")?;
                }
                if memory.content_hash.starts_with("h1.") {
                    memory.content_hash = content_hash(&memory.content);
                }
                Ok(memory)
            })
            .collect()
    }

    #[cfg(test)]
    pub fn encrypt_skill(&self, skill: Skill) -> Result<Skill> {
        one(self.encrypt_skills(vec![skill])?)
    }

    /// Two batches: every file path with the project and content hashes,
    /// then every file's bytes bound to its encrypted path.
    pub fn encrypt_skills(&self, skills: Vec<Skill>) -> Result<Vec<Skill>> {
        if !self.should_encrypt() { return Ok(skills); }
        let mut ops = Vec::new();
        for skill in &skills {
            let record = skill_record(skill);
            for path in skill.files.keys() {
                if !path.is_empty() { ops.push(CryptOp::seal(&record, "path", path.as_bytes())); }
            }
            if !skill.project.is_empty() { ops.push(CryptOp::keyed_hash(skill.project.as_bytes())); }
            ops.push(CryptOp::keyed_hash(skill_hash(&skill.files).as_bytes()));
        }
        let mut results = self.run(ops)?.into_iter();
        let mut names = Vec::new();
        let mut staged = Vec::with_capacity(skills.len());
        for skill in skills {
            let paths = skill.files.keys()
                .map(|path| if path.is_empty() { Ok(String::new()) } else { next_text(&mut results) })
                .collect::<Result<Vec<_>>>()?;
            let project = if skill.project.is_empty() {
                String::new()
            } else {
                let hash = next_text(&mut results)?;
                names.push((hash.clone(), skill.project.clone()));
                hash
            };
            let hash = next_text(&mut results)?;
            staged.push((skill, paths, project, hash));
        }
        let mut ops = Vec::new();
        for (skill, paths, _, _) in &staged {
            let record = skill_record(skill);
            for ((_, bytes), path) in skill.files.iter().zip(paths) {
                if !bytes.is_empty() { ops.push(CryptOp::seal(&record, &format!("file:{path}"), bytes)); }
            }
        }
        let mut results = self.run(ops)?.into_iter();
        let mut encrypted = Vec::with_capacity(staged.len());
        for (mut skill, paths, project, hash) in staged {
            let mut files = std::collections::BTreeMap::new();
            for ((_, bytes), path) in skill.files.iter().zip(paths) {
                let sealed = if bytes.is_empty() { String::new() } else { next_text(&mut results)? };
                files.insert(path, sealed.into_bytes());
            }
            skill.files = files;
            skill.project = project;
            skill.content_hash = hash;
            encrypted.push(skill);
        }
        self.remember(names)?;
        Ok(encrypted)
    }

    pub fn decrypt_skill(&self, skill: Skill) -> Result<Skill> {
        self.decrypt_skills(vec![skill])?.into_iter().next().ok_or_else(|| anyhow!("decryption returned nothing"))
    }

    pub fn decrypt_skills(&self, skills: Vec<Skill>) -> Result<Vec<Skill>> {
        if self.mode == EncryptionMode::Off { return Ok(skills); }
        for skill in &skills {
            self.require_sealed(&skill.project, "h1.", "skill project")?;
            for path in skill.files.keys() {
                self.require_sealed(path, "e1.", "skill file path")?;
            }
        }
        let names = if skills.iter().any(|skill| skill.project.starts_with("h1.")) { Some(self.names()?) } else { None };
        let sealed = |skill: &Skill| skill.files.keys().any(|path| path.starts_with("e1."));
        let mut ops = Vec::new();
        for skill in skills.iter().filter(|skill| sealed(skill)) {
            let record = skill_record(skill);
            for (path, bytes) in &skill.files {
                if !path.is_empty() { ops.push(CryptOp::open(&record, "path", path)); }
                let envelope = std::str::from_utf8(bytes).context("skill ciphertext is not UTF-8")?;
                if !envelope.is_empty() { ops.push(CryptOp::open(&record, &format!("file:{path}"), envelope)); }
            }
        }
        let mut results = self.run(ops)?.into_iter();
        skills.into_iter()
            .map(|mut skill| {
                if skill.project.starts_with("h1.") {
                    skill.project = names.as_ref()
                        .and_then(|names| names.name(&self.data_account, &skill.project))
                        .map(str::to_string)
                        .ok_or_else(|| anyhow!(UNKNOWN_PROJECT))?;
                }
                if sealed(&skill) {
                    let mut files = std::collections::BTreeMap::new();
                    for (path, bytes) in &skill.files {
                        let plain_path = if path.is_empty() { Vec::new() } else { next_plain(&mut results)? };
                        let plain_path = String::from_utf8(plain_path).context("skill path is not UTF-8")?;
                        let plain = if bytes.is_empty() { Vec::new() } else { next_plain(&mut results)? };
                        files.insert(plain_path, plain);
                    }
                    skill.files = files;
                }
                if skill.content_hash.starts_with("h1.") {
                    skill.content_hash = skill_hash(&skill.files);
                }
                Ok(skill)
            })
            .collect()
    }

    fn remember(&self, names: Vec<(String, String)>) -> Result<()> {
        crate::memory::project_names::remember(&self.names_path, &self.data_account, names)
    }

    fn names(&self) -> Result<crate::memory::project_names::ProjectNames> {
        crate::memory::project_names::ProjectNames::load_from(&self.names_path)
    }
}

fn skill_record(skill: &Skill) -> String {
    format!("{}:{}:{}", skill.scope.as_str(), skill.name, skill.version)
}
```

(`field_aad`, `remember_project` and `resolve_project` are gone; `skill_record` is kept as above.)

4. Delete `fn stored_summary_at` (old lines 626–637). `migrate_account` stays unchanged.

5. Tests module: delete `fn context()` and the tests `envelope_round_trip_and_tamper_failure`, `memory_and_binary_skill_round_trip`, `rotation_keeps_old_key_until_migration_and_off_removes_keys`, `unverified_astation_ignores_stored_mode_and_key`, `verified_signed_on_with_missing_key_store_is_an_error`, `unreadable_key_store_is_preserved_before_requesting_a_new_grant`, `plain_text_from_the_relay_is_rejected_while_on`, `purge_unverified_removes_legacy_keys_history_and_names` and `plain_text_is_still_read_during_migration`. Keep `concurrent_private_writes_to_one_file_never_collide`, `DEAD_PID` and the `write_private_*` tests. After `use std::collections::BTreeMap;` add:

```rust
    use crate::memory::fake_astation::{ASTATION_ID, UnlockedDevice};
    use crate::memory::key_agent::{Reply, Request};

    /// An agent an off context must never reach.
    struct NoAgent;

    impl KeyAgentApi for NoAgent {
        fn call(&self, _request: Request) -> Result<Reply> {
            panic!("an off or unverified context must not call the key agent")
        }
    }

    /// An unlocked device holding K = [7; 32] (kid 0123abcd) in `mode`.
    fn device(dir: &Path, mode: EncryptionMode) -> (UnlockedDevice, EncryptionContext) {
        let mut device = UnlockedDevice::new(dir);
        device.set_key(mode, "0123abcd", [7; 32]);
        let context = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone()).unwrap();
        (device, context)
    }

    fn memory(id: &str, project: &str, content: &str) -> Memory {
        Memory {
            id: id.into(),
            scope: crate::memory::model::Scope::Project,
            project: project.into(),
            content: content.into(),
            content_hash: content_hash(content),
            confidence: "high".into(),
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            ..Memory::default()
        }
    }

    #[test]
    fn envelope_round_trip_and_tamper_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::On);
        let sealed = context.seal("mem-1", "content", b"hello").unwrap();
        assert!(sealed.starts_with("e1.0123abcd."));
        assert_eq!(context.open("mem-1", "content", &sealed).unwrap(), b"hello");
        assert!(context.open("mem-2", "content", &sealed).is_err());
        let mut bad = sealed.into_bytes();
        let last = bad.len() - 2;
        bad[last] = if bad[last] == b'A' { b'B' } else { b'A' };
        assert!(context.open("mem-1", "content", std::str::from_utf8(&bad).unwrap()).is_err());
        assert!(context.keyed_hash(b"x").unwrap().starts_with("h1.0123abcd."));
    }

    #[test]
    fn memory_and_binary_skill_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::On);
        let plain = memory("mem-1", "github.com/agora/atem", "use port 27183");
        let encrypted = context.encrypt_memory(plain.clone()).unwrap();
        assert!(encrypted.content.starts_with("e1.0123abcd."));
        assert!(encrypted.project.starts_with("h1.0123abcd."));
        assert_eq!(context.decrypt_memory(encrypted).unwrap(), plain);

        let files = BTreeMap::from([
            ("SKILL.md".to_string(), b"hello".to_vec()),
            ("asset.bin".to_string(), vec![0, 159, 146, 150]),
            ("empty.txt".to_string(), Vec::new()),
        ]);
        let skill = Skill {
            scope: crate::memory::model::Scope::Global,
            project: String::new(),
            name: "sample".into(),
            version: 1,
            content_hash: skill_hash(&files),
            files,
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            deleted: false,
            seq: 1,
        };
        let encrypted = context.encrypt_skill(skill.clone()).unwrap();
        assert!(encrypted.files.keys().all(|path| path.starts_with("e1.0123abcd.")));
        assert_eq!(context.decrypt_skill(encrypted).unwrap(), skill);
    }

    #[test]
    fn batches_keep_order_and_empty_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::On);
        let plain = vec![
            memory("mem-1", "github.com/agora/atem", "first"),
            memory("mem-2", "", ""),
            memory("mem-3", "github.com/agora/dialf", "third"),
        ];
        let encrypted = context.encrypt_memories(plain.clone()).unwrap();
        assert_eq!(encrypted[1].content, "");
        assert_eq!(encrypted[1].content_hash, "");
        assert_eq!(encrypted[1].project, "");
        assert_eq!(context.decrypt_memories(encrypted).unwrap(), plain);
        let sealed = context.seal_many(&[("v", "summary", b"s"), ("v", "content", b""), ("v", "content", b"c")]).unwrap();
        assert_eq!(sealed[1], "");
        let items: Vec<(&str, &str, &str)> = vec![("v", "summary", &sealed[0]), ("v", "content", &sealed[1]), ("v", "content", &sealed[2])];
        assert_eq!(context.open_many(&items).unwrap(), vec![b"s".to_vec(), Vec::new(), b"c".to_vec()]);
    }

    #[test]
    fn project_names_are_remembered_locally_and_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let (device, context) = device(dir.path(), EncryptionMode::On);
        let wire = context.wire_project("github.com/agora/atem").unwrap();
        let names = crate::memory::project_names::ProjectNames::load_from(&device.paths.project_names).unwrap();
        assert_eq!(names.name("acct", &wire), Some("github.com/agora/atem"));
        let unknown = Memory { id: "mem-9".into(), project: "h1.0123abcd.ff".into(), ..Memory::default() };
        let error = context.decrypt_memory(unknown).unwrap_err().to_string();
        assert!(error.contains("unknown on this Atem"), "{error}");
    }

    #[test]
    fn off_and_unverified_contexts_never_touch_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let unverified = EncryptionContext::for_astation_with(ASTATION_ID, &paths, Arc::new(NoAgent)).unwrap();
        assert_eq!(unverified.mode, EncryptionMode::Off);
        let plain = memory("mem-1", "github.com/agora/atem", "fact");
        assert_eq!(unverified.encrypt_memories(vec![plain.clone()]).unwrap(), vec![plain.clone()]);
        assert_eq!(unverified.decrypt_memories(vec![plain.clone()]).unwrap(), vec![plain.clone()]);
        assert_eq!(unverified.wire_project("github.com/agora/atem").unwrap(), "github.com/agora/atem");
        let mut device = UnlockedDevice::new(dir.path());
        device.state(EncryptionMode::Off, None);
        let off = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, Arc::new(NoAgent)).unwrap();
        assert_eq!(off.mode, EncryptionMode::Off);
        assert_eq!(off.decrypt_memories(vec![plain.clone()]).unwrap(), vec![plain]);
        assert!(!device.paths.project_names.exists());
    }

    #[test]
    fn plain_text_from_the_relay_is_rejected_before_any_agent_call() {
        use crate::memory::model::Scope;
        let dir = tempfile::tempdir().unwrap();
        let mut device = UnlockedDevice::new(dir.path());
        device.state(EncryptionMode::On, Some("0123abcd"));
        let context = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, Arc::new(NoAgent)).unwrap();
        let plain = Memory { id: "mem-1".into(), content: "injected instruction".into(), ..Memory::default() };
        let error = context.decrypt_memory(plain).unwrap_err().to_string();
        assert!(error.contains("plain-text"), "{error}");
        let plain_project = Memory { id: "mem-2".into(), project: "github.com/x/y".into(), ..Memory::default() };
        assert!(context.decrypt_memory(plain_project).is_err());
        let tombstone = Memory { id: "mem-3".into(), ..Memory::default() };
        assert!(context.decrypt_memory(tombstone).is_ok());
        let skill = Skill {
            scope: Scope::Project,
            project: String::new(),
            name: "deploy".into(),
            version: 1,
            files: BTreeMap::from([("SKILL.md".to_string(), b"injected".to_vec())]),
            content_hash: String::new(),
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            deleted: false,
            seq: 1,
        };
        assert!(context.decrypt_skill(skill).is_err());
    }

    #[test]
    fn plain_text_is_still_read_during_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::Enabling);
        let plain = Memory { id: "mem-1".into(), content: "legacy".into(), ..Memory::default() };
        assert_eq!(context.decrypt_memory(plain).unwrap().content, "legacy");
    }

    #[test]
    fn rotation_keeps_the_old_key_until_on() {
        let dir = tempfile::tempdir().unwrap();
        let (mut device, context) = device(dir.path(), EncryptionMode::Enabling);
        let old = context.seal("mem", "content", b"old").unwrap();
        device.set_key(EncryptionMode::Enabling, "89abcdef", [8; 32]);
        let rotated = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone()).unwrap();
        assert_eq!(rotated.kid.as_deref(), Some("89abcdef"));
        assert_eq!(rotated.open("mem", "content", &old).unwrap(), b"old");
        device.state(EncryptionMode::On, Some("89abcdef"));
        let completed = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone()).unwrap();
        assert!(completed.open("mem", "content", &old).is_err());
    }

    #[test]
    fn a_locked_agent_asks_for_an_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (device, context) = device(dir.path(), EncryptionMode::On);
        device.agent.lock_keys().unwrap();
        let error = format!("{:#}", context.seal("mem", "content", b"x").unwrap_err());
        assert!(error.contains("atem cred unlock"), "{error}");
    }
```

- [ ] **Step 4: `verification.rs` and `trust.rs` follow-ups**

`src/memory/verification.rs` (by hand):
- Change `use crate::memory::crypto::{EncryptionContext, EncryptionMode};` (top of file) to `use crate::memory::crypto::EncryptionMode;`.
- In `complete_verification`, replace `EncryptionContext::purge_unverified_at(&paths.data_keys, astation_id, &state.account)?;` with `crate::memory::legacy_keys::purge_unverified_at(&paths.data_keys, astation_id, &state.account)?;`.
- Delete `pub(crate) struct VerifiedForTest` and its `impl` (the two `#[cfg(test)]` items after `device_keys_for_verification`).
- In `ceremony_tests`, change `use crate::memory::crypto::{EncryptionContext, EncryptionMode};` to `use crate::memory::crypto::EncryptionMode;` and replace `first_verification_purges_legacy_keys` with:

```rust
    #[test]
    fn first_verification_purges_legacy_keys() {
        use crate::memory::legacy_keys::{summary_at, write_for_test};
        let dir = tempfile::tempdir().unwrap();
        let legacy = KeyPaths::in_dir(dir.path());
        // K, its rotation history and a project name from the unauthenticated #36 path.
        write_for_test(&legacy.data_keys, ASTATION_ID, "acct", &[("0123abcd", [1; 32]), ("11112222", [2; 32])], &[("h1.11112222.aa", "github.com/agora/atem")]);
        crate::memory::project_names::remember(&legacy.project_names, "acct", [("h1.11112222.aa".to_string(), "github.com/agora/atem".to_string())]).unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::On, Some("89abcdef"), 2), vec![])
        });
        result.unwrap();
        assert_eq!(summary_at(&paths.data_keys, "acct"), (None, vec![], 0), "the old K and its history must be gone");
        assert_eq!(crate::memory::project_names::ProjectNames::load_from(&paths.project_names).unwrap().len("acct"), 0);
    }
```

`src/memory/trust.rs`: delete `pub fn trust_path_for` (with its doc comment) and, in its test, the line `assert_eq!(trust_path_for(&dir.path().join("data_keys.enc")), path);`.

- [ ] **Step 5: `api.rs` (by hand, never rustfmt)**

1. Imports: replace `use crate::memory::crypto::EncryptionContext;` with:

```rust
use crate::memory::crypto::{EncryptionContext, EncryptionMode};
```

2. In `struct KnowledgeClient`, replace the `encryption_store` field with:

```rust
    #[cfg(test)]
    encryption_with: Option<(crate::memory::verification::KeyPaths, std::sync::Arc<dyn crate::memory::key_agent::KeyAgentApi>)>,
```

in `new`, `encryption_store: None,` → `encryption_with: None,`; replace `with_encryption_store` and `encryption` with:

```rust
    #[cfg(test)]
    pub(crate) fn with_encryption(mut self, paths: crate::memory::verification::KeyPaths, agent: std::sync::Arc<dyn crate::memory::key_agent::KeyAgentApi>) -> Self {
        self.encryption_with = Some((paths, agent));
        self
    }
```

```rust
    fn encryption(&self) -> Result<EncryptionContext, ApiError> {
        #[cfg(test)]
        if let Some((paths, agent)) = &self.encryption_with {
            return EncryptionContext::for_astation_with(&self.astation_id, paths, agent.clone())
                .map_err(|error| ApiError::Encryption(error.to_string()));
        }
        EncryptionContext::for_astation(&self.astation_id)
            .map_err(|error| ApiError::Encryption(error.to_string()))
    }
```

3. Delete the method `encrypted_op` and add this free function before `impl KnowledgeClient`:

```rust
/// The wire form of `ops`, encrypted when the account is: every memory,
/// skill and project hash of the batch in a few key-agent round trips.
fn encrypted_ops(encryption: &EncryptionContext, ops: &[PendingOp]) -> anyhow::Result<Vec<Value>> {
    if !encryption.should_encrypt() {
        return Ok(ops.iter().map(op_to_wire).collect());
    }
    let memories = encryption.encrypt_memories(ops.iter().filter_map(|op| match op {
        PendingOp::AddMemory { memory } => Some(memory.clone()),
        _ => None,
    }).collect())?;
    let skills = encryption.encrypt_skills(ops.iter().filter_map(|op| match op {
        PendingOp::PushSkill { skill, .. } => Some(skill.clone()),
        _ => None,
    }).collect())?;
    let projects = encryption.wire_projects(&ops.iter().filter_map(|op| match op {
        PendingOp::DeleteSkill { project, .. } | PendingOp::PurgeSkill { project, .. } => Some(project.clone()),
        _ => None,
    }).collect::<Vec<_>>())?;
    let (mut memories, mut skills, mut projects) = (memories.into_iter(), skills.into_iter(), projects.into_iter());
    let missing = || anyhow::anyhow!("an encrypted field of the batch is missing");
    ops.iter().map(|op| Ok(match op {
        PendingOp::AddMemory { .. } => json!({"op": "add", "memory": memories.next().ok_or_else(missing)?}),
        PendingOp::PushSkill { base_version, .. } => json!({"op": "push", "skill": skills.next().ok_or_else(missing)?, "base_version": base_version}),
        PendingOp::DeleteSkill { scope, name, .. } => json!({"op": "delete", "scope": scope, "project": projects.next().ok_or_else(missing)?, "name": name}),
        PendingOp::PurgeSkill { scope, name, versions, .. } => json!({"op": "purge", "scope": scope, "project": projects.next().ok_or_else(missing)?, "name": name, "versions": versions}),
        _ => op_to_wire(op),
    })).collect()
}
```

4. Replace `push`, `pull_memories`, `pull_skills`, `skill_versions`, `skill_version` with:

```rust
    pub async fn push(&self, ops: &[&PendingOp], memory: bool) -> Result<Vec<OpResult>, ApiError> {
        let encryption = self.encryption()?;
        let kind = if memory { "memory" } else { "skills" };
        let owned: Vec<PendingOp> = ops.iter().map(|op| (*op).clone()).collect();
        let wire = encryption.blocking(move |encryption| encrypted_ops(encryption, &owned)).await?;
        let req = ApiRequest {
            method: "POST",
            url: format!("{}/api/{kind}/batch?id={}", base_trim(&self.base), enc(&self.client_id)),
            body: Some(json!({"ops": wire})),
        };
        let resp: BatchResponse = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(resp.results)
    }

    pub async fn pull_memories(&self, since: i64) -> Result<Vec<Memory>, ApiError> {
        let req = memory_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: MemoryPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        let encryption = self.encryption()?;
        encryption.blocking(move |encryption| encryption.decrypt_memories(page.memories)).await.map_err(ApiError::from)
    }

    pub async fn pull_skills(&self, since: i64) -> Result<Vec<Skill>, ApiError> {
        let req = skills_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: SkillPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        let encryption = self.encryption()?;
        encryption.blocking(move |encryption| encryption.decrypt_skills(page.skills)).await.map_err(ApiError::from)
    }

    /// A skill's history, newest first (no files).
    pub async fn skill_versions(&self, scope: Scope, project: &str, name: &str) -> Result<Vec<SkillVersionInfo>, ApiError> {
        let encryption = self.encryption()?;
        let project = project.to_string();
        let project = encryption.blocking(move |encryption| encryption.wire_project(&project)).await.map_err(ApiError::from)?;
        let req = skill_versions_request(&self.base, &self.client_id, scope, &project, name);
        let page: VersionsPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.versions)
    }

    /// One version with its files. 404 unknown, 410 purged (as `ApiError::Http`).
    pub async fn skill_version(&self, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill, ApiError> {
        let encryption = self.encryption()?;
        let project = project.to_string();
        let project = encryption.blocking(move |encryption| encryption.wire_project(&project)).await.map_err(ApiError::from)?;
        let req = skill_version_request(&self.base, &self.client_id, scope, &project, name, version);
        let page: VersionPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        encryption.blocking(move |encryption| encryption.decrypt_skill(page.skill)).await.map_err(ApiError::from)
    }
```

5. In `migrate_encryption`, delete the line `use crate::memory::crypto::EncryptionMode;` (now imported at the top), and replace the body of the memory chunk loop up to (not including) `let response: BatchResponse = ...` with:

```rust
            let raw = chunk.to_vec();
            let ops = encryption.blocking(move |encryption| {
                let plain = encryption.decrypt_memories(raw.clone())?;
                let desired = if encryption.mode == EncryptionMode::Enabling { encryption.encrypt_memories(plain)? } else { plain };
                Ok(raw.iter().zip(desired).map(|(old, desired)| json!({
                    "op": "rewrite",
                    "id": old.id,
                    "project": desired.project,
                    "content": desired.content,
                    "content_hash": desired.content_hash,
                })).collect::<Vec<_>>())
            }).await?;
```

and the skill chunk loop's body up to `let response: BatchResponse = ...` with:

```rust
            let raw = chunk.to_vec();
            let ops = encryption.blocking(move |encryption| {
                let plain = encryption.decrypt_skills(raw.clone())?;
                let desired = if encryption.mode == EncryptionMode::Enabling { encryption.encrypt_skills(plain)? } else { plain };
                Ok(raw.iter().zip(desired).map(|(old, desired)| json!({
                    "op": "rewrite",
                    "scope": desired.scope,
                    "old_project": old.project,
                    "name": desired.name,
                    "version": desired.version,
                    "project": desired.project,
                    "files": desired.files,
                    "content_hash": desired.content_hash,
                })).collect::<Vec<_>>())
            }).await?;
```

- [ ] **Step 6: `vault_client.rs` (by hand, never rustfmt)**

1. Replace the `encryption_store` field with:

```rust
    #[cfg(test)]
    encryption_with: Option<(crate::memory::verification::KeyPaths, std::sync::Arc<dyn crate::memory::key_agent::KeyAgentApi>)>,
```

`new`: `encryption_store: None,` → `encryption_with: None,`. Replace `with_encryption_store` and `encryption` with:

```rust
    #[cfg(test)]
    pub(crate) fn with_encryption(mut self, paths: crate::memory::verification::KeyPaths, agent: std::sync::Arc<dyn crate::memory::key_agent::KeyAgentApi>) -> Self {
        self.encryption_with = Some((paths, agent));
        self
    }

    fn encryption(&self) -> Result<EncryptionContext> {
        #[cfg(test)]
        if let Some((paths, agent)) = &self.encryption_with {
            return EncryptionContext::for_astation_with(&self.astation_id, paths, agent.clone());
        }
        EncryptionContext::for_astation(&self.astation_id)
    }
```

2. Replace `list`, `read`, `write`, `set_summary` with:

```rust
    pub async fn list(&self) -> Result<Vec<VaultListItem>> {
        let req = list_vaults_request(&self.base, &self.client_id);
        let encryption = self.encryption()?;
        let items: Vec<VaultListItem> = self.send(req).await?.json().await?;
        encryption.blocking(move |encryption| open_summaries(encryption, items)).await
    }

    pub async fn read(&self, vault_id: &str, since: Option<u64>, history: bool) -> Result<Vec<VaultEntry>> {
        let req = read_vault_request(&self.base, &self.client_id, vault_id, since, history);
        let encryption = self.encryption()?;
        let entries: Vec<VaultEntry> = self.send(req).await?.json().await?;
        let vault_id = vault_id.to_string();
        encryption.blocking(move |encryption| open_entries(encryption, &vault_id, entries)).await
    }

    pub async fn write(&self, vault_id: &str, text: &str, entry_id: Option<u32>) -> Result<WriteResult> {
        let encryption = self.encryption()?;
        let text = if encryption.should_encrypt() {
            let (id, plain) = (vault_id.to_string(), text.to_string());
            encryption.blocking(move |encryption| encryption.seal(&id, "content", plain.as_bytes())).await?
        } else { text.to_string() };
        let req = write_vault_request(&self.base, &self.client_id, vault_id, &text, entry_id);
        Ok(self.send(req).await?.json().await?)
    }

    pub async fn set_summary(&self, vault_id: &str, text: &str) -> Result<()> {
        let encryption = self.encryption()?;
        let text = if encryption.should_encrypt() {
            let (id, plain) = (vault_id.to_string(), text.to_string());
            encryption.blocking(move |encryption| encryption.seal(&id, "summary", plain.as_bytes())).await?
        } else { text.to_string() };
        let req = set_summary_request(&self.base, &self.client_id, vault_id, &text);
        self.send(req).await?;
        Ok(())
    }
```

3. In `migrate_encryption`, replace the `for (item, entries) in snapshot { ... }` loop with:

```rust
        for (item, entries) in snapshot {
            let vault_id = item.vault_id.clone();
            let body = encryption.blocking(move |encryption| migrated_vault(encryption, &item, &entries)).await?;
            self.send(VaultRequest {
                method: "POST",
                url: format!(
                    "{}/api/vault/{}/encryption?id={}",
                    base_trim(&self.base),
                    enc(&vault_id),
                    enc(&self.client_id),
                ),
                body: Some(body),
            }).await?;
        }
```

4. Add before `#[cfg(test)] mod tests`:

```rust
/// Opens every sealed summary in one key-agent round trip; plain text is
/// refused while encryption is on.
fn open_summaries(encryption: &EncryptionContext, mut items: Vec<VaultListItem>) -> Result<Vec<VaultListItem>> {
    for item in &items {
        encryption.require_sealed(&item.summary, "e1.", "vault summary")?;
    }
    let opened = {
        let sealed: Vec<(&str, &str, &str)> = items.iter()
            .filter(|item| item.summary.starts_with("e1."))
            .map(|item| (item.vault_id.as_str(), "summary", item.summary.as_str()))
            .collect();
        encryption.open_many(&sealed)?
    };
    let mut opened = opened.into_iter();
    for item in &mut items {
        if item.summary.starts_with("e1.") {
            let plain = opened.next().ok_or_else(|| anyhow!("a vault summary was not opened"))?;
            item.summary = String::from_utf8(plain).context("vault summary is not UTF-8")?;
        }
    }
    Ok(items)
}

/// Opens every sealed entry of `vault_id` in one key-agent round trip.
fn open_entries(encryption: &EncryptionContext, vault_id: &str, mut entries: Vec<VaultEntry>) -> Result<Vec<VaultEntry>> {
    for entry in &entries {
        encryption.require_sealed(&entry.content, "e1.", "vault entry")?;
    }
    let opened = {
        let sealed: Vec<(&str, &str, &str)> = entries.iter()
            .filter(|entry| entry.content.starts_with("e1."))
            .map(|entry| (vault_id, "content", entry.content.as_str()))
            .collect();
        encryption.open_many(&sealed)?
    };
    let mut opened = opened.into_iter();
    for entry in &mut entries {
        if entry.content.starts_with("e1.") {
            let plain = opened.next().ok_or_else(|| anyhow!("a vault entry was not opened"))?;
            entry.content = String::from_utf8(plain).context("vault entry is not UTF-8")?;
        }
    }
    Ok(entries)
}

/// One vault's summary and every entry version, re-sealed under the current
/// key (`enabling`) or opened to plain text (`disabling`): the body of
/// `POST /api/vault/{id}/encryption`, in one or two key-agent round trips.
fn migrated_vault(encryption: &EncryptionContext, item: &VaultListItem, entries: &[VaultEntry]) -> Result<Value> {
    use crate::memory::crypto::EncryptionMode;
    let id = item.vault_id.as_str();
    let mut sealed: Vec<(&str, &str, &str)> = Vec::new();
    if item.summary.starts_with("e1.") {
        sealed.push((id, "summary", item.summary.as_str()));
    }
    sealed.extend(entries.iter()
        .filter(|entry| entry.content.starts_with("e1."))
        .map(|entry| (id, "content", entry.content.as_str())));
    let mut opened = encryption.open_many(&sealed)?.into_iter();
    let mut plain = |value: &str, what: &'static str| -> Result<String> {
        if !value.starts_with("e1.") {
            return Ok(value.to_string());
        }
        let bytes = opened.next().ok_or_else(|| anyhow!("a vault field was not opened"))?;
        String::from_utf8(bytes).context(what)
    };
    let summary = plain(&item.summary, "vault summary is not UTF-8")?;
    let contents = entries.iter()
        .map(|entry| plain(&entry.content, "vault entry is not UTF-8"))
        .collect::<Result<Vec<_>>>()?;
    let (summary, contents) = if encryption.mode == EncryptionMode::Enabling {
        let mut fields: Vec<(&str, &str, &[u8])> = vec![(id, "summary", summary.as_bytes())];
        fields.extend(contents.iter().map(|content| (id, "content", content.as_bytes())));
        let mut resealed = encryption.seal_many(&fields)?.into_iter();
        let summary = resealed.next().unwrap_or_default();
        (summary, resealed.collect::<Vec<_>>())
    } else {
        (summary, contents)
    };
    let rewritten: Vec<Value> = entries.iter().zip(contents)
        .map(|(entry, content)| json!({
            "entry_no": entry.entry_no,
            "version": entry.version,
            "content": content,
        }))
        .collect();
    Ok(json!({"summary": summary, "entries": rewritten}))
}
```

- [ ] **Step 7: `e2e_tests.rs` against the agent (by hand)**

1. Imports: replace `use crate::memory::crypto::{EncryptionContext, EncryptionMode};` with:

```rust
use crate::memory::account_keys::CryptOp;
use crate::memory::crypto::{EncryptionContext, EncryptionMode};
use crate::memory::fake_astation::UnlockedDevice;
use crate::memory::key_agent::{KeyAgent, KeyAgentApi, Reply, Request, error_of, test_agent};
use crate::memory::verification::KeyPaths;
use std::sync::atomic::{AtomicUsize, Ordering};
```

Delete `const ACCOUNT: &str = "account-1";` (the fake device's account is `acct`; `ASTATION` stays `"astation-1"`, the fake device's Astation id).

2. Replace `clients` and `set_key` with:

```rust
fn clients(base: &str, device: &UnlockedDevice) -> (KnowledgeClient, VaultClient) {
    (
        KnowledgeClient::new(
            base.into(),
            "atem-1".into(),
            "session-1".into(),
            ASTATION.into(),
        )
        .with_encryption(device.paths.clone(), device.agent.clone()),
        VaultClient::new(
            base.into(),
            "atem-1".into(),
            "session-1".into(),
            ASTATION.into(),
        )
        .with_encryption(device.paths.clone(), device.agent.clone()),
    )
}
```

3. In `real_clients_migrate_upload_pull_and_rotate_every_history_row`: replace the first lines through `let mut verified = ...;` with

```rust
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    let relay_state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(relay_state.clone()).await;
    let (knowledge, vault) = clients(&base, &device);
```

replace `set_key(&mut verified, &key_store, EncryptionMode::Enabling, OLD_KID, [7; 32]);` with `device.set_key(EncryptionMode::Enabling, OLD_KID, [7; 32]);`, `set_key(&mut verified, &key_store, EncryptionMode::Enabling, NEW_KID, [8; 32]);` with `device.set_key(EncryptionMode::Enabling, NEW_KID, [8; 32]);`, and the block `EncryptionContext::update_mode_at(...).unwrap(); verified.state(EncryptionMode::On, Some(NEW_KID));` with `device.state(EncryptionMode::On, Some(NEW_KID));`.

4. Replace `missing_encryption_key_keeps_sync_operations_queued` with:

```rust
#[tokio::test]
async fn missing_encryption_key_keeps_sync_operations_queued() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    // On, but no grant yet: the agent holds no K.
    device.state(EncryptionMode::On, Some(OLD_KID));
    let relay_state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(relay_state).await;
    let (knowledge, _) = clients(&base, &device);
    let store = Store::open_in_memory().unwrap();
    let memory = Memory {
        id: "mem-queued".into(),
        scope: Scope::Global,
        content: "must remain queued".into(),
        content_hash: content_hash("must remain queued"),
        confidence: "high".into(),
        source_agent: "test".into(),
        source_machine: "mac".into(),
        created_at: 1,
        ..Memory::default()
    };
    store.upsert_memory(&memory).unwrap();
    store.enqueue(&PendingOp::AddMemory { memory }).unwrap();
    let context = Ctx {
        home: directory.path().into(),
        repo: None,
        atem_id: "atem-1".into(),
        allow_tracked: false,
    };
    let options = SyncOptions { harvest: false };

    let outcome = run_sync(&store, Some(&knowledge), &context, &options).await.unwrap();
    assert!(outcome.relay_error);
    assert!(outcome.notes.iter().any(|note| note.contains("requires encryption")), "{:?}", outcome.notes);
    assert_eq!(store.pending_count().unwrap(), 1);

    // A locked agent takes the same path: queued, with the way out.
    device.agent.lock_keys().unwrap();
    let outcome = run_sync(&store, Some(&knowledge), &context, &options).await.unwrap();
    assert!(outcome.relay_error);
    assert!(outcome.notes.iter().any(|note| note.contains("atem cred unlock")), "{:?}", outcome.notes);
    assert_eq!(store.pending_count().unwrap(), 1);
}
```

5. In `relay_injected_plain_text_is_rejected_while_on`, replace the setup lines through `let (knowledge, vault) = clients(&base, &store_path);` with:

```rust
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
    let state = Arc::new(Mutex::new(RelayState::seeded()));
    let base = stub_relay(state.clone()).await;
    let (knowledge, vault) = clients(&base, &device);
```

6. Append the batching and copied-directory tests:

```rust
/// Counts the `Crypt` requests that reach the agent.
struct CountingAgent {
    inner: Arc<Mutex<KeyAgent>>,
    crypts: AtomicUsize,
}

impl KeyAgentApi for CountingAgent {
    fn call(&self, request: Request) -> anyhow::Result<Reply> {
        if matches!(request, Request::Crypt { .. }) {
            self.crypts.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.call(request)
    }
}

fn numbered(n: usize) -> Memory {
    let content = format!("fact number {n}");
    Memory {
        id: format!("mem-{n}"),
        scope: Scope::Project,
        project: "github.com/agora/atem".into(),
        content_hash: content_hash(&content),
        content,
        confidence: "high".into(),
        source_agent: "test".into(),
        source_machine: "mac".into(),
        created_at: 1,
        seq: n as i64 + 1,
        ..Memory::default()
    }
}

#[tokio::test]
async fn a_full_pull_and_push_are_one_agent_round_trip_each() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::On, OLD_KID, [7; 32]);
    let counting = Arc::new(CountingAgent { inner: device.agent.clone(), crypts: AtomicUsize::new(0) });
    let context = EncryptionContext::for_astation_with(ASTATION, &device.paths, counting.clone()).unwrap();
    let plain: Vec<Memory> = (0..200).map(numbered).collect();
    let sealed = context.encrypt_memories(plain.clone()).unwrap();
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 1, "200 memories encrypt in one request");

    let mut relay = RelayState::seeded();
    relay.memories = sealed;
    let base = stub_relay(Arc::new(Mutex::new(relay))).await;
    let knowledge = KnowledgeClient::new(base, "atem-1".into(), "session-1".into(), ASTATION.into())
        .with_encryption(device.paths.clone(), counting.clone());
    counting.crypts.store(0, Ordering::SeqCst);
    let pulled = knowledge.pull_memories(0).await.unwrap();
    assert_eq!(
        pulled.iter().map(|memory| memory.content.as_str()).collect::<Vec<_>>(),
        plain.iter().map(|memory| memory.content.as_str()).collect::<Vec<_>>()
    );
    assert!(pulled.iter().all(|memory| memory.project == "github.com/agora/atem"));
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 1, "a 200-memory page opens in one request");

    counting.crypts.store(0, Ordering::SeqCst);
    let ops: Vec<PendingOp> = plain.into_iter().map(|memory| PendingOp::AddMemory { memory }).collect();
    let refs: Vec<&PendingOp> = ops.iter().collect();
    assert_eq!(knowledge.push(&refs, true).await.unwrap().len(), 200);
    assert_eq!(counting.crypts.load(Ordering::SeqCst), 1, "a 200-op push seals in one request");
}

#[test]
fn a_copied_config_directory_yields_no_k() {
    let directory = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(directory.path());
    device.set_key(EncryptionMode::On, OLD_KID, [42; 32]);
    EncryptionContext::for_astation_with(ASTATION, &device.paths, device.agent.clone())
        .unwrap()
        .wire_project("github.com/agora/atem")
        .unwrap();
    let copy = tempfile::tempdir().unwrap();
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), copy.path().join(entry.file_name())).unwrap();
        }
    }
    let paths = KeyPaths::in_dir(copy.path());
    assert!(paths.device_keys_sealed.exists() && paths.project_names.exists() && paths.trust.exists());
    assert!(!paths.data_keys.exists() && !paths.device_keys.exists());
    // No file holds K in any encoding.
    let k = [42u8; 32];
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k);
    let hex: String = k.iter().map(|byte| format!("{byte:02x}")).collect();
    for entry in std::fs::read_dir(copy.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!bytes.windows(32).any(|window| window == k));
        assert!(!text.contains(&encoded) && !text.contains(&hex));
    }
    // An agent over the copy starts locked: nothing can be sealed or opened.
    let agent = Arc::new(test_agent(&paths));
    assert!(!agent.status().unwrap().unlocked);
    let context = EncryptionContext::for_astation_with(ASTATION, &paths, agent.clone()).unwrap();
    assert_eq!(context.mode, EncryptionMode::On);
    assert!(format!("{:#}", context.seal("mem", "content", b"x").unwrap_err()).contains("atem cred unlock"));
    assert!(error_of(agent.crypt(ASTATION, vec![CryptOp::keyed_hash(b"x")])).contains("atem cred unlock"));
}
```

- [ ] **Step 8: Run the tests**

Run: `cargo test memory::crypto`
Expected: PASS.

Run: `cargo test memory::e2e_tests`
Expected: PASS (migration/rotation, queued ops, plain-text rejection, batching, copied directory).

Run: `cargo test memory::verification`
Expected: PASS.

Run: `cargo test memory::sync`
Expected: PASS (sync tests use unverified accounts: off, no agent).

Run: `cargo test vault_client`
Expected: PASS.

Run: `cargo build && cargo clippy --all-targets --all-features 2>&1 | grep -E "^(warning|error)" | sort | uniq -c`
Expected: build succeeds; no new warnings (in particular no `dead_code` for `EncryptionContext` methods).

- [ ] **Step 9: Format and commit**

```bash
rustfmt --edition 2024 src/memory/legacy_keys.rs src/memory/trust.rs
git add src/memory/legacy_keys.rs src/memory/mod.rs src/memory/crypto.rs src/memory/api.rs src/vault_client.rs src/memory/verification.rs src/memory/trust.rs src/memory/e2e_tests.rs
git commit -m "feat(memory): EncryptionContext asks the key agent, in batches; data_keys.enc is read-only

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 8: The agent moves `data_keys.enc` in and deletes it

**Files:**
- Modify: `src/memory/account_keys.rs` (`merge`), `src/memory/legacy_keys.rs` (`keys_for`, `names_for`), `src/memory/key_agent.rs` (`migrate_data_keys`, `drop_unverified_data_keys`, `after_unlock`, `new`, `confirm_rotation`, `remove_synced`, test hook)
- Test: `src/memory/account_keys.rs`, `src/memory/k_agent_tests.rs`

**Interfaces:**
- Consumes: Task 7 (`legacy_keys::{read, Legacy}`), Task 3 (`project_names::remember`), Task 4 (`persist`, `reconcile`).
- Produces:
  - `AccountKeys::merge(&mut self, account: &str, current: AccountKey, previous: Vec<AccountKey>) -> bool`
  - `LegacyKeys::keys_for(&self, accounts: &BTreeSet<String>) -> Vec<(String, AccountKey, Vec<AccountKey>)>`, `LegacyKeys::names_for(&self, accounts: &BTreeSet<String>) -> Vec<(String, Vec<(String, String)>)>`
  - `#[cfg(test)] KeyAgent::kids_for_test(&self, account: &str) -> (Option<String>, Vec<String>)`
  - Behaviour: at every unlock (and at start when the agent starts unlocked from a plain `device_keys`, and at the first confirmed escrow) the agent merges `data_keys.enc` (verified accounts only) and deletes it once escrowed and not unlocked via `.prev`; unreadable → deleted; no verified Astation at agent start → deleted.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `src/memory/account_keys.rs`:

```rust
    #[test]
    fn merge_adds_older_keys_and_never_replaces_the_current_one() {
        let mut keys = AccountKeys::default();
        assert!(keys.merge("acct", key("0123abcd", 1), vec![key("11112222", 2)]));
        assert_eq!(keys.current_kid("acct"), Some("0123abcd"));
        assert_eq!(keys.previous_kids("acct"), vec!["11112222".to_string()]);
        // A newer K installed meanwhile stays current; the merge only adds history.
        keys.install("acct", "89abcdef", Zeroizing::new([3; 32]));
        assert!(!keys.merge("acct", key("0123abcd", 1), vec![key("11112222", 2)]), "a repeat changes nothing");
        assert_eq!(keys.current_kid("acct"), Some("89abcdef"));
        let mut previous = keys.previous_kids("acct");
        previous.sort();
        assert_eq!(previous, vec!["0123abcd".to_string(), "11112222".to_string()]);
    }
```

Append to `src/memory/k_agent_tests.rs`:

```rust
use crate::memory::account_keys::{AccountKey, seal_field};
use crate::memory::fake_astation::{ACCOUNT, FakeKeyServer, pin};
use crate::memory::legacy_keys::write_for_test;
use crate::memory::project_names::ProjectNames;
use crate::memory::statements::FakeAstation;
use crate::memory::device_keys::DeviceKeys;
use crate::memory::verification::KeyPaths;

const OLD: &str = "11112222";

/// A step-2a data_keys.enc for the fake device: K = [42; 32] (kid A) with
/// the older [1; 32] (kid OLD), and one project name.
fn legacy(paths: &KeyPaths, account: &str) {
    write_for_test(
        &paths.data_keys,
        ASTATION_ID,
        account,
        &[(OLD, [1; 32]), (A, [42; 32])],
        &[("h1.0123abcd.aa", "github.com/agora/atem")],
    );
}

/// A field sealed under the older key, as the relay may still hold it.
fn sealed_under_old() -> String {
    seal_field(
        &AccountKey { kid: OLD.into(), key: zeroize::Zeroizing::new([1; 32]) },
        "mem",
        "content",
        b"old",
    )
    .unwrap()
}

#[test]
fn an_unlock_moves_data_keys_enc_into_the_sealed_file() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
    set_state(&paths, &server.astation, EncryptionMode::Enabling, Some(A), 2);
    legacy(&paths, ACCOUNT);
    let agent = std::sync::Arc::new(test_agent(&paths));
    assert!(paths.data_keys.exists(), "a locked agent leaves it");
    unlock_with(agent.as_ref(), &server, &paths).unwrap();
    assert!(!paths.data_keys.exists());
    assert_eq!(agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some(A));
    let names = ProjectNames::load_from(&paths.project_names).unwrap();
    assert_eq!(names.name(ACCOUNT, "h1.0123abcd.aa"), Some("github.com/agora/atem"));
    let opened = agent.crypt(ASTATION_ID, vec![CryptOp::open("mem", "content", &sealed_under_old())]).unwrap();
    assert_eq!(&*opened.into_iter().next().unwrap().into_plain().unwrap(), b"old");
    // From now on K comes from the sealed file.
    agent.lock_keys().unwrap();
    unlock_with(agent.as_ref(), &server, &paths).unwrap();
    assert!(holds_k(agent.as_ref(), ASTATION_ID));
}

#[test]
fn a_failed_re_seal_keeps_data_keys_enc_for_the_next_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
    set_state(&paths, &server.astation, EncryptionMode::On, Some(A), 2);
    legacy(&paths, ACCOUNT);
    let agent = test_agent(&paths);
    {
        let _failing = fail_writes_to(&paths.device_keys_sealed);
        unlock_with(&agent, &server, &paths).unwrap();
    }
    assert!(paths.data_keys.exists(), "the only copy of K is never deleted before it is sealed");
    assert_eq!(agent.held_kid(ASTATION_ID).unwrap(), None);
    agent.lock_keys().unwrap();
    unlock_with(&agent, &server, &paths).unwrap();
    assert!(!paths.data_keys.exists());
    assert!(holds_k(&agent, ASTATION_ID));
}

#[test]
fn a_repeated_migration_keeps_the_newer_k_and_adds_no_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::Enabling, B, [2; 32]);
    for _ in 0..2 {
        // A crash after the re-seal, before the delete, leaves it behind again.
        legacy(&device.paths, ACCOUNT);
        relock(&device);
        assert!(!device.paths.data_keys.exists());
    }
    let (current, mut previous) = device.agent.lock().unwrap().kids_for_test(ACCOUNT);
    previous.sort();
    assert_eq!(current.as_deref(), Some(B));
    assert_eq!(previous, vec![A.to_string(), OLD.to_string()]);
}

#[test]
fn only_verified_accounts_move() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
    legacy(&paths, "someone-else");
    let agent = test_agent(&paths);
    unlock_with(&agent, &server, &paths).unwrap();
    assert!(!paths.data_keys.exists());
    assert_eq!(agent.lock().unwrap().kids_for_test("someone-else"), (None, vec![]));
    assert_eq!(ProjectNames::load_from(&paths.project_names).unwrap().len("someone-else"), 0);
}

#[test]
fn an_unreadable_data_keys_enc_is_deleted_at_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
    std::fs::write(&paths.data_keys, b"from another machine").unwrap();
    let agent = test_agent(&paths);
    unlock_with(&agent, &server, &paths).unwrap();
    assert!(!paths.data_keys.exists());
}

#[test]
fn an_unverified_device_deletes_data_keys_enc_and_a_locked_one_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let paths = KeyPaths::in_dir(dir.path());
    legacy(&paths, ACCOUNT);
    let _agent = test_agent(&paths);
    assert!(!paths.data_keys.exists(), "never used by an unverified device");

    let dir = tempfile::tempdir().unwrap();
    let (paths, _, _) = sealed_device(dir.path(), "0a1b2c3d");
    legacy(&paths, ACCOUNT);
    let _agent = test_agent(&paths);
    assert!(paths.data_keys.exists(), "verified but locked: moved at the unlock");
}

#[test]
fn before_its_first_escrow_a_device_keeps_data_keys_enc() {
    let dir = tempfile::tempdir().unwrap();
    let paths = KeyPaths::in_dir(dir.path());
    let keys = DeviceKeys::generate();
    keys.save_to(&paths.device_keys).unwrap();
    let astation = FakeAstation::new();
    pin(&paths, &astation, &keys, false);
    set_state(&paths, &astation, EncryptionMode::Enabling, Some(A), 2);
    legacy(&paths, ACCOUNT);
    // The agent seals the plain file and starts unlocked, not escrowed.
    let agent = test_agent(&paths);
    assert!(holds_k(&agent, ASTATION_ID));
    assert!(paths.data_keys.exists(), "Astation doesn't hold this storage key yet");
    // Restarted before the escrow: the new sealed file gets K again from it.
    drop(agent);
    let agent = test_agent(&paths);
    assert!(holds_k(&agent, ASTATION_ID));
    // The first escrow is confirmed: now it goes.
    let mut server = FakeKeyServer {
        astation,
        device_sign_pub: keys.device_sign_pub(),
        unlock_auth_pub: keys.unlock_auth_pub(),
        storage_keys: Default::default(),
        pending: None,
        pending_statement: None,
        acked: Default::default(),
    };
    let ack = server.accept_rotation(&agent.begin_rotation(ASTATION_ID).unwrap()).unwrap();
    agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    assert!(!paths.data_keys.exists());
    assert!(holds_k(&agent, ASTATION_ID));
}
```

(Add these `use` lines next to the existing ones at the top of the file.)

Run: `cargo test memory::k_agent_tests`
Expected: FAIL to compile (`merge`, `kids_for_test` not found).

- [ ] **Step 2: Implement `merge` in `account_keys.rs`**

Add to `impl AccountKeys`:

```rust
    /// Adds keys found in data_keys.enc: `current` becomes the account's
    /// current key only if it has none; every key not held yet is added to
    /// the previous keys. A repeat changes nothing. Returns whether anything
    /// changed.
    pub fn merge(&mut self, account: &str, current: AccountKey, previous: Vec<AccountKey>) -> bool {
        let mut keys = std::iter::once(current).chain(previous);
        let ring = match self.rings.get_mut(account) {
            Some(ring) => ring,
            None => {
                let current = keys.next().expect("once yields one");
                self.rings.insert(
                    account.into(),
                    KeyRing {
                        current,
                        previous: Vec::new(),
                    },
                );
                let ring = self.rings.get_mut(account).expect("just inserted");
                for key in keys {
                    if key.kid != ring.current.kid && !ring.previous.iter().any(|held| held.kid == key.kid) {
                        ring.previous.push(key);
                    }
                }
                return true;
            }
        };
        let mut changed = false;
        for key in keys {
            if key.kid != ring.current.kid && !ring.previous.iter().any(|held| held.kid == key.kid) {
                ring.previous.push(key);
                changed = true;
            }
        }
        changed
    }
```

- [ ] **Step 3: Implement `keys_for` / `names_for` in `legacy_keys.rs`**

Add imports `use std::collections::BTreeSet;` and `use crate::memory::account_keys::AccountKey;`, and:

```rust
impl LegacyKeys {
    /// Each account in `accounts` (the verified ones) with its current key
    /// and the keys it replaced. Malformed entries are skipped: they could
    /// never open anything.
    pub fn keys_for(&self, accounts: &BTreeSet<String>) -> Vec<(String, AccountKey, Vec<AccountKey>)> {
        let parse = |stored: &StoredKey| -> Option<AccountKey> {
            if !crate::memory::crypto::valid_kid(&stored.kid) {
                return None;
            }
            Some(AccountKey {
                kid: stored.kid.clone(),
                key: crate::memory::device_keys::decode32(&stored.key, "account key").ok()?,
            })
        };
        self.accounts
            .iter()
            .filter(|(account, _)| accounts.contains(*account))
            .filter_map(|(account, stored)| {
                let current = parse(stored)?;
                let previous = self
                    .previous_keys
                    .get(account)
                    .into_iter()
                    .flatten()
                    .filter_map(parse)
                    .collect();
                Some((account.clone(), current, previous))
            })
            .collect()
    }

    /// The project names of each account in `accounts`.
    pub fn names_for(&self, accounts: &BTreeSet<String>) -> Vec<(String, Vec<(String, String)>)> {
        self.project_names
            .iter()
            .filter(|(account, _)| accounts.contains(*account))
            .map(|(account, names)| {
                (
                    account.clone(),
                    names.iter().map(|(hash, name)| (hash.clone(), name.clone())).collect(),
                )
            })
            .collect()
    }
}
```

(The existing `impl LegacyKeys { fn save_to … }` block may simply receive these two methods.)

- [ ] **Step 4: Implement the migration in `key_agent.rs`**

1. Imports: add `use std::collections::BTreeSet;` (next to `BTreeMap`) and `use crate::memory::legacy_keys::{self, Legacy};`.

2. `KeyAgent::new`: add `&paths.data_keys,` and `&paths.project_names,` to the sweep list, and replace

```rust
        if let Err(error) = agent.migrate_plain_keys() {
            eprintln!("key agent: {error:#}");
            agent.wipe();
        }
        Ok(agent)
```

with

```rust
        if let Err(error) = agent.migrate_plain_keys() {
            eprintln!("key agent: {error:#}");
            agent.wipe();
        }
        if agent.unlocked.is_some() {
            agent.after_unlock();
        } else if let Err(error) = agent.drop_unverified_data_keys() {
            eprintln!("key agent: {error:#}");
        }
        Ok(agent)
```

3. Replace `after_unlock` with:

```rust
    /// Once unlocked: moves a leftover data_keys.enc in, and drops account
    /// keys a signed state retired while the agent was locked. Never fatal:
    /// logged, and repeated at the next unlock.
    fn after_unlock(&mut self) {
        if let Err(error) = self.migrate_data_keys() {
            eprintln!("key agent: data_keys.enc not moved yet (tried again at the next unlock): {error:#}");
        }
        if let Err(error) = self.reconcile() {
            eprintln!("key agent: {error:#}");
        }
    }

    /// Moves data_keys.enc (build steps 0–2a) into this agent: `K` and its
    /// previous keys of every verified account into the sealed file, the
    /// project names into project_names.json. Crash-safe order: the names
    /// first (no secrets, merged), then the re-sealed file, and data_keys.enc
    /// is deleted last, only once Astation is known to hold the storage key
    /// of the file the keys now live in (never the only copy of a key in a
    /// file nobody can open). A crash anywhere leaves data_keys.enc, and the
    /// next unlock repeats the merge, which is idempotent.
    fn migrate_data_keys(&mut self) -> Result<()> {
        let legacy = match legacy_keys::read(&self.paths.data_keys)? {
            Legacy::Missing => return Ok(()),
            Legacy::Unreadable(error) => {
                // It can never be read on this machine; K comes back by a signed grant.
                eprintln!(
                    "key agent: deleting data_keys.enc, which can't be read ({error:#}); atem asks Astation for the encryption key again"
                );
                return remove_synced(&self.paths.data_keys);
            }
            Legacy::Keys(legacy) => legacy,
        };
        let unlocked = self.unlocked()?;
        let (escrowed, via_prev) = (unlocked.escrowed, unlocked.via_prev);
        let mut accounts = unlocked.accounts.clone();
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let verified: BTreeSet<String> = trust
            .verified_entries()
            .map(|entry| entry.data_account.clone())
            .collect();
        for (account, names) in legacy.names_for(&verified) {
            crate::memory::project_names::remember(&self.paths.project_names, &account, names)?;
        }
        let mut changed = false;
        for (account, current, previous) in legacy.keys_for(&verified) {
            changed |= accounts.merge(&account, current, previous);
        }
        if changed {
            self.persist(&accounts)?;
            self.unlocked.as_mut().expect("unlocked above").accounts = accounts;
        }
        if escrowed && !via_prev {
            remove_synced(&self.paths.data_keys)?;
            eprintln!("key agent: moved data_keys.enc into device_keys.sealed and project_names.json");
        }
        Ok(())
    }

    /// An unverified device never used data_keys.enc (step 1 ignores it): it
    /// holds only what the unauthenticated #36 path stored. Deleted.
    fn drop_unverified_data_keys(&self) -> Result<()> {
        if self.paths.data_keys.symlink_metadata().is_err() {
            return Ok(());
        }
        if TrustStore::load_from(&self.paths.trust)?
            .verified_entries()
            .next()
            .is_none()
        {
            remove_synced(&self.paths.data_keys)?;
            eprintln!("key agent: deleted data_keys.enc: this device isn't verified, so it was never used");
        }
        Ok(())
    }

    /// Test view: the current kid and previous kids held for `account`.
    #[cfg(test)]
    pub(crate) fn kids_for_test(&self, account: &str) -> (Option<String>, Vec<String>) {
        match &self.unlocked {
            Some(unlocked) => (
                unlocked.accounts.current_kid(account).map(str::to_string),
                unlocked.accounts.previous_kids(account),
            ),
            None => (None, Vec::new()),
        }
    }
```

4. `confirm_rotation`: replace its tail

```rust
        let pending = self.pending_rotation.take().expect("checked above");
        let unlocked = self.unlocked.as_mut().expect("checked above");
        unlocked.storage_kid = pending.storage_kid.clone();
        unlocked.storage_key = pending.storage_key;
        unlocked.escrowed = true;
        Ok(Reply::Confirmed {
            storage_kid: pending.storage_kid,
            confirm,
        })
```

with

```rust
        let pending = self.pending_rotation.take().expect("checked above");
        let first_escrow = pending.initial;
        let unlocked = self.unlocked.as_mut().expect("checked above");
        unlocked.storage_kid = pending.storage_kid.clone();
        unlocked.storage_key = pending.storage_key;
        unlocked.escrowed = true;
        // Astation now holds the key of the file data_keys.enc was moved into.
        if first_escrow {
            self.after_unlock();
        }
        Ok(Reply::Confirmed {
            storage_kid: pending.storage_kid,
            confirm,
        })
```

5. Add next to `remove_plain_keys`:

```rust
/// Deletes `path` (absent is fine) and syncs its directory, so the deletion
/// survives a crash.
fn remove_synced(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    std::fs::File::open(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test memory::k_agent_tests`
Expected: PASS (16 tests).

Run: `cargo test memory::account_keys`
Expected: PASS.

Run: `cargo test memory::key_agent`
Expected: PASS (an agent with no `data_keys.enc` is unchanged).

Run: `cargo test memory::verification`
Expected: PASS. (`first_verification_purges_legacy_keys` still passes: the unverified agent that `first_verification` starts may delete the legacy file before the purge; either way nothing of it survives.)

- [ ] **Step 6: Format and commit**

```bash
rustfmt --edition 2024 src/memory/account_keys.rs src/memory/legacy_keys.rs src/memory/key_agent.rs src/memory/k_agent_tests.rs
git add src/memory/account_keys.rs src/memory/legacy_keys.rs src/memory/key_agent.rs src/memory/k_agent_tests.rs
git commit -m "feat(memory): the key agent moves data_keys.enc into the sealed file and deletes it

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 9: Design doc and AGENTS.md

**Files:**
- Modify: `designs/e2e-encryption.md`, `AGENTS.md`

**Interfaces:**
- Consumes: the behaviour of Tasks 1–8.
- Produces: documentation only.

- [ ] **Step 1: `designs/e2e-encryption.md`**

1. Status paragraph: replace the sentence starting `Moving `K` behind the agent (2b), device-signed writes (3),` with:

```markdown
Build step 2b is built on the atem side (2026-10-11): `K` and its previous
keys live in the sealed payload of `device_keys.sealed`, only the key agent
uses them (batched `Crypt` requests), the mode and kid come from the signed
account state alone, project names live in `project_names.json`, and
`data_keys.enc` is moved in at the first unlock and deleted. 2b needs nothing
new from Astation. Device-signed writes (3), the recovery
```

(keep the rest of that sentence: `secret (4), credentials (5–6, 8) and auto-unlock (7): design approved …`).

2. In "How build step 2a builds it", change `request carries `"v": 1`` to `request carries `"v": 2` (v1 until step 2b)`.

3. Replace the bullet starting `- Until build step 2b, the agent opens `K` grants and hands `K` back to the` (through `ignored and requested again after `atem cred unlock`.`) with:

```markdown
**How build step 2b builds it.**

- **`K` in the sealed payload.** The encrypted payload of
  `device_keys.sealed` gains `account_keys`: per account, the current `kid`
  and key and the keys it replaced (`previous`). The field is omitted when
  empty, so a step-2a file reads as "no keys". Every re-seal (rotation phase
  1, a `.next` promotion) carries it.
- **Installing `K`.** `InstallGrant` (protocol v2) opens a signed grant with
  the unchanged checks, requires its kid to be the kid of the latest signed
  account state, and re-seals the file the agent holds the storage key for
  (and a pending rotation's `.next`) under the same storage key: temp file,
  fsync, rename. `K` is used only once it is on disk. The old and the new
  file open with the same storage key, so no crash leaves a key only in a
  file nothing can open; at worst a newly installed `K` is missing, and atem
  asks for it again (`keyRequest`), since a `K` always arrives as a signed
  grant. Verification checks grants first (`CheckGrant` for sealed keys)
  and installs them after the pins are saved; a failed install is a warning.
- **The agent never hands out `K`.** No reply carries it. Callers send
  `Crypt { astation_id, ops }` with `seal` / `open` / `keyed_hash` ops and
  get the results in order, in exactly the `e1.`/`h1.` formats and associated
  data of steps 0–2a. Plain text on the socket is parsed straight into
  wiped buffers. `EncryptionContext` batches a call site (a pull page, a push
  chunk, a migration chunk) into as few requests as a 2 MiB budget allows,
  always from a blocking thread.
- **Mode and kid** come only from the latest signed account state in
  `cred_state.json`. Unverified devices are `off`; an `off` (or unverified)
  context never contacts the agent. A locked agent, or one without `K`,
  makes sync keep its changes queued and say `atem cred unlock` or that the
  account requires encryption.
- **Retired keys.** An `off` state drops the account's keys; `on` with the
  current kid drops the previous keys. The agent applies this at its next
  request for that account, when a running agent is told of a new `off`
  state, and at every unlock.
- **Project names** (`h1.` hash → project key) live in `project_names.json`
  (0600, no secrets); the hash itself is computed by the agent.
- **Migration from `data_keys.enc`.** At every unlock (and at the start of an
  agent that starts unlocked from a plain `device_keys`, and at the first
  confirmed escrow) the agent merges `data_keys.enc` (verified accounts only)
  into the sealed payload and `project_names.json`, then deletes it once the
  home Astation is known to hold the storage key of that sealed file. A
  crash at any point leaves `data_keys.enc`, and the next unlock repeats the
  merge. An unreadable `data_keys.enc` is deleted; an unverified device's is
  deleted when the agent starts.
- **Cost.** Before the first escrow a restarted agent re-seals the plain
  `device_keys` under a new storage key and can't open the earlier sealed
  file, so a `K` installed after step 2b is asked for again (rotation history
  from before 2b comes back from `data_keys.enc` while it exists).
```

4. "What each side stores", atem list: replace the `data_keys.enc` bullet with:

```markdown
- `project_names.json`: the readable project key of each `h1.` project
  hash, per account. No secrets.
- `data_keys.enc`: gone in step 2b. Steps 0–2a kept `K`, its previous keys
  and the project names there under the machine-bound key; the key agent
  moves it into `device_keys.sealed` and `project_names.json` at the first
  unlock and deletes it.
```

and in the `device_keys.sealed` bullet, change `the device key and device signing key, encrypted` to `the device key, the device signing key and the account keys (`K` and its previous keys, step 2b), encrypted`. Change the "Key agent memory" bullet to `- Key agent memory: the unsealed device keys, `K` and its previous keys, index subkeys and scope keys.`

5. "Migration": replace the `data_keys.enc` bullet with:

```markdown
- **`data_keys.enc`** (built, step 2b): the key agent moves `K`, its previous
  keys and the project names into `device_keys.sealed` and
  `project_names.json` at the first unlock, then deletes the file.
```

6. "Where the work lands", step 2: change `2b moves `K` and `data_keys.enc` behind the agent.` to `2b (built on atem) moves `K` and `data_keys.enc` behind the agent.`

- [ ] **Step 2: `AGENTS.md`**

1. Source tree under `memory/`: after `│   ├── grant.rs ...` add

```text
│   ├── account_keys.rs  #   K per account (current + previous) in the agent; e1./h1. field ops (Crypt)
│   ├── project_names.rs #   project_names.json: h1. project hash → project key
│   ├── legacy_keys.rs   #   read-only data_keys.enc (steps 0–2a), moved in by the agent
│   ├── crypto.rs        #   EncryptionContext: mode from the signed state, batched Crypt via the agent; private writes
```

change the `agent_socket.rs` line's `(v1 JSON lines, same UID only)` to `(v2 JSON lines, same UID only)`, change the `key_agent.rs` line to `key agent state: unlock, rotation, abandon, K installed and used in memory (Crypt)`, and after the `kat_tests.rs` line add `│   ├── k_agent_tests.rs #   (test-only) K in the agent: install, Crypt, rotation, data_keys.enc migration`.

2. Key agent paragraph: change `` `"v": 1` JSON lines`` to `` `"v": 2` JSON lines``, and replace the sentence `Until step 2b the agent hands `K` back to the caller.` with:

```markdown
Since step 2b `K` lives only in the agent: it installs granted keys into the sealed payload (`InstallGrant`), does every seal/open/keyed hash for `EncryptionContext` in batched `Crypt` requests, takes the mode and kid from the signed account state, and moves a leftover `data_keys.enc` in at the first unlock (then deletes it); a locked agent keeps sync changes queued until `atem cred unlock`.
```

3. Files table: change the `device_keys.sealed` row's contents to begin `This device's X25519 device key, Ed25519 signing key and account keys (`K` + previous, step 2b) (`{version, device_id, storage_kid, nonce, ciphertext}`); …` (rest unchanged), and add after the `cred_state.json` row:

```markdown
| `project_names.json` | `h1.` project hash → readable project key, per account (memory/skills project names the relay sees only as HMACs); replaces the names part of the removed `data_keys.enc` | None (chmod 0600; no secrets) |
```

(There is no `data_keys.enc` row today; the key agent deletes that file at the first unlock.)

- [ ] **Step 3: Check and commit**

Run: `grep -n "data_keys" AGENTS.md designs/e2e-encryption.md`
Expected: every hit describes it as removed/migrated (step 2b), none as current storage.

```bash
git add designs/e2e-encryption.md AGENTS.md
git commit -m "docs: e2e step 2b — K behind the key agent, project_names.json, data_keys.enc migrated

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 10: Full verification

**Files:** none (verification only; fix forward in the task whose code is wrong).

- [ ] **Step 1: Full test suite**

Run: `cargo test -- --test-threads=1`
Expected: all tests pass (including `memory::kat_tests` unchanged and `tests/key_agent_binary.rs`).

- [ ] **Step 2: Lint**

Run: `cargo clippy --all-targets --all-features 2>&1 | grep -E "src/memory/(account_keys|project_names|legacy_keys|k_agent_tests|key_agent|agent_socket|crypto|api|verification|device_keys|storage_key|fake_astation|e2e_tests)\.rs|src/vault_client\.rs"`
Expected: no output (no warnings in the files this plan touched).

- [ ] **Step 3: macOS build check of cfg gates**

Run: `grep -n "libc::\|prctl\|SO_PEERCRED" src/memory/account_keys.rs src/memory/project_names.rs src/memory/legacy_keys.rs src/memory/k_agent_tests.rs`
Expected: no hits (the new files are platform-neutral; `remove_synced` syncs the directory under `#[cfg(unix)]`).

- [ ] **Step 4: CLI smoke test**

Run: `cargo build && ./scripts/run-local-dev-tests.sh`
Expected: only the 3 known `atem list` failures.

- [ ] **Step 5: Wire-format spot check**

Run: `cargo test fields_keep_the_format_of_steps_0_to_2a`
Expected: PASS — the relay ciphertext format is identical to steps 0–2a.

---

## Self-Review

**1. Spec coverage**

| Scope item | Task |
|---|---|
| 1. `account_keys` in the sealed payload; rotation re-seals it; install = atomic re-seal under the current storage key; crash reasoning documented | 2 (payload), 4 (`persist`, `install_grant`, rotation carries keys, `k_survives_a_storage_key_rotation`, `k_installed_mid_rotation_also_reaches_the_next_file`, `a_failed_re_seal_installs_nothing`), 9 (doc) |
| 2. Mode/kid from the signed state; `StoredMode` and the mismatch check removed; unverified = Off | 3 (`account_mode`), 5 (no mode written), 7 (`StoredKeys` gone, `off_and_unverified_contexts_never_touch_the_agent`) |
| 3. `project_names.json`, HMAC by the agent | 3, 7 (`wire_projects` via `KeyedHash`, `project_names_are_remembered_locally_and_resolved`) |
| 4. `data_keys.enc` migration at first unlock / agent start, delete, unverified delete, crash-safe ordering + tests | 8 (all migration tests) |
| 5. Batched `Crypt`, `Zeroizing` wire, no `K` returned | 4 (`Crypt`, `InstallGrant`), 5 (`OpenGrant`/`Reply::Grant` removed), 6 (wire parsing) |
| 6. Thin `EncryptionContext`, same public methods, batching per call site, `blocking` (R7) | 7 |
| 7. Locked agent = missing-key path; queued ops stay queued; off never touches the agent | 7 (`missing_encryption_key_keeps_sync_operations_queued`, `a_locked_agent_asks_for_an_unlock`, NoAgent test) |
| 8. Out of scope respected | No subkeys, no format change (vector test), no auto-unlock, no cred get/list |
| 9. Tests: in-process agent + FakeKeyServer; e2e relay tests; copied config dir; batching count; migration crash windows; KATs unchanged | 4, 7, 8, 10 |
| Docs: design doc status/what each side stores/files; AGENTS.md | 9 |

**2. Placeholder scan:** every code step carries complete code; edits name the exact item and give the full replacement. No TBD/TODO.

**3. Type consistency:** `install_grant`/`check_grant`/`crypt`/`held_kid` (Task 4) are the names used in Tasks 5–8; `AccountKeys::{install, reconcile, merge, crypt, current_kid, previous_kids, to_wire, from_wire, is_empty}`; `SignedModes`; `CryptOp::{seal, open, keyed_hash}` + `wire_len`; `CryptOut::{into_text, into_plain}`; `account_mode`/`AccountMode` (Task 3) used in Tasks 5 and 7; `project_names::{remember, forget_account_at, ProjectNames::{load_from, name, len}}`; `legacy_keys::{read, Legacy, purge_unverified_at, write_for_test, summary_at, LegacyKeys::{keys_for, names_for}}`; `UnlockedDevice::{new, state, grant, set_key}` and fields `paths`, `server`, `keys`, `agent`; `KeyPaths.project_names`.

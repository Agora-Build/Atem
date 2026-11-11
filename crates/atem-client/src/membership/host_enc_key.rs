//! The host encryption key (delegated host-work design II.4.1, option (b)):
//! the `host_enc_key` entry of the device list, the host's `enc_sig` inside
//! it, what follows from it on a verifier, and its typed builder.
//!
//! A host's only key in the device list is its `host_key` (Ed25519, from
//! `add_host`), which signs. Mail from host senders is sealed to an X25519
//! `enc_key` that a native manager installs with a `host_enc_key` entry:
//!
//! - **The binding.** The host vouches for its key with `enc_sig`, pure
//!   Ed25519 by its `host_key` over [`host_enc_sig_input`]:
//!   `enc(["atem-host-enc-key-v1", account_id, genesis_hash, host_id,
//!   u64(host_trust_gen), enc_pub])`, with `genesis_hash` as its 32 raw bytes
//!   (§R9.1: hashes inside `enc` are raw). The manager gets `{enc_pub,
//!   enc_sig}` from the host over its channel. The binding proves the host
//!   vouched for this key in this generation; it doesn't prove the key is
//!   the host's newest. Every entry body is public, so anyone holding the
//!   log holds a valid pair for each key the host had: the reuse rule
//!   below keeps those from coming back, and a carrier can offer only a
//!   key the host vouched for in this generation and that was never set.
//! - **Valid** when the host is current, `host_trust_gen` is its newest
//!   `add_host`'s (else `host_trust_gen_not_current`), `enc_sig` verifies
//!   with that `add_host`'s `host_key` (else `bad_enc_sig`), and `enc_key`
//!   (its 32 bytes as written) is no key a `host_enc_key` set for the host
//!   since that `add_host`: not the current key, the previous one, a
//!   retired one or one no longer kept (else `enc_key_reused`). A retired
//!   key stays retired. A key of an earlier generation can't come back
//!   with its old `enc_sig` either: the binding names that generation
//!   (`host_trust_gen_not_current`); only the host, vouching again with the
//!   new `host_key`, makes it a key of the new generation. The entry
//!   itself is signed by a native manager like every entry.
//! - **Rotation.** A newer entry for the same generation replaces the key
//!   and keeps the one it replaced as the previous key (one only); with
//!   `retire_previous` (after a suspected compromise) the previous key is
//!   retired at once. How long a routine previous key still opens mail
//!   (24 h) is counted on the receiving host's own clock from when it
//!   applied the entry, by the host (step 4), never here.
//! - **Voided** by a newer `add_host` of the host (`atem pair verify`, or a
//!   re-add) and by its `remove_host`: no key until a new entry for the new
//!   generation, and no previous key carries over.
//!
//! The key's id is R9.9's `enc_kid` ([`crate::keys::enc_kid`]). Atem never
//! signs these entries. Astation signs them only once every strict verifier
//! of the account knows them (the signing gate, II.2.2).
use std::collections::{BTreeMap, BTreeSet};

use crate::domain::{SignLabel, SigningInput};
use crate::encoding::{Hash32, u64_field};
use crate::error::{Error, Result};
use crate::keys::{Alg, PublicKey, enc_kid_bytes};
use crate::provider::{KeyId, KeyProvider};

use super::draft::verified;
use super::entry::{Action, HostRecord};
use super::{Invalid, Membership};

/// A host encryption key as an entry set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKey {
    /// R9.9's `enc_kid` of `key` (its hex is the 16-character `enc_kid`).
    pub kid: [u8; 8],
    /// X25519.
    pub key: PublicKey,
    /// The `seq` of the `host_enc_key` entry that set it.
    pub seq: u64,
    /// The host's trust generation it is bound to (its `add_host` then).
    pub host_trust_gen: u64,
}

impl EncKey {
    /// `key` is X25519 (the entry's parse pins it).
    fn new(key: &PublicKey, seq: u64, host_trust_gen: u64) -> Self {
        EncKey {
            kid: enc_kid_bytes(key).expect("an enc_key is X25519"),
            key: key.clone(),
            seq,
            host_trust_gen,
        }
    }
}

/// The key a rotation replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousEncKey {
    pub key: EncKey,
    /// Retired at once (`retire_previous`): it opens nothing. Otherwise the
    /// host keeps it for 24 h on its own clock from when it applied the
    /// entry at `replaced_at_seq`.
    pub retired: bool,
    /// The `seq` of the entry that replaced it.
    pub replaced_at_seq: u64,
}

/// A host's encryption keys for its current trust generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEncKeys {
    pub current: EncKey,
    pub previous: Option<PreviousEncKey>,
}

/// Every current host's keys (part of the derived state: a pure function of
/// the entries, replayed like the rest).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct EncKeys {
    by_host: BTreeMap<String, HostEncKeys>,
    /// The 32 bytes (as written) of every key a `host_enc_key` set for the
    /// host since its newest `add_host`: current, previous, retired or no
    /// longer kept. None is set again (`enc_key_reused`). A set, so replay
    /// in entry order always derives the same one.
    set_since_add: BTreeMap<String, BTreeSet<Vec<u8>>>,
}

impl EncKeys {
    /// A `host_enc_key` at `seq` (the chain checked the generation is the
    /// host's newest, so a key it replaces has the same one).
    pub(super) fn set(
        &mut self,
        host_id: &str,
        key: &PublicKey,
        host_trust_gen: u64,
        retire_previous: bool,
        seq: u64,
    ) {
        let previous = self.by_host.remove(host_id).map(|old| PreviousEncKey {
            key: old.current,
            retired: retire_previous,
            replaced_at_seq: seq,
        });
        self.by_host.insert(
            host_id.to_owned(),
            HostEncKeys {
                current: EncKey::new(key, seq, host_trust_gen),
                previous,
            },
        );
        self.set_since_add
            .entry(host_id.to_owned())
            .or_default()
            .insert(key.as_bytes().to_vec());
    }

    /// A newer `add_host` of the host, or its `remove_host`: both keys go,
    /// and the next generation starts with no key set.
    pub(super) fn void(&mut self, host_id: &str) {
        self.by_host.remove(host_id);
        self.set_since_add.remove(host_id);
    }

    pub(super) fn get(&self, host_id: &str) -> Option<&HostEncKeys> {
        self.by_host.get(host_id)
    }

    /// Whether a `host_enc_key` set `key` for `host_id` since its newest
    /// `add_host` (compared as the 32 bytes written).
    pub(super) fn was_set(&self, host_id: &str, key: &PublicKey) -> bool {
        self.set_since_add
            .get(host_id)
            .is_some_and(|set| set.contains(key.as_bytes()))
    }
}

/// The chain rule (II.4.1) for a `host_enc_key` of a current host whose
/// newest `add_host` is `host`, with the hosts' keys at `seq-1` in `keys`
/// (the caller refuses one that isn't current, `not_a_host`).
pub(super) fn check(
    host: &HostRecord,
    keys: &EncKeys,
    account_id: &str,
    genesis_hash: &Hash32,
    host_trust_gen: u64,
    enc_key: &PublicKey,
    enc_sig: &[u8],
) -> std::result::Result<(), Invalid> {
    if host_trust_gen != host.host_trust_gen {
        return Err(Invalid::HostTrustGenNotCurrent);
    }
    // The parse pins it; checked again so an `Entry` whose public `action`
    // was changed after parsing can't install another kind of key.
    if enc_key.alg() != Alg::X25519 {
        return Err(Invalid::WrongAlg);
    }
    let enc_pub = enc_key.as_32().ok_or(Invalid::WrongAlg)?;
    verify_host_enc_sig(
        &host.host_key,
        account_id,
        genesis_hash,
        &host.host_id,
        host_trust_gen,
        enc_pub,
        enc_sig,
    )
    .map_err(|_| Invalid::BadEncSig)?;
    // Only after the binding: a key the host vouched for, set before in
    // this generation (the current, previous, a retired or a dropped key).
    // Across generations a replay is already refused above: the binding
    // names `host_trust_gen`.
    if keys.was_set(&host.host_id, enc_key) {
        return Err(Invalid::EncKeyReused);
    }
    Ok(())
}

impl Membership {
    /// `host_id`'s encryption keys: `None` for a host that isn't current,
    /// or none of whose `host_enc_key` entries is for its newest `add_host`.
    pub fn host_enc_key(&self, host_id: &str) -> Option<&HostEncKeys> {
        self.derived.host_enc_keys.get(host_id)
    }
}

/// What a host signs to vouch for its encryption key:
/// `enc(["atem-host-enc-key-v1", account_id, genesis_hash, host_id,
/// u64(host_trust_gen), enc_pub])`, `genesis_hash` as its 32 raw bytes.
pub fn host_enc_sig_input(
    account_id: &str,
    genesis_hash: &Hash32,
    host_id: &str,
    host_trust_gen: u64,
    enc_pub: &[u8; 32],
) -> SigningInput {
    SigningInput::fields(
        SignLabel::HostEncKey,
        &[
            account_id.as_bytes(),
            genesis_hash.as_bytes(),
            host_id.as_bytes(),
            &u64_field(host_trust_gen),
            enc_pub,
        ],
    )
}

/// The host's `enc_sig` over its `enc_pub`, by its `host_key` (Ed25519 only:
/// any other key is `WrongAlg`). Checked against the key's public half.
pub fn sign_host_enc_key(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    account_id: &str,
    genesis_hash: &Hash32,
    host_id: &str,
    host_trust_gen: u64,
    enc_pub: &[u8; 32],
) -> Result<Vec<u8>> {
    if provider.public_key(host_key)?.alg() != Alg::Ed25519 {
        return Err(Error::WrongAlg);
    }
    let input = host_enc_sig_input(account_id, genesis_hash, host_id, host_trust_gen, enc_pub);
    crate::provider::sign(provider, host_key, &input)
}

/// Checks a host's `enc_sig` with its `host_key` (from its newest
/// `add_host`; Ed25519 only, `verify_strict`).
pub fn verify_host_enc_sig(
    host_key: &PublicKey,
    account_id: &str,
    genesis_hash: &Hash32,
    host_id: &str,
    host_trust_gen: u64,
    enc_pub: &[u8; 32],
    sig: &[u8],
) -> Result<()> {
    if host_key.alg() != Alg::Ed25519 {
        return Err(Error::WrongAlg);
    }
    let input = host_enc_sig_input(account_id, genesis_hash, host_id, host_trust_gen, enc_pub);
    host_key.verify(&input, sig)
}

/// A `host_enc_key` entry's action, as the verifier parses it: `enc_key`
/// X25519, `enc_sig` 64 bytes. That the host is current, the generation its
/// newest and `enc_sig` valid is checked against the chain. `signed_at` is
/// the time the manager signs it (display only).
pub fn host_enc_key(
    host_id: &str,
    host_trust_gen: u64,
    enc_key: &PublicKey,
    enc_sig: &[u8],
    retire_previous: bool,
    signed_at: u64,
) -> std::result::Result<Action, Invalid> {
    verified(
        Action::HostEncKey {
            host_id: host_id.to_owned(),
            host_trust_gen,
            enc_key: enc_key.clone(),
            enc_sig: enc_sig.to_vec(),
            retire_previous,
        },
        signed_at,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x(byte: u8) -> PublicKey {
        PublicKey::new(Alg::X25519, &[byte; 32]).unwrap()
    }

    fn current(keys: &EncKeys, host_id: &str) -> Option<(PublicKey, u64)> {
        keys.get(host_id)
            .map(|k| (k.current.key.clone(), k.current.seq))
    }

    #[test]
    fn set_rotate_retire_and_void() {
        let mut keys = EncKeys::default();
        assert_eq!(keys.get("a"), None);
        keys.set("a", &x(1), 1, false, 3);
        assert_eq!(current(&keys, "a"), Some((x(1), 3)));
        assert_eq!(keys.get("a").unwrap().previous, None);
        assert_eq!(
            keys.get("a").unwrap().current.kid,
            enc_kid_bytes(&x(1)).unwrap()
        );
        // A routine rotation keeps the one it replaced.
        keys.set("a", &x(2), 1, false, 5);
        let previous = keys.get("a").unwrap().previous.clone().unwrap();
        assert_eq!(previous.key, EncKey::new(&x(1), 3, 1));
        assert!(!previous.retired);
        assert_eq!(previous.replaced_at_seq, 5);
        // A retiring one retires it; only one previous key is kept, but
        // every key set since the add_host is remembered.
        keys.set("a", &x(3), 1, true, 6);
        let previous = keys.get("a").unwrap().previous.clone().unwrap();
        assert_eq!(previous.key, EncKey::new(&x(2), 5, 1));
        assert!(previous.retired);
        for key in [x(1), x(2), x(3)] {
            assert!(keys.was_set("a", &key));
        }
        assert!(!keys.was_set("a", &x(4)));
        // Another host is apart; voiding drops both keys of one host.
        keys.set("b", &x(4), 2, true, 7);
        assert_eq!(keys.get("b").unwrap().previous, None);
        keys.void("a");
        assert_eq!(keys.get("a"), None);
        assert_eq!(current(&keys, "b"), Some((x(4), 7)));
        keys.void("z");
        // A void forgets the keys set since the newest add_host too.
        assert!(!keys.was_set("a", &x(1)));
        assert!(keys.was_set("b", &x(4)));
        // After a void, a new key starts without a previous one.
        keys.set("a", &x(5), 2, false, 9);
        assert_eq!(keys.get("a").unwrap().previous, None);
    }

    #[test]
    fn the_chain_rule_checks_generation_then_signature() {
        // Any Ed25519 provider will do: a kit's signing key.
        let provider = crate::kit::RecoveryKit::make(&[4; 32], "acct", Hash32([0; 32]));
        let host = HostRecord {
            host_id: "host-a".into(),
            host_trust_gen: 2,
            host_key: provider.recovery_key(),
        };
        let genesis = Hash32([1; 32]);
        let enc = x(9);
        let sig = sign_host_enc_key(
            &provider,
            &crate::kit::RecoveryKit::sign_id(),
            "acct",
            &genesis,
            "host-a",
            2,
            &[9; 32],
        )
        .unwrap();
        let none = EncKeys::default();
        assert_eq!(check(&host, &none, "acct", &genesis, 2, &enc, &sig), Ok(()));
        assert_eq!(
            check(&host, &none, "acct", &genesis, 1, &enc, &sig),
            Err(Invalid::HostTrustGenNotCurrent)
        );
        assert_eq!(
            check(&host, &none, "acct", &genesis, 2, &x(8), &sig),
            Err(Invalid::BadEncSig)
        );
        assert_eq!(
            check(&host, &none, "other", &genesis, 2, &enc, &sig),
            Err(Invalid::BadEncSig)
        );
        // The same 32 bytes as an Ed25519 key: never an encryption key.
        let ed = crate::kit::recovery_key_of_seed(&[6; 32]);
        assert_eq!(
            check(&host, &none, "acct", &genesis, 2, &ed, &sig),
            Err(Invalid::WrongAlg)
        );
        // A key set before in this generation is refused once its binding
        // verifies: as the current key, as the previous one, and once a
        // later rotation dropped it.
        let mut keys = EncKeys::default();
        keys.set("host-a", &enc, 2, false, 3);
        assert_eq!(
            check(&host, &keys, "acct", &genesis, 2, &enc, &sig),
            Err(Invalid::EncKeyReused)
        );
        assert_eq!(
            check(&host, &keys, "acct", &genesis, 1, &enc, &sig),
            Err(Invalid::HostTrustGenNotCurrent)
        );
        keys.set("host-a", &x(8), 2, true, 4);
        assert_eq!(
            check(&host, &keys, "acct", &genesis, 2, &enc, &sig),
            Err(Invalid::EncKeyReused)
        );
        keys.set("host-a", &x(7), 2, false, 5);
        assert_eq!(
            check(&host, &keys, "acct", &genesis, 2, &enc, &sig),
            Err(Invalid::EncKeyReused)
        );
        // Another host's keys are apart; a void starts afresh.
        keys.set("host-b", &enc, 1, false, 6);
        keys.void("host-a");
        assert!(!keys.was_set("host-a", &enc));
        assert!(keys.was_set("host-b", &enc));
        assert_eq!(check(&host, &keys, "acct", &genesis, 2, &enc, &sig), Ok(()));
    }
}

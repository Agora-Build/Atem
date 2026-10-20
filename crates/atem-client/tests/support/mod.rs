//! Shared by the scenario runner and the local end-to-end tests: the r9
//! fixtures, their test keys in a software provider, entries by label, and
//! a fake relay (the log CAS and put-if-absent envelope store of §R9.4 and
//! §R9.5; the real relay is Astation's).
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use atem_client::canonical::{self, Numbers, StrictValue};
use atem_client::encoding::Hash32;
use atem_client::kit::RecoveryKit;
use atem_client::membership::publish::AppendReply;
use atem_client::membership::{Entry, Head, HostNow};
use atem_client::{KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use serde_json::Value;

pub mod host;

pub const ACCOUNT: &str = "acct-test-1";

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../designs/protocol/fixtures")
}

pub fn load(name: &str) -> Value {
    let bytes = std::fs::read(fixtures_dir().join(format!("{name}.json"))).unwrap();
    canonical::parse_strict(&bytes, usize::MAX, Numbers::IntegersOnly)
        .unwrap_or_else(|e| panic!("{name}: not strict JSON: {e:?}"))
}

pub fn unhex32(text: &str) -> [u8; 32] {
    Hash32::from_hex(text).unwrap().0
}

pub fn strict(value: &Value) -> StrictValue {
    StrictValue::parse(value.to_string().as_bytes(), usize::MAX).unwrap()
}

/// A host clock reading: one boot, wall and monotonic moving together
/// unless a test moves one alone.
#[derive(Debug, Clone)]
pub struct Clock {
    pub now: HostNow,
}

impl Clock {
    pub fn at(wall_ms: u64) -> Self {
        Clock {
            now: HostNow {
                wall_ms,
                mono_ms: 1_000,
                boot_id: "boot-1".into(),
            },
        }
    }

    pub fn advance(&mut self, ms: u64) {
        self.now.wall_ms += ms;
        self.now.mono_ms += ms;
    }

    pub fn set_wall(&mut self, wall_ms: u64) {
        self.now.wall_ms = wall_ms;
    }

    pub fn reboot(&mut self, boot_id: &str) {
        self.now.boot_id = boot_id.into();
        self.now.mono_ms = 500;
    }
}

/// The test keys of `r9-vectors-keys` in a software provider: a device's
/// `auth` and `enc` keys are `<device>/auth` and `<device>/enc`, a kit's
/// recovery key `<kit>/sign`.
pub struct Book {
    pub keys: Value,
    pub provider: SoftwareKeys,
}

impl Book {
    pub fn load() -> Self {
        let keys = load("r9-vectors-keys")["keys"].clone();
        let mut provider = SoftwareKeys::new();
        for (name, entry) in keys.as_object().unwrap() {
            for part in ["auth", "enc", "host_key"] {
                let Some(key) = entry.get(part) else { continue };
                let secret = unhex32(key["secret_hex"].as_str().unwrap());
                let id = KeyId::new(format!("{name}/{part}"));
                match key.get("alg").and_then(Value::as_str) {
                    Some("p256") => provider.insert_p256(id, &secret).unwrap(),
                    Some("ed25519") => provider.insert_ed25519(id, &secret),
                    _ => provider.insert_x25519(id, &secret),
                }
            }
            // A key named by its entry alone (the browser's WebCrypto key).
            if let (Some(alg), Some(secret)) = (
                entry.get("alg").and_then(Value::as_str),
                entry.get("secret_hex").and_then(Value::as_str),
            ) {
                let id = KeyId::new(format!("{name}/auth"));
                let secret = unhex32(secret);
                match alg {
                    "p256" => provider.insert_p256(id, &secret).unwrap(),
                    "ed25519" => provider.insert_ed25519(id, &secret),
                    _ => {}
                }
            }
            if let Some(seed) = entry.get("sign_seed_hex") {
                provider.insert_ed25519(
                    KeyId::new(format!("{name}/sign")),
                    &unhex32(seed.as_str().unwrap()),
                );
            }
        }
        Book { keys, provider }
    }

    pub fn auth(&self, device: &str) -> KeyId {
        KeyId::new(format!("{device}/auth"))
    }

    pub fn public(&self, id: &str) -> PublicKey {
        self.provider.public_key(&KeyId::new(id)).unwrap()
    }

    /// A kit from the book (`recovery`, `recovery-2`), read with its tag.
    pub fn kit(&self, name: &str) -> RecoveryKit {
        let entry = &self.keys[name];
        let tag: [u8; 16] = hex16(entry["kit_tag_hex"].as_str().unwrap());
        RecoveryKit::read(
            &unhex32(entry["R_hex"].as_str().unwrap()),
            ACCOUNT,
            genesis_hash(),
            &tag,
        )
        .unwrap()
    }

    /// An account key `K` by kid (`K-gen-3`, `K-evil`), if the book has it.
    pub fn k_by_kid(&self, kid: &str) -> Option<[u8; 32]> {
        self.keys.as_object().unwrap().values().find_map(|entry| {
            (entry.get("kid").and_then(Value::as_str) == Some(kid))
                .then(|| unhex32(entry["secret_hex"].as_str().unwrap()))
        })
    }
}

pub fn hex16(text: &str) -> [u8; 16] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

/// The membership-log vectors by label.
pub struct Vectors {
    pub file: Value,
    by_label: BTreeMap<String, Value>,
}

impl Vectors {
    pub fn load() -> Self {
        let file = load("r9-vectors-membership-log");
        let mut by_label = BTreeMap::new();
        for vector in file["log"]
            .as_array()
            .unwrap()
            .iter()
            .chain(file["others"].as_array().unwrap())
        {
            by_label.insert(vector["label"].as_str().unwrap().to_owned(), vector.clone());
        }
        Vectors { file, by_label }
    }

    pub fn vector(&self, label: &str) -> &Value {
        self.by_label
            .get(label)
            .unwrap_or_else(|| panic!("no vector {label}"))
    }

    /// The wire object of an entry.
    pub fn wire(&self, label: &str) -> &Value {
        &self.vector(label)["entry"]
    }

    pub fn object(&self, label: &str) -> SignedObject {
        SignedObject::from_strict(&strict(self.wire(label)))
            .unwrap_or_else(|e| panic!("{label}: {e}"))
    }

    pub fn entry(&self, label: &str) -> Entry {
        Entry::from_strict(&strict(self.wire(label))).unwrap_or_else(|e| panic!("{label}: {e}"))
    }

    pub fn entries(&self, labels: &[&str]) -> Vec<Entry> {
        labels.iter().map(|l| self.entry(l)).collect()
    }

    pub fn hash(&self, label: &str) -> Hash32 {
        Hash32::from_hex(self.vector(label)["entry_hash"].as_str().unwrap()).unwrap()
    }

    pub fn head(&self, label: &str) -> Head {
        Head {
            seq: self.wire(label)["body"]["seq"].as_u64().unwrap(),
            hash: self.hash(label),
        }
    }

    pub fn label_of(&self, hash: &Hash32) -> Option<&str> {
        self.by_label
            .iter()
            .find(|(_, v)| v["entry_hash"].as_str() == Some(hash.to_hex().as_str()))
            .map(|(label, _)| label.as_str())
    }
}

pub fn genesis_hash() -> Hash32 {
    Hash32::from_hex(
        load("r9-vectors-membership-log")["genesis_hash"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

/// A fake relay for one log: the append CAS (§R9.4) and the envelope store
/// (§R9.5). It verifies nothing (the real relay verifies as a convenience
/// only); `cas_broken` lets a test model a relay whose CAS failed.
#[derive(Default)]
pub struct FakeRelay {
    pub log: Vec<SignedObject>,
    pub blobs: BTreeMap<u64, String>,
    pub cas_broken: bool,
    /// Sibling entries a broken CAS accepted: (seq, entry).
    pub siblings: Vec<SignedObject>,
}

/// The relay's answer to an append.
#[derive(Debug, Clone)]
pub enum RelayAppend {
    Ok(SignedObject),
    Conflict {
        head: Head,
        entries: Vec<SignedObject>,
        more: bool,
    },
}

impl RelayAppend {
    pub fn status(&self) -> u16 {
        match self {
            RelayAppend::Ok(_) => 200,
            RelayAppend::Conflict { .. } => 409,
        }
    }

    pub fn reply(&self) -> AppendReply {
        match self {
            RelayAppend::Ok(_) => AppendReply::Stored,
            RelayAppend::Conflict {
                head,
                entries,
                more,
            } => AppendReply::Conflict {
                head: *head,
                entries: entries.clone(),
                more: *more,
            },
        }
    }
}

pub fn seq_of(object: &SignedObject) -> u64 {
    object.body()["seq"].as_u64().unwrap()
}

pub fn head_of(object: &SignedObject) -> Head {
    Head {
        seq: seq_of(object),
        hash: object.entry_hash().unwrap(),
    }
}

/// The relay's bounds on one reply (§R9.4): at most 64 entries and
/// 256 KiB; `more` when entries were left out.
pub const RELAY_MAX_ENTRIES: usize = 64;
pub const RELAY_MAX_BYTES: usize = 256 * 1024;

pub fn bounded(entries: &[SignedObject]) -> (Vec<SignedObject>, bool) {
    let mut out = Vec::new();
    let mut bytes = 0;
    for entry in entries {
        let size = entry.to_json().to_string().len();
        if out.len() == RELAY_MAX_ENTRIES || bytes + size > RELAY_MAX_BYTES {
            return (out, true);
        }
        bytes += size;
        out.push(entry.clone());
    }
    (out, false)
}

impl FakeRelay {
    pub fn with_log(entries: Vec<SignedObject>) -> Self {
        FakeRelay {
            log: entries,
            ..Default::default()
        }
    }

    pub fn head(&self) -> Head {
        head_of(self.log.last().unwrap())
    }

    /// `POST …/entries {entry, expected}`.
    pub fn append(&mut self, entry: &SignedObject, expected: Head) -> RelayAppend {
        let seq = seq_of(entry);
        let hash = entry.entry_hash().unwrap();
        // Idempotent retry: the same entry_hash at that seq.
        if let Some(stored) = self.log.get((seq - 1) as usize)
            && stored.entry_hash().unwrap() == hash
        {
            return RelayAppend::Ok(stored.clone());
        }
        let at_expected = self
            .log
            .get((expected.seq - 1) as usize)
            .map(|e| e.entry_hash().unwrap());
        if self.head() == expected && seq == expected.seq + 1 {
            self.log.push(entry.clone());
            return RelayAppend::Ok(entry.clone());
        }
        if self.cas_broken && at_expected == Some(expected.hash) && seq == expected.seq + 1 {
            self.siblings.push(entry.clone());
            return RelayAppend::Ok(entry.clone());
        }
        let after = if at_expected == Some(expected.hash) {
            expected.seq as usize
        } else {
            // A window from before the divergence.
            (expected.seq as usize).saturating_sub(8).max(1)
        };
        let (entries, more) = bounded(&self.log[after..]);
        RelayAppend::Conflict {
            head: self.head(),
            entries,
            more,
        }
    }

    /// `GET …/entries?after=<seq>`, bounded like a `409`: `(entries, more)`.
    pub fn after_page(&self, seq: u64) -> (Vec<SignedObject>, bool) {
        bounded(&self.log[seq as usize..])
    }

    /// Everything after `seq` (a client paging through `after_page`).
    pub fn after(&self, seq: u64) -> Vec<SignedObject> {
        self.log[seq as usize..].to_vec()
    }

    /// Put-if-absent of an envelope: `200` or `409 {max_occupied}`.
    pub fn put(&mut self, blob_version: u64, bytes: &str) -> Result<(), u64> {
        match self.blobs.get(&blob_version) {
            Some(stored) if stored == bytes => Ok(()),
            Some(_) => Err(*self.blobs.keys().next_back().unwrap()),
            None => {
                self.blobs.insert(blob_version, bytes.to_owned());
                Ok(())
            }
        }
    }

    /// Occupies a version with other bytes (a writer that crashed before its
    /// CAS, or lost a race).
    pub fn occupy(&mut self, blob_version: u64) {
        self.blobs
            .insert(blob_version, format!("{{\"orphan\":{blob_version}}}"));
    }

    pub fn versions(&self) -> BTreeSet<u64> {
        self.blobs.keys().copied().collect()
    }
}

/// A host's `init`/`accept` pair as a restoring device gets it (§R9.7):
/// `head` signed by `key` (the host's `host_channel_key`) over `th2` for the
/// log `genesis_hash`, `host_id` at trust generation 1.
pub fn signed_accept(
    provider: &dyn KeyProvider,
    key: &KeyId,
    genesis_hash: Hash32,
    host_id: &str,
    head: Head,
) -> atem_client::channel::HostAccept {
    let mut pair = atem_client::channel::HostAccept {
        e_c: [1; 32],
        n_c: [2; 32],
        genesis_hash,
        host_id: host_id.into(),
        host_trust_gen: 1,
        e_h: [3; 32],
        n_h: [4; 32],
        head,
        sig: Vec::new(),
    };
    pair.sig = atem_client::provider::sign(provider, key, &pair.signing_input()).unwrap();
    pair
}

//! The K backup `atem-k-backup-v2` (§R9.5): the account keys `K`, sealed to
//! the Recovery Kit's X25519 key in an envelope the relay stores per log.
//!
//! ```json
//! {"v":2,"account_id":"…","genesis_hash":"<hex>","blob_version":3,
//!  "kids":["b982533d","1f2e3d4c"],"recovery_key":{"alg":"ed25519","pub":"<b64u>"},
//!  "enc":"<b64u>","ct":"<b64u>"}
//! ```
//!
//! `info = enc(["atem-k-backup-v2", account_id, genesis_hash(32), u64(blob_version),
//! jcs(kids), recovery_key.pub(32)])`, empty AAD, plaintext
//! `jcs({"keys":[{"k":"<b64u 32>","kid":"…"},…]})`, current key first, then
//! retained generations newest first (1–8; a sequence, never sorted).
//! `backup_hash = hex(SHA-256(enc(["atem-k-backup-hash-v1", jcs(envelope)])))`.
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::canonical::{self, Numbers, StrictValue, jcs};
use crate::domain;
use crate::encoding::{Hash32, b64u, b64u_decode, b64u_decode_array, ct_eq, enc, u64_field};
use crate::error::{Error, Result};
use crate::hpke;
use crate::keys::{Alg, PublicKey};
use crate::kit::{RecoveryKit, kit_x25519_public};
use crate::provider::{KeyId, KeyProvider};
use crate::signed::{ArrayKind, MAX_BACKUP_KEYS, check_value};

/// Bound on an envelope (8 keys and their framing fit well within it).
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024;

/// One account key and its id. The key is wiped on drop.
pub struct BackupKey {
    pub kid: String,
    pub k: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BackupKey({}, …)", self.kid)
    }
}

/// A key id: 1–64 bytes of `[A-Za-z0-9._:-]` (kids are short hex today), so
/// it needs no JSON escaping.
pub(crate) fn kid_ok(kid: &str) -> bool {
    (1..=64).contains(&kid.len())
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KBackupEnvelope {
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub blob_version: u64,
    /// A sequence: current kid first.
    pub kids: Vec<String>,
    /// The kit the backup is sealed to (Ed25519).
    pub recovery_key: PublicKey,
    pub enc: [u8; 32],
    pub ct: Vec<u8>,
}

/// The HPKE `info` of an envelope.
pub fn info(
    account_id: &str,
    genesis_hash: &Hash32,
    blob_version: u64,
    kids: &[String],
    recovery_key: &PublicKey,
) -> Result<Vec<u8>> {
    let recovery_pub = recovery_key.as_32().ok_or(Error::WrongAlg)?;
    let kids_jcs = jcs(&Value::from(kids.to_vec()))?;
    Ok(enc(&[
        domain::K_BACKUP.as_bytes(),
        account_id.as_bytes(),
        genesis_hash.as_bytes(),
        &u64_field(blob_version),
        kids_jcs.as_bytes(),
        recovery_pub,
    ]))
}

/// The exact length of `plaintext(keys)`: `{"keys":[` and `]}`, then per
/// key `{"k":"` + 43 + `","kid":"` + kid + `"}`, and the commas between.
fn plaintext_len(keys: &[BackupKey]) -> usize {
    11 + keys.iter().map(|key| 60 + key.kid.len()).sum::<usize>() + keys.len().saturating_sub(1)
}

/// `jcs({"keys":[{"k":…,"kid":…},…]})`, built in one wiped buffer sized
/// exactly, so it never reallocates (a freed buffer would keep key
/// material unwiped).
fn plaintext(keys: &[BackupKey]) -> Zeroizing<String> {
    let capacity = plaintext_len(keys);
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    out.push_str(r#"{"keys":["#);
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let k = Zeroizing::new(b64u(&*key.k));
        out.push_str(r#"{"k":""#);
        out.push_str(&k);
        out.push_str(r#"","kid":""#);
        out.push_str(&key.kid);
        out.push_str(r#""}"#);
    }
    out.push_str("]}");
    debug_assert_eq!(out.len(), capacity);
    out
}

impl KBackupEnvelope {
    /// Seals `keys` (current first) to the kit named by `recovery_key`. Any
    /// manager holding `K` can do this; no `R` is needed.
    pub fn seal(
        account_id: &str,
        genesis_hash: Hash32,
        blob_version: u64,
        recovery_key: &PublicKey,
        keys: &[BackupKey],
    ) -> Result<Self> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut *ikm);
        Self::seal_derived(
            account_id,
            genesis_hash,
            blob_version,
            recovery_key,
            keys,
            &ikm,
        )
    }

    /// `seal` with the HPKE ephemeral `DeriveKeyPair(ikm_e)`: known-answer
    /// vectors only (feature `test-vectors`, never exported).
    #[cfg(feature = "test-vectors")]
    pub fn seal_with_ikm(
        account_id: &str,
        genesis_hash: Hash32,
        blob_version: u64,
        recovery_key: &PublicKey,
        keys: &[BackupKey],
        ikm_e: &[u8; 32],
    ) -> Result<Self> {
        Self::seal_derived(
            account_id,
            genesis_hash,
            blob_version,
            recovery_key,
            keys,
            ikm_e,
        )
    }

    fn seal_derived(
        account_id: &str,
        genesis_hash: Hash32,
        blob_version: u64,
        recovery_key: &PublicKey,
        keys: &[BackupKey],
        ikm_e: &[u8; 32],
    ) -> Result<Self> {
        if recovery_key.alg() != Alg::Ed25519 {
            return Err(Error::WrongAlg);
        }
        if blob_version == 0 || blob_version > canonical::MAX_SAFE_INTEGER {
            return Err(Error::BackupInvalid);
        }
        let kids: Vec<String> = keys.iter().map(|key| key.kid.clone()).collect();
        check_kids(&kids)?;
        let info = info(account_id, &genesis_hash, blob_version, &kids, recovery_key)?;
        let recipient = kit_x25519_public(recovery_key)?;
        let sealed = hpke::seal_derived(&recipient, &info, b"", plaintext(keys).as_bytes(), ikm_e)?;
        Ok(KBackupEnvelope {
            account_id: account_id.to_owned(),
            genesis_hash,
            blob_version,
            kids,
            recovery_key: recovery_key.clone(),
            enc: sealed.enc,
            ct: sealed.ct,
        })
    }

    /// Strict parse of envelope bytes; anything wrong is `backup_invalid`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = canonical::parse_strict(bytes, MAX_ENVELOPE_BYTES, Numbers::IntegersOnly)
            .map_err(|_| Error::BackupInvalid)?;
        Self::from_value(&value)
    }

    /// From a part of a strictly parsed message.
    pub fn from_strict(value: &StrictValue) -> Result<Self> {
        Self::from_value(value.value())
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        Self::from_value_inner(value).map_err(|_| Error::BackupInvalid)
    }

    fn from_value_inner(value: &Value) -> Result<Self> {
        let object = value.as_object().ok_or(Error::BackupInvalid)?;
        const FIELDS: [&str; 8] = [
            "v",
            "account_id",
            "genesis_hash",
            "blob_version",
            "kids",
            "recovery_key",
            "enc",
            "ct",
        ];
        if object.len() != FIELDS.len() || !FIELDS.iter().all(|f| object.contains_key(*f)) {
            return Err(Error::BackupInvalid);
        }
        check_value(value, &|path| {
            (path == ["kids"]).then_some(ArrayKind::Sequence {
                max: MAX_BACKUP_KEYS,
            })
        })?;
        let text = |field: &str| object[field].as_str().ok_or(Error::BackupInvalid);
        if object["v"].as_u64() != Some(2) {
            return Err(Error::BackupInvalid);
        }
        let blob_version = object["blob_version"]
            .as_u64()
            .ok_or(Error::BackupInvalid)?;
        if blob_version == 0 {
            return Err(Error::BackupInvalid);
        }
        let kids: Vec<String> = object["kids"]
            .as_array()
            .ok_or(Error::BackupInvalid)?
            .iter()
            .map(|kid| kid.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or(Error::BackupInvalid)?;
        check_kids(&kids)?;
        Ok(KBackupEnvelope {
            account_id: text("account_id")?.to_owned(),
            genesis_hash: Hash32::from_hex(text("genesis_hash")?)?,
            blob_version,
            kids,
            recovery_key: PublicKey::from_json_as(&object["recovery_key"], Alg::Ed25519)?,
            enc: b64u_decode_array(text("enc")?)?,
            ct: b64u_decode(text("ct")?)?,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("v".into(), Value::from(2));
        object.insert("account_id".into(), Value::from(self.account_id.clone()));
        object.insert(
            "genesis_hash".into(),
            Value::from(self.genesis_hash.to_hex()),
        );
        object.insert("blob_version".into(), Value::from(self.blob_version));
        object.insert("kids".into(), Value::from(self.kids.clone()));
        object.insert("recovery_key".into(), self.recovery_key.to_json());
        object.insert("enc".into(), Value::from(b64u(&self.enc)));
        object.insert("ct".into(), Value::from(b64u(&self.ct)));
        Value::Object(object)
    }

    /// `jcs(envelope)`: the bytes uploaded and hashed.
    pub fn jcs(&self) -> String {
        jcs(&self.to_json()).expect("an envelope is in the jcs domain")
    }

    /// `SHA-256(enc(["atem-k-backup-hash-v1", jcs(envelope)]))`, recorded by
    /// the `k_backup` entry.
    pub fn backup_hash(&self) -> Hash32 {
        Hash32::of_enc(&[domain::K_BACKUP_HASH.as_bytes(), self.jcs().as_bytes()])
    }

    pub fn info(&self) -> Result<Vec<u8>> {
        info(
            &self.account_id,
            &self.genesis_hash,
            self.blob_version,
            &self.kids,
            &self.recovery_key,
        )
    }

    /// Opens with the kit's X25519 key held by `provider`. The plaintext's
    /// kids must be the envelope's, in the same order.
    pub fn open(&self, provider: &dyn KeyProvider, kit_key: &KeyId) -> Result<Vec<BackupKey>> {
        let plain = provider
            .hpke_open(kit_key, &self.enc, &self.ct, &self.info()?, b"")
            .map_err(|_| Error::BackupInvalid)?;
        self.keys_of(&plain)
    }

    /// Opens with the kit itself (a restore holds `R`). Refuses an envelope
    /// sealed to another kit before trying.
    pub fn open_with_kit(&self, kit: &RecoveryKit) -> Result<Vec<BackupKey>> {
        if kit.recovery_key() != self.recovery_key {
            return Err(Error::BackupInvalid);
        }
        let plain = hpke::open_with_secret(
            &kit.x25519_secret(),
            &self.enc,
            &self.ct,
            &self.info()?,
            b"",
        )
        .map_err(|_| Error::BackupInvalid)?;
        self.keys_of(&plain)
    }

    fn keys_of(&self, plain: &[u8]) -> Result<Vec<BackupKey>> {
        let mut value = canonical::parse_strict(plain, MAX_ENVELOPE_BYTES, Numbers::IntegersOnly)
            .map_err(|_| Error::BackupInvalid)?;
        let keys = read_keys(&value, &self.kids).and_then(|keys| {
            // One encoding on read as on write: the plaintext must be exactly
            // `jcs` of what it holds (rebuilt in a wiped buffer).
            if ct_eq(plaintext(&keys).as_bytes(), plain) {
                Ok(keys)
            } else {
                Err(Error::BackupInvalid)
            }
        });
        wipe_strings(&mut value);
        keys
    }
}

fn check_kids(kids: &[String]) -> Result<()> {
    if kids.is_empty() || kids.len() > MAX_BACKUP_KEYS || !kids.iter().all(|kid| kid_ok(kid)) {
        return Err(Error::BackupInvalid);
    }
    let items: Vec<Value> = kids.iter().map(|kid| Value::from(kid.as_str())).collect();
    crate::signed::check_array(
        ArrayKind::Sequence {
            max: MAX_BACKUP_KEYS,
        },
        &items,
    )
    .map_err(|_| Error::BackupInvalid)
}

fn read_keys(value: &Value, kids: &[String]) -> Result<Vec<BackupKey>> {
    let object = value.as_object().ok_or(Error::BackupInvalid)?;
    if object.len() != 1 {
        return Err(Error::BackupInvalid);
    }
    check_value(value, &|path| {
        (path == ["keys"]).then_some(ArrayKind::KeyedSequence {
            max: MAX_BACKUP_KEYS,
        })
    })
    .map_err(|_| Error::BackupInvalid)?;
    let entries = object
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Error::BackupInvalid)?;
    if entries.len() != kids.len() {
        return Err(Error::BackupInvalid);
    }
    let mut keys = Vec::with_capacity(entries.len());
    for (entry, kid) in entries.iter().zip(kids) {
        let entry = entry.as_object().ok_or(Error::BackupInvalid)?;
        if entry.len() != 2 || entry.get("kid").and_then(Value::as_str) != Some(kid.as_str()) {
            return Err(Error::BackupInvalid);
        }
        let k = entry
            .get("k")
            .and_then(Value::as_str)
            .ok_or(Error::BackupInvalid)?;
        let raw = Zeroizing::new(b64u_decode(k).map_err(|_| Error::BackupInvalid)?);
        let mut k = Zeroizing::new([0u8; 32]);
        if raw.len() != 32 {
            return Err(Error::BackupInvalid);
        }
        k.copy_from_slice(&raw);
        keys.push(BackupKey {
            kid: kid.clone(),
            k,
        });
    }
    Ok(keys)
}

/// Wipes every string of a parsed plaintext (the key material).
fn wipe_strings(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        Value::Object(map) => map.values_mut().for_each(wipe_strings),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kid: &str, byte: u8) -> BackupKey {
        BackupKey {
            kid: kid.into(),
            k: Zeroizing::new([byte; 32]),
        }
    }

    fn kit() -> RecoveryKit {
        RecoveryKit::make(&[3u8; 32], "acct", Hash32([5u8; 32]))
    }

    #[test]
    fn a_backup_round_trips_and_keeps_its_order() {
        let kit = kit();
        let env = KBackupEnvelope::seal(
            "acct",
            kit.genesis_hash(),
            2,
            &kit.recovery_key(),
            &[key("b9", 1), key("1f", 2)],
        )
        .unwrap();
        let reparsed = KBackupEnvelope::parse(env.jcs().as_bytes()).unwrap();
        assert_eq!(reparsed, env);
        let keys = reparsed.open_with_kit(&kit).unwrap();
        assert_eq!(
            keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
            ["b9", "1f"]
        );
        assert_eq!(*keys[1].k, [2u8; 32]);
    }

    #[test]
    fn any_change_to_the_bound_fields_fails_the_tag() {
        let kit = kit();
        let env = KBackupEnvelope::seal(
            "acct",
            kit.genesis_hash(),
            2,
            &kit.recovery_key(),
            &[key("b9", 1)],
        )
        .unwrap();
        for tamper in [
            |e: &mut KBackupEnvelope| e.blob_version = 3,
            |e: &mut KBackupEnvelope| e.account_id = "other".into(),
            |e: &mut KBackupEnvelope| e.genesis_hash = Hash32([6u8; 32]),
            |e: &mut KBackupEnvelope| e.kids = vec!["c0".into()],
        ] {
            let mut changed = env.clone();
            tamper(&mut changed);
            assert!(matches!(
                changed.open_with_kit(&kit),
                Err(Error::BackupInvalid)
            ));
        }
    }

    #[test]
    fn the_plaintext_buffer_is_sized_exactly() {
        let long = "k".repeat(64);
        for keys in [
            vec![key("b9", 1)],
            vec![key(&long, 1), key("1f", 2), key(&"x".repeat(40), 3)],
            (0..8)
                .map(|i| key(&format!("{long:.60}{i:04}"), i))
                .collect(),
        ] {
            let plain = plaintext(&keys);
            assert_eq!(plain.len(), plaintext_len(&keys));
            // Never grown past its first allocation.
            assert_eq!(plain.capacity(), plaintext_len(&keys));
            let value: Value = serde_json::from_str(&plain).unwrap();
            assert_eq!(jcs(&value).unwrap(), *plain, "already canonical");
        }
    }

    #[test]
    fn a_plaintext_that_is_not_canonical_is_refused() {
        let kit = kit();
        let env = KBackupEnvelope::seal(
            "acct",
            kit.genesis_hash(),
            2,
            &kit.recovery_key(),
            &[key("b9", 1)],
        )
        .unwrap();
        let k = b64u(&[1u8; 32]);
        let recipient = kit_x25519_public(&kit.recovery_key()).unwrap();
        for plain in [
            format!(r#"{{"keys":[{{"kid":"b9","k":"{k}"}}]}}"#),
            format!(r#"{{ "keys":[{{"k":"{k}","kid":"b9"}}]}}"#),
            format!(r#"{{"keys":[{{"k":"{k}","kid":"\u0062\u0039"}}]}}"#),
        ] {
            let sealed = hpke::seal_derived(
                &recipient,
                &env.info().unwrap(),
                b"",
                plain.as_bytes(),
                &[9u8; 32],
            )
            .unwrap();
            let forged = KBackupEnvelope {
                enc: sealed.enc,
                ct: sealed.ct,
                ..env.clone()
            };
            assert_eq!(
                forged.open_with_kit(&kit).unwrap_err(),
                Error::BackupInvalid,
                "{plain}"
            );
        }
        // The canonical spelling of the same keys opens.
        let canonical = format!(r#"{{"keys":[{{"k":"{k}","kid":"b9"}}]}}"#);
        let sealed = hpke::seal_derived(
            &recipient,
            &env.info().unwrap(),
            b"",
            canonical.as_bytes(),
            &[9u8; 32],
        )
        .unwrap();
        let ok = KBackupEnvelope {
            enc: sealed.enc,
            ct: sealed.ct,
            ..env
        };
        assert_eq!(*ok.open_with_kit(&kit).unwrap()[0].k, [1u8; 32]);
    }

    #[test]
    fn duplicate_or_empty_kids_are_refused() {
        let kit = kit();
        let seal = |keys: &[BackupKey]| {
            KBackupEnvelope::seal("acct", kit.genesis_hash(), 1, &kit.recovery_key(), keys)
        };
        assert_eq!(seal(&[]).unwrap_err(), Error::BackupInvalid);
        assert_eq!(
            seal(&[key("a", 1), key("a", 2)]).unwrap_err(),
            Error::BackupInvalid
        );
        let mut json = seal(&[key("a", 1)]).unwrap().to_json();
        json["kids"] = serde_json::json!(["a", "a"]);
        assert_eq!(
            KBackupEnvelope::from_value(&json),
            Err(Error::BackupInvalid)
        );
    }
}

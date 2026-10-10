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
    pub fn migration_proof(&self, account: &str, kid: &str, input: &[u8]) -> Result<[u8; 32]> {
        let ring = self.rings.get(account).filter(|ring| ring.current.kid == kid)
            .ok_or_else(|| anyhow!(MISSING_KEY))?;
        let mut derived = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<Sha256>::new(None, &ring.current.key[..])
            .expand(b"atem-migration-proof-v1", &mut *derived)
            .map_err(|_| anyhow!("migration proof key derivation failed"))?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&derived[..])
            .expect("HMAC accepts a 32-byte key");
        mac.update(input);
        Ok(mac.finalize().into_bytes().into())
    }

    pub fn is_empty(&self) -> bool {
        self.rings.is_empty()
    }

    pub fn current_kid(&self, account: &str) -> Option<&str> {
        self.rings
            .get(account)
            .map(|ring| ring.current.kid.as_str())
    }

    /// The kids of the keys `account`'s current key replaced, oldest first.
    #[cfg(test)]
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

    /// Adds keys found in data_keys.enc (build steps 0–2a): `current`
    /// becomes the account's current key only if it has none; every other
    /// key not held yet (by kid) is added to the previous keys, so a newer
    /// `K` installed meanwhile stays current. Without a `current` (its entry
    /// was missing or malformed) and with no key held, the newest previous
    /// key stands in as current: it is used only if the signed state names
    /// its kid, and a granted `K` replaces it. A repeat changes nothing.
    /// Returns whether anything changed.
    pub fn merge(
        &mut self,
        account: &str,
        current: Option<AccountKey>,
        mut previous: Vec<AccountKey>,
    ) -> bool {
        use std::collections::btree_map::Entry;
        let current = current.or_else(|| match self.rings.contains_key(account) {
            true => None,
            false => previous.pop(),
        });
        let mut keys = current.into_iter().chain(previous).peekable();
        if keys.peek().is_none() {
            return false;
        }
        let (ring, mut changed) = match self.rings.entry(account.into()) {
            Entry::Occupied(ring) => (ring.into_mut(), false),
            Entry::Vacant(slot) => {
                let current = keys.next().expect("peeked above");
                let ring = slot.insert(KeyRing {
                    current,
                    previous: Vec::new(),
                });
                (ring, true)
            }
        };
        for key in keys {
            if key.kid != ring.current.kid && !ring.previous.iter().any(|held| held.kid == key.kid)
            {
                ring.previous.push(key);
                changed = true;
            }
        }
        changed
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
                    Ok(CryptOut::Opened(Zeroizing::new(
                        STANDARD.encode(&plain[..]),
                    )))
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

    /// The size of the field itself, in bytes (for error messages): the
    /// plain text to seal or hash, or the `e1.` value to open.
    pub fn field_len(&self) -> usize {
        let decoded = |b64: &str| {
            let padding = b64.bytes().rev().take_while(|byte| *byte == b'=').count();
            (b64.len() / 4 * 3).saturating_sub(padding)
        };
        match self {
            Self::Seal { plain, .. } => decoded(plain),
            Self::Open { value, .. } => value.len(),
            Self::KeyedHash { value } => decoded(value),
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
            Self::Opened(_) => {
                bail!("the key agent answered an open where a seal or hash was asked")
            }
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
pub(crate) fn seal_field(
    key: &AccountKey,
    record: &str,
    field: &str,
    plain: &[u8],
) -> Result<String> {
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
    let payload = STANDARD
        .decode(encoded)
        .context("invalid encrypted field")?;
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
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.key[..]).expect("HMAC accepts 32 bytes");
    mac.update(value);
    let digest: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("h1.{}.{digest}", key.kid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "0123abcd";
    /// `e1.` of "use port 27183" for record `mem-1`, field `content`, under
    /// K = [7; 32] with nonce 00 01 … 17: the format of build steps 0–2a.
    const E1_VECTOR: &str =
        "e1.0123abcd.AAECAwQFBgcICQoLDA0ODxAREhMUFRYX3WTOpYpzKdEF9bZ23tEau96ycT/fld12nKOh2bIB";
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
        assert_eq!(
            &*out.next().unwrap().into_plain().unwrap(),
            b"use port 27183"
        );
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
            &*open("mem-1", "content", &sealed)
                .unwrap()
                .remove(0)
                .into_plain()
                .unwrap(),
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
        assert!(
            error(keys.crypt("acct", EncryptionMode::On, Some("89abcdef"), hash()))
                .contains("requires encryption")
        );
        assert!(
            error(keys.crypt("other", EncryptionMode::On, Some(KID), hash()))
                .contains("requires encryption")
        );
        assert!(error(keys.crypt("acct", EncryptionMode::Off, None, hash())).contains("off"));
        assert!(
            keys.crypt("acct", EncryptionMode::Enabling, Some(KID), hash())
                .is_ok()
        );
    }

    #[test]
    fn previous_keys_open_until_the_state_is_on() {
        let mut keys = keys_with("0123abcd", 1);
        let old = seal_field(&key("0123abcd", 1), "mem", "content", b"old").unwrap();
        assert!(keys.install("acct", "89abcdef", Zeroizing::new([2; 32])));
        assert_eq!(keys.current_kid("acct"), Some("89abcdef"));
        assert_eq!(keys.previous_kids("acct"), vec!["0123abcd".to_string()]);
        let open = |keys: &AccountKeys, mode| {
            keys.crypt(
                "acct",
                mode,
                Some("89abcdef"),
                vec![CryptOp::open("mem", "content", &old)],
            )
        };
        assert!(open(&keys, EncryptionMode::Enabling).is_ok());
        assert!(open(&keys, EncryptionMode::Disabling).is_ok());
        let error = format!("{:#}", open(&keys, EncryptionMode::On).err().unwrap());
        assert!(error.contains("unavailable key id"), "{error}");
    }

    #[test]
    fn install_reports_changes_and_never_duplicates_kids() {
        let mut keys = keys_with("0123abcd", 1);
        assert!(
            !keys.install("acct", "0123abcd", Zeroizing::new([1; 32])),
            "a repeat changes nothing"
        );
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
        modes.insert(
            "acct".into(),
            Some((EncryptionMode::Enabling, Some("89abcdef".into()))),
        );
        modes.insert("waiting".into(), None);
        assert!(
            keys.reconcile(&modes),
            "an account no verified Astation names goes"
        );
        assert_eq!(keys.current_kid("gone"), None);
        assert_eq!(
            keys.current_kid("waiting"),
            Some("33334444"),
            "no state yet: kept"
        );
        assert_eq!(keys.previous_kids("acct"), vec!["0123abcd".to_string()]);
        assert!(!keys.reconcile(&modes));
        modes.insert(
            "acct".into(),
            Some((EncryptionMode::On, Some("89abcdef".into()))),
        );
        assert!(keys.reconcile(&modes));
        assert!(
            keys.previous_kids("acct").is_empty(),
            "on with the current kid: history goes"
        );
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
        let bad_kid =
            r#"{"acct":{"kid":"XYZ","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}"#;
        assert!(AccountKeys::from_wire(serde_json::from_str(bad_kid).unwrap()).is_err());
        let short_key = r#"{"acct":{"kid":"0123abcd","key":"AAAA"}}"#;
        assert!(AccountKeys::from_wire(serde_json::from_str(short_key).unwrap()).is_err());
    }

    #[test]
    fn field_len_is_the_size_of_the_field_itself() {
        for len in [0, 1, 2, 3, 4, 5, 1000] {
            let plain = vec![7u8; len];
            assert_eq!(CryptOp::seal("r", "f", &plain).field_len(), len);
            assert_eq!(CryptOp::keyed_hash(&plain).field_len(), len);
        }
        assert_eq!(CryptOp::open("r", "f", "e1.0123abcd.AAAA").field_len(), 16);
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

    #[test]
    fn merge_adds_older_keys_and_never_replaces_the_current_one() {
        let mut keys = AccountKeys::default();
        assert!(keys.merge("acct", Some(key("0123abcd", 1)), vec![key("11112222", 2)]));
        assert_eq!(keys.current_kid("acct"), Some("0123abcd"));
        assert_eq!(keys.previous_kids("acct"), vec!["11112222".to_string()]);
        // A newer K installed meanwhile stays current; the merge only adds history.
        keys.install("acct", "89abcdef", Zeroizing::new([3; 32]));
        assert!(
            !keys.merge("acct", Some(key("0123abcd", 1)), vec![key("11112222", 2)]),
            "a repeat changes nothing"
        );
        assert_eq!(keys.current_kid("acct"), Some("89abcdef"));
        let mut previous = keys.previous_kids("acct");
        previous.sort();
        assert_eq!(
            previous,
            vec!["0123abcd".to_string(), "11112222".to_string()]
        );
        // A key held under the same kid isn't replaced by the merge.
        assert!(!keys.merge("acct", Some(key("89abcdef", 9)), vec![]));
    }

    #[test]
    fn merge_without_a_current_key_keeps_the_valid_previous_ones() {
        let mut keys = AccountKeys::default();
        assert!(!keys.merge("acct", None, vec![]), "nothing to add");
        assert!(keys.is_empty());
        // No key held: the newest previous key stands in as current.
        assert!(keys.merge("acct", None, vec![key("0123abcd", 1), key("11112222", 2)]));
        assert_eq!(keys.current_kid("acct"), Some("11112222"));
        assert_eq!(keys.previous_kids("acct"), vec!["0123abcd".to_string()]);
        // A key held already stays current; the others are added as history.
        keys.install("acct", "89abcdef", Zeroizing::new([3; 32]));
        assert!(keys.merge("other", Some(key("44445555", 4)), vec![]));
        assert!(!keys.merge("acct", None, vec![key("0123abcd", 1)]));
        assert!(keys.merge("acct", None, vec![key("66667777", 6)]));
        assert_eq!(keys.current_kid("acct"), Some("89abcdef"));
        assert!(keys.previous_kids("acct").contains(&"66667777".to_string()));
    }
}

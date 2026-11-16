//! The host encryption key (delegated host-work design II.4.1, option (b);
//! session-v1 R9.14 item 8; host-work-v1 §11.5, "The recipient's keys" and
//! "The host encryption key in the ceremony"), on the host: the X25519 key
//! other hosts seal host-sender mail to, the record of every key id this
//! host made at its trust generation, what `host_enc_key_get` answers a
//! native manager, and this host as the receiver of that mail.
//!
//! - **In every build:** the verification ceremony's key
//!   ([`make_for_ceremony_locked`], [`keep_at_pin`]), since its reveal
//!   requires it (agreed with Astation 2026-11-16, no compatibility).
//! - **Behind the debug-only hook's `host.senders`:** everything else (a
//!   key made at a start, `host_enc_key_get`, the receiver). With the hook
//!   off none of it runs: the op keeps its refusal.
//!
//! ```text
//! <profile>/pairing/host_enc_key        {"v":1,"host_trust_gen":N,"secret":"<b64u>","pub":"<b64u>"}
//! <profile>/pairing/host_enc_generated  {"v":1,"host_trust_gen":N,"kids":["<16 hex>",…]}
//! ```
//!
//! - **The key.** Plain, 0600, replaced whole like `host_channel_key`
//!   (`membership::store`), so a host whose cred agent is locked still opens
//!   its mail. One key per trust generation in this version (no rotation
//!   within a generation):
//!   - made in the verification ceremony (`atem pair`, and `atem pair
//!     verify` in the next generation), after `verifyKeys`, vouched for by
//!     the ceremony's new `host_channel_key` (`enc_sig`), its id recorded
//!     before the reveal carries it, and kept with the device list's pin;
//!   - with the hook, made at a runtime start (or a reopen of the list) on
//!     a pinned host that holds none for its generation (paired before
//!     this change). One of an earlier generation is replaced then; one that
//!     can't be read is left as it is (the op answers `busy`, and the start
//!     says why).
//!
//!   A pin replaces both files with its ceremony's; a pin taken back
//!   removes the key and keeps the record (the reveal handed the key's id
//!   out); `atem unpair` deletes both. One left without the list (by a build
//!   that doesn't know them, or an aborted ceremony's record) grants nothing
//!   and is no device-list leftover: it doesn't fail the list's start
//!   closed.
//! - **The record.** The `enc_kid` (R9.9's, `atem_client::keys::enc_kid`) of
//!   every key made at the current generation, written (fsync, rename)
//!   before the key is handed out (the reveal, `host_enc_key_get`) or its
//!   file written, and checked again before a key is handed out (one that
//!   lists it already is synced, file and directory, first): II.4.2's
//!   receiver refuses for good mail sealed to a key id the host made but the
//!   record lacks. Only the current generation is kept. A lost or
//!   unreadable record, or one of another generation, is rebuilt from the
//!   key the host holds, with a runtime.log line.
//! - **`host_enc_key_get`** (`R9Host`'s handler, [`hand_out`]): the key the
//!   host holds for the welcome's trust generation and its `enc_sig`, the
//!   host vouching for it with its `host_channel_key` (the shared core's
//!   `sign_host_enc_key`). Nothing is made or rotated for a request; the
//!   key's id is recorded first when the record lacks it, and a failed
//!   write is `busy`, nothing handed out. After a ceremony whose entries
//!   ended at the `add_host`, it is the ceremony's key, with the same
//!   `enc_sig`.
//! - **The receiver's view** ([`recipient`]): this host's id and pairing
//!   generation, the generation's key and the record, as II.4.2's receiver
//!   takes them (`atem_client::host_mail::Recipient`).
use atem_client::encoding::{Hash32, b64u, hex, hex_decode_array};
use atem_client::host_mail::Recipient;
use atem_client::keys::enc_kid_bytes;
use atem_client::membership::{Membership, sign_host_enc_key};
use atem_client::{KeyId, KeyProvider, PublicKey, SoftwareKeys};
use rand::RngCore;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::HostKey;
use crate::paths::PairingPaths;
use crate::session_protocol::membership::journal_of;
use crate::session_protocol::membership::store::{self, DlFile, Store, WriteError};

/// `busy` detail of `host_enc_key_get` (session-v1 R9.14 item 8): the host
/// holds no key for its trust generation (none made, or the file can't be
/// read), or couldn't record the key's id before handing it out.
pub const DETAIL_UNAVAILABLE: &str = "host encryption key unavailable";

/// The key's name behind its provider.
const KEY_NAME: &str = "host_enc_key";

/// A host encryption key, as made or read: its generation, its public half
/// and id, and the private key behind a provider.
pub struct HostEncKey {
    pub host_trust_gen: u64,
    /// X25519.
    pub public: PublicKey,
    /// Its `enc_kid` (8 bytes; the hex is the 16-character id).
    pub kid: [u8; 8],
    keys: SoftwareKeys,
}

impl std::fmt::Debug for HostEncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostEncKey")
            .field("host_trust_gen", &self.host_trust_gen)
            .field("kid", &hex(&self.kid))
            .finish_non_exhaustive()
    }
}

impl HostEncKey {
    fn from_secret(host_trust_gen: u64, secret: &[u8; 32]) -> Self {
        let mut keys = SoftwareKeys::new();
        keys.insert_x25519(Self::key_id(), secret);
        let public = keys
            .public_key(&Self::key_id())
            .expect("an X25519 key has a public half");
        let kid = enc_kid_bytes(&public).expect("an X25519 key has an enc_kid");
        HostEncKey {
            host_trust_gen,
            public,
            kid,
            keys,
        }
    }

    /// A new random key for `host_trust_gen`, and its secret (for the file).
    fn generate(host_trust_gen: u64) -> (Self, Zeroizing<[u8; 32]>) {
        let mut secret = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(secret.as_mut());
        (Self::from_secret(host_trust_gen, &secret), secret)
    }

    /// The name of the private key behind its provider.
    pub fn key_id() -> KeyId {
        KeyId::new(KEY_NAME)
    }

    /// The 32 bytes of the public half.
    pub fn enc_pub(&self) -> &[u8; 32] {
        self.public.as_32().expect("an X25519 key is 32 bytes")
    }

    /// The key's id as the record and the mail carry it.
    pub fn enc_kid(&self) -> String {
        hex(&self.kid)
    }
}

/// `host_enc_key`'s bytes: the secret and its public half (base64url), with
/// the generation it was made for. No `serde_json::Value` in between, and
/// one buffer of the exact size: the copies made here are wiped (base64url
/// needs no JSON escaping).
fn key_bytes(host_trust_gen: u64, secret: &[u8; 32], public: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let head = format!(r#"{{"v":1,"host_trust_gen":{host_trust_gen},"secret":""#);
    const MIDDLE: &[u8] = br#"","pub":""#;
    const TAIL: &[u8] = br#""}"#;
    let secret = Zeroizing::new(b64u(secret));
    let public = b64u(public);
    // Its exact size: the buffer never grows (a reallocation would leave an
    // unwiped copy of the secret's text).
    let len = head.len() + secret.len() + MIDDLE.len() + public.len() + TAIL.len();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(secret.as_bytes());
    out.extend_from_slice(MIDDLE);
    out.extend_from_slice(public.as_bytes());
    out.extend_from_slice(TAIL);
    out
}

/// `host_enc_key` as read: the secret's text is wiped on drop.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    v: u64,
    host_trust_gen: u64,
    secret: Zeroizing<String>,
    #[serde(rename = "pub")]
    public: String,
}

/// What `host_enc_key` holds.
enum Held {
    Missing,
    Key(HostEncKey),
    /// It can't be read, or isn't a key file (why).
    Unreadable(String),
}

fn read_key(store: &Store) -> Held {
    let path = store.path(DlFile::HostEncKey);
    let bytes = match store.read(DlFile::HostEncKey) {
        Ok(None) => return Held::Missing,
        Ok(Some(bytes)) => Zeroizing::new(bytes),
        Err(e) => return Held::Unreadable(format!("cannot read {}: {e}", path.display())),
    };
    let damaged = || Held::Unreadable(format!("{} is damaged", path.display()));
    let Ok(file) = serde_json::from_slice::<KeyFile>(&bytes) else {
        return damaged();
    };
    if file.v != 1 || file.host_trust_gen == 0 {
        return damaged();
    }
    let Some(secret) = atem_client::encoding::b64u_decode(&file.secret)
        .ok()
        .map(Zeroizing::new)
    else {
        return damaged();
    };
    let Ok(secret) = <[u8; 32]>::try_from(secret.as_slice()).map(Zeroizing::new) else {
        return damaged();
    };
    let key = HostEncKey::from_secret(file.host_trust_gen, &secret);
    if b64u(key.enc_pub()) != file.public {
        return damaged();
    }
    Held::Key(key)
}

/// `host_enc_generated` as stored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    v: u64,
    host_trust_gen: u64,
    kids: Vec<String>,
}

/// What `host_enc_generated` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Record {
    Missing,
    /// It can't be read, or isn't a record (why).
    Unreadable(String),
    Of {
        host_trust_gen: u64,
        kids: Vec<[u8; 8]>,
    },
}

fn read_record(store: &Store) -> Record {
    let path = store.path(DlFile::HostEncGenerated);
    let bytes = match store.read(DlFile::HostEncGenerated) {
        Ok(None) => return Record::Missing,
        Ok(Some(bytes)) => bytes,
        Err(e) => return Record::Unreadable(format!("cannot read {}: {e}", path.display())),
    };
    let damaged = || Record::Unreadable(format!("{} is damaged", path.display()));
    let Ok(file) = serde_json::from_slice::<RecordFile>(&bytes) else {
        return damaged();
    };
    let mut kids = Vec::with_capacity(file.kids.len());
    for kid in &file.kids {
        let Ok(kid) = hex_decode_array::<8>(kid) else {
            return damaged();
        };
        if kids.contains(&kid) {
            return damaged();
        }
        kids.push(kid);
    }
    if file.v != 1 || file.host_trust_gen == 0 {
        return damaged();
    }
    Record::Of {
        host_trust_gen: file.host_trust_gen,
        kids,
    }
}

fn record_bytes(host_trust_gen: u64, kids: &[[u8; 8]]) -> Vec<u8> {
    let kids: Vec<String> = kids.iter().map(|k| hex(k)).collect();
    serde_json::json!({"v": 1, "host_trust_gen": host_trust_gen, "kids": kids})
        .to_string()
        .into_bytes()
}

/// What the record held before [`record_kid`] made it list a key's id.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Prior {
    /// It listed it already: nothing was written; the file and its
    /// directory were synced.
    Listed,
    /// The generation's record without it: the id was added.
    Added,
    /// None, one of another generation, or one that can't be read: a new
    /// record with this id only.
    Missing,
    Other(u64),
    Unreadable(String),
}

impl Prior {
    /// Why a record listing a key already held was rebuilt (a runtime.log
    /// line), if it was.
    fn rebuilt(&self, key: &HostEncKey) -> Option<String> {
        let was = match self {
            Prior::Listed => return None,
            Prior::Added => "without its id".to_string(),
            Prior::Missing => "missing".to_string(),
            Prior::Other(generation) => format!("of trust generation {generation}"),
            Prior::Unreadable(why) => format!("unreadable ({why})"),
        };
        Some(format!(
            "the record of keys made was {was}; rebuilt from the key held (enc_kid {}, trust generation {})",
            key.enc_kid(),
            key.host_trust_gen
        ))
    }
}

/// Makes the record of generation `generation` list `kid`, durably (fsync,
/// rename, directory fsync). One that lists it already is synced (the file,
/// then the directory): a record left visible by a failed directory fsync
/// isn't durable yet, and the id must be before a key goes.
fn record_kid(store: &mut Store, generation: u64, kid: [u8; 8]) -> Result<Prior, WriteError> {
    let (prior, mut kids) = match read_record(store) {
        Record::Of {
            host_trust_gen,
            kids,
        } if host_trust_gen == generation => {
            if kids.contains(&kid) {
                store.sync(DlFile::HostEncGenerated)?;
                return Ok(Prior::Listed);
            }
            (Prior::Added, kids)
        }
        Record::Of { host_trust_gen, .. } => (Prior::Other(host_trust_gen), Vec::new()),
        Record::Missing => (Prior::Missing, Vec::new()),
        Record::Unreadable(why) => (Prior::Unreadable(why), Vec::new()),
    };
    kids.push(kid);
    store.replace(DlFile::HostEncGenerated, &record_bytes(generation, &kids))?;
    Ok(prior)
}

/// Makes a new key for `generation`: its id recorded first, then the key
/// file. The caller holds `trust_gen.lock`. What the record held before.
fn make(store: &mut Store, generation: u64) -> Result<(HostEncKey, Prior), WriteError> {
    let (key, secret) = HostEncKey::generate(generation);
    let prior = record_kid(store, generation, key.kid)?;
    store.replace(
        DlFile::HostEncKey,
        &key_bytes(generation, &secret, key.enc_pub()),
    )?;
    Ok((key, prior))
}

/// The line for a key made (`replaced`: the generation of the one it
/// replaced), and for a record it couldn't carry over.
fn made_lines(key: &HostEncKey, replaced: Option<u64>, prior: &Prior) -> Vec<String> {
    let mut lines = vec![match replaced {
        Some(old) => format!(
            "made for trust generation {} (enc_kid {}), replacing the key of trust generation {old}",
            key.host_trust_gen,
            key.enc_kid()
        ),
        None => format!(
            "made for trust generation {} (enc_kid {})",
            key.host_trust_gen,
            key.enc_kid()
        ),
    }];
    if let Prior::Unreadable(why) = prior {
        lines.push(format!(
            "the record of keys made was unreadable ({why}); it now lists this key only"
        ));
    }
    lines
}

/// What a verification ceremony's key is vouched for (host-work-v1 §11.5):
/// the account and genesis `verifyKeys` named, and this host's id and trust
/// generation (`verifyCommit`'s), by the ceremony's new `host_channel_key`.
pub struct Vouch<'a> {
    pub account_id: &'a str,
    pub genesis_hash: &'a Hash32,
    pub host_id: &'a str,
    pub host_trust_gen: u64,
    /// The new `host_channel_key`'s seed (revealed as `host_channel_pub`).
    pub host_seed: &'a [u8; 32],
}

/// A host encryption key made in a verification ceremony (host-work-v1
/// §11.5), after `verifyKeys` and before the reveal: its `enc_sig` by the
/// ceremony's new `host_channel_key`, and its id durably in the record
/// before anything hands it out (only [`make_for_ceremony_locked`] makes
/// one, so a reveal built from it always follows the record). The private
/// key stays here, wiped on drop, until the pin keeps it as
/// `pairing/host_enc_key` ([`keep_at_pin`]).
pub struct CeremonyKey {
    key: HostEncKey,
    secret: Zeroizing<[u8; 32]>,
    host_id: String,
    enc_sig: [u8; 64],
}

impl std::fmt::Debug for CeremonyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeremonyKey")
            .field("key", &self.key)
            .field("host_id", &self.host_id)
            .finish_non_exhaustive()
    }
}

impl CeremonyKey {
    /// `verifyCommit.device_id`: this host's id in the device list.
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// `verifyCommit.host_trust_gen`.
    pub fn host_trust_gen(&self) -> u64 {
        self.key.host_trust_gen
    }

    /// The X25519 public half.
    pub fn enc_pub(&self) -> &[u8; 32] {
        self.key.enc_pub()
    }

    /// Ed25519 by the ceremony's `host_channel_key` over
    /// `enc(["atem-host-enc-key-v1", account_id, genesis_hash, host_id,
    /// u64(host_trust_gen), enc_pub])`.
    pub fn enc_sig(&self) -> &[u8; 64] {
        &self.enc_sig
    }

    /// Its `enc_kid` (16 hex).
    pub fn enc_kid(&self) -> String {
        self.key.enc_kid()
    }
}

#[cfg(test)]
thread_local! {
    /// Tests: the next record write of a ceremony's key that fails.
    pub(crate) static CEREMONY_FAULT: std::cell::Cell<Option<store::Injected>> =
        const { std::cell::Cell::new(None) };
}

/// In a verification ceremony, after `verifyKeys` (host-work-v1 §11.5;
/// `atem pair` and `atem pair verify`, in every build: the reveal carries
/// the key, required): a new key for the ceremony's trust generation, its
/// `enc_sig` by the ceremony's new `host_channel_key` (the shared core's
/// `sign_host_enc_key`), and its id durably in the record (fsync, rename,
/// directory fsync; a record of another generation, or one that can't be
/// read, is replaced by this generation's), before the reveal hands it out.
/// The caller holds `trust_gen.lock`, under the pairing the ceremony runs
/// in. Nothing else is written: the key file only at the pin. `Err`: why
/// (the ceremony aborts before the reveal).
pub fn make_for_ceremony_locked(
    pairing: &PairingPaths,
    vouch: &Vouch<'_>,
) -> Result<CeremonyKey, String> {
    if vouch.host_trust_gen == 0 {
        return Err("no trust generation".into());
    }
    let (key, secret) = HostEncKey::generate(vouch.host_trust_gen);
    let host_key = HostKey::new(vouch.host_seed);
    let enc_sig = sign_host_enc_key(
        &host_key.keys,
        &host_key.id,
        vouch.account_id,
        vouch.genesis_hash,
        vouch.host_id,
        vouch.host_trust_gen,
        key.enc_pub(),
    )
    .map_err(|e| format!("cannot sign it: {e}"))?
    .try_into()
    .map_err(|_| "cannot sign it: not a 64-byte signature".to_string())?;
    let mut store = Store::new(pairing, &journal_of(pairing));
    #[cfg(test)]
    if let Some(fault) = CEREMONY_FAULT.with(|f| f.take()) {
        store.inject(fault);
    }
    let prior = record_kid(&mut store, vouch.host_trust_gen, key.kid)
        .map_err(|e| format!("cannot record its id: {e}"))?;
    if let Prior::Unreadable(why) = prior {
        eprintln!(
            "atem: host encryption key: the record of keys made was unreadable ({why}); it now lists trust generation {}'s key (enc_kid {}) only",
            vouch.host_trust_gen,
            key.enc_kid()
        );
    }
    Ok(CeremonyKey {
        key,
        secret,
        host_id: vouch.host_id.to_string(),
        enc_sig,
    })
}

/// With the device list's pin (`atem pair` and `atem pair verify`;
/// `MembershipHost::pin_locked`, under `trust_gen.lock`, before the list
/// itself is written): the ceremony's key is kept as `pairing/host_enc_key`
/// for its trust generation, its id in the record first (synced when it
/// lists it already; a record lost or of another generation since the
/// reveal is rebuilt). A write that fails fails the pin. What happened, as
/// runtime.log lines.
pub(crate) fn keep_at_pin(store: &mut Store, key: &CeremonyKey) -> Result<Vec<String>, WriteError> {
    let generation = key.host_trust_gen();
    let prior = record_kid(store, generation, key.key.kid)?;
    store.replace(
        DlFile::HostEncKey,
        &key_bytes(generation, &key.secret, key.enc_pub()),
    )?;
    let mut lines = vec![format!(
        "kept for trust generation {generation} (enc_kid {}), made in the verification",
        key.enc_kid()
    )];
    lines.extend(prior.rebuilt(&key.key));
    Ok(lines)
}

/// At a runtime start, or a reopen of the pinned device list, with the
/// hook's `host.senders` on: the host's key for its trust generation
/// `generation`, made when it holds none (or one of an earlier generation),
/// and its id in the record (a lost record rebuilt). Under `trust_gen.lock`,
/// and only while the list is still pinned (an `atem unpair` racing it
/// leaves no key behind). What happened, as runtime.log lines.
pub fn ensure(
    pairing: &PairingPaths,
    journal_dir: &std::path::Path,
    generation: u64,
) -> Vec<String> {
    let mut store = Store::new(pairing, journal_dir);
    ensure_with(&mut store, pairing, generation)
}

pub(crate) fn ensure_with(
    store: &mut Store,
    pairing: &PairingPaths,
    generation: u64,
) -> Vec<String> {
    // Pinned, checked first without the lock (whose file a host without a
    // list never gets from here), then again under it.
    let pinned = || store::present(&pairing.membership) && generation > 0;
    if !pinned() {
        return Vec::new();
    }
    let _lock = match store.lock() {
        Ok(lock) => lock,
        Err(e) => return vec![format!("not checked: {e:#}")],
    };
    if !pinned() {
        return Vec::new();
    }
    let replaced = match read_key(store) {
        Held::Key(key) if key.host_trust_gen == generation => {
            return match record_kid(store, generation, key.kid) {
                Ok(prior) => prior.rebuilt(&key).into_iter().collect(),
                Err(e) => vec![format!("cannot record the id of the key held: {e}")],
            };
        }
        Held::Key(key) if key.host_trust_gen > generation => {
            return vec![format!(
                "{} is of trust generation {}, beyond this host's {generation}; none is handed out",
                pairing.host_enc_key.display(),
                key.host_trust_gen
            )];
        }
        Held::Key(key) => Some(key.host_trust_gen),
        Held::Missing => None,
        Held::Unreadable(why) => {
            return vec![format!(
                "{why}; none is handed out (move it aside and restart the runtime to make a new one)"
            )];
        }
    };
    match make(store, generation) {
        Ok((key, prior)) => made_lines(&key, replaced, &prior),
        Err(e) => vec![format!("cannot make it: {e}")],
    }
}

/// What `host_enc_key_get` hands out at `generation` (the welcome's trust
/// generation): the key the host holds for it, its id durably in the
/// record first, and `enc_sig` by the host's `host_channel_key` over the
/// key at this list's account and genesis for `host_id`. Nothing is made.
/// `Err`: why none is handed out (the op answers `busy`,
/// [`DETAIL_UNAVAILABLE`]). The line says a record was rebuilt.
pub(super) fn hand_out(
    store: &mut Store,
    pairing: &PairingPaths,
    m: &Membership,
    host_key: &HostKey,
    host_id: &str,
    generation: u64,
) -> Result<(HostEncKey, Vec<u8>, Option<String>), String> {
    let _lock = store.lock().map_err(|e| format!("{e:#}"))?;
    if !store::present(&pairing.membership) {
        return Err("the device list is gone".into());
    }
    let key = match read_key(store) {
        Held::Key(key) if key.host_trust_gen == generation => key,
        Held::Key(key) => {
            return Err(format!(
                "the key held is of trust generation {}, not {generation}",
                key.host_trust_gen
            ));
        }
        Held::Missing => return Err(format!("no key for trust generation {generation}")),
        Held::Unreadable(why) => return Err(why),
    };
    let prior = record_kid(store, generation, key.kid)
        .map_err(|e| format!("cannot record the key's id: {e}"))?;
    let sig = sign_host_enc_key(
        &host_key.keys,
        &host_key.id,
        m.account_id(),
        &m.genesis_hash(),
        host_id,
        generation,
        key.enc_pub(),
    )
    .map_err(|e| format!("cannot sign it: {e}"))?;
    let line = prior.rebuilt(&key);
    Ok((key, sig, line))
}

/// This host as the receiver of host-sender mail (design II.4.2;
/// host-work-v1 §11.5), for the receiving side of host senders (nothing
/// calls it yet): the [`Recipient`] and the provider behind its keys.
#[cfg_attr(not(test), allow(dead_code))]
pub struct HostRecipient {
    pub recipient: Recipient,
    pub provider: SoftwareKeys,
}

/// This host as the receiver of host-sender mail at its current trust
/// generation: its `host_id` (the device id its pairing was verified with)
/// and `host_trust_gen` from its own pairing (`pairing/trust_gen`, as
/// `pairing::load` reads it), never from its device list, which may lag
/// behind its own new `add_host`; `keys` the generation's private key (none
/// when the key held is of another generation, or there is none);
/// `generated` the record's ids for the generation (none for a record of
/// another generation or one that can't be read: the key held still counts
/// as made). `Err` for a profile that isn't paired and verified.
#[cfg_attr(not(test), allow(dead_code))]
pub fn recipient(src: &crate::profile::Sources) -> Result<HostRecipient, String> {
    let state = crate::pairing::load(src).map_err(|e| format!("{e:#}"))?;
    let binding = state.binding.ok_or("not paired")?;
    let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)
        .map_err(|e| format!("{e:#}"))?;
    let host_id = trust
        .verified(&binding.astation_id)
        .map(|entry| entry.device_id.clone())
        .ok_or("this device isn't verified")?;
    let generation = state.host_trust_gen;
    let store = Store::new(&src.paths.pairing, &journal_of(&src.paths.pairing));
    let (keys, provider) = match read_key(&store) {
        Held::Key(key) if key.host_trust_gen == generation => {
            (vec![(HostEncKey::key_id(), key.kid)], key.keys)
        }
        _ => (Vec::new(), SoftwareKeys::new()),
    };
    let generated = match read_record(&store) {
        Record::Of {
            host_trust_gen,
            kids,
        } if host_trust_gen == generation => kids,
        _ => Vec::new(),
    };
    Ok(HostRecipient {
        recipient: Recipient {
            host_id,
            host_trust_gen: generation,
            keys,
            generated,
        },
        provider,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key file's bytes are built in one buffer of their exact size:
    /// no reallocation leaves an unwiped copy of the secret's text behind,
    /// whatever the generation's digits.
    #[test]
    fn the_key_files_bytes_fit_their_buffer() {
        for generation in [1, 42, u64::MAX] {
            let bytes = key_bytes(generation, &[1; 32], &[2; 32]);
            assert_eq!(bytes.capacity(), bytes.len(), "{generation}");
            let file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(file["host_trust_gen"], generation);
        }
    }
}

//! The host encryption key (delegated host-work design II.4.1, option (b);
//! session-v1 R9.14 item 8; host-work-v1 §11.5, "The recipient's keys"), on
//! the host, behind the debug-only hook's `host.senders`: the X25519 keys
//! other hosts seal host-sender mail to, the record of every key id this
//! host made at its trust generation and of those it retired, what
//! `host_enc_key_get` and `host_enc_key_new` answer a native manager, the
//! routine rotation (agreed with Astation on 2026-11-23, #120 comment
//! 7089435308), and this host as the receiver of that mail. With the hook
//! off nothing here runs: no file is made and both ops keep their refusal.
//!
//! ```text
//! <profile>/pairing/host_enc_key        {"v":2,"host_trust_gen":N,
//!                                         "current":{"secret":"<b64u>","pub":"<b64u>"},
//!                                         "pending":{"secret":…,"pub":…,
//!                                                    "applied":{"seq":S,"hash":"<64 hex>","d_ms":D}},
//!                                         "previous":{"secret":…,"pub":…,
//!                                                     "replaced_at_seq":S,"applied_d_ms":D}}
//! <profile>/pairing/host_enc_generated  {"v":2,"host_trust_gen":N,"kids":["<16 hex>",…],
//!                                         "retired":["<16 hex>",…]}
//! ```
//!
//! Each slot of the key file is optional; a v1 file (`{"v":1,
//! "host_trust_gen", "secret", "pub"}`, a current key only) and a v1 record
//! (no `retired`) are read as such and written as v2 at their next change.
//!
//! - **The keys.** Plain, 0600, replaced whole like `host_channel_key`
//!   (`membership::store`: temp, fsync, rename, directory fsync), so a host
//!   whose cred agent is locked still opens its mail. Made with the device
//!   list's pin when a pairing is verified and at `atem pair verify` (the
//!   next generation, beside the new `host_channel_key`), and at a runtime
//!   start (or a reopen of the list) on a pinned host that holds none for
//!   its generation: the **current** key. One of an earlier generation is
//!   replaced then; one that can't be read is left as it is (the ops answer
//!   `busy`, and the start says why). Every pin, a pin taken back and `atem
//!   unpair` delete both files; one left without the list (by a build that
//!   doesn't know them) grants nothing and is no device-list leftover.
//! - **The record.** The `enc_kid` (R9.9's, `atem_client::keys::enc_kid`)
//!   of every key made at the current generation, written (fsync, rename)
//!   before the key file, and checked again before a key is handed out (one
//!   that lists it already is synced, file and directory, first): II.4.2's
//!   receiver refuses for good mail sealed to a key id the host made but
//!   the record lacks. And `retired`: the id of every key whose secret this
//!   host erased, written durably before the erasure, only ever growing in
//!   the generation. A retired id is never accepted and never waits again,
//!   whatever a restored or rolled-back key file holds (no resurrection).
//!   Only the current generation is kept. A lost or unreadable record, or
//!   one of another generation, is rebuilt from the keys the host holds,
//!   with a runtime.log line.
//! - **`host_enc_key_get`** ([`hand_out`]): the current key and its
//!   `enc_sig`, the host vouching for it with its `host_channel_key` (the
//!   shared core's `sign_host_enc_key`). A pure read: nothing is made or
//!   rotated for it; the key's id is recorded first when the record lacks
//!   it, and a failed write is `busy`, nothing handed out.
//! - **`host_enc_key_new`** ([`new_pending`]): the host's one **pending**
//!   key of the generation, made at the first request: a fresh key whose id
//!   is neither in the record nor among the keys the committed list set for
//!   this host since its `add_host` (drawn again otherwise), its id
//!   appended to the record and synced, then the key file written with it
//!   as `pending`; any write that fails is `busy` and hands nothing out.
//!   Every later request, another manager's or a retry after a lost answer,
//!   gets that same key (the key file synced first). It is kept, with no
//!   expiry, until an entry sets it or its generation goes; while an entry
//!   the list committed sets it and it isn't promoted yet, a request is
//!   `busy`.
//! - **The stamp** ([`stamp_application_locked`], the device list's commit
//!   watch): just before the list writes a commit whose newest
//!   `host_enc_key` entry for this host sets the pending key, the delegated
//!   clock's `D` (the start view's latest reading, at or before the
//!   commit) is written into the pending key with that entry's `seq` and
//!   hash, durably: the evidence of when the host applied it. A stamp is
//!   written once per entry; a later commit of the same entry keeps it.
//! - **The promotion and retirement** ([`reconcile`]; the bridge runs it on
//!   every pass where the list moved or a deadline is due, and before
//!   building the receiver's view, so before any mail is opened): the
//!   committed list rules. When its current key is the pending one, one
//!   atomic replace makes it current; the old current key becomes the
//!   **previous** key, opening mail until `D` reaches the stamp's `D` plus
//!   24 h ([`RETAIN_MS`]), when the list keeps it as its previous key, not
//!   retired, and the stamp names the entry the list holds; otherwise (a
//!   `retire_previous`, no stamp, a stamp naming another entry) it is erased
//!   at once: a crash between the list's commit and the promotion never
//!   restarts or lengthens the window, and when its start can't be
//!   established the old key is retired at once. An older previous key goes
//!   (one previous only). The previous key is erased at its deadline, when
//!   `D` reads below its application time (the window can't be
//!   established), and whenever the list no longer keeps it. A key the list
//!   set and moved away from is erased; every key of a generation the list
//!   voided (a newer `add_host`, a `remove_host`) is erased, the pending key
//!   included. Each erasure writes the ids to `retired` first, then the key
//!   file.
//! - **The receiver's view** ([`recipient_at`]): this host's id and
//!   pairing generation; the accepted keys are the committed list's current
//!   key, and its previous key while the list doesn't retire it and its
//!   window is open on `D`, each only if held and not retired; a pending or
//!   otherwise generated key is never accepted (mail naming it waits for
//!   the list beyond its head). `generated` is the record's ids and the
//!   keys held, less the retired ones.
//!
//! Static-key HPKE: a rotation gives no forward secrecy across a key
//! compromise; `retire_previous` stops new exposure only (design VI).
use atem_client::encoding::{Hash32, b64u, b64u_decode, hex, hex_decode_array};
use atem_client::host_mail::Recipient;
use atem_client::keys::enc_kid_bytes;
use atem_client::membership::{Membership, sign_host_enc_key};
use atem_client::{Alg, KeyId, PublicKey, SoftwareKeys};
use rand::RngCore;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::HostKey;
use crate::paths::PairingPaths;
use crate::session_protocol::membership::journal_of;
use crate::session_protocol::membership::store::{self, DlFile, Store, WriteError};

/// `busy` detail of `host_enc_key_get` and `host_enc_key_new` (session-v1
/// R9.14 item 8): the host holds no key to hand out (none made, the file
/// can't be read, the new key's entry is being applied), or couldn't
/// record or write it before handing it out.
pub const DETAIL_UNAVAILABLE: &str = "host encryption key unavailable";

/// How long a routine rotation's previous key still opens mail, on the
/// delegated clock from when the host applied the entry (II.4.1).
pub const RETAIN_MS: u64 = 24 * 3_600_000;

/// The key's name behind its provider: the current key.
const KEY_NAME: &str = "host_enc_key";
/// The previous key's, in the receiver's provider.
const PREVIOUS_NAME: &str = "host_enc_key.previous";

/// A host encryption key, as handed out: its generation, its public half
/// and id (the secret stays in the key file).
pub struct HostEncKey {
    pub host_trust_gen: u64,
    /// X25519.
    pub public: PublicKey,
    /// Its `enc_kid` (8 bytes; the hex is the 16-character id).
    pub kid: [u8; 8],
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
    /// The name of the current key in the receiver's provider.
    pub fn key_id() -> KeyId {
        KeyId::new(KEY_NAME)
    }

    /// The name of the previous key in the receiver's provider.
    pub fn previous_key_id() -> KeyId {
        KeyId::new(PREVIOUS_NAME)
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

// ── The key file ──

/// One key the file holds: its secret (wiped on drop), public half and id.
struct Slot {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    kid: [u8; 8],
}

impl Slot {
    fn of(secret: Zeroizing<[u8; 32]>) -> Slot {
        let public =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).as_bytes();
        let key = PublicKey::new(Alg::X25519, &public).expect("32 bytes");
        Slot {
            secret,
            kid: enc_kid_bytes(&key).expect("an X25519 key has an enc_kid"),
            public,
        }
    }

    fn key(&self, generation: u64) -> HostEncKey {
        HostEncKey {
            host_trust_gen: generation,
            public: self.public_key(),
            kid: self.kid,
        }
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::new(Alg::X25519, &self.public).expect("32 bytes")
    }
}

/// When the host applied the entry that sets a pending key: that entry's
/// `seq` and hash, and the delegated clock's `D` written before the list
/// committed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Applied {
    seq: u64,
    hash: Hash32,
    d_ms: u64,
}

struct Pending {
    slot: Slot,
    applied: Option<Applied>,
}

/// A routine rotation's previous key: the `seq` of the entry that replaced
/// it, and `D` when the host applied that entry (its window ends
/// [`RETAIN_MS`] later).
struct Previous {
    slot: Slot,
    replaced_at_seq: u64,
    applied_d_ms: u64,
}

impl Previous {
    fn retire_at(&self) -> u64 {
        self.applied_d_ms.saturating_add(RETAIN_MS)
    }

    /// Its window, at `D` = `now`: open, or over (passed, or `D` below the
    /// application time, when it can't be established).
    fn open_at(&self, now: u64) -> bool {
        (self.applied_d_ms..self.retire_at()).contains(&now)
    }
}

/// The key file: a generation's keys.
struct Ring {
    generation: u64,
    current: Option<Slot>,
    pending: Option<Pending>,
    previous: Option<Previous>,
}

impl Ring {
    fn new(generation: u64) -> Ring {
        Ring {
            generation,
            current: None,
            pending: None,
            previous: None,
        }
    }

    /// Every key held, current, pending, previous.
    fn held(&self) -> Vec<&Slot> {
        self.current
            .iter()
            .chain(self.pending.iter().map(|p| &p.slot))
            .chain(self.previous.iter().map(|p| &p.slot))
            .collect()
    }

    fn held_kids(&self) -> Vec<[u8; 8]> {
        self.held().iter().map(|s| s.kid).collect()
    }
}

/// The file's bytes, in one buffer of its exact size: every copy of a
/// secret's text made here is wiped (base64url needs no JSON escaping).
fn ring_bytes(ring: &Ring) -> Zeroizing<Vec<u8>> {
    let mut parts: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let plain = |s: String| Zeroizing::new(s.into_bytes());
    let secret = |slot: &Slot| Zeroizing::new(b64u(&*slot.secret).into_bytes());
    parts.push(plain(format!(
        r#"{{"v":2,"host_trust_gen":{}"#,
        ring.generation
    )));
    let slot_head = |parts: &mut Vec<Zeroizing<Vec<u8>>>, name: &str, slot: &Slot| {
        parts.push(plain(format!(r#","{name}":{{"secret":""#)));
        parts.push(secret(slot));
        parts.push(plain(format!(r#"","pub":"{}""#, b64u(&slot.public))));
    };
    if let Some(slot) = &ring.current {
        slot_head(&mut parts, "current", slot);
        parts.push(plain("}".into()));
    }
    if let Some(pending) = &ring.pending {
        slot_head(&mut parts, "pending", &pending.slot);
        if let Some(a) = &pending.applied {
            parts.push(plain(format!(
                r#","applied":{{"seq":{},"hash":"{}","d_ms":{}}}"#,
                a.seq,
                a.hash.to_hex(),
                a.d_ms
            )));
        }
        parts.push(plain("}".into()));
    }
    if let Some(previous) = &ring.previous {
        slot_head(&mut parts, "previous", &previous.slot);
        parts.push(plain(format!(
            r#","replaced_at_seq":{},"applied_d_ms":{}}}"#,
            previous.replaced_at_seq, previous.applied_d_ms
        )));
    }
    parts.push(plain("}".into()));
    // Its exact size: the buffer never grows (a reallocation would leave an
    // unwiped copy of a secret's text).
    let len = parts.iter().map(|p| p.len()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for part in &parts {
        out.extend_from_slice(part);
    }
    out
}

/// The version a key file or record names, its other fields skipped.
#[derive(Deserialize)]
struct Version {
    v: u64,
}

/// A v1 key file: the current key only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileV1 {
    #[allow(dead_code)]
    v: u64,
    host_trust_gen: u64,
    secret: Zeroizing<String>,
    #[serde(rename = "pub")]
    public: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotV2 {
    secret: Zeroizing<String>,
    #[serde(rename = "pub")]
    public: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedV2 {
    seq: u64,
    hash: String,
    d_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingV2 {
    secret: Zeroizing<String>,
    #[serde(rename = "pub")]
    public: String,
    applied: Option<AppliedV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousV2 {
    secret: Zeroizing<String>,
    #[serde(rename = "pub")]
    public: String,
    replaced_at_seq: u64,
    applied_d_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileV2 {
    #[allow(dead_code)]
    v: u64,
    host_trust_gen: u64,
    current: Option<SlotV2>,
    pending: Option<PendingV2>,
    previous: Option<PreviousV2>,
}

/// A slot's secret, checked against its public half.
fn slot_of(secret: &str, public: &str) -> Option<Slot> {
    let bytes = Zeroizing::new(b64u_decode(secret).ok()?);
    let secret = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).ok()?);
    let slot = Slot::of(secret);
    (b64u(&slot.public) == public).then_some(slot)
}

/// What `host_enc_key` holds.
enum Held {
    Missing,
    Ring(Box<Ring>),
    /// It can't be read, or isn't a key file (why).
    Unreadable(String),
}

fn read_ring(store: &Store) -> Held {
    let path = store.path(DlFile::HostEncKey);
    let bytes = match store.read(DlFile::HostEncKey) {
        Ok(None) => return Held::Missing,
        Ok(Some(bytes)) => Zeroizing::new(bytes),
        Err(e) => return Held::Unreadable(format!("cannot read {}: {e}", path.display())),
    };
    match parse_ring(&bytes) {
        Some(ring) => Held::Ring(Box::new(ring)),
        None => Held::Unreadable(format!("{} is damaged", path.display())),
    }
}

fn parse_ring(bytes: &[u8]) -> Option<Ring> {
    let version = serde_json::from_slice::<Version>(bytes).ok()?.v;
    let ring = match version {
        1 => {
            let file = serde_json::from_slice::<FileV1>(bytes).ok()?;
            Ring {
                generation: file.host_trust_gen,
                current: Some(slot_of(&file.secret, &file.public)?),
                pending: None,
                previous: None,
            }
        }
        2 => {
            let file = serde_json::from_slice::<FileV2>(bytes).ok()?;
            let current = match &file.current {
                Some(s) => Some(slot_of(&s.secret, &s.public)?),
                None => None,
            };
            let pending = match &file.pending {
                Some(p) => Some(Pending {
                    slot: slot_of(&p.secret, &p.public)?,
                    applied: match &p.applied {
                        Some(a) => Some(Applied {
                            seq: a.seq,
                            hash: Hash32::from_hex(&a.hash).ok()?,
                            d_ms: a.d_ms,
                        }),
                        None => None,
                    },
                }),
                None => None,
            };
            let previous = match &file.previous {
                Some(p) => Some(Previous {
                    slot: slot_of(&p.secret, &p.public)?,
                    replaced_at_seq: p.replaced_at_seq,
                    applied_d_ms: p.applied_d_ms,
                }),
                None => None,
            };
            Ring {
                generation: file.host_trust_gen,
                current,
                pending,
                previous,
            }
        }
        _ => return None,
    };
    let mut kids = ring.held_kids();
    kids.sort();
    kids.dedup();
    (ring.generation > 0 && kids.len() == ring.held().len()).then_some(ring)
}

// ── The record ──

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    v: u64,
    host_trust_gen: u64,
    kids: Vec<String>,
    retired: Option<Vec<String>>,
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
        retired: Vec<[u8; 8]>,
    },
}

impl Record {
    /// The generation's ids made and retired (none for another
    /// generation's record, a missing or unreadable one).
    fn of(&self, generation: u64) -> (Vec<[u8; 8]>, Vec<[u8; 8]>) {
        match self {
            Record::Of {
                host_trust_gen,
                kids,
                retired,
            } if *host_trust_gen == generation => (kids.clone(), retired.clone()),
            _ => (Vec::new(), Vec::new()),
        }
    }
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
    let ids = |list: &[String]| -> Option<Vec<[u8; 8]>> {
        let mut out = Vec::with_capacity(list.len());
        for kid in list {
            let kid = hex_decode_array::<8>(kid).ok()?;
            if out.contains(&kid) {
                return None;
            }
            out.push(kid);
        }
        Some(out)
    };
    let Some(kids) = ids(&file.kids) else {
        return damaged();
    };
    let retired = match (file.v, &file.retired) {
        (1, None) => Vec::new(),
        (2, Some(list)) => match ids(list) {
            Some(retired) => retired,
            None => return damaged(),
        },
        _ => return damaged(),
    };
    if file.host_trust_gen == 0 {
        return damaged();
    }
    Record::Of {
        host_trust_gen: file.host_trust_gen,
        kids,
        retired,
    }
}

fn record_bytes(host_trust_gen: u64, kids: &[[u8; 8]], retired: &[[u8; 8]]) -> Vec<u8> {
    let ids = |l: &[[u8; 8]]| l.iter().map(|k| hex(k)).collect::<Vec<_>>();
    serde_json::json!({"v": 2, "host_trust_gen": host_trust_gen, "kids": ids(kids),
        "retired": ids(retired)})
    .to_string()
    .into_bytes()
}

/// What the record held before [`record_kids`] made it list ids.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Prior {
    /// It listed them already: nothing was written; the file and its
    /// directory were synced.
    Listed,
    /// The generation's record without them: they were added.
    Added,
    /// None, one of another generation, or one that can't be read: a new
    /// record with these ids only.
    Missing,
    Other(u64),
    Unreadable(String),
}

impl Prior {
    /// Why a record listing a key already held was rebuilt (a runtime.log
    /// line), if it was.
    fn rebuilt(&self, kids: &[[u8; 8]], generation: u64) -> Option<String> {
        let was = match self {
            Prior::Listed => return None,
            Prior::Added => "without its id".to_string(),
            Prior::Missing => "missing".to_string(),
            Prior::Other(generation) => format!("of trust generation {generation}"),
            Prior::Unreadable(why) => format!("unreadable ({why})"),
        };
        let ids: Vec<String> = kids.iter().map(|k| hex(k)).collect();
        Some(format!(
            "the record of keys made was {was}; rebuilt from the keys held (enc_kid {}, trust generation {generation})",
            ids.join(", ")
        ))
    }
}

/// Makes the record of generation `generation` list every id in `kids`,
/// durably (fsync, rename, directory fsync), its retired ids kept. One
/// that lists them already is synced (the file, then the directory): a
/// record left visible by a failed directory fsync isn't durable yet, and
/// an id must be before its key goes.
fn record_kids(store: &mut Store, generation: u64, add: &[[u8; 8]]) -> Result<Prior, WriteError> {
    let (prior, mut kids, retired) = match read_record(store) {
        Record::Of {
            host_trust_gen,
            kids,
            retired,
        } if host_trust_gen == generation => {
            if add.iter().all(|k| kids.contains(k)) {
                store.sync(DlFile::HostEncGenerated)?;
                return Ok(Prior::Listed);
            }
            (Prior::Added, kids, retired)
        }
        Record::Of { host_trust_gen, .. } => (Prior::Other(host_trust_gen), Vec::new(), Vec::new()),
        Record::Missing => (Prior::Missing, Vec::new(), Vec::new()),
        Record::Unreadable(why) => (Prior::Unreadable(why), Vec::new(), Vec::new()),
    };
    for kid in add {
        if !kids.contains(kid) {
            kids.push(*kid);
        }
    }
    store.replace(
        DlFile::HostEncGenerated,
        &record_bytes(generation, &kids, &retired),
    )?;
    Ok(prior)
}

/// Makes the record of generation `generation` list every id in `ids` as
/// retired (and made), durably, before their secrets are erased: from then
/// on none of them is accepted, whatever the key file holds. Only grows.
fn retire_kids(store: &mut Store, generation: u64, ids: &[[u8; 8]]) -> Result<(), WriteError> {
    let (mut kids, mut retired) = match read_record(store) {
        Record::Of {
            host_trust_gen,
            kids,
            retired,
        } if host_trust_gen == generation => {
            if ids.iter().all(|k| retired.contains(k)) {
                return store.sync(DlFile::HostEncGenerated);
            }
            (kids, retired)
        }
        _ => (Vec::new(), Vec::new()),
    };
    for kid in ids {
        if !kids.contains(kid) {
            kids.push(*kid);
        }
        if !retired.contains(kid) {
            retired.push(*kid);
        }
    }
    store.replace(
        DlFile::HostEncGenerated,
        &record_bytes(generation, &kids, &retired),
    )
}

// ── Making keys ──

#[cfg(test)]
thread_local! {
    /// Tests: the secrets the next draws take, in order (then random).
    pub(crate) static DRAWS: std::cell::RefCell<std::collections::VecDeque<[u8; 32]>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

/// A new random secret.
fn draw() -> Zeroizing<[u8; 32]> {
    #[cfg(test)]
    if let Some(secret) = DRAWS.with(|d| d.borrow_mut().pop_front()) {
        return Zeroizing::new(secret);
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(secret.as_mut());
    secret
}

/// Makes a new current key for `generation`: its id recorded first, then
/// the key file (any key of another generation replaced). The caller holds
/// `trust_gen.lock`. The key and what the record held before.
fn make(store: &mut Store, generation: u64) -> Result<(HostEncKey, Prior), WriteError> {
    let slot = Slot::of(draw());
    let prior = record_kids(store, generation, &[slot.kid])?;
    let key = slot.key(generation);
    let mut ring = Ring::new(generation);
    ring.current = Some(slot);
    store.replace(DlFile::HostEncKey, &ring_bytes(&ring))?;
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

/// With the device list's pin (`atem pair` and `atem pair verify`; the
/// caller holds `trust_gen.lock` and just pinned the list, which removed
/// any earlier key and record): the key of the pin's `generation`, beside
/// its new `host_channel_key`. What happened, as runtime.log lines.
pub fn make_at_pin_locked(pairing: &PairingPaths, generation: u64) -> Result<Vec<String>, String> {
    let mut store = Store::new(pairing, &journal_of(pairing));
    #[cfg(test)]
    if let Some(fault) = PIN_FAULT.with(|f| f.take()) {
        store.inject(fault);
    }
    let (key, prior) = make(&mut store, generation).map_err(|e| format!("cannot make it: {e}"))?;
    Ok(made_lines(&key, None, &prior))
}

#[cfg(test)]
thread_local! {
    /// Tests: the next write at a pin that fails.
    pub(crate) static PIN_FAULT: std::cell::Cell<Option<store::Injected>> =
        const { std::cell::Cell::new(None) };
}

/// At a runtime start, or a reopen of the pinned device list, with the
/// hook's `host.senders` on: the host's key for its trust generation
/// `generation`, made when it holds none (or one of an earlier generation),
/// and the ids of the keys it holds in the record (a lost record rebuilt).
/// Under `trust_gen.lock`, and only while the list is still pinned (an
/// `atem unpair` racing it leaves no key behind). What happened, as
/// runtime.log lines.
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
    let replaced = match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => {
            let held = ring.held_kids();
            if held.is_empty() {
                // Every key of the generation erased (the list voided it, or
                // moved away from them): a manager asks for a new one.
                return Vec::new();
            }
            return match record_kids(store, generation, &held) {
                Ok(prior) => prior.rebuilt(&held, generation).into_iter().collect(),
                Err(e) => vec![format!("cannot record the ids of the keys held: {e}")],
            };
        }
        Held::Ring(ring) if ring.generation > generation => {
            return vec![format!(
                "{} is of trust generation {}, beyond this host's {generation}; none is handed out",
                pairing.host_enc_key.display(),
                ring.generation
            )];
        }
        Held::Ring(ring) => Some(ring.generation),
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

/// The key file of `generation` under the lock, or why there is none to
/// hand out.
fn ring_of(store: &Store, generation: u64) -> Result<Ring, String> {
    match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => Ok(*ring),
        Held::Ring(ring) => Err(format!(
            "the key held is of trust generation {}, not {generation}",
            ring.generation
        )),
        Held::Missing => Err(format!("no key for trust generation {generation}")),
        Held::Unreadable(why) => Err(why),
    }
}

/// `enc_sig`: the host's `host_channel_key` over `key` at `m`'s account and
/// genesis for `host_id` at `generation`.
fn vouch(
    m: &Membership,
    host_key: &HostKey,
    host_id: &str,
    generation: u64,
    key: &HostEncKey,
) -> Result<Vec<u8>, String> {
    sign_host_enc_key(
        &host_key.keys,
        &host_key.id,
        m.account_id(),
        &m.genesis_hash(),
        host_id,
        generation,
        key.enc_pub(),
    )
    .map_err(|e| format!("cannot sign it: {e}"))
}

/// What `host_enc_key_get` hands out at `generation` (the welcome's trust
/// generation): the current key the host holds for it, its id durably in
/// the record first, and `enc_sig` by the host's `host_channel_key` over
/// the key at this list's account and genesis for `host_id`. Nothing is
/// made. `Err`: why none is handed out (the op answers `busy`,
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
    let ring = ring_of(store, generation)?;
    let Some(current) = &ring.current else {
        return Err(format!(
            "no current key for trust generation {generation} (ask for a new one)"
        ));
    };
    let (_, retired) = read_record(store).of(generation);
    if retired.contains(&current.kid) {
        return Err(format!("the current key {} is retired", hex(&current.kid)));
    }
    let prior = record_kids(store, generation, &[current.kid])
        .map_err(|e| format!("cannot record the key's id: {e}"))?;
    let key = current.key(generation);
    let sig = vouch(m, host_key, host_id, generation, &key)?;
    let line = prior.rebuilt(&[current.kid], generation);
    Ok((key, sig, line))
}

/// What `host_enc_key_new` hands out at `generation` (the routine rotation):
/// the generation's pending key and its `enc_sig`. The first request makes
/// it: a fresh key whose id is in neither the record (made or retired) nor
/// the keys the committed list `m` set for `host_id` since its `add_host`
/// (drawn again otherwise), its id appended to the record and synced, then
/// the key file written with it pending. A later request gets the same key,
/// the key file and record synced first. `Err`: why none is handed out
/// (`busy`, [`DETAIL_UNAVAILABLE`]): a write that failed, a key file that
/// can't be read, or a pending key an entry of `m` already set (its
/// promotion is due). The lines say what was made and a record rebuilt.
pub(crate) fn new_pending(
    store: &mut Store,
    pairing: &PairingPaths,
    m: &Membership,
    host_key: &HostKey,
    host_id: &str,
    generation: u64,
) -> Result<(HostEncKey, Vec<u8>, Vec<String>), String> {
    let _lock = store.lock().map_err(|e| format!("{e:#}"))?;
    if !store::present(&pairing.membership) || generation == 0 {
        return Err("the device list is gone".into());
    }
    let mut ring = match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => *ring,
        Held::Missing => Ring::new(generation),
        Held::Ring(ring) => {
            return Err(format!(
                "the key held is of trust generation {}, not {generation}",
                ring.generation
            ));
        }
        Held::Unreadable(why) => return Err(why),
    };
    let (made, retired) = read_record(store).of(generation);
    if let Some(pending) = &ring.pending {
        if m.host_enc_key_set_before(host_id, &pending.slot.public_key()) {
            return Err(format!(
                "the pending key {} is set by the device list and not yet promoted; ask again",
                hex(&pending.slot.kid)
            ));
        }
        if retired.contains(&pending.slot.kid) {
            return Err(format!(
                "the pending key {} is retired",
                hex(&pending.slot.kid)
            ));
        }
        // A retry after a lost answer, or another manager: the same key,
        // durable before it goes again (a write whose directory fsync
        // failed is visible, not yet durable).
        let prior = record_kids(store, generation, &[pending.slot.kid])
            .map_err(|e| format!("cannot record the key's id: {e}"))?;
        store
            .sync(DlFile::HostEncKey)
            .map_err(|e| format!("cannot sync the key file: {e}"))?;
        let key = pending.slot.key(generation);
        let sig = vouch(m, host_key, host_id, generation, &key)?;
        return Ok((
            key,
            sig,
            prior
                .rebuilt(&[pending.slot.kid], generation)
                .into_iter()
                .collect(),
        ));
    }
    let held = ring.held_kids();
    let fresh = |slot: &Slot| {
        !made.contains(&slot.kid)
            && !retired.contains(&slot.kid)
            && !held.contains(&slot.kid)
            && !m.host_enc_key_set_before(host_id, &slot.public_key())
    };
    let slot = (0..16)
        .map(|_| Slot::of(draw()))
        .find(fresh)
        .ok_or("no fresh key drawn")?;
    let prior = record_kids(store, generation, &[slot.kid])
        .map_err(|e| format!("cannot record the new key's id: {e}"))?;
    let key = slot.key(generation);
    ring.pending = Some(Pending {
        slot,
        applied: None,
    });
    store
        .replace(DlFile::HostEncKey, &ring_bytes(&ring))
        .map_err(|e| format!("cannot write the new key: {e}"))?;
    let sig = vouch(m, host_key, host_id, generation, &key)?;
    let mut lines = vec![format!(
        "made a pending key for trust generation {generation} (enc_kid {}) for a manager's rotation",
        key.enc_kid()
    )];
    if let Prior::Unreadable(why) = prior {
        lines.push(format!(
            "the record of keys made was unreadable ({why}); it now lists this key only"
        ));
    }
    Ok((key, sig, lines))
}

/// The newest `host_enc_key` entry `m` holds for `host_id` at `generation`:
/// the key it set and its `seq`.
fn current_entry(m: &Membership, host_id: &str, generation: u64) -> Option<([u8; 8], u64)> {
    m.host_enc_key(host_id)
        .filter(|k| k.current.host_trust_gen == generation)
        .map(|k| (k.current.kid, k.current.seq))
}

/// The device list's commit watch (the caller, the list's commit, holds
/// `trust_gen.lock`): just before `next` is written over `prev`, when
/// `next`'s newest `host_enc_key` entry for `host_id` at `generation` is a
/// new one and sets the key file's pending key, `now_d` (the delegated
/// clock's `D`, read at or before this commit) is written into the pending
/// key with that entry's `seq` and hash, durably (one atomic replace): the
/// evidence of when the host applied it. A stamp already naming that entry
/// is kept (a commit of the same entry again never moves it later). No
/// `D`, or a write that fails: no stamp, and the promotion retires the
/// previous key at once. What happened, as runtime.log lines.
pub fn stamp_application_locked(
    store: &mut Store,
    prev: &Membership,
    next: &Membership,
    host_id: &str,
    generation: u64,
    now_d: Option<u64>,
) -> Vec<String> {
    let Some((kid, seq)) = current_entry(next, host_id, generation) else {
        return Vec::new();
    };
    if current_entry(prev, host_id, generation).is_some_and(|(_, before)| before == seq) {
        return Vec::new();
    }
    let Some(hash) = next.entry_hash_at(seq) else {
        return Vec::new();
    };
    let Held::Ring(mut ring) = read_ring(store) else {
        return Vec::new();
    };
    if ring.generation != generation {
        return Vec::new();
    }
    let Some(pending) = ring.pending.as_mut().filter(|p| p.slot.kid == kid) else {
        return Vec::new();
    };
    if pending
        .applied
        .is_some_and(|a| a.seq == seq && a.hash == hash)
    {
        return Vec::new();
    }
    let Some(d_ms) = now_d else {
        return vec![format!(
            "the entry at seq {seq} sets the pending key {}, and the delegated clock has no reading: its application time isn't recorded, so the previous key will be retired at once",
            hex(&kid)
        )];
    };
    pending.applied = Some(Applied { seq, hash, d_ms });
    match store.replace(DlFile::HostEncKey, &ring_bytes(&ring)) {
        Ok(()) => Vec::new(),
        Err(e) => vec![format!(
            "the application time of the entry at seq {seq} couldn't be recorded ({e}); the previous key will be retired at once"
        )],
    }
}

// ── Promotion and retirement ──

/// What [`reconcile`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// The key file changed: a promotion or an erasure (the keys this host
    /// accepts may have changed: waiting mail is judged again).
    pub changed: bool,
    /// When the previous key's window ends, on `D` (none: no previous key).
    pub retire_at: Option<u64>,
    /// What happened, as runtime.log lines.
    pub lines: Vec<String>,
}

/// Where the committed list stands on this host's generation.
enum Standing<'a> {
    /// The host's `add_host` at this generation: its keys, if any entry set
    /// one.
    Current(Option<&'a atem_client::membership::HostEncKeys>),
    /// A newer `add_host`, or a `remove_host` at or after this generation:
    /// no key of this generation is ever accepted again.
    Voided,
    /// The list is behind this host's own generation (its new `add_host`
    /// not applied yet): nothing to judge.
    Behind,
}

fn standing<'a>(m: &'a Membership, host_id: &str, generation: u64) -> Standing<'a> {
    match m.host(host_id) {
        Some(h) if h.host_trust_gen == generation => Standing::Current(m.host_enc_key(host_id)),
        Some(h) if h.host_trust_gen > generation => Standing::Voided,
        Some(_) => Standing::Behind,
        None => match m.removed_host(host_id) {
            Some(h) if h.host_trust_gen >= generation => Standing::Voided,
            _ => Standing::Behind,
        },
    }
}

/// The key file brought to what the committed list `m` says (see the
/// module doc), at `D` = `now_d` (none: no deadline is judged, nothing is
/// erased for the time), under `trust_gen.lock`. The ids of erased keys go
/// to the record's `retired` first, synced; then one atomic replace of the
/// key file. `Err`: a file that can't be read or a write that failed
/// (nothing is decided on such a state: the caller opens no mail).
pub fn reconcile(
    pairing: &PairingPaths,
    host_id: &str,
    generation: u64,
    m: &Membership,
    now_d: Option<u64>,
) -> Result<Reconciled, String> {
    let mut store = Store::new(pairing, &journal_of(pairing));
    reconcile_with(&mut store, host_id, generation, m, now_d)
}

pub(crate) fn reconcile_with(
    store: &mut Store,
    host_id: &str,
    generation: u64,
    m: &Membership,
    now_d: Option<u64>,
) -> Result<Reconciled, String> {
    let _lock = store.lock().map_err(|e| format!("{e:#}"))?;
    reconcile_locked(store, host_id, generation, m, now_d)
}

fn reconcile_locked(
    store: &mut Store,
    host_id: &str,
    generation: u64,
    m: &Membership,
    now_d: Option<u64>,
) -> Result<Reconciled, String> {
    let mut ring = match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => ring,
        // Another generation's file is `ensure`'s; none is nothing to do.
        Held::Ring(_) | Held::Missing => return Ok(Reconciled::default()),
        Held::Unreadable(why) => return Err(why),
    };
    // A record that can't be read, is missing or of another generation is
    // rebuilt from the keys held (below), its retired ids lost: the keys a
    // retirement cut short then go by the list's rules alone (the list no
    // longer keeps a key retired early, and the windows are absolute).
    let record = read_record(store);
    let rebuild = match &record {
        Record::Of { host_trust_gen, .. } if *host_trust_gen == generation => None,
        Record::Of { host_trust_gen, .. } => Some(format!("of trust generation {host_trust_gen}")),
        Record::Missing => Some("missing".to_string()),
        Record::Unreadable(why) => Some(format!("unreadable ({why})")),
    };
    let (_, retired) = record.of(generation);
    let mut erase: Vec<[u8; 8]> = Vec::new();
    let mut lines = Vec::new();
    let mut changed = false;
    // A key whose id is retired (a retirement cut short, a rolled-back
    // file) is erased whatever else holds.
    let gone = |slot: &Slot| retired.contains(&slot.kid);
    if ring.current.as_ref().is_some_and(gone) {
        erase.push(ring.current.take().unwrap().kid);
    }
    if ring.pending.as_ref().is_some_and(|p| gone(&p.slot)) {
        erase.push(ring.pending.take().unwrap().slot.kid);
    }
    if ring.previous.as_ref().is_some_and(|p| gone(&p.slot)) {
        erase.push(ring.previous.take().unwrap().slot.kid);
    }
    match standing(m, host_id, generation) {
        Standing::Behind => {}
        Standing::Voided => {
            for slot in [
                ring.current.take(),
                ring.pending.take().map(|p| p.slot),
                ring.previous.take().map(|p| p.slot),
            ]
            .into_iter()
            .flatten()
            {
                lines.push(format!(
                    "{} retired: the device list voided trust generation {generation}",
                    hex(&slot.kid)
                ));
                erase.push(slot.kid);
            }
        }
        Standing::Current(keys) => {
            let set = |slot: &Slot| m.host_enc_key_set_before(host_id, &slot.public_key());
            let list_current = keys.map(|k| (k.current.kid, k.current.seq));
            let list_previous = keys.and_then(|k| k.previous.as_ref());
            // The promotion: the list's current key is the pending one.
            if let Some((kid, seq)) = list_current
                && ring.pending.as_ref().is_some_and(|p| p.slot.kid == kid)
            {
                let pending = ring.pending.take().unwrap();
                changed = true;
                lines.push(format!(
                    "{} promoted: the entry at seq {seq} set it",
                    hex(&kid)
                ));
                if let Some(old) = ring.previous.take() {
                    lines.push(format!(
                        "{} retired: a newer rotation replaced it (one previous key only)",
                        hex(&old.slot.kid)
                    ));
                    erase.push(old.slot.kid);
                }
                if let Some(old) = ring.current.take() {
                    let kept = list_previous.is_some_and(|p| p.key.kid == old.kid);
                    let retiring = list_previous.is_some_and(|p| p.retired);
                    let stamp = pending
                        .applied
                        .filter(|a| a.seq == seq && m.entry_hash_at(seq) == Some(a.hash));
                    match stamp {
                        Some(stamp) if kept && !retiring => {
                            ring.previous = Some(Previous {
                                slot: old,
                                replaced_at_seq: seq,
                                applied_d_ms: stamp.d_ms,
                            });
                        }
                        _ => {
                            let why = if retiring {
                                "the entry retires it (retire_previous)"
                            } else if !kept {
                                "the device list keeps no window for it"
                            } else {
                                "the entry's application time isn't known (no stamp before the commit)"
                            };
                            lines.push(format!("{} retired at once: {why}", hex(&old.kid)));
                            erase.push(old.kid);
                        }
                    }
                }
                ring.current = Some(pending.slot);
            }
            // The current key: the list's, or a key no entry set yet; one
            // the list set and moved away from is dead.
            if let Some(current) = &ring.current
                && list_current.is_none_or(|(kid, _)| kid != current.kid)
                && set(current)
            {
                lines.push(format!(
                    "{} retired: the device list moved away from it",
                    hex(&current.kid)
                ));
                erase.push(ring.current.take().unwrap().kid);
            }
            // A pending key some entry set (and not the current one): it
            // can never be set again.
            if let Some(pending) = &ring.pending
                && set(&pending.slot)
            {
                lines.push(format!(
                    "{} retired: the device list set it and moved away from it",
                    hex(&pending.slot.kid)
                ));
                erase.push(ring.pending.take().unwrap().slot.kid);
            }
            // The previous key: kept while the list keeps it, not retired,
            // and its window is open on `D`.
            if let Some(previous) = &ring.previous {
                let listed = list_previous.is_some_and(|p| {
                    p.key.kid == previous.slot.kid
                        && !p.retired
                        && p.replaced_at_seq == previous.replaced_at_seq
                });
                let why = if !listed {
                    Some("the device list no longer keeps it".to_string())
                } else {
                    now_d.filter(|now| !previous.open_at(*now)).map(|now| {
                        if now < previous.applied_d_ms {
                            "the delegated clock reads below its application; its window can't be established".to_string()
                        } else {
                            "its 24 h window ended".to_string()
                        }
                    })
                };
                if let Some(why) = why {
                    lines.push(format!("{} retired: {why}", hex(&previous.slot.kid)));
                    erase.push(ring.previous.take().unwrap().slot.kid);
                }
            }
        }
    }
    if !erase.is_empty() {
        retire_kids(store, generation, &erase)
            .map_err(|e| format!("cannot record the retired keys: {e}"))?;
        changed = true;
    }
    if let Some(was) = rebuild {
        let held = ring.held_kids();
        record_kids(store, generation, &held)
            .map_err(|e| format!("cannot rebuild the record of keys: {e}"))?;
        lines.push(format!(
            "the record of keys made was {was}; rebuilt from the keys held"
        ));
    }
    if changed {
        store
            .replace(DlFile::HostEncKey, &ring_bytes(&ring))
            .map_err(|e| format!("cannot write the key file: {e}"))?;
    }
    Ok(Reconciled {
        changed,
        retire_at: ring.previous.as_ref().map(Previous::retire_at),
        lines,
    })
}

// ── The receiver ──

/// This host as the receiver of host-sender mail (design II.4.2;
/// host-work-v1 §11.5), for the receiving side of host senders (the
/// runtime's mailbox): the [`Recipient`] and the provider behind its keys.
pub struct HostRecipient {
    pub recipient: Recipient,
    pub provider: SoftwareKeys,
    /// What bringing the key file to the list did first.
    pub reconciled: Reconciled,
}

/// This host as the receiver of host-sender mail at its current trust
/// generation: its `host_id` (the device id its pairing was verified with)
/// and `host_trust_gen` from its own pairing (`pairing/trust_gen`, as
/// `pairing::load` reads it), never from its device list, which may lag
/// behind its own new `add_host`; its keys as [`recipient_at`] gives them
/// against the committed list `m` at `D` = `now_d`. `Err` for a profile
/// that isn't paired and verified, or a key state that can't be brought to
/// the list.
#[cfg_attr(not(test), allow(dead_code))]
pub fn recipient(
    src: &crate::profile::Sources,
    m: &Membership,
    now_d: Option<u64>,
) -> Result<HostRecipient, String> {
    let state = crate::pairing::load(src).map_err(|e| format!("{e:#}"))?;
    let binding = state.binding.ok_or("not paired")?;
    let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)
        .map_err(|e| format!("{e:#}"))?;
    let host_id = trust
        .verified(&binding.astation_id)
        .map(|entry| entry.device_id.clone())
        .ok_or("this device isn't verified")?;
    recipient_at(&src.paths.pairing, host_id, state.host_trust_gen, m, now_d)
}

/// This host as the receiver of host-sender mail as `host_id` at trust
/// generation `generation` (what [`recipient`] reads from the pairing; the
/// runtime's mailbox gives its own identity's), against the committed list
/// `m` at `D` = `now_d`: the key file first brought to the list
/// ([`reconcile`]: a promotion and the retirements due, before any mail is
/// opened), then the keys it accepts (the list's current key, and its
/// previous one while the list keeps it and its window is open on `D`,
/// each held and not retired; never a pending key) and the ids it made
/// (the record and the keys held, less the retired). `Err`: the key state
/// couldn't be brought to the list (nothing is decided then).
pub fn recipient_at(
    pairing: &PairingPaths,
    host_id: String,
    generation: u64,
    m: &Membership,
    now_d: Option<u64>,
) -> Result<HostRecipient, String> {
    let mut store = Store::new(pairing, &journal_of(pairing));
    recipient_with(&mut store, host_id, generation, m, now_d)
}

pub(crate) fn recipient_with(
    store: &mut Store,
    host_id: String,
    generation: u64,
    m: &Membership,
    now_d: Option<u64>,
) -> Result<HostRecipient, String> {
    let _lock = store.lock().map_err(|e| format!("{e:#}"))?;
    let reconciled = reconcile_locked(store, &host_id, generation, m, now_d)?;
    let ring = match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => Some(ring),
        _ => None,
    };
    let (mut generated, retired) = read_record(store).of(generation);
    let mut keys = Vec::new();
    let mut provider = SoftwareKeys::new();
    if let (Some(ring), Standing::Current(Some(list))) = (&ring, standing(m, &host_id, generation))
    {
        if let Some(current) = &ring.current
            && current.kid == list.current.kid
            && !retired.contains(&current.kid)
        {
            provider.insert_x25519(HostEncKey::key_id(), &current.secret);
            keys.push((HostEncKey::key_id(), current.kid));
        }
        if let (Some(previous), Some(listed), Some(now)) = (&ring.previous, &list.previous, now_d)
            && listed.key.kid == previous.slot.kid
            && !listed.retired
            && listed.replaced_at_seq == previous.replaced_at_seq
            && previous.open_at(now)
            && !retired.contains(&previous.slot.kid)
        {
            provider.insert_x25519(HostEncKey::previous_key_id(), &previous.slot.secret);
            keys.push((HostEncKey::previous_key_id(), previous.slot.kid));
        }
    }
    for kid in ring.iter().flat_map(|ring| ring.held_kids()) {
        if !generated.contains(&kid) {
            generated.push(kid);
        }
    }
    generated.retain(|kid| !retired.contains(kid));
    Ok(HostRecipient {
        recipient: Recipient {
            host_id,
            host_trust_gen: generation,
            keys,
            generated,
        },
        provider,
        reconciled,
    })
}

/// `atem status`'s `Host key:` text, read from the files (no lock: each is
/// replaced whole): the current key's id, a pending one, and the previous
/// one with when its window ends on the delegated clock. `None` without a
/// key file (the hook never made one).
pub fn status_text(pairing: &PairingPaths) -> Option<String> {
    let store = Store::new(pairing, &journal_of(pairing));
    let ring = match read_ring(&store) {
        Held::Missing => return None,
        Held::Unreadable(why) => return Some(format!("unreadable ({why})")),
        Held::Ring(ring) => ring,
    };
    let mut parts = vec![match &ring.current {
        Some(current) => format!("enc_kid {} (current)", hex(&current.kid)),
        None => "no current key (a manager asks for a new one)".to_string(),
    }];
    if let Some(pending) = &ring.pending {
        parts.push(format!("{} pending", hex(&pending.slot.kid)));
    }
    if let Some(previous) = &ring.previous {
        parts.push(format!(
            "{} previous until {} on the delegated clock",
            hex(&previous.slot.kid),
            utc(previous.retire_at())
        ));
    }
    Some(parts.join("; "))
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
fn utc(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX);
    let s = secs.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        crate::memory::model::format_date(secs),
        s / 3600,
        s / 60 % 60,
        s % 60,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key file's bytes are built in one buffer of their exact size:
    /// no reallocation leaves an unwiped copy of a secret's text behind,
    /// whatever the generation's digits and the slots held; and they read
    /// back as written.
    #[test]
    fn the_key_files_bytes_fit_their_buffer() {
        for generation in [1, 42, u64::MAX] {
            let mut ring = Ring::new(generation);
            ring.current = Some(Slot::of(Zeroizing::new([1; 32])));
            let bytes = ring_bytes(&ring);
            assert_eq!(bytes.capacity(), bytes.len(), "{generation}");
            let file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(file["host_trust_gen"], generation);
            ring.pending = Some(Pending {
                slot: Slot::of(Zeroizing::new([2; 32])),
                applied: Some(Applied {
                    seq: 9,
                    hash: Hash32([3; 32]),
                    d_ms: u64::MAX,
                }),
            });
            ring.previous = Some(Previous {
                slot: Slot::of(Zeroizing::new([4; 32])),
                replaced_at_seq: 7,
                applied_d_ms: 5,
            });
            let bytes = ring_bytes(&ring);
            assert_eq!(bytes.capacity(), bytes.len(), "{generation}");
            let back = parse_ring(&bytes).expect("reads back");
            assert_eq!(back.held_kids(), ring.held_kids());
            assert_eq!(back.pending.unwrap().applied, ring.pending.unwrap().applied);
            let previous = back.previous.unwrap();
            assert_eq!((previous.replaced_at_seq, previous.applied_d_ms), (7, 5));
        }
    }

    /// A v1 file reads as its current key; a file whose public half isn't
    /// its secret's, or holding one key twice, is damaged.
    #[test]
    fn v1_files_read_and_damage_is_refused() {
        let slot = Slot::of(Zeroizing::new([1; 32]));
        let v1 = serde_json::json!({"v": 1, "host_trust_gen": 3,
            "secret": b64u(&[1u8; 32]), "pub": b64u(&slot.public)});
        let ring = parse_ring(v1.to_string().as_bytes()).unwrap();
        assert_eq!(ring.generation, 3);
        assert_eq!(ring.current.unwrap().kid, slot.kid);
        let mut wrong = v1.clone();
        wrong["pub"] = serde_json::json!(b64u(&[9u8; 32]));
        assert!(parse_ring(wrong.to_string().as_bytes()).is_none());
        let twice = serde_json::json!({"v": 2, "host_trust_gen": 3,
            "current": {"secret": b64u(&[1u8; 32]), "pub": b64u(&slot.public)},
            "pending": {"secret": b64u(&[1u8; 32]), "pub": b64u(&slot.public)}});
        assert!(parse_ring(twice.to_string().as_bytes()).is_none());
        let unknown = serde_json::json!({"v": 2, "host_trust_gen": 3, "extra": 1});
        assert!(parse_ring(unknown.to_string().as_bytes()).is_none());
        assert!(parse_ring(br#"{"v":3,"host_trust_gen":3}"#).is_none());
    }
}

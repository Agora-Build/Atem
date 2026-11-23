//! The host encryption key (delegated host-work design II.4.1, option (b);
//! session-v1 R9.14 item 8; host-work-v1 §11.5, "The recipient's keys"), on
//! the host, behind the debug-only hook's `host.senders`: the X25519 keys
//! other hosts seal host-sender mail to, the record of every key id this
//! host made at its trust generation, of those it retired and of the
//! requests it answered, what `host_enc_key_get` and `host_enc_key_new`
//! answer a native manager, the routine rotation (agreed with Astation on
//! 2026-11-23, #120 comment 7089435308), and this host as the receiver of
//! that mail. With the hook off nothing here runs: no file is made and both
//! ops keep their refusal.
//!
//! ```text
//! <profile>/pairing/host_enc_key        {"v":2,"host_trust_gen":N,
//!                                         "current":{"secret":"<b64u>","pub":"<b64u>"},
//!                                         "pending":{"secret":…,"pub":…},
//!                                         "previous":{"secret":…,"pub":…,"replaced_at_seq":S,
//!                                                     "applied_d_ms":D,"clock":C},
//!                                         "applied":{"seq":S,"hash":"<64 hex>","d_ms":D,
//!                                                    "clock":C}}
//! <profile>/pairing/host_enc_generated  {"v":2,"host_trust_gen":N,"kids":["<16 hex>",…],
//!                                         "retired":["<16 hex>",…],
//!                                         "requests":[{"request_id","kid","pub"},…]}
//! ```
//!
//! Each slot of the key file is optional (`C`, the delegated clock's mark,
//! `host_clock::mark_of`, is a number); a v1 file
//! (`{"v":1, "host_trust_gen", "secret", "pub"}`, a current key only) and a
//! v1 record (no `retired`, no `requests`) are read as such and written as
//! v2 at their next change.
//!
//! - **The keys.** Plain, 0600, replaced whole like `host_channel_key`
//!   (`membership::store`: temp, fsync, rename, directory fsync), so a host
//!   whose cred agent is locked still opens its mail. Made with the device
//!   list's pin when a pairing is verified and at `atem pair verify` (the
//!   next generation, beside the new `host_channel_key`), and at a runtime
//!   start (or a reopen of the list) on a pinned host that holds none for
//!   its generation. One of an earlier generation is replaced then; one
//!   that can't be read is left as it is (the ops answer `busy`, and the
//!   start says why). Every pin, a pin taken back and `atem unpair` delete
//!   both files; one left without the list (by a build that doesn't know
//!   them) grants nothing and is no device-list leftover.
//! - **The slots follow the committed list, entry by entry** (fix round 1,
//!   ruling R61). `current` is the list's current key when the host holds
//!   it, else the key the host offers (one no entry has set yet);
//!   `previous` is the list's previous key, not retired, with the window
//!   the entry that made it previous was stamped with; `pending` is a key
//!   the host made that no entry has set yet. A key this host made in the
//!   generation that no entry has set is kept, unaccepted, never erased,
//!   until an entry sets it or the generation ends. A secret is erased only
//!   when the list retired it (`retire_previous`), its window passed (or
//!   can't be established), a later entry replaced it as the previous key,
//!   or its generation ended.
//! - **The record.** The `enc_kid` (R9.9's, `atem_client::keys::enc_kid`)
//!   of every key made at the current generation, written (fsync, rename)
//!   before the key file, and checked again before a key is handed out (one
//!   that lists it already is synced, file and directory, first): II.4.2's
//!   receiver refuses for good mail sealed to a key id the host made but
//!   the record lacks. `retired`: the id of every key whose secret this
//!   host erased, written durably before the erasure, only ever growing in
//!   the generation; a retired id is never accepted and never waits again,
//!   whatever a restored or rolled-back key file holds (no resurrection; a
//!   restore of all of `pairing/` from a backup is the accepted residual).
//!   `requests`: the last 64 `host_enc_key_new` requests answered, each
//!   `request_id` with the key's id and public half (R62). Only the current
//!   generation is kept. A lost or unreadable record, or one of another
//!   generation, is rebuilt from the keys the host holds, with a
//!   runtime.log line.
//! - **`host_enc_key_get`** ([`hand_out`]): the `current` slot's key and its
//!   `enc_sig`, the host vouching for it with its `host_channel_key` (the
//!   shared core's `sign_host_enc_key`). A pure read: nothing is made or
//!   rotated for it; the key's id is recorded first when the record lacks
//!   it, and a failed write is `busy`, nothing handed out.
//! - **`host_enc_key_new`** ([`new_pending`]): a retry under a `request_id`
//!   the record names gets that same key, before or after an entry set it,
//!   while the host holds it or the list has set it. Otherwise the key no
//!   entry has set: the current one while no entry set it (R61 rule 2, so a
//!   stale `host_enc_key_get` answer can only name the key the host will
//!   promote), else the pending one, else a fresh key whose id is neither
//!   in the record nor among the keys the committed list set for this host
//!   since its `add_host` (drawn again otherwise), made pending. The
//!   request is recorded with the key's id (and the new key's id) before the
//!   key file is written, synced, and before the answer; any write that
//!   fails is `busy` and hands nothing out. While an entry the list
//!   committed sets the pending key and it isn't promoted yet, a new
//!   request is `busy`.
//! - **The stamp** ([`stamp_application_locked`], the device list's commit
//!   watch): just before the list writes a commit whose newest
//!   `host_enc_key` entry for this host turns a key the host holds into the
//!   list's previous key (not retired), the delegated clock's `D` (read
//!   fresh) and its mark (its record's epoch, drawn at every fresh start,
//!   and its latest repair or lowering) are written into the key file
//!   with that entry's `seq` and hash, durably: the evidence of when the
//!   host applied it. A stamp is written once per entry; a later commit of
//!   the same entry keeps it. A carriage replayed at a start is stamped at
//!   that commit, with the clock as its record has it then.
//! - **Following the list** ([`reconcile`]; the bridge runs it on every pass
//!   where the list moved or a deadline is due, and before building the
//!   receiver's view, so before any mail is opened). The previous key opens
//!   mail until `D` reaches its stamp's `D` plus 24 h ([`RETAIN_MS`]); with
//!   no stamp naming the entry the list holds, `D` below the stamp, or the
//!   clock's mark changed since the stamp (a repair, a lowering, or a fresh
//!   start: a damaged record started afresh, a record read as none), it is
//!   erased at once (fail closed: never a fresh or longer window). A
//!   crash between the list's commit and the key file following it never
//!   restarts or lengthens the window: the stamp is absolute. Each erasure
//!   writes the ids to `retired` first, then the key file.
//! - **The receiver's view** ([`recipient_at`]): this host's id and
//!   pairing generation; the accepted keys are the committed list's current
//!   key, and its previous key while the list doesn't retire it and its
//!   window is open, each only if held and not retired; a key no entry has
//!   set is never accepted (mail naming it waits for the list beyond its
//!   head). `generated` is the record's ids and the keys held, less the
//!   retired ones.
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

/// The `host_enc_key_new` requests the record remembers.
const MAX_REQUESTS: usize = 64;

/// The key's name behind its provider: the current key.
const KEY_NAME: &str = "host_enc_key";
/// The previous key's, in the receiver's provider.
const PREVIOUS_NAME: &str = "host_enc_key.previous";

/// The delegated clock now, as the key file's windows are judged on it:
/// `D`, and its mark (`host_clock::mark_of`: its record's epoch and its
/// latest repair or lowering; it changes at each, and at a fresh start).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DNow {
    pub d_ms: u64,
    pub clock: u64,
}

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
    fn of(generation: u64, public: &[u8; 32]) -> HostEncKey {
        let public = PublicKey::new(Alg::X25519, public).expect("32 bytes");
        HostEncKey {
            host_trust_gen: generation,
            kid: enc_kid_bytes(&public).expect("an X25519 key has an enc_kid"),
            public,
        }
    }

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
        HostEncKey::of(generation, &self.public)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::new(Alg::X25519, &self.public).expect("32 bytes")
    }
}

/// When the host applied the entry at `seq` (its hash `hash`) that turned
/// a key it holds into the list's previous key: `D` read before the list
/// committed it, and the delegated clock's mark then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Applied {
    seq: u64,
    hash: Hash32,
    d_ms: u64,
    clock: u64,
}

/// A routine rotation's previous key: the `seq` of the entry that replaced
/// it, `D` when the host applied that entry (its window ends [`RETAIN_MS`]
/// later), and the clock's mark then.
struct Previous {
    slot: Slot,
    replaced_at_seq: u64,
    applied_d_ms: u64,
    clock: u64,
}

impl Previous {
    fn retire_at(&self) -> u64 {
        self.applied_d_ms.saturating_add(RETAIN_MS)
    }

    /// Why its window is over at `now` (passed, `D` below its application,
    /// or the clock repaired, lowered or started afresh since: its mark
    /// differs), if it is.
    fn over(&self, now: &DNow) -> Option<&'static str> {
        if now.d_ms < self.applied_d_ms {
            Some("the delegated clock reads below its application; its window can't be established")
        } else if now.d_ms >= self.retire_at() {
            Some("its 24 h window ended")
        } else if now.clock != self.clock {
            Some(
                "the delegated clock was repaired, lowered or started afresh after its application; its window can't be established",
            )
        } else {
            None
        }
    }
}

/// The key file: a generation's keys.
struct Ring {
    generation: u64,
    current: Option<Slot>,
    pending: Option<Slot>,
    previous: Option<Previous>,
    applied: Option<Applied>,
}

impl Ring {
    fn new(generation: u64) -> Ring {
        Ring {
            generation,
            current: None,
            pending: None,
            previous: None,
            applied: None,
        }
    }

    /// Every key held, current, pending, previous.
    fn held(&self) -> Vec<&Slot> {
        self.current
            .iter()
            .chain(self.pending.iter())
            .chain(self.previous.iter().map(|p| &p.slot))
            .collect()
    }

    fn held_kids(&self) -> Vec<[u8; 8]> {
        self.held().iter().map(|s| s.kid).collect()
    }

    fn holds(&self, kid: &[u8; 8]) -> bool {
        self.held().iter().any(|s| s.kid == *kid)
    }

    /// What is in which slot (secrets left out): two shapes differ when the
    /// file must be written again.
    fn shape(&self) -> String {
        let kid = |s: Option<&Slot>| s.map(|s| hex(&s.kid));
        format!(
            "{:?}/{:?}/{:?}/{:?}",
            kid(self.current.as_ref()),
            kid(self.pending.as_ref()),
            self.previous.as_ref().map(|p| (
                hex(&p.slot.kid),
                p.replaced_at_seq,
                p.applied_d_ms,
                p.clock
            )),
            self.applied
        )
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
    if let Some(slot) = &ring.pending {
        slot_head(&mut parts, "pending", slot);
        parts.push(plain("}".into()));
    }
    if let Some(previous) = &ring.previous {
        slot_head(&mut parts, "previous", &previous.slot);
        parts.push(plain(format!(
            r#","replaced_at_seq":{},"applied_d_ms":{},"clock":{}}}"#,
            previous.replaced_at_seq, previous.applied_d_ms, previous.clock
        )));
    }
    if let Some(a) = &ring.applied {
        parts.push(plain(format!(
            r#","applied":{{"seq":{},"hash":"{}","d_ms":{},"clock":{}}}"#,
            a.seq,
            a.hash.to_hex(),
            a.d_ms,
            a.clock
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
    clock: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousV2 {
    secret: Zeroizing<String>,
    #[serde(rename = "pub")]
    public: String,
    replaced_at_seq: u64,
    applied_d_ms: u64,
    clock: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileV2 {
    #[allow(dead_code)]
    v: u64,
    host_trust_gen: u64,
    current: Option<SlotV2>,
    pending: Option<SlotV2>,
    previous: Option<PreviousV2>,
    applied: Option<AppliedV2>,
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
                current: Some(slot_of(&file.secret, &file.public)?),
                ..Ring::new(file.host_trust_gen)
            }
        }
        2 => {
            let file = serde_json::from_slice::<FileV2>(bytes).ok()?;
            let slot = |s: &Option<SlotV2>| match s {
                Some(s) => slot_of(&s.secret, &s.public).map(Some),
                None => Some(None),
            };
            Ring {
                generation: file.host_trust_gen,
                current: slot(&file.current)?,
                pending: slot(&file.pending)?,
                previous: match &file.previous {
                    Some(p) => Some(Previous {
                        slot: slot_of(&p.secret, &p.public)?,
                        replaced_at_seq: p.replaced_at_seq,
                        applied_d_ms: p.applied_d_ms,
                        clock: p.clock,
                    }),
                    None => None,
                },
                applied: match &file.applied {
                    Some(a) => Some(Applied {
                        seq: a.seq,
                        hash: Hash32::from_hex(&a.hash).ok()?,
                        d_ms: a.d_ms,
                        clock: a.clock,
                    }),
                    None => None,
                },
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
struct RequestV2 {
    request_id: String,
    kid: String,
    #[serde(rename = "pub")]
    public: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    v: u64,
    host_trust_gen: u64,
    kids: Vec<String>,
    retired: Option<Vec<String>>,
    requests: Option<Vec<RequestV2>>,
}

/// A `host_enc_key_new` request the host answered: the key's id and public
/// half (R62: a retry gets the same key).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    request_id: String,
    kid: [u8; 8],
    public: [u8; 32],
}

/// A generation's record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Kept {
    kids: Vec<[u8; 8]>,
    retired: Vec<[u8; 8]>,
    requests: Vec<Request>,
}

/// What `host_enc_generated` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Record {
    Missing,
    /// It can't be read, or isn't a record (why).
    Unreadable(String),
    Of {
        host_trust_gen: u64,
        kept: Kept,
    },
}

impl Record {
    /// The generation's record (empty for another generation's record, a
    /// missing or unreadable one).
    fn of(&self, generation: u64) -> Kept {
        match self {
            Record::Of {
                host_trust_gen,
                kept,
            } if *host_trust_gen == generation => kept.clone(),
            _ => Kept::default(),
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
    let (retired, requests) = match (file.v, &file.retired, &file.requests) {
        (1, None, None) => (Vec::new(), Vec::new()),
        (2, Some(list), requests) => {
            let Some(retired) = ids(list) else {
                return damaged();
            };
            let mut out = Vec::new();
            for r in requests.iter().flatten() {
                let Some(public) = b64u_decode(&r.public)
                    .ok()
                    .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
                else {
                    return damaged();
                };
                let Ok(kid) = hex_decode_array::<8>(&r.kid) else {
                    return damaged();
                };
                if HostEncKey::of(1, &public).kid != kid
                    || out.iter().any(|o: &Request| o.request_id == r.request_id)
                {
                    return damaged();
                }
                out.push(Request {
                    request_id: r.request_id.clone(),
                    kid,
                    public,
                });
            }
            (retired, out)
        }
        _ => return damaged(),
    };
    if file.host_trust_gen == 0 {
        return damaged();
    }
    Record::Of {
        host_trust_gen: file.host_trust_gen,
        kept: Kept {
            kids,
            retired,
            requests,
        },
    }
}

fn record_bytes(host_trust_gen: u64, kept: &Kept) -> Vec<u8> {
    let ids = |l: &[[u8; 8]]| l.iter().map(|k| hex(k)).collect::<Vec<_>>();
    let requests: Vec<serde_json::Value> = kept
        .requests
        .iter()
        .map(|r| serde_json::json!({"request_id": r.request_id, "kid": hex(&r.kid), "pub": b64u(&r.public)}))
        .collect();
    serde_json::json!({"v": 2, "host_trust_gen": host_trust_gen, "kids": ids(&kept.kids),
        "retired": ids(&kept.retired), "requests": requests})
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

/// Makes the record of generation `generation` list every id in `add` and,
/// with `request`, that request's key (the oldest of more than
/// [`MAX_REQUESTS`] dropped), durably (fsync, rename, directory fsync), its
/// retired ids kept. One that lists them already is synced (the file, then
/// the directory): a record left visible by a failed directory fsync isn't
/// durable yet, and an id must be before its key goes.
fn record_kids(
    store: &mut Store,
    generation: u64,
    add: &[[u8; 8]],
    request: Option<&Request>,
) -> Result<Prior, WriteError> {
    let (prior, mut kept) = match read_record(store) {
        Record::Of {
            host_trust_gen,
            kept,
        } if host_trust_gen == generation => {
            let listed = add.iter().all(|k| kept.kids.contains(k))
                && request.is_none_or(|r| kept.requests.contains(r));
            if listed {
                store.sync(DlFile::HostEncGenerated)?;
                return Ok(Prior::Listed);
            }
            (Prior::Added, kept)
        }
        Record::Of { host_trust_gen, .. } => (Prior::Other(host_trust_gen), Kept::default()),
        Record::Missing => (Prior::Missing, Kept::default()),
        Record::Unreadable(why) => (Prior::Unreadable(why), Kept::default()),
    };
    for kid in add {
        if !kept.kids.contains(kid) {
            kept.kids.push(*kid);
        }
    }
    if let Some(request) = request {
        kept.requests.retain(|r| r.request_id != request.request_id);
        kept.requests.push(request.clone());
        let over = kept.requests.len().saturating_sub(MAX_REQUESTS);
        kept.requests.drain(..over);
    }
    store.replace(DlFile::HostEncGenerated, &record_bytes(generation, &kept))?;
    Ok(prior)
}

/// Makes the record of generation `generation` list every id in `ids` as
/// retired (and made), durably, before their secrets are erased: from then
/// on none of them is accepted, whatever the key file holds. Only grows.
fn retire_kids(store: &mut Store, generation: u64, ids: &[[u8; 8]]) -> Result<(), WriteError> {
    let mut kept = match read_record(store) {
        Record::Of {
            host_trust_gen,
            kept,
        } if host_trust_gen == generation => {
            if ids.iter().all(|k| kept.retired.contains(k)) {
                return store.sync(DlFile::HostEncGenerated);
            }
            kept
        }
        _ => Kept::default(),
    };
    for kid in ids {
        if !kept.kids.contains(kid) {
            kept.kids.push(*kid);
        }
        if !kept.retired.contains(kid) {
            kept.retired.push(*kid);
        }
    }
    store.replace(DlFile::HostEncGenerated, &record_bytes(generation, &kept))
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
    let prior = record_kids(store, generation, &[slot.kid], None)?;
    let key = slot.key(generation);
    let ring = Ring {
        current: Some(slot),
        ..Ring::new(generation)
    };
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
                // Every key of the generation erased (the list voided it):
                // a manager asks for a new one.
                return Vec::new();
            }
            return match record_kids(store, generation, &held, None) {
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
/// generation): the `current` slot's key (the list's current key, or the
/// key the host offers while no entry set one it holds), its id durably in
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
    let ring = match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => ring,
        Held::Ring(ring) => {
            return Err(format!(
                "the key held is of trust generation {}, not {generation}",
                ring.generation
            ));
        }
        Held::Missing => return Err(format!("no key for trust generation {generation}")),
        Held::Unreadable(why) => return Err(why),
    };
    let Some(current) = &ring.current else {
        return Err(format!(
            "no current key for trust generation {generation} (ask for a new one)"
        ));
    };
    if read_record(store)
        .of(generation)
        .retired
        .contains(&current.kid)
    {
        return Err(format!("the current key {} is retired", hex(&current.kid)));
    }
    let prior = record_kids(store, generation, &[current.kid], None)
        .map_err(|e| format!("cannot record the key's id: {e}"))?;
    let key = current.key(generation);
    let sig = vouch(m, host_key, host_id, generation, &key)?;
    let line = prior.rebuilt(&[current.kid], generation);
    Ok((key, sig, line))
}

/// What `host_enc_key_new` hands out at `generation` for `request_id` (the
/// routine rotation; see the module doc): a retry's same key, the key no
/// entry has set (the current one first, R61 rule 2), or a fresh pending
/// key; the request recorded with its key (and a new key's id) before the
/// key file is written, both synced, before the answer. `Err`: why none is
/// handed out (`busy`, [`DETAIL_UNAVAILABLE`]). The lines say what was made
/// and a record rebuilt.
pub(crate) fn new_pending(
    store: &mut Store,
    pairing: &PairingPaths,
    m: &Membership,
    host_key: &HostKey,
    host_id: &str,
    generation: u64,
    request_id: &str,
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
    let kept = read_record(store).of(generation);
    let set = |public: &[u8; 32]| {
        m.host_enc_key_set_before(
            host_id,
            &PublicKey::new(Alg::X25519, public).expect("32 bytes"),
        )
    };
    let answer = |key: HostEncKey, lines: Vec<String>| {
        let sig = vouch(m, host_key, host_id, generation, &key)?;
        Ok((key, sig, lines))
    };
    // A retry (R62): the same key, before or after an entry set it, while
    // the host holds it or the list set it (never one the host lost before
    // writing it: that request is answered anew).
    if let Some(request) = kept.requests.iter().find(|r| r.request_id == request_id)
        && (ring.holds(&request.kid) || set(&request.public))
    {
        record_kids(store, generation, &[request.kid], Some(request))
            .map_err(|e| format!("cannot record the request: {e}"))?;
        if ring.holds(&request.kid) {
            store
                .sync(DlFile::HostEncKey)
                .map_err(|e| format!("cannot sync the key file: {e}"))?;
        }
        return answer(HostEncKey::of(generation, &request.public), Vec::new());
    }
    // The key no entry has set: the current one first (R61 rule 2), else
    // the pending one.
    let offered = match (&ring.current, &ring.pending) {
        (Some(current), _) if !set(&current.public) => Some(current.public),
        (_, Some(pending)) if set(&pending.public) => {
            return Err(format!(
                "the pending key {} is set by the device list and not yet promoted; ask again",
                hex(&pending.kid)
            ));
        }
        (_, Some(pending)) => Some(pending.public),
        (_, None) => None,
    };
    if let Some(public) = offered {
        let key = HostEncKey::of(generation, &public);
        if kept.retired.contains(&key.kid) {
            return Err(format!("the key {} is retired", key.enc_kid()));
        }
        let request = Request {
            request_id: request_id.to_owned(),
            kid: key.kid,
            public,
        };
        let prior = record_kids(store, generation, &[key.kid], Some(&request))
            .map_err(|e| format!("cannot record the request: {e}"))?;
        store
            .sync(DlFile::HostEncKey)
            .map_err(|e| format!("cannot sync the key file: {e}"))?;
        let lines = prior.rebuilt(&[key.kid], generation).into_iter().collect();
        return answer(key, lines);
    }
    // A fresh key, made pending (or current, on a host that holds none).
    let held = ring.held_kids();
    let fresh = |slot: &Slot| {
        !kept.kids.contains(&slot.kid)
            && !kept.retired.contains(&slot.kid)
            && !held.contains(&slot.kid)
            && !set(&slot.public)
    };
    let slot = (0..16)
        .map(|_| Slot::of(draw()))
        .find(fresh)
        .ok_or("no fresh key drawn")?;
    let key = slot.key(generation);
    let request = Request {
        request_id: request_id.to_owned(),
        kid: slot.kid,
        public: slot.public,
    };
    let prior = record_kids(store, generation, &[slot.kid], Some(&request))
        .map_err(|e| format!("cannot record the new key's id: {e}"))?;
    if ring.current.is_none() {
        ring.current = Some(slot);
    } else {
        ring.pending = Some(slot);
    }
    store
        .replace(DlFile::HostEncKey, &ring_bytes(&ring))
        .map_err(|e| format!("cannot write the new key: {e}"))?;
    let mut lines = vec![format!(
        "made a key for trust generation {generation} (enc_kid {}) for a manager's rotation",
        key.enc_kid()
    )];
    if let Prior::Unreadable(why) = prior {
        lines.push(format!(
            "the record of keys made was unreadable ({why}); it now lists this key only"
        ));
    }
    answer(key, lines)
}

/// The newest `host_enc_key` entry `m` holds for `host_id` at `generation`:
/// its `seq`, and the previous key it made, if not retired.
fn newest_entry(m: &Membership, host_id: &str, generation: u64) -> Option<(u64, Option<[u8; 8]>)> {
    m.host_enc_key(host_id)
        .filter(|k| k.current.host_trust_gen == generation)
        .map(|k| {
            (
                k.current.seq,
                k.previous
                    .as_ref()
                    .filter(|p| !p.retired)
                    .map(|p| p.key.kid),
            )
        })
}

/// The device list's commit watch (the caller, the list's commit, holds
/// `trust_gen.lock`, or is the start's replay): just before `next` is
/// written over `prev`, when `next`'s newest `host_enc_key` entry for
/// `host_id` at `generation` is a new one that turns a key this host holds
/// into the list's previous key (not retired), `now` (the delegated clock's
/// `D`, read fresh, and its mark) is written into the
/// key file with that entry's `seq` and hash, durably (one atomic replace):
/// the evidence of when the host applied it. A stamp already naming that
/// entry is kept (a commit of the same entry again never moves it later).
/// No `D`, or a write that fails: no stamp, and the previous key is retired
/// at once. What happened, as runtime.log lines.
pub fn stamp_application_locked(
    store: &mut Store,
    prev: &Membership,
    next: &Membership,
    host_id: &str,
    generation: u64,
    now: Option<DNow>,
) -> Vec<String> {
    let Some((seq, Some(previous))) = newest_entry(next, host_id, generation) else {
        return Vec::new();
    };
    if newest_entry(prev, host_id, generation).is_some_and(|(before, _)| before == seq) {
        return Vec::new();
    }
    let Some(hash) = next.entry_hash_at(seq) else {
        return Vec::new();
    };
    let Held::Ring(mut ring) = read_ring(store) else {
        return Vec::new();
    };
    if ring.generation != generation || !ring.holds(&previous) {
        return Vec::new();
    }
    if ring.applied.is_some_and(|a| a.seq == seq && a.hash == hash) {
        return Vec::new();
    }
    let Some(now) = now else {
        return vec![format!(
            "the entry at seq {seq} makes {} the previous key, and the delegated clock has no reading: its application time isn't recorded, so it will be retired at once",
            hex(&previous)
        )];
    };
    ring.applied = Some(Applied {
        seq,
        hash,
        d_ms: now.d_ms,
        clock: now.clock,
    });
    match store.replace(DlFile::HostEncKey, &ring_bytes(&ring)) {
        Ok(()) => Vec::new(),
        Err(e) => vec![format!(
            "the application time of the entry at seq {seq} couldn't be recorded ({e}); the previous key will be retired at once"
        )],
    }
}

// ── Following the list ──

/// What [`reconcile`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// The key file changed (a key moved between slots, or was erased): the
    /// keys this host accepts may have changed, so waiting mail is judged
    /// again.
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
/// module doc), at `now` (none: no window is judged for the time), under
/// `trust_gen.lock`. The ids of erased keys go to the record's `retired`
/// first, synced; then one atomic replace of the key file. `Err`: a file
/// that can't be read, a write that failed, or more keys no entry has set
/// than the file has room for (nothing is decided on such a state: the
/// caller opens no mail).
pub fn reconcile(
    pairing: &PairingPaths,
    host_id: &str,
    generation: u64,
    m: &Membership,
    now: Option<DNow>,
) -> Result<Reconciled, String> {
    let mut store = Store::new(pairing, &journal_of(pairing));
    reconcile_with(&mut store, host_id, generation, m, now)
}

pub(crate) fn reconcile_with(
    store: &mut Store,
    host_id: &str,
    generation: u64,
    m: &Membership,
    now: Option<DNow>,
) -> Result<Reconciled, String> {
    let _lock = store.lock().map_err(|e| format!("{e:#}"))?;
    reconcile_locked(store, host_id, generation, m, now)
}

/// Where a slot's key came from in the key file.
enum From {
    Current,
    Pending,
    Previous {
        replaced_at_seq: u64,
        applied_d_ms: u64,
        clock: u64,
    },
}

fn reconcile_locked(
    store: &mut Store,
    host_id: &str,
    generation: u64,
    m: &Membership,
    now: Option<DNow>,
) -> Result<Reconciled, String> {
    let mut ring = match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => *ring,
        // Another generation's file is `ensure`'s; none is nothing to do.
        Held::Ring(_) | Held::Missing => return Ok(Reconciled::default()),
        Held::Unreadable(why) => return Err(why),
    };
    // A record that can't be read, is missing or of another generation is
    // rebuilt from the keys held (below), its retired ids and requests
    // lost: the keys a retirement cut short then go by the list's rules
    // alone (the list no longer keeps a key retired early, and the windows
    // are absolute).
    let record = read_record(store);
    let rebuild = match &record {
        Record::Of { host_trust_gen, .. } if *host_trust_gen == generation => None,
        Record::Of { host_trust_gen, .. } => Some(format!("of trust generation {host_trust_gen}")),
        Record::Missing => Some("missing".to_string()),
        Record::Unreadable(why) => Some(format!("unreadable ({why})")),
    };
    let retired = record.of(generation).retired;
    let before = ring.shape();
    let mut slots: Vec<(Slot, From)> = Vec::new();
    slots.extend(ring.current.take().map(|s| (s, From::Current)));
    slots.extend(ring.pending.take().map(|s| (s, From::Pending)));
    slots.extend(ring.previous.take().map(|p| {
        (
            p.slot,
            From::Previous {
                replaced_at_seq: p.replaced_at_seq,
                applied_d_ms: p.applied_d_ms,
                clock: p.clock,
            },
        )
    }));
    let mut erase: Vec<[u8; 8]> = Vec::new();
    let mut lines = Vec::new();
    let mut gone = |slot: Slot, why: String, lines: &mut Vec<String>| {
        lines.push(format!("{} retired: {why}", hex(&slot.kid)));
        erase.push(slot.kid);
    };
    // A key whose id is retired (a retirement cut short, a rolled-back
    // file) is erased whatever else holds.
    let (dead, live): (Vec<_>, Vec<_>) = slots
        .into_iter()
        .partition(|(slot, _)| retired.contains(&slot.kid));
    for (slot, _) in dead {
        gone(slot, "its id is retired".into(), &mut lines);
    }
    let mut promotion = false;
    match standing(m, host_id, generation) {
        Standing::Behind => {
            // Back as they were: nothing of this generation is judged yet.
            for (slot, from) in live {
                match from {
                    From::Current => ring.current = Some(slot),
                    From::Pending => ring.pending = Some(slot),
                    From::Previous {
                        replaced_at_seq,
                        applied_d_ms,
                        clock,
                    } => {
                        ring.previous = Some(Previous {
                            slot,
                            replaced_at_seq,
                            applied_d_ms,
                            clock,
                        })
                    }
                }
            }
        }
        Standing::Voided => {
            for (slot, _) in live {
                gone(
                    slot,
                    format!("the device list voided trust generation {generation}"),
                    &mut lines,
                );
            }
        }
        Standing::Current(keys) => {
            let list_current = keys.map(|k| (k.current.kid, k.current.seq));
            let list_previous = keys.and_then(|k| k.previous.as_ref());
            let mut unset: Vec<(Slot, From)> = Vec::new();
            for (slot, from) in live {
                if list_current.is_some_and(|(kid, _)| kid == slot.kid) {
                    if !matches!(from, From::Current) {
                        promotion = true;
                        lines.push(format!(
                            "{} is the current key: the entry at seq {} set it",
                            hex(&slot.kid),
                            list_current.map_or(0, |(_, seq)| seq)
                        ));
                    }
                    ring.current = Some(slot);
                    continue;
                }
                match list_previous.filter(|p| p.key.kid == slot.kid) {
                    Some(p) if p.retired => {
                        gone(
                            slot,
                            "the entry retires it (retire_previous)".into(),
                            &mut lines,
                        );
                        continue;
                    }
                    Some(p) => {
                        // Its window: the one it was given at this entry, or
                        // the stamp of the entry that made it previous.
                        let window = match from {
                            From::Previous {
                                replaced_at_seq,
                                applied_d_ms,
                                clock,
                            } if replaced_at_seq == p.replaced_at_seq => {
                                Some((applied_d_ms, clock))
                            }
                            _ => ring
                                .applied
                                .filter(|a| {
                                    a.seq == p.replaced_at_seq
                                        && m.entry_hash_at(a.seq) == Some(a.hash)
                                })
                                .map(|a| (a.d_ms, a.clock)),
                        };
                        let Some((applied_d_ms, clock)) = window else {
                            gone(
                                slot,
                                "retired at once: the entry's application time isn't known (no stamp before the commit)".into(),
                                &mut lines,
                            );
                            continue;
                        };
                        let previous = Previous {
                            slot,
                            replaced_at_seq: p.replaced_at_seq,
                            applied_d_ms,
                            clock,
                        };
                        match now.as_ref().and_then(|now| previous.over(now)) {
                            Some(why) => gone(previous.slot, why.into(), &mut lines),
                            None => ring.previous = Some(previous),
                        }
                        continue;
                    }
                    None => {}
                }
                let public = slot.public_key();
                if m.host_enc_key_set_before(host_id, &public) {
                    gone(
                        slot,
                        "a later entry replaced it as the previous key".into(),
                        &mut lines,
                    );
                } else {
                    // A key no entry has set: kept, unaccepted.
                    unset.push((slot, from));
                }
            }
            // The keys no entry has set: offered as current while the host
            // holds no key the list made current, the other one pending.
            unset.sort_by_key(|(_, from)| !matches!(from, From::Current));
            for (slot, _) in unset {
                if ring.current.is_none() {
                    ring.current = Some(slot);
                } else if ring.pending.is_none() {
                    ring.pending = Some(slot);
                } else {
                    return Err(format!(
                        "the key file holds more keys no entry has set than it has room for ({}); move it aside",
                        hex(&slot.kid)
                    ));
                }
            }
        }
    }
    let changed = !erase.is_empty() || ring.shape() != before;
    if promotion {
        // Debug builds: the runtime is killed here, after the device list
        // committed the entry, before the key file follows it.
        #[cfg(not(test))]
        crate::runtime::test_hooks::crash_point(
            "crash_before_enc_key_promotion",
            "after the device list committed a host_enc_key entry, before the host's key file follows it",
        );
    }
    if !erase.is_empty() {
        retire_kids(store, generation, &erase)
            .map_err(|e| format!("cannot record the retired keys: {e}"))?;
    }
    if let Some(was) = rebuild {
        let held = ring.held_kids();
        record_kids(store, generation, &held, None)
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
/// against the committed list `m` at `now`. `Err` for a profile that isn't
/// paired and verified, or a key state that can't be brought to the list.
#[cfg_attr(not(test), allow(dead_code))]
pub fn recipient(
    src: &crate::profile::Sources,
    m: &Membership,
    now: Option<DNow>,
) -> Result<HostRecipient, String> {
    let state = crate::pairing::load(src).map_err(|e| format!("{e:#}"))?;
    let binding = state.binding.ok_or("not paired")?;
    let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)
        .map_err(|e| format!("{e:#}"))?;
    let host_id = trust
        .verified(&binding.astation_id)
        .map(|entry| entry.device_id.clone())
        .ok_or("this device isn't verified")?;
    recipient_at(&src.paths.pairing, host_id, state.host_trust_gen, m, now)
}

/// This host as the receiver of host-sender mail as `host_id` at trust
/// generation `generation` (what [`recipient`] reads from the pairing; the
/// runtime's mailbox gives its own identity's), against the committed list
/// `m` at `now`: the key file first brought to the list ([`reconcile`]:
/// what the list's entries ask, before any mail is opened), then the keys
/// it accepts (the list's current key, and its previous one while the list
/// keeps it and its window is open, each held and not retired; never a key
/// no entry has set) and the ids it made (the record and the keys held,
/// less the retired). `Err`: the key state couldn't be brought to the list
/// (nothing is decided then).
pub fn recipient_at(
    pairing: &PairingPaths,
    host_id: String,
    generation: u64,
    m: &Membership,
    now: Option<DNow>,
) -> Result<HostRecipient, String> {
    let mut store = Store::new(pairing, &journal_of(pairing));
    recipient_with(&mut store, host_id, generation, m, now)
}

pub(crate) fn recipient_with(
    store: &mut Store,
    host_id: String,
    generation: u64,
    m: &Membership,
    now: Option<DNow>,
) -> Result<HostRecipient, String> {
    let _lock = store.lock().map_err(|e| format!("{e:#}"))?;
    let reconciled = reconcile_locked(store, &host_id, generation, m, now)?;
    let ring = match read_ring(store) {
        Held::Ring(ring) if ring.generation == generation => Some(ring),
        _ => None,
    };
    let kept = read_record(store).of(generation);
    let (mut generated, retired) = (kept.kids, kept.retired);
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
        if let (Some(previous), Some(listed), Some(now)) = (&ring.previous, &list.previous, &now)
            && listed.key.kid == previous.slot.kid
            && !listed.retired
            && listed.replaced_at_seq == previous.replaced_at_seq
            && previous.over(now).is_none()
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
        parts.push(format!("{} pending", hex(&pending.kid)));
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
            ring.pending = Some(Slot::of(Zeroizing::new([2; 32])));
            ring.applied = Some(Applied {
                seq: 9,
                hash: Hash32([3; 32]),
                d_ms: u64::MAX,
                clock: 6,
            });
            ring.previous = Some(Previous {
                slot: Slot::of(Zeroizing::new([4; 32])),
                replaced_at_seq: 7,
                applied_d_ms: 5,
                clock: u64::MAX,
            });
            let bytes = ring_bytes(&ring);
            assert_eq!(bytes.capacity(), bytes.len(), "{generation}");
            let back = parse_ring(&bytes).expect("reads back");
            assert_eq!(back.held_kids(), ring.held_kids());
            assert_eq!(back.applied, ring.applied);
            assert_eq!(back.shape(), ring.shape());
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

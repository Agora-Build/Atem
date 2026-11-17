//! The Station's reference mailbox (host-work-v1 §11.5, "The mailbox
//! calls", rules 1 to 9 and the readings agreed with Astation; delegated
//! host-work design II.4.3). Like [`crate::control::ledger::AckLedger`] for
//! acknowledgments, it is a model of the Station's side, sans-I/O, pure and
//! deterministic: no clock (`now_ms` is a parameter), no storage, no
//! network and no randomness (its `mailbox_id`s come from a seed it is
//! given). Atem's fake Station and Astation's Station can both be checked
//! against it, through the shared vectors `r9-vectors-mailbox-calls`.
//!
//! **A transition never changes the mailbox it is called on.**
//! [`ReferenceMailbox::call`], [`ReferenceMailbox::heads`],
//! [`ReferenceMailbox::reset`], [`ReferenceMailbox::tick`] and
//! [`ReferenceMailbox::list_moved`] return the next state; `call` and
//! `heads` also the answer to send and what happened. A Station commits the
//! next state durably and only then sends the answer: `mailbox_stored` goes
//! only once the object is durably stored (rule 3).
//!
//! **Inputs and answers.** A call is the bytes the Station received, read
//! by the shared core's reader ([`super::mailbox::MailboxToStation`]), and
//! every answer is built by its builders, so what the model answers reads
//! back with [`super::mailbox::MailboxToHost`]. The calling host is the
//! link's verified association ([`LinkAssociation`]: account, root, host,
//! trust generation and connection), never a field of the call (rule 1).
//! The Station's copy of the device list is the [`CurrentHosts`] it was
//! last given.
//!
//! **What the model does** (rule numbers are §11.5's; where the rules leave
//! a choice, its "reference mailbox's readings", Atem's, agreed with Astation 2026-11-16,
//! #120 comment 6930157163):
//! - **Mailboxes** (rule 2): one per receiving `(account_id, genesis_hash,
//!   host_id, host_trust_gen)` of this device list, minted by the first
//!   object stored in it or the first `heads` with `host.senders` of its host
//!   (a refused put mints none), with a `mailbox_id` that is never reused
//!   ([`mailbox_id`]) and positions 1, 2, … in store order.
//! - **Puts** (rules 1 and 3), in this order: a put the shared reader
//!   refuses is dropped unanswered and counted ([`Dropped::Unread`]), one
//!   whose object, as received, is over what a page can carry at every
//!   position included (`too_large`, the reader's
//!   [`MAX_SERVED_OBJECT_BYTES`](super::mailbox::MAX_SERVED_OBJECT_BYTES):
//!   Atem's reading, agreed with Astation 2026-11-16); `forbidden` unless the caller
//!   is a current host at its link's generation, the object's sender, of the
//!   link's account and root, and the recipient is a current host at the
//!   generation the object names; `expired` when `now_ms` is at or past
//!   `expires_at`, or `expires_at` isn't after `created_at`, or is more than
//!   24 hours after it (Atem's reading, agreed with Astation 2026-11-16);
//!   then the key `(calling host_id, body.id)` within the recipient's
//!   mailbox: the same [`super::object_hash`] is answered `mailbox_stored`
//!   and charged nothing ([`Outcome::AlreadyStored`]), another is
//!   `id_reused` and the first stays; then the quotas; then the object is
//!   stored at the next position.
//! - **Quotas** ([`Quotas`], design II.4.3's starting figures by default):
//!   per sending host (the calling `host_id`), per receiving host (its
//!   mailbox) and per account (this device list), each in objects and in
//!   encoded bytes as received: the object's exact text in the put
//!   ([`super::mailbox::MailboxPut::object_bytes`]; design II.4.3, "the
//!   encoded wire bytes it received"), not the call's own fields. A stored
//!   object is charged once; a resend after it was removed is a new
//!   delivery, charged again. A page serves the object compact.
//! - **Pages** (rule 4): at most one object; `through` is fixed and covers
//!   every removed or expired position up to the next stored object (or
//!   the head); a call whose `after` is beyond the head gets the reset
//!   page.
//! - **Done** (rule 5): only on the caller's own mailbox; removes the object
//!   there, if any, freeing its key and quota, and answers the same either
//!   way.
//! - **Sync and done come only from a current host and name only its own
//!   mailbox** (rule 1): a caller that isn't a current host of the list at
//!   its link's generation (as for a put), or any other `mailbox_id`
//!   (another host's, an old one after a reset, an unknown one), is refused
//!   `forbidden`, and nothing of another mailbox is served or removed.
//! - **Expiry**: every transition first removes each object whose
//!   `expires_at` is at or before its `now_ms` (the receiver's `expired`).
//! - **Heads** (rule 6): `mailbox:{mailbox_id, head}`, the caller's own,
//!   only for a host whose `welcome` lists `host.senders`. It is the
//!   Station's announcement on the link, not a call: it checks no current
//!   host.
//! - **Resets** (rule 7): [`Reset::NewMailbox`], a Station that can't vouch
//!   for a mailbox's positions minting a new one (what it held is lost and
//!   its keys and quota freed), or [`Reset::HeadBack`], a mailbox gone back
//!   under the same id (what it stored after that head is lost), the fault
//!   a host reads as a reset when a head comes below its cursor.
//!
//! **Not modelled:** reserved capacity for small control objects (rule 3:
//! the Station's own, from the body's `type` and the object's size),
//! answering within 30 seconds (rule 8), when `heads` goes (rule 6: on each
//! connection, every 30 seconds and at once when an object is stored; here
//! [`ReferenceMailbox::heads`] is asked for), and persistence.
use std::collections::BTreeMap;

use serde_json::Value;

use super::mailbox::{
    MailboxCallRefused, MailboxDone, MailboxDoneResult, MailboxEntry, MailboxPut,
    MailboxPutRefused, MailboxRefusedCall, MailboxStored, MailboxSync, MailboxSyncResult,
    MailboxToStation, PutRefusal,
};
use super::{MailBody, object_hash};
use crate::control::ledger::LinkAssociation;
use crate::control::relay::{Heads, HeadsWithMailbox, MailboxHead, RefusalCode, RelayError};
use crate::domain::REFERENCE_MAILBOX_ID;
use crate::encoding::{Hash32, enc, u64_field};
use crate::membership::Membership;
use crate::signed::SignedObject;

/// The longest lifetime an object may have: `expires_at` at most 24 hours
/// after `created_at` (rule 3).
pub const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

/// One limit: at most `objects` objects and `bytes` encoded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub objects: u64,
    pub bytes: u64,
}

/// The mailbox's limits (design II.4.3, "Limits"), whichever comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    /// Per sending host: its objects stored in every mailbox.
    pub sender: Quota,
    /// Per receiving host: the objects stored in its mailbox.
    pub receiver: Quota,
    /// Per account: every object stored for this device list.
    pub account: Quota,
}

impl Default for Quotas {
    /// The contract's starting figures: 128 objects or 32 MiB per sending
    /// host, 256 or 64 MiB per receiving host, 1,024 or 256 MiB per account.
    fn default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Quotas {
            sender: Quota {
                objects: 128,
                bytes: 32 * MIB,
            },
            receiver: Quota {
                objects: 256,
                bytes: 64 * MIB,
            },
            account: Quota {
                objects: 1024,
                bytes: 256 * MIB,
            },
        }
    }
}

/// What is stored against a limit: objects and their encoded bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub objects: u64,
    pub bytes: u64,
}

impl Usage {
    fn add(&mut self, bytes: u64) {
        self.objects += 1;
        self.bytes += bytes;
    }

    /// Whether one more object of `bytes` would go over `quota`.
    fn over(&self, quota: Quota, bytes: u64) -> bool {
        self.objects + 1 > quota.objects || self.bytes + bytes > quota.bytes
    }
}

/// The Station's copy of the device list, as the mailbox reads it: each
/// current host at the generation of its newest `add_host` (rules 1 and 3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurrentHosts(BTreeMap<String, u64>);

impl CurrentHosts {
    pub fn new(hosts: impl IntoIterator<Item = (String, u64)>) -> Self {
        CurrentHosts(hosts.into_iter().collect())
    }

    /// A device list's current hosts.
    pub fn of(list: &Membership) -> Self {
        Self::new(
            list.hosts()
                .map(|host| (host.host_id.clone(), host.host_trust_gen)),
        )
    }

    /// The host's current generation, if it is a current host.
    pub fn generation(&self, host_id: &str) -> Option<u64> {
        self.0.get(host_id).copied()
    }

    /// Whether `host_id` is a current host at exactly `host_trust_gen`.
    pub fn is_current(&self, host_id: &str, host_trust_gen: u64) -> bool {
        self.generation(host_id) == Some(host_trust_gen)
    }

    /// Every current host and its generation, by host id.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.0
            .iter()
            .map(|(host, generation)| (host.as_str(), *generation))
    }
}

/// A reset of one mailbox (rule 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reset {
    /// The Station can't vouch for the mailbox's positions (a restore, a
    /// lost store): a new `mailbox_id`, from position 1; what the old one
    /// held is lost, its keys and quota freed.
    NewMailbox,
    /// The mailbox went back to `head` under the same id: what it stored
    /// after that position is lost, and the next object is stored at
    /// `head + 1`. A Station must not do this (positions are never reused
    /// under a `mailbox_id`); the model does it so a host's handling of it
    /// can be checked.
    HeadBack { head: u64 },
}

/// Why a call got no answer: the Station dropped it and counted it, and
/// the caller retires it at its deadline, as an unanswered call (rule 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dropped {
    /// The shared core's reader refused it (rule 3, "A put the Station can't
    /// read", a put whose object a page couldn't carry at every position
    /// included, `too_large`:
    /// [`MAX_SERVED_OBJECT_BYTES`](super::mailbox::MAX_SERVED_OBJECT_BYTES);
    /// any other call likewise).
    Unread(RelayError),
}

/// What a transition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Stored at `position` of the recipient's mailbox, and charged.
    Stored { position: u64 },
    /// The same object is stored under its key already, at `position`:
    /// answered `mailbox_stored`, charged nothing.
    AlreadyStored { position: u64 },
    /// `mailbox_put_refused` with this code.
    PutRefused(PutRefusal),
    /// No answer.
    Dropped(Dropped),
    /// A page: its scan boundary and the position of the object it lists,
    /// if any; `reset` when the call's `after` was beyond the head.
    Page {
        through: u64,
        position: Option<u64>,
        reset: bool,
    },
    /// `mailbox_done_result`; `removed` when an object was there.
    Done { removed: bool },
    /// `mailbox_sync_refused` or `mailbox_done_refused`, `forbidden`.
    Refused(MailboxRefusedCall),
    /// A `heads`, with the caller's mailbox head when it lists
    /// `host.senders`.
    Heads { mailbox: Option<MailboxHead> },
}

/// The next state, what to send (built by the shared core's builders; none
/// for a dropped call) and what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxTransition {
    pub next: ReferenceMailbox,
    pub answer: Option<Value>,
    pub outcome: Outcome,
}

/// Why the model refused to take a call at all: the Station's own mistake,
/// never an answer on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// An account id that isn't 1 to 128 bytes.
    Malformed(&'static str),
    /// The caller's association lacks a part, or a part is out of its
    /// grammar.
    IncompleteLink,
    /// The caller's link belongs to another device list than this one.
    OtherAccount,
    /// The `heads` given can't be sent (its builder refused it).
    Heads(RelayError),
    /// A reset of a mailbox that doesn't exist, or a `HeadBack` not below
    /// its head.
    NoSuchReset,
}

/// A stored object.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stored {
    /// The calling host that put it: the first half of its key and the
    /// sending host its quota counts.
    sender: String,
    /// Its body's `id`: the second half of its key.
    id: String,
    object_hash: Hash32,
    object: SignedObject,
    /// Its exact bytes as received, what it is charged.
    bytes: u64,
    expires_at: u64,
}

/// One mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mailbox {
    mailbox_id: String,
    /// The last position given (0: none).
    head: u64,
    objects: BTreeMap<u64, Stored>,
}

/// A stored object, as a Station or a test sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredView {
    pub position: u64,
    pub sender: String,
    pub id: String,
    pub object_hash: Hash32,
    pub bytes: u64,
    pub expires_at: u64,
}

/// One device list's mailboxes at one Station (rule 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceMailbox {
    account_id: String,
    genesis_hash: Hash32,
    quotas: Quotas,
    seed: [u8; 32],
    hosts: CurrentHosts,
    /// By receiving `(host_id, host_trust_gen)`.
    mailboxes: BTreeMap<(String, u64), Mailbox>,
    /// How many `mailbox_id`s each receiving host has had.
    minted: BTreeMap<(String, u64), u64>,
    /// Calls dropped unanswered.
    dropped: u64,
}

/// The `mailbox_id` a reference mailbox seeded with `seed` mints for the
/// `n`th mailbox (from 0) of a receiving host: the first 16 bytes of
/// `SHA-256(enc(["atem-reference-mailbox-id-v1", seed, account_id,
/// genesis_hash, host_id, u64(host_trust_gen), u64(n)]))` as a UUID v4
/// (RFC 9562: the version nibble 4, the variant bits 10), written
/// lowercase. A Station gives each store a fresh seed from its CSPRNG, so
/// a restored store mints new ids; the vectors give a fixed one.
pub fn mailbox_id(
    seed: &[u8; 32],
    account_id: &str,
    genesis_hash: &Hash32,
    host_id: &str,
    host_trust_gen: u64,
    n: u64,
) -> String {
    let digest = Hash32::of(&enc(&[
        REFERENCE_MAILBOX_ID.as_bytes(),
        seed,
        account_id.as_bytes(),
        &genesis_hash.0,
        host_id.as_bytes(),
        &u64_field(host_trust_gen),
        &u64_field(n),
    ]));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

impl ReferenceMailbox {
    /// No mailbox yet, for the device list `(account_id, genesis_hash)`,
    /// with `quotas` and the `seed` its `mailbox_id`s come from, and no
    /// current host until [`ReferenceMailbox::list_moved`].
    pub fn new(
        account_id: &str,
        genesis_hash: Hash32,
        quotas: Quotas,
        seed: [u8; 32],
    ) -> Result<Self, ModelError> {
        if account_id.is_empty() || account_id.len() > MAX_ACCOUNT_ID_BYTES {
            return Err(ModelError::Malformed("account_id"));
        }
        Ok(ReferenceMailbox {
            account_id: account_id.to_owned(),
            genesis_hash,
            quotas,
            seed,
            hosts: CurrentHosts::default(),
            mailboxes: BTreeMap::new(),
            minted: BTreeMap::new(),
            dropped: 0,
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    pub fn quotas(&self) -> Quotas {
        self.quotas
    }

    /// The Station's copy of the device list, as last given.
    pub fn hosts(&self) -> &CurrentHosts {
        &self.hosts
    }

    /// The Station's copy of the device list moved: puts are checked against
    /// `hosts` from now on. Mailboxes stay as they are.
    pub fn list_moved(&self, hosts: CurrentHosts) -> Self {
        let mut next = self.clone();
        next.hosts = hosts;
        next
    }

    /// Every receiving host with a mailbox, by host id and generation.
    pub fn receivers(&self) -> impl Iterator<Item = (&str, u64)> {
        self.mailboxes
            .keys()
            .map(|(host_id, host_trust_gen)| (host_id.as_str(), *host_trust_gen))
    }

    /// The mailbox of a receiving host, if one was minted: its id and head.
    pub fn mailbox(&self, host_id: &str, host_trust_gen: u64) -> Option<MailboxHead> {
        self.mailboxes
            .get(&(host_id.to_owned(), host_trust_gen))
            .map(|m| MailboxHead {
                mailbox_id: m.mailbox_id.clone(),
                head: m.head,
            })
    }

    /// The objects stored in a receiving host's mailbox, by position.
    pub fn stored(&self, host_id: &str, host_trust_gen: u64) -> Vec<StoredView> {
        self.mailboxes
            .get(&(host_id.to_owned(), host_trust_gen))
            .map(|m| {
                m.objects
                    .iter()
                    .map(|(position, s)| StoredView {
                        position: *position,
                        sender: s.sender.clone(),
                        id: s.id.clone(),
                        object_hash: s.object_hash,
                        bytes: s.bytes,
                        expires_at: s.expires_at,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What a sending host has stored, in every mailbox.
    pub fn sender_usage(&self, host_id: &str) -> Usage {
        self.usage(|_, stored| stored.sender == host_id)
    }

    /// What a receiving host's mailbox holds.
    pub fn receiver_usage(&self, host_id: &str, host_trust_gen: u64) -> Usage {
        self.usage(|key, _| key.0 == host_id && key.1 == host_trust_gen)
    }

    /// What this device list's mailboxes hold.
    pub fn account_usage(&self) -> Usage {
        self.usage(|_, _| true)
    }

    fn usage(&self, counts: impl Fn(&(String, u64), &Stored) -> bool) -> Usage {
        let mut usage = Usage::default();
        for (key, mailbox) in &self.mailboxes {
            for stored in mailbox.objects.values() {
                if counts(key, stored) {
                    usage.add(stored.bytes);
                }
            }
        }
        usage
    }

    /// How many calls were dropped unanswered.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// A call (`mailbox_put`, `mailbox_sync` or `mailbox_done`), as the
    /// bytes received on the link whose verified association is `caller`,
    /// at `now_ms`.
    pub fn call(
        &self,
        caller: &LinkAssociation,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<MailboxTransition, ModelError> {
        self.check_caller(caller)?;
        let next = self.tick(now_ms);
        let call = match MailboxToStation::decode(bytes) {
            Ok(call) => call,
            Err(error) => return Ok(next.drop_call(Dropped::Unread(error))),
        };
        Ok(match call {
            MailboxToStation::Put(put) => next.put(caller, put, now_ms),
            MailboxToStation::Sync(sync) => next.sync(caller, sync),
            MailboxToStation::Done(done) => next.done(caller, done),
        })
    }

    /// The `heads` the Station sends `caller` at `now_ms`: `heads` with the
    /// caller's own mailbox head when its `welcome` lists `host.senders`
    /// (its mailbox minted then if it had none), else `heads` as §11.4 has
    /// it.
    pub fn heads(
        &self,
        caller: &LinkAssociation,
        heads: &Heads,
        host_senders: bool,
        now_ms: u64,
    ) -> Result<MailboxTransition, ModelError> {
        self.check_caller(caller)?;
        let mut next = self.tick(now_ms);
        let mailbox = host_senders.then(|| {
            let m = next.mailbox_or_mint(&caller.host_id, caller.host_trust_gen);
            MailboxHead {
                mailbox_id: m.mailbox_id.clone(),
                head: m.head,
            }
        });
        let answer = HeadsWithMailbox {
            heads: heads.clone(),
            mailbox: mailbox.clone(),
        }
        .to_json()
        .map_err(ModelError::Heads)?;
        Ok(MailboxTransition {
            next,
            answer: Some(answer),
            outcome: Outcome::Heads { mailbox },
        })
    }

    /// A reset of a receiving host's mailbox (rule 7).
    pub fn reset(
        &self,
        host_id: &str,
        host_trust_gen: u64,
        reset: Reset,
    ) -> Result<Self, ModelError> {
        let key = (host_id.to_owned(), host_trust_gen);
        let mut next = self.clone();
        let head = next
            .mailboxes
            .get(&key)
            .ok_or(ModelError::NoSuchReset)?
            .head;
        match reset {
            Reset::NewMailbox => {
                let mailbox_id = next.mint(&key);
                next.mailboxes.insert(
                    key,
                    Mailbox {
                        mailbox_id,
                        head: 0,
                        objects: BTreeMap::new(),
                    },
                );
            }
            Reset::HeadBack { head: back } => {
                if back >= head {
                    return Err(ModelError::NoSuchReset);
                }
                let mailbox = next.mailboxes.get_mut(&key).expect("checked above");
                mailbox.objects.retain(|position, _| *position <= back);
                mailbox.head = back;
            }
        }
        Ok(next)
    }

    /// The time is `now_ms`: every object whose `expires_at` has come is
    /// removed.
    pub fn tick(&self, now_ms: u64) -> Self {
        let mut next = self.clone();
        for mailbox in next.mailboxes.values_mut() {
            mailbox
                .objects
                .retain(|_, stored| stored.expires_at > now_ms);
        }
        next
    }

    // ------------------------------------------------------------ calls

    /// The caller is a complete association of this device list (the
    /// Station gives each device list's calls to its own model).
    fn check_caller(&self, caller: &LinkAssociation) -> Result<(), ModelError> {
        if !caller.complete() {
            return Err(ModelError::IncompleteLink);
        }
        if caller.account_id != self.account_id || caller.genesis_hash != self.genesis_hash {
            return Err(ModelError::OtherAccount);
        }
        Ok(())
    }

    fn drop_call(mut self, why: Dropped) -> MailboxTransition {
        self.dropped += 1;
        MailboxTransition {
            next: self,
            answer: None,
            outcome: Outcome::Dropped(why),
        }
    }

    fn mint(&mut self, key: &(String, u64)) -> String {
        let n = self.minted.entry(key.clone()).or_default();
        let id = mailbox_id(
            &self.seed,
            &self.account_id,
            &self.genesis_hash,
            &key.0,
            key.1,
            *n,
        );
        *n += 1;
        id
    }

    fn mailbox_or_mint(&mut self, host_id: &str, host_trust_gen: u64) -> &mut Mailbox {
        let key = (host_id.to_owned(), host_trust_gen);
        if !self.mailboxes.contains_key(&key) {
            let mailbox_id = self.mint(&key);
            self.mailboxes.insert(
                key.clone(),
                Mailbox {
                    mailbox_id,
                    head: 0,
                    objects: BTreeMap::new(),
                },
            );
        }
        self.mailboxes.get_mut(&key).expect("inserted above")
    }

    /// The caller's own mailbox, when `mailbox_id` names it and the caller
    /// is a current host of the list at its link's generation (rule 1, as
    /// for a put).
    fn own(&self, caller: &LinkAssociation, mailbox_id: &str) -> Option<(String, u64)> {
        let key = (caller.host_id.clone(), caller.host_trust_gen);
        let named = self
            .mailboxes
            .get(&key)
            .is_some_and(|m| m.mailbox_id == mailbox_id);
        (named && self.hosts.is_current(&key.0, key.1)).then_some(key)
    }

    /// Rules 1 and 3.
    fn put(mut self, caller: &LinkAssociation, put: MailboxPut, now_ms: u64) -> MailboxTransition {
        let (_, body) = put.mail().expect("the reader read the body");
        // Charged as received (design II.4.3); the reader bounded it.
        let bytes = put.object_bytes().len() as u64;
        let refuse = |next: ReferenceMailbox, code: PutRefusal| MailboxTransition {
            answer: Some(
                MailboxPutRefused {
                    request_id: put.request_id.clone(),
                    id: body.id.clone(),
                    code,
                }
                .to_json()
                .expect("the reader's own fields"),
            ),
            next,
            outcome: Outcome::PutRefused(code),
        };
        // Rule 1: a current host of the account, with its own objects; rule
        // 3: to a current host at the generation it names.
        let own = self
            .hosts
            .is_current(&caller.host_id, caller.host_trust_gen)
            && body.sender.host_id == caller.host_id
            && body.account_id == caller.account_id
            && body.genesis_hash == caller.genesis_hash;
        if !own
            || !self
                .hosts
                .is_current(&body.recipient.host_id, body.recipient.host_trust_gen)
        {
            return refuse(self, PutRefusal::Forbidden);
        }
        // Passed, or times no receiver takes (Atem's reading, agreed).
        if now_ms >= body.expires_at
            || body.expires_at <= body.created_at
            || body.expires_at - body.created_at > MAX_LIFETIME_MS
        {
            return refuse(self, PutRefusal::Expired);
        }
        let hash = object_hash(put.object());
        let recipient = (
            body.recipient.host_id.clone(),
            body.recipient.host_trust_gen,
        );
        // Only a store mints the recipient's mailbox: a refused put leaves
        // none behind.
        let held = self.mailboxes.get(&recipient).and_then(|mailbox| {
            mailbox
                .objects
                .iter()
                .find(|(_, s)| s.sender == caller.host_id && s.id == body.id)
                .map(|(position, s)| (*position, s.object_hash))
        });
        match held {
            Some((position, held)) if held == hash => {
                let answer = stored_answer(&put, &body);
                return MailboxTransition {
                    next: self,
                    answer: Some(answer),
                    outcome: Outcome::AlreadyStored { position },
                };
            }
            Some(_) => return refuse(self, PutRefusal::IdReused),
            None => {}
        }
        if self
            .sender_usage(&caller.host_id)
            .over(self.quotas.sender, bytes)
            || self
                .receiver_usage(&recipient.0, recipient.1)
                .over(self.quotas.receiver, bytes)
            || self.account_usage().over(self.quotas.account, bytes)
        {
            return refuse(self, PutRefusal::Quota);
        }
        let answer = stored_answer(&put, &body);
        let mailbox = self.mailbox_or_mint(&recipient.0, recipient.1);
        let position = mailbox.head + 1;
        mailbox.head = position;
        mailbox.objects.insert(
            position,
            Stored {
                sender: caller.host_id.clone(),
                id: body.id.clone(),
                object_hash: hash,
                object: put.object().clone(),
                bytes,
                expires_at: body.expires_at,
            },
        );
        MailboxTransition {
            next: self,
            answer: Some(answer),
            outcome: Outcome::Stored { position },
        }
    }

    /// Rules 1 and 4.
    fn sync(self, caller: &LinkAssociation, sync: MailboxSync) -> MailboxTransition {
        let Some(key) = self.own(caller, &sync.mailbox_id) else {
            return refused(self, MailboxRefusedCall::Sync);
        };
        let mailbox = &self.mailboxes[&key];
        let head = mailbox.head;
        let reset = sync.after > head;
        let (through, entry) = if reset {
            (head, None)
        } else {
            let mut after = mailbox.objects.range(sync.after + 1..);
            match after.next() {
                // The first stored object, and every removed position up to
                // the next one (or the head).
                Some((position, stored)) => (
                    after.next().map_or(head, |(next, _)| next - 1),
                    Some(MailboxEntry::new(*position, &stored.object)),
                ),
                None => (head, None),
            }
        };
        let position = entry.as_ref().map(|e| e.position);
        let page = MailboxSyncResult {
            request_id: sync.request_id,
            mailbox_id: sync.mailbox_id,
            after: sync.after,
            head,
            through,
            objects: entry.into_iter().collect(),
        };
        let answer = page.to_json().expect("every stored object is served");
        MailboxTransition {
            next: self,
            answer: Some(answer),
            outcome: Outcome::Page {
                through,
                position,
                reset,
            },
        }
    }

    /// Rules 1 and 5.
    fn done(mut self, caller: &LinkAssociation, done: MailboxDone) -> MailboxTransition {
        let Some(key) = self.own(caller, &done.mailbox_id) else {
            return refused(self, MailboxRefusedCall::Done);
        };
        let mailbox = self.mailboxes.get_mut(&key).expect("its own");
        let removed = mailbox.objects.remove(&done.position).is_some();
        let answer = MailboxDoneResult {
            request_id: done.request_id,
            mailbox_id: done.mailbox_id,
            position: done.position,
        }
        .to_json()
        .expect("the reader's own fields");
        MailboxTransition {
            next: self,
            answer: Some(answer),
            outcome: Outcome::Done { removed },
        }
    }
}

/// `account_id`: 1 to this many bytes, as the device list's (§R9.2).
const MAX_ACCOUNT_ID_BYTES: usize = 128;

fn stored_answer(put: &MailboxPut, body: &MailBody) -> Value {
    MailboxStored {
        request_id: put.request_id.clone(),
        id: body.id.clone(),
    }
    .to_json()
    .expect("the reader's own fields")
}

fn refused(next: ReferenceMailbox, call: MailboxRefusedCall) -> MailboxTransition {
    MailboxTransition {
        next,
        answer: Some(
            MailboxCallRefused {
                call,
                code: RefusalCode::Forbidden,
            }
            .to_json()
            .expect("a refusal's one field"),
        ),
        outcome: Outcome::Refused(call),
    }
}

#[cfg(test)]
#[path = "reference_tests.rs"]
mod tests;

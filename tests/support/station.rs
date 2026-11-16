//! A fake Station on the fake Astation's links (host-work-v1 §11.4): an
//! account's control feed and its heads, the host's own device-list fetch
//! and the reference acknowledgment ledger, answered as the agreed contract
//! says. It speaks only the shared core: every message it sends is made by
//! a builder of `atem_client::control::relay` (or `ledger`), and every call
//! the host sends is read by its strict reader, from the bytes the host
//! sent; the fake writes no wire JSON of its own.
//!
//! The test drives it: the `FakeStation` itself runs nothing in the
//! background ([`Pump`] puts it online on a thread of its own, when a test
//! asks). Make it before the
//! runtime starts (it takes the host's calls from then on:
//! [`FakeAstation::station_calls`]), then [`FakeStation::serve`] the
//! host's link: on a link it hasn't served it announces `heads` (as on
//! every (re)connection), then it answers every call the host sent so far
//! on the link the call came on, and announces `heads` again once 30
//! seconds passed (the heartbeat). [`FakeStation::next_call`] waits for
//! the host's next call and answers it.
//!
//! The heartbeat runs on the real clock, whenever `serve` or `next_call`
//! is called: a test that reads the link message by message (a slow
//! runner can take 30 s between two steps) silences it
//! ([`FakeStation::silence_heads`]) or reads past `heads` to the message
//! it wants.
//!
//! What it answers (§11.4):
//! - `control_sync`: the records after `after` of the account's one feed at
//!   this Station, ascending, as many as fit in one message (at most 64,
//!   and the whole message within 256 KiB: the builder's own bounds), with
//!   the feed's head and the Station's time, the call's `request_id` and
//!   `after` echoed (wire rule 11). A call for a feed that isn't the
//!   account's at this Station (another origin, a `feed_id` the account
//!   never had here) is refused, `control_sync_refused` ("One feed per
//!   account").
//! - A `control_sync` naming the account's feed from before a reset is
//!   refused, `control_sync_refused` (wire rule 11, as Astation decided on
//!   #164): [`StaleFeed::Refuse`], the default. [`StaleFeed::ServeCurrent`]
//!   is a Station that breaks the rule, for the host's defences: the
//!   account's current feed from position 0 (`after: 0` echoed), its
//!   `feed_id` not the call's, a page the host takes for no answer.
//! - `membership_fetch`: the device list's entries after `after`, as many
//!   as fit (at most 64, within 256 KiB), and its head.
//! - `control_ack`: no answer when the reference [`AckLedger`] counts it;
//!   `control_ack_refused` when it refuses the ack for its association on
//!   this link ([`AckRefusal::reply`]); nothing for any other refusal. The
//!   link's verified association is the host the fake was made for, its
//!   connection `link-<n>`. An ack is counted as it comes, even while the
//!   test waits for another call to hold ([`FakeStation::hold_call`];
//!   [`FakeStation::hold_ack`] holds one).
//! - [`FakeStation::refuse`]: that call answered with its typed refusal,
//!   nothing served or counted.
//! - [`FakeStation::serve_other_account`]: a Station that serves another
//!   account's data on this link ([`OTHER_ACCOUNT`]): its heads, feed and
//!   device list, as if the link were that account's.
//! - Bytes the shared reader refuses get no answer (kept in
//!   [`FakeStation::sent`]).
//! - [`FakeStation::require_proof`]: a Station that requires the host's
//!   fresh route proof on each link before it serves the link's calls (the
//!   delegated host-work design I.5.8, "Which host is calling": session-v1
//!   R9.7b's challenge, carried through Astation's local `:8080` proxy
//!   unchanged). It challenges a link it hasn't served, verifies the host's
//!   `host_route` with the shared verifier of the proxy kind (a forwarded
//!   proof is never a relay route) against its own device list,
//!   answers the verdict, and only then serves the link's calls and
//!   announces its `heads` there; until then every call gets its typed
//!   refusal. Off (the default) it needs no proof, as before.
//!
//! Host senders' mailboxes (host-work-v1 §11.5, "The mailbox calls"),
//! read and answered with `atem_client::host_mail::mailbox`'s readers and
//! builders only:
//! - One mailbox per receiving host and trust generation (rule 2), its
//!   `mailbox_id` a UUID v4 minted with it and never reused; `heads` carry
//!   the calling host's own only when the test says the host's welcome
//!   lists `host.senders` ([`FakeStation::host_lists_senders`]: the
//!   welcome is end to end, the fake can't read it), and go at once when an
//!   object is stored there (unless silenced).
//! - Puts ([`FakeStation::put`], from a sending host the test plays, as
//!   over its own link): rule 1 (the object's sender is the calling host,
//!   a current host of the account at that generation; its account and
//!   genesis the link's), then rule 3 (the recipient a current host at that
//!   generation; the times; idempotency on `(calling host, body.id)` by
//!   `object_hash` while stored, `id_reused` for other bytes; the quotas,
//!   [`MailboxQuota`] per sending host, receiving host and account, on
//!   each object's bytes as received, or [`FakeStation::refuse_quota`]).
//!   A put it can't read gets no answer (dropped, counted). Capacity
//!   reserved for control objects isn't modelled.
//! - `mailbox_sync` (rule 4): the first stored object after `after`, the
//!   page's `through` covering every position up to the next stored one
//!   (done or expired positions included), or to the head; a reset's form
//!   when `after` is beyond the head. Objects expire on the Station's clock.
//! - `mailbox_done` (rule 5): only on the receiving host's own link (its
//!   association's mailbox); removes the object, its key freed, and is
//!   answered the same when nothing is there.
//! - A call naming another mailbox (another host's, or the host's own from
//!   before a reset or under its earlier trust generation) is refused
//!   (`mailbox_sync_refused`, `mailbox_done_refused`); so is every one while
//!   [`FakeStation::refuse_mailbox`] says.
//! - Switches: [`FakeStation::drop_stored`] and
//!   [`FakeStation::drop_done_results`] (the next answers lost, their
//!   effect kept), [`FakeStation::reset_mailbox`] (a new `mailbox_id`) and
//!   [`FakeStation::roll_back_mailbox`] (the head back under the same id, a
//!   Station fault); a page delivered late is a held call
//!   ([`FakeStation::hold_mailbox`]) answered later.
//!   [`FakeStation::store_unchecked`] stores an object with no intake check
//!   (a Station that misroutes).
//!
//! What a well-behaved Station never does, for the host's defences:
//! [`FakeStation::heads_with`] (heads naming any feeds, another origin's
//! included), [`FakeStation::append_gap`] (positions left out, which §11.4
//! allows) and [`FakeStation::truncate`] (the feed rolled back under the
//! same `feed_id`: a head below the host's cursor). Messages outside the
//! contract (over 256 KiB, not strict JSON, a record the parser refuses)
//! the builders can't make: a test sends those bytes itself
//! ([`FakeAstation::send`]).
#![allow(dead_code)]

use super::astation::{FakeAstation, LinkSender};
use super::r9log::{TestLog, auth, secret};
use atem_client::control::relay::{MAX_FEED_RECORDS, MAX_FETCH_ENTRIES};
use atem_client::control::{
    AckLedger, AckRefusal, CallRefused, ControlAbout, ControlAck, ControlAction, ControlBody,
    ControlFeed, ControlPrincipal, ControlRecord, ControlSigner, ControlSync, ControlSyncResult,
    FeedEntry, FeedHead, Heads, LinkAssociation, MembershipFetch, MembershipFetchResult,
    RefusalCode, RefusedCall, RelayError, ToStation, build_control, principal_key_of,
};
use atem_client::control::{HeadsWithMailbox, MailboxHead};
use atem_client::encoding::Hash32;
use atem_client::host_mail::MailBody;
use atem_client::host_mail::mailbox::{
    MailboxCallRefused, MailboxDone, MailboxDoneResult, MailboxEntry, MailboxPut,
    MailboxPutRefused, MailboxRefusedCall, MailboxStored, MailboxSync, MailboxSyncResult,
    MailboxToStation, PutRefusal, is_mailbox_op, object_hash,
};
use atem_client::host_route::{
    HostChallenge, HostRoute, HostRouteRefusal, RelayReply, RouteKind, verify_host_route_message_as,
};
use atem_client::membership::{Head, Membership};
use atem_client::{KeyProvider, SignedObject, SoftwareKeys};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The account whose data the fake serves when told to
/// ([`FakeStation::serve_other_account`]).
pub const OTHER_ACCOUNT: &str = "acct-fake-station-other";

/// The Station's heartbeat: `heads` every 30 seconds (§11.4).
const HEARTBEAT: Duration = Duration::from_secs(30);

/// The longest [`FakeStation::next_call`] waits; it only bounds a failure.
const WAIT: Duration = Duration::from_secs(60);

/// What a `control_sync` naming the account's feed from before a reset
/// gets (the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleFeed {
    /// `control_sync_refused`: wire rule 11, as Astation decided on #164.
    Refuse,
    /// A Station that breaks the rule: the account's current feed from
    /// position 0 (`after: 0`: a cursor belongs to a feed), as for a call
    /// with no `feed_id`. The page names another feed than the call, so it
    /// doesn't answer it (`ControlSyncResult::answers`).
    ServeCurrent,
}

/// A call of the host's the fake took and hasn't answered
/// ([`FakeStation::hold_call`]).
#[derive(Debug)]
pub struct Held {
    link: u64,
    bytes: String,
}

impl Held {
    /// The call, as the shared reader reads it.
    pub fn call(&self) -> Result<ToStation, RelayError> {
        ToStation::decode(self.bytes.as_bytes())
    }

    /// The link it came on.
    pub fn link(&self) -> u64 {
        self.link
    }

    /// The call as the shared mailbox reader reads it (host-work-v1
    /// §11.5).
    pub fn mailbox(&self) -> Result<MailboxToStation, RelayError> {
        MailboxToStation::decode(self.bytes.as_bytes())
    }
}

/// The Station's limits on mailbox objects (design II.4.3's starting
/// limits, whichever comes first), on the encoded bytes of each object:
/// stored per sending host, per receiving host's mailbox and per account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxQuota {
    pub per_sender: usize,
    pub per_sender_bytes: usize,
    pub per_mailbox: usize,
    pub per_mailbox_bytes: usize,
    pub per_account: usize,
    pub per_account_bytes: usize,
}

impl Default for MailboxQuota {
    /// 128 objects or 32 MiB per sending host, 256 objects or 64 MiB per
    /// receiving host, 1,024 objects or 256 MiB per account (design
    /// II.4.3).
    fn default() -> Self {
        MailboxQuota {
            per_sender: 128,
            per_sender_bytes: 32 << 20,
            per_mailbox: 256,
            per_mailbox_bytes: 64 << 20,
            per_account: 1024,
            per_account_bytes: 256 << 20,
        }
    }
}

/// A receiving host's mailbox at this Station (§11.5 rule 2).
#[derive(Debug, Clone)]
struct Mailbox {
    mailbox_id: String,
    /// The last position given (0: none).
    head: u64,
    /// The objects stored, by position.
    stored: BTreeMap<u64, Stored>,
}

/// An object stored in a mailbox.
#[derive(Debug, Clone)]
struct Stored {
    /// Its key (rule 3): the calling host and the body's `id`.
    sender: String,
    id: String,
    /// Its identity (`object_hash`).
    hash: Hash32,
    expires_at: u64,
    /// The encoded bytes charged.
    bytes: usize,
    object: SignedObject,
}

/// A host's `host_route` on a link ([`FakeStation::require_proof`]): the
/// challenge's nonce, the bytes the host sent and the shared verifier's
/// verdict.
#[derive(Debug, Clone)]
pub struct ProofSeen {
    pub link: u64,
    /// `None`: no challenge was open on the link.
    pub nonce: Option<[u8; 32]>,
    pub message: String,
    pub verdict: Result<HostRoute, HostRouteRefusal>,
}

/// What a link's proof must name ([`FakeStation::require_proof`]).
struct ProofRule {
    room: String,
    atem_id: String,
}

/// One account at this Station: its device list and its one control feed
/// (§11.4, "One feed per account").
struct Account {
    account_id: String,
    genesis_hash: Hash32,
    /// The device list from its genesis (`seq` n is `entries[n - 1]`).
    entries: Vec<SignedObject>,
    /// The same list, verified (a proof is checked against it, and the
    /// mailbox's puts: who is a current host; entries stored beyond it
    /// aren't in it).
    membership: Membership,
    head: Head,
    /// How many feeds the account had here (a reset mints the next): its
    /// `n`th `feed_id` is `feed_id(origin, account, n)`.
    feeds: u64,
    feed_id: String,
    /// The feed's records with their `feed_seq`, ascending.
    records: Vec<(u64, ControlRecord)>,
    /// Positions left out before the next record ([`FakeStation::append_gap`]).
    gap: u64,
}

impl Account {
    fn of(origin: &str, log: &TestLog) -> Account {
        let account_id = log.account.clone();
        Account {
            feed_id: feed_id(origin, &account_id, 1),
            account_id,
            genesis_hash: log.genesis_hash(),
            entries: log.entries.iter().map(|e| e.object().clone()).collect(),
            membership: log.log.clone(),
            head: log.log.head(),
            feeds: 1,
            records: Vec::new(),
            gap: 0,
        }
    }

    /// The feed's head: its last record's position (0: none).
    fn feed_head(&self) -> u64 {
        self.records.last().map_or(0, |(seq, _)| *seq)
    }
}

/// A UUID v4 from `parts` (deterministic: a run repeats).
fn uuid_v4(parts: &[&str]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(parts.join("\n"));
    let bytes: [u8; 16] = digest[..16].try_into().unwrap();
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

/// The `feed_id` of an account's `n`th feed at `origin`.
fn feed_id(origin: &str, account_id: &str, n: u64) -> String {
    uuid_v4(&["atem fake station feed", origin, account_id, &n.to_string()])
}

/// The key of `service:<service>` as [`TestLog`] makes it (Ed25519 from
/// `secret("<service> auth")`): a Station holds its integrations' keys.
fn service_key(service: &str) -> SoftwareKeys {
    let mut keys = SoftwareKeys::new();
    keys.insert_ed25519(auth(service), &secret(&format!("{service} auth")));
    keys
}

fn refusal(call: RefusedCall) -> Value {
    CallRefused {
        call,
        code: RefusalCode::Forbidden,
    }
    .to_json()
    .expect("a refusal")
}

fn slot(call: RefusedCall) -> usize {
    match call {
        RefusedCall::ControlSync => 0,
        RefusedCall::MembershipFetch => 1,
        RefusedCall::ControlAck => 2,
    }
}

/// The message of as many of `max` items as fit: `build(n)` for the
/// largest `n ≤ max` the builder accepts (it refuses a message over 256
/// KiB, `too_large`). Size grows with `n`, so a binary search finds it.
fn fit(max: usize, build: impl Fn(usize) -> Result<Value, RelayError>) -> Value {
    let fits = |n| match build(n) {
        Ok(_) => true,
        Err(RelayError::TooLarge) => false,
        Err(e) => panic!("the builder refuses the fake's message: {e}"),
    };
    let (mut lo, mut hi) = (0, max);
    if !fits(hi) {
        // `lo` fits (an empty page does), `hi` doesn't.
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            if fits(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        hi = lo;
    }
    build(hi).expect("a message within the bound")
}

/// The fake Station (the module docs give its rules).
pub struct FakeStation {
    /// The Station's exact origin.
    origin: String,
    /// The host it serves: the link's verified association.
    host_id: String,
    host_trust_gen: u64,
    /// The host's calls, from the fake Astation, and where answers go.
    calls: mpsc::Receiver<(u64, String)>,
    out: LinkSender,
    /// The calling host's account, and the one served when told to.
    own: Account,
    other: Account,
    other_on: bool,
    /// The reference acknowledgment ledger of the host's account here.
    ledger: AckLedger,
    ack_refusals: Vec<AckRefusal>,
    refusing: [bool; 3],
    stale: StaleFeed,
    silent: bool,
    /// The Station's clock (ms): fixed by the test, else the wall clock.
    time: Option<u64>,
    /// The link served, and when it last got `heads`.
    link: Option<u64>,
    last_heads: Option<Instant>,
    /// Every call the host sent, as its bytes, and the link it came on.
    sent: Vec<String>,
    sent_on: Vec<u64>,
    /// Links before this one were associated with an identity of the host
    /// that has moved on ([`FakeStation::reassociate`]): their acks are
    /// refused.
    retired_below: u64,
    /// Records signed so far (their `record_id`s).
    minted: u64,
    /// While set, each link must prove its host first
    /// ([`FakeStation::require_proof`]): the challenges open, by link, the
    /// links whose proof verified, and every proof the host sent.
    proof: Option<ProofRule>,
    challenges: std::collections::HashMap<u64, [u8; 32]>,
    proved: std::collections::HashSet<u64>,
    proofs: Vec<ProofSeen>,
    /// The host's trust generation its links below `retired_below` are
    /// associated with ([`FakeStation::reassociate`]): their mailbox calls
    /// name that generation's mailbox.
    prior_gen: u64,
    /// Host senders' mailboxes, by receiving `(host_id, host_trust_gen)`
    /// (§11.5 rule 2), and how many were minted (a new `mailbox_id` each).
    mailboxes: BTreeMap<(String, u64), Mailbox>,
    mailboxes_minted: u64,
    /// The host's welcome lists `host.senders`: `heads` carry its mailbox.
    senders: bool,
    quota: MailboxQuota,
    refuse_quota: bool,
    /// The mailbox calls refused while on: `mailbox_sync`, `mailbox_done`.
    refusing_mailbox: [bool; 2],
    /// How many of the next `mailbox_stored` and `mailbox_done_result` are
    /// lost (their effect kept).
    drop_stored: u64,
    drop_done_results: u64,
    /// Puts the Station couldn't read (dropped unanswered, rule 3).
    puts_dropped: u64,
}

impl FakeStation {
    /// The Station at `origin` (exact, as `normalize_relay` writes it) of
    /// `log`'s account, serving the host `host_id` in `host_trust_gen` on
    /// `astation`'s links: its feed empty, its device list `log`'s. One per
    /// origin and account in a test (feed and record ids are derived from
    /// them, so a run repeats).
    pub fn new(
        astation: &FakeAstation,
        origin: &str,
        log: &TestLog,
        host_id: &str,
        host_trust_gen: u64,
    ) -> FakeStation {
        let own = Account::of(origin, log);
        let mut other_log = TestLog::genesis(OTHER_ACCOUNT, &secret("fake station other account"));
        other_log.add_host(host_id, host_trust_gen, &secret("fake station other host"));
        let ledger = AckLedger::new(origin, &own.account_id, own.genesis_hash)
            .expect("an exact origin and an account id");
        FakeStation {
            origin: origin.to_owned(),
            host_id: host_id.to_owned(),
            host_trust_gen,
            calls: astation.station_calls(),
            out: astation.sender(),
            other: Account::of(origin, &other_log),
            own,
            other_on: false,
            ledger,
            ack_refusals: Vec::new(),
            refusing: [false; 3],
            stale: StaleFeed::Refuse,
            silent: false,
            time: None,
            link: None,
            last_heads: None,
            sent: Vec::new(),
            sent_on: Vec::new(),
            retired_below: 0,
            minted: 0,
            proof: None,
            challenges: Default::default(),
            proved: Default::default(),
            proofs: Vec::new(),
            prior_gen: host_trust_gen,
            mailboxes: BTreeMap::new(),
            mailboxes_minted: 0,
            senders: false,
            quota: MailboxQuota::default(),
            refuse_quota: false,
            refusing_mailbox: [false; 2],
            drop_stored: 0,
            drop_done_results: 0,
            puts_dropped: 0,
        }
    }

    /// From now on a link's calls are served only after the host proved on
    /// it which host it is (the module docs): on a link it hasn't served
    /// yet the Station sends `host_challenge` for `room` (instead of its
    /// `heads`) and expects the proof for `room` and `atem_id` (the host's
    /// relay room and `atem_id`, as a relay checks them).
    pub fn require_proof(&mut self, room: &str, atem_id: &str) {
        self.proof = Some(ProofRule {
            room: room.to_owned(),
            atem_id: atem_id.to_owned(),
        });
    }

    /// A fresh `host_challenge` on `link` now, for the room
    /// [`FakeStation::require_proof`] named (the Station asking again).
    pub fn challenge(&mut self, link: u64) {
        let room = &self.proof.as_ref().expect("require_proof first").room;
        let challenge = HostChallenge::new(room);
        self.challenges.insert(link, challenge.nonce);
        self.out.send(link, challenge.to_json().to_string());
    }

    /// `before` (Astation's own message, as its `authenticated`) and right
    /// behind it a fresh `host_challenge` on `link` (as
    /// [`FakeStation::challenge`]), in one write: the host reads them
    /// together, as a challenge Astation's proxy forwards right after
    /// Astation's reply.
    pub fn challenge_behind(&mut self, link: u64, before: String) {
        let room = &self.proof.as_ref().expect("require_proof first").room;
        let challenge = HostChallenge::new(room);
        self.challenges.insert(link, challenge.nonce);
        self.out
            .send_all(link, vec![before, challenge.to_json().to_string()]);
    }

    /// Every `host_route` the host sent so far (read by
    /// [`FakeStation::serve`] and the others as they come), in order.
    pub fn proofs(&self) -> &[ProofSeen] {
        &self.proofs
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The served account's current `feed_id`.
    pub fn feed_id(&self) -> &str {
        &self.served().feed_id
    }

    /// The served account's feed: each record with its `feed_seq`,
    /// ascending.
    pub fn records(&self) -> Vec<(u64, &ControlRecord)> {
        self.served()
            .records
            .iter()
            .map(|(seq, record)| (*seq, record))
            .collect()
    }

    /// The reference ledger of the host's account at this Station: what it
    /// counted of the host's acks.
    pub fn acks(&self) -> &AckLedger {
        &self.ledger
    }

    /// The acks the ledger refused, in order.
    pub fn ack_refusals(&self) -> &[AckRefusal] {
        &self.ack_refusals
    }

    /// Every Station call the fake has read so far (by
    /// [`FakeStation::serve`] or [`FakeStation::next_call`]), as the bytes
    /// the host sent, in order: a call that arrived but wasn't served yet
    /// isn't here, so serve before comparing. What reaches the fake is a
    /// text frame the fake Astation reads as JSON, or one that names a
    /// Station call (`"control_sync"`, `"control_ack"`,
    /// `"membership_fetch"`, or a mailbox call: `"mailbox_sync"`,
    /// `"mailbox_done"`, `"mailbox_put"`); a binary frame never does.
    pub fn sent(&self) -> Vec<String> {
        self.sent.clone()
    }

    /// [`FakeStation::sent`], only the calls that came on `link`.
    pub fn sent_on(&self, link: u64) -> Vec<String> {
        self.sent
            .iter()
            .zip(&self.sent_on)
            .filter(|(_, on)| **on == link)
            .map(|(bytes, _)| bytes.clone())
            .collect()
    }

    /// The host's identity moved on (a re-verify: its next trust
    /// generation in the device list, `host_trust_gen`), as a Station
    /// applies it (Astation's item 15 on #120): a link from `from_link` on
    /// is associated with the new identity; an older link's association is
    /// never relabelled, and its acks are refused for it from now on
    /// (`control_ack_refused`, metadata-free; [`FakeStation::ack_refusals`]
    /// says `NotTheLink`), nothing counted.
    /// Its mailbox calls are the new identity's too (§11.5 rule 1): a link
    /// from `from_link` on reads and marks the mailbox of the new trust
    /// generation (a new mailbox), an older one its old generation's.
    pub fn reassociate(&mut self, host_trust_gen: u64, from_link: u64) {
        self.prior_gen = self.host_trust_gen;
        self.host_trust_gen = host_trust_gen;
        self.retired_below = from_link;
    }

    /// Serves `link`: `heads` when it is a link not served yet, or when
    /// 30 seconds passed since the last (unless silenced), then an answer to
    /// every call the host sent so far. The calls answered, as the shared
    /// reader read them.
    pub fn serve(&mut self, link: u64) -> Vec<Result<ToStation, RelayError>> {
        self.attach(link);
        let mut served = Vec::new();
        while let Ok((from, bytes)) = self.calls.try_recv() {
            if is_host_route(&bytes) {
                self.on_proof(from, bytes);
                continue;
            }
            served.push(self.answer(from, bytes));
        }
        served
    }

    /// Takes `link` as the host's link, answering nothing: `heads` there
    /// when it is a link not served yet (unless silenced), as
    /// [`FakeStation::serve`] would.
    pub fn on_link(&mut self, link: u64) {
        self.attach(link);
    }

    /// [`FakeStation::serve`] on the newest link of the fake Astation (a
    /// runtime started again connects anew), if it has one.
    pub fn serve_latest(&mut self) -> Vec<Result<ToStation, RelayError>> {
        match self.out.latest() {
            Some(link) => self.serve(link),
            None => Vec::new(),
        }
    }

    /// Serves `link` until the host's next call of any kind (a
    /// `control_ack` included) arrived (at most a minute) and answers it.
    pub fn next_call(&mut self, link: u64) -> Result<ToStation, RelayError> {
        let held = self.hold_next(link, |_| true, Some(&|_: &MailboxToStation| true));
        self.answer_held(held)
    }

    /// Serves `link` until the host's next call that isn't a `control_ack`
    /// or a mailbox call arrived (at most a minute) and keeps it unanswered (in
    /// [`FakeStation::sent`] from now): a Station slow to answer, or one
    /// whose answer the test writes itself. [`FakeStation::answer_held`]
    /// answers it later; a call never answered is one the Station never
    /// answers. The host's acks that come first are counted as they come,
    /// as a Station does (an ack has no answer): [`FakeStation::hold_ack`]
    /// holds one.
    pub fn hold_call(&mut self, link: u64) -> Held {
        self.hold_next(
            link,
            |call| !matches!(call, Ok(ToStation::ControlAck(_))),
            None,
        )
    }

    /// Serves `link` until the host's next `control_ack` arrived (at most
    /// a minute) and keeps it uncounted, as [`FakeStation::hold_call`]
    /// keeps a call; the calls that come first are answered as they come.
    pub fn hold_ack(&mut self, link: u64) -> Held {
        self.hold_next(
            link,
            |call| matches!(call, Ok(ToStation::ControlAck(_))),
            None,
        )
    }

    /// The host's next call on `link` that `held` takes (a mailbox call
    /// only when `mailbox` takes it), kept unanswered; the ones before it
    /// answered as they come.
    fn hold_next(
        &mut self,
        link: u64,
        held: impl Fn(&Result<ToStation, RelayError>) -> bool,
        mailbox: Option<&dyn Fn(&MailboxToStation) -> bool>,
    ) -> Held {
        self.attach(link);
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let (from, bytes) = self
                .calls
                .recv_timeout(left)
                .expect("the host sent no such Station call");
            if is_host_route(&bytes) {
                self.on_proof(from, bytes);
                continue;
            }
            let take = if mailbox_call(&bytes) {
                mailbox.is_some_and(|take| {
                    MailboxToStation::decode(bytes.as_bytes()).is_ok_and(|call| take(&call))
                })
            } else {
                held(&ToStation::decode(bytes.as_bytes()))
            };
            if take {
                self.sent.push(bytes.clone());
                self.sent_on.push(from);
                return Held { link: from, bytes };
            }
            let _ = self.answer(from, bytes);
        }
    }

    /// The host's `control_ack`s the fake read so far, as the shared reader
    /// reads them.
    pub fn acks_sent(&self) -> Vec<ControlAck> {
        self.sent
            .iter()
            .filter_map(|bytes| match ToStation::decode(bytes.as_bytes()) {
                Ok(ToStation::ControlAck(ack)) => Some(ack),
                _ => None,
            })
            .collect()
    }

    /// Answers `held` now, as [`FakeStation::serve`] would answer it then,
    /// on the link it came on (a link gone since gets nothing).
    pub fn answer_held(&mut self, held: Held) -> Result<ToStation, RelayError> {
        self.reply(held.link, &held.bytes)
    }

    /// The served account's device list from now on: `log`. A log of the
    /// served account (its account and genesis) is its list grown; one of
    /// another account replaces the served account (its list, a new empty
    /// feed and, for the host's own, a new ledger). Announced at the next
    /// heads ([`FakeStation::heads_now`]).
    pub fn set_log(&mut self, log: &TestLog) {
        let origin = self.origin.clone();
        let same = {
            let served = self.served();
            served.account_id == log.account && served.genesis_hash == log.genesis_hash()
        };
        if same {
            let served = self.served_mut();
            served.entries = log.entries.iter().map(|e| e.object().clone()).collect();
            served.membership = log.log.clone();
            served.head = log.log.head();
            return;
        }
        *self.served_mut() = Account::of(&origin, log);
        if !self.other_on {
            self.ledger =
                AckLedger::new(&origin, &log.account, log.genesis_hash()).expect("an account id");
        }
    }

    /// [`FakeStation::set_log`], then `beyond` after `log`'s head: signed
    /// entries `log` can't verify yet (one its subject signed while a
    /// recovery's wait runs, R9.5), stored as a Station stores what devices
    /// send it; the device list's head is the last one's. Announced at the
    /// next heads.
    pub fn set_log_beyond(&mut self, log: &TestLog, beyond: &[Value]) {
        self.set_log(log);
        let served = self.served_mut();
        for value in beyond {
            let entry = atem_client::membership::Entry::parse_bytes(value.to_string().as_bytes())
                .expect("a signed entry");
            assert_eq!(entry.seq, served.head.seq + 1, "contiguous");
            served.head = Head {
                seq: entry.seq,
                hash: entry.hash(),
            };
            served.entries.push(entry.object().clone());
        }
    }

    /// Stores `record` at the next position of the served account's feed
    /// (after any [`FakeStation::append_gap`]): the reference ledger sees
    /// it first (for the host's account), then the feed serves it and
    /// `heads` go at once (unless silenced). Its `feed_seq`. The fake
    /// stores what the test hands it: a record the ledger refuses at intake
    /// (another account's or Station's, a reused `record_id`) is served
    /// untracked, as by a Station that skipped its intake checks; one the
    /// control parser refuses can't be served (the shared builder takes
    /// only a parsed record).
    pub fn append(&mut self, record: SignedObject) -> u64 {
        let record = ControlRecord::from_signed(record).expect("a control record");
        self.store(record);
        if !self.silent {
            self.send_heads();
        }
        self.served().feed_head()
    }

    /// The next `n` positions of the served feed hold no record: the next
    /// [`FakeStation::append`] is `n` past the head (§11.4 rule 7 allows
    /// gaps; whether one is a hole the cursor waits at is the host's).
    pub fn append_gap(&mut self, n: u64) {
        self.served_mut().gap += n;
    }

    /// The served feed rolled back to its records at or before position
    /// `n`, under the same `feed_id` (a Station fault: a restore mints a
    /// new `feed_id`, I.5.2), then `heads` at once (unless silenced). A host
    /// whose cursor passed the new head reads it as a reset.
    pub fn truncate(&mut self, n: u64) {
        let served = self.served_mut();
        served.records.retain(|(seq, _)| *seq <= n);
        served.gap = 0;
        if !self.silent {
            self.send_heads();
        }
    }

    /// A record of the served account's feed about `service:<service>`,
    /// signed with that service's key as [`TestLog`] makes it: what a
    /// Station issues for its integration (`i-<service>`, `about.by`
    /// `owner`), at the Station's time. Not stored: [`FakeStation::append`].
    pub fn record_for(&mut self, service: &str, action: ControlAction) -> SignedObject {
        let keys = service_key(service);
        let public = keys.public_key(&auth(service)).unwrap();
        let record_id = self.mint();
        let served = self.served();
        let body = ControlBody {
            account_id: served.account_id.clone(),
            genesis_hash: served.genesis_hash,
            feed: Some(ControlFeed {
                origin: self.origin.clone(),
                feed_id: served.feed_id.clone(),
            }),
            principal: ControlPrincipal::Service(service.to_owned()),
            principal_key: Some(principal_key_of(&public).unwrap()),
            signer: ControlSigner::Principal,
            action,
            record_id,
            issued_at: self.now(),
            about: ControlAbout {
                integration_id: Some(format!("i-{service}")),
                by: "owner".into(),
            },
        };
        build_control(&keys, &auth(service), &body).expect("a record the parser reads")
    }

    /// `heads` on the served link now (silenced or not).
    pub fn heads_now(&mut self) {
        let served = self.served();
        let feed = FeedHead {
            origin: self.origin.clone(),
            feed_id: served.feed_id.clone(),
            head: served.feed_head(),
            station_time: self.now(),
        };
        self.heads_with(vec![feed]);
    }

    /// `heads` naming exactly `feeds` (any origins and feeds, none
    /// included) and the served device list's head, on the served link
    /// now (silenced or not). The builder's bounds apply (64 feeds, a feed
    /// once).
    pub fn heads_with(&mut self, feeds: Vec<FeedHead>) {
        let link = self.link.expect("serve the host's link first");
        let heads = Heads {
            feeds,
            membership: self.served().head,
        };
        // The calling host's own mailbox, only for a host whose welcome
        // lists `host.senders` (§11.5 rule 6).
        let mailbox = self.senders.then(|| {
            let now = self.now();
            let mailbox = self.own_mailbox(link, now);
            MailboxHead {
                mailbox_id: mailbox.mailbox_id.clone(),
                head: mailbox.head,
            }
        });
        let heads = HeadsWithMailbox { heads, mailbox }
            .to_json()
            .expect("heads within the builder's bounds");
        self.out.send(link, heads.to_string());
        self.last_heads = Some(Instant::now());
    }

    /// No `heads` of its own while on: none for a new link, a stored
    /// record, a reset, a truncation or the heartbeat (the host's 60 s
    /// without heads). [`FakeStation::heads_now`] and
    /// [`FakeStation::heads_with`] still announce.
    pub fn silence_heads(&mut self, on: bool) {
        self.silent = on;
    }

    /// The served account's feed is reset (a Station restored from a
    /// backup, I.5.2): a new `feed_id`, never one used before, starting
    /// with the snapshot of the Station's current effective state, then
    /// `heads` at once (unless silenced). For each principal, in the order
    /// the old feed first named it: its latest `cover` and its latest
    /// `hold` or `release`, signed anew for the new feed with the service's
    /// key (newer than the old ones), then its `revoke` and
    /// `interrupt_running` records as they are. A record the Station can't
    /// sign anew (a host principal's, a key that isn't [`TestLog`]'s) is
    /// carried as it is. A `control_sync` naming the old feed gets what
    /// [`FakeStation::stale_feed`] says.
    pub fn reset(&mut self) {
        let origin = self.origin.clone();
        let served = self.served_mut();
        let old: Vec<ControlRecord> = std::mem::take(&mut served.records)
            .into_iter()
            .map(|(_, record)| record)
            .collect();
        served.gap = 0;
        served.feeds += 1;
        served.feed_id = feed_id(&origin, &served.account_id, served.feeds);
        for record in self.snapshot(&old) {
            self.store(record);
        }
        if !self.silent {
            self.send_heads();
        }
    }

    /// What a `control_sync` naming the account's feed from before a reset
    /// gets from now on (the default [`StaleFeed::Refuse`]).
    pub fn stale_feed(&mut self, mode: StaleFeed) {
        self.stale = mode;
    }

    /// The served account's feed, still empty, is named `feed_id` (a UUID
    /// v4) instead of the fake's own: a test comparing the host's calls
    /// with vectors that name a feed. A later [`FakeStation::reset`] mints
    /// the fake's own ids again (and a call naming this one then is refused
    /// as an unknown feed's, whatever [`FakeStation::stale_feed`] says).
    pub fn name_feed(&mut self, feed_id: &str) {
        let served = self.served_mut();
        assert!(
            served.records.is_empty(),
            "name the feed before it holds a record"
        );
        served.feed_id = feed_id.to_owned();
    }

    /// The Station's clock from now on, `ms` (`station_time` in heads and
    /// pages, the ledger's time, records' `issued_at`).
    pub fn station_time(&mut self, ms: u64) {
        self.time = Some(ms);
    }

    /// While on, `call` is answered with its typed refusal
    /// (`<call>_refused`, `forbidden`), and nothing is served or counted.
    pub fn refuse(&mut self, call: RefusedCall, on: bool) {
        self.refusing[slot(call)] = on;
    }

    /// While on, the fake serves another account's data on this link
    /// ([`OTHER_ACCOUNT`]: its device list, a genesis and this host, and
    /// its own feed): heads, pages and fetches are that account's, and
    /// [`FakeStation::append`], [`FakeStation::record_for`],
    /// [`FakeStation::reset`] and [`FakeStation::set_log`] act on it. Acks
    /// still count for the link's host, in its account's ledger.
    pub fn serve_other_account(&mut self, on: bool) {
        self.other_on = on;
    }

    // ------------------------------------------------------------ inside

    fn served(&self) -> &Account {
        if self.other_on {
            &self.other
        } else {
            &self.own
        }
    }

    fn served_mut(&mut self) -> &mut Account {
        if self.other_on {
            &mut self.other
        } else {
            &mut self.own
        }
    }

    fn now(&self) -> u64 {
        self.time.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        })
    }

    fn mint(&mut self) -> String {
        self.minted += 1;
        let account = self.served().account_id.clone();
        uuid_v4(&[
            "atem fake station record",
            &self.origin,
            &account,
            &self.minted.to_string(),
        ])
    }

    fn attach(&mut self, link: u64) {
        if self.link != Some(link) {
            self.link = Some(link);
            self.last_heads = None;
            if self.proof.is_some()
                && !self.proved.contains(&link)
                && !self.challenges.contains_key(&link)
            {
                self.challenge(link);
            }
        }
        // No `heads` before the link's proof, when one is required.
        if !self.serves(link) {
            return;
        }
        let due = self.last_heads.is_none_or(|at| at.elapsed() >= HEARTBEAT);
        if due && !self.silent {
            self.send_heads();
        }
    }

    /// The Station's own `heads`, on the served link if there is one (and
    /// it proved its host, when [`FakeStation::require_proof`] says so).
    fn send_heads(&mut self) {
        if self.link.is_some_and(|link| self.serves(link)) {
            self.heads_now();
        }
    }

    /// Whether the Station serves `link`'s calls: no proof required, or
    /// the link's verified.
    fn serves(&self, link: u64) -> bool {
        self.proof.is_none() || self.proved.contains(&link)
    }

    /// The host's `host_route` on `link`, checked against the Station's own
    /// device list (the shared verifier, the challenge's nonce and the
    /// required room and `atem_id`) and answered with the verdict; a proof
    /// that verifies lets the link's calls be served, and its `heads` go
    /// at once (unless silenced). A challenge takes one proof.
    fn on_proof(&mut self, link: u64, message: String) {
        let nonce = self.challenges.remove(&link);
        let verdict = match (&self.proof, nonce) {
            (Some(rule), Some(nonce)) => verify_host_route_message_as(
                RouteKind::Proxy,
                &self.own.membership,
                message.as_bytes(),
                &nonce,
                &rule.room,
                &rule.atem_id,
            ),
            _ => Err(HostRouteRefusal::Malformed("no challenge on this link")),
        };
        let reply = match &verdict {
            Ok(route) => RelayReply::ok(route),
            Err(refusal) => RelayReply::refused(refusal),
        };
        self.out.send(link, reply.to_json().to_string());
        let verified = verdict.is_ok();
        self.proofs.push(ProofSeen {
            link,
            nonce,
            message,
            verdict,
        });
        if verified {
            self.proved.insert(link);
            if self.link == Some(link) && !self.silent {
                self.send_heads();
            }
        }
    }

    /// The reference ledger sees a record of the host's account before the
    /// feed serves it (`AckLedger::record`: a revoke's start is the
    /// Station's time, its covered host the one served).
    fn store(&mut self, record: ControlRecord) {
        if !self.other_on {
            let now = self.now();
            let covered = [self.host_id.clone()];
            if let Ok(t) = self.ledger.record(&record, now, &covered, now) {
                self.ledger = t.next;
            }
        }
        let served = self.served_mut();
        let seq = served.feed_head() + served.gap + 1;
        served.gap = 0;
        served.records.push((seq, record));
    }

    fn snapshot(&mut self, old: &[ControlRecord]) -> Vec<ControlRecord> {
        let mut principals: Vec<&ControlPrincipal> = Vec::new();
        for record in old {
            if !principals.contains(&record.principal()) {
                principals.push(record.principal());
            }
        }
        let mut snapshot = Vec::new();
        for principal in principals {
            let of: Vec<&ControlRecord> =
                old.iter().filter(|r| r.principal() == principal).collect();
            let latest = |pick: fn(ControlAction) -> bool| {
                of.iter().rev().find(|r| pick(r.action())).copied()
            };
            if let Some(cover) = latest(|a| a == ControlAction::Cover) {
                snapshot.push(self.anew(cover));
            }
            if let Some(state) =
                latest(|a| matches!(a, ControlAction::Hold | ControlAction::Release))
            {
                snapshot.push(self.anew(state));
            }
            snapshot.extend(
                of.iter()
                    .filter(|r| {
                        matches!(
                            r.action(),
                            ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. }
                        )
                    })
                    .map(|r| (*r).clone()),
            );
        }
        snapshot
    }

    /// `record` signed anew for the served feed with its service's key,
    /// issued after it; as it is when the Station doesn't hold that key.
    fn anew(&mut self, record: &ControlRecord) -> ControlRecord {
        let ControlPrincipal::Service(service) = record.principal() else {
            return record.clone();
        };
        let keys = service_key(service);
        let public = keys.public_key(&auth(service)).unwrap();
        if principal_key_of(&public).ok() != record.principal_key() {
            return record.clone();
        }
        let mut body = record.body().clone();
        body.feed = Some(ControlFeed {
            origin: self.origin.clone(),
            feed_id: self.served().feed_id.clone(),
        });
        body.signer = ControlSigner::Principal;
        body.record_id = self.mint();
        body.issued_at = self.now().max(record.issued_at() + 1);
        let object = build_control(&keys, &auth(service), &body).expect("a record");
        ControlRecord::from_signed(object).unwrap()
    }

    /// Reads the host's call and answers it on its link.
    fn answer(&mut self, link: u64, bytes: String) -> Result<ToStation, RelayError> {
        self.sent.push(bytes.clone());
        self.sent_on.push(link);
        self.reply(link, &bytes)
    }

    /// Answers the host's call `bytes` (already in `sent`) on `link`.
    fn reply(&mut self, link: u64, bytes: &str) -> Result<ToStation, RelayError> {
        // Host senders' mailbox calls (§11.5), told by their `op`: read by
        // the shared mailbox reader (one it refuses gets no answer).
        if mailbox_call(bytes) {
            if let Ok(call) = MailboxToStation::decode(bytes.as_bytes())
                && let Some(reply) = self.mailbox_reply(link, call)
            {
                self.out.send(link, reply);
            }
            return ToStation::decode(bytes.as_bytes());
        }
        let call = ToStation::decode(bytes.as_bytes());
        // A link that hasn't proved its host, when one is required: every
        // call refused, nothing served or counted.
        if !self.serves(link) {
            let refused = match &call {
                Ok(ToStation::ControlSync(_)) => Some(RefusedCall::ControlSync),
                Ok(ToStation::MembershipFetch(_)) => Some(RefusedCall::MembershipFetch),
                Ok(ToStation::ControlAck(_)) => Some(RefusedCall::ControlAck),
                Err(_) => None,
            };
            if let Some(refused) = refused {
                self.out.send(link, refusal(refused).to_string());
            }
            return call;
        }
        let reply = match &call {
            Ok(ToStation::ControlSync(sync)) => Some(self.page(sync)),
            Ok(ToStation::MembershipFetch(fetch)) => Some(self.fetched(*fetch)),
            Ok(ToStation::ControlAck(ack)) => self.counted(link, ack),
            Err(_) => None,
        };
        if let Some(reply) = reply {
            self.out.send(link, reply.to_string());
        }
        call
    }

    fn page(&self, sync: &ControlSync) -> Value {
        let served = self.served();
        let current = sync.feed_id.as_ref().is_none_or(|id| *id == served.feed_id);
        // The account's feed before a reset (an unknown id stays refused:
        // it may be another account's).
        let stale = sync.feed_id.as_ref().is_some_and(|id| {
            (1..served.feeds).any(|n| feed_id(&self.origin, &served.account_id, n) == *id)
        });
        let serve_current = stale && self.stale == StaleFeed::ServeCurrent;
        if self.refusing[slot(RefusedCall::ControlSync)]
            || sync.origin != self.origin
            || !(current || serve_current)
        {
            return refusal(RefusedCall::ControlSync);
        }
        // A cursor belongs to a feed: another feed's is no position here.
        let after = if current { sync.after } else { 0 };
        let entries: Vec<FeedEntry> = served
            .records
            .iter()
            .filter(|(seq, _)| *seq > after)
            .map(|(seq, record)| FeedEntry::new(*seq, record))
            .collect();
        let now = self.now();
        fit(entries.len().min(MAX_FEED_RECORDS), |n| {
            ControlSyncResult {
                // The call's id, and the `after` served from (the call's
                // own, but for another feed's: wire rule 11).
                request_id: sync.request_id.clone(),
                origin: self.origin.clone(),
                feed_id: served.feed_id.clone(),
                after,
                head: served.feed_head(),
                station_time: now,
                records: entries[..n].to_vec(),
            }
            .to_json()
        })
    }

    fn fetched(&self, fetch: MembershipFetch) -> Value {
        if self.refusing[slot(RefusedCall::MembershipFetch)] {
            return refusal(RefusedCall::MembershipFetch);
        }
        let served = self.served();
        let from = usize::try_from(fetch.after)
            .unwrap_or(usize::MAX)
            .min(served.entries.len());
        let entries = &served.entries[from..];
        fit(entries.len().min(MAX_FETCH_ENTRIES), |n| {
            MembershipFetchResult {
                head: served.head,
                entries: entries[..n].to_vec(),
            }
            .to_json()
        })
    }

    /// The ledger's verdict on an ack from `link`: no answer when counted.
    fn counted(&mut self, link: u64, ack: &ControlAck) -> Option<Value> {
        if self.refusing[slot(RefusedCall::ControlAck)] {
            return Some(refusal(RefusedCall::ControlAck));
        }
        if link < self.retired_below {
            // An association of the host's old identity: refused for it.
            let refused = AckRefusal::NotTheLink;
            let reply = refused.reply().map(|r| r.to_json().expect("a refusal"));
            self.ack_refusals.push(refused);
            return reply;
        }
        let association = LinkAssociation {
            account_id: self.own.account_id.clone(),
            genesis_hash: self.own.genesis_hash,
            host_id: self.host_id.clone(),
            host_trust_gen: self.host_trust_gen,
            connection_id: format!("link-{link}"),
        };
        match self.ledger.ack(&association, ack, self.now()) {
            Ok(t) => {
                self.ledger = t.next;
                None
            }
            Err(refused) => {
                let reply = refused.reply().map(|r| r.to_json().expect("a refusal"));
                self.ack_refusals.push(refused);
                reply
            }
        }
    }
}

/// Whether `bytes` name a mailbox call by their top-level `op` (a scan to
/// dispatch: the shared mailbox reader reads them).
fn mailbox_call(bytes: &str) -> bool {
    serde_json::from_str::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("op").and_then(Value::as_str).map(is_mailbox_op))
        .unwrap_or(false)
}

/// The length of a put's `object` as the call carried it (its exact text,
/// whitespace and escapes included).
fn received_object_len(bytes: &[u8]) -> Option<usize> {
    #[derive(serde::Deserialize)]
    struct Put<'a> {
        #[serde(borrow)]
        object: &'a serde_json::value::RawValue,
    }
    serde_json::from_slice::<Put>(bytes)
        .ok()
        .map(|put| put.object.get().len())
}

/// A mailbox's `mailbox_id`: the `n`th minted at `origin` for `account_id`
/// (deterministic: a run repeats; never reused within it).
fn mailbox_id(origin: &str, account_id: &str, n: u64) -> String {
    uuid_v4(&[
        "atem fake station mailbox",
        origin,
        account_id,
        &n.to_string(),
    ])
}

// ------------------------------------------- host senders' mailboxes (§11.5)

impl FakeStation {
    /// Whether the host's welcome lists `host.senders` (the test says: the
    /// welcome is end to end): from now on `heads` carry its own mailbox
    /// (rule 6), and go at once when an object is stored there (unless
    /// silenced). Off (the default): `heads` exactly as §11.4 has them.
    pub fn host_lists_senders(&mut self, on: bool) {
        self.senders = on;
    }

    /// The Station's limits on mailbox objects from now on.
    pub fn set_mailbox_quota(&mut self, quota: MailboxQuota) {
        self.quota = quota;
    }

    /// While on, every put that would be stored is refused `quota`.
    pub fn refuse_quota(&mut self, on: bool) {
        self.refuse_quota = on;
    }

    /// While on, `call` (`mailbox_sync` or `mailbox_done`) is refused
    /// (`mailbox_sync_refused`, `mailbox_done_refused`: `forbidden`),
    /// nothing served or removed.
    pub fn refuse_mailbox(&mut self, call: MailboxRefusedCall, on: bool) {
        self.refusing_mailbox[mailbox_slot(call)] = on;
    }

    /// The next `n` `mailbox_stored` are lost: the object is stored, the
    /// answer never sent.
    pub fn drop_stored(&mut self, n: u64) {
        self.drop_stored = n;
    }

    /// The next `n` `mailbox_done_result` are lost: the object is removed,
    /// the answer never sent.
    pub fn drop_done_results(&mut self, n: u64) {
        self.drop_done_results = n;
    }

    /// The puts the Station couldn't read so far (dropped unanswered).
    pub fn puts_dropped(&self) -> u64 {
        self.puts_dropped
    }

    /// The `mailbox_id` of the host's own mailbox, as its newest link's
    /// association names it (its current trust generation).
    pub fn mailbox_id(&mut self) -> String {
        let now = self.now();
        let (host_id, generation) = (self.host_id.clone(), self.host_trust_gen);
        self.mailbox_of(&host_id, generation, now)
            .mailbox_id
            .clone()
    }

    /// The host's own mailbox's head (its current trust generation).
    pub fn mailbox_head(&mut self) -> u64 {
        let now = self.now();
        let (host_id, generation) = (self.host_id.clone(), self.host_trust_gen);
        self.mailbox_of(&host_id, generation, now).head
    }

    /// The positions of the objects the host's own mailbox stores now
    /// (its current trust generation), ascending.
    pub fn mailbox_positions(&mut self) -> Vec<u64> {
        let now = self.now();
        let (host_id, generation) = (self.host_id.clone(), self.host_trust_gen);
        self.mailbox_of(&host_id, generation, now)
            .stored
            .keys()
            .copied()
            .collect()
    }

    /// The position of the object `id` (its body's) in the host's own
    /// mailbox, while stored.
    pub fn position_of(&mut self, id: &str) -> Option<u64> {
        let now = self.now();
        let (host_id, generation) = (self.host_id.clone(), self.host_trust_gen);
        self.mailbox_of(&host_id, generation, now)
            .stored
            .iter()
            .find(|(_, stored)| stored.id == id)
            .map(|(position, _)| *position)
    }

    /// How many objects the mailbox of `host_id` in `host_trust_gen`
    /// stores now (another receiving host's, too).
    pub fn stored_for(&mut self, host_id: &str, host_trust_gen: u64) -> usize {
        let now = self.now();
        self.mailbox_of(host_id, host_trust_gen, now).stored.len()
    }

    /// `mailbox_put` from the sending host `host_id` in `host_trust_gen`
    /// (its link's verified association; an account's host), `bytes` as
    /// sent, read by the shared reader: the answer's bytes, as the Station
    /// sends them on that host's link (rules 1 and 3), or none for a put it
    /// can't read (dropped, counted) and for a lost `mailbox_stored`.
    pub fn put(&mut self, host_id: &str, host_trust_gen: u64, bytes: &[u8]) -> Option<String> {
        let Ok(MailboxToStation::Put(put)) = MailboxToStation::decode(bytes) else {
            self.puts_dropped += 1;
            return None;
        };
        let Ok((_, body)) = put.mail() else {
            self.puts_dropped += 1;
            return None;
        };
        let refused = |code| {
            MailboxPutRefused {
                request_id: put.request_id.clone(),
                id: body.id.clone(),
                code,
            }
            .to_json()
            .expect("a put refusal")
            .to_string()
        };
        // Rule 1: the object's own sender is the calling host, a current
        // host of the account at that generation, and the link's account.
        let own = &self.own;
        let current = |host: &str, generation: u64| {
            own.membership
                .host(host)
                .is_some_and(|h| h.host_trust_gen == generation)
        };
        if body.sender.host_id != host_id
            || body.account_id != own.account_id
            || body.genesis_hash != own.genesis_hash
            || !current(host_id, host_trust_gen)
            // Rule 3: the recipient is a current host at that generation.
            || !current(&body.recipient.host_id, body.recipient.host_trust_gen)
        {
            return Some(refused(PutRefusal::Forbidden));
        }
        // The times (rule 3, Atem's reading agreed 2026-11-16): not
        // expired, after `created_at`, at most 24 h after it.
        let now = self.now();
        if body.expires_at <= now
            || body.expires_at <= body.created_at
            || body.expires_at - body.created_at > 24 * 60 * 60 * 1000
        {
            return Some(refused(PutRefusal::Expired));
        }
        let hash = object_hash(&put.object);
        // Its bytes as received (design II.4.3: limits on the encoded wire
        // bytes), never a serialization of the fake's own.
        let size = received_object_len(bytes).unwrap_or(bytes.len());
        let recipient = (
            body.recipient.host_id.clone(),
            body.recipient.host_trust_gen,
        );
        // Idempotency (rule 3): the key `(calling host, body.id)` while
        // stored; the same `object_hash` is stored (charged no second time).
        let held = self
            .mailbox_of(&recipient.0, recipient.1, now)
            .stored
            .values()
            .find(|s| s.sender == host_id && s.id == body.id)
            .map(|s| s.hash);
        match held {
            Some(h) if h == hash => return self.stored_answer(&put),
            Some(_) => return Some(refused(PutRefusal::IdReused)),
            None => {}
        }
        if self.refuse_quota || !self.within_quota(host_id, &recipient, size, now) {
            return Some(refused(PutRefusal::Quota));
        }
        self.store_at(
            &recipient,
            Stored {
                sender: host_id.to_owned(),
                id: body.id.clone(),
                hash,
                expires_at: body.expires_at,
                bytes: size,
                object: put.object.clone(),
            },
        );
        self.stored_answer(&put)
    }

    /// Stores `object` in the host's own mailbox (its current trust
    /// generation) with no intake check, as a Station that misroutes or
    /// skipped its checks does: its position. Its key is the body's sender
    /// and `id`, when the body reads.
    pub fn store_unchecked(&mut self, object: &SignedObject) -> u64 {
        let body = MailBody::from_object(object).ok().map(|(_, body)| body);
        let stored = Stored {
            sender: body
                .as_ref()
                .map_or(String::new(), |b| b.sender.host_id.clone()),
            id: body.as_ref().map_or(String::new(), |b| b.id.clone()),
            hash: object_hash(object),
            expires_at: body.map_or(u64::MAX, |b| b.expires_at),
            bytes: object.to_json().to_string().len(),
            object: object.clone(),
        };
        let recipient = (self.host_id.clone(), self.host_trust_gen);
        self.store_at(&recipient, stored)
    }

    /// The host's own mailbox is reset (a Station restored or its store
    /// lost, rule 2): a new `mailbox_id`, never used before; with `keep`,
    /// the objects it still stored are stored again in the new one, in
    /// their order, at new positions (as a restore and the senders'
    /// resends would); then `heads` at once (unless silenced).
    pub fn reset_mailbox(&mut self, keep: bool) {
        let now = self.now();
        let key = (self.host_id.clone(), self.host_trust_gen);
        let old = self.mailbox_of(&key.0, key.1, now).clone();
        self.mailboxes_minted += 1;
        let mut new = Mailbox {
            mailbox_id: mailbox_id(&self.origin, &self.own.account_id, self.mailboxes_minted),
            head: 0,
            stored: BTreeMap::new(),
        };
        if keep {
            for stored in old.stored.into_values() {
                new.head += 1;
                new.stored.insert(new.head, stored);
            }
        }
        self.mailboxes.insert(key, new);
        self.mailbox_heads();
    }

    /// The host's own mailbox went back under the same `mailbox_id` (a
    /// Station fault: a restore mints a new id, rule 2): the objects after
    /// position `to` are gone and the next object stored gets `to + 1`
    /// again; then `heads` at once (unless silenced).
    pub fn roll_back_mailbox(&mut self, to: u64) {
        let now = self.now();
        let (host_id, generation) = (self.host_id.clone(), self.host_trust_gen);
        let mailbox = self.mailbox_of(&host_id, generation, now);
        mailbox.stored.retain(|position, _| *position <= to);
        mailbox.head = to;
        self.mailbox_heads();
    }

    /// The host's next mailbox call on `link` that `held` takes, kept
    /// unanswered (in [`FakeStation::sent`] from now): a page or a done's
    /// answer delivered late, when the test answers it
    /// ([`FakeStation::answer_held`]). The calls that come first are
    /// answered as they come (at most a minute).
    pub fn hold_mailbox(&mut self, link: u64, held: impl Fn(&MailboxToStation) -> bool) -> Held {
        self.hold_next(link, |_| false, Some(&held))
    }

    /// The host's mailbox calls the fake read so far (by
    /// [`FakeStation::serve`] or a hold), with the link each came on, as
    /// the shared mailbox reader reads them.
    pub fn mailbox_calls(&self) -> Vec<(u64, MailboxToStation)> {
        self.sent
            .iter()
            .zip(&self.sent_on)
            .filter(|(bytes, _)| mailbox_call(bytes))
            .map(|(bytes, on)| {
                let call = MailboxToStation::decode(bytes.as_bytes())
                    .expect("the host's mailbox call reads");
                (*on, call)
            })
            .collect()
    }

    // ------------------------------------------------------------ inside

    /// The mailbox of `host_id` in `host_trust_gen` (minted at its first
    /// use), its expired objects gone (on the Station's clock `now`).
    fn mailbox_of(&mut self, host_id: &str, host_trust_gen: u64, now: u64) -> &mut Mailbox {
        let key = (host_id.to_owned(), host_trust_gen);
        if !self.mailboxes.contains_key(&key) {
            self.mailboxes_minted += 1;
            let id = mailbox_id(&self.origin, &self.own.account_id, self.mailboxes_minted);
            self.mailboxes.insert(
                key.clone(),
                Mailbox {
                    mailbox_id: id,
                    head: 0,
                    stored: BTreeMap::new(),
                },
            );
        }
        let mailbox = self.mailboxes.get_mut(&key).expect("minted");
        mailbox.stored.retain(|_, stored| stored.expires_at > now);
        mailbox
    }

    /// The receiving host's own mailbox as `link`'s association names it:
    /// its trust generation then (§11.5 rule 1).
    fn own_mailbox(&mut self, link: u64, now: u64) -> &mut Mailbox {
        let generation = if link < self.retired_below {
            self.prior_gen
        } else {
            self.host_trust_gen
        };
        let host_id = self.host_id.clone();
        self.mailbox_of(&host_id, generation, now)
    }

    /// `object` stored at the next position of the mailbox `recipient`
    /// names; `heads` at once when it is the host's own (unless silenced).
    fn store_at(&mut self, recipient: &(String, u64), stored: Stored) -> u64 {
        let now = self.now();
        let mailbox = self.mailbox_of(&recipient.0, recipient.1, now);
        mailbox.head += 1;
        let position = mailbox.head;
        mailbox.stored.insert(position, stored);
        if *recipient == (self.host_id.clone(), self.host_trust_gen) {
            self.mailbox_heads();
        }
        position
    }

    /// `heads` on the served link now, for a host that reads its mailbox
    /// (unless silenced).
    fn mailbox_heads(&mut self) {
        if self.senders && !self.silent {
            self.send_heads();
        }
    }

    /// Whether `size` more bytes from `sender` fit the quotas: its own, the
    /// recipient's mailbox's and the account's.
    fn within_quota(
        &mut self,
        sender: &str,
        recipient: &(String, u64),
        size: usize,
        now: u64,
    ) -> bool {
        let quota = self.quota;
        // Every mailbox's expired objects gone first.
        let keys: Vec<(String, u64)> = self.mailboxes.keys().cloned().collect();
        for (host, generation) in keys {
            self.mailbox_of(&host, generation, now);
        }
        // Every mailbox here is the account's (the fake serves one).
        let (mut of_sender, mut sender_bytes) = (0, 0);
        let (mut in_account, mut account_bytes) = (0, 0);
        for stored in self.mailboxes.values().flat_map(|m| m.stored.values()) {
            in_account += 1;
            account_bytes += stored.bytes;
            if stored.sender == sender {
                of_sender += 1;
                sender_bytes += stored.bytes;
            }
        }
        let mailbox = self.mailbox_of(&recipient.0, recipient.1, now);
        let in_mailbox = mailbox.stored.len();
        let mailbox_bytes: usize = mailbox.stored.values().map(|s| s.bytes).sum();
        of_sender < quota.per_sender
            && sender_bytes + size <= quota.per_sender_bytes
            && in_mailbox < quota.per_mailbox
            && mailbox_bytes + size <= quota.per_mailbox_bytes
            && in_account < quota.per_account
            && account_bytes + size <= quota.per_account_bytes
    }

    /// `mailbox_stored` for `put`, unless the next one is lost.
    fn stored_answer(&mut self, put: &MailboxPut) -> Option<String> {
        if self.drop_stored > 0 {
            self.drop_stored -= 1;
            return None;
        }
        let id = put.mail().expect("a put that reads").1.id;
        let stored = MailboxStored {
            request_id: put.request_id.clone(),
            id,
        };
        Some(stored.to_json().expect("a stored answer").to_string())
    }

    /// The answer to the receiving host's mailbox call on `link` (none: a
    /// lost answer, or a put on this link, which is the receiving host's).
    fn mailbox_reply(&mut self, link: u64, call: MailboxToStation) -> Option<String> {
        let now = self.now();
        let refused = |call| {
            MailboxCallRefused {
                call,
                code: RefusalCode::Forbidden,
            }
            .to_json()
            .expect("a refusal")
            .to_string()
        };
        // A link that hasn't proved its host, when one is required: refused,
        // nothing served or removed.
        if !self.serves(link) {
            return match call {
                MailboxToStation::Sync(_) => Some(refused(MailboxRefusedCall::Sync)),
                MailboxToStation::Done(_) => Some(refused(MailboxRefusedCall::Done)),
                MailboxToStation::Put(_) => None,
            };
        }
        match call {
            MailboxToStation::Sync(sync) => {
                let refusing = self.refusing_mailbox[mailbox_slot(MailboxRefusedCall::Sync)];
                let mailbox = self.own_mailbox(link, now);
                if refusing || sync.mailbox_id != mailbox.mailbox_id {
                    return Some(refused(MailboxRefusedCall::Sync));
                }
                let page = page_of(mailbox, &sync);
                Some(page.to_json().expect("a page within the bound").to_string())
            }
            MailboxToStation::Done(done) => {
                let refusing = self.refusing_mailbox[mailbox_slot(MailboxRefusedCall::Done)];
                let mailbox = self.own_mailbox(link, now);
                if refusing || done.mailbox_id != mailbox.mailbox_id {
                    return Some(refused(MailboxRefusedCall::Done));
                }
                // Removed, its key freed; the same answer when nothing is
                // there (rule 5).
                mailbox.stored.remove(&done.position);
                if self.drop_done_results > 0 {
                    self.drop_done_results -= 1;
                    return None;
                }
                Some(done_result(&done))
            }
            // The receiving host puts nothing in this version.
            MailboxToStation::Put(_) => None,
        }
    }
}

fn mailbox_slot(call: MailboxRefusedCall) -> usize {
    match call {
        MailboxRefusedCall::Sync => 0,
        MailboxRefusedCall::Done => 1,
    }
}

fn done_result(done: &MailboxDone) -> String {
    MailboxDoneResult {
        request_id: done.request_id.clone(),
        mailbox_id: done.mailbox_id.clone(),
        position: done.position,
    }
    .to_json()
    .expect("a done result")
    .to_string()
}

/// The page answering `sync` on `mailbox` (rule 4): the first object
/// stored after `after`, scanned through every position before the next
/// one stored (or the head); a reset's form when `after` is beyond the
/// head.
fn page_of(mailbox: &Mailbox, sync: &MailboxSync) -> MailboxSyncResult {
    let mut page = MailboxSyncResult {
        request_id: sync.request_id.clone(),
        mailbox_id: mailbox.mailbox_id.clone(),
        after: sync.after,
        head: mailbox.head,
        through: mailbox.head,
        objects: Vec::new(),
    };
    if sync.after >= mailbox.head {
        return page;
    }
    let mut next = mailbox.stored.range(sync.after + 1..);
    if let Some((position, stored)) = next.next() {
        page.through = next.next().map_or(mailbox.head, |(after, _)| after - 1);
        page.objects = vec![MailboxEntry::new(*position, &stored.object)];
    }
    page
}

/// A fake Station online, as a Station is ([`Pump::start`]): a thread
/// answers every call of the host's newest link at once and announces
/// `heads` (on a new link at once unless silenced, then every second of
/// real time, so the host's 60 seconds without `heads` never lapse on a
/// slow runner). It stops when dropped.
pub struct Pump {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Pump {
    /// `station` online from now on (the test shares it with the thread).
    pub fn start(station: std::sync::Arc<std::sync::Mutex<FakeStation>>) -> Pump {
        Pump::every(station, Duration::from_millis(50))
    }

    /// [`Pump::start`], the calls answered every `period` (a mailbox read
    /// object by object goes as fast as its Station answers).
    pub fn every(station: std::sync::Arc<std::sync::Mutex<FakeStation>>, period: Duration) -> Pump {
        use std::sync::atomic::Ordering;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut last = Instant::now();
            while !stopped.load(Ordering::SeqCst) {
                {
                    let mut station = station.lock().unwrap_or_else(|e| e.into_inner());
                    station.serve_latest();
                    if last.elapsed() >= Duration::from_secs(1) {
                        if station.link.is_some_and(|link| station.serves(link)) {
                            station.heads_now();
                        }
                        last = Instant::now();
                    }
                }
                std::thread::sleep(period);
            }
        });
        Pump {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Whether `bytes` is a `host_route` (the host's answer to a challenge).
fn is_host_route(bytes: &str) -> bool {
    serde_json::from_str::<Value>(bytes)
        .is_ok_and(|value| value["type"] == "relay" && value["op"] == "host_route")
}

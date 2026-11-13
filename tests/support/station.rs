//! A fake Station on the fake Astation's links (host-work-v1 §11.4): an
//! account's control feed and its heads, the host's own device-list fetch
//! and the reference acknowledgment ledger, answered as the agreed contract
//! says. It speaks only the shared core: every message it sends is made by
//! a builder of `atem_client::control::relay` (or `ledger`), and every call
//! the host sends is read by its strict reader, from the bytes the host
//! sent; the fake writes no wire JSON of its own.
//!
//! The test drives it, nothing runs in the background. Make it before the
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
//!   the feed's head and the Station's time. A call for a feed that isn't
//!   the account's at this Station (another origin, a `feed_id` the
//!   account never had here) is refused, `control_sync_refused` ("One feed
//!   per account").
//! - A `control_sync` naming the account's feed from before a reset: §11.4
//!   doesn't say. Two readings, chosen with [`FakeStation::stale_feed`]:
//!   [`StaleFeed::Refuse`] (the default), `control_sync_refused`, the
//!   literal reading of "not its account's feed at this Station": **Atem's
//!   reading, not confirmed with Astation**; or [`StaleFeed::ServeCurrent`],
//!   the account's current feed from position 0, as for a call without a
//!   `feed_id` (the result's `feed_id` is then the only in-band reset
//!   signal the wire has). A host must handle both until Astation answers.
//! - `membership_fetch`: the device list's entries after `after`, as many
//!   as fit (at most 64, within 256 KiB), and its head.
//! - `control_ack`: no answer when the reference [`AckLedger`] counts it;
//!   `control_ack_refused` when it refuses the ack for its association on
//!   this link ([`AckRefusal::reply`]); nothing for any other refusal. The
//!   link's verified association is the host the fake was made for, its
//!   connection `link-<n>`.
//! - [`FakeStation::refuse`]: that call answered with its typed refusal,
//!   nothing served or counted.
//! - [`FakeStation::serve_other_account`]: a Station that serves another
//!   account's data on this link ([`OTHER_ACCOUNT`]): its heads, feed and
//!   device list, as if the link were that account's.
//! - Bytes the shared reader refuses get no answer (kept in
//!   [`FakeStation::sent`]).
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
use atem_client::encoding::Hash32;
use atem_client::membership::Head;
use atem_client::{KeyProvider, SignedObject, SoftwareKeys};
use serde_json::Value;
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
/// gets: §11.4 doesn't say (the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleFeed {
    /// `control_sync_refused`: the literal "not its account's feed at this
    /// Station" (Atem's reading, not confirmed with Astation).
    Refuse,
    /// The account's current feed from position 0 (`after` ignored: a
    /// cursor belongs to a feed), as for a call with no `feed_id`. The
    /// result's `feed_id` is then the only in-band reset signal the wire
    /// has.
    ServeCurrent,
}

/// One account at this Station: its device list and its one control feed
/// (§11.4, "One feed per account").
struct Account {
    account_id: String,
    genesis_hash: Hash32,
    /// The device list from its genesis (`seq` n is `entries[n - 1]`).
    entries: Vec<SignedObject>,
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
    /// Every call the host sent, as its bytes.
    sent: Vec<String>,
    /// Records signed so far (their `record_id`s).
    minted: u64,
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
            minted: 0,
        }
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
    /// `"membership_fetch"`); a binary frame never does.
    pub fn sent(&self) -> Vec<String> {
        self.sent.clone()
    }

    /// Serves `link`: `heads` when it is a link not served yet, or when
    /// 30 seconds passed since the last (unless silenced), then an answer to
    /// every call the host sent so far. The calls answered, as the shared
    /// reader read them.
    pub fn serve(&mut self, link: u64) -> Vec<Result<ToStation, RelayError>> {
        self.attach(link);
        let mut served = Vec::new();
        while let Ok((from, bytes)) = self.calls.try_recv() {
            served.push(self.answer(from, bytes));
        }
        served
    }

    /// [`FakeStation::serve`] on the newest link of the fake Astation (a
    /// runtime started again connects anew), if it has one.
    pub fn serve_latest(&mut self) -> Vec<Result<ToStation, RelayError>> {
        match self.out.latest() {
            Some(link) => self.serve(link),
            None => Vec::new(),
        }
    }

    /// Serves `link` until the host's next call arrived (at most a minute)
    /// and answers it.
    pub fn next_call(&mut self, link: u64) -> Result<ToStation, RelayError> {
        self.attach(link);
        let (from, bytes) = self
            .calls
            .recv_timeout(WAIT)
            .expect("the host sent no Station call");
        self.answer(from, bytes)
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
        let heads = heads.to_json().expect("heads within the builder's bounds");
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
        }
        let due = self.last_heads.is_none_or(|at| at.elapsed() >= HEARTBEAT);
        if due && !self.silent {
            self.send_heads();
        }
    }

    /// The Station's own `heads`, on the served link if there is one.
    fn send_heads(&mut self) {
        if self.link.is_some() {
            self.heads_now();
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
        let call = ToStation::decode(bytes.as_bytes());
        self.sent.push(bytes);
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
                origin: self.origin.clone(),
                feed_id: served.feed_id.clone(),
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

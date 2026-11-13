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
//! What it answers (§11.4):
//! - `control_sync`: the records after `after` of the account's one feed at
//!   this Station, ascending, as many as fit in one message (at most 64,
//!   and the whole message within 256 KiB: the builder's own bounds), with
//!   the feed's head and the Station's time. A call for a feed that isn't
//!   the account's at this Station (another origin, an unknown `feed_id`,
//!   the feed before a reset) is refused, `control_sync_refused`.
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

/// One account at this Station: its device list and its one control feed
/// (§11.4, "One feed per account").
struct Account {
    account_id: String,
    genesis_hash: Hash32,
    /// The device list from its genesis (`seq` n is `entries[n - 1]`).
    entries: Vec<SignedObject>,
    head: Head,
    /// How many feeds the account had here (a reset mints the next).
    feeds: u64,
    feed_id: String,
    /// The feed's records: `feed_seq` n is `records[n - 1]`.
    records: Vec<ControlRecord>,
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
        }
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

    /// The served account's feed, in `feed_seq` order.
    pub fn records(&self) -> &[ControlRecord] {
        &self.served().records
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

    /// Every Station call the host sent, as the bytes it sent, in order.
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

    /// Stores `record` at the end of the served account's feed: the
    /// reference ledger sees it first (for the host's account), then the
    /// feed serves it and `heads` go at once (unless silenced). Its
    /// `feed_seq`. The fake stores what the test hands it: a record the
    /// ledger refuses at intake (another account's or Station's, a reused
    /// `record_id`) is served untracked, as by a Station that skipped its
    /// intake checks; one the control parser refuses can't be served (the
    /// shared builder takes only a parsed record).
    pub fn append(&mut self, record: SignedObject) -> u64 {
        let record = ControlRecord::from_signed(record).expect("a control record");
        self.store(record);
        if !self.silent {
            self.send_heads();
        }
        self.served().records.len() as u64
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
        assert!(self.link.is_some(), "serve the host's link first");
        self.send_heads();
    }

    /// No `heads` of its own while on: none for a new link, a stored
    /// record, a reset or the heartbeat (the host's 60 s without heads).
    /// [`FakeStation::heads_now`] still announces.
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
    /// carried as it is.
    pub fn reset(&mut self) {
        let origin = self.origin.clone();
        let served = self.served_mut();
        let old = std::mem::take(&mut served.records);
        served.feeds += 1;
        served.feed_id = feed_id(&origin, &served.account_id, served.feeds);
        for record in self.snapshot(&old) {
            self.store(record);
        }
        if !self.silent {
            self.send_heads();
        }
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

    fn send_heads(&mut self) {
        let Some(link) = self.link else { return };
        let served = self.served();
        let heads = Heads {
            feeds: vec![FeedHead {
                origin: self.origin.clone(),
                feed_id: served.feed_id.clone(),
                head: served.records.len() as u64,
                station_time: self.now(),
            }],
            membership: served.head,
        };
        let heads = heads.to_json().expect("heads within the builder's bounds");
        self.out.send(link, heads.to_string());
        self.last_heads = Some(Instant::now());
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
        self.served_mut().records.push(record);
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
        let ours = sync.origin == self.origin
            && sync.feed_id.as_ref().is_none_or(|id| *id == served.feed_id);
        if self.refusing[slot(RefusedCall::ControlSync)] || !ours {
            return refusal(RefusedCall::ControlSync);
        }
        let from = usize::try_from(sync.after)
            .unwrap_or(usize::MAX)
            .min(served.records.len());
        let entries: Vec<FeedEntry> = (from..served.records.len())
            .map(|i| FeedEntry::new(i as u64 + 1, &served.records[i]))
            .collect();
        let now = self.now();
        fit(entries.len().min(MAX_FEED_RECORDS), |n| {
            ControlSyncResult {
                origin: self.origin.clone(),
                feed_id: served.feed_id.clone(),
                head: served.records.len() as u64,
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

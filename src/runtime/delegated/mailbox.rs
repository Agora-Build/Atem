//! The receiving host's mailbox client (host-work-v1 §11.5, "The mailbox
//! calls"; the delegated host-work design II.4.2, II.4.3, II.5), behind the
//! debug-only hook's `host.senders` (with `host.delegated`): the host's own
//! mailbox on its Station, read over the host's Station link (relay, local
//! `:8080` or routed: [`super::station`]), as the feed's sync reads the
//! control feed ([`super::sync`]). Pure: the store's committed cursor is
//! handed in ([`MailboxClient::observe`]) and its writes are the bridge's
//! (`mail_pass.rs`, [`super::mailbox_store`]).
//!
//! - **Heads** (rule 6). Each `heads` on the link announces the host's own
//!   mailbox `{mailbox_id, head}`, or none (then nothing is synced and the
//!   gate's mailbox part stays closed).
//! - **One live sync** (rule 8). `mailbox_sync` names the announced
//!   mailbox and the host's committed cursor; at most one is live per link
//!   generation, each call with a fresh lowercase UUID v4 from the OS
//!   CSPRNG. A page applies only as the live call's answer
//!   ([`MailboxSyncResult::answers`]: the same `request_id`, `mailbox_id`
//!   and `after`), on the link generation and socket it went on and under
//!   the host identity it was asked under ([`PageCheck::Apply`]); the
//!   bridge then commits it from the store's own cursor (a continuation
//!   from another cursor is drained there). A page of a retired call (one
//!   answered, refused, unanswered for 35 s, of an earlier link generation,
//!   or asked before the host's identity changed) is drained: it advances
//!   nothing and opens nothing. A page with an id the host never sent (or
//!   no longer keeps: the latest [`RETIRED_KEPT`]), one with the live id
//!   that doesn't answer the live call, and one the reader refused (its id
//!   unread: taken as the live call's answer) are Station faults: the gate
//!   stays closed until a page asked after the fault reads.
//! - **Resets** (rule 7). An announced `mailbox_id` other than the one the
//!   host read, or a head below the furthest position it read (its cursor,
//!   or more while a rewind's re-read runs; in a `heads` or a page), is a
//!   reset: nothing is asked until the bridge
//!   marks it durably ([`MailboxClient::reset_due`]: the store's cursor
//!   rewritten to the announced mailbox at 0, the dones owed to the old one
//!   dropped), then the mailbox is read from 0; the gate stays closed until
//!   it is read to the announced head.
//! - **Pacing** (rule 8, as the feed's). A sync a `heads` or the pass
//!   starts goes at most once a second; the next goes at once after a page
//!   that moved the cursor while the host is still behind; none for 30 s
//!   after a page that moved nothing while it is (or a fault). A call
//!   unanswered for 35 s is retired and asked again with a fresh id.
//! - **Refusals** (rule 8). A `mailbox_sync_refused` retires the live sync
//!   and keeps the gate's mailbox part closed until a page asked after it
//!   reads; nothing is asked before a `heads` 30 s or more later (or the
//!   next link generation).
//! - **Dones** (rules 5 and 8). A done goes only for a position the store
//!   owes, written with its page's commit ([`Observed::owed`]): never
//!   before that commit. Only in the mailbox this link generation's `heads`
//!   announced and the store has read (none to a mailbox being reset); at
//!   most [`MAX_LIVE_DONES`] live, each with a fresh id; one answered
//!   (`request_id`, `mailbox_id` and `position`) is freed for the bridge to
//!   remove; one unanswered for 35 s goes again with a fresh id; a
//!   `mailbox_done_refused` retires every live done and none goes again on
//!   that link generation. Owed dones survive a restart in the store. While
//!   more than [`MAX_OWED_DONES`] are owed, no page is asked.
//! - **A rewind** (ruling R31): an object the store left on the Station for
//!   want of room is read again once room frees: the store's cursor is
//!   rewound to just before it, the live call retired and the re-read asked
//!   at once ([`MailboxClient::cursor_rewound`]); the furthest position
//!   read stays ([`Observed::read_to`]).
//! - **An identity change** on the live link (§11.4): every live mailbox
//!   call retired, nothing more synced or marked done on that socket.
//! - **The gate's mailbox part** (design II.5; [`MailboxClient::open`]):
//!   the link up, a mailbox announced on this generation and read up to its
//!   head (the furthest position read: a rewind's re-read closes nothing on
//!   its own), no refusal, fault or reset waiting, and no request, cancel
//!   or complete left on the Station, or waiting in the store, for want of
//!   room ([`Observed::waiting_for_room`]): until then nobody can say whose
//!   objects wait, so every host sender waits. Objects waiting for a newer
//!   sender generation don't hold it (ruling R39: design II.5 exempts only
//!   those), nor do results, kept or left on the Station (ruling R35: they
//!   start no work, and a flood of them must not hold task admission). Only
//!   host senders wait for it.
//! - **The inbox's senders** ([`MailboxClient::undecided`]): a request,
//!   cancel or complete committed with the cursor and not yet admitted
//!   holds its own sender's task starts only, never another sender's
//!   (final readings item 6's proviso, #120 comment 7028723996), read from
//!   the store's rows each time it is observed, so a restart, or a store
//!   fault that keeps a row undecided, still holds them.
use super::fetch::{HEADS_PACE_MS, REFUSAL_BACKOFF_MS, STALL_PAUSE_MS};
use super::station::StationLink;
use super::sync::{ALERT_EVERY_MS, HostIdentity, RETIRED_KEPT, SYNC_TIMEOUT_MS};
use atem_client::control::{MailboxHead, RelayError};
use atem_client::host_mail::mailbox::{
    MailboxDone, MailboxDoneResult, MailboxMismatch, MailboxSync, MailboxSyncResult,
};
use serde_json::{Value, json};
use std::collections::VecDeque;

/// What the store holds, as the bridge reads it for the host's current
/// identity: the committed cursor `(mailbox_id, cursor)` (none: never
/// read) and how many inbox rows wait for admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub identity: HostIdentity,
    pub cursor: Option<(String, u64)>,
    /// The inbox rows waiting for admission (a request, cancel or complete
    /// committed with the cursor, not yet decided; held ones included).
    pub inbox: u64,
    /// The dones owed to the cursor's mailbox (positions, the first 64),
    /// each written with its page's commit, and how many in all.
    pub owed: Vec<u64>,
    pub owed_count: u64,
    /// An object was left on the Station for want of room (ruling R31):
    /// not committed yet.
    pub skipped: bool,
    /// One of them is a request, cancel or complete, not read again since:
    /// the gate's mailbox part stays closed (ruling R35: a result left there
    /// holds no gate).
    pub skipped_inbox: bool,
    /// The furthest position read in the cursor's mailbox (at least the
    /// cursor; beyond it while a rewind's re-read runs).
    pub read_to: u64,
    /// Waiting objects that decided to open with no room in the inbox
    /// (review finding 2, ruling R39): they hold the gate's mailbox part.
    pub waiting_for_room: u64,
    /// Room freed since: the store's cursor is to be rewound to just before
    /// it (`mailbox_store::rewind_if_room`).
    pub rewind_due: bool,
    /// When every object left on the Station has expired (the Station drops
    /// them then): the rewind is due once `D` passes it, whatever the room.
    pub skip_expires: Option<u64>,
    /// The senders (`host_id`) of those rows: each row holds its own
    /// sender's task starts only, never the gate's mailbox part (final
    /// readings item 6's proviso, #120 comment 7028723996; ruling R47 for a
    /// stop admission holds for room).
    pub undecided: std::collections::BTreeSet<String>,
}

/// What a page is to the live call ([`MailboxClient::on_page`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageCheck {
    /// It answers the live call: the bridge commits it from the store's
    /// cursor, then calls [`MailboxClient::committed`] (or
    /// [`MailboxClient::failed`]).
    Apply(Applying),
    /// A retired call's, or one asked on another link or under another
    /// identity: nothing applies.
    Drained,
    /// A Station fault (its code): nothing applies.
    Fault(&'static str),
    /// The page's head is below the furthest position read (the cursor, or
    /// more while a rewind's re-read runs): a reset, to be marked.
    Reset,
    /// No link: nothing arrives.
    Nothing,
}

/// A page that answers the live call, to commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applying {
    pub page: MailboxSyncResult,
    /// The sync's epoch when the call was asked: a page asked before the
    /// latest refusal or fault ends no resynchronization.
    epoch: u64,
}

/// The host's calls to send now ([`MailboxClient::take_outgoing`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outgoing {
    pub sync: Vec<MailboxSync>,
    pub dones: Vec<MailboxDone>,
}

/// Why a fresh page is needed before the gate opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resync {
    Refused,
    Fault(&'static str),
}

/// The live `mailbox_sync`, and what it was captured with.
#[derive(Debug, Clone)]
struct Ask {
    call: MailboxSync,
    link_gen: u64,
    socket: u64,
    identity: HostIdentity,
    sent_at: u64,
    epoch: u64,
    /// Handed to the link ([`MailboxClient::take_outgoing`]).
    sent: bool,
}

/// A live `mailbox_done`.
#[derive(Debug, Clone)]
struct DoneAsk {
    call: MailboxDone,
    sent_at: u64,
}

/// §11.4's refusal lines, for the mailbox's two calls (rule 8).
const REFUSED_SYNC: &str = "the Station refused this host's mailbox_sync (forbidden); retrying";
const REFUSED_DONE: &str = "the Station refused this host's mailbox_done (forbidden); retrying";

/// While more dones than this are owed, no page is asked (review O5): a
/// Station that serves pages but never answers dones can't grow them
/// without end. An honest Station drains 8 a round trip against at most
/// one object a page.
pub const MAX_OWED_DONES: u64 = 256;

/// The most dones live per link generation (rule 8).
pub const MAX_LIVE_DONES: usize = 8;

/// The host's side of its own mailbox on its Station link (the module
/// docs give the rules).
#[derive(Debug, Default)]
pub struct MailboxClient {
    link_gen: Option<u64>,
    socket: Option<u64>,
    /// The host's identity moved since the link's socket was authenticated:
    /// nothing more is asked or applied on that socket.
    moved: bool,
    /// The host's monotonic clock at the last tick (ms).
    now: u64,
    announced: Option<MailboxHead>,
    /// The store as last observed (none: not loaded for this identity).
    observed: Option<Observed>,
    in_flight: Option<Ask>,
    retired: VecDeque<String>,
    /// The live dones, and the ids of those retired (their answers
    /// drained), the latest [`RETIRED_KEPT`].
    dones: Vec<DoneAsk>,
    retired_dones: VecDeque<String>,
    /// A `mailbox_done_refused` on this link generation: no more dones.
    dones_refused: bool,
    resync: Option<Resync>,
    epoch: u64,
    refused_at: Option<u64>,
    paced_at: Option<u64>,
    stalled_at: Option<u64>,
    /// A reset found and not marked yet.
    reset: bool,
    // Counts, for the state dump and the log.
    pages: u64,
    drained: u64,
    faults: u64,
    resets: u64,
    refusals: u64,
    timeouts: u64,
    dones_sent: u64,
    dones_answered: u64,
    unsolicited: u64,
    /// The alerts (rule 8: §11.4's hourly alerts and refusals), per
    /// [`Alert`] kind, the runtime.log lines not taken yet, and the run's
    /// count and latest text (`atem status`).
    alerts: [Hourly; 3],
    lines: Vec<String>,
    alerts_in_run: u64,
    last_alert: Option<String>,
}

/// One kind of alert's hourly line: when it last went, and how many came
/// since without one.
#[derive(Debug, Default, Clone)]
struct Hourly {
    last: Option<u64>,
    counted: u64,
}

/// The kinds of the mailbox's alerts.
#[derive(Debug, Clone, Copy)]
enum Alert {
    Fault = 0,
    SyncRefused = 1,
    DoneRefused = 2,
}

/// A fresh `request_id` (rule 8): a lowercase UUID v4 from the operating
/// system's CSPRNG.
pub(crate) fn fresh_request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
}

impl MailboxClient {
    /// The link as the Station link has it (`None`: down). A new generation
    /// starts afresh: every live call retired, nothing announced, no
    /// refusal's backoff or resynchronization (a page asked on it reads
    /// anew); a new socket is authenticated under the identity now.
    pub fn on_link(&mut self, link: Option<&StationLink>) {
        let now = link.map(|l| (l.link_gen, l.socket));
        if now == self.link_gen.zip(self.socket) {
            return;
        }
        self.retire_all();
        self.announced = None;
        self.resync = None;
        self.refused_at = None;
        self.dones_refused = false;
        if now.map(|(_, socket)| socket) != self.socket {
            self.moved = false;
        }
        self.link_gen = now.map(|(link_gen, _)| link_gen);
        self.socket = now.map(|(_, socket)| socket);
    }

    /// The host's identity changed on the live link (host-work-v1 §11.4,
    /// "An identity change"; rule 8): every live mailbox call is retired and
    /// nothing more is synced or marked done on that socket.
    pub fn on_identity_moved(&mut self) {
        self.retire_all();
        self.announced = None;
        self.moved = true;
    }

    /// The pass's monotonic time: a live call unanswered for 35 s is
    /// retired, and a sync due now is asked (none after a refusal: only a
    /// `heads` past its backoff asks then).
    pub fn tick(&mut self, now: u64) {
        self.now = now;
        if let Some(ask) = &self.in_flight
            && now >= ask.sent_at.saturating_add(SYNC_TIMEOUT_MS)
        {
            self.timeouts += 1;
            self.retire_live();
        }
        // A done unanswered for 35 s goes again, with a fresh id.
        let late: Vec<String> = self
            .dones
            .iter()
            .filter(|d| now >= d.sent_at.saturating_add(SYNC_TIMEOUT_MS))
            .map(|d| d.call.request_id.clone())
            .collect();
        for id in late {
            self.retire_done(&id);
        }
        if self.resync != Some(Resync::Refused) {
            self.ask(true);
        }
    }

    /// The senders whose task starts their own inbox rows hold, as the
    /// store was last observed (none while it isn't loaded: the gate's
    /// mailbox part is closed for every host sender then).
    pub fn undecided(&self) -> std::collections::BTreeSet<String> {
        self.observed
            .as_ref()
            .map(|o| o.undecided.clone())
            .unwrap_or_default()
    }

    /// The store as it is now for the host's current identity (`None`: not
    /// loaded). A reset found against the announcement waits for its mark.
    pub fn observe(&mut self, observed: Option<Observed>) {
        self.observed = observed;
        self.check_reset();
    }

    /// A `heads` on the link: the host's own mailbox, or none (rule 6). A
    /// sync, if one is due.
    pub fn on_heads(&mut self, mailbox: Option<MailboxHead>) {
        if self.link_gen.is_none() || self.moved {
            return;
        }
        self.announced = mailbox;
        // The live call's mailbox is no longer the announced one: a page
        // for it applies nothing more.
        self.check_reset();
        self.ask(true);
    }

    /// The mailbox to mark a reset for, durably (the store's cursor at its
    /// position 0, the old mailbox's owed dones dropped), before anything
    /// is asked for it.
    pub fn reset_due(&self) -> Option<String> {
        self.reset
            .then(|| self.announced.as_ref().map(|a| a.mailbox_id.clone()))
            .flatten()
    }

    /// The reset is marked (the bridge observed the store since): the
    /// announced mailbox is read from 0.
    pub fn reset_written(&mut self) {
        self.reset = false;
        self.resets += 1;
        self.ask(false);
    }

    /// A `mailbox_sync_result` on the link, or a message that was one and
    /// the reader refused (`Err`), matched to the live call (rule 8).
    pub fn on_page(&mut self, page: Result<MailboxSyncResult, RelayError>) -> PageCheck {
        if self.link_gen.is_none() {
            return PageCheck::Nothing;
        }
        let page = match page {
            Ok(page) => page,
            Err(e) => {
                // Its id can't be read: taken as the live call's answer.
                self.retire_live();
                return self.fault(e.code());
            }
        };
        let live = self
            .in_flight
            .as_ref()
            .is_some_and(|ask| ask.call.request_id == page.request_id);
        if !live {
            if self.retired.contains(&page.request_id) {
                self.drained += 1;
                return PageCheck::Drained;
            }
            return self.fault("unsolicited");
        }
        let Some(ask) = self.in_flight.take() else {
            return PageCheck::Nothing;
        };
        self.retire(ask.call.request_id.clone());
        if let Err(m) = page.answers(&ask.call) {
            return self.fault(match m {
                MailboxMismatch::MailboxId => "mismatched_mailbox_id",
                MailboxMismatch::After => "mismatched_after",
                _ => "unsolicited",
            });
        }
        let identity = self.observed.as_ref().map(|o| &o.identity);
        if self.link_gen.zip(self.socket) != Some((ask.link_gen, ask.socket))
            || identity != Some(&ask.identity)
            || self.moved
        {
            self.drained += 1;
            return PageCheck::Drained;
        }
        // Its head below the cursor, or below the furthest position read
        // (a rewind's re-read): the mailbox went back.
        let read_to = self
            .observed
            .as_ref()
            .filter(|o| {
                o.cursor
                    .as_ref()
                    .is_some_and(|(id, _)| *id == page.mailbox_id)
            })
            .map_or(0, |o| o.read_to);
        if page.is_reset() || page.head < read_to {
            self.reset = true;
            return PageCheck::Reset;
        }
        // Its head is the Station's word, as fresh as a `heads`'s: the gate
        // needs that much read, and a cursor moved past the head the last
        // `heads` named is no reset.
        if let Some(a) = self
            .announced
            .as_mut()
            .filter(|a| a.mailbox_id == page.mailbox_id)
        {
            a.head = a.head.max(page.head);
        }
        PageCheck::Apply(Applying {
            page,
            epoch: ask.epoch,
        })
    }

    /// `applying` committed (the bridge observed the store since). A
    /// refusal's or a fault's resynchronization ends only with a page
    /// asked after its cause. The next page is asked at once when this one
    /// moved the cursor and the host is still behind; after one that moved
    /// nothing while it is, none for 30 s.
    pub fn committed(&mut self, applying: Applying) {
        self.pages += 1;
        let page = applying.page;
        if applying.epoch == self.epoch {
            self.resync = None;
        }
        if page.through > page.after {
            self.ask(false);
        } else if self.behind() {
            self.stalled_at = Some(self.now);
        }
    }

    /// The page couldn't be committed (nothing of it applied): asked again
    /// after the pause.
    pub fn failed(&mut self) {
        self.stalled_at = Some(self.now);
    }

    /// `mailbox_sync_refused` (rule 8): the live sync retired, the gate
    /// closed until a page asked after it reads.
    pub fn on_sync_refused(&mut self) {
        if self.link_gen.is_none() {
            return;
        }
        self.refusals += 1;
        self.alert(Alert::SyncRefused, REFUSED_SYNC.into());
        self.retire_live();
        self.resync = Some(Resync::Refused);
        self.refused_at = Some(self.now);
        self.epoch += 1;
    }

    /// A `mailbox_done_result` (rule 8): it applies only to a live done
    /// with its `request_id`, `mailbox_id` and `position`, which is then
    /// retired; the position it frees (`(mailbox_id, position)`), for the
    /// bridge to remove from the dones owed. Anything else changes nothing
    /// (an unsolicited one counted, no Station fault).
    pub fn on_done_result(&mut self, result: MailboxDoneResult) -> Option<(String, u64)> {
        let live = self
            .dones
            .iter()
            .find(|d| d.call.request_id == result.request_id);
        match live {
            Some(done) if result.answers(&done.call).is_ok() => {
                let freed = (done.call.mailbox_id.clone(), done.call.position);
                self.retire_done(&result.request_id);
                self.dones_answered += 1;
                Some(freed)
            }
            _ => {
                if !self.retired_dones.contains(&result.request_id) {
                    self.unsolicited += 1;
                }
                None
            }
        }
    }

    /// `mailbox_done_refused` (rule 8): every live done retired; they go
    /// again on the next link generation.
    pub fn on_done_refused(&mut self) {
        self.refusals += 1;
        self.alert(Alert::DoneRefused, REFUSED_DONE.into());
        self.dones_refused = true;
        for id in self.live_done_ids() {
            self.retire_done(&id);
        }
    }

    /// Room freed since an object was left on the Station: the store's
    /// cursor is due to be rewound to it (ruling R31).
    pub fn rewind_due(&self) -> bool {
        self.observed.as_ref().is_some_and(|o| o.rewind_due)
    }

    /// When every object left on the Station has expired (none: none left).
    pub fn skip_expires(&self) -> Option<u64> {
        self.observed.as_ref().and_then(|o| o.skip_expires)
    }

    /// The store's cursor was rewound to re-read an object left on the
    /// Station for want of room (ruling R31; the bridge observed it since):
    /// the live call is retired and the re-read asked at once.
    pub fn cursor_rewound(&mut self) {
        self.retire_live();
        self.stalled_at = None;
        self.ask(false);
    }

    /// The calls to send now, marked sent: the live sync if it wasn't yet,
    /// and a done for each owed position not live (at most
    /// [`MAX_LIVE_DONES`] live), only in the mailbox this link generation's
    /// `heads` announced and the store has read (never to one being reset).
    pub fn take_outgoing(&mut self) -> Outgoing {
        let mut out = Outgoing::default();
        if let Some(ask) = self.in_flight.as_mut().filter(|ask| !ask.sent) {
            ask.sent = true;
            out.sync.push(ask.call.clone());
        }
        if self.link_gen.is_none() || self.moved || self.dones_refused || self.reset {
            return out;
        }
        let (Some(announced), Some(observed)) = (&self.announced, &self.observed) else {
            return out;
        };
        let Some((mailbox_id, _)) = observed
            .cursor
            .as_ref()
            .filter(|(id, _)| *id == announced.mailbox_id)
        else {
            return out;
        };
        for &position in &observed.owed {
            if self.dones.len() >= MAX_LIVE_DONES {
                break;
            }
            if self
                .dones
                .iter()
                .any(|d| d.call.mailbox_id == *mailbox_id && d.call.position == position)
            {
                continue;
            }
            let call = MailboxDone {
                request_id: fresh_request_id(),
                mailbox_id: mailbox_id.clone(),
                position,
            };
            self.dones.push(DoneAsk {
                call: call.clone(),
                sent_at: self.now,
            });
            self.dones_sent += 1;
            out.dones.push(call);
        }
        out
    }

    /// The done `request_id` wasn't handed to the link: no longer live (it
    /// goes again), and its id never one an answer may carry.
    pub fn done_unsent(&mut self, request_id: &str) {
        self.dones.retain(|d| d.call.request_id != request_id);
    }

    /// The call `request_id` wasn't handed to the link: none is live (it
    /// is asked again), and its id is never one a page may carry.
    pub fn unsent(&mut self, request_id: &str) {
        if self
            .in_flight
            .as_ref()
            .is_some_and(|ask| ask.call.request_id == request_id)
        {
            self.in_flight = None;
        }
    }

    /// The gate's mailbox part (design II.5; the module docs).
    pub fn open(&self) -> bool {
        self.closed().is_none()
    }

    /// Why the gate's mailbox part is closed (`None`: open), as `atem
    /// status` says it.
    pub fn closed(&self) -> Option<String> {
        if self.link_gen.is_none() {
            return Some("no Station link".into());
        }
        if self.moved {
            return Some("this host's identity changed".into());
        }
        let Some(observed) = &self.observed else {
            return Some("the mailbox state isn't loaded".into());
        };
        match self.resync {
            Some(Resync::Refused) => {
                return Some("Station refused mailbox access (forbidden); retrying".into());
            }
            Some(Resync::Fault(code)) => {
                return Some(format!("Station sent a mailbox page it shouldn't ({code})"));
            }
            None => {}
        }
        let Some(announced) = &self.announced else {
            return Some("the Station announced no mailbox for this host".into());
        };
        if self.reset {
            return Some("the mailbox was reset; reading it again from position 0".into());
        }
        // Read to the furthest position read (ruling R35: a rewind's
        // re-read closes nothing on its own).
        let read = observed
            .cursor
            .as_ref()
            .filter(|(id, _)| *id == announced.mailbox_id)
            .map(|(_, at)| (*at).max(observed.read_to));
        if read.is_none_or(|at| at < announced.head) {
            return Some(format!(
                "reading the mailbox ({} of {})",
                read.unwrap_or(0),
                announced.head
            ));
        }
        // Only a request, cancel or complete left on the Station holds it
        // (ruling R35): a result starts no work.
        if observed.skipped_inbox {
            return Some(
                "a mailbox object waits on the Station for room in this host's inbox".into(),
            );
        }
        // So does a waiting one that decided to open with no room (review
        // finding 2, ruling R39).
        if observed.waiting_for_room > 0 {
            return Some(format!(
                "{} waiting mailbox object(s) wait for room in this host's inbox",
                observed.waiting_for_room
            ));
        }
        // An inbox row waiting for admission is committed, its sender known:
        // it holds that sender's task starts only ([`Self::undecided`]).
        None
    }

    /// The inbox rows waiting for admission and the senders whose task
    /// starts they hold, as `atem status` says it (`None`: none, or the
    /// store isn't loaded).
    pub fn holding(&self) -> Option<String> {
        let observed = self.observed.as_ref().filter(|o| o.inbox > 0)?;
        let senders: Vec<String> = observed
            .undecided
            .iter()
            .map(|host_id| format!("host:{host_id}"))
            .collect();
        Some(format!(
            "{} mailbox object(s) wait for admission, holding the tasks of {} only",
            observed.inbox,
            senders.join(", ")
        ))
    }

    /// The positions of the live dones (tests).
    #[cfg(test)]
    pub fn live_done_positions(&self) -> Vec<u64> {
        self.dones.iter().map(|d| d.call.position).collect()
    }

    /// The runtime.log lines not taken yet (alerts).
    pub fn take_lines(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    /// The alerts in this run: how many, and the latest's text.
    pub fn alerts(&self) -> (u64, Option<&str>) {
        (self.alerts_in_run, self.last_alert.as_deref())
    }

    /// The host's own mailbox as last announced.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn announced(&self) -> Option<&MailboxHead> {
        self.announced.as_ref()
    }

    /// For the state dump.
    pub fn dump(&self) -> Value {
        json!({
            "announced": self.announced.as_ref().map(|a| json!({"mailbox_id": a.mailbox_id, "head": a.head})),
            "cursor": self.observed.as_ref().and_then(|o| o.cursor.as_ref()).map(|(id, at)| json!({"mailbox_id": id, "cursor": at})),
            "inbox": self.observed.as_ref().map(|o| o.inbox),
            "undecided": self.observed.as_ref().map(|o| o.undecided.iter().collect::<Vec<_>>()),
            "holding": self.holding(),
            "in_flight": self.in_flight.as_ref().map(|a| json!({"request_id": a.call.request_id, "after": a.call.after})),
            "open": self.open(),
            "closed": self.closed(),
            "reset": self.reset,
            "pages": self.pages,
            "drained": self.drained,
            "faults": self.faults,
            "resets": self.resets,
            "refusals": self.refusals,
            "timeouts": self.timeouts,
            "dones": self.dones.iter().map(|d| d.call.position).collect::<Vec<_>>(),
            "owed": self.observed.as_ref().map(|o| o.owed.clone()),
            "dones_sent": self.dones_sent,
            "dones_answered": self.dones_answered,
            "dones_refused": self.dones_refused,
            "unsolicited": self.unsolicited,
            "identity_moved": self.moved,
        })
    }

    // ------------------------------------------------------------ inside

    fn retire(&mut self, request_id: String) {
        if self.retired.len() >= RETIRED_KEPT {
            self.retired.pop_front();
        }
        self.retired.push_back(request_id);
    }

    fn retire_live(&mut self) {
        if let Some(ask) = self.in_flight.take() {
            self.retire(ask.call.request_id);
        }
    }

    fn retire_all(&mut self) {
        self.retire_live();
        for id in self.live_done_ids() {
            self.retire_done(&id);
        }
    }

    fn live_done_ids(&self) -> Vec<String> {
        self.dones
            .iter()
            .map(|d| d.call.request_id.clone())
            .collect()
    }

    fn retire_done(&mut self, request_id: &str) {
        self.dones.retain(|d| d.call.request_id != request_id);
        if self.retired_dones.len() >= RETIRED_KEPT {
            self.retired_dones.pop_front();
        }
        self.retired_dones.push_back(request_id.to_string());
    }

    /// A Station fault: the gate closed until a page asked after it reads.
    fn fault(&mut self, code: &'static str) -> PageCheck {
        self.faults += 1;
        self.epoch += 1;
        self.resync = Some(Resync::Fault(code));
        self.stalled_at = Some(self.now);
        self.alert(
            Alert::Fault,
            format!(
                "Station sent a mailbox page it shouldn't ({code}); host senders' gate stays closed and the page is asked again"
            ),
        );
        PageCheck::Fault(code)
    }

    /// An alert: counted for `atem status`, and a runtime.log line now when
    /// its kind's hour passed (with how many came since the last), else
    /// counted for the next.
    fn alert(&mut self, kind: Alert, text: String) {
        self.alerts_in_run += 1;
        self.last_alert = Some(text.clone());
        let now = self.now;
        let h = &mut self.alerts[kind as usize];
        let due = h
            .last
            .is_none_or(|last| now < last || now >= last.saturating_add(ALERT_EVERY_MS));
        if !due {
            h.counted += 1;
            return;
        }
        let more = std::mem::take(&mut h.counted);
        h.last = Some(now);
        let more = if more > 0 {
            format!(" ({more} more since the last such line)")
        } else {
            String::new()
        };
        self.lines.push(format!(
            "atem runtime: {text}{more}; at most one such line an hour"
        ));
    }

    /// The announcement against the store's cursor: another mailbox, or a
    /// head of the same one below the furthest position read (the cursor,
    /// or more while a rewind's re-read runs), is a reset.
    fn check_reset(&mut self) {
        let Some(announced) = &self.announced else {
            return;
        };
        let Some((id, at, read_to)) = self
            .observed
            .as_ref()
            .and_then(|o| o.cursor.as_ref().map(|(id, at)| (id, *at, o.read_to)))
        else {
            return;
        };
        // A head below the furthest position read (the cursor, or more
        // while a rewind's re-read runs) is the mailbox gone back.
        if *id != announced.mailbox_id || announced.head < at.max(read_to) {
            if !self.reset {
                eprintln!(
                    "atem runtime: host senders' mailbox was reset; reading it again from position 0"
                );
            }
            self.reset = true;
            self.retire_all();
        }
    }

    /// The host's cursor in the announced mailbox (none: not read).
    fn read(&self) -> Option<u64> {
        let announced = self.announced.as_ref()?;
        self.observed
            .as_ref()?
            .cursor
            .as_ref()
            .filter(|(id, _)| *id == announced.mailbox_id)
            .map(|(_, at)| *at)
    }

    fn behind(&self) -> bool {
        self.announced
            .as_ref()
            .is_some_and(|a| self.read().is_none_or(|at| at < a.head))
    }

    /// The sync the announced mailbox needs now, if any (the module docs:
    /// one live, none before a reset's mark or in a refusal's backoff;
    /// `paced` at most one a second, none in a stall's 30 s).
    fn ask(&mut self, paced: bool) {
        if self.in_flight.is_some() || self.moved || self.reset {
            return;
        }
        let (Some(link_gen), Some(socket), Some(announced), Some(observed)) = (
            self.link_gen,
            self.socket,
            self.announced.clone(),
            self.observed.clone(),
        ) else {
            return;
        };
        if let Some(at) = self.refused_at {
            if self.now < at.saturating_add(REFUSAL_BACKOFF_MS) {
                return;
            }
            self.refused_at = None;
        }
        if !(self.behind() || self.resync.is_some()) {
            return;
        }
        // Too many dones owed: none more until they are answered (O5).
        if observed.owed_count > MAX_OWED_DONES {
            return;
        }
        if paced {
            let within =
                |at: Option<u64>, ms: u64| at.is_some_and(|at| self.now < at.saturating_add(ms));
            if within(self.paced_at, HEADS_PACE_MS) || within(self.stalled_at, STALL_PAUSE_MS) {
                return;
            }
            self.paced_at = Some(self.now);
        }
        self.in_flight = Some(Ask {
            call: MailboxSync {
                request_id: fresh_request_id(),
                mailbox_id: announced.mailbox_id,
                after: self.read().unwrap_or(0),
            },
            link_gen,
            socket,
            identity: observed.identity,
            sent_at: self.now,
            epoch: self.epoch,
            sent: false,
        });
    }
}

#[cfg(test)]
#[path = "mailbox_tests.rs"]
mod tests;

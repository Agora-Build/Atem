//! The host's Station link (the delegated host-work design I.5.8;
//! host-work-v1 §11.4): the Station's messages to this host on Atem's one
//! link, read strictly by the shared reader (`atem_client::control::relay`),
//! and the calls the host makes. Only with `host.delegated` on (step 4's
//! Decision 11): no welcome feature gates relay messages, so the hook is
//! the switch, and no call reaches today's relay or Station otherwise.
//!
//! The link is whichever the host has: the relay (Astation authenticating
//! it), Astation's local `:8080` (which proxies the calls to the Station),
//! or a routed relay link with no Astation (§R9.7b). Its Station is the
//! selected Station ([`StationLink::origin`]). A new link generation starts
//! afresh: the fetch in flight doesn't carry over, a refusal's backoff
//! ends, and the live `control_sync` is retired by its id (a page that
//! still carries it is drained: [`FeedSync::on_link`], ruling C1b-a); the
//! fetch's pacing carries over ([`DeviceListFetch::next_generation`]), and
//! so does the sync's.
//!
//! Here: the device list's fetch ([`super::fetch`]) and its part of the
//! revocation gate ([`Station::list_fetch`]), the sync of the host's own
//! Station's control feed and the gate's feed part ([`super::sync`]: the
//! bridge hands it `heads` and pages, [`Inbound::Heads`] and
//! [`Inbound::Page`], with the feed store and the clock), and the
//! refusals: every gate the link serves closes ([`FeedSync::on_refused`])
//! and a runtime.log line goes at most once an hour per kind (Decision 20).
//! A message the reader refuses is counted and dropped, unless it is a
//! `control_sync_result` (peeked leniently, so a page that isn't strict
//! JSON is still known as one): that page is a Station fault the sync
//! answers ([`Inbound::Page`] with the reader's error).
use super::fetch::{DeviceListFetch, FetchApply};
use super::start::StationFetch;
use super::sync::FeedSync;
use atem_client::SignedObject;
use atem_client::control::{
    ControlSync, ControlSyncResult, Heads, MembershipFetch, RefusedCall, RelayError, ToHost,
};
use atem_client::membership::Head;
use serde_json::{Value, json};

/// A refusal's runtime.log line at most this often per kind (Decision 20).
const REFUSAL_LOG_EVERY_MS: u64 = 60 * 60 * 1000;

/// How the host's link reaches its Station.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// The relay, Astation authenticating the link.
    Relay,
    /// Astation's local link (`:8080`), which proxies the calls.
    Local,
    /// A relay link routed on the host's route proof, no Astation (§R9.7b).
    Routed,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Relay => "relay",
            LinkKind::Local => "local",
            LinkKind::Routed => "routed",
        }
    }
}

/// The host's link to its Station, one link generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationLink {
    /// The link generation (the App's `astation_link_gen`).
    pub link_gen: u64,
    /// The socket it runs on (`AstationClient::socket_id`): captured with
    /// each `control_sync`, which a page answers only on the generation and
    /// socket it went on (host-work-v1 §11.4, "Matching a page to its
    /// call"; ruling C1b-a).
    pub socket: u64,
    pub kind: LinkKind,
    /// The selected Station's origin (`station_route::destination`,
    /// normalized by `normalize_relay`), whatever the link: Astation's
    /// `:8080` proxies to it. `None` when the selection can't be read: no
    /// feed is this host's own Station's then (fail closed).
    pub origin: Option<String>,
}

/// What the bridge does with a Station's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Nothing,
    /// Apply these entries as any carriage (`HostBridge::carry`, then
    /// `R9Host::carried`), then [`DeviceListFetch::carried`] with where the
    /// carriage stopped at a deferred entry.
    Carry(Vec<SignedObject>),
    /// `heads`: the fetch's call, if one is due ([`DeviceListFetch`] took
    /// the announced list head already); the heads for the feed sync
    /// ([`FeedSync::on_heads`], with the clock and the feed store).
    Heads(Heads, Option<MembershipFetch>),
    /// A `control_sync_result`, or a message that was one and the reader
    /// refused: for [`FeedSync::on_page`].
    Page(Result<ControlSyncResult, RelayError>),
}

/// A call the host sends its Station on the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Fetch(MembershipFetch),
    Sync(ControlSync),
}

impl Call {
    /// The wire message (the shared builder's).
    pub fn to_json(&self) -> Option<Value> {
        match self {
            Call::Fetch(fetch) => fetch.to_json().ok(),
            Call::Sync(sync) => sync.to_json().ok(),
        }
    }
}

/// The host's side of its Station (the module docs give the rules).
#[derive(Debug, Default)]
pub struct Station {
    link: Option<StationLink>,
    pub fetch: DeviceListFetch,
    /// The sync of the host's own Station's control feed.
    pub feed: FeedSync,
    /// The host's monotonic clock at the last tick (ms).
    now: u64,
    /// `heads` read.
    heads: u64,
    /// Refusals read, and when each kind was last logged, by
    /// [`slot`].
    refusals: [u64; 3],
    logged: [Option<u64>; 3],
    /// Messages the shared reader refused.
    unread: u64,
}

fn slot(call: RefusedCall) -> usize {
    match call {
        RefusedCall::ControlSync => 0,
        RefusedCall::MembershipFetch => 1,
        RefusedCall::ControlAck => 2,
    }
}

/// The call a refusal answers, as named on the wire.
fn call_name(call: RefusedCall) -> &'static str {
    match call {
        RefusedCall::ControlSync => "control_sync",
        RefusedCall::MembershipFetch => "membership_fetch",
        RefusedCall::ControlAck => "control_ack",
    }
}

impl Station {
    pub fn new() -> Station {
        Station::default()
    }

    /// The link as the App has it now (`link_gen`: the r9 link generation, none
    /// while it is down; `socket`: the socket it runs on): a new generation
    /// starts afresh (the fetch's pacing kept), its kind and origin taken
    /// then; the kind is followed within a generation (a routed link
    /// Astation authenticates becomes a relay link).
    pub fn sync_link(
        &mut self,
        link_gen: Option<u64>,
        socket: u64,
        kind: impl FnOnce() -> LinkKind,
        origin: impl FnOnce() -> Option<String>,
    ) {
        let Some(link_gen) = link_gen else {
            if self.link.take().is_some() {
                self.fetch = self.fetch.next_generation();
                self.feed.on_link_down();
            }
            return;
        };
        match self.link.as_mut() {
            Some(link) if link.link_gen == link_gen && link.socket == socket => link.kind = kind(),
            _ => {
                self.link = Some(StationLink {
                    link_gen,
                    socket,
                    kind: kind(),
                    origin: origin(),
                });
                self.fetch = self.fetch.next_generation();
                self.feed.on_link(self.link.as_ref());
            }
        }
    }

    /// The link now (the feeds read its origin).
    pub fn link(&self) -> Option<&StationLink> {
        self.link.as_ref()
    }

    /// What the revocation gate reads of the host's own fetch on this link
    /// (design I.5.8): its Station's origin and the fetch's device-list part;
    /// none without a link.
    pub fn list_fetch(&self) -> Option<StationFetch> {
        let link = self.link.as_ref()?;
        Some(StationFetch {
            origin: link.origin.clone(),
            part: self.fetch.part(),
        })
    }

    /// The pass's monotonic time, the device list's head (`None`: no list)
    /// and its deferral (the deferred entry's `seq`): a call due now.
    pub fn tick(
        &mut self,
        now_mono: u64,
        applied: Option<Head>,
        deferred: Option<u64>,
    ) -> Option<MembershipFetch> {
        self.now = now_mono;
        self.fetch.tick(now_mono, applied.as_ref(), deferred)
    }

    /// A Station's message on the link (`bytes` as received); `applied`:
    /// the device list's head (`None`: no list, nothing to fetch), and its
    /// deferral (`deferred`, the deferred entry's `seq`).
    pub fn receive(
        &mut self,
        bytes: &str,
        applied: Option<Head>,
        deferred: Option<u64>,
    ) -> Inbound {
        if self.link.is_none() {
            return Inbound::Nothing;
        }
        match ToHost::decode(bytes.as_bytes()) {
            Ok(ToHost::Heads(heads)) => {
                self.heads += 1;
                let fetch = applied
                    .and_then(|applied| self.fetch.on_heads(&heads.membership, &applied, deferred));
                Inbound::Heads(heads, fetch)
            }
            Ok(ToHost::MembershipFetchResult(result)) => match self.fetch.on_result(result) {
                FetchApply::Carry(entries) => Inbound::Carry(entries),
                FetchApply::Unasked => Inbound::Nothing,
            },
            Ok(ToHost::MembershipFetchRefused(_)) => {
                self.refused(RefusedCall::MembershipFetch);
                self.fetch.on_refused();
                Inbound::Nothing
            }
            Ok(ToHost::ControlSyncRefused(_)) => {
                self.refused(RefusedCall::ControlSync);
                Inbound::Nothing
            }
            Ok(ToHost::ControlAckRefused(_)) => {
                self.refused(RefusedCall::ControlAck);
                Inbound::Nothing
            }
            Ok(ToHost::ControlSyncResult(page)) => Inbound::Page(Ok(page)),
            // A page the reader refused as a whole: a Station fault, for
            // the sync to answer (§11.4).
            Err(e) if is_page(bytes) => Inbound::Page(Err(e)),
            Err(e) => {
                // Counted, never its content.
                self.unread += 1;
                if self.unread.is_power_of_two() {
                    eprintln!(
                        "atem runtime: {} Station message(s) the reader refused were dropped (the last: {})",
                        self.unread,
                        e.code()
                    );
                }
                Inbound::Nothing
            }
        }
    }

    /// For the state dump.
    pub fn dump(&self) -> Value {
        json!({
            "link": self.link.as_ref().map(|l| json!({
                "gen": l.link_gen, "kind": l.kind.as_str(), "origin": l.origin})),
            "fetch": self.fetch.dump(),
            "heads": self.heads,
            "refusals": {
                "control_sync": self.refusals[0],
                "membership_fetch": self.refusals[1],
                "control_ack": self.refusals[2],
            },
            "unread": self.unread,
            "feed": self.feed.dump(),
        })
    }

    /// A refusal of `call` on this link (Decision 20): counted, every gate
    /// the link serves closes (the feed sync's part, whatever the call),
    /// and a runtime.log line at most once an hour per kind. It names no
    /// request and completes none.
    fn refused(&mut self, call: RefusedCall) {
        self.feed.on_refused(call);
        let i = slot(call);
        self.refusals[i] += 1;
        let due = self.logged[i]
            .is_none_or(|at| self.now < at || self.now >= at.saturating_add(REFUSAL_LOG_EVERY_MS));
        if due {
            self.logged[i] = Some(self.now);
            eprintln!(
                "atem runtime: the Station refused this host's {} (forbidden); retrying",
                call_name(call)
            );
        }
    }
}

/// Whether `bytes` is a `control_sync_result`, its top-level names read
/// with no tree (`peek`: any `op` occurrence, whatever else it holds: a
/// lone surrogate, a fraction, a duplicate key, nesting past a parser's
/// depth, a page cut short), so a page the strict reader refuses is still
/// known as a page (Task 30 review 5, Task 33 review m2).
fn is_page(bytes: &str) -> bool {
    crate::session_protocol::r9::peek::top_level_strings(bytes, "op")
        .iter()
        .any(|op| op == atem_client::control::relay::op::CONTROL_SYNC_RESULT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::delegated::fetch::{HEADS_PACE_MS, STALL_PAUSE_MS};
    use atem_client::control::{CallRefused, Heads, MembershipFetchResult, RefusalCode};
    use atem_client::encoding::Hash32;

    fn head(seq: u64) -> Head {
        Head {
            seq,
            hash: Hash32([seq as u8; 32]),
        }
    }

    fn heads(seq: u64) -> String {
        Heads {
            feeds: Vec::new(),
            membership: head(seq),
        }
        .to_json()
        .unwrap()
        .to_string()
    }

    fn refused(call: RefusedCall) -> String {
        CallRefused {
            call,
            code: RefusalCode::Forbidden,
        }
        .to_json()
        .unwrap()
        .to_string()
    }

    /// What a `heads` gave the fetch: its call, if one went.
    fn fetched(inbound: Inbound) -> Option<MembershipFetch> {
        match inbound {
            Inbound::Heads(_, call) => call,
            Inbound::Nothing => None,
            other => panic!("not a heads: {other:?}"),
        }
    }

    fn up(station: &mut Station, link_gen: u64) {
        station.sync_link(
            Some(link_gen),
            1,
            || LinkKind::Routed,
            || Some("https://s.test".into()),
        );
    }

    /// The link: a new generation starts afresh, the kind is followed,
    /// the origin taken once; with no link, nothing is read.
    #[test]
    fn a_new_link_generation_starts_afresh() {
        let mut s = Station::new();
        assert_eq!(fetched(s.receive(&heads(5), Some(head(3)), None)), None);
        up(&mut s, 1);
        assert_eq!(
            fetched(s.receive(&heads(5), Some(head(3)), None)),
            Some(MembershipFetch { after: 3 })
        );
        s.sync_link(Some(1), 1, || LinkKind::Relay, || panic!("not asked again"));
        assert_eq!(s.link().unwrap().kind, LinkKind::Relay);
        assert_eq!(s.dump()["fetch"]["in_flight"], 3, "the same generation");
        up(&mut s, 2);
        assert_eq!(s.dump()["fetch"]["in_flight"], Value::Null);
        assert_eq!(s.link().unwrap().origin.as_deref(), Some("https://s.test"));
        s.sync_link(None, 0, || LinkKind::Relay, || None);
        assert!(s.link().is_none());
    }

    /// Without a device list nothing is fetched; a result is carried only
    /// for the fetch asked; what the reader refuses is counted, dropped.
    #[test]
    fn messages_are_read_strictly() {
        let mut s = Station::new();
        up(&mut s, 1);
        assert_eq!(fetched(s.receive(&heads(5), None, None)), None);
        assert_eq!(s.dump()["heads"], 1);
        let result = MembershipFetchResult {
            head: head(5),
            entries: Vec::new(),
        }
        .to_json()
        .unwrap()
        .to_string();
        assert_eq!(s.receive(&result, Some(head(3)), None), Inbound::Nothing);
        fetched(s.receive(&heads(5), Some(head(3)), None));
        assert_eq!(
            s.receive(&result, Some(head(3)), None),
            Inbound::Carry(Vec::new())
        );
        let duplicate = r#"{"type":"relay","op":"heads","feeds":[],"feeds":[],"membership":{"seq":5,"hash":"00"}}"#;
        assert_eq!(s.receive(duplicate, Some(head(3)), None), Inbound::Nothing);
        assert_eq!(s.dump()["unread"], 1);
    }

    /// Decision 20: each refusal counted per kind; a membership_fetch
    /// refusal ends the fetch in flight; nothing else changes.
    #[test]
    fn refusals_are_counted_per_kind() {
        let mut s = Station::new();
        up(&mut s, 1);
        s.tick(1_000, Some(head(3)), None);
        fetched(s.receive(&heads(5), Some(head(3)), None));
        for call in [
            RefusedCall::ControlSync,
            RefusedCall::ControlAck,
            RefusedCall::MembershipFetch,
            RefusedCall::MembershipFetch,
        ] {
            assert_eq!(
                s.receive(&refused(call), Some(head(3)), None),
                Inbound::Nothing
            );
        }
        let dump = s.dump();
        assert_eq!(dump["refusals"]["control_sync"], 1);
        assert_eq!(dump["refusals"]["control_ack"], 1);
        assert_eq!(dump["refusals"]["membership_fetch"], 2);
        assert_eq!(dump["fetch"]["in_flight"], Value::Null);
        assert_eq!(dump["fetch"]["backoff"], true);
        // Logged once per kind within the hour, again after it.
        assert_eq!(s.logged, [Some(1_000); 3]);
        s.tick(1_000 + REFUSAL_LOG_EVERY_MS, Some(head(3)), None);
        s.receive(&refused(RefusedCall::ControlAck), None, None);
        assert_eq!(s.logged[2], Some(1_000 + REFUSAL_LOG_EVERY_MS));
        assert_eq!(s.logged[0], Some(1_000));
    }

    /// Task 30 re-review N1: a new link generation (or the link dropping
    /// and coming back) keeps the fetch's pacing: after a carriage that
    /// moved nothing, no fetch at a `heads` for 30 s whatever the
    /// generation; and at most one a second a `heads` starts.
    #[test]
    fn a_new_link_generation_keeps_the_fetch_pacing() {
        let mut s = Station::new();
        up(&mut s, 1);
        s.tick(10_000, Some(head(3)), None);
        let fetch = |after| Some(MembershipFetch { after });
        assert_eq!(fetched(s.receive(&heads(5), Some(head(3)), None)), fetch(3));
        let junk = MembershipFetchResult {
            head: head(5),
            entries: Vec::new(),
        }
        .to_json()
        .unwrap()
        .to_string();
        assert_eq!(
            s.receive(&junk, Some(head(3)), None),
            Inbound::Carry(Vec::new())
        );
        assert_eq!(s.fetch.carried(&head(3), &head(3), None), None, "a stall");
        up(&mut s, 2);
        s.tick(10_000 + STALL_PAUSE_MS - 1, Some(head(3)), None);
        assert_eq!(fetched(s.receive(&heads(5), Some(head(3)), None)), None);
        s.tick(10_000 + STALL_PAUSE_MS, Some(head(3)), None);
        assert_eq!(fetched(s.receive(&heads(5), Some(head(3)), None)), fetch(3));
        // Down and up again at once: nothing in flight, the pace kept.
        s.sync_link(None, 0, || LinkKind::Relay, || None);
        up(&mut s, 3);
        assert_eq!(s.dump()["fetch"]["in_flight"], Value::Null);
        assert_eq!(fetched(s.receive(&heads(5), Some(head(3)), None)), None);
        s.tick(10_000 + STALL_PAUSE_MS + HEADS_PACE_MS, Some(head(3)), None);
        assert_eq!(fetched(s.receive(&heads(5), Some(head(3)), None)), fetch(3));
    }

    /// I1: a Station that sends `heads` and junk results, many in one pass
    /// (the host's clock still), gets at most one carriage applied.
    #[test]
    fn heads_and_junk_results_in_one_pass_carry_at_most_once() {
        let mut s = Station::new();
        up(&mut s, 1);
        s.tick(5_000, Some(head(3)), None);
        let junk = MembershipFetchResult {
            head: head(9),
            entries: Vec::new(),
        }
        .to_json()
        .unwrap()
        .to_string();
        let mut carriages = 0;
        for _ in 0..32 {
            fetched(s.receive(&heads(9), Some(head(3)), None));
            if let Inbound::Carry(_) = s.receive(&junk, Some(head(3)), None) {
                carriages += 1;
                s.fetch.carried(&head(3), &head(3), None);
            }
        }
        assert_eq!(carriages, 1);
    }

    /// Decision 20: a refusal of any kind closes the gates the link serves
    /// (the feed sync's part), and a `membership_fetch_refused` leaves the
    /// fetch's announced head and stop as they were (Task 31 review).
    #[test]
    fn every_refusal_closes_the_links_feed_gate() {
        for call in [
            RefusedCall::ControlSync,
            RefusedCall::MembershipFetch,
            RefusedCall::ControlAck,
        ] {
            let mut s = Station::new();
            up(&mut s, 1);
            s.tick(1_000, Some(head(3)), None);
            fetched(s.receive(&heads(5), Some(head(3)), None));
            let part = s.fetch.part();
            s.receive(&refused(call), Some(head(3)), None);
            assert_eq!(
                s.feed.closed(),
                Some(crate::runtime::delegated::sync::Closed::Refused),
                "{call:?}"
            );
            assert_eq!(s.fetch.part(), part, "{call:?}");
        }
    }

    /// §11.4: a `control_sync_result` the reader refuses as a whole (here a
    /// lone surrogate, a duplicate key) is still known as a page, for the
    /// sync to answer as a Station fault; any other message it refuses is
    /// counted and dropped.
    #[test]
    fn a_page_the_reader_refuses_is_still_a_page() {
        let mut s = Station::new();
        up(&mut s, 1);
        for bytes in [
            r#"{"type":"relay","op":"control_sync_result","origin":"https://s.test","feed_id":"\ud800","head":0,"station_time":1,"records":[]}"#,
            r#"{"type":"relay","op":"control_sync_result","origin":"https://s.test","origin":"https://s.test","feed_id":"6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b","head":0,"station_time":1,"records":[]}"#,
            r#"{"type":"relay","op":"control_sync_result","origin":"https://s.test","feed_id":"6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b","head":0.5,"station_time":1,"records":[]}"#,
        ] {
            assert_eq!(
                s.receive(bytes, Some(head(3)), None),
                Inbound::Page(Err(RelayError::NotStrict)),
                "{bytes}"
            );
        }
        // Task 33 review m2: nesting past the parsers' depth, and a
        // duplicate `op` key, are pages too.
        let deep = format!(
            r#"{{"type":"relay","op":"control_sync_result","records":[{{"feed_seq":1,"record":{}1{}}}]}}"#,
            "[".repeat(300),
            "]".repeat(300)
        );
        let twice = r#"{"type":"relay","op":"heads","op":"control_sync_result","records":[]}"#;
        for bytes in [deep.as_str(), twice] {
            assert_eq!(
                s.receive(bytes, Some(head(3)), None),
                Inbound::Page(Err(RelayError::NotStrict)),
                "{bytes}"
            );
        }
        assert_eq!(s.dump()["unread"], 0);
        let page = r#"{"type":"relay","op":"control_sync_result","origin":"https://s.test","feed_id":"6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b","head":0,"station_time":1,"records":[],"extra":1}"#;
        assert_eq!(
            s.receive(page, Some(head(3)), None),
            Inbound::Page(Err(RelayError::UnknownField))
        );
    }
}

//! The revocation gate (design I.5.8; host-work-v1 §11.6, start check
//! condition 5): an unstarted delegated task starts only while its sender's
//! gate is open.
//!
//! - **A Station's gate** has two parts (I.5.8): its feed, applied up to
//!   the announced head (the host's sync, [`super::sync`]), and the device
//!   list, fetched up to the head that Station announced or up to a
//!   deferred entry (`StartView::fetched`, from the host's own fetch on its
//!   link, so only the host's own Station's gate can have it). It opens
//!   only with both.
//! - **A covered service** waits for the gate of the origin of its
//!   principal's **current** coverage (step 4's Decision 14).
//! - **A native member** waits for the gate of the host's own Station (the
//!   selected route's relay origin), or passes while it holds an authorized
//!   channel whose `hello` carriage brought the host up to the native's own
//!   head (I.5.8, "Native senders"; `R9Host::native_caught_up`). That is
//!   v1's rule (a native's task dispatches while its channel is open), so a
//!   host reached only on a local network, with no Station, still runs a
//!   connected native's work (VII.A test 20).
//!
//! - **A host sender** waits for the host's own Station's gate and, with
//!   it, the gate's mailbox part (design II.5): the host's own mailbox read
//!   and committed up to the announced head, nothing left for want of room
//!   ([`super::mailbox::MailboxClient::open`], [`Gates::set_mailbox`]), and
//!   none of its own inbox rows waiting for admission
//!   ([`Gates::set_mailbox_undecided`]): a committed row holds its own
//!   sender's task starts only, never another sender's (final readings
//!   item 6's proviso, #120 comment 7028723996). Natives and services never
//!   wait for the mailbox.
//!
//! The feed part is the host's sync's ([`super::sync::FeedSync`]): it
//! syncs only its own Station's feed (Decision 14), so only that Station's
//! gate opens. The start view holds a copy ([`Gates`]), given at each
//! change ([`Gates::set_feeds`], Decision 16), beside the natives'
//! caught-up channels.
use super::DelegatedSender;
use std::collections::BTreeSet;

/// Whether a delegated sender's gate is open now; `fetched`: the Station
/// whose gate has its device-list part (`StartView::fetched`).
pub trait GateView {
    fn open_for(&self, sender: &DelegatedSender, fetched: Option<&str>) -> bool;
}

/// The gates as the start view holds them: all closed by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gates {
    /// The Station origins whose feed part is open (design I.5.8): the
    /// host's own, or none ([`super::sync::FeedSync::take_gates`]).
    open: BTreeSet<String>,
    /// Tests only: the Station origins whose whole gate is open, its
    /// device-list part too, with no fetch.
    #[cfg(test)]
    stood_in: BTreeSet<String>,
    /// The host's own Station's origin: a native member's gate.
    own: Option<String>,
    /// The native members (`member:<id>`) holding a caught-up channel
    /// (`R9Host::native_caught_up`).
    caught_up: BTreeSet<String>,
    /// The mailbox part, host senders' only (design II.5): what holds every
    /// host sender (the mailbox not read to its head, a reset, an object
    /// left for want of room: nobody knows whose it is yet).
    mailbox: bool,
    /// The host senders (`host_id`) with committed inbox rows not yet
    /// decided: each holds its own sender's task starts only.
    mailbox_undecided: BTreeSet<String>,
}

impl Gates {
    /// The native members holding a caught-up channel, as the r9 engine
    /// has them now.
    pub fn set_caught_up(&mut self, natives: BTreeSet<String>) {
        self.caught_up = natives;
    }

    /// The feed part as the host's sync has it now: its own Station's
    /// origin, and the origins whose feed part is open.
    pub fn set_feeds(&mut self, own: Option<String>, open: BTreeSet<String>) {
        self.own = own;
        self.open = open;
    }

    /// The mailbox part as the host's mailbox client has it now (design
    /// II.5).
    pub fn set_mailbox(&mut self, open: bool) {
        self.mailbox = open;
    }

    /// The host senders whose task starts their own inbox rows hold, as
    /// the store committed them (a request, `cancel` or `complete` waiting
    /// for admission, one held for room among its sender's early stops
    /// included, ruling R47): read from the same store as the mailbox part,
    /// so a restart has them before the part opens.
    pub fn set_mailbox_undecided(&mut self, undecided: BTreeSet<String>) {
        self.mailbox_undecided = undecided;
    }

    /// Every Station's gate closed (design I.6.2 step 7, at a start's
    /// recovery): a delegated sender's remote tasks wait until its feed is
    /// synced again (the sync is told too, `FeedSync::restart`). The
    /// natives' caught-up channels stay: each one's carriage was applied in
    /// this run.
    pub fn close_stations(&mut self) {
        self.open.clear();
        self.mailbox = false;
        #[cfg(test)]
        self.stood_in.clear();
    }

    /// Whether any Station's gate is open.
    #[cfg(test)]
    pub fn any_station_open(&self) -> bool {
        !self.open.is_empty()
    }

    /// Tests: `origin`'s whole gate is open, and it is the host's own
    /// Station's, with no feed sync and no fetch (unit tests of the
    /// lifecycle; the binary tests go through both).
    #[cfg(test)]
    pub fn open_own_station(&mut self, origin: &str) {
        self.open_feed(origin);
        self.stood_in.insert(origin.to_string());
        self.mailbox = true;
    }

    /// Tests: `origin`'s feed part is open, and it is the host's own
    /// Station's; its device-list part is the fetch's.
    #[cfg(test)]
    pub fn open_feed(&mut self, origin: &str) {
        self.own = Some(origin.to_string());
        self.open.insert(origin.to_string());
    }

    /// `origin`'s gate: its feed part, and its device-list part (`fetched`
    /// names it).
    fn station_open(&self, origin: &str, fetched: Option<&str>) -> bool {
        #[cfg(test)]
        let fetched = if self.stood_in.contains(origin) {
            Some(origin)
        } else {
            fetched
        };
        self.open.contains(origin) && fetched == Some(origin)
    }
}

impl GateView for Gates {
    fn open_for(&self, sender: &DelegatedSender, fetched: Option<&str>) -> bool {
        match sender {
            DelegatedSender::Native { device_id } => {
                self.own
                    .as_deref()
                    .is_some_and(|own| self.station_open(own, fetched))
                    || self.caught_up.contains(&format!("member:{device_id}"))
            }
            DelegatedSender::Service { feed, .. } => self.station_open(&feed.origin, fetched),
            // The host's own Station's gate (design II.5): its feed and its
            // device list, which carry every stop of a host sender. No
            // channel opens it: a host sender has none, and a native's
            // caught-up channel speaks for that native only.
            // And the mailbox part (design II.5), with none of its own
            // inbox rows undecided.
            DelegatedSender::Host { host_id, .. } => {
                self.mailbox
                    && !self.mailbox_undecided.contains(host_id)
                    && self
                        .own
                        .as_deref()
                        .is_some_and(|own| self.station_open(own, fetched))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::delegated::FeedRef;

    const ORIGIN: &str = "https://station-dev.agora.build";

    fn native(id: &str) -> DelegatedSender {
        DelegatedSender::Native {
            device_id: id.into(),
        }
    }

    fn service(origin: &str) -> DelegatedSender {
        DelegatedSender::Service {
            device_id: "svc-bot".into(),
            feed: FeedRef {
                origin: origin.into(),
                feed_id: "feed-1".into(),
            },
        }
    }

    /// The gates closed (VII.A test 20, design I.5.8): a service never
    /// passes and a native passes only while it holds a caught-up channel,
    /// its own; once the host's own Station's gate opens, every native
    /// passes and a service whose current coverage names that origin does.
    #[test]
    fn closed_gates_pass_only_a_caught_up_native() {
        let mut gates = Gates::default();
        assert!(!gates.open_for(&native("dev-phone"), None));
        assert!(!gates.open_for(&service(ORIGIN), None));
        gates.set_caught_up(BTreeSet::from(["member:dev-phone".to_string()]));
        assert!(gates.open_for(&native("dev-phone"), None));
        assert!(
            !gates.open_for(&native("dev-tablet"), None),
            "its own channel only"
        );
        assert!(!gates.open_for(&service(ORIGIN), None));
        gates.set_caught_up(BTreeSet::new());
        assert!(
            !gates.open_for(&native("dev-phone"), None),
            "the channel closed"
        );

        gates.open_own_station(ORIGIN);
        assert!(gates.open_for(&native("dev-tablet"), None));
        assert!(gates.open_for(&service(ORIGIN), None));
        assert!(!gates.open_for(&service("https://other.example"), None));

        // A start's recovery closes every Station's gate; a native's own
        // caught-up channel still opens its own.
        gates.set_caught_up(BTreeSet::from(["member:dev-phone".to_string()]));
        gates.close_stations();
        assert!(!gates.any_station_open());
        assert!(!gates.open_for(&native("dev-tablet"), None));
        assert!(!gates.open_for(&service(ORIGIN), None));
        assert!(gates.open_for(&native("dev-phone"), None));

        // The feed part alone: the device-list part is the fetch's, and
        // only for the Station it names.
        let mut gates = Gates::default();
        gates.open_feed(ORIGIN);
        assert!(!gates.open_for(&service(ORIGIN), None));
        assert!(!gates.open_for(&native("dev-tablet"), None));
        assert!(!gates.open_for(&service(ORIGIN), Some("https://other.example")));
        assert!(gates.open_for(&service(ORIGIN), Some(ORIGIN)));
        assert!(gates.open_for(&native("dev-tablet"), Some(ORIGIN)));
        // The fetch's part with no feed part: closed.
        let gates = Gates::default();
        assert!(!gates.open_for(&service(ORIGIN), Some(ORIGIN)));
    }

    /// Design II.5: a host sender waits for the host's own Station's gate,
    /// its feed and device-list parts both (its stops come with them); no
    /// channel opens it, a caught-up native's included.
    #[test]
    fn a_host_sender_waits_for_the_own_stations_gate() {
        let host = DelegatedSender::Host {
            host_id: "host-b".into(),
            generation: 3,
            epoch: 3,
        };
        let mut gates = Gates::default();
        gates.set_caught_up(BTreeSet::from(["member:dev-phone".to_string()]));
        gates.set_mailbox(true);
        assert!(!gates.open_for(&host, None));
        gates.open_feed(ORIGIN);
        assert!(!gates.open_for(&host, None), "the feed part alone");
        assert!(!gates.open_for(&host, Some("https://other.example")));
        assert!(gates.open_for(&host, Some(ORIGIN)));
        gates.close_stations();
        assert!(!gates.open_for(&host, Some(ORIGIN)));
        gates.open_own_station(ORIGIN);
        assert!(gates.open_for(&host, None));
    }

    /// Design II.5: a host sender's gate also needs the mailbox part (the
    /// host's own mailbox read and committed to the announced head; its own
    /// inbox rows, below); natives and services never wait for it. A
    /// start's recovery closes it with the Stations' gates.
    #[test]
    fn only_host_senders_wait_for_the_mailbox() {
        let host = DelegatedSender::Host {
            host_id: "host-b".into(),
            generation: 1,
            epoch: 1,
        };
        let mut gates = Gates::default();
        gates.open_feed(ORIGIN);
        let fetched = Some(ORIGIN);
        assert!(gates.open_for(&native("dev-tablet"), fetched));
        assert!(gates.open_for(&service(ORIGIN), fetched));
        assert!(!gates.open_for(&host, fetched), "the mailbox part");
        gates.set_mailbox(true);
        assert!(gates.open_for(&host, fetched));
        gates.close_stations();
        gates.open_feed(ORIGIN);
        assert!(!gates.open_for(&host, fetched), "closed with the Stations");
        assert!(gates.open_for(&service(ORIGIN), fetched));
    }

    /// Final readings item 6's proviso (#120 comment 7028723996): a host
    /// sender's committed inbox rows waiting for admission hold its own
    /// task starts only; another host sender's, natives' and services'
    /// pass. The mailbox part closed holds every host sender, rows or not.
    #[test]
    fn an_undecided_inbox_row_holds_only_its_own_sender() {
        let host = |id: &str| DelegatedSender::Host {
            host_id: id.into(),
            generation: 1,
            epoch: 1,
        };
        let mut gates = Gates::default();
        gates.open_own_station(ORIGIN);
        gates.set_mailbox_undecided(BTreeSet::from(["host-b".to_string()]));
        assert!(!gates.open_for(&host("host-b"), None), "its own row");
        assert!(gates.open_for(&host("host-c"), None), "not another's");
        assert!(gates.open_for(&native("dev-tablet"), None));
        assert!(gates.open_for(&service(ORIGIN), None));
        gates.set_mailbox(false);
        assert!(!gates.open_for(&host("host-c"), None), "the part closed");
        gates.set_mailbox(true);
        gates.set_mailbox_undecided(BTreeSet::new());
        assert!(gates.open_for(&host("host-b"), None), "decided");
    }
}

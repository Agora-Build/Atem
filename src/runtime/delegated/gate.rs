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

    /// Every Station's gate closed (design I.6.2 step 7, at a start's
    /// recovery): a delegated sender's remote tasks wait until its feed is
    /// synced again (the sync is told too, `FeedSync::restart`). The
    /// natives' caught-up channels stay: each one's carriage was applied in
    /// this run.
    pub fn close_stations(&mut self) {
        self.open.clear();
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
}

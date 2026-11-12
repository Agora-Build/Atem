//! The revocation gate (design I.5.8; host-work-v1 §11.6, start check
//! condition 5): an unstarted delegated task starts only while its sender's
//! gate is open.
//!
//! - **A covered service** waits for the gate of the origin of its
//!   principal's **current** coverage (step 4's Decision 14): open once the
//!   host applied that origin's feeds up to the announced heads and fetched
//!   the device list up to its head (I.5.8).
//! - **A native member** waits for the gate of the host's own Station (the
//!   selected route's relay origin), or passes while it holds an authorized
//!   channel whose `hello` carriage brought the host up to the native's own
//!   head (I.5.8, "Native senders"; `R9Host::native_caught_up`). That is
//!   v1's rule (a native's task dispatches while its channel is open), so a
//!   host reached only on a local network, with no Station, still runs a
//!   connected native's work (VII.A test 20).
//!
//! This version syncs no feed: every Station's gate is closed
//! ([`Gates::closed_until_feeds`]) until the feeds exist (PR 10), so only a
//! native with a caught-up channel passes.
use super::DelegatedSender;
use std::collections::BTreeSet;

/// Whether a delegated sender's gate is open now.
pub trait GateView {
    fn open_for(&self, sender: &DelegatedSender) -> bool;
}

/// The gates as the host knows them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gates {
    /// The Station origins whose gate is open (design I.5.8): none until
    /// the host syncs feeds.
    open: BTreeSet<String>,
    /// The host's own Station's origin: a native member's gate.
    own: Option<String>,
    /// The native members (`member:<id>`) holding a caught-up channel
    /// (`R9Host::native_caught_up`).
    caught_up: BTreeSet<String>,
}

impl Gates {
    /// Every Station's gate closed: the host syncs no feed yet (PR 10), so
    /// a native member passes only with its own caught-up channel and a
    /// service never does.
    pub fn closed_until_feeds() -> Gates {
        Gates::default()
    }

    /// The native members holding a caught-up channel, as the r9 engine
    /// has them now.
    pub fn set_caught_up(&mut self, natives: BTreeSet<String>) {
        self.caught_up = natives;
    }

    /// Tests: `origin`'s gate is open, and it is the host's own Station's
    /// (what the feeds will make it, PR 10).
    #[cfg(test)]
    pub fn open_own_station(&mut self, origin: &str) {
        self.own = Some(origin.to_string());
        self.open.insert(origin.to_string());
    }
}

impl GateView for Gates {
    fn open_for(&self, sender: &DelegatedSender) -> bool {
        match sender {
            DelegatedSender::Native { device_id } => {
                self.own.as_ref().is_some_and(|own| self.open.contains(own))
                    || self.caught_up.contains(&format!("member:{device_id}"))
            }
            DelegatedSender::Service { feed, .. } => self.open.contains(&feed.origin),
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

    /// This version's gates (VII.A test 20, design I.5.8): every Station's
    /// closed, so a service never passes and a native passes only while it
    /// holds a caught-up channel, its own; once the feeds open the host's
    /// own Station's gate, every native passes and a service whose current
    /// coverage names that origin does.
    #[test]
    fn closed_until_feeds_passes_only_a_caught_up_native() {
        let mut gates = Gates::closed_until_feeds();
        assert!(!gates.open_for(&native("dev-phone")));
        assert!(!gates.open_for(&service(ORIGIN)));
        gates.set_caught_up(BTreeSet::from(["member:dev-phone".to_string()]));
        assert!(gates.open_for(&native("dev-phone")));
        assert!(
            !gates.open_for(&native("dev-tablet")),
            "its own channel only"
        );
        assert!(!gates.open_for(&service(ORIGIN)));
        gates.set_caught_up(BTreeSet::new());
        assert!(!gates.open_for(&native("dev-phone")), "the channel closed");

        gates.open_own_station(ORIGIN);
        assert!(gates.open_for(&native("dev-tablet")));
        assert!(gates.open_for(&service(ORIGIN)));
        assert!(!gates.open_for(&service("https://other.example")));
    }
}

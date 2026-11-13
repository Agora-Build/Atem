//! The host's own device-list fetch (the delegated host-work design I.5.8,
//! "the host fetches the device list itself"; session-v1 R9.3; host-work-v1
//! §11.4): announced a device-list head beyond its own by its Station
//! (`heads`), the host asks for the entries after its head
//! (`membership_fetch{after}`) over its one link, and applies the result as
//! any carriage: it gets no more trust than any carrier (R9.3), the list's
//! own verification decides.
//!
//! - **One fetch at a time.** A `heads` while one is in flight only notes
//!   the head the Station named.
//! - **A result is taken only for a fetch in flight** ([`FetchApply`]): a
//!   Station can't make the host apply carriages it didn't ask for.
//! - **Again while behind.** After a result's carriage, the host fetches
//!   again from its new head while that is behind the Station's last named
//!   head, as long as the carriage moved the head (a carriage that moved
//!   nothing, a deferred or conflicting entry say, waits for the next
//!   `heads`, so a Station can't spin the host).
//! - **A refusal** (`membership_fetch_refused`, step 4's Decision 20)
//!   advances nothing (no head, nothing applied) and correlates no request:
//!   the host forgets what it had in flight on the link, and fetches again
//!   only at a `heads` at least [`REFUSAL_BACKOFF_MS`] later on its
//!   monotonic clock, or on the next link generation (a new
//!   [`DeviceListFetch`]).
//! - **A fetch with no answer** for [`FETCH_TIMEOUT_MS`] (lost, or its
//!   result over 256 KiB, dropped unread: Decision 21) is sent again.
//!
//! The clock is the host's monotonic clock, given at every pass
//! ([`DeviceListFetch::tick`]).
use atem_client::SignedObject;
use atem_client::control::{MembershipFetch, MembershipFetchResult};
use atem_client::membership::Head;
use serde_json::{Value, json};

/// After a refusal, no fetch at a `heads` before this long (Decision 20).
pub const REFUSAL_BACKOFF_MS: u64 = 30_000;
/// A fetch unanswered this long is sent again.
pub const FETCH_TIMEOUT_MS: u64 = 30_000;

/// What to do with a `membership_fetch_result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchApply {
    /// No fetch of this link waits for one: nothing is applied.
    Unasked,
    /// Its entries, to apply as any carriage; then
    /// [`DeviceListFetch::carried`].
    Carry(Vec<SignedObject>),
}

/// The fetch in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    after: u64,
    sent_at: u64,
}

/// The fetch on one link generation (the module docs give the rules).
#[derive(Debug, Clone, Default)]
pub struct DeviceListFetch {
    /// The host's monotonic clock at the last tick (ms).
    now: u64,
    /// The head the Station named last (`heads`, or a result's): its word,
    /// not signed authority (I.5.8).
    named: Option<Head>,
    in_flight: Option<InFlight>,
    /// The last refusal (monotonic ms).
    refused_at: Option<u64>,
    /// Results taken.
    results: u64,
}

impl DeviceListFetch {
    /// The Station announced the device list's head `membership`; the
    /// host's list is at `applied`. The fetch to send, if any.
    pub fn on_heads(&mut self, membership: &Head, applied: &Head) -> Option<MembershipFetch> {
        self.named = Some(*membership);
        if self.in_flight.is_some() {
            return None;
        }
        if let Some(at) = self.refused_at {
            if self.now < at.saturating_add(REFUSAL_BACKOFF_MS) {
                return None;
            }
            self.refused_at = None;
        }
        self.ask(applied)
    }

    /// A `membership_fetch_result` (read by the shared reader, within 256
    /// KiB): its entries to carry, if a fetch waits for one.
    pub fn on_result(&mut self, r: MembershipFetchResult) -> FetchApply {
        if self.in_flight.take().is_none() {
            return FetchApply::Unasked;
        }
        self.results += 1;
        self.named = Some(r.head);
        FetchApply::Carry(r.entries)
    }

    /// A result's carriage was applied, the list's head going from `before`
    /// to `after`: the next fetch while still behind, if it moved.
    pub fn carried(&mut self, before: &Head, after: &Head) -> Option<MembershipFetch> {
        if after.seq <= before.seq {
            return None;
        }
        self.ask(after)
    }

    /// `membership_fetch_refused`: nothing advances; no fetch at a `heads`
    /// before the backoff.
    pub fn on_refused(&mut self) {
        self.in_flight = None;
        self.refused_at = Some(self.now);
    }

    /// The pass's monotonic time: a fetch unanswered too long, sent again.
    pub fn tick(&mut self, now_mono: u64) -> Option<MembershipFetch> {
        self.now = now_mono;
        let in_flight = self.in_flight.as_mut()?;
        if now_mono < in_flight.sent_at.saturating_add(FETCH_TIMEOUT_MS) {
            return None;
        }
        in_flight.sent_at = now_mono;
        Some(MembershipFetch {
            after: in_flight.after,
        })
    }

    /// The fetch just asked for couldn't be handed to the link: none in
    /// flight (the next `heads` asks again).
    pub fn unsent(&mut self) {
        self.in_flight = None;
    }

    /// For the state dump.
    pub fn dump(&self) -> Value {
        json!({
            "named": self.named.map(|h| h.seq),
            "in_flight": self.in_flight.map(|f| f.after),
            "backoff": self.refused_at.is_some(),
            "results": self.results,
        })
    }

    fn ask(&mut self, applied: &Head) -> Option<MembershipFetch> {
        let named = self.named?;
        if named.seq <= applied.seq {
            return None;
        }
        self.in_flight = Some(InFlight {
            after: applied.seq,
            sent_at: self.now,
        });
        Some(MembershipFetch { after: applied.seq })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atem_client::encoding::Hash32;

    fn head(seq: u64) -> Head {
        Head {
            seq,
            hash: Hash32([seq as u8; 32]),
        }
    }

    fn fetch(after: u64) -> Option<MembershipFetch> {
        Some(MembershipFetch { after })
    }

    fn result(seq: u64) -> MembershipFetchResult {
        MembershipFetchResult {
            head: head(seq),
            entries: Vec::new(),
        }
    }

    /// R9.3, I.5.8: a named head beyond the list's is fetched from the
    /// list's head; one at or below it isn't; one fetch at a time.
    #[test]
    fn fetch_when_the_named_head_is_beyond_the_list() {
        let mut f = DeviceListFetch::default();
        f.tick(1_000);
        assert_eq!(f.on_heads(&head(3), &head(3)), None);
        assert_eq!(f.on_heads(&head(2), &head(3)), None);
        assert_eq!(f.on_heads(&head(5), &head(3)), fetch(3));
        assert_eq!(f.on_heads(&head(6), &head(3)), None, "one at a time");
    }

    /// A result is taken only for a fetch in flight.
    #[test]
    fn a_result_nobody_asked_for_is_not_applied() {
        let mut f = DeviceListFetch::default();
        assert_eq!(f.on_result(result(5)), FetchApply::Unasked);
        f.on_heads(&head(5), &head(3));
        assert_eq!(f.on_result(result(5)), FetchApply::Carry(Vec::new()));
        assert_eq!(f.on_result(result(5)), FetchApply::Unasked, "taken once");
    }

    /// R9.3's 64-entry carriage: after a carriage that moved the head, the
    /// host fetches again while behind the named head; one that moved
    /// nothing waits for the next `heads`.
    #[test]
    fn fetch_again_while_behind_the_announced_head() {
        let mut f = DeviceListFetch::default();
        assert_eq!(f.on_heads(&head(80), &head(3)), fetch(3));
        assert!(matches!(f.on_result(result(80)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(3), &head(67)), fetch(67));
        assert!(matches!(f.on_result(result(80)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(67), &head(80)), None, "caught up");

        // A carriage that moved nothing (a deferred or conflicting entry).
        assert_eq!(f.on_heads(&head(90), &head(80)), fetch(80));
        assert!(matches!(f.on_result(result(90)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(80), &head(80)), None);
        assert_eq!(
            f.on_heads(&head(90), &head(80)),
            fetch(80),
            "at the next heads"
        );
    }

    /// Decision 20: a refusal advances nothing and ends what was in flight;
    /// a `heads` within 30 s fetches nothing, one 30 s later does; a new
    /// link generation (a new fetch) has no backoff.
    #[test]
    fn fetch_refused_advances_nothing_and_retries() {
        let mut f = DeviceListFetch::default();
        f.tick(10_000);
        assert_eq!(f.on_heads(&head(5), &head(3)), fetch(3));
        f.on_refused();
        assert_eq!(f.on_result(result(5)), FetchApply::Unasked, "nothing waits");
        f.tick(10_000 + REFUSAL_BACKOFF_MS - 1);
        assert_eq!(f.on_heads(&head(5), &head(3)), None);
        assert_eq!(f.dump()["backoff"], true);
        f.tick(10_000 + REFUSAL_BACKOFF_MS);
        assert_eq!(f.on_heads(&head(5), &head(3)), fetch(3));
        assert_eq!(f.dump()["backoff"], false);

        f.on_refused();
        let mut next_link = DeviceListFetch::default();
        next_link.tick(10_000 + REFUSAL_BACKOFF_MS);
        assert_eq!(next_link.on_heads(&head(5), &head(3)), fetch(3));
    }

    /// Decision 21's drop, or a lost answer: the fetch is sent again after
    /// 30 s; one that couldn't be handed to the link isn't in flight.
    #[test]
    fn an_unanswered_fetch_is_sent_again() {
        let mut f = DeviceListFetch::default();
        f.tick(1_000);
        assert_eq!(f.on_heads(&head(5), &head(3)), fetch(3));
        assert_eq!(f.tick(1_000 + FETCH_TIMEOUT_MS - 1), None);
        assert_eq!(f.tick(1_000 + FETCH_TIMEOUT_MS), fetch(3));
        assert_eq!(f.tick(1_000 + FETCH_TIMEOUT_MS + 1), None);
        f.unsent();
        assert_eq!(f.dump()["in_flight"], Value::Null);
        assert_eq!(f.on_heads(&head(5), &head(3)), fetch(3));
    }
}

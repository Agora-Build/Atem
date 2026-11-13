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
//! - **Again while behind.** After a result's carriage that moved the
//!   head, the host fetches again at once from its new head while that is
//!   behind the Station's last named head: real entries bound it (a list
//!   holds at most 1,024).
//! - **Paced at a `heads`.** A carriage is a durable write, so a Station
//!   gets no more of them than any carrier: the fetches a `heads` starts
//!   are at most one every [`HEADS_PACE_MS`] (a channel's init's pace), and
//!   none for [`STALL_PAUSE_MS`] after a result whose carriage moved
//!   nothing (a deferred, conflicting or junk carriage). So `heads` and
//!   results in a burst carry at most once.
//! - **A refusal** (`membership_fetch_refused`, step 4's Decision 20)
//!   advances nothing (no head, nothing applied) and is never taken as an
//!   answer: it ends the host's own wait on the link (no fetch is in flight
//!   any more, so a result arriving after it is one nobody asked for), and
//!   the host fetches again only at a `heads` at least
//!   [`REFUSAL_BACKOFF_MS`] later on its monotonic clock, or on the next
//!   link generation ([`DeviceListFetch::next_generation`]).
//! - **A new link generation** starts with nothing in flight, no named
//!   head and no refusal's backoff, but keeps the pacing: a Station that
//!   forces new generations (a dropped socket, a re-authentication) gets
//!   no more fetches than at a `heads`.
//! - **A fetch with no answer** for [`FETCH_TIMEOUT_MS`] (lost, or its
//!   result over 256 KiB, dropped unread: Decision 21) is sent again, from
//!   the list's head then; not once another carrier (a phone's channel)
//!   brought the list to the named head.
//! - **A stop at a deferred entry** (design I.4.3, "Deferred entries";
//!   R9.5): a result whose carriage stopped at an entry the list defers
//!   (signed by the subject of a recovery still pending on this host)
//!   fetches nothing more, since nothing past it applies until the wait
//!   ends; the stop is kept with the head announced then ([`Stopped`]).
//!   While the list still defers that entry, a `heads` naming that same head
//!   isn't "behind" (no fetch, so no carriage written again for nothing); a
//!   head announced anew is fetched as any, paced. When the deferral ends
//!   (the wait ended on this host, an approval, a veto, a carriage past it)
//!   the host fetches again at once, with no `heads`: the entry is carried
//!   again after the wait (R9.5). One that ends during a refusal's backoff
//!   is fetched when the backoff ends, still with no `heads` (Astation,
//!   #164: the fetch resumes when its deferred entry clears, the existing
//!   backoffs applying); one that ends with a fetch in flight needs none.
//!
//! **The gate's device-list part** ([`ListPart`], design I.5.8): fetched up
//! to the head the Station announced last on this link generation (the last
//! `heads`' `membership`, never a result's `head`, which may be lower), or
//! up to a deferred entry. "Up to the head" is the list holding that very
//! entry, `(seq, hash)`: a list with another entry at that `seq` differs from
//! the Station's (a fork, or a Station's word that names nothing), so the
//! gate stays closed (fail closed) until they agree. The fetch itself still
//! goes by `seq`: `membership_fetch{after}` returns a suffix, so a list that
//! holds the `seq` has nothing to ask; a fork reaches the host with a
//! carrier's window (R9.3) and the conflict rule (R9.4).
//!
//! The clock is the host's monotonic clock, given at every pass
//! ([`DeviceListFetch::tick`]).
use atem_client::SignedObject;
use atem_client::control::{MembershipFetch, MembershipFetchResult};
use atem_client::membership::{Head, Membership};
use serde_json::{Value, json};

/// After a refusal, no fetch at a `heads` before this long (Decision 20).
pub const REFUSAL_BACKOFF_MS: u64 = 30_000;
/// A fetch unanswered this long is sent again.
pub const FETCH_TIMEOUT_MS: u64 = 30_000;
/// The fetches a `heads` starts: at most one this often (I1).
pub const HEADS_PACE_MS: u64 = 1_000;
/// After a result whose carriage moved nothing, no fetch at a `heads` for
/// this long (I1).
pub const STALL_PAUSE_MS: u64 = 30_000;

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

/// Where the host's fetch stopped at a deferred entry (design I.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped {
    /// The deferred entry's `seq`.
    pub seq: u64,
    /// The head the Station had announced when the fetch stopped there.
    pub announced: Head,
}

/// What the revocation gate reads of the fetch on the link (design I.5.8:
/// "fetched the device list up to its head, or up to a deferred entry").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListPart {
    /// The head the Station announced last on this link generation.
    pub announced: Option<Head>,
    /// Where the fetch stopped at a deferred entry, if it did.
    pub stopped: Option<Stopped>,
}

impl ListPart {
    /// The gate's device-list part, against the list as it committed
    /// (`deferred`: the `seq` of the entry its deferral stops at): the list
    /// holds the announced head's own entry, `(seq, hash)`; or the fetch
    /// stopped, under that same announced head, at the deferred entry the
    /// list still defers. Nothing announced: no.
    pub fn holds(&self, list: &Membership, deferred: Option<u64>) -> bool {
        let Some(announced) = self.announced else {
            return false;
        };
        if list
            .entry(announced.seq)
            .is_some_and(|entry| entry.hash() == announced.hash)
        {
            return true;
        }
        self.stopped
            .is_some_and(|stop| stop.announced == announced && deferred == Some(stop.seq))
    }
}

/// The fetch on one link generation (the module docs give the rules).
#[derive(Debug, Clone, Default)]
pub struct DeviceListFetch {
    /// The host's monotonic clock at the last tick (ms).
    now: u64,
    /// The head the Station named last (`heads`, or a result's): its word,
    /// not signed authority (I.5.8).
    named: Option<Head>,
    /// The head the last `heads` announced (never a result's): the gate's.
    announced: Option<Head>,
    /// Where a fetch stopped at a deferred entry, kept while it may hold.
    stopped: Option<Stopped>,
    /// Its deferral ended with no fetch in flight: fetch again as soon as
    /// nothing holds it (a refusal's backoff), with no `heads`.
    resume: bool,
    in_flight: Option<InFlight>,
    /// The last refusal (monotonic ms).
    refused_at: Option<u64>,
    /// The last fetch a `heads` started (monotonic ms).
    heads_fetch_at: Option<u64>,
    /// The last result whose carriage moved nothing (monotonic ms).
    stalled_at: Option<u64>,
    /// Results taken.
    results: u64,
}

impl DeviceListFetch {
    /// The Station announced the device list's head `membership`; the
    /// host's list is at `applied`, its deferral (if any) at `deferred`
    /// (the deferred entry's `seq`). The fetch to send, if any.
    pub fn on_heads(
        &mut self,
        membership: &Head,
        applied: &Head,
        deferred: Option<u64>,
    ) -> Option<MembershipFetch> {
        self.named = Some(*membership);
        self.announced = Some(*membership);
        self.settle_stop(deferred);
        if self.in_flight.is_some() {
            return None;
        }
        if let Some(at) = self.refused_at {
            if self.now < at.saturating_add(REFUSAL_BACKOFF_MS) {
                return None;
            }
            self.refused_at = None;
        }
        // Not behind while its deferral holds: the head it stopped under
        // brings nothing that applies before the wait ends.
        if self
            .stopped
            .is_some_and(|stop| stop.announced == *membership)
        {
            return None;
        }
        let within =
            |at: Option<u64>, ms: u64| at.is_some_and(|at| self.now < at.saturating_add(ms));
        if within(self.heads_fetch_at, HEADS_PACE_MS) || within(self.stalled_at, STALL_PAUSE_MS) {
            return None;
        }
        let call = self.ask(applied)?;
        self.heads_fetch_at = Some(self.now);
        Some(call)
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
    /// to `after`, the carriage stopping at the deferred entry `stopped_at`
    /// (its `seq`) if it did: the next fetch while still behind, if it moved
    /// and stopped at no deferred entry (nothing past one applies before
    /// its wait ends: the stop is kept instead); if it moved nothing, a
    /// pause for the fetches a `heads` starts.
    pub fn carried(
        &mut self,
        before: &Head,
        after: &Head,
        stopped_at: Option<u64>,
    ) -> Option<MembershipFetch> {
        if after.seq <= before.seq {
            self.stalled_at = Some(self.now);
        }
        if let Some(seq) = stopped_at {
            self.stopped = self.announced.map(|announced| Stopped { seq, announced });
            return None;
        }
        if after.seq <= before.seq {
            return None;
        }
        self.ask(after)
    }

    /// `membership_fetch_refused`: nothing advances, and it answers
    /// nothing: the host's own wait ends; no fetch at a `heads` before the
    /// backoff.
    pub fn on_refused(&mut self) {
        self.in_flight = None;
        self.refused_at = Some(self.now);
    }

    /// The pass's monotonic time, the list's head (`None`: no list) and its
    /// deferral (`deferred`, the deferred entry's `seq`): when the deferral
    /// a fetch stopped at ended, the fetch from the list's head, at once
    /// (none while one is in flight or a refusal's backoff runs); a fetch
    /// unanswered too long, sent again from the list's head; none once the
    /// list reached the named head through another carrier.
    pub fn tick(
        &mut self,
        now_mono: u64,
        applied: Option<&Head>,
        deferred: Option<u64>,
    ) -> Option<MembershipFetch> {
        self.now = now_mono;
        self.settle_stop(deferred);
        if self.resume
            && self.in_flight.is_none()
            && self
                .refused_at
                .is_none_or(|at| now_mono >= at.saturating_add(REFUSAL_BACKOFF_MS))
            && let Some(applied) = applied
        {
            self.resume = false;
            return self.ask(applied);
        }
        let in_flight = self.in_flight?;
        if self
            .named
            .zip(applied)
            .is_some_and(|(named, applied)| applied.seq >= named.seq)
        {
            self.in_flight = None;
            return None;
        }
        if now_mono < in_flight.sent_at.saturating_add(FETCH_TIMEOUT_MS) {
            return None;
        }
        let after = applied.map_or(in_flight.after, |h| h.seq.max(in_flight.after));
        self.in_flight = Some(InFlight {
            after,
            sent_at: now_mono,
        });
        Some(MembershipFetch { after })
    }

    /// The fetch just asked for couldn't be handed to the link: none in
    /// flight (the next `heads` asks again).
    pub fn unsent(&mut self) {
        self.in_flight = None;
    }

    /// The fetch on the link's next generation (a new link, or none): nothing
    /// in flight, no head named or announced, no stop at a deferred entry
    /// and no refusal's backoff (Decision 20), but the pacing of the fetches
    /// a `heads` starts carries over, so a new generation buys a Station no
    /// carriage (Task 30 re-review N1). The clock and the count of results
    /// go on too.
    pub fn next_generation(&self) -> DeviceListFetch {
        DeviceListFetch {
            now: self.now,
            heads_fetch_at: self.heads_fetch_at,
            stalled_at: self.stalled_at,
            results: self.results,
            ..DeviceListFetch::default()
        }
    }

    /// What the revocation gate reads of the fetch (design I.5.8).
    pub fn part(&self) -> ListPart {
        ListPart {
            announced: self.announced,
            stopped: self.stopped,
        }
    }

    /// For the state dump.
    pub fn dump(&self) -> Value {
        json!({
            "named": self.named.map(|h| h.seq),
            "announced": self.announced.map(|h| h.seq),
            "stopped": self.stopped.map(|s| s.seq),
            "in_flight": self.in_flight.map(|f| f.after),
            "backoff": self.refused_at.is_some(),
            "results": self.results,
        })
    }

    /// The stop at a deferred entry is dropped once the list no longer
    /// defers that entry (`deferred`: the list's deferral now); the fetch
    /// resumes then, unless one is in flight (it carries the entry).
    fn settle_stop(&mut self, deferred: Option<u64>) {
        if self.stopped.is_some_and(|stop| deferred != Some(stop.seq)) {
            self.stopped = None;
            self.resume = self.in_flight.is_none();
        }
    }

    fn ask(&mut self, applied: &Head) -> Option<MembershipFetch> {
        let named = self.named?;
        if named.seq <= applied.seq {
            return None;
        }
        self.resume = false;
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
        f.tick(1_000, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(3), &head(3), None), None);
        assert_eq!(f.on_heads(&head(2), &head(3), None), None);
        assert_eq!(f.on_heads(&head(5), &head(3), None), fetch(3));
        assert_eq!(f.on_heads(&head(6), &head(3), None), None, "one at a time");
    }

    /// A result is taken only for a fetch in flight.
    #[test]
    fn a_result_nobody_asked_for_is_not_applied() {
        let mut f = DeviceListFetch::default();
        assert_eq!(f.on_result(result(5)), FetchApply::Unasked);
        f.on_heads(&head(5), &head(3), None);
        assert_eq!(f.on_result(result(5)), FetchApply::Carry(Vec::new()));
        assert_eq!(f.on_result(result(5)), FetchApply::Unasked, "taken once");
    }

    /// R9.3's 64-entry carriage: after a carriage that moved the head, the
    /// host fetches again at once while behind the named head (real
    /// entries bound it: a list holds at most 1,024).
    #[test]
    fn fetch_again_while_behind_the_announced_head() {
        let mut f = DeviceListFetch::default();
        f.tick(1_000, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(200), &head(3), None), fetch(3));
        assert!(matches!(f.on_result(result(200)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(3), &head(67), None), fetch(67));
        assert!(matches!(f.on_result(result(200)), FetchApply::Carry(_)));
        assert_eq!(
            f.carried(&head(67), &head(131), None),
            fetch(131),
            "not paced"
        );
        assert!(matches!(f.on_result(result(200)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(131), &head(200), None), None, "caught up");
    }

    /// I1: the fetches a `heads` starts are paced on the host's clock: at
    /// most one a second, and none within 30 s of a result whose carriage
    /// moved nothing (a deferred, conflicting or junk carriage), so a
    /// Station can't make the host write a carriage per message.
    #[test]
    fn fetches_a_heads_starts_are_paced() {
        let mut f = DeviceListFetch::default();
        f.tick(10_000, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(9), &head(3), None), fetch(3));
        assert!(matches!(f.on_result(result(9)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(3), &head(5), None), fetch(5), "not paced");
        assert!(matches!(f.on_result(result(9)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(5), &head(9), None), None, "caught up");
        // A heads within a second of the last a heads started: nothing.
        f.tick(10_999, Some(&head(9)), None);
        assert_eq!(f.on_heads(&head(12), &head(9), None), None);
        f.tick(11_000, Some(&head(9)), None);
        assert_eq!(f.on_heads(&head(12), &head(9), None), fetch(9));
        // Its carriage moved nothing: no fetch at a heads for 30 s.
        assert!(matches!(f.on_result(result(12)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(9), &head(9), None), None);
        f.tick(11_000 + STALL_PAUSE_MS - 1, Some(&head(9)), None);
        assert_eq!(f.on_heads(&head(12), &head(9), None), None);
        f.tick(11_000 + STALL_PAUSE_MS, Some(&head(9)), None);
        assert_eq!(f.on_heads(&head(12), &head(9), None), fetch(9));
    }

    /// I1: many `heads` and junk results in one pass (the host's clock
    /// still): at most one carriage.
    #[test]
    fn heads_and_junk_results_in_one_pass_carry_at_most_once() {
        let mut f = DeviceListFetch::default();
        f.tick(10_000, Some(&head(3)), None);
        let mut carriages = 0;
        for _ in 0..32 {
            f.on_heads(&head(9), &head(3), None);
            if let FetchApply::Carry(_) = f.on_result(result(9)) {
                carriages += 1;
                f.carried(&head(3), &head(3), None);
            }
        }
        assert_eq!(carriages, 1);
    }

    /// Decision 20: a refusal advances nothing and ends the host's own
    /// wait (never taken as an answer); a `heads` within 30 s fetches
    /// nothing, one 30 s later does; a new link generation (a new fetch)
    /// has no backoff.
    #[test]
    fn fetch_refused_advances_nothing_and_retries() {
        let mut f = DeviceListFetch::default();
        f.tick(10_000, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(5), &head(3), None), fetch(3));
        f.on_refused();
        assert_eq!(f.on_result(result(5)), FetchApply::Unasked, "nothing waits");
        f.tick(10_000 + REFUSAL_BACKOFF_MS - 1, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(5), &head(3), None), None);
        assert_eq!(f.dump()["backoff"], true);
        f.tick(10_000 + REFUSAL_BACKOFF_MS, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(5), &head(3), None), fetch(3));
        assert_eq!(f.dump()["backoff"], false);

        // Refused again: the next link generation has no backoff, but keeps
        // the pacing (a second after the last fetch a heads started).
        f.on_refused();
        let mut next_link = f.next_generation();
        assert_eq!(next_link.dump()["backoff"], false);
        assert_eq!(next_link.on_heads(&head(5), &head(3), None), None, "paced");
        next_link.tick(
            10_000 + REFUSAL_BACKOFF_MS + HEADS_PACE_MS,
            Some(&head(3)),
            None,
        );
        assert_eq!(next_link.on_heads(&head(5), &head(3), None), fetch(3));
    }

    /// Decision 21's drop, or a lost answer: the fetch is sent again after
    /// 30 s, from the list's head then; not once another carrier brought
    /// the list to the named head; one that couldn't be handed to the link
    /// isn't in flight.
    #[test]
    fn an_unanswered_fetch_is_sent_again() {
        let mut f = DeviceListFetch::default();
        f.tick(1_000, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(5), &head(3), None), fetch(3));
        assert_eq!(
            f.tick(1_000 + FETCH_TIMEOUT_MS - 1, Some(&head(3)), None),
            None
        );
        assert_eq!(
            f.tick(1_000 + FETCH_TIMEOUT_MS, Some(&head(3)), None),
            fetch(3)
        );
        assert_eq!(
            f.tick(1_000 + FETCH_TIMEOUT_MS + 1, Some(&head(3)), None),
            None
        );
        // A phone's carriage moved the list meanwhile: from its head.
        assert_eq!(
            f.tick(1_000 + 2 * FETCH_TIMEOUT_MS, Some(&head(4)), None),
            fetch(4)
        );
        // And to the named head: nothing more to fetch, nothing in flight.
        assert_eq!(
            f.tick(1_000 + 3 * FETCH_TIMEOUT_MS, Some(&head(5)), None),
            None
        );
        assert_eq!(f.dump()["in_flight"], Value::Null);
        assert_eq!(f.on_heads(&head(6), &head(5), None), fetch(5));
        f.unsent();
        assert_eq!(f.dump()["in_flight"], Value::Null);
    }

    /// Design I.4.3, R9.5: a carriage that stops at a deferred entry
    /// fetches nothing more (nothing past it applies until its wait ends);
    /// while the list still defers it, the head the Station announced then
    /// isn't "behind" (no fetch at its `heads`, past every pace), a head it
    /// announces anew is fetched as any; when the deferral ends, the entry
    /// is fetched again at once, with no `heads`. The next link generation
    /// starts with no stop and nothing announced.
    #[test]
    fn a_stop_at_a_deferred_entry_holds_the_fetch_until_its_deferral_ends() {
        let mut f = DeviceListFetch::default();
        f.tick(10_000, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(9), &head(3), None), fetch(3));
        assert!(matches!(f.on_result(result(9)), FetchApply::Carry(_)));
        // 4 and 5 applied, 6 deferred: no fetch again.
        assert_eq!(f.carried(&head(3), &head(5), Some(6)), None);
        assert_eq!(f.dump()["stopped"], 6);
        assert_eq!(f.dump()["announced"], 9);
        assert_eq!(
            f.part(),
            ListPart {
                announced: Some(head(9)),
                stopped: Some(Stopped {
                    seq: 6,
                    announced: head(9)
                }),
            }
        );
        // The same head again, past every pace, the deferral holding.
        let later = 10_000 + STALL_PAUSE_MS + HEADS_PACE_MS;
        assert_eq!(f.tick(later, Some(&head(5)), Some(6)), None);
        assert_eq!(f.on_heads(&head(9), &head(5), Some(6)), None);
        // A head announced anew: fetched (paced as any); stopped again at
        // the same entry, a stall, under the new head.
        assert_eq!(f.on_heads(&head(10), &head(5), Some(6)), fetch(5));
        assert!(matches!(f.on_result(result(10)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(5), &head(5), Some(6)), None);
        assert_eq!(f.part().stopped.map(|s| s.announced), Some(head(10)));
        f.tick(later + STALL_PAUSE_MS, Some(&head(5)), Some(6));
        assert_eq!(f.on_heads(&head(10), &head(5), Some(6)), None);
        // The deferral ends (the wait ended on this host): fetched again at
        // once, though paced at a heads.
        assert_eq!(
            f.tick(later + STALL_PAUSE_MS + 1, Some(&head(5)), None),
            fetch(5)
        );
        assert_eq!(f.dump()["stopped"], Value::Null);
        assert_eq!(f.part().announced, Some(head(10)));
        // The next link generation: nothing announced, no stop.
        assert_eq!(f.next_generation().part(), ListPart::default());
    }

    /// Astation (#164, item 2: the fetch resumes as soon as its deferred
    /// entry clears, with no `heads`; the existing pacing and backoffs
    /// apply): a deferral that clears during a refusal's backoff resumes
    /// the fetch when the backoff ends, still with no `heads`, once.
    #[test]
    fn a_deferral_that_clears_in_a_refusals_backoff_resumes_after_it() {
        let mut f = DeviceListFetch::default();
        f.tick(1_000, Some(&head(3)), None);
        assert_eq!(f.on_heads(&head(9), &head(3), None), fetch(3));
        assert!(matches!(f.on_result(result(9)), FetchApply::Carry(_)));
        assert_eq!(f.carried(&head(3), &head(5), Some(6)), None);
        // A head announced anew while it defers: fetched, then refused.
        f.tick(2_000, Some(&head(5)), Some(6));
        assert_eq!(f.on_heads(&head(10), &head(5), Some(6)), fetch(5));
        f.on_refused();
        // The deferral clears in the backoff: nothing yet.
        assert_eq!(f.tick(3_000, Some(&head(5)), None), None, "backing off");
        let end = 2_000 + REFUSAL_BACKOFF_MS;
        assert_eq!(f.tick(end - 1, Some(&head(5)), None), None);
        // The backoff over: resumed at once, no heads.
        assert_eq!(f.tick(end, Some(&head(5)), None), fetch(5));
        assert_eq!(f.tick(end + 1, Some(&head(5)), None), None, "once");
        assert_eq!(f.dump()["in_flight"], 5);
    }

    /// A stop whose deferral ended while a fetch was refused waits out the
    /// refusal's backoff; one whose deferral ends with a fetch in flight
    /// sends nothing more.
    #[test]
    fn a_deferral_that_ends_fetches_only_when_nothing_holds_it() {
        let mut f = DeviceListFetch::default();
        f.tick(1_000, Some(&head(3)), None);
        f.on_heads(&head(9), &head(3), None);
        f.on_result(result(9));
        f.carried(&head(3), &head(5), Some(6));
        f.on_refused();
        assert_eq!(f.tick(2_000, Some(&head(5)), None), None, "backing off");
        assert_eq!(f.dump()["stopped"], Value::Null);

        let mut f = DeviceListFetch::default();
        f.tick(1_000, Some(&head(3)), None);
        f.on_heads(&head(9), &head(3), None);
        f.on_result(result(9));
        f.carried(&head(3), &head(5), Some(6));
        f.tick(5_000, Some(&head(5)), Some(6));
        assert_eq!(f.on_heads(&head(10), &head(5), Some(6)), fetch(5));
        assert_eq!(f.tick(5_001, Some(&head(5)), None), None, "one at a time");
        assert_eq!(f.dump()["in_flight"], 5);
    }
}

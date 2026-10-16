//! Client-side state machines for atem-session v1: the control-lease client
//! (§5 reply-correlation rules 1–5) and the session registry client (§4),
//! which also keeps the pending approvals (r7) of the processes it holds.
//!
//! Both are pure: the caller passes a monotonic `now_ms` with every event and
//! performs any I/O they ask for (`RegistryClient::take_list_request`).
//! Neither relies on a timer having fired: every query and every reply checks
//! `now >= deadline` itself.

use super::wire::{ApprovalRequest, Binding, Descriptor, Op, SessionMessage, SessionState, Target};
use std::collections::{BTreeMap, HashMap};

// ── Control lease (§5) ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRequest {
    Acquire,
    Renew,
    Release,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    kind: LeaseRequest,
    sent_at: u64,
}

/// Why a request was not recorded (the caller must not send it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRefused {
    /// `renew`/`release` without control (never renew after the local estimate
    /// of expiry; nothing to release).
    NotControlling,
    /// The id is already outstanding.
    DuplicateId,
    /// More than `MAX_IN_FLIGHT` requests outstanding.
    TooManyInFlight,
}

/// What happened to a host reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// The reply changed the lease state (granted, renewed, released, or an
    /// error that made this client a viewer).
    Applied,
    /// The reply was applied but the resulting deadline had already been
    /// reached, so control and input are off (rule 5).
    AppliedExpired,
    /// Rule 1: `re` is absent, unknown, already consumed or a duplicate.
    UnknownRe,
    /// Rule 2: the previously acknowledged deadline had passed; this client is
    /// now a viewer and only a new `acquire` regains control.
    DeadlinePassed,
    /// The reply doesn't fit the request (other target/attachment, wrong op,
    /// or a renew answered for another epoch — which also ends control).
    Mismatch,
    /// The granted epoch is older than one already seen in `lease_changed`.
    StaleEpoch,
    /// Not a lease reply (`lease`, `lease_released` or `error`).
    NotALeaseReply,
}

/// One client's view of its control lease on one session.
#[derive(Debug, Clone)]
pub struct LeaseClient {
    target: Target,
    attachment_gen: String,
    outstanding: HashMap<String, Pending>,
    /// Acknowledged local deadline (monotonic ms); `Some` while controlling.
    deadline: Option<u64>,
    lease_epoch: Option<u64>,
    /// Highest `lease_epoch` seen for this target (grants and
    /// `lease_changed`), kept while a viewer; older grants are dropped.
    highest_epoch_seen: Option<u64>,
    authorization_deadline: Option<u64>,
}

// ── Session registry (§4) ─────────────────────────────────────────────────

/// What happened to a `sessions` / `session_changed` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryOutcome {
    Applied,
    /// From a lower `runtime_epoch` than the highest accepted one.
    StaleEpoch,
    /// Same epoch as the accepted one with another `runtime_gen`.
    RuntimeGenMismatch,
    /// A snapshot older than the last applied state of this epoch.
    StaleSnapshot,
    /// `seq` ≤ the last applied one.
    Duplicate,
    /// Held until the awaited snapshot arrives (discarded then if its `seq` is
    /// ≤ the snapshot's).
    Buffered,
    /// A change that would revive a removed session's `process_gen`.
    Resurrection,
    /// An approval for a session or process the registry doesn't hold, or a
    /// close of an approval it doesn't know.
    Ignored,
    /// Not a registry message.
    NotARegistryMessage,
}

/// Bound on changes held while awaiting a snapshot; beyond it they're dropped
/// (the snapshot carries the full state anyway).
pub const MAX_BUFFERED_CHANGES: usize = 256;

#[derive(Debug, Clone, Default)]
pub struct RegistryClient {
    /// Highest accepted `(runtime_epoch, runtime_gen)`.
    epoch: Option<(u64, String)>,
    /// Last applied `seq` in the accepted epoch; `None` until its snapshot.
    last_seq: Option<u64>,
    /// A `list` was sent (or must be) and its snapshot hasn't arrived.
    awaiting_snapshot: bool,
    list_wanted: bool,
    lists_requested: u64,
    sessions: BTreeMap<String, Descriptor>,
    /// session_id → (seq of the removal, removed process_gen), per epoch.
    removed: HashMap<String, (u64, String)>,
    buffered: BTreeMap<u64, Descriptor>,
    /// approval_id → pending approval of a session process held here.
    approvals: BTreeMap<String, ApprovalRequest>,
}

impl LeaseClient {
    pub fn new(target: Target, attachment_gen: String) -> Self {
        Self {
            target,
            attachment_gen,
            outstanding: HashMap::new(),
            deadline: None,
            lease_epoch: None,
            highest_epoch_seen: None,
            authorization_deadline: None,
        }
    }

    /// The attachment's authorization deadline on the monotonic clock (from
    /// `welcome.authorization_ms_left`); every lease deadline is capped by it.
    pub fn set_authorization_deadline(&mut self, deadline: Option<u64>) {
        self.authorization_deadline = deadline;
        if let (Some(d), Some(a)) = (self.deadline, deadline) {
            self.deadline = Some(d.min(a));
        }
    }

    /// Records an outgoing `acquire`/`renew`/`release` with its monotonic send
    /// time. Call before sending; an `Err` means don't send it.
    pub fn sent(
        &mut self,
        id: &str,
        kind: LeaseRequest,
        now_ms: u64,
    ) -> Result<(), RequestRefused> {
        self.tick(now_ms);
        if self.outstanding.contains_key(id) {
            return Err(RequestRefused::DuplicateId);
        }
        if self.outstanding.len() >= super::wire::MAX_IN_FLIGHT {
            return Err(RequestRefused::TooManyInFlight);
        }
        match kind {
            LeaseRequest::Acquire => {}
            LeaseRequest::Renew | LeaseRequest::Release if self.deadline.is_none() => {
                return Err(RequestRefused::NotControlling);
            }
            LeaseRequest::Renew => {}
            // Input stops as soon as a release is sent, and no earlier
            // acquire/renew reply may grant control again.
            LeaseRequest::Release => self.become_viewer(),
        }
        self.outstanding.insert(
            id.to_string(),
            Pending {
                kind,
                sent_at: now_ms,
            },
        );
        Ok(())
    }

    /// Applies a host reply (`lease`, `lease_released` or `error`) per §5
    /// rules 1–5.
    pub fn on_reply(&mut self, msg: &SessionMessage, now_ms: u64) -> ReplyOutcome {
        if !matches!(
            msg.op,
            Op::Lease { .. } | Op::LeaseReleased {} | Op::Error { .. }
        ) {
            return ReplyOutcome::NotALeaseReply;
        }
        // Rule 1: one reply per outstanding request.
        let Some(pending) = msg.re.as_ref().and_then(|re| self.outstanding.remove(re)) else {
            return ReplyOutcome::UnknownRe;
        };
        // Rule 2: the acknowledged deadline is checked before anything is applied.
        if self.deadline.is_some_and(|d| now_ms >= d) {
            self.become_viewer();
            return ReplyOutcome::DeadlinePassed;
        }
        match &msg.op {
            Op::Lease { binding, ms_left } => self.apply_lease(pending, binding, *ms_left, now_ms),
            Op::LeaseReleased {} if pending.kind == LeaseRequest::Release => {
                self.become_viewer();
                ReplyOutcome::Applied
            }
            Op::LeaseReleased {} => ReplyOutcome::Mismatch,
            // Any error to a lease request leaves this client without a lease
            // (fail closed: the host's state is unknown).
            _ => {
                self.become_viewer();
                ReplyOutcome::Applied
            }
        }
    }

    fn apply_lease(
        &mut self,
        pending: Pending,
        binding: &Binding,
        ms_left: u64,
        now_ms: u64,
    ) -> ReplyOutcome {
        let Some(epoch) = binding.lease_epoch else {
            return ReplyOutcome::Mismatch;
        };
        if binding.target != self.target || binding.attachment_gen != self.attachment_gen {
            return ReplyOutcome::Mismatch;
        }
        if self.highest_epoch_seen.is_some_and(|h| epoch < h) {
            return ReplyOutcome::StaleEpoch;
        }
        // Rule 3: send time + ms_left, capped by authorization.
        let mut candidate = pending.sent_at.saturating_add(ms_left);
        if let Some(a) = self.authorization_deadline {
            candidate = candidate.min(a);
        }
        let new = match (pending.kind, self.deadline) {
            (LeaseRequest::Release, _) => return ReplyOutcome::Mismatch,
            (LeaseRequest::Renew, None) => return ReplyOutcome::Mismatch,
            (LeaseRequest::Renew, Some(_)) if self.lease_epoch != Some(epoch) => {
                // Fail closed: the host's lease isn't the one this client holds.
                self.become_viewer();
                return ReplyOutcome::Mismatch;
            }
            (LeaseRequest::Renew, Some(_)) => candidate,
            // Rule 4: a repeat acquire never extends.
            (LeaseRequest::Acquire, Some(prev)) => prev.min(candidate),
            (LeaseRequest::Acquire, None) => candidate,
        };
        // Rule 5: never hold control with zero remaining lifetime.
        if now_ms >= new {
            self.become_viewer();
            return ReplyOutcome::AppliedExpired;
        }
        self.deadline = Some(new);
        self.lease_epoch = Some(epoch);
        self.highest_epoch_seen = Some(self.highest_epoch_seen.map_or(epoch, |h| h.max(epoch)));
        ReplyOutcome::Applied
    }

    /// `lease_changed` for this target: a newer epoch than ours means the
    /// lease moved, expired, was released or revoked.
    pub fn on_lease_changed(&mut self, session_id: &str, process_gen: &str, lease_epoch: u64) {
        if session_id != self.target.session_id || process_gen != self.target.process_gen {
            return;
        }
        self.highest_epoch_seen = Some(
            self.highest_epoch_seen
                .map_or(lease_epoch, |h| h.max(lease_epoch)),
        );
        if self.lease_epoch.is_some_and(|e| lease_epoch > e) {
            self.become_viewer();
        }
    }

    /// Notices expiry (`now >= deadline`); replies to requests sent before it
    /// are then dropped.
    pub fn tick(&mut self, now_ms: u64) {
        if self.deadline.is_some_and(|d| now_ms >= d) {
            self.become_viewer();
        }
    }

    fn become_viewer(&mut self) {
        self.deadline = None;
        self.lease_epoch = None;
        self.outstanding.clear();
    }

    pub fn controls(&self, now_ms: u64) -> bool {
        self.deadline.is_some_and(|d| now_ms < d)
    }

    pub fn input_enabled(&self, now_ms: u64) -> bool {
        self.controls(now_ms)
    }

    /// The acknowledged local deadline (monotonic ms); `None` as a viewer or
    /// once `now >= deadline`.
    pub fn deadline_ms(&self, now_ms: u64) -> Option<u64> {
        self.deadline.filter(|d| now_ms < *d)
    }

    pub fn lease_epoch(&self) -> Option<u64> {
        self.lease_epoch
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn is_outstanding(&self, id: &str) -> bool {
        self.outstanding.contains_key(id)
    }
}

enum EpochCheck {
    Same,
    New,
    Reject(RegistryOutcome),
}

impl RegistryClient {
    /// The caller sent `list` (it subscribes the attachment): changes are held
    /// until the snapshot arrives.
    pub fn note_list_sent(&mut self) {
        self.awaiting_snapshot = true;
    }

    /// `true` once per needed `list` (gap, or a new epoch seen in a change);
    /// the caller sends it and calls `note_list_sent`.
    pub fn take_list_request(&mut self) -> bool {
        std::mem::take(&mut self.list_wanted)
    }

    pub fn lists_requested(&self) -> u64 {
        self.lists_requested
    }

    fn want_list(&mut self) {
        if !self.list_wanted {
            self.list_wanted = true;
            self.lists_requested += 1;
        }
        self.awaiting_snapshot = true;
    }

    fn check_epoch(&self, epoch: u64, rgen: &str) -> EpochCheck {
        match &self.epoch {
            None => EpochCheck::New,
            Some((e, _)) if epoch < *e => EpochCheck::Reject(RegistryOutcome::StaleEpoch),
            Some((e, g)) if epoch == *e && g != rgen => {
                EpochCheck::Reject(RegistryOutcome::RuntimeGenMismatch)
            }
            Some((e, _)) if epoch == *e => EpochCheck::Same,
            Some(_) => EpochCheck::New,
        }
    }

    /// A new attachment was welcomed (reconnect): `seq` counts per
    /// attachment, so its registry starts over — the next snapshot is
    /// awaited and applies at any `seq`. The highest accepted
    /// `(runtime_epoch, runtime_gen)` stays as the floor.
    pub fn new_attachment(&mut self) {
        self.last_seq = None;
        self.sessions.clear();
        self.approvals.clear();
        self.removed.clear();
        self.buffered.clear();
        self.list_wanted = false;
        self.awaiting_snapshot = false;
    }

    fn reset(&mut self, epoch: u64, rgen: &str) {
        self.epoch = Some((epoch, rgen.to_string()));
        self.last_seq = None;
        self.sessions.clear();
        self.approvals.clear();
        self.removed.clear();
        self.buffered.clear();
        self.list_wanted = false;
    }

    pub fn on_message(&mut self, op: &Op) -> RegistryOutcome {
        match op {
            Op::Sessions {
                runtime_gen,
                runtime_epoch,
                seq,
                sessions,
            } => self.on_snapshot(runtime_gen, *runtime_epoch, *seq, sessions),
            Op::SessionChanged {
                runtime_gen,
                runtime_epoch,
                seq,
                descriptor,
            } => self.on_change(runtime_gen, *runtime_epoch, *seq, descriptor),
            // Pending approvals follow the snapshot (`list`) and arrive live;
            // they're kept only for a process the registry holds.
            Op::ApprovalRequest(r) => {
                let held = self.sessions.get(&r.session_id).is_some_and(|d| {
                    d.process_gen == r.process_gen && d.state == SessionState::Running
                });
                if !held {
                    return RegistryOutcome::Ignored;
                }
                self.approvals.insert(r.approval_id.clone(), r.clone());
                RegistryOutcome::Applied
            }
            Op::ApprovalClosed { approval_id, .. } => match self.approvals.remove(approval_id) {
                Some(_) => RegistryOutcome::Applied,
                None => RegistryOutcome::Ignored,
            },
            _ => RegistryOutcome::NotARegistryMessage,
        }
    }

    fn on_snapshot(
        &mut self,
        rgen: &str,
        epoch: u64,
        seq: u64,
        sessions: &[Descriptor],
    ) -> RegistryOutcome {
        match self.check_epoch(epoch, rgen) {
            EpochCheck::Reject(r) => return r,
            EpochCheck::New => self.reset(epoch, rgen),
            EpochCheck::Same => {
                if self.last_seq.is_some_and(|l| seq < l) {
                    return RegistryOutcome::StaleSnapshot;
                }
            }
        }
        self.sessions.clear();
        for d in sessions {
            if d.state == SessionState::Removed {
                self.removed
                    .insert(d.session_id.clone(), (seq, d.process_gen.clone()));
            } else if !self.is_removed_process(&d.session_id, &d.process_gen) {
                self.sessions.insert(d.session_id.clone(), d.clone());
            }
        }
        self.last_seq = Some(seq);
        self.awaiting_snapshot = false;
        self.list_wanted = false;
        self.drop_stale_approvals();
        // Held changes: those at or below the snapshot are discarded, the rest
        // apply in order; one still ahead is a new gap.
        let held = std::mem::take(&mut self.buffered);
        for (s, d) in held.into_iter().filter(|(s, _)| *s > seq) {
            if !self.awaiting_snapshot && self.last_seq == Some(s - 1) {
                self.apply_change(s, &d);
            } else {
                if !self.awaiting_snapshot {
                    self.want_list();
                }
                self.buffered.insert(s, d);
            }
        }
        RegistryOutcome::Applied
    }

    fn on_change(&mut self, rgen: &str, epoch: u64, seq: u64, d: &Descriptor) -> RegistryOutcome {
        match self.check_epoch(epoch, rgen) {
            EpochCheck::Reject(r) => return r,
            EpochCheck::New => {
                // Accept the epoch, apply nothing from it until its snapshot.
                self.reset(epoch, rgen);
                self.want_list();
                self.buffer(seq, d);
                return RegistryOutcome::Buffered;
            }
            EpochCheck::Same => {}
        }
        if self.last_seq.is_some_and(|l| seq <= l) {
            return RegistryOutcome::Duplicate;
        }
        if self.awaiting_snapshot || self.last_seq.is_none() {
            self.buffer(seq, d);
            return RegistryOutcome::Buffered;
        }
        let last = self.last_seq.unwrap_or(0);
        if seq == last + 1 {
            self.apply_change(seq, d)
        } else {
            self.want_list();
            self.buffer(seq, d);
            RegistryOutcome::Buffered
        }
    }

    fn buffer(&mut self, seq: u64, d: &Descriptor) {
        if self.buffered.len() < MAX_BUFFERED_CHANGES {
            self.buffered.insert(seq, d.clone());
        }
    }

    fn is_removed_process(&self, session_id: &str, process_gen: &str) -> bool {
        self.removed
            .get(session_id)
            .is_some_and(|(_, pg)| pg == process_gen)
    }

    fn apply_change(&mut self, seq: u64, d: &Descriptor) -> RegistryOutcome {
        self.last_seq = Some(seq);
        if d.state == SessionState::Removed {
            self.sessions.remove(&d.session_id);
            self.removed
                .insert(d.session_id.clone(), (seq, d.process_gen.clone()));
            self.drop_stale_approvals();
            return RegistryOutcome::Applied;
        }
        if let Some((removed_at, pg)) = self.removed.get(&d.session_id) {
            if *pg == d.process_gen || seq <= *removed_at {
                return RegistryOutcome::Resurrection;
            }
            self.removed.remove(&d.session_id);
        }
        self.sessions.insert(d.session_id.clone(), d.clone());
        self.drop_stale_approvals();
        RegistryOutcome::Applied
    }

    /// Approvals of a session no longer held, or of an older process, go.
    fn drop_stale_approvals(&mut self) {
        let sessions = &self.sessions;
        self.approvals.retain(|_, a| {
            sessions
                .get(&a.session_id)
                .is_some_and(|d| d.process_gen == a.process_gen && d.state == SessionState::Running)
        });
    }

    /// Pending approvals, by `approval_id`.
    pub fn pending_approvals(&self) -> impl Iterator<Item = &ApprovalRequest> {
        self.approvals.values()
    }

    pub fn runtime_epoch(&self) -> Option<u64> {
        self.epoch.as_ref().map(|(e, _)| *e)
    }

    pub fn runtime_gen(&self) -> Option<&str> {
        self.epoch.as_ref().map(|(_, g)| g.as_str())
    }

    pub fn seq(&self) -> Option<u64> {
        self.last_seq
    }

    pub fn awaiting_snapshot(&self) -> bool {
        self.awaiting_snapshot
    }

    pub fn session(&self, session_id: &str) -> Option<&Descriptor> {
        self.sessions.get(session_id)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Descriptor> {
        self.sessions.values()
    }

    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_protocol::wire::{Activity, ErrorCode};

    const PG: &str = "22222222-2222-4222-8222-222222222222";
    const PG2: &str = "22222222-2222-4222-8222-222222222223";
    const AG: &str = "33333333-3333-4333-8333-333333333333";
    const RG7: &str = "77777777-7777-4777-8777-777777777777";
    const RG8: &str = "55555555-5555-4555-8555-555555555555";

    fn target() -> Target {
        Target {
            account_id: "account-a".into(),
            atem_device_id: "host-a".into(),
            host_trust_gen: 1,
            session_id: "ses-aaaaaaaaaaaa".into(),
            process_gen: PG.into(),
        }
    }

    fn id(n: u32) -> String {
        format!("11111111-1111-4111-8111-{n:012}")
    }

    fn lease(re: &str, epoch: u64, ms_left: u64) -> SessionMessage {
        SessionMessage {
            id: id(900),
            re: Some(re.into()),
            op: Op::Lease {
                binding: Binding {
                    target: target(),
                    attachment_gen: AG.into(),
                    lease_epoch: Some(epoch),
                },
                ms_left,
            },
        }
    }

    fn reply(re: &str, op: Op) -> SessionMessage {
        SessionMessage {
            id: id(901),
            re: Some(re.into()),
            op,
        }
    }

    fn client() -> LeaseClient {
        LeaseClient::new(target(), AG.into())
    }

    #[test]
    fn grant_sets_deadline_from_send_time_not_arrival() {
        let mut c = client();
        assert!(!c.controls(0));
        c.sent(&id(1), LeaseRequest::Acquire, 1_000).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(1), 1, 15_000), 1_400),
            ReplyOutcome::Applied
        );
        assert_eq!(c.deadline_ms(0), Some(16_000));
        assert_eq!(c.lease_epoch(), Some(1));
        assert!(c.controls(15_999) && c.input_enabled(15_999));
        assert!(
            !c.controls(16_000) && !c.input_enabled(16_000),
            "now >= deadline"
        );
    }

    #[test]
    fn each_request_consumes_one_reply_and_unknown_re_is_dropped() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(1), 1, 15_000), 0),
            ReplyOutcome::Applied
        );
        c.sent(&id(2), LeaseRequest::Renew, 5_000).unwrap();
        // Duplicate of the consumed acquire reply: dropped though the binding matches.
        assert_eq!(
            c.on_reply(&lease(&id(1), 1, 15_000), 6_000),
            ReplyOutcome::UnknownRe
        );
        assert_eq!(
            c.on_reply(&lease(&id(77), 1, 15_000), 6_000),
            ReplyOutcome::UnknownRe
        );
        let mut no_re = lease(&id(2), 1, 15_000);
        no_re.re = None;
        assert_eq!(c.on_reply(&no_re, 6_000), ReplyOutcome::UnknownRe);
        assert_eq!(c.deadline_ms(0), Some(15_000));
        assert_eq!(
            c.on_reply(&lease(&id(2), 1, 15_000), 6_000),
            ReplyOutcome::Applied
        );
        assert_eq!(c.deadline_ms(0), Some(20_000));
        assert_eq!(
            c.on_reply(&lease(&id(2), 1, 15_000), 6_000),
            ReplyOutcome::UnknownRe
        );
    }

    #[test]
    fn late_reply_after_deadline_is_dropped_without_a_timer() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Renew, 5_000).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(2), 1, 15_000), 15_000),
            ReplyOutcome::DeadlinePassed
        );
        assert!(!c.controls(15_000));
        assert_eq!(c.deadline_ms(0), None);
        assert_eq!(c.lease_epoch(), None);
        // Renew is refused without control.
        assert_eq!(
            c.sent(&id(3), LeaseRequest::Renew, 15_000),
            Err(RequestRefused::NotControlling)
        );
    }

    #[test]
    fn replies_to_requests_sent_before_expiry_never_regrant() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Renew, 5_000).unwrap();
        // Expiry noticed when sending a new acquire.
        c.sent(&id(3), LeaseRequest::Acquire, 16_000).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(2), 1, 15_000), 16_100),
            ReplyOutcome::UnknownRe
        );
        assert!(!c.controls(16_100));
        assert_eq!(
            c.on_reply(&lease(&id(3), 3, 15_000), 16_200),
            ReplyOutcome::Applied
        );
        assert_eq!(c.deadline_ms(0), Some(31_000));
        assert_eq!(c.lease_epoch(), Some(3));
    }

    #[test]
    fn expiry_noticed_by_tick_drops_outstanding() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Renew, 14_000).unwrap();
        c.tick(15_000);
        assert_eq!(c.deadline_ms(0), None);
        assert_eq!(
            c.on_reply(&lease(&id(2), 1, 15_000), 15_000),
            ReplyOutcome::UnknownRe
        );
    }

    #[test]
    fn repeat_acquire_never_extends() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Acquire, 1_000).unwrap();
        c.on_reply(&lease(&id(2), 1, 15_000), 1_000);
        assert_eq!(
            c.deadline_ms(0),
            Some(15_000),
            "min(previous, send + ms_left)"
        );
        c.sent(&id(3), LeaseRequest::Acquire, 2_000).unwrap();
        c.on_reply(&lease(&id(3), 1, 4_000), 2_500);
        assert_eq!(
            c.deadline_ms(0),
            Some(6_000),
            "a shorter remaining lifetime wins"
        );
        // Near expiry: the computed deadline is already reached on arrival.
        c.sent(&id(4), LeaseRequest::Acquire, 5_000).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(4), 1, 500), 5_500),
            ReplyOutcome::AppliedExpired
        );
        assert!(!c.controls(5_500) && !c.input_enabled(5_500));
        assert_eq!(c.deadline_ms(0), None);
    }

    #[test]
    fn renew_sets_send_time_plus_ms_left() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Renew, 5_000).unwrap();
        c.on_reply(&lease(&id(2), 1, 14_000), 9_000);
        assert_eq!(c.deadline_ms(0), Some(19_000));
    }

    #[test]
    fn authorization_deadline_caps() {
        let mut c = client();
        c.set_authorization_deadline(Some(10_000));
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        assert_eq!(c.deadline_ms(0), Some(10_000));
        c.set_authorization_deadline(Some(8_000));
        assert_eq!(
            c.deadline_ms(0),
            Some(8_000),
            "a shorter authorization caps at once"
        );
        c.sent(&id(2), LeaseRequest::Renew, 7_000).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(2), 1, 15_000), 7_000),
            ReplyOutcome::Applied
        );
        assert_eq!(c.deadline_ms(0), Some(8_000));
    }

    #[test]
    fn mismatched_replies_are_dropped() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        let mut other = lease(&id(1), 1, 15_000);
        if let Op::Lease { binding, .. } = &mut other.op {
            binding.target.process_gen = PG2.into();
        }
        assert_eq!(c.on_reply(&other, 0), ReplyOutcome::Mismatch);
        assert!(!c.controls(0));
        // The request was consumed by the mismatching reply.
        assert_eq!(
            c.on_reply(&lease(&id(1), 1, 15_000), 0),
            ReplyOutcome::UnknownRe
        );
        let not_reply = reply(&id(1), Op::List {});
        assert_eq!(c.on_reply(&not_reply, 0), ReplyOutcome::NotALeaseReply);
    }

    #[test]
    fn errors_releases_and_lease_changes_make_a_viewer() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Renew, 5_000).unwrap();
        let err = Op::Error {
            code: ErrorCode::StaleLease,
            detail: None,
        };
        assert_eq!(
            c.on_reply(&reply(&id(2), err), 5_100),
            ReplyOutcome::Applied
        );
        assert!(!c.controls(5_100));

        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 4, 15_000), 0);
        // A grant notice for our own epoch keeps control; a newer epoch revokes it.
        c.on_lease_changed(&target().session_id, PG, 4);
        assert!(c.controls(1));
        c.on_lease_changed(&target().session_id, PG, 5);
        assert!(!c.controls(1));

        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Renew, 1_000).unwrap();
        c.sent(&id(3), LeaseRequest::Release, 1_000).unwrap();
        assert!(!c.controls(1_000), "input stops as soon as release is sent");
        assert_eq!(
            c.on_reply(&lease(&id(2), 1, 15_000), 1_100),
            ReplyOutcome::UnknownRe
        );
        assert_eq!(
            c.on_reply(&reply(&id(3), Op::LeaseReleased {}), 1_200),
            ReplyOutcome::Applied
        );
        assert!(!c.controls(1_200));
    }

    #[test]
    fn in_flight_and_duplicate_ids_are_bounded() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        assert_eq!(
            c.sent(&id(1), LeaseRequest::Acquire, 0),
            Err(RequestRefused::DuplicateId)
        );
        for n in 2..=crate::session_protocol::wire::MAX_IN_FLIGHT as u32 {
            c.sent(&id(n), LeaseRequest::Acquire, 0).unwrap();
        }
        assert_eq!(
            c.sent(&id(999), LeaseRequest::Acquire, 0),
            Err(RequestRefused::TooManyInFlight)
        );
    }

    #[test]
    fn deadline_reads_none_once_reached() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 1, 15_000), 0);
        assert_eq!(c.deadline_ms(14_999), Some(15_000));
        assert_eq!(c.deadline_ms(15_000), None, "now >= deadline");
    }

    #[test]
    fn renew_reply_with_another_epoch_fails_closed() {
        let mut c = client();
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_reply(&lease(&id(1), 4, 15_000), 0);
        c.sent(&id(2), LeaseRequest::Renew, 5_000).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(2), 5, 15_000), 5_100),
            ReplyOutcome::Mismatch
        );
        assert!(
            !c.controls(5_100),
            "a renew answered for another epoch ends control"
        );
        assert_eq!(c.lease_epoch(), None);
    }

    #[test]
    fn release_needs_control() {
        let mut c = client();
        assert_eq!(
            c.sent(&id(1), LeaseRequest::Release, 0),
            Err(RequestRefused::NotControlling)
        );
    }

    #[test]
    fn lease_replies_older_than_a_seen_lease_change_are_dropped() {
        let mut c = client();
        // A viewer with an acquire outstanding sees the lease move to epoch 6.
        c.sent(&id(1), LeaseRequest::Acquire, 0).unwrap();
        c.on_lease_changed(&target().session_id, PG, 6);
        assert_eq!(
            c.on_reply(&lease(&id(1), 5, 15_000), 100),
            ReplyOutcome::StaleEpoch
        );
        assert!(!c.controls(100));
        // A grant at (or after) the highest seen epoch applies.
        c.sent(&id(2), LeaseRequest::Acquire, 200).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(2), 6, 15_000), 300),
            ReplyOutcome::Applied
        );
        assert!(c.controls(300));
        // Other targets' changes don't count.
        c.on_lease_changed(&target().session_id, PG2, 50);
        c.on_lease_changed("ses-bbbbbbbbbbbb", PG, 50);
        assert!(c.controls(300));
        c.sent(&id(3), LeaseRequest::Acquire, 400).unwrap();
        assert_eq!(
            c.on_reply(&lease(&id(3), 6, 15_000), 500),
            ReplyOutcome::Applied
        );
    }

    // ── registry ──

    fn desc(sid: &str, pg: &str, state: SessionState) -> Descriptor {
        Descriptor {
            session_id: sid.into(),
            process_gen: pg.into(),
            provider: "claude".into(),
            cwd_label: "Atem".into(),
            state,
            activity: Activity::Ready,
            activity_since: 1,
            controller: None,
            capabilities: vec![],
            created_at: 1,
        }
    }

    fn snap(rgen: &str, epoch: u64, seq: u64, sessions: Vec<Descriptor>) -> Op {
        Op::Sessions {
            runtime_gen: rgen.into(),
            runtime_epoch: epoch,
            seq,
            sessions,
        }
    }

    fn change(rgen: &str, epoch: u64, seq: u64, d: Descriptor) -> Op {
        Op::SessionChanged {
            runtime_gen: rgen.into(),
            runtime_epoch: epoch,
            seq,
            descriptor: d,
        }
    }

    const A: &str = "ses-aaaaaaaaaaaa";
    const B: &str = "ses-bbbbbbbbbbbb";

    #[test]
    fn a_new_attachment_restarts_seq_but_keeps_the_epoch_floor() {
        let s1 = || desc("ses-aaaaaaaaaaaa", PG, SessionState::Running);
        let mut r = RegistryClient::default();
        assert_eq!(
            r.on_message(&snap(RG8, 8, 5, vec![s1()])),
            RegistryOutcome::Applied
        );
        // Without a reset, the new attachment's snapshot (seq 1) is stale.
        let mut frozen = r.clone();
        assert_eq!(
            frozen.on_message(&snap(RG8, 8, 1, vec![])),
            RegistryOutcome::StaleSnapshot
        );
        r.new_attachment();
        assert!(r.session_ids().is_empty() && r.seq().is_none());
        assert_eq!(r.runtime_epoch(), Some(8));
        // Older-epoch messages stay fenced.
        assert_eq!(
            r.on_message(&snap(RG7, 7, 9, vec![s1()])),
            RegistryOutcome::StaleEpoch
        );
        assert_eq!(
            r.on_message(&snap(RG8, 8, 1, vec![s1()])),
            RegistryOutcome::Applied
        );
        assert_eq!(r.seq(), Some(1));
        assert_eq!(
            r.on_message(&change(
                RG8,
                8,
                2,
                desc("ses-aaaaaaaaaaaa", PG, SessionState::Exited)
            )),
            RegistryOutcome::Applied
        );
    }

    #[test]
    fn epochs_fence_snapshots() {
        let mut r = RegistryClient::default();
        let run = desc(A, PG, SessionState::Running);
        assert_eq!(
            r.on_message(&snap(RG7, 7, 100, vec![desc(B, PG, SessionState::Running)])),
            RegistryOutcome::Applied
        );
        assert_eq!(
            r.on_message(&snap(RG8, 8, 1, vec![run.clone()])),
            RegistryOutcome::Applied
        );
        assert_eq!(r.session_ids(), vec![A.to_string()]);
        assert_eq!((r.runtime_epoch(), r.seq()), (Some(8), Some(1)));
        assert_eq!(
            r.on_message(&snap(RG7, 7, 101, vec![])),
            RegistryOutcome::StaleEpoch
        );
        assert_eq!(
            r.on_message(&change(RG7, 7, 2, run.clone())),
            RegistryOutcome::StaleEpoch
        );
        // Same epoch, other runtime_gen.
        assert_eq!(
            r.on_message(&snap(RG7, 8, 5, vec![])),
            RegistryOutcome::RuntimeGenMismatch
        );
        assert_eq!(
            r.on_message(&change(RG7, 8, 2, run)),
            RegistryOutcome::RuntimeGenMismatch
        );
        assert_eq!(r.session_ids(), vec![A.to_string()]);
        assert!(!r.take_list_request());
    }

    #[test]
    fn changes_apply_in_order_and_duplicates_are_ignored() {
        let mut r = RegistryClient::default();
        r.on_message(&snap(RG8, 8, 4, vec![desc(A, PG, SessionState::Running)]));
        assert_eq!(
            r.on_message(&change(RG8, 8, 5, desc(A, PG, SessionState::Exited))),
            RegistryOutcome::Applied
        );
        assert_eq!(r.session(A).unwrap().state, SessionState::Exited);
        assert_eq!(
            r.on_message(&change(RG8, 8, 5, desc(A, PG, SessionState::Running))),
            RegistryOutcome::Duplicate
        );
        assert_eq!(
            r.on_message(&change(RG8, 8, 3, desc(A, PG, SessionState::Running))),
            RegistryOutcome::Duplicate
        );
        assert_eq!(r.session(A).unwrap().state, SessionState::Exited);
        assert_eq!(
            r.on_message(&snap(RG8, 8, 4, vec![])),
            RegistryOutcome::StaleSnapshot
        );
        assert!(!r.take_list_request());
    }

    #[test]
    fn gap_requests_list_and_resync_discards_older_changes() {
        let mut r = RegistryClient::default();
        r.on_message(&snap(RG8, 8, 1, vec![desc(A, PG, SessionState::Running)]));
        assert_eq!(
            r.on_message(&change(RG8, 8, 3, desc(A, PG, SessionState::Exited))),
            RegistryOutcome::Buffered
        );
        assert!(r.take_list_request());
        assert!(!r.take_list_request(), "one list per gap");
        assert_eq!(r.lists_requested(), 1);
        assert_eq!(r.session(A).unwrap().state, SessionState::Running);
        assert_eq!(
            r.on_message(&change(RG8, 8, 2, desc(A, PG, SessionState::Removed))),
            RegistryOutcome::Buffered
        );
        // A further gap while awaiting the snapshot doesn't send another list.
        r.on_message(&change(RG8, 8, 9, desc(A, PG, SessionState::Exited)));
        assert!(!r.take_list_request());
        // Snapshot at 3: buffered 2 and 3 are discarded; 9 is still ahead (gap → list).
        assert_eq!(
            r.on_message(&snap(RG8, 8, 3, vec![])),
            RegistryOutcome::Applied
        );
        assert!(r.session_ids().is_empty());
        assert_eq!(r.seq(), Some(3));
        assert!(r.take_list_request());
        assert_eq!(
            r.on_message(&change(RG8, 8, 3, desc(A, PG, SessionState::Exited))),
            RegistryOutcome::Duplicate
        );
        assert!(r.session_ids().is_empty());
    }

    #[test]
    fn buffered_changes_after_the_snapshot_apply_in_order() {
        let mut r = RegistryClient::default();
        r.note_list_sent();
        assert_eq!(
            r.on_message(&change(RG8, 8, 6, desc(A, PG, SessionState::Exited))),
            RegistryOutcome::Buffered
        );
        assert!(
            r.take_list_request(),
            "a change from a new epoch needs a list"
        );
        assert!(r.session_ids().is_empty());
        r.on_message(&change(RG8, 8, 7, desc(B, PG, SessionState::Running)));
        r.on_message(&snap(RG8, 8, 5, vec![desc(A, PG, SessionState::Running)]));
        assert_eq!(r.seq(), Some(7));
        assert_eq!(r.session(A).unwrap().state, SessionState::Exited);
        assert!(r.session(B).is_some());
        assert!(!r.take_list_request());
    }

    #[test]
    fn new_epoch_from_a_change_applies_nothing_until_its_snapshot() {
        let mut r = RegistryClient::default();
        r.on_message(&snap(RG7, 7, 100, vec![desc(B, PG, SessionState::Running)]));
        assert_eq!(
            r.on_message(&change(RG8, 8, 1, desc(A, PG, SessionState::Running))),
            RegistryOutcome::Buffered
        );
        assert_eq!(r.runtime_epoch(), Some(8));
        assert_eq!(r.seq(), None);
        assert!(
            r.session_ids().is_empty(),
            "a higher epoch replaces all state"
        );
        assert!(r.take_list_request());
        assert_eq!(
            r.on_message(&snap(RG7, 7, 101, vec![])),
            RegistryOutcome::StaleEpoch
        );
        assert_eq!(
            r.on_message(&snap(RG8, 8, 1, vec![desc(A, PG, SessionState::Exited)])),
            RegistryOutcome::Applied
        );
        assert_eq!(r.session(A).unwrap().state, SessionState::Exited);
    }

    #[test]
    fn removal_is_never_resurrected() {
        let mut r = RegistryClient::default();
        r.on_message(&snap(RG8, 8, 1, vec![desc(A, PG, SessionState::Running)]));
        assert_eq!(
            r.on_message(&change(RG8, 8, 2, desc(A, PG, SessionState::Removed))),
            RegistryOutcome::Applied
        );
        assert!(r.session(A).is_none());
        assert_eq!(
            r.on_message(&change(RG8, 8, 2, desc(A, PG, SessionState::Running))),
            RegistryOutcome::Duplicate
        );
        assert_eq!(
            r.on_message(&change(RG8, 8, 3, desc(A, PG, SessionState::Running))),
            RegistryOutcome::Resurrection
        );
        assert!(r.session(A).is_none());
        assert_eq!(r.seq(), Some(3), "the seq was consumed");
        // A snapshot can't revive that process_gen either.
        r.on_message(&snap(RG8, 8, 4, vec![desc(A, PG, SessionState::Running)]));
        assert!(r.session(A).is_none());
        // A new process for the same session id is accepted with a higher seq.
        assert_eq!(
            r.on_message(&change(RG8, 8, 5, desc(A, PG2, SessionState::Running))),
            RegistryOutcome::Applied
        );
        assert_eq!(r.session(A).unwrap().process_gen, PG2);
    }

    #[test]
    fn snapshot_never_lists_removed_descriptors() {
        let mut r = RegistryClient::default();
        r.on_message(&snap(
            RG8,
            8,
            1,
            vec![
                desc(A, PG, SessionState::Removed),
                desc(B, PG, SessionState::Running),
            ],
        ));
        assert_eq!(r.session_ids(), vec![B.to_string()]);
        assert_eq!(
            r.on_message(&Op::List {}),
            RegistryOutcome::NotARegistryMessage
        );
    }
}

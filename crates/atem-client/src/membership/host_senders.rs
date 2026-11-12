//! Host senders' Revoke and Readmit (delegated host-work design II.3.1) and
//! a host's membership epoch (II.2.2): the `host_sender_revoke` and
//! `host_sender_readmit` entries of the device list, what follows from them
//! on a verifier, and their typed builders.
//!
//! **Where authorization lives.** In the device list, keyed by the logical
//! `host_id`, never by a key: every verifier (hosts, native devices, Station
//! replicas) derives it from the log the same way. Each host has one of two
//! sending states:
//!
//! - `authorized(g)`, entered by the host's first `add_host` (`g` is its
//!   `seq`) or by a `host_sender_readmit` (`g` is the readmit's `seq`): its
//!   envelopes signed at or after `g` are accepted (`signed_at_head`, within
//!   project grants and route consent);
//! - `revoked(r)`, entered by a `host_sender_revoke` (`r` is its `seq`):
//!   none are.
//!
//! A revoke needs an `add_host` of the host in the log, current or removed
//! (else `unknown_host`), and `authorized` at `seq-1` (else
//! `already_revoked`); a readmit needs `revoked` at `seq-1` (else
//! `not_revoked`). Key changes never change authorization: a newer
//! `add_host` without a removal (re-verification), a `remove_host`, or an
//! `add_host` after a `remove_host` leave the sending state as it was, so a
//! revoked host stays revoked until a native manager readmits it.
//!
//! **Membership epoch** (II.2.2): the `seq` of the host's first `add_host`
//! after its last `remove_host` (its first `add_host`, if it was never
//! removed). Re-verification keeps it; a re-add after a removal changes it.
//! A task records it at admission and the start check refuses a task whose
//! sender's epoch has changed. A host that is removed has none.
//!
//! Atem never signs these. Astation signs them only once every strict
//! verifier of the account knows them (the signing gate, II.2.2): a verifier
//! that doesn't know an action fails the whole chain at that entry.
use std::collections::BTreeMap;

use crate::encoding::Hash32;

use super::draft::verified;
use super::entry::Action;
use super::{Invalid, Membership};

/// A host's sending authorization on a verifier (II.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSenderState {
    /// Its envelopes signed at or after `generation` are accepted: the `seq`
    /// of its first `add_host`, or of its latest `host_sender_readmit`.
    Authorized { generation: u64 },
    /// Revoked by the `host_sender_revoke` at `seq`: none are accepted.
    Revoked { seq: u64 },
}

/// One host as a sender: its sending state and its membership epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostSender {
    state: HostSenderState,
    /// The `seq` of its first `add_host` after its last `remove_host`;
    /// `None` while it is removed.
    epoch: Option<u64>,
}

/// Every host an `add_host` named, as a sender (part of the derived state:
/// a pure function of the entries, replayed like the rest).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct HostSenders {
    by_host: BTreeMap<String, HostSender>,
}

impl HostSenders {
    /// `add_host` at `seq`: a host's first is `authorized(seq)` and starts
    /// its epoch; one after its `remove_host` starts a new epoch; neither it
    /// nor a re-verification changes the sending state.
    pub(super) fn host_added(&mut self, host_id: &str, seq: u64) {
        self.by_host
            .entry(host_id.to_owned())
            .and_modify(|sender| {
                sender.epoch.get_or_insert(seq);
            })
            .or_insert(HostSender {
                state: HostSenderState::Authorized { generation: seq },
                epoch: Some(seq),
            });
    }

    /// `remove_host`: its epoch ends; its sending state stays.
    pub(super) fn host_removed(&mut self, host_id: &str) {
        if let Some(sender) = self.by_host.get_mut(host_id) {
            sender.epoch = None;
        }
    }

    /// `host_sender_revoke` at `seq` (the chain checked the host is
    /// `authorized` at `seq-1`).
    pub(super) fn revoke(&mut self, host_id: &str, seq: u64) {
        if let Some(sender) = self.by_host.get_mut(host_id) {
            sender.state = HostSenderState::Revoked { seq };
        }
    }

    /// `host_sender_readmit` at `seq` (the chain checked the host is
    /// `revoked` at `seq-1`).
    pub(super) fn readmit(&mut self, host_id: &str, seq: u64) {
        if let Some(sender) = self.by_host.get_mut(host_id) {
            sender.state = HostSenderState::Authorized { generation: seq };
        }
    }

    pub(super) fn state(&self, host_id: &str) -> Option<HostSenderState> {
        self.by_host.get(host_id).map(|sender| sender.state)
    }

    fn epoch(&self, host_id: &str) -> Option<u64> {
        self.by_host.get(host_id).and_then(|sender| sender.epoch)
    }
}

impl Membership {
    /// `host_id`'s sending authorization; `None` for a host no `add_host`
    /// ever named. A removed host keeps its state (it can't send while it
    /// isn't a current host, [`Membership::host`]).
    pub fn host_sender_state(&self, host_id: &str) -> Option<HostSenderState> {
        self.derived.host_senders.state(host_id)
    }

    /// `host_id`'s membership epoch: the `seq` of its first `add_host` after
    /// its last `remove_host` (its first, if it was never removed). `None`
    /// for a host never added, or removed and not added again.
    pub fn host_membership_epoch(&self, host_id: &str) -> Option<u64> {
        self.derived.host_senders.epoch(host_id)
    }

    /// The `entry_hash` of the entry at `seq` (1-based): what an envelope's
    /// `signed_at_head{seq, hash}` must name (II.3.1, "No replay across a
    /// revoke"). `None` beyond the head.
    pub fn entry_hash_at(&self, seq: u64) -> Option<Hash32> {
        self.entry(seq).map(|entry| entry.hash())
    }
}

/// A `host_sender_revoke` of `host_id`, as the verifier parses it (that the
/// host was added and is `authorized` is checked against the chain).
/// `interrupt_running` asks the receiving hosts for an interrupt intent for
/// each of its started tasks. `signed_at` is the time the manager signs it
/// (display only).
pub fn host_sender_revoke(
    host_id: &str,
    interrupt_running: bool,
    signed_at: u64,
) -> Result<Action, Invalid> {
    verified(
        Action::HostSenderRevoke {
            host_id: host_id.to_owned(),
            interrupt_running,
        },
        signed_at,
    )
}

/// A `host_sender_readmit` of `host_id`, as the verifier parses it (that
/// the host is `revoked` is checked against the chain).
pub fn host_sender_readmit(host_id: &str, signed_at: u64) -> Result<Action, Invalid> {
    verified(
        Action::HostSenderReadmit {
            host_id: host_id.to_owned(),
        },
        signed_at,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized(generation: u64) -> Option<HostSenderState> {
        Some(HostSenderState::Authorized { generation })
    }

    #[test]
    fn host_sender_state_follows_add_revoke_and_readmit_only() {
        let mut senders = HostSenders::default();
        assert_eq!(senders.state("a"), None);
        senders.host_added("a", 2);
        assert_eq!(senders.state("a"), authorized(2));
        // Re-verification, a removal and a re-add keep the state.
        senders.host_added("a", 3);
        senders.host_removed("a");
        senders.host_added("a", 5);
        assert_eq!(senders.state("a"), authorized(2));
        senders.revoke("a", 6);
        assert_eq!(
            senders.state("a"),
            Some(HostSenderState::Revoked { seq: 6 })
        );
        senders.host_removed("a");
        senders.host_added("a", 8);
        assert_eq!(
            senders.state("a"),
            Some(HostSenderState::Revoked { seq: 6 })
        );
        senders.readmit("a", 9);
        assert_eq!(senders.state("a"), authorized(9));
        // A host never added: nothing to change, nothing created.
        senders.host_removed("b");
        senders.revoke("b", 10);
        senders.readmit("b", 11);
        assert_eq!(senders.state("b"), None);
        assert_eq!(senders.by_host.len(), 1);
    }

    #[test]
    fn host_membership_epoch_moves_only_on_a_re_add() {
        let mut senders = HostSenders::default();
        assert_eq!(senders.epoch("a"), None);
        senders.host_added("a", 2);
        senders.host_added("a", 3);
        senders.revoke("a", 4);
        senders.readmit("a", 5);
        assert_eq!(senders.epoch("a"), Some(2));
        senders.host_removed("a");
        assert_eq!(senders.epoch("a"), None);
        senders.host_added("a", 7);
        senders.host_added("a", 8);
        assert_eq!(senders.epoch("a"), Some(7));
        senders.host_removed("a");
        senders.host_removed("a");
        senders.host_added("a", 10);
        assert_eq!(senders.epoch("a"), Some(10));
    }
}

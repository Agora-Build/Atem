//! Publishing an entry with the relay's compare-and-swap (§R9.4 client rules
//! 1–5), sans-I/O.
//!
//! 1. Prepare durably: the body is drafted on a verified head and stored
//!    ([`Prepared`] is the durable part) before the key signs it; then the
//!    signature is stored.
//! 2. Publish before use: the entry joins the signer's own log only after
//!    the relay answered `200` for it.
//! 3. Lost the race (`409`): the prepared body is discarded (never carried),
//!    the returned entries are verified and applied; a new body needs a new
//!    owner confirmation.
//! 4. Uncertain outcome: the same stored bytes are resent; a lost signature
//!    is re-made over the same body (same `entry_hash`).
//! 5. One outstanding append per device.
use serde_json::Value;

use crate::encoding::Hash32;
use crate::provider::{KeyId, KeyProvider};
use crate::signed::SignedObject;

use super::{
    Conflict, Entry, Evaluation, Head, HostNow, Invalid, Membership, Stop, sign_entry,
    sign_entry_cosigned,
};

/// The relay's answer to `POST …/entries {entry, expected}`.
#[derive(Debug, Clone)]
pub enum AppendReply {
    /// `200`: stored (or the same `entry_hash` was already stored there).
    Stored,
    /// `409 {head, entries, more?}`: the relay's head, and its entries after
    /// `expected.seq` (or a window from before a divergence).
    Conflict {
        head: Head,
        entries: Vec<SignedObject>,
        more: bool,
    },
}

/// The durable part of an append in flight.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepared {
    /// The exact body to sign (stored before signing).
    pub body: Value,
    /// The head it was built on (`expected`).
    pub expected: Head,
    /// The signed entry, once signed and stored.
    pub signed: Option<Entry>,
}

/// What an append came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Published {
    /// `200`: the entry is in the relay's log and now in ours.
    Committed(Head),
    /// `200`, but our own log can't apply the entry yet: it depends on an
    /// entry still pending on this device's clock. It is committed at the
    /// relay; it joins our log when the dependency takes effect here.
    StoredPending { head: Head, on: Hash32 },
    /// `409`: our body was discarded; the returned entries were verified and
    /// applied (our log's head is the new one).
    LostRace { discarded: Prepared, head: Head },
    /// `409` with `more`: our body was discarded; fetch `…/entries?after=`
    /// this `seq`, verify, then decide again.
    FetchMore { discarded: Prepared, after: u64 },
    /// The relay showed conflicting signed history (two entries at one
    /// `seq`): stop signing entries and carry the window to hosts (§R9.4).
    Diverged { discarded: Prepared },
    /// The `409`'s entries go beyond an entry still pending on this
    /// device's clock: wait (don't rebuild on an unchanged head).
    Waiting { discarded: Prepared, on: Hash32 },
    /// The `409` didn't move our verified log to the head it reported (a
    /// window that doesn't chain from our log, whose entries were therefore
    /// never verified: refetch an earlier window; an ignored conflicting
    /// entry; or a head the entries don't reach): refetch later; never
    /// rebuild on the unchanged head.
    RelayInconsistent { discarded: Prepared, head: Head },
    /// The relay returned entries that don't verify.
    RelayInvalid {
        discarded: Prepared,
        index: usize,
        reason: Invalid,
    },
}

/// Why an append can't start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// One outstanding append per device (rule 5).
    Outstanding,
    /// The body doesn't chain from the log's head.
    NotOnHead,
    /// Nothing is prepared.
    NothingPrepared,
    /// Signing failed or produced an entry the verifier refuses.
    Sign(Invalid),
}

/// One device's appends: at most one in flight.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Publisher {
    prepared: Option<Prepared>,
}

impl Publisher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resumes from the stored state after a restart.
    pub fn resume(prepared: Option<Prepared>) -> Self {
        Publisher { prepared }
    }

    /// The durable part (store it after each call that changes it).
    pub fn prepared(&self) -> Option<&Prepared> {
        self.prepared.as_ref()
    }

    /// Rule 1: stores `body`, drafted on `log`'s head.
    pub fn prepare(&mut self, log: &Membership, body: Value) -> Result<(), PublishError> {
        if self.prepared.is_some() {
            return Err(PublishError::Outstanding);
        }
        let head = log.head();
        let seq = body.get("seq").and_then(Value::as_u64);
        let prev = body.get("prev_hash").and_then(Value::as_str);
        if seq != Some(head.seq + 1) || prev != Some(head.hash.to_hex().as_str()) {
            return Err(PublishError::NotOnHead);
        }
        self.prepared = Some(Prepared {
            body,
            expected: head,
            signed: None,
        });
        Ok(())
    }

    /// Signs the stored body (again, if the signature was lost: the same
    /// `entry_hash`). `cosign`: the current kit for a `kit: "current"`
    /// `set_recovery_key`.
    pub fn sign(
        &mut self,
        provider: &dyn KeyProvider,
        key: &KeyId,
        cosign: Option<(&dyn KeyProvider, &KeyId)>,
    ) -> Result<&Entry, PublishError> {
        let prepared = self
            .prepared
            .as_mut()
            .ok_or(PublishError::NothingPrepared)?;
        let entry = match cosign {
            Some((kit, kit_key)) => {
                sign_entry_cosigned(provider, key, kit, kit_key, prepared.body.clone())
            }
            None => sign_entry(provider, key, prepared.body.clone()),
        }
        .map_err(PublishError::Sign)?;
        prepared.signed = Some(entry);
        Ok(prepared.signed.as_ref().expect("just stored"))
    }

    /// What to send (and resend after an uncertain outcome): the signed
    /// entry and the head it expects.
    pub fn outstanding(&self) -> Option<(&Entry, Head)> {
        let prepared = self.prepared.as_ref()?;
        Some((prepared.signed.as_ref()?, prepared.expected))
    }

    /// Applies the relay's answer to `log` (rules 2 and 3).
    pub fn reply(
        &mut self,
        reply: AppendReply,
        log: &mut Membership,
        now: &HostNow,
    ) -> Result<Published, PublishError> {
        let prepared = self.prepared.take().ok_or(PublishError::NothingPrepared)?;
        match reply {
            AppendReply::Stored => {
                let Some(entry) = prepared.signed.clone() else {
                    self.prepared = Some(prepared);
                    return Err(PublishError::NothingPrepared);
                };
                let eval = log.evaluate_objects(&[entry.object().clone()], now);
                let stop = eval.stop.clone();
                *log = eval.next;
                let ours = Head {
                    seq: entry.seq,
                    hash: entry.hash(),
                };
                match stop {
                    Some(Stop::Invalid { index, reason }) => {
                        return Ok(Published::RelayInvalid {
                            discarded: prepared,
                            index,
                            reason,
                        });
                    }
                    Some(Stop::Deferred { on, .. }) => {
                        return Ok(Published::StoredPending { head: ours, on });
                    }
                    _ => {}
                }
                if log.entry(ours.seq).map(|e| e.hash()) == Some(ours.hash) {
                    Ok(Published::Committed(ours))
                } else {
                    // Our log took another entry at that seq meanwhile: the
                    // relay showed two histories.
                    Ok(Published::Diverged {
                        discarded: prepared,
                    })
                }
            }
            AppendReply::Conflict {
                head,
                entries,
                more,
            } => {
                let eval: Evaluation = log.evaluate_objects(&entries, now);
                let stop = eval.stop.clone();
                *log = eval.next;
                let moved = log.head() != prepared.expected;
                Ok(match stop {
                    Some(Stop::Conflict {
                        outcome: Conflict::Freeze,
                        ..
                    })
                    | Some(Stop::Frozen) => Published::Diverged {
                        discarded: prepared,
                    },
                    // The window's entry at a seq we hold doesn't chain from
                    // ours. Its signature was never checked, so this isn't
                    // signed conflicting history (which stops signing):
                    // refetch an earlier window.
                    Some(Stop::NeedBefore { .. }) => Published::RelayInconsistent {
                        discarded: prepared,
                        head,
                    },
                    Some(Stop::Invalid { index, reason }) => Published::RelayInvalid {
                        discarded: prepared,
                        index,
                        reason,
                    },
                    Some(Stop::Deferred { on, .. }) => Published::Waiting {
                        discarded: prepared,
                        on,
                    },
                    Some(Stop::Conflict {
                        outcome: Conflict::Ignored(_),
                        ..
                    }) => Published::RelayInconsistent {
                        discarded: prepared,
                        head,
                    },
                    _ if more && moved => Published::FetchMore {
                        after: log.head().seq,
                        discarded: prepared,
                    },
                    _ if !more && log.head() == head && moved => Published::LostRace {
                        discarded: prepared,
                        head,
                    },
                    _ => Published::RelayInconsistent {
                        discarded: prepared,
                        head,
                    },
                })
            }
        }
    }
}

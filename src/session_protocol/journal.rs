//! The host's durable receipt journal (§6), lease-epoch reservations (§5)
//! and, for r8, the principals' control generations (§H), the refusal list
//! and the clean-close record (§I).
//!
//! A `Journal` appends one record at a time and makes it durable (fsync)
//! before `append` returns `Ok`; the host reports a state only after its record
//! is durable. On restart the host reloads every durable record with `load` and
//! folds them with `replay`, then applies the crash rules itself.
//!
//! Apart from the appended log, a journal keeps two small records, each
//! replaced atomically and never counted as an append: the refusal list
//! (requests answered `busy` because their admission write failed, §I.2)
//! and the clean-close record (`{"runtime_epoch": n}`, written at an
//! orderly shutdown with a healthy journal, §H).
//!
//! `MemJournal` keeps everything in memory and can fail the n-th next append
//! (`fail_fsync_of`; with `undo_fails` the failed record is kept, the worst
//! case of a failed rollback) or "crash" right after the next `Accepted`
//! (`crash_after_accepted`). After a failure it refuses every append until
//! `reopen`, as `FileJournal` does.

use super::wire::{ReceiptKind, ReceiptState, Target};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// A new request admitted as `accepted`, with what a dispatch after a
    /// crash needs (its payload) and, r8 §H, the submitter principal and its
    /// control generation at admission (admission metadata: ids only, in
    /// neither the digest nor the immutable request).
    Accepted {
        request_id: String,
        target: Target,
        kind: ReceiptKind,
        payload_digest: String,
        payload: Value,
        updated_at: u64,
        principal: String,
        control_gen: u64,
    },
    /// A later state of a recorded request.
    Transition {
        request_id: String,
        state: ReceiptState,
        detail: Option<String>,
        updated_at: u64,
    },
    /// — → `rejected`: a request on the refusal list whose `accepted` record
    /// never reached the disk, resolved at restart with its immutable values
    /// (§I.3). Nothing was accepted.
    Rejected {
        request_id: String,
        target: Target,
        kind: ReceiptKind,
        payload_digest: String,
        detail: String,
        updated_at: u64,
    },
    /// The receipt left the retention window and is forgotten.
    Evicted { request_id: String },
    /// Lease epochs up to `reserved` may have been issued for `session_id`;
    /// none of them is ever issued again.
    LeaseEpochs { session_id: String, reserved: u64 },
    /// A principal's control state (§H): whether it holds `control`, and its
    /// `control_gen` (from 1, never decreasing). A revocation (the fence) is
    /// `control: false` with the raised generation; a later grant keeps it.
    Control {
        principal: String,
        control: bool,
        control_gen: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalError(pub String);

/// A request refused `busy` because its admission write failed (§I.2): its
/// immutable values, never its payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub request_id: String,
    pub target: Target,
    pub kind: ReceiptKind,
    pub payload_digest: String,
    pub updated_at: u64,
}

/// Durable receipt storage.
///
/// A file journal can't know what an fsync error left on disk (the record may
/// or may not have been written). After one it refuses every append until it
/// is reopened (a restart); the host treats every `Err` as "maybe written"
/// and halts (§I).
///
/// A request's payload is only needed while it is `accepted` (a dispatch
/// after a crash); once a `Transition` moves it on, the journal may drop the
/// payload (compaction). The digest is kept forever, for duplicates.
pub trait Journal {
    /// Appends `record` and makes it durable (fsync) before returning `Ok`.
    fn append(&mut self, record: Record) -> Result<(), JournalError>;
    /// Every durable record, in append order.
    fn load(&self) -> Result<Vec<Record>, JournalError>;
    /// Adds `refusal` to the refusal list durably (replaced atomically),
    /// apart from the appended log: it works after a failed append.
    fn record_refusal(&mut self, refusal: Refusal) -> Result<(), JournalError>;
    /// The refusal list.
    fn refusals(&self) -> Result<Vec<Refusal>, JournalError>;
    /// Empties the refusal list durably.
    fn clear_refusals(&mut self) -> Result<(), JournalError>;
    /// Writes the clean-close record naming `runtime_epoch` durably.
    fn write_clean_close(&mut self, runtime_epoch: u64) -> Result<(), JournalError>;
    /// The epoch the clean-close record names, if one exists and parses;
    /// the record is removed either way (a failed removal is harmless: the
    /// next run's epoch supersedes it).
    fn take_clean_close(&mut self) -> Option<u64>;
    /// After a restart: reload what is durable and accept appends again.
    fn reopen(&mut self) -> Result<(), JournalError>;
}

/// In-memory journal with failure injection, for tests and the fixtures.
#[derive(Debug, Default)]
pub struct MemJournal {
    records: Vec<Record>,
    refused: Vec<Refusal>,
    clean_close: Option<u64>,
    /// Appends left before the one whose fsync fails, and whether its
    /// rollback fails too (the record stays).
    fail_in: Option<(u64, bool)>,
    /// The next `Accepted` becomes durable, then the "process" dies: every
    /// later append fails until `reopen`.
    crash_after_accepted: bool,
    crashed: bool,
    /// A failed append: no more appends until `reopen`.
    failed: bool,
    /// The next refusal-list write fails.
    fail_refusal: bool,
    fsyncs: u64,
}

impl MemJournal {
    /// The next `append` fails its fsync; the record is lost.
    #[cfg(test)]
    pub fn fail_next_fsync(&mut self) {
        self.fail_fsync_of(1);
    }

    /// The `n`-th next `append` (1-based) fails its fsync.
    #[cfg(test)]
    pub fn fail_fsync_of(&mut self, n: u64) {
        self.fail_in = Some((n.saturating_sub(1), false));
    }

    /// The `n`-th next `append` fails, and so does its rollback: the record
    /// is durable although the append reported a failure.
    #[cfg(test)]
    pub fn fail_fsync_and_undo_of(&mut self, n: u64) {
        self.fail_in = Some((n.saturating_sub(1), true));
    }

    /// The next `Accepted` becomes durable, then the journal stops (a crash).
    #[cfg(test)]
    pub fn crash_after_accepted(&mut self) {
        self.crash_after_accepted = true;
    }

    /// Whether `crash_after_accepted` fired.
    #[cfg(test)]
    pub fn crashed(&self) -> bool {
        self.crashed
    }

    /// The next refusal-list write fails.
    #[cfg(test)]
    pub fn fail_next_refusal(&mut self) {
        self.fail_refusal = true;
    }

    /// Successful fsyncs so far.
    pub fn fsyncs(&self) -> u64 {
        self.fsyncs
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    fn push(&mut self, record: Record) {
        if let Record::Transition { request_id, .. } = &record {
            // Compaction: the payload isn't needed past `accepted`.
            for r in &mut self.records {
                if let Record::Accepted {
                    request_id: id,
                    payload,
                    ..
                } = r
                    && id == request_id
                {
                    *payload = Value::Null;
                }
            }
        }
        self.records.push(record);
    }
}

impl Journal for MemJournal {
    fn append(&mut self, record: Record) -> Result<(), JournalError> {
        if self.failed || self.crashed {
            return Err(JournalError("journal failed; reopen it".into()));
        }
        match self.fail_in {
            Some((0, undo_fails)) => {
                self.fail_in = None;
                self.failed = true;
                if undo_fails {
                    self.push(record);
                }
                return Err(JournalError("fsync failed".into()));
            }
            Some((n, undo_fails)) => self.fail_in = Some((n - 1, undo_fails)),
            None => {}
        }
        let accepted = matches!(record, Record::Accepted { .. });
        self.push(record);
        self.fsyncs += 1;
        if accepted && std::mem::take(&mut self.crash_after_accepted) {
            self.crashed = true;
        }
        Ok(())
    }

    fn load(&self) -> Result<Vec<Record>, JournalError> {
        Ok(self.records.clone())
    }

    fn record_refusal(&mut self, refusal: Refusal) -> Result<(), JournalError> {
        if std::mem::take(&mut self.fail_refusal) || self.crashed {
            return Err(JournalError("cannot write the refusal list".into()));
        }
        self.refused.retain(|r| r.request_id != refusal.request_id);
        self.refused.push(refusal);
        Ok(())
    }

    fn refusals(&self) -> Result<Vec<Refusal>, JournalError> {
        Ok(self.refused.clone())
    }

    fn clear_refusals(&mut self) -> Result<(), JournalError> {
        if self.failed || self.crashed {
            return Err(JournalError("journal failed; reopen it".into()));
        }
        self.refused.clear();
        Ok(())
    }

    fn write_clean_close(&mut self, runtime_epoch: u64) -> Result<(), JournalError> {
        if self.failed || self.crashed {
            return Err(JournalError("journal failed".into()));
        }
        self.clean_close = Some(runtime_epoch);
        Ok(())
    }

    fn take_clean_close(&mut self) -> Option<u64> {
        self.clean_close.take()
    }

    fn reopen(&mut self) -> Result<(), JournalError> {
        self.failed = false;
        self.crashed = false;
        self.crash_after_accepted = false;
        self.fail_in = None;
        Ok(())
    }
}

/// One recorded request as replayed from the journal.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub request_id: String,
    pub target: Target,
    pub kind: ReceiptKind,
    pub payload_digest: String,
    /// Present only while `accepted` (needed to dispatch after a crash).
    pub payload: Option<Value>,
    pub state: ReceiptState,
    pub detail: Option<String>,
    pub updated_at: u64,
    /// Admission order (position of its `Accepted` record).
    pub order: u64,
    /// The submitter principal and its control generation at admission
    /// (r8 §H); empty and 0 for a request nothing accepted.
    pub principal: String,
    pub control_gen: u64,
}

/// A principal's durable control state (§H).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlState {
    pub control: bool,
    pub control_gen: u64,
}

#[derive(Debug, Default)]
pub struct Replayed {
    pub receipts: BTreeMap<String, Stored>,
    pub lease_epochs: HashMap<String, u64>,
    pub principals: BTreeMap<String, ControlState>,
}

pub fn is_final(state: ReceiptState) -> bool {
    matches!(
        state,
        ReceiptState::Completed | ReceiptState::Rejected | ReceiptState::OutcomeUnknown
    )
}

/// The §6 transition table (never into `accepted`; finals are final).
pub fn valid_transition(from: ReceiptState, to: ReceiptState) -> bool {
    use ReceiptState::*;
    matches!(
        (from, to),
        (Accepted, Executing)
            | (Accepted, Rejected)
            | (Executing, Completed)
            | (Executing, Rejected)
            | (Executing, OutcomeUnknown)
    )
}

/// Folds durable records into the current receipts, epoch reservations and
/// principal control states. A record that breaks the transition table or
/// names an unknown request is a corrupt journal; a control generation never
/// goes down (the highest seen wins).
pub fn replay(records: Vec<Record>) -> Result<Replayed, JournalError> {
    let mut out = Replayed::default();
    for (i, record) in records.into_iter().enumerate() {
        match record {
            Record::Accepted {
                request_id,
                target,
                kind,
                payload_digest,
                payload,
                updated_at,
                principal,
                control_gen,
            } => {
                if out.receipts.contains_key(&request_id) {
                    return Err(JournalError(format!("request {request_id} admitted twice")));
                }
                let stored = Stored {
                    request_id: request_id.clone(),
                    target,
                    kind,
                    payload_digest,
                    payload: Some(payload),
                    state: ReceiptState::Accepted,
                    detail: None,
                    updated_at,
                    order: i as u64,
                    principal,
                    control_gen,
                };
                out.receipts.insert(request_id, stored);
            }
            Record::Rejected {
                request_id,
                target,
                kind,
                payload_digest,
                detail,
                updated_at,
            } => {
                if out.receipts.contains_key(&request_id) {
                    return Err(JournalError(format!("request {request_id} recorded twice")));
                }
                let stored = Stored {
                    request_id: request_id.clone(),
                    target,
                    kind,
                    payload_digest,
                    payload: None,
                    state: ReceiptState::Rejected,
                    detail: Some(detail),
                    updated_at,
                    order: i as u64,
                    principal: String::new(),
                    control_gen: 0,
                };
                out.receipts.insert(request_id, stored);
            }
            Record::Transition {
                request_id,
                state,
                detail,
                updated_at,
            } => {
                let s = out
                    .receipts
                    .get_mut(&request_id)
                    .ok_or_else(|| JournalError(format!("transition of unknown {request_id}")))?;
                if !valid_transition(s.state, state) {
                    return Err(JournalError(format!(
                        "invalid transition {:?} -> {state:?} for {request_id}",
                        s.state
                    )));
                }
                s.state = state;
                s.payload = None;
                s.detail = detail;
                s.updated_at = updated_at;
            }
            Record::Evicted { request_id } => {
                out.receipts.remove(&request_id);
            }
            Record::LeaseEpochs {
                session_id,
                reserved,
            } => {
                let e = out.lease_epochs.entry(session_id).or_default();
                *e = (*e).max(reserved);
            }
            Record::Control {
                principal,
                control,
                control_gen,
            } => {
                let current = out.principals.get(&principal).copied();
                if current.is_none_or(|c| control_gen >= c.control_gen) {
                    out.principals.insert(
                        principal,
                        ControlState {
                            control,
                            control_gen,
                        },
                    );
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn target() -> Target {
        Target {
            account_id: "account-a".into(),
            atem_device_id: "host-a".into(),
            host_trust_gen: 1,
            session_id: "ses-aaaaaaaaaaaa".into(),
            process_gen: "22222222-2222-4222-8222-222222222222".into(),
        }
    }

    fn accepted(id: &str) -> Record {
        Record::Accepted {
            request_id: id.into(),
            target: target(),
            kind: ReceiptKind::Prompt,
            payload_digest: "0".repeat(64),
            payload: json!({"text": "hi"}),
            updated_at: 1,
            principal: "p1".into(),
            control_gen: 1,
        }
    }

    fn to(id: &str, state: ReceiptState) -> Record {
        Record::Transition {
            request_id: id.into(),
            state,
            detail: None,
            updated_at: 2,
        }
    }

    /// A failed append loses that record and stops the journal until it is
    /// reopened (as after a restart).
    #[test]
    fn failed_fsync_loses_only_that_record_and_halts() {
        let mut j = MemJournal::default();
        j.append(accepted("a")).unwrap();
        j.fail_next_fsync();
        assert!(j.append(to("a", ReceiptState::Executing)).is_err());
        assert!(j.append(to("a", ReceiptState::Rejected)).is_err());
        j.reopen().unwrap();
        j.append(to("a", ReceiptState::Rejected)).unwrap();
        assert_eq!(j.fsyncs(), 2);
        let r = replay(j.load().unwrap()).unwrap();
        assert_eq!(r.receipts["a"].state, ReceiptState::Rejected);
    }

    #[test]
    fn a_later_fsync_can_fail_and_a_failed_undo_keeps_the_record() {
        let mut j = MemJournal::default();
        j.fail_fsync_of(2);
        j.append(accepted("a")).unwrap();
        assert!(j.append(to("a", ReceiptState::Executing)).is_err());
        assert_eq!(j.records().len(), 1);
        let mut j = MemJournal::default();
        j.fail_fsync_and_undo_of(1);
        assert!(j.append(accepted("a")).is_err());
        assert_eq!(j.records().len(), 1, "the record is there after all");
    }

    #[test]
    fn crash_after_accepted_keeps_only_the_accepted_record() {
        let mut j = MemJournal::default();
        j.crash_after_accepted();
        j.append(Record::LeaseEpochs {
            session_id: "s".into(),
            reserved: 64,
        })
        .unwrap();
        j.append(accepted("a")).unwrap();
        assert!(j.crashed());
        assert!(j.append(to("a", ReceiptState::Executing)).is_err());
        j.reopen().unwrap();
        let r = replay(j.load().unwrap()).unwrap();
        assert_eq!(r.receipts["a"].state, ReceiptState::Accepted);
    }

    #[test]
    fn refusals_and_clean_close_are_apart_from_the_log() {
        let mut j = MemJournal::default();
        j.fail_next_fsync();
        assert!(j.append(accepted("a")).is_err());
        let refusal = Refusal {
            request_id: "a".into(),
            target: target(),
            kind: ReceiptKind::Prompt,
            payload_digest: "0".repeat(64),
            updated_at: 1,
        };
        j.record_refusal(refusal.clone()).unwrap();
        assert!(j.write_clean_close(7).is_err(), "never after a failure");
        j.reopen().unwrap();
        assert_eq!(j.refusals().unwrap(), vec![refusal]);
        j.clear_refusals().unwrap();
        assert!(j.refusals().unwrap().is_empty());
        j.write_clean_close(8).unwrap();
        assert_eq!(j.take_clean_close(), Some(8));
        assert_eq!(j.take_clean_close(), None, "taking removes it");
    }

    #[test]
    fn control_generations_never_go_down() {
        let control = |control, control_gen| Record::Control {
            principal: "p1".into(),
            control,
            control_gen,
        };
        let r = replay(vec![control(false, 3), control(true, 2), control(true, 3)]).unwrap();
        assert_eq!(
            r.principals["p1"],
            ControlState {
                control: true,
                control_gen: 3
            }
        );
        let rejected = Record::Rejected {
            request_id: "b".into(),
            target: target(),
            kind: ReceiptKind::Prompt,
            payload_digest: "0".repeat(64),
            detail: "acceptance not confirmed".into(),
            updated_at: 3,
        };
        let r = replay(vec![rejected.clone()]).unwrap();
        assert_eq!(r.receipts["b"].state, ReceiptState::Rejected);
        assert!(replay(vec![accepted("b"), rejected]).is_err());
    }

    #[test]
    fn replay_follows_the_transition_table() {
        use ReceiptState::*;
        let ok = replay(vec![
            accepted("a"),
            to("a", Executing),
            to("a", OutcomeUnknown),
        ])
        .unwrap();
        assert_eq!(ok.receipts["a"].state, OutcomeUnknown);
        for bad in [
            vec![accepted("a"), to("a", Completed)],
            vec![accepted("a"), to("a", Executing), to("a", Accepted)],
            vec![accepted("a"), to("a", Rejected), to("a", Executing)],
            vec![to("a", Executing)],
            vec![accepted("a"), accepted("a")],
        ] {
            assert!(replay(bad.clone()).is_err(), "{bad:?}");
        }
        let gone = replay(vec![
            accepted("a"),
            Record::Evicted {
                request_id: "a".into(),
            },
        ])
        .unwrap();
        assert!(gone.receipts.is_empty());
    }

    #[test]
    fn lease_reservations_keep_the_highest() {
        let r = replay(vec![
            Record::LeaseEpochs {
                session_id: "s".into(),
                reserved: 64,
            },
            Record::LeaseEpochs {
                session_id: "s".into(),
                reserved: 128,
            },
        ])
        .unwrap();
        assert_eq!(r.lease_epochs["s"], 128);
    }
}

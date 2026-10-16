//! The host's durable receipt journal (§6) and lease-epoch reservations (§5).
//!
//! A `Journal` appends one record at a time and makes it durable (fsync)
//! before `append` returns `Ok`; the host reports a state only after its record
//! is durable. On restart the host reloads every durable record with `load` and
//! folds them with `replay`, then applies the §6 crash rules itself.
//!
//! `MemJournal` keeps the records in memory and can fail the next fsync
//! (`fail_next_fsync`): the failed record is lost, as after a crash.

use super::wire::{ReceiptKind, ReceiptState, Target};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// A new request admitted as `accepted`, with what a dispatch after a
    /// crash needs (its payload).
    Accepted {
        request_id: String,
        target: Target,
        kind: ReceiptKind,
        payload_digest: String,
        payload: Value,
        updated_at: u64,
    },
    /// A later state of a recorded request.
    Transition {
        request_id: String,
        state: ReceiptState,
        detail: Option<String>,
        updated_at: u64,
    },
    /// The receipt left the retention window and is forgotten.
    Evicted { request_id: String },
    /// Lease epochs up to `reserved` may have been issued for `session_id`;
    /// none of them is ever issued again.
    LeaseEpochs { session_id: String, reserved: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalError(pub String);

/// Durable receipt storage.
///
/// A file journal can't know what an fsync error left on disk (the record may
/// or may not have been written). After one, a real implementation must stop
/// admitting new records until it has truncated back to its last durable
/// record; the host treats every `Err` as "not written".
///
/// A request's payload is only needed while it is `accepted` (a dispatch
/// after a crash); once a `Transition` moves it on, the journal may drop the
/// payload (compaction). The digest is kept forever, for duplicates.
pub trait Journal {
    /// Appends `record` and makes it durable (fsync) before returning `Ok`.
    /// On `Err` the record must be treated as not written.
    fn append(&mut self, record: Record) -> Result<(), JournalError>;
    /// Every durable record, in append order.
    fn load(&self) -> Result<Vec<Record>, JournalError>;
}

/// In-memory journal with failure injection, for tests and the fixtures.
#[derive(Debug, Default)]
pub struct MemJournal {
    records: Vec<Record>,
    /// Appends left before the one whose fsync fails.
    fail_in: Option<u64>,
    fsyncs: u64,
}

impl MemJournal {
    /// The next `append` fails its fsync; the record is lost.
    pub fn fail_next_fsync(&mut self) {
        self.fail_fsync_of(1);
    }

    /// The `n`-th next `append` (1-based) fails its fsync.
    pub fn fail_fsync_of(&mut self, n: u64) {
        self.fail_in = Some(n.saturating_sub(1));
    }

    /// Successful fsyncs so far.
    pub fn fsyncs(&self) -> u64 {
        self.fsyncs
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }
}

impl Journal for MemJournal {
    fn append(&mut self, record: Record) -> Result<(), JournalError> {
        match self.fail_in {
            Some(0) => {
                self.fail_in = None;
                return Err(JournalError("fsync failed".into()));
            }
            Some(n) => self.fail_in = Some(n - 1),
            None => {}
        }
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
        self.fsyncs += 1;
        Ok(())
    }

    fn load(&self) -> Result<Vec<Record>, JournalError> {
        Ok(self.records.clone())
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
}

#[derive(Debug, Default)]
pub struct Replayed {
    pub receipts: BTreeMap<String, Stored>,
    pub lease_epochs: HashMap<String, u64>,
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

/// Folds durable records into the current receipts and epoch reservations.
/// A record that breaks the transition table or names an unknown request is
/// a corrupt journal.
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

    #[test]
    fn failed_fsync_loses_only_that_record() {
        let mut j = MemJournal::default();
        j.append(accepted("a")).unwrap();
        j.fail_next_fsync();
        assert!(j.append(to("a", ReceiptState::Executing)).is_err());
        j.append(to("a", ReceiptState::Rejected)).unwrap();
        assert_eq!(j.fsyncs(), 2);
        let r = replay(j.load().unwrap()).unwrap();
        assert_eq!(r.receipts["a"].state, ReceiptState::Rejected);
    }

    #[test]
    fn a_later_fsync_can_fail() {
        let mut j = MemJournal::default();
        j.fail_fsync_of(2);
        j.append(accepted("a")).unwrap();
        assert!(j.append(to("a", ReceiptState::Executing)).is_err());
        j.append(to("a", ReceiptState::Rejected)).unwrap();
        assert_eq!(j.records().len(), 2);
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

//! The durable form of a verified log (§R9.3 `membership.json`, without the
//! host's own fields): what a host writes after each committed carriage and
//! reads back at start.
//!
//! [`Membership::to_stored`] writes the entries (wire objects, signatures
//! kept), the recovery records with their host-clock anchors and decisions
//! (the field mapping is in the module docs of [`super`]), the evidence, a
//! freeze and the decision counter. [`Membership::from_stored`] rebuilds the
//! state from them and checks it: the genesis is the pinned one, every later
//! entry verifies against the chain before it with the decisions this host
//! recorded up to that position (§R9.2; the same replay conflicts are judged
//! on), every pending-type entry has exactly one record, decisions sit at
//! positions the chain reached, and the stored head, recovery key and
//! retired keys equal the derived ones. Anything else is refused
//! ([`StoredError`]): the host then disables remote sessions rather than
//! guess (§R9.3 "Crash recovery").
use serde_json::{Map, Value, json};

use super::{
    Decision, Evidence, EvidenceReason, EvidenceRecord, Freeze, Head, Membership, RecoveryReason,
    RecoveryRecord, RecoveryState, WaitClock,
};
use crate::canonical::StrictValue;
use crate::encoding::{Hash32, b64u, b64u_decode};
use crate::keys::PublicKey;
use crate::membership::entry::Entry;
use crate::signed::SignedObject;

/// Largest stored object accepted on load (an entry's body is ≤ 4096 bytes).
const MAX_STORED_OBJECT: usize = 64 * 1024;

/// Why a stored log was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredError(pub String);

impl std::fmt::Display for StoredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoredError {}

fn bad(what: impl Into<String>) -> StoredError {
    StoredError(what.into())
}

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, StoredError> {
    object.get(key).ok_or_else(|| bad(format!("missing {key}")))
}

fn u64_of(object: &Map<String, Value>, key: &str) -> Result<u64, StoredError> {
    field(object, key)?
        .as_u64()
        .ok_or_else(|| bad(format!("{key} is not an unsigned integer")))
}

fn str_of<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, StoredError> {
    field(object, key)?
        .as_str()
        .ok_or_else(|| bad(format!("{key} is not a string")))
}

fn hash_of(object: &Map<String, Value>, key: &str) -> Result<Hash32, StoredError> {
    Hash32::from_hex(str_of(object, key)?).map_err(|_| bad(format!("{key} is not a hash")))
}

fn object_of(value: &Value, what: &str) -> Result<SignedObject, StoredError> {
    let bytes = value.to_string();
    let strict = StrictValue::parse(bytes.as_bytes(), MAX_STORED_OBJECT)
        .map_err(|_| bad(format!("{what} is not strict JSON")))?;
    SignedObject::from_strict(&strict).map_err(|e| bad(format!("{what}: {e}")))
}

fn state_name(state: RecoveryState) -> &'static str {
    state.as_str()
}

fn parse_state(text: &str) -> Option<RecoveryState> {
    Some(match text {
        "pending" => RecoveryState::Pending,
        "active" => RecoveryState::Active,
        "cancelled" => RecoveryState::Cancelled,
        _ => return None,
    })
}

/// Who reads a stored log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// The host (`membership.json`).
    Host,
    /// A client's own snapshot: also a log a kit restore produced.
    Client,
}

fn parse_reason(text: &str, reader: Reader) -> Option<RecoveryReason> {
    Some(match text {
        "approved" => RecoveryReason::Approved,
        "wait_ended" => RecoveryReason::WaitEnded,
        "vetoed" => RecoveryReason::Vetoed,
        "kit_replaced" => RecoveryReason::KitReplaced,
        // Restore-only (`verify_chain_confirmed`): a host never records it,
        // so a host's file holding it is refused; a client's restored log
        // holds it.
        "host_confirmed" if reader == Reader::Client => RecoveryReason::HostConfirmed,
        _ => return None,
    })
}

fn parse_evidence_reason(text: &str) -> Option<EvidenceReason> {
    Some(match text {
        "duplicate_veto" => EvidenceReason::DuplicateVeto,
        "late_decision" => EvidenceReason::LateDecision,
        "invalid" => EvidenceReason::Invalid,
        "signer_removed" => EvidenceReason::SignerRemoved,
        "signer_not_in_effect" => EvidenceReason::SignerNotInEffect,
        _ => return None,
    })
}

fn record_json(record: &RecoveryRecord) -> Value {
    let mut object = Map::new();
    object.insert("entry_hash".into(), json!(record.entry_hash.to_hex()));
    object.insert("seq".into(), json!(record.seq));
    object.insert("state".into(), json!(state_name(record.state())));
    object.insert(
        "first_seen_wall".into(),
        json!(record.clock.first_seen_wall),
    );
    object.insert("boot_id".into(), json!(record.clock.boot_id));
    object.insert("mono_anchor_ms".into(), json!(record.clock.mono_anchor_ms));
    object.insert("mono_waited_ms".into(), json!(record.clock.mono_waited_ms));
    if let Some(decision) = &record.decision {
        object.insert("decided_at_wall".into(), json!(decision.at_wall));
        object.insert("decided_at_seq".into(), json!(decision.at_seq));
        object.insert("order".into(), json!(decision.order));
        object.insert("reason".into(), json!(decision.reason.as_str()));
    }
    Value::Object(object)
}

fn parse_record(value: &Value, reader: Reader) -> Result<RecoveryRecord, StoredError> {
    let object = value
        .as_object()
        .ok_or_else(|| bad("a recovery record is not an object"))?;
    let state = parse_state(str_of(object, "state")?).ok_or_else(|| bad("recovery state"))?;
    let clock = WaitClock {
        first_seen_wall: u64_of(object, "first_seen_wall")?,
        boot_id: str_of(object, "boot_id")?.to_owned(),
        mono_anchor_ms: field(object, "mono_anchor_ms")?
            .as_i64()
            .ok_or_else(|| bad("mono_anchor_ms"))?,
        mono_waited_ms: u64_of(object, "mono_waited_ms")?,
    };
    let decision = match state {
        RecoveryState::Pending => {
            if ["decided_at_wall", "decided_at_seq", "order", "reason"]
                .iter()
                .any(|k| object.contains_key(*k))
            {
                return Err(bad("a pending record carries a decision"));
            }
            None
        }
        state => {
            let reason = parse_reason(str_of(object, "reason")?, reader)
                .ok_or_else(|| bad("recovery reason"))?;
            Some(Decision {
                state,
                reason,
                at_seq: u64_of(object, "decided_at_seq")?,
                order: u64_of(object, "order")?,
                at_wall: u64_of(object, "decided_at_wall")?,
            })
        }
    };
    Ok(RecoveryRecord {
        entry_hash: hash_of(object, "entry_hash")?,
        seq: u64_of(object, "seq")?,
        clock,
        decision,
    })
}

impl Membership {
    /// The durable form: `{account_id, genesis_hash, recovery_key,
    /// retired_recovery_keys, head, entries, recovery, decision_order,
    /// evidence, frozen?}` (§R9.3; the host adds its own fields).
    pub fn to_stored(&self) -> Value {
        let mut object = Map::new();
        object.insert("account_id".into(), json!(self.account_id));
        object.insert("genesis_hash".into(), json!(self.genesis_hash.to_hex()));
        object.insert("recovery_key".into(), self.recovery_key().to_json());
        object.insert(
            "retired_recovery_keys".into(),
            Value::Array(
                self.retired_recovery_keys()
                    .iter()
                    .map(|k| json!(b64u(k.as_bytes())))
                    .collect(),
            ),
        );
        object.insert("head".into(), self.head().to_json());
        object.insert(
            "entries".into(),
            Value::Array(self.entries.iter().map(|e| e.object().to_json()).collect()),
        );
        object.insert(
            "recovery".into(),
            Value::Array(self.records.iter().map(record_json).collect()),
        );
        object.insert("decision_order".into(), json!(self.decision_order));
        object.insert(
            "evidence".into(),
            json!({
                "count": self.evidence.count,
                "recent": self.evidence.recent.iter().map(|r| json!({
                    "seq": r.seq, "entry_hash": r.entry_hash.to_hex(), "signer": r.signer,
                    "reason": r.reason.as_str(), "at": r.at,
                })).collect::<Vec<_>>(),
            }),
        );
        if let Some(freeze) = &self.frozen {
            object.insert("frozen".into(), freeze_json(freeze));
        }
        Value::Object(object)
    }

    /// Rebuilds a log from [`Membership::to_stored`]'s form, checking it
    /// (module docs). `genesis_hash` is the pin; `account_id` the account.
    /// The host's reader: a record decided `host_confirmed` (restore-only)
    /// is refused.
    pub fn from_stored(
        account_id: &str,
        genesis_hash: &Hash32,
        stored: &Value,
    ) -> Result<Membership, StoredError> {
        Self::load_stored(account_id, genesis_hash, stored, Reader::Host)
    }

    /// [`Membership::from_stored`] for a client's own snapshot: the same
    /// checks, and a record a kit restore decided `host_confirmed` (a
    /// host-signed head showed it took effect, `verify_chain_confirmed`) is
    /// accepted. Never for a host's file.
    pub fn from_stored_client(
        account_id: &str,
        genesis_hash: &Hash32,
        stored: &Value,
    ) -> Result<Membership, StoredError> {
        Self::load_stored(account_id, genesis_hash, stored, Reader::Client)
    }

    fn load_stored(
        account_id: &str,
        genesis_hash: &Hash32,
        stored: &Value,
        reader: Reader,
    ) -> Result<Membership, StoredError> {
        let object = stored
            .as_object()
            .ok_or_else(|| bad("membership is not an object"))?;
        if str_of(object, "account_id")? != account_id {
            return Err(bad("another account"));
        }
        if hash_of(object, "genesis_hash")? != *genesis_hash {
            return Err(bad("another genesis"));
        }
        let entries = field(object, "entries")?
            .as_array()
            .ok_or_else(|| bad("entries"))?
            .iter()
            .enumerate()
            .map(|(i, v)| {
                Entry::parse(object_of(v, &format!("entry {i}"))?)
                    .map_err(|e| bad(format!("entry {i}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let genesis = entries.first().ok_or_else(|| bad("no genesis"))?;
        let mut m = Membership::from_genesis(account_id, genesis_hash, genesis.clone())
            .map_err(|e| bad(format!("genesis: {e}")))?;
        m.entries = entries;
        m.records = field(object, "recovery")?
            .as_array()
            .ok_or_else(|| bad("recovery"))?
            .iter()
            .map(|r| parse_record(r, reader))
            .collect::<Result<_, _>>()?;
        m.decision_order = u64_of(object, "decision_order")?;
        m.evidence = parse_evidence(field(object, "evidence")?)?;
        m.frozen = object.get("frozen").map(parse_freeze).transpose()?;

        // Records: one per pending-type entry, naming it; decisions at
        // positions the chain reached, after their entry, in a strict order.
        let pending_type: Vec<(u64, Hash32)> = m
            .entries
            .iter()
            .filter(|e| e.action.is_pending_type())
            .map(|e| (e.seq, e.hash()))
            .collect();
        let named: Vec<(u64, Hash32)> = m.records.iter().map(|r| (r.seq, r.entry_hash)).collect();
        if named != pending_type {
            return Err(bad("the recovery records don't match the log"));
        }
        let head_seq = m.entries.last().expect("a genesis").seq;
        let mut orders = Vec::new();
        for record in &m.records {
            if let Some(d) = &record.decision {
                if d.at_seq < record.seq || d.at_seq > head_seq || d.order > m.decision_order {
                    return Err(bad("a decision outside the log"));
                }
                orders.push(d.order);
            }
        }
        orders.sort_unstable();
        if orders.windows(2).any(|w| w[0] == w[1]) || orders.contains(&0) {
            return Err(bad("decision order"));
        }

        // Every later entry verifies against the chain before it, with the
        // decisions recorded up to that position (the replay conflicts are
        // judged on).
        let mut derived = super::Derived::new(&m.entries[0]);
        m.apply_decisions_at(&mut derived, 1);
        for i in 1..m.entries.len() {
            let entry = &m.entries[i];
            if entry.seq != i as u64 + 1 {
                return Err(bad(format!("entry {i}: seq")));
            }
            match m.check_against(&derived, &m.entries[..i], entry) {
                super::Check::Valid => {}
                other => return Err(bad(format!("entry {i} doesn't verify: {other:?}"))),
            }
            derived.apply(entry);
            m.apply_decisions_at(&mut derived, entry.seq);
        }
        m.derived = derived;

        // The summary fields must say what the entries say.
        let head = Head::from_json(field(object, "head")?).ok_or_else(|| bad("head"))?;
        if head != m.head() {
            return Err(bad("the stored head isn't the log's"));
        }
        if let Some(freeze) = &m.frozen {
            let ours = usize::try_from(freeze.seq)
                .ok()
                .and_then(|seq| m.entries.get(seq.checked_sub(1)?));
            if ours.is_none_or(|e| e.object() != &freeze.ours) {
                return Err(bad("the freeze doesn't name our entry"));
            }
        }
        let key = PublicKey::from_json(field(object, "recovery_key")?)
            .map_err(|_| bad("recovery_key"))?;
        if key != *m.recovery_key() {
            return Err(bad("the stored recovery key isn't the log's"));
        }
        let retired: Vec<Vec<u8>> = field(object, "retired_recovery_keys")?
            .as_array()
            .ok_or_else(|| bad("retired_recovery_keys"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .and_then(|t| b64u_decode(t).ok())
                    .ok_or_else(|| bad("retired_recovery_keys"))
            })
            .collect::<Result<_, _>>()?;
        let derived_retired: Vec<Vec<u8>> = m
            .retired_recovery_keys()
            .iter()
            .map(|k| k.as_bytes().to_vec())
            .collect();
        if retired != derived_retired {
            return Err(bad("the stored retired keys aren't the log's"));
        }
        Ok(m)
    }
}

fn freeze_json(freeze: &Freeze) -> Value {
    json!({"at": freeze.at, "seq": freeze.seq, "ours": freeze.ours.to_json(),
           "theirs": freeze.theirs.to_json()})
}

/// A freeze record (`membership.freeze`, `frozen` in `membership.json`).
pub fn freeze_to_json(freeze: &Freeze) -> Value {
    freeze_json(freeze)
}

/// Reads a freeze record written by [`freeze_to_json`].
pub fn parse_freeze(value: &Value) -> Result<Freeze, StoredError> {
    let object = value.as_object().ok_or_else(|| bad("frozen"))?;
    Ok(Freeze {
        seq: u64_of(object, "seq")?,
        at: u64_of(object, "at")?,
        ours: object_of(field(object, "ours")?, "frozen.ours")?,
        theirs: object_of(field(object, "theirs")?, "frozen.theirs")?,
    })
}

fn parse_evidence(value: &Value) -> Result<Evidence, StoredError> {
    let object = value.as_object().ok_or_else(|| bad("evidence"))?;
    let recent = field(object, "recent")?
        .as_array()
        .ok_or_else(|| bad("evidence.recent"))?
        .iter()
        .map(|r| {
            let r = r.as_object().ok_or_else(|| bad("evidence record"))?;
            Ok(EvidenceRecord {
                seq: u64_of(r, "seq")?,
                entry_hash: hash_of(r, "entry_hash")?,
                signer: str_of(r, "signer")?.to_owned(),
                reason: parse_evidence_reason(str_of(r, "reason")?)
                    .ok_or_else(|| bad("evidence reason"))?,
                at: u64_of(r, "at")?,
            })
        })
        .collect::<Result<Vec<_>, StoredError>>()?;
    if recent.len() > super::MAX_EVIDENCE {
        return Err(bad("evidence.recent is too long"));
    }
    Ok(Evidence {
        count: u64_of(object, "count")?,
        recent,
    })
}

impl Membership {
    /// A freeze read back from its own file (`membership.freeze`, durable
    /// before `membership.json` says `frozen`, §R9.3): the log is frozen
    /// from now on. Refused when its `ours` isn't our entry at its `seq`.
    pub fn restore_freeze(&mut self, freeze: Freeze) -> Result<(), StoredError> {
        let ours = usize::try_from(freeze.seq)
            .ok()
            .and_then(|seq| self.entries.get(seq.checked_sub(1)?));
        if ours.is_none_or(|e| e.object() != &freeze.ours) {
            return Err(bad("the freeze doesn't name our entry"));
        }
        if self.frozen.is_none() {
            self.frozen = Some(freeze);
        }
        Ok(())
    }
}

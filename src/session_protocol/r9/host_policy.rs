//! The host policy of §R9.8a (relay only), on the host: the stored policy
//! and the answer to a `host_policy_set`/`host_policy_get`.
//!
//! `pairing/host_policy.json` holds `{v, account_id, genesis_hash,
//! revision, relay_only, requests}`, bound to the pinned device list (a
//! file for another account or genesis, or one that can't be read, fails
//! closed). A change is written first as `host_policy.pending` (its whole
//! new file), then over `host_policy.json`, then the pending file goes.
//! A pending file that is present is the policy (rolled forward by
//! [`roll_forward`], at start and on the pass), and while it exists no
//! local link is allowed: a write whose durability is unknown never lets
//! an older `false` stand in for it. A failure before the pending file's
//! rename changed nothing (`save_failed`).
//!
//! Every read goes to disk: sets and gets are rare, and the connect loop
//! ([`local_allowed`]) reads the same files the host writes.
use std::collections::VecDeque;

use atem_client::session::host_policy::{Outcome, Policy, PolicyState};
use serde::{Deserialize, Serialize};

use crate::paths::PairingPaths;
use crate::session_protocol::membership::store::{self, DlFile, Step, Store};

/// Requests recorded with the policy (the newest; an evicted one's retry
/// meets the `expected_revision` check and is a `conflict`).
pub const MAX_REQUESTS: usize = 64;

/// `busy` detail: the stored policy can't be read or belongs to another
/// list (re-pair to reset it).
pub const DETAIL_UNREADABLE: &str = "host policy unreadable";

/// A change recorded with the policy it made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recorded {
    pub request_id: String,
    /// The principal that sent it (`member:<device_id>`): another
    /// principal's retry of the same id is `request_id_reused`.
    pub principal: String,
    pub relay_only: bool,
    pub expected_revision: u64,
    /// The revision it committed.
    pub revision: u64,
}

/// `host_policy.json` (and the pending file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Doc {
    pub v: u64,
    pub account_id: String,
    pub genesis_hash: String,
    pub revision: u64,
    pub relay_only: bool,
    pub requests: VecDeque<Recorded>,
}

impl Doc {
    fn fresh(account_id: &str, genesis_hash: &str) -> Doc {
        Doc {
            v: 1,
            account_id: account_id.into(),
            genesis_hash: genesis_hash.into(),
            revision: 0,
            relay_only: false,
            requests: VecDeque::new(),
        }
    }

    fn parse(bytes: &[u8]) -> Option<Doc> {
        serde_json::from_slice::<Doc>(bytes)
            .ok()
            .filter(|d| d.v == 1 && d.requests.len() <= MAX_REQUESTS)
    }
}

/// The policy as stored now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    pub doc: Doc,
    /// A pending file exists: the change isn't known durable yet.
    pub uncertain: bool,
}

impl Current {
    pub fn policy(&self) -> Policy {
        Policy {
            relay_only: self.doc.relay_only,
            revision: self.doc.revision,
            state: if self.uncertain {
                PolicyState::Uncertain
            } else {
                PolicyState::Durable
            },
        }
    }
}

/// The policy for the pinned list `(account_id, genesis_hash)`: the
/// pending file if present, else `host_policy.json`, else the fresh one.
/// `Err` (fail closed) for a file that can't be read or names another list.
pub fn current(
    paths: &PairingPaths,
    account_id: &str,
    genesis_hash: &str,
) -> Result<Current, String> {
    let read = |path: &std::path::Path| -> Result<Option<Doc>, String> {
        match store::read_private(path) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => Doc::parse(&bytes)
                .map(Some)
                .ok_or_else(|| format!("{} is damaged", path.display())),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    };
    let pending = read(&paths.host_policy_pending)?;
    let uncertain = pending.is_some();
    let doc = match pending {
        Some(doc) => doc,
        None => read(&paths.host_policy)?.unwrap_or_else(|| Doc::fresh(account_id, genesis_hash)),
    };
    if doc.account_id != account_id || doc.genesis_hash != genesis_hash {
        return Err("the host policy belongs to another device list".into());
    }
    Ok(Current { doc, uncertain })
}

/// Whether the connect loop may try a local (direct) link: no pending
/// write, and a readable `host_policy.json` for the pinned list saying
/// `relay_only: false` (or none). A policy without a readable pinned list
/// is no policy only when neither file exists.
pub fn local_allowed(paths: &PairingPaths) -> bool {
    if store::present(&paths.host_policy_pending) {
        return false;
    }
    if !store::present(&paths.host_policy) {
        return true;
    }
    let Some((account, _, genesis)) = crate::session_protocol::membership::peek_pin_genesis(paths)
    else {
        return false;
    };
    current(paths, &account, &genesis).is_ok_and(|c| !c.uncertain && !c.doc.relay_only)
}

/// What a set did, and the policy after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetResult {
    pub outcome: Outcome,
    pub policy: Policy,
}

/// A `host_policy_set` as the host handles it.
#[derive(Debug, Clone, Copy)]
pub struct Change<'a> {
    /// Who sent it (`member:<device_id>`).
    pub principal: &'a str,
    pub request_id: &'a str,
    pub relay_only: bool,
    pub expected_revision: u64,
}

/// Why a set or get got no result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The same `request_id` with another body.
    Reused,
    /// The stored policy can't be read (`busy`, [`DETAIL_UNREADABLE`]).
    Unreadable(String),
}

/// Applies `host_policy_set` from `principal` for the pinned list
/// (§R9.8a's table). Holds
/// `trust_gen.lock` across the read and the write, as every pairing change.
pub fn set(
    store: &mut Store,
    paths: &PairingPaths,
    account_id: &str,
    genesis_hash: &str,
    change: &Change<'_>,
) -> Result<SetResult, Refused> {
    let Change {
        principal,
        request_id,
        relay_only,
        expected_revision,
    } = *change;
    let _lock = store
        .lock()
        .map_err(|e| Refused::Unreadable(format!("{e:#}")))?;
    let now = current(paths, account_id, genesis_hash).map_err(Refused::Unreadable)?;
    let mut doc = now.doc.clone();
    let result = |outcome, now: &Current| {
        Ok(SetResult {
            outcome,
            policy: now.policy(),
        })
    };
    if let Some(r) = doc.requests.iter().find(|r| r.request_id == request_id) {
        if r.principal != principal
            || r.relay_only != relay_only
            || r.expected_revision != expected_revision
        {
            return Err(Refused::Reused);
        }
        if r.revision != doc.revision {
            return result(Outcome::Superseded, &now);
        }
        let outcome = if now.uncertain {
            Outcome::Uncertain
        } else {
            Outcome::Committed
        };
        return result(outcome, &now);
    }
    if expected_revision != doc.revision {
        return result(Outcome::Conflict, &now);
    }
    if relay_only == doc.relay_only {
        return result(Outcome::Unchanged, &now);
    }
    doc.revision += 1;
    doc.relay_only = relay_only;
    doc.requests.push_back(Recorded {
        request_id: request_id.into(),
        principal: principal.into(),
        relay_only,
        expected_revision,
        revision: doc.revision,
    });
    while doc.requests.len() > MAX_REQUESTS {
        doc.requests.pop_front();
    }
    let bytes = serde_json::to_vec(&doc).expect("a policy serializes");
    let after = |uncertain| Current {
        doc: doc.clone(),
        uncertain,
    };
    // The pending file first: once it is visible, the change stands (it is
    // rolled forward); before its rename, nothing changed.
    if let Err(e) = store.replace(DlFile::HostPolicyPending, &bytes) {
        if e.step != Step::DirectoryFsync {
            log(&format!("policy not saved: {e}"));
            return result(Outcome::SaveFailed, &now);
        }
        log(&format!("policy durability unknown: {e}"));
        return result(Outcome::Uncertain, &after(true));
    }
    if let Err(e) = store.replace(DlFile::HostPolicy, &bytes) {
        log(&format!("policy durability unknown: {e}"));
        return result(Outcome::Uncertain, &after(true));
    }
    let uncertain = match store.remove(DlFile::HostPolicyPending) {
        Ok(()) => false,
        Err(e) => {
            log(&format!("policy pending file not removed: {e}"));
            store::present(&paths.host_policy_pending)
        }
    };
    result(
        if uncertain {
            Outcome::Uncertain
        } else {
            Outcome::Committed
        },
        &after(uncertain),
    )
}

/// Makes a pending change durable: `host_policy.json` gets the pending
/// file's bytes (temp, fsync, rename, directory fsync), then the pending
/// file goes. `Ok(true)` when nothing is pending any more. A pending file
/// that can't be read stays (no local link) and is reported.
pub fn roll_forward(store: &mut Store, paths: &PairingPaths) -> Result<bool, String> {
    if !store::present(&paths.host_policy_pending) {
        return Ok(true);
    }
    let _lock = store.lock().map_err(|e| format!("{e:#}"))?;
    let bytes = store::read_private(&paths.host_policy_pending)
        .map_err(|e| e.to_string())?
        .filter(|b| Doc::parse(b).is_some())
        .ok_or_else(|| format!("{} is damaged", paths.host_policy_pending.display()))?;
    store
        .replace(DlFile::HostPolicy, &bytes)
        .map_err(|e| e.to_string())?;
    store
        .remove(DlFile::HostPolicyPending)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

fn log(line: &str) {
    eprintln!("atem runtime: r9: host policy: {line}");
}

/// Tests of the link side: relay only as a commit leaves it (`true`: a
/// policy file, which also fails closed on a profile without a pinned
/// list), or no policy (`false`).
#[cfg(test)]
pub fn write_for_test(paths: &PairingPaths, relay_only: bool) {
    if relay_only {
        let mut doc = Doc::fresh("acct-test", "00");
        doc.revision = 1;
        doc.relay_only = true;
        store::private_dir(paths.dir()).unwrap();
        std::fs::write(&paths.host_policy, serde_json::to_vec(&doc).unwrap()).unwrap();
    } else {
        let _ = std::fs::remove_file(&paths.host_policy);
    }
}

#[cfg(test)]
#[path = "host_policy_tests.rs"]
mod tests;

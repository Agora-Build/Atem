//! The owner's own commands on the host, in the bridge (host-work-v1 §11.6
//! "On the host"; design I.4.6; step 4's open question 2): `atem task list
//! --unknown` and `atem task resolve`, and `atem status`'s `Delegated:`
//! line.
//!
//! - **The unresolved outcomes** are the host's unresolved alerts
//!   ([`Store::unresolved`]): one per delegated task of unknown outcome
//!   nobody resolved, with its session, sender, reason and when it was
//!   raised, in the host's order.
//! - **A resolution** is `work_resolve`'s ([`resolve`]) with `resolved.by`
//!   `local` (§11.2): only a delegated task of unknown outcome, a revoked
//!   sender's too; the same resolution again returns the recorded status;
//!   another is refused. It is committed (`BEGIN IMMEDIATE`) before the
//!   runtime answers. It needs no sender authority and works **whether or
//!   not `host.delegated` is on** (ruling T23a): with the hook off nothing
//!   remote can settle such a task, so the owner's command is the only way.
//!   `resolved` still reaches the wire only behind `host.delegated`.
//! - **`done`'s snapshot** is taken as `atem message reply --memory/--vault`
//!   takes one ([`collab_context::capture`], then the relay publication and
//!   read-back), with the same rules (vault context only with the account's
//!   signed encryption mode `on`, a vault entry named `ID:ENTRY@VERSION`,
//!   the credential redactor). The runtime publishes it off its pass and
//!   resolves with it once it is read back.
//!
//! Who may run them (the owner at a terminal outside any agent session) is
//! the local server's check; same-user, so a correctness guard, not a
//! security boundary.
use super::*;
use crate::runtime::collab_context::{self, ContextSpec, RelayPublisher, VaultRef};
use crate::runtime::delegated::resolve::{ResolveRefusal, resolve};
use crate::runtime::protocol::{DelegatedStatus, UnknownTask};
use anyhow::{Result, anyhow, bail};
use hw::{ContextKind, ContextSnapshot, Resolution};

/// How long `done`'s publication may take (as a reply's).
const PUBLISH_WAIT: Duration = Duration::from_secs(10);

/// What a `done` resolution does next.
pub enum OwnerDone {
    /// The task was resolved `done` with this same snapshot before: its
    /// status as recorded, and nothing to publish.
    Recorded(WorkStatus),
    /// Its snapshot, captured, to be published and read back first.
    Publish(OwnerPublication),
}

/// A `done` resolution's snapshot, captured and waiting to be published:
/// [`OwnerPublication::publish`] runs off the runtime's pass.
pub struct OwnerPublication {
    pub specs: Vec<ContextSpec>,
    publisher: RelayPublisher,
}

impl OwnerPublication {
    /// Publishes the snapshot and reads it back (`collab_context::publish`,
    /// within [`PUBLISH_WAIT`]): the one snapshot, as a `done` takes it.
    pub async fn publish(self) -> Result<ContextSnapshot> {
        let mut snapshots = tokio::time::timeout(
            PUBLISH_WAIT,
            collab_context::publish(&self.publisher, &self.specs),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow!("relay unreachable")))?;
        match (snapshots.pop(), snapshots.is_empty()) {
            (Some(snapshot), true) => Ok(snapshot),
            _ => bail!("invalid context snapshot"),
        }
    }
}

impl HostBridge {
    /// The `Delegated:` line's data (`atem status`): the unresolved
    /// outcomes, only while something is delegated (`host.delegated` on,
    /// a delegated task open, or one unresolved), so a host without
    /// delegated work shows exactly what main shows. Read from the store
    /// as it is (an unresolved count through its partial index, and the
    /// open delegated tasks through `open_records`); none without one.
    pub fn delegated_status(&self) -> Option<DelegatedStatus> {
        let store = self.work.store.as_ref()?;
        let unresolved = store.unresolved().ok()?.0;
        let delegated =
            self.features.delegated || unresolved > 0 || store.has_delegated().unwrap_or(false);
        delegated.then_some(DelegatedStatus { unresolved })
    }

    /// `atem task list --unknown`: the unresolved outcomes, in the host's
    /// order, whatever the hook says now.
    pub fn owner_unknown_tasks(&mut self) -> Result<Vec<UnknownTask>> {
        let store = self.owner_store()?;
        Ok(store
            .unresolved_alerts()?
            .into_iter()
            .map(|a| UnknownTask {
                task_id: a.task_id,
                session_id: a.session_id,
                sender: a.sender,
                reason: a.reason,
                at_ms: a.created_at,
            })
            .collect())
    }

    /// `atem task resolve <task_id> failed [--detail TEXT]` and, with its
    /// snapshot published, `done`: the task's status as resolved by
    /// `local`, committed before this returns; or why it isn't.
    pub fn owner_resolve(&mut self, task_id: &str, resolution: &Resolution) -> Result<WorkStatus> {
        if !resolution.valid() {
            match resolution {
                Resolution::Failed { .. } => bail!(INVALID_DETAIL),
                Resolution::Done { .. } => bail!("invalid context snapshot"),
            }
        }
        let store = self.owner_store()?;
        let record = owner_resolvable(store, task_id)?;
        let tx = store.immediate().map_err(|_| anyhow!(NOT_WRITTEN))?;
        let status = match resolve(store, &tx, task_id, LOCAL, resolution, host_now().wall_ms) {
            Ok(status) => status,
            Err(ResolveRefusal::Reused) => bail!(already_resolved(task_id, &record)),
            Err(ResolveRefusal::Forbidden) => bail!(
                "task {task_id} is {}; only a task of unknown outcome is resolved",
                state_word(record.status.state)
            ),
            Err(ResolveRefusal::Store) => bail!(NOT_WRITTEN),
        };
        tx.commit().map_err(|_| anyhow!(NOT_WRITTEN))?;
        Ok(status)
    }

    /// `atem task resolve <task_id> done (--memory ID | --vault
    /// ID:ENTRY@VERSION)` before its publication: the task is checked (a
    /// delegated task of unknown outcome, or one already resolved), and its
    /// one snapshot captured as a reply's (`collab_context::capture`: a
    /// memory as it is now, vault context only with the account's
    /// encryption `on`), to be published off the pass. A task already
    /// resolved publishes nothing (review M2): the same snapshot again (the
    /// same memory with its text unchanged, read locally; the same vault
    /// entry and version, whose text never changes) is the same resolution,
    /// its recorded status; anything else is refused as another.
    pub fn owner_done(
        &mut self,
        task_id: &str,
        memory: Option<&str>,
        vault: Option<&str>,
    ) -> Result<OwnerDone> {
        let store = self.owner_store()?;
        let record = owner_resolvable(store, task_id)?;
        let (memories, vaults): (Vec<String>, Vec<String>) = match (memory, vault) {
            (Some(m), None) => (vec![m.to_owned()], vec![]),
            (None, Some(v)) => {
                // Named by its entry, as a reply's vault reference is.
                if VaultRef::parse(v).is_ok_and(|r| r.entry.is_none()) {
                    bail!(
                        "ambiguous vault reference {v}: a resolution names the entry, ID:ENTRY@VERSION"
                    );
                }
                (vec![], vec![v.to_owned()])
            }
            _ => bail!("done needs one --memory or --vault"),
        };
        let host = self.work_host();
        if record.status.resolved.is_some() {
            let same = record
                .status
                .result
                .as_ref()
                .filter(|_| record.status.state == WorkState::Completed)
                .is_some_and(|result| match (memory, vault) {
                    (Some(_), None) => {
                        collab_context::capture(&self.work.dir, &host.account_id, &memories, &[])
                            .ok()
                            .and_then(|mut specs| specs.pop())
                            .is_some_and(|spec| match spec {
                                ContextSpec::Memory { memory } => {
                                    result.kind == ContextKind::Memory
                                        && result.id == memory.id
                                        && result.digest == hw::digest(memory.content.as_bytes())
                                }
                                ContextSpec::Vault { .. } => false,
                            })
                    }
                    _ => vaults
                        .first()
                        .and_then(|v| VaultRef::parse(v).ok())
                        .is_some_and(|r| {
                            result.kind == ContextKind::Vault
                                && r.entry
                                    .is_some_and(|n| result.id == format!("{}:{n}", r.id))
                                && result.version == u64::from(r.version)
                        }),
                });
            if same {
                return Ok(OwnerDone::Recorded(record.status));
            }
            bail!(already_resolved(task_id, &record));
        }
        let specs = collab_context::capture(&self.work.dir, &host.account_id, &memories, &vaults)?;
        Ok(OwnerDone::Publish(OwnerPublication {
            specs,
            publisher: RelayPublisher::new(self.work.dir.clone(), host),
        }))
    }

    /// The host-work store, for the owner's commands: open, sound and bound
    /// to this host's identity (records of an earlier identity are moved
    /// aside, as a pass moves them). With hosting off it is kept open, so
    /// the owner still settles what is there.
    fn owner_store(&mut self) -> Result<&Store> {
        self.work_config();
        if self.work.error {
            bail!("agent hosting records are unavailable; run `atem runtime restart`");
        }
        let identity = self.work_host();
        if self.work.store.is_none()
            || identity.account_id == UNPAIRED
            || !self.work_store_ready(&identity)
        {
            bail!(
                "agent hosting records are unavailable (hosting off in runtime.toml, or this host isn't verified: `atem status`)"
            );
        }
        Ok(self.work.store.as_ref().expect("checked above"))
    }
}

/// `resolved.by` for the host's own command (host-work-v1 §11.2).
const LOCAL: &str = "local";

/// A `failed` detail no reader would take (host-work-v1 §11.2).
const INVALID_DETAIL: &str = "a failed task's detail is 1-1024 bytes on one line, not blank, with no control or format character";

/// A resolution whose write failed: nothing was resolved.
const NOT_WRITTEN: &str = "the resolution couldn't be recorded; nothing was resolved";

/// The task `task_id` if a resolution may name it: a delegated task of
/// unknown outcome, or one resolved already (the same resolution returns
/// its status). Anything else is refused with its own reason.
fn owner_resolvable(store: &Store, task_id: &str) -> Result<WorkRecord> {
    let record = store
        .work(task_id)
        .map_err(|_| anyhow!(NOT_WRITTEN))?
        .ok_or_else(|| anyhow!("no task {task_id} in this runtime"))?;
    if record.delegated.is_none() {
        bail!(
            "task {task_id} is not a delegated sender's task; only those are resolved (a v1 task's unknown outcome expires at its deadline)"
        );
    }
    if record.status.resolved.is_none() && record.status.state != WorkState::OutcomeUnknown {
        bail!(
            "task {task_id} is {}; only a task of unknown outcome is resolved",
            state_word(record.status.state)
        );
    }
    Ok(record)
}

/// Why a resolved task takes no other resolution.
fn already_resolved(task_id: &str, record: &WorkRecord) -> String {
    format!(
        "task {task_id} was already resolved ({}, by {}); another resolution is refused",
        state_word(record.status.state),
        record
            .status
            .resolved
            .as_ref()
            .map_or("?", |r| r.by.as_str())
    )
}

/// A task state as the wire names it (`outcome_unknown`, `failed`, …).
fn state_word(state: WorkState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

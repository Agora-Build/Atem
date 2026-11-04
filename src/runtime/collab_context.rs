//! Context must be committed, read back and frozen before any task is queued.

use crate::memory::{api::KnowledgeClient, model::Memory, store::Store};
use crate::vault_client::VaultClient;
use anyhow::{Result, anyhow, bail};
use atem_client::session::host_work::{self as hw, ContextKind, ContextSnapshot};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultRef {
    pub id: String,
    pub entry: Option<u32>,
    pub version: u32,
}

impl VaultRef {
    pub fn parse(text: &str) -> Result<Self> {
        let (id, version) = text
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("vault reference must be ID[:ENTRY]@VERSION"))?;
        let (id, entry) = match id.rsplit_once(':') {
            Some((id, entry)) => (id, Some(entry.parse::<u32>()?)),
            None => (id, None),
        };
        let version = version.parse::<u32>()?;
        if !atem_client::session::wire::is_opaque_id(id) || version == 0 || entry == Some(0) {
            bail!("invalid vault reference");
        }
        Ok(Self {
            id: id.into(),
            entry,
            version,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContextSpec {
    Memory { memory: Memory },
    Vault { reference: VaultRef },
}

pub fn capture(dir: &Path, memories: &[String], vaults: &[String]) -> Result<Vec<ContextSpec>> {
    if memories.len() + vaults.len() > 8 {
        bail!("at most 8 context snapshots");
    }
    let mut specs = Vec::new();
    if !memories.is_empty() {
        let store = Store::open(&dir.join("knowledge.db"))?;
        for id in memories {
            let id = store.resolve_memory_id(id)?;
            let memory = store
                .get_memory(&id)?
                .filter(Memory::is_valid)
                .ok_or_else(|| anyhow!("memory is no longer valid"))?;
            if memory.content.len() > hw::MAX_CONTEXT_BYTES {
                bail!("context is too large");
            }
            specs.push(ContextSpec::Memory { memory });
        }
    }
    for text in vaults {
        specs.push(ContextSpec::Vault {
            reference: VaultRef::parse(text)?,
        });
    }
    Ok(specs)
}

#[allow(async_fn_in_trait)]
pub trait ContextPublisher {
    async fn memory(&self, memory: &Memory) -> Result<ContextSnapshot>;
    async fn vault(&self, reference: &VaultRef) -> Result<ContextSnapshot>;
}

pub async fn publish(
    publisher: &impl ContextPublisher,
    specs: &[ContextSpec],
) -> Result<Vec<ContextSnapshot>> {
    let mut snapshots = Vec::new();
    for spec in specs {
        let snapshot = match spec {
            ContextSpec::Memory { memory } => {
                let snapshot = publisher.memory(memory).await?;
                if snapshot.kind != ContextKind::Memory || snapshot.text != memory.content {
                    bail!("context changed");
                }
                snapshot
            }
            ContextSpec::Vault { reference } => {
                let snapshot = publisher.vault(reference).await?;
                if snapshot.kind != ContextKind::Vault
                    || snapshot.version != u64::from(reference.version)
                {
                    bail!("context changed");
                }
                snapshot
            }
        };
        if !snapshot.valid() {
            bail!("invalid context snapshot");
        }
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

pub struct RelayPublisher {
    dir: PathBuf,
    host: hw::HostTarget,
}

impl RelayPublisher {
    pub fn new(dir: PathBuf, host: hw::HostTarget) -> Self {
        Self { dir, host }
    }
    fn clients(&self) -> Result<(KnowledgeClient, VaultClient)> {
        // Constructed in a background task, never on the host's pass.
        let src = crate::profile::Sources::current()?;
        let paired =
            crate::auth::pairing_session_in(&src).map_err(|_| anyhow!("relay unreachable"))?;
        if src.paths.config.parent() != Some(self.dir.as_path()) {
            bail!("context profile changed");
        }
        let state = crate::pairing::load(&src)?;
        let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)?;
        let verified = trust
            .verified(&paired.astation_id)
            .ok_or_else(|| anyhow!("context profile changed"))?;
        if state.host_trust_gen != self.host.host_trust_gen
            || verified.data_account != self.host.account_id
            || verified.device_id != self.host.atem_device_id
        {
            bail!("context profile changed");
        }
        let id = src
            .config
            .instance_id
            .ok_or_else(|| anyhow!("context profile changed"))?;
        Ok((
            KnowledgeClient::new(
                paired.relay_base.clone(),
                id.clone(),
                paired.session_id.clone(),
                paired.astation_id.clone(),
            ),
            VaultClient::new(paired.relay_base, id, paired.session_id, paired.astation_id),
        ))
    }
}

impl ContextPublisher for RelayPublisher {
    async fn memory(&self, memory: &Memory) -> Result<ContextSnapshot> {
        if let Some(result) = test_snapshot(&memory.id).await {
            return result;
        }
        let (client, _) = self.clients()?;
        let snapshot = crate::memory::sync::push_memory_and_read_back(&client, memory).await?;
        let store = Store::open(&self.dir.join("knowledge.db"))?;
        if let Some(current) = store.get_memory(&memory.id)? {
            if current.content != memory.content || !current.is_valid() {
                bail!("context changed");
            }
            if snapshot.id != memory.id {
                store.rewrite_memory_id(&memory.id, &snapshot.id)?;
            }
            store.set_memory_seq(&snapshot.id, snapshot.version as i64)?;
            for (n, op) in store.pending()? {
                if let crate::memory::store::PendingOp::AddMemory { memory: pending } = op
                    && pending.id == snapshot.id
                    && pending.content == snapshot.text
                {
                    store.ack(n)?;
                }
            }
        }
        Ok(snapshot)
    }
    async fn vault(&self, reference: &VaultRef) -> Result<ContextSnapshot> {
        let key = match reference.entry {
            Some(n) => format!("{}:{n}@{}", reference.id, reference.version),
            None => format!("{}@{}", reference.id, reference.version),
        };
        if let Some(result) = test_snapshot(&key).await {
            return result;
        }
        let (_, client) = self.clients()?;
        let versions = client.read(&reference.id, None, true).await?;
        let mut matches = versions.iter().filter(|e| {
            e.kind == "content"
                && e.version == reference.version
                && reference.entry.is_none_or(|n| e.entry_no == n)
        });
        let first = matches
            .next()
            .ok_or_else(|| anyhow!("published vault version not readable"))?;
        if matches.next().is_some() {
            bail!("ambiguous vault reference: use ID:ENTRY@VERSION");
        }
        let text = client
            .read_back(&reference.id, first.entry_no, first.version, first.seq)
            .await?;
        if text != first.content {
            bail!("context changed");
        }
        Ok(ContextSnapshot {
            kind: ContextKind::Vault,
            id: format!("{}:{}", reference.id, first.entry_no),
            version: first.version.into(),
            digest: hw::digest(text.as_bytes()),
            text,
        })
    }
}

async fn test_snapshot(key: &str) -> Option<Result<ContextSnapshot>> {
    let dir = super::test_hooks::context_dir()?;
    let path = dir.join(format!("{}.json", hw::digest(key.as_bytes())));
    Some(
        async {
            let bytes = tokio::fs::read(path)
                .await
                .map_err(|_| anyhow!("relay unreachable"))?;
            let snapshot = serde_json::from_slice(&bytes)?;
            Ok(snapshot)
        }
        .await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Publisher {
        attempts: AtomicUsize,
        mismatch: bool,
    }
    impl ContextPublisher for Publisher {
        async fn memory(&self, memory: &Memory) -> Result<ContextSnapshot> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                anyhow::bail!("relay unreachable");
            }
            let text = if self.mismatch {
                "other text"
            } else {
                &memory.content
            };
            Ok(ContextSnapshot {
                kind: ContextKind::Memory,
                id: memory.id.clone(),
                version: 1,
                digest: hw::digest(text.as_bytes()),
                text: text.into(),
            })
        }
        async fn vault(&self, _: &VaultRef) -> Result<ContextSnapshot> {
            unreachable!()
        }
    }
    fn memory() -> Memory {
        Memory {
            id: "mem_f00dbabe".into(),
            content: "exact  bytes\n".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn publishing_failure_never_sends_and_retries() {
        let p = Publisher {
            attempts: AtomicUsize::new(0),
            mismatch: false,
        };
        let specs = vec![ContextSpec::Memory { memory: memory() }];
        assert!(publish(&p, &specs).await.is_err());
        assert!(publish(&p, &specs).await.is_err());
        let snapshots = publish(&p, &specs).await.unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].text, "exact  bytes\n");
        assert_eq!(snapshots[0].digest, hw::digest(b"exact  bytes\n"));
    }

    #[tokio::test]
    async fn a_mismatched_read_back_is_refused() {
        let p = Publisher {
            attempts: AtomicUsize::new(2),
            mismatch: true,
        };
        assert_eq!(
            publish(&p, &[ContextSpec::Memory { memory: memory() }])
                .await
                .unwrap_err()
                .to_string(),
            "context changed"
        );
    }

    #[test]
    fn vault_references_pin_entry_and_version() {
        let r = VaultRef::parse("v-a:2@7").unwrap();
        assert_eq!((r.id.as_str(), r.entry, r.version), ("v-a", Some(2), 7));
        for bad in ["v-a", "v-a@0", "v-a:0@1", "../../v@1"] {
            assert!(VaultRef::parse(bad).is_err(), "{bad}");
        }
    }
}

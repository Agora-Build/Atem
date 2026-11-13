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
    Memory { memory: Box<Memory> },
    Vault { reference: VaultRef },
}

impl ContextSpec {
    /// The snapshot as far as it is known before publication: a memory's own
    /// text. A vault entry's text is only known once it is read back.
    pub fn known_snapshot(&self) -> Option<ContextSnapshot> {
        match self {
            Self::Memory { memory } => Some(ContextSnapshot {
                kind: ContextKind::Memory,
                id: memory.id.clone(),
                version: 1,
                digest: hw::digest(memory.content.as_bytes()),
                text: memory.content.clone(),
            }),
            Self::Vault { .. } => None,
        }
    }

    /// Drops a memory's text (`Store::drop_payloads`); its id, hash and
    /// times stay. A vault reference carries no text.
    pub fn drop_payload(&mut self) {
        if let Self::Memory { memory } = self {
            memory.content.clear();
        }
    }
}

/// Why a vault reference can't be context: its text comes from the relay,
/// and only vault encryption keeps the relay from writing it (spec section
/// 8).
pub const VAULT_NEEDS_E2E: &str = "vault context needs end-to-end encryption on";

/// Why a vault entry read for context can't be frozen: the redactor chat-v1
/// applies to agent output would change its text.
pub const VAULT_CREDENTIAL: &str = "vault context contains a credential value; remove it";

/// Refuses vault context unless the newest signed encryption state of
/// `account` (the host's verified account) in the profile at `dir` is `on`:
/// only then are its entries sealed end to end, so the relay can't author
/// them (an entry in the clear is refused when it is read). Anything else,
/// an unreadable state included, refuses.
pub fn require_vault_encryption(dir: &Path, account: &str) -> Result<()> {
    let trust =
        crate::memory::trust::TrustStore::load_from(&crate::paths::CredPaths::in_dir(dir).trust);
    let on = trust
        .and_then(|trust| crate::memory::verification::newest_states(&trust))
        .ok()
        .and_then(|mut states| states.remove(account).flatten())
        .is_some_and(|state| state.mode == crate::memory::crypto::EncryptionMode::On);
    if !on {
        bail!(VAULT_NEEDS_E2E);
    }
    Ok(())
}

/// The context of a send or a reply by `account`'s host: memories frozen as
/// they are now, vault references to be read (with encryption on only).
pub fn capture(
    dir: &Path,
    account: &str,
    memories: &[String],
    vaults: &[String],
) -> Result<Vec<ContextSpec>> {
    if memories.len() + vaults.len() > 8 {
        bail!("at most 8 context snapshots");
    }
    let references = vaults
        .iter()
        .map(|text| VaultRef::parse(text))
        .collect::<Result<Vec<_>>>()?;
    if !references.is_empty() {
        require_vault_encryption(dir, account)?;
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
            specs.push(ContextSpec::Memory {
                memory: Box::new(memory),
            });
        }
    }
    for reference in references {
        specs.push(ContextSpec::Vault { reference });
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
                // Its text reaches other agents and remote senders as is.
                if crate::chat::session::redact(&snapshot.text) != snapshot.text {
                    bail!(VAULT_CREDENTIAL);
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
            VaultClient::new(paired.relay_base, id, paired.session_id, paired.astation_id)
                .encryption_on_only(),
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
    /// The mode is checked again here, before the entry is read and once
    /// it was (it may have changed since the send or reply was captured, or
    /// while the entry was read), and by every read of the vault client.
    async fn vault(&self, reference: &VaultRef) -> Result<ContextSnapshot> {
        require_vault_encryption(&self.dir, &self.host.account_id)?;
        let key = match reference.entry {
            Some(n) => format!("{}:{n}@{}", reference.id, reference.version),
            None => format!("{}@{}", reference.id, reference.version),
        };
        let snapshot = match test_snapshot(&key).await {
            Some(result) => result?,
            None => self.read_vault(reference).await?,
        };
        require_vault_encryption(&self.dir, &self.host.account_id)?;
        Ok(snapshot)
    }
}

impl RelayPublisher {
    /// Entry `reference` as the relay holds it, read twice and opened with
    /// the account's key.
    async fn read_vault(&self, reference: &VaultRef) -> Result<ContextSnapshot> {
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

/// Debug builds (`ATEM_TEST_CONTEXT_DIR`): the snapshot published for `key`
/// is `<sha256(key)>.json` in that directory (none: the relay is
/// unreachable); while `<sha256(key)>.hold` exists the publication waits,
/// and says so first with `<sha256(key)>.held` (a test acts once a
/// publication is parked, never after a fixed wait).
async fn test_snapshot(key: &str) -> Option<Result<ContextSnapshot>> {
    let dir = super::test_hooks::context_dir()?;
    let name = hw::digest(key.as_bytes());
    let path = dir.join(format!("{name}.json"));
    let hold = dir.join(format!("{name}.hold"));
    Some(
        async {
            if tokio::fs::try_exists(&hold).await.unwrap_or(false) {
                let _ = tokio::fs::write(dir.join(format!("{name}.held")), b"").await;
            }
            while tokio::fs::try_exists(&hold).await.unwrap_or(false) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
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
        let specs = vec![ContextSpec::Memory {
            memory: Box::new(memory()),
        }];
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
            publish(
                &p,
                &[ContextSpec::Memory {
                    memory: Box::new(memory()),
                }]
            )
            .await
            .unwrap_err()
            .to_string(),
            "context changed"
        );
    }

    /// Vault context is taken only while the newest signed encryption state
    /// of the host's account is `on`: not before a signed state, not off or
    /// migrating, not for another account. A memory needs no vault.
    #[test]
    fn vault_context_needs_the_accounts_signed_mode_on() {
        use crate::memory::crypto::EncryptionMode;
        use crate::memory::fake_astation::{ACCOUNT, pin, set_state};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::CredPaths::in_dir(dir.path());
        std::fs::create_dir_all(&paths.dir).unwrap();
        let vault = || capture(dir.path(), ACCOUNT, &[], &["v-a:1@1".into()]);
        let refused = |result: Result<Vec<ContextSpec>>| {
            assert_eq!(result.unwrap_err().to_string(), VAULT_NEEDS_E2E);
        };
        refused(vault());
        let astation = crate::memory::statements::FakeAstation::new();
        pin(
            &paths,
            &astation,
            &crate::memory::device_keys::DeviceKeys::generate(),
            true,
        );
        refused(vault());
        set_state(&paths, &astation, EncryptionMode::Off, None, 2);
        refused(vault());
        set_state(
            &paths,
            &astation,
            EncryptionMode::Enabling,
            Some("0a1b2c3d"),
            3,
        );
        refused(vault());
        set_state(&paths, &astation, EncryptionMode::On, Some("0a1b2c3d"), 4);
        assert!(matches!(
            vault().unwrap().as_slice(),
            [ContextSpec::Vault { .. }]
        ));
        refused(capture(
            dir.path(),
            "another-account",
            &[],
            &["v-a:1@1".into()],
        ));
        // A malformed reference says so, whatever the mode.
        assert_eq!(
            capture(dir.path(), ACCOUNT, &[], &["v-a".into()])
                .unwrap_err()
                .to_string(),
            "vault reference must be ID[:ENTRY]@VERSION"
        );
        set_state(
            &paths,
            &astation,
            EncryptionMode::Disabling,
            Some("0a1b2c3d"),
            5,
        );
        refused(vault());
        assert!(capture(dir.path(), ACCOUNT, &[], &[]).unwrap().is_empty());
    }

    /// The publisher checks the mode again before it reads an entry: a send
    /// or reply captured with encryption on whose encryption is off by then
    /// is refused, before any relay or test hook is asked.
    #[tokio::test]
    async fn the_publisher_checks_the_mode_before_it_reads() {
        let dir = tempfile::tempdir().unwrap();
        let publisher = RelayPublisher::new(
            dir.path().to_path_buf(),
            hw::HostTarget {
                account_id: crate::memory::fake_astation::ACCOUNT.into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
            },
        );
        let error = publisher
            .vault(&VaultRef::parse("v-a:1@1").unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), VAULT_NEEDS_E2E);
    }

    struct VaultPublisher(&'static str);
    impl ContextPublisher for VaultPublisher {
        async fn memory(&self, _: &Memory) -> Result<ContextSnapshot> {
            unreachable!()
        }
        async fn vault(&self, reference: &VaultRef) -> Result<ContextSnapshot> {
            Ok(ContextSnapshot {
                kind: ContextKind::Vault,
                id: format!("{}:1", reference.id),
                version: reference.version.into(),
                digest: hw::digest(self.0.as_bytes()),
                text: self.0.into(),
            })
        }
    }

    /// An entry the credential redactor would change is refused before its
    /// snapshot is frozen; its text never reaches another agent or a remote
    /// sender.
    #[tokio::test]
    async fn a_vault_entry_with_a_credential_value_is_refused() {
        let specs = [ContextSpec::Vault {
            reference: VaultRef::parse("v-a:1@1").unwrap(),
        }];
        let error = publish(
            &VaultPublisher("deploy with ghp_Zq8XfE2rT6yU1iO9pA3sD5fG7hJ4kL0mNbVc"),
            &specs,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), VAULT_CREDENTIAL);
        let snapshots = publish(&VaultPublisher("deploy with the stored key"), &specs)
            .await
            .unwrap();
        assert_eq!(snapshots[0].text, "deploy with the stored key");
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

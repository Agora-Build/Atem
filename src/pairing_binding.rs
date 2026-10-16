//! The host trust generation and the pairing binding (`pairing.json`).
//!
//! Every pairing gets a binding: a random id, the Astation it pairs with and
//! the host trust generation it was created in. `atem pair` creates one in
//! the next generation; `atem unpair` commits the next generation without a
//! binding *before* it removes credentials and sessions, so an interrupted
//! unpair still invalidates the old binding. The generation never decreases
//! or repeats.
//!
//! Asynchronous Astation work (authentication, re-authentication,
//! verification, unlock, rotation, escrow, credential reports) captures the
//! state when it starts (`Captured`) and applies a reply only while the
//! state is still the captured one, under the file's lock (`Captured::apply`):
//! a delayed reply never refreshes a replacement session or adopts a later
//! binding.
//!
//! A profile paired before this file existed migrates to generation 1 with a
//! deterministic binding id (`legacy-<astation id>`), computed in memory by
//! readers (`atem status` writes nothing) and recorded by the first
//! operation that captures it. Unpairing keeps memory, vault, credentials
//! data and keys: only the binding goes.
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

use crate::memory::key_agent::{KeyAgentApi, Reply, Request};
use crate::memory::trust::{TrustLock, TrustStore};
use crate::status::Sources;

/// A reply arrived for a pairing that is no longer the current one.
pub const CHANGED: &str = "The Astation pairing changed while this was in progress (atem unpair or atem pair); nothing from it was applied";
/// Work that needs a pairing binding on a profile without one.
pub const NO_BINDING: &str =
    "This profile has no current pairing binding. Run `atem unpair`, then `atem pair`.";

/// One pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub binding_id: String,
    pub astation_id: String,
    pub host_trust_gen: u64,
    /// Unix seconds; 0 for a migrated pairing not recorded yet.
    pub created_at: u64,
}

/// The host trust generation and the current binding, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustState {
    /// 0 only for a profile that never had a pairing binding.
    pub host_trust_gen: u64,
    pub binding: Option<Binding>,
    /// Read from `pairing.json` (else computed: never paired, or migrating).
    pub recorded: bool,
}

impl TrustState {
    /// The same generation and binding (identity only: not when it was
    /// created or whether it is recorded yet).
    pub fn same(&self, other: &TrustState) -> bool {
        let id = |state: &TrustState| {
            state
                .binding
                .as_ref()
                .map(|b| (b.binding_id.clone(), b.astation_id.clone()))
        };
        self.host_trust_gen == other.host_trust_gen && id(self) == id(other)
    }
}

/// `pairing.json`.
#[derive(Debug, Serialize, Deserialize)]
struct PairingFile {
    version: u8,
    host_trust_gen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    astation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<u64>,
}

/// Reads `pairing.json` without changing anything (no permission repair,
/// never through a symlink). `None` when there is no file.
fn read_file(path: &Path) -> Result<Option<TrustState>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow!(error).context(format!("could not read {}", path.display())));
        }
    };
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    let file: PairingFile = serde_json::from_slice(&raw)
        .with_context(|| format!("{} is unreadable", path.display()))?;
    if file.version != 1 {
        bail!("unsupported {} version {}", path.display(), file.version);
    }
    if file.host_trust_gen == 0 {
        bail!("{} has no host trust generation", path.display());
    }
    let binding = match (file.binding_id, file.astation_id) {
        (None, None) => None,
        (Some(binding_id), Some(astation_id))
            if !binding_id.is_empty() && !astation_id.is_empty() =>
        {
            Some(Binding {
                binding_id,
                astation_id,
                host_trust_gen: file.host_trust_gen,
                created_at: file.created_at.unwrap_or(0),
            })
        }
        _ => bail!("{} has an incomplete binding", path.display()),
    };
    Ok(Some(TrustState {
        host_trust_gen: file.host_trust_gen,
        binding,
        recorded: true,
    }))
}

fn write_file(path: &Path, state: &TrustState) -> Result<()> {
    let binding = state.binding.as_ref();
    let file = PairingFile {
        version: 1,
        host_trust_gen: state.host_trust_gen,
        binding_id: binding.map(|b| b.binding_id.clone()),
        astation_id: binding.map(|b| b.astation_id.clone()),
        created_at: binding.map(|b| b.created_at),
    };
    crate::memory::crypto::write_private(path, &serde_json::to_vec_pretty(&file)?)
}

/// The binding a pairing from before `pairing.json` migrates to.
fn legacy(src: &Sources) -> Option<Binding> {
    let astation_id = crate::status::pairing(src)?.astation_id?;
    Some(Binding {
        binding_id: format!("legacy-{astation_id}"),
        astation_id,
        host_trust_gen: 1,
        created_at: 0,
    })
}

/// The current state, read-only: `pairing.json`, else an existing pairing
/// as it migrates (generation 1), else generation 0 without a binding.
pub fn load(src: &Sources) -> Result<TrustState> {
    if let Some(state) = read_file(&src.pairing)? {
        return Ok(state);
    }
    let binding = legacy(src);
    Ok(TrustState {
        host_trust_gen: u64::from(binding.is_some()),
        binding,
        recorded: false,
    })
}

/// The lock every change of `pairing.json` and every bound apply holds
/// (`pairing.lock` beside it).
fn lock(src: &Sources) -> Result<TrustLock> {
    TrustStore::lock(&src.pairing)
}

fn now_secs() -> u64 {
    crate::credentials::CredentialEntry::now_secs()
}

/// The state at the start of asynchronous work. Records a migrating
/// pairing's binding (best effort: the computed one is the same).
pub fn capture(src: &Sources) -> Result<TrustState> {
    let _lock = lock(src)?;
    let mut state = load(src)?;
    if !state.recorded
        && let Some(binding) = state.binding.as_mut()
    {
        binding.created_at = now_secs();
        if write_file(&src.pairing, &state).is_ok() {
            state.recorded = true;
        }
    }
    Ok(state)
}

/// `atem unpair`'s first step: durably commits the next generation without
/// a binding, so every capture of the old one goes stale before anything is
/// removed. Returns the new generation.
pub fn commit_unpair(src: &Sources) -> Result<u64> {
    let _lock = lock(src)?;
    let current = load(src)?;
    let next = current.host_trust_gen + 1;
    write_file(
        &src.pairing,
        &TrustState {
            host_trust_gen: next,
            binding: None,
            recorded: true,
        },
    )?;
    Ok(next)
}

/// `atem pair`: a new binding with `astation_id` in the next generation,
/// unless the state changed since `expected` was captured (another pair or
/// unpair ran meanwhile).
pub fn bind_new(src: &Sources, expected: &TrustState, astation_id: &str) -> Result<TrustState> {
    let _lock = lock(src)?;
    let current = load(src)?;
    if !current.same(expected) {
        bail!(CHANGED);
    }
    let host_trust_gen = current.host_trust_gen + 1;
    let state = TrustState {
        host_trust_gen,
        binding: Some(Binding {
            binding_id: uuid::Uuid::new_v4().to_string(),
            astation_id: astation_id.to_string(),
            host_trust_gen,
            created_at: now_secs(),
        }),
        recorded: true,
    };
    write_file(&src.pairing, &state)?;
    Ok(state)
}

/// What asynchronous work started under: the state and the session its
/// authentication used (`(session_id, token)`; `None` for the local proof or
/// a pairing in progress).
#[derive(Clone)]
pub struct Captured {
    src: Sources,
    pub state: TrustState,
    pub session: Option<(String, String)>,
}

impl std::fmt::Debug for Captured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Captured")
            .field("state", &self.state)
            .field("session_id", &self.session.as_ref().map(|(id, _)| id))
            .finish_non_exhaustive()
    }
}

impl Captured {
    /// Captures `src`'s state now (`capture`).
    pub fn now(src: &Sources) -> Result<Self> {
        Ok(Self {
            state: capture(src)?,
            src: src.clone(),
            session: None,
        })
    }

    pub fn sources(&self) -> &Sources {
        &self.src
    }

    /// The captured binding (an error without one).
    pub fn bound(&self) -> Result<&Binding> {
        self.state
            .binding
            .as_ref()
            .ok_or_else(|| anyhow!(NO_BINDING))
    }

    /// The captured binding, which must be with `astation_id`.
    pub fn bound_to(&self, astation_id: &str) -> Result<&Binding> {
        let binding = self.bound()?;
        if binding.astation_id != astation_id {
            bail!(
                "This profile is paired with Astation {}, not {astation_id}. Run `atem unpair`, then `atem pair`.",
                binding.astation_id
            );
        }
        Ok(binding)
    }

    /// Whether the state is still the captured one (no lock held).
    pub fn check(&self) -> Result<()> {
        if load(&self.src)?.same(&self.state) {
            Ok(())
        } else {
            Err(anyhow!(CHANGED))
        }
    }

    /// Runs `apply` under the lock, only while the state is still the
    /// captured one. `apply` must not take the lock again (no `BoundAgent`
    /// inside).
    pub fn apply<T>(&self, apply: impl FnOnce() -> Result<T>) -> Result<T> {
        let _lock = lock(&self.src)?;
        self.check()?;
        apply()
    }

    /// The pairing this work runs under created a binding (`bind_new`) from
    /// `before`: go on under the new one. Nothing changes unless this capture
    /// is of `before`.
    pub fn adopt(&mut self, before: &TrustState, after: &TrustState) -> Result<()> {
        if !self.state.same(before) {
            bail!(CHANGED);
        }
        self.state = after.clone();
        Ok(())
    }
}

/// A key agent whose every request runs only while the pairing it was
/// captured under is current (under the lock, so `atem unpair` waits for a
/// request in flight and every later one is refused).
pub struct BoundAgent {
    captured: Captured,
    inner: Arc<dyn KeyAgentApi>,
}

impl BoundAgent {
    /// Needs a bound capture.
    pub fn new(captured: Captured, inner: Arc<dyn KeyAgentApi>) -> Result<Self> {
        captured.bound()?;
        Ok(Self { captured, inner })
    }
}

impl KeyAgentApi for BoundAgent {
    fn call(&self, request: Request) -> Result<Reply> {
        self.captured.apply(|| self.inner.call(request))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn paired(dir: &Path, astation_id: &str) {
        let path = dir.join("credentials.enc");
        let mut store = crate::credentials::CredentialStore::load_from(&path);
        store.upsert(crate::credentials::CredentialEntry::new_paired(
            "access".into(),
            "refresh".into(),
            crate::credentials::CredentialEntry::now_secs() + 3600,
            None,
            astation_id.into(),
            true,
            1,
        ));
        store.save_to(&path).unwrap();
    }

    /// A profile in `dir` bound to `astation_id` (a fresh `atem pair`).
    pub(crate) fn bound_profile(dir: &Path, astation_id: &str) -> Captured {
        let src = Sources::in_dir(dir);
        let before = capture(&src).unwrap();
        bind_new(&src, &before, astation_id).unwrap();
        paired(dir, astation_id);
        Captured::now(&src).unwrap()
    }

    #[test]
    fn a_new_profile_has_generation_zero_and_no_binding() {
        let dir = tempfile::tempdir().unwrap();
        let state = load(&Sources::in_dir(dir.path())).unwrap();
        assert_eq!(state.host_trust_gen, 0);
        assert_eq!(state.binding, None);
        assert!(!dir.path().join("pairing.json").exists());
    }

    #[test]
    fn pair_unpair_cycles_never_repeat_a_generation() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        let mut seen = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for _ in 0..3 {
            let before = capture(&src).unwrap();
            let bound = bind_new(&src, &before, "astation-1").unwrap();
            let binding = bound.binding.clone().unwrap();
            assert!(seen.insert(binding.host_trust_gen));
            assert!(ids.insert(binding.binding_id.clone()));
            assert_eq!(load(&src).unwrap().binding, Some(binding));
            assert!(seen.insert(commit_unpair(&src).unwrap()));
            assert_eq!(load(&src).unwrap().binding, None);
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);
        // Unpairing again (an interrupted unpair, retried) still moves on.
        assert_eq!(commit_unpair(&src).unwrap(), 7);
    }

    #[test]
    fn the_file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        commit_unpair(&src).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&src.pairing)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn an_existing_pairing_migrates_to_generation_one_when_first_captured() {
        let dir = tempfile::tempdir().unwrap();
        paired(dir.path(), "astation-1");
        let src = Sources::in_dir(dir.path());
        let computed = load(&src).unwrap();
        assert!(!computed.recorded);
        assert_eq!(computed.host_trust_gen, 1);
        assert_eq!(
            computed.binding.as_ref().unwrap().binding_id,
            "legacy-astation-1"
        );
        assert!(!src.pairing.exists(), "reading writes nothing");
        let captured = capture(&src).unwrap();
        assert!(captured.recorded);
        assert!(captured.same(&computed));
        assert!(load(&src).unwrap().recorded);
        // Unpairing it moves past generation 1.
        assert_eq!(commit_unpair(&src).unwrap(), 2);
        let before = capture(&src).unwrap();
        let next = bind_new(&src, &before, "astation-1").unwrap();
        assert_eq!(next.host_trust_gen, 3);
        assert_ne!(next.binding.unwrap().binding_id, "legacy-astation-1");
    }

    #[test]
    fn a_capture_goes_stale_after_unpair_and_re_pair() {
        let dir = tempfile::tempdir().unwrap();
        let old = bound_profile(dir.path(), "astation-1");
        old.check().unwrap();
        commit_unpair(old.sources()).unwrap();
        let error = old
            .apply(|| -> Result<()> { panic!("applied") })
            .unwrap_err();
        assert_eq!(error.to_string(), CHANGED);
        // Re-paired with the same Astation: still not the captured binding.
        let before = capture(old.sources()).unwrap();
        bind_new(old.sources(), &before, "astation-1").unwrap();
        assert!(old.check().is_err());
        // bind_new refuses a stale expectation (another pair ran meanwhile).
        assert_eq!(
            bind_new(old.sources(), &before, "astation-1")
                .unwrap_err()
                .to_string(),
            CHANGED
        );
    }

    #[test]
    fn an_unreadable_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        std::fs::write(&src.pairing, b"not json").unwrap();
        assert!(load(&src).is_err());
        assert!(commit_unpair(&src).is_err());
        assert_eq!(std::fs::read(&src.pairing).unwrap(), b"not json");
        std::fs::write(
            &src.pairing,
            br#"{"version":1,"host_trust_gen":2,"binding_id":"x"}"#,
        )
        .unwrap();
        assert!(load(&src).is_err());
    }

    /// Fails every request it gets.
    struct NeverCalled;

    impl KeyAgentApi for NeverCalled {
        fn call(&self, _: Request) -> Result<Reply> {
            panic!("the key agent was called for a stale pairing")
        }
    }

    #[test]
    fn a_bound_agent_refuses_requests_after_unpair() {
        let dir = tempfile::tempdir().unwrap();
        let captured = bound_profile(dir.path(), "astation-1");
        let agent = BoundAgent::new(captured.clone(), Arc::new(NeverCalled)).unwrap();
        commit_unpair(captured.sources()).unwrap();
        assert_eq!(agent.status().unwrap_err().to_string(), CHANGED);
        // And an unbound capture can't make one.
        let unbound = Captured::now(captured.sources()).unwrap();
        assert!(BoundAgent::new(unbound, Arc::new(NeverCalled)).is_err());
    }
}

//! The one pairing (`pairing/pairing.enc`) and the host trust generation
//! (`pairing/trust_gen`).
//!
//! A profile is paired with at most one Astation. Its record holds the
//! Astation id, the pairing binding once `atem pair` created it, the session
//! Astation granted (its id and token prove this device at each connect), the
//! login Astation shared (`credentials::Login`), whether that login may be
//! kept offline (`save_credentials`) and when the link last dropped.
//!
//! Every pairing gets a binding: a random id, made in the next host trust
//! generation. `atem unpair` commits the next generation *before* it removes
//! the record, so an interrupted unpair still invalidates the old binding
//! (a binding of an older generation than `trust_gen` is no binding). The
//! generation never decreases or repeats; it survives unpairing.
//!
//! Asynchronous Astation work (authentication, re-authentication,
//! verification, unlock, rotation, escrow, credential reports, credentials
//! Astation sends) captures the state when it starts (`Captured`) and applies
//! a reply only while the state is still the captured one, under the
//! `trust_gen.lock` (`Captured::apply`): a delayed reply never refreshes a
//! replacement session or adopts a later binding.
use crate::records::{BindingRecord, Login, PairingRecord, SavedSession};
use anyhow::{Context, Result, anyhow, bail};
use std::sync::Arc;

use crate::credentials::now_secs;
use crate::memory::cred_agent::{CredAgentApi, Reply, Request};
use crate::memory::trust::{TrustLock, TrustStore};
use crate::paths::PairingPaths;
use crate::profile::Sources;

/// A reply arrived for a pairing that is no longer the current one.
pub const CHANGED: &str = "The Astation pairing changed while this was in progress (atem unpair or atem pair); nothing from it was applied";
/// Work that needs a pairing binding on a profile without one.
pub const NO_BINDING: &str = "This profile has no current pairing binding. Run `atem pair`.";

/// Seconds a session stays valid without activity.
const SESSION_IDLE_SECS: u64 = 7 * 24 * 60 * 60;
/// After the link drops, a login shared without `save_credentials` stays
/// usable this long.
pub const GRACE_PERIOD_SECS: u64 = 5 * 60;

impl SavedSession {
    pub fn new(session_id: String, token: String, hostname: String) -> Self {
        Self {
            session_id,
            token,
            hostname,
            last_activity: now_secs(),
        }
    }

    /// Used within the last 7 days.
    pub fn is_valid(&self) -> bool {
        now_secs().saturating_sub(self.last_activity) < SESSION_IDLE_SECS
    }
}

impl PairingRecord {
    pub fn new(astation_id: &str) -> Self {
        Self {
            astation_id: astation_id.to_string(),
            binding: None,
            session: None,
            shared: None,
            save_credentials: false,
            disconnected_at: None,
        }
    }

    /// The record at `paths`: `None` without one; an error when it can't be
    /// read (another machine's file, damaged): fail closed.
    pub fn load(paths: &PairingPaths) -> Result<Option<Self>> {
        let raw = match read_no_follow(&paths.record) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(
                    anyhow!(error).context(format!("could not read {}", paths.record.display()))
                );
            }
        };
        let plain = crate::machine_key::decrypt(crate::machine_key::PAIRING, &raw)
            .with_context(|| format!("{} is unreadable", paths.record.display()))?;
        let record = serde_json::from_slice(&plain)
            .with_context(|| format!("{} is unreadable", paths.record.display()))?;
        Ok(Some(record))
    }

    /// Writes the record (machine-bound, atomically, 0600). Callers that
    /// apply Astation replies hold the lock (`Captured::apply`).
    pub fn save(&self, paths: &PairingPaths) -> Result<()> {
        let sealed =
            crate::machine_key::encrypt(crate::machine_key::PAIRING, &serde_json::to_vec(self)?)?;
        crate::memory::crypto::write_private(&paths.record, &sealed)
    }

    /// Changes the record at `paths` with `edit`, under the pairing lock,
    /// only while it is still the pairing with `astation_id` and the binding
    /// `binding_id` the caller read (never creates or re-creates one). Whether
    /// it did. For callers outside `Captured::apply`.
    pub fn update(
        paths: &PairingPaths,
        astation_id: &str,
        binding_id: Option<&str>,
        edit: impl FnOnce(&mut Self),
    ) -> Result<bool> {
        let _lock = TrustStore::lock(&paths.trust_gen)?;
        let same_binding =
            |record: &Self| record.binding.as_ref().map(|b| b.binding_id.as_str()) == binding_id;
        match Self::load(paths)? {
            Some(record) if !same_binding(&record) => Ok(false),
            _ => Self::update_locked(paths, astation_id, edit),
        }
    }

    /// `update` for callers that hold the lock (inside `Captured::apply`,
    /// which already checked the binding).
    pub fn update_locked(
        paths: &PairingPaths,
        astation_id: &str,
        edit: impl FnOnce(&mut Self),
    ) -> Result<bool> {
        match Self::load(paths)? {
            Some(mut record) if record.astation_id == astation_id => {
                edit(&mut record);
                record.save(paths)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Astation shared `login` with this pairing (`credentialSync`, or the
    /// end of `atem pair`); `save`: whether it may be kept offline, when
    /// that is decided too. The link is up again (`disconnected_at` goes).
    /// Never creates a pairing: an error when the one with `astation_id` is
    /// gone. Callers hold the lock (`Captured::apply`).
    pub fn receive_login(
        paths: &PairingPaths,
        astation_id: &str,
        login: Login,
        save: Option<bool>,
    ) -> Result<()> {
        let updated = Self::update_locked(paths, astation_id, |record| {
            record.shared = Some(login);
            if let Some(save) = save {
                record.save_credentials = save;
            }
            record.disconnected_at = None;
        })?;
        if !updated {
            bail!(
                "the pairing with Astation {astation_id} was removed meanwhile; nothing was saved"
            );
        }
        Ok(())
    }

    /// The valid session for `astation_id`.
    pub fn session_for(&self, astation_id: &str) -> Option<&SavedSession> {
        self.session
            .as_ref()
            .filter(|session| self.astation_id == astation_id && session.is_valid())
    }

    /// Whether the saved session exists but expired.
    pub fn session_expired(&self) -> bool {
        self.session.as_ref().is_some_and(|s| !s.is_valid())
    }

    /// The login Astation shared, while the link to this Astation is up
    /// (`connected`): it comes before the user's own login.
    pub fn shared_while_connected(&self, connected: Option<&str>) -> Option<&Login> {
        self.shared
            .as_ref()
            .filter(|_| connected == Some(self.astation_id.as_str()))
    }

    /// The login Astation shared, when it may be used offline (`now` in Unix
    /// seconds): kept by choice (`save_credentials`), or within
    /// `GRACE_PERIOD_SECS` after the link dropped. It comes after the
    /// user's own login.
    pub fn shared_offline(&self, now: u64) -> Option<&Login> {
        let usable = self.save_credentials
            || match self.disconnected_at {
                None => true,
                Some(at) => now.saturating_sub(at) < GRACE_PERIOD_SECS,
            };
        self.shared.as_ref().filter(|_| usable)
    }
}

/// The file at `path`, never through a symlink.
fn read_no_follow(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut raw = Vec::new();
    options.open(path)?.read_to_end(&mut raw)?;
    Ok(raw)
}

/// Removes the record (nothing when there is none).
fn remove_record(paths: &PairingPaths) -> Result<()> {
    match std::fs::remove_file(&paths.record) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// One pairing binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub binding_id: String,
    pub astation_id: String,
    pub host_trust_gen: u64,
    /// Unix seconds.
    pub created_at: u64,
}

/// The host trust generation and the current binding, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustState {
    /// 0 only for a profile that never had a pairing binding.
    pub host_trust_gen: u64,
    pub binding: Option<Binding>,
}

impl TrustState {
    /// The same generation and binding.
    pub fn same(&self, other: &TrustState) -> bool {
        self == other
    }
}

/// `trust_gen` (0 without the file); an error when it can't be read.
fn read_trust_gen(paths: &PairingPaths) -> Result<u64> {
    match std::fs::read_to_string(&paths.trust_gen) {
        Ok(text) => text
            .trim()
            .parse()
            .with_context(|| format!("{} is unreadable", paths.trust_gen.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => {
            Err(anyhow!(error).context(format!("could not read {}", paths.trust_gen.display())))
        }
    }
}

fn write_trust_gen(paths: &PairingPaths, generation: u64) -> Result<()> {
    crate::memory::crypto::write_private(&paths.trust_gen, format!("{generation}\n").as_bytes())
}

/// The current state, read-only: the generation and the record's binding
/// when it is of that generation.
pub fn load(src: &Sources) -> Result<TrustState> {
    let paths = &src.paths.pairing;
    let host_trust_gen = read_trust_gen(paths)?;
    let binding = PairingRecord::load(paths)?.and_then(|record| {
        let binding = record.binding?;
        (binding.host_trust_gen == host_trust_gen).then_some(Binding {
            binding_id: binding.binding_id,
            astation_id: record.astation_id,
            host_trust_gen,
            created_at: binding.created_at,
        })
    });
    Ok(TrustState {
        host_trust_gen,
        binding,
    })
}

/// The lock every pairing change and every bound apply holds
/// (`trust_gen.lock`).
fn lock(src: &Sources) -> Result<TrustLock> {
    TrustStore::lock(&src.paths.pairing.trust_gen)
}

/// The state at the start of asynchronous work (under the lock).
pub fn capture(src: &Sources) -> Result<TrustState> {
    let _lock = lock(src)?;
    load(src)
}

/// `atem unpair`: removes the r9 device list, durably commits the next
/// generation (so every capture of the old binding goes stale), then
/// removes the pairing record. Returns the new generation. All under
/// `trust_gen.lock`. The device list goes first: a failure before its
/// removal began leaves the host paired as it was; once it began, the
/// unpair completes (never a paired host without its list).
pub fn unpair(src: &Sources) -> Result<u64> {
    let _lock = lock(src)?;
    let next = read_trust_gen(&src.paths.pairing)? + 1;
    // r9 §R9.3: a frozen list's genesis is kept on `frozen_genesis`, so it
    // can't be re-paired to. A failure before the list's removal began
    // changes nothing; one after it finishes the unpair (the files left
    // make the next runtime start fail closed, and `atem pair` removes
    // them): a paired host is never left without its list.
    if let Err(e) = crate::session_protocol::membership::forget_on_unpair(&src.paths.pairing) {
        if !e.begun {
            anyhow::bail!("could not remove the device list: {e}");
        }
        eprintln!(
            "atem: some device-list files couldn't be removed ({e}); remote access stays off until the next atem pair"
        );
    }
    write_trust_gen(&src.paths.pairing, next)?;
    remove_record(&src.paths.pairing)?;
    Ok(next)
}

/// `atem pair`: a new binding with `astation_id` in the next generation,
/// unless the state changed since `expected` was captured (another pair or
/// unpair ran meanwhile). The record (with the session the pairing saved)
/// gains the binding.
pub fn bind_new(src: &Sources, expected: &TrustState, astation_id: &str) -> Result<TrustState> {
    let _lock = lock(src)?;
    let paths = &src.paths.pairing;
    if !load(src)?.same(expected) {
        bail!(CHANGED);
    }
    let host_trust_gen = read_trust_gen(paths)? + 1;
    let binding = BindingRecord {
        binding_id: uuid::Uuid::new_v4().to_string(),
        host_trust_gen,
        created_at: now_secs(),
    };
    let mut record = PairingRecord::load(paths)?
        .filter(|record| record.astation_id == astation_id)
        .unwrap_or_else(|| PairingRecord::new(astation_id));
    record.binding = Some(binding.clone());
    write_trust_gen(paths, host_trust_gen)?;
    record.save(paths)?;
    Ok(TrustState {
        host_trust_gen,
        binding: Some(Binding {
            binding_id: binding.binding_id,
            astation_id: astation_id.to_string(),
            host_trust_gen,
            created_at: binding.created_at,
        }),
    })
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

/// A cred agent whose every request runs only while the pairing it was
/// captured under is current (under the lock, so `atem unpair` waits for a
/// request in flight and every later one is refused).
pub struct BoundAgent {
    captured: Captured,
    inner: Arc<dyn CredAgentApi>,
}

impl BoundAgent {
    /// Needs a bound capture.
    pub fn new(captured: Captured, inner: Arc<dyn CredAgentApi>) -> Result<Self> {
        captured.bound()?;
        Ok(Self { captured, inner })
    }
}

impl CredAgentApi for BoundAgent {
    fn call(&self, request: Request) -> Result<Reply> {
        self.captured.apply(|| self.inner.call(request))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::records::Tokens;

    /// A paired record for `astation_id` with a session and a shared login
    /// (no binding: `bound_profile` adds one).
    pub(crate) fn paired_record(astation_id: &str) -> PairingRecord {
        PairingRecord {
            session: Some(SavedSession::new(
                format!("session-{astation_id}"),
                "token".into(),
                "host".into(),
            )),
            shared: Some(Login::shared_by_astation(
                Some("me".into()),
                Tokens {
                    access_token: "access".into(),
                    refresh_token: "refresh".into(),
                    expires_at: now_secs() + 3600,
                },
            )),
            save_credentials: true,
            ..PairingRecord::new(astation_id)
        }
    }

    /// Writes the profile at `dir` as paired with `astation_id`, bound in
    /// generation `trust_gen` (`binding_id`), with the session
    /// `session_id`/`token` and a shared login.
    pub(crate) fn write_bound(
        dir: &std::path::Path,
        astation_id: &str,
        trust_gen: u64,
        binding_id: &str,
        (session_id, token): (&str, &str),
    ) {
        let paths = crate::paths::ProfilePaths::in_dir(dir).pairing;
        write_trust_gen(&paths, trust_gen).unwrap();
        PairingRecord {
            binding: Some(BindingRecord {
                binding_id: binding_id.into(),
                host_trust_gen: trust_gen,
                created_at: 1,
            }),
            session: Some(SavedSession::new(
                session_id.into(),
                token.into(),
                "host".into(),
            )),
            ..paired_record(astation_id)
        }
        .save(&paths)
        .unwrap();
    }

    /// Sets the saved session of the profile at `dir` (a record for
    /// `astation_id` is created when there is none).
    pub(crate) fn set_session(
        dir: &std::path::Path,
        astation_id: &str,
        session_id: &str,
        token: &str,
    ) {
        let paths = crate::paths::ProfilePaths::in_dir(dir).pairing;
        let mut record = PairingRecord::load(&paths)
            .unwrap()
            .filter(|record| record.astation_id == astation_id)
            .unwrap_or_else(|| PairingRecord::new(astation_id));
        record.session = Some(SavedSession::new(
            session_id.into(),
            token.into(),
            "host".into(),
        ));
        record.save(&paths).unwrap();
    }

    /// An `atem unpair` interrupted after its first step: the generation
    /// moved on, the record is still there.
    pub(crate) fn interrupted_unpair(dir: &std::path::Path) {
        let paths = crate::paths::ProfilePaths::in_dir(dir).pairing;
        write_trust_gen(&paths, read_trust_gen(&paths).unwrap() + 1).unwrap();
    }

    /// Edits the record of the profile at `dir` (under the lock).
    pub(crate) fn edit(dir: &std::path::Path, edit: impl FnOnce(&mut PairingRecord)) {
        let src = Sources::in_dir(dir);
        let _lock = lock(&src).unwrap();
        let mut record = PairingRecord::load(&src.paths.pairing).unwrap().unwrap();
        edit(&mut record);
        record.save(&src.paths.pairing).unwrap();
    }

    /// The saved session id of the profile at `dir`.
    pub(crate) fn session_id(dir: &std::path::Path) -> Option<String> {
        let paths = crate::paths::ProfilePaths::in_dir(dir).pairing;
        PairingRecord::load(&paths)
            .unwrap()?
            .session
            .map(|s| s.session_id)
    }

    /// A profile in `dir` bound to `astation_id` (a fresh `atem pair`).
    pub(crate) fn bound_profile(dir: &std::path::Path, astation_id: &str) -> Captured {
        let src = Sources::in_dir(dir);
        let before = capture(&src).unwrap();
        paired_record(astation_id).save(&src.paths.pairing).unwrap();
        bind_new(&src, &before, astation_id).unwrap();
        Captured::now(&src).unwrap()
    }

    #[test]
    fn a_new_profile_has_generation_zero_and_no_binding() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        let state = load(&src).unwrap();
        assert_eq!(state.host_trust_gen, 0);
        assert_eq!(state.binding, None);
        assert!(
            !src.paths.pairing.trust_gen.exists(),
            "reading writes nothing"
        );
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
            assert!(seen.insert(unpair(&src).unwrap()));
            assert_eq!(load(&src).unwrap().binding, None);
            assert!(
                !src.paths.pairing.record.exists(),
                "unpair removes the record"
            );
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);
        // Unpairing again (an interrupted unpair, retried) still moves on.
        assert_eq!(unpair(&src).unwrap(), 7);
    }

    #[test]
    fn the_files_are_private_and_the_record_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let captured = bound_profile(dir.path(), "astation-1");
        let paths = &captured.sources().paths.pairing;
        let raw = std::fs::read(&paths.record).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("astation-1"));
        assert_eq!(std::fs::read_to_string(&paths.trust_gen).unwrap(), "1\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&paths.record, &paths.trust_gen] {
                let mode = std::fs::metadata(path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{}", path.display());
            }
            let dir = paths.record.parent().unwrap();
            let mode = std::fs::metadata(dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        // The pairing's session and shared login survive the binding.
        let record = PairingRecord::load(paths).unwrap().unwrap();
        assert_eq!(record.session_for("astation-1").unwrap().token, "token");
        assert!(record.shared.is_some());
    }

    #[test]
    fn a_binding_of_an_older_generation_is_no_binding() {
        let dir = tempfile::tempdir().unwrap();
        let captured = bound_profile(dir.path(), "astation-1");
        let paths = &captured.sources().paths.pairing;
        interrupted_unpair(dir.path());
        assert!(paths.record.exists());
        assert_eq!(load(captured.sources()).unwrap().binding, None);
        assert_eq!(captured.check().unwrap_err().to_string(), CHANGED);
    }

    #[test]
    fn a_capture_goes_stale_after_unpair_and_re_pair() {
        let dir = tempfile::tempdir().unwrap();
        let old = bound_profile(dir.path(), "astation-1");
        old.check().unwrap();
        unpair(old.sources()).unwrap();
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

    /// r9: the device list is removed first, under the lock; when that
    /// fails the pairing is left as it was (no unpaired host keeps a list).
    #[test]
    fn unpair_removes_the_device_list_before_the_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        bound_profile(dir.path(), "astation-a");
        let paths = &src.paths.pairing;
        let gen_before = read_trust_gen(paths).unwrap();
        // A frozen list whose genesis can't be kept: frozen_genesis is a
        // directory, so its write fails.
        std::fs::write(
            &paths.membership,
            format!(r#"{{"genesis_hash":"{}"}}"#, "a".repeat(64)),
        )
        .unwrap();
        std::fs::write(&paths.freeze, b"x").unwrap();
        std::fs::create_dir(&paths.frozen_genesis).unwrap();
        assert!(unpair(&src).is_err());
        assert_eq!(
            read_trust_gen(paths).unwrap(),
            gen_before,
            "nothing committed"
        );
        assert!(
            PairingRecord::load(paths).unwrap().is_some(),
            "still paired"
        );
        assert!(paths.membership.exists(), "the list stays with the pairing");
        std::fs::remove_dir(&paths.frozen_genesis).unwrap();
        assert_eq!(unpair(&src).unwrap(), gen_before + 1);
        assert!(!paths.membership.exists() && !paths.freeze.exists());
        assert!(PairingRecord::load(paths).unwrap().is_none());
        assert_eq!(
            crate::session_protocol::membership::frozen_genesis(paths).len(),
            1
        );
    }

    /// r9 (re-review New Important 2): each step of the device list's
    /// removal fails in turn; afterwards the host is either still paired
    /// with its whole list, or unpaired. Never paired without a list that
    /// opens as "no device list".
    #[test]
    fn a_failed_device_list_removal_never_leaves_a_paired_host_without_its_list() {
        use crate::session_protocol::membership::store::{DlFile, Injected, Step, Store};
        use crate::session_protocol::membership::{FORGET_FAULT, MembershipHost};
        let steps = [
            (DlFile::State, Step::Remove),
            (DlFile::Carriage, Step::Remove),
            (DlFile::Intent, Step::Remove),
            (DlFile::Freeze, Step::Remove),
            (DlFile::Fault, Step::Remove),
            (DlFile::HostChannelKey, Step::Remove),
            (DlFile::Applied, Step::Remove),
        ];
        for (file, step) in steps {
            let dir = tempfile::tempdir().unwrap();
            let src = Sources::in_dir(dir.path());
            bound_profile(dir.path(), "astation-a");
            let paths = &src.paths.pairing;
            let journal = crate::runtime::state_dir(dir.path()).join("journal");
            crate::session_protocol::membership::store::private_dir(&journal).unwrap();
            let store = Store::new(paths, &journal);
            // A held r9 host with every file a list can have.
            std::fs::write(&paths.membership, b"{}").unwrap();
            for f in [
                DlFile::Carriage,
                DlFile::Intent,
                DlFile::Fault,
                DlFile::HostChannelKey,
                DlFile::Applied,
            ] {
                std::fs::write(store.path(f), b"x").unwrap();
            }
            FORGET_FAULT.with(|f| f.set(Some(Injected { file, step })));
            let unpaired = unpair(&src).is_ok();
            let paired = PairingRecord::load(paths).unwrap().is_some();
            assert_eq!(paired, !unpaired, "{file:?}");
            let opened = MembershipHost::open(
                paths,
                &journal,
                9,
                &atem_client::membership::HostNow {
                    wall_ms: 1,
                    mono_ms: 1,
                    boot_id: "b".into(),
                },
                &mut NoFences,
            );
            // The removal had begun (the unlink is done; only its directory
            // fsync failed): the unpair completes.
            assert!(unpaired, "{file:?}");
            assert!(!paired && !paths.membership.exists(), "{file:?}");
            let left = [
                DlFile::Carriage,
                DlFile::Intent,
                DlFile::Fault,
                DlFile::HostChannelKey,
                DlFile::Applied,
            ]
            .into_iter()
            .any(|f| store.present(f));
            // Whatever is left fails closed until `atem pair`.
            assert_eq!(matches!(opened, Ok(None)), !left, "{file:?}");
        }
        // The list's own unlink fails (a directory is in its way): nothing
        // changed, the host stays paired and its list never opens as none.
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        bound_profile(dir.path(), "astation-a");
        let paths = &src.paths.pairing;
        std::fs::create_dir(&paths.membership).unwrap();
        std::fs::write(paths.membership.join("x"), b"x").unwrap();
        std::fs::write(&paths.fault, b"x").unwrap();
        assert!(unpair(&src).is_err());
        assert!(
            PairingRecord::load(paths).unwrap().is_some(),
            "still paired"
        );
        assert!(paths.fault.exists(), "its fault record kept");
        let journal = crate::runtime::state_dir(dir.path()).join("journal");
        let opened = MembershipHost::open(
            paths,
            &journal,
            9,
            &atem_client::membership::HostNow {
                wall_ms: 1,
                mono_ms: 1,
                boot_id: "b".into(),
            },
            &mut NoFences,
        );
        assert!(opened.is_err(), "Failed, never None");
    }

    struct NoFences;
    impl crate::session_protocol::membership::Fences for NoFences {
        fn fence(&mut self, _: &str, _: u64) {}
        fn fault(&mut self, _: Option<&[String]>) {}
        fn halt(&mut self) {}
        fn remote_principals(&self) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn unreadable_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        let paths = &src.paths.pairing;
        crate::paths::write_test_file(&paths.trust_gen, b"not a number");
        assert!(load(&src).is_err());
        assert!(unpair(&src).is_err());
        assert_eq!(std::fs::read(&paths.trust_gen).unwrap(), b"not a number");
        std::fs::write(&paths.trust_gen, b"3\n").unwrap();
        std::fs::write(&paths.record, b"not encrypted").unwrap();
        assert!(load(&src).is_err());
        assert!(PairingRecord::load(paths).is_err());
    }

    #[test]
    fn the_shared_login_follows_the_connection_save_and_grace_rules() {
        let now = now_secs();
        let mut record = paired_record("astation-1");
        record.save_credentials = false;
        // Connected to that Astation: first choice.
        assert!(record.shared_while_connected(Some("astation-1")).is_some());
        assert!(record.shared_while_connected(Some("another")).is_none());
        assert!(record.shared_while_connected(None).is_none());
        // Offline: never disconnected, or within the grace period.
        assert!(record.shared_offline(now).is_some());
        record.disconnected_at = Some(now - GRACE_PERIOD_SECS + 10);
        assert!(record.shared_offline(now).is_some());
        record.disconnected_at = Some(now - GRACE_PERIOD_SECS - 1);
        assert!(record.shared_offline(now).is_none());
        // Saved: usable offline.
        record.save_credentials = true;
        assert!(record.shared_offline(now).is_some());
    }

    #[test]
    fn a_write_that_read_before_unpair_never_brings_the_pairing_back() {
        let dir = tempfile::tempdir().unwrap();
        let captured = bound_profile(dir.path(), "astation-1");
        let src = captured.sources();
        let paths = &src.paths.pairing;
        let read = PairingRecord::load(paths).unwrap().unwrap();
        let binding = read.binding.as_ref().map(|b| b.binding_id.clone());
        unpair(src).unwrap();
        let updated = PairingRecord::update(paths, "astation-1", binding.as_deref(), |r| {
            r.save_credentials = false
        })
        .unwrap();
        assert!(!updated);
        assert!(!paths.record.exists());
        // Paired again: another binding, still refused.
        let before = capture(src).unwrap();
        bind_new(src, &before, "astation-1").unwrap();
        let updated = PairingRecord::update(paths, "astation-1", binding.as_deref(), |r| {
            r.save_credentials = false
        })
        .unwrap();
        assert!(!updated);
    }

    #[test]
    fn concurrent_writers_lose_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let captured = bound_profile(dir.path(), "astation-1");
        let paths = captured.sources().paths.pairing.clone();
        let binding = captured.state.binding.clone().map(|b| b.binding_id);
        let writers: Vec<_> = (0..8)
            .map(|n| {
                let (paths, binding) = (paths.clone(), binding.clone());
                std::thread::spawn(move || {
                    for i in 0..10 {
                        PairingRecord::update(&paths, "astation-1", binding.as_deref(), |r| {
                            let session = r.session.as_mut().unwrap();
                            session.hostname.push_str(&format!("{n}.{i};"));
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let record = PairingRecord::load(&paths).unwrap().unwrap();
        let hostname = &record.session.unwrap().hostname;
        assert_eq!(hostname.matches(';').count(), 80, "{hostname}");
    }

    #[test]
    fn a_session_expires_after_seven_idle_days() {
        let mut session = SavedSession::new("s".into(), "t".into(), "h".into());
        assert!(session.is_valid());
        session.last_activity = now_secs() - SESSION_IDLE_SECS + 60;
        assert!(session.is_valid());
        session.last_activity = now_secs() - SESSION_IDLE_SECS - 1;
        assert!(!session.is_valid());
        let mut record = paired_record("astation-1");
        record.session = Some(session);
        assert!(record.session_expired());
        assert!(record.session_for("astation-1").is_none());
    }

    #[test]
    fn credentials_never_create_a_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::ProfilePaths::in_dir(dir.path()).pairing;
        let login = paired_record("astation-1").shared.unwrap();
        let error = PairingRecord::receive_login(&paths, "astation-1", login.clone(), Some(true))
            .unwrap_err();
        assert!(error.to_string().contains("removed meanwhile"), "{error}");
        assert!(!paths.record.exists());
        // An existing one takes them, with the save choice, and is up again.
        let mut record = PairingRecord::new("astation-1");
        record.disconnected_at = Some(1);
        record.save(&paths).unwrap();
        PairingRecord::receive_login(&paths, "astation-1", login.clone(), Some(true)).unwrap();
        let record = PairingRecord::load(&paths).unwrap().unwrap();
        assert_eq!(record.shared, Some(login.clone()));
        assert!(record.save_credentials && record.disconnected_at.is_none());
        // Never for another Astation.
        assert!(PairingRecord::receive_login(&paths, "astation-2", login, None).is_err());
    }

    /// Fails every request it gets.
    struct NeverCalled;

    impl CredAgentApi for NeverCalled {
        fn call(&self, _: Request) -> Result<Reply> {
            panic!("the cred agent was called for a stale pairing")
        }
    }

    #[test]
    fn a_bound_agent_refuses_requests_after_unpair() {
        let dir = tempfile::tempdir().unwrap();
        let captured = bound_profile(dir.path(), "astation-1");
        let agent = BoundAgent::new(captured.clone(), Arc::new(NeverCalled)).unwrap();
        unpair(captured.sources()).unwrap();
        assert_eq!(agent.status().unwrap_err().to_string(), CHANGED);
        // And an unbound capture can't make one.
        let unbound = Captured::now(captured.sources()).unwrap();
        assert!(BoundAgent::new(unbound, Arc::new(NeverCalled)).is_err());
    }
}

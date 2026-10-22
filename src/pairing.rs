//! The one pairing (`pairing/pairing.enc`) and the host trust generation
//! (`pairing/trust_gen`, floor copy `cred/trust_gen_floor`).
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
//! generation never decreases or repeats; it survives unpairing. A floor
//! copy lives in `cred/trust_gen_floor`, beside the device id Astation keys
//! its own floor by. The generation is the highest of the two files, the
//! record's binding and the legacy `pairing.json` (where it lived until
//! v0.7.1; moving here restarted it at 1, below generations Astation had
//! already accepted), so losing `pairing/` or either file never lowers it.
//! An unreadable one fails closed; its error says how to recover (`damaged`).
//! A new generation goes to the floor copy first; a file found below the
//! generation is raised to it under the lock (`capture`); `pairing.json` is
//! only read, never written or removed.
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

/// The file at `path` (`None` without it), never through a symlink; an
/// error when it can't be read.
fn read_optional(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    match read_no_follow(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow!(error).context(format!("could not read {}", path.display()))),
    }
}

/// A generation file (0 without it); an error when it can't be read.
fn read_gen_file(path: &std::path::Path) -> Result<u64> {
    let Some(raw) = read_optional(path)? else {
        return Ok(0);
    };
    std::str::from_utf8(&raw)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .ok_or_else(|| anyhow!("{} is unreadable", path.display()))
}

fn write_gen_file(path: &std::path::Path, generation: u64) -> Result<()> {
    crate::memory::crypto::write_private(path, format!("{generation}\n").as_bytes())
}

/// The legacy `pairing.json` (until v0.7.1), exactly as that version wrote
/// it.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Parsed to check the shape; only the generation is used.
struct LegacyPairing {
    version: u8,
    host_trust_gen: u64,
    #[serde(default)]
    binding_id: Option<String>,
    #[serde(default)]
    astation_id: Option<String>,
    #[serde(default)]
    created_at: Option<u64>,
}

/// The legacy `pairing.json`'s generation (0 without the file); an error
/// when it can't be read or isn't that file's version 1.
fn read_legacy_gen(path: &std::path::Path) -> Result<u64> {
    let Some(raw) = read_optional(path)? else {
        return Ok(0);
    };
    let legacy: LegacyPairing = serde_json::from_slice(&raw)
        .with_context(|| format!("{} is unreadable", path.display()))?;
    if legacy.version != 1 {
        bail!(
            "{} is unreadable (version {})",
            path.display(),
            legacy.version
        );
    }
    Ok(legacy.host_trust_gen)
}

/// `error` (reading the generation file at `path`) with what to do about it.
/// Both copies are written before a generation is used, so with the other
/// one readable (`copy`) the damaged one can go: the next capture rebuilds
/// it from the copy. Otherwise nothing proves which generation Astation last
/// accepted, and a lower one makes Astation refuse this host.
fn damaged(
    error: anyhow::Error,
    path: &std::path::Path,
    copy: Option<(&std::path::PathBuf, u64)>,
) -> anyhow::Error {
    match copy {
        Some((copy, generation)) if generation > 0 => anyhow!(
            "{error:#}. {copy} holds a copy of the host trust generation \
             ({generation}): move {path} aside (`mv {path} {path}.damaged`) \
             and Atem rebuilds it from that copy",
            copy = copy.display(),
            path = path.display(),
        ),
        _ => anyhow!(
            "{error:#}. No other copy holds the host trust generation: restore \
             {path} from a backup (removing it could lower the generation below \
             one Astation already accepted, and Astation then refuses this host)",
            path = path.display(),
        ),
    }
}

/// What the profile holds of the generation: `pairing/trust_gen`, the floor
/// copy `cred/trust_gen_floor`, the legacy `pairing.json` and the record.
struct Generations {
    file: u64,
    floor: u64,
    legacy: u64,
    record: Option<PairingRecord>,
}

impl Generations {
    /// An unreadable file fails closed.
    fn read(src: &Sources) -> Result<Self> {
        Ok(Self {
            record: PairingRecord::load(&src.paths.pairing)?,
            ..Self::files(src)?
        })
    }

    /// The files only, without the record. An unreadable one fails closed
    /// with what to do about it (`damaged`).
    fn files(src: &Sources) -> Result<Self> {
        let file_path = &src.paths.pairing.trust_gen;
        let floor_path = &src.paths.cred.trust_gen_floor;
        let legacy_path = &src.paths.legacy_pairing;
        match (
            read_gen_file(file_path),
            read_gen_file(floor_path),
            read_legacy_gen(legacy_path),
        ) {
            (Ok(file), Ok(floor), Ok(legacy)) => Ok(Self {
                file,
                floor,
                legacy,
                record: None,
            }),
            (Err(error), Ok(floor), _) => Err(damaged(error, file_path, Some((floor_path, floor)))),
            (Ok(file), Err(error), _) => Err(damaged(error, floor_path, Some((file_path, file)))),
            (Err(error), Err(_), _) => Err(damaged(error, file_path, None)),
            (Ok(_), Ok(_), Err(error)) => Err(damaged(error, legacy_path, None)),
        }
    }

    /// The generation: the highest of the two files and the record's
    /// binding, so losing either file (or `pairing/`) never lowers it.
    fn effective(&self) -> u64 {
        let bound = self
            .record
            .as_ref()
            .and_then(|record| record.binding.as_ref())
            .map_or(0, |binding| binding.host_trust_gen);
        self.file.max(self.floor).max(self.legacy).max(bound)
    }

    fn state(self) -> TrustState {
        let host_trust_gen = self.effective();
        let binding = self.record.and_then(|record| {
            let binding = record.binding?;
            (binding.host_trust_gen == host_trust_gen).then_some(Binding {
                binding_id: binding.binding_id,
                astation_id: record.astation_id,
                host_trust_gen,
                created_at: binding.created_at,
            })
        });
        TrustState {
            host_trust_gen,
            binding,
        }
    }

    /// Raises a file below the generation to it (the floor copy first).
    /// Under the lock.
    fn heal(&self, src: &Sources) -> Result<()> {
        let generation = self.effective();
        if self.floor < generation {
            write_gen_file(&src.paths.cred.trust_gen_floor, generation)?;
        }
        if self.file < generation {
            write_gen_file(&src.paths.pairing.trust_gen, generation)?;
        }
        Ok(())
    }
}

/// Commits a new `generation` (above `load`'s) to both files: the floor copy
/// first, then `pairing/trust_gen`. Under the lock.
fn commit_generation(src: &Sources, generation: u64) -> Result<()> {
    write_gen_file(&src.paths.cred.trust_gen_floor, generation)?;
    write_gen_file(&src.paths.pairing.trust_gen, generation)
}

/// The current state, read-only: the generation (`Generations::effective`)
/// and the record's binding when it is of that generation.
pub fn load(src: &Sources) -> Result<TrustState> {
    Ok(Generations::read(src)?.state())
}

/// The lock every pairing change and every bound apply holds
/// (`trust_gen.lock`).
fn lock(src: &Sources) -> Result<TrustLock> {
    TrustStore::lock(&src.paths.pairing.trust_gen)
}

/// The state at the start of asynchronous work (under the lock). A file
/// below the generation is raised to it first (best effort: the state is
/// the same either way, and `unpair`/`bind_new` write both files).
pub fn capture(src: &Sources) -> Result<TrustState> {
    let _lock = lock(src)?;
    let generations = Generations::read(src)?;
    if let Err(error) = generations.heal(src) {
        crate::diagnostics::warn(format!(
            "Couldn't raise the stored host trust generation to {}: {error:#}",
            generations.effective()
        ));
    }
    Ok(generations.state())
}

/// `atem unpair`: durably commits the next generation (so every capture of
/// the old binding goes stale), then removes the pairing record. Returns
/// the new generation. An unreadable record still goes (its binding counts
/// for nothing: it is never read again).
pub fn unpair(src: &Sources) -> Result<u64> {
    let _lock = lock(src)?;
    let generations = Generations {
        record: PairingRecord::load(&src.paths.pairing).unwrap_or(None),
        ..Generations::files(src)?
    };
    let next = generations.effective() + 1;
    commit_generation(src, next)?;
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
    let generations = Generations::read(src)?;
    let host_trust_gen = generations.effective() + 1;
    if !generations.state().same(expected) {
        bail!(CHANGED);
    }
    let binding = BindingRecord {
        binding_id: uuid::Uuid::new_v4().to_string(),
        host_trust_gen,
        created_at: now_secs(),
    };
    let mut record = PairingRecord::load(paths)?
        .filter(|record| record.astation_id == astation_id)
        .unwrap_or_else(|| PairingRecord::new(astation_id));
    record.binding = Some(binding.clone());
    commit_generation(src, host_trust_gen)?;
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
        write_gen_file(&paths.trust_gen, trust_gen).unwrap();
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
        write_gen_file(
            &paths.trust_gen,
            read_gen_file(&paths.trust_gen).unwrap() + 1,
        )
        .unwrap();
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
    fn an_unreadable_copy_says_how_to_recover() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        let file = &src.paths.pairing.trust_gen;
        let floor = &src.paths.cred.trust_gen_floor;
        for (damaged, copy) in [(file, floor), (floor, file)] {
            crate::paths::write_test_file(copy, b"7\n");
            crate::paths::write_test_file(damaged, b"not a number");
            let error = format!("{:#}", load(&src).unwrap_err());
            assert!(
                error.contains(&format!("{} is unreadable", damaged.display())),
                "{error}"
            );
            assert!(
                error.contains(&format!("{} holds a copy", copy.display())),
                "{error}"
            );
            assert!(
                error.contains(&format!("mv {d} {d}.damaged", d = damaged.display())),
                "{error}"
            );
            // Following the advice keeps the generation and rebuilds the file.
            std::fs::rename(damaged, damaged.with_extension("damaged")).unwrap();
            assert_eq!(capture(&src).unwrap().host_trust_gen, 7);
            assert_eq!(std::fs::read(damaged).unwrap(), b"7\n");
        }
        // No readable copy: restore from a backup, never remove.
        crate::paths::write_test_file(file, b"x");
        crate::paths::write_test_file(floor, b"y");
        let error = format!("{:#}", capture(&src).unwrap_err());
        assert!(
            error.contains("restore") && !error.contains("mv "),
            "{error}"
        );
        std::fs::remove_file(floor).unwrap();
        let error = format!("{:#}", unpair(&src).unwrap_err());
        assert!(
            error.contains("restore") && !error.contains("mv "),
            "{error}"
        );
        // The legacy pairing.json has no copy either.
        crate::paths::write_test_file(file, b"7\n");
        crate::paths::write_test_file(floor, b"7\n");
        std::fs::write(&src.paths.legacy_pairing, b"not json").unwrap();
        let error = format!("{:#}", load(&src).unwrap_err());
        assert!(
            error.contains("restore") && error.contains("pairing.json"),
            "{error}"
        );
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

    fn floor(src: &Sources) -> u64 {
        read_gen_file(&src.paths.cred.trust_gen_floor).unwrap()
    }

    fn file(src: &Sources) -> u64 {
        read_gen_file(&src.paths.pairing.trust_gen).unwrap()
    }

    /// Paired, then unpaired four times and paired again: generation 5 is
    /// bound, and both files say so.
    fn bound_at_five(dir: &std::path::Path) -> Sources {
        let src = Sources::in_dir(dir);
        bound_profile(dir, "astation-1");
        for _ in 0..3 {
            unpair(&src).unwrap();
        }
        bound_profile(dir, "astation-1");
        assert_eq!(load(&src).unwrap().host_trust_gen, 5);
        assert_eq!((floor(&src), file(&src)), (5, 5));
        src
    }

    #[test]
    fn a_lost_or_reset_trust_gen_file_never_lowers_the_generation() {
        for reset in [None, Some(1)] {
            let dir = tempfile::tempdir().unwrap();
            let src = bound_at_five(dir.path());
            // The record goes too, as after an unpair.
            remove_record(&src.paths.pairing).unwrap();
            match reset {
                None => std::fs::remove_file(&src.paths.pairing.trust_gen).unwrap(),
                Some(generation) => {
                    write_gen_file(&src.paths.pairing.trust_gen, generation).unwrap()
                }
            }
            assert_eq!(load(&src).unwrap().host_trust_gen, 5);
            let captured = capture(&src).unwrap();
            assert_eq!(captured.host_trust_gen, 5);
            assert_eq!(file(&src), 5, "raised under the lock");
            assert_eq!(unpair(&src).unwrap(), 6);
            let before = capture(&src).unwrap();
            paired_record("astation-1")
                .save(&src.paths.pairing)
                .unwrap();
            let after = bind_new(&src, &before, "astation-1").unwrap();
            assert_eq!(after.host_trust_gen, 7);
            assert_eq!((floor(&src), file(&src)), (7, 7));
        }
    }

    #[test]
    fn pairing_again_after_losing_the_pairing_dir_goes_above_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let src = bound_at_five(dir.path());
        std::fs::remove_dir_all(dir.path().join("pairing")).unwrap();
        let before = capture(&src).unwrap();
        assert_eq!(before.host_trust_gen, 5);
        assert!(before.binding.is_none());
        paired_record("astation-1")
            .save(&src.paths.pairing)
            .unwrap();
        let after = bind_new(&src, &before, "astation-1").unwrap();
        assert_eq!(after.host_trust_gen, 6);
        assert_eq!(load(&src).unwrap(), after);
    }

    #[test]
    fn a_binding_above_the_files_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let src = bound_at_five(dir.path());
        let binding = load(&src).unwrap().binding.unwrap();
        // Both files lost: the record's binding still says 5.
        std::fs::remove_file(&src.paths.pairing.trust_gen).unwrap();
        std::fs::remove_file(&src.paths.cred.trust_gen_floor).unwrap();
        let state = load(&src).unwrap();
        assert_eq!(state.host_trust_gen, 5);
        assert_eq!(
            state.binding.as_ref(),
            Some(&binding),
            "still the current binding"
        );
        assert_eq!(capture(&src).unwrap(), state);
        assert_eq!((floor(&src), file(&src)), (5, 5), "both raised");
        assert_eq!(unpair(&src).unwrap(), 6);
    }

    #[test]
    fn a_profile_without_a_floor_copy_gets_one_at_the_first_capture() {
        let dir = tempfile::tempdir().unwrap();
        // An existing profile: written before the floor copy existed.
        write_bound(dir.path(), "astation-1", 4, "binding-4", ("s", "t"));
        let src = Sources::in_dir(dir.path());
        assert!(!src.paths.cred.trust_gen_floor.exists());
        let state = load(&src).unwrap();
        assert_eq!(state.host_trust_gen, 4);
        assert!(
            !src.paths.cred.trust_gen_floor.exists(),
            "load is read-only"
        );
        assert_eq!(capture(&src).unwrap(), state);
        assert_eq!((floor(&src), file(&src)), (4, 4));
        // A floor above the file is never lowered by a capture.
        write_gen_file(&src.paths.cred.trust_gen_floor, 9).unwrap();
        assert_eq!(capture(&src).unwrap().host_trust_gen, 9);
        assert_eq!((floor(&src), file(&src)), (9, 9));
        // The old binding (4) is no longer current.
        assert!(load(&src).unwrap().binding.is_none());
    }

    const LEGACY_6: &[u8] = br#"{
  "version": 1,
  "host_trust_gen": 6,
  "binding_id": "legacy-binding",
  "astation_id": "astation-1",
  "created_at": 1
}"#;

    /// Astation's #91: a profile upgraded across the move to `pairing/`.
    #[test]
    fn the_legacy_pairing_json_is_a_floor_the_generation_never_goes_below() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        std::fs::write(&src.paths.legacy_pairing, LEGACY_6).unwrap();
        write_bound(dir.path(), "astation-1", 3, "binding-3", ("s", "t"));
        let state = load(&src).unwrap();
        assert_eq!(state.host_trust_gen, 6);
        assert!(state.binding.is_none(), "the binding at 3 is not current");
        let before = capture(&src).unwrap();
        assert_eq!(before, state);
        assert_eq!((floor(&src), file(&src)), (6, 6), "raised at the capture");
        assert_eq!(
            std::fs::read(&src.paths.legacy_pairing).unwrap(),
            LEGACY_6,
            "kept as is"
        );
        // `atem pair` replaces the stale binding above everything seen.
        let after = bind_new(&src, &before, "astation-1").unwrap();
        assert_eq!(after.host_trust_gen, 7);
        assert_eq!(load(&src).unwrap(), after);
        let mut issued = vec![after.host_trust_gen];
        for _ in 0..2 {
            issued.push(unpair(&src).unwrap());
            let before = capture(&src).unwrap();
            paired_record("astation-1")
                .save(&src.paths.pairing)
                .unwrap();
            issued.push(
                bind_new(&src, &before, "astation-1")
                    .unwrap()
                    .host_trust_gen,
            );
        }
        assert_eq!(issued, [7, 8, 9, 10, 11]);
        // Without `pairing/`, the floor copy holds.
        std::fs::remove_dir_all(dir.path().join("pairing")).unwrap();
        assert_eq!(capture(&src).unwrap().host_trust_gen, 11);
        assert_eq!(unpair(&src).unwrap(), 12);
    }

    #[test]
    fn an_unreadable_legacy_pairing_json_fails_closed() {
        for contents in [
            &b"not json"[..],
            br#"{"version":2,"host_trust_gen":6}"#,
            br#"{"version":1,"host_trust_gen":6,"extra":1}"#,
            br#"{"version":1}"#,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let src = Sources::in_dir(dir.path());
            std::fs::write(&src.paths.legacy_pairing, contents).unwrap();
            assert!(load(&src).is_err());
            assert!(capture(&src).is_err());
            assert!(unpair(&src).is_err());
            assert!(
                bind_new(
                    &src,
                    &load(&src).unwrap_or(TrustState {
                        host_trust_gen: 0,
                        binding: None,
                    }),
                    "astation-1"
                )
                .is_err()
            );
        }
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let src = Sources::in_dir(dir.path());
            let target = dir.path().join("elsewhere.json");
            std::fs::write(&target, LEGACY_6).unwrap();
            std::os::unix::fs::symlink(&target, &src.paths.legacy_pairing).unwrap();
            assert!(load(&src).is_err(), "never through a symlink");
        }
    }

    #[test]
    fn a_fresh_profile_writes_no_floor_copy() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        assert_eq!(capture(&src).unwrap().host_trust_gen, 0);
        assert!(!src.paths.cred.dir.exists());
    }
}
